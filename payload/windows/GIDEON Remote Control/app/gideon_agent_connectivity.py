#!/usr/bin/env python3
from __future__ import annotations

"""Network resiliency primitives for the standalone GIDEON Agent.

This module intentionally uses only the Python standard library so it travels in
all Windows/Linux/macOS/Raspberry Agent packages without adding a new system
requirement.  IP/interface/DNS data is telemetry and reconnect input only; it is
never part of the Agent identity.
"""

from dataclasses import dataclass, asdict
import hashlib
import ipaddress
import os
import random
import re
import socket
import subprocess
import time
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit


LOOPBACK_HOSTS = {"localhost", "ip6-localhost", "ip6-loopback", "::1"}
REMOTE_MODES = {"production", "lan", "automatic", "manual", "personalized", "personalizado"}
KNOWN_ROLES = {"primary", "secondary", "lan", "contingency"}


def _clean_url(value: Any) -> str:
    raw = str(value or "").strip().rstrip("/")
    if not raw:
        return ""
    parsed = urlsplit(raw)
    if parsed.scheme.lower() not in {"https", "http"} or not parsed.hostname:
        return ""
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        return ""
    return raw


def is_loopback_url(value: str) -> bool:
    raw = _clean_url(value)
    if not raw:
        return False
    host = str(urlsplit(raw).hostname or "").strip().lower()
    if host in LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def normalize_mode(value: Any) -> str:
    mode = str(value or "production").strip().lower().replace("-", "_")
    aliases = {
        "local": "local_test",
        "localtest": "local_test",
        "local_test": "local_test",
        "prod": "production",
        "internet": "production",
        "auto": "automatic",
        "custom": "personalized",
        "personalizado": "personalized",
    }
    return aliases.get(mode, mode if mode in REMOTE_MODES else "production")


@dataclass(frozen=True)
class Endpoint:
    url: str
    role: str = "secondary"
    priority: int = 100
    label: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def normalize_endpoints(control_plane: Mapping[str, Any]) -> list[Endpoint]:
    """Return an ordered, de-duplicated endpoint list.

    Backward compatibility: legacy ``base_url`` alone becomes the primary
    endpoint.  New configs may use ``endpoints`` plus named endpoint keys.
    Loopback is accepted only in explicit LOCAL_TEST mode.
    """

    mode = normalize_mode(control_plane.get("connectivity_mode") or control_plane.get("mode"))
    rows: list[Endpoint] = []

    def add(value: Any, role: str, priority: int, label: str = "") -> None:
        if isinstance(value, Mapping):
            url = _clean_url(value.get("url"))
            role_value = str(value.get("role") or role or "secondary").strip().lower()
            try:
                prio = int(value.get("priority", priority))
            except (TypeError, ValueError):
                prio = priority
            label_value = str(value.get("label") or label or "").strip()
        else:
            url = _clean_url(value)
            role_value = role
            prio = priority
            label_value = label
        if not url:
            return
        if mode != "local_test" and is_loopback_url(url):
            return
        if mode == "local_test" and not is_loopback_url(url):
            return
        role_value = role_value if role_value in KNOWN_ROLES else "secondary"
        rows.append(Endpoint(url=url, role=role_value, priority=prio, label=label_value))

    # Explicit structured list first.  It can describe primary/secondary/LAN/
    # contingency without changing the legacy installer contract.
    raw_rows = control_plane.get("endpoints")
    if isinstance(raw_rows, list):
        for idx, item in enumerate(raw_rows):
            add(item, "primary" if idx == 0 else "secondary", 10 + idx * 10)

    add(control_plane.get("primary_url"), "primary", 10)
    add(control_plane.get("base_url"), "primary", 10)
    add(control_plane.get("secondary_url"), "secondary", 20)
    add(control_plane.get("lan_url"), "lan", 30)
    add(control_plane.get("contingency_url"), "contingency", 40)

    # De-duplicate by normalized URL while preserving the best priority/role.
    unique: dict[str, Endpoint] = {}
    for row in rows:
        key = row.url.casefold()
        previous = unique.get(key)
        if previous is None or row.priority < previous.priority:
            unique[key] = row
    ordered = sorted(unique.values(), key=lambda x: (x.priority, x.url.casefold()))
    if not ordered:
        if mode == "local_test":
            raise ValueError("LOCAL_TEST requiere un endpoint loopback https://127.0.0.1/localhost.")
        raise ValueError("control_plane requiere al menos un endpoint remoto válido.")
    return ordered


def retry_delay(attempt: int, *, jitter_ratio: float = 0.15, random_value: float | None = None) -> float:
    """5, 10, 20, 40, 60... seconds with bounded positive/negative jitter."""

    base = min(60.0, 5.0 * (2 ** max(0, int(attempt))))
    ratio = max(0.0, min(float(jitter_ratio), 0.5))
    rv = random.random() if random_value is None else max(0.0, min(float(random_value), 1.0))
    factor = 1.0 + ((rv * 2.0) - 1.0) * ratio
    return max(1.0, base * factor)


class EndpointPool:
    def __init__(self, control_plane: Mapping[str, Any], runtime: Mapping[str, Any] | None = None) -> None:
        self.mode = normalize_mode(control_plane.get("connectivity_mode") or control_plane.get("mode"))
        self.endpoints = normalize_endpoints(control_plane)
        self._by_url = {x.url.casefold(): x for x in self.endpoints}
        runtime = runtime or {}
        last = _clean_url(runtime.get("last_known_good_endpoint"))
        self.last_good_url = last if last and last.casefold() in self._by_url else ""
        current = _clean_url(runtime.get("current_gateway_endpoint"))
        if current and current.casefold() in self._by_url:
            self.current_url = self._by_url[current.casefold()].url
        else:
            self.current_url = self.endpoints[0].url
        self._cycle: list[str] = []
        self._cycle_index = 0
        self.retry_attempt = 0
        self.failure_counts: dict[str, int] = {x.url: 0 for x in self.endpoints}
        self.cooldown_until: dict[str, float] = {x.url: 0.0 for x in self.endpoints}
        self.begin_cycle(prefer_last_good=False)

    def endpoint_dicts(self) -> list[dict[str, Any]]:
        return [x.as_dict() for x in self.endpoints]

    def begin_cycle(self, *, prefer_last_good: bool, now: float | None = None) -> str:
        moment = time.monotonic() if now is None else float(now)
        all_urls = [x.url for x in self.endpoints]
        urls = [url for url in all_urls if float(self.cooldown_until.get(url, 0.0)) <= moment]
        # Never deadlock: if every endpoint is cooling down, probe the one whose
        # cooldown expires first. This preserves eventual recovery without
        # hammering every known-bad route on each retry cycle.
        if not urls:
            urls = [min(all_urls, key=lambda url: float(self.cooldown_until.get(url, 0.0)))]
        if prefer_last_good and self.last_good_url in urls:
            urls = [self.last_good_url] + [x for x in urls if x != self.last_good_url]
        self._cycle = urls
        self._cycle_index = 0
        self.current_url = self._cycle[0]
        return self.current_url

    def ensure_current_cycle_position(self) -> None:
        if self.current_url in self._cycle:
            self._cycle_index = self._cycle.index(self.current_url)

    def next_after_failure(self) -> str | None:
        self.ensure_current_cycle_position()
        next_index = self._cycle_index + 1
        if next_index >= len(self._cycle):
            return None
        self._cycle_index = next_index
        self.current_url = self._cycle[next_index]
        return self.current_url

    def record_failure(self, url: str | None = None, *, now: float | None = None) -> None:
        clean = _clean_url(url or self.current_url)
        if not clean or clean.casefold() not in self._by_url:
            return
        canonical = self._by_url[clean.casefold()].url
        count = int(self.failure_counts.get(canonical, 0)) + 1
        self.failure_counts[canonical] = count
        # First failure still allows a normal priority retry next cycle. From the
        # second consecutive failure onward, quarantine the route briefly.
        if count >= 2:
            cooldown = min(120.0, 10.0 * (2 ** min(count - 2, 4)))
            moment = time.monotonic() if now is None else float(now)
            self.cooldown_until[canonical] = moment + cooldown

    def runtime_health(self, *, now: float | None = None) -> list[dict[str, Any]]:
        moment = time.monotonic() if now is None else float(now)
        rows: list[dict[str, Any]] = []
        for endpoint in self.endpoints:
            until = float(self.cooldown_until.get(endpoint.url, 0.0))
            rows.append({
                **endpoint.as_dict(),
                "failure_count": int(self.failure_counts.get(endpoint.url, 0)),
                "cooldown_seconds": round(max(0.0, until - moment), 2),
                "available": until <= moment,
                "last_known_good": endpoint.url == self.last_good_url,
                "current": endpoint.url == self.current_url,
            })
        return rows

    def cycle_exhausted(self) -> None:
        self.retry_attempt += 1

    def delay(self, *, random_value: float | None = None) -> float:
        # attempt=0 is 5 seconds. retry_attempt is incremented after exhausting
        # all endpoints, therefore subtract one for the first retry cycle.
        return retry_delay(max(0, self.retry_attempt - 1), random_value=random_value)

    def record_success(self, url: str | None = None) -> None:
        clean = _clean_url(url or self.current_url)
        if clean and clean.casefold() in self._by_url:
            self.current_url = self._by_url[clean.casefold()].url
            self.last_good_url = self.current_url
            self.failure_counts[self.current_url] = 0
            self.cooldown_until[self.current_url] = 0.0
        self.retry_attempt = 0
        self.begin_cycle(prefer_last_good=True)
        # begin_cycle may have selected LKG, which is the same successful URL.
        self.current_url = self.last_good_url or self.current_url
        self.ensure_current_cycle_position()

    def reset_after_network_change(self) -> str:
        self.retry_attempt = 0
        # A route/interface/DNS change invalidates old reachability evidence.
        for url in self.failure_counts:
            self.failure_counts[url] = 0
            self.cooldown_until[url] = 0.0
        return self.begin_cycle(prefer_last_good=True)

    def reset_after_wait(self) -> str:
        return self.begin_cycle(prefer_last_good=True)


@dataclass(frozen=True)
class NetworkSnapshot:
    interfaces: tuple[str, ...]
    local_ips: tuple[str, ...]
    default_gateway: str
    dns_servers: tuple[str, ...]
    dns_signature: str
    source_ip: str

    @property
    def signature(self) -> str:
        payload = "|".join([
            ",".join(self.interfaces),
            ",".join(self.local_ips),
            self.default_gateway,
            ",".join(self.dns_servers),
            self.dns_signature,
            self.source_ip,
        ])
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def as_dict(self) -> dict[str, Any]:
        return {
            "interfaces": list(self.interfaces),
            "local_ips": list(self.local_ips),
            "default_gateway": self.default_gateway,
            "dns_servers": list(self.dns_servers),
            "dns_signature": self.dns_signature,
            "source_ip": self.source_ip,
            "signature": self.signature,
        }


def _run_hidden(command: list[str], timeout: float = 3.0) -> str:
    kwargs: dict[str, Any] = {
        "capture_output": True,
        "text": True,
        "timeout": timeout,
        "errors": "replace",
    }
    if os.name == "nt":
        kwargs["creationflags"] = 0x08000000
    try:
        cp = subprocess.run(command, **kwargs)
        return (cp.stdout or "") + "\n" + (cp.stderr or "")
    except Exception:
        return ""


def _active_interfaces() -> tuple[str, ...]:
    values: set[str] = set()
    if os.name == "nt":
        text = _run_hidden([
            "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
            "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -ExpandProperty Name",
        ], timeout=4.0)
        values.update(x.strip() for x in text.splitlines() if x.strip())
    elif sys_platform() == "darwin":
        text = _run_hidden(["ifconfig"], timeout=3.0)
        current = ""
        active = False
        for line in text.splitlines():
            if line and not line[0].isspace() and ":" in line:
                if current and active and current != "lo0":
                    values.add(current)
                current = line.split(":", 1)[0].strip()
                active = False
            elif "status: active" in line:
                active = True
        if current and active and current != "lo0":
            values.add(current)
    else:
        text = _run_hidden(["ip", "-o", "link", "show", "up"], timeout=3.0)
        for match in re.finditer(r"^\d+:\s+([^:]+):", text, re.M):
            name = match.group(1).split("@", 1)[0]
            if name != "lo":
                values.add(name)
    if not values:
        try:
            values.update(name for _index, name in socket.if_nameindex() if name not in {"lo", "lo0"})
        except Exception:
            pass
    return tuple(sorted(values))


def _source_ip() -> str:
    for family, target in ((socket.AF_INET, ("1.1.1.1", 443)), (socket.AF_INET6, ("2606:4700:4700::1111", 443, 0, 0))):
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(0.2)
                sock.connect(target)
                return str(sock.getsockname()[0])
        except Exception:
            continue
    return ""


def _local_ips() -> tuple[str, ...]:
    values: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, type=socket.SOCK_STREAM):
            address = str(info[4][0]).split("%", 1)[0]
            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                continue
            if not ip.is_loopback:
                values.add(address)
    except Exception:
        pass
    source = _source_ip()
    if source:
        values.add(source.split("%", 1)[0])
    return tuple(sorted(values))


def _windows_network_values() -> tuple[str, tuple[str, ...], str]:
    text = _run_hidden(["ipconfig", "/all"], timeout=5.0)
    gateway = ""
    dns: list[str] = []
    lines = text.splitlines()
    gateway_re = re.compile(r"(?:Default Gateway|Puerta de enlace predeterminada)[ .]*:\s*(.*)$", re.I)
    dns_re = re.compile(r"(?:DNS Servers|Servidores DNS)[ .]*:\s*(.*)$", re.I)
    capture_dns = False
    for line in lines:
        match = gateway_re.search(line)
        if match and match.group(1).strip() and not gateway:
            gateway = match.group(1).strip().split("%", 1)[0]
        match = dns_re.search(line)
        if match:
            capture_dns = True
            first = match.group(1).strip().split("%", 1)[0]
            if first:
                dns.append(first)
            continue
        if capture_dns:
            stripped = line.strip().split("%", 1)[0]
            if re.fullmatch(r"[0-9a-fA-F:.]+", stripped or ""):
                dns.append(stripped)
                continue
            capture_dns = False
    sig = hashlib.sha256("\n".join(sorted(set(dns))).encode("utf-8")).hexdigest()
    return gateway, tuple(sorted(set(dns))), sig


def _unix_network_values() -> tuple[str, tuple[str, ...], str]:
    gateway = ""
    if sys_platform() == "darwin":
        text = _run_hidden(["route", "-n", "get", "default"], timeout=3.0)
        match = re.search(r"^\s*gateway:\s*(\S+)", text, re.M)
        gateway = match.group(1) if match else ""
    else:
        text = _run_hidden(["ip", "route", "show", "default"], timeout=3.0)
        match = re.search(r"\bdefault\s+via\s+(\S+)", text)
        gateway = match.group(1) if match else ""
    dns: list[str] = []
    raw = ""
    try:
        # This runs on every connectivity snapshot.  Keep the descriptor
        # lifetime explicit so a long-lived Agent cannot accumulate handles
        # while network state is being polled.
        with open("/etc/resolv.conf", "r", encoding="utf-8", errors="replace") as resolver_file:
            raw = resolver_file.read()
        for value in re.findall(r"^\s*nameserver\s+(\S+)", raw, re.M):
            dns.append(value.split("%", 1)[0])
    except OSError:
        pass
    sig = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return gateway, tuple(sorted(set(dns))), sig


def sys_platform() -> str:
    import sys
    return sys.platform


def capture_network_snapshot() -> NetworkSnapshot:
    if os.name == "nt":
        gateway, dns, dns_sig = _windows_network_values()
    else:
        gateway, dns, dns_sig = _unix_network_values()
    source = _source_ip()
    return NetworkSnapshot(
        interfaces=_active_interfaces(),
        local_ips=_local_ips(),
        default_gateway=gateway,
        dns_servers=dns,
        dns_signature=dns_sig,
        source_ip=source,
    )


def snapshot_changes(previous: NetworkSnapshot | None, current: NetworkSnapshot) -> list[str]:
    if previous is None:
        return []
    changes: list[str] = []
    if previous.interfaces != current.interfaces:
        changes.append("INTERFACE")
    if previous.local_ips != current.local_ips:
        changes.append("IP_LOCAL")
    if previous.default_gateway != current.default_gateway:
        changes.append("DEFAULT_GATEWAY")
    if previous.dns_servers != current.dns_servers or previous.dns_signature != current.dns_signature:
        changes.append("DNS")
    if previous.source_ip != current.source_ip:
        changes.append("SOURCE_ROUTE")
    return changes


def resolve_endpoint_dns(endpoints: Iterable[Endpoint]) -> dict[str, dict[str, Any]]:
    """Force a fresh resolver lookup for every configured endpoint."""

    results: dict[str, dict[str, Any]] = {}
    for endpoint in endpoints:
        parsed = urlsplit(endpoint.url)
        host = str(parsed.hostname or "")
        port = int(parsed.port or (443 if parsed.scheme.lower() == "https" else 80))
        addresses: set[str] = set()
        error = ""
        started = time.monotonic()
        try:
            for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
                addresses.add(str(info[4][0]).split("%", 1)[0])
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
        results[endpoint.url] = {
            "host": host,
            "port": port,
            "addresses": sorted(addresses),
            "ok": bool(addresses),
            "error": error,
            "elapsed_ms": round((time.monotonic() - started) * 1000.0, 1),
        }
    return results


__all__ = [
    "Endpoint",
    "EndpointPool",
    "NetworkSnapshot",
    "capture_network_snapshot",
    "is_loopback_url",
    "normalize_endpoints",
    "normalize_mode",
    "resolve_endpoint_dns",
    "retry_delay",
    "snapshot_changes",
]
