from __future__ import annotations

"""GIDEON-only Diagnostics service.

It observes only allowlisted GIDEON services/units and GIDEON HTTP health endpoints.
It has no start/stop/config capability and cannot modify Defender, OpenSSH,
firewall, systemd units or unrelated Windows services.
"""

import argparse
from functools import lru_cache
import json
import os
from pathlib import Path
import ssl
import sys
import time
from typing import Any, Callable, Sequence

from gideon_common.tls import gideon_private_ca_context
import urllib.error
import urllib.request

from gideon_service_health import (
    HealthSnapshot,
    HealthState,
    ServiceObservation,
    aggregate_state,
    atomic_write_json,
    merge_state,
    service_manager_observations,
    utc_now,
)


def default_data_root() -> Path:
    value = os.environ.get("GIDEON_DATA_ROOT", "").strip()
    if value:
        return Path(value)
    if os.name == "nt":
        return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "GIDEON Remote Control"
    return Path("/var/lib/gideon")


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
        return dict(value) if isinstance(value, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def _config_paths(data_root: Path) -> tuple[Path, Path]:
    if os.name == "nt" or (data_root / "config").exists():
        return data_root / "config" / "gateway.json", data_root / "config" / "web_admin.json"
    return Path("/etc/gideon/gateway/gateway.json"), Path("/etc/gideon/web/web_admin.json")


def _health_url(config: dict[str, Any], path: str) -> tuple[str, str]:
    port = int(config.get("listen_port") or 0)
    ca_file = str(config.get("ca_file") or config.get("gateway_ca_file") or "")
    public_url = str(config.get("public_url") or "").strip().rstrip("/")
    if public_url.lower().startswith("https://"):
        # The active certificate is normally issued for the advertised DNS
        # name, not 127.0.0.1. Installers map that name to loopback locally, so
        # this still avoids an external round trip while preserving hostname
        # verification and eliminating a failed TLS handshake every cycle.
        return public_url + path, ca_file
    if not port:
        return "", ca_file
    return f"https://127.0.0.1:{port}{path}", ca_file


@lru_cache(maxsize=8)
def _probe_ssl_context(ca_file: str, mtime_ns: int, size: int) -> ssl.SSLContext:
    """Cache parsed trust stores while invalidating on certificate replacement."""
    del mtime_ns, size
    return gideon_private_ca_context(ca_file) if ca_file else ssl.create_default_context()


def _context_for_probe(ca_file: str) -> ssl.SSLContext:
    clean = str(ca_file or "").strip()
    if not clean:
        return _probe_ssl_context("", 0, 0)
    path = Path(clean)
    if not path.is_file():
        return _probe_ssl_context("", 0, 0)
    stat = path.stat()
    return _probe_ssl_context(str(path.resolve()), stat.st_mtime_ns, stat.st_size)


def probe_https(url: str, ca_file: str = "", timeout: float = 3.0) -> tuple[HealthState, str]:
    if not url:
        return HealthState.FAILED, "Endpoint no configurado"
    try:
        context = _context_for_probe(ca_file)
        request = urllib.request.Request(url, method="GET", headers={"User-Agent": "GIDEON-Diagnostics/1"})
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            body = response.read(4096).decode("utf-8", errors="replace")
            if not 200 <= int(response.status) < 300:
                return HealthState.FAILED, f"HTTP {response.status}"
            return HealthState.RUNNING, f"HTTP {response.status} {body[:120]}".strip()
    except Exception as exc:
        return HealthState.FAILED, f"{type(exc).__name__}: {exc}"


def collect_snapshot(
    data_root: Path,
    *,
    platform: str | None = None,
    runner=None,
    http_probe: Callable[[str, str, float], tuple[HealthState, str]] = probe_https,
) -> HealthSnapshot:
    kwargs = {"platform": platform}
    if runner is not None:
        kwargs["runner"] = runner
    services = service_manager_observations(**kwargs)
    by_component = {row.component: row for row in services}

    gateway_cfg_path, web_cfg_path = _config_paths(Path(data_root))
    gateway_cfg = _load_json(gateway_cfg_path)
    web_cfg = _load_json(web_cfg_path)

    gateway_url, gateway_ca = _health_url(gateway_cfg, "/health")
    web_url, web_ca = _health_url(web_cfg, "/healthz")
    if not web_ca:
        web_ca = str(web_cfg.get("gateway_ca_file") or "")

    for component, url, ca_file in (
        ("gateway", gateway_url, gateway_ca),
        ("web_admin", web_url, web_ca),
    ):
        manager = by_component.get(component)
        if manager is None:
            continue
        functional_state, detail = http_probe(url, ca_file, 3.0)
        manager.state = merge_state(manager.state, functional_state)
        manager.detail = f"{manager.detail}; health={detail}"
        manager.source += "+https"
        manager.checked_at_utc = utc_now()

    state = aggregate_state(row.state for row in services)
    return HealthSnapshot(state=state, services=services, generated_at_utc=utc_now())


def write_snapshot(data_root: Path, snapshot: HealthSnapshot) -> Path:
    target = Path(data_root) / "diagnostics" / "health.json"
    atomic_write_json(target, snapshot.as_dict())
    return target


def run_daemon_cycle(data_root: Path, *, platform: str | None = None) -> tuple[bool, str]:
    """Run one diagnostics cycle without ever hiding a publish failure.

    Windows services must remain alive across transient ACL/SCM/network startup
    races. A cycle failure is surfaced to stderr and, where possible, persisted
    as a FAILED snapshot; the outer daemon decides when to retry.
    """
    target = Path(data_root) / "diagnostics" / "health.json"
    try:
        snapshot = collect_snapshot(data_root, platform=platform)
        write_snapshot(data_root, snapshot)
        return True, f"snapshot={target}"
    except Exception as exc:
        detail = f"{type(exc).__name__}: {exc}"
        try:
            atomic_write_json(
                target,
                {
                    "schema_version": 1,
                    "state": HealthState.FAILED.value,
                    "generated_at_utc": utc_now(),
                    "services": [],
                    "error": detail,
                },
            )
            return False, detail
        except Exception as publish_exc:
            return False, detail + f"; publish={type(publish_exc).__name__}: {publish_exc}"


def run_daemon(data_root: Path, interval: float, *, platform: str | None = None) -> int:
    while True:
        ok, detail = run_daemon_cycle(data_root, platform=platform)
        if not ok:
            print(f"GIDEON Diagnostics cycle degraded: {detail}", file=sys.stderr, flush=True)
        time.sleep(max(2.0, interval))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="GIDEON Remote Control Diagnostics service")
    parser.add_argument("--data-root", type=Path, default=default_data_root())
    parser.add_argument("--platform", choices=["windows", "linux"], default=None)
    parser.add_argument("--interval", type=float, default=10.0)
    parser.add_argument("--daemon", action="store_true")
    parser.add_argument("--json", action="store_true")
    ns = parser.parse_args(list(argv) if argv is not None else None)
    if ns.daemon:
        return run_daemon(ns.data_root, ns.interval, platform=ns.platform)
    snapshot = collect_snapshot(ns.data_root, platform=ns.platform)
    write_snapshot(ns.data_root, snapshot)
    print(json.dumps(snapshot.as_dict(), ensure_ascii=False, indent=2))
    return 0 if snapshot.state is HealthState.RUNNING else 2


if __name__ == "__main__":
    raise SystemExit(main())
