#!/usr/bin/env python3
"""Bootstrap/configuration helpers for the GIDEON Agent Gateway.

The Gateway works in two explicit network modes:

* ``internal_test``: uses a physical LAN IPv4 address of the server for local tests.
* ``production``: uses a manually configured public IPv4 address published by the Internet edge/NAT.

The Gateway does not use the corporate VPN as its production transport.

IPv6 link-local addresses (``fe80::/10``) are never auto-selected because they are
interface-scoped and are not a valid deployment endpoint for remote stores.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
import logging
import os
import secrets
import socket
import sys
import subprocess
import shutil
import time
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from gideon_infrastructure.subprocess_utils import run_hidden
from gideon_gateway_tls import GatewayTLSLifecycle

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "config" / "config.json"


def default_gateway_state_root() -> Path:
    """Return a version-independent Gateway state root.

    Gateway identity (CA, database, enrollment grants and config) must survive
    application upgrades/extractions.  Keeping it under the versioned program
    directory caused every new release folder to behave like a new Gateway.
    """
    override = str(os.environ.get("GIDEON_GATEWAY_STATE_ROOT") or "").strip()
    if override:
        return Path(os.path.expanduser(os.path.expandvars(override))).resolve()
    if os.name == "nt":
        base = os.environ.get("PROGRAMDATA") or os.environ.get("LOCALAPPDATA") or str(Path.home())
        return (Path(base) / "GIDEONRemoteControl" / "Gateway").resolve()
    if sys.platform == "darwin":
        return (Path.home() / "Library" / "Application Support" / "GIDEONRemoteControl" / "Gateway").resolve()
    xdg = os.environ.get("XDG_STATE_HOME")
    base = Path(xdg).expanduser() if xdg else (Path.home() / ".local" / "state")
    return (base / "gideon-remote-control" / "gateway").resolve()


GATEWAY_STATE_ROOT = default_gateway_state_root()
_LOG = logging.getLogger(__name__)

GATEWAY_CONFIG_PATH = GATEWAY_STATE_ROOT / "agent_gateway.json"
TLS_DIR = GATEWAY_STATE_ROOT / "tls"
GATEWAY_DATA_DIR = GATEWAY_STATE_ROOT / "data"
CA_NAME = "gideon_gateway_ca.pem"
CERT_NAME = "gideon_gateway_server.pem"
KEY_NAME = "gideon_gateway_server.key"
NETWORK_MODE_INTERNAL = "internal_test"
NETWORK_MODE_PRODUCTION = "production"

_LOCAL_IPV4_CACHE: tuple[float, list[str]] = (0.0, [])
_LOCAL_IPV4_CACHE_TTL = 30.0


def _load(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    return value if isinstance(value, dict) else {}


def _save(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _meaningful_gateway_config(path: Path) -> dict[str, Any] | None:
    try:
        value = _load(path)
    except Exception:
        return None
    if not value:
        return None
    meaningful = any(str(value.get(key) or "").strip() for key in (
        "public_url", "public_host", "test_host", "production_host", "admin_api_key", "enrollment_secret", "ca_file"
    ))
    return value if meaningful else None


def _legacy_gateway_candidates() -> list[Path]:
    """Find recent versioned Gateway configs near the current release only."""
    candidates: list[Path] = []
    direct = ROOT / "config" / "agent_gateway.json"
    if direct != GATEWAY_CONFIG_PATH and direct.is_file():
        candidates.append(direct)
    bases = []
    for base in (ROOT.parent, ROOT.parent.parent):
        if base.exists() and base not in bases:
            bases.append(base)
    patterns = (
        "GIDEON-Remote-Control-v6*/config/agent_gateway.json",
        "GIDEON-Remote-Control-v6*/GIDEON-Remote-Control-v6*/config/agent_gateway.json",
    )
    for base in bases:
        for pattern in patterns:
            try:
                candidates.extend(base.glob(pattern))
            except Exception as exc:
                _LOG.debug("No se pudo inspeccionar ruta de Gateway %s/%s: %s", base, pattern, exc)
    unique: dict[str, Path] = {}
    for path in candidates:
        try:
            resolved = path.resolve()
        except Exception:
            continue
        if resolved == GATEWAY_CONFIG_PATH.resolve():
            continue
        if _meaningful_gateway_config(resolved):
            unique[str(resolved).casefold()] = resolved
    return sorted(unique.values(), key=lambda x: x.stat().st_mtime_ns if x.exists() else 0, reverse=True)


def _legacy_data_dir(cfg: dict[str, Any], config_path: Path) -> Path:
    raw = str(cfg.get("data_dir") or "./gateway-data").strip()
    expanded = Path(os.path.expanduser(os.path.expandvars(raw)))
    if expanded.is_absolute():
        return expanded
    # Legacy normal layout: <app>/config/agent_gateway.json and data_dir=./gateway-data
    app_root = config_path.parent.parent if config_path.parent.name.casefold() == "config" else config_path.parent
    return (app_root / expanded).resolve()


def migrate_legacy_gateway_state() -> bool:
    """One-time migration from a versioned portable release into persistent state."""
    if _meaningful_gateway_config(GATEWAY_CONFIG_PATH):
        return False
    candidates = _legacy_gateway_candidates()
    if not candidates:
        return False
    source_cfg_path = candidates[0]
    source_cfg = _load(source_cfg_path)
    GATEWAY_STATE_ROOT.mkdir(parents=True, exist_ok=True)
    TLS_DIR.mkdir(parents=True, exist_ok=True)
    GATEWAY_DATA_DIR.mkdir(parents=True, exist_ok=True)

    # Copy the exact trust identity from the previous release.  This is what keeps
    # already-installed agents valid after upgrading GIDEON Remote Control.
    tls_sources: dict[str, Path] = {}
    legacy_tls_dir = source_cfg_path.parent / "gateway-tls"
    # A modern config may point ca_file to the *trust bundle*.  Never copy that
    # multi-certificate bundle on top of the canonical root CA file.  Prefer the
    # dedicated root CA beside the legacy TLS key and migrate the bundle separately.
    legacy_root_ca = legacy_tls_dir / "gideon_gateway_ca.pem"
    if legacy_root_ca.is_file():
        tls_sources["gideon_gateway_ca.pem"] = legacy_root_ca
    else:
        raw_ca = str(source_cfg.get("ca_file") or "").strip()
        candidate_ca = Path(os.path.expanduser(os.path.expandvars(raw_ca))) if raw_ca else legacy_root_ca
        if raw_ca and not candidate_ca.is_absolute():
            candidate_ca = (source_cfg_path.parent.parent / candidate_ca).resolve()
        if candidate_ca.is_file():
            tls_sources["gideon_gateway_ca.pem"] = candidate_ca
    for key, filename in (
        ("tls_certfile", "gideon_gateway_server.pem"),
        ("tls_keyfile", "gideon_gateway_server.key"),
    ):
        raw = str(source_cfg.get(key) or "").strip()
        candidate = Path(os.path.expanduser(os.path.expandvars(raw))) if raw else (legacy_tls_dir / filename)
        if raw and not candidate.is_absolute():
            candidate = (source_cfg_path.parent.parent / candidate).resolve()
        if not candidate.is_file():
            fallback = legacy_tls_dir / filename
            candidate = fallback if fallback.is_file() else candidate
        if candidate.is_file():
            tls_sources[filename] = candidate
    ca_key = legacy_tls_dir / "gideon_gateway_ca.key"
    if ca_key.is_file():
        tls_sources["gideon_gateway_ca.key"] = ca_key
    bundle = legacy_tls_dir / "gideon_gateway_trust_bundle.pem"
    if bundle.is_file():
        tls_sources["gideon_gateway_trust_bundle.pem"] = bundle
    for filename, source in tls_sources.items():
        try:
            shutil.copy2(source, TLS_DIR / filename)
        except Exception as exc:
            _LOG.warning("No se pudo migrar material TLS %s: %s", filename, exc)

    source_data = _legacy_data_dir(source_cfg, source_cfg_path)
    if source_data.is_dir():
        try:
            shutil.copytree(source_data, GATEWAY_DATA_DIR, dirs_exist_ok=True)
        except Exception as exc:
            _LOG.warning("No se pudo migrar data legacy de Gateway desde %s: %s", source_data, exc)

    migrated = dict(source_cfg)
    migrated["data_dir"] = str(GATEWAY_DATA_DIR)
    # v6.0.26 policy: the operational trust anchor is always the single active
    # root.  Transition bundles are tracked separately and never become the
    # default ca_file for agents/health checks.
    migrated["ca_file"] = str(TLS_DIR / "gideon_gateway_ca.pem")
    migrated["tls_trust_bundle_file"] = str(TLS_DIR / "gideon_gateway_trust_bundle.pem")
    migrated["tls_certfile"] = str(TLS_DIR / "gideon_gateway_server.pem")
    migrated["tls_keyfile"] = str(TLS_DIR / "gideon_gateway_server.key")
    migrated["migrated_from"] = str(source_cfg_path)
    _save(GATEWAY_CONFIG_PATH, migrated)
    return True


def _usable_ip(value: str, *, ipv4_only: bool = False) -> bool:
    """Return True for interface addresses that are meaningful to other hosts."""
    try:
        ip = ipaddress.ip_address(str(value).split("%", 1)[0])
    except ValueError:
        return False
    if ipv4_only and ip.version != 4:
        return False
    return not (
        ip.is_loopback
        or ip.is_unspecified
        or ip.is_multicast
        or ip.is_link_local
    )


def _address_sort_key(value: str) -> tuple[int, int, str]:
    ip = ipaddress.ip_address(value.split("%", 1)[0])
    # Prefer private IPv4 (LAN), then other IPv4, then global IPv6.
    return (0 if ip.version == 4 and ip.is_private else 1 if ip.version == 4 else 2, ip.version, value)


def _virtual_or_tunnel_interface(text: str) -> bool:
    value = str(text or "").casefold()
    hints = (
        "vethernet", "wsl", "hyper-v", "docker", "virtualbox", "vmware",
        "loopback", "tailscale", "zerotier", "wireguard", "openvpn", "vpn",
        "fortinet", "forticlient", "anyconnect", "globalprotect", "juniper",
        "sonicwall", "zscaler", "tap-windows", "tunnel", "teredo",
    )
    return any(hint in value for hint in hints)


def _windows_lan_ipv4_addresses() -> list[str]:
    """Enumerate active Windows LAN adapters, excluding VPN/WSL/virtual NICs."""
    if os.name != "nt":
        return []
    ps = shutil.which("powershell.exe") or shutil.which("powershell")
    if not ps:
        return []
    script = r'''$rows = Get-NetIPConfiguration -ErrorAction SilentlyContinue | ForEach-Object {
  $cfg = $_
  if ($cfg.NetAdapter -and $cfg.NetAdapter.Status -eq 'Up') {
    foreach ($ip in @($cfg.IPv4Address)) {
      if ($ip -and $ip.IPAddress) {
        [pscustomobject]@{
          IPAddress = [string]$ip.IPAddress
          Alias = [string]$cfg.InterfaceAlias
          Description = [string]$cfg.InterfaceDescription
          Metric = [int]($cfg.NetIPv4Interface.InterfaceMetric | Select-Object -First 1)
        }
      }
    }
  }
}
@($rows) | ConvertTo-Json -Compress'''
    try:
        proc = run_hidden(
            [ps, "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script],
            check=False, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=20,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return []
        raw = json.loads(proc.stdout.strip())
        rows = raw if isinstance(raw, list) else [raw]
        candidates: list[tuple[int, str]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            addr = str(row.get("IPAddress") or "").strip()
            alias = str(row.get("Alias") or "")
            desc = str(row.get("Description") or "")
            if not _usable_ip(addr, ipv4_only=True):
                continue
            if _virtual_or_tunnel_interface(alias + " " + desc):
                continue
            try:
                metric = int(row.get("Metric") or 9999)
            except Exception:
                metric = 9999
            candidates.append((metric, addr))
        result: list[str] = []
        for _metric, addr in sorted(candidates, key=lambda item: (item[0], item[1])):
            if addr not in result:
                result.append(addr)
        return result
    except Exception:
        return []


def local_ipv4_addresses(*, force: bool = False) -> list[str]:
    """Return usable local IPv4 addresses with a short shared cache.

    Windows adapter discovery uses PowerShell and is intentionally not executed on
    every paint/navigation event. ``force=True`` is reserved for the explicit
    "Detectar IPv4 locales" action or a background probe.
    """
    global _LOCAL_IPV4_CACHE
    now = time.monotonic()
    stamp, cached = _LOCAL_IPV4_CACHE
    if not force and cached and now - stamp < _LOCAL_IPV4_CACHE_TTL:
        return list(cached)

    physical = _windows_lan_ipv4_addresses()
    if physical:
        _LOCAL_IPV4_CACHE = (now, list(physical))
        return list(physical)

    result: list[str] = []
    for probe in (("1.1.1.1", 80), ("8.8.8.8", 53)):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(0.20)
                sock.connect(probe)
                addr = str(sock.getsockname()[0])
            if _usable_ip(addr, ipv4_only=True) and addr not in result:
                result.append(addr)
                break
        except Exception as exc:
            _LOG.debug("No se pudo resolver ruta UDP local: %s", exc)

    try:
        infos = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET, socket.SOCK_STREAM)
        for info in infos:
            addr = str(info[4][0])
            if _usable_ip(addr, ipv4_only=True) and addr not in result:
                result.append(addr)
    except Exception as exc:
        _LOG.debug("No se pudieron enumerar IPv4 locales: %s", exc)
    _LOCAL_IPV4_CACHE = (now, list(result))
    return result


def local_addresses() -> list[str]:
    """Return usable local addresses with IPv4 preferred; excludes fe80:: link-local."""
    result = local_ipv4_addresses()
    try:
        infos = socket.getaddrinfo(socket.gethostname(), None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for info in infos:
            addr = str(info[4][0])
            clean = addr.split("%", 1)[0]
            if _usable_ip(clean) and clean not in result:
                result.append(clean)
    except Exception as exc:
        _LOG.debug("No se pudieron enumerar direcciones locales: %s", exc)
    return sorted(result, key=_address_sort_key)


def format_url_host(host: str) -> str:
    """Return an RFC-compatible URL host, adding brackets around IPv6 literals."""
    value = str(host or "").strip()
    if not value:
        return value
    clean = value.strip("[]")
    try:
        ip = ipaddress.ip_address(clean.split("%", 1)[0])
    except ValueError:
        return value
    return f"[{clean}]" if ip.version == 6 else clean


def make_gateway_url(host: str, port: int) -> str:
    return f"https://{format_url_host(host)}:{int(port)}"


def is_public_ipv4(value: str) -> bool:
    """True only for an Internet-routable public IPv4 literal."""
    try:
        ip = ipaddress.ip_address(str(value or "").strip().strip("[]"))
    except ValueError:
        return False
    return ip.version == 4 and ip.is_global


def _valid_explicit_host(value: str) -> bool:
    return is_public_ipv4(value)


def gateway_network_snapshot(
    cfg: dict[str, Any] | None = None,
    *,
    include_local_ipv4s: bool = True,
    force_network_probe: bool = False,
) -> dict[str, Any]:
    """Resolve the active Gateway endpoint.

    ``include_local_ipv4s=False`` is the UI fast path: it reads persisted state
    only and never launches PowerShell/network discovery. This keeps tab changes
    instantaneous. Explicit discovery runs in a worker and uses ``force_network_probe``.
    """
    cfg = dict(cfg or _load(GATEWAY_CONFIG_PATH))
    configured_test = str(cfg.get("test_host") or "").strip()
    configured_valid = _usable_ip(configured_test, ipv4_only=True)
    ipv4s: list[str] = []
    if include_local_ipv4s:
        # Network discovery is explicit/background work only.  The UI fast path
        # (include_local_ipv4s=False) must remain a pure persisted-state read even
        # on first run when no test_host exists yet.
        ipv4s = local_ipv4_addresses(force=True) if force_network_probe else local_ipv4_addresses()
    detected = ipv4s[0] if ipv4s else (configured_test if configured_valid else "")
    if not configured_valid:
        configured_test = detected
    production = str(cfg.get("production_host") or "").strip().strip("[]")
    if not is_public_ipv4(production):
        production = ""
    legacy = str(cfg.get("public_host") or "").strip().strip("[]")
    if not production and is_public_ipv4(legacy):
        production = legacy
    mode = str(cfg.get("network_mode") or "").strip().lower()
    if mode not in {NETWORK_MODE_INTERNAL, NETWORK_MODE_PRODUCTION}:
        mode = NETWORK_MODE_PRODUCTION if production else NETWORK_MODE_INTERNAL
    active = configured_test if mode == NETWORK_MODE_INTERNAL else production
    if not active:
        active = configured_test
        mode = NETWORK_MODE_INTERNAL
    return {
        "mode": mode,
        "active_host": active,
        "test_host": configured_test,
        "production_host": production,
        "local_ipv4s": ipv4s,
    }


def detect_gateway_host(cfg: dict[str, Any]) -> str:
    explicit_env = str(os.environ.get("GIDEON_GATEWAY_PUBLIC_HOST", "")).strip()
    if _valid_explicit_host(explicit_env):
        return explicit_env.strip("[]")
    return str(gateway_network_snapshot(cfg)["active_host"])


def _write_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def ensure_gateway_tls(host: str, *, force: bool = False, rotate_ca: bool = False) -> dict[str, str]:
    """Ensure TLS material while keeping the root CA stable.

    ``force=True`` means *renew/reissue only the server leaf certificate*.  It no
    longer rotates the trust anchor.  Root CA rotation is deliberately explicit
    through ``rotate_ca=True`` because changing the CA invalidates trust in
    already-deployed agents.
    """
    material = GatewayTLSLifecycle(TLS_DIR).ensure(
        host,
        force_leaf=bool(force),
        rotate_ca=bool(rotate_ca),
        local_addresses=local_addresses(),
    )
    return {
        "ca_file": material.ca_file,
        "cert_file": material.cert_file,
        "key_file": material.key_file,
        "trust_bundle_file": material.trust_bundle_file,
        "ca_fingerprint": material.ca_fingerprint,
        "cert_fingerprint": material.cert_fingerprint,
        "ca_created": material.ca_created,
        "cert_reissued": material.cert_reissued,
    }


def ensure_gateway_configuration(*, force_tls: bool = False) -> dict[str, Any]:
    migrate_legacy_gateway_state()
    main_cfg = _load(CONFIG_PATH)
    agent_cfg = main_cfg.setdefault("agent_control_plane", {})
    gw_cfg = _load(GATEWAY_CONFIG_PATH)
    previous_compat_host = str(gw_cfg.get("public_host") or "").strip().strip("[]")
    network = gateway_network_snapshot(gw_cfg)
    host = str(network["active_host"])
    port = int(gw_cfg.get("listen_port") or 8443)
    # Migration safety: if an older release stored fe80:: or another host that
    # no longer matches the active endpoint, the existing TLS cert must not be reused.
    force_tls = bool(force_tls or (previous_compat_host and previous_compat_host != host))
    current_url = str(gw_cfg.get("advertised_endpoint") or gw_cfg.get("public_url") or "").strip().rstrip("/")
    expected_url = make_gateway_url(host, port)

    # Regenerate the endpoint URL whenever the active network mode/host changed.
    public_url = expected_url if current_url != expected_url else current_url
    admin_key = str(gw_cfg.get("admin_api_key") or "").strip() or secrets.token_urlsafe(48)
    enrollment_secret = str(gw_cfg.get("enrollment_secret") or "").strip() or secrets.token_urlsafe(48)
    tls = ensure_gateway_tls(host, force=force_tls)
    client_ca_file = str(gw_cfg.get("client_ca_file") or "").strip()
    client_ca_key_file = str(gw_cfg.get("client_ca_key_file") or "").strip()
    if client_ca_file and not client_ca_key_file:
        client_ca_key_file = str(Path(client_ca_file).with_suffix(".key"))

    gw_cfg.update(
        {
            # Portable state root.  v6.0.18 could omit this field on a clean
            # configuration, which made gideon_agent_gateway.py raise KeyError.
            # Keep it relative in JSON and resolve it against the application
            # root inside the Gateway, never against the process CWD.
            # Legacy v6.0.19 contract used: "data_dir": str(gw_cfg.get("data_dir") or "./gateway-data")
            # Persistent state supersedes that version-local fallback.
            "data_dir": str(GATEWAY_DATA_DIR),
            "listen_host": "0.0.0.0",
            "listen_address": "0.0.0.0",
            "listen_port": port,
            "network_mode": network["mode"],
            "test_host": network["test_host"],
            "production_host": network["production_host"],
            # Compatibility fields consumed by existing agents/UI.
            "public_host": host,
            "public_url": public_url,
            # Phase 2 explicit endpoint roles. public_url remains for backwards
            # compatibility, but Agents/Builders should consume advertised_endpoint.
            "advertised_endpoint": public_url,
            "internal_endpoint": f"https://127.0.0.1:{port}",
            "tls_certfile": tls["cert_file"],
            "tls_keyfile": tls["key_file"],
            "ca_file": tls["ca_file"],
            "client_ca_file": client_ca_file or None,
            "client_ca_key_file": client_ca_key_file or None,
            "tls_trust_bundle_file": tls.get("trust_bundle_file", ""),
            "tls_ca_fingerprint": tls.get("ca_fingerprint", ""),
            "tls_cert_fingerprint": tls.get("cert_fingerprint", ""),
            "tls_root_rotated": bool(tls.get("ca_created", False)),
            "tls_leaf_reissued": bool(tls.get("cert_reissued", False)),
            "admin_api_key": admin_key,
            "enrollment_secret": enrollment_secret,
            "admin_api_key_env": str(gw_cfg.get("admin_api_key_env") or "GIDEON_AGENT_ADMIN_TOKEN"),
            "enrollment_secret_env": str(gw_cfg.get("enrollment_secret_env") or "GIDEON_AGENT_ENROLL_SECRET"),
            "require_agent_mtls": bool(gw_cfg.get("require_agent_mtls", False)),
            "installer_enrollment_ttl_seconds": int(gw_cfg.get("installer_enrollment_ttl_seconds") or 7 * 86400),
            "installer_enrollment_max_uses": int(gw_cfg.get("installer_enrollment_max_uses") or 64),
            "hot_reload_enabled": True,
        }
    )
    _save(GATEWAY_CONFIG_PATH, gw_cfg)

    agent_cfg.update(
        {
            "enabled": True,
            "base_url": public_url,
            "require_https": True,
            "verify_tls": True,
            "ca_file": tls["ca_file"],
            "tls_trust_bundle_file": tls.get("trust_bundle_file", ""),
            "tls_ca_fingerprint": tls.get("ca_fingerprint", ""),
            "tls_cert_fingerprint": tls.get("cert_fingerprint", ""),
            "tls_root_rotated": bool(tls.get("ca_created", False)),
            "tls_leaf_reissued": bool(tls.get("cert_reissued", False)),
            # Security boundary: the generated admin secret lives only in the
            # persistent Gateway runtime config (or its environment variable).
            # Never copy it into the versioned/releasable config.json.
            "admin_api_key": "",
        }
    )
    _save(CONFIG_PATH, main_cfg)
    return {
        "public_url": public_url,
        "advertised_endpoint": public_url,
        "internal_endpoint": f"https://127.0.0.1:{port}",
        "listen_address": "0.0.0.0",
        "ca_file": tls["ca_file"],
        "trust_bundle_file": tls.get("trust_bundle_file", ""),
        "ca_fingerprint": tls.get("ca_fingerprint", ""),
        "cert_fingerprint": tls.get("cert_fingerprint", ""),
        "ca_created": bool(tls.get("ca_created", False)),
        "cert_reissued": bool(tls.get("cert_reissued", False)),
        "cert_file": tls["cert_file"],
        "key_file": tls["key_file"],
        "host": host,
        "port": port,
        "network_mode": network["mode"],
        "test_host": network["test_host"],
        "production_host": network["production_host"],
        "local_ipv4s": network["local_ipv4s"],
    }


def gateway_status() -> dict[str, Any]:
    gw = _load(GATEWAY_CONFIG_PATH)
    main = _load(CONFIG_PATH)
    network = gateway_network_snapshot(gw, include_local_ipv4s=False)
    return {
        "public_url": str(gw.get("advertised_endpoint") or gw.get("public_url") or main.get("agent_control_plane", {}).get("base_url") or ""),
        "advertised_endpoint": str(gw.get("advertised_endpoint") or gw.get("public_url") or main.get("agent_control_plane", {}).get("base_url") or ""),
        "internal_endpoint": str(gw.get("internal_endpoint") or (f"https://127.0.0.1:{int(gw.get('listen_port') or 8443)}")),
        "listen_address": str(gw.get("listen_address") or gw.get("listen_host") or "0.0.0.0"),
        "host": str(gw.get("public_host") or network["active_host"] or ""),
        "port": int(gw.get("listen_port") or 8443),
        "tls": bool(gw.get("tls_certfile") and gw.get("tls_keyfile")),
        "ca_file": str(gw.get("ca_file") or main.get("agent_control_plane", {}).get("ca_file") or ""),
        "tls_ca_fingerprint": str(gw.get("tls_ca_fingerprint") or main.get("agent_control_plane", {}).get("tls_ca_fingerprint") or ""),
        "tls_cert_fingerprint": str(gw.get("tls_cert_fingerprint") or ""),
        "network_mode": network["mode"],
        "test_host": network["test_host"],
        "production_host": network["production_host"],
        "local_ipv4s": network["local_ipv4s"],
        "hot_reload_enabled": bool(gw.get("hot_reload_enabled", True)),
    }
