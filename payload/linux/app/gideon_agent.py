#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GIDEON Cross-Platform Agent v2.4.56.

Compatible con Windows, Linux, Raspberry Pi y macOS. El modo Agentless
SSH/SFTP no depende de este componente.
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import json
import logging
import hashlib
import os
import random
from pathlib import Path
import platform
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import traceback
import uuid
import zipfile
from typing import Any, Optional
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from gideon_agent_http import AgentHttpClient, AgentHttpError
from gideon_agent_config import CentralConfigError, CentralConfigStore, merge_effective_config, validate_document
from gideon_agent_connectivity import (
    EndpointPool,
    capture_network_snapshot,
    resolve_endpoint_dns,
    snapshot_changes,
)
from gideon_agent_security import sha256_file, verify_file
from gideon_agent_display_capability import detect_display_capability
from gideon_agent_rdp_capability import detect_rdp_capability
from gideon_agent_session_handoff import run_session_switch_helper
from gideon_agent_vnc_bridge import LocalWaylandConsoleBridge
from gideon_agent_job_contract import validate_job_envelope
from gideon_agent_bootstrap import (
    AgentPaths,
    AgentTimingPolicy,
    PRIVATE_FILE_MODE,
    PUBLIC_STATUS_MODE,
    atomic_json,
    enforce_path_mode,
)
from gideon_host_profiles import HostProfileStore, normalize_arch, normalize_platform, normalize_profile_runtime
from gideon_common.redaction import redact, redact_error
import gideon_reverse_tunnel as _gideon_reverse_tunnel

# GIDEON Player is optional by design.  Its source can be absent from an older
# payload or fail to import on an endpoint with a damaged optional dependency;
# neither condition may stop the core Agent service that owns mTLS, jobs,
# remote support and the reverse tunnel.  The small no-op bridge below keeps
# the capability/reporting contract stable until a signed runtime update fixes
# the Player component.
_PLAYER_RUNTIME_IMPORT_ERROR = ""
try:
    from gideon_agent_player import PlayerAgentBridge as _PlayerAgentBridge
except Exception as exc:  # pragma: no cover - exercised through _new_player_bridge
    _PlayerAgentBridge = None
    _PLAYER_RUNTIME_IMPORT_ERROR = type(exc).__name__

# The verified offline VLC installer is deliberately optional for the same
# reason as the Player: an incomplete third-party kit must never stop core
# Agent services.  The controller refuses autonomous installation; it only
# reacts to a short-lived, GIDEON-signed request that an administrator explicitly
# acknowledged in the console.
_OFFLINE_VLC_RUNTIME_IMPORT_ERROR = ""
try:
    from gideon_agent_vlc_offline_control import OfflineVlcInstallController as _OfflineVlcInstallController
except Exception as exc:  # pragma: no cover - platform/legacy payload guard
    _OfflineVlcInstallController = None
    _OFFLINE_VLC_RUNTIME_IMPORT_ERROR = type(exc).__name__


class _DisabledPlayerBridge:
    """Fail-closed optional Player replacement; it never touches core state."""

    def __init__(self, reason: str = "PLAYER_RUNTIME_UNAVAILABLE") -> None:
        self.reason = reason

    def capability(self, display: dict[str, Any] | None = None) -> dict[str, Any]:
        display_info = dict(display or {})
        return {
            "Supported": False,
            "ManifestSchema": "gideon-media-player-manifest/v1",
            "RuntimeVersion": "",
            "ExecutionModel": "disabled",
            "ExternalVlcOnly": True,
            "NetworkDownloads": False,
            "MediaCache": "phase2-logical-cache",
            "VLC": {"Installed": False, "Version": "", "Provenance": "runtime-unavailable", "License": "GPL-2.0-or-later"},
            "Graphics": {
                "Session": dict(display_info.get("Session") or {}),
                "OutputCount": len(display_info.get("Outputs") or []),
            },
            "State": "RUNTIME_UNAVAILABLE",
            "Reason": self.reason,
        }

    def status_for_report(self) -> dict[str, Any]:
        return {
            "Schema": "gideon-agent-player-status/v1",
            "RuntimeVersion": "",
            "State": "RUNTIME_UNAVAILABLE",
            "ManifestVersion": 0,
            "ManifestSha256": "",
            "VLC": {"Installed": False, "Version": "", "Provenance": "runtime-unavailable", "License": "GPL-2.0-or-later"},
            "FreeBytes": 0,
            "Screens": [],
            "LastSyncState": "RUNTIME_UNAVAILABLE",
            "LastSyncError": self.reason,
        }

    def sync_from_gateway(self, _client: Any, **_kwargs: Any) -> dict[str, Any]:
        return {"State": "RUNTIME_UNAVAILABLE"}

    def report_to_gateway(self, _client: Any, **_kwargs: Any) -> dict[str, Any]:
        return {"State": "RUNTIME_UNAVAILABLE"}


def _new_player_bridge(*, agent_root: Path, agent_id: str, public_key_path: Path | None) -> Any:
    """Instantiate optional Player without allowing it to block core startup."""
    if _PlayerAgentBridge is None:
        return _DisabledPlayerBridge("PLAYER_RUNTIME_IMPORT_FAILED")
    try:
        return _PlayerAgentBridge(
            agent_root=agent_root,
            agent_id=agent_id,
            public_key_path=public_key_path,
        )
    except Exception:
        # Do not surface raw filesystem/module data through Agent telemetry.
        return _DisabledPlayerBridge("PLAYER_RUNTIME_INITIALIZATION_FAILED")


class _DisabledOfflineVlcController:
    """Compatibility placeholder for older or damaged optional payloads."""

    def __init__(self, reason: str = "VLC_OFFLINE_RUNTIME_UNAVAILABLE") -> None:
        self.reason = reason

    def capability(self) -> dict[str, Any]:
        return {
            "Bundled": False,
            "State": "RUNTIME_UNAVAILABLE",
            "Reason": self.reason,
            "NetworkDownloads": False,
            "InstallRequiresSignedApproval": True,
            "License": "GPL-2.0-or-later",
        }

    def synchronize(self, _request: Any, *, busy_reason: str = "") -> dict[str, Any] | None:
        del busy_reason
        return None


def _new_offline_vlc_controller(
    *, agent_root: Path, state_root: Path, agent_id: str, public_key_path: Path | None
) -> Any:
    if _OfflineVlcInstallController is None:
        return _DisabledOfflineVlcController(
            "VLC_OFFLINE_RUNTIME_IMPORT_FAILED" if _OFFLINE_VLC_RUNTIME_IMPORT_ERROR else "VLC_OFFLINE_RUNTIME_UNAVAILABLE"
        )
    try:
        return _OfflineVlcInstallController(
            agent_root=agent_root, state_root=state_root, agent_id=agent_id, public_key_path=public_key_path,
        )
    except Exception:
        return _DisabledOfflineVlcController("VLC_OFFLINE_RUNTIME_INITIALIZATION_FAILED")

AgentReverseTunnelClient = _gideon_reverse_tunnel.AgentReverseTunnelClient
REVERSE_TUNNEL_VERSION = str(getattr(_gideon_reverse_tunnel, "TUNNEL_VERSION", "0"))
REVERSE_TUNNEL_API_VERSION = int(getattr(_gideon_reverse_tunnel, "TUNNEL_API_VERSION", 0) or 0)
REVERSE_TUNNEL_API_REQUIRED = 2

if REVERSE_TUNNEL_API_VERSION != REVERSE_TUNNEL_API_REQUIRED:
    raise RuntimeError(
        "REVERSE_TUNNEL_API_MISMATCH: "
        f"gideon_agent requires API {REVERSE_TUNNEL_API_REQUIRED}, "
        f"but gideon_reverse_tunnel provides API {REVERSE_TUNNEL_API_VERSION}. "
        "gideon_agent.py and gideon_reverse_tunnel.py must be updated as one runtime bundle."
    )

VERSION = "2.4.56"
PROTOCOL_VERSION = "2.0"
# Core Agent self-updates must remain small enough for constrained endpoints.
# Large reviewed components (for example the offline VLC kit and GPL source)
# are preserved locally and delivered only through their explicit signed flow.
MAX_SELF_UPDATE_BUNDLE_BYTES = 256 * 1024 * 1024

_LOG = logging.getLogger(__name__)


def now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def operating_system_identity(os_release_path: Path = Path("/etc/os-release")) -> dict[str, str]:
    """Return a small, non-secret OS selector for capability negotiation."""
    family = normalize_platform()
    result = {"Family": family, "Distribution": "", "Codename": "", "VersionId": ""}
    if family != "linux":
        return result
    values: dict[str, str] = {}
    try:
        for raw in Path(os_release_path).read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" not in raw or raw.lstrip().startswith("#"):
                continue
            key, value = raw.split("=", 1)
            key = key.strip().upper()
            if key not in {"ID", "VERSION_CODENAME", "VERSION_ID"}:
                continue
            values[key] = value.strip().strip('"').strip("'")[:80]
    except OSError:
        return result
    result.update({
        "Distribution": values.get("ID", "").casefold(),
        "Codename": values.get("VERSION_CODENAME", "").casefold(),
        "VersionId": values.get("VERSION_ID", ""),
    })
    return result


def _certificate_expiry_utc(cert: x509.Certificate) -> dt.datetime:
    """Return certificate expiry on old and new cryptography releases."""
    value = getattr(cert, "not_valid_after_utc", None)
    if value is None:
        value = cert.not_valid_after
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc)


def _atomic_bytes(path: Path, payload: bytes, *, mode: int = PRIVATE_FILE_MODE) -> None:
    """Persist a private PKI file atomically on every supported Agent OS."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}.{time.time_ns()}")
    try:
        tmp.write_bytes(payload)
        enforce_path_mode(tmp, mode)
        os.replace(tmp, path)
        enforce_path_mode(path, mode)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def legacy_agent_id(site_code: str, hostname: str) -> str:
    """Stable identity used only when upgrading an already-enrolled v2.0 Agent."""
    seed = f"{str(site_code).strip().lower()}|{str(hostname).strip().lower()}"
    return "agt-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:24]


def default_data_dir() -> Path:
    system = normalize_platform()
    if system == "windows":
        return Path(os.path.expandvars(r"%PROGRAMDATA%\GIDEONAgent"))
    if system == "darwin":
        return Path("/Library/Application Support/GIDEONAgent")
    return Path("/var/lib/gideon-agent")


def safe_extract(zip_path: Path, target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    root = target.resolve()
    with zipfile.ZipFile(zip_path, "r") as z:
        for info in z.infolist():
            dest = (target / info.filename).resolve()
            if root not in dest.parents and dest != root:
                raise RuntimeError(f"Unsafe zip entry: {info.filename}")
        z.extractall(target)


def process_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        if os.name == "nt":
            cp = subprocess.run(
                ["tasklist.exe", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                timeout=4,
                creationflags=0x08000000,
            )
            return str(pid) in cp.stdout
        # ``kill(pid, 0)`` also succeeds for a terminated child that has not
        # been reaped yet (a zombie).  Treating that PID as alive leaves
        # execute_job() in its status/cancel loop forever and blocks the next
        # file-transfer job.  Read the kernel process state first when procfs
        # is available; state ``Z`` is terminal and must not keep the Agent
        # marked BUSY.
        stat_path = Path(f"/proc/{pid}/stat")
        if stat_path.is_file():
            raw = stat_path.read_text(encoding="utf-8", errors="replace")
            closing = raw.rfind(")")
            fields = raw[closing + 2 :].split() if closing >= 0 else []
            if fields and fields[0] == "Z":
                return False
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def reap_process(pid: int) -> None:
    """Reap a finished POSIX worker when it is our child.

    A resumed job may refer to a PID owned by a previous Agent process, so
    ``ChildProcessError`` is expected and deliberately ignored.
    """
    if pid <= 0 or os.name == "nt":
        return
    try:
        os.waitpid(pid, os.WNOHANG)
    except (ChildProcessError, ProcessLookupError, OSError):
        pass


def kill_tree(pid: int) -> None:
    if pid <= 0:
        return
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill.exe", "/PID", str(pid), "/T", "/F"],
                capture_output=True,
                timeout=10,
                creationflags=0x08000000,
            )
        else:
            try:
                os.killpg(os.getpgid(pid), signal.SIGTERM)
                time.sleep(1)
                if process_alive(pid):
                    os.killpg(os.getpgid(pid), signal.SIGKILL)
            except Exception:
                os.kill(pid, signal.SIGTERM)
    except Exception as exc:
        _LOG.warning("No se pudo terminar el árbol de procesos PID %s: %s", pid, exc)


class Agent:
    def __init__(self, cfg_path: Path) -> None:
        self.cfg_path = Path(cfg_path).resolve()
        self.cfg = json.loads(self.cfg_path.read_text(encoding="utf-8-sig"))
        # agent.json may still contain a legacy bearer token or one-time
        # enrollment grant. Repair permissions even when no metadata rewrite is
        # needed during this startup.
        enforce_path_mode(self.cfg_path, PRIVATE_FILE_MODE)
        # A software upgrade must never leave stale package metadata in agent.json.
        # Identity, token, site and Gateway settings are preserved; only version/schema
        # metadata owned by the runtime is synchronized. This works for every OS and
        # every installer path because all of them eventually instantiate Agent.
        config_changed = False
        for key, value in (("agent_version", VERSION), ("agent_protocol", PROTOCOL_VERSION), ("schema_version", 2)):
            if self.cfg.get(key) != value:
                self.cfg[key] = value
                config_changed = True
        if config_changed:
            try:
                atomic_json(self.cfg_path, self.cfg)
            except Exception as exc:
                _LOG.warning("No se pudo sincronizar metadata de versión en %s: %s", self.cfg_path, exc)
        # P6: agent.json remains the immutable local/bootstrap baseline. Central
        # configuration is overlaid from the Agent data directory and never owns
        # identity, bearer tokens or PKI trust material.
        self.base_cfg = copy.deepcopy(self.cfg)
        self.site_code = str(self.cfg.get("site_code") or "").strip()
        self.site_name = str(self.cfg.get("site_name") or "").strip()
        self.agent_name = str(self.cfg.get("agent_name") or "").strip() or socket.gethostname()
        self.host_profile_id = str(self.cfg.get("host_profile") or "").strip()
        if not self.site_code:
            raise RuntimeError("agent config requires site_code")

        configured_data = str(self.cfg.get("data_dir") or "").strip()
        configured_root = Path(os.path.expandvars(configured_data)) if configured_data else default_data_dir()
        self.paths = AgentPaths.from_root(configured_root)
        self.paths.ensure()
        # Compatibility aliases remain while filesystem ownership moves to AgentPaths.
        self.root = self.paths.root
        self.jobs_dir = self.paths.jobs
        self.packages_dir = self.paths.packages
        self.security_dir = self.paths.security
        self.replay_path = self.paths.replay
        self.runtime_cfg_path = self.paths.runtime_config
        self.status_path = self.paths.status
        self.log_path = self.paths.log
        self.active_job_id = ""
        self.suppress_local_status = False
        self.config_store = CentralConfigStore(self.root)
        recovered = self.config_store.recover_interrupted()
        if recovered:
            _LOG.warning("Configuración central recuperada tras transacción interrumpida: %s", recovered)
        self.central_document = self.config_store.load_current()
        self.config_version = int(self.central_document.get("version") or 0) if self.central_document else 0
        self.cfg = merge_effective_config(self.base_cfg, self.central_document)
        self.agent_id = self._load_or_create_agent_id()

        self.profile = self._load_profile()
        self._validate_profile()

        cp = dict(self.cfg.get("control_plane", {}) or {})
        # P3: the endpoint pool owns route selection.  Agent identity remains in
        # agent.runtime.json and is never derived from IP/interface/network state.
        self.connectivity = EndpointPool(cp, self._runtime_config())
        self.base_url = self.connectivity.current_url
        self.require_https = bool(cp.get("require_https", True))
        self.verify_tls = bool(cp.get("verify_tls", True))
        self.ca_file = self._resolve_optional(cp.get("ca_file"))
        self.ca_sha256 = str(cp.get("ca_sha256") or "").strip().lower()
        if self.ca_sha256:
            if not self.ca_file or not Path(self.ca_file).is_file():
                raise RuntimeError(f"TLS_CA_MISSING: no existe la CA incluida por el instalador: {self.ca_file or '-'}")
            actual_ca_sha256 = sha256_file(Path(self.ca_file)).lower()
            if actual_ca_sha256 != self.ca_sha256:
                raise RuntimeError(
                    "TLS_CA_INTEGRITY: la CA local no coincide con la huella incluida en el instalador "
                    f"(esperada={self.ca_sha256[:16]}…, actual={actual_ca_sha256[:16]}…)."
                )
        runtime_mtls = self._runtime_config()
        self.client_cert = self._resolve_optional(runtime_mtls.get("mtls_client_cert") or cp.get("client_cert"))
        self.client_key = self._resolve_optional(runtime_mtls.get("mtls_client_key") or cp.get("client_key"))
        self.minimum_tls = str(cp.get("minimum_tls") or "TLSv1.2")
        self.timeout = float(cp.get("timeout_seconds", 20))
        self.timing = AgentTimingPolicy.from_config(self.cfg, self.base_cfg)
        self.network_check_seconds = self.timing.network_check_seconds
        self.poll_seconds = self.timing.poll_seconds
        self.status_seconds = self.timing.status_seconds
        self.cancel_grace_seconds = self.timing.cancel_grace_seconds

        security = self.cfg.get("security", {})
        self.mtls_required = bool(security.get("mtls_required", False))
        if self.mtls_required:
            if not self.client_cert or not self.client_key:
                raise RuntimeError("MTLS_REQUIRED: client_cert/client_key must be configured")
            if not Path(self.client_cert).exists() or not Path(self.client_key).exists():
                raise RuntimeError("MTLS_REQUIRED: client.crt/client.key not found")
        self.signature_required = bool(security.get("package_signature_required", True))
        self.job_freshness_required = bool(security.get("job_freshness_required", False))
        self.signing_public_key = self._resolve_optional(security.get("trusted_signing_public_key"))
        # The Player bridge is deliberately credential-free.  It can verify a
        # signed campaign and read Phase-2's local media cache, but it cannot
        # touch reverse tunnels, the Job queue, or the Agent mTLS identity.
        self.player_bridge = _new_player_bridge(
            agent_root=self.root,
            agent_id=self.agent_id,
            public_key_path=Path(self.signing_public_key) if self.signing_public_key else None,
        )
        # The catalog is installed beside the immutable Agent runtime, whereas
        # audit and short-lived approval material live under the protected data
        # root.  Keeping those locations distinct prevents an update/cache
        # cleanup from being mistaken for an authorization channel.
        self.offline_vlc = _new_offline_vlc_controller(
            agent_root=Path(__file__).resolve().parent,
            state_root=self.root,
            agent_id=self.agent_id,
            public_key_path=Path(self.signing_public_key) if self.signing_public_key else None,
        )
        # An offline package install is a short endpoint-maintenance window.
        # Keep this independent from the controller subprocess so the Agent can
        # atomically stop new reverse-tunnel streams and avoid claiming Jobs or
        # starting Player work while VLC files are being replaced.
        self._offline_vlc_maintenance = False
        self._offline_vlc_tunnel_quiesced = False
        self.update_cfg = self.cfg.get("update", {}) or {}
        self.update_channel = str(self.update_cfg.get("channel") or "stable")
        self.next_version_check = 0.0
        self.version_state: dict[str, Any] = {}
        self.update_install_started = False
        self._force_update_once = False
        self._next_mtls_attempt = 0.0
        self.config_check_seconds = self.timing.config_check_seconds
        self.next_config_check = 0.0

        self.token = self._load_token()
        self.client = self._client(self.token)
        self.reverse_tunnel: AgentReverseTunnelClient | None = None
        self.local_wayland_console_bridge = LocalWaylandConsoleBridge(agent_id=self.agent_id)
        self._reverse_tunnel_signature = ""
        self._network_snapshot = capture_network_snapshot()
        self._next_network_check = 0.0
        self._last_dns_resolution: dict[str, Any] = {}
        self._rdp_capability_cache: tuple[float, tuple[str, int, bool], dict[str, Any]] | None = None
        # Physical display discovery can involve platform APIs.  Cache it across
        # normal heartbeats so telemetry never becomes a graphical polling loop.
        self._display_capability_cache: tuple[float, dict[str, Any]] | None = None
        self._persist_runtime(
            current_gateway_endpoint=self.base_url,
            last_known_good_endpoint=self.connectivity.last_good_url,
            connectivity_mode=self.connectivity.mode,
            config_version=self.config_version,
            config_state=str(self.config_store.status().get("state") or ("APPLIED" if self.config_version else "BASELINE")),
        )

    def _read_runtime_status(self) -> dict[str, Any]:
        try:
            if self.status_path.exists():
                value = json.loads(self.status_path.read_text(encoding="utf-8-sig"))
                return value if isinstance(value, dict) else {}
        except Exception as exc:
            self._log_event(f"STATUS_READ_WARNING: {type(exc).__name__}: {exc}", "WARN")
        return {}

    def _status_update(self, **updates: Any) -> None:
        value = self._read_runtime_status()
        value.update({
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "site_code": self.site_code,
            "site_name": self.site_name,
            "hostname": socket.gethostname(),
            "agent_version": VERSION,
            "protocol_version": PROTOCOL_VERSION,
            "process_pid": os.getpid(),
            "gateway_url": self.base_url if hasattr(self, "base_url") else "",
            "gateway_candidates": self.connectivity.endpoint_dicts() if hasattr(self, "connectivity") else [],
            "last_known_good_endpoint": self.connectivity.last_good_url if hasattr(self, "connectivity") else "",
            "connectivity_mode": self.connectivity.mode if hasattr(self, "connectivity") else "",
            "config_version": int(getattr(self, "config_version", 0) or 0),
            "config_state": str((self.config_store.status().get("state") if hasattr(self, "config_store") else "") or ("APPLIED" if getattr(self, "config_version", 0) else "BASELINE")),
            "updated_at": now_iso(),
        })
        value.update(updates)
        # This status document is intentionally credential-free and must remain
        # readable by a tray process running outside the service account.
        atomic_json(self.status_path, value, mode=PUBLIC_STATUS_MODE)

    def _log_event(self, message: str, level: str = "INFO") -> None:
        # P7: operational logs are useful for copy/download diagnostics, but no
        # reusable credential may ever be persisted in clear text.
        safe_message = redact_error(message)
        try:
            if self.log_path.exists() and self.log_path.stat().st_size > 2 * 1024 * 1024:
                previous = self.log_path.with_suffix(".log.1")
                previous.unlink(missing_ok=True)
                os.replace(self.log_path, previous)
            with self.log_path.open("a", encoding="utf-8") as fh:
                fh.write(f"[{now_iso()}] {level.upper()} {safe_message}\n")
        except Exception as exc:
            _LOG.warning("No se pudo escribir agent.log: %s", redact_error(exc))

    def _diagnostic_snapshot(self) -> dict[str, Any]:
        """Build a bounded, secret-free connectivity snapshot for Gateway/WebAdmin."""
        status = self._read_runtime_status()
        network = self._network_snapshot.as_dict() if hasattr(self, "_network_snapshot") else {}
        if not self._last_dns_resolution:
            try:
                self._last_dns_resolution = resolve_endpoint_dns(self.connectivity.endpoints)
            except Exception as exc:
                self._last_dns_resolution = {
                    self.base_url: {"ok": False, "error": redact_error(exc), "addresses": [], "elapsed_ms": 0}
                }
        current_dns = dict((self._last_dns_resolution or {}).get(self.base_url) or {})
        connected = bool(status.get("gateway_connected"))
        state = str(status.get("connectivity_state") or status.get("status") or "CONNECTING").upper()

        def check(name: str) -> dict[str, Any]:
            if connected:
                return {"status": "OK", "detail": "Validado por la última conexión HTTPS autenticada."}
            if state == name:
                return {"status": "ERROR", "detail": redact_error(status.get("last_gateway_error") or status.get("last_error") or name)}
            return {"status": "UNKNOWN", "detail": "Sin prueba concluyente en este instante."}

        dns_check = {
            "status": "OK" if current_dns.get("ok") else ("ERROR" if current_dns.get("error") else "UNKNOWN"),
            "detail": redact_error(current_dns.get("error") or (", ".join(current_dns.get("addresses") or []) if current_dns else "Sin resolución registrada")),
            "elapsed_ms": current_dns.get("elapsed_ms"),
        }
        snapshot = {
            "schema": 1,
            "captured_at": now_iso(),
            "agent": {
                "agent_id": self.agent_id, "site_code": self.site_code, "site_name": self.site_name,
                "agent_name": self.agent_name, "hostname": socket.gethostname(),
                "platform": normalize_platform(), "architecture": normalize_arch(),
                "agent_version": VERSION, "protocol_version": PROTOCOL_VERSION,
                "host_profile": str(self.profile.get("id") or ""),
            },
            "state": {
                "status": str(status.get("status") or state),
                "connectivity_state": state,
                "gateway_connected": connected,
                "active_job_id": str(self.active_job_id or ""),
                "active_remote_streams": self._active_remote_stream_count(),
            },
            "network": {
                "interfaces": list(network.get("interfaces") or []),
                "local_ips": list(network.get("local_ips") or []),
                "source_ip": str(network.get("source_ip") or ""),
                "default_gateway": str(network.get("default_gateway") or ""),
                "dns_servers": list(network.get("dns_servers") or []),
                "gateway_observed_ip": str(status.get("gateway_observed_ip") or ""),
            },
            "gateway": {
                "configured_endpoint": str(self.base_url or ""),
                "current_endpoint": str(self.base_url or ""),
                "last_known_good_endpoint": str(self.connectivity.last_good_url or ""),
                "connectivity_mode": str(self.connectivity.mode or ""),
                "candidates": self.connectivity.runtime_health(),
                # The most recently completed heartbeat latency is reported on the
                # next heartbeat. This avoids adding a second probe just for UI.
                "latency_ms": status.get("gateway_latency_ms"),
            },
            "checks": {
                "dns": dns_check,
                "tcp": check("GATEWAY_UNREACHABLE"),
                "tls": check("TLS_ERROR"),
                "api": check("GATEWAY_UNREACHABLE"),
                "authentication": check("AUTH_ERROR"),
            },
            "configuration": {
                "local_version": int(getattr(self, "config_version", 0) or 0),
                "state": str(status.get("config_state") or "BASELINE"),
                "last_error": redact_error(status.get("last_config_error") or status.get("config_sync_error") or ""),
            },
            "security": {
                "mtls_ready": bool(status.get("mtls_ready") or (
                    self.client_cert and self.client_key and Path(self.client_cert).is_file() and Path(self.client_key).is_file()
                )),
                "mtls_fingerprint_sha256": str(status.get("mtls_fingerprint") or ""),
                "mtls_expires_at": str(status.get("mtls_expires_at") or ""),
            },
            "update": {
                "state": str(status.get("update_state") or self.version_state.get("Status") or "CURRENT"),
                "target_version": str(status.get("update_target_version") or status.get("available_update") or ""),
                "channel": str(status.get("update_channel") or self.update_channel or ""),
                "last_error": redact_error(status.get("update_error") or self.version_state.get("Error") or ""),
                "request_id": str(status.get("update_request_id") or ""),
                "requested_at": str(status.get("update_requested_at") or ""),
                "checked_at": str(status.get("update_checked_at") or ""),
                "started_at": str(status.get("update_started_at") or ""),
                "updated_at": str(status.get("update_updated_at") or ""),
                "completed_at": str(status.get("update_completed_at") or ""),
            },
            "timestamps": {
                "last_heartbeat": str(status.get("last_heartbeat") or ""),
                "last_network_change": str(status.get("last_network_change") or ""),
                "last_dns_refresh": str(status.get("last_dns_refresh") or ""),
                "last_gateway_attempt": str(status.get("last_gateway_attempt") or ""),
                "last_gateway_success": str(self._runtime_config().get("last_gateway_success_at") or ""),
            },
            "error_record": {
                "timestamp": str(status.get("last_error_at") or ""),
                "component": str(status.get("last_error_component") or "GIDEONAgent"),
                "operation": str(status.get("last_error_operation") or ""),
                "error": redact_error(status.get("last_error") or status.get("last_gateway_error") or ""),
                "traceback": redact_error(status.get("last_error_traceback") or "", max_chars=12000),
                "agent_id": self.agent_id,
                "gateway": str(self.base_url or ""),
                "version": VERSION,
            },
            "last_error": redact_error(status.get("last_error") or status.get("last_gateway_error") or ""),
        }
        return redact(snapshot)

    def _resolve_optional(self, value: Any) -> Optional[str]:
        if not value:
            return None
        p = Path(os.path.expandvars(str(value)))
        if not p.is_absolute():
            p = self.cfg_path.parent / p
        return str(p)

    def _load_profile(self) -> dict[str, Any]:
        local = self.cfg_path.parent / "host_profile.json"
        if local.exists():
            value = json.loads(local.read_text(encoding="utf-8-sig"))
            if isinstance(value, dict):
                value.setdefault("id", self.host_profile_id)
                return normalize_profile_runtime(value)
        app_profiles = Path(__file__).resolve().parent / "config" / "host_profiles.json"
        if app_profiles.exists() and self.host_profile_id:
            return HostProfileStore(app_profiles).get(self.host_profile_id)
        return {
            "id": self.host_profile_id or "auto",
            "platform": normalize_platform(),
            "architectures": [normalize_arch()],
            "allowed_extensions": [".ps1", ".py"] if os.name == "nt" else [".sh", ".py", ".ps1"],
            "preferred_executors": [],
        }

    def _validate_profile(self) -> None:
        expected = normalize_platform(str(self.profile.get("platform") or ""))
        current = normalize_platform()
        if expected and expected != current:
            raise RuntimeError(f"HOST_PROFILE_MISMATCH: profile={expected} runtime={current}")
        supported = [normalize_arch(str(x)) for x in self.profile.get("architectures", [])]
        current_arch = normalize_arch()
        if supported and current_arch not in supported:
            raise RuntimeError(f"HOST_ARCH_MISMATCH: profile={supported} runtime={current_arch}")

    def _client(self, token: str, base_url: str | None = None) -> AgentHttpClient:
        return AgentHttpClient(
            (base_url or self.base_url),
            bearer_token=token,
            timeout=self.timeout,
            verify_tls=self.verify_tls,
            ca_file=self.ca_file,
            require_https=self.require_https,
            client_cert=self.client_cert,
            client_key=self.client_key,
            minimum_tls=self.minimum_tls,
            user_agent=f"GIDEON-Agent/{VERSION} {normalize_platform()}/{normalize_arch()}",
        )

    def _effective_from_central(self, document: dict[str, Any] | None) -> dict[str, Any]:
        return merge_effective_config(self.base_cfg, document or {})

    def _client_for_effective(self, effective: dict[str, Any], base_url: str, token: str | None = None) -> AgentHttpClient:
        cp = dict(effective.get("control_plane", {}) or {})
        ca_file = self._resolve_optional(cp.get("ca_file"))
        runtime_mtls = self._runtime_config()
        client_cert = self._resolve_optional(runtime_mtls.get("mtls_client_cert") or cp.get("client_cert"))
        client_key = self._resolve_optional(runtime_mtls.get("mtls_client_key") or cp.get("client_key"))
        return AgentHttpClient(
            base_url,
            bearer_token=self.token if token is None else token,
            timeout=float(cp.get("timeout_seconds", 20)),
            verify_tls=bool(cp.get("verify_tls", True)),
            ca_file=ca_file,
            require_https=bool(cp.get("require_https", True)),
            client_cert=client_cert,
            client_key=client_key,
            minimum_tls=str(cp.get("minimum_tls") or "TLSv1.2"),
            user_agent=f"GIDEON-Agent/{VERSION} {normalize_platform()}/{normalize_arch()}",
        )

    def _probe_effective_configuration(self, effective: dict[str, Any], version: int) -> str:
        """Prove that at least one endpoint in a candidate can authenticate.

        The candidate is tested before commit and once again after it becomes the
        active runtime.  This is deliberately stronger than probing /health:
        bearer authentication against the Agent config endpoint proves that the
        same Gateway identity/database can actually serve this Agent.
        """
        cp = dict(effective.get("control_plane", {}) or {})
        pool = EndpointPool(cp, self._runtime_config())
        errors: list[str] = []
        for endpoint in pool.endpoints:
            try:
                client = self._client_for_effective(effective, endpoint.url)
                response = client.json("GET", f"/api/v1/agent/config?current={int(version)}", timeout=min(float(cp.get("timeout_seconds", 20)), 10.0))
                if str(response.get("Status") or "").upper() not in {"CURRENT", "UPDATE_AVAILABLE", "NO_CONFIGURATION"}:
                    raise AgentHttpError(f"Respuesta de configuración inesperada: {response}")
                return endpoint.url
            except Exception as exc:
                errors.append(f"{endpoint.url}: {type(exc).__name__}: {exc}")
        raise AgentHttpError("Ningún endpoint de la configuración candidata pudo autenticar al Agent. " + " | ".join(errors[-4:]))

    def _apply_central_document(self, document: dict[str, Any] | None, *, preferred_url: str = "", reason: str = "central-config") -> None:
        effective = self._effective_from_central(document)
        cp = dict(effective.get("control_plane", {}) or {})
        runtime = self._runtime_config()
        new_pool = EndpointPool(cp, runtime)
        candidate_urls = [x.url for x in new_pool.endpoints]
        preferred = str(preferred_url or "").strip().rstrip("/")
        if preferred and preferred in candidate_urls:
            new_pool.current_url = preferred
            new_pool.ensure_current_cycle_position()
        self.cfg = effective
        self.central_document = dict(document or {})
        self.config_version = int(self.central_document.get("version") or 0) if self.central_document else 0
        self.connectivity = new_pool
        self.base_url = preferred if preferred and preferred in candidate_urls else new_pool.current_url
        self.require_https = bool(cp.get("require_https", True))
        self.verify_tls = bool(cp.get("verify_tls", True))
        self.ca_file = self._resolve_optional(cp.get("ca_file"))
        self.ca_sha256 = str(cp.get("ca_sha256") or "").strip().lower()
        if self.ca_sha256:
            if not self.ca_file or not Path(self.ca_file).is_file():
                raise RuntimeError(f"TLS_CA_MISSING: no existe la CA local: {self.ca_file or '-'}")
            actual = sha256_file(Path(self.ca_file)).lower()
            if actual != self.ca_sha256:
                raise RuntimeError("TLS_CA_INTEGRITY: la CA local cambió; configuración central rechazada")
        runtime_mtls = self._runtime_config()
        self.client_cert = self._resolve_optional(runtime_mtls.get("mtls_client_cert") or cp.get("client_cert"))
        self.client_key = self._resolve_optional(runtime_mtls.get("mtls_client_key") or cp.get("client_key"))
        self.minimum_tls = str(cp.get("minimum_tls") or "TLSv1.2")
        self.timeout = float(cp.get("timeout_seconds", 20))
        self.network_check_seconds = max(2, int(cp.get("network_check_seconds", 3)))
        self.poll_seconds = max(2, int(effective.get("poll_seconds", 5)))
        self.status_seconds = max(2, int(effective.get("status_seconds", 5)))
        self.update_cfg = effective.get("update", {}) or {}
        self.update_channel = str(self.update_cfg.get("channel") or "stable")
        self.client = self._client(self.token, base_url=self.base_url)
        self._persist_runtime(
            current_gateway_endpoint=self.base_url,
            last_known_good_endpoint=self.connectivity.last_good_url,
            connectivity_mode=self.connectivity.mode,
            config_version=self.config_version,
            config_state=str(self.config_store.status().get("state") or "PENDING"),
        )
        self._status_update(
            gateway_url=self.base_url,
            gateway_candidates=self.connectivity.endpoint_dicts(),
            config_version=self.config_version,
            config_apply_reason=reason,
        )

    def _report_config_status(self, status: str, version: int, detail: str = "") -> None:
        if not self.token:
            return
        try:
            self.client.json(
                "POST",
                "/api/v1/agent/config/status",
                {
                    "AgentId": self.agent_id,
                    "Version": int(version),
                    "Status": str(status or "UNKNOWN").upper(),
                    "Detail": str(detail or "")[:4000],
                    "Time": now_iso(),
                },
                timeout=min(self.timeout, 10.0),
            )
        except Exception as exc:
            self._log_event(f"CONFIG_STATUS_REPORT_WARNING: {type(exc).__name__}: {exc}", "WARN")

    def sync_central_config(self, *, force: bool = False) -> bool:
        """Fetch and transactionally apply a newer Gateway configuration."""
        if not self.token:
            return False
        now = time.monotonic()
        if not force and now < self.next_config_check:
            return False
        self.next_config_check = now + self.config_check_seconds
        response = self.client.json("GET", f"/api/v1/agent/config?current={int(self.config_version)}", timeout=min(self.timeout, 12.0))
        status = str(response.get("Status") or "NO_CONFIGURATION").upper()
        if status in {"CURRENT", "NO_CONFIGURATION"}:
            return False
        if status != "UPDATE_AVAILABLE" or not isinstance(response.get("Configuration"), dict):
            raise AgentHttpError(f"Gateway devolvió estado de configuración inválido: {status}")
        candidate = validate_document(response["Configuration"])
        version = int(candidate.get("version") or 0)
        if version <= int(self.config_version):
            return False

        # A version that already failed validation/activation must not be retried
        # on every heartbeat.  The administrator can publish a corrected next
        # version, while an explicit force=True remains available for diagnostics.
        store_status = self.config_store.status()
        rejected_version = int(store_status.get("rejected_version") or 0)
        rejected_state = str(store_status.get("state") or "").upper()
        if not force and rejected_version == version and rejected_state in {"REJECTED", "ROLLED_BACK"}:
            self._status_update(
                config_state=rejected_state,
                config_candidate_version=version,
                config_rejected_version=version,
            )
            return False

        self._status_update(config_state="VALIDATING", config_candidate_version=version)
        self._log_event(f"CONFIG_UPDATE_AVAILABLE: local={self.config_version} gateway={version}")
        try:
            self.config_store.stage(candidate)
            effective = self._effective_from_central(candidate)
            preferred = self._probe_effective_configuration(effective, version)
        except Exception as exc:
            try:
                self.config_store.reject_staged(f"PRECHECK_FAILED: {type(exc).__name__}: {exc}")
            except Exception:
                pass
            self._status_update(config_state="REJECTED", config_candidate_version=version, last_config_error=str(exc))
            self._report_config_status("REJECTED", version, f"PRECHECK_FAILED: {type(exc).__name__}: {exc}")
            self._log_event(f"CONFIG_REJECTED_PRECHECK v{version}: {type(exc).__name__}: {exc}", "ERROR")
            return False

        # Commit only after the candidate has proved at least one authenticated
        # route.  Keep the pending journal until the post-commit probe succeeds;
        # a crash in this window is automatically rolled back on next startup.
        old_url = self.base_url
        old_document = dict(self.central_document or {})
        try:
            committed = self.config_store.commit_staged()
            self._apply_central_document(committed, preferred_url=preferred, reason="central-config-commit")
            post = self.client.json("GET", f"/api/v1/agent/config?current={version}", timeout=min(self.timeout, 10.0))
            if str(post.get("Status") or "").upper() not in {"CURRENT", "UPDATE_AVAILABLE"}:
                raise AgentHttpError(f"Validación post-commit inesperada: {post}")
            self._record_gateway_success()
            self.config_store.finalize()
            self._persist_runtime(config_version=version, config_state="APPLIED")
            self._status_update(config_state="APPLIED", config_version=version, last_config_error="", config_applied_at=now_iso())
            self._report_config_status("APPLIED", version, "Configuración aplicada y conectividad validada")
            self._log_event(f"CONFIG_APPLIED: v{version} · endpoint={self.base_url}")
            return True
        except Exception as exc:
            detail = f"POST_APPLY_FAILED: {type(exc).__name__}: {exc}"
            try:
                self.config_store.rollback_committed(detail)
            except Exception as rollback_exc:
                detail += f" | ROLLBACK_STORE_FAILED: {type(rollback_exc).__name__}: {rollback_exc}"
            restored = self.config_store.load_current()
            try:
                self._apply_central_document(restored or old_document, preferred_url=old_url, reason="central-config-rollback")
            except Exception as restore_exc:
                detail += f" | RUNTIME_RESTORE_FAILED: {type(restore_exc).__name__}: {restore_exc}"
            self._persist_runtime(config_version=self.config_version, config_state="ROLLED_BACK")
            self._status_update(
                config_state="ROLLED_BACK",
                config_version=self.config_version,
                config_rejected_version=version,
                last_config_error=detail,
                config_rollback_at=now_iso(),
            )
            self._report_config_status("ROLLED_BACK", version, detail)
            self._log_event(f"CONFIG_ROLLBACK v{version}: {detail}", "ERROR")
            return False

    def _activate_endpoint(self, url: str, *, reason: str) -> None:
        clean = str(url or "").strip().rstrip("/")
        if not clean:
            return
        previous = getattr(self, "base_url", "")
        self.base_url = clean
        self.client = self._client(self.token, base_url=clean)
        self._persist_runtime(
            current_gateway_endpoint=clean,
            last_known_good_endpoint=self.connectivity.last_good_url,
            connectivity_mode=self.connectivity.mode,
        )
        if previous != clean:
            self._log_event(f"ENDPOINT_SWITCH: {previous or '-'} -> {clean} · reason={reason}", "WARN")
        self._status_update(
            connectivity_state="ENDPOINT_TEST",
            gateway_connected=False,
            gateway_url=clean,
            failover_reason=reason,
        )

    def _record_gateway_success(self) -> None:
        previous_good = self.connectivity.last_good_url
        self.connectivity.record_success(self.base_url)
        self._persist_runtime(
            current_gateway_endpoint=self.base_url,
            last_known_good_endpoint=self.connectivity.last_good_url,
            connectivity_mode=self.connectivity.mode,
            last_gateway_success_at=now_iso(),
        )
        if previous_good != self.connectivity.last_good_url:
            self._log_event(f"LAST_KNOWN_GOOD: {self.connectivity.last_good_url}")

    @staticmethod
    def _connectivity_error_state(exc: Exception) -> str:
        text = f"{type(exc).__name__}: {exc}".casefold()
        if any(x in text for x in ("name or service not known", "nodename nor servname", "getaddrinfo", "temporary failure in name resolution", "no such host")):
            return "DNS_ERROR"
        if any(x in text for x in ("ssl", "certificate", "tls_", "hostname mismatch")):
            return "TLS_ERROR"
        if "http 403" in text and any(x in text for x in ("enroll", "grant", "secret", "credential")):
            return "ENROLLMENT_ERROR"
        if "http 401" in text or "authentication" in text:
            return "AUTH_ERROR"
        return "GATEWAY_UNREACHABLE"

    def _handle_connectivity_failure(self, exc: Exception) -> float | None:
        """Advance failover. Return sleep seconds only after all endpoints fail."""
        detail = redact_error(f"{type(exc).__name__}: {exc}")
        state = self._connectivity_error_state(exc)
        self._status_update(
            status=state,
            connectivity_state=state,
            gateway_connected=False,
            last_gateway_error=detail,
            last_error=detail,
            last_error_at=now_iso(),
            last_error_component="GIDEONAgent",
            last_error_operation="gateway.connectivity",
            last_error_traceback="",
            failed_gateway_endpoint=self.base_url,
        )
        self._log_event(f"{state}: {self.base_url}: {detail}", "WARN")
        self.connectivity.record_failure(self.base_url)
        next_url = self.connectivity.next_after_failure()
        if next_url:
            self._activate_endpoint(next_url, reason=state)
            return None
        self.connectivity.cycle_exhausted()
        delay = self.connectivity.delay()
        self._status_update(
            status="RECONNECTING",
            connectivity_state="RECONNECTING",
            gateway_connected=False,
            retry_in_seconds=round(delay, 2),
            retry_attempt=self.connectivity.retry_attempt,
        )
        self._log_event(f"RECONNECTING: endpoints agotados; reintento en {delay:.1f}s", "WARN")
        return delay

    def _resume_after_retry_wait(self) -> None:
        next_url = self.connectivity.reset_after_wait()
        self._activate_endpoint(next_url, reason="retry-cycle")

    def _refresh_dns(self) -> dict[str, Any]:
        self._status_update(connectivity_state="DNS_REFRESH", gateway_connected=False)
        results = resolve_endpoint_dns(self.connectivity.endpoints)
        self._last_dns_resolution = results
        self._status_update(dns_resolution=results, last_dns_refresh=now_iso())
        return results

    def _check_network_change(self, *, force: bool = False) -> bool:
        now = time.monotonic()
        if not force and now < self._next_network_check:
            return False
        self._next_network_check = now + self.network_check_seconds
        current = capture_network_snapshot()
        changes = snapshot_changes(self._network_snapshot, current)
        self._network_snapshot = current
        self._status_update(network=current.as_dict())
        if not changes:
            return False
        self._status_update(
            status="NETWORK_CHANGED",
            connectivity_state="NETWORK_CHANGED",
            gateway_connected=False,
            network_change=changes,
            last_network_change=now_iso(),
        )
        self._log_event("NETWORK_CHANGED: " + ",".join(changes), "WARN")
        self._refresh_dns()
        next_url = self.connectivity.reset_after_network_change()
        # Recreate urllib/TLS client even when the URL is unchanged.  urllib does
        # not keep a pool, but rebuilding guarantees the next request performs a
        # fresh route/DNS/TLS connection after interface/DHCP/VPN changes.
        self._activate_endpoint(next_url, reason="network-change")
        return True

    def _runtime_config(self) -> dict[str, Any]:
        if self.runtime_cfg_path.exists():
            try:
                value = json.loads(self.runtime_cfg_path.read_text(encoding="utf-8-sig"))
                return value if isinstance(value, dict) else {}
            except Exception:
                return {}
        return {}

    def _persist_runtime(self, **updates: Any) -> None:
        value = self._runtime_config()
        value.update({
            "agent_id": self.agent_id,
            "site_code": self.site_code,
            "site_name": self.site_name,
            "agent_name": self.agent_name,
        })
        value.update(updates)
        atomic_json(self.runtime_cfg_path, value)

    def _load_or_create_agent_id(self) -> str:
        runtime = self._runtime_config()
        existing = str(runtime.get("agent_id") or self.cfg.get("agent_id") or "").strip()
        if existing:
            agent_id = existing
        elif str(runtime.get("agent_token") or self.cfg.get("agent_token") or "").strip():
            # Upgrade compatibility: the old Gateway used SiteCode as identity.
            # Derive the same stable ID that the v2.1 Gateway migration creates.
            agent_id = legacy_agent_id(self.site_code, socket.gethostname())
        else:
            # New machines get a persistent machine identity. SiteCode is only
            # the location and is intentionally allowed to repeat.
            agent_id = "agt-" + uuid.uuid4().hex
        value = dict(runtime)
        value.update({
            "agent_id": agent_id,
            "site_code": self.site_code,
            "site_name": self.site_name,
            "agent_name": self.agent_name,
        })
        atomic_json(self.runtime_cfg_path, value)
        return agent_id

    def _adopt_gateway_agent_id(self, value: Any) -> None:
        returned = str(value or "").strip()
        if returned and returned != self.agent_id:
            self.agent_id = returned
            self._persist_runtime()
            # A manifest is identity-bound.  Recreate the bridge on the rare
            # legacy-ID migration so it never accepts a campaign for an old ID.
            if hasattr(self, "player_bridge"):
                self.player_bridge = _new_player_bridge(
                    agent_root=self.root,
                    agent_id=self.agent_id,
                    public_key_path=Path(self.signing_public_key) if self.signing_public_key else None,
                )

    def _load_token(self) -> str:
        if self.runtime_cfg_path.exists():
            try:
                value = json.loads(self.runtime_cfg_path.read_text(encoding="utf-8-sig"))
                token = str(value.get("agent_token") or "")
                if token:
                    return token
            except Exception as exc:
                self._log_event(f"TOKEN_RUNTIME_READ_WARNING: {type(exc).__name__}: {exc}", "WARN")
        return str(self.cfg.get("agent_token") or "")

    def _cached_rdp_capability(self, host: str, port: int, ready: bool) -> dict[str, Any]:
        key = (str(host), int(port), bool(ready))
        now = time.monotonic()
        cached = self._rdp_capability_cache
        if cached is not None and cached[1] == key and now - cached[0] <= 60.0:
            return dict(cached[2])
        detected = detect_rdp_capability(
            target_host=str(host), target_port=int(port), socket_ready=bool(ready)
        )
        self._rdp_capability_cache = (now, key, dict(detected))
        return detected

    def _cached_display_capability(self) -> dict[str, Any]:
        now = time.monotonic()
        cached = self._display_capability_cache
        if cached is not None and now - cached[0] <= 45.0:
            return dict(cached[1])
        # Capability discovery is intentionally best effort.  The module itself
        # returns an UNAVAILABLE document on errors, and this guard makes sure a
        # future platform-specific regression can never make the Agent OFFLINE.
        try:
            self.local_wayland_console_bridge.ensure_running()
            detected = self._load_interactive_display_capability() or detect_display_capability()
            detected = self._merge_player_display_capability(detected)
            # The service has no desktop environment of its own.  Merge only
            # outputs discovered through the verified, local WayVNC owner; the
            # bridge marks them LOCAL_WAYLAND_SESSION and never upgrades them
            # into evidence of a connected HDMI/DRM connector.
            detected = self.local_wayland_console_bridge.enrich_display_capability(detected)
        except Exception:
            detected = {
                "Schema": "gideon-display-capability/v1",
                "Supported": False,
                "State": "UNAVAILABLE",
                "Session": {"Available": False, "Type": "unknown", "Interactive": False},
                "Outputs": [],
                "Error": "DISPLAY_DISCOVERY_FAILED",
            }
        self._display_capability_cache = (now, dict(detected))
        return detected

    def _merge_player_display_capability(self, detected: dict[str, Any]) -> dict[str, Any]:
        """Use the signed Player's physical-session report from Windows service mode.

        A service in Session 0 cannot enumerate the user's User32 desktop. Once
        the Player has been launched in the active console, its bounded status
        contains the verified output binding and physical-session proof. That
        local report is sufficient to reconcile the already configured Screen;
        it never invents a monitor before the Player has observed one.
        """
        if os.name != "nt" or str(detected.get("State") or "").upper() not in {"UNAVAILABLE", "DEGRADED"}:
            return detected
        try:
            report = self.player_bridge.status_for_report()
            graphics = report.get("Graphics") if isinstance(report.get("Graphics"), dict) else {}
            physical = graphics.get("PhysicalSession") if isinstance(graphics.get("PhysicalSession"), dict) else {}
            screens = report.get("Screens") if isinstance(report.get("Screens"), list) else []
            if str(graphics.get("State") or "").upper() not in {"READY", "PLAYING"}:
                return detected
            if not bool(physical.get("Physical")) or not screens:
                return detected
            manifest = self.player_bridge.store.load_desktop_manifest()
            assignments = list(getattr(manifest, "assignments", ()) or ()) if manifest is not None else []
            outputs: list[dict[str, Any]] = []
            for assignment in assignments:
                if str(getattr(assignment, "target_kind", "")) != "PHYSICAL_CONNECTOR":
                    continue
                resolution = str(getattr(assignment, "resolution", "") or "")
                width = height = 0
                if "x" in resolution:
                    try:
                        width, height = (int(value) for value in resolution.lower().split("x", 1))
                    except (TypeError, ValueError):
                        width = height = 0
                outputs.append({
                    "Key": str(getattr(assignment, "output_key", "") or "windows-display1"),
                    "Label": str(getattr(assignment, "output_label", "") or "Pantalla física"),
                    "Identity": str(getattr(assignment, "output_identity", "") or ""),
                    "Primary": len(outputs) == 0,
                    "Width": width,
                    "Height": height,
                })
            if not outputs:
                return detected
            return {
                "Schema": "gideon-display-capability/v1",
                "Supported": True,
                "State": "READY",
                "Session": {"Available": True, "Type": "windows-console", "Interactive": True},
                "Outputs": outputs,
                "Error": "",
                "Source": "player-runtime-physical-console",
            }
        except Exception:
            return detected

    def _load_interactive_display_capability(self) -> dict[str, Any] | None:
        """Read the fresh, secret-free report emitted by the desktop tray."""
        if os.name != "nt" and sys.platform not in {"linux", "linux2"}:
            return None
        identity = str(self.agent_id or self.cfg_path).strip()
        digest = hashlib.sha256(identity.casefold().encode("utf-8", "ignore")).hexdigest()[:16]
        candidates = [
            self.root / "display-session-capability.json",
            Path(tempfile.gettempdir()) / f"gideon-agent-display-{digest}.json",
        ]
        try:
            candidates.extend(Path("/run/user").glob(f"*/gideon-agent-display-{digest}.json"))
        except OSError:
            pass
        now = dt.datetime.now(dt.timezone.utc)
        for path in candidates:
            try:
                if not path.is_file() or now.timestamp() - path.stat().st_mtime > 90.0:
                    continue
                value = json.loads(path.read_text(encoding="utf-8-sig"))
                if not isinstance(value, dict) or value.get("Schema") != "gideon-display-capability/v1":
                    continue
                updated = str(value.get("UpdatedAt") or "").replace("Z", "+00:00")
                stamp = dt.datetime.fromisoformat(updated)
                if stamp.tzinfo is None:
                    stamp = stamp.replace(tzinfo=dt.timezone.utc)
                if (now - stamp.astimezone(dt.timezone.utc)).total_seconds() > 90.0:
                    continue
                session = value.get("Session") if isinstance(value.get("Session"), dict) else {}
                outputs = value.get("Outputs") if isinstance(value.get("Outputs"), list) else []
                safe_outputs: list[dict[str, Any]] = []
                for item in outputs[:16]:
                    if not isinstance(item, dict):
                        continue
                    width, height = int(item.get("Width") or 0), int(item.get("Height") or 0)
                    target_kind = str(item.get("TargetKind") or "")[:48]
                    if (width <= 0 or height <= 0) and target_kind != "LOCAL_WAYLAND_SESSION":
                        continue
                    safe_outputs.append({
                        key: item.get(key)
                        for key in (
                            "OutputKey", "Connector", "Index", "Connected", "Enabled", "Primary",
                            "Physical", "Virtual", "TargetKind", "Width", "Height", "RefreshHz",
                            "Orientation", "ResolutionSource", "OutputIdentity", "OutputIdentitySource",
                        )
                        if key in item
                    })
                result = {
                    "Schema": "gideon-display-capability/v1",
                    "Supported": bool(value.get("Supported")),
                    "State": str(value.get("State") or "NO_OUTPUTS")[:32],
                    "DetectedAt": str(value.get("DetectedAt") or value.get("UpdatedAt") or "")[:64],
                    "Session": {
                        "Available": bool(session.get("Available")),
                        "Type": str(session.get("Type") or "unknown")[:48],
                        "Interactive": bool(session.get("Interactive")),
                    },
                    "Outputs": safe_outputs,
                    "Error": str(value.get("Error") or "")[:240],
                    "Source": "interactive-tray",
                }
                if safe_outputs:
                    result["State"] = "READY"
                return result
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                continue
        return None

    def _remote_access_capability(self) -> dict[str, Any]:
        cfg = self.cfg.get("remote_access")
        if not isinstance(cfg, dict):
            cfg = {}
        protocol = str(cfg.get("protocol") or "").upper()
        host = str(cfg.get("target_host") or "127.0.0.1").strip()
        try:
            port = int(cfg.get("target_port") or (5900 if protocol == "VNC" else 3389))
        except Exception:
            port = 5900 if protocol == "VNC" else 3389

        enabled = bool(cfg.get("enabled", True))
        ready = False
        error = ""
        if enabled and host and port > 0:
            try:
                with socket.create_connection((host, port), timeout=1.5):
                    ready = True
            except Exception as exc:
                error = redact_error(f"{type(exc).__name__}: {exc}", max_chars=240)

        support_state = str(cfg.get("support_state") or "").strip().lower()
        if not support_state:
            if ready:
                support_state = "ready"
            elif not enabled:
                support_state = "disabled"
            else:
                support_state = "unavailable"

        result = {
            "Enabled": enabled,
            "Supported": support_state != "unsupported",
            "ManagedByInstaller": bool(cfg.get("managed_by_installer", False)),
            "RequireReady": bool(cfg.get("require_ready", False)),
            "Mode": str(cfg.get("mode") or "tunnel-only"),
            "Protocol": protocol or None,
            "TargetHost": host,
            "TargetPort": port,
            "Server": str(cfg.get("server") or ""),
            "Ready": ready,
            "SupportState": support_state,
            "SupportReason": str(cfg.get("support_reason") or ""),
            "SupportDetail": str(cfg.get("support_detail") or ""),
            "Error": error,
            "InboundFirewallOpenedByGIDEON": False,
        }
        # Guacamole's RDP drive is not enough on Linux: xrdp must have its
        # channel helper installed so the redirected GIDEON Transfer drive can
        # actually be mounted inside the remote desktop.  Advertise this
        # separately instead of making WebAdmin promise a file-transfer
        # button that will hang on a minimal xrdp installation.
        transfer_ready = False
        transfer_method = "unsupported"
        transfer_reason = ""
        if (protocol or "RDP") == "RDP" and ready:
            if os.name == "nt":
                transfer_ready = True
                transfer_method = "windows-rdpdr"
            elif normalize_platform() == "linux":
                chansrv_candidates = (
                    "/usr/sbin/xrdp-chansrv",
                    "/usr/lib/xrdp/xrdp-chansrv",
                    "/usr/libexec/xrdp-chansrv",
                )
                transfer_ready = any(Path(path).is_file() and os.access(path, os.X_OK) for path in chansrv_candidates)
                transfer_method = "xrdp-chansrv" if transfer_ready else "none"
                if not transfer_ready:
                    transfer_reason = "Falta xrdp-chansrv; instale el paquete xrdp completo para habilitar GIDEON Transfer."
            else:
                transfer_reason = "El protocolo remoto anunciado no publica un canal de archivos compatible."
        elif protocol == "RDP" and not ready:
            transfer_reason = "El listener RDP todavía no está listo."
        result["FileTransfer"] = {
            "Supported": bool(transfer_ready),
            "Ready": bool(transfer_ready),
            "Method": transfer_method,
            "Reason": transfer_reason,
        }
        if (protocol or "RDP") == "RDP":
            result["RDP"] = self._cached_rdp_capability(host, port, ready)
        # Raspberry Pi Connect owns the visible local Wayland desktop.  When
        # its protected RFB socket exists, advertise that exact local session
        # without claiming that an electrical HDMI connector is present.
        self.local_wayland_console_bridge.ensure_running()
        local_wayland = self.local_wayland_console_bridge.status()
        if local_wayland.get("Ready"):
            result["VNC"] = {
                "Usable": True,
                "Ready": True,
                "TargetHost": str(local_wayland.get("TargetHost") or "127.0.0.1"),
                "TargetPort": int(local_wayland.get("TargetPort") or 5900),
                "Server": "wayvnc-local-wayland-console",
                "SessionKind": "local-wayland-console",
                "TargetKind": "LOCAL_WAYLAND_SESSION",
                "PhysicalConsole": False,
                "AuthMode": "control-plane",
                "PasswordRequired": False,
                "LoopbackOnly": True,
                "Source": "rpi-connect-wayvnc-unix-socket",
            }
        return result

    def capabilities(self) -> dict[str, Any]:
        operations = self._job_capabilities()
        display = self._cached_display_capability()
        player = self.player_bridge.capability(display)
        if not isinstance(player, dict):
            player = _DisabledPlayerBridge("PLAYER_CAPABILITY_INVALID").capability(display)
        try:
            player["OfflineVlc"] = self.offline_vlc.capability()
        except Exception:
            player["OfflineVlc"] = _DisabledOfflineVlcController("VLC_OFFLINE_CAPABILITY_UNAVAILABLE").capability()
        return {
            "Platform": normalize_platform(),
            "Architecture": normalize_arch(),
            "OperatingSystem": operating_system_identity(),
            "PythonVersion": platform.python_version(),
            "HostProfile": self.profile.get("id"),
            "AllowedExtensions": self.profile.get("allowed_extensions", []),
            "Operations": operations,
            "ReverseTunnel": {
                "Supported": True,
                "ProtocolVersion": REVERSE_TUNNEL_VERSION,
                "RuntimeApiVersion": REVERSE_TUNNEL_API_VERSION,
                "OutboundOnly": True,
                "PlatformIndependent": True,
                "AllowedTargets": list(
                    (self.cfg.get("reverse_tunnel") or {}).get(
                        "allowed_targets",
                        ["127.0.0.1:3389", "127.0.0.1:5900"],
                    )
                ) if isinstance(self.cfg.get("reverse_tunnel"), dict) else ["127.0.0.1:3389", "127.0.0.1:5900"],
            },
            "RemoteAccess": self._remote_access_capability(),
            "Display": display,
            "Player": player,
            "Updates": {
                "ProtocolVersion": 2,
                "Channel": self.update_channel,
                "ForcedCheck": True,
                "SignedBundles": True,
                "Sha256Required": True,
                "Rollback": True,
                "PlatformIndependentRuntime": True,
            },
            "Executors": {
                "powershell": shutil.which("powershell.exe") or shutil.which("pwsh"),
                "pwsh": shutil.which("pwsh"),
                "bash": shutil.which("bash"),
                "sh": shutil.which("sh"),
                "zsh": shutil.which("zsh"),
                "cmd": os.environ.get("COMSPEC") if os.name == "nt" else None,
                "python": sys.executable,
            },
        }

    def _reverse_tunnel_status(self, state: str, detail: str = "") -> None:
        # Status is secret-free and bounded. It is included in normal Agent diagnostics.
        try:
            self._status_update(
                reverse_tunnel_state=str(state),
                reverse_tunnel_error=redact_error(detail or "", max_chars=500),
                reverse_tunnel_updated_at=now_iso(),
            )
        except Exception:
            pass

    def _stop_reverse_tunnel(self) -> None:
        client = self.reverse_tunnel
        self.reverse_tunnel = None
        self._reverse_tunnel_signature = ""
        if client is not None:
            try:
                client.stop()
            except Exception:
                pass

    def _ensure_reverse_tunnel(self) -> None:
        # Reverse tunnel is a management-plane side channel. Any tunnel failure
        # must never make jobs/heartbeat OFFLINE.
        cfg = self.cfg.get("reverse_tunnel", {}) if isinstance(self.cfg.get("reverse_tunnel"), dict) else {}
        enabled = bool(cfg.get("enabled", True))
        if not enabled or not self.token or not self.base_url:
            self._stop_reverse_tunnel()
            return
        allowed_targets = cfg.get("allowed_targets")
        if not isinstance(allowed_targets, list) or not allowed_targets:
            allowed_targets = ["127.0.0.1:3389", "127.0.0.1:5900"]
        allowed_targets = [str(x).strip() for x in allowed_targets if str(x).strip()]

        signature = "|".join((
            self.base_url, self.token, self.agent_id,
            str(self.verify_tls), str(self.ca_file or ""),
            str(self.client_cert or ""), str(self.client_key or ""),
            ",".join(sorted(allowed_targets)),
        ))
        if self.reverse_tunnel is not None and self._reverse_tunnel_signature == signature:
            self.reverse_tunnel.start()
            return
        self._stop_reverse_tunnel()
        client = AgentReverseTunnelClient(
            base_url=self.base_url,
            bearer_token=self.token,
            agent_id=self.agent_id,
            verify_tls=self.verify_tls,
            ca_file=self.ca_file,
            client_cert=self.client_cert,
            client_key=self.client_key,
            allowed_targets=allowed_targets,
            status_callback=self._reverse_tunnel_status,
        )
        self.reverse_tunnel = client
        self._reverse_tunnel_signature = signature
        if getattr(self, "_offline_vlc_maintenance", False):
            # A route failover/reconnect must not reopen remote streams in the
            # middle of a package-maintenance window.
            self._offline_vlc_tunnel_quiesced = bool(client.begin_update_quiesce())
        client.start()

    def _ensure_mtls_identity(self) -> bool:
        """Enroll a per-Agent client certificate without transporting its key.

        This is intentionally opportunistic while the Gateway is in compatibility
        mode.  Once the Gateway requires mTLS, the same endpoint remains the only
        unauthenticated-by-certificate exception and still requires this Agent's
        bearer token.  A failed/old endpoint never blocks normal heartbeat traffic
        when mTLS is not yet mandatory.
        """
        if not self.token:
            return False
        previous_cert = self.client_cert
        previous_key = self.client_key
        previous_client = self.client
        renewal_required = False
        identity_configured = bool(self.client_cert or self.client_key)
        had_usable_identity = bool(
            self.client_cert and self.client_key
            and Path(self.client_cert).is_file() and Path(self.client_key).is_file()
        )
        if self.client_cert and self.client_key and Path(self.client_cert).is_file() and Path(self.client_key).is_file():
            try:
                current_cert = x509.load_pem_x509_certificate(Path(self.client_cert).read_bytes())
                current_key = serialization.load_pem_private_key(Path(self.client_key).read_bytes(), password=None)
                cert_public = current_cert.public_key().public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
                )
                key_public = current_key.public_key().public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
                )
                if cert_public != key_public:
                    renewal_required = True
                    self._log_event("AGENT_MTLS_RENEWAL_DUE: client certificate and key do not match", "WARN")
                elif _certificate_expiry_utc(current_cert) > dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=14):
                    return True
                else:
                    renewal_required = True
                    self._log_event("AGENT_MTLS_RENEWAL_DUE: client certificate expires within 14 days", "INFO")
            except Exception:
                # A malformed/expired leaf is replaced through the same CSR flow.
                renewal_required = True
        elif identity_configured:
            # A configured-but-missing pair must also use bearer-only migration;
            # presenting a broken client certificate can prevent the CSR request.
            renewal_required = True
        now = time.monotonic()
        if now < self._next_mtls_attempt:
            return False
        self._next_mtls_attempt = now + 300.0
        cert_path = self.paths.security / "client.crt"
        key_path = self.paths.security / "client.key"
        try:
            key = None
            if key_path.is_file():
                try:
                    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
                except Exception:
                    key = None
            if key is None:
                key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                _atomic_bytes(
                    key_path,
                    key.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.TraditionalOpenSSL,
                        serialization.NoEncryption(),
                    ),
                )
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.agent_id)])
            csr_builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
            try:
                hostname = socket.gethostname().strip()
                if hostname:
                    csr_builder = csr_builder.add_extension(
                        x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False
                    )
            except Exception:
                pass
            csr = csr_builder.sign(key, hashes.SHA256())
            # An expired or malformed certificate must not be presented to the
            # enrollment endpoint.  Use the already-authenticated bearer channel
            # for this migration request, then restore the prior client only if
            # enrollment fails and no replacement was activated.
            if renewal_required:
                self.client_cert = None
                self.client_key = None
                self.client = self._client(self.token)
            response = self.client.json(
                "POST",
                "/api/v1/agent/mtls/enroll",
                {
                    "AgentId": self.agent_id,
                    "Hostname": socket.gethostname(),
                    "AgentVersion": VERSION,
                    "CSR": csr.public_bytes(serialization.Encoding.PEM).decode("ascii"),
                },
                timeout=min(self.timeout, 15.0),
            )
            cert_pem = str(response.get("Certificate") or "").encode("ascii")
            if not cert_pem or b"BEGIN CERTIFICATE" not in cert_pem:
                raise AgentHttpError("Gateway did not return an Agent client certificate")
            # Validate the returned leaf before making it active.  The Gateway is
            # still trusted through the existing TLS channel, but this catches a
            # malformed response before the next TLS handshake.
            cert = x509.load_pem_x509_certificate(cert_pem)
            if cert.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            ) != key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            ):
                raise RuntimeError("AGENT_MTLS_CERT_KEY_MISMATCH")
            _atomic_bytes(cert_path, cert_pem)
            self.client_cert = str(cert_path)
            self.client_key = str(key_path)
            self._persist_runtime(
                mtls_client_cert=self.client_cert,
                mtls_client_key=self.client_key,
                mtls_ready=True,
                mtls_fingerprint=str(response.get("FingerprintSHA256") or cert.fingerprint(hashes.SHA256()).hex()),
                mtls_expires_at=str(response.get("ExpiresAt") or _certificate_expiry_utc(cert).isoformat()),
            )
            self.client = self._client(self.token)
            if had_usable_identity and self.reverse_tunnel is not None:
                # A certificate renewal must not tear down active RDP/VNC data
                # streams.  The existing TLS channel remains valid until its
                # natural reconnect, which will load the renewed files.
                self.reverse_tunnel.client_cert = self.client_cert
                self.reverse_tunnel.client_key = self.client_key
            else:
                # First-time enrollment changes an unauthenticated channel into
                # an mTLS channel and therefore requires one controlled reconnect.
                self._stop_reverse_tunnel()
                self._ensure_reverse_tunnel()
            self._status_update(
                mtls_ready=True,
                mtls_fingerprint=str(response.get("FingerprintSHA256") or cert.fingerprint(hashes.SHA256()).hex()),
                mtls_expires_at=str(response.get("ExpiresAt") or _certificate_expiry_utc(cert).isoformat()),
            )
            self._log_event("AGENT_MTLS_ENROLLED: client certificate installed")
            return True
        except Exception as exc:
            if renewal_required and previous_cert and previous_key:
                self.client_cert = previous_cert
                self.client_key = previous_key
                self.client = previous_client
            self._status_update(mtls_ready=False, mtls_last_error=redact_error(exc, max_chars=500))
            self._log_event(f"AGENT_MTLS_ENROLLMENT_DEFERRED: {type(exc).__name__}: {exc}", "WARN")
            return False

    def enroll(self) -> None:
        if self.token:
            return
        secret = str(
            self.cfg.get("enrollment_secret")
            or os.environ.get(str(self.cfg.get("enrollment_secret_env", "GIDEON_AGENT_ENROLL_SECRET")), "")
        )
        if not secret:
            raise RuntimeError("Agent enrollment secret missing")
        bootstrap = self._client("")
        response = bootstrap.json(
            "POST",
            "/api/v1/agent/enroll",
            {
                "AgentId": self.agent_id,
                "SiteCode": self.site_code,
                "SiteName": self.site_name,
                "AgentName": self.agent_name,
                "Hostname": socket.gethostname(),
                "AgentVersion": VERSION,
                "ProtocolVersion": PROTOCOL_VERSION,
                "Platform": normalize_platform(),
                "Architecture": normalize_arch(),
                "HostProfile": self.profile.get("id"),
                "Capabilities": self.capabilities(),
                "EnrollmentSecret": secret,
            },
        )
        self._adopt_gateway_agent_id(response.get("AgentId"))
        token = str(response.get("AgentToken") or "")
        if not token:
            raise RuntimeError("Gateway did not return AgentToken")
        self.token = token
        self._persist_runtime(
            agent_token=token,
            enrolled_at=now_iso(),
            agent_version=VERSION,
            protocol_version=PROTOCOL_VERSION,
        )
        try:
            persisted = dict(self.cfg)
            if persisted.get("enrollment_secret"):
                persisted["enrollment_secret"] = ""
                atomic_json(self.cfg_path, persisted)
                self.cfg = persisted
            # Defense in depth: setup scripts already remove this one-time file,
            # but the Agent also removes it immediately after successful enrollment
            # so a partial/manual installation cannot leave reusable bootstrap data.
            bootstrap_file = self.cfg_path.parent / "bootstrap.enrollment"
            if bootstrap_file.exists():
                bootstrap_file.unlink()
        except Exception as exc:
            self._log_event(f"ENROLLMENT_SECRET_CLEANUP_WARNING: {type(exc).__name__}: {exc}", "WARN")
        self.client = self._client(token)
        self._record_gateway_success()
        self._ensure_reverse_tunnel()

    def heartbeat(self, *, update_local_status: bool = True) -> None:
        # Capture the attempt before the request.  If it fails, the next successful
        # heartbeat still carries the previous failure/network context to WebAdmin.
        self._status_update(last_gateway_attempt=now_iso())
        heartbeat_started = time.monotonic()
        response = self.client.json(
            "POST",
            "/api/v1/agent/heartbeat",
            {
                "AgentId": self.agent_id,
                "AgentName": self.agent_name,
                "Hostname": socket.gethostname(),
                "AgentVersion": VERSION,
                "ProtocolVersion": PROTOCOL_VERSION,
                "Platform": normalize_platform(),
                "Architecture": normalize_arch(),
                "HostProfile": self.profile.get("id"),
                "Capabilities": self.capabilities(),
                "VersionState": self.version_state,
                "Diagnostics": self._diagnostic_snapshot(),
                "Time": now_iso(),
            },
        )
        heartbeat_latency_ms = max(0, int((time.monotonic() - heartbeat_started) * 1000))
        self._adopt_gateway_agent_id(response.get("AgentId"))
        update_request = response.get("UpdateRequest") if isinstance(response.get("UpdateRequest"), dict) else {}
        offline_vlc_request = response.get("OfflineVlcInstallRequest") if isinstance(response.get("OfflineVlcInstallRequest"), dict) else {}
        request_state = str(update_request.get("status") or "").upper()
        request_target = str(update_request.get("target_version") or "").strip()
        if request_state in {"REQUESTED", "DELIVERED"} and request_target and request_target != VERSION:
            self._force_update_once = True
            self.next_version_check = 0.0
            self._status_update(
                update_state="CHECK_REQUESTED", update_target_version=request_target,
                update_request_id=str(update_request.get("request_id") or ""),
                update_requested_at=str(update_request.get("requested_at") or ""),
            )
        self._record_gateway_success()
        self._ensure_reverse_tunnel()
        offline_request_state = str(offline_vlc_request.get("State") or "").upper()
        offline_busy_reason = ""
        offline_gate_acquired = False
        if offline_vlc_request and offline_request_state in {"REQUESTED", "DELIVERED", "DEFERRED"}:
            offline_busy_reason = self._offline_vlc_busy_reason()
            if not offline_busy_reason:
                offline_gate_acquired = self._begin_offline_vlc_maintenance(require_tunnel=True)
                if not offline_gate_acquired:
                    offline_busy_reason = "ACTIVE_REMOTE_SESSION"
        elif offline_vlc_request and offline_request_state == "RUNNING":
            # Recover the local maintenance gate after an Agent-service restart.
            # The child is already running, so block new local work even if an
            # older remote stream prevents the tunnel from fully quiescing.
            self._begin_offline_vlc_maintenance(require_tunnel=False)
        elif self._offline_vlc_maintenance:
            self._end_offline_vlc_maintenance()

        # Media Player synchronization is intentionally best effort.  A
        # missing endpoint on an older Gateway, a rejected manifest, or a VLC
        # problem is reported separately and cannot invalidate this successful
        # authenticated heartbeat, transfer queue, or remote tunnel.
        try:
            if not self._offline_vlc_maintenance:
                self.player_bridge.sync_from_gateway(self.client)
            self.player_bridge.report_to_gateway(self.client)
        except Exception as exc:
            self._log_event(f"PLAYER_SYNC_WARNING: {type(exc).__name__}: {exc}", "WARN")
        # This has no authority to install unless the Gateway supplied a
        # short-lived, GIDEON-signed request.  The controller runs its fixed
        # installer out-of-process and returns a bounded status only; an offline
        # VLC package can never block the normal heartbeat/tunnel loop.
        if offline_vlc_request:
            try:
                offline_vlc_status = self.offline_vlc.synchronize(
                    offline_vlc_request, busy_reason=offline_busy_reason,
                )
                if isinstance(offline_vlc_status, dict):
                    self.client.json(
                        "POST", "/api/v1/agent/vlc-offline/install/status", offline_vlc_status,
                    )
                    offline_result_state = str(offline_vlc_status.get("State") or "").upper()
                    if offline_result_state in {"INSTALLED", "FAILED", "EXPIRED", "SUPERSEDED"}:
                        self._end_offline_vlc_maintenance()
                    elif offline_result_state == "RUNNING":
                        # The controller may have recovered an already-running
                        # child while the Gateway still showed DELIVERED.
                        self._begin_offline_vlc_maintenance(require_tunnel=False)
                    elif offline_result_state != "RUNNING" and offline_gate_acquired:
                        # Validation/dispatch did not start a child; never leave
                        # the reverse tunnel quiesced for a deferred request.
                        self._end_offline_vlc_maintenance()
            except Exception as exc:
                if offline_gate_acquired:
                    self._end_offline_vlc_maintenance()
                self._log_event(f"VLC_OFFLINE_INSTALL_WARNING: {type(exc).__name__}: {redact_error(exc, max_chars=240)}", "WARN")
        if update_local_status and not self.suppress_local_status:
            stamp = now_iso()
            player_status = self.player_bridge.status_for_report()
            self._status_update(
                status="BUSY" if self.active_job_id else "ACTIVE",
                connectivity_state="CONNECTED",
                gateway_connected=True,
                last_heartbeat=stamp,
                gateway_observed_ip=str(response.get("RemoteIP") or ""),
                gateway_time=str(response.get("Time") or ""),
                gateway_latency_ms=heartbeat_latency_ms,
                last_gateway_error="",
                last_error="",
                active_job_id=self.active_job_id,
                active_remote_streams=self._active_remote_stream_count(),
                player_state=str(player_status.get("State") or ""),
                player_manifest_version=int(player_status.get("ManifestVersion") or 0),
                player_screen_count=len(player_status.get("Screens") or []),
            )
        # Central configuration is management-plane metadata, not a heartbeat
        # dependency. A temporary failure (or an older Gateway without P6) must
        # never turn a successful Agent connection into OFFLINE.
        try:
            self.sync_central_config()
        except Exception as exc:
            safe_exc = redact_error(f"{type(exc).__name__}: {exc}")
            safe_tb = redact_error(traceback.format_exc(), max_chars=12000)
            self._status_update(
                config_state="CONFIG_ERROR", config_sync_error=safe_exc,
                last_error=safe_exc, last_error_at=now_iso(),
                last_error_component="GIDEONAgent", last_error_operation="configuration.sync",
                last_error_traceback=safe_tb,
            )
            self._log_event(f"CONFIG_SYNC_WARNING: {safe_exc}", "WARN")

    def _update_service_identity(self) -> tuple[str, str]:
        platform_id = normalize_platform()
        if platform_id == "windows":
            return "windows-service", str(self.update_cfg.get("service_id") or "GIDEONAgent")
        if platform_id == "linux":
            return "systemd", str(self.update_cfg.get("service_id") or "gideon-agent.service")
        bundle_id = str(self.update_cfg.get("service_id") or "").strip()
        if not bundle_id:
            try:
                branding = Path(__file__).resolve().parent / "branding.json"
                if branding.is_file():
                    bundle_id = str(json.loads(branding.read_text(encoding="utf-8-sig")).get("bundle_id") or "").strip()
            except Exception as exc:
                self._log_event(f"UPDATE_BRANDING_WARNING: {type(exc).__name__}: {exc}", "WARN")
        return "launchd", bundle_id or "pe.com.gideons.gideonagent"

    def _active_remote_stream_count(self) -> int:
        tunnel = self.reverse_tunnel
        if tunnel is None:
            return 0
        try:
            return max(0, int(tunnel.active_stream_count))
        except Exception:
            # Failing closed here would permanently block updates on an older
            # optional tunnel implementation. The final atomic quiesce remains
            # the authoritative race-free gate.
            return 0

    def _offline_vlc_busy_reason(self) -> str:
        """Return a stable reason to defer third-party package installation.

        Installing VLC changes files that a running Player can be using.  It is
        also deliberately deferred while an operator controls the endpoint or a
        normal Agent Job is executing.  A later heartbeat retries the exact same
        signed request; no request is discarded simply because the device was
        busy at that instant.
        """
        if self.active_job_id:
            return "ACTIVE_JOB"
        if self._active_remote_stream_count() > 0:
            return "ACTIVE_REMOTE_SESSION"
        try:
            player_status = self.player_bridge.status_for_report()
            if str(player_status.get("State") or "").upper() == "PLAYING":
                return "PLAYER_ACTIVE"
            if any(str(row.get("State") or "").upper() == "PLAYING" for row in (player_status.get("Screens") or []) if isinstance(row, dict)):
                return "PLAYER_ACTIVE"
        except Exception:
            # The installer itself re-validates the catalog and does not touch
            # Agent core state.  A transient optional Player status failure must
            # not turn into a permanent inability to install a reviewed kit.
            pass
        return ""

    def _begin_offline_vlc_maintenance(self, *, require_tunnel: bool) -> bool:
        """Block new endpoint work while the verified VLC child is active.

        ``begin_update_quiesce`` shares the tunnel stream lock with connection
        acceptance, closing the last-check/launch race.  During restart
        recovery the child may already exist; in that case local Jobs/Player
        remain blocked even if an older stream cannot be retroactively closed.
        """
        if self._offline_vlc_maintenance:
            return self._offline_vlc_tunnel_quiesced or not require_tunnel
        tunnel = self.reverse_tunnel
        tunnel_quiesced = False
        if tunnel is not None:
            try:
                tunnel_quiesced = bool(tunnel.begin_update_quiesce())
            except Exception:
                tunnel_quiesced = False
            if not tunnel_quiesced and require_tunnel:
                return False
        self._offline_vlc_maintenance = True
        self._offline_vlc_tunnel_quiesced = tunnel_quiesced
        return tunnel_quiesced or tunnel is None

    def _end_offline_vlc_maintenance(self) -> None:
        tunnel = self.reverse_tunnel
        if self._offline_vlc_tunnel_quiesced and tunnel is not None:
            try:
                tunnel.cancel_update_quiesce()
            except Exception as exc:
                self._log_event(f"VLC_OFFLINE_TUNNEL_RESUME_WARNING: {type(exc).__name__}", "WARN")
        self._offline_vlc_tunnel_quiesced = False
        self._offline_vlc_maintenance = False

    def _defer_update_busy(self, version: str, reason: str) -> None:
        """Keep the durable request pending without interrupting endpoint work."""
        self._force_update_once = True
        self.next_version_check = time.monotonic() + 30.0
        self._status_update(
            update_state="UPDATE_DEFERRED_BUSY",
            update_target_version=str(version or ""),
            update_deferred_reason=str(reason or "BUSY"),
            active_remote_streams=self._active_remote_stream_count(),
            update_checked_at=now_iso(),
        )

    def _schedule_update(self, release: dict[str, Any]) -> bool:
        """Verify and schedule an approved stable update on every Agent OS.

        Update bundles are site-neutral.  Machine identity, Gateway trust, token,
        certificates and the local virtualenv are preserved by gideon_agent_update.py.
        The updater performs a runtime import smoke-test and rolls back before the
        service is restarted if a file/dependency is incomplete.
        """
        if self.update_install_started:
            return False
        if str(release.get("approval_state") or "").upper() != "APPROVED":
            return False
        if self.update_channel.lower() != "stable":
            return False
        version = str(release.get("version") or "").strip()
        if not version or version == VERSION:
            return False
        if self.active_job_id:
            self._defer_update_busy(version, "ACTIVE_JOB")
            return False
        if self._active_remote_stream_count():
            self._defer_update_busy(version, "ACTIVE_REMOTE_SESSION")
            return False
        signature = str(release.get("signature") or "").strip()
        expected_sha = str(release.get("bundle_sha256") or "").strip().lower()
        key_id = str(release.get("key_id") or "").strip()
        if not (signature and expected_sha and key_id):
            raise RuntimeError("UPDATE_METADATA_INVALID: release aprobado sin firma/SHA256/KeyId")
        if not self.signing_public_key or not Path(self.signing_public_key).is_file():
            raise RuntimeError("UPDATE_SIGNING_KEY_MISSING: no existe la clave pública de confianza")
        try:
            bundle_bytes = int(release.get("bundle_bytes") or 0)
        except (TypeError, ValueError):
            bundle_bytes = 0
        if bundle_bytes <= 0:
            raise RuntimeError("UPDATE_BUNDLE_SIZE_MISSING: Gateway no informó un tamaño verificable")
        if bundle_bytes > MAX_SELF_UPDATE_BUNDLE_BYTES:
            raise RuntimeError(
                f"UPDATE_BUNDLE_TOO_LARGE: {bundle_bytes} > {MAX_SELF_UPDATE_BUNDLE_BYTES}; "
                "los componentes grandes se entregan mediante su flujo firmado explícito"
            )

        update_root = self.root / "updates" / version
        if update_root.exists():
            shutil.rmtree(update_root, ignore_errors=True)
        update_root.mkdir(parents=True, exist_ok=True)
        bundle = update_root / "agent-release.zip"
        platform_id = normalize_platform()
        arch = normalize_arch()
        self._status_update(
            update_state="DOWNLOADING", update_target_version=version,
            update_channel=self.update_channel, update_started_at=now_iso(), update_error="",
        )
        self.client.download_file(
            f"/api/v2/agent/releases/{platform_id}/{arch}/{self.update_channel}/{version}/bundle",
            bundle,
            timeout=max(120, self.timeout),
        )
        actual = sha256_file(bundle).lower()
        if actual != expected_sha:
            raise RuntimeError(f"UPDATE_SHA256_MISMATCH: expected={expected_sha} actual={actual}")
        if not verify_file(bundle, signature, Path(self.signing_public_key)):
            raise RuntimeError("UPDATE_SIGNATURE_INVALID: firma Ed25519 inválida")

        self._status_update(
            update_state="VERIFYING", update_target_version=version,
            update_bundle_sha256=actual, update_key_id=key_id,
        )

        extracted = update_root / "extracted"
        safe_extract(bundle, extracted)
        payload = extracted / "payload" if (extracted / "payload").is_dir() else extracted
        new_agent = payload / "gideon_agent.py"
        updater = payload / "gideon_agent_update.py"
        common_pkg = payload / "gideon_common" / "__init__.py"
        if not new_agent.is_file():
            raise RuntimeError("UPDATE_PAYLOAD_INVALID: gideon_agent.py no existe en el release")
        if not updater.is_file():
            raise RuntimeError("UPDATE_PAYLOAD_INVALID: gideon_agent_update.py no existe en el release")
        if not common_pkg.is_file():
            raise RuntimeError("UPDATE_PAYLOAD_INVALID: gideon_common no existe; actualización bloqueada")
        marker = f'VERSION = "{version}"'
        source = new_agent.read_text(encoding="utf-8-sig", errors="replace")
        if marker not in source:
            raise RuntimeError(f"UPDATE_VERSION_MISMATCH: el bundle {version} no contiene el Agent con esa versión")

        install_root = Path(__file__).resolve().parent
        service_kind, service_id = self._update_service_identity()
        args = [
            sys.executable, str(updater),
            "--install-root", str(install_root),
            "--payload", str(payload),
            "--data-root", str(self.root),
            "--current-pid", str(os.getpid()),
            "--version", version,
            "--service-kind", service_kind,
            "--service-id", service_id,
        ]
        kwargs: dict[str, Any] = {
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
        }
        tunnel = self.reverse_tunnel
        tunnel_quiesced = False
        if tunnel is not None:
            try:
                tunnel_quiesced = bool(tunnel.begin_update_quiesce())
            except Exception:
                tunnel_quiesced = False
            if not tunnel_quiesced:
                self._defer_update_busy(version, "ACTIVE_REMOTE_SESSION")
                return False
        try:
            if platform_id == "windows":
                kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "DETACHED_PROCESS", 0)
                subprocess.Popen(args, **kwargs)
            elif platform_id == "linux" and shutil.which("systemd-run"):
                # A transient unit is outside gideon-agent.service's cgroup, so it can
                # safely restart the Agent after the old PID exits.
                unit = f"gideon-agent-update-{os.getpid()}"
                subprocess.Popen(
                    ["systemd-run", "--quiet", "--collect", f"--unit={unit}"] + args,
                    **kwargs,
                )
            elif platform_id == "linux":
                raise RuntimeError(
                    "UPDATE_SYSTEMD_RUN_MISSING: la actualización automática Linux requiere systemd-run; "
                    "instale el paquete nativo manualmente para reparar/actualizar este host."
                )
            else:
                # macOS launchd and non-systemd Linux: detached updater survives the
                # normal Agent exit, replaces the runtime and then restarts service.
                kwargs["start_new_session"] = True
                subprocess.Popen(args, **kwargs)
        except Exception:
            if tunnel_quiesced and tunnel is not None:
                tunnel.cancel_update_quiesce()
            raise

        self.update_install_started = True
        self._status_update(
            status="UPDATING", update_target_version=version, update_channel=self.update_channel,
            update_approved=True, update_key_id=key_id, update_started_at=now_iso(),
            update_deferred_reason="", active_remote_streams=0,
            update_service_kind=service_kind, update_service_id=service_id,
        )
        self._log_event(f"Actualización estable aprobada {version} verificada y programada para {platform_id}")
        return True

    def check_version(self, *, force: bool = False) -> None:
        forced = bool(force or self._force_update_once)
        if not forced and time.monotonic() < self.next_version_check:
            return
        self._force_update_once = False
        self.next_version_check = time.monotonic() + max(60, int(self.update_cfg.get("check_seconds", 3600)))
        try:
            self._status_update(
                update_state="CHECKING", update_channel=self.update_channel,
                update_checked_at=now_iso(), update_error="",
            )
            path = (
                f"/api/v2/agent/release?platform={normalize_platform()}"
                f"&arch={normalize_arch()}&channel={self.update_channel}&current={VERSION}"
            )
            self.version_state = self.client.json("GET", path)
            release = self.version_state.get("Release") if isinstance(self.version_state.get("Release"), dict) else {}
            remote_state = str(self.version_state.get("Status") or "UNKNOWN").upper()
            if remote_state == "UPDATE_AVAILABLE":
                self._status_update(
                    update_state="UPDATE_PENDING",
                    available_update=str(release.get("version") or ""),
                    update_approval_state=str(release.get("approval_state") or ""),
                    update_channel=self.update_channel,
                )
                auto = bool(self.update_cfg.get("auto_install_approved", True))
                require_approved = bool(self.update_cfg.get("require_approved", True))
                approved = str(release.get("approval_state") or "").upper() == "APPROVED"
                should_install = bool(forced or auto) and (approved or not require_approved)
                if should_install and self._schedule_update(release):
                    # Exit cleanly; the detached updater replaces the files and then
                    # restarts the Scheduled Task. No concurrent old/new Agent.
                    raise SystemExit(0)
                if forced and should_install:
                    # A running Job is the only normal reason scheduling returns
                    # False. Retain the one-shot request and retry soon without
                    # interrupting endpoint work already in progress.
                    self._force_update_once = True
                    self.next_version_check = time.monotonic() + 30.0
                    self._status_update(
                        update_state="UPDATE_DEFERRED_BUSY", update_target_version=str(release.get("version") or ""),
                        update_checked_at=now_iso(),
                    )
            else:
                target = str(release.get("version") or "")
                self._status_update(
                    update_state=remote_state, update_target_version=target,
                    available_update="", update_approval_state=str(release.get("approval_state") or ""),
                    update_channel=self.update_channel, update_error="", update_checked_at=now_iso(),
                    update_completed_at=now_iso() if remote_state in {"CURRENT", "AHEAD"} else "",
                )
        except SystemExit:
            raise
        except Exception as exc:
            safe_exc = redact_error(f"{type(exc).__name__}: {exc}")
            safe_tb = redact_error(traceback.format_exc(), max_chars=12000)
            self.version_state = {"Status": "UNAVAILABLE", "Error": safe_exc, "CheckedAt": now_iso()}
            self._status_update(
                update_state="UPDATE_ERROR", update_error=safe_exc,
                last_error=safe_exc, last_error_at=now_iso(),
                last_error_component="GIDEONAgent", last_error_operation="update.check",
                last_error_traceback=safe_tb,
            )
            self._log_event(f"No se pudo comprobar/aplicar actualización: {safe_exc}", "WARN")

    def next_job(self) -> Optional[dict[str, Any]]:
        if self._offline_vlc_maintenance:
            return None
        response = self.client.json("GET", "/api/v1/agent/jobs/next")
        job = response.get("Job")
        return job if isinstance(job, dict) else None

    def _state_path(self, job_id: str) -> Path:
        return self.jobs_dir / job_id / "agent_state.json"

    def _read_state(self, job_id: str) -> dict[str, Any]:
        path = self._state_path(job_id)
        if not path.exists():
            return {}
        try:
            value = json.loads(path.read_text(encoding="utf-8-sig"))
            return value if isinstance(value, dict) else {}
        except Exception:
            return {}

    def _write_state(self, job_id: str, value: dict[str, Any]) -> None:
        value = dict(value)
        value["updated_at"] = now_iso()
        atomic_json(self._state_path(job_id), value)

    def _verify_package(self, package: Path, job: dict[str, Any]) -> None:
        expected = str(job.get("package_sha256") or "").lower()
        actual = sha256_file(package)
        if expected and actual != expected:
            raise RuntimeError(f"Package SHA256 mismatch expected={expected} actual={actual}")
        signature = str(job.get("package_signature") or "")
        if self.signature_required:
            if not signature:
                raise RuntimeError("PACKAGE_SIGNATURE_REQUIRED: gateway did not provide Ed25519 signature")
            if not self.signing_public_key:
                raise RuntimeError("PACKAGE_SIGNING_KEY_MISSING")
            if not verify_file(package, signature, Path(self.signing_public_key)):
                raise RuntimeError("PACKAGE_SIGNATURE_INVALID")

    def _read_replay_state(self) -> dict[str, Any]:
        if not self.replay_path.is_file():
            return {"jobs": {}}
        try:
            value = json.loads(self.replay_path.read_text(encoding="utf-8-sig"))
            return value if isinstance(value, dict) else {"jobs": {}}
        except Exception as exc:
            self._log_event(f"REPLAY_STATE_READ_WARNING: {type(exc).__name__}: {exc}", "WARN")
            return {"jobs": {}}

    def _remember_completed_job(self, job_id: str, job_root: Path) -> None:
        envelope_path = job_root / "agent_job.json"
        nonce = ""
        try:
            if envelope_path.is_file():
                value = json.loads(envelope_path.read_text(encoding="utf-8-sig"))
                if isinstance(value, dict):
                    nonce = str(value.get("Nonce") or "")
        except Exception as exc:
            self._log_event(f"REPLAY_ENVELOPE_READ_WARNING: {type(exc).__name__}: {exc}", "WARN")
        state = self._read_replay_state()
        jobs = state.get("jobs") if isinstance(state.get("jobs"), dict) else {}
        jobs[str(job_id)] = {"nonce": nonce, "completed_at": now_iso()}
        if len(jobs) > 2048:
            ordered = list(jobs.items())[-2048:]
            jobs = dict(ordered)
        atomic_json(self.replay_path, {"schema": 1, "jobs": jobs})

    def _verify_job_envelope(self, job_id: str, job_root: Path) -> None:
        path = job_root / "agent_job.json"
        if not path.is_file():
            if self.job_freshness_required:
                raise RuntimeError("JOB_ENVELOPE_REQUIRED")
            return
        value = json.loads(path.read_text(encoding="utf-8-sig"))
        if not isinstance(value, dict):
            raise RuntimeError("JOB_ENVELOPE_INVALID")
        value = validate_job_envelope(
            value,
            expected_job_id=job_id,
            expected_agent_id=self.agent_id,
            expected_site_code=self.site_code,
            expected_host_profile=str((getattr(self, "profile", {}) or {}).get("id") or ""),
            freshness_required=self.job_freshness_required,
        )

        # Content binding is checked again on the endpoint after extraction.
        # A valid outer ZIP signature is necessary, but the inner script hash
        # makes the exact payload visible in diagnostics and prevents accidental
        # path/collision mistakes in future producers.
        if str(value.get("JobType") or "").upper() == "SCRIPT_EXECUTION":
            for index, item in enumerate(value.get("Scripts") or [], 1):
                rel = str(item.get("Path") or "")
                script = (job_root / rel).resolve()
                if job_root.resolve() not in script.parents or not script.is_file():
                    raise RuntimeError(f"JOB_SCRIPT_MISSING: index={index} path={rel}")
                expected_sha = str(item.get("Sha256") or "").strip().lower()
                actual_sha = sha256_file(script).lower()
                if expected_sha != actual_sha:
                    raise RuntimeError(
                        f"JOB_SCRIPT_SHA256_MISMATCH: index={index} expected={expected_sha} actual={actual_sha}"
                    )

        nonce = str(value.get("Nonce") or "").strip()
        replay = self._read_replay_state()
        jobs = replay.get("jobs") if isinstance(replay.get("jobs"), dict) else {}
        previous = jobs.get(str(job_id))
        if isinstance(previous, dict):
            previous_nonce = str(previous.get("nonce") or "")
            if not nonce or not previous_nonce or previous_nonce == nonce:
                raise RuntimeError("JOB_REPLAY_REJECTED")

    def _job_capabilities(self) -> dict[str, Any]:
        allowed = sorted({str(x).lower() for x in self.profile.get("allowed_extensions", []) if str(x).strip()})
        return {
            "SignedJobs": True,
            "ScriptExecution": True,
            "ScriptExtensions": allowed,
            "FileTransfer": True,
            "Cancellation": True,
            "ResultUpload": True,
            "Freshness": bool(self.job_freshness_required),
            "ReplayProtection": True,
            "SelfUpdate": True,
            "DeviceRestart": True,
        }

    def _write_failure_result(self, job_id: str, job_root: Path, error: str) -> None:
        """Persist a minimal result package when failure happens before/around worker startup."""
        try:
            collection = job_root / "collection"
            collection.mkdir(parents=True, exist_ok=True)
            status = {
                "State": "FAILED",
                "JobId": job_id,
                "AgentId": self.agent_id,
                "SiteCode": self.site_code,
                "Error": error,
                "UpdatedAt": now_iso(),
                "CompletedAt": now_iso(),
            }
            atomic_json(job_root / "status.json", status)
            atomic_json(job_root / "progress.json", {
                "Type": "JOB_FAILED", "Phase": "FAILED", "Error": error, "UpdatedAt": now_iso(),
            })
            atomic_json(collection / "job_result.json", {
                "JobId": job_id,
                "AgentId": self.agent_id,
                "AgentName": self.agent_name,
                "Hostname": socket.gethostname(),
                "SiteCode": self.site_code,
                "SiteName": self.site_name,
                "Success": False,
                "Cancelled": False,
                "ScriptsTotal": 0,
                "ScriptsFailed": 0,
                "ScriptsSkipped": 0,
                "Results": [],
                "Error": error,
                "Platform": normalize_platform(),
                "Architecture": normalize_arch(),
                "AgentVersion": VERSION,
                "CompletedAt": now_iso(),
            })
        except Exception as exc:
            self._log_event(f"FAILURE_RESULT_WRITE_WARNING {job_id}: {type(exc).__name__}: {exc}", "WARN")

    def _download_prepare(self, job: dict[str, Any]) -> Path:
        job_id = str(job["job_id"])
        package = self.packages_dir / f"{job_id}.zip"
        self.client.download_file(
            f"/api/v1/agent/jobs/{job_id}/{self.agent_id}/package",
            package,
            timeout=max(60.0, self.timeout),
        )
        self._verify_package(package, job)
        job_root = self.jobs_dir / job_id
        if job_root.exists():
            shutil.rmtree(job_root, ignore_errors=True)
        safe_extract(package, job_root)
        try:
            self._verify_job_envelope(job_id, job_root)
        except Exception:
            shutil.rmtree(job_root, ignore_errors=True)
            raise
        self._write_state(job_id, {"status": "PREPARED", "package_sha256": sha256_file(package)})
        return job_root

    def _start_worker(self, job_id: str, job_root: Path) -> subprocess.Popen:
        generic = job_root / "gideon_agent_worker.py"
        legacy = job_root / "remote_job_worker.ps1"
        if generic.exists():
            cmd = [sys.executable, str(generic), "--job-root", str(job_root)]
        elif legacy.exists() and os.name == "nt":
            cmd = [
                "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass", "-File", str(legacy),
                "-JobRoot", str(job_root), "-TaskName", f"GIDEONAGENT_{job_id}_{self.agent_id[-8:]}",
            ]
        else:
            raise RuntimeError("AGENT_WORKER_NOT_COMPATIBLE_WITH_HOST")
        kwargs: dict[str, Any] = {
            "cwd": str(job_root),
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
        }
        if os.name == "nt":
            kwargs["creationflags"] = 0x08000000 | 0x00000200
        else:
            kwargs["start_new_session"] = True
        proc = subprocess.Popen(cmd, **kwargs)
        self._write_state(job_id, {"status": "RUNNING", "worker_pid": proc.pid, "started_at": now_iso(), "worker_command": cmd})
        return proc

    def _status_payload(self, job_id: str, job_root: Path, fallback_state: str = "RUNNING") -> dict[str, Any]:
        status_path = job_root / "status.json"
        progress_path = job_root / "progress.json"
        status: dict[str, Any] = {}
        progress: dict[str, Any] = {}
        try:
            if status_path.exists(): status = json.loads(status_path.read_text(encoding="utf-8-sig"))
        except Exception as exc:
            status = {"State": fallback_state, "Error": f"status read: {exc}"}
        try:
            if progress_path.exists(): progress = json.loads(progress_path.read_text(encoding="utf-8-sig"))
        except Exception:
            progress = {}
        state = str(status.get("State") or fallback_state).upper()
        return {
            "JobId": job_id,
            "AgentId": self.agent_id,
            "AgentName": self.agent_name,
            "SiteCode": self.site_code,
            "SiteName": self.site_name,
            "State": state,
            "TaskState": "Running" if state not in {"RESULT_READY","RESULT_READY_WITH_ERRORS","FAILED","CANCELLED"} else "Ready",
            "Status": status,
            "Progress": progress,
            "Transport": "AGENT_HTTPS_PULL",
            "AgentVersion": VERSION,
            "ProtocolVersion": PROTOCOL_VERSION,
            "HostProfile": self.profile.get("id"),
            "Platform": normalize_platform(),
            "Architecture": normalize_arch(),
            "Hostname": socket.gethostname(),
            "UpdatedAt": now_iso(),
            "Error": status.get("Error"),
        }

    def _cancel_requested(self, job_id: str) -> bool:
        try:
            return bool(self.client.json("GET", f"/api/v1/agent/jobs/{job_id}/cancel").get("CancelRequested"))
        except Exception:
            return False

    def _zip_result(self, job_id: str, job_root: Path) -> Path:
        out = self.packages_dir / f"{job_id}.result.zip"
        tmp = out.with_suffix(".result.zip.tmp")
        if tmp.exists(): tmp.unlink()
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as z:
            collection = job_root / "collection"
            if collection.exists():
                for p in collection.rglob("*"):
                    if p.is_file(): z.write(p, arcname=str(Path("collection") / p.relative_to(collection)))
            for name in ("status.json", "progress.json", "agent_job.json", "job.json"):
                p = job_root / name
                if p.exists(): z.write(p, arcname=name)
        os.replace(tmp, out)
        return out

    def _upload_result(self, job_id: str, job_root: Path) -> None:
        archive = self._zip_result(job_id, job_root)
        digest = sha256_file(archive)
        self.client.upload_file(
            "POST", f"/api/v1/agent/jobs/{job_id}/result", archive,
            headers={"X-GIDEON-SHA256": digest}, timeout=max(120.0, self.timeout),
        )
        self._write_state(job_id, {"status": "UPLOADED", "result_sha256": digest})
        self._remember_completed_job(job_id, job_root)

    def execute_job(self, job: dict[str, Any]) -> None:
        job_id = str(job.get("job_id") or "")
        if not job_id:
            return
        self.active_job_id = job_id
        terminal_state = "FAILED"
        terminal_error = ""
        self._status_update(
            status="BUSY",
            active_job_id=job_id,
            active_job_state="CLAIMING",
            last_error="",
        )
        self._log_event(f"Job {job_id} recibido para {self.agent_id}")
        try:
            claim = self.client.json("POST", f"/api/v1/agent/jobs/{job_id}/claim", {})
            if not bool(claim.get("Ok")):
                if bool(claim.get("Deferred")):
                    terminal_state = "DEFERRED"
                    retry = max(1.0, min(float(claim.get("RetryAfterSeconds") or 3), 15.0))
                    self._status_update(status="ACTIVE", active_job_id="", active_job_state="WAITING_FLEET_SLOT")
                    time.sleep(retry + random.uniform(0.0, 1.5))
                    return
                raise RuntimeError("JOB_CLAIM_REJECTED: " + str(claim.get("Reason") or "UNKNOWN"))
            if self._cancel_requested(job_id):
                terminal_state = "CANCELLED"
                self.client.json("POST", f"/api/v1/agent/jobs/{job_id}/status", {
                    "JobId": job_id, "AgentId": self.agent_id, "AgentName": self.agent_name,
                    "SiteCode": self.site_code, "SiteName": self.site_name,
                    "State": "CANCELLED", "TaskState": "Ready",
                    "Status": {"State": "CANCELLED", "Error": "CANCELLED_BEFORE_DOWNLOAD"},
                    "Progress": {}, "Transport": "AGENT_HTTPS_PULL",
                    "AgentVersion": VERSION, "ProtocolVersion": PROTOCOL_VERSION,
                    "HostProfile": self.profile.get("id"), "Platform": normalize_platform(),
                    "Architecture": normalize_arch(), "Hostname": socket.gethostname(),
                    "UpdatedAt": now_iso(), "Error": "CANCELLED_BEFORE_DOWNLOAD",
                })
                return
            state = self._read_state(job_id)
            job_root = self.jobs_dir / job_id
            if (job_root / "collection" / "job_result.json").exists():
                payload = self._status_payload(job_id, job_root, "RESULT_READY")
                terminal_state = str(payload.get("State") or "RESULT_READY").upper()
                self.client.json("POST", f"/api/v1/agent/jobs/{job_id}/status", payload)
                self._upload_result(job_id, job_root)
                return
            pid = int(state.get("worker_pid") or 0)
            if not (job_root.exists() and pid > 0 and process_alive(pid)):
                self._status_update(status="BUSY", active_job_id=job_id, active_job_state="DOWNLOADING")
                job_root = self._download_prepare(job)
                self._status_update(status="BUSY", active_job_id=job_id, active_job_state="STARTING")
                proc = self._start_worker(job_id, job_root)
                pid = proc.pid
            self._status_update(status="BUSY", active_job_id=job_id, active_job_state="RUNNING", active_worker_pid=pid)
            next_status = 0.0
            next_cancel_check = 0.0
            next_heartbeat = 0.0
            cancel_written = False
            cancel_deadline = 0.0
            force_killed = False
            while process_alive(pid):
                now = time.monotonic()
                if now >= next_status:
                    self.client.json("POST", f"/api/v1/agent/jobs/{job_id}/status", self._status_payload(job_id, job_root))
                    next_status = now + self.status_seconds
                # Un Job largo no debe volver al Agent 'offline': mantenemos el
                # heartbeat en paralelo a los reportes de progreso.
                if now >= next_heartbeat:
                    self.heartbeat()
                    self._status_update(status="BUSY", active_job_id=job_id, active_job_state="RUNNING", active_worker_pid=pid)
                    next_heartbeat = now + 30.0 + random.uniform(-3.0, 3.0)
                if now >= next_cancel_check or cancel_written:
                    next_cancel_check = now + max(1.0, min(self.status_seconds, 5.0))
                    if self._cancel_requested(job_id):
                        if not cancel_written:
                            (job_root / "cancel.request").write_text(f"RequestedAt={now_iso()}", encoding="utf-8")
                            cancel_written = True
                            cancel_deadline = time.monotonic() + self.cancel_grace_seconds
                            self._status_update(status="BUSY", active_job_id=job_id, active_job_state="CANCELLING")
                        elif time.monotonic() >= cancel_deadline:
                            kill_tree(pid)
                            force_killed = True
                            break
                time.sleep(1.0)
            # Reap the short-lived worker before publishing the terminal
            # status.  This prevents a zombie PID from keeping active_job_id
            # alive across heartbeat cycles on Linux/Raspberry Pi.
            reap_process(pid)
            fallback_state = "CANCELLED" if (force_killed or cancel_written) else "FAILED"
            payload = self._status_payload(job_id, job_root, fallback_state)
            if force_killed:
                payload["State"] = "CANCELLED"
                payload.setdefault("Status", {})["State"] = "CANCELLED"
            terminal_state = str(payload.get("State") or fallback_state).upper()
            terminal_error = str(payload.get("Error") or "")
            self.client.json("POST", f"/api/v1/agent/jobs/{job_id}/status", payload)
            if (job_root / "collection" / "job_result.json").exists():
                self._status_update(status="BUSY", active_job_id=job_id, active_job_state="UPLOADING")
                self._upload_result(job_id, job_root)
            else:
                self._write_state(job_id, {"status": "FAILED_NO_RESULT", "worker_pid": pid})
                if terminal_state not in {"CANCELLED"}:
                    terminal_state = "FAILED_NO_RESULT"
        except Exception as exc:
            terminal_state = "FAILED"
            terminal_error = f"{type(exc).__name__}: {exc}"
            self._log_event(f"Job {job_id} falló: {terminal_error}", "ERROR")
            # Fail closed, but never leave the Gateway row stranded in CLAIMED.
            # Package/signature/freshness/worker-start errors are Job failures,
            # not Agent-service failures; after reporting them the Agent remains
            # healthy and continues consuming the queue.
            try:
                failure_root = self.jobs_dir / job_id
                failure_root.mkdir(parents=True, exist_ok=True)
                self._write_failure_result(job_id, failure_root, terminal_error)
                self.client.json("POST", f"/api/v1/agent/jobs/{job_id}/status", {
                    "JobId": job_id,
                    "AgentId": self.agent_id,
                    "AgentName": self.agent_name,
                    "SiteCode": self.site_code,
                    "SiteName": self.site_name,
                    "State": "FAILED",
                    "TaskState": "Ready",
                    "Status": {"State": "FAILED", "Error": terminal_error},
                    "Progress": {"Type": "JOB_FAILED", "Phase": "FAILED"},
                    "Transport": "AGENT_HTTPS_PULL",
                    "AgentVersion": VERSION,
                    "ProtocolVersion": PROTOCOL_VERSION,
                    "HostProfile": self.profile.get("id"),
                    "Platform": normalize_platform(),
                    "Architecture": normalize_arch(),
                    "Hostname": socket.gethostname(),
                    "UpdatedAt": now_iso(),
                    "Error": terminal_error,
                })
                # Best-effort result upload gives WebAdmin a downloadable forensic
                # bundle even when execution never reached the worker.
                try:
                    self._upload_result(job_id, failure_root)
                except Exception as upload_exc:
                    self._log_event(
                        f"No se pudo subir result FAILED para {job_id}: {type(upload_exc).__name__}: {upload_exc}",
                        "WARN",
                    )
            except Exception as report_exc:
                self._log_event(
                    f"No se pudo reportar FAILED para {job_id}: {type(report_exc).__name__}: {report_exc}",
                    "WARN",
                )
            return
        finally:
            self.active_job_id = ""
            self._status_update(
                status="ACTIVE",
                active_job_id="",
                active_job_state="",
                active_worker_pid=0,
                last_job_id=job_id,
                last_job_state=terminal_state,
                last_job_finished_at=now_iso(),
                last_job_error=terminal_error,
            )
            self._log_event(f"Job {job_id} finalizó con estado {terminal_state}")

    def connect_once_with_failover(self) -> None:
        """Enroll/heartbeat using every configured endpoint once, without sleeping.

        Installer self-tests use this path so a temporarily unavailable primary
        does not make a valid multi-endpoint package look broken.
        """
        start = self.connectivity.reset_after_network_change()
        self._activate_endpoint(start, reason="one-shot-start")
        last_exc: AgentHttpError | None = None
        for _ in range(len(self.connectivity.endpoints)):
            try:
                self.enroll()
                self._ensure_mtls_identity()
                self.heartbeat(update_local_status=not self.suppress_local_status)
                return
            except AgentHttpError as exc:
                last_exc = exc
                self.connectivity.record_failure(self.base_url)
                next_url = self.connectivity.next_after_failure()
                if not next_url:
                    break
                self._activate_endpoint(next_url, reason=self._connectivity_error_state(exc))
        if last_exc is not None:
            raise last_exc
        raise AgentHttpError("No hay endpoints disponibles para validar el Gateway.")

    def run_forever(self) -> None:
        self._status_update(
            status="CONNECTING", connectivity_state="CONNECTING", gateway_connected=False, started_at=now_iso(),
            active_job_id="", active_job_state="", last_gateway_error="", last_error="",
            network=self._network_snapshot.as_dict(),
        )
        self._log_event(
            f"Agent {VERSION} iniciado · {self.agent_name} · {self.site_code} · {self.agent_id} · "
            f"mode={self.connectivity.mode} · endpoints={len(self.connectivity.endpoints)}"
        )
        next_heartbeat = 0.0
        while True:
            try:
                # Enrollment is deliberately inside the resilient loop.  A first
                # boot with the primary endpoint down must fail over/retry rather
                # than terminate the service or require reinstallation.
                if self._check_network_change():
                    next_heartbeat = 0.0
                if not self.token:
                    self._status_update(status="CONNECTING", connectivity_state="ENDPOINT_TEST", gateway_connected=False)
                    self.enroll()
                    next_heartbeat = 0.0
                if time.monotonic() >= next_heartbeat:
                    self._ensure_mtls_identity()
                    self.check_version()
                    self.heartbeat()
                    next_heartbeat = time.monotonic() + 30 + random.uniform(-3.0, 3.0)
                job = self.next_job()
                if job:
                    self.execute_job(job)
                else:
                    time.sleep(max(1.0, self.poll_seconds * random.uniform(0.80, 1.25)))
            except KeyboardInterrupt:
                self._stop_reverse_tunnel()
                self.local_wayland_console_bridge.stop()
                self._status_update(status="STOPPING", connectivity_state="STOPPING", gateway_connected=False)
                self._log_event("Agent detenido por solicitud local")
                return
            except AgentHttpError as exc:
                delay = self._handle_connectivity_failure(exc)
                print(f"[{now_iso()}] gateway unavailable: {redact_error(exc)}")
                if delay is None:
                    # Another configured endpoint is ready; do not penalize it
                    # with the global backoff.  The next loop probes immediately.
                    next_heartbeat = 0.0
                    continue
                time.sleep(delay)
                self._resume_after_retry_wait()
                next_heartbeat = 0.0
            except Exception as exc:
                detail = redact_error(f"{type(exc).__name__}: {exc}")
                safe_tb = redact_error(traceback.format_exc(), max_chars=12000)
                self._status_update(
                    status="ERROR", connectivity_state="ERROR", last_error=detail,
                    last_error_at=now_iso(), last_error_component="GIDEONAgent",
                    last_error_operation="runtime.loop", last_error_traceback=safe_tb,
                )
                self._log_event(f"Error del Agent: {detail}", "ERROR")
                print(f"[{now_iso()}] agent error: {redact_error(detail)}")
                # Non-network failures retain a bounded delay but do not mutate
                # Agent identity or force re-enrollment.
                time.sleep(5.0)



def _gateway_transport_preflight(agent: "Agent") -> dict[str, Any]:
    """Validate DNS, TCP and TLS before enrollment without touching Agent identity.

    The authenticated API check remains the real enroll/heartbeat operation.  This
    preflight exists to make installer failures actionable instead of collapsing
    DNS/TCP/TLS/API problems into a generic rc=20.
    """
    parsed = urlsplit(str(agent.base_url or "").strip())
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise RuntimeError(f"PREFLIGHT_URL: Gateway inválido para Agent: {agent.base_url!r}")

    host = str(parsed.hostname)
    port = int(parsed.port or 443)
    timeout = min(max(float(getattr(agent, "timeout", 5.0) or 5.0), 1.0), 6.0)
    started = time.monotonic()
    try:
        rows = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        addresses = sorted({str(row[4][0]) for row in rows if row and len(row) >= 5 and row[4]})
    except Exception as exc:
        raise RuntimeError(f"PREFLIGHT_DNS: {host}: {type(exc).__name__}: {exc}") from exc
    dns_ms = max(0, int((time.monotonic() - started) * 1000))

    started = time.monotonic()
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
    except Exception as exc:
        raise RuntimeError(f"PREFLIGHT_TCP: {host}:{port}: {type(exc).__name__}: {exc}") from exc
    tcp_ms = max(0, int((time.monotonic() - started) * 1000))

    tls_version = ""
    cipher = ""
    try:
        started = time.monotonic()
        if bool(getattr(agent, "verify_tls", True)):
            cafile = str(agent.ca_file) if getattr(agent, "ca_file", None) else None
            ctx = ssl.create_default_context(cafile=cafile)
        else:
            ctx = ssl._create_unverified_context()  # noqa: SLF001 - explicit config compatibility

        minimum = str(getattr(agent, "minimum_tls", "TLSv1.2") or "TLSv1.2").upper().replace(" ", "")
        if minimum in {"TLSV1.3", "TLS1.3"} and hasattr(ssl.TLSVersion, "TLSv1_3"):
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        elif hasattr(ssl.TLSVersion, "TLSv1_2"):
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        cert = getattr(agent, "client_cert", None)
        key = getattr(agent, "client_key", None)
        if cert and key:
            ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))

        with raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                tls_version = str(tls.version() or "")
                selected = tls.cipher()
                cipher = str(selected[0]) if selected else ""
        tls_ms = max(0, int((time.monotonic() - started) * 1000))
    except Exception as exc:
        try:
            raw.close()
        except Exception:
            pass
        raise RuntimeError(f"PREFLIGHT_TLS: {host}:{port}: {type(exc).__name__}: {exc}") from exc

    return {
        "Gateway": f"https://{host}:{port}",
        "DNS": {"Ok": True, "Addresses": addresses[:8], "ElapsedMs": dns_ms},
        "TCP": {"Ok": True, "ElapsedMs": tcp_ms},
        "TLS": {"Ok": True, "Version": tls_version, "Cipher": cipher, "ElapsedMs": tls_ms},
    }



def _self_test_category(exc: Exception) -> str:
    text = f"{type(exc).__name__}: {exc}".casefold()
    if "preflight_dns" in text:
        return "DNS"
    if "preflight_tcp" in text:
        return "CONNECTIVITY"
    if "preflight_tls" in text:
        return "TLS_CERTIFICATE"
    if "preflight_url" in text:
        return "CONFIGURATION"
    if "tls_ca_missing" in text or "tls_ca_integrity" in text:
        return "TLS_CA_LOCAL"
    if "unable to get local issuer" in text or "unable to get issuer" in text:
        return "TLS_CA_MISMATCH"
    if "ip address mismatch" in text or "hostname mismatch" in text:
        return "TLS_HOSTNAME"
    if "certificate has expired" in text or "certificate expired" in text:
        return "TLS_EXPIRED"
    if "certificate_verify_failed" in text or "sslcertverificationerror" in text:
        return "TLS_CERTIFICATE"
    if "http 403" in text or "credential invalid" in text or "enrollment" in text and "secret" in text:
        return "ENROLLMENT"
    if "http 401" in text or "authentication failed" in text:
        return "AUTHENTICATION"
    if "connectionrefused" in text or "timed out" in text or "timeouterror" in text or "unreachable" in text:
        return "CONNECTIVITY"
    if "no such file" in text or "filenotfounderror" in text:
        return "LOCAL_FILE"
    return "AGENT_STARTUP"


def main() -> int:
    parser=argparse.ArgumentParser(description="GIDEON Cross-Platform Agent")
    parser.add_argument("--config",type=Path,default=default_data_dir()/"agent.json")
    parser.add_argument("--once",action="store_true")
    parser.add_argument("--self-test",action="store_true",help="Enroll + heartbeat only; never consumes queued jobs.")
    parser.add_argument("--version",action="store_true")
    parser.add_argument("--session-switch-helper",action="store_true",help=argparse.SUPPRESS)
    parser.add_argument("--request-id",default="",help=argparse.SUPPRESS)
    parser.add_argument("--active-user",default="",help=argparse.SUPPRESS)
    parser.add_argument("--requested-user",default="",help=argparse.SUPPRESS)
    parser.add_argument("--timeout",default="35",help=argparse.SUPPRESS)
    args=parser.parse_args()
    if args.session_switch_helper:
        return run_session_switch_helper(sys.argv[1:])
    if args.version:
        print(f"GIDEON Agent {VERSION} protocol {PROTOCOL_VERSION} {normalize_platform()}/{normalize_arch()}"); return 0

    # Installer-facing self-test must be machine-readable and must never dump a
    # raw traceback into the setup UI. Full detail is preserved in Error/Type;
    # the Windows/Linux/macOS setup layers persist it to their installation log.
    if args.self_test:
        stage = "startup"
        agent = None
        preflight: dict[str, Any] = {}
        try:
            agent = Agent(args.config)
            # The transport preflight is deliberately identity-neutral: it only
            # proves DNS -> TCP -> TLS. The API itself is then proven by
            # enroll/heartbeat below.
            stage = "preflight"
            preflight = _gateway_transport_preflight(agent)
            stage = "enrollment/heartbeat"
            # El self-test valida el Gateway pero no debe sobrescribir el PID/
            # heartbeat del servicio real en agent.status.json.
            agent.suppress_local_status = True
            agent.connect_once_with_failover()
            print(json.dumps({
                "Ok": True,
                "Stage": "complete",
                "AgentId": agent.agent_id,
                "SiteCode": agent.site_code,
                "AgentName": agent.agent_name,
                "Gateway": agent.base_url,
                "Preflight": preflight,
            }, ensure_ascii=False))
            return 0
        except Exception as exc:
            payload = {
                "Ok": False,
                "Stage": stage,
                "Category": _self_test_category(exc),
                "Type": type(exc).__name__,
                "Error": redact_error(str(exc), max_chars=2000),
                "Gateway": str(getattr(agent, "base_url", "") or ""),
                "Preflight": preflight,
            }
            print(json.dumps(payload, ensure_ascii=False), file=sys.stderr)
            return 20

    agent=Agent(args.config)
    if args.once:
        # One-shot/installer probes may discover a release, but never replace files
        # while the installation transaction is still open.
        agent.update_cfg["auto_install_approved"] = False
        agent.connect_once_with_failover()
        agent.check_version(); job=agent.next_job();
        if job: agent.execute_job(job)
        return 0
    agent.run_forever(); return 0

if __name__ == "__main__": raise SystemExit(main())
