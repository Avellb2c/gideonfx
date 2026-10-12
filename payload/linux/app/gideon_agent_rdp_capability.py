from __future__ import annotations

"""Secret-free RDP listener capability detection for GIDEON Agents.

Windows registry/service state is authoritative for the local endpoint.  Other
platforms expose only a conservative TCP observation so WebAdmin can keep its
normal negotiation fallback.  This module never reads accounts or credentials.
"""

import datetime as dt
import os
import platform
import re
import socket
import subprocess
import time
from typing import Any


RDP_CAPABILITY_SCHEMA = "gideon-rdp-capability/v1"
RDP_SECURITY_NAMES = {0: "rdp", 1: "negotiate", 2: "tls"}
WTS_SESSION_STATES = {
    0: "ACTIVE", 1: "CONNECTED", 2: "CONNECT_QUERY", 3: "SHADOW",
    4: "DISCONNECTED", 5: "IDLE", 6: "LISTEN", 7: "RESET",
    8: "DOWN", 9: "INITIALIZING",
}


def _now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def recommend_rdp_security(
    *, supported: bool, enabled: bool, service_running: bool,
    ready: bool, nla_required: bool | None, security_layer: int | None,
) -> tuple[str, bool, str]:
    """Return preferred FreeRDP mode, legacy permission and explanation."""
    if not supported:
        return "", False, "La edición del sistema no ofrece un servidor RDP compatible."
    if not enabled:
        return "", False, "El listener RDP está deshabilitado en el sistema."
    if not service_running:
        return "", False, "TermService no está en ejecución."
    if not ready:
        return "", False, "El puerto RDP local no responde."
    if nla_required is True:
        return "nla", False, "Windows exige NLA/CredSSP."
    if security_layer == 2:
        return "tls", False, "Windows exige la capa TLS del listener RDP."
    if security_layer == 0 and nla_required is False:
        return "rdp", True, "Windows declara explícitamente la capa RDP heredada sin NLA."
    if security_layer == 1:
        return "any", False, "Windows permite negociar automáticamente la capa de seguridad."
    return "any", False, "El listener responde, pero la política exacta no pudo determinarse."


def _windows_registry_snapshot() -> dict[str, Any]:
    try:
        import winreg  # type: ignore
    except Exception:
        return {}

    def read(path: str, name: str) -> Any:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
                return winreg.QueryValueEx(key, name)[0]
        except OSError:
            return None

    terminal = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
    listener = terminal + r"\WinStations\RDP-Tcp"
    current = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    product_options = r"SYSTEM\CurrentControlSet\Control\ProductOptions"
    thumbprint = read(listener, "SSLCertificateSHA1Hash")
    if isinstance(thumbprint, bytes):
        thumbprint = thumbprint.hex().upper()
    elif thumbprint is not None:
        thumbprint = str(thumbprint).replace(" ", "").upper()[:80]
    return {
        "deny_connections": read(terminal, "fDenyTSConnections"),
        "nla_required": read(listener, "UserAuthentication"),
        "security_layer": read(listener, "SecurityLayer"),
        "min_encryption_level": read(listener, "MinEncryptionLevel"),
        "listener_port": read(listener, "PortNumber"),
        "certificate_thumbprint": thumbprint or "",
        "product_name": read(current, "ProductName"),
        "edition_id": read(current, "EditionID"),
        "installation_type": read(current, "InstallationType"),
        "product_type": read(product_options, "ProductType"),
        "display_version": read(current, "DisplayVersion") or read(current, "ReleaseId"),
        "build": read(current, "CurrentBuildNumber"),
    }


def _windows_agent_session_id() -> int | None:
    """Return the Agent process session without inspecting user credentials."""
    try:
        import ctypes

        session_id = ctypes.c_ulong()
        ok = ctypes.windll.kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(session_id))
        return int(session_id.value) if ok else None
    except Exception:
        return None


def _windows_active_console() -> dict[str, Any]:
    """Read the physical console identity through documented WTS APIs."""
    try:
        import ctypes

        session_id = int(ctypes.windll.kernel32.WTSGetActiveConsoleSessionId())
        if session_id == 0xFFFFFFFF:
            return {"SessionId": None, "Connected": False, "User": "", "Domain": ""}
        wts = ctypes.windll.wtsapi32
        wts.WTSQuerySessionInformationW.argtypes = [
            ctypes.c_void_p, ctypes.c_ulong, ctypes.c_int,
            ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_ulong),
        ]
        wts.WTSQuerySessionInformationW.restype = ctypes.c_int
        wts.WTSFreeMemory.argtypes = [ctypes.c_void_p]
        wts.WTSFreeMemory.restype = None

        def text_value(info_class: int) -> str:
            buffer = ctypes.c_void_p()
            size = ctypes.c_ulong()
            if not wts.WTSQuerySessionInformationW(
                ctypes.c_void_p(0), ctypes.c_ulong(session_id), info_class,
                ctypes.byref(buffer), ctypes.byref(size),
            ):
                return ""
            try:
                return str(ctypes.wstring_at(buffer) or "")[:256]
            finally:
                wts.WTSFreeMemory(buffer)

        user = text_value(5)  # WTSUserName
        domain = text_value(7)  # WTSDomainName
        return {
            "SessionId": session_id,
            "Connected": bool(user),
            "User": user,
            "Domain": domain,
        }
    except Exception:
        return {"SessionId": None, "Connected": False, "User": "", "Domain": ""}


def _windows_sessions() -> list[dict[str, Any]]:
    """Enumerate bounded, secret-free WTS session state for handoff diagnosis."""
    try:
        import ctypes
        from ctypes import wintypes

        class WTS_SESSION_INFOW(ctypes.Structure):
            _fields_ = [
                ("SessionId", wintypes.DWORD),
                ("pWinStationName", wintypes.LPWSTR),
                ("State", ctypes.c_int),
            ]

        wts = ctypes.windll.wtsapi32
        pointer = ctypes.POINTER(WTS_SESSION_INFOW)()
        count = wintypes.DWORD()
        wts.WTSEnumerateSessionsW.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
            ctypes.POINTER(ctypes.POINTER(WTS_SESSION_INFOW)), ctypes.POINTER(wintypes.DWORD),
        ]
        wts.WTSEnumerateSessionsW.restype = wintypes.BOOL
        wts.WTSQuerySessionInformationW.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, ctypes.c_int,
            ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD),
        ]
        wts.WTSQuerySessionInformationW.restype = wintypes.BOOL
        wts.WTSFreeMemory.argtypes = [ctypes.c_void_p]
        wts.WTSFreeMemory.restype = None
        if not wts.WTSEnumerateSessionsW(None, 0, 1, ctypes.byref(pointer), ctypes.byref(count)):
            return []

        def query_text(session_id: int, info_class: int) -> str:
            buffer = ctypes.c_void_p()
            size = wintypes.DWORD()
            if not wts.WTSQuerySessionInformationW(None, session_id, info_class, ctypes.byref(buffer), ctypes.byref(size)):
                return ""
            try:
                return str(ctypes.wstring_at(buffer) or "")[:256]
            finally:
                wts.WTSFreeMemory(buffer)

        rows: list[dict[str, Any]] = []
        try:
            for index in range(min(int(count.value), 32)):
                item = pointer[index]
                session_id = int(item.SessionId)
                rows.append({
                    "SessionId": session_id,
                    "Station": str(item.pWinStationName or "")[:80],
                    "State": WTS_SESSION_STATES.get(int(item.State), f"UNKNOWN_{int(item.State)}"),
                    "User": query_text(session_id, 5),  # WTSUserName
                    "Domain": query_text(session_id, 7),  # WTSDomainName
                    "Client": query_text(session_id, 10),  # WTSClientName
                })
        finally:
            wts.WTSFreeMemory(pointer)
        return rows
    except Exception:
        return []


def _windows_termservice_running() -> bool | None:
    try:
        completed = subprocess.run(
            ["sc.exe", "query", "TermService"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=4,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
        )
        if completed.returncode != 0:
            return False
        # The label is localized, but the SCM numeric RUNNING state is always 4.
        return bool(re.search(r":\s*4(?:\s|$)", completed.stdout or ""))
    except Exception:
        return None


def _tcp_ready(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=1.0):
            return True
    except Exception:
        return False


def detect_rdp_capability(
    *, target_host: str = "127.0.0.1", target_port: int = 3389,
    system_name: str | None = None, registry_snapshot: dict[str, Any] | None = None,
    service_running: bool | None = None, socket_ready: bool | None = None,
) -> dict[str, Any]:
    """Detect local RDP policy without attempting authentication."""
    system = str(system_name or platform.system()).strip().lower()
    host = str(target_host or "127.0.0.1").strip()
    requested_port = max(1, min(int(target_port or 3389), 65535))
    captured_unix = int(time.time())

    if system != "windows":
        ready = _tcp_ready(host, requested_port) if socket_ready is None else bool(socket_ready)
        return {
            "Schema": RDP_CAPABILITY_SCHEMA,
            "DetectedAt": _now_iso(),
            "DetectedAtUnix": captured_unix,
            "Platform": system or "unknown",
            "Applicable": True,
            "Supported": ready,
            "Usable": ready,
            "Ready": ready,
            "ListenerPort": requested_port,
            "NlaRequired": None,
            "SecurityLayer": None,
            "SecurityLayerName": "unknown",
            "RecommendedSecurity": "any" if ready else "",
            "AllowLegacyRdp": False,
            "Confidence": "low",
            "Source": "local-tcp-probe",
            "Reason": "El listener local responde; el sistema no expone la política RDP de Windows." if ready else "No se detectó un listener RDP local.",
        }

    snapshot = dict(registry_snapshot) if isinstance(registry_snapshot, dict) else _windows_registry_snapshot()

    def as_int(name: str) -> int | None:
        try:
            value = snapshot.get(name)
            return None if value is None else int(value)
        except (TypeError, ValueError):
            return None

    edition = str(snapshot.get("edition_id") or "").strip()
    edition_key = edition.casefold()
    product_name = str(snapshot.get("product_name") or "").strip()
    product_type = str(snapshot.get("product_type") or "").strip()
    installation_type = str(snapshot.get("installation_type") or "").strip()
    server_host = product_type.casefold() in {"servernt", "lanmannt"} or "windows server" in product_name.casefold()
    agent_session_id = _windows_agent_session_id()
    active_console = _windows_active_console()
    sessions = _windows_sessions()
    supported = not (edition_key.startswith("core") or edition_key in {"starter", "home", "homesinglelanguage"})
    deny = as_int("deny_connections")
    nla_value = as_int("nla_required")
    nla_required = None if nla_value is None else nla_value == 1
    security_layer = as_int("security_layer")
    listener_port = as_int("listener_port") or requested_port
    listener_port = max(1, min(listener_port, 65535))
    running_observation = _windows_termservice_running() if service_running is None else bool(service_running)
    ready = _tcp_ready(host, listener_port) if socket_ready is None else bool(socket_ready)
    enabled = deny == 0 if deny is not None else ready
    running = ready if running_observation is None else bool(running_observation)
    preferred, allow_legacy, reason = recommend_rdp_security(
        supported=supported,
        enabled=enabled,
        service_running=running,
        ready=ready,
        nla_required=nla_required,
        security_layer=security_layer,
    )
    usable = bool(preferred)
    confidence = "high" if deny is not None and nla_required is not None and security_layer in RDP_SECURITY_NAMES else "medium" if ready else "low"
    return {
        "Schema": RDP_CAPABILITY_SCHEMA,
        "DetectedAt": _now_iso(),
        "DetectedAtUnix": captured_unix,
        "Platform": "windows",
        "Applicable": True,
        "Supported": supported,
        "Usable": usable,
        "Ready": ready,
        "ListenerEnabled": enabled,
        "ServiceRunning": running,
        "ListenerPort": listener_port,
        "NlaRequired": nla_required,
        "SecurityLayer": security_layer,
        "SecurityLayerName": RDP_SECURITY_NAMES.get(security_layer, "unknown"),
        "MinEncryptionLevel": as_int("min_encryption_level"),
        "CertificateThumbprint": str(snapshot.get("certificate_thumbprint") or "")[:80],
        "RecommendedSecurity": preferred,
        "AllowLegacyRdp": allow_legacy,
        "Confidence": confidence,
        "Source": "windows-registry-service-and-local-tcp",
        "Reason": reason,
        "SessionModel": {
            "Kind": "multi-session-capable" if server_host else "single-interactive-session",
            "ConcurrentSessionsPossible": server_host,
            "ConcurrentSessionsLicensed": None,
            "ResumeSameUserSession": True,
            "AdministrativeConsole": True,
            # RDP transfers an interactive desktop; it does not mirror the
            # physical console like an assistance/screen-capture component.
            "InteractiveScreenSharing": False,
            "AgentSessionId": agent_session_id,
            "AgentRunsAsService": agent_session_id == 0,
            "UnattendedAgent": agent_session_id == 0,
            "ActiveConsole": active_console,
            "Sessions": sessions,
            "ActiveSessionCount": sum(1 for row in sessions if row.get("State") == "ACTIVE"),
            "DisconnectedSessionCount": sum(1 for row in sessions if row.get("State") == "DISCONNECTED"),
        },
        "Windows": {
            "ProductName": product_name[:160],
            "EditionId": edition[:80],
            "InstallationType": installation_type[:80],
            "ProductType": product_type[:80],
            "DisplayVersion": str(snapshot.get("display_version") or "")[:80],
            "Build": str(snapshot.get("build") or "")[:40],
        },
    }


__all__ = ["RDP_CAPABILITY_SCHEMA", "detect_rdp_capability", "recommend_rdp_security"]
