from __future__ import annotations

"""Strict selection of Agent-reported RDP negotiation capabilities."""

import datetime as dt
import time
from typing import Any


RDP_CAPABILITY_SCHEMA = "gideon-rdp-capability/v1"
SAFE_SECURITY_MODES = frozenset({"any", "nla", "tls"})


def select_agent_remote_profile(agent: dict[str, Any]) -> dict[str, Any]:
    """Normalize the authenticated Agent remote-access advertisement.

    RDP capability detection is intentionally Windows-specific, while the
    reverse tunnel is platform independent.  Linux/xrdp and Raspberry Pi
    Agents therefore need a small generic profile so the UI does not silently
    fall back to ``RDP automático`` or a stale direct IP.
    """
    capabilities = agent.get("Capabilities") if isinstance(agent, dict) else None
    remote = capabilities.get("RemoteAccess") if isinstance(capabilities, dict) else None
    if not isinstance(remote, dict):
        return {
            "known": False, "ready": None, "supported": True, "protocol": "RDP",
            "protocols": ["RDP"], "port": 3389, "server": "", "reason": "",
            "file_transfer": False,
            "file_transfer_reason": "El Agent no publicó capacidad de transferencia; se requiere una señal explícita.",
        }
    protocol = str(remote.get("Protocol") or "").strip().upper()
    protocols: list[str] = []
    if protocol in {"RDP", "VNC"}:
        protocols.append(protocol)
    for candidate in ("RDP", "VNC"):
        nested = remote.get(candidate)
        if isinstance(nested, dict) and bool(nested.get("Usable", nested.get("Ready", False))):
            if candidate not in protocols:
                protocols.append(candidate)
    if not protocols:
        # A configured but not-yet-ready service is still the only valid choice;
        # expose it in the UI with its actual reason instead of offering both
        # protocols and letting Guacamole fail after the tunnel opens.
        if protocol in {"RDP", "VNC"}:
            protocols = [protocol]
        else:
            protocols = ["RDP"]
            protocol = "RDP"
    selected = protocol if protocol in protocols else protocols[0]
    ports: dict[str, int] = {}
    servers: dict[str, str] = {}
    ready_by_protocol: dict[str, bool] = {}
    password_required: dict[str, bool] = {}
    session_kinds: dict[str, str] = {}
    for candidate in protocols:
        nested = remote.get(candidate) if isinstance(remote.get(candidate), dict) else {}
        default_port = 5900 if candidate == "VNC" else 3389
        raw_port = nested.get("TargetPort")
        if raw_port in {None, ""} and candidate == protocol:
            raw_port = remote.get("TargetPort")
        try:
            ports[candidate] = max(1, min(int(raw_port or default_port), 65535))
        except (TypeError, ValueError):
            ports[candidate] = default_port
        servers[candidate] = str(
            nested.get("Server") or (remote.get("Server") if candidate == protocol else "") or ""
        )[:80]
        ready_by_protocol[candidate] = bool(
            nested.get("Usable", nested.get("Ready", remote.get("Ready") if candidate == protocol else False))
        )
        password_required[candidate] = bool(nested.get("PasswordRequired", True))
        session_kinds[candidate] = str(nested.get("SessionKind") or "")[:80]
    port = ports[selected]
    known = "Protocol" in remote or "Ready" in remote or "SupportState" in remote
    ready = bool(ready_by_protocol.get(selected, remote.get("Ready")))
    supported = bool(remote.get("Supported", True)) and str(remote.get("SupportState") or "").lower() != "unsupported"
    reason = str(remote.get("SupportReason") or remote.get("SupportDetail") or remote.get("Error") or "")[:300]
    transfer = remote.get("FileTransfer") if isinstance(remote.get("FileTransfer"), dict) else {}
    # Legacy Agents did not publish this field.  Keep their sessions usable,
    # but do not claim Linux/xrdp drive support without xrdp-chansrv.
    transfer_known = bool(transfer) or str(remote.get("Server") or "").casefold() in {"windows-rdp", "windows"}
    file_transfer = bool(transfer.get("Ready", transfer.get("Supported", False))) if transfer else transfer_known and str(remote.get("Server") or "").casefold() in {"windows-rdp", "windows"}
    file_transfer_reason = str(transfer.get("Reason") or "")[:300]
    return {
        "known": known, "ready": ready, "supported": supported, "protocol": selected,
        "protocols": protocols, "port": port, "server": servers.get(selected, ""),
        "ports": ports, "servers": servers, "ready_by_protocol": ready_by_protocol,
        "password_required": password_required, "session_kinds": session_kinds,
        "physical_console": any(kind == "physical-console" for kind in session_kinds.values()),
        "reason": reason, "file_transfer": selected == "RDP" and ready and supported and file_transfer,
        "file_transfer_reason": file_transfer_reason,
    }


def _observed_age_seconds(value: Any, now_unix: int) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return max(0, now_unix - int(parsed.timestamp()))
    except (TypeError, ValueError, OverflowError):
        return None


def select_agent_rdp_profile(
    agent: dict[str, Any], *, fallback_security: str = "nla",
    max_age_seconds: int = 180, allow_policy_legacy: bool = False,
    now_unix: int | None = None,
) -> dict[str, Any]:
    """Return a fail-closed RDP preference from an authenticated heartbeat.

    The Gateway's ``last_seen`` timestamp is authoritative for freshness; an
    endpoint clock is not trusted.  Legacy RDP is accepted only when the Agent
    explicitly observed it or WebAdmin policy deliberately enables it.
    """
    now = int(time.time() if now_unix is None else now_unix)
    fallback = str(fallback_security or "nla").strip().lower()
    if fallback not in SAFE_SECURITY_MODES:
        fallback = "nla"
    result = {
        "valid": False,
        "preferred_security": fallback,
        "allow_legacy_rdp": bool(allow_policy_legacy),
        "source": "webadmin-default",
        "reason": "El Agent todavía no publicó una detección RDP vigente.",
        "confidence": "none",
        "nla_required": None,
        "security_layer": "unknown",
        "listener_port": 3389,
        "observed_age_seconds": None,
        "product_name": "",
        "session_model": "unknown",
        "concurrent_sessions_possible": False,
        "concurrent_sessions_licensed": None,
        "resume_same_user_session": True,
        "administrative_console": True,
        "interactive_screen_sharing": False,
        "agent_background_ready": False,
        "active_console_session_id": None,
        "active_console_user": "",
        "active_console_domain": "",
        "sessions": [],
        "active_session_count": 0,
        "disconnected_session_count": 0,
    }
    capabilities = agent.get("Capabilities") if isinstance(agent, dict) else None
    remote = capabilities.get("RemoteAccess") if isinstance(capabilities, dict) else None
    rdp = remote.get("RDP") if isinstance(remote, dict) else None
    if not isinstance(rdp, dict) or str(rdp.get("Schema") or "") != RDP_CAPABILITY_SCHEMA:
        return result
    age = _observed_age_seconds(agent.get("last_seen"), now)
    result["observed_age_seconds"] = age
    if age is None or age > max(30, min(int(max_age_seconds or 180), 900)):
        result["reason"] = "La detección RDP del Agent está vencida; se utilizará la política segura del servidor."
        return result
    if not bool(agent.get("reverse_tunnel_online")):
        result["reason"] = "El túnel del Agent no está ONLINE; no se confiará en su detección para esta sesión."
        return result
    preferred = str(rdp.get("RecommendedSecurity") or "").strip().lower()
    reported_legacy = bool(rdp.get("AllowLegacyRdp"))
    if preferred == "rdp" and not (reported_legacy or allow_policy_legacy):
        result["reason"] = "El Agent reportó RDP heredado sin autorización verificable."
        return result
    if preferred not in SAFE_SECURITY_MODES | {"rdp"} or not bool(rdp.get("Usable")):
        result["reason"] = str(rdp.get("Reason") or "El listener RDP reportado no está listo.")[:300]
        return result
    try:
        listener_port = max(1, min(int(rdp.get("ListenerPort") or 3389), 65535))
    except (TypeError, ValueError):
        listener_port = 3389
    windows = rdp.get("Windows") if isinstance(rdp.get("Windows"), dict) else {}
    product_name = str(windows.get("ProductName") or "")[:160]
    product_type = str(windows.get("ProductType") or "").casefold()
    reported_model = rdp.get("SessionModel") if isinstance(rdp.get("SessionModel"), dict) else {}
    server_host = (
        product_type in {"servernt", "lanmannt"}
        or "windows server" in product_name.casefold()
        or str(reported_model.get("Kind") or "") == "multi-session-capable"
    )
    session_model = str(reported_model.get("Kind") or ("multi-session-capable" if server_host else "single-interactive-session"))
    concurrent_possible = bool(reported_model.get("ConcurrentSessionsPossible", server_host))
    unattended_reported = reported_model.get("UnattendedAgent")
    active_console = reported_model.get("ActiveConsole") if isinstance(reported_model.get("ActiveConsole"), dict) else {}
    reported_sessions = reported_model.get("Sessions") if isinstance(reported_model.get("Sessions"), list) else []
    sessions = []
    for item in reported_sessions[:32]:
        if not isinstance(item, dict):
            continue
        try:
            session_id = int(item.get("SessionId"))
        except (TypeError, ValueError):
            continue
        sessions.append({
            "session_id": session_id,
            "station": str(item.get("Station") or "")[:80],
            "state": str(item.get("State") or "UNKNOWN")[:40],
            "user": str(item.get("User") or "")[:256],
            "domain": str(item.get("Domain") or "")[:256],
            "client": str(item.get("Client") or "")[:256],
        })
    # Older Agents already run as SCM services but did not publish the field.
    # An authenticated, fresh heartbeat plus an ONLINE reverse tunnel is direct
    # evidence that the resident process is available without a browser user.
    unattended_ready = bool(agent.get("reverse_tunnel_online")) and (
        True if unattended_reported is None else bool(unattended_reported)
    )
    result.update({
        "valid": True,
        "preferred_security": preferred,
        "allow_legacy_rdp": bool(allow_policy_legacy or reported_legacy),
        "source": str(rdp.get("Source") or "agent-heartbeat")[:120],
        "reason": str(rdp.get("Reason") or "Detección RDP vigente del Agent.")[:300],
        "confidence": str(rdp.get("Confidence") or "unknown")[:40],
        "nla_required": rdp.get("NlaRequired"),
        "security_layer": str(rdp.get("SecurityLayerName") or "unknown")[:40],
        "listener_port": listener_port,
        "product_name": product_name,
        "session_model": session_model,
        "concurrent_sessions_possible": concurrent_possible,
        "concurrent_sessions_licensed": reported_model.get("ConcurrentSessionsLicensed"),
        "resume_same_user_session": bool(reported_model.get("ResumeSameUserSession", True)),
        "administrative_console": bool(reported_model.get("AdministrativeConsole", True)),
        "interactive_screen_sharing": bool(reported_model.get("InteractiveScreenSharing", False)),
        "agent_background_ready": unattended_ready,
        "active_console_session_id": active_console.get("SessionId"),
        "active_console_user": str(active_console.get("User") or "")[:256],
        "active_console_domain": str(active_console.get("Domain") or "")[:256],
        "sessions": sessions,
        "active_session_count": sum(1 for row in sessions if row.get("state") == "ACTIVE"),
        "disconnected_session_count": sum(1 for row in sessions if row.get("state") == "DISCONNECTED"),
    })
    return result


__all__ = ["RDP_CAPABILITY_SCHEMA", "select_agent_rdp_profile", "select_agent_remote_profile"]
