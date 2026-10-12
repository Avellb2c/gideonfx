from __future__ import annotations

"""P7 diagnostic presentation helpers for GIDEON Web Admin."""

import datetime as dt
import json
from typing import Any
from urllib.parse import urlsplit

from gideon_common.redaction import redact, redact_error

STATE_EXPLANATIONS: dict[str, str] = {
    "ONLINE": "El Agent mantiene heartbeat autenticado con el Gateway.",
    "OFFLINE": "El Gateway no ha recibido heartbeat dentro del tiempo esperado.",
    "CONNECTING": "El Agent está intentando establecer su primera conexión.",
    "CONNECTED": "La ruta actual hacia el Gateway está operativa.",
    "RECONNECTING": "Se agotaron temporalmente los endpoints y el Agent reintentará automáticamente.",
    "NETWORK_CHANGED": "El Agent detectó un cambio de interfaz, IP, gateway o DNS y está recalculando la ruta.",
    "DNS_REFRESH": "El Agent está resolviendo nuevamente los nombres de los endpoints configurados.",
    "ENDPOINT_TEST": "El Agent está probando un endpoint del Gateway.",
    "GATEWAY_UNREACHABLE": "No se pudo establecer la conexión de red con el Gateway.",
    "DNS_ERROR": "No se pudo resolver el nombre del Gateway.",
    "TLS_ERROR": "La conexión TLS/certificado no pudo validarse correctamente.",
    "AUTH_ERROR": "El Gateway rechazó la autenticación del Agent.",
    "ENROLLMENT_ERROR": "El primer enrolamiento del Agent no pudo completarse.",
    "CONFIG_ERROR": "La configuración central no pudo validarse o aplicarse.",
    "UPDATE_PENDING": "Existe una actualización del Agent pendiente.",
    "UPDATE_ERROR": "La actualización del Agent produjo un error.",
    "ROLLED_BACK": "La configuración nueva falló y el Agent restauró automáticamente la anterior.",
    "REJECTED": "El Agent rechazó una configuración antes de aplicarla.",
    "ERROR": "El Agent reportó un error no clasificado.",
    "UNKNOWN": "No existe información suficiente para determinar el estado técnico.",
}

ERROR_STATES = {
    "OFFLINE", "GATEWAY_UNREACHABLE", "DNS_ERROR", "TLS_ERROR", "AUTH_ERROR",
    "ENROLLMENT_ERROR", "CONFIG_ERROR", "UPDATE_ERROR", "ERROR", "REJECTED", "ROLLED_BACK",
}
WARNING_STATES = {"CONNECTING", "RECONNECTING", "NETWORK_CHANGED", "DNS_REFRESH", "ENDPOINT_TEST", "UPDATE_PENDING"}


def _parse_iso(value: Any) -> dt.datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        return dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except Exception:
        return None


def heartbeat_age_seconds(last_seen: Any, *, now: dt.datetime | None = None) -> float | None:
    stamp = _parse_iso(last_seen)
    if stamp is None:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=dt.timezone.utc)
    reference = now or dt.datetime.now(stamp.tzinfo)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=stamp.tzinfo)
    return max(0.0, (reference.astimezone(stamp.tzinfo) - stamp).total_seconds())


def effective_state(agent: dict[str, Any], *, ttl_seconds: int = 90, now: dt.datetime | None = None) -> dict[str, Any]:
    age = heartbeat_age_seconds(agent.get("last_seen"), now=now)
    diagnostics = agent.get("Diagnostics") if isinstance(agent.get("Diagnostics"), dict) else {}
    state_block = diagnostics.get("state") if isinstance(diagnostics.get("state"), dict) else {}
    technical = str(state_block.get("connectivity_state") or state_block.get("status") or agent.get("status") or "UNKNOWN").upper()
    if age is None or age > max(5, int(ttl_seconds)):
        code = "OFFLINE"
    elif technical in {"CONNECTED", "ACTIVE", "BUSY", "ONLINE"}:
        code = "ONLINE"
    else:
        code = technical if technical in STATE_EXPLANATIONS else "ONLINE"
    css = "danger" if code in ERROR_STATES else "warning" if code in WARNING_STATES else "success" if code == "ONLINE" else "info"
    return {
        "code": code,
        "technical": technical,
        "description": STATE_EXPLANATIONS.get(code, STATE_EXPLANATIONS["UNKNOWN"]),
        "css": css,
        "heartbeat_age_seconds": round(age, 1) if age is not None else None,
    }


def build_agent_diagnostic(agent: dict[str, Any], config_info: dict[str, Any] | None = None, *, ttl_seconds: int = 90) -> dict[str, Any]:
    diagnostics = agent.get("Diagnostics") if isinstance(agent.get("Diagnostics"), dict) else {}
    diagnostics = redact(diagnostics)
    config_info = config_info if isinstance(config_info, dict) else {}
    desired = config_info.get("Configuration") if isinstance(config_info.get("Configuration"), dict) else {}
    cfg_status = config_info.get("Status") if isinstance(config_info.get("Status"), dict) else {}
    state = effective_state(agent, ttl_seconds=ttl_seconds)

    network = diagnostics.get("network") if isinstance(diagnostics.get("network"), dict) else {}
    gateway = diagnostics.get("gateway") if isinstance(diagnostics.get("gateway"), dict) else {}
    current_endpoint = str(gateway.get("current_endpoint") or "")
    configured_endpoint = str(gateway.get("configured_endpoint") or "")
    endpoint_for_port = current_endpoint or configured_endpoint
    gateway_port: int | None = None
    if endpoint_for_port:
        try:
            parsed_endpoint = urlsplit(endpoint_for_port)
            gateway_port = parsed_endpoint.port or (443 if parsed_endpoint.scheme.lower() == "https" else 80 if parsed_endpoint.scheme.lower() == "http" else None)
        except Exception:
            gateway_port = None
    checks = diagnostics.get("checks") if isinstance(diagnostics.get("checks"), dict) else {}
    timestamps = diagnostics.get("timestamps") if isinstance(diagnostics.get("timestamps"), dict) else {}
    config_diag = diagnostics.get("configuration") if isinstance(diagnostics.get("configuration"), dict) else {}
    update_diag = diagnostics.get("update") if isinstance(diagnostics.get("update"), dict) else {}
    error_diag = diagnostics.get("error_record") if isinstance(diagnostics.get("error_record"), dict) else {}

    report = {
        "GeneratedAt": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "Agent": {
            "AgentId": str(agent.get("agent_id") or ""),
            "SiteCode": str(agent.get("site_code") or ""),
            "SiteName": str(agent.get("site_name") or ""),
            "AgentName": str(agent.get("agent_name") or ""),
            "Hostname": str(agent.get("hostname") or ""),
            "Platform": str(agent.get("platform") or ""),
            "Architecture": str(agent.get("architecture") or ""),
            "HostProfile": str(agent.get("host_profile") or ""),
            "AgentVersion": str(agent.get("agent_version") or ""),
            "ProtocolVersion": str(agent.get("protocol_version") or ""),
            "EnrolledAt": str(agent.get("enrolled_at") or ""),
        },
        "State": {
            "Code": state["code"],
            "TechnicalState": state["technical"],
            "Description": state["description"],
            "LastHeartbeat": str(agent.get("last_seen") or timestamps.get("last_heartbeat") or ""),
            "HeartbeatAgeSeconds": state["heartbeat_age_seconds"],
        },
        "Network": {
            "Interfaces": list(network.get("interfaces") or []),
            "LocalIPs": list(network.get("local_ips") or []),
            "SourceIP": str(network.get("source_ip") or ""),
            "ObservedRemoteIP": str(agent.get("last_remote_ip") or network.get("gateway_observed_ip") or ""),
            "DefaultGateway": str(network.get("default_gateway") or ""),
            "DNSServers": list(network.get("dns_servers") or []),
        },
        "Gateway": {
            "ConfiguredEndpoint": configured_endpoint,
            "CurrentEndpoint": current_endpoint,
            "LastKnownGoodEndpoint": str(gateway.get("last_known_good_endpoint") or ""),
            "ConnectivityMode": str(gateway.get("connectivity_mode") or ""),
            "Port": gateway_port,
            "LatencyMs": gateway.get("latency_ms"),
            "Candidates": list(gateway.get("candidates") or []),
        },
        "Checks": {
            "DNS": checks.get("dns") or {"status": "UNKNOWN", "detail": "Sin datos"},
            "TCP": checks.get("tcp") or {"status": "UNKNOWN", "detail": "Sin datos"},
            "TLS": checks.get("tls") or {"status": "UNKNOWN", "detail": "Sin datos"},
            "API": checks.get("api") or {"status": "UNKNOWN", "detail": "Sin datos"},
            "Authentication": checks.get("authentication") or {"status": "UNKNOWN", "detail": "Sin datos"},
        },
        "Configuration": {
            "LocalVersion": int(config_diag.get("local_version") or (cfg_status.get("applied_version") or 0)),
            "DesiredVersion": int(desired.get("version") or agent.get("DesiredConfigVersion") or 0),
            "State": str(cfg_status.get("status") or config_diag.get("state") or "UNKNOWN"),
            "ReportedAt": str(cfg_status.get("reported_at") or ""),
            "Detail": redact_error(cfg_status.get("detail") or config_diag.get("last_error") or ""),
        },
        "Update": {
            "State": str(update_diag.get("state") or "UNKNOWN"),
            "TargetVersion": str(update_diag.get("target_version") or ""),
            "Channel": str(update_diag.get("channel") or ""),
            "LastError": redact_error(update_diag.get("last_error") or ""),
            "RequestId": str(update_diag.get("request_id") or ""),
            "RequestedAt": str(update_diag.get("requested_at") or ""),
            "CheckedAt": str(update_diag.get("checked_at") or ""),
            "StartedAt": str(update_diag.get("started_at") or ""),
            "UpdatedAt": str(update_diag.get("updated_at") or ""),
            "CompletedAt": str(update_diag.get("completed_at") or ""),
        },
        "Timestamps": {
            "LastNetworkChange": str(timestamps.get("last_network_change") or ""),
            "LastDNSRefresh": str(timestamps.get("last_dns_refresh") or ""),
            "LastGatewayAttempt": str(timestamps.get("last_gateway_attempt") or ""),
            "LastGatewaySuccess": str(timestamps.get("last_gateway_success") or ""),
        },
        "ErrorRecord": {
            "Timestamp": str(error_diag.get("timestamp") or ""),
            "Component": str(error_diag.get("component") or "GIDEONAgent"),
            "Operation": str(error_diag.get("operation") or ""),
            "Error": redact_error(error_diag.get("error") or diagnostics.get("last_error") or cfg_status.get("detail") or ""),
            "Traceback": redact_error(error_diag.get("traceback") or "", max_chars=12000),
            "AgentId": str(error_diag.get("agent_id") or agent.get("agent_id") or ""),
            "Gateway": str(error_diag.get("gateway") or current_endpoint or configured_endpoint or ""),
            "Version": str(error_diag.get("version") or agent.get("agent_version") or ""),
        },
        "LastError": redact_error(diagnostics.get("last_error") or cfg_status.get("detail") or ""),
    }
    return redact(report)


def diagnostic_text(report: dict[str, Any]) -> str:
    """Human-readable complete diagnostic suitable for clipboard/support tickets."""
    report = redact(report)
    lines: list[str] = []
    lines.append("GIDEON REMOTE CONTROL - DIAGNÓSTICO DE AGENT")
    lines.append("=" * 62)
    lines.append(f"Generado: {report.get('GeneratedAt') or '-'}")
    for section in ("Agent", "State", "Network", "Gateway", "Checks", "Configuration", "Update", "Timestamps", "ErrorRecord"):
        lines.append("")
        lines.append(section.upper())
        lines.append("-" * len(section))
        value = report.get(section) or {}
        if section == "Checks" and isinstance(value, dict):
            for name, check in value.items():
                if isinstance(check, dict):
                    detail = str(check.get("detail") or "")
                    elapsed = f" · {check.get('elapsed_ms')} ms" if check.get("elapsed_ms") not in (None, "") else ""
                    lines.append(f"{name}: {check.get('status') or 'UNKNOWN'}{elapsed} · {detail}")
                else:
                    lines.append(f"{name}: {check}")
            continue
        if isinstance(value, dict):
            for key, item in value.items():
                if isinstance(item, (dict, list)):
                    shown = json.dumps(item, ensure_ascii=False, sort_keys=True)
                else:
                    shown = str(item if item not in (None, "") else "-")
                lines.append(f"{key}: {shown}")
    lines.append("")
    lines.append("ÚLTIMO ERROR")
    lines.append("------------")
    lines.append(str(report.get("LastError") or "Sin error reportado"))
    lines.append("")
    lines.append("Nota: contraseñas, tokens, secretos MFA, bootstrap y claves privadas se omiten automáticamente.")
    return redact_error("\n".join(lines), max_chars=50000) + "\n"


__all__ = [
    "STATE_EXPLANATIONS", "ERROR_STATES", "WARNING_STATES", "heartbeat_age_seconds",
    "effective_state", "build_agent_diagnostic", "diagnostic_text",
]
