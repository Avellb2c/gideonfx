from __future__ import annotations

from typing import Any
from .models import ValidationReport
from .transport_profiles import VALID_TRANSPORT_PROFILES, normalize_transport_profile

_REQUIRED_PATHS = {
    "known_hosts", "results_dir", "raw_dir", "fanout_jobs_dir",
    "script_library_dir", "packages_dir",
}


def validate_config(cfg: dict[str, Any]) -> ValidationReport:
    report = ValidationReport()
    if not isinstance(cfg, dict):
        report.errors.append("config.json no contiene un objeto JSON.")
        return report

    for section in ("ssh", "paths", "fanout", "adaptive_vpn", "gui", "connectivity"):
        if not isinstance(cfg.get(section), dict):
            report.errors.append(f"Falta sección obligatoria: {section}")

    if report.errors:
        return report

    ssh = cfg["ssh"]
    fanout = cfg["fanout"]
    paths = cfg["paths"]
    vpn = cfg["adaptive_vpn"]
    gui = cfg["gui"]
    connectivity = cfg["connectivity"]

    if not str(ssh.get("user") or "").strip():
        report.errors.append("ssh.user no puede estar vacío.")
    if not str(ssh.get("key_path") or "").strip():
        report.errors.append("ssh.key_path no puede estar vacío.")
    port = int(ssh.get("port", 22) or 22)
    if not 1 <= port <= 65535:
        report.errors.append("ssh.port fuera de rango 1..65535.")

    missing_paths = sorted(k for k in _REQUIRED_PATHS if not paths.get(k))
    if missing_paths:
        report.errors.append("paths incompletos: " + ", ".join(missing_paths))

    try:
        selected_transport = normalize_transport_profile(
            fanout.get("transport_profile")
        )
        if selected_transport not in VALID_TRANSPORT_PROFILES:
            report.errors.append(
                "fanout.transport_profile no es válido."
            )
    except Exception as exc:
        report.errors.append(
            f"fanout.transport_profile inválido: {exc}"
        )

    if str(fanout.get("control_transport", "ssh")).lower() != "ssh":
        report.errors.append(
            "fanout.control_transport debe permanecer en 'ssh'."
        )

    for key in ("dispatch_workers", "poll_workers", "cancel_workers"):
        value = int(fanout.get(key, 1) or 1)
        if not 1 <= value <= 64:
            report.errors.append(f"fanout.{key} debe estar entre 1 y 64.")

    poll = int(fanout.get("poll_interval_seconds", 15) or 15)
    if poll < 5:
        report.warnings.append("poll_interval_seconds < 5 puede generar demasiadas conexiones SSH.")

    min_w = int(vpn.get("min_workers", 1) or 1)
    normal_w = int(vpn.get("normal_workers", min_w) or min_w)
    max_w = int(vpn.get("max_workers", normal_w) or normal_w)
    if not (1 <= min_w <= normal_w <= max_w):
        report.errors.append("adaptive_vpn requiere min_workers <= normal_workers <= max_workers.")

    hot = float(gui.get("hot_refresh_seconds", 2) or 2)
    if hot < 1:
        report.warnings.append("gui.hot_refresh_seconds < 1 puede generar I/O local innecesario.")


    if float(connectivity.get("probe_timeout_seconds", 2) or 2) <= 0:
        report.errors.append("connectivity.probe_timeout_seconds debe ser > 0.")
    if int(connectivity.get("sample_targets", 5) or 5) < 1:
        report.errors.append("connectivity.sample_targets debe ser >= 1.")

    if fanout.get("cancel_unload_ssh_agent") is True:
        report.warnings.append("cancel_unload_ssh_agent=true puede afectar otros Jobs/sesiones.")

    return report


def require_valid_config(cfg: dict[str, Any]) -> None:
    report = validate_config(cfg)
    if report.errors:
        raise ValueError("Configuración GIDEON inválida: " + " | ".join(report.errors))
