from __future__ import annotations

"""Local GIDEON Agent inspection helpers.

Read-only diagnostics live outside Qt so the Installed Agents page remains a
presentation layer. No secret values are returned by this module.
"""

import datetime as dt
import json
import os
from pathlib import Path
import shutil
import sys
from typing import Any

from gideon_infrastructure.subprocess_utils import run_hidden
from gideon_gateway_bootstrap import GATEWAY_CONFIG_PATH


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def candidate_roots() -> list[Path]:
    if os.name == "nt":
        values = [
            Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "GIDEONAgent",
            Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "GIDEONAgent",
        ]
    elif sys.platform == "darwin":
        values = [Path("/Library/Application Support/GIDEONAgent")]
    else:
        values = [Path("/opt/gideon-agent"), Path("/var/lib/gideon-agent")]
    result: list[Path] = []
    for value in values:
        if value not in result:
            result.append(value)
    return result


def _service_state() -> str:
    try:
        if os.name == "nt":
            exe = shutil.which("schtasks.exe") or shutil.which("schtasks")
            if not exe:
                return "schtasks no disponible"
            proc = run_hidden([exe, "/Query", "/TN", "GIDEONAgent", "/FO", "LIST", "/V"], check=False, capture_output=True, text=True, timeout=15)
            if proc.returncode != 0:
                return "Tarea GIDEONAgent no registrada"
            text = (proc.stdout or "").strip()
            for line in text.splitlines():
                low = line.casefold()
                if "status" in low or "estado" in low:
                    return line.split(":", 1)[-1].strip() or "Registrada"
            return "Registrada"
        if sys.platform == "darwin":
            proc = run_hidden(["launchctl", "print", "system/pe.com.gideons.gideonagent"], check=False, capture_output=True, text=True, timeout=15)
            return "Cargado" if proc.returncode == 0 else "LaunchDaemon no cargado"
        proc = run_hidden(["systemctl", "is-active", "gideon-agent.service"], check=False, capture_output=True, text=True, timeout=15)
        return (proc.stdout or "").strip() or ("activo" if proc.returncode == 0 else "inactivo")
    except Exception as exc:
        return f"No se pudo consultar: {type(exc).__name__}"


def inspect_local_agent(app_root: Path | None = None) -> dict[str, Any]:
    root = next((p for p in candidate_roots() if (p / "gideon_agent.py").is_file()), None)
    checks: list[dict[str, Any]] = []
    if root is None:
        return {
            "ok": False,
            "installed": False,
            "title": "Agente local no encontrado",
            "summary": "No se encontró una instalación GIDEON Agent en las rutas estándar de este sistema.",
            "checks": [{"ok": False, "name": "Instalación", "detail": "No encontrada"}],
        }

    cfg_path = root / "agent.json"
    cfg = _load_json(cfg_path)
    configured_data = str(cfg.get("data_dir") or "").strip()
    data_root = Path(os.path.expandvars(configured_data)) if configured_data else root
    runtime_path = data_root / "agent.runtime.json"
    status_path = data_root / "agent.status.json"
    runtime = _load_json(runtime_path)
    status = _load_json(status_path)

    checks.append({"ok": cfg_path.is_file(), "name": "Configuración", "detail": str(cfg_path)})
    code = str(cfg.get("site_code") or "").strip()
    site = str(cfg.get("site_name") or "").strip()
    agent_name = str(cfg.get("agent_name") or "").strip()
    base = str((cfg.get("control_plane") or {}).get("base_url") or "").strip()
    checks.append({"ok": bool(code and site and agent_name), "name": "Identidad", "detail": f"{agent_name or '-'} · {code or '-'} · {site or '-'}"})
    checks.append({"ok": base.lower().startswith("https://"), "name": "Gateway configurado", "detail": base or "Vacío"})
    if app_root is not None:
        console_cfg = _load_json(GATEWAY_CONFIG_PATH)
        console_gateway = str(console_cfg.get("public_url") or "").strip().rstrip("/")
        if console_gateway:
            same_gateway = base.rstrip("/") == console_gateway
            checks.append({"ok": same_gateway, "name": "Mismo Gateway que la consola", "detail": console_gateway if same_gateway else f"Agente={base or '-'} · Consola={console_gateway}"})

    token_present = bool(str(runtime.get("agent_token") or "").strip())
    checks.append({"ok": token_present, "name": "Enrolamiento", "detail": "Token de agente presente" if token_present else "SIN token: el agente no completó /api/v1/agent/enroll"})

    last = str(status.get("last_heartbeat") or "").strip()
    checks.append({"ok": bool(last), "name": "Heartbeat local", "detail": last or "Nunca registrado"})
    service = _service_state()
    service_ok = not any(x in service.casefold() for x in ("no registrada", "no cargado", "inactivo", "failed", "error"))
    checks.append({"ok": service_ok, "name": "Servicio / tarea", "detail": service})

    ca_value = str((cfg.get("control_plane") or {}).get("ca_file") or "").strip()
    ca_path = (root / ca_value).resolve() if ca_value and not Path(ca_value).is_absolute() else Path(ca_value) if ca_value else None
    ca_ok = bool(ca_path and ca_path.is_file())
    checks.append({"ok": ca_ok, "name": "CA TLS", "detail": str(ca_path) if ca_path else "No configurada"})

    ok = all(bool(c.get("ok")) for c in checks)
    if not token_present:
        summary = "El agente está instalado, pero no quedó enrolado. La causa más probable es una credencial bootstrap ausente/incorrecta o un fallo TLS/Gateway durante la instalación."
    elif not last:
        summary = "El agente está enrolado, pero todavía no dejó heartbeat local. Revise la tarea/servicio y conectividad al Gateway."
    elif not service_ok:
        summary = "El agente tiene identidad/token, pero su servicio o tarea no está activo."
    else:
        summary = "La instalación local tiene identidad, token y heartbeat. Si no aparece en la tabla, pulse Actualizar y valide que la consola consulte el mismo Gateway configurado en el agente."
    return {
        "ok": ok,
        "installed": True,
        "title": "Agente local correcto" if ok else "Agente local requiere atención",
        "summary": summary,
        "root": str(root),
        "site_code": code,
        "site_name": site,
        "agent_name": agent_name,
        "gateway": base,
        "checks": checks,
    }
