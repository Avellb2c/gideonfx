from __future__ import annotations

import argparse
import atexit
import datetime as dt
import getpass
import hashlib
import json
import logging
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from gideon_agent_display_capability import detect_display_capability

TRAY_VERSION = "1.1.0"

_LOG = logging.getLogger(__name__)
DEFAULT_REFRESH_SECONDS = 5
DEFAULT_HEARTBEAT_STALE_SECONDS = 75
DISPLAY_CAPABILITY_FILE = "display-session-capability.json"
DISPLAY_CAPABILITY_INTERVAL_SECONDS = 15.0

STATUS_META = {
    "ACTIVE": ("Activo", (44, 180, 92, 255)),
    "BUSY": ("Ejecutando trabajo", (41, 128, 235, 255)),
    "UPDATING": ("Actualizando Agent", (126, 87, 194, 255)),
    "CONNECTING": ("Conectando", (240, 180, 41, 255)),
    "NO_GATEWAY": ("Sin conexión al Gateway", (232, 132, 36, 255)),
    "ERROR": ("Error del Agent", (214, 55, 55, 255)),
    "STOPPED": ("Agent detenido", (190, 49, 49, 255)),
    "UNKNOWN": ("Estado desconocido", (117, 117, 117, 255)),
}


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def _load_config(path: Path) -> dict[str, Any]:
    return _load_json(path)


def _expand_path(value: Any, base: Path) -> Path | None:
    if not value:
        return None
    p = Path(os.path.expandvars(str(value)))
    if not p.is_absolute():
        p = base / p
    return p


def _data_root(cfg_path: Path, cfg: dict[str, Any]) -> Path:
    configured = str(cfg.get("data_dir") or "").strip()
    if configured:
        return Path(os.path.expandvars(configured))
    if os.name == "nt":
        return Path(os.path.expandvars(r"%PROGRAMDATA%\GIDEONAgent"))
    if sys.platform == "darwin":
        return Path("/Library/Application Support/GIDEONAgent")
    return Path("/var/lib/gideon-agent")


def _display_capability_temp_path(cfg_path: Path, cfg: dict[str, Any]) -> Path:
    """Return a non-secret fallback shared by the desktop tray and service."""
    runtime = _load_json(_data_root(cfg_path, cfg) / "agent.runtime.json")
    identity = str(runtime.get("agent_id") or cfg.get("agent_id") or cfg_path).strip()
    digest = hashlib.sha256(identity.casefold().encode("utf-8", "ignore")).hexdigest()[:16]
    return Path(tempfile.gettempdir()) / f"gideon-agent-display-{digest}.json"


def _bounded_display_capability(value: Any) -> dict[str, Any]:
    """Keep the tray-to-service report small, public and data-only."""
    raw = value if isinstance(value, dict) else {}
    session_raw = raw.get("Session") if isinstance(raw.get("Session"), dict) else {}
    session = {
        "Available": bool(session_raw.get("Available")),
        "Type": str(session_raw.get("Type") or "unknown")[:48],
        "Interactive": bool(session_raw.get("Interactive")),
    }
    outputs: list[dict[str, Any]] = []
    for item in list(raw.get("Outputs") or [])[:16]:
        if not isinstance(item, dict):
            continue
        output = {
            "OutputKey": str(item.get("OutputKey") or item.get("Key") or "")[:128],
            "Connector": str(item.get("Connector") or "")[:64],
            "Index": int(item.get("Index") or len(outputs) + 1),
            "Connected": bool(item.get("Connected")),
            "Enabled": bool(item.get("Enabled", item.get("Connected"))),
            "Primary": bool(item.get("Primary")),
            "Physical": bool(item.get("Physical", True)),
            "Virtual": bool(item.get("Virtual", False)),
            "TargetKind": str(item.get("TargetKind") or "")[:48],
            "Width": int(item.get("Width") or 0),
            "Height": int(item.get("Height") or 0),
            "RefreshHz": str(item.get("RefreshHz") or "")[:16],
            "Orientation": str(item.get("Orientation") or "")[:24],
            "ResolutionSource": str(item.get("ResolutionSource") or "")[:48],
            "OutputIdentity": str(item.get("OutputIdentity") or "")[:128],
            "OutputIdentitySource": str(item.get("OutputIdentitySource") or "")[:48],
        }
        if output["Width"] > 0 and output["Height"] > 0:
            outputs.append(output)
    return {
        "Schema": "gideon-display-capability/v1",
        "Supported": bool(raw.get("Supported")),
        "State": str(raw.get("State") or "UNAVAILABLE")[:32],
        "DetectedAt": str(raw.get("DetectedAt") or "")[:64],
        "Session": session,
        "Outputs": outputs,
        "Error": str(raw.get("Error") or "")[:240],
    }


def _write_display_session_capability(*, cfg_path: Path, cfg: dict[str, Any], data_root: Path) -> None:
    """Publish interactive-console outputs for the Session-0 Agent service."""
    try:
        document = _bounded_display_capability(detect_display_capability())
        document["UpdatedAt"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
        payload = json.dumps(document, ensure_ascii=False, separators=(",", ":")) + "\n"
        if len(payload.encode("utf-8")) > 64 * 1024:
            raise ValueError("DISPLAY_CAPABILITY_REPORT_TOO_LARGE")
        targets = [data_root / DISPLAY_CAPABILITY_FILE, _display_capability_temp_path(cfg_path, cfg)]
        for target in targets:
            temp = target.with_suffix(target.suffix + f".tmp.{os.getpid()}")
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                temp.write_text(payload, encoding="utf-8")
                os.replace(temp, target)
                try:
                    target.chmod(0o644)
                except OSError:
                    pass
                return
            except Exception:
                try:
                    temp.unlink()
                except Exception:
                    pass
        _LOG.debug("No se pudo publicar la capacidad de pantalla desde el tray")
    except Exception as exc:
        _LOG.debug("DISPLAY_CAPABILITY_REPORT_FAILED: %s", exc)


def _parse_iso(value: Any) -> dt.datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.datetime.now().astimezone().tzinfo)
        return parsed.astimezone()
    except Exception:
        return None


def _tray_lock_path(cfg_path: Path) -> Path:
    user = getpass.getuser() or "user"
    digest = hashlib.sha256(str(cfg_path).casefold().encode("utf-8")).hexdigest()[:12]
    safe_user = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in user)[:40] or "user"
    return Path(tempfile.gettempdir()) / f"gideon-agent-tray-{safe_user}-{digest}.pid"


def _acquire_single_instance(cfg_path: Path) -> Path | None:
    lock = _tray_lock_path(cfg_path)
    for _ in range(2):
        try:
            fd = os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            with os.fdopen(fd, "w", encoding="ascii") as fh:
                fh.write(str(os.getpid()))
            return lock
        except FileExistsError:
            try:
                existing = int(lock.read_text(encoding="ascii").strip() or "0")
            except Exception:
                existing = 0
            if existing > 0 and _process_alive(existing):
                return None
            try:
                lock.unlink(missing_ok=True)
            except Exception:
                return None
        except Exception:
            # El lock es una mejora UX; no debe bloquear el monitor si el
            # directorio temporal tiene una política inusual.
            return Path()
    return None


def _release_single_instance(lock: Path | None) -> None:
    if lock is None or str(lock) in {"", "."}:
        return
    try:
        if lock.exists() and lock.read_text(encoding="ascii").strip() == str(os.getpid()):
            lock.unlink(missing_ok=True)
    except Exception as exc:
        _LOG.debug("No se pudo retirar lock de tray: %s", exc)


def _process_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        if os.name == "nt":
            cp = subprocess.run(
                ["tasklist.exe", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                timeout=3,
                creationflags=0x08000000,
            )
            return str(pid) in cp.stdout
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def _start_player_companion(
    *,
    install_root: Path,
    data_root: Path,
    cfg: dict[str, Any],
    status: dict[str, Any],
) -> str:
    """Start the credential-free desktop Player from an interactive tray only.

    The Windows Agent service remains the owner of mTLS, reverse tunnels and
    Jobs. This child receives only local paths and independently verifies the
    public signed manifest before it can invoke the externally installed VLC.
    """
    # The tray can run inside RDP. A campaign associated with a physical Screen
    # must never start from that remote session; the Player module checks the
    # same condition continuously and exits after a console switch.
    try:
        from gideon_agent_player import physical_session_context

        physical = physical_session_context()
    except Exception:
        physical = {}
    if not bool(physical.get("Physical")):
        return "PLAYER_WAITING_FOR_PHYSICAL_CONSOLE"
    script = install_root / "gideon_agent_player.py"
    if not script.is_file():
        return "PLAYER_RUNTIME_NOT_INSTALLED"
    security = cfg.get("security") if isinstance(cfg.get("security"), dict) else {}
    raw_key = str(security.get("trusted_signing_public_key") or "gideon_agent_signing_public.pem").strip()
    public_key = Path(os.path.expandvars(raw_key))
    if not public_key.is_absolute():
        public_key = install_root / public_key
    if not public_key.is_file():
        return "PLAYER_SIGNING_KEY_MISSING"
    agent_id = str(status.get("agent_id") or _load_json(data_root / "agent.runtime.json").get("agent_id") or "").strip()
    if not agent_id:
        return "PLAYER_WAITING_FOR_AGENT_ID"
    command = [
        sys.executable,
        str(script),
        "--run",
        "--agent-root", str(data_root),
        "--agent-id", agent_id,
        "--public-key", str(public_key),
    ]
    kwargs: dict[str, Any] = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
    }
    if os.name == "nt":
        kwargs["creationflags"] = 0x08000000 | 0x00000200
    else:
        kwargs["start_new_session"] = True
    try:
        subprocess.Popen(command, **kwargs)
        return "PLAYER_DESKTOP_COMPANION_STARTED"
    except Exception as exc:
        _LOG.warning("No se pudo iniciar GIDEON Player de escritorio: %s", exc)
        return "PLAYER_DESKTOP_COMPANION_DEFERRED"


def _open_player_output_mapping(*, install_root: Path) -> str:
    """Open the signed local Windows mapping helper through UAC.

    The ordinary tray user never writes the map. The helper is local-only and
    elevated, so it can protect the map ACL before the desktop Player reads it.
    """
    if os.name != "nt":
        return "PLAYER_OUTPUT_MAPPING_USE_LOCAL_ADMIN_LAUNCHER"
    try:
        from gideon_agent_player import physical_session_context
        if not bool(physical_session_context().get("Physical")):
            return "PLAYER_OUTPUT_MAPPING_PHYSICAL_CONSOLE_REQUIRED"
        script = install_root / "gideon-agent-player-map.ps1"
        if not script.is_file():
            return "PLAYER_OUTPUT_MAPPING_HELPER_MISSING"
        import ctypes
        args = f'-NoProfile -ExecutionPolicy Bypass -File "{script}" -InstallRoot "{install_root}"'
        result = int(ctypes.windll.shell32.ShellExecuteW(None, "runas", "powershell.exe", args, str(install_root), 1))
        return "PLAYER_OUTPUT_MAPPING_ELEVATION_REQUESTED" if result > 32 else "PLAYER_OUTPUT_MAPPING_ELEVATION_REJECTED"
    except Exception as exc:
        _LOG.warning("No se pudo abrir el mapeo local de pantallas: %s", exc)
        return "PLAYER_OUTPUT_MAPPING_ELEVATION_DEFERRED"


def _health(status: dict[str, Any], *, stale_seconds: int = DEFAULT_HEARTBEAT_STALE_SECONDS, now: dt.datetime | None = None) -> dict[str, Any]:
    now = now or dt.datetime.now().astimezone()
    pid = int(status.get("process_pid") or 0)
    alive = _process_alive(pid) if pid else False
    heartbeat = _parse_iso(status.get("last_heartbeat"))
    age = None if heartbeat is None else max(0.0, (now - heartbeat).total_seconds())
    raw = str(status.get("status") or "").strip().upper()
    active_job = str(status.get("active_job_id") or "").strip()
    gateway_connected = status.get("gateway_connected")

    if pid and not alive:
        key = "STOPPED"
    elif raw == "UPDATING" and alive:
        key = "UPDATING"
    elif raw in {"ERROR", "FAILED"} and alive:
        key = "ERROR"
    elif alive and active_job:
        # El trabajo continúa siendo la actividad principal. Si además perdimos
        # Gateway, el tooltip conserva el error de conexión para diagnóstico.
        key = "BUSY"
    elif alive and gateway_connected is False:
        key = "NO_GATEWAY"
    elif alive and heartbeat is None:
        key = "CONNECTING"
    elif alive and age is not None and age > max(10, stale_seconds):
        key = "NO_GATEWAY"
    elif alive and heartbeat is not None:
        key = "ACTIVE"
    elif not pid:
        # Instalación recién creada o status todavía no emitido.
        key = "CONNECTING" if raw in {"STARTING", "CONNECTING"} else "STOPPED"
    else:
        key = "UNKNOWN"
    label, color = STATUS_META[key]
    return {
        "key": key,
        "label": label,
        "color": color,
        "process_pid": pid,
        "process_alive": alive,
        "heartbeat_age_seconds": age,
    }


def _ago(seconds: float | None) -> str:
    if seconds is None:
        return "sin heartbeat"
    if seconds < 2:
        return "ahora"
    if seconds < 60:
        return f"hace {int(seconds)} s"
    if seconds < 3600:
        return f"hace {int(seconds // 60)} min"
    return f"hace {int(seconds // 3600)} h"


def _open_path(path: Path) -> None:
    try:
        if os.name == "nt":
            os.startfile(str(path))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.Popen(["xdg-open", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as exc:
        _LOG.warning("No se pudo abrir la ruta solicitada: %s", exc)


def _show_message(title: str, text: str, *, error: bool = False) -> None:
    try:
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        if error:
            messagebox.showerror(title, text, parent=root)
        else:
            messagebox.showinfo(title, text, parent=root)
        root.destroy()
        return
    except Exception as exc:
        _LOG.debug("Tkinter no disponible para mensaje de tray: %s", exc)
    # Fallbacks sin dependencia Python adicional para escritorios donde
    # tkinter no está disponible.
    try:
        if sys.platform == "darwin":
            escaped_title = title.replace('"', '\"')
            escaped_text = text.replace('"', '\"').replace("\n", " ")
            subprocess.Popen(["osascript", "-e", f'display dialog "{escaped_text}" with title "{escaped_title}" buttons {{"OK"}} default button "OK"'])
            return
        if shutil.which("zenity"):
            flag = "--error" if error else "--info"
            subprocess.Popen(["zenity", flag, f"--title={title}", f"--text={text}", "--width=560"])
            return
        if shutil.which("kdialog"):
            flag = "--error" if error else "--msgbox"
            subprocess.Popen(["kdialog", flag, text, "--title", title])
            return
    except Exception as exc:
        _LOG.debug("Fallback gráfico del tray no disponible: %s", exc)


def _copy_clipboard(text: str) -> bool:
    try:
        if os.name == "nt":
            cp = subprocess.run(["clip.exe"], input=text, text=True, timeout=5, creationflags=0x08000000)
            return cp.returncode == 0
        if sys.platform == "darwin":
            cp = subprocess.run(["pbcopy"], input=text, text=True, timeout=5)
            return cp.returncode == 0
        for cmd in (["wl-copy"], ["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]):
            try:
                cp = subprocess.run(cmd, input=text, text=True, timeout=5)
                if cp.returncode == 0:
                    return True
            except Exception:
                continue
    except Exception as exc:
        _LOG.debug("Clipboard nativo no disponible: %s", exc)
    try:
        import tkinter as tk
        root = tk.Tk(); root.withdraw(); root.clipboard_clear(); root.clipboard_append(text); root.update(); root.destroy()
        return True
    except Exception:
        return False


def _sanitized_config(cfg: dict[str, Any]) -> dict[str, Any]:
    safe = json.loads(json.dumps(cfg))
    for key in ("agent_token", "enrollment_secret"):
        if key in safe:
            safe[key] = "***"
    return safe


def _probe_gateway(cfg_path: Path, cfg: dict[str, Any], data_root: Path) -> tuple[bool, str]:
    try:
        from gideon_agent_http import AgentHttpClient
        runtime = _load_json(data_root / "agent.runtime.json")
        token = str(runtime.get("agent_token") or cfg.get("agent_token") or "").strip()
        if not token:
            return False, "El Agent todavía no tiene token de enrolamiento."
        cp = cfg.get("control_plane") if isinstance(cfg.get("control_plane"), dict) else {}
        base_url = str(cp.get("base_url") or "").rstrip("/")
        if not base_url:
            return False, "control_plane.base_url no está configurado."
        base = cfg_path.parent
        ca = _expand_path(cp.get("ca_file"), base)
        cert = _expand_path(cp.get("client_cert"), base)
        key = _expand_path(cp.get("client_key"), base)
        client = AgentHttpClient(
            base_url,
            bearer_token=token,
            timeout=min(10.0, float(cp.get("timeout_seconds") or 10)),
            verify_tls=bool(cp.get("verify_tls", True)),
            ca_file=str(ca) if ca else None,
            require_https=bool(cp.get("require_https", True)),
            client_cert=str(cert) if cert else None,
            client_key=str(key) if key else None,
            minimum_tls=str(cp.get("minimum_tls") or "TLSv1.2"),
            user_agent=f"GIDEON-Agent-Tray/{TRAY_VERSION}",
        )
        # GET de lectura autenticada: verifica DNS/ruta/TLS/token/Gateway sin
        # registrar un heartbeat falso ni consumir/reclamar un Job.
        reply = client.json("GET", "/api/v1/agent/jobs/next", timeout=8.0)
        queued = "sí" if isinstance(reply.get("Job"), dict) else "no"
        return True, f"Gateway accesible por HTTPS. Autenticación OK. Job pendiente: {queued}."
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def _decorate_icon(base_image: Any, color: tuple[int, int, int, int]) -> Any:
    from PIL import ImageDraw
    image = base_image.copy().convert("RGBA")
    draw = ImageDraw.Draw(image)
    width, height = image.size
    diameter = max(10, int(min(width, height) * 0.34))
    margin = max(1, int(diameter * 0.08))
    x1 = width - diameter - margin
    y1 = height - diameter - margin
    x2 = width - margin
    y2 = height - margin
    outline = max(2, diameter // 8)
    draw.ellipse((x1, y1, x2, y2), fill=(255, 255, 255, 255))
    draw.ellipse((x1 + outline, y1 + outline, x2 - outline, y2 - outline), fill=color)
    return image


def _diagnostic_text(cfg_path: Path, cfg: dict[str, Any], status: dict[str, Any], health: dict[str, Any], data_root: Path) -> str:
    runtime = _load_json(data_root / "agent.runtime.json")
    cp = cfg.get("control_plane") if isinstance(cfg.get("control_plane"), dict) else {}
    lines = [
        "Gideon Rx Agent · diagnóstico local",
        f"Generado: {dt.datetime.now().astimezone().isoformat(timespec='seconds')}",
        f"Equipo: {status.get('hostname') or socket.gethostname()}",
        f"Usuario del tray: {getpass.getuser()}",
        f"Sede: {status.get('site_code') or cfg.get('site_code') or '-'} · {status.get('site_name') or cfg.get('site_name') or '-'}",
        f"AgentName: {status.get('agent_name') or cfg.get('agent_name') or '-'}",
        f"AgentId: {status.get('agent_id') or runtime.get('agent_id') or '-'}",
        f"AgentVersion: {status.get('agent_version') or runtime.get('agent_version') or '-'}",
        f"TrayVersion: {TRAY_VERSION}",
        f"Estado: {health.get('label')} ({health.get('key')})",
        f"PID Agent: {health.get('process_pid') or '-'} · vivo={health.get('process_alive')}",
        f"Gateway: {status.get('gateway_url') or cp.get('base_url') or '-'}",
        f"Gateway conectado: {status.get('gateway_connected')}",
        f"Último heartbeat: {status.get('last_heartbeat') or '-'} · {_ago(health.get('heartbeat_age_seconds'))}",
        f"IP observada por Gateway: {status.get('gateway_observed_ip') or '-'}",
        f"Job activo: {status.get('active_job_id') or '-'} · {status.get('active_job_state') or '-'}",
        f"Último Job: {status.get('last_job_id') or '-'} · {status.get('last_job_state') or '-'} · {status.get('last_job_finished_at') or '-'}",
        f"Último error Gateway: {status.get('last_gateway_error') or '-'}",
        f"Último error Agent: {status.get('last_error') or '-'}",
        f"Config: {cfg_path}",
        f"DataDir: {data_root}",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    cfg_path = args.config.resolve()
    cfg = _load_config(cfg_path)
    if not cfg.get("site_code"):
        return 2
    tray_lock = _acquire_single_instance(cfg_path)
    if tray_lock is None:
        # Ya existe una miniatura para este Agent en la sesión de usuario.
        return 0
    atexit.register(_release_single_instance, tray_lock)
    try:
        import pystray
        from PIL import Image
    except Exception:
        _release_single_instance(tray_lock)
        return 3

    install_root = cfg_path.parent
    data_root = _data_root(cfg_path, cfg)
    status_path = data_root / "agent.status.json"
    log_path = data_root / "agent.log"
    icon_path = install_root / "gideon_agent_tray.png"
    if not icon_path.is_file():
        _release_single_instance(tray_lock)
        return 4
    try:
        base_image = Image.open(icon_path).convert("RGBA")
    except Exception:
        _release_single_instance(tray_lock)
        return 5

    brand = _load_config(install_root / "branding.json")
    agent_product = str(brand.get("agent_product_name") or "Gideon Rx Agent").strip()
    site_code = str(cfg.get("site_code") or "").strip()
    site_name = str(cfg.get("site_name") or "").strip()
    agent_name = str(cfg.get("agent_name") or "").strip() or os.environ.get("COMPUTERNAME") or os.environ.get("HOSTNAME") or agent_product
    tray_cfg = cfg.get("tray") if isinstance(cfg.get("tray"), dict) else {}
    refresh_seconds = max(2, int(tray_cfg.get("refresh_seconds") or DEFAULT_REFRESH_SECONDS))
    stale_seconds = max(30, int(tray_cfg.get("heartbeat_stale_seconds") or DEFAULT_HEARTBEAT_STALE_SECONDS))

    state: dict[str, Any] = {"status": {}, "health": {"key": "UNKNOWN", "label": "Estado desconocido", "color": STATUS_META["UNKNOWN"][1]}}
    stop_event = threading.Event()
    icon: Any = None
    next_player_companion = 0.0
    next_display_capability = 0.0

    def refresh() -> None:
        nonlocal state, next_player_companion, next_display_capability
        status = _load_json(status_path)
        if time.monotonic() >= next_display_capability:
            _write_display_session_capability(cfg_path=cfg_path, cfg=cfg, data_root=data_root)
            next_display_capability = time.monotonic() + DISPLAY_CAPABILITY_INTERVAL_SECONDS
        # The companion has its own PID lock and reads only the signed public
        # media exchange.  Retrying its launch is harmless and lets a campaign
        # received after user login begin without restarting Agent/remote work.
        if time.monotonic() >= next_player_companion:
            _start_player_companion(
                install_root=install_root,
                data_root=data_root,
                cfg=cfg,
                status=status,
            )
            next_player_companion = time.monotonic() + 30.0
        health = _health(status, stale_seconds=stale_seconds)
        state = {"status": status, "health": health}
        if icon is not None:
            try:
                icon.icon = _decorate_icon(base_image, health["color"])
                short_agent = str(status.get("agent_name") or agent_name)
                icon.title = f"Gideon Rx Agent · {short_agent} · {site_code} · {health['label']}"
                icon.update_menu()
            except Exception as exc:
                _LOG.warning("No se pudo refrescar el icono de estado del Agent: %s", exc)

    def current() -> tuple[dict[str, Any], dict[str, Any]]:
        return state.get("status", {}), state.get("health", {})

    def show_status(_icon: object = None, _item: object = None) -> None:
        refresh()
        status, health = current()
        runtime = _load_json(data_root / "agent.runtime.json")
        cp = cfg.get("control_plane") if isinstance(cfg.get("control_plane"), dict) else {}
        text = "\n".join([
            f"{agent_product}",
            "",
            f"Equipo: {status.get('agent_name') or agent_name} · {status.get('hostname') or socket.gethostname()}",
            f"Sede: {site_code} · {site_name}",
            f"Agent ID: {status.get('agent_id') or runtime.get('agent_id') or '-'}",
            "",
            f"Estado: {health.get('label')}",
            f"Gateway: {status.get('gateway_url') or cp.get('base_url') or '-'}",
            f"Conexión: {'OK' if status.get('gateway_connected') is True else 'Sin confirmar' if status.get('gateway_connected') is None else 'Sin conexión'}",
            f"Último heartbeat: {_ago(health.get('heartbeat_age_seconds'))}",
            f"IP observada: {status.get('gateway_observed_ip') or '-'}",
            f"Job activo: {status.get('active_job_id') or '-'}",
            f"Último Job: {status.get('last_job_id') or '-'} · {status.get('last_job_state') or '-'}",
            f"Versión Agent: {status.get('agent_version') or runtime.get('agent_version') or '-'}",
            f"Actualización disponible: {status.get('available_update') or '-'} · aprobación {status.get('update_approval_state') or '-'}",
            f"Actualizando a: {status.get('update_target_version') or '-'}",
            "",
            f"Último error: {status.get('last_gateway_error') or status.get('last_error') or '-'}",
        ])
        _show_message("Gideon Rx Agent · Estado", text, error=health.get("key") in {"ERROR", "STOPPED"})

    def test_gateway(_icon: object = None, _item: object = None) -> None:
        def worker() -> None:
            ok, detail = _probe_gateway(cfg_path, cfg, data_root)
            _show_message("Gideon Rx Agent · Prueba de Gateway", detail, error=not ok)
            refresh()
        threading.Thread(target=worker, name="GIDEONTrayProbe", daemon=True).start()

    def show_last_job(_icon: object = None, _item: object = None) -> None:
        refresh(); status, _ = current()
        text = "\n".join([
            f"Job activo: {status.get('active_job_id') or '-'}",
            f"Estado activo: {status.get('active_job_state') or '-'}",
            "",
            f"Último Job: {status.get('last_job_id') or '-'}",
            f"Estado final: {status.get('last_job_state') or '-'}",
            f"Finalizado: {status.get('last_job_finished_at') or '-'}",
            f"Error: {status.get('last_job_error') or '-'}",
        ])
        _show_message("Gideon Rx Agent · Jobs", text)

    def copy_diagnostic(_icon: object = None, _item: object = None) -> None:
        refresh(); status, health = current()
        text = _diagnostic_text(cfg_path, cfg, status, health, data_root)
        ok = _copy_clipboard(text)
        _show_message("Gideon Rx Agent · Diagnóstico", "Diagnóstico copiado al portapapeles." if ok else "No fue posible copiar automáticamente el diagnóstico.", error=not ok)

    def configure_player_outputs(_icon: object = None, _item: object = None) -> None:
        result = _open_player_output_mapping(install_root=install_root)
        messages = {
            "PLAYER_OUTPUT_MAPPING_ELEVATION_REQUESTED": "Se abrió la confirmación de Windows. Un administrador local debe asociar cada salida física al número de pantalla de VLC.",
            "PLAYER_OUTPUT_MAPPING_PHYSICAL_CONSOLE_REQUIRED": "Abra esta opción desde la consola física, no desde RDP/VNC.",
            "PLAYER_OUTPUT_MAPPING_HELPER_MISSING": "Esta versión del Agent aún no incluye el asistente de mapeo. Actualícela desde la consola Gideon Rx.",
            "PLAYER_OUTPUT_MAPPING_USE_LOCAL_ADMIN_LAUNCHER": "En Linux/Raspberry ejecute como administrador: sudo gideon-agent-player-launch --list-outputs y luego sudo gideon-agent-player-launch --map-output IDENTIDAD --screen-number N.",
        }
        _show_message("Gideon Rx Player · Salidas físicas", messages.get(result, "No se pudo abrir el asistente local. Revise el estado del Agent o solicite elevación local."), error=result not in {"PLAYER_OUTPUT_MAPPING_ELEVATION_REQUESTED", "PLAYER_OUTPUT_MAPPING_USE_LOCAL_ADMIN_LAUNCHER"})

    def open_logs(_icon: object = None, _item: object = None) -> None:
        _open_path(log_path if log_path.exists() else data_root)

    def hide_indicator(_icon: object, _item: object) -> None:
        stop_event.set()
        try:
            _icon.stop()  # type: ignore[attr-defined]
        except Exception as exc:
            _LOG.debug("No se pudo detener el icono de tray: %s", exc)

    def text_agent(_item: object) -> str:
        status, _ = current(); return f"Agente: {status.get('agent_name') or agent_name} · {status.get('hostname') or socket.gethostname()}"
    def text_site(_item: object) -> str:
        return f"Sede: {site_code} · {site_name}"
    def text_id(_item: object) -> str:
        status, _ = current(); runtime = _load_json(data_root / "agent.runtime.json"); return f"Agent ID: {status.get('agent_id') or runtime.get('agent_id') or '-'}"
    def text_state(_item: object) -> str:
        _, health = current(); return f"Estado: {health.get('label') or 'desconocido'}"
    def text_heartbeat(_item: object) -> str:
        _, health = current(); return f"Heartbeat: {_ago(health.get('heartbeat_age_seconds'))}"

    menu = pystray.Menu(
        pystray.MenuItem(text_agent, None, enabled=False),
        pystray.MenuItem(text_site, None, enabled=False),
        pystray.MenuItem(text_id, None, enabled=False),
        pystray.MenuItem(text_state, None, enabled=False),
        pystray.MenuItem(text_heartbeat, None, enabled=False),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Ver estado del Agent", show_status, default=True),
        pystray.MenuItem("Probar conexión con Gateway", test_gateway),
        pystray.MenuItem("Ver último Job", show_last_job),
        pystray.MenuItem("Configurar salidas físicas de Player", configure_player_outputs),
        pystray.MenuItem("Abrir logs", open_logs),
        pystray.MenuItem("Copiar diagnóstico", copy_diagnostic),
        pystray.MenuItem("Actualizar estado", lambda _icon, _item: refresh()),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Abrir carpeta de datos", lambda _icon, _item: _open_path(data_root)),
        pystray.MenuItem("Ocultar icono de estado (el Agent continúa activo)", hide_indicator),
    )

    refresh()
    initial = state["health"]
    icon = pystray.Icon(
        "GIDEONAgent",
        _decorate_icon(base_image, initial["color"]),
        f"Gideon Rx Agent · {agent_name} · {site_code} · {initial['label']}",
        menu,
    )

    def monitor() -> None:
        while not stop_event.wait(refresh_seconds):
            refresh()

    threading.Thread(target=monitor, name="GIDEONAgentTrayMonitor", daemon=True).start()
    try:
        icon.run()
        return 0
    except Exception:
        # En servidores/headless el indicador nunca debe convertir el servicio
        # principal del Agent en un fallo.
        return 0
    finally:
        stop_event.set()
        _release_single_instance(tray_lock)


if __name__ == "__main__":
    raise SystemExit(main())
