"""Authenticated WebAdmin adapter for Linux TLS broker and Windows ACME."""
from __future__ import annotations

import asyncio
import base64
import datetime as dt
import hashlib
import json
import re
import secrets
import socket
import ssl
import subprocess
import sys
import uuid
from pathlib import Path

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse, Response

SOCKET_PATH = '/run/gideon-tls-manager/control.sock'
MAX_BODY = 8 * 1024 * 1024
WINDOWS_PLAN_NAME = "windows-letsencrypt-plan.json"
WINDOWS_JOB_NAME = "windows-letsencrypt-job.json"
WINDOWS_JOB_WRAPPER = "gideon_windows_acme_job.py"
WINDOWS_FQDN = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)


def _windows_file_status(value):
    """Return a safe, read-only certificate summary for Windows installs."""
    path = Path(str(value or "")).expanduser() if value else None
    result = {"path": str(path) if path else "", "sha256": "", "expires": "", "days_left": None}
    if not path or not path.is_file():
        result["error"] = "Archivo TLS no encontrado."
        return result
    try:
        data = path.read_bytes()
        result["sha256"] = hashlib.sha256(data).hexdigest()
        decoded = ssl._ssl._test_decode_cert(str(path))
        not_after = str(decoded.get("notAfter") or "").strip()
        if not_after:
            expires = dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
            result["expires"] = expires.isoformat()
            result["days_left"] = int((expires - dt.datetime.now(dt.timezone.utc)).total_seconds() // 86400)
        result["subject"] = str(decoded.get("subject") or "")
    except Exception as exc:
        result["error"] = "No se pudo leer el certificado local: " + type(exc).__name__
    return result


def _windows_data_root(config):
    gateway_path = Path(str(config.get("gateway_config_file") or ""))
    if gateway_path.parent.name and gateway_path.parent.parent:
        return gateway_path.parent.parent
    return Path(str(config.get("data_dir") or "")).expanduser()


def _windows_plan_status(config):
    """Read the optional future ACME plan without exposing secrets or applying it."""
    path = _windows_data_root(config) / "config" / WINDOWS_PLAN_NAME
    empty = {
        "configured": False,
        "web_host": "",
        "gateway_host": "",
        "email": "",
        "environment": "production",
        "saved_utc": "",
    }
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
        if not isinstance(value, dict):
            return empty
        return {
            "configured": True,
            "web_host": str(value.get("web_host") or ""),
            "gateway_host": str(value.get("gateway_host") or ""),
            "email": str(value.get("email") or ""),
            "environment": str(value.get("environment") or "production"),
            "saved_utc": str(value.get("saved_utc") or ""),
        }
    except (OSError, ValueError, TypeError):
        return empty


def _validate_windows_plan(params):
    if not isinstance(params, dict):
        raise ValueError("La configuración Let’s Encrypt debe ser un objeto.")

    def host(value, label, required=True):
        text = str(value or "").strip().rstrip(".").lower()
        if not text and not required:
            return ""
        if (
            not text
            or text in {"localhost", "127.0.0.1", "::1"}
            or not WINDOWS_FQDN.fullmatch(text)
        ):
            raise ValueError(f"{label} debe ser un dominio público completo, por ejemplo {label}.example.com.")
        return text

    web_host = host(params.get("web_host"), "WebAdmin")
    gateway_host = host(params.get("gateway_host"), "Gateway", required=False)
    email = str(params.get("email") or "").strip()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise ValueError("El correo ACME no es válido.")
    environment = str(params.get("environment") or "production").strip().lower()
    if environment not in {"production", "staging"}:
        raise ValueError("El entorno ACME debe ser production o staging.")
    if not bool(params.get("agree_acme_tos")):
        raise ValueError("Confirme los términos de Let’s Encrypt para guardar el plan.")
    return {
        "schema_version": 1,
        "web_host": web_host,
        "gateway_host": gateway_host,
        "email": email,
        "environment": environment,
        "saved_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
    }


def _windows_save_plan(config, params):
    """Persist an editable ACME plan without requesting a certificate."""
    value = _validate_windows_plan(params)
    path = _windows_data_root(config) / "config" / WINDOWS_PLAN_NAME
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp.replace(path)
    return _windows_plan_status(config)


def _windows_job_path(config):
    return _windows_data_root(config) / "config" / WINDOWS_JOB_NAME


def _windows_job_status(config):
    """Read the public state of the detached Windows ACME operation."""
    empty = {"id": "", "state": "IDLE", "web_host": "", "gateway_host": "",
             "environment": "", "started_utc": "", "finished_utc": "", "log_path": "", "error": ""}
    path = _windows_job_path(config)
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
        if not isinstance(value, dict):
            return empty
        return {key: str(value.get(key) or "") for key in empty}
    except (OSError, ValueError, TypeError):
        return empty


def _windows_install_root():
    """Resolve the OneClick installation root from this package location."""
    return Path(__file__).resolve().parents[2]


def _windows_write_job(config, value):
    path = _windows_job_path(config)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp.replace(path)


def _windows_public_job(config):
    value = _windows_job_status(config)
    if value.get("error"):
        value["error"] = value["error"][:700]
    return value


def _windows_start_apply(config, params, actor):
    """Start the allow-listed Windows ACME OneClick operation detached from WebAdmin.

    The existing PowerShell integrator performs the privileged work, including
    win-acme issuance, atomic configuration updates, service restart and hook
    rollback.  WebAdmin only validates inputs and starts this narrow wrapper;
    it never accepts an arbitrary command or script path from the browser.
    """
    value = _validate_windows_plan(params)
    previous = _windows_job_status(config)
    if previous.get("state") in {"QUEUED", "RUNNING"}:
        raise ValueError("Ya hay una operación Let’s Encrypt de Windows en curso.")
    install_root = _windows_install_root()
    wrapper = install_root / "app" / "deploy" / "windows" / WINDOWS_JOB_WRAPPER
    script = install_root / "app" / "deploy" / "windows" / "Configure-GIDEONWindowsLetsEncrypt.ps1"
    if not wrapper.is_file() or not script.is_file():
        raise ValueError("La integración ACME de Windows no está instalada en este OneClick.")
    data_root = _windows_data_root(config).resolve()
    log_dir = data_root / "acme" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    job_id = uuid.uuid4().hex
    log_path = log_dir / f"windows-letsencrypt-{job_id}.log"
    job = {
        "id": job_id,
        "state": "QUEUED",
        "actor": str(actor or ""),
        "web_host": value["web_host"],
        "gateway_host": value["gateway_host"],
        "email": value["email"],
        "environment": value["environment"],
        "started_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "finished_utc": "",
        "log_path": str(log_path),
        "error": "",
    }
    _windows_write_job(config, job)
    command = [
        sys.executable, str(wrapper),
        "--install-root", str(install_root),
        "--data-root", str(data_root),
        "--web-host", value["web_host"],
        "--gateway-host", value["gateway_host"],
        "--email", value["email"],
        "--environment", value["environment"],
        "--job-path", str(_windows_job_path(config)),
        "--log-path", str(log_path),
    ]
    creationflags = (getattr(subprocess, "DETACHED_PROCESS", 0)
                     | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                     | getattr(subprocess, "CREATE_NO_WINDOW", 0))
    try:
        with log_path.open("a", encoding="utf-8", newline="") as log:
            process = subprocess.Popen(
                command, cwd=str(install_root), stdin=subprocess.DEVNULL,
                stdout=log, stderr=subprocess.STDOUT, close_fds=True,
                creationflags=creationflags,
            )
    except (OSError, ValueError) as exc:
        job["state"] = "FAILED"
        job["finished_utc"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
        job["error"] = "No se pudo iniciar la operación ACME: " + type(exc).__name__
        _windows_write_job(config, job)
        raise ValueError(job["error"]) from exc
    job["state"] = "RUNNING"
    job["pid"] = str(process.pid)
    _windows_write_job(config, job)
    return _windows_public_job(config)


def _windows_config_status(config):
    """Build the Windows installer-managed TLS status response."""
    def port(value, default):
        try:
            return max(1, min(int(value), 65535))
        except (TypeError, ValueError):
            return default

    gateway = {}
    gateway_path = Path(str(config.get("gateway_config_file") or ""))
    try:
        if gateway_path.is_file():
            raw = json.loads(gateway_path.read_text(encoding="utf-8-sig"))
            if isinstance(raw, dict):
                gateway = raw
    except Exception:
        gateway = {}
    web_port = port(config.get("listen_port"), 28443)
    gateway_port = port(gateway.get("listen_port"), 29443)
    acme = {"enabled": False, "configured": False, "client_installed": False,
            "certificate": {"error": "Integración ACME no configurada."},
            "renewal_task": {"present": False, "status": "not-configured", "name": ""}}
    try:
        from deploy.windows.gideon_windows_acme import status as acme_status

        data_root = gateway_path.parent.parent if gateway_path.is_file() else Path(str(config.get("data_dir") or "")).parent
        if data_root and str(data_root) not in {".", ""}:
            acme = acme_status(data_root)
    except Exception as exc:
        acme["error"] = "No se pudo consultar el estado ACME: " + type(exc).__name__
    acme_enabled = bool(acme.get("enabled"))
    planned = _windows_plan_status(config)
    windows_job = _windows_public_job(config)
    current = {
        "web_url": f"https://127.0.0.1:{web_port}",
        "agent_url": str(config.get("gateway_public_url") or config.get("gateway_base_url") or f"https://127.0.0.1:{gateway_port}"),
        "mode": "Let’s Encrypt administrado por win-acme (Windows)" if acme_enabled else "TLS administrado por el instalador (Windows)",
        "web_host": acme.get("web_host", ""),
        "agent_host": acme.get("gateway_host", ""),
        "web_port": web_port,
        "agent_port": gateway_port,
        "certificates": {
            "web": _windows_file_status(config.get("tls_certfile")),
            "gateway": _windows_file_status(gateway.get("tls_certfile")),
        },
    }
    return {
        "platform": "windows",
        "managed_by": "gideon-oneclick",
        "current": current,
        "jobs": [],
        "acme": acme,
        "certbot_installed": False,
        "acme_client_installed": bool(acme.get("client_installed")),
        "renewal_timer_active": bool(acme.get("renewal_task", {}).get("present")),
        "renewal_task_active": bool(acme.get("renewal_task", {}).get("present")),
        "actions_supported": ["status", "download-ca", "save-plan", "apply-plan"],
        "planned": planned,
        "windows_job": windows_job,
        "ca_path": str(config.get("gateway_ca_file") or gateway.get("ca_file") or ""),
        "tls_transport": "HTTPS local verificado; renovación automática con win-acme." if acme_enabled else "HTTPS local verificado; configuración externa mediante OneClick.",
    }


def _windows_ca_result(config):
    path = Path(str(config.get("gateway_ca_file") or ""))
    if not path.is_file():
        raise ValueError("La CA local de Windows no está disponible.")
    return {"ca": base64.b64encode(path.read_bytes()).decode("ascii")}


def broker_call(payload):
    encoded = json.dumps(payload, ensure_ascii=False).encode()
    if len(encoded) > MAX_BODY:
        raise ValueError('Solicitud TLS demasiado grande.')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(45)
        conn.connect(SOCKET_PATH)
        conn.sendall(encoded)
        conn.shutdown(socket.SHUT_WR)
        result = bytearray()
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            result.extend(chunk)
            if len(result) > MAX_BODY:
                raise ValueError('Respuesta TLS demasiado grande.')
    message = json.loads(result)
    if not message.get('ok'):
        raise ValueError(message.get('error') or 'El gestor rechazó la solicitud.')
    return message['result']


def register_tls_routes(app, *, config, require, security, template, call=broker_call):
    def authorize(request):
        identity = require(request, 'security_assets.manage')
        if identity.role != 'SUPERADMIN':
            raise HTTPException(403, 'Solo SuperAdmin administra TLS y acceso externo.')
        return identity

    def enabled():
        return sys.platform == 'linux' and bool(config.get('tls_manager_enabled', False))

    async def contact(payload):
        if sys.platform == "win32":
            action = str(payload.get("action") or "")
            if action == "status":
                return _windows_config_status(config)
            if action == "download-ca":
                return _windows_ca_result(config)
            if action == "save-plan":
                return _windows_save_plan(config, payload.get("params"))
            if action == "apply-plan":
                return _windows_start_apply(config, payload.get("params"), payload.get("actor"))
            raise ValueError("Acción TLS de Windows no disponible.")
        if not enabled():
            raise ValueError('Gestor TLS disponible en Ubuntu con el OneClick actualizado. No se elevan privilegios desde la web.')
        return await asyncio.to_thread(call, payload)

    @app.get('/infrastructure/tls')
    async def tls_page(request: Request):
        identity = authorize(request)
        result, error = {}, ''
        try:
            result = await contact({'action': 'status', 'actor': identity.username})
        except (OSError, ValueError):
            error = 'El gestor local no está disponible. Instale o actualice su integración en Ubuntu; consulte la guía del paquete.'
        return template(request, 'tls_management.html', {'title': 'TLS y acceso externo',
                        'tls_status': result, 'tls_error': error, 'tls_enabled': enabled(),
                        'tls_platform': 'windows' if sys.platform == 'win32' else 'linux',
                        'client_ip': str(request.client.host if request.client else '')})

    @app.get('/infrastructure/tls/status')
    async def tls_status(request: Request):
        identity = authorize(request)
        try:
            result = await contact({'action': 'status', 'actor': identity.username})
            return JSONResponse({'ok': True, 'result': result})
        except (OSError, ValueError):
            return JSONResponse({'ok': False, 'error': 'Gestor TLS no disponible. Puede estar aplicando cambios; vuelva a conectarse.'}, status_code=503)

    @app.get('/infrastructure/tls/ca.pem')
    async def tls_ca(request: Request):
        identity = authorize(request)
        try:
            result = await contact({'action': 'download-ca', 'actor': identity.username})
            return Response(base64.b64decode(result['ca'], validate=True), media_type='application/x-pem-file',
                            headers={'Content-Disposition': 'attachment; filename=gideon-laboratory-ca.pem'})
        except (ValueError, OSError) as error:
            raise HTTPException(400, 'La CA pública de laboratorio no está disponible.') from error

    @app.post('/infrastructure/tls/{action}')
    async def tls_action(request: Request, action: str):
        identity = authorize(request)
        if request.url.scheme != 'https':
            raise HTTPException(400, 'La administración de certificados requiere HTTPS.')
        if action not in {'prepare', 'apply', 'confirm', 'cancel', 'save-plan', 'apply-plan'}:
            raise HTTPException(404, 'Acción TLS no disponible.')
        token = request.headers.get('x-csrf-token', '')
        if not token or not secrets.compare_digest(token, identity.csrf_token):
            raise HTTPException(403, 'Token CSRF inválido.')
        if request.headers.get('content-type', '').split(';')[0].strip() != 'application/json':
            raise HTTPException(415, 'Se requiere application/json.')
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > MAX_BODY:
                raise HTTPException(413, 'Archivos TLS demasiado grandes.')
        try:
            data = json.loads(body)
            if not isinstance(data, dict) or set(data) - {'params', 'uploads', 'passwords', 'id', 'current_password', 'mfa_code'}:
                raise ValueError('Campos no permitidos.')
            password, mfa = data.pop('current_password', ''), data.pop('mfa_code', '')
            if not isinstance(password, str) or not isinstance(mfa, str) or not password or not mfa:
                raise ValueError('Ingrese contraseña actual y MFA para esta operación TLS.')
            # TLS changes deliberately require a fresh step-up, not the shared
            # fifteen-minute cached grant used by less disruptive operations.
            try:
                security.step_up_authenticate(identity.user_id, password, mfa, actor=identity.username,
                    remote_ip=str(request.client.host if request.client else ''), resource=request.url.path, role=identity.role)
            except Exception as error:
                raise HTTPException(403, 'Contraseña/MFA inválidos o autorización bloqueada.') from error
            del password, mfa
            payload = {'action': action, 'actor': identity.username}
            if action == 'prepare':
                payload.update(params=data.get('params'), uploads=data.get('uploads', {}), passwords=data.get('passwords', {}),
                               client_ip=str(request.client.host if request.client else ''))
            elif action in {'save-plan', 'apply-plan'}:
                payload['params'] = data.get('params')
            else:
                payload['id'] = data.get('id')
            if action == 'confirm':
                port = request.url.port or (443 if request.url.scheme == 'https' else 80)
                payload['origin'] = request.url.scheme + '://' + request.url.hostname + ('' if port == 443 else ':' + str(port))
            result = await contact(payload)
            security.audit(identity.username, 'tls.' + action, 'SUCCESS', 'Request=' + str(result.get('id', '')),
                           str(request.client.host if request.client else ''), role=identity.role)
            return JSONResponse({'ok': True, 'result': result})
        except HTTPException:
            raise
        except (ValueError, OSError) as error:
            security.audit(identity.username, 'tls.' + action, 'FAILED', 'TLS request rejected',
                           str(request.client.host if request.client else ''), role=identity.role)
            detail = str(error)[:700] if isinstance(error, ValueError) else 'No se pudo contactar al gestor TLS de Ubuntu.'
            return JSONResponse({'ok': False, 'error': detail}, status_code=400)
