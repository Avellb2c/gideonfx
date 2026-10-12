"""Authenticated WebAdmin adapter for the narrow Ubuntu TLS broker."""
from __future__ import annotations

import asyncio
import base64
import json
import secrets
import socket
import sys

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse, Response

SOCKET_PATH = '/run/gideon-tls-manager/control.sock'
MAX_BODY = 8 * 1024 * 1024


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
        if action not in {'prepare', 'apply', 'confirm', 'cancel'}:
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
