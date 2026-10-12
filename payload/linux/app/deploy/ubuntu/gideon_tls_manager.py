#!/usr/bin/env python3
"""Socket-activated, root-only TLS broker. No shell, client paths or arbitrary commands."""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import time
from types import SimpleNamespace

import gideon_external_access as tls

ROOT = Path('/var/lib/gideon/tls-manager')
ACTIVE = ROOT / 'active.json'
LOCK = Path('/run/lock/gideon-external-access.lock')
MAX_MESSAGE = 8 * 1024 * 1024
PREPARE_TTL = 1800
CONFIRM_TTL = 300
MATERIAL = ('web.pem', 'web.key', 'gateway.pem', 'gateway.key', 'trust.pem')
UPLOADS = {'web_cert', 'web_key', 'web_pfx', 'agent_cert', 'agent_key', 'agent_pfx', 'ca'}
PARAMS = {'mode', 'web_host', 'agent_host', 'web_port', 'agent_port', 'admin_cidr',
          'email', 'agree_acme_tos', 'accept_agent_reconfiguration'}


@contextmanager
def locked(blocking=False):
    import fcntl
    with LOCK.open('a') as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        except BlockingIOError as error:
            raise ValueError('Otra operación TLS está en curso; vuelva a intentarlo.') from error
        yield


def save(path, data):
    tls.atomic_write(path, tls.json_bytes(data), 0o600)


def job_path(job_id):
    if not isinstance(job_id, str) or not re.fullmatch(r'[a-f0-9]{32}', job_id):
        raise ValueError('Identificador de solicitud inválido.')
    return ROOT / job_id


def load_job(job_id, actor=None):
    job = tls.read_json(job_path(job_id) / 'job.json')
    if actor is not None and job['actor'] != actor:
        raise ValueError('La solicitud pertenece a otro SuperAdmin.')
    return job


def store_job(job):
    save(job_path(job['id']) / 'job.json', job)


def clear_material(job):
    for name in MATERIAL:
        (job_path(job['id']) / name).unlink(missing_ok=True)


def audit(job, event):
    # No certificates, passwords, private keys or raw request bodies in logs.
    print(json.dumps({'event': event, 'id': job['id'], 'actor': job['actor'],
                      'state': job['state'], 'time': int(time.time())}), file=sys.stderr, flush=True)


def revision():
    return hashlib.sha256(tls.json_bytes(tls.snapshot_configuration())).hexdigest()


def certificate_info(chain):
    cert = tls.x509.load_pem_x509_certificates(chain)[0]
    return {'subject': cert.subject.rfc4514_string(), 'issuer': cert.issuer.rfc4514_string(),
            'expires': cert.not_valid_after_utc.isoformat(),
            'days_left': (cert.not_valid_after_utc - dt.datetime.now(tls.UTC)).days,
            'sha256': cert.fingerprint(tls.hashes.SHA256()).hex()}


def public_job(job):
    return {key: job.get(key) for key in ('id', 'actor', 'state', 'created', 'expires', 'deadline',
                                         'preview', 'error', 'needs_agent_reconfiguration')}


def cleanup():
    for path in ROOT.glob('*/job.json'):
        if not re.fullmatch(r'[a-f0-9]{32}', path.parent.name):
            continue
        job = tls.read_json(path)
        if job['state'] == 'PREPARED' and job['expires'] < time.time():
            job['state'] = 'EXPIRED'
            clear_material(job)
            store_job(job)


def status(actor):
    web, gateway = tls.read_json(tls.WEB), tls.read_json(tls.GATEWAY)
    state = tls.read_json(tls.STATE) if tls.STATE.exists() else {}
    certs = {}
    for role, config in (('web', web), ('gateway', gateway)):
        try:
            certs[role] = certificate_info(Path(config['tls_certfile']).read_bytes())
        except (ValueError, OSError, KeyError):
            certs[role] = {'error': 'Certificado instalado no disponible.'}
    jobs = []
    for path in ROOT.glob('*/job.json'):
        if re.fullmatch(r'[a-f0-9]{32}', path.parent.name):
            job = tls.read_json(path)
            if job['actor'] == actor:
                jobs.append(public_job(job))
    jobs.sort(key=lambda job: job['created'], reverse=True)
    renewal = subprocess.run(['systemctl', 'is-active', 'certbot.timer'], capture_output=True, text=True, timeout=15)
    return {'current': {**{key: state.get(key) for key in ('mode', 'web_url', 'agent_url', 'status')},
                        'web_host': web.get('public_fqdn', ''), 'agent_host': gateway.get('public_host', ''),
                        'web_port': web.get('listen_port', 9443), 'agent_port': gateway.get('listen_port', 443),
                        'admin_cidr': web.get('admin_allowed_cidrs', []), 'certificates': certs},
            'jobs': jobs[:10], 'busy': ACTIVE.exists(), 'certbot_installed': bool(shutil.which('certbot')),
            'renewal_timer_active': renewal.returncode == 0, 'confirmation_seconds': CONFIRM_TTL}


def parameters(raw, client_ip):
    if not isinstance(raw, dict) or set(raw) - PARAMS:
        raise ValueError('Parámetros no permitidos.')
    args = tls.parser().parse_args([])
    args.mode = raw.get('mode')
    if args.mode not in ('existing', 'private-ca', 'pem', 'pfx', 'letsencrypt'):
        raise ValueError('Modo de certificados inválido.')
    args.web_host = tls.host_name(raw.get('web_host', ''))
    args.agent_host = tls.host_name(raw.get('agent_host', ''))
    args.web_port, args.agent_port = int(raw.get('web_port', 9443)), int(raw.get('agent_port', 443))
    if args.web_port == args.agent_port or any(p < 1 or p > 65535 or p in (22, 80, 4822) for p in (args.web_port, args.agent_port)):
        raise ValueError('Puertos distintos entre 1 y 65535; no 22, 80 ni 4822.')
    cidrs = raw.get('admin_cidr')
    if not isinstance(cidrs, list) or len(cidrs) > 64 or not all(isinstance(x, str) for x in cidrs):
        raise ValueError('Lista CIDR inválida.')
    args.admin_cidr = tls.admin_networks(cidrs)
    address = ipaddress.ip_address(client_ip)
    if getattr(address, 'ipv4_mapped', None):
        address = address.ipv4_mapped
    if not any(address in ipaddress.ip_network(net) for net in args.admin_cidr):
        raise ValueError('La lista administrativa debe incluir su IP actual: ' + str(address))
    for key in ('agree_acme_tos', 'accept_agent_reconfiguration'):
        value = raw.get(key, False)
        if not isinstance(value, bool):
            raise ValueError('Confirmación inválida.')
        setattr(args, key, value)
    args.email = str(raw.get('email') or '').strip()
    if args.mode == 'letsencrypt':
        if any(tls.is_ip(host) for host in (args.web_host, args.agent_host)):
            raise ValueError('Let’s Encrypt integrado requiere dominios DNS, no IP.')
        if not args.agree_acme_tos or not re.fullmatch(r'[^\s@\x00-\x1f]{1,120}@[^\s@\x00-\x1f]{1,120}\.[^\s@\x00-\x1f]{2,30}', args.email):
            raise ValueError('Indique email y acepte explícitamente los términos ACME.')
        if not shutil.which('certbot'):
            raise ValueError('Falta Certbot. Ejecute el OneClick actualizado o instale el paquete certbot en Ubuntu.')
        tls.check_port(80, -1)
    return args


def decode_uploads(raw):
    if not isinstance(raw, dict) or set(raw) - UPLOADS:
        raise ValueError('Archivos no permitidos; no se aceptan rutas del servidor.')
    result = {}
    for name, value in raw.items():
        if not isinstance(value, str):
            raise ValueError('Archivo inválido.')
        data = base64.b64decode(value, validate=True)
        limit = 2 * 1024 * 1024 if name == 'ca' else 512 * 1024
        if not data or len(data) > limit:
            raise ValueError('Archivo vacío o demasiado grande: ' + name)
        result[name] = data
    return result


def prepare_pairs(args, uploads, passwords):
    if args.mode == 'letsencrypt':
        return {}, b''
    if args.mode == 'existing':
        web, gateway = tls.read_json(tls.WEB), tls.read_json(tls.GATEWAY)
        pairs = {role: tls.load_pair(config['tls_certfile'], config['tls_keyfile'])
                 for role, config in (('web', web), ('gateway', gateway))}
        return pairs, Path(web['gateway_ca_file']).read_bytes()
    if args.mode == 'private-ca':
        ca_path = tls.BASE / 'pki/root/gideon-root-ca.pem'
        ca = tls.x509.load_pem_x509_certificate(ca_path.read_bytes())
        key = tls.serialization.load_pem_private_key((ca_path.parent / 'gideon-root-ca.key').read_bytes(), None)
        return {role: tls.private_pair(host, ca, key) for role, host in
                (('web', args.web_host), ('gateway', args.agent_host))}, ca_path.read_bytes()
    trust = uploads.get('ca')
    if not trust:
        ca_path = ssl.get_default_verify_paths().cafile
        if not ca_path:
            raise ValueError('No se encontró almacén de CA; cargue su CA de confianza.')
        trust = Path(ca_path).read_bytes()
    # Temporary plaintext material is root-only and removed before replying.
    import tempfile
    with tempfile.TemporaryDirectory(prefix='gideon-tls-upload-') as directory:
        root = Path(directory)
        for name, data in uploads.items():
            tls.atomic_write(root / name, data, 0o600)
        pairs = {}
        for role, prefix in (('web', 'web'), ('gateway', 'agent')):
            if args.mode == 'pfx':
                field = prefix + '_pfx' if prefix + '_pfx' in uploads else 'web_pfx'
                if field not in uploads:
                    raise ValueError('Falta PFX para ' + role)
                password = passwords.get(prefix) or passwords.get('web') or ''
                pairs[role] = tls.load_pair(pfx_path=root / field, password=password.encode() or None)
            else:
                cert = prefix + '_cert' if prefix + '_cert' in uploads else 'web_cert'
                key = prefix + '_key' if prefix + '_key' in uploads else 'web_key'
                if cert not in uploads or key not in uploads:
                    raise ValueError('Faltan certificado y clave PEM para ' + role)
                password = passwords.get(prefix) or passwords.get('web') or ''
                pairs[role] = tls.load_pair(root / cert, root / key, password=password.encode() or None)
        return pairs, trust


def validate_material(args, pairs, trust):
    for role, host in (('web', args.web_host), ('gateway', args.agent_host)):
        tls.validate_pair(*pairs[role], host, trust)
        if tls.is_ip(host):
            tls.validate_pair(*pairs[role], '127.0.0.1', trust)
    web = tls.read_json(tls.WEB)
    assets = Path(web.get('data_dir', '/var/lib/gideon/web')) / 'security-assets'
    if (assets / 'assets.json').is_file() and tls.read_json(assets / 'assets.json').get('gateway_ca', {}).get('active'):
        try:
            tls.validate_pair(*pairs['gateway'], args.agent_host, (assets / 'ca/gateway-ca.pem').read_bytes())
        except (ValueError, OSError) as error:
            raise ValueError('Desactive primero la CA de confianza anterior en Claves y secretos: no confía en el nuevo certificado.') from error
    old = tls.read_json(tls.STATE) if tls.STATE.exists() else {}
    if not old:
        return False
    changed = old.get('agent_url') != tls.https_url(args.agent_host, args.agent_port)
    try:
        previous = (Path(old['generation']) / 'trust.pem').read_bytes()
        tls.validate_pair(*pairs['gateway'], args.agent_host, previous)
    except (KeyError, ValueError, OSError):
        changed = True
    return changed


def prepare(request):
    if ACTIVE.exists():
        raise ValueError('Confirme o restaure el cambio pendiente antes de preparar otro.')
    cleanup()
    if sum(1 for path in ROOT.glob('*/job.json') if tls.read_json(path).get('state') == 'PREPARED') >= 5:
        raise ValueError('Hay cinco solicitudes preparadas. Cancele alguna antes de continuar.')
    args = parameters(request.get('params'), request['client_ip'])
    passwords = request.get('passwords', {})
    if not isinstance(passwords, dict) or set(passwords) - {'web', 'agent'} or not all(isinstance(x, str) and len(x) <= 1024 for x in passwords.values()):
        raise ValueError('Contraseñas de certificados inválidas.')
    uploads = decode_uploads(request.get('uploads', {}))
    if args.mode not in ('pem', 'pfx') and (uploads or any(passwords.values())):
        raise ValueError('Solo PEM/PFX admite archivos y contraseñas.')
    pairs, trust = prepare_pairs(args, uploads, passwords)
    changed = validate_material(args, pairs, trust) if pairs else tls.STATE.exists()
    web, gateway = tls.read_json(tls.WEB), tls.read_json(tls.GATEWAY)
    tls.check_port(args.web_port, int(web['listen_port']))
    tls.check_port(args.agent_port, int(gateway['listen_port']))
    tls.managed_hosts(tls.HOSTS.read_text(), [args.web_host, args.agent_host])
    job_id = secrets.token_hex(16)
    job_path(job_id).mkdir(mode=0o700)
    safe_params = {key: getattr(args, key) for key in PARAMS}
    if args.mode == 'existing':
        safe_params['mode'] = (tls.read_json(tls.STATE).get('mode', 'pem') if tls.STATE.exists() else 'pem')
    job = {'id': job_id, 'actor': request['actor'], 'client_ip': request['client_ip'],
           'created': int(time.time()), 'expires': int(time.time()) + PREPARE_TTL, 'state': 'PREPARED',
           'params': safe_params, 'baseline': revision(), 'needs_agent_reconfiguration': changed,
           'issue_acme': args.mode == 'letsencrypt',
           'preview': {'web_url': tls.https_url(args.web_host, args.web_port),
                       'agent_url': tls.https_url(args.agent_host, args.agent_port),
                       'mode': safe_params['mode'], 'admin_cidr': args.admin_cidr,
                       'certificates': {role: certificate_info(pair[0]) for role, pair in pairs.items()},
                       'acme_pending': args.mode == 'letsencrypt'}}
    for role, pair in pairs.items():
        tls.atomic_write(job_path(job_id) / (role + '.pem'), pair[0], 0o600)
        tls.atomic_write(job_path(job_id) / (role + '.key'), pair[1], 0o600)
    if trust:
        tls.atomic_write(job_path(job_id) / 'trust.pem', trust, 0o600)
    store_job(job)
    try:
        subprocess.run(['systemctl', 'restart', 'gideon-tls-cleanup.timer'], check=True, timeout=30)
    except BaseException:
        clear_material(job)
        job['state'] = 'CANCELLED'
        store_job(job)
        raise
    audit(job, 'TLS_PREPARED')
    return public_job(job)


def schedule_apply(job_id, actor):
    if ACTIVE.exists():
        raise ValueError('Ya existe un cambio en curso.')
    job = load_job(job_id, actor)
    if job['state'] != 'PREPARED' or job['expires'] <= time.time():
        raise ValueError('Solicitud caducada o ya utilizada; valide otra vez.')
    if job['baseline'] != revision():
        raise ValueError('La configuración cambió desde la validación; prepare de nuevo.')
    if job['needs_agent_reconfiguration'] and not job['params']['accept_agent_reconfiguration']:
        raise ValueError('Confirme el posible cambio de URL/CA de los agentes al preparar la solicitud.')
    job['state'] = 'APPLYING'
    job['started'] = int(time.time())
    store_job(job)
    save(ACTIVE, {'id': job_id})
    # Separate systemd job survives the WebAdmin restart and browser disconnects.
    try:
        subprocess.run(['systemctl', 'restart', 'gideon-tls-rollback.timer'], check=True, timeout=30)
        subprocess.run(['systemctl', 'start', '--no-block', 'gideon-tls-apply@' + job_id + '.service'], check=True, timeout=30)
    except BaseException:
        ACTIVE.unlink(missing_ok=True)
        job['state'] = 'PREPARED'
        store_job(job)
        raise
    audit(job, 'TLS_APPLY_QUEUED')
    return public_job(job)


def finish(job, state, error=''):
    job['state'], job['error'] = state, error
    clear_material(job)
    store_job(job)
    ACTIVE.unlink(missing_ok=True)
    subprocess.run(['systemctl', 'stop', 'gideon-tls-rollback.timer'], check=False, timeout=30)
    audit(job, 'TLS_' + state)


def rollback(job):
    snapshot = job_path(job['id']) / 'rollback.json'
    if snapshot.exists():
        tls.restore_configuration(tls.read_json(snapshot))
        finish(job, 'ROLLED_BACK', 'Se restauró la configuración anterior; confirme acceso antes de reintentar.')
    else:
        finish(job, 'FAILED', 'La operación se interrumpió antes de publicar cambios.')


def apply_job(job_id):
    job = load_job(job_id)
    if job['state'] != 'APPLYING' or not ACTIVE.exists() or tls.read_json(ACTIVE)['id'] != job_id:
        raise ValueError('Solicitud no autorizada para aplicar.')
    try:
        if job['baseline'] != revision():
            raise ValueError('La configuración cambió; prepare la solicitud otra vez.')
        args = SimpleNamespace(**job['params'])
        if job['issue_acme']:
            tls.obtain_letsencrypt(args, allow_install=False)
            pairs = {role: tls.load_pair(args.web_cert, args.web_key) for role in ('web', 'gateway')}
            trust = Path(ssl.get_default_verify_paths().cafile).read_bytes()
        else:
            pairs = {role: tls.load_pair(job_path(job_id) / (role + '.pem'), job_path(job_id) / (role + '.key'))
                     for role in ('web', 'gateway')}
            trust = (job_path(job_id) / 'trust.pem').read_bytes()
        if validate_material(args, pairs, trust) and not args.accept_agent_reconfiguration:
            raise ValueError('Los agentes requieren confirmar cambio de URL/CA; prepare otra solicitud.')
        job['preview']['certificates'] = {role: certificate_info(pair[0]) for role, pair in pairs.items()}
        save(job_path(job_id) / 'rollback.json', tls.snapshot_configuration())
        job['deadline'] = int(time.time()) + CONFIRM_TTL
        store_job(job)
        subprocess.run(['systemctl', 'restart', 'gideon-tls-rollback.timer'], check=True, timeout=30)
        tls.apply_configuration(args, pairs, trust)
        job['state'] = 'AWAITING_CONFIRMATION'
        job['deadline'] = int(time.time()) + CONFIRM_TTL
        store_job(job)
        subprocess.run(['systemctl', 'restart', 'gideon-tls-rollback.timer'], check=True, timeout=30)
        clear_material(job)
        audit(job, 'TLS_LOCAL_HEALTH_PASS_CONFIRMATION_PENDING')
    except Exception as error:
        # Raw cryptographic input / password never reaches a response or log.
        detail = str(error)[:600] if isinstance(error, ValueError) else 'Falló la aplicación o la comprobación HTTPS; revise journalctl de gideon-tls-apply.'
        if (job_path(job_id) / 'rollback.json').exists():
            rollback(job)
        else:
            finish(job, 'FAILED', detail)


def confirm(job_id, actor, origin):
    job = load_job(job_id, actor)
    if job['state'] != 'AWAITING_CONFIRMATION' or job.get('deadline', 0) <= time.time():
        raise ValueError('No existe cambio confirmable o venció el plazo.')
    if origin != job['preview']['web_url']:
        raise ValueError('Abra la nueva URL HTTPS de WebAdmin e inicie sesión allí para confirmar.')
    if job['params']['mode'] == 'letsencrypt':
        tls.configure_renewal()
    finish(job, 'CONFIRMED')
    return public_job(job)


def recover(boot=False):
    if ACTIVE.exists():
        job = load_job(tls.read_json(ACTIVE)['id'])
        if job['state'] in ('CONFIRMED', 'ROLLED_BACK', 'FAILED', 'CANCELLED'):
            ACTIVE.unlink(missing_ok=True)
        elif boot or job['state'] == 'APPLYING' or job.get('deadline', 0) <= time.time():
            rollback(job)
    cleanup()


def dispatch(request):
    if not isinstance(request, dict) or set(request) - {'action', 'actor', 'client_ip', 'params', 'uploads', 'passwords', 'id', 'origin'}:
        raise ValueError('Solicitud no permitida.')
    actor = request.get('actor')
    if not isinstance(actor, str) or not actor or len(actor) > 160 or any(ord(c) < 32 for c in actor):
        raise ValueError('Identidad administrativa inválida.')
    action = request.get('action')
    if action == 'status':
        return status(actor)
    with locked():
        if action == 'prepare':
            return prepare(request)
        if action == 'apply':
            return schedule_apply(request.get('id'), actor)
        if action == 'confirm':
            return confirm(request.get('id'), actor, request.get('origin'))
        if action == 'cancel':
            job = load_job(request.get('id'), actor)
            if job['state'] != 'PREPARED':
                raise ValueError('Solo se pueden cancelar solicitudes aún no aplicadas.')
            clear_material(job)
            job['state'] = 'CANCELLED'
            store_job(job)
            audit(job, 'TLS_CANCELLED')
            return public_job(job)
        if action == 'download-ca':
            state = tls.read_json(tls.STATE) if tls.STATE.exists() else {}
            if state.get('mode') != 'private-ca':
                raise ValueError('La descarga de CA de laboratorio requiere modo private-ca.')
            data = (tls.BASE / 'pki/root/gideon-root-ca.pem').read_bytes()
            return {'ca': base64.b64encode(data).decode()}
    raise ValueError('Acción no permitida.')


def peer_allowed(conn):
    import pwd
    pid, uid, gid = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
    if uid not in (0, pwd.getpwnam('gideonweb').pw_uid):
        raise ValueError('El socket solo acepta al servicio gideonweb.')


def receive(conn):
    data = bytearray()
    while True:
        chunk = conn.recv(min(65536, MAX_MESSAGE + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > MAX_MESSAGE:
            raise ValueError('Solicitud demasiado grande.')
    return json.loads(data)


def serve(conn):
    conn.settimeout(45)
    try:
        peer_allowed(conn)
        result = {'ok': True, 'result': dispatch(receive(conn))}
    except Exception as error:
        detail = str(error)[:700] if isinstance(error, ValueError) else 'Operación TLS no disponible; consulte el estado del gestor en Ubuntu.'
        result = {'ok': False, 'error': detail}
    conn.sendall(tls.json_bytes(result))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--socket', action='store_true')
    group.add_argument('--apply-job')
    group.add_argument('--recover', action='store_true')
    parser.add_argument('--boot', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Este componente solo se ejecuta mediante sus unidades systemd root.')
    os.umask(0o077)
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    if args.socket:
        with socket.socket(fileno=0) as conn:
            serve(conn)
    else:
        with locked(blocking=True):
            if args.apply_job:
                apply_job(args.apply_job)
            else:
                recover(args.boot)


if __name__ == '__main__':
    main()
