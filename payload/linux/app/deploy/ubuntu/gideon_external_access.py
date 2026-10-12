#!/usr/bin/env python3
"""Publish GIDEON HTTPS directly; validate/import/rotate server TLS without changing agent mTLS."""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import errno
import getpass
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

BASE = Path('/etc/gideon')
WEB = BASE / 'web/web_admin.json'
GATEWAY = BASE / 'gateway/gateway.json'
STATE = BASE / 'external-access.json'
HOSTS = Path('/etc/hosts')
SYSTEMD = Path('/etc/systemd/system')
BACKUP_ROOT = Path('/var/lib/gideon/backups/external-access')
UNITS = ('gideon-agent-gateway.service', 'gideon-web-admin.service')
UTC = dt.timezone.utc
BEGIN = '# BEGIN GIDEON EXTERNAL LOOPBACK'
END = '# END GIDEON EXTERNAL LOOPBACK'


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def host_name(value):
    value = value.strip().lower().rstrip('.')
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        if len(value) > 253 or '.' not in value or not all(
            re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
            for part in value.split('.')
        ):
            raise ValueError('Hostname/IP inválido; no incluya https://, puerto ni ruta.')
        if re.fullmatch(r'[0-9.]+', value):
            raise ValueError('IP inválida.')
        return value
    if address.is_unspecified or address.is_loopback or address.is_multicast or address.is_link_local:
        raise ValueError('Use una IP de acceso real, no loopback/multicast/link-local.')
    if address.version != 4:
        raise ValueError('Este publicador directo utiliza IPv4. Use una IPv4 o un dominio con registro A.')
    return str(address)


def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def https_url(host, port):
    name = '[' + host + ']' if ':' in host else host
    return 'https://' + name + ('' if port == 443 else ':' + str(port))


def admin_networks(values):
    networks = [ipaddress.ip_network(value.strip(), strict=False) for value in values if value.strip()]
    if not networks or any(network.prefixlen == 0 for network in networks):
        raise ValueError('Indique al menos una IP/CIDR administrativa; no se permite 0.0.0.0/0 ni ::/0.')
    return sorted(set(map(str, networks)) | {'127.0.0.1/32', '::1/128'})


def pem_key(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def load_pair(cert_path=None, key_path=None, pfx_path=None, password=None):
    if pfx_path:
        key, cert, chain = pkcs12.load_key_and_certificates(Path(pfx_path).read_bytes(), password)
        if key is None or cert is None:
            raise ValueError('El PFX debe incluir certificado y clave privada.')
        certificates = [cert, *(chain or [])]
    else:
        certificates = x509.load_pem_x509_certificates(Path(cert_path).read_bytes())
        key = serialization.load_pem_private_key(Path(key_path).read_bytes(), password)
    if not certificates:
        raise ValueError('La cadena PEM está vacía.')
    public_format = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if key.public_key().public_bytes(*public_format) != certificates[0].public_key().public_bytes(*public_format):
        raise ValueError('El certificado no corresponde a la clave privada.')
    if isinstance(key, rsa.RSAPrivateKey) and key.key_size < 2048:
        raise ValueError('RSA requiere al menos 2048 bits.')
    if isinstance(key, ec.EllipticCurvePrivateKey) and key.key_size < 256:
        raise ValueError('EC requiere al menos 256 bits.')
    now = dt.datetime.now(UTC)
    for cert in certificates:
        if cert.not_valid_before_utc > now or cert.not_valid_after_utc <= now + dt.timedelta(hours=24):
            raise ValueError('Certificado no vigente o con menos de 24 horas de vigencia.')
    # PFX additional bags have no guaranteed order. Send leaf, intermediate(s), root.
    ordered = [certificates[0]]
    remaining = certificates[1:]
    while remaining and ordered[-1].issuer != ordered[-1].subject:
        issuer = next((item for item in remaining if item.subject == ordered[-1].issuer), None)
        if issuer is None:
            break
        ordered.append(issuer)
        remaining.remove(issuer)
    return b''.join(cert.public_bytes(serialization.Encoding.PEM) for cert in ordered), pem_key(key)


def validate_pair(chain, key, host, trust, openssl='openssl'):
    # OpenSSL validates chain, identity, expiry, key use and serverAuth. Never -k.
    with tempfile.TemporaryDirectory(prefix='gideon-tls-check-') as temporary:
        root = Path(temporary)
        certs = x509.load_pem_x509_certificates(chain)
        leaf = certs[0]
        try:
            leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        except x509.ExtensionNotFound as error:
            raise ValueError('El certificado servidor requiere Subject Alternative Name (SAN).') from error
        try:
            if leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise ValueError('Una CA no puede utilizarse como certificado servidor.')
        except x509.ExtensionNotFound:
            pass
        paths = {'leaf': certs[0].public_bytes(serialization.Encoding.PEM), 'chain': chain,
                 'trust': trust, 'key': key}
        for name, data in paths.items():
            (root / name).write_bytes(data)
            os.chmod(root / name, 0o600)
        flag = '-verify_ip' if is_ip(host) else '-verify_hostname'
        command = [openssl, 'verify', '-purpose', 'sslserver', flag, host,
                   '-CAfile', str(root / 'trust'), '-untrusted', str(root / 'chain'), str(root / 'leaf')]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise ValueError('Cadena/identidad TLS inválida para ' + host + ': ' + result.stderr.strip())
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(root / 'chain'), str(root / 'key'))


def private_pair(host, ca_cert, ca_key):
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    now = dt.datetime.now(UTC)
    names = [x509.DNSName('localhost'), x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]
    names.append(x509.IPAddress(ipaddress.ip_address(host)) if is_ip(host) else x509.DNSName(host))
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
            .issuer_name(ca_cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(min(now + dt.timedelta(days=365), ca_cert.not_valid_after_utc))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM) + ca_cert.public_bytes(serialization.Encoding.PEM), pem_key(key)


def managed_hosts(original, names):
    if original.count(BEGIN) != original.count(END) or original.count(BEGIN) > 1:
        raise ValueError('Bloque GIDEON de /etc/hosts mal formado; no se modifica.')
    clean = re.sub(re.escape(BEGIN) + r'.*?' + re.escape(END) + r'\n?', '', original, flags=re.S)
    names = sorted({name for name in names if not is_ip(name)})
    for line in clean.splitlines():
        fields = line.split('#', 1)[0].split()
        if len(fields) > 1 and any(name in fields[1:] for name in names) and fields[0] != '127.0.0.1':
            raise ValueError('Existe una entrada ajena de /etc/hosts para el dominio GIDEON; resuelva el conflicto primero.')
    return clean.rstrip() + '\n' + BEGIN + '\n' + ''.join('127.0.0.1 ' + name + '\n' for name in names) + END + '\n'


def build_configs(web, gateway, args, generation):
    web, gateway = dict(web), dict(gateway)
    agent_url = https_url(args.agent_host, args.agent_port)
    web_url = https_url(args.web_host, args.web_port)
    # DNS is pinned to loopback on this host so public certificates do not need
    # a forbidden 127.0.0.1 SAN. Numeric laboratory certificates include that SAN.
    internal = https_url('127.0.0.1' if is_ip(args.agent_host) else args.agent_host, args.agent_port)
    gateway.update(listen_host='0.0.0.0', listen_address='0.0.0.0', listen_port=args.agent_port,
                   public_host=args.agent_host, public_url=agent_url, advertised_endpoint=agent_url,
                   internal_endpoint=internal, tls_certfile=str(generation / 'gateway/fullchain.pem'),
                   tls_keyfile=str(generation / 'gateway/privkey.pem'), ca_file=str(generation / 'trust.pem'))
    # client_ca_file and require_agent_mtls are intentionally preserved.
    web.update(listen_host='0.0.0.0', listen_port=args.web_port,
               public_fqdn=args.web_host, public_url=web_url,
               gateway_base_url=internal, gateway_public_url=agent_url, agent_public_gateway_url=agent_url,
               gateway_config_file=str(GATEWAY), gateway_ca_file=str(generation / 'trust.pem'),
               tls_certfile=str(generation / 'web/fullchain.pem'), tls_keyfile=str(generation / 'web/privkey.pem'),
               trust_proxy_headers=False, forwarded_allow_ips='127.0.0.1',
               admin_allowed_cidrs=admin_networks(args.admin_cidr))
    return web, gateway


def atomic_write(path, data, mode=0o640, gid=0):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path == HOSTS:
        # systemd exposes /etc/hosts as a writable single-file bind mount while
        # ProtectSystem=strict keeps its parent (/etc) read-only.  Creating the
        # usual sibling tempfile therefore fails before os.replace() can reach
        # the existing EBUSY fallback.  This is the only fixed target allowed
        # to use an in-place write; never follow a caller-controlled symlink.
        if path.is_symlink():
            raise ValueError('No se permite reemplazar un enlace simbólico: ' + str(path))
        flags = os.O_WRONLY | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0)
        target = os.open(path, flags)
        with os.fdopen(target, 'wb') as handle:
            os.fchmod(handle.fileno(), mode)
            if hasattr(os, 'fchown'):
                os.fchown(handle.fileno(), 0, gid)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        return
    fd, name = tempfile.mkstemp(prefix='.gideon-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as handle:
            os.fchmod(handle.fileno(), mode)
            if hasattr(os, 'fchown'):
                os.fchown(handle.fileno(), 0, gid)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.replace(name, path)
        except OSError as error:
            # systemd ReadWritePaths=/etc/hosts is a bind mount, not renameable.
            # Only this fixed target may use an in-place write; rollback retains
            # the complete previous bytes. Never follow a symlink here.
            if path != HOSTS or error.errno != errno.EBUSY:
                raise
            target = os.open(path, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
            with os.fdopen(target, 'wb') as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
    finally:
        if os.path.exists(name):
            os.unlink(name)


def json_bytes(value):
    return (json.dumps(value, indent=2, ensure_ascii=False) + '\n').encode()


def snapshot_configuration():
    paths = [WEB, GATEWAY, HOSTS, STATE, *[
        SYSTEMD / (unit + '.d/20-gideon-public-tls.conf') for unit in UNITS]]
    result = {}
    for path in paths:
        if path.is_symlink():
            raise ValueError('No se permite reemplazar un enlace simbólico: ' + str(path))
        if path.exists():
            stat = path.stat()
            result[str(path)] = {'data': base64.b64encode(path.read_bytes()).decode(),
                                 'mode': stat.st_mode & 0o777, 'gid': stat.st_gid}
        else:
            result[str(path)] = None
    return result


def restore_configuration(snapshot):
    # The persisted rollback record can restore only this closed set of GIDEON files.
    if set(snapshot) != set(snapshot_configuration()):
        raise ValueError('Registro de restauración con destinos no permitidos.')
    for name, original in snapshot.items():
        path = Path(name)
        if original is None:
            path.unlink(missing_ok=True)
        else:
            atomic_write(path, base64.b64decode(original['data'], validate=True), original['mode'], original['gid'])
    subprocess.run(['systemctl', 'daemon-reload'], check=True, timeout=45)
    subprocess.run(['systemctl', 'restart', *UNITS], check=True, timeout=120)


def configure_renewal():
    hook = Path('/etc/letsencrypt/renewal-hooks/deploy/50-gideon-public-tls')
    command = ('#!/bin/sh\nset -eu\n[ "${RENEWED_LINEAGE:-}" = /etc/letsencrypt/live/gideon-public ] || exit 0\n'
               'exec /usr/bin/flock -n /run/lock/gideon-external-access.lock /opt/gideon/web/venv/bin/python /opt/gideon/web/app/deploy/ubuntu/gideon_external_access.py --renew\n')
    atomic_write(hook, command.encode(), 0o700)
    subprocess.run(['systemctl', 'enable', '--now', 'certbot.timer'], check=True, timeout=45)


def check_live(host, port, path, trust):
    context = ssl.create_default_context(cadata=trust.decode())
    # GIDEON's pre-RC31 private CA may lack modern strict-only extensions. Trust,
    # chain, hostname and time checks remain enabled; never disable verification.
    context.verify_flags &= ~getattr(ssl, 'VERIFY_X509_STRICT', 0)
    with socket.create_connection(('127.0.0.1', port), timeout=8) as raw:
        with context.wrap_socket(raw, server_hostname=host) as conn:
            conn.sendall(('GET ' + path + ' HTTP/1.1\r\nHost: ' + host + '\r\nConnection: close\r\n\r\n').encode())
            status = conn.recv(512).split(b'\r\n', 1)[0]
            if b' 200 ' not in status:
                raise RuntimeError('Health HTTPS no satisfactorio: ' + status.decode(errors='replace'))


def check_port(port, current):
    if port == current:
        return
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(('0.0.0.0', port))


def apply_configuration(args, pairs, trust):
    import grp
    web, gateway = read_json(WEB), read_json(GATEWAY)
    for unit in UNITS:
        subprocess.run(['systemctl', 'cat', unit], check=True, stdout=subprocess.DEVNULL)
    check_port(args.web_port, int(web['listen_port']))
    check_port(args.agent_port, int(gateway['listen_port']))
    hosts = managed_hosts(HOSTS.read_text(), [args.web_host, args.agent_host])
    stamp = dt.datetime.now(UTC).strftime('%Y%m%dT%H%M%S') + '-' + os.urandom(4).hex()
    generation = BASE / 'public-tls' / stamp
    generation.mkdir(parents=True, mode=0o755)
    os.chmod(generation.parent, 0o755)
    os.chmod(generation, 0o755)
    for role, group in (('web', 'gideonweb'), ('gateway', 'gideongateway')):
        gid = grp.getgrnam(group).gr_gid
        directory = generation / role
        directory.mkdir(mode=0o750)
        os.chown(directory, 0, gid)
        # The TLS manager runs with UMask=0077.  mkdir(mode=0750) is therefore
        # created as 0700 unless the intended group traversal is restored
        # explicitly after assigning the service group.
        os.chmod(directory, 0o750)
        atomic_write(directory / 'fullchain.pem', pairs[role][0], 0o640, gid)
        atomic_write(directory / 'privkey.pem', pairs[role][1], 0o640, gid)
    atomic_write(generation / 'trust.pem', trust, 0o644)
    next_web, next_gateway = build_configs(web, gateway, args, generation)
    changes = {WEB: (json_bytes(next_web), 0o640, grp.getgrnam('gideonweb').gr_gid),
               GATEWAY: (json_bytes(next_gateway), 0o640, grp.getgrnam('gideongateway').gr_gid),
               HOSTS: (hosts.encode(), 0o644, 0)}
    for unit, port in zip(UNITS, (args.agent_port, args.web_port)):
        cap = 'CAP_NET_BIND_SERVICE' if port < 1024 else ''
        dropin = SYSTEMD / (unit + '.d/20-gideon-public-tls.conf')
        changes[dropin] = (('[Service]\nCapabilityBoundingSet=\nCapabilityBoundingSet=' + cap +
                           '\nAmbientCapabilities=\nAmbientCapabilities=' + cap + '\n').encode(), 0o644, 0)
    backup = BACKUP_ROOT / stamp
    backup.mkdir(parents=True, mode=0o700)
    state = {'mode': args.mode, 'web_host': args.web_host, 'agent_host': args.agent_host,
             'web_port': args.web_port, 'agent_port': args.agent_port,
             'admin_cidr': admin_networks(args.admin_cidr), 'generation': str(generation),
             'web_url': https_url(args.web_host, args.web_port),
             'agent_url': https_url(args.agent_host, args.agent_port),
             'status': 'LOCAL_HTTPS_PASS_EXTERNAL_DNS_FIREWALL_PENDING', 'backup': str(backup)}
    changes[STATE] = (json_bytes(state), 0o600, 0)
    originals = {}
    for index, path in enumerate(changes):
        if path.is_symlink():
            raise ValueError('Se rechaza sobrescribir un enlace simbólico: ' + str(path))
        if path.exists():
            stat = path.stat()
            originals[path] = (path.read_bytes(), stat.st_mode & 0o777, stat.st_gid)
            atomic_write(backup / (str(index) + '-' + path.name), path.read_bytes(), 0o600)
        else:
            originals[path] = None
    try:
        for path, (data, mode, gid) in changes.items():
            atomic_write(path, data, mode, gid)
        subprocess.run(['systemctl', 'daemon-reload'], check=True)
        subprocess.run(['systemctl', 'restart', *UNITS], check=True)
        for attempt in range(12):
            try:
                check_live(args.agent_host, args.agent_port, '/health', trust)
                check_live(args.web_host, args.web_port, '/healthz', trust)
                break
            except (OSError, RuntimeError):
                if attempt == 11:
                    raise
                time.sleep(1)
    except BaseException:
        for path, original in originals.items():
            if original is None:
                path.unlink(missing_ok=True)
            else:
                atomic_write(path, *original)
        subprocess.run(['systemctl', 'daemon-reload'], check=False)
        subprocess.run(['systemctl', 'restart', *UNITS], check=False)
        raise
    print('LOCAL_HTTPS=PASS; PUBLIC_DNS_FIREWALL=REQUIRES_EXTERNAL_TEST')
    print('WEBADMIN=' + state['web_url'])
    print('AGENTS=' + state['agent_url'])
    print('GCP: permitir TCP ' + str(args.web_port) + ' solo desde ' + ', '.join(args.admin_cidr))
    print('GCP: permitir TCP ' + str(args.agent_port) + ' desde sus agentes; no publicar 4822/28443/29443.')
    if args.mode == 'private-ca':
        print('CA pública para confiar en navegador/agentes: /etc/gideon/pki/root/gideon-root-ca.pem')
        print('Nunca distribuya gideon-root-ca.key ni las claves de agent-ca.')


def prompt(label, default=''):
    value = input(label + (' [' + str(default) + ']' if default else '') + ': ').strip()
    return value or default


def wizard(args):
    old = read_json(STATE) if STATE.exists() else {}
    gateway = read_json(GATEWAY)
    web = read_json(WEB)
    print('GIDEON HTTPS externo: private-ca (laboratorio), letsencrypt, pem, pfx o later.')
    args.mode = prompt('Certificados', old.get('mode', 'private-ca'))
    if args.mode == 'later':
        print('EXTERNAL_ACCESS=UNCHANGED; no se han modificado certificados ni puertos.')
        return False
    if args.mode not in ('private-ca', 'letsencrypt', 'pem', 'pfx'):
        raise ValueError('Seleccione private-ca, letsencrypt, pem, pfx o later.')
    args.web_host = prompt('Dominio o IP pública WebAdmin', old.get('web_host', web.get('public_fqdn', '')))
    args.agent_host = prompt('Dominio o IP pública agentes', old.get('agent_host', gateway.get('public_host', '')))
    args.web_port = int(prompt('Puerto externo WebAdmin', old.get('web_port', 9443)))
    args.agent_port = int(prompt('Puerto externo agentes', old.get('agent_port', 443)))
    args.admin_cidr = prompt('IP/CIDR de administradores, separados por coma', ','.join(old.get('admin_cidr', []))).split(',')
    if args.mode == 'pem':
        args.web_cert = prompt('WebAdmin: fullchain.pem (certificado y cadena)')
        args.web_key = prompt('WebAdmin: clave privada PEM')
        args.agent_cert = prompt('Agentes: fullchain.pem', args.web_cert)
        args.agent_key = prompt('Agentes: clave privada PEM', args.web_key)
        args.ca = prompt('CA de confianza PEM; vacío para CA públicas del sistema') or None
    elif args.mode == 'pfx':
        args.web_pfx = prompt('WebAdmin: archivo .pfx/.p12')
        args.agent_pfx = prompt('Agentes: archivo .pfx/.p12', args.web_pfx)
        args.ca = prompt('CA de confianza PEM; vacío para CA públicas del sistema') or None
    elif args.mode == 'letsencrypt':
        args.email = prompt('Email para Let’s Encrypt')
        print('Requiere DNS público correcto y TCP/80 accesible. Términos: https://letsencrypt.org/repository/')
        args.agree_acme_tos = prompt('Escriba ACEPTO para aceptar términos y solicitar el certificado') == 'ACEPTO'
    args.apply = True
    return True


def obtain_letsencrypt(args, *, allow_install=True):
    if is_ip(args.web_host) or is_ip(args.agent_host):
        raise ValueError('Este flujo Certbot usa dominios DNS; use private-ca para el laboratorio por IP.')
    if not args.agree_acme_tos or not args.email or '@' not in args.email:
        raise ValueError('Let’s Encrypt requiere email y aceptación explícita de sus términos.')
    if not shutil.which('certbot'):
        if not allow_install:
            raise ValueError('Certbot no está instalado. Instale certbot en Ubuntu y habilite certbot.timer; WebAdmin no instala paquetes como root.')
        if not shutil.which('apt-get'):
            raise ValueError('Instale certbot con su gestor de paquetes y repita.')
        subprocess.run(['apt-get', 'update'], check=True, timeout=600)
        subprocess.run(['apt-get', 'install', '-y', '--no-install-recommends', 'certbot'], check=True, timeout=600)
    check_port(80, -1)
    command = ['certbot', 'certonly', '--standalone', '--preferred-challenges', 'http',
               '--non-interactive', '--agree-tos', '--email', args.email, '--cert-name', 'gideon-public', '--renew-with-new-domains']
    for host in sorted({args.web_host, args.agent_host}):
        command.extend(['-d', host])
    subprocess.run(command, check=True, timeout=600)
    args.web_cert = args.agent_cert = '/etc/letsencrypt/live/gideon-public/fullchain.pem'
    args.web_key = args.agent_key = '/etc/letsencrypt/live/gideon-public/privkey.pem'


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--wizard', action='store_true')
    p.add_argument('--apply', action='store_true', help='Aplicar; sin esta opción solo valida certificados/configuración.')
    p.add_argument('--renew', action='store_true', help='Importar renovación Certbot de la identidad GIDEON existente.')
    p.add_argument('--verify-current', action='store_true', help='Verificar HTTPS local de los servicios instalados.')
    p.add_argument('--mode', choices=['private-ca', 'letsencrypt', 'pem', 'pfx'])
    for name in ('web-host', 'agent-host', 'web-cert', 'web-key', 'agent-cert', 'agent-key', 'web-pfx', 'agent-pfx', 'ca', 'email'):
        p.add_argument('--' + name)
    p.add_argument('--web-port', type=int, default=9443)
    p.add_argument('--agent-port', type=int, default=443)
    p.add_argument('--admin-cidr', action='append', default=[])
    p.add_argument('--agree-acme-tos', action='store_true')
    p.add_argument('--accept-agent-reconfiguration', action='store_true',
                   help='Confirmar actualización de agentes si cambia su URL o CA de confianza.')
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    if args.verify_current:
        web, gateway = read_json(WEB), read_json(GATEWAY)
        from urllib.parse import urlsplit
        gateway_url = urlsplit(gateway.get('advertised_endpoint') or gateway['public_url'])
        web_host = web.get('public_fqdn') or '127.0.0.1'
        trust = Path(web['gateway_ca_file']).read_bytes()
        for attempt in range(30):
            try:
                check_live(gateway_url.hostname, int(gateway['listen_port']), '/health', trust)
                check_live(web_host, int(web['listen_port']), '/healthz', trust)
                break
            except (OSError, RuntimeError):
                if attempt == 29:
                    raise
                time.sleep(2)
        print('LOCAL_HTTPS=PASS; INTERNET_REACHABILITY=NOT_TESTED')
        return 0
    if args.wizard or args.apply or args.renew:
        if not hasattr(os, 'geteuid') or os.geteuid() != 0:
            raise ValueError('Se requiere sudo/root para publicar o solicitar certificados.')
        if Path('/var/lib/gideon/tls-manager/active.json').exists():
            raise ValueError('Hay un cambio TLS pendiente desde WebAdmin. Confírmelo o espere su restauración antes de usar la consola/renovación.')
    if args.wizard and not wizard(args):
        return 0
    if args.renew:
        old = read_json(STATE)
        if old['mode'] != 'letsencrypt' or not old.get('status', '').startswith('LOCAL_HTTPS_PASS'):
            print('RENEW=SKIP no administrado por Certbot'); return 0
        for key in ('web_host', 'agent_host', 'web_port', 'agent_port', 'admin_cidr'):
            setattr(args, key, old[key])
        args.mode = 'pem'
        args.web_cert = args.agent_cert = '/etc/letsencrypt/live/gideon-public/fullchain.pem'
        args.web_key = args.agent_key = '/etc/letsencrypt/live/gideon-public/privkey.pem'
        args.apply = True
    args.web_host = host_name(args.web_host or '')
    args.agent_host = host_name(args.agent_host or '')
    args.admin_cidr = admin_networks(args.admin_cidr)
    if not args.mode:
        raise ValueError('Indique --mode o ejecute --wizard.')
    if args.mode in ('pem', 'pfx'):
        for prefix in ('web', 'agent'):
            if args.mode == 'pfx' and not getattr(args, prefix + '_pfx'):
                raise ValueError('Falta --' + prefix + '-pfx.')
            if args.mode == 'pem' and not (getattr(args, prefix + '_cert') and getattr(args, prefix + '_key')):
                raise ValueError('Faltan certificado/cadena y clave PEM para ' + prefix + '.')
    if args.web_port == args.agent_port or any(p < 1 or p > 65535 or p in (22, 80, 4822) for p in (args.web_port, args.agent_port)):
        raise ValueError('Use puertos externos distintos, entre 1 y 65535, excepto 22/80/4822.')
    if args.mode == 'letsencrypt':
        if not args.apply:
            raise ValueError('La solicitud ACME requiere --apply y consentimiento; no se solicita en validación.')
        obtain_letsencrypt(args)
    if args.mode == 'private-ca':
        ca_path = BASE / 'pki/root/gideon-root-ca.pem'
        ca_key_path = BASE / 'pki/root/gideon-root-ca.key'
        ca = x509.load_pem_x509_certificate(ca_path.read_bytes())
        key = serialization.load_pem_private_key(ca_key_path.read_bytes(), None)
        pairs = {role: private_pair(host, ca, key) for role, host in (('web', args.web_host), ('gateway', args.agent_host))}
        trust = ca_path.read_bytes()
    else:
        trust_path = args.ca or ssl.get_default_verify_paths().cafile
        if not trust_path:
            raise ValueError('Indique --ca con un bundle de CA raíz confiable.')
        trust = Path(trust_path).read_bytes()
        pairs = {}
        for role, prefix in (('web', 'web'), ('gateway', 'agent')):
            pfx = getattr(args, prefix + '_pfx')
            password = getpass.getpass('Contraseña PFX ' + role + ' (no se guarda): ').encode() if pfx else None
            try:
                pairs[role] = load_pair(getattr(args, prefix + '_cert'), getattr(args, prefix + '_key'), pfx, password)
            except TypeError as exc:
                if pfx or 'encrypted' not in str(exc).lower():
                    raise
                password = getpass.getpass('Contraseña clave PEM ' + role + ' (no se guarda): ').encode()
                pairs[role] = load_pair(getattr(args, prefix + '_cert'), getattr(args, prefix + '_key'), None, password)
    for role, host in (('web', args.web_host), ('gateway', args.agent_host)):
        validate_pair(*pairs[role], host, trust)
        if is_ip(host):
            validate_pair(*pairs[role], '127.0.0.1', trust)
        cert = x509.load_pem_x509_certificates(pairs[role][0])[0]
        print('CERTIFICATE_' + role.upper() + '=PASS host=' + host +
              ' expires=' + cert.not_valid_after_utc.isoformat() + ' sha256=' + cert.fingerprint(hashes.SHA256()).hex())
    if args.apply:
        # A WebAdmin-uploaded CA takes precedence over the JSON config at runtime.
        # Do not report a successful rotation while leaving WebAdmin unable to
        # contact the Gateway or generating installers with stale trust.
        web_config = read_json(WEB)
        asset_root = Path(web_config.get('data_dir') or '/var/lib/gideon/web') / 'security-assets'
        asset_metadata = asset_root / 'assets.json'
        if asset_metadata.is_file() and read_json(asset_metadata).get('gateway_ca', {}).get('active'):
            try:
                validate_pair(*pairs['gateway'], args.agent_host, (asset_root / 'ca/gateway-ca.pem').read_bytes())
            except (OSError, ValueError) as error:
                raise ValueError('La CA cargada desde WebAdmin reemplaza la CA de configuración y no confía en el nuevo certificado. Desactive ese override en Seguridad/CA del Gateway y repita.') from error
        if STATE.exists():
            old = read_json(STATE)
            current_gateway = read_json(GATEWAY)
            needs_reconfiguration = old.get('agent_url') != https_url(args.agent_host, args.agent_port)
            try:
                previous_path = Path(old.get('generation', '')) / 'trust.pem'
                if not previous_path.is_file():
                    previous_path = Path(current_gateway['ca_file'])
                previous_trust = previous_path.read_bytes()
                validate_pair(*pairs['gateway'], args.agent_host, previous_trust)
            except (OSError, ValueError):
                needs_reconfiguration = True
            if needs_reconfiguration and not args.accept_agent_reconfiguration:
                if args.wizard:
                    print('ATENCIÓN: la URL o confianza TLS cambia. Los agentes existentes necesitarán actualizar su configuración/CA.')
                    args.accept_agent_reconfiguration = prompt('Escriba ACTUALIZAR-AGENTES para continuar') == 'ACTUALIZAR-AGENTES'
                if not args.accept_agent_reconfiguration:
                    raise ValueError('Cambio no aplicado: confirme --accept-agent-reconfiguration después de planificar la actualización de agentes.')
        if args.renew:
            args.mode = 'letsencrypt'
        apply_configuration(args, pairs, trust)
        if args.mode == 'letsencrypt':
            configure_renewal()
    else:
        print('VALIDATE_ONLY=PASS no se han cambiado servicios ni archivos instalados.')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.SubprocessError, RuntimeError) as error:
        print('[FAIL] ' + str(error), file=sys.stderr)
        raise SystemExit(1)
