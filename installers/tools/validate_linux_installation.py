#!/usr/bin/env python3
"""Acceptance checks against real installed GIDEON services; no mock services.

Run as root on a GIDEON laboratory host. --exercise-backup starts the real backup
service. Does not print keys, passwords, tokens, HTTP bodies or Docker secrets.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import ssl
import stat
import subprocess
import urllib.error
import urllib.request


def command(*args):
    return subprocess.run(args, capture_output=True, text=True, timeout=120)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', required=True)
    ap.add_argument('--exercise-backup', action='store_true')
    args = ap.parse_args()
    if os.geteuid() != 0:
        ap.error('Run as root on the laboratory host.')
    checks = []

    def check(name, function):
        try:
            detail = function()
            checks.append(dict(name=name, status='PASS', detail=detail))
        except Exception as exc:
            checks.append(dict(name=name, status='FAIL', detail=str(exc)))
        print(f'{name}={checks[-1]["status"]}', flush=True)

    def expect(value, message):
        if not value:
            raise AssertionError(message)

    web = json.loads(Path('/etc/gideon/web/web_admin.json').read_text())
    gw = json.loads(Path('/etc/gideon/gateway/gateway.json').read_text())
    ca = '/etc/gideon/pki/root/gideon-root-ca.pem'
    ctx = ssl.create_default_context(cafile=ca)
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), NoRedirect())

    def request(port, path, expected, data=None):
        req = urllib.request.Request(f'https://localhost:{port}{path}', data=data)
        try:
            response = opener.open(req, timeout=15)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            code = response.code
            expect(code in expected, f'Unexpected HTTP status {code} for {path}')
            return {'status': code}

    services = ['gideon-agent-gateway.service', 'gideon-web-admin.service',
                'gideon-coordinator.service', 'gideon-diagnostics.service',
                'gideon-tls-manager.socket', 'gideon-update.path', 'gideon-backup.timer']
    for unit in services:
        def active(unit=unit):
            import time
            for _ in range(30):
                if command('systemctl', 'is-active', '--quiet', unit).returncode == 0:
                    return 'Active after boot/install'
                time.sleep(2)
            raise AssertionError('Service not active after 60 seconds')
        check('active_' + unit, active)

    for unit in services[:4]:
        def hardening(unit=unit):
            result = command('systemctl', 'show', unit, '-p', 'User', '-p', 'NoNewPrivileges',
                             '-p', 'ProtectSystem', '-p', 'ProtectHome')
            values = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
            expect(values.get('User') not in ('', 'root', None), 'Daemon runs as root')
            expect(values.get('NoNewPrivileges') == 'yes', 'NoNewPrivileges missing')
            expect(values.get('ProtectSystem') == 'strict', 'ProtectSystem not strict')
            expect(values.get('ProtectHome') == 'yes', 'ProtectHome missing')
            return values
        check('hardening_' + unit, hardening)

    check('https_web_health', lambda: request(web['listen_port'], '/healthz', {200}))
    check('https_gateway_health', lambda: request(gw['listen_port'], '/health', {200}))
    check('anonymous_admin_denied', lambda: request(web['listen_port'], '/settings', {302, 303, 401, 403}))
    check('anonymous_gateway_admin_denied', lambda: request(gw['listen_port'], '/api/v1/admin/health', {401, 403}))
    check('invalid_gateway_enrollment_denied', lambda: request(gw['listen_port'], '/api/v1/agent/enroll', {400, 401, 403}, b'{}'))
    check('invalid_web_login_denied', lambda: request(web['listen_port'], '/login', {401}, b'username=invalid&password=invalid&next=%2F'))
    check('mfa_required_config', lambda: expect(web.get('require_mfa') is True, 'MFA not required'))
    check('secure_cookies_config', lambda: expect(web.get('secure_cookies') is True, 'Cookies not secure'))

    def no_untrusted_tls():
        try:
            urllib.request.urlopen(f'https://localhost:{web["listen_port"]}/healthz', timeout=10)
        except urllib.error.URLError as exc:
            expect(isinstance(exc.reason, ssl.SSLCertVerificationError), 'Unexpected TLS error')
            return 'Private CA is not trusted implicitly'
        raise AssertionError('Private certificate accepted without configured trust')
    check('untrusted_certificate_rejected', no_untrusted_tls)

    for path in ['/etc/gideon/pki/root/gideon-root-ca.key', '/etc/gideon/pki/agent-ca/agent-client-ca.key']:
        check('private_key_' + Path(path).name, lambda path=path: expect(
            stat.S_IMODE(Path(path).stat().st_mode) == 0o600 and Path(path).stat().st_uid == 0,
            'CA key must be root-owned 0600'))

    def container():
        result = command('/usr/bin/docker', 'inspect', 'gideon-guacd')
        expect(result.returncode == 0, 'GIDEON container missing')
        row = json.loads(result.stdout)[0]
        host = row['HostConfig']
        expect(row['State']['Running'], 'Container stopped')
        expect(host['ReadonlyRootfs'], 'Container filesystem not read-only')
        expect('ALL' in host['CapDrop'], 'Capabilities not dropped')
        expect(any('no-new-privileges' in item for item in host['SecurityOpt']), 'Privilege escalation allowed')
        home_tmpfs = str((host.get('Tmpfs') or {}).get('/home/guacd') or '')
        expect(home_tmpfs and 'rw' in home_tmpfs.split(','), 'FreeRDP HOME is not a writable tmpfs')
        bindings = host['PortBindings']['4822/tcp']
        expect(all(x['HostIp'] == '127.0.0.1' for x in bindings), 'Guacd exposed outside loopback')
        with socket.create_connection(('127.0.0.1', int(bindings[0]['HostPort'])), timeout=10):
            pass
        return {'loopback': True, 'readonly': True, 'cap_drop': 'ALL', 'freerdp_home_tmpfs': True}
    check('guacd_isolation_and_tcp', container)

    def broker():
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(20)
            client.connect('/run/gideon-tls-manager/control.sock')
            client.sendall(b'{"action":"status","actor":"wsl-validation"}\n')
            client.shutdown(socket.SHUT_WR)
            data = json.loads(client.recv(1024 * 1024))
        expect(data.get('ok') is True, 'Real TLS socket broker failed')
        return 'systemd socket activation, real process'
    check('tls_broker_real_socket', broker)
    def foreign_broker():
        probe = "import socket;s=socket.socket(socket.AF_UNIX);s.connect('/run/gideon-tls-manager/control.sock')"
        result = command('runuser', '-u', 'gideonbackup', '--', '/usr/bin/python3', '-c', probe)
        expect(result.returncode != 0, 'Unprivileged service account reached privileged broker')
        return 'Kernel socket ACL rejected gideonbackup'
    check('tls_broker_foreign_account_denied', foreign_broker)

    if args.exercise_backup:
        def backup():
            result = command('systemctl', 'start', 'gideon-backup.service')
            expect(result.returncode == 0, 'Real backup service failed; inspect its journal')
            targets = sorted(Path('/var/lib/gideon/backups/local').glob('*/manifest.json'))
            expect(bool(targets), 'No backup manifest')
            path = targets[-1]
            doc = json.loads(path.read_text())
            expect({'gateway.sqlite3', 'web-security.sqlite3'} <= set(doc['Files']), 'Backup missing databases')
            for entry in doc['Entries']:
                target = path.parent / entry['Name']
                expect(hashlib.sha256(target.read_bytes()).hexdigest() == entry['Sha256'], 'Backup hash mismatch')
                if target.suffix == '.sqlite3':
                    with sqlite3.connect(f'file:{target}?mode=ro', uri=True) as conn:
                        expect(conn.execute('PRAGMA integrity_check').fetchone()[0] == 'ok', 'SQLite integrity failure')
            return 'Real service; SHA-256 and SQLite integrity checked; restore not exercised'
        check('backup_real_service', backup)

    report = {'schema': 'gideon-linux-live-validation/v1',
              'date_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
              'os_release': Path('/etc/os-release').read_text(),
              'kernel': os.uname().release, 'checks': checks,
              'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
              'security_posture': {'agent_mtls_required': bool(gw.get('require_agent_mtls')),
                                   'web_mfa_required': bool(web.get('require_mfa')),
                                   'listeners_are_loopback_only': web.get('listen_host') == '127.0.0.1' and gw.get('listen_host') == '127.0.0.1'},
              'passed': sum(x['status'] == 'PASS' for x in checks),
              'failed': sum(x['status'] == 'FAIL' for x in checks),
              'not_tested': ['Public Internet/DNS/cloud firewall', 'Live ACME issuance and renewal',
                             'Full RDP desktop session', 'Concurrent user load', 'Disaster recovery restore']}
    Path(args.output).write_text(json.dumps(report, indent=2) + '\n')
    print(f'LIVE_VALIDATION={"PASS" if not report["failed"] else "FAIL"} passed={report["passed"]} failed={report["failed"]}')
    return 1 if report['failed'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
