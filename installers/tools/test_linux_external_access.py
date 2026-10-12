"""Isolated TLS/ingress regression tests; never configure the development host."""
from __future__ import annotations
import asyncio
import datetime as dt
import importlib.util
import json
import os
import re
from pathlib import Path
import shutil
import ssl
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / 'payload/linux/app'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


external = load('gideon_external_access', APP / 'deploy/ubuntu/gideon_external_access.py')
boundary = load('gideon_ingress', APP / 'gideon_web_admin/ingress_security.py')
OPENSSL = shutil.which('openssl') or str(Path('C:/Program Files/Git/usr/bin/openssl.exe'))


class CertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = dt.datetime.now(dt.timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'GIDEON Test CA')])
        cls.ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                  .public_key(cls.key.public_key()).serial_number(x509.random_serial_number())
                  .not_valid_before(now-dt.timedelta(days=1)).not_valid_after(now+dt.timedelta(days=3650))
                  .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                  .sign(cls.key, hashes.SHA256()))
        cls.trust = cls.ca.public_bytes(serialization.Encoding.PEM)
        cls.chain, cls.private = external.private_pair('agents.example.test', cls.ca, cls.key)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='gideon-ingress-tests-')
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        (self.root/'cert.pem').write_bytes(self.chain)
        (self.root/'key.pem').write_bytes(self.private)

    def test_matching_pem_and_chain(self):
        pair = external.load_pair(self.root/'cert.pem', self.root/'key.pem')
        external.validate_pair(*pair, 'agents.example.test', self.trust, OPENSSL)

    def test_wrong_key_rejected(self):
        (self.root/'key.pem').write_bytes(external.pem_key(self.key))
        with self.assertRaisesRegex(ValueError, 'no corresponde'):
            external.load_pair(self.root/'cert.pem', self.root/'key.pem')

    def test_wrong_hostname_rejected(self):
        with self.assertRaises(ValueError):
            external.validate_pair(self.chain, self.private, 'other.example.test', self.trust, OPENSSL)

    def test_untrusted_ca_rejected(self):
        with self.assertRaises(ValueError):
            external.validate_pair(self.chain, self.private, 'agents.example.test', b'not a CA', OPENSSL)

    def test_password_protected_pfx(self):
        cert = x509.load_pem_x509_certificates(self.chain)[0]
        key = serialization.load_pem_private_key(self.private, None)
        pfx = pkcs12.serialize_key_and_certificates(b'gideon', key, cert, [self.ca], serialization.BestAvailableEncryption(b'fixture-password'))
        (self.root/'cert.pfx').write_bytes(pfx)
        pair = external.load_pair(pfx_path=self.root/'cert.pfx', password=b'fixture-password')
        external.validate_pair(*pair, 'agents.example.test', self.trust, OPENSSL)
        with self.assertRaises(ValueError):
            external.load_pair(pfx_path=self.root/'cert.pfx', password=b'wrong')

    def test_expired_leaf_rejected(self):
        now = dt.datetime.now(dt.timezone.utc)
        leaf = (x509.CertificateBuilder().subject_name(self.ca.subject).issuer_name(self.ca.subject)
                .public_key(self.key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now-dt.timedelta(days=3)).not_valid_after(now-dt.timedelta(days=2))
                .sign(self.key, hashes.SHA256()))
        (self.root/'cert.pem').write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        (self.root/'key.pem').write_bytes(external.pem_key(self.key))
        with self.assertRaisesRegex(ValueError, 'no vigente'):
            external.load_pair(self.root/'cert.pem', self.root/'key.pem')

    def test_lab_ip_certificate(self):
        pair = external.private_pair('203.0.113.12', self.ca, self.key)
        external.validate_pair(*pair, '203.0.113.12', self.trust, OPENSSL)
        external.validate_pair(*pair, '127.0.0.1', self.trust, OPENSSL)

    def test_real_tls_health_handshake(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200); self.end_headers(); self.wfile.write(b'{}')
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.root/'cert.pem', self.root/'key.pem')
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            external.check_live('agents.example.test', server.server_port, '/health', self.trust)
        finally:
            server.shutdown(); server.server_close(); thread.join()

    def exercise_transaction(self, health_failure):
        web = self.root/'etc/web.json'; gateway = self.root/'etc/gateway.json'
        web.parent.mkdir()
        web.write_text(json.dumps({'listen_port': 28443}))
        gateway.write_text(json.dumps({'listen_port': 29443, 'require_agent_mtls': True}))
        hosts = self.root/'etc/hosts'; hosts.write_text('127.0.0.1 localhost\n')
        state = self.root/'etc/state.json'
        originals = {p: p.read_bytes() for p in (web, gateway, hosts)}
        args = SimpleNamespace(web_host='admin.example.test', agent_host='agents.example.test', web_port=9443,
                               agent_port=443, admin_cidr=['203.0.113.4/32'], mode='private-ca')
        fake_grp = SimpleNamespace(getgrnam=lambda name: SimpleNamespace(gr_gid=0))
        chmod_calls = []
        with patch.multiple(external, BASE=self.root/'etc', WEB=web, GATEWAY=gateway, STATE=state,
                            HOSTS=hosts, SYSTEMD=self.root/'systemd', BACKUP_ROOT=self.root/'backups'), \
             patch.dict(sys.modules, {'grp': fake_grp}), \
             patch.object(external.os, 'chown', create=True), \
             patch.object(external.os, 'chmod', side_effect=lambda path, mode: chmod_calls.append((Path(path), mode))), \
             patch.object(external, 'check_port'), patch.object(external.subprocess, 'run'), \
             patch.object(external, 'check_live', side_effect=RuntimeError('bad health') if health_failure else None), \
             patch.object(external.time, 'sleep'):
            if health_failure:
                with self.assertRaisesRegex(RuntimeError, 'bad health'):
                    external.apply_configuration(args, {'web': (self.chain,self.private), 'gateway': (self.chain,self.private)}, self.trust)
            else:
                external.apply_configuration(args, {'web': (self.chain,self.private), 'gateway': (self.chain,self.private)}, self.trust)
        return originals, state, web, gateway, chmod_calls

    def test_transaction_rolls_back_on_failed_health(self):
        originals, state, web, gateway, _ = self.exercise_transaction(True)
        for path, data in originals.items():
            self.assertEqual(path.read_bytes(), data)
        self.assertFalse(state.exists())
        self.assertEqual(list((self.root/'systemd').rglob('*.conf')), [])

    def test_transaction_publishes_verified_state_and_minimal_capability(self):
        originals, state, web, gateway, chmod_calls = self.exercise_transaction(False)
        result = external.read_json(state)
        self.assertEqual(result['status'], 'LOCAL_HTTPS_PASS_EXTERNAL_DNS_FIREWALL_PENDING')
        self.assertEqual(result['agent_url'], 'https://agents.example.test')
        self.assertTrue(external.read_json(gateway)['require_agent_mtls'])
        self.assertEqual(external.read_json(web)['listen_port'], 9443)
        self.assertTrue((Path(result['generation'])/'trust.pem').is_file())
        self.assertEqual(len(list(Path(result['backup']).iterdir())), len(originals))
        gateway_dropin = self.root/'systemd/gideon-agent-gateway.service.d/20-gideon-public-tls.conf'
        web_dropin = self.root/'systemd/gideon-web-admin.service.d/20-gideon-public-tls.conf'
        self.assertIn('AmbientCapabilities=CAP_NET_BIND_SERVICE', gateway_dropin.read_text())
        self.assertNotIn('CAP_NET_BIND_SERVICE', web_dropin.read_text())
        role_modes = {(path.name, mode) for path, mode in chmod_calls if path.name in {'web', 'gateway'}}
        self.assertEqual(role_modes, {('web', 0o750), ('gateway', 0o750)})


class ConfigTests(unittest.TestCase):
    def test_hosts_bind_mount_write_does_not_create_tempfile_in_read_only_etc(self):
        with tempfile.TemporaryDirectory(prefix='gideon-hosts-write-') as root:
            hosts = Path(root) / 'hosts'
            hosts.write_text('127.0.0.1 localhost\n')
            with patch.object(external, 'HOSTS', hosts), \
                 patch.object(external.tempfile, 'mkstemp', side_effect=AssertionError('must not write beside /etc/hosts')):
                external.atomic_write(hosts, b'127.0.0.1 localhost admin.example.test\n', 0o644)
            self.assertEqual(hosts.read_bytes(), b'127.0.0.1 localhost admin.example.test\n')

    def test_later_preserves_installed_certificate_and_renewal_state(self):
        args = external.parser().parse_args(['--wizard'])
        old = {'mode': 'letsencrypt', 'status': 'LOCAL_HTTPS_PASS_EXTERNAL_DNS_FIREWALL_PENDING'}
        with patch.object(external.Path, 'exists', return_value=True), \
             patch.object(external, 'read_json', return_value=old), \
             patch.object(external, 'prompt', return_value='later'), \
             patch.object(external, 'atomic_write') as write:
            self.assertFalse(external.wizard(args))
            self.assertTrue(old['status'].startswith('LOCAL_HTTPS_PASS'))
            write.assert_not_called()

    def test_invalid_interactive_mode_fails_before_collecting_paths(self):
        args = external.parser().parse_args(['--wizard'])
        with patch.object(external.Path, 'exists', return_value=False), \
             patch.object(external, 'read_json', return_value={}), \
             patch.object(external, 'prompt', return_value='typo') as prompt:
            with self.assertRaisesRegex(ValueError, 'Seleccione'):
                external.wizard(args)
            self.assertEqual(prompt.call_count, 1)

    def test_acme_validation_does_not_request_certificate(self):
        with patch.object(external.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'ACME requiere'):
                external.main(['--mode','letsencrypt','--web-host','admin.example.com',
                               '--agent-host','agents.example.com','--admin-cidr','203.0.113.4/32'])
            run.assert_not_called()

    def test_embedded_installer_python_syntax(self):
        paths = [ROOT/'installers/LINUX/install-gideon-master-linux.sh', APP/'deploy/aws/install_gideon_aws.sh']
        count=0
        for path in paths:
            text=path.read_text(encoding='utf-8-sig')
            for code in re.findall(r"<<'?PY'?[^\n]*\n(.*?)\nPY(?:\n|$)", text, re.S):
                compile(code, str(path), 'exec')
                count+=1
        self.assertGreater(count,20)

    def test_host_validation(self):
        self.assertEqual(external.host_name('Agents.Example.com.'), 'agents.example.com')
        for value in ('https://example.com', 'a.com:443', 'evil.com\nfoo', '0.0.0.0', '127.0.0.1', '999.4.4.4', '-x.test', '169.254.1.2', '2001:db8::1'):
            with self.subTest(value=value), self.assertRaises(ValueError): external.host_name(value)

    def test_deny_open_admin(self):
        for value in ([], ['0.0.0.0/0'], ['::/0'], ['bad']):
            with self.subTest(value=value), self.assertRaises(ValueError): external.admin_networks(value)

    def test_url_and_mtls_preserved(self):
        args = SimpleNamespace(web_host='admin.example.com',agent_host='agents.example.com',web_port=9443,
                               agent_port=443,admin_cidr=['203.0.113.1/32'])
        web, gw = external.build_configs({'agent_public_gateway_url':'https://old:29443'},
                                         {'require_agent_mtls':True,'client_ca_file':'/private/agent-ca.pem'},args,Path('/generation'))
        self.assertTrue(gw['require_agent_mtls'])
        self.assertEqual(gw['client_ca_file'], '/private/agent-ca.pem')
        self.assertEqual(gw['public_url'], 'https://agents.example.com')
        self.assertEqual(web['gateway_base_url'], 'https://agents.example.com')
        self.assertFalse(web['trust_proxy_headers'])
        self.assertEqual(web['agent_public_gateway_url'], gw['public_url'])

    def test_hosts_idempotent_and_preserves_others(self):
        original='127.0.0.1 localhost\n10.0.0.2 another.internal\n'
        updated=external.managed_hosts(original,['admin.example.com','agents.example.com'])
        self.assertIn('10.0.0.2 another.internal',updated)
        self.assertEqual(updated,external.managed_hosts(updated,['admin.example.com','agents.example.com']))
        with self.assertRaises(ValueError):
            external.managed_hosts(original+'10.0.0.4 agents.example.com\n',['agents.example.com'])


class BoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def run_scope(self, address, kind='http', networks=None):
        sent=[]
        async def app(scope,receive,send): sent.append({'type':'allowed'})
        async def send(message): sent.append(message)
        gate=boundary.AdminNetworkBoundary(app, networks if networks is not None else ['203.0.113.4/32'])
        await gate({'type':kind,'client':(address,1),'headers':[(b'x-forwarded-for',b'203.0.113.4')]},None,send)
        return sent

    async def test_spoofed_forwarded_header_denied(self):
        self.assertEqual((await self.run_scope('198.51.100.9'))[0]['status'],403)

    async def test_websocket_denied(self):
        self.assertEqual((await self.run_scope('198.51.100.9','websocket'))[0]['code'],1008)

    async def test_allowed_http_and_websocket(self):
        for kind in ('http','websocket'):
            self.assertEqual((await self.run_scope('203.0.113.4',kind))[0]['type'],'allowed')

    async def test_empty_allowlist_fails_closed(self):
        self.assertEqual((await self.run_scope('203.0.113.4',networks=[]))[0]['status'],403)

    async def test_ipv4_mapped(self):
        self.assertEqual((await self.run_scope('::ffff:203.0.113.4'))[0]['type'],'allowed')


if __name__ == '__main__':
    unittest.main(verbosity=2)
