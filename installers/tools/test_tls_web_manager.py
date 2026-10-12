"""TLS broker/HTTP regression suite. Isolated files; no systemd, cloud or production keys."""
from __future__ import annotations

import asyncio
import base64
from contextlib import nullcontext
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / 'payload/linux/app'
# Reuse bundled pure-Python Web dependencies when the host Python has none.
try:
    import fastapi
except ImportError:
    sys.path.append(str(ROOT/'payload/windows/GIDEON Remote Control/venv/Lib/site-packages'))
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

sys.path.insert(0, str(APP/'deploy/ubuntu'))
import gideon_tls_manager as broker
import gideon_external_access as tls
import test_linux_external_access as fixtures

spec = importlib.util.spec_from_file_location('tls_management', APP/'gideon_web_admin/tls_management.py')
web = importlib.util.module_from_spec(spec)
spec.loader.exec_module(web)


def systemd_stub():
    original = broker.subprocess.run
    return patch.object(broker.subprocess, 'run', side_effect=lambda command, **kwargs:
                        SimpleNamespace(returncode=0) if command[0] == 'systemctl' else original(command, **kwargs))


class BrokerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.CertificateTests.setUpClass()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='gideon-tls-broker-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.jobs = self.root/'jobs'; self.jobs.mkdir()
        self.active = self.jobs/'active.json'
        self.patches = patch.multiple(broker, ROOT=self.jobs, ACTIVE=self.active)
        self.patches.start(); self.addCleanup(self.patches.stop)
        self.params = dict(mode='pem', web_host='admin.example.com', agent_host='agents.example.com',
                           web_port=9443, agent_port=443, admin_cidr=['203.0.113.4/32'])
        self.job_id = 'a'*32

    def job(self, state='PREPARED'):
        path = broker.job_path(self.job_id); path.mkdir(exist_ok=True)
        job = {'id': self.job_id, 'actor': 'admin', 'state': state, 'created': int(time.time()),
               'expires': int(time.time())+60, 'deadline': int(time.time())+60, 'baseline': 'old',
               'params': {**self.params, 'accept_agent_reconfiguration': True},
               'preview': {'web_url': 'https://admin.example.com:9443'}, 'needs_agent_reconfiguration': False}
        broker.store_job(job)
        return job

    def test_rejects_arbitrary_paths_and_fields(self):
        for value in ('../../etc/passwd', '/tmp/job', 'A'*32, '', None):
            with self.subTest(value=value), self.assertRaises(ValueError): broker.job_path(value)
        with self.assertRaises(ValueError): broker.parameters({**self.params, 'command': 'id'}, '203.0.113.4')
        with self.assertRaises(ValueError): broker.decode_uploads({'../../secret': 'YQ=='})

    def test_rejects_admin_lockout(self):
        with self.assertRaisesRegex(ValueError, 'IP actual'):
            broker.parameters(self.params, '198.51.100.7')

    def test_rejects_open_admin_and_port_collision(self):
        with self.assertRaises(ValueError): broker.parameters({**self.params, 'admin_cidr':['0.0.0.0/0']}, '203.0.113.4')
        with self.assertRaises(ValueError): broker.parameters({**self.params, 'web_port':443}, '203.0.113.4')

    def test_rejects_non_boolean_consent(self):
        with self.assertRaises(ValueError): broker.parameters({**self.params, 'agree_acme_tos':'false'}, '203.0.113.4')

    def test_acme_preflight_does_not_issue(self):
        with patch.object(broker.shutil, 'which', return_value='/usr/bin/certbot'), \
             patch.object(tls, 'check_port'), patch.object(tls, 'obtain_letsencrypt') as obtain:
            args = broker.parameters({**self.params, 'mode':'letsencrypt','email':'admin@example.com','agree_acme_tos':True}, '203.0.113.4')
            self.assertEqual(broker.prepare_pairs(args, {}, {}), ({}, b''))
            obtain.assert_not_called()

    def test_bounded_uploads(self):
        self.assertEqual(broker.decode_uploads({'web_cert':'YQ=='}), {'web_cert':b'a'})
        for value in ('not_base64', base64.b64encode(b'x'*(512*1024+1)).decode()):
            with self.assertRaises(ValueError): broker.decode_uploads({'web_key':value})

    def test_actor_ownership(self):
        self.job()
        with self.assertRaises(ValueError): broker.load_job(self.job_id, 'another-admin')

    def test_preview_never_returns_internal_state_or_material(self):
        job = self.job(); job.update(private_key='SECRET', passwords={'web':'SECRET'}, rollback='SECRET')
        self.assertNotIn('SECRET', json.dumps(broker.public_job(job)))
        self.assertNotIn('params', broker.public_job(job))

    def test_apply_rejects_stale_configuration(self):
        self.job()
        with patch.object(broker, 'revision', return_value='new'), patch.object(broker.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'cambió'): broker.schedule_apply(self.job_id, 'admin')
            run.assert_not_called()

    def test_apply_is_single_use_and_independent_systemd_job(self):
        self.job()
        with patch.object(broker, 'revision', return_value='old'), patch.object(broker.subprocess, 'run') as run:
            result = broker.schedule_apply(self.job_id, 'admin')
            self.assertEqual(result['state'], 'APPLYING')
            self.assertTrue(self.active.exists())
            command = run.call_args.args[0]
            self.assertEqual(command, ['systemctl','start','--no-block','gideon-tls-apply@'+self.job_id+'.service'])
            with self.assertRaises(ValueError): broker.schedule_apply(self.job_id, 'admin')

    def test_dispatch_failure_clears_active_marker(self):
        self.job()
        with patch.object(broker, 'revision', return_value='old'), patch.object(broker.subprocess, 'run', side_effect=OSError('fixture')):
            with self.assertRaises(OSError): broker.schedule_apply(self.job_id, 'admin')
        self.assertFalse(self.active.exists())
        self.assertEqual(broker.load_job(self.job_id)['state'], 'PREPARED')

    def test_confirmation_requires_new_origin_and_deadline(self):
        job = self.job('AWAITING_CONFIRMATION')
        with self.assertRaises(ValueError): broker.confirm(self.job_id, 'admin', 'https://old.example.com')
        job['deadline'] = int(time.time())-1; broker.store_job(job)
        with self.assertRaises(ValueError): broker.confirm(self.job_id, 'admin', 'https://admin.example.com:9443')

    def test_confirmation_commits_and_clears_material(self):
        job = self.job('AWAITING_CONFIRMATION'); broker.save(self.active, {'id':self.job_id})
        (broker.job_path(self.job_id)/'web.key').write_bytes(b'fixture-not-a-real-key')
        with patch.object(broker.subprocess, 'run'):
            result = broker.confirm(self.job_id, 'admin', 'https://admin.example.com:9443')
        self.assertEqual(result['state'], 'CONFIRMED')
        self.assertFalse(self.active.exists())
        self.assertFalse((broker.job_path(self.job_id)/'web.key').exists())

    def test_deadline_and_reboot_restore_snapshot(self):
        for boot in (False, True):
            job = self.job('AWAITING_CONFIRMATION'); job['deadline'] = time.time() + (60 if boot else -1)
            broker.store_job(job); broker.save(self.active, {'id':self.job_id})
            broker.save(broker.job_path(self.job_id)/'rollback.json', {'fixture':'snapshot'})
            with patch.object(tls, 'restore_configuration') as restore, patch.object(broker.subprocess, 'run'):
                broker.recover(boot=boot)
                restore.assert_called_once_with({'fixture':'snapshot'})
            self.assertEqual(broker.load_job(self.job_id)['state'], 'ROLLED_BACK')

    def test_confirmed_marker_never_rolls_back_on_reboot(self):
        self.job('CONFIRMED'); broker.save(self.active, {'id':self.job_id})
        with patch.object(tls, 'restore_configuration') as restore:
            broker.recover(boot=True); restore.assert_not_called()
        self.assertFalse(self.active.exists())

    def test_expiration_removes_private_staging_files(self):
        job = self.job(); job['expires'] = time.time()-1; broker.store_job(job)
        (broker.job_path(self.job_id)/'web.key').write_bytes(b'test-key')
        broker.cleanup()
        self.assertEqual(broker.load_job(self.job_id)['state'], 'EXPIRED')
        self.assertFalse((broker.job_path(self.job_id)/'web.key').exists())

    def test_socket_rejects_foreign_uid_before_reading_request(self):
        conn = Mock(); conn.getsockopt.return_value = struct.pack('3i', 17, 999, 999)
        pwd = SimpleNamespace(getpwnam=lambda name: SimpleNamespace(pw_uid=200))
        with patch.dict(sys.modules, {'pwd':pwd}), patch.object(socket, 'SO_PEERCRED', 17, create=True):
            with self.assertRaises(ValueError): broker.peer_allowed(conn)

    def test_socket_oversized_request(self):
        conn = Mock(); conn.recv.return_value = b'x'*12
        with patch.object(broker, 'MAX_MESSAGE', 10):
            with self.assertRaises(ValueError): broker.receive(conn)

    def test_restore_rejects_unapproved_targets(self):
        with patch.object(tls, 'snapshot_configuration', return_value={'/safe':None}), patch.object(tls, 'atomic_write') as write:
            with self.assertRaises(ValueError): tls.restore_configuration({'/etc/shadow':None})
            write.assert_not_called()

    def prepare_pfx(self):
        fixture = fixtures.CertificateTests
        cert = tls.x509.load_pem_x509_certificates(fixture.chain)[0]
        key = tls.serialization.load_pem_private_key(fixture.private, None)
        pfx = tls.pkcs12.serialize_key_and_certificates(b'test',key,cert,[fixture.ca],
                    tls.serialization.BestAvailableEncryption(b'stage-pfx-password'))
        config = self.root/'etc'; config.mkdir()
        web_config=config/'web.json'; gateway_config=config/'gateway.json'; hosts=config/'hosts'
        web_config.write_text(json.dumps({'listen_port':28443,'data_dir':str(self.root/'web-data')}))
        gateway_config.write_text(json.dumps({'listen_port':29443,'require_agent_mtls':True}))
        hosts.write_text('127.0.0.1 localhost\n')
        patched=patch.multiple(tls, WEB=web_config,GATEWAY=gateway_config,STATE=config/'state.json',
                               HOSTS=hosts,SYSTEMD=self.root/'systemd')
        patched.start(); self.addCleanup(patched.stop)
        original = tls.validate_pair
        validator=patch.object(tls,'validate_pair',side_effect=lambda *args:original(*args,openssl=fixtures.OPENSSL))
        validator.start();self.addCleanup(validator.stop)
        request={'actor':'admin','client_ip':'203.0.113.4','params':{**self.params,'mode':'pfx',
                 'web_host':'agents.example.test','agent_host':'agents.example.test'},
                 'uploads':{'web_pfx':base64.b64encode(pfx).decode(),'ca':base64.b64encode(fixture.trust).decode()},
                 'passwords':{'web':'stage-pfx-password'}}
        with patch.object(tls,'check_port'), systemd_stub():
            result=broker.prepare(request)
        return result

    def test_encrypted_pfx_prepare_keeps_no_password_or_raw_pfx(self):
        result=self.prepare_pfx()
        path=broker.job_path(result['id'])
        self.assertTrue((path/'web.key').is_file())
        self.assertNotIn('stage-pfx-password', (path/'job.json').read_text())
        self.assertFalse(list(path.glob('*.pfx')))
        self.assertNotIn('PRIVATE KEY',json.dumps(result))

    def test_prepared_pfx_apply_waits_for_remote_confirmation(self):
        result=self.prepare_pfx()
        with systemd_stub(), patch.object(tls,'apply_configuration') as apply:
            broker.schedule_apply(result['id'],'admin')
            broker.apply_job(result['id'])
            apply.assert_called_once()
            self.assertEqual(broker.load_job(result['id'])['state'],'AWAITING_CONFIRMATION')
            self.assertTrue(self.active.exists())
            self.assertFalse((broker.job_path(result['id'])/'web.key').exists())

    def test_failed_apply_restores_prior_snapshot(self):
        result=self.prepare_pfx()
        with systemd_stub(), patch.object(tls,'apply_configuration',side_effect=RuntimeError('health failed')), \
             patch.object(tls,'restore_configuration') as restore:
            broker.schedule_apply(result['id'],'admin')
            broker.apply_job(result['id'])
            restore.assert_called_once()
        self.assertEqual(broker.load_job(result['id'])['state'],'ROLLED_BACK')
        self.assertFalse(self.active.exists())


async def asgi_request(app, method, path, payload=None, headers=None, scheme='https'):
    body = json.dumps(payload).encode() if payload is not None else b''
    provided = {'host':'admin.example.com:9443', 'content-type':'application/json', **(headers or {})}
    scope = {'type':'http','asgi':{'version':'3.0'},'http_version':'1.1','method':method,'scheme':scheme,
             'path':path,'raw_path':path.encode(),'query_string':b'','root_path':'',
             'headers':[(k.encode(),v.encode()) for k,v in provided.items()],
             'client':('203.0.113.4',12345),'server':('127.0.0.1',9443)}
    sent = []
    delivered = False
    async def receive():
        nonlocal delivered
        if not delivered:
            delivered=True; return {'type':'http.request','body':body,'more_body':False}
        return {'type':'http.disconnect'}
    async def send(message): sent.append(message)
    await app(scope, receive, send)
    status = next(message['status'] for message in sent if message['type']=='http.response.start')
    content = b''.join(message.get('body',b'') for message in sent if message['type']=='http.response.body')
    return status, content


class RouteTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.app = FastAPI()
        self.identity = SimpleNamespace(role='SUPERADMIN', username='admin', user_id=1, csrf_token='fixture-csrf')
        self.security = SimpleNamespace(step_up_authenticate=Mock(), audit=Mock())
        self.call = Mock(return_value={'id':'a'*32, 'state':'PREPARED'})
        def require(request, permission):
            if request.headers.get('x-test-anonymous'):
                raise HTTPException(401, 'Login required')
            return self.identity
        web.register_tls_routes(self.app, config={'tls_manager_enabled':True}, require=require, security=self.security,
                                template=lambda *args: HTMLResponse('fixture'), call=self.call)
        self.platform = patch.object(web.sys, 'platform', 'linux'); self.platform.start(); self.addCleanup(self.platform.stop)
        self.payload = {'params':{'mode':'private-ca'},'current_password':'fixture-password','mfa_code':'123456'}

    async def request(self, action='prepare', **kwargs):
        return await asgi_request(self.app,'POST','/infrastructure/tls/'+action,
                                  kwargs.pop('payload',self.payload), headers=kwargs.pop('headers',{'x-csrf-token':'fixture-csrf'}), **kwargs)

    async def test_anonymous_denied(self):
        status, _ = await self.request(headers={'x-test-anonymous':'1'})
        self.assertEqual(status,401); self.call.assert_not_called()

    async def test_non_superadmin_denied(self):
        self.identity.role='ADMIN'; status,_=await self.request()
        self.assertEqual(status,403); self.call.assert_not_called()

    async def test_csrf_and_https_required(self):
        for kwargs,expected in (({'headers':{}},403),({'scheme':'http'},400)):
            status,_=await self.request(**kwargs); self.assertEqual(status,expected)
        self.call.assert_not_called()

    async def test_wrong_mfa_denied(self):
        self.security.step_up_authenticate.side_effect=ValueError('invalid')
        status,body=await self.request(); self.assertEqual(status,403)
        self.call.assert_not_called(); self.assertNotIn(b'fixture-password',body)

    async def test_each_action_requires_fresh_step_up(self):
        for _ in range(2): self.assertEqual((await self.request())[0],200)
        self.assertEqual(self.security.step_up_authenticate.call_count,2)
        forwarded=self.call.call_args.args[0]
        self.assertNotIn('current_password',forwarded); self.assertNotIn('mfa_code',forwarded)
        self.assertEqual(forwarded['client_ip'],'203.0.113.4')

    async def test_unknown_fields_and_actions_rejected(self):
        status,_=await self.request(payload={**self.payload,'command':'id'}); self.assertEqual(status,400)
        status,_=await self.request(action='shell'); self.assertEqual(status,404)
        self.call.assert_not_called()

    async def test_request_body_is_bounded_without_content_length(self):
        with patch.object(web,'MAX_BODY',32):
            status,_=await self.request(); self.assertEqual(status,413)
        self.call.assert_not_called()

    async def test_confirm_origin_derived_from_request_not_payload(self):
        status,_=await self.request(action='confirm',payload={'id':'a'*32,'current_password':'fixture-password','mfa_code':'123456'})
        self.assertEqual(status,200)
        self.assertEqual(self.call.call_args.args[0]['origin'],'https://admin.example.com:9443')

    async def test_no_sensitive_payload_in_audit(self):
        await self.request()
        self.assertNotIn('fixture-password',str(self.security.audit.call_args))
        self.assertNotIn('123456',str(self.security.audit.call_args))


if __name__ == '__main__':
    unittest.main(verbosity=2)
