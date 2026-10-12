from __future__ import annotations
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Any
from gideon_agent_builder import AGENT_PROTOCOL, AgentBuilder, validate_version
from gideon_agent_security import ensure_ed25519_keypair, sha256_file, sign_file
from gideon_agent_payload import PRESERVED_RUNTIME_NAMES, RUNTIME_FILES, copy_agent_runtime_payload, runtime_relative_files
from gideon_agent_catalog import DEBIAN_AGENT_REQUIREMENTS, DEBIAN_SYSTEM_PYTHON_DEPENDENCIES, TARGETS
from gideon_agent_windows_runtime import DEFAULT_REQUIREMENTS
from gideon_branding import BrandingRepository
from gideon_packaging.windows_exe import WindowsExePackager

PLAYER_LAUNCHER_PROFILE = {
    'Schema': 'gideon-agent-player-launch/v1',
    # Playback is still authorized only by a signed campaign manifest.  The
    # signed update is allowed to install the fixed retry units so a physical
    # screen survives boot and local user switches without manual intervention.
    'Delivery': 'install-root-and-systemd',
    'RelativePath': 'gideon-agent-player-launch',
    'Activation': 'signed-campaign-auto',
    'AutoEnable': True,
    'SystemdUnits': 'signed-update-or-native-installer',
}

# A self-update must stay small enough to verify, unpack and roll back on an
# entry-level Raspberry without taking down its Agent. The legal offline VLC
# kit (including corresponding source) belongs to fresh installers or a later,
# explicit signed component-maintenance flow, never to the Agent core update.
MAX_SELF_UPDATE_BUNDLE_BYTES = 256 * 1024 * 1024
CORE_UPDATE_OFFLINE_VLC_POLICY = {
    'Bundled': False,
    'ExternalVlcOnly': True,
    'NetworkDownloads': False,
    'InstallRequiresSignedApproval': True,
    'Delivery': 'fresh-installer-or-explicit-signed-component',
    'ExistingKit': 'preserved',
    'Reason': 'VLC_OFFLINE_EXCLUDED_FROM_CORE_SELF_UPDATE',
}

def _norm_platform(v:str)->str:
    v=str(v or '').strip().lower(); return {'macos':'darwin','mac':'darwin','win32':'windows'}.get(v,v)
def _norm_arch(v:str)->str:
    v=str(v or '').strip().lower(); return {'amd64':'x86_64','x64':'x86_64','aarch64':'arm64','armv7':'armv7l','armhf':'armv7l'}.get(v,v)

def stable_release_targets()->list[dict[str,Any]]:
    grouped={}
    for target_id,raw in TARGETS.items():
        if not isinstance(raw,dict): continue
        p=_norm_platform(raw.get('platform')); a=_norm_arch(raw.get('architecture'))
        if not p or not a: continue
        row=grouped.setdefault((p,a),{'id':f'{p}_{a}','platform':p,'architecture':a,'labels':[],'generator_targets':[],'package_types':[]})
        label=str(raw.get('label') or target_id); pt=str(raw.get('package_type') or '')
        if label not in row['labels']: row['labels'].append(label)
        row['generator_targets'].append(str(target_id))
        if pt and pt not in row['package_types']: row['package_types'].append(pt)
    for row in grouped.values():
        p,a=row['platform'],row['architecture']
        if p=='windows': row['label']='Windows x64 / Server' if a=='x86_64' else f'Windows {a}'
        elif p=='linux' and a=='x86_64': row['label']='Linux x64 · DEB/RPM'
        elif p=='linux' and a=='arm64': row['label']='Linux ARM64 · DEB/RPM'
        elif p=='linux' and a=='armv7l': row['label']='Raspberry Pi / Linux ARMHF'
        elif p=='darwin' and a=='arm64': row['label']='macOS Apple Silicon'
        elif p=='darwin' and a=='x86_64': row['label']='macOS Intel'
        else: row['label']=f'{p} {a}'
        row['coverage']=' · '.join(row['labels'])
    order={'windows':0,'linux':1,'darwin':2}
    return sorted(grouped.values(),key=lambda x:(order.get(x['platform'],99),x['architecture']))

def resolve_release_target(*,target_id:str='',platform:str='',architecture:str='')->dict[str,Any]:
    rows=stable_release_targets()
    if target_id:
        for r in rows:
            if r['id']==target_id:return dict(r)
        raise ValueError(f'RELEASE_TARGET_UNKNOWN: {target_id}')
    p=_norm_platform(platform); a=_norm_arch(architecture)
    for r in rows:
        if r['platform']==p and r['architecture']==a:return dict(r)
    raise ValueError(f'RELEASE_TARGET_UNSUPPORTED: {p}/{a}')

class AgentUpdateBundleBuilder:
    RUNTIME_FILES=RUNTIME_FILES
    def __init__(self,app_root:Path,profiles_path:Path|None=None)->None:
        self.app_root=Path(app_root).resolve()
        candidates=[
            Path(profiles_path).resolve() if profiles_path else None,
            self.app_root/'config'/'host_profiles.json',
            self.app_root/'deploy'/'web'/'default-host-profiles.json',
            Path(os.environ.get('GIDEON_WEB_DATA_DIR','')).expanduser()/'config'/'host_profiles.json' if os.environ.get('GIDEON_WEB_DATA_DIR') else None,
        ]
        profiles=next((p for p in candidates if p and p.is_file()), self.app_root/'config'/'host_profiles.json')
        if not profiles.is_file():
            raise FileNotFoundError('RELEASE_PROFILE_CATALOG_MISSING: config/host_profiles.json o deploy/web/default-host-profiles.json')
        self.builder=AgentBuilder(self.app_root,profiles_path=profiles)
    @staticmethod
    def now_iso()->str:return dt.datetime.now().astimezone().isoformat(timespec='seconds')
    @staticmethod
    def _sha256(path:Path)->str:
        h=hashlib.sha256()
        with Path(path).open('rb') as f:
            for c in iter(lambda:f.read(1024*1024),b''):h.update(c)
        return h.hexdigest()
    def _generator_sources(self,target):
        p=target['platform']
        files=[self.app_root/'gideon_agent.py',self.app_root/'gideon_reverse_tunnel.py',self.app_root/'gideon_agent_payload.py',self.app_root/'gideon_agent_catalog.py',self.app_root/'gideon_agent_update.py',self.app_root/'gideon_agent_vlc_offline.py']
        if p=='windows': files += [self.app_root/'deploy/agent/windows/gideon-agent-setup.ps1',self.app_root/'deploy/agent/windows/GIDEONAgentServiceHost.cs',self.app_root/'gideon_packaging/windows_exe.py']
        elif p=='linux': files += [self.app_root/'deploy/agent/linux/gideon-agent-setup',self.app_root/'deploy/agent/linux/gideon-agent-first-run-launch',self.app_root/'deploy/agent/linux/gideon-agent-first-run-native',self.app_root/'deploy/agent/linux/gideon-agent-player-launch']
        else: files += [self.app_root/'deploy/agent/macos/gideon-agent-setup',self.app_root/'deploy/agent/macos/gideon-agent-first-run-native']
        miss=[str(x) for x in files if not x.is_file()]
        if miss: raise RuntimeError('GENERATOR_SOURCE_INCOMPLETE: '+', '.join(miss))
        return files
    def _runtime_contract(self,payload:Path,version:str):
        a=payload/'gideon_agent.py'; t=payload/'gideon_reverse_tunnel.py'; at=a.read_text(encoding='utf-8-sig'); tt=t.read_text(encoding='utf-8-sig')
        req=re.search(r'(?m)^REVERSE_TUNNEL_API_REQUIRED\s*=\s*(\d+)\s*$',at); got=re.search(r'(?m)^TUNNEL_API_VERSION\s*=\s*(\d+)\s*$',tt)
        if not req or not got or int(req.group(1))!=int(got.group(1)): raise RuntimeError('RELEASE_RUNTIME_CONTRACT_MISMATCH: BUILD BLOCKED')
        c={'schema':'gideon-agent-runtime-contract/v1','agent_version':version,'reverse_tunnel_api_required':int(req.group(1)),'reverse_tunnel_api_provided':int(got.group(1)),'platform_independent':True,'sha256':{'gideon_agent.py':self._sha256(a),'gideon_reverse_tunnel.py':self._sha256(t)}}
        (payload/'runtime.contract.json').write_text(json.dumps(c,ensure_ascii=False,indent=2),encoding='utf-8'); return c
    @staticmethod
    def _profile(target):
        p=target['platform']
        if p=='windows': return {'ServiceKind':'windows-service','ServiceId':'GIDEONAgent','RemoteAccess':{'Protocol':'RDP','Host':'127.0.0.1','Port':3389,'Server':'windows-rdp','Managed':True,'OpenInboundFirewall':False}}
        if p=='linux': return {'ServiceKind':'systemd','ServiceId':'gideon-agent.service','RemoteAccess':{'Protocol':'RDP','Host':'127.0.0.1','Port':3389,'Server':'xrdp','Managed':True,'LoopbackOnly':True,'OpenInboundFirewall':False}}
        return {'ServiceKind':'launchd','ServiceId':'pe.com.gideons.gideonagent','RemoteAccess':{'Protocol':'VNC','Host':'127.0.0.1','Port':5900,'Server':'apple-remote-management','Managed':True,'OpenInboundFirewall':False}}
    def build(self,*,version:str,target_id:str='',platform:str='windows',architecture:str='x86_64',channel:str='stable',output_dir:Path|None=None,offline_vlc_distribution:str='',offline_vlc_codename:str='')->dict[str,Any]:
        version=validate_version(version); channel=str(channel or 'stable').lower()
        if channel!='stable': raise ValueError('Only stable channel is supported')
        target=resolve_release_target(target_id=target_id,platform=platform,architecture=architecture); p=target['platform']; a=target['architecture']
        ensure_ed25519_keypair(self.builder.private_key,self.builder.public_key)
        out=Path(output_dir or (self.builder.state_dir/'update-bundles')); out.mkdir(parents=True,exist_ok=True)
        final=out/f'GIDEONAgent-Update-{p}-{a}-{channel}-v{version}.zip'
        with tempfile.TemporaryDirectory(prefix='gideon-agent-update-') as td:
            stage=Path(td); payload=stage/'payload'; payload.mkdir(parents=True); copy_agent_runtime_payload(self.app_root,payload)
            # Do not embed a full VLC/component closure in ordinary updates.
            # A fresh generated installer still stages the target-specific kit
            # through AgentBuilder, with the corresponding GPL sources.
            offline_vlc_bundle=dict(CORE_UPDATE_OFFLINE_VLC_POLICY)
            ap=payload/'gideon_agent.py'; s=ap.read_text(encoding='utf-8-sig'); s,n=re.subn(r'^VERSION\s*=\s*["\'][^"\']+["\']',f'VERSION = "{version}"',s,count=1,flags=re.M)
            if n!=1: raise RuntimeError('No se pudo fijar VERSION en gideon_agent.py')
            ap.write_text(s,encoding='utf-8'); contract=self._runtime_contract(payload,version)
            shutil.copy2(self.builder.public_key,payload/'gideon_agent_signing_public.pem')
            (payload/'requirements-agent.txt').write_text(DEFAULT_REQUIREMENTS,encoding='utf-8')
            if p=='linux':
                # Debian-family Agents select this file during update.  The
                # package manager supplies cryptography/Pillow for the host
                # architecture and pip installs only pystray's universal wheel.
                (payload/'requirements-agent-debian.txt').write_text(DEBIAN_AGENT_REQUIREMENTS,encoding='utf-8')
                player_launcher=self.app_root/'deploy'/'agent'/'linux'/'gideon-agent-player-launch'
                if not player_launcher.is_file(): raise RuntimeError('PLAYER_LINUX_LAUNCHER_MISSING')
                shutil.copy2(player_launcher,payload/'gideon-agent-player-launch')
                (payload/'gideon-agent-player-launch').chmod(0o755)
            for icon in ('gideon_agent_tray.png','gideon_agent_tray.ico'):
                src=self.app_root/'assets'/icon
                if src.is_file():shutil.copy2(src,payload/icon)
            branding=self.app_root/'config/branding.json'
            if branding.is_file():shutil.copy2(branding,payload/'branding.json')
            if p=='windows':
                pack=WindowsExePackager(self.app_root); brand=BrandingRepository(self.app_root).load(); host=pack._build_agent_service_host(payload_dir=payload,source_dir=stage/'windows-service-host-build',version=version,brand=brand)
                if not host.is_file():raise RuntimeError('WINDOWS_RELEASE_SERVICE_HOST_MISSING')
            profile={'Schema':'gideon-agent-update-profile/v2','Version':version,'Platform':p,'Architecture':a,'GeneratorTargetId':target['id'],'GeneratorTargets':target['generator_targets'],'PackageTypes':target['package_types'],'PreserveIdentity':True,'PreserveSite':True,'PreserveToken':True,'PreserveGatewayTrust':True,**self._profile(target)}
            if offline_vlc_bundle is not None:profile['OfflineVlc']=offline_vlc_bundle
            if p=='linux':
                profile['DebianSystemPythonDependencies']=list(DEBIAN_SYSTEM_PYTHON_DEPENDENCIES)
                profile['PlayerLauncher']=dict(PLAYER_LAUNCHER_PROFILE)
            (payload/'update-profile.json').write_text(json.dumps(profile,ensure_ascii=False,indent=2),encoding='utf-8')
            sources={x.relative_to(self.app_root).as_posix():self._sha256(x) for x in self._generator_sources(target)}
            (stage/'generator-source.json').write_text(json.dumps({'Schema':'gideon-agent-generator-source/v1','Version':version,'ReleaseTarget':target,'Sources':sources},ensure_ascii=False,indent=2),encoding='utf-8')
            manifest={'Product':'Gideon Rx Agent Update','Version':version,'ProtocolVersion':AGENT_PROTOCOL,'Platform':p,'Architecture':a,'Channel':channel,'CreatedAt':self.now_iso(),'SiteNeutral':True,'Preserves':sorted(PRESERVED_RUNTIME_NAMES),'PreserveIdentity':True,'GeneratorDerived':True,'GeneratorTargetId':target['id'],'GeneratorTargets':target['generator_targets'],'RuntimeContract':contract,'HostService':profile['ServiceKind'],'RemoteAccess':profile['RemoteAccess'],'OfflineVlc':offline_vlc_bundle,'Files':{}}
            for rel in runtime_relative_files(payload):manifest['Files'][rel.as_posix()]=sha256_file(payload/rel)
            mp=stage/'release-manifest.json'; mp.write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8'); (stage/'release-manifest.sig').write_text(sign_file(mp,self.builder.private_key),encoding='ascii')
            if final.exists():final.unlink()
            with zipfile.ZipFile(final,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as zf:
                for f in stage.rglob('*'):
                    if f.is_file():zf.write(f,f.relative_to(stage).as_posix())
        if final.stat().st_size > MAX_SELF_UPDATE_BUNDLE_BYTES:
            final.unlink(missing_ok=True)
            raise RuntimeError(
                f'RELEASE_SELF_UPDATE_BUNDLE_TOO_LARGE: {MAX_SELF_UPDATE_BUNDLE_BYTES} bytes maximum; '
                'deliver third-party components through their explicit signed flow.'
            )
        row={'version':version,'protocol':AGENT_PROTOCOL,'channel':channel,'platform':p,'architectures':[a],'architecture':a,'target_id':target['id'],'target_label':target['label'],'generator_targets':target['generator_targets'],'bundle':str(final),'sha256':sha256_file(final),'signature':sign_file(final,self.builder.private_key),'key_id':'gideon-agent-ed25519-1','created_at':self.now_iso(),'site_neutral':True,'generator_derived':True,'offline_vlc':offline_vlc_bundle}
        hist=[x for x in self.builder.release_history() if not (str(x.get('version') or '')==version and str(x.get('platform') or '').lower()==p and str(x.get('architecture') or '').lower()==a)]; hist.insert(0,row); self.builder.release_file.write_text(json.dumps(hist[:300],ensure_ascii=False,indent=2),encoding='utf-8'); return row
