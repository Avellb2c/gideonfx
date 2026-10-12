#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,os,platform,re,secrets,shutil,socket,stat,subprocess,sys,time
from pathlib import Path
from typing import Iterable
# ``third_party`` contains reviewed component kits such as VLC plus its
# corresponding GPL source. A core Agent update must neither back up nor
# replace that potentially gigabyte-sized, independently signed material.
PRESERVE_TOP_LEVEL={'agent.json','agent.runtime.json','agent.status.json','host_profile.json','gideon_gateway_ca.pem','client.crt','client.key','bootstrap.enrollment','config.current.json','config.previous.json','config.pending.json','config.rejected.json','config.status.json','third_party','venv','runtime'}
PLAYER_LAUNCHER_PROFILE_SCHEMA='gideon-agent-player-launch/v1'
PLAYER_LAUNCHER_RELATIVE_PATH='gideon-agent-player-launch'
PLAYER_LAUNCHER_ALLOWED_ROOTS={Path('/opt/gideon-agent'),Path('/usr/lib/gideon-agent')}
PLAYER_SYSTEMD_UNIT_DIR=Path('/etc/systemd/system')
def now_stamp():return time.strftime('%Y-%m-%dT%H:%M:%S%z')
def append_log(path,message):
    try:
        path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('a',encoding='utf-8') as handle:handle.write(f'[{now_stamp()}] {message}\n')
    except Exception:return
def update_status(data,state,version,detail=''):
    """Persist updater progress while the main Agent process is stopped."""
    path=data/'agent.status.json';value={}
    try:
        if path.is_file():
            parsed=json.loads(path.read_text(encoding='utf-8-sig'))
            value=parsed if isinstance(parsed,dict) else {}
        value.update({'update_state':str(state),'update_target_version':str(version),'update_updated_at':now_stamp(),'update_error':str(detail or '')[:2000]})
        tmp=path.with_suffix(path.suffix+'.tmp');tmp.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');os.chmod(tmp,0o644);os.replace(tmp,path)
    except Exception:return
def _run(cmd,*,timeout=300,cwd=None):
    kw={'capture_output':True,'text':True,'timeout':timeout,'cwd':str(cwd) if cwd else None}
    if os.name=='nt':kw['creationflags']=getattr(subprocess,'CREATE_NO_WINDOW',0)
    return subprocess.run(cmd,**kw)
def pid_alive(pid):
    if pid<=0:return False
    try:
        if os.name=='nt':return str(pid) in (_run(['tasklist.exe','/FI',f'PID eq {pid}','/FO','CSV','/NH'],timeout=4).stdout or '')
        os.kill(pid,0);return True
    except Exception:return False
def wait_for_exit(pid,timeout=90):
    end=time.monotonic()+timeout
    while pid_alive(pid) and time.monotonic()<end:time.sleep(.5)
    if pid_alive(pid):raise RuntimeError(f'Agent PID {pid} no terminó dentro de {timeout}s')
def _platform_id():
    if os.name=='nt':return 'windows'
    return 'darwin' if sys.platform.startswith('darwin') else 'linux' if sys.platform.startswith('linux') else sys.platform.lower()
def _arch_id():
    v=platform.machine().strip().lower();return {'amd64':'x86_64','x64':'x86_64','aarch64':'arm64','armv7':'armv7l','armhf':'armv7l'}.get(v,v)
def _profile(payload,log):
    p=payload/'update-profile.json'
    if not p.is_file():append_log(log,'WARN legacy release without update-profile.json');return {}
    try:v=json.loads(p.read_text(encoding='utf-8-sig'))
    except Exception as e:raise RuntimeError(f'UPDATE_PROFILE_INVALID: {e}')
    if str(v.get('Platform') or '').lower()!=_platform_id() or str(v.get('Architecture') or '').lower()!=_arch_id():raise RuntimeError(f'UPDATE_TARGET_MISMATCH bundle={v.get("Platform")}/{v.get("Architecture")} host={_platform_id()}/{_arch_id()}')
    if v.get('PreserveIdentity') is not True or v.get('PreserveToken') is not True:raise RuntimeError('UPDATE_PROFILE_IDENTITY_POLICY_INVALID')
    return v
def _restore_linux_player_launcher(profile,root,log):
    """Restore the signed launcher and enable its bounded systemd retry timer.

    The timer does not authorize playback by itself: the launcher still needs
    a GIDEON-signed campaign manifest, verified media and an active local physical
    session.  Unit contents are generated from fixed text and only for the two
    supported root-owned install locations; no bundle field reaches a shell.
    """
    if _platform_id()!='linux':return
    declaration=profile.get('PlayerLauncher') if isinstance(profile,dict) else None
    expected={
        'Schema':PLAYER_LAUNCHER_PROFILE_SCHEMA,
        'Delivery':'install-root-and-systemd',
        'RelativePath':PLAYER_LAUNCHER_RELATIVE_PATH,
        'Activation':'signed-campaign-auto',
        'AutoEnable':True,
        'SystemdUnits':'signed-update-or-native-installer',
    }
    if not isinstance(declaration,dict) or any(declaration.get(k)!=v for k,v in expected.items()):
        append_log(log,'PLAYER_LAUNCHER_SKIPPED reason=PROFILE_NOT_DECLARED_OR_INVALID')
        return
    launcher=root/PLAYER_LAUNCHER_RELATIVE_PATH
    try:
        if launcher.is_symlink() or not launcher.is_file() or not stat.S_ISREG(launcher.stat().st_mode):
            raise OSError('launcher is not a regular file')
        os.chmod(launcher,0o755)
        resolved_root=root.resolve()
        if resolved_root not in PLAYER_LAUNCHER_ALLOWED_ROOTS:
            append_log(log,'PLAYER_LAUNCHER_READY activation=SIGNED_CAMPAIGN_AUTO units=SKIPPED_UNSUPPORTED_ROOT')
            return
        unit_dir=PLAYER_SYSTEMD_UNIT_DIR
        unit_dir.mkdir(parents=True,exist_ok=True)
        if unit_dir.is_symlink():raise OSError('systemd unit directory is a symlink')
        service=(
            '[Unit]\nDescription=GIDEON Player physical-screen launcher\n'
            'After=graphical.target gideon-agent.service\n'
            f'ConditionPathExists={launcher}\n\n[Service]\nType=oneshot\nExecStart={launcher}\n'
        )
        timer=(
            '[Unit]\nDescription=Retry GIDEON Player physical-screen launch\n\n'
            '[Timer]\nOnBootSec=30s\nOnUnitActiveSec=30s\nPersistent=true\n\n'
            '[Install]\nWantedBy=timers.target\n'
        )
        for name,text in (
            ('gideon-agent-player-launch.service',service),
            ('gideon-agent-player-launch.timer',timer),
        ):
            destination=unit_dir/name
            if destination.is_symlink():raise OSError(f'{name} is a symlink')
            temporary=unit_dir/f'.{name}.tmp-{os.getpid()}'
            temporary.write_text(text,encoding='utf-8',newline='\n')
            os.chmod(temporary,0o644);os.replace(temporary,destination);os.chmod(destination,0o644)
        reload_result=_run(['systemctl','daemon-reload'],timeout=30)
        enable_result=_run(['systemctl','enable','--now','gideon-agent-player-launch.timer'],timeout=60)
        if reload_result.returncode!=0 or enable_result.returncode!=0:
            raise OSError('systemd player timer activation failed')
        append_log(log,'PLAYER_LAUNCHER_READY activation=SIGNED_CAMPAIGN_AUTO auto_enable=true timer=ACTIVE')
    except OSError as exc:
        # Player remains isolated from the normal Agent.  A launcher/timer
        # repair failure must not roll back identity, mTLS, jobs or tunnels.
        append_log(log,f'PLAYER_LAUNCHER_UNAVAILABLE reason=FILE_OR_SYSTEMD_ERROR detail={type(exc).__name__}')
def _copy(src,dst,preserve=None):
    preserve=preserve or set();dst.mkdir(parents=True,exist_ok=True)
    for i in src.iterdir():
        if i.name in preserve:continue
        d=dst/i.name
        if i.is_dir():
            if d.exists():shutil.rmtree(d) if d.is_dir() else d.unlink()
            shutil.copytree(i,d)
        else:d.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(i,d)
def _backup(root,b):
    b.mkdir(parents=True,exist_ok=True)
    for i in root.iterdir():
        if i.name in PRESERVE_TOP_LEVEL or (i.name.startswith('unins') and i.suffix.lower() in {'.exe','.dat','.msg'}):continue
        d=b/i.name;shutil.copytree(i,d,dirs_exist_ok=True) if i.is_dir() else shutil.copy2(i,d)
def _restore(root,b):
    for i in list(root.iterdir()):
        if i.name in PRESERVE_TOP_LEVEL or (i.name.startswith('unins') and i.suffix.lower() in {'.exe','.dat','.msg'}):continue
        try:shutil.rmtree(i) if i.is_dir() else i.unlink()
        except Exception:pass
    _copy(b,root)
def _python(root):
    c=[root/'runtime/python/python.exe',root/'venv/Scripts/python.exe'] if os.name=='nt' else [root/'venv/bin/python',root/'runtime/python/bin/python3']
    for p in c:
        if p.is_file():return p
    raise RuntimeError('Agent Python runtime not found')
def refresh_dependencies(root,log):
    if os.name=='nt':append_log(log,'Windows private runtime preserved; pip skipped');return
    req=root/'requirements-agent.txt';py=_python(root);extra=[]
    deb_req=root/'requirements-agent-debian.txt'
    if sys.platform.startswith('linux') and shutil.which('dpkg') and deb_req.is_file():
        base=shutil.which('python3')
        if not base:raise RuntimeError('DEBIAN_SYSTEM_PYTHON_MISSING')
        cp=_run([base,'-m','venv','--system-site-packages',str(root/'venv')],timeout=180)
        append_log(log,f'Debian system-site-packages venv exit={cp.returncode}')
        if cp.returncode!=0:raise RuntimeError('DEBIAN_SYSTEM_SITE_VENV_FAILED')
        py=_python(root);req=deb_req;extra=['--only-binary=:all:','--no-deps']
        cp=_run([str(py),'-c','import cryptography,PIL;print(cryptography.__version__,PIL.__version__)'],timeout=30)
        if cp.returncode!=0:raise RuntimeError('DEBIAN_SYSTEM_PYTHON_DEPENDENCIES_MISSING: python3-cryptography/python3-pil')
    if req.is_file():
        cp=_run([str(py),'-m','pip','install','--disable-pip-version-check',*extra,'-r',str(req)],timeout=600);append_log(log,f'pip exit={cp.returncode}')
        if cp.returncode!=0:raise RuntimeError('pip dependency refresh failed')
def smoke(root,log):
    py=_python(root);code=f"import sys;sys.path.insert(0,{str(root)!r});import gideon_agent,gideon_reverse_tunnel,gideon_agent_http,gideon_agent_security,gideon_agent_worker,gideon_agent_job_contract,gideon_common;assert gideon_reverse_tunnel.TUNNEL_API_VERSION==gideon_agent.REVERSE_TUNNEL_API_REQUIRED;print(gideon_agent.VERSION,gideon_reverse_tunnel.TUNNEL_API_VERSION)";cp=_run([str(py),'-c',code],timeout=60,cwd=root);append_log(log,f'smoke exit={cp.returncode}: {(cp.stdout or cp.stderr or "")[-1000:]}')
    if cp.returncode!=0:raise RuntimeError('runtime/API smoke test failed')
def _svc_exists(n):return _run(['sc.exe','query',n],timeout=12).returncode==0
def _kind(kind,sid,log):
    k=str(kind or '').lower()
    if os.name=='nt' and k=='windows-task' and _svc_exists(sid or 'GIDEONAgent'):append_log(log,'legacy windows-task identity migrated to windows-service');return 'windows-service'
    return k
def quiesce_agent(kind,sid,log):
    k=_kind(kind,sid,log)
    if k=='windows-service':cp=_run(['sc.exe','stop',sid or 'GIDEONAgent'],timeout=45)
    elif k=='windows-task':cp=_run(['schtasks.exe','/End','/TN',sid or 'GIDEONAgent'],timeout=20)
    elif k=='systemd':cp=_run(['systemctl','stop',sid or 'gideon-agent.service'],timeout=60)
    elif k=='launchd':cp=_run(['launchctl','bootout','system',f'/Library/LaunchDaemons/{sid or "pe.com.gideons.gideonagent"}.plist'],timeout=60)
    else:raise RuntimeError(f'unsupported service kind {kind}')
    append_log(log,f'quiesce {k} exit={cp.returncode}')
def _tcp(h,p):
    try:
        with socket.create_connection((h,p),timeout=.8):return True
    except Exception:return False
def _linux_desktop_available():
    return bool(shutil.which('x-session-manager') or list(Path('/usr/share/xsessions').glob('*.desktop')) or list(Path('/usr/share/wayland-sessions').glob('*.desktop')))
def _rewrite_xrdp_loopback(text):
    lines=str(text or '').splitlines();out=[];section='';globals_seen=False;port_written=False
    for line in lines:
        m=re.match(r'^\s*\[([^\]]+)\]\s*$',line)
        if m:
            if section.casefold()=='globals' and not port_written:out.append('port=tcp://127.0.0.1:3389');port_written=True
            section=m.group(1).strip();globals_seen=globals_seen or section.casefold()=='globals';out.append(line);continue
        if section.casefold()=='globals':
            if re.match(r'^\s*address\s*=',line,re.I):continue
            if re.match(r'^\s*port\s*=',line,re.I):
                if not port_written:out.append('port=tcp://127.0.0.1:3389');port_written=True
                continue
        out.append(line)
    if section.casefold()=='globals' and not port_written:out.append('port=tcp://127.0.0.1:3389');port_written=True
    if not globals_seen:raise RuntimeError('XRDP_GLOBALS_SECTION_MISSING')
    return '\n'.join(out)+'\n'
def _xrdp_isolated_startwm():
    return '''#!/bin/sh
unset DBUS_SESSION_BUS_ADDRESS
unset WAYLAND_DISPLAY
unset WAYLAND_SOCKET
export XDG_SESSION_TYPE=x11
runtime_suffix=$(printf '%s' "${DISPLAY:-xrdp}" | tr -cd 'A-Za-z0-9_.-')
export XDG_RUNTIME_DIR="/tmp/gideon-xrdp-${UID:-$(id -u)}-${runtime_suffix}"
mkdir -p "$XDG_RUNTIME_DIR"
chmod 700 "$XDG_RUNTIME_DIR"
if command -v startlxde-pi >/dev/null 2>&1; then
  export XDG_CURRENT_DESKTOP=LXDE
  export DESKTOP_SESSION=LXDE-pi
  session=$(command -v startlxde-pi)
elif command -v startlxde >/dev/null 2>&1; then
  export XDG_CURRENT_DESKTOP=LXDE
  export DESKTOP_SESSION=LXDE
  session=$(command -v startlxde)
elif command -v startxfce4 >/dev/null 2>&1; then
  export XDG_CURRENT_DESKTOP=XFCE
  export DESKTOP_SESSION=xfce
  session=$(command -v startxfce4)
elif command -v mate-session >/dev/null 2>&1; then
  session=$(command -v mate-session)
elif command -v gnome-session >/dev/null 2>&1; then
  session=$(command -v gnome-session)
else
  session=/etc/X11/Xsession
fi
if command -v dbus-run-session >/dev/null 2>&1; then
  exec dbus-run-session -- "$session"
fi
if command -v dbus-launch >/dev/null 2>&1; then
  exec dbus-launch --exit-with-session "$session"
fi
exec "$session"
'''
def _configure_xrdp_session_isolation(log):
    startwm=Path('/etc/xrdp/startwm.sh')
    if not startwm.is_file():return
    original=startwm.with_name(startwm.name+'.gideon-original')
    if not original.exists():shutil.copy2(startwm,original)
    startwm.write_text(_xrdp_isolated_startwm(),encoding='utf-8')
    os.chmod(startwm,0o755)
    append_log(log,'REMOTE_ACCESS_SESSION_ISOLATION XRDP display/runtime/DBus separated from physical session')
def _rewrite_xorgxrdp_arm_software(text):
    lines=str(text or '').splitlines();out=[];section='';device=[];is_xrdp=False
    def flush():
        cleaned=[row for row in device if not re.match(r'^\s*Option\s+"(?:DRMDevice|DRI|DRI3|Glamor)"',row,re.I)]
        insert=max(1,len(cleaned)-1)
        cleaned[insert:insert]=['    Option "DRMDevice" ""','    Option "DRI" "0"','    Option "DRI3" "0"','    Option "Glamor" "off"']
        return cleaned
    for line in lines:
        start=re.match(r'^\s*Section\s+"([^"]+)"',line,re.I)
        if start:
            section=start.group(1).casefold()
            if section=='device':device=[line];is_xrdp=False;continue
        if section=='device':
            device.append(line)
            if re.search(r'Identifier\s+"Video Card \(xrdpdev\)"',line,re.I):is_xrdp=True
            if re.match(r'^\s*EndSection\s*$',line,re.I):out.extend(flush() if is_xrdp else device);device=[];section=''
            continue
        if section=='serverflags' and re.match(r'^\s*EndSection\s*$',line,re.I):
            if not any(re.match(r'^\s*Option\s+"AutoAddGPU"',row,re.I) for row in out[-20:]):out.append('    Option "AutoAddGPU" "off"')
        out.append(line)
    if device:out.extend(device)
    return '\n'.join(out)+'\n'
def _configure_xorgxrdp_arm_software(log):
    if not re.match(r'^(?:arm|aarch64)',platform.machine(),re.I):return
    conf=Path('/etc/X11/xrdp/xorg.conf')
    if not conf.is_file():return
    original=conf.with_name(conf.name+'.gideon-original')
    if not original.exists():shutil.copy2(conf,original)
    conf.write_text(_rewrite_xorgxrdp_arm_software(conf.read_text(encoding='utf-8',errors='replace')),encoding='utf-8')
    append_log(log,'REMOTE_ACCESS_ARM_SOFTWARE_RENDERING XRDP DRM/glamor disabled; physical session unchanged')
def _linux_rdp_listener():
    if shutil.which('ss') is None:raise RuntimeError('REMOTE_ACCESS_LISTENER_TOOL_MISSING: iproute2/ss')
    cp=_run(['ss','-H','-ltn'],timeout=10)
    if cp.returncode!=0:raise RuntimeError('REMOTE_ACCESS_LISTENER_QUERY_FAILED')
    for line in (cp.stdout or '').splitlines():
        fields=line.split()
        if len(fields)>3 and re.search(r':3389$',fields[3]):return fields[3]
    return ''
def _win_service(root,sid,log):
    n=sid or 'GIDEONAgent';host=root/'GIDEONAgentServiceHost.exe'
    if not host.is_file():raise RuntimeError('WINDOWS_SERVICE_HOST_MISSING_IN_RELEASE')
    bp=f'"{host}"'
    cp=_run(['sc.exe','config',n,'binPath=',bp,'start=','delayed-auto'],timeout=30) if _svc_exists(n) else _run(['sc.exe','create',n,'binPath=',bp,'start=','delayed-auto','obj=','LocalSystem','DisplayName=','GIDEON Remote Control Agent'],timeout=30)
    if cp.returncode!=0:raise RuntimeError(f'WINDOWS_SERVICE_ENSURE_FAILED {cp.returncode}')
    _run(['sc.exe','failure',n,'reset=','86400','actions=','restart/5000/restart/15000/restart/60000'],timeout=20);_run(['sc.exe','failureflag',n,'1'],timeout=20);_run(['schtasks.exe','/Delete','/TN','GIDEONAgent','/F'],timeout=20)
def _win_remote(log):
    cp=_run(['powershell.exe','-NoLogo','-NoProfile','-NonInteractive','-Command',"(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').EditionID"],timeout=15);ed=(cp.stdout or '').strip()
    if re.match(r'(?i)^(core|home)',ed):raise RuntimeError(f'REMOTE_ACCESS_UNSUPPORTED_WINDOWS_EDITION: {ed}')
    cmds=[['reg.exe','add',r'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server','/v','fDenyTSConnections','/t','REG_DWORD','/d','0','/f'],['reg.exe','add',r'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp','/v','UserAuthentication','/t','REG_DWORD','/d','1','/f'],['reg.exe','add',r'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp','/v','SecurityLayer','/t','REG_DWORD','/d','1','/f'],['sc.exe','config','TermService','start=','auto'],['sc.exe','start','TermService']]
    for c in cmds:_run(c,timeout=30)
    end=time.monotonic()+20
    while time.monotonic()<end:
        if _tcp('127.0.0.1',3389):append_log(log,'REMOTE_ACCESS_READY windows-rdp 127.0.0.1:3389');return
        time.sleep(.5)
    raise RuntimeError('REMOTE_ACCESS_RDP_NOT_LISTENING')
def _linux_remote(log):
    if not _linux_desktop_available():raise RuntimeError('UNSUPPORTED_HEADLESS_NO_DESKTOP: RDP requiere escritorio X11/Wayland; Agent/SSH no se modifican')
    if shutil.which('xrdp') is None:
        if shutil.which('apt-get'):_run(['apt-get','update'],timeout=300);cp=_run(['apt-get','install','-y','xrdp','xorgxrdp','dbus-x11'],timeout=600);cp=cp if cp.returncode==0 else _run(['apt-get','install','-y','xrdp','dbus-x11'],timeout=600)
        elif shutil.which('dnf'):cp=_run(['dnf','install','-y','xrdp'],timeout=600)
        elif shutil.which('yum'):cp=_run(['yum','install','-y','xrdp'],timeout=600)
        else:raise RuntimeError('REMOTE_ACCESS_XRDP_INSTALL_UNSUPPORTED')
        if cp.returncode!=0:raise RuntimeError('REMOTE_ACCESS_XRDP_INSTALL_FAILED')
    ini=Path('/etc/xrdp/xrdp.ini')
    if not ini.is_file():raise RuntimeError('REMOTE_ACCESS_XRDP_CONFIG_MISSING')
    shutil.copy2(ini,ini.with_name(ini.name+'.gideon-backup'))
    ini.write_text(_rewrite_xrdp_loopback(ini.read_text(encoding='utf-8',errors='replace')),encoding='utf-8')
    _configure_xrdp_session_isolation(log)
    _configure_xorgxrdp_arm_software(log)
    cp=_run(['systemctl','enable','xrdp.service'],timeout=30)
    if cp.returncode!=0:raise RuntimeError('REMOTE_ACCESS_XRDP_ENABLE_FAILED')
    cp=_run(['systemctl','restart','xrdp.service'],timeout=60)
    if cp.returncode!=0:raise RuntimeError('REMOTE_ACCESS_XRDP_RESTART_FAILED')
    end=time.monotonic()+20;observed=''
    while time.monotonic()<end:
        if _run(['systemctl','is-active','--quiet','xrdp.service'],timeout=10).returncode==0:
            observed=_linux_rdp_listener()
            if observed=='127.0.0.1:3389':append_log(log,'REMOTE_ACCESS_READY linux-xrdp 127.0.0.1:3389 VERIFIED_LOOPBACK');return
        time.sleep(.5)
    raise RuntimeError(f'REMOTE_ACCESS_XRDP_BIND_FAILED: expected=127.0.0.1:3389 observed={observed or "NONE"}; global listener is rejected')
def _mac_remote(data,log):
    k=Path('/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart')
    if not k.is_file():raise RuntimeError('REMOTE_ACCESS_MACOS_KICKSTART_MISSING')
    sf=data/'vnc.secret';alpha='ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';pw=sf.read_text(encoding='utf-8',errors='ignore').strip()[:8] if sf.is_file() else ''.join(secrets.choice(alpha) for _ in range(8))
    if not sf.is_file():sf.write_text(pw,encoding='utf-8');os.chmod(sf,0o600)
    cp=_run([str(k),'-activate','-configure','-access','-on','-allowAccessFor','-allUsers','-privs','-all','-clientopts','-setvnclegacy','-vnclegacy','yes','-clientopts','-setvncpw','-vncpw',pw,'-restart','-agent','-menu'],timeout=90)
    if cp.returncode!=0:raise RuntimeError('REMOTE_ACCESS_MACOS_KICKSTART_FAILED')
    end=time.monotonic()+20
    while time.monotonic()<end:
        if _tcp('127.0.0.1',5900):append_log(log,'REMOTE_ACCESS_READY macos-vnc 127.0.0.1:5900');return
        time.sleep(.5)
    raise RuntimeError('REMOTE_ACCESS_VNC_NOT_LISTENING')
def ensure_remote(profile,root,data,sid,log):
    p=_platform_id()
    if p=='windows':_win_service(root,sid,log);_win_remote(log)
    elif p=='linux':_linux_remote(log)
    elif p=='darwin':_mac_remote(data,log)
def record_remote_state_after_core_update(profile,log):
    """Report the existing remote listener without changing it during an update.

    The Agent core and its reverse tunnel must be recoverable even on a
    headless/offline host.  Provisioning or repairing RDP/VNC is an explicit
    installer/administrative action, not a prerequisite for replacing the
    signed core runtime.  In particular, a core update must never run apt,
    restart xrdp, or roll itself back solely because a graphical session is
    absent.
    """
    remote=profile.get('RemoteAccess') if isinstance(profile,dict) else None
    if not isinstance(remote,dict):
        append_log(log,'REMOTE_ACCESS_RECONCILIATION_DEFERRED reason=PROFILE_MISSING')
        return
    host=str(remote.get('Host') or '127.0.0.1').strip() or '127.0.0.1'
    try:port=int(remote.get('Port') or 0)
    except (TypeError,ValueError):port=0
    if port>0 and _tcp(host,port):
        append_log(log,f'REMOTE_ACCESS_PRESERVED host={host} port={port}')
        return
    append_log(log,'REMOTE_ACCESS_RECONCILIATION_DEFERRED reason=CORE_UPDATE_NO_SERVICE_MUTATION')
def restart_agent(kind,sid,log):
    k=_kind(kind,sid,log)
    if k=='windows-service':cp=_run(['sc.exe','start',sid or 'GIDEONAgent'],timeout=45);ok=cp.returncode in (0,1056)
    elif k=='windows-task':cp=_run(['schtasks.exe','/Run','/TN',sid or 'GIDEONAgent'],timeout=30);ok=cp.returncode==0
    elif k=='systemd':cp=_run(['systemctl','restart',sid or 'gideon-agent.service'],timeout=60);ok=cp.returncode==0
    elif k=='launchd':
        label=sid or 'pe.com.gideons.gideonagent';plist=Path('/Library/LaunchDaemons')/f'{label}.plist';_run(['launchctl','bootstrap','system',str(plist)],timeout=60) if plist.is_file() else None;cp=_run(['launchctl','kickstart','-k',f'system/{label}'],timeout=60);ok=cp.returncode==0
    else:raise RuntimeError(f'unsupported service kind {kind}')
    append_log(log,f'restart {k} exit={cp.returncode}')
    if not ok:raise RuntimeError(f'SERVICE_RESTART_FAILED {k} {cp.returncode}')
def apply_update(*,install_root,payload,data_root,current_pid,version,service_kind,service_id):
    root=install_root.resolve();payload=payload.resolve();data=data_root.resolve();data.mkdir(parents=True,exist_ok=True);log=data/'update.log';backup=data/'updates'/f'rollback-{version}-{time.strftime("%Y%m%d%H%M%S")}'
    append_log(log,f'Applying stable release {version}');update_status(data,'APPLYING',version)
    try:
        profile=_profile(payload,log)
        quiesce_agent(service_kind,service_id,log);wait_for_exit(current_pid)
        for req in [payload/'gideon_agent.py',payload/'gideon_reverse_tunnel.py',payload/'gideon_common/__init__.py']:
            if not req.is_file():raise RuntimeError(f'UPDATE_PAYLOAD_INVALID: {req.name}')
        _backup(root,backup);_copy(payload,root,preserve=PRESERVE_TOP_LEVEL);refresh_dependencies(root,log);smoke(root,log);_restore_linux_player_launcher(profile,root,log)
        sid=str(profile.get('ServiceId') or service_id or '');record_remote_state_after_core_update(profile,log);update_status(data,'RESTARTING',version);restart_agent(str(profile.get('ServiceKind') or service_kind),sid,log);append_log(log,f'Update complete {version}');return 0
    except Exception as e:
        detail=f'{type(e).__name__}: {e}';append_log(log,f'ERROR update {version}: {detail}');update_status(data,'UPDATE_ERROR',version,detail)
        try:
            if backup.is_dir():_restore(root,backup);smoke(root,log);update_status(data,'ROLLED_BACK',version,detail);restart_agent(service_kind,service_id,log);append_log(log,'Rollback complete')
        except Exception as r:append_log(log,f'ERROR rollback: {type(r).__name__}: {r}')
        return 41
def main(argv:Iterable[str]|None=None):
    p=argparse.ArgumentParser();p.add_argument('--install-root',required=True,type=Path);p.add_argument('--payload',required=True,type=Path);p.add_argument('--data-root',required=True,type=Path);p.add_argument('--current-pid',required=True,type=int);p.add_argument('--version',required=True);p.add_argument('--service-kind',required=True);p.add_argument('--service-id',default='');a=p.parse_args(list(argv) if argv is not None else None);return apply_update(install_root=a.install_root,payload=a.payload,data_root=a.data_root,current_pid=a.current_pid,version=a.version,service_kind=a.service_kind,service_id=a.service_id)
if __name__=='__main__':raise SystemExit(main())
