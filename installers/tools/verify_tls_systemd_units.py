"""Static systemd verification on Linux; never installs or starts services."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

source = Path(__file__).resolve().parents[2]/'payload/linux/app/deploy/ubuntu/systemd'
if sys.platform != 'linux':
    raise SystemExit('Run using Linux/WSL Python.')
with tempfile.TemporaryDirectory(prefix='gideon-systemd-verify-') as directory:
    root=Path(directory)
    units=[]
    for path in source.iterdir():
        if path.suffix not in ('.service','.socket','.timer'):
            continue
        # Only substitute the executable path for a read-only verification host
        # that has no installed GIDEON virtualenv. Commands are never executed.
        text=path.read_text().replace('/opt/gideon/web/venv/bin/python',sys.executable)
        target=root/path.name;target.write_text(text);target.chmod(0o644);units.append(str(target))
        if path.suffix=='.service':
            dropin=root/(path.name+'.d');dropin.mkdir()
            (dropin/'20-tls-hardening.conf').write_text((source/'tls-hardening.conf').read_text())
    result=subprocess.run(['systemd-analyze','verify','--man=no',*units],
                          env={**os.environ,'SYSTEMD_UNIT_PATH':str(root)+':/usr/lib/systemd/system'},
                          capture_output=True,text=True,timeout=60)
    print(result.stdout+result.stderr)
    print('SYSTEMD_STATIC_VERIFY='+('PASS' if result.returncode==0 else 'FAIL')+' units='+str(len(units)))
    raise SystemExit(result.returncode)
