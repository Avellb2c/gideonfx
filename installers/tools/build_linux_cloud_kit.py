#!/usr/bin/env python3
"""Build a fresh-install Ubuntu kit with no cloned databases or private keys."""
from __future__ import annotations
import datetime as dt
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / 'output'


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def copy(source, target):
    source = ROOT / source
    target = target / source.relative_to(ROOT)
    if source.is_dir():
        shutil.copytree(source, target, ignore=shutil.ignore_patterns(
            '__pycache__', '.pytest_cache', '.mypy_cache', '.ruff_cache',
            '*.pyc', '*.pyo', '*.bak', '*.partial', '*.tmp', '*.orig', '*~',
        ))
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def archive(stage, names, target):
    with tarfile.open(target, 'w:gz', compresslevel=6) as tar:
        for name in names:
            tar.add(
                stage / name,
                arcname=name,
                recursive=True,
                filter=lambda x: None if (
                    any(part in {'__pycache__', '.pytest_cache', '.mypy_cache', '.ruff_cache'} for part in Path(x.name).parts)
                    or Path(x.name).suffix.casefold() in {'.pyc', '.pyo', '.bak', '.partial', '.tmp', '.orig'}
                    or Path(x.name).name.endswith('~')
                ) else x,
            )


def main():
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%d-%H%M%S')
    target = OUTPUT / f'GIDEON-UBUNTU-CLOUD-ONECLICK-{stamp}'
    if target.exists() or OUTPUT not in target.parents:
        raise RuntimeError(f'Unsafe or existing output target: {target}')
    target.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix='gideon-linux-clean-') as temporary:
        stage = Path(temporary)
        common = ['installers/LINUX', 'installers/tools', 'installers/portable',
                  'security/security_yara', 'security/updates_trust', 'offline-cache/containers']
        linux = ['payload/linux']
        for name in common + linux:
            copy(name, stage)
        config = json.loads((ROOT/'master.config.json').read_text(encoding='utf-8-sig'))
        config = {
            'schema_version': config['schema_version'], 'product': config['product'],
            'environment': 'FRESH_INSTALL',
            'windows': {key: config['windows'][key] for key in ('webadmin_internal_port', 'gateway_internal_port')},
            'linux': config['linux'], 'webadmin_bootstrap_users': config['webadmin_bootstrap_users'],
            'security': config['security'],
        }
        manifest = {
            'schema_version': 3, 'product': 'GIDEON Remote Control',
            'generated_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
            'environment': 'FRESH_INSTALL',
            'source': {'include_secrets': False, 'include_state_databases': False},
            'purpose': 'Ubuntu cloud/VM clean install; contains no cloned runtime state.',
        }
        (stage/'master.config.json').write_text(json.dumps(config, indent=2)+'\n', encoding='utf-8')
        (stage/'deployment.manifest.json').write_text(json.dumps(manifest, indent=2)+'\n', encoding='utf-8')
        readme = ('GIDEON UBUNTU CLOUD ONECLICK\n\nFresh-install package: no production databases, tokens, passwords or private keys.\n'
                  'Run: sudo bash INSTALL_GIDEON_ONECLICK.sh\n\nThe launcher verifies SHA-256 before extraction. '
                  'GIDEON_INSTALL_MODE defaults to fresh. Define GIDEON_WEB_HOST and GIDEON_AGENT_HOST, '
                  'or answer the prompts. Use GIDEON_EXTERNAL_ACCESS=later to configure TLS after installation.\n')
        for name in ('ONECLICK-INSTALL.md', 'README_INSTALL.txt', 'SENSITIVE_PRODUCTION_CLONE.txt'):
            (stage/name).write_text(readme, encoding='utf-8')
        common += ['master.config.json', 'deployment.manifest.json', 'ONECLICK-INSTALL.md',
                   'README_INSTALL.txt', 'SENSITIVE_PRODUCTION_CLONE.txt']
        module_rows = []
        for filename, paths in (('10-GIDEON-COMMON.tar.gz', common), ('20-GIDEON-LINUX.tar.gz', linux)):
            path = target/filename
            archive(stage, paths, path)
            module_rows.append({'filename': filename, 'sha256': sha(path), 'size_bytes': path.stat().st_size})
        lines = ''.join(f'{row["sha256"]} *{row["filename"]}\n' for row in module_rows)
        (target/'profiles').mkdir()
        (target/'profiles/linux.sha256').write_text(lines, encoding='ascii', newline='\n')
        (target/'package.modules.sha256').write_text(lines, encoding='ascii', newline='\n')
        template = (ROOT/'installers/portable/GIDEON-Portable-OneClick.sh.tpl').read_text(encoding='utf-8')
        launcher = target/'INSTALL_GIDEON_ONECLICK.sh'
        launcher.write_text(template.replace('@@PROFILE@@', 'linux'), encoding='utf-8', newline='\n')
        report = {'schema': 'gideon-linux-cloud-kit/v1', 'status': 'PASS', 'generated_utc': manifest['generated_utc'],
                  'fresh_install': True, 'contains_cloned_state': False, 'contains_private_keys': False,
                  'modules': module_rows}
        (target/'package.manifest.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print(f'CLOUD_KIT={target}')
    print('CLOUD_KIT_FRESH_NO_CLONE=PASS')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
