#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from gideon_common.observability import best_effort_warning

import datetime as dt
import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Any
from gideon_io import atomic_write_json, read_json_retry

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_BUILTINS = [
    'find_backup_folders.ps1',
    'audit_server.ps1',
    'disk_inventory.ps1',
    'service_inventory.ps1',
]


def _appdata_root() -> Path:
    return Path(os.path.expandvars(r'%LOCALAPPDATA%\GIDEONSSH'))



def _execution_sidecar(path: Path) -> Path:
    return path.with_suffix('.execution.json')

def _load_execution(path: Path) -> dict[str, Any]:
    sidecar=_execution_sidecar(path)
    if not sidecar.exists():
        return {}
    try:
        value=json.loads(sidecar.read_text(encoding='utf-8-sig'))
        return value if isinstance(value,dict) else {}
    except Exception:
        return {}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


class ScriptLibrary:
    def __init__(self, scripts_dir: Path | None = None) -> None:
        self.scripts_dir = scripts_dir or (SCRIPT_DIR / 'scripts')
        self.root = _appdata_root() / 'script_library'
        self.custom_dir = self.root / 'custom'
        self.index_path = self.root / 'library.json'
        self.custom_dir.mkdir(parents=True, exist_ok=True)

    def _load_index(self) -> list[dict[str, Any]]:
        if not self.index_path.exists():
            return []
        try:
            data = read_json_retry(self.index_path, retries=3)
            return data if isinstance(data, list) else []
        except Exception:
            return []

    def _save_index(self, rows: list[dict[str, Any]]) -> None:
        atomic_write_json(self.index_path, rows, lock_timeout=2.0, retries=8)

    def builtins(self) -> list[dict[str, Any]]:
        rows=[]
        for name in DEFAULT_BUILTINS:
            path=self.scripts_dir/name
            if not path.exists():
                continue
            rows.append({
                'id': f'builtin:{name.lower()}',
                'name': path.stem,
                'filename': path.name,
                'path': str(path.resolve()),
                'source': 'PRECARGADO',
                'builtin': True,
                'added_at': None,
                'sha256': _sha256(path),
                'execution': _load_execution(path),
            })
        return rows

    def custom(self) -> list[dict[str, Any]]:
        rows=[]
        changed=False
        for row in self._load_index():
            p=Path(str(row.get('path','')))
            if not p.exists():
                changed=True
                continue
            row=dict(row)
            row['source']='CARGADO'
            row['builtin']=False
            row['execution']=_load_execution(p)
            rows.append(row)
        if changed:
            self._save_index(rows)
        return rows

    def all(self) -> list[dict[str, Any]]:
        return self.builtins()+self.custom()

    def add_files(self, files: list[str]) -> list[dict[str, Any]]:
        current=self._load_index()
        by_hash={str(x.get('sha256')): x for x in current}
        added=[]
        for raw in files:
            src=Path(raw)
            if src.suffix.lower() not in {'.ps1','.py','.sh','.command','.cmd','.bat'}:
                continue
            if not src.exists():
                continue
            digest=_sha256(src)
            if digest in by_hash:
                added.append(by_hash[digest])
                continue
            dest=self.custom_dir/src.name
            if dest.exists():
                dest=self.custom_dir/f'{src.stem}_{digest[:8]}{src.suffix}'
            shutil.copy2(src,dest)
            src_sidecar=_execution_sidecar(src)
            if src_sidecar.exists():
                try:
                    shutil.copy2(src_sidecar,_execution_sidecar(dest))
                except Exception as exc:
                    best_effort_warning(f"No se pudo copiar sidecar de ejecución {src_sidecar}", exc)
            row={
                'id': f'custom:{digest[:16]}',
                'name': src.stem,
                'filename': dest.name,
                'path': str(dest.resolve()),
                'source': 'CARGADO',
                'builtin': False,
                'added_at': dt.datetime.now().astimezone().isoformat(timespec='seconds'),
                'sha256': digest,
            }
            current.append(row)
            by_hash[digest]=row
            added.append(row)
        self._save_index(current)
        return added

    def remove(self, script_id: str) -> bool:
        rows=self._load_index()
        keep=[]
        removed=None
        for row in rows:
            if row.get('id') == script_id:
                removed=row
            else:
                keep.append(row)
        if not removed:
            return False
        try:
            p=Path(str(removed.get('path','')))
            if p.exists() and self.custom_dir in p.parents:
                p.unlink()
                sidecar=_execution_sidecar(p)
                if sidecar.exists():
                    sidecar.unlink()
        except Exception as exc:
            best_effort_warning(f"No se pudo retirar el script/sidecar {path}", exc)
        self._save_index(keep)
        return True
