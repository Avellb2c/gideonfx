#!/usr/bin/env python3
"""GIDEON operational SQLite/settings backup worker."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import shutil
import sqlite3
from pathlib import Path


def sqlite_backup(source: Path, target: Path) -> bool:
    if not source.is_file():
        return False
    target.parent.mkdir(parents=True, exist_ok=True)
    src = sqlite3.connect(f"file:{source}?mode=ro", uri=True, timeout=15)
    dst = sqlite3.connect(target, timeout=15)
    try:
        src.backup(dst)
    finally:
        dst.close()
        src.close()
    return True


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_settings(path: Path) -> dict:
    defaults = {"backup_enabled": True, "backup_retention_days": 14}
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
        if isinstance(value, dict):
            defaults.update(value)
    except FileNotFoundError:
        pass
    return defaults


def main() -> int:
    parser = argparse.ArgumentParser(description="GIDEON isolated backup")
    parser.add_argument("--settings", required=True)
    parser.add_argument("--root", required=True)
    parser.add_argument("--external-root", required=True)
    parser.add_argument("--gateway-db", required=True)
    parser.add_argument("--web-db", required=True)
    args = parser.parse_args()
    settings_path = Path(args.settings)
    settings = load_settings(settings_path)
    if not bool(settings.get("backup_enabled", True)):
        print("Backup disabled by runtime settings")
        return 0
    stamp = dt.datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
    target = Path(args.root).resolve() / stamp
    target.mkdir(parents=True, exist_ok=True)
    copied: list[str] = []
    for source, name in ((Path(args.gateway_db), "gateway.sqlite3"), (Path(args.web_db), "web-security.sqlite3")):
        if sqlite_backup(source, target / name):
            copied.append(name)
    if settings_path.is_file():
        shutil.copy2(settings_path, target / "runtime_settings.json")
        copied.append("runtime_settings.json")
    entries = [{"Name": name, "Size": (target / name).stat().st_size, "Sha256": sha256(target / name)} for name in copied]
    manifest = {"Schema": "gideon-operational-backup/v1", "CreatedAt": dt.datetime.now().astimezone().isoformat(timespec="seconds"), "Files": copied, "Entries": entries, "Complete": True}
    (target / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    retention = max(1, min(int(settings.get("backup_retention_days") or 14), 365))
    cutoff = dt.datetime.now().timestamp() - retention * 86400
    root = target.parent
    for item in root.iterdir():
        try:
            if item.is_dir() and item != target and item.stat().st_mtime < cutoff:
                shutil.rmtree(item)
        except OSError:
            continue
    print(f"Backup OK: {target} ({len(copied)} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
