from __future__ import annotations

"""Build and verify the immutable post-install GIDEON application baseline."""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from gideon_packaging.runtime_profile import production_payload_files  # noqa: E402
from gideon_version import PRODUCT_VERSION  # noqa: E402


MANIFEST_NAME = "INSTALL-INTEGRITY-MANIFEST.json"
MUTABLE_STATE_EXCLUDED = (
    ".git", ".pytest_cache", "PHASE8A-AUDIT", "PHASE8B-AUDIT",
    "PHASE8C-AUDIT", "PHASE8D-AUDIT", "PHASE8E-AUDIT", "PHASE8F-AUDIT",
    "PHASE8G-AUDIT", "PHASE8H-AUDIT", "backups", "config", "data", "docs",
    "gateway-data", "legacy_tkinter", "logs", "quarantine", "releases", "scripts",
    "tests", "uploads", "web-data",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def immutable_paths(root: Path) -> list[Path]:
    excluded = set(MUTABLE_STATE_EXCLUDED)
    rows: list[Path] = []
    for path in production_payload_files(root):
        rel = path.relative_to(root)
        if rel.name in {MANIFEST_NAME, "RELEASE-MANIFEST.json"}:
            continue
        if rel.parts and rel.parts[0] in excluded:
            continue
        rows.append(path)
    return sorted(rows, key=lambda item: item.relative_to(root).as_posix().casefold())


def build_manifest(root: Path) -> dict[str, Any]:
    return {
        "schema": "gideon-install-integrity/v1",
        "product": "GIDEON Remote Control",
        "version": PRODUCT_VERSION,
        "purpose": "post-install immutable application integrity",
        "mutable_state_excluded": list(MUTABLE_STATE_EXCLUDED),
        "files": [
            {"path": path.relative_to(root).as_posix(), "size_bytes": path.stat().st_size, "sha256": sha256(path)}
            for path in immutable_paths(root)
        ],
    }


def write_manifest(root: Path) -> Path:
    root = root.resolve()
    target = root / MANIFEST_NAME
    target.write_text(json.dumps(build_manifest(root), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return target


def verify_manifest(root: Path, *, require_exact_file_set: bool = True) -> list[str]:
    root = root.resolve(); target = root / MANIFEST_NAME
    if not target.is_file(): return [f"Falta {MANIFEST_NAME}"]
    try: manifest = json.loads(target.read_text(encoding="utf-8-sig"))
    except Exception as exc: return [f"{MANIFEST_NAME} inválido: {type(exc).__name__}: {exc}"]
    if not isinstance(manifest, dict): return [f"{MANIFEST_NAME} debe contener un objeto"]
    errors: list[str] = []
    if manifest.get("schema") != "gideon-install-integrity/v1": errors.append("schema de integridad no soportado")
    if str(manifest.get("version") or "") != PRODUCT_VERSION: errors.append("versión de integridad no coincide con PRODUCT_VERSION")
    declared = manifest.get("files")
    if not isinstance(declared, list): return errors + ["files debe ser una lista"]
    declared_paths: set[str] = set()
    for index, row in enumerate(declared):
        if not isinstance(row, dict): errors.append(f"files[{index}] no es objeto"); continue
        rel_text = str(row.get("path") or ""); rel = PurePosixPath(rel_text)
        if not rel_text or rel.is_absolute() or ".." in rel.parts: errors.append(f"path inseguro en files[{index}]: {rel_text!r}"); continue
        if rel_text in declared_paths: errors.append(f"path duplicado: {rel_text}"); continue
        declared_paths.add(rel_text); path = root.joinpath(*rel.parts)
        if not path.is_file(): errors.append(f"archivo inmutable ausente: {rel_text}"); continue
        if int(row.get("size_bytes") or -1) != path.stat().st_size: errors.append(f"tamaño no coincide: {rel_text}")
        if str(row.get("sha256") or "").lower() != sha256(path): errors.append(f"SHA-256 no coincide: {rel_text}")
    if require_exact_file_set:
        expected = {path.relative_to(root).as_posix() for path in immutable_paths(root)}
        missing = sorted(expected - declared_paths); extra = sorted(declared_paths - expected)
        if missing: errors.append("archivos inmutables no declarados: " + ", ".join(missing))
        if extra: errors.append("archivos declarados fuera del baseline: " + ", ".join(extra))
    return errors


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("action", choices=("build", "check")); parser.add_argument("--root", default=str(ROOT)); parser.add_argument("--allow-extra-files", action="store_true"); ns = parser.parse_args(list(argv) if argv is not None else None)
    root = Path(ns.root).resolve()
    if ns.action == "build": print(write_manifest(root)); return 0
    errors = verify_manifest(root, require_exact_file_set=not ns.allow_extra_files)
    if errors:
        for error in errors: print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"OK: {MANIFEST_NAME} files={len(immutable_paths(root))}"); return 0


if __name__ == "__main__": raise SystemExit(main())
