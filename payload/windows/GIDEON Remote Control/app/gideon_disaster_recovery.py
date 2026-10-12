from __future__ import annotations

"""Encrypted Disaster Recovery bundles for GIDEON Remote Control persistent state.

Routine backups remain least-privilege.  DR bundles are explicit administrative
operations because they include private PKI and service secrets.  The module
never starts/stops services and never touches non-GIDEON paths.
"""

import argparse
import datetime as dt
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import struct
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Iterable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"GIDEONDR1\n\0"
SALT_BYTES = 16
NONCE_BYTES = 12
TAG_BYTES = 16
CHUNK = 1024 * 1024
MAX_MEMBERS = 20000


class DisasterRecoveryError(RuntimeError):
    pass


def default_state_root() -> Path:
    if os.name == "nt":
        return Path(os.environ.get("PROGRAMDATA") or str(Path.home())) / "GIDEON Remote Control"
    return Path("/var/lib/gideon")


def default_config_root() -> Path:
    if os.name == "nt":
        return default_state_root()
    return Path("/etc/gideon")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    if len(passphrase) < 16:
        raise DisasterRecoveryError("La passphrase DR debe tener al menos 16 caracteres.")
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(passphrase.encode("utf-8"))


def _allowed_state_names() -> tuple[str, ...]:
    return (
        "config", "gateway", "web", "shared", "pki", "secrets", "security",
        "releases", "approved", "scripts", "updates/trust",
    )


def _iter_files(root: Path, names: Iterable[str]):
    root = Path(root).resolve()
    for name in names:
        candidate = (root / name).resolve()
        if candidate != root and root not in candidate.parents:
            raise DisasterRecoveryError("Ruta DR fuera del root permitido.")
        if candidate.is_file():
            yield candidate, PurePosixPath(name)
        elif candidate.is_dir():
            for path in sorted(candidate.rglob("*")):
                if path.is_symlink():
                    raise DisasterRecoveryError(f"No se permiten symlinks en DR: {path}")
                if path.is_file():
                    yield path, PurePosixPath(name, *path.relative_to(candidate).parts)


def _owner_names(path: Path) -> tuple[str, str]:
    if os.name == "nt":
        return "", ""
    try:
        import grp, pwd
        st = Path(path).stat()
        return pwd.getpwuid(st.st_uid).pw_name, grp.getgrgid(st.st_gid).gr_name
    except Exception:
        return "", ""


def _restore_owner(path: Path, owner: str, group: str) -> None:
    if os.name == "nt" or not owner or not group:
        return
    try:
        import grp, pwd
        os.chown(path, pwd.getpwnam(owner).pw_uid, grp.getgrnam(group).gr_gid)
    except Exception:
        pass


def _sqlite_snapshot(source: Path, target: Path) -> Path:
    target.parent.mkdir(parents=True, exist_ok=True)
    src = sqlite3.connect(f"file:{source}?mode=ro", uri=True, timeout=15)
    dst = sqlite3.connect(target, timeout=15)
    try:
        src.backup(dst)
    except sqlite3.DatabaseError as exc:
        raise DisasterRecoveryError(f"No se pudo obtener snapshot SQLite consistente de {source}: {exc}") from exc
    finally:
        dst.close(); src.close()
    return target


def _build_tar(state_root: Path, config_root: Path, output_tar: Path) -> dict:
    state_root = Path(state_root).resolve()
    config_root = Path(config_root).resolve()
    files: list[dict] = []
    snapshots = output_tar.parent / "sqlite-snapshots"
    with tarfile.open(output_tar, "w:gz") as tar:
        for index, (source, rel) in enumerate(_iter_files(state_root, _allowed_state_names())):
            arc = PurePosixPath("state", *rel.parts)
            archived_source = _sqlite_snapshot(source, snapshots / f"{index:04d}.sqlite3") if source.suffix.lower() == ".sqlite3" else source
            tar.add(archived_source, arcname=arc.as_posix(), recursive=False)
            owner, group = _owner_names(source)
            files.append({"path": arc.as_posix(), "sha256": _sha256(archived_source), "size": archived_source.stat().st_size, "mode": stat.S_IMODE(source.stat().st_mode), "owner": owner, "group": group})
        if config_root != state_root:
            # /etc/gideon is entirely GIDEON-owned; include all regular files, including PKI/secrets.
            for source, rel in _iter_files(config_root, [p.name for p in config_root.iterdir()] if config_root.exists() else []):
                arc = PurePosixPath("config", *rel.parts)
                tar.add(source, arcname=arc.as_posix(), recursive=False)
                owner, group = _owner_names(source)
                files.append({"path": arc.as_posix(), "sha256": _sha256(source), "size": source.stat().st_size, "mode": stat.S_IMODE(source.stat().st_mode), "owner": owner, "group": group})
        manifest = {
            "schema": "gideon-disaster-recovery/v1",
            "created_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "platform": "windows" if os.name == "nt" else "linux",
            "files": files,
        }
        payload = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        info = tarfile.TarInfo("DR-MANIFEST.json")
        info.size = len(payload)
        info.mode = 0o600
        info.mtime = int(dt.datetime.now().timestamp())
        import io
        tar.addfile(info, io.BytesIO(payload))
    return manifest


def _encrypt_file(source: Path, destination: Path, passphrase: str) -> None:
    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    key = _derive_key(passphrase, salt)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with Path(source).open("rb") as src, Path(destination).open("wb") as dst:
        dst.write(MAGIC)
        dst.write(salt)
        dst.write(nonce)
        while True:
            chunk = src.read(CHUNK)
            if not chunk:
                break
            dst.write(encryptor.update(chunk))
        dst.write(encryptor.finalize())
        dst.write(encryptor.tag)
        dst.flush()
        os.fsync(dst.fileno())
    try:
        os.chmod(destination, 0o600)
    except OSError:
        pass


def _decrypt_file(source: Path, destination: Path, passphrase: str) -> None:
    source = Path(source)
    size = source.stat().st_size
    minimum = len(MAGIC) + SALT_BYTES + NONCE_BYTES + TAG_BYTES
    if size <= minimum:
        raise DisasterRecoveryError("Bundle DR truncado.")
    with source.open("rb") as src:
        if src.read(len(MAGIC)) != MAGIC:
            raise DisasterRecoveryError("Bundle DR no reconocido.")
        salt = src.read(SALT_BYTES)
        nonce = src.read(NONCE_BYTES)
        src.seek(-TAG_BYTES, os.SEEK_END)
        tag = src.read(TAG_BYTES)
        ciphertext_start = len(MAGIC) + SALT_BYTES + NONCE_BYTES
        ciphertext_end = size - TAG_BYTES
        src.seek(ciphertext_start)
        key = _derive_key(passphrase, salt)
        decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
        with Path(destination).open("wb") as dst:
            remaining = ciphertext_end - ciphertext_start
            try:
                while remaining:
                    chunk = src.read(min(CHUNK, remaining))
                    if not chunk:
                        raise DisasterRecoveryError("Bundle DR truncado durante descifrado.")
                    remaining -= len(chunk)
                    dst.write(decryptor.update(chunk))
                dst.write(decryptor.finalize())
            except Exception as exc:
                dst.close()
                Path(destination).unlink(missing_ok=True)
                raise DisasterRecoveryError("No se pudo descifrar/autenticar el bundle DR; passphrase incorrecta o archivo alterado.") from exc


def create_bundle(output: Path, *, state_root: Path, config_root: Path, passphrase: str) -> dict:
    with tempfile.TemporaryDirectory(prefix="gideon-dr-") as tmp:
        tar_path = Path(tmp) / "gideon-dr.tar.gz"
        manifest = _build_tar(Path(state_root), Path(config_root), tar_path)
        _encrypt_file(tar_path, Path(output), passphrase)
    return {"ok": True, "bundle": str(Path(output).resolve()), "files": len(manifest["files"]), "sha256": _sha256(Path(output))}


def _safe_member(member: tarfile.TarInfo) -> PurePosixPath:
    p = PurePosixPath(member.name)
    if p.is_absolute() or not p.parts or any(part in {"", ".", ".."} for part in p.parts):
        raise DisasterRecoveryError(f"Ruta insegura en bundle DR: {member.name}")
    if member.issym() or member.islnk() or member.isdev():
        raise DisasterRecoveryError(f"Tipo de archivo no permitido en DR: {member.name}")
    return p


def restore_bundle(bundle: Path, *, state_root: Path, config_root: Path, passphrase: str, force: bool = False) -> dict:
    state_root = Path(state_root).resolve()
    config_root = Path(config_root).resolve()
    with tempfile.TemporaryDirectory(prefix="gideon-dr-restore-") as tmp:
        tar_path = Path(tmp) / "gideon-dr.tar.gz"
        _decrypt_file(Path(bundle), tar_path, passphrase)
        with tarfile.open(tar_path, "r:gz") as tar:
            members = tar.getmembers()
            if len(members) > MAX_MEMBERS:
                raise DisasterRecoveryError("Bundle DR excede el máximo de entradas.")
            manifest_member = next((m for m in members if m.name == "DR-MANIFEST.json"), None)
            if manifest_member is None:
                raise DisasterRecoveryError("Falta DR-MANIFEST.json.")
            extracted_manifest = tar.extractfile(manifest_member)
            if extracted_manifest is None:
                raise DisasterRecoveryError("No se pudo leer DR-MANIFEST.json.")
            manifest = json.loads(extracted_manifest.read().decode("utf-8-sig"))
            if manifest.get("schema") != "gideon-disaster-recovery/v1":
                raise DisasterRecoveryError("Schema DR no soportado.")
            declared = {str(x["path"]): x for x in manifest.get("files") or [] if isinstance(x, dict) and x.get("path")}
            actual_files = [m for m in members if m.isfile() and m.name != "DR-MANIFEST.json"]
            if set(declared) != {m.name for m in actual_files}:
                raise DisasterRecoveryError("El manifest DR y los archivos del bundle no coinciden exactamente.")
            staged: list[tuple[Path, Path, dict]] = []
            stage_root = Path(tmp) / "validated"
            stage_root.mkdir()
            for index, member in enumerate(actual_files):
                p = _safe_member(member)
                meta = declared[p.as_posix()]
                if p.parts[0] == "state":
                    destination = state_root.joinpath(*p.parts[1:]).resolve()
                    allowed_root = state_root
                elif p.parts[0] == "config":
                    destination = config_root.joinpath(*p.parts[1:]).resolve()
                    allowed_root = config_root
                else:
                    raise DisasterRecoveryError(f"Namespace DR no permitido: {p}")
                if destination != allowed_root and allowed_root not in destination.parents:
                    raise DisasterRecoveryError(f"Destino DR fuera de GIDEON: {destination}")
                if destination.exists() and not force:
                    raise DisasterRecoveryError(f"Destino ya existe: {destination}. Use --force solo para restore deliberado.")
                source = tar.extractfile(member)
                if source is None:
                    raise DisasterRecoveryError(f"No se pudo leer {p}")
                validated_path = stage_root / f"{index:05d}.bin"
                digest = hashlib.sha256()
                with validated_path.open("wb") as out:
                    while True:
                        chunk = source.read(CHUNK)
                        if not chunk:
                            break
                        digest.update(chunk); out.write(chunk)
                if digest.hexdigest() != str(meta.get("sha256") or ""):
                    raise DisasterRecoveryError(f"SHA-256 DR no coincide: {p}")
                if validated_path.stat().st_size != int(meta.get("size") or -1):
                    raise DisasterRecoveryError(f"Tamaño DR no coincide: {p}")
                staged.append((validated_path, destination, meta))

            # Solo después de autenticar y validar TODO el bundle se escriben destinos GIDEON.
            for validated_path, destination, meta in staged:
                destination.parent.mkdir(parents=True, exist_ok=True)
                temp = destination.with_name(f".{destination.name}.gideon-dr.tmp")
                shutil.copyfile(validated_path, temp)
                os.replace(temp, destination)
                try:
                    os.chmod(destination, int(meta.get("mode") or 0o600))
                except OSError:
                    pass
                _restore_owner(destination, str(meta.get("owner") or ""), str(meta.get("group") or ""))
    return {"ok": True, "status": "RESTORED", "files": len(declared), "state_root": str(state_root), "config_root": str(config_root)}


def _passphrase(ns) -> str:
    value = os.environ.get(ns.passphrase_env or "GIDEON_DR_BACKUP_PASSPHRASE", "")
    if not value:
        raise DisasterRecoveryError(f"Defina la passphrase en {ns.passphrase_env or 'GIDEON_DR_BACKUP_PASSPHRASE'}; no se acepta por argumento CLI.")
    return value


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="GIDEON Remote Control encrypted Disaster Recovery")
    sub = ap.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create")
    create.add_argument("--output", required=True)
    create.add_argument("--state-root", default=str(default_state_root()))
    create.add_argument("--config-root", default=str(default_config_root()))
    create.add_argument("--passphrase-env", default="GIDEON_DR_BACKUP_PASSPHRASE")
    restore = sub.add_parser("restore")
    restore.add_argument("--bundle", required=True)
    restore.add_argument("--state-root", default=str(default_state_root()))
    restore.add_argument("--config-root", default=str(default_config_root()))
    restore.add_argument("--passphrase-env", default="GIDEON_DR_BACKUP_PASSPHRASE")
    restore.add_argument("--force", action="store_true")
    ns = ap.parse_args(argv)
    if ns.command == "create":
        result = create_bundle(Path(ns.output), state_root=Path(ns.state_root), config_root=Path(ns.config_root), passphrase=_passphrase(ns))
    else:
        result = restore_bundle(Path(ns.bundle), state_root=Path(ns.state_root), config_root=Path(ns.config_root), passphrase=_passphrase(ns), force=bool(ns.force))
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
