from __future__ import annotations

"""GIDEON-owned SSH identity vault.

Private SSH identities imported from WebAdmin are encrypted at rest and are
never loaded into the host ssh-agent, sshd or authorized_keys.  A private key
may be materialized only into a 0600 temporary file for the duration of one
GIDEON-owned operation, then it is deleted.
"""

import base64
import contextlib
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from threading import RLock
from typing import Any, Iterator

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

MAX_SSH_PRIVATE_KEY_BYTES = 128 * 1024
MAX_SSH_FOLDER_FILES = 64
MAX_SSH_FOLDER_TOTAL_BYTES = 2 * 1024 * 1024
_SUPPORTED = (Ed25519PrivateKey, RSAPrivateKey, EllipticCurvePrivateKey)


_PRIVATE_KEY_MARKERS = (
    b"-----BEGIN OPENSSH " + b"PRIVATE KEY-----",
    b"-----BEGIN " + b"PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED " + b"PRIVATE KEY-----",
    b"-----BEGIN RSA " + b"PRIVATE KEY-----",
    b"-----BEGIN EC " + b"PRIVATE KEY-----",
    b"-----BEGIN DSA " + b"PRIVATE KEY-----",
)


def classify_private_key_blob(content: bytes) -> str:
    """Classify an uploaded SSH key candidate without persisting it.

    The browser folder picker can legitimately submit id_ed25519/id_rsa files
    with no extension.  Classification is therefore content-based rather than
    filename-based.  Only metadata is returned; plaintext is never written.
    """
    sample = bytes(content or b"")[:4096].lstrip(b"\xef\xbb\xbf \t\r\n")
    if not sample:
        return "empty"
    if sample.startswith(b"PuTTY-User-Key-File-"):
        return "putty-ppk"
    if any(sample.startswith(marker) for marker in _PRIVATE_KEY_MARKERS):
        return "private-key"
    if sample.startswith((b"ssh-ed25519 ", b"ssh-rsa ", b"ecdsa-sha2-", b"sk-ssh-", b"sk-ecdsa-")):
        return "public-key"
    return "other"


class SshVaultError(RuntimeError):
    pass


def _now() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def _chmod(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def _windows_system_tool(name: str) -> str | None:
    direct = shutil.which(name)
    if direct:
        return direct
    system_root = Path(os.environ.get("SystemRoot") or r"C:\Windows")
    candidate = system_root / "System32" / name
    return str(candidate) if candidate.is_file() else None


def _current_windows_sid() -> str:
    """Return the SID of the token that will launch ssh.exe/sftp.exe.

    We deliberately resolve the *runtime* token rather than assuming LocalSystem
    or the GIDEON virtual service SID.  This keeps the ACL correct if the service
    identity is changed later.
    """
    whoami = _windows_system_tool("whoami.exe") or shutil.which("whoami")
    if not whoami:
        raise SshVaultError("WINDOWS_OPENSSH_KEY_ACL_FAILED: whoami.exe no está disponible.")
    try:
        cp = subprocess.run(
            [whoami, "/user", "/fo", "csv", "/nh"],
            capture_output=True, text=True, timeout=10, shell=False,
            encoding="utf-8", errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception as exc:
        raise SshVaultError(f"WINDOWS_OPENSSH_KEY_ACL_FAILED: no se pudo resolver el SID actual: {type(exc).__name__}: {exc}") from exc
    text = ((cp.stdout or "") + "\n" + (cp.stderr or "")).strip()
    match = re.search(r"S-\d+(?:-\d+)+", text)
    if cp.returncode != 0 or not match:
        raise SshVaultError(
            f"WINDOWS_OPENSSH_KEY_ACL_FAILED: whoami /user rc={cp.returncode}; no se obtuvo SID del proceso."
        )
    return match.group(0)


def _run_icacls(args: list[str]) -> None:
    icacls = _windows_system_tool("icacls.exe") or shutil.which("icacls")
    if not icacls:
        raise SshVaultError("WINDOWS_OPENSSH_KEY_ACL_FAILED: icacls.exe no está disponible.")
    try:
        cp = subprocess.run(
            [icacls, *args], capture_output=True, text=True, timeout=15, shell=False,
            encoding="utf-8", errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception as exc:
        raise SshVaultError(f"WINDOWS_OPENSSH_KEY_ACL_FAILED: icacls no pudo ejecutarse: {type(exc).__name__}: {exc}") from exc
    if cp.returncode != 0:
        detail = ((cp.stdout or "") + "\n" + (cp.stderr or "")).strip().replace("\r", " " ).replace("\n", " " )[:700]
        raise SshVaultError(f"WINDOWS_OPENSSH_KEY_ACL_FAILED: icacls rc={cp.returncode}: {detail}")


def _is_windows() -> bool:
    return os.name == "nt"


def harden_openssh_private_key_permissions(path: Path) -> None:
    """Make an ephemeral private key acceptable to native OpenSSH.

    POSIX uses 0600.  Windows OpenSSH does not interpret ``chmod(0600)`` as an
    NTFS DACL restriction, so inherited ACEs can make ssh.exe reject the key as
    "UNPROTECTED PRIVATE KEY FILE".  On Windows we explicitly grant the
    current process SID, make that SID the owner, then remove inherited ACEs.
    The operation fails closed if the ACL cannot be hardened.
    """
    target = Path(path).resolve()
    if not target.is_file():
        raise SshVaultError(f"WINDOWS_OPENSSH_KEY_ACL_FAILED: archivo temporal inexistente: {target}")
    if not _is_windows():
        try:
            os.chmod(target, 0o600)
        except OSError as exc:
            raise SshVaultError(f"OPENSSH_KEY_MODE_FAILED: {type(exc).__name__}: {exc}") from exc
        return

    sid = _current_windows_sid()
    sid_ref = f"*{sid}"
    # Order matters: first give the running token an explicit ACE, then make it
    # the owner, and only then strip inheritance.  That prevents a temporary
    # lock-out between ACL operations.
    _run_icacls([str(target), "/grant:r", f"{sid_ref}:F", "/q"])
    _run_icacls([str(target), "/setowner", sid_ref, "/q"])
    _run_icacls([str(target), "/inheritance:r", "/q"])
    _run_icacls([str(target), "/grant:r", f"{sid_ref}:F", "/q"])


def _fingerprint(public_openssh: bytes) -> str:
    digest = hashlib.sha256(public_openssh).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


class SshIdentityVault:
    def __init__(self, data_dir: Path) -> None:
        self.root = (Path(data_dir).resolve() / "security-assets" / "ssh-identities").resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        _chmod(self.root, 0o700)
        self.metadata_path = self.root / "identities.json"
        self._lock = RLock()
        if not self.metadata_path.exists():
            self._write([])

    @staticmethod
    def _fernet() -> Fernet:
        raw = str(os.environ.get("GIDEON_WEB_TOTP_ENCRYPTION_KEY") or "").strip().encode("ascii", "ignore")
        if not raw:
            raise SshVaultError("No existe GIDEON_WEB_TOTP_ENCRYPTION_KEY; no se puede proteger una identidad SSH privada.")
        try:
            master = base64.urlsafe_b64decode(raw)
        except Exception as exc:
            raise SshVaultError("GIDEON_WEB_TOTP_ENCRYPTION_KEY no es una clave Fernet válida.") from exc
        if len(master) != 32:
            raise SshVaultError("GIDEON_WEB_TOTP_ENCRYPTION_KEY no tiene 32 bytes efectivos.")
        # Domain-separated key: SSH material does not reuse the TOTP/signing Fernet key.
        derived = hmac.new(master, b"GIDEON-REMOTE-CONTROL\x00SSH-IDENTITY-VAULT\x00v1", hashlib.sha256).digest()
        return Fernet(base64.urlsafe_b64encode(derived))

    def _read(self) -> list[dict[str, Any]]:
        try:
            value = json.loads(self.metadata_path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            return []
        return [dict(x) for x in value if isinstance(x, dict)] if isinstance(value, list) else []

    def _write(self, rows: list[dict[str, Any]]) -> None:
        fd, name = tempfile.mkstemp(prefix=".identities-", suffix=".json", dir=str(self.root))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(rows, fh, ensure_ascii=False, indent=2)
                fh.write("\n")
                fh.flush(); os.fsync(fh.fileno())
            tmp = Path(name); _chmod(tmp, 0o600); os.replace(tmp, self.metadata_path); _chmod(self.metadata_path, 0o600)
        finally:
            try:
                if os.path.exists(name): os.unlink(name)
            except OSError:
                pass

    @staticmethod
    def _load_private(content: bytes, passphrase: str = ""):
        if not content or len(content) > MAX_SSH_PRIVATE_KEY_BYTES:
            raise SshVaultError("La clave SSH privada está vacía o excede 128 KiB.")
        kind = classify_private_key_blob(content)
        if kind == "putty-ppk":
            raise SshVaultError(
                "La clave está en formato PuTTY PPK. El vault GIDEON no la convierte de forma insegura: "
                "expórtela una vez como OpenSSH (id_ed25519/id_rsa) o PEM y vuelva a cargarla."
            )
        if kind == "public-key":
            raise SshVaultError("El archivo seleccionado es una clave pública (.pub), no una clave privada SSH.")
        if kind not in {"private-key"}:
            raise SshVaultError("El archivo no parece contener una clave privada SSH OpenSSH/PEM válida.")
        password = passphrase.encode("utf-8") if passphrase else None
        last: Exception | None = None
        for loader in (serialization.load_ssh_private_key, serialization.load_pem_private_key):
            try:
                key = loader(content, password=password)
                if not isinstance(key, _SUPPORTED):
                    raise SshVaultError("Tipo de clave SSH no soportado. Use Ed25519, RSA o ECDSA.")
                if isinstance(key, RSAPrivateKey) and key.key_size < 3072:
                    raise SshVaultError("Las identidades RSA SSH deben tener al menos 3072 bits.")
                return key
            except SshVaultError:
                raise
            except Exception as exc:
                last = exc
        if last is not None and type(last).__name__ == "UnsupportedAlgorithm" and "bcrypt" in str(last).casefold():
            raise SshVaultError(
                "BCRYPT_RUNTIME_MISSING: falta la dependencia Python 'bcrypt' en el runtime de WebAdmin. "
                "Abra Entorno y dependencias y ejecute la reparación Python GIDEON; la passphrase no ha sido validada todavía."
            ) from last
        raise SshVaultError("No se pudo abrir la clave SSH privada. Verifique formato y passphrase.") from last
    @staticmethod
    def _canonical(key: Any) -> bytes:
        # Materialize in native OpenSSH private-key format.  PKCS#8 is valid key
        # storage but is not accepted consistently by ssh.exe/OpenSSH for Ed25519.
        # The vault remains encrypted at rest; this is only the plaintext form
        # inside the encrypted blob / ephemeral GIDEON-owned operation file.
        return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption())

    @staticmethod
    def _public(key: Any) -> bytes:
        return key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)

    @staticmethod
    def _key_type(key: Any) -> str:
        if isinstance(key, Ed25519PrivateKey): return "ED25519"
        if isinstance(key, RSAPrivateKey): return f"RSA-{key.key_size}"
        if isinstance(key, EllipticCurvePrivateKey): return f"ECDSA-{key.curve.name}"
        return type(key).__name__

    def import_identity(self, content: bytes, *, label: str, passphrase: str = "") -> dict[str, Any]:
        key = self._load_private(content, passphrase)
        public = self._public(key)
        fingerprint = _fingerprint(public)
        identity_id = hashlib.sha256(public).hexdigest()[:16]
        encrypted_path = self.root / f"identity-{identity_id}.key.fernet"
        public_path = self.root / f"identity-{identity_id}.pub"
        encrypted = self._fernet().encrypt(self._canonical(key))
        with self._lock:
            encrypted_path.write_bytes(encrypted); _chmod(encrypted_path, 0o600)
            public_path.write_bytes(public + b"\n"); _chmod(public_path, 0o640)
            rows = [x for x in self._read() if str(x.get("id")) != identity_id]
            row = {
                "id": identity_id,
                "label": str(label or "Identidad SSH GIDEON").strip()[:120],
                "fingerprint": fingerprint,
                "key_type": self._key_type(key),
                "encrypted_path": str(encrypted_path),
                "public_path": str(public_path),
                "updated_at": _now(),
            }
            rows.append(row)
            rows.sort(key=lambda x: str(x.get("label") or "").casefold())
            self._write(rows)
            return dict(row)

    def list_identities(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(x) for x in self._read()]

    def set_connection_defaults(
        self, identity_id: str, *, username: str, port: int = 22,
        verified_site_code: str = "", ssh_ok: bool = True, sftp_ok: bool = True,
    ) -> dict[str, Any]:
        clean_user = str(username or "").strip()
        if not clean_user or len(clean_user) > 64 or any(ch.isspace() for ch in clean_user):
            raise SshVaultError("Usuario SSH inválido para el perfil de conexión.")
        try:
            clean_port = int(port)
        except (TypeError, ValueError) as exc:
            raise SshVaultError("Puerto SSH inválido.") from exc
        if clean_port < 1 or clean_port > 65535:
            raise SshVaultError("Puerto SSH fuera de rango.")
        with self._lock:
            row = self._row(identity_id)
            rows = self._read()
            updated = None
            for idx, current in enumerate(rows):
                if str(current.get("id") or "") != str(row.get("id") or ""):
                    continue
                item = dict(current)
                item["default_username"] = clean_user
                item["default_port"] = clean_port
                item["connection_verified_at"] = _now()
                item["connection_verified_site_code"] = str(verified_site_code or "").strip()[:32]
                item["connection_scope"] = "GLOBAL"
                item["connection_last_test_site_code"] = str(verified_site_code or "").strip()[:32]
                item["connection_ssh_ok"] = bool(ssh_ok)
                item["connection_sftp_ok"] = bool(sftp_ok)
                rows[idx] = item
                updated = item
                break
            if updated is None:
                raise SshVaultError("Identidad SSH no encontrada al guardar el perfil de conexión.")
            self._write(rows)
            return dict(updated)

    def _row(self, identity_id: str) -> dict[str, Any]:
        clean = re.sub(r"[^0-9a-f]", "", str(identity_id or "").lower())[:16]
        if len(clean) != 16:
            raise SshVaultError("Identificador de identidad SSH inválido.")
        row = next((x for x in self._read() if str(x.get("id")) == clean), None)
        if row is None:
            raise SshVaultError("Identidad SSH no encontrada.")
        return dict(row)

    def private_key_bytes(self, identity_id: str) -> bytes:
        with self._lock:
            row = self._row(identity_id)
            path = Path(str(row.get("encrypted_path") or "")).resolve()
            try:
                path.relative_to(self.root)
            except ValueError as exc:
                raise SshVaultError("Ruta de identidad SSH fuera del vault GIDEON.") from exc
            try:
                plaintext = self._fernet().decrypt(path.read_bytes())
            except (OSError, InvalidToken) as exc:
                raise SshVaultError("No se pudo descifrar la identidad SSH administrada.") from exc
            # Cryptographic self-check before exposing bytes to a GIDEON operation.
            key = self._load_private(plaintext)
            if _fingerprint(self._public(key)) != str(row.get("fingerprint") or ""):
                raise SshVaultError("La identidad SSH no coincide con su fingerprint registrado.")
            # Re-encode legacy PKCS#8 entries as OpenSSH for ssh/sftp/scp.
            return self._canonical(key)

    def test_identity(self, identity_id: str) -> dict[str, Any]:
        row = self._row(identity_id)
        self.private_key_bytes(identity_id)
        return {"ok": True, "id": row["id"], "fingerprint": row["fingerprint"], "key_type": row["key_type"]}

    @contextlib.contextmanager
    def temporary_private_key(self, identity_id: str) -> Iterator[Path]:
        plaintext = self.private_key_bytes(identity_id)
        fd, name = tempfile.mkstemp(prefix="gideon-ssh-", suffix=".key")
        path = Path(name)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(plaintext); fh.flush(); os.fsync(fh.fileno())
            harden_openssh_private_key_permissions(path)
            yield path
        finally:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass

    def delete_identity(self, identity_id: str) -> None:
        with self._lock:
            row = self._row(identity_id)
            for key in ("encrypted_path", "public_path"):
                path = Path(str(row.get(key) or "")).resolve()
                try:
                    path.relative_to(self.root)
                except ValueError as exc:
                    raise SshVaultError("Ruta de identidad SSH fuera del vault GIDEON.") from exc
                path.unlink(missing_ok=True)
            self._write([x for x in self._read() if str(x.get("id")) != str(row.get("id"))])
