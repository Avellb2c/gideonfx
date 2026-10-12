from __future__ import annotations

"""Web-managed security assets for GIDEON Remote Control.

Private execution-signing keys are never stored as plaintext application files.
Managed keys are encrypted at rest with the Web Admin Fernet KEK and protected
by the operating-system ACL of the persistent GIDEON data tree. Public assets
(CA certificates, YARA policy and SSH public keys) are stored separately.
"""

import base64
import datetime as dt
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from threading import Lock
from typing import Any

from cryptography import x509
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey


MAX_PRIVATE_KEY_BYTES = 64 * 1024
MAX_CA_BYTES = 2 * 1024 * 1024
MAX_YARA_BYTES = 1024 * 1024
MAX_SSH_PUBLIC_KEY_BYTES = 64 * 1024


def _now() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _ssh_sha256(public_bytes: bytes) -> str:
    digest = hashlib.sha256(public_bytes).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _chmod_best_effort(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError:
        pass


class SecurityAssetError(RuntimeError):
    pass


class SecurityAssetManager:
    def __init__(self, data_dir: Path, config: dict[str, Any]) -> None:
        self.data_dir = Path(data_dir).resolve()
        self.config = config
        self.root = (self.data_dir / "security-assets").resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        _chmod_best_effort(self.root, 0o700)
        self.signing_dir = self.root / "signing"
        self.ca_dir = self.root / "ca"
        self.yara_dir = self.root / "yara"
        self.ssh_dir = self.root / "ssh-public"
        for path in (self.signing_dir, self.ca_dir, self.yara_dir, self.ssh_dir):
            path.mkdir(parents=True, exist_ok=True)
            _chmod_best_effort(path, 0o700)
        self.metadata_path = self.root / "assets.json"
        self.managed_private_path = self.signing_dir / "execution-ed25519.key.fernet"
        self.managed_public_path = self.signing_dir / "execution-ed25519.pub.pem"
        self.gateway_ca_path = self.ca_dir / "gateway-ca.pem"
        self.yara_rules_path = self.yara_dir / "gideon-policy.yar"
        self._lock = Lock()
        self._ensure_metadata()
        self.apply_runtime_overrides()

    @staticmethod
    def _default_metadata() -> dict[str, Any]:
        return {
            "schema": 1,
            "execution_signing": {
                "mode": "none",
                "key_id": "",
                "fingerprint": "",
                "source": "",
                "updated_at": "",
            },
            "gateway_ca": {"active": False, "sha256": "", "subjects": [], "updated_at": ""},
            "yara": {"active": False, "sha256": "", "updated_at": ""},
            "ssh_public_keys": [],
        }

    def _ensure_metadata(self) -> None:
        if not self.metadata_path.exists():
            self._write_metadata(self._default_metadata())

    def _load_metadata(self) -> dict[str, Any]:
        base = self._default_metadata()
        try:
            raw = json.loads(self.metadata_path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            return base
        if not isinstance(raw, dict):
            return base
        for key in ("execution_signing", "gateway_ca", "yara"):
            if isinstance(raw.get(key), dict):
                base[key].update(raw[key])
        if isinstance(raw.get("ssh_public_keys"), list):
            base["ssh_public_keys"] = [dict(x) for x in raw["ssh_public_keys"] if isinstance(x, dict)]
        return base

    def _write_metadata(self, value: dict[str, Any]) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=".assets-", suffix=".json", dir=str(self.root))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(value, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            _chmod_best_effort(Path(tmp_name), 0o600)
            os.replace(tmp_name, self.metadata_path)
            _chmod_best_effort(self.metadata_path, 0o600)
        finally:
            try:
                if os.path.exists(tmp_name):
                    os.unlink(tmp_name)
            except OSError:
                pass

    @staticmethod
    def _fernet() -> Fernet:
        raw = str(os.environ.get("GIDEON_WEB_TOTP_ENCRYPTION_KEY") or "").strip().encode("ascii", "ignore")
        if not raw:
            raise SecurityAssetError("No existe GIDEON_WEB_TOTP_ENCRYPTION_KEY; no se puede proteger una clave privada administrada por la Web.")
        try:
            return Fernet(raw)
        except Exception as exc:
            raise SecurityAssetError("GIDEON_WEB_TOTP_ENCRYPTION_KEY no es una clave Fernet válida.") from exc

    @staticmethod
    def _load_ed25519_private(content: bytes, passphrase: str = "") -> Ed25519PrivateKey:
        if not content or len(content) > MAX_PRIVATE_KEY_BYTES:
            raise SecurityAssetError("La clave privada está vacía o excede 64 KiB.")
        password = passphrase.encode("utf-8") if passphrase else None
        loaders = (
            serialization.load_pem_private_key,
            serialization.load_ssh_private_key,
        )
        last: Exception | None = None
        for loader in loaders:
            try:
                key = loader(content, password=password)
                if not isinstance(key, Ed25519PrivateKey):
                    raise SecurityAssetError("La clave debe ser Ed25519; RSA/ECDSA no se aceptan para firma de Jobs GIDEON.")
                return key
            except SecurityAssetError:
                raise
            except Exception as exc:
                last = exc
        raise SecurityAssetError("No se pudo abrir la clave privada Ed25519. Verifique formato y passphrase.") from last

    @staticmethod
    def _canonical_private(key: Ed25519PrivateKey) -> bytes:
        return key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    @staticmethod
    def _public_pem(key: Ed25519PrivateKey) -> bytes:
        return key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @staticmethod
    def _public_raw(key: Ed25519PrivateKey) -> bytes:
        return key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

    def _persist_public(self, public_pem: bytes) -> None:
        self.managed_public_path.write_bytes(public_pem)
        _chmod_best_effort(self.managed_public_path, 0o640)

    def _set_signing_metadata(self, *, mode: str, key: Ed25519PrivateKey, source: str) -> dict[str, Any]:
        public_raw = self._public_raw(key)
        fingerprint = _ssh_sha256(public_raw)
        key_id = "gideon-agent-ed25519-" + hashlib.sha256(public_raw).hexdigest()[:12]
        meta = self._load_metadata()
        meta["execution_signing"] = {
            "mode": mode,
            "key_id": key_id,
            "fingerprint": fingerprint,
            "source": source,
            "updated_at": _now(),
        }
        self._write_metadata(meta)
        self._persist_public(self._public_pem(key))
        return dict(meta["execution_signing"])

    def generate_signing_key(self) -> dict[str, Any]:
        with self._lock:
            key = Ed25519PrivateKey.generate()
            plaintext = self._canonical_private(key)
            encrypted = self._fernet().encrypt(plaintext)
            self.managed_private_path.write_bytes(encrypted)
            _chmod_best_effort(self.managed_private_path, 0o600)
            return self._set_signing_metadata(mode="managed", key=key, source="Generada por Web Admin")

    def import_signing_key(self, content: bytes, *, passphrase: str = "") -> dict[str, Any]:
        with self._lock:
            key = self._load_ed25519_private(content, passphrase)
            encrypted = self._fernet().encrypt(self._canonical_private(key))
            self.managed_private_path.write_bytes(encrypted)
            _chmod_best_effort(self.managed_private_path, 0o600)
            return self._set_signing_metadata(mode="managed", key=key, source="Importada por Web Admin")

    def configure_external_signing_key(self, raw_path: str) -> dict[str, Any]:
        clean = os.path.expandvars(str(raw_path or "").strip())
        if not clean:
            raise SecurityAssetError("Indique la ruta absoluta de una clave Ed25519 externa de solo lectura.")
        path = Path(clean).expanduser()
        if not path.is_absolute():
            raise SecurityAssetError("La ruta de clave externa debe ser absoluta.")
        path = path.resolve()
        if not path.is_file():
            raise SecurityAssetError(f"La clave externa no existe: {path}")
        key = self._load_ed25519_private(path.read_bytes())
        with self._lock:
            # Do not copy or delete the external private key. Only remember its path.
            try:
                self.managed_private_path.unlink(missing_ok=True)
            except OSError:
                pass
            return self._set_signing_metadata(mode="external_path", key=key, source=str(path))

    def signing_private_key_bytes(self) -> bytes:
        meta = self._load_metadata().get("execution_signing") or {}
        mode = str(meta.get("mode") or "none")
        if mode == "managed":
            if not self.managed_private_path.is_file():
                raise SecurityAssetError("La metadata indica clave administrada pero el secreto cifrado no existe.")
            try:
                plaintext = self._fernet().decrypt(self.managed_private_path.read_bytes())
            except InvalidToken as exc:
                raise SecurityAssetError("No se pudo descifrar la clave de firma administrada.") from exc
            # Re-validate before every signing operation.
            self._load_ed25519_private(plaintext)
            return plaintext
        if mode == "external_path":
            path = Path(str(meta.get("source") or "")).expanduser()
            if not path.is_file():
                raise SecurityAssetError(f"La clave externa ya no está disponible: {path}")
            content = path.read_bytes()
            self._load_ed25519_private(content)
            return content
        raise SecurityAssetError("No hay una clave Ed25519 de ejecución configurada.")

    def signing_key_id(self) -> str:
        return str((self._load_metadata().get("execution_signing") or {}).get("key_id") or "gideon-agent-ed25519-1")

    def signing_public_key_bytes(self) -> bytes:
        if not self.managed_public_path.is_file():
            raise SecurityAssetError("No existe clave pública de ejecución.")
        return self.managed_public_path.read_bytes()

    def test_signing(self) -> dict[str, Any]:
        private = self._load_ed25519_private(self.signing_private_key_bytes())
        challenge = b"GIDEON-Remote-Control-signing-self-test-v1"
        signature = private.sign(challenge)
        public = private.public_key()
        public.verify(signature, challenge)
        return {
            "ok": True,
            "key_id": self.signing_key_id(),
            "fingerprint": _ssh_sha256(public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
        }

    def remove_signing_key(self) -> None:
        with self._lock:
            meta = self._load_metadata()
            mode = str((meta.get("execution_signing") or {}).get("mode") or "none")
            if mode == "managed":
                try:
                    self.managed_private_path.unlink(missing_ok=True)
                except OSError as exc:
                    raise SecurityAssetError(f"No se pudo eliminar la clave administrada: {exc}") from exc
            try:
                self.managed_public_path.unlink(missing_ok=True)
            except OSError:
                pass
            meta["execution_signing"] = self._default_metadata()["execution_signing"]
            self._write_metadata(meta)

    def signing_status(self) -> dict[str, Any]:
        row = dict(self._load_metadata().get("execution_signing") or {})
        mode = str(row.get("mode") or "none")
        row["configured"] = mode in {"managed", "external_path"}
        row["public_key_available"] = self.managed_public_path.is_file()
        try:
            test = self.test_signing() if row["configured"] else {"ok": False}
            row["usable"] = bool(test.get("ok"))
            row["error"] = ""
        except Exception as exc:
            row["usable"] = False
            row["error"] = str(exc)
        return row

    @staticmethod
    def _certificate_blocks(content: bytes) -> list[bytes]:
        return re.findall(br"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", content, flags=re.DOTALL)

    def import_gateway_ca(self, content: bytes) -> dict[str, Any]:
        if not content or len(content) > MAX_CA_BYTES:
            raise SecurityAssetError("El bundle CA está vacío o excede 2 MiB.")
        blocks = self._certificate_blocks(content)
        if not blocks:
            raise SecurityAssetError("El archivo no contiene certificados PEM.")
        subjects: list[str] = []
        normalized: list[bytes] = []
        for block in blocks:
            try:
                cert = x509.load_pem_x509_certificate(block + b"\n")
            except Exception as exc:
                raise SecurityAssetError("El bundle contiene un certificado PEM inválido.") from exc
            try:
                bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
                if not bc.ca:
                    raise SecurityAssetError(f"El certificado no es una CA: {cert.subject.rfc4514_string()}")
            except x509.ExtensionNotFound:
                # Some legacy enterprise roots do not carry BasicConstraints.
                pass
            subjects.append(cert.subject.rfc4514_string() or "(sin subject)")
            normalized.append(cert.public_bytes(serialization.Encoding.PEM))
        payload = b"".join(normalized)
        with self._lock:
            self.gateway_ca_path.write_bytes(payload)
            _chmod_best_effort(self.gateway_ca_path, 0o640)
            meta = self._load_metadata()
            meta["gateway_ca"] = {
                "active": True,
                "sha256": _sha256_bytes(payload),
                "subjects": subjects,
                "updated_at": _now(),
            }
            self._write_metadata(meta)
            self.apply_runtime_overrides()
            return dict(meta["gateway_ca"])

    def disable_gateway_ca_override(self) -> None:
        with self._lock:
            meta = self._load_metadata()
            row = dict(meta.get("gateway_ca") or {})
            row["active"] = False
            row["updated_at"] = _now()
            meta["gateway_ca"] = row
            self._write_metadata(meta)
            self.apply_runtime_overrides()

    def import_yara_rules(self, content: bytes) -> dict[str, Any]:
        if not content or len(content) > MAX_YARA_BYTES:
            raise SecurityAssetError("Las reglas YARA están vacías o exceden 1 MiB.")
        if b"\x00" in content:
            raise SecurityAssetError("Las reglas YARA deben ser texto UTF-8, no binario.")
        try:
            text = content.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise SecurityAssetError("Las reglas YARA deben estar codificadas en UTF-8.") from exc
        # Prevent rules from reading arbitrary server-side include files.
        if re.search(r"(?im)^\s*include\s+[\"']", text):
            raise SecurityAssetError("Por aislamiento, las reglas YARA administradas por Web no pueden usar include.")
        if not re.search(r"(?im)^\s*(private\s+|global\s+)?rule\s+[A-Za-z_]", text):
            raise SecurityAssetError("No se encontró ninguna declaración YARA 'rule'.")
        payload = text.replace("\r\n", "\n").encode("utf-8")
        with self._lock:
            self.yara_rules_path.write_bytes(payload)
            _chmod_best_effort(self.yara_rules_path, 0o640)
            meta = self._load_metadata()
            meta["yara"] = {"active": True, "sha256": _sha256_bytes(payload), "updated_at": _now()}
            self._write_metadata(meta)
            self.apply_runtime_overrides()
            return dict(meta["yara"])

    def disable_yara(self) -> None:
        with self._lock:
            meta = self._load_metadata()
            row = dict(meta.get("yara") or {})
            row["active"] = False
            row["updated_at"] = _now()
            meta["yara"] = row
            self._write_metadata(meta)
            self.apply_runtime_overrides()

    @staticmethod
    def _load_ssh_public(content: bytes):
        if not content or len(content) > MAX_SSH_PUBLIC_KEY_BYTES:
            raise SecurityAssetError("La clave pública SSH está vacía o excede 64 KiB.")
        upper = content.upper()
        if b"PRIVATE KEY" in upper:
            raise SecurityAssetError("Se rechazó una CLAVE PRIVADA. Esta sección acepta únicamente claves públicas SSH.")
        line = next((x.strip() for x in content.splitlines() if x.strip() and not x.lstrip().startswith(b"#")), b"")
        if not line:
            raise SecurityAssetError("No se encontró una clave pública SSH.")
        try:
            key = serialization.load_ssh_public_key(line)
        except Exception as exc:
            raise SecurityAssetError("Formato de clave pública SSH inválido.") from exc
        if isinstance(key, RSAPublicKey) and key.key_size < 3072:
            raise SecurityAssetError("Las claves RSA SSH deben tener al menos 3072 bits.")
        if not isinstance(key, (Ed25519PublicKey, RSAPublicKey, EllipticCurvePublicKey)):
            raise SecurityAssetError("Tipo de clave SSH no soportado.")
        canonical = key.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        return key, canonical

    def import_ssh_public_key(self, content: bytes, *, label: str = "") -> dict[str, Any]:
        _key, canonical = self._load_ssh_public(content)
        fingerprint = _ssh_sha256(canonical)
        safe_id = hashlib.sha256(canonical).hexdigest()[:16]
        target = self.ssh_dir / f"ssh-{safe_id}.pub"
        target.write_bytes(canonical + b"\n")
        _chmod_best_effort(target, 0o640)
        with self._lock:
            meta = self._load_metadata()
            rows = [dict(x) for x in meta.get("ssh_public_keys") or [] if str(x.get("id")) != safe_id]
            row = {
                "id": safe_id,
                "label": str(label or "SSH public key").strip()[:120],
                "fingerprint": fingerprint,
                "path": str(target),
                "updated_at": _now(),
            }
            rows.append(row)
            meta["ssh_public_keys"] = sorted(rows, key=lambda x: str(x.get("label") or "").casefold())
            self._write_metadata(meta)
            return row

    def delete_ssh_public_key(self, key_id: str) -> None:
        clean = re.sub(r"[^0-9a-f]", "", str(key_id or "").lower())[:16]
        if len(clean) != 16:
            raise SecurityAssetError("Identificador de clave SSH inválido.")
        with self._lock:
            meta = self._load_metadata()
            rows = [dict(x) for x in meta.get("ssh_public_keys") or []]
            match = next((x for x in rows if str(x.get("id")) == clean), None)
            if match is None:
                raise SecurityAssetError("Clave SSH no encontrada.")
            path = Path(str(match.get("path") or ""))
            try:
                # Only delete a file physically located in this manager's SSH directory.
                path.resolve().relative_to(self.ssh_dir.resolve())
            except ValueError as exc:
                raise SecurityAssetError("Ruta SSH administrada inválida.") from exc
            path.unlink(missing_ok=True)
            meta["ssh_public_keys"] = [x for x in rows if str(x.get("id")) != clean]
            self._write_metadata(meta)

    def status(self) -> dict[str, Any]:
        meta = self._load_metadata()
        return {
            "signing": self.signing_status(),
            "gateway_ca": {**dict(meta.get("gateway_ca") or {}), "path": str(self.gateway_ca_path) if self.gateway_ca_path.is_file() else ""},
            "yara": {**dict(meta.get("yara") or {}), "path": str(self.yara_rules_path) if self.yara_rules_path.is_file() else ""},
            "ssh_public_keys": [dict(x) for x in meta.get("ssh_public_keys") or []],
        }

    def apply_runtime_overrides(self) -> None:
        meta = self._load_metadata()
        ca = dict(meta.get("gateway_ca") or {})
        if bool(ca.get("active")) and self.gateway_ca_path.is_file():
            self.config["gateway_ca_file"] = str(self.gateway_ca_path)
        yara = dict(meta.get("yara") or {})
        if bool(yara.get("active")) and self.yara_rules_path.is_file():
            self.config["yara_rules_file"] = str(self.yara_rules_path)
