from __future__ import annotations

"""Encrypted credential vault for browser-based RDP/VNC sessions.

The browser never receives the secret.  WebAdmin decrypts a credential only
inside the process that is establishing the guacd session.  The encryption key
is domain-separated from TOTP, SSH identities and Agent signing material.
"""

import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
import time
from pathlib import Path
from threading import RLock
from typing import Any

from cryptography.fernet import Fernet, InvalidToken


MAX_REMOTE_PASSWORD_CHARS = 1024
MAX_REMOTE_USERNAME_CHARS = 256
MAX_REMOTE_DOMAIN_CHARS = 256
SUPPORTED_REMOTE_PROTOCOLS = frozenset({"RDP", "VNC"})


class RemoteCredentialError(RuntimeError):
    pass


def _now() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def _chmod(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError:
        pass


class RemoteCredentialVault:
    def __init__(self, data_dir: Path) -> None:
        self.root = (Path(data_dir).resolve() / "security-assets" / "remote-credentials").resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        _chmod(self.root, 0o700)
        self.metadata_path = self.root / "credentials.json"
        self._lock = RLock()
        # Interactive credentials never enter the persistent Vault.  They live
        # only in this WebAdmin process, are scoped to one authenticated WebAdmin
        # session and expire quickly.  A bounded number of reads allows GIDEON to
        # test the RDP security modes automatically without asking the operator
        # to retype the same password.  No value is ever persisted or logged.
        self._ephemeral: dict[str, dict[str, Any]] = {}
        self._ephemeral_max = 256
        if not self.metadata_path.exists():
            self._write([])

    @staticmethod
    def _fernet() -> Fernet:
        raw = str(os.environ.get("GIDEON_WEB_TOTP_ENCRYPTION_KEY") or "").strip().encode("ascii", "ignore")
        if not raw:
            raise RemoteCredentialError(
                "No existe GIDEON_WEB_TOTP_ENCRYPTION_KEY; no se pueden proteger credenciales de escritorio remoto."
            )
        try:
            master = base64.urlsafe_b64decode(raw)
        except Exception as exc:
            raise RemoteCredentialError("GIDEON_WEB_TOTP_ENCRYPTION_KEY no es una clave Fernet válida.") from exc
        if len(master) != 32:
            raise RemoteCredentialError("GIDEON_WEB_TOTP_ENCRYPTION_KEY no tiene 32 bytes efectivos.")
        derived = hmac.new(
            master,
            b"GIDEON-REMOTE-CONTROL\x00REMOTE-CREDENTIAL-VAULT\x00v1",
            hashlib.sha256,
        ).digest()
        return Fernet(base64.urlsafe_b64encode(derived))

    def _read(self) -> list[dict[str, Any]]:
        try:
            raw = json.loads(self.metadata_path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            return []
        return [dict(x) for x in raw if isinstance(x, dict)] if isinstance(raw, list) else []

    def _write(self, rows: list[dict[str, Any]]) -> None:
        fd, name = tempfile.mkstemp(prefix=".remote-credentials-", suffix=".json", dir=str(self.root))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(rows, fh, ensure_ascii=False, indent=2)
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
            tmp = Path(name)
            _chmod(tmp, 0o600)
            os.replace(tmp, self.metadata_path)
            _chmod(self.metadata_path, 0o600)
        finally:
            try:
                if os.path.exists(name):
                    os.unlink(name)
            except OSError:
                pass

    @staticmethod
    def _normalize_protocol(value: str) -> str:
        protocol = str(value or "").strip().upper()
        if protocol not in SUPPORTED_REMOTE_PROTOCOLS:
            raise RemoteCredentialError("Protocolo de credencial no soportado. Use RDP o VNC.")
        return protocol

    @staticmethod
    def _validate_fields(
        *, protocol: str, label: str, username: str, domain: str, password: str,
        allow_empty_rdp_password: bool = False, allow_empty_password: bool = False,
    ) -> tuple[str, str, str, str, str]:
        p = RemoteCredentialVault._normalize_protocol(protocol)
        clean_label = str(label or "").strip()[:120]
        clean_user = str(username or "").strip()
        clean_domain = str(domain or "").strip()
        secret = str(password or "")
        if not clean_label:
            raise RemoteCredentialError("Indique una etiqueta para la credencial.")
        if p == "RDP" and not clean_user:
            raise RemoteCredentialError("RDP requiere un usuario.")
        if not secret and not allow_empty_password and not (allow_empty_rdp_password and p == "RDP"):
            raise RemoteCredentialError("La contraseña no puede estar vacía.")
        if len(clean_user) > MAX_REMOTE_USERNAME_CHARS:
            raise RemoteCredentialError("El usuario excede el tamaño permitido.")
        if len(clean_domain) > MAX_REMOTE_DOMAIN_CHARS:
            raise RemoteCredentialError("El dominio excede el tamaño permitido.")
        if len(secret) > MAX_REMOTE_PASSWORD_CHARS:
            raise RemoteCredentialError("La contraseña excede el tamaño permitido.")
        return p, clean_label, clean_user, clean_domain, secret

    def create(
        self,
        *,
        protocol: str,
        label: str,
        username: str,
        password: str,
        domain: str = "",
    ) -> dict[str, Any]:
        p, clean_label, clean_user, clean_domain, secret = self._validate_fields(
            protocol=protocol, label=label, username=username, domain=domain, password=password
        )
        credential_id = secrets.token_hex(8)
        payload = {
            "schema": 1,
            "protocol": p,
            "username": clean_user,
            "domain": clean_domain,
            "password": secret,
        }
        encrypted = self._fernet().encrypt(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
        secret_path = self.root / f"credential-{credential_id}.fernet"
        stamp = _now()
        row = {
            "id": credential_id,
            "label": clean_label,
            "protocol": p,
            "username": clean_user,
            "domain": clean_domain,
            "secret_path": str(secret_path),
            "created_at": stamp,
            "updated_at": stamp,
        }
        with self._lock:
            secret_path.write_bytes(encrypted)
            _chmod(secret_path, 0o600)
            rows = [x for x in self._read() if str(x.get("id")) != credential_id]
            rows.append(row)
            rows.sort(key=lambda x: (str(x.get("protocol") or ""), str(x.get("label") or "").casefold()))
            self._write(rows)
        return dict(row)

    def _cleanup_ephemeral_locked(self, now: int | None = None) -> None:
        current = int(time.time() if now is None else now)
        expired = [key for key, row in self._ephemeral.items() if int(row.get("expires_unix") or 0) <= current]
        for key in expired:
            row = self._ephemeral.pop(key, None)
            if isinstance(row, dict):
                row.clear()

    def create_ephemeral(
        self,
        *,
        protocol: str,
        username: str,
        password: str,
        domain: str = "",
        user_id: int,
        web_session_id: int,
        ttl_seconds: int = 180,
        max_uses: int = 1,
        allow_empty_password: bool = False,
    ) -> str:
        """Create a bounded-use in-memory credential for an interactive session.

        Nothing is written to ``credentials.json`` or to a ``.fernet`` file.
        The returned opaque id is safe to persist in the remote-session row; it
        carries no username, password or domain.
        """
        p, _label, clean_user, clean_domain, secret = self._validate_fields(
            protocol=protocol, label="Interactive session", username=username, domain=domain, password=password,
            allow_empty_rdp_password=True, allow_empty_password=allow_empty_password,
        )
        now = int(time.time())
        ttl = max(30, min(int(ttl_seconds or 180), 600))
        # Four negotiation modes plus one bounded Windows session-handoff
        # reconnect may consume this credential.  It still expires in memory
        # and is never serialized.
        uses = max(1, min(int(max_uses or 1), 5))
        token = secrets.token_hex(24)
        with self._lock:
            self._cleanup_ephemeral_locked(now)
            if len(self._ephemeral) >= self._ephemeral_max:
                # Fail closed instead of evicting a possibly pending session.
                raise RemoteCredentialError("Capacidad temporal de credenciales interactivas agotada; espere y vuelva a intentar.")
            self._ephemeral[token] = {
                "protocol": p, "username": clean_user, "domain": clean_domain, "password": secret,
                "user_id": int(user_id), "web_session_id": int(web_session_id), "expires_unix": now + ttl,
                "remaining_uses": uses,
            }
        return "ephemeral:" + token

    def ephemeral_available(
        self,
        credential_id: str,
        *,
        protocol: str,
        user_id: int,
        web_session_id: int,
    ) -> bool:
        """Return whether an interactive credential can be read again.

        This intentionally exposes only availability.  Username, domain and
        password remain inside the in-memory cache.
        """
        value = str(credential_id or "")
        if not value.startswith("ephemeral:"):
            return False
        token = value.split(":", 1)[1]
        if not re.fullmatch(r"[0-9a-f]{48}", token):
            return False
        with self._lock:
            self._cleanup_ephemeral_locked()
            row = self._ephemeral.get(token)
            return bool(
                isinstance(row, dict)
                and int(row.get("remaining_uses") or 0) > 0
                and int(row.get("user_id") or 0) == int(user_id)
                and int(row.get("web_session_id") or 0) == int(web_session_id)
                and str(row.get("protocol") or "").upper() == self._normalize_protocol(protocol)
            )

    def discard_ephemeral(self, credential_id: str) -> None:
        value = str(credential_id or "")
        if not value.startswith("ephemeral:"):
            return
        token = value.split(":", 1)[1]
        with self._lock:
            row = self._ephemeral.pop(token, None)
            if isinstance(row, dict):
                row.clear()

    def list_credentials(self, protocol: str = "") -> list[dict[str, Any]]:
        requested = str(protocol or "").strip().upper()
        with self._lock:
            rows = [dict(x) for x in self._read()]
        if requested:
            rows = [x for x in rows if str(x.get("protocol") or "").upper() == requested]
        # Do not expose secret_path to templates or callers that only need metadata.
        for row in rows:
            row.pop("secret_path", None)
        return rows

    def _row(self, credential_id: str) -> dict[str, Any]:
        clean = re.sub(r"[^0-9a-f]", "", str(credential_id or "").lower())[:16]
        if len(clean) != 16:
            raise RemoteCredentialError("Identificador de credencial inválido.")
        row = next((x for x in self._read() if str(x.get("id")) == clean), None)
        if row is None:
            raise RemoteCredentialError("Credencial de escritorio remoto no encontrada.")
        return dict(row)

    def reveal_for_session(
        self, credential_id: str, *, protocol: str, user_id: int = 0, web_session_id: int = 0
    ) -> dict[str, str]:
        requested = str(credential_id or "")
        if requested.startswith("ephemeral:"):
            token = requested.split(":", 1)[1]
            if not re.fullmatch(r"[0-9a-f]{48}", token):
                raise RemoteCredentialError("Identificador temporal de credencial inválido.")
            with self._lock:
                self._cleanup_ephemeral_locked()
                row = self._ephemeral.get(token)
                if row is None:
                    raise RemoteCredentialError("La credencial interactiva expiró o ya fue utilizada.")
                if int(row.get("user_id") or 0) != int(user_id) or int(row.get("web_session_id") or 0) != int(web_session_id):
                    row.clear()
                    raise RemoteCredentialError("La credencial interactiva pertenece a otra sesión WebAdmin.")
                if str(row.get("protocol") or "").upper() != self._normalize_protocol(protocol):
                    row.clear()
                    raise RemoteCredentialError("La credencial interactiva no corresponde al protocolo solicitado.")
                result = {
                    "protocol": str(row.get("protocol") or ""),
                    "username": str(row.get("username") or ""),
                    "domain": str(row.get("domain") or ""),
                    "password": str(row.get("password") or ""),
                }
                remaining = max(0, int(row.get("remaining_uses") or 1) - 1)
                row["remaining_uses"] = remaining
                if remaining == 0:
                    self._ephemeral.pop(token, None)
                    row.clear()
                return result
        with self._lock:
            row = self._row(requested)
            if str(row.get("protocol") or "").upper() != self._normalize_protocol(protocol):
                raise RemoteCredentialError("La credencial seleccionada no corresponde al protocolo solicitado.")
            path = Path(str(row.get("secret_path") or "")).resolve()
            try:
                path.relative_to(self.root)
            except ValueError as exc:
                raise RemoteCredentialError("Ruta de secreto fuera del vault GIDEON.") from exc
            try:
                plaintext = self._fernet().decrypt(path.read_bytes())
            except (OSError, InvalidToken) as exc:
                raise RemoteCredentialError("No se pudo descifrar la credencial remota.") from exc
            try:
                payload = json.loads(plaintext.decode("utf-8"))
            except Exception as exc:
                raise RemoteCredentialError("El secreto remoto almacenado está dañado.") from exc
            if not isinstance(payload, dict):
                raise RemoteCredentialError("El secreto remoto almacenado es inválido.")
            return {
                "protocol": str(payload.get("protocol") or ""),
                "username": str(payload.get("username") or ""),
                "domain": str(payload.get("domain") or ""),
                "password": str(payload.get("password") or ""),
            }

    def delete(self, credential_id: str) -> dict[str, Any]:
        with self._lock:
            row = self._row(credential_id)
            path = Path(str(row.get("secret_path") or "")).resolve()
            try:
                path.relative_to(self.root)
            except ValueError as exc:
                raise RemoteCredentialError("Ruta de secreto fuera del vault GIDEON.") from exc
            try:
                path.unlink(missing_ok=True)
            except OSError as exc:
                raise RemoteCredentialError("No se pudo eliminar el secreto cifrado.") from exc
            rows = [x for x in self._read() if str(x.get("id")) != str(row.get("id"))]
            self._write(rows)
            clean = dict(row)
            clean.pop("secret_path", None)
            return clean
