"""Create narrowly-scoped authorisations for an offline VLC installation.

The WebAdmin process is the only component that can use the protected GIDEON
release-signing key.  This module deliberately produces a small, Agent-bound
envelope instead of accepting an installer path, command line, package URL, or
any other mutable execution input.  The Agent validates the exact canonical
payload again with its enrolled public key before it launches its fixed local
installer.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import re
import secrets
from typing import Any, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


OFFLINE_VLC_AUTHORIZATION_SCHEMA = "gideon-vlc-offline-install-authorization/v1"
OFFLINE_VLC_AUTHORIZATION_TTL_SECONDS = 15 * 60

_AGENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_REQUEST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,159}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")


class OfflineVlcAuthorizationError(ValueError):
    """An explicit offline VLC authorisation cannot be safely issued."""


def canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    """Return the byte-for-byte JSON representation checked by the Agent."""
    return (
        json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _required_identifier(value: Any, *, name: str, pattern: re.Pattern[str]) -> str:
    text = str(value or "").strip()
    if not pattern.fullmatch(text):
        raise OfflineVlcAuthorizationError(f"{name} inválido para autorización VLC sin conexión.")
    return text


def _utc_now(now: dt.datetime | None) -> dt.datetime:
    if now is None:
        return dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None:
        raise OfflineVlcAuthorizationError("La hora de autorización VLC debe incluir zona horaria.")
    return now.astimezone(dt.timezone.utc)


def _release_signing_key(security_assets: Any) -> Ed25519PrivateKey:
    """Load the existing protected release key without exposing its bytes."""
    try:
        status = security_assets.signing_status()
        private_bytes = security_assets.signing_private_key_bytes()
    except Exception as exc:
        raise OfflineVlcAuthorizationError(
            "La firma Ed25519 de releases no está disponible para autorizar VLC sin conexión."
        ) from exc
    if not isinstance(status, Mapping) or not bool(status.get("usable")) or not private_bytes:
        raise OfflineVlcAuthorizationError(
            "Configure una firma Ed25519 de releases antes de autorizar VLC sin conexión."
        )
    # SecurityAssetManager accepts both PKCS#8 PEM and OpenSSH Ed25519 keys.
    # Keep this signing boundary aligned with that contract: an external
    # OpenSSH key that passes signing_status() must not fail only on this path.
    last_error: Exception | None = None
    for loader in (serialization.load_pem_private_key, serialization.load_ssh_private_key):
        try:
            private = loader(bytes(private_bytes), password=None)
        except Exception as exc:
            last_error = exc
            continue
        if not isinstance(private, Ed25519PrivateKey):
            raise OfflineVlcAuthorizationError("La clave configurada para releases no es Ed25519.")
        return private
    raise OfflineVlcAuthorizationError(
        "No se pudo abrir la firma Ed25519 configurada para autorizar VLC sin conexión."
    ) from last_error


def build_install_authorization(
    *,
    agent_id: str,
    catalog_sha256: str,
    security_assets: Any,
    gpl_acknowledged: bool,
    now: dt.datetime | None = None,
    request_id: str | None = None,
) -> dict[str, Any]:
    """Create one strictly fifteen-minute, signed offline VLC install grant.

    There is intentionally no caller-controlled expiration duration.  A
    request can only be issued after the browser explicitly acknowledges the
    GPL terms, and is inseparably bound to both one Agent ID and the exact
    reviewed catalog hash it reported in its authenticated heartbeat.
    """
    if gpl_acknowledged is not True:
        raise OfflineVlcAuthorizationError(
            "Debe confirmar explícitamente la licencia GPL de VLC antes de autorizar la instalación."
        )
    clean_agent_id = _required_identifier(agent_id, name="AgentId", pattern=_AGENT_ID)
    clean_catalog_sha256 = str(catalog_sha256 or "").strip().lower()
    if not _SHA256.fullmatch(clean_catalog_sha256):
        raise OfflineVlcAuthorizationError(
            "El Agent no reportó un hash SHA-256 válido del catálogo VLC sin conexión."
        )
    generated_request_id = request_id or ("vlc-" + secrets.token_hex(16))
    clean_request_id = _required_identifier(generated_request_id, name="RequestId", pattern=_REQUEST_ID)
    issued_at = _utc_now(now)
    expires_at = issued_at + dt.timedelta(seconds=OFFLINE_VLC_AUTHORIZATION_TTL_SECONDS)
    # UTC and second precision keep the signed value stable and compatible with
    # the Agent's timezone-aware ISO-8601 parser.
    expires_text = expires_at.isoformat(timespec="seconds")
    payload = {
        "Action": "INSTALL",
        "AgentId": clean_agent_id,
        "CatalogSha256": clean_catalog_sha256,
        "RequestId": clean_request_id,
        "ExpiresAt": expires_text,
        "GplAcknowledged": True,
    }
    document = canonical_json_bytes(payload)
    private = _release_signing_key(security_assets)
    return {
        "Schema": OFFLINE_VLC_AUTHORIZATION_SCHEMA,
        "Payload": payload,
        "Signature": base64.b64encode(private.sign(document)).decode("ascii"),
    }


def authorization_audit_metadata(envelope: Mapping[str, Any]) -> dict[str, str]:
    """Return safe audit fields; deliberately never return signature/key data."""
    payload = envelope.get("Payload") if isinstance(envelope, Mapping) else {}
    if not isinstance(payload, Mapping):
        return {}
    catalog_sha256 = str(payload.get("CatalogSha256") or "").strip().lower()
    return {
        "RequestId": str(payload.get("RequestId") or "").strip()[:160],
        "AgentId": str(payload.get("AgentId") or "").strip()[:160],
        "CatalogSha256": catalog_sha256 if _SHA256.fullmatch(catalog_sha256) else "",
        "ExpiresAt": str(payload.get("ExpiresAt") or "").strip()[:80],
    }


__all__ = [
    "OFFLINE_VLC_AUTHORIZATION_SCHEMA",
    "OFFLINE_VLC_AUTHORIZATION_TTL_SECONDS",
    "OfflineVlcAuthorizationError",
    "authorization_audit_metadata",
    "build_install_authorization",
    "canonical_json_bytes",
]
