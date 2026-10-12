from __future__ import annotations

"""Detached Ed25519 signatures and trust-store handling for product updates.

The product never ships a private release-signing key.  Update packages contain
only a detached signature envelope.  Verification succeeds exclusively when the
signing public key already exists in the local GIDEON trust store.
"""

import base64
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SIGNATURE_SCHEMA = "gideon-product-update-signature/v1"
SIGNATURE_FILE = "manifest.sig.json"
REVOCATION_FILE = "revoked.json"
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,95}$")


class UpdateSignatureError(RuntimeError):
    pass


def _web_readable_best_effort(path: Path, *, directory: bool = False) -> None:
    """Linux: root owns trust material, gideonweb receives read/traverse only."""
    try:
        os.chmod(path, 0o750 if directory else 0o640)
    except OSError:
        pass
    if os.name == "nt":
        return
    try:
        import grp
        gid = grp.getgrnam("gideonweb").gr_gid
        os.chown(path, -1, gid)
    except (KeyError, OSError):
        pass


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _validate_key_id(value: str) -> str:
    key_id = str(value or "").strip()
    if not _KEY_ID_RE.fullmatch(key_id):
        raise UpdateSignatureError("key_id de release inválido.")
    return key_id


def load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    except Exception as exc:
        raise UpdateSignatureError(f"No se pudo abrir la clave privada Ed25519: {exc}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise UpdateSignatureError("La clave privada de releases debe ser Ed25519.")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(Path(path).read_bytes())
    except Exception as exc:
        raise UpdateSignatureError(f"No se pudo abrir la clave pública de releases: {exc}") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise UpdateSignatureError("La clave pública confiable debe ser Ed25519.")
    return key


def public_key_fingerprint(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")


def public_key_id(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "gideon-release-ed25519-" + hashlib.sha256(raw).hexdigest()[:16]


def sign_manifest_bytes(manifest_bytes: bytes, private_key_path: Path, *, key_id: str = "") -> dict[str, Any]:
    key = load_private_key(Path(private_key_path))
    public = key.public_key()
    resolved_key_id = _validate_key_id(key_id or public_key_id(public))
    signature = key.sign(bytes(manifest_bytes))
    return {
        "schema": SIGNATURE_SCHEMA,
        "algorithm": "Ed25519",
        "key_id": resolved_key_id,
        "manifest_sha256": sha256_bytes(bytes(manifest_bytes)),
        "signature": base64.b64encode(signature).decode("ascii"),
        "public_fingerprint": public_key_fingerprint(public),
    }


def parse_signature_envelope(content: bytes | str) -> dict[str, Any]:
    try:
        if isinstance(content, bytes):
            value = json.loads(content.decode("utf-8-sig"))
        else:
            value = json.loads(content)
    except Exception as exc:
        raise UpdateSignatureError(f"{SIGNATURE_FILE} inválido: {exc}") from exc
    if not isinstance(value, dict):
        raise UpdateSignatureError(f"{SIGNATURE_FILE} debe contener un objeto JSON.")
    if value.get("schema") != SIGNATURE_SCHEMA or value.get("algorithm") != "Ed25519":
        raise UpdateSignatureError("Firma de actualización no soportada.")
    _validate_key_id(str(value.get("key_id") or ""))
    digest = str(value.get("manifest_sha256") or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise UpdateSignatureError("manifest_sha256 de la firma es inválido.")
    signature = str(value.get("signature") or "")
    try:
        decoded = base64.b64decode(signature, validate=True)
    except Exception as exc:
        raise UpdateSignatureError("Firma Ed25519 no está en Base64 válido.") from exc
    if len(decoded) != 64:
        raise UpdateSignatureError("Firma Ed25519 tiene longitud inválida.")
    return value


def trusted_public_key_path(trust_dir: Path, key_id: str) -> Path:
    key_id = _validate_key_id(key_id)
    root = Path(trust_dir).resolve()
    candidate = (root / f"{key_id}.pub.pem").resolve()
    if candidate.parent != root:
        raise UpdateSignatureError("Ruta de clave confiable inválida.")
    return candidate


def revoked_key_ids(trust_dir: Path) -> set[str]:
    path = Path(trust_dir) / REVOCATION_FILE
    if not path.is_file():
        return set()
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        raise UpdateSignatureError(f"Lista de revocación inválida: {exc}") from exc
    rows = value.get("revoked_key_ids") if isinstance(value, dict) else None
    if not isinstance(rows, list):
        raise UpdateSignatureError("Lista de revocación inválida.")
    return {_validate_key_id(str(x)) for x in rows}


def set_key_revocation(trust_dir: Path, key_id: str, *, revoked: bool = True) -> dict[str, Any]:
    root = Path(trust_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    _web_readable_best_effort(root, directory=True)
    key_id = _validate_key_id(key_id)
    current = revoked_key_ids(root)
    if revoked:
        current.add(key_id)
    else:
        current.discard(key_id)
    payload = {"schema": "gideon-update-key-revocation/v1", "revoked_key_ids": sorted(current)}
    target = root / REVOCATION_FILE
    temp = root / f".{REVOCATION_FILE}.tmp"
    temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    _web_readable_best_effort(temp)
    os.replace(temp, target)
    _web_readable_best_effort(target)
    return {"key_id": key_id, "revoked": revoked, "path": str(target)}


def list_trusted_public_keys(trust_dir: Path) -> list[dict[str, Any]]:
    root = Path(trust_dir).resolve()
    revoked = revoked_key_ids(root)
    rows: list[dict[str, Any]] = []
    for path in sorted(root.glob("*.pub.pem")) if root.exists() else []:
        try:
            key = load_public_key(path)
            key_id = path.name[:-8]
            rows.append({"key_id": key_id, "fingerprint": public_key_fingerprint(key), "revoked": key_id in revoked, "path": str(path)})
        except UpdateSignatureError:
            rows.append({"key_id": path.name[:-8], "fingerprint": "INVALID", "revoked": True, "path": str(path)})
    return rows


def verify_manifest_bytes(manifest_bytes: bytes, signature_content: bytes | str, trust_dir: Path) -> dict[str, Any]:
    envelope = parse_signature_envelope(signature_content)
    expected_digest = str(envelope["manifest_sha256"]).lower()
    actual_digest = sha256_bytes(manifest_bytes)
    if actual_digest != expected_digest:
        raise UpdateSignatureError("El SHA-256 de manifest.json no coincide con la firma.")
    key_id = str(envelope["key_id"])
    if key_id in revoked_key_ids(Path(trust_dir)):
        raise UpdateSignatureError(f"UNTRUSTED_SIGNATURE: key_id={key_id} está revocado.")
    public_path = trusted_public_key_path(Path(trust_dir), key_id)
    if not public_path.is_file():
        raise UpdateSignatureError(
            f"UNTRUSTED_SIGNATURE: no existe clave pública confiable para key_id={key_id}."
        )
    public = load_public_key(public_path)
    declared_fingerprint = str(envelope.get("public_fingerprint") or "").strip()
    actual_fingerprint = public_key_fingerprint(public)
    if declared_fingerprint and declared_fingerprint != actual_fingerprint:
        raise UpdateSignatureError("La huella de la clave confiable no coincide con el sobre de firma.")
    try:
        public.verify(base64.b64decode(str(envelope["signature"]), validate=True), manifest_bytes)
    except Exception as exc:
        raise UpdateSignatureError("UNTRUSTED_SIGNATURE: firma Ed25519 inválida.") from exc
    return {
        "verified": True,
        "key_id": key_id,
        "fingerprint": actual_fingerprint,
        "manifest_sha256": actual_digest,
    }


def install_trusted_public_key(public_key: Path, trust_dir: Path, *, key_id: str = "", replace: bool = False) -> dict[str, str]:
    public = load_public_key(Path(public_key))
    resolved_key_id = _validate_key_id(key_id or public_key_id(public))
    root = Path(trust_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    _web_readable_best_effort(root, directory=True)
    target = trusted_public_key_path(root, resolved_key_id)
    pem = public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    if target.exists() and not replace:
        existing = load_public_key(target)
        if existing.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) != public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw):
            raise UpdateSignatureError(f"key_id={resolved_key_id} ya existe con otra clave; use rotación explícita.")
        return {"key_id": resolved_key_id, "fingerprint": public_key_fingerprint(existing), "path": str(target)}
    temp = target.with_name(f".{target.name}.tmp")
    temp.write_bytes(pem)
    _web_readable_best_effort(temp)
    os.replace(temp, target)
    _web_readable_best_effort(target)
    return {"key_id": resolved_key_id, "fingerprint": public_key_fingerprint(public), "path": str(target)}
