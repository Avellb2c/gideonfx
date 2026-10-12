from __future__ import annotations

"""Cryptographic sealing for native certification evidence.

The evidence private key belongs to the pilot operator/host and is never bundled
with GIDEON Remote Control. The production gate receives only the corresponding
public key and verifies the canonical JSON before trusting PASS results.
"""

import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SEAL_SCHEMA = "gideon-native-evidence-seal/v1"
SEAL_ALGORITHM = "Ed25519"


def _canonical_payload(report: dict[str, Any]) -> bytes:
    value = copy.deepcopy(report)
    value.pop("evidence_seal", None)
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _public_raw(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def public_fingerprint(public_key: Ed25519PublicKey) -> str:
    return hashlib.sha256(_public_raw(public_key)).hexdigest()


def load_private_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("La clave de evidencia debe ser Ed25519")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("La clave pública de evidencia debe ser Ed25519")
    return key


def sign_report(report: dict[str, Any], private_key_path: Path, *, key_id: str = "") -> dict[str, Any]:
    key = load_private_key(private_key_path)
    public = key.public_key()
    fingerprint = public_fingerprint(public)
    sealed = copy.deepcopy(report)
    sealed.pop("evidence_seal", None)
    signature = key.sign(_canonical_payload(sealed))
    sealed["evidence_seal"] = {
        "schema": SEAL_SCHEMA,
        "algorithm": SEAL_ALGORITHM,
        "key_id": key_id.strip() or f"pilot-{fingerprint[:16]}",
        "public_key_sha256": fingerprint,
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    }
    return sealed


def verify_report(report: dict[str, Any], public_key_path: Path) -> list[str]:
    errors: list[str] = []
    seal = report.get("evidence_seal")
    if not isinstance(seal, dict):
        return ["Falta evidence_seal Ed25519"]
    if seal.get("schema") != SEAL_SCHEMA:
        errors.append("Schema de evidence_seal inválido")
    if seal.get("algorithm") != SEAL_ALGORITHM:
        errors.append("Algoritmo de evidence_seal inválido")
    try:
        public = load_public_key(public_key_path)
    except Exception as exc:
        return errors + [f"No se pudo cargar clave pública de evidencia: {exc}"]
    fingerprint = public_fingerprint(public)
    if str(seal.get("public_key_sha256") or "") != fingerprint:
        errors.append("Fingerprint de clave pública de evidencia no coincide")
    try:
        signature = base64.b64decode(str(seal.get("signature_b64") or ""), validate=True)
    except Exception:
        errors.append("Firma de evidencia no es Base64 válido")
        return errors
    try:
        public.verify(signature, _canonical_payload(report))
    except InvalidSignature:
        errors.append("Firma Ed25519 de evidencia inválida")
    except Exception as exc:
        errors.append(f"No se pudo verificar firma de evidencia: {exc}")
    return errors
