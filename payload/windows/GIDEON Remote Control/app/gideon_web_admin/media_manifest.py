"""Small, signed control-plane manifests for the isolated GIDEON Player.

This module never starts VLC and never transports media. Phase 2 remains the
only media transport: a manifest merely references a SHA-256 addressed file
already placed in the Agent's managed cache. The exact JSON bytes match the
Agent verifier, including its final newline.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Any, Iterable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


PLAYER_MANIFEST_SCHEMA = "gideon-media-player-manifest/v1"
PHYSICAL_CONNECTOR = "PHYSICAL_CONNECTOR"
LOCAL_WAYLAND_SESSION = "LOCAL_WAYLAND_SESSION"
PLAYER_TARGET_KINDS = {PHYSICAL_CONNECTOR, LOCAL_WAYLAND_SESSION}
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$")


class MediaManifestError(ValueError):
    """A Player manifest could not be made safe to publish."""


def canonical_json_bytes(value: dict[str, Any]) -> bytes:
    """Return the byte sequence authenticated by ``gideon_agent_player``."""
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def media_cache_filename(sha256: str) -> str:
    """Match Phase 2's managed cache convention without accepting a path."""
    digest = str(sha256 or "").strip().lower()
    if not _SHA256_RE.fullmatch(digest):
        raise MediaManifestError("SHA-256 de video inválido para manifiesto.")
    return digest + ".mp4"


def _text(value: Any, *, maximum: int, identifier: bool = False, required: bool = True) -> str:
    text = str(value or "").strip()
    if len(text) > maximum or "\x00" in text or any(ord(ch) < 32 for ch in text):
        raise MediaManifestError("El manifiesto contiene un campo de texto no válido.")
    if required and not text:
        raise MediaManifestError("El manifiesto contiene un campo obligatorio vacío.")
    if identifier and text and not _ID_RE.fullmatch(text):
        raise MediaManifestError("El manifiesto contiene un identificador no válido.")
    return text


def _number(value: Any, *, name: str, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise MediaManifestError(f"{name} inválido en manifiesto.") from exc
    if number < minimum or number > maximum:
        raise MediaManifestError(f"{name} fuera de rango en manifiesto.")
    return number


def _flag(value: Any, *, default: bool) -> bool:
    """Parse form/JSON booleans without treating the string ``false`` as true."""
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().casefold() in {"1", "true", "yes", "on", "si", "sí"}


def build_payload(agent_id: str, assignments: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Build the strict v1 Player payload for one Agent.

    ``CampaignStore`` must provide at most one already-resolved assignment per
    configured screen/output target. We enforce that invariant again here before a
    signature is issued, so a faulty scheduling query cannot create a manifest
    the Agent will reject or make one output play two campaigns.
    """
    clean_agent = _text(agent_id, maximum=160, identifier=True)
    screens: list[dict[str, Any]] = []
    seen_screens: set[str] = set()
    seen_outputs: set[tuple[str, str]] = set()
    for raw in assignments:
        if not isinstance(raw, dict):
            raise MediaManifestError("Asignación de Player inválida.")
        screen_id = _text(raw.get("screen_id"), maximum=160, identifier=True)
        output_key = _text(raw.get("output_key"), maximum=160, identifier=True)
        policy = raw.get("policy") if isinstance(raw.get("policy"), dict) else {}
        target_kind = _text(
            raw.get("target_kind")
            or raw.get("TargetKind")
            or policy.get("target_kind")
            or policy.get("TargetKind")
            or PHYSICAL_CONNECTOR,
            maximum=64,
        ).upper()
        if target_kind not in PLAYER_TARGET_KINDS:
            raise MediaManifestError("El destino de reproducción del manifiesto no es válido.")
        output_identity = _text(policy.get("output_identity", policy.get("OutputIdentity", "")), maximum=160, identifier=True, required=False)
        # A stable connector/device identity is authoritative when present. A
        # renamed connector must not let two campaigns reach the same physical
        # panel. Legacy assignments without it retain OutputKey protection.
        output_binding = (target_kind, (output_identity or output_key).casefold())
        if screen_id in seen_screens or output_binding in seen_outputs:
            raise MediaManifestError("Un destino de reproducción sólo puede tener una campaña activa.")
        seen_screens.add(screen_id)
        seen_outputs.add(output_binding)
        digest = _text(raw.get("sha256"), maximum=64).lower()
        if not _SHA256_RE.fullmatch(digest):
            raise MediaManifestError("El video de Player no tiene SHA-256 válido.")
        orientation = _text(raw.get("orientation") or "landscape", maximum=24).lower()
        if orientation not in {"landscape", "portrait", "inverted", "unknown"}:
            orientation = "unknown"
        resolution = _text(raw.get("resolution"), maximum=32, required=False).lower()
        if resolution and not re.fullmatch(r"\d{2,5}x\d{2,5}", resolution):
            raise MediaManifestError("La resolución de Player no es válida.")
        screen_mode = _text(policy.get("screen_mode", policy.get("ScreenMode", "DEDICATED")), maximum=64).upper()
        if screen_mode not in {"DEDICATED", "SHARED_PAUSE_ON_HUMAN_ACTIVITY"}:
            raise MediaManifestError("El modo físico de Player no es válido.")
        expected_session_policy = (
            "LOCAL_WAYLAND_SESSION" if target_kind == LOCAL_WAYLAND_SESSION
            else "PERSISTENT_PHYSICAL_OUTPUT"
        )
        session_independence = _text(
            policy.get("session_independence", policy.get("SessionIndependence", expected_session_policy)),
            maximum=80,
        ).upper()
        if session_independence != expected_session_policy:
            raise MediaManifestError("La política de sesión Player no es válida.")
        physical_output = _flag(
            policy.get("physical_output", policy.get("PhysicalOutput")),
            default=target_kind == PHYSICAL_CONNECTOR,
        )
        if physical_output != (target_kind == PHYSICAL_CONNECTOR):
            raise MediaManifestError("El tipo de destino Player contradice su política de salida.")
        screens.append({
            "ScreenId": screen_id,
            "OutputKey": output_key,
            "TargetKind": target_kind,
            "OutputLabel": _text(raw.get("output_label") or output_key, maximum=100),
            "Orientation": orientation,
            "Resolution": resolution,
            "CampaignId": _text(raw.get("campaign_id"), maximum=160, identifier=True),
            "RevisionNo": _number(raw.get("revision_no"), name="RevisionNo", minimum=1, maximum=2_147_483_647),
            "Playlist": [{
                "AssetId": _text(raw.get("asset_id") or digest, maximum=160, identifier=True),
                "Sha256": digest,
                "FileName": media_cache_filename(digest),
                "SizeBytes": _number(raw.get("size_bytes"), name="SizeBytes", minimum=1, maximum=16 * 1024 * 1024 * 1024),
                "DurationMs": _number(raw.get("duration_ms"), name="DurationMs", minimum=0, maximum=24 * 60 * 60 * 1000),
            }],
            "Policy": {
                "Fullscreen": _flag(policy.get("fullscreen", policy.get("Fullscreen")), default=True),
                "Kiosk": _flag(policy.get("kiosk", policy.get("Kiosk")), default=True),
                "Volume": _number(policy.get("volume", 100), name="Volume", minimum=0, maximum=100),
                # Additive v1 fields: older Agents safely ignore them, while
                # newer runtimes can bind VLC to the real physical output
                # independently of any RDP/VNC/user session.
                "TargetKind": target_kind,
                "PhysicalOutput": physical_output,
                "SessionIndependence": session_independence,
                "ScreenMode": screen_mode,
                "PauseOnHumanActivity": _flag(
                    policy.get("pause_on_human_activity", policy.get("PauseOnHumanActivity")),
                    default=screen_mode == "SHARED_PAUSE_ON_HUMAN_ACTIVITY",
                ),
                "EmergencyTakeover": _flag(
                    policy.get("emergency_takeover", policy.get("EmergencyTakeover")), default=False,
                ),
                "OutputIdentity": output_identity,
            },
        })
    screens.sort(key=lambda value: (
        str(value["TargetKind"]), str(value["OutputKey"]).casefold(), str(value["ScreenId"]),
    ))
    return {"AgentId": clean_agent, "Screens": screens}


def sign_payload(payload: dict[str, Any], security_assets: Any, *, manifest_version: int) -> dict[str, Any]:
    """Sign an Agent-verifiable v1 envelope using the existing Ed25519 key."""
    if not isinstance(payload, dict) or not _ID_RE.fullmatch(str(payload.get("AgentId") or "")):
        raise MediaManifestError("Payload Player inválido.")
    version = _number(manifest_version, name="ManifestVersion", minimum=1, maximum=2_147_483_647)
    try:
        status = security_assets.signing_status()
        private_bytes = security_assets.signing_private_key_bytes()
        key_id = _text(security_assets.signing_key_id(), maximum=160, identifier=True)
    except Exception as exc:
        raise MediaManifestError("La firma Ed25519 de WebAdmin no está disponible.") from exc
    if not bool(status.get("usable")) or not private_bytes:
        raise MediaManifestError("Configure la firma Ed25519 antes de publicar una campaña Player.")
    try:
        private = serialization.load_pem_private_key(bytes(private_bytes), password=None)
    except Exception as exc:
        raise MediaManifestError("No se pudo abrir la clave Ed25519 configurada.") from exc
    if not isinstance(private, Ed25519PrivateKey):
        raise MediaManifestError("La clave configurada no es Ed25519.")
    document = canonical_json_bytes(payload)
    return {
        "Schema": PLAYER_MANIFEST_SCHEMA,
        "ManifestVersion": version,
        "Payload": payload,
        "ManifestSha256": hashlib.sha256(document).hexdigest(),
        "Signature": base64.b64encode(private.sign(document)).decode("ascii"),
        "KeyId": key_id,
    }


__all__ = [
    "LOCAL_WAYLAND_SESSION", "MediaManifestError", "PHYSICAL_CONNECTOR",
    "PLAYER_MANIFEST_SCHEMA", "PLAYER_TARGET_KINDS", "build_payload",
    "canonical_json_bytes", "media_cache_filename", "sign_payload",
]
