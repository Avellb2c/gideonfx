"""Bounded media conformance checks for GIDEON Screens campaigns.

This module does one small, deliberately isolated job: it asks ``ffprobe`` for
the metadata of a candidate media file and accepts only the first GIDEON media
profile: MP4, H.264/AVC, optional AAC-LC audio, yuv420p and a maximum 1080p
frame.  A silent video is valid; when an audio track exists it must be AAC-LC.
It does
not upload, execute, play or retain the input file.

The caller must still place the file in GIDEON-owned quarantine and run the
normal malware/integrity controls.  Keeping format inspection independent of
those concerns makes it safe to reuse from campaign uploads and Transfers.
"""
from __future__ import annotations

import json
import math
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping


DEFAULT_FFPROBE_TIMEOUT_SECONDS = 20.0
MAX_FFPROBE_TIMEOUT_SECONDS = 120.0
MAX_FFPROBE_JSON_BYTES = 256 * 1024
MAX_FFPROBE_STREAMS = 32


class MediaValidationError(ValueError):
    """A media file is incompatible or its metadata could not be checked.

    ``message`` is deliberately suitable for Marketing-facing UI.  Technical
    process output, command lines and absolute paths never become part of it.
    ``code`` is stable enough for audit and tests without exposing internals.
    """

    def __init__(self, code: str, message: str) -> None:
        self.code = str(code or "MEDIA_VALIDATION_FAILED")
        super().__init__(str(message or "No se pudo validar el video."))


@dataclass(frozen=True, slots=True)
class MediaValidationResult:
    """Sanitized conformance metadata that can be persisted with a MediaAsset."""

    filename: str
    size_bytes: int
    duration_seconds: float
    width: int
    height: int
    video_codec: str
    audio_codec: str
    audio_profile: str
    pixel_format: str
    container: str = "MP4"

    @property
    def resolution(self) -> str:
        return f"{self.width}x{self.height}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "container": self.container,
            "duration_seconds": self.duration_seconds,
            "width": self.width,
            "height": self.height,
            "resolution": self.resolution,
            "video_codec": self.video_codec,
            "audio_codec": self.audio_codec,
            "audio_profile": self.audio_profile,
            "pixel_format": self.pixel_format,
            "size_bytes": self.size_bytes,
        }


Runner = Callable[..., Any]


def _fail(code: str, message: str) -> None:
    raise MediaValidationError(code, message)


def _bounded_timeout(value: float | int | str) -> float:
    try:
        timeout = float(value)
    except (TypeError, ValueError):
        _fail("MEDIA_VALIDATION_TIMEOUT_INVALID", "La configuración de validación de video no es válida.")
    if not math.isfinite(timeout) or timeout <= 0:
        _fail("MEDIA_VALIDATION_TIMEOUT_INVALID", "La configuración de validación de video no es válida.")
    return max(1.0, min(timeout, MAX_FFPROBE_TIMEOUT_SECONDS))


def _text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value or "")


def _bounded_json(value: Any) -> Mapping[str, Any]:
    text = _text(value)
    if len(text.encode("utf-8", errors="replace")) > MAX_FFPROBE_JSON_BYTES:
        _fail("MEDIA_METADATA_TOO_LARGE", "El archivo contiene demasiada información multimedia para validarlo de forma segura.")
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError, json.JSONDecodeError):
        _fail("MEDIA_METADATA_INVALID", "No se pudo leer la información de formato del video.")
    if not isinstance(parsed, Mapping):
        _fail("MEDIA_METADATA_INVALID", "No se pudo leer la información de formato del video.")
    streams = parsed.get("streams")
    if not isinstance(streams, list) or len(streams) > MAX_FFPROBE_STREAMS:
        _fail("MEDIA_STREAMS_INVALID", "El archivo tiene una estructura multimedia no compatible.")
    return parsed


def _positive_int(value: Any, *, code: str, message: str) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        _fail(code, message)
    if number <= 0:
        _fail(code, message)
    return number


def _positive_duration(value: Any) -> float:
    try:
        duration = float(str(value).strip())
    except (TypeError, ValueError):
        _fail("MEDIA_DURATION_INVALID", "El video debe indicar una duración válida mayor que cero.")
    if not math.isfinite(duration) or duration <= 0:
        _fail("MEDIA_DURATION_INVALID", "El video debe indicar una duración válida mayor que cero.")
    return duration


def _profile_key(value: Any) -> str:
    return "".join(ch for ch in str(value or "").casefold() if ch.isalnum())


def _first_stream(streams: list[Any], kind: str) -> Mapping[str, Any] | None:
    for item in streams:
        if isinstance(item, Mapping) and str(item.get("codec_type") or "").casefold() == kind:
            return item
    return None


def _is_mp4(format_name: Any) -> bool:
    return "mp4" in {part.strip().casefold() for part in str(format_name or "").split(",")}


def validate_media_file(
    path: str | Path,
    *,
    ffprobe_path: str | Path = "ffprobe",
    timeout_seconds: float | int = DEFAULT_FFPROBE_TIMEOUT_SECONDS,
    runner: Runner | None = None,
) -> MediaValidationResult:
    """Validate one locally quarantined MP4 without invoking a shell.

    ``runner`` exists solely to make the parser deterministic in unit tests.
    It receives the same keyword arguments as :func:`subprocess.run`; callers
    must not substitute it with an untrusted command interpreter.
    """
    candidate = Path(path).expanduser().resolve()
    filename = candidate.name
    if candidate.suffix.casefold() != ".mp4":
        _fail("MEDIA_EXTENSION_UNSUPPORTED", "Solo se aceptan videos MP4 para esta campaña.")
    if not candidate.is_file() or candidate.stat().st_size <= 0:
        _fail("MEDIA_FILE_UNAVAILABLE", "El video cargado no está disponible o está vacío.")

    executable = str(ffprobe_path or "").strip()
    if not executable or "\x00" in executable:
        _fail("MEDIA_VALIDATOR_UNAVAILABLE", "El verificador de formato multimedia no está disponible.")
    timeout = _bounded_timeout(timeout_seconds)
    command = [
        executable,
        "-v", "error",
        "-show_entries",
        "format=format_name,duration:stream=codec_type,codec_name,profile,pix_fmt,width,height",
        "-of", "json",
        str(candidate),
    ]
    invoke = runner or subprocess.run
    try:
        completed = invoke(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            # ffprobe never needs interactive input.  Closing stdin avoids a
            # stalled worker (or inherited service pipe) influencing a media
            # validation job.
            stdin=subprocess.DEVNULL,
            shell=False,
            check=False,
        )
    except FileNotFoundError:
        _fail("MEDIA_VALIDATOR_UNAVAILABLE", "El verificador de formato multimedia no está disponible.")
    except (subprocess.TimeoutExpired, TimeoutError):
        _fail("MEDIA_VALIDATION_TIMEOUT", "El análisis de formato tardó demasiado. Intente nuevamente con un video más pequeño.")
    except OSError:
        _fail("MEDIA_VALIDATOR_UNAVAILABLE", "El verificador de formato multimedia no está disponible.")

    if int(getattr(completed, "returncode", 1) or 0) != 0:
        _fail("MEDIA_PROBE_FAILED", "No se pudo leer el formato del video MP4.")
    payload = _bounded_json(getattr(completed, "stdout", ""))
    format_info = payload.get("format") if isinstance(payload.get("format"), Mapping) else {}
    if not _is_mp4(format_info.get("format_name")):
        _fail("MEDIA_CONTAINER_UNSUPPORTED", "El archivo debe ser un contenedor MP4 válido.")

    streams = payload.get("streams")
    assert isinstance(streams, list)  # checked by _bounded_json
    video = _first_stream(streams, "video")
    if video is None:
        _fail("MEDIA_VIDEO_REQUIRED", "El MP4 debe incluir una pista de video H.264/AVC.")
    audio = _first_stream(streams, "audio")

    video_codec = str(video.get("codec_name") or "").casefold()
    if video_codec not in {"h264", "avc"}:
        _fail("MEDIA_VIDEO_CODEC_UNSUPPORTED", "El video debe usar H.264/AVC.")
    pixel_format = str(video.get("pix_fmt") or "").casefold()
    if pixel_format != "yuv420p":
        _fail("MEDIA_PIXEL_FORMAT_UNSUPPORTED", "El video debe usar el formato de color yuv420p.")

    width = _positive_int(video.get("width"), code="MEDIA_RESOLUTION_INVALID", message="El video debe indicar una resolución válida.")
    height = _positive_int(video.get("height"), code="MEDIA_RESOLUTION_INVALID", message="El video debe indicar una resolución válida.")
    # The rule is orientation-independent: 1920x1080 and 1080x1920 pass, but
    # 1920x1200 and 2160x1080 do not.  This is the familiar 1080p envelope.
    if max(width, height) > 1920 or min(width, height) > 1080:
        _fail("MEDIA_RESOLUTION_TOO_LARGE", "El video no puede superar 1080p (máximo 1920x1080 o 1080x1920).")

    # Digital-signage creatives are frequently silent.  Absence of audio is
    # therefore valid and is surfaced as a Marketing warning by the catalog.
    # If a track is present, keep the portable Player contract strict: VLC on
    # Windows/Linux/Raspberry receives AAC-LC only.
    audio_codec = ""
    audio_profile = ""
    if audio is not None:
        audio_codec = str(audio.get("codec_name") or "").casefold()
        if audio_codec != "aac":
            _fail("MEDIA_AUDIO_CODEC_UNSUPPORTED", "Si el video incluye audio, debe usar AAC-LC.")
        audio_profile = str(audio.get("profile") or "").strip()
        if _profile_key(audio_profile) not in {"lc", "aaclc", "mpeg4aaclc"}:
            _fail("MEDIA_AUDIO_PROFILE_UNSUPPORTED", "Si el video incluye audio, debe usar el perfil AAC-LC.")

    duration = _positive_duration(format_info.get("duration"))
    return MediaValidationResult(
        filename=filename,
        size_bytes=candidate.stat().st_size,
        duration_seconds=duration,
        width=width,
        height=height,
        video_codec="h264",
        audio_codec=audio_codec,
        audio_profile=(audio_profile or "LC") if audio is not None else "",
        pixel_format="yuv420p",
    )


__all__ = [
    "DEFAULT_FFPROBE_TIMEOUT_SECONDS",
    "MAX_FFPROBE_JSON_BYTES",
    "MediaValidationError",
    "MediaValidationResult",
    "validate_media_file",
]
