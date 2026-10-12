"""Unit checks for the bounded Phase 2 MP4 validator.

The test suite never invokes a real decoder or reads media metadata from the
host.  A fake ``ffprobe`` runner proves the exact command contract and makes
the checks portable to Windows, Linux and CI.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from typing import Any


ROOT = Path(os.environ.get("GIDEON_TEST_ROOT") or Path(__file__).resolve().parents[2]).resolve()
LINUX_APP = Path(os.environ.get("GIDEON_TEST_APP") or (ROOT / "payload/linux/app")).resolve()
MODULE_PATH = LINUX_APP / "gideon_web_admin" / "media_validation.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("gideon_test_media_validation", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"No se pudo cargar {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


media = _load_module()
MediaValidationError = media.MediaValidationError
validate_media_file = media.validate_media_file


def _probe_payload(
    *, width: int = 1920, height: int = 1080, video_codec: str = "h264",
    pixel_format: str = "yuv420p", audio_codec: str = "aac", audio_profile: str = "LC",
    duration: str = "12.500000", format_name: str = "mov,mp4,m4a,3gp,3g2,mj2",
    include_audio: bool = True,
) -> dict[str, Any]:
    streams = [
        {"codec_type": "video", "codec_name": video_codec, "pix_fmt": pixel_format, "width": width, "height": height},
    ]
    if include_audio:
        streams.append({"codec_type": "audio", "codec_name": audio_codec, "profile": audio_profile})
    return {
        "format": {"format_name": format_name, "duration": duration},
        "streams": streams,
    }


class ProbeRunner:
    def __init__(self, payload: Any, *, returncode: int = 0, error: BaseException | None = None) -> None:
        self.payload = payload
        self.returncode = returncode
        self.error = error
        self.calls: list[tuple[list[str], dict[str, Any]]] = []

    def __call__(self, command: list[str], **kwargs: Any) -> Any:
        self.calls.append((list(command), dict(kwargs)))
        if self.error is not None:
            raise self.error
        stdout = self.payload if isinstance(self.payload, str) else json.dumps(self.payload)
        return SimpleNamespace(returncode=self.returncode, stdout=stdout, stderr="private stderr must not leak")


class MediaValidationTests(unittest.TestCase):
    def _candidate(self, root: Path, name: str = "campana.mp4") -> Path:
        path = root / name
        path.write_bytes(b"not decoded because ffprobe is mocked")
        return path

    def assert_error(self, code: str, callback) -> MediaValidationError:
        with self.assertRaises(MediaValidationError) as raised:
            callback()
        error = raised.exception
        self.assertEqual(code, error.code)
        self.assertNotIn("private stderr", str(error))
        return error

    def test_accepts_landscape_h264_aac_lc_yuv420p_mp4(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            candidate = self._candidate(Path(td))
            runner = ProbeRunner(_probe_payload())
            result = validate_media_file(candidate, runner=runner)
            self.assertEqual("MP4", result.container)
            self.assertEqual("1920x1080", result.resolution)
            self.assertEqual(12.5, result.duration_seconds)
            self.assertEqual("h264", result.video_codec)
            self.assertEqual("aac", result.audio_codec)
            self.assertEqual("yuv420p", result.pixel_format)
            command, kwargs = runner.calls[0]
            self.assertEqual("ffprobe", command[0])
            self.assertEqual(str(candidate.resolve()), command[-1])
            self.assertFalse(kwargs["shell"])
            self.assertTrue(kwargs["capture_output"])
            self.assertTrue(kwargs["text"])
            self.assertIs(kwargs["stdin"], media.subprocess.DEVNULL)
            self.assertFalse(kwargs["check"])

    def test_accepts_portrait_1080x1920(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            candidate = self._candidate(Path(td))
            result = validate_media_file(candidate, runner=ProbeRunner(_probe_payload(width=1080, height=1920)))
            self.assertEqual("1080x1920", result.resolution)

    def test_accepts_silent_h264_mp4_and_does_not_invent_audio(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            candidate = self._candidate(Path(td), "cartel-silencioso.mp4")
            result = validate_media_file(
                candidate, runner=ProbeRunner(_probe_payload(include_audio=False)),
            )
            self.assertEqual("h264", result.video_codec)
            self.assertEqual("", result.audio_codec)
            self.assertEqual("", result.audio_profile)
            self.assertEqual("yuv420p", result.pixel_format)

    def test_rejects_extension_before_spawning_ffprobe(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            candidate = self._candidate(Path(td), "campana.webm")
            runner = ProbeRunner(_probe_payload())
            self.assert_error("MEDIA_EXTENSION_UNSUPPORTED", lambda: validate_media_file(candidate, runner=runner))
            self.assertEqual([], runner.calls)

    def test_rejects_container_video_audio_and_pixel_incompatibilities(self) -> None:
        cases = (
            ("MEDIA_CONTAINER_UNSUPPORTED", {"format_name": "matroska,webm"}),
            ("MEDIA_VIDEO_CODEC_UNSUPPORTED", {"video_codec": "hevc"}),
            ("MEDIA_PIXEL_FORMAT_UNSUPPORTED", {"pixel_format": "yuv420p10le"}),
            ("MEDIA_AUDIO_CODEC_UNSUPPORTED", {"audio_codec": "mp3"}),
            ("MEDIA_AUDIO_PROFILE_UNSUPPORTED", {"audio_profile": "HE-AAC"}),
        )
        with tempfile.TemporaryDirectory() as td:
            candidate = self._candidate(Path(td))
            for code, overrides in cases:
                with self.subTest(code=code):
                    self.assert_error(code, lambda: validate_media_file(candidate, runner=ProbeRunner(_probe_payload(**overrides))))

    def test_rejects_resolution_above_orientation_independent_1080p_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            candidate = self._candidate(Path(td))
            for width, height in ((3840, 2160), (1920, 1200), (2160, 1080)):
                with self.subTest(width=width, height=height):
                    self.assert_error(
                        "MEDIA_RESOLUTION_TOO_LARGE",
                        lambda: validate_media_file(candidate, runner=ProbeRunner(_probe_payload(width=width, height=height))),
                    )

    def test_rejects_zero_or_invalid_duration(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            candidate = self._candidate(Path(td))
            for duration in ("0", "-1", "N/A", "nan"):
                with self.subTest(duration=duration):
                    self.assert_error(
                        "MEDIA_DURATION_INVALID",
                        lambda: validate_media_file(candidate, runner=ProbeRunner(_probe_payload(duration=duration))),
                    )

    def test_timeout_is_bounded_and_human_readable(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            candidate = self._candidate(Path(td))
            runner = ProbeRunner(_probe_payload(), error=TimeoutError("sensitive timeout"))
            self.assert_error("MEDIA_VALIDATION_TIMEOUT", lambda: validate_media_file(candidate, runner=runner, timeout_seconds=9999))
            command, kwargs = runner.calls[0]
            self.assertEqual("ffprobe", command[0])
            self.assertEqual(120.0, kwargs["timeout"])

    def test_rejects_missing_validator_nonzero_and_unbounded_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            candidate = self._candidate(Path(td))
            self.assert_error(
                "MEDIA_VALIDATOR_UNAVAILABLE",
                lambda: validate_media_file(candidate, runner=ProbeRunner(_probe_payload(), error=FileNotFoundError("ffprobe private path"))),
            )
            self.assert_error(
                "MEDIA_PROBE_FAILED",
                lambda: validate_media_file(candidate, runner=ProbeRunner(_probe_payload(), returncode=2)),
            )
            self.assert_error(
                "MEDIA_METADATA_TOO_LARGE",
                lambda: validate_media_file(candidate, runner=ProbeRunner("{" + "x" * (media.MAX_FFPROBE_JSON_BYTES + 1))),
            )

    def test_rejects_malformed_or_overly_complex_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            candidate = self._candidate(Path(td))
            self.assert_error(
                "MEDIA_METADATA_INVALID",
                lambda: validate_media_file(candidate, runner=ProbeRunner("not-json")),
            )
            many_streams = {"format": {"format_name": "mp4", "duration": "1"}, "streams": [{}] * (media.MAX_FFPROBE_STREAMS + 1)}
            self.assert_error(
                "MEDIA_STREAMS_INVALID",
                lambda: validate_media_file(candidate, runner=ProbeRunner(many_streams)),
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
