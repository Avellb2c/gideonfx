"""End-to-end contract checks for the signed Phase 3 WebAdmin -> Agent manifest.

The test intentionally uses a temporary Ed25519 key and a local cache file. It
does not start VLC, an Agent service, a Gateway listener, or any network path.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[2]
LINUX_APP = ROOT / "payload/linux/app"
WINDOWS_APP = ROOT / "payload/windows/GIDEON Remote Control/app"
if str(LINUX_APP) not in sys.path:
    sys.path.insert(0, str(LINUX_APP))

from gideon_agent_player import PlayerManifestStore  # noqa: E402
from gideon_web_admin.media_manifest import (  # noqa: E402
    MediaManifestError,
    build_payload,
    sign_payload,
)


class _SigningAssets:
    def __init__(self, private: Ed25519PrivateKey) -> None:
        self.private = private

    def signing_status(self):
        return {"usable": True}

    def signing_private_key_bytes(self):
        return self.private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    def signing_key_id(self):
        return "gideon-player-contract-key"


class MediaPlayerManifestContractTests(unittest.TestCase):
    agent_id = "agt-player-contract-01"

    def test_webadmin_signed_payload_is_accepted_by_the_isolated_agent_cache(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-player-contract-") as td:
            root = Path(td)
            media_root = root / "media"; media_root.mkdir()
            content = b"h264-aac-yuv420p-contract"
            digest = hashlib.sha256(content).hexdigest()
            (media_root / f"{digest}.mp4").write_bytes(content)
            private = Ed25519PrivateKey.generate()
            public = root / "gideon-agent-signing-public.pem"
            public.write_bytes(private.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
            payload = build_payload(self.agent_id, [{
                "screen_id": "scr-caja-01", "output_key": "linux-hdmi-1",
                "output_label": "Pantalla Caja", "orientation": "landscape",
                "resolution": "1920x1080", "campaign_id": "cmp-promocion-01",
                "revision_no": 3, "asset_id": "ast-promocion-01", "sha256": digest,
                "size_bytes": len(content), "duration_ms": 12_000,
                "policy": {
                    "fullscreen": True, "kiosk": True, "volume": 55,
                    "physical_output": True, "session_independence": "PERSISTENT_PHYSICAL_OUTPUT",
                    "screen_mode": "SHARED_PAUSE_ON_HUMAN_ACTIVITY", "pause_on_human_activity": True,
                    "emergency_takeover": True, "output_identity": "hdmi-1:edid-contract",
                },
            }])
            policy = payload["Screens"][0]["Policy"]
            self.assertTrue(policy["PhysicalOutput"])
            self.assertEqual("PERSISTENT_PHYSICAL_OUTPUT", policy["SessionIndependence"])
            self.assertEqual("SHARED_PAUSE_ON_HUMAN_ACTIVITY", policy["ScreenMode"])
            self.assertTrue(policy["PauseOnHumanActivity"])
            self.assertTrue(policy["EmergencyTakeover"])
            self.assertEqual("hdmi-1:edid-contract", policy["OutputIdentity"])
            envelope = sign_payload(payload, _SigningAssets(private), manifest_version=7)
            store = PlayerManifestStore(
                agent_root=root / "agent", agent_id=self.agent_id, public_key_path=public,
                media_root=media_root,
            )
            verified = store.apply(envelope)
            self.assertEqual(7, verified.manifest_version)
            self.assertEqual("cmp-promocion-01", verified.assignments[0].campaign_id)
            self.assertTrue(store.paths.public_manifest.is_file())
            self.assertNotIn("private", store.paths.public_manifest.read_text(encoding="utf-8").casefold())

    def test_manifest_builder_rejects_an_ambiguous_physical_output(self) -> None:
        common = {
            "output_key": "HDMI-1", "orientation": "landscape", "resolution": "1920x1080",
            "campaign_id": "cmp-promocion-01", "revision_no": 1, "asset_id": "ast-promocion-01",
            "sha256": "a" * 64, "size_bytes": 1, "duration_ms": 1,
        }
        with self.assertRaises(MediaManifestError):
            build_payload(self.agent_id, [
                dict(common, screen_id="scr-caja-01"),
                dict(common, screen_id="scr-caja-02"),
            ])

    def test_manifest_builder_rejects_two_connectors_bound_to_one_stable_monitor(self) -> None:
        common = {
            "orientation": "landscape", "resolution": "1920x1080",
            "campaign_id": "cmp-promocion-01", "revision_no": 1, "asset_id": "ast-promocion-01",
            "sha256": "a" * 64, "size_bytes": 1, "duration_ms": 1,
            "policy": {"output_identity": "linux-hdmi-1:monitor-contract"},
        }
        with self.assertRaises(MediaManifestError):
            build_payload(self.agent_id, [
                dict(common, screen_id="scr-caja-01", output_key="linux-hdmi-1"),
                dict(common, screen_id="scr-caja-02", output_key="linux-dp-1"),
            ])

    def test_local_wayland_target_is_explicit_signed_and_not_physical(self) -> None:
        assignment = {
            "screen_id": "scr-wayland-01", "output_key": "linux-wayland-noop-1",
            "target_kind": "LOCAL_WAYLAND_SESSION", "output_label": "Pantalla visible",
            "orientation": "landscape", "resolution": "1920x1080",
            "campaign_id": "cmp-wayland-01", "revision_no": 1,
            "asset_id": "ast-wayland-01", "sha256": "b" * 64,
            "size_bytes": 10, "duration_ms": 1_000,
            "policy": {
                "target_kind": "LOCAL_WAYLAND_SESSION", "physical_output": False,
                "session_independence": "LOCAL_WAYLAND_SESSION",
                "output_identity": "linux-wayland-noop-1",
            },
        }
        payload = build_payload(self.agent_id, [assignment])
        screen = payload["Screens"][0]
        self.assertEqual("LOCAL_WAYLAND_SESSION", screen["TargetKind"])
        self.assertEqual("LOCAL_WAYLAND_SESSION", screen["Policy"]["TargetKind"])
        self.assertFalse(screen["Policy"]["PhysicalOutput"])
        self.assertEqual("LOCAL_WAYLAND_SESSION", screen["Policy"]["SessionIndependence"])

        conflicting = dict(assignment)
        conflicting["policy"] = dict(assignment["policy"], physical_output=True)
        with self.assertRaises(MediaManifestError):
            build_payload(self.agent_id, [conflicting])

    def test_webadmin_manifest_module_is_an_exact_windows_mirror(self) -> None:
        relative = "gideon_web_admin/media_manifest.py"
        self.assertTrue((LINUX_APP / relative).is_file())
        self.assertTrue((WINDOWS_APP / relative).is_file())
        self.assertEqual((LINUX_APP / relative).read_bytes(), (WINDOWS_APP / relative).read_bytes())


if __name__ == "__main__":
    unittest.main(verbosity=2)
