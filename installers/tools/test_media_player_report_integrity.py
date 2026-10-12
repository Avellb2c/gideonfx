"""Gateway regression checks for Phase 3 Player telemetry binding.

The desktop Player is deliberately a separate process.  These tests make sure
that its untrusted status reports can describe only the exact screen/output/
campaign/revision/video combination already contained in an immutable,
WebAdmin-signed manifest envelope.  They do not start VLC, an Agent, or a
network listener.
"""
from __future__ import annotations

import base64
import copy
import hashlib
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[2]
LINUX_APP = ROOT / "payload/linux/app"
WINDOWS_APP = ROOT / "payload/windows/GIDEON Remote Control/app"
if str(LINUX_APP) not in sys.path:
    sys.path.insert(0, str(LINUX_APP))

from gideon_agent_gateway import (  # noqa: E402
    GatewayDB,
    PLAYER_MANIFEST_SCHEMA,
    PLAYER_STATUS_SCHEMA,
    sha256_bytes,
)


class MediaPlayerReportIntegrityTests(unittest.TestCase):
    agent_id = "agt-media-report-test"

    def _manifest(self) -> tuple[dict[str, object], str]:
        video_sha = hashlib.sha256(b"phase-three-video").hexdigest()
        payload: dict[str, object] = {
            "AgentId": self.agent_id,
            "Screens": [{
                "ScreenId": "scr-caja-01",
                "OutputKey": "linux-hdmi-1",
                "TargetKind": "PHYSICAL_CONNECTOR",
                "OutputLabel": "Pantalla Caja",
                "Orientation": "landscape",
                "Resolution": "1920x1080",
                "CampaignId": "cmp-promo-septiembre",
                "RevisionNo": 4,
                "Policy": {
                    "Fullscreen": True, "Kiosk": True, "Volume": 55,
                    "TargetKind": "PHYSICAL_CONNECTOR", "PhysicalOutput": True,
                    "SessionIndependence": "PERSISTENT_PHYSICAL_OUTPUT",
                },
                "Playlist": [{
                    "AssetId": "asset-promo-01",
                    "Sha256": video_sha,
                    "FileName": video_sha + ".mp4",
                    "SizeBytes": 4096,
                    "DurationMs": 15000,
                }],
            }],
        }
        document = GatewayDB._canonical_media_manifest(payload)
        signature = Ed25519PrivateKey.generate().sign(document)
        return {
            "Schema": PLAYER_MANIFEST_SCHEMA,
            "ManifestVersion": 1,
            "Payload": payload,
            "ManifestSha256": sha256_bytes(document),
            "Signature": base64.b64encode(signature).decode("ascii"),
            "KeyId": "gideon-player-test-key",
        }, video_sha

    def _report(self, envelope: dict[str, object], video_sha: str) -> dict[str, object]:
        return {
            "Player": {
                "Schema": PLAYER_STATUS_SCHEMA,
                "ManifestVersion": 1,
                "ManifestSha256": str(envelope["ManifestSha256"]),
                "VLC": {"Installed": True, "Version": "3.0.21", "License": "GPL-2.0-or-later"},
                "FreeBytes": 12_000_000,
                "Graphics": {"State": "READY", "OutputCount": 1},
                "Screens": [{
                    "ScreenId": "scr-caja-01",
                    "OutputKey": "linux-hdmi-1",
                    "TargetKind": "PHYSICAL_CONNECTOR",
                    "CampaignId": "cmp-promo-septiembre",
                    "RevisionNo": 4,
                    "CurrentVideo": video_sha + ".mp4",
                    "PlaylistItems": 1,
                    "State": "PLAYING",
                    "LastSuccessAt": "2026-09-20T00:00:00+00:00",
                    "Error": "",
                }],
            }
        }

    def _db_with_manifest(self, root: Path) -> tuple[GatewayDB, dict[str, object], str]:
        db = GatewayDB(root)
        db.enroll_agent("18601", "SISTEMAS", "screen-host", "2.4.23", agent_id=self.agent_id)
        envelope, video_sha = self._manifest()
        db.put_agent_media_manifest(self.agent_id, envelope)
        return db, envelope, video_sha

    def test_report_is_bound_to_immutable_signed_manifest_assignment(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-player-report-") as td:
            db, envelope, video_sha = self._db_with_manifest(Path(td))
            saved = db.report_agent_media_player(self.agent_id, self._report(envelope, video_sha))
            self.assertEqual(1, len(saved))
            rows = db.list_agent_media_player_reports(agent_id=self.agent_id)
            self.assertEqual(1, len(rows))
            self.assertEqual(video_sha, rows[0]["video_sha256"])
            self.assertEqual("linux-hdmi-1", rows[0]["graphics"]["output_key"])
            self.assertEqual("PHYSICAL_CONNECTOR", rows[0]["graphics"]["target_kind"])

            # The reports are linked to an append-only manifest.  Changing the
            # assignment after it was signed is prevented by the database too.
            with db.connect() as con:
                with self.assertRaises(sqlite3.IntegrityError):
                    con.execute(
                        "UPDATE agent_media_manifests SET manifest_json='{}' WHERE agent_id=?",
                        (self.agent_id,),
                    )

    def test_same_resolved_payload_can_be_reissued_with_a_new_monotonic_version(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-player-reissue-") as td:
            db = GatewayDB(Path(td))
            db.enroll_agent("18601", "SISTEMAS", "screen-host", "2.4.38", agent_id=self.agent_id)
            first, _ = self._manifest()
            saved_first = db.put_agent_media_manifest(self.agent_id, first)
            self.assertTrue(saved_first["created"])

            repeated = copy.deepcopy(first)
            repeated["ManifestVersion"] = 2
            saved_second = db.put_agent_media_manifest(self.agent_id, repeated)
            self.assertTrue(saved_second["created"])
            self.assertEqual(2, saved_second["manifest_version"])
            self.assertEqual(saved_first["manifest_sha256"], saved_second["manifest_sha256"])

            retried = db.put_agent_media_manifest(self.agent_id, repeated)
            self.assertFalse(retried["created"])
            self.assertEqual(2, retried["manifest_version"])
            with db.connect() as con:
                count = con.execute(
                    "SELECT COUNT(*) FROM agent_media_manifests WHERE agent_id=?",
                    (self.agent_id,),
                ).fetchone()[0]
            self.assertEqual(2, count)
            status = db.schema_status()
            self.assertEqual(10, status["SchemaVersion"])
            self.assertTrue(status["AgentMediaManifestReissue"])

    def test_legacy_digest_unique_schema_is_migrated_without_losing_history(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-player-schema-") as td:
            root = Path(td)
            database = root / "gateway.sqlite3"
            legacy = sqlite3.connect(database)
            try:
                con = legacy
                con.executescript(
                    """
                    CREATE TABLE agent_media_manifests (
                        agent_id TEXT NOT NULL,
                        manifest_version TEXT NOT NULL,
                        manifest_sha256 TEXT NOT NULL,
                        key_id TEXT NOT NULL,
                        signature TEXT NOT NULL,
                        manifest_json TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        PRIMARY KEY(agent_id, manifest_version),
                        UNIQUE(agent_id, manifest_sha256)
                    );
                    INSERT INTO agent_media_manifests VALUES(
                        'agt-legacy','1','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                        'legacy-key','legacy-signature','{}','2026-09-30T00:00:00+00:00'
                    );
                    """
                )
                con.commit()
            finally:
                legacy.close()
            db = GatewayDB(root)
            with db.connect() as con:
                migrated = con.execute(
                    "SELECT manifest_version,manifest_sha256 FROM agent_media_manifests WHERE agent_id='agt-legacy'"
                ).fetchone()
                digest_unique = db._table_has_unique_key(
                    con, "agent_media_manifests", ["agent_id", "manifest_sha256"]
                )
            self.assertIsNotNone(migrated)
            self.assertEqual("1", migrated["manifest_version"])
            self.assertFalse(digest_unique)
            self.assertTrue(db.schema_status()["AgentMediaManifestReissue"])

    def test_mismatched_assignment_fields_and_digest_are_rejected_without_echo(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-player-report-") as td:
            db, envelope, video_sha = self._db_with_manifest(Path(td))
            baseline = self._report(envelope, video_sha)
            variants = (
                ("screen", lambda report: report["Player"]["Screens"][0].update({"ScreenId": "scr-other-01"})),
                ("campaign", lambda report: report["Player"]["Screens"][0].update({"CampaignId": "cmp-other"})),
                ("revision", lambda report: report["Player"]["Screens"][0].update({"RevisionNo": 5})),
                ("output", lambda report: report["Player"]["Screens"][0].update({"OutputKey": "linux-hdmi-2"})),
                ("target", lambda report: report["Player"]["Screens"][0].update({"TargetKind": "LOCAL_WAYLAND_SESSION"})),
                ("video", lambda report: report["Player"]["Screens"][0].update({"CurrentVideo": "f" * 64 + ".mp4"})),
                ("playlist", lambda report: report["Player"]["Screens"][0].update({"PlaylistItems": 2})),
            )
            for label, mutate in variants:
                with self.subTest(label=label):
                    candidate = copy.deepcopy(baseline)
                    mutate(candidate)
                    with self.assertRaisesRegex(ValueError, r"^Player report assignment mismatch$") as error:
                        db.report_agent_media_player(self.agent_id, candidate)
                    self.assertNotIn("cmp-other", str(error.exception))

            digest_mismatch = copy.deepcopy(baseline)
            digest_mismatch["Player"]["ManifestSha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, r"^Player report manifest mismatch$"):
                db.report_agent_media_player(self.agent_id, digest_mismatch)

            missing_digest = copy.deepcopy(baseline)
            missing_digest["Player"].pop("ManifestSha256")
            with self.assertRaisesRegex(ValueError, r"^Player report manifest mismatch$"):
                db.report_agent_media_player(self.agent_id, missing_digest)

            self.assertEqual([], db.list_agent_media_player_reports(agent_id=self.agent_id))

    def test_duplicate_screens_and_malformed_numbers_fail_closed_without_reflecting_input(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-player-report-") as td:
            db, envelope, video_sha = self._db_with_manifest(Path(td))
            duplicate = self._report(envelope, video_sha)
            duplicate["Player"]["Screens"].append(copy.deepcopy(duplicate["Player"]["Screens"][0]))
            with self.assertRaisesRegex(ValueError, r"^Player report assignment mismatch$"):
                db.report_agent_media_player(self.agent_id, duplicate)

            malformed = self._report(envelope, video_sha)
            marker = "not-a-number-or-secret"
            malformed["Player"]["FreeBytes"] = marker
            with self.assertRaisesRegex(ValueError, r"^Player report number invalid$") as error:
                db.report_agent_media_player(self.agent_id, malformed)
            self.assertNotIn(marker, str(error.exception))
            # The duplicate report's first screen was otherwise valid.  It
            # still must not survive when the later duplicate is rejected.
            self.assertEqual([], db.list_agent_media_player_reports(agent_id=self.agent_id))

    def test_windows_gateway_mirrors_are_exact(self) -> None:
        for relative in ("gideon_agent_gateway.py", "gideon_gateway_schema.py"):
            with self.subTest(relative=relative):
                self.assertEqual(
                    (LINUX_APP / relative).read_bytes(),
                    (WINDOWS_APP / relative).read_bytes(),
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
