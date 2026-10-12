"""Regression checks for Phase 2 MediaAsset and campaign distribution state.

These tests deliberately exercise only the persistent CampaignStore contract.
They never upload a real file, invoke ffprobe, contact the Gateway, or start a
player.  The WebAdmin dispatcher is responsible for turning the durable outbox
records checked here into the existing signed Transfer/Job workflow.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest


ROOT = Path(os.environ.get("GIDEON_TEST_ROOT") or Path(__file__).resolve().parents[2]).resolve()
LINUX_APP = Path(os.environ.get("GIDEON_TEST_APP") or (ROOT / "payload/linux/app")).resolve()
sys.path.insert(0, str(LINUX_APP))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"No se pudo cargar {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


media = _load("gideon_test_media_campaigns_phase2", LINUX_APP / "gideon_web_admin/media_campaigns.py")
CampaignStore = media.CampaignStore
CampaignStoreError = media.CampaignStoreError


class AuditSink:
    """Small SecurityStore-compatible audit recorder for domain tests."""

    def __init__(self) -> None:
        self.rows: list[dict[str, str]] = []

    def audit(
        self, username: str, action: str, result: str, detail: str = "", remote_ip: str = "", *,
        resource: str = "", role: str = "",
    ) -> None:
        self.rows.append({
            "username": username,
            "action": action,
            "result": result,
            "detail": detail,
            "remote_ip": remote_ip,
            "resource": resource,
            "role": role,
        })


def _schedule() -> dict[str, object]:
    return {
        "start_date": "2026-10-01",
        "end_date": "2026-12-31",
        "weekdays": list(range(7)),
        "start_time": "08:00",
        "end_time": "22:00",
        "blackout_dates": ["2026-12-25"],
        "timezone": "America/Lima",
    }


class MediaPhase2StoreTests(unittest.TestCase):
    actor = "marketing.phase2"

    def _store(self, root: Path) -> tuple[CampaignStore, AuditSink]:
        audit = AuditSink()
        return CampaignStore(root, security=audit), audit

    def _screen(self, store: CampaignStore, name: str, agent_id: str, output: str) -> dict[str, object]:
        return store.create_screen(
            site_code="18601",
            commercial_name=name,
            physical_location="Área de marketing",
            agent_id=agent_id,
            output_key=output,
            output_label=output,
            orientation="LANDSCAPE",
            resolution="1920x1080",
            actor=self.actor,
            valid_site_codes={"18601"},
        )

    @staticmethod
    def _assignment(screen_id: str, title: str, asset_id: str = "", *, emergency: bool = False) -> dict[str, object]:
        return {
            "screen_id": screen_id,
            "playlist_name": f"Lista {title}",
            "content_title": title,
            "content_note": f"Contenido de {title}",
            "asset_id": asset_id,
            "priority": 100 if emergency else 50,
            "emergency": emergency,
            "schedule": _schedule(),
        }

    def _ready_asset(self, store: CampaignStore, name: str, marker: int) -> dict[str, object]:
        """Create a store-level ready asset; validation itself is covered elsewhere."""
        asset = store.create_media_asset(
            display_name=name,
            actor=self.actor,
            valid_from="2026-01-01",
            valid_until="2099-12-31",
        )
        asset_id = str(asset["asset_id"])
        store.attach_media_asset_job(asset_id, f"prep-{marker}", actor="worker")
        return store.complete_media_asset(
            asset_id,
            sha256=(f"{marker:02x}" * 32),
            size_bytes=1024 + marker,
            metadata={
                "duration_seconds": 15.25,
                "container": "MP4",
                "video_codec": "h264",
                "video_profile": "High",
                "audio_codec": "aac",
                "audio_profile": "LC",
                "pixel_format": "yuv420p",
                "width": 1920,
                "height": 1080,
            },
            blob_relpath=f"assets/{marker:02x}/campaign-{marker}.mp4",
            actor="worker",
        )

    def test_v2_migration_is_additive_and_preserves_phase1_rows(self):
        """A Phase 1 catalogue upgrades without recreating or losing its plans."""
        with tempfile.TemporaryDirectory(prefix="gideon-media-v2-migration-") as td:
            root = Path(td)
            store, _ = self._store(root)
            screen = self._screen(store, "Pantalla histórica", "agt-v1", "HDMI-1")
            legacy = store.create_campaign_draft(
                title="Campaña de Fase 1",
                assignments=[self._assignment(str(screen["screen_id"]), "Contenido histórico")],
                actor=self.actor,
            )

            # Build a faithful, data-bearing v1 boundary from the current
            # database: retain base tables and erase only v2 additive objects
            # plus its ledger record.  This is confined to a temporary DB.
            with store.connect() as con:
                for trigger in (
                    "media_distribution_events_no_delete",
                    "media_distribution_events_no_update",
                    "media_asset_events_no_delete",
                    "media_asset_events_no_update",
                ):
                    con.execute(f"DROP TRIGGER IF EXISTS {trigger}")
                for table in (
                    "media_distribution_events",
                    "media_distribution_targets",
                    "media_agent_deliveries",
                    "media_agent_assets",
                    "campaign_assignment_policies",
                    "campaign_assignment_assets",
                    "playlist_item_assets",
                    "media_asset_events",
                    "media_assets",
                ):
                    con.execute(f"DROP TABLE IF EXISTS {table}")
                con.execute("DELETE FROM media_schema_versions WHERE version=2")

            reopened, _ = self._store(root)
            self.assertEqual("Campaña de Fase 1", reopened.campaign_detail(str(legacy["campaign_id"]))["title"])
            self.assertEqual("Pantalla histórica", reopened.screen_detail(str(screen["screen_id"]))["commercial_name"])
            with reopened.connect() as con:
                versions = [int(row["version"]) for row in con.execute(
                    "SELECT version FROM media_schema_versions ORDER BY version"
                )]
                v2_tables = {
                    str(row["name"])
                    for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")
                }
            # A v1 catalogue must receive every additive migration supported
            # by the current store.  v5 preserves physical output identity
            # and v6 adds only read-path indexes; neither may be skipped by a
            # recovery that first replays the Phase 2 migration.
            self.assertEqual([1, 2, 3, 4, 5, 6, 7], versions)
            self.assertTrue({
                "media_assets", "playlist_item_assets", "campaign_assignment_assets",
                "media_agent_assets", "media_agent_deliveries", "media_distribution_targets",
                "media_distribution_events",
            }.issubset(v2_tables))

    def test_asset_lifecycle_is_audited_and_transfer_import_is_hash_idempotent(self):
        with tempfile.TemporaryDirectory(prefix="gideon-media-assets-") as td:
            store, audit = self._store(Path(td))
            reserved = store.create_media_asset(
                display_name="Promoción familiar.mp4",
                actor=self.actor,
                valid_from="2026-01-01",
                valid_until="2099-12-31",
            )
            asset_id = str(reserved["asset_id"])
            self.assertEqual("GIDEON", reserved["owner"])
            self.assertEqual("QUARANTINED", reserved["status"])

            analyzing = store.attach_media_asset_job(asset_id, "prep-ingest-01", actor="worker")
            self.assertEqual("ANALYZING", analyzing["status"])
            digest = "ab" * 32
            ready = store.complete_media_asset(
                asset_id,
                sha256=digest,
                size_bytes=4096,
                metadata={
                    "duration_seconds": 22.5,
                    "container": "MP4",
                    "video_codec": "h264",
                    "audio_codec": "aac",
                    "audio_profile": "LC",
                    "pixel_format": "yuv420p",
                    "width": 1920,
                    "height": 1080,
                },
                blob_relpath="assets/ab/promo-familiar.mp4",
                actor="worker",
            )
            self.assertEqual("READY", ready["status"])
            self.assertEqual(digest, ready["sha256"])
            self.assertEqual("1920x1080", ready["resolution"])
            self.assertEqual(22.5, ready["duration_seconds"])

            # A valid MP4 first uploaded through Transferencias must become a
            # campaign candidate, not a duplicate library object.
            imported = store.import_transfer_media_asset(
                display_name="Nombre alternativo.mp4",
                sha256=digest,
                size_bytes=4096,
                metadata={"duration_seconds": 22.5, "width": 1920, "height": 1080},
                blob_relpath="assets/ab/promo-familiar.mp4",
                actor=self.actor,
            )
            self.assertEqual(asset_id, imported["asset_id"])
            self.assertEqual(1, len(store.list_media_assets(state="READY")))

            events = store.media_asset_detail(asset_id)["events"]
            self.assertTrue({"media.assets.reserve", "media.assets.analysis_queued", "media.assets.ready"}.issubset(
                {row["action"] for row in events}
            ))
            self.assertTrue({"media.assets.reserve", "media.assets.ready"}.issubset({row["action"] for row in audit.rows}))
            with store.connect() as con:
                with self.assertRaises(sqlite3.IntegrityError):
                    con.execute("UPDATE media_asset_events SET actor='mutated' WHERE asset_id=?", (asset_id,))

    def test_three_distinct_screen_assets_are_snapshotted_in_campaign_revision(self):
        with tempfile.TemporaryDirectory(prefix="gideon-media-three-screens-") as td:
            store, _ = self._store(Path(td))
            screens = [
                self._screen(store, "Pantalla Caja", "agt-win", "HDMI-1"),
                self._screen(store, "Pantalla Delivery", "agt-win", "HDMI-2"),
                self._screen(store, "Pantalla Menuboard", "agt-pi", "HDMI-A-1"),
            ]
            assets = [
                self._ready_asset(store, "Caja.mp4", 17),
                self._ready_asset(store, "Delivery.mp4", 34),
                self._ready_asset(store, "Menuboard.mp4", 51),
            ]
            campaign = store.create_campaign_draft(
                title="Semana familiar",
                objective="Promoción por pantalla",
                assignments=[
                    self._assignment(str(screens[0]["screen_id"]), "Caja", str(assets[0]["asset_id"])),
                    self._assignment(str(screens[1]["screen_id"]), "Delivery", str(assets[1]["asset_id"])),
                    self._assignment(str(screens[2]["screen_id"]), "Menuboard", str(assets[2]["asset_id"]), emergency=True),
                ],
                actor=self.actor,
            )
            actual = store.campaign_detail(str(campaign["campaign_id"]))
            by_screen = {str(row["screen_id"]): str(row["asset_id"]) for row in actual["assignments"]}
            self.assertEqual({str(asset["asset_id"]) for asset in assets}, set(by_screen.values()))
            self.assertTrue(next(row for row in actual["assignments"] if row["emergency"])["emergency"])
            with store.connect() as con:
                linked_count = int(con.execute("SELECT COUNT(*) AS c FROM playlist_item_assets").fetchone()["c"])
                snapshot = json.loads(con.execute(
                    "SELECT snapshot_json FROM campaign_revisions WHERE campaign_id=? AND revision_no=1",
                    (campaign["campaign_id"],),
                ).fetchone()["snapshot_json"])
            self.assertEqual(3, linked_count)
            self.assertEqual({str(asset["asset_id"]) for asset in assets}, {
                str(row["asset_id"]) for row in snapshot["assignments"]
            })

    def test_publishable_rejects_a_video_that_has_not_finished_analysis(self):
        with tempfile.TemporaryDirectory(prefix="gideon-media-unready-") as td:
            store, _ = self._store(Path(td))
            screen = self._screen(store, "Pantalla Caja", "agt-unready", "HDMI-1")
            asset = store.create_media_asset(display_name="Pendiente.mp4", actor=self.actor)
            campaign = store.create_campaign_draft(
                title="No publicar todavía",
                assignments=[self._assignment(str(screen["screen_id"]), "Pendiente", str(asset["asset_id"]))],
                actor=self.actor, state="SCHEDULED",
            )
            campaign_id = str(campaign["campaign_id"])
            with self.assertRaisesRegex(CampaignStoreError, "análisis"):
                store.assert_publishable(campaign_id)
            with self.assertRaisesRegex(CampaignStoreError, "análisis"):
                store.queue_campaign_distribution(campaign_id, actor=self.actor)

            self._ready_asset_for_existing(store, str(asset["asset_id"]), 68)
            self.assertEqual(campaign_id, store.assert_publishable(campaign_id)["campaign_id"])
            self.assertEqual(1, len(store.queue_campaign_distribution(campaign_id, actor=self.actor)))

    def _ready_asset_for_existing(self, store: CampaignStore, asset_id: str, marker: int) -> dict[str, object]:
        store.attach_media_asset_job(asset_id, f"prep-{marker}", actor="worker")
        return store.complete_media_asset(
            asset_id,
            sha256=(f"{marker:02x}" * 32),
            size_bytes=2048,
            metadata={"duration_seconds": 5, "width": 1920, "height": 1080},
            blob_relpath=f"assets/{marker:02x}/ready.mp4",
            actor="worker",
        )

    def test_agent_hash_dedup_reuses_one_outbox_delivery_for_multiple_screens(self):
        with tempfile.TemporaryDirectory(prefix="gideon-media-outbox-") as td:
            store, _ = self._store(Path(td))
            left = self._screen(store, "Caja", "agt-shared", "HDMI-1")
            right = self._screen(store, "Delivery", "agt-shared", "HDMI-2")
            third = self._screen(store, "Menuboard", "agt-shared", "HDMI-3")
            asset = self._ready_asset(store, "Mismo video.mp4", 85)
            campaign = store.create_campaign_draft(
                title="Dos salidas, un video",
                assignments=[
                    self._assignment(str(left["screen_id"]), "Caja", str(asset["asset_id"])),
                    self._assignment(str(right["screen_id"]), "Delivery", str(asset["asset_id"])),
                ],
                actor=self.actor, state="SCHEDULED",
            )
            campaign_id = str(campaign["campaign_id"])
            targets = store.queue_campaign_distribution(campaign_id, actor=self.actor)
            self.assertEqual(2, len(targets))
            self.assertEqual({"PENDING"}, {str(row["state"]) for row in targets})
            pending = store.pending_media_deliveries(campaign_id=campaign_id)
            self.assertEqual(1, len(pending), "un Agent sólo debe recibir un despacho por hash")
            delivery_id = str(pending[0]["delivery_id"])
            store.mark_media_delivery_dispatched(delivery_id, preparation_job_id="prep-delivery-1", actor="worker")
            self.assertEqual("READY", store.reconcile_media_delivery(
                delivery_id, gateway_state="RESULT_READY", agent_online=True, actor="worker"
            ))

            # Reusing the same asset on a third output of the same Agent must
            # create only the screen target; it must not enqueue another file.
            repeated = store.create_campaign_draft(
                title="Tercera salida reutiliza",
                assignments=[self._assignment(str(third["screen_id"]), "Menuboard", str(asset["asset_id"]))],
                actor=self.actor, state="SCHEDULED",
            )
            repeated_id = str(repeated["campaign_id"])
            repeated_targets = store.queue_campaign_distribution(repeated_id, actor=self.actor)
            self.assertEqual(["READY"], [str(row["state"]) for row in repeated_targets])
            self.assertEqual([], store.pending_media_deliveries(campaign_id=repeated_id))
            with store.connect() as con:
                deliveries = int(con.execute("SELECT COUNT(*) AS c FROM media_agent_deliveries").fetchone()["c"])
            self.assertEqual(1, deliveries)

    def test_offline_retry_projects_status_and_keeps_immutable_distribution_history(self):
        with tempfile.TemporaryDirectory(prefix="gideon-media-offline-") as td:
            store, _ = self._store(Path(td))
            screen = self._screen(store, "Pantalla temporal", "agt-offline", "HDMI-1")
            asset = self._ready_asset(store, "Reintento.mp4", 102)
            campaign = store.create_campaign_draft(
                title="Reintento cuando vuelva",
                assignments=[self._assignment(str(screen["screen_id"]), "Reintento", str(asset["asset_id"]))],
                actor=self.actor, state="SCHEDULED",
            )
            campaign_id = str(campaign["campaign_id"])
            store.queue_campaign_distribution(campaign_id, actor=self.actor)
            delivery = store.pending_media_deliveries(campaign_id=campaign_id)[0]
            delivery_id = str(delivery["delivery_id"])
            store.mark_media_delivery_dispatched(delivery_id, preparation_job_id="prep-offline-1", actor="worker")
            self.assertEqual("OFFLINE", store.reconcile_media_delivery(
                delivery_id, gateway_state="QUEUED", agent_online=False, actor="worker"
            ))
            self.assertEqual("OFFLINE", store.list_campaign_distribution(campaign_id)[0]["state"])

            self.assertEqual("ERROR", store.reconcile_media_delivery(
                delivery_id, gateway_state="FAILED", agent_online=True, error="El Agent no respondió", actor="worker"
            ))
            retry = store.pending_media_deliveries(campaign_id=campaign_id, now="9999-12-31T23:59:59+00:00")
            self.assertEqual([delivery_id], [str(row["delivery_id"]) for row in retry])
            store.mark_media_delivery_dispatched(delivery_id, preparation_job_id="prep-offline-2", actor="worker")
            self.assertEqual("READY", store.reconcile_media_delivery(
                delivery_id, gateway_state="SUCCESS", agent_online=True, actor="worker"
            ))
            final = store.list_campaign_distribution(campaign_id)[0]
            self.assertEqual("READY", final["state"])
            self.assertEqual(2, final["attempts"])

            with store.connect() as con:
                events = con.execute(
                    "SELECT action,state FROM media_distribution_events ORDER BY created_at ASC"
                ).fetchall()
                with self.assertRaises(sqlite3.IntegrityError):
                    con.execute("UPDATE media_distribution_events SET state='MUTATED'")
            observed_states = {str(row["state"]) for row in events}
            self.assertTrue({"PENDING", "SYNCING", "OFFLINE", "ERROR", "READY"}.issubset(observed_states))
            self.assertIn("media.distribution.queued", {row["action"] for row in store.list_history(campaign_id=campaign_id)})


if __name__ == "__main__":
    unittest.main(verbosity=2)
