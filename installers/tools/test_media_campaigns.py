"""Regression checks for GIDEON Screens, Campaigns and Phase 2 media delivery.

The suite stays offline-safe: it validates the durable catalogue, protected
WebAdmin contracts and source parity without playing media, contacting an
Agent, or invoking a live Gateway.  Real uploads and signed dispatch remain
covered by their bounded worker/domain tests.
"""
from __future__ import annotations

import importlib.util
import json
import os
import datetime as dt
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor


ROOT = Path(os.environ.get("GIDEON_TEST_ROOT") or Path(__file__).resolve().parents[2]).resolve()
LINUX_APP = Path(os.environ.get("GIDEON_TEST_APP") or (ROOT / "payload/linux/app")).resolve()
WINDOWS_APP = Path(
    os.environ.get("GIDEON_TEST_WINDOWS_APP") or (ROOT / "payload/windows/GIDEON Remote Control/app")
).resolve()
sys.path.insert(0, str(LINUX_APP))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"No se pudo cargar {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


media = _load("gideon_test_media_campaigns", LINUX_APP / "gideon_web_admin/media_campaigns.py")
CampaignStore = media.CampaignStore
CampaignStoreError = media.CampaignStoreError
CampaignConflictError = media.CampaignConflictError


class AuditSink:
    """Small SecurityStore-compatible recorder without importing auth/argon2."""

    def __init__(self) -> None:
        self.rows: list[dict[str, str]] = []

    def audit(
        self, username: str, action: str, result: str, detail: str = "", remote_ip: str = "", *,
        resource: str = "", role: str = "",
    ) -> None:
        self.rows.append({
            "username": username, "action": action, "result": result, "detail": detail,
            "remote_ip": remote_ip, "resource": resource, "role": role,
        })


def _schedule(
    *, start_date: str = "2026-10-01", end_date: str = "2026-10-31",
    weekdays: list[int] | None = None, start_time: str = "08:00", end_time: str = "22:00",
    blackout_dates: list[str] | None = None,
) -> dict[str, object]:
    return {
        "start_date": start_date,
        "end_date": end_date,
        "weekdays": list(range(7)) if weekdays is None else weekdays,
        "start_time": start_time,
        "end_time": end_time,
        "blackout_dates": [] if blackout_dates is None else blackout_dates,
        "timezone": "America/Lima",
    }


def _assignment(
    screen_id: str, content_title: str, *, priority: int | None = 50,
    schedule: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "screen_id": screen_id,
        "playlist_name": f"Lista {content_title}",
        "content_title": content_title,
        "content_note": f"Nota de {content_title}",
        "priority": priority,
        "schedule": _schedule() if schedule is None else schedule,
    }


class MediaCampaignStoreTests(unittest.TestCase):
    actor = "marketing.test"
    valid_sites = {"18601", "18610"}

    def _store(self, root: Path) -> tuple[CampaignStore, AuditSink]:
        audit = AuditSink()
        return CampaignStore(root, security=audit), audit

    def _screen(
        self, store: CampaignStore, *, name: str, agent_id: str, output_key: str,
        site_code: str = "18601", orientation: str = "LANDSCAPE", resolution: str = "1920x1080",
    ) -> dict[str, object]:
        return store.create_screen(
            site_code=site_code,
            commercial_name=name,
            physical_location=f"{site_code} - área comercial",
            agent_id=agent_id,
            output_key=output_key,
            output_label=output_key,
            orientation=orientation,
            resolution=resolution,
            actor=self.actor,
            valid_site_codes=self.valid_sites,
        )

    def _three_screens(self, store: CampaignStore) -> list[dict[str, object]]:
        return [
            self._screen(store, name="Pantalla Caja", agent_id="agt-win-01", output_key="HDMI-1"),
            self._screen(store, name="Pantalla Delivery", agent_id="agt-win-01", output_key="HDMI-2"),
            self._screen(
                store, name="Pantalla Menuboard", agent_id="agt-pi-01", output_key="HDMI-A-1",
                orientation="PORTRAIT", resolution="1080x1920",
            ),
        ]

    def test_fresh_schema_reopen_and_screen_inventory_filters(self):
        """A site may contain many independently-addressed commercial screens."""
        with tempfile.TemporaryDirectory(prefix="gideon-media-schema-") as td:
            root = Path(td)
            store, audit = self._store(root)
            screens = self._three_screens(store)

            self.assertEqual(3, len(store.list_screens(site_code="18601")))
            self.assertEqual(2, len(store.list_screens(group_agent_ids=["agt-win-01"])))
            self.assertEqual(
                [screens[2]["screen_id"]],
                [row["screen_id"] for row in store.list_screens(
                    os_name="linux", agent_platforms={"agt-pi-01": "linux", "agt-win-01": "windows"},
                )],
            )
            self.assertEqual([], store.list_screens(group_agent_ids=[]))
            self.assertEqual(3, len(store.list_screens(state="READY")))
            self.assertTrue(all(row["physical_location"] for row in screens))
            self.assertEqual("PORTRAIT", screens[2]["orientation"])

            with self.assertRaises(CampaignStoreError):
                self._screen(store, name="Duplicada", agent_id="agt-win-01", output_key="HDMI-1")
            with self.assertRaises(CampaignStoreError):
                self._screen(store, name="Sede inexistente", agent_id="agt-other", output_key="HDMI-9", site_code="99999")

            # Reopening verifies that the independent catalogue keeps Phase 1
            # planning data while the additive Phase 2 migration is recorded.
            reopened, _ = self._store(root)
            self.assertEqual(3, len(reopened.list_screens(site_code="18601")))
            with reopened.connect() as con:
                versions = con.execute("SELECT version FROM media_schema_versions ORDER BY version").fetchall()
            self.assertEqual([1, 2, 3, 4, 5, 6, 7], [int(row["version"]) for row in versions])
            self.assertEqual(3, sum(row["action"] == "screens.create" for row in audit.rows))

    def test_screen_catalog_is_paged_searchable_and_selected_ids_are_bounded(self):
        """The campaign picker reads one Screen page, never the whole inventory."""
        with tempfile.TemporaryDirectory(prefix="gideon-media-screen-page-") as td:
            store, _ = self._store(Path(td))
            screens = [
                self._screen(
                    store, name=f"Pantalla {index:02d}", agent_id="agt-page",
                    output_key=f"HDMI-{index:02d}",
                )
                for index in range(27)
            ]
            page = store.list_screens_page(page=2, page_size=10)
            self.assertEqual(27, page["total"])
            self.assertEqual(10, len(page["items"]))
            self.assertEqual(2, page["pagination"]["page"])
            self.assertEqual(3, page["pagination"]["pages"])
            self.assertTrue(page["pagination"]["has_previous"])
            self.assertTrue(page["pagination"]["has_next"])

            match = store.list_screens_page(query="Pantalla 19", page=1, page_size=10)
            self.assertEqual(1, match["total"])
            self.assertEqual("Pantalla 19", match["items"][0]["commercial_name"])

            requested = [str(screens[-1]["screen_id"]), str(screens[0]["screen_id"]), str(screens[-1]["screen_id"])]
            selected = store.screens_by_ids(requested)
            self.assertEqual(requested[:2], [row["screen_id"] for row in selected])
            self.assertEqual([], store.screens_by_ids([]))
            with self.assertRaisesRegex(CampaignStoreError, "máximo 250"):
                store.screens_by_ids([f"scr-{index:03d}" for index in range(251)])

    def test_capability_report_only_updates_registered_outputs(self):
        """Agent discovery is bounded and never creates a commercial screen silently."""
        with tempfile.TemporaryDirectory(prefix="gideon-media-capability-") as td:
            store, _ = self._store(Path(td))
            screens = self._three_screens(store)
            updated = store.report_screen_capabilities([
                {
                    "AgentId": "agt-win-01",
                    "Capabilities": {
                        "Displays": {
                            "Source": "windows-display-api",
                            "Outputs": [
                                {"OutputKey": "HDMI-1", "Label": "Caja principal", "Connected": True,
                                 "Resolution": "1920x1080", "Orientation": "LANDSCAPE", "Primary": True},
                                {"OutputKey": "HDMI-2", "Label": "Delivery", "Connected": False,
                                 "Resolution": "1920x1080", "Orientation": "LANDSCAPE"},
                                {"OutputKey": "UNKNOWN-9", "Label": "No debe autocrearse", "Connected": True},
                            ],
                        }
                    },
                },
                {
                    "AgentId": "agt-pi-01",
                    "Capabilities": {"Displays": {"Outputs": [
                        {"OutputKey": "HDMI-A-1", "Connected": True, "Resolution": "1080×1920",
                         "Orientation": "PORTRAIT"},
                    ]}},
                },
            ])
            self.assertEqual(3, updated)
            observed = store.screen_detail(str(screens[0]["screen_id"]))
            self.assertTrue(observed["connected"])
            self.assertEqual("1920x1080", observed["reported_resolution"])
            self.assertEqual("windows-display-api", observed["source"])
            self.assertTrue(observed["last_sync_at"])
            self.assertEqual(3, len(store.list_screens()))
            self.assertNotIn("UNKNOWN-9", {row["output_key"] for row in store.list_screens()})

            projection = CampaignStore.normalized_display_outputs({
                "Capabilities": {"Displays": {"Outputs": [
                    {"OutputKey": "HDMI-1", "Label": "Caja", "Connected": True, "Secret": "must-not-leak"},
                ]}}
            })
            self.assertEqual(
                {"output_key", "label", "connected", "enabled", "physical", "virtual", "resolution", "orientation", "primary", "output_identity", "connector",
                 "target_kind", "target_kind_label"},
                set(projection[0]),
            )
            self.assertTrue(projection[0]["physical"])
            self.assertFalse(projection[0]["virtual"])
            self.assertNotIn("Secret", projection[0])

    def test_screen_target_kind_keeps_wayland_session_distinct_from_physical_connector(self):
        with tempfile.TemporaryDirectory(prefix="gideon-media-target-kind-") as td:
            store, _ = self._store(Path(td))
            physical = store.create_screen(
                site_code="18601", commercial_name="HDMI", agent_id="agt-target-kind",
                output_key="DISPLAY-1", output_identity="DISPLAY-1", target_kind="PHYSICAL_CONNECTOR",
                actor=self.actor, valid_site_codes=self.valid_sites,
            )
            wayland = store.create_screen(
                site_code="18601", commercial_name="Wayland", agent_id="agt-target-kind",
                output_key="DISPLAY-1", output_identity="DISPLAY-1", target_kind="LOCAL_WAYLAND_SESSION",
                actor=self.actor, valid_site_codes=self.valid_sites,
            )
            self.assertEqual("HDMI físico", physical["target_kind_label"])
            self.assertEqual("Sesión Wayland local", wayland["target_kind_label"])
            self.assertFalse(wayland["playback_config"]["physical_output"])
            self.assertEqual("LOCAL_WAYLAND_SESSION", wayland["playback_config"]["session_independence"])

            updated = store.report_screen_capabilities([{
                "AgentId": "agt-target-kind",
                "Capabilities": {"Displays": {"Outputs": [{
                    "OutputKey": "DISPLAY-1", "OutputIdentity": "DISPLAY-1",
                    "TargetKind": "LOCAL_WAYLAND_SESSION", "Virtual": True,
                    "Connected": True, "Enabled": True, "Resolution": "1920x1080",
                }]}},
            }])
            self.assertEqual(2, updated)
            self.assertFalse(store.screen_detail(str(physical["screen_id"]))["connected"])
            self.assertTrue(store.screen_detail(str(wayland["screen_id"]))["connected"])

    def test_capability_report_normalizes_exact_legacy_drm_connector_identity(self):
        """A raw cardN connector is upgraded without guessing or requiring signal."""
        with tempfile.TemporaryDirectory(prefix="gideon-media-identity-reconcile-") as td:
            store, audit = self._store(Path(td))
            screen = store.create_screen(
                site_code="18601", commercial_name="Menuboard", physical_location="Menú",
                agent_id="agt-pi-identity", output_key="linux-hdmi-1", output_label="HDMI 1",
                output_identity="card1-HDMI-A-1", actor=self.actor,
                valid_site_codes=self.valid_sites,
            )
            result = store.reconcile_screen_capabilities([{
                "AgentId": "agt-pi-identity",
                "Capabilities": {"Displays": {"Source": "linux-drm", "Outputs": [{
                    "OutputKey": "linux-hdmi-1", "OutputIdentity": "linux-hdmi-1",
                    "Connector": "card1-HDMI-A-1", "Connected": False,
                }]}},
            }], actor="system")
            self.assertEqual(1, result.screens_remapped)
            self.assertEqual(("agt-pi-identity",), result.manifest_agent_ids)
            current = store.screen_detail(str(screen["screen_id"]))
            self.assertEqual("linux-hdmi-1", current["output_identity"])
            self.assertIn(
                "screens.output_identity.auto_reconciled",
                {row["action"] for row in audit.rows},
            )

            # A real monitor fingerprint is intentionally not downgraded merely
            # because the connector happens to have the same OutputKey.
            store.update_screen(
                str(screen["screen_id"]), commercial_name="Menuboard", physical_location="Menú",
                agent_id="agt-pi-identity", output_key="linux-hdmi-1", output_label="HDMI 1",
                output_identity="linux-hdmi-1:monitor-expected", actor=self.actor,
            )
            unchanged = store.reconcile_screen_capabilities([{
                "AgentId": "agt-pi-identity",
                "Capabilities": {"Displays": {"Outputs": [{
                    "OutputKey": "linux-hdmi-1", "OutputIdentity": "linux-hdmi-1:monitor-other",
                    "Connector": "card1-HDMI-A-1", "Connected": True,
                }]}},
            }], actor="system")
            self.assertEqual(0, unchanged.screens_remapped)
            self.assertEqual("linux-hdmi-1:monitor-expected", store.screen_detail(str(screen["screen_id"]))["output_identity"])

    def test_capability_report_reconciles_one_unambiguous_legacy_output_once(self):
        """A sole connected connector safely replaces one synthetic SCREEN-N binding."""
        with tempfile.TemporaryDirectory(prefix="gideon-media-output-reconcile-") as td:
            store, audit = self._store(Path(td))
            screen = self._screen(
                store, name="Menuboard legacy", agent_id="agt-pi-legacy", output_key="SCREEN-1",
            )
            report = [{
                "AgentId": "agt-pi-legacy",
                "Capabilities": {"Display": {
                    "Source": "linux-drm",
                    "Outputs": [
                        {"OutputKey": "linux-hdmi-1", "OutputIdentity": "linux-hdmi-1:monitor-a1",
                         "Label": "HDMI-A-1", "Connected": True, "Resolution": "1280x720",
                         "Orientation": "LANDSCAPE", "Primary": True},
                        {"OutputKey": "linux-hdmi-2", "Label": "HDMI-A-2", "Connected": False},
                    ],
                }},
            }]

            result = store.reconcile_screen_capabilities(report, actor="system")
            self.assertEqual(1, result.screens_remapped)
            self.assertEqual(1, result.observations_updated)
            self.assertEqual(("agt-pi-legacy",), result.manifest_agent_ids)
            current = store.screen_detail(str(screen["screen_id"]))
            self.assertEqual("linux-hdmi-1", current["output_key"])
            self.assertEqual("linux-hdmi-1:monitor-a1", current["output_identity"])
            self.assertEqual("HDMI-A-1", current["output_label"])
            self.assertEqual("1280x720", current["resolution"])
            self.assertTrue(current["connected"])
            self.assertIn("screens.output.auto_reconciled", {row["action"] for row in audit.rows})
            self.assertIn(
                "screens.output.auto_reconciled",
                {row["action"] for row in store.list_history(limit=20)},
            )

            unchanged = store.reconcile_screen_capabilities(report, actor="system")
            self.assertEqual(0, unchanged.screens_remapped)
            self.assertEqual(0, unchanged.observations_updated)
            self.assertEqual((), unchanged.manifest_agent_ids)

    def test_capability_report_never_guesses_between_legacy_screens(self):
        """One connector cannot be silently assigned when two legacy Screens are candidates."""
        with tempfile.TemporaryDirectory(prefix="gideon-media-output-ambiguous-") as td:
            store, audit = self._store(Path(td))
            first = self._screen(store, name="Caja legacy", agent_id="agt-ambiguous", output_key="SCREEN-1")
            second = self._screen(store, name="Menú legacy", agent_id="agt-ambiguous", output_key="SCREEN-2")
            result = store.reconcile_screen_capabilities([{
                "AgentId": "agt-ambiguous",
                "Capabilities": {"Displays": {"Outputs": [
                    {"OutputKey": "linux-hdmi-1", "Connected": True, "Resolution": "1920x1080"},
                ]}},
            }], actor="system")
            self.assertEqual(0, result.screens_remapped)
            self.assertEqual((), result.manifest_agent_ids)
            self.assertEqual("SCREEN-1", store.screen_detail(str(first["screen_id"]))["output_key"])
            self.assertEqual("SCREEN-2", store.screen_detail(str(second["screen_id"]))["output_key"])
            self.assertNotIn("screens.output.auto_reconciled", {row["action"] for row in audit.rows})

    def test_v4_adds_safe_physical_defaults_to_existing_inventory(self):
        """A v3 database remains readable and defaults historic screens to dedicated signage."""
        with tempfile.TemporaryDirectory(prefix="gideon-media-v4-migration-") as td:
            root = Path(td)
            store, _ = self._store(root)
            screen = self._screen(store, name="Pantalla histórica", agent_id="agt-history", output_key="HDMI-1")
            with store.connect() as con:
                con.execute("DROP TRIGGER IF EXISTS campaign_schedule_preferences_no_update")
                con.execute("DROP TRIGGER IF EXISTS campaign_schedule_preferences_no_delete")
                con.execute("DROP TABLE IF EXISTS campaign_schedule_preferences")
                con.execute("DROP TABLE IF EXISTS screen_runtime_policies")
                con.execute("DELETE FROM media_schema_versions WHERE version=4")

            reopened, _ = self._store(root)
            restored = reopened.screen_detail(str(screen["screen_id"]))
            self.assertEqual("DEDICATED", restored["playback_policy"])
            self.assertTrue(restored["playback_config"]["physical_output"])
            self.assertFalse(restored["playback_config"]["pause_on_human_activity"])
            with reopened.connect() as con:
                versions = [int(row["version"]) for row in con.execute(
                    "SELECT version FROM media_schema_versions ORDER BY version"
                )]
            self.assertEqual([1, 2, 3, 4, 5, 6, 7], versions)

    def test_v5_rejects_duplicate_stable_output_identity_without_rewriting_legacy_rows(self):
        """A monitor fingerprint is a stronger identity than a connector name."""
        with tempfile.TemporaryDirectory(prefix="gideon-media-v5-identity-") as td:
            store, audit = self._store(Path(td))
            identity = "linux-hdmi-1:monitor-" + ("a" * 24)
            first = store.create_screen(
                site_code="18601", commercial_name="Caja", physical_location="Caja",
                agent_id="agt-output", output_key="HDMI-1", output_label="Caja",
                output_identity=identity, actor=self.actor, valid_site_codes=self.valid_sites,
            )
            self.assertEqual(identity, first["output_identity"])
            with self.assertRaises(CampaignStoreError):
                store.create_screen(
                    site_code="18601", commercial_name="Delivery", physical_location="Delivery",
                    agent_id="agt-output", output_key="DP-9", output_label="Delivery",
                    output_identity=identity, actor=self.actor, valid_site_codes=self.valid_sites,
                )
            self.assertIn("screens.create", {row["action"] for row in audit.rows})

    def test_campaign_has_distinct_content_per_screen_and_immutable_revisions(self):
        with tempfile.TemporaryDirectory(prefix="gideon-media-revisions-") as td:
            store, audit = self._store(Path(td))
            screens = self._three_screens(store)
            first_assignments = [
                _assignment(str(screens[0]["screen_id"]), "Oferta Caja"),
                _assignment(str(screens[1]["screen_id"]), "Oferta Delivery"),
                _assignment(str(screens[2]["screen_id"]), "Menú Familiar"),
            ]
            campaign = store.create_campaign_draft(
                title="Campaña Octubre", objective="Promoción familiar", assignments=first_assignments,
                actor=self.actor,
            )
            campaign_id = str(campaign["campaign_id"])
            self.assertEqual("DRAFT", campaign["state"])
            self.assertEqual(1, campaign["current_revision_no"])
            self.assertEqual(
                {"Oferta Caja", "Oferta Delivery", "Menú Familiar"},
                {row["content_title"] for row in campaign["assignments"]},
            )

            revised_assignments = list(first_assignments)
            revised_assignments[1] = _assignment(str(screens[1]["screen_id"]), "Delivery 2x1", priority=55)
            revised = store.save_campaign_revision(
                campaign_id, title="Campaña Octubre v2", assignments=revised_assignments,
                state="SCHEDULED", change_note="Actualización Delivery", actor=self.actor,
            )
            self.assertEqual(2, revised["current_revision_no"])
            self.assertEqual("Campaña Octubre v2", revised["title"])
            with store.connect() as con:
                revision_one = con.execute(
                    "SELECT snapshot_json FROM campaign_revisions WHERE campaign_id=? AND revision_no=1", (campaign_id,)
                ).fetchone()
                self.assertIsNotNone(revision_one)
                snapshot = json.loads(str(revision_one["snapshot_json"]))
                self.assertEqual("Campaña Octubre", snapshot["title"])
                self.assertIn("Oferta Delivery", {row["content_title"] for row in snapshot["assignments"]})
                with self.assertRaises(sqlite3.IntegrityError):
                    con.execute(
                        "UPDATE campaign_revisions SET title='mutation' WHERE campaign_id=? AND revision_no=1",
                        (campaign_id,),
                    )
            self.assertIn("campaigns.create", {row["action"] for row in audit.rows})
            self.assertIn("campaigns.edit", {row["action"] for row in audit.rows})

    def test_campaign_version_token_rejects_stale_revision_and_lifecycle_actions(self):
        """A later revision must not silently accept an older editor's action."""
        with tempfile.TemporaryDirectory(prefix="gideon-media-campaign-version-") as td:
            store, _ = self._store(Path(td))
            screen = self._screen(store, name="Versión", agent_id="agt-version", output_key="HDMI-1")
            campaign = store.create_campaign_draft(
                title="Campaña con versión",
                assignments=[_assignment(str(screen["screen_id"]), "Contenido inicial")],
                actor=self.actor,
            )
            campaign_id = str(campaign["campaign_id"])
            first_token = str(campaign["version_token"])
            first_stamp = str(campaign["updated_at"])

            page = store.list_campaigns_page(page=1, page_size=10)
            listed = next(item for item in page["items"] if item["campaign_id"] == campaign_id)
            self.assertEqual(first_token, listed["version_token"])

            revised = store.save_campaign_revision(
                campaign_id, title="Campaña con versión v2", actor=self.actor,
                expected_version_token=first_token,
            )
            self.assertEqual(2, revised["current_revision_no"])
            self.assertNotEqual(first_token, revised["version_token"])

            with self.assertRaisesRegex(CampaignStoreError, "cambió mientras"):
                store.save_campaign_revision(
                    campaign_id, title="Intento obsoleto", actor=self.actor,
                    expected_version_token=first_token,
                )
            with self.assertRaisesRegex(CampaignStoreError, "cambió mientras"):
                store.pause_campaign(
                    campaign_id, actor=self.actor, expected_updated_at=first_stamp + ".stale",
                )

            paused = store.pause_campaign(
                campaign_id, actor=self.actor, expected_version_token=str(revised["version_token"]),
            )
            self.assertEqual("PAUSED", paused["state"])
            with self.assertRaisesRegex(CampaignStoreError, "cambió mientras"):
                store.duplicate_campaign(
                    campaign_id, actor=self.actor, expected_version_token=str(revised["version_token"]),
                )

    def test_scheduling_conflicts_priority_and_blackout_dates(self):
        with tempfile.TemporaryDirectory(prefix="gideon-media-conflicts-") as td:
            store, _ = self._store(Path(td))
            screens = self._three_screens(store)
            target = str(screens[0]["screen_id"])
            active = store.create_campaign_draft(
                title="Base activa", assignments=[_assignment(target, "Base", priority=50)],
                actor=self.actor, state="ACTIVE",
            )
            same_priority = [_assignment(target, "Colisión", priority=50)]
            conflicts = store.find_schedule_conflicts(same_priority)
            self.assertEqual(1, len(conflicts))
            self.assertFalse(conflicts[0]["resolvable"])
            self.assertEqual(active["campaign_id"], conflicts[0]["campaign_id"])
            with self.assertRaises(CampaignConflictError):
                store.create_campaign_draft(
                    title="No publicar", assignments=same_priority, actor=self.actor, state="SCHEDULED",
                )

            priority_override = [_assignment(target, "Prioridad superior", priority=60)]
            self.assertTrue(store.find_schedule_conflicts(priority_override)[0]["resolvable"])
            higher = store.create_campaign_draft(
                title="Prioridad superior", assignments=priority_override, actor=self.actor, state="SCHEDULED",
            )
            self.assertEqual("SCHEDULED", higher["state"])

            # A blocked date removes the only common day, so no phantom
            # conflict prevents a marketer from publishing a valid schedule.
            blacked_screen = str(screens[1]["screen_id"])
            store.create_campaign_draft(
                title="Fecha bloqueada", actor=self.actor, state="ACTIVE",
                assignments=[_assignment(
                    blacked_screen, "Sólo bloqueada", priority=50,
                    schedule=_schedule(start_date="2026-11-03", end_date="2026-11-03", blackout_dates=["2026-11-03"]),
                )],
            )
            no_overlap = [_assignment(
                blacked_screen, "Nueva fecha", priority=50,
                schedule=_schedule(start_date="2026-11-03", end_date="2026-11-03"),
            )]
            self.assertEqual([], store.find_schedule_conflicts(no_overlap))
            self.assertEqual(
                "SCHEDULED",
                store.create_campaign_draft(
                    title="Sin conflicto por bloqueo", assignments=no_overlap, actor=self.actor, state="SCHEDULED",
                )["state"],
            )

    def test_concurrent_same_priority_publication_allows_exactly_one_campaign(self):
        """The conflict check must run inside the SQLite writer lock, not only before it."""
        with tempfile.TemporaryDirectory(prefix="gideon-media-race-") as td:
            root = Path(td)
            store, _ = self._store(root)
            screen = self._screen(store, name="Pantalla única", agent_id="agt-race", output_key="HDMI-1")
            screen_id = str(screen["screen_id"])
            start = threading.Barrier(2)

            def publish(title: str):
                contender = CampaignStore(root)
                start.wait(timeout=10)
                try:
                    return contender.create_campaign_draft(
                        title=title,
                        assignments=[_assignment(screen_id, title, priority=50)],
                        actor=self.actor,
                        state="SCHEDULED",
                    )
                except Exception as exc:  # The expected domain error is asserted below.
                    return exc

            with ThreadPoolExecutor(max_workers=2) as pool:
                outcomes = list(pool.map(publish, ("Carrera A", "Carrera B")))
            successes = [item for item in outcomes if isinstance(item, dict)]
            failures = [item for item in outcomes if isinstance(item, Exception)]
            self.assertEqual(1, len(successes), outcomes)
            self.assertEqual(1, len(failures), outcomes)
            self.assertIsInstance(failures[0], CampaignConflictError)
            self.assertEqual(1, len(store.list_campaigns(state="SCHEDULED")))

    def test_lifecycle_filters_and_audit_are_logically_deleted_only(self):
        with tempfile.TemporaryDirectory(prefix="gideon-media-life-") as td:
            store, audit = self._store(Path(td))
            screens = self._three_screens(store)
            campaign = store.create_campaign_draft(
                title="Ciclo", assignments=[_assignment(str(screens[2]["screen_id"]), "Contenido Pi")], actor=self.actor,
            )
            campaign_id = str(campaign["campaign_id"])
            self.assertEqual(1, len(store.list_campaigns(site_code="18601")))
            self.assertEqual(1, len(store.list_campaigns(
                group_agent_ids=["agt-pi-01"], os_name="linux",
                agent_platforms={"agt-pi-01": "linux", "agt-win-01": "windows"},
            )))
            self.assertEqual([], store.list_campaigns(os_name="windows", agent_platforms={"agt-pi-01": "linux"}))

            active = store.activate_campaign(campaign_id, actor=self.actor)
            paused = store.pause_campaign(campaign_id, actor=self.actor)
            archived = store.archive_campaign(campaign_id, actor=self.actor)
            self.assertEqual("ACTIVE", active["state"])
            self.assertEqual("PAUSED", paused["state"])
            self.assertTrue(archived["archived"])
            self.assertEqual([], store.list_campaigns())
            self.assertEqual(1, len(store.list_campaigns(include_archived=True)))

            reactivated = store.reactivate_campaign(campaign_id, actor=self.actor)
            duplicate = store.duplicate_campaign(campaign_id, actor=self.actor, title="Ciclo duplicado")
            self.assertEqual("SCHEDULED", reactivated["state"])
            self.assertFalse(reactivated["archived"])
            self.assertNotEqual(campaign_id, duplicate["campaign_id"])
            self.assertEqual("DRAFT", duplicate["state"])
            self.assertEqual(1, duplicate["current_revision_no"])
            self.assertGreaterEqual(reactivated["current_revision_no"], 5)

            history = store.list_history(campaign_id=campaign_id)
            actions = {row["action"] for row in history}
            self.assertTrue({"campaigns.create", "campaigns.activate", "campaigns.pause", "campaigns.archive", "campaigns.reactivate"}.issubset(actions))
            audited_actions = {row["action"] for row in audit.rows}
            self.assertTrue({"campaigns.create", "campaigns.activate", "campaigns.pause", "campaigns.archive", "campaigns.reactivate", "campaigns.duplicate"}.issubset(audited_actions))

    def test_archived_screen_cannot_receive_a_new_campaign_assignment(self):
        """History may retain its label, but future programming must be safe."""
        with tempfile.TemporaryDirectory(prefix="gideon-media-archived-screen-") as td:
            store, _ = self._store(Path(td))
            screen = self._screen(store, name="Temporal", agent_id="agt-win-02", output_key="HDMI-1")
            store.archive_screen(str(screen["screen_id"]), actor=self.actor)
            with self.assertRaises(CampaignStoreError):
                store.create_campaign_draft(
                    title="No usar pantalla archivada",
                    assignments=[_assignment(str(screen["screen_id"]), "Contenido")],
                    actor=self.actor,
                )

    def test_screen_logical_archive_can_restore_only_into_review_with_audit(self):
        """A bad physical mapping stays recoverable without silently playing again."""
        with tempfile.TemporaryDirectory(prefix="gideon-media-screen-restore-") as td:
            store, audit = self._store(Path(td))
            screen = self._screen(store, name="Pantalla por corregir", agent_id="agt-win-restore", output_key="HDMI-1")
            archived = store.archive_screen(str(screen["screen_id"]), actor=self.actor)
            self.assertTrue(archived["archived"])
            self.assertEqual("ARCHIVED", archived["state"])
            self.assertTrue(archived["manifest_refresh_required"])

            restored = store.restore_screen(str(screen["screen_id"]), actor=self.actor)
            self.assertFalse(restored["archived"])
            self.assertEqual("NEEDS_REVIEW", restored["state"])
            self.assertTrue(restored["manifest_refresh_required"])
            self.assertTrue(restored["restored_to_review"])
            self.assertEqual([str(screen["screen_id"])], [row["screen_id"] for row in store.list_screens()])
            self.assertTrue({"screens.archive", "screens.restore"}.issubset({row["action"] for row in audit.rows}))

    def test_screen_restore_refuses_live_name_or_output_collision(self):
        """An archived mapping cannot overwrite a newer physical screen."""
        with tempfile.TemporaryDirectory(prefix="gideon-media-screen-restore-conflict-") as td:
            store, _ = self._store(Path(td))
            original = self._screen(store, name="Caja", agent_id="agt-win-restore", output_key="HDMI-1")
            store.archive_screen(str(original["screen_id"]), actor=self.actor)
            self._screen(store, name="Caja", agent_id="agt-win-restore", output_key="HDMI-1")
            with self.assertRaises(CampaignStoreError):
                store.restore_screen(str(original["screen_id"]), actor=self.actor)

    def test_player_manifest_resolution_stops_removed_outputs_and_keeps_versions_monotonic(self):
        """A revision may never leave old signage playing by accident."""
        with tempfile.TemporaryDirectory(prefix="gideon-media-player-manifest-") as td:
            store, _ = self._store(Path(td))
            first = self._screen(store, name="Caja original", agent_id="agt-player-01", output_key="HDMI-1")
            second = self._screen(store, name="Caja reemplazo", agent_id="agt-player-01", output_key="HDMI-2")
            asset = store.create_media_asset(display_name="Oferta Player", actor=self.actor)
            ready = store.complete_media_asset(
                str(asset["asset_id"]), sha256="a" * 64, size_bytes=128,
                metadata={"duration_seconds": 12, "width": 1920, "height": 1080,
                          "container": "MP4", "video_codec": "h264", "audio_codec": "aac",
                          "pixel_format": "yuv420p"},
                blob_relpath="aa/" + "a" * 64 + ".mp4", actor=self.actor,
            )
            today = dt.datetime.now(dt.timezone.utc).date().isoformat()
            schedule = {"start_date": today, "end_date": today, "weekdays": list(range(7)),
                        "start_time": "00:00", "end_time": "00:00", "blackout_dates": [], "timezone": "UTC"}
            original = _assignment(str(first["screen_id"]), "Caja original", schedule=schedule)
            original["asset_id"] = str(ready["asset_id"])
            campaign = store.create_campaign_draft(
                title="Cambio de pantalla", assignments=[original], actor=self.actor, state="ACTIVE",
            )
            with store.connect() as con:
                con.execute(
                    "INSERT INTO media_agent_assets(agent_id,sha256,size_bytes,state,last_confirmed_at) VALUES(?,?,?,?,?)",
                    ("agt-player-01", "a" * 64, 128, "READY", "2026-01-01T00:00:00+00:00"),
                )
            # Windows build hosts may not package IANA tzdata.  Schedule
            # arithmetic has its own tests; this resolver test only needs a
            # deterministic eligible window and must run on every build host.
            original_active_now = media._window_active_now
            media._window_active_now = lambda _window: True
            try:
                first_inputs = store.agent_player_manifest_inputs("agt-player-01")
                self.assertEqual([str(first["screen_id"])], [row["screen_id"] for row in first_inputs["assignments"]])
                first_version = int(first_inputs["manifest_version"])

                replacement = _assignment(str(second["screen_id"]), "Caja reemplazo", schedule=schedule)
                replacement["asset_id"] = str(ready["asset_id"])
                store.save_campaign_revision(
                    str(campaign["campaign_id"]), title="Cambio de pantalla v2", assignments=[replacement],
                    state="ACTIVE", change_note="Se movió la salida física", actor=self.actor,
                )
                self.assertEqual(["agt-player-01"], store.agent_ids_for_campaign(str(campaign["campaign_id"])))
                second_inputs = store.agent_player_manifest_inputs("agt-player-01")
                self.assertEqual([str(second["screen_id"])], [row["screen_id"] for row in second_inputs["assignments"]])
                self.assertGreater(int(second_inputs["manifest_version"]), first_version)
                self.assertEqual(second_inputs["manifest_version"], store.agent_player_manifest_inputs("agt-player-01")["manifest_version"])

                # A removed/archived Agent still receives a monotonic signed
                # stop manifest instead of colliding with an earlier gateway
                # version.
                with store.connect() as con:
                    con.execute(
                        "INSERT INTO media_player_manifest_state(agent_id,content_sha256,manifest_version,updated_at) VALUES(?,?,?,?)",
                        ("agt-player-stop", "b" * 64, 7, "2026-01-01T00:00:00+00:00"),
                    )
                stopped = store.agent_player_manifest_inputs("agt-player-stop")
                self.assertEqual([], stopped["assignments"])
                self.assertEqual(8, stopped["manifest_version"])
            finally:
                media._window_active_now = original_active_now

    def test_physical_screen_policy_is_audited_and_resolved_without_user_session(self):
        """Dedicated/shared behaviour is screen inventory, not a remote-session setting."""
        with tempfile.TemporaryDirectory(prefix="gideon-media-physical-policy-") as td:
            store, audit = self._store(Path(td))
            dedicated = self._screen(store, name="Menuboard dedicado", agent_id="agt-policy", output_key="HDMI-1")
            shared = self._screen(store, name="Caja compartida", agent_id="agt-policy", output_key="HDMI-2")
            identity = "hdmi-2:" + ("b" * 64)
            shared = store.update_screen(
                str(shared["screen_id"]), commercial_name="Caja compartida",
                physical_location="18601 - área comercial", agent_id="agt-policy", output_key="HDMI-2",
                output_label="HDMI-2", orientation="LANDSCAPE", resolution="1920x1080", state="READY",
                playback_mode="SHARED_PAUSE_ON_HUMAN_ACTIVITY", output_identity=identity,
                actor=self.actor,
            )
            self.assertEqual("SHARED_PAUSE_ON_HUMAN_ACTIVITY", shared["playback_policy"])
            self.assertTrue(shared["playback_config"]["pause_on_human_activity"])

            asset = store.create_media_asset(display_name="Aviso físico.mp4", actor=self.actor)
            ready = store.complete_media_asset(
                str(asset["asset_id"]), sha256="c" * 64, size_bytes=321,
                metadata={"duration_seconds": 12, "width": 1920, "height": 1080,
                          "container": "MP4", "video_codec": "h264", "audio_codec": "aac",
                          "pixel_format": "yuv420p"},
                blob_relpath="cc/aviso.mp4", actor=self.actor,
            )
            today = dt.datetime.now(dt.timezone.utc).date().isoformat()
            active_schedule = {
                "start_date": today, "end_date": today, "weekdays": list(range(7)),
                "start_time": "00:00", "end_time": "00:00", "blackout_dates": [], "timezone": "UTC",
            }
            first = _assignment(str(dedicated["screen_id"]), "Menuboard", schedule=active_schedule)
            second = _assignment(str(shared["screen_id"]), "Aviso prioritario", schedule=active_schedule, priority=100)
            first["asset_id"] = str(ready["asset_id"])
            second["asset_id"] = str(ready["asset_id"])
            second["emergency"] = True
            campaign = store.create_campaign_draft(
                title="Política física", assignments=[first, second], actor=self.actor, state="ACTIVE",
            )
            with store.connect() as con:
                con.execute(
                    "INSERT INTO media_agent_assets(agent_id,sha256,size_bytes,state,last_confirmed_at) VALUES(?,?,?,?,?)",
                    ("agt-policy", "c" * 64, 321, "READY", "2026-01-01T00:00:00+00:00"),
                )
            original_active_now = media._window_active_now
            media._window_active_now = lambda _window: True
            try:
                inputs = store.agent_player_manifest_inputs("agt-policy")
            finally:
                media._window_active_now = original_active_now
            self.assertIsNotNone(inputs)
            rows = {row["screen_id"]: row for row in inputs["assignments"]}
            self.assertEqual("PERSISTENT_PHYSICAL_OUTPUT", rows[str(dedicated["screen_id"])]["policy"]["session_independence"])
            self.assertFalse(rows[str(dedicated["screen_id"])]["policy"]["pause_on_human_activity"])
            self.assertEqual("SHARED_PAUSE_ON_HUMAN_ACTIVITY", rows[str(shared["screen_id"])]["policy"]["screen_mode"])
            self.assertTrue(rows[str(shared["screen_id"])]["policy"]["pause_on_human_activity"])
            self.assertTrue(rows[str(shared["screen_id"])]["policy"]["emergency_takeover"])
            self.assertEqual(identity, rows[str(shared["screen_id"])]["policy"]["output_identity"])

            # Connector/EDID identity takes precedence over a renamed output
            # key and never creates a second commercial screen automatically.
            updated = store.report_screen_capabilities([{
                "AgentId": "agt-policy",
                "Capabilities": {"Displays": {"Outputs": [
                    {"OutputKey": "DP-7", "OutputIdentity": identity, "Connected": True,
                     "Resolution": "1920x1080", "Orientation": "LANDSCAPE"},
                ]}},
            }])
            # The authenticated report is an authoritative snapshot for the
            # Agent: the matched output becomes connected and the other
            # registered output receives an explicit disconnected observation.
            self.assertEqual(2, updated)
            observed = store.screen_detail(str(shared["screen_id"]))
            self.assertTrue(observed["connected"])
            self.assertIn("screens.playback_policy.edit", {row["action"] for row in audit.rows})
            self.assertEqual("ACTIVE", campaign["state"])

    def test_calendar_schedule_presets_are_immutable_and_keep_canonical_runtime_window(self):
        with tempfile.TemporaryDirectory(prefix="gideon-media-calendar-schedule-") as td:
            store, _ = self._store(Path(td))
            screen = self._screen(store, name="Calendario", agent_id="agt-calendar", output_key="HDMI-1")
            weekday_schedule = {
                "preset": "WEEKDAYS", "start_at": "2026-10-01T08:30", "end_at": "2026-10-31T20:15",
                "blackout_dates": ["2026-10-12"], "timezone": "America/Lima",
            }
            campaign = store.create_campaign_draft(
                title="Calendario visual", assignments=[_assignment(
                    str(screen["screen_id"]), "Oferta laboral", schedule=weekday_schedule,
                )], actor=self.actor,
            )
            first = campaign["assignments"][0]["schedule"]
            self.assertEqual("WEEKDAYS", first["preset"])
            self.assertEqual([0, 1, 2, 3, 4], first["weekdays"])
            self.assertEqual("2026-10-01", first["start_date"])
            self.assertEqual("08:30", first["start_time"])
            self.assertIn("lunes a viernes", first["summary"])
            self.assertIn("2026-10-12", first["blackout_dates"])
            schedule_id = campaign["assignments"][0]["schedule_id"]
            with store.connect() as con:
                with self.assertRaises(sqlite3.IntegrityError):
                    con.execute(
                        "UPDATE campaign_schedule_preferences SET preset='CUSTOM' WHERE schedule_id=?", (schedule_id,)
                    )

            always = _assignment(str(screen["screen_id"]), "Oferta continua", schedule={
                "preset": "ALWAYS", "timezone": "America/Lima",
            })
            revised = store.save_campaign_revision(
                str(campaign["campaign_id"]), title="Calendario visual continuo", assignments=[always],
                state="DRAFT", change_note="Nueva programación continua", actor=self.actor,
            )
            self.assertEqual(2, revised["current_revision_no"])
            self.assertEqual("ALWAYS", revised["assignments"][0]["schedule"]["preset"])
            with store.connect() as con:
                snapshot = json.loads(str(con.execute(
                    "SELECT snapshot_json FROM campaign_revisions WHERE campaign_id=? AND revision_no=1",
                    (campaign["campaign_id"],),
                ).fetchone()["snapshot_json"]))
            self.assertEqual("WEEKDAYS", snapshot["assignments"][0]["schedule"]["preset"])

    def test_media_asset_edit_and_logical_archive_preserve_campaign_history(self):
        """Library metadata is editable, while active plans and evidence stay safe."""
        with tempfile.TemporaryDirectory(prefix="gideon-media-asset-crud-") as td:
            store, audit = self._store(Path(td))
            screen = self._screen(store, name="Caja activos", agent_id="agt-asset", output_key="HDMI-1")
            asset = store.create_media_asset(
                display_name="Oferta original", actor=self.actor,
                valid_from="2026-10-01", valid_until="2026-10-31",
            )
            ready = store.complete_media_asset(
                str(asset["asset_id"]), sha256="d" * 64, size_bytes=456,
                metadata={"duration_seconds": 15, "width": 1920, "height": 1080,
                          "container": "MP4", "video_codec": "h264", "audio_codec": "aac",
                          "pixel_format": "yuv420p"},
                blob_relpath="dd/oferta.mp4", actor=self.actor,
            )
            assignment = _assignment(str(screen["screen_id"]), "Oferta Caja")
            assignment["asset_id"] = str(ready["asset_id"])
            campaign = store.create_campaign_draft(
                title="Campaña en curso", assignments=[assignment], actor=self.actor, state="ACTIVE",
            )

            references = store.media_asset_references(str(ready["asset_id"]))
            self.assertEqual(1, references["current_count"])
            self.assertEqual(1, references["active_count"])
            self.assertFalse(references["can_archive"])

            renamed = store.update_media_asset(
                str(ready["asset_id"]), display_name="Oferta Caja octubre",
                valid_from="2026-10-01", valid_until="2026-10-31", actor=self.actor,
            )
            self.assertEqual("Oferta Caja octubre", renamed["display_name"])
            self.assertEqual("d" * 64, renamed["sha256"])
            self.assertEqual("dd/oferta.mp4", renamed["blob_relpath"])
            with self.assertRaisesRegex(CampaignStoreError, "nueva vigencia"):
                store.update_media_asset(
                    str(ready["asset_id"]), display_name="Oferta Caja octubre",
                    valid_from="2026-10-01", valid_until="2026-10-20", actor=self.actor,
                )
            with self.assertRaisesRegex(CampaignStoreError, "todavía está asignado"):
                store.archive_media_asset(str(ready["asset_id"]), actor=self.actor)

            # Pausing alone does not let a current revision become silently
            # invalid.  Archive or revise the campaign first, then archive
            # only the library record while retaining all revision evidence.
            store.pause_campaign(str(campaign["campaign_id"]), actor=self.actor)
            with self.assertRaisesRegex(CampaignStoreError, "todavía está asignado"):
                store.archive_media_asset(str(ready["asset_id"]), actor=self.actor)
            store.archive_campaign(str(campaign["campaign_id"]), actor=self.actor)
            archived = store.archive_media_asset(str(ready["asset_id"]), actor=self.actor)
            self.assertTrue(archived["archived"])
            self.assertEqual("ARCHIVED", archived["status"])
            references = store.media_asset_references(str(ready["asset_id"]))
            self.assertEqual(0, references["current_count"])
            self.assertGreaterEqual(references["historical_revision_count"], 1)
            self.assertFalse(references["can_archive"])
            with self.assertRaises(CampaignStoreError):
                store.update_media_asset(
                    str(ready["asset_id"]), display_name="No debe cambiar", actor=self.actor,
                )
            actions = {event["action"] for event in archived["events"]}
            self.assertTrue({"media.assets.edit", "media.assets.archive"}.issubset(actions))
            audited = {row["action"] for row in audit.rows}
            self.assertTrue({"media.assets.edit", "media.assets.archive"}.issubset(audited))


class MediaCampaignMirrorContractTests(unittest.TestCase):
    def test_campaign_store_is_mirrored_and_uses_independent_versioned_schema(self):
        relative = "gideon_web_admin/media_campaigns.py"
        self.assertTrue((LINUX_APP / relative).is_file(), relative)
        self.assertTrue((WINDOWS_APP / relative).is_file(), relative)
        self.assertEqual(
            (LINUX_APP / relative).read_bytes(),
            (WINDOWS_APP / relative).read_bytes(),
            "Las copias Linux/Windows de CampaignStore difieren.",
        )
        source = (LINUX_APP / relative).read_text(encoding="utf-8-sig")
        for required in (
            "media-campaigns.sqlite3", "media_schema_versions", "campaign_revisions_no_update",
            "campaign_revisions_no_delete", "report_screen_capabilities", "find_schedule_conflicts",
            "duplicate_campaign", "reactivate_campaign",
            "media_player_manifest_state", "agent_player_manifest_inputs",
            "screen_runtime_policies", "campaign_schedule_preferences",
            "SHARED_PAUSE_ON_HUMAN_ACTIVITY", "PERSISTENT_PHYSICAL_OUTPUT",
        ):
            self.assertIn(required, source)

    def test_phase2_web_api_ui_permissions_and_mirrors_are_present(self):
        """Phase 2 adds safe media handling, never a player or Input Share."""
        required_relative = (
            "gideon_web_admin/app.py", "gideon_web_admin/auth.py", "gideon_web_admin/services.py",
            "gideon_web_admin/operations.py", "gideon_web_admin/media_validation.py",
            "gideon_web_admin/templates/base.html", "gideon_web_admin/templates/media_campaigns.html",
            "gideon_web_admin/templates/media_campaign_wizard.html", "gideon_web_admin/templates/media_screens.html",
            "gideon_web_admin/templates/media_campaign_detail.html", "gideon_web_admin/templates/media_library.html",
            "gideon_web_admin/templates/media_asset_edit.html",
            "gideon_web_admin/templates/media_schedule.html", "gideon_web_admin/templates/media_history.html",
            "gideon_web_admin/templates/transfers.html", "gideon_web_admin/templates/transfer_job_detail.html",
            "gideon_web_admin/static/media_campaigns.css", "gideon_web_admin/static/media_campaigns.js",
            "tools/dependencies/install-gideon-dependencies-linux.sh",
        )
        for relative in required_relative:
            self.assertTrue((LINUX_APP / relative).is_file(), relative)
            self.assertTrue((WINDOWS_APP / relative).is_file(), relative)
            self.assertEqual((LINUX_APP / relative).read_bytes(), (WINDOWS_APP / relative).read_bytes(), relative)
        app_source = (LINUX_APP / "gideon_web_admin/app.py").read_text(encoding="utf-8-sig")
        auth_source = (LINUX_APP / "gideon_web_admin/auth.py").read_text(encoding="utf-8-sig")
        operations_source = (LINUX_APP / "gideon_web_admin/operations.py").read_text(encoding="utf-8-sig")
        validation_source = (LINUX_APP / "gideon_web_admin/media_validation.py").read_text(encoding="utf-8-sig")
        dependency_source = (LINUX_APP / "tools/dependencies/install-gideon-dependencies-linux.sh").read_text(encoding="utf-8-sig")
        navigation = (LINUX_APP / "gideon_web_admin/templates/base.html").read_text(encoding="utf-8-sig")
        wizard = (LINUX_APP / "gideon_web_admin/templates/media_campaign_wizard.html").read_text(encoding="utf-8-sig")
        for required in (
            '@app.get("/api/v1/media/screens"', '@app.get("/api/v1/media/campaigns"',
            '@app.get("/media/campaigns"', '@app.post("/media/campaigns/new"',
            '@app.post("/media/screens/create"', '@app.post("/media/assets/upload"',
            '@app.get("/api/v1/media/assets/{asset_id}"', '@app.get("/transfers/{job_id}/create-campaign"',
            '@app.get("/api/v1/media/campaigns/{campaign_id}/distribution"',
            '@app.get("/media/assets/{asset_id}/edit"', '@app.post("/media/assets/{asset_id}/edit")',
            'media_distribution_scheduler_enabled', 'media_form_snapshot', 'validate_csrf(request, identity)',
        ):
            self.assertIn(required, app_source)
        for permission in ("media.view", "media.manage", "screens.view", "screens.manage", "campaigns.approve", '"MARKETING"'):
            self.assertIn(permission, auth_source)
        for label in ("Biblioteca", "Campañas", "Programación", "Pantallas", "Historial"):
            self.assertIn(label, navigation)
        for label in ("¿Qué quiere comunicar?", "¿Qué contenido se mostrará?", "¿En qué pantallas?", "¿Cuándo debe reproducirse?", "Revisar y publicar"):
            self.assertIn(label, wizard)
        for required in ("MEDIA_ASSET_INGEST", "MEDIA_DISTRIBUTION", "MediaCampaignCandidate", "Distribucion/Videos", "_remote_join"):
            self.assertIn(required, operations_source)
        for required in ("shell=False", "MAX_FFPROBE_TIMEOUT_SECONDS", "yuv420p", "AAC-LC"):
            self.assertIn(required, validation_source)
        self.assertIn("install_pkgs ffmpeg", dependency_source)
        self.assertIn("MEDIA_VALIDATION=PASS", dependency_source)
        campaign_store_source = (LINUX_APP / "gideon_web_admin/media_campaigns.py").read_text(encoding="utf-8-sig")
        self.assertIn("update_media_asset", campaign_store_source)
        self.assertIn("media.assets.edit", campaign_store_source)
        distribution_route = app_source[app_source.index('def media_campaign_distribution_api'):]
        self.assertIn('identity.can("jobs.view")', distribution_route)
        self.assertIn('"job_url"', distribution_route)
        self.assertNotIn('"job":', distribution_route.split('@app.get("/groups"', 1)[0])
        combined = "\n".join((app_source, operations_source, validation_source, (LINUX_APP / "gideon_web_admin/media_campaigns.py").read_text(encoding="utf-8-sig"))).casefold()
        self.assertNotIn("import vlc", combined)
        self.assertNotIn("input share", combined)


if __name__ == "__main__":
    unittest.main(verbosity=2)
