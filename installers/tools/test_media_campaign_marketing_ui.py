"""Offline contracts for the Marketing campaign and screen configuration UI."""
from __future__ import annotations

import ast
import os
from pathlib import Path
import unittest


ROOT = Path(os.environ.get("GIDEON_TEST_ROOT") or Path(__file__).resolve().parents[2]).resolve()
LINUX = ROOT / "payload/linux/app/gideon_web_admin"
WINDOWS = ROOT / "payload/windows/GIDEON Remote Control/app/gideon_web_admin"


class MediaCampaignMarketingUiTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        linux = LINUX / relative
        windows = WINDOWS / relative
        self.assertTrue(linux.is_file(), linux)
        self.assertTrue(windows.is_file(), windows)
        self.assertEqual(linux.read_bytes(), windows.read_bytes(), f"Mirror differs: {relative}")
        return linux.read_text(encoding="utf-8-sig")

    def test_campaign_schedule_has_visual_calendar_clock_and_human_review(self):
        wizard = self.read("templates/media_campaign_wizard.html")
        script = self.read("static/media_campaigns.js")
        styles = self.read("static/media_campaigns.css")
        for marker in (
            'data-schedule-designer', 'data-schedule-calendar', 'data-calendar-grid',
            'data-calendar-mode="blackout"', 'data-schedule-time', 'data-blackout-chips',
            'data-schedule-summary', 'data-schedule-preset-output', 'data-schedule-weekdays-output',
        ):
            self.assertIn(marker, wizard)
        for marker in (
            "initCampaignScheduleDesigner", "parseCalendarDate", "renderCalendar",
            "renderBlackoutChips", "scheduleSummary", "Antes de publicar, complete lo siguiente",
        ):
            self.assertIn(marker, script)
        for marker in ("media-schedule-designer", "media-calendar-day", "media-time-slots", "media-blackout-chip"):
            self.assertIn(marker, styles)
        self.assertNotIn("AgentId", wizard)
        self.assertNotIn("output_key", wizard)

    def test_asset_validity_uses_localized_calendar_without_changing_iso_form_contract(self):
        """Marketing sees es-PE dates even when Chrome itself uses another locale."""
        wizard = self.read("templates/media_campaign_wizard.html")
        library = self.read("templates/media_library.html")
        script = self.read("static/media_campaigns.js")
        styles = self.read("static/media_campaigns.css")
        for template in (wizard, library):
            self.assertEqual(2, template.count("data-localized-date-picker"))
            self.assertIn('type="date" name="valid_from"', template)
            self.assertIn('type="date" name="valid_until"', template)
            # Content-addressed assets prevent a browser from combining an old
            # calendar script with newly deployed HTML.  Do not reintroduce a
            # hand-maintained RC suffix here.
            self.assertIn("static_url('media_campaigns.js')", template)
            self.assertNotIn("RC30.102.0", template)
        for marker in (
            "initLocalizedDatePickers", "calendarDateLongLabel", '"es-PE"',
            "syncAssetDateWindow", "La vigencia hasta debe ser igual o posterior",
            "data-localized-date-value",
        ):
            self.assertIn(marker, script)
        for marker in (
            "media-local-date-trigger", "media-local-date-popover",
            "media-local-date-day", "media-local-date-native",
        ):
            self.assertIn(marker, styles)

    def test_localized_date_popup_is_portalled_compact_and_viewport_bound(self):
        """The calendar must not be clipped by a rounded upload card on wide forms."""
        script = self.read("static/media_campaigns.js")
        styles = self.read("static/media_campaigns.css")
        for marker in (
            "const placePopup", "document.body.append(popup)",
            "--gideon-local-date-picker-width", "--gideon-local-date-picker-max-height",
            'trigger.setAttribute("aria-controls", popup.id)',
            "document.addEventListener(\"scroll\", repositionOpenPopup, true)",
        ):
            self.assertIn(marker, script)
        self.assertNotIn("root.append(trigger, popup)", script)
        for marker in (
            ".media-local-date-popover{position:fixed", "max-inline-size:calc(100vw - 1.5rem)",
            "max-block-size:var(--gideon-local-date-picker-max-height", "overscroll-behavior:contain",
        ):
            self.assertIn(marker, styles)

    def test_screen_policy_is_marketing_facing_and_separates_local_target_from_remote_sessions(self):
        screens = self.read("templates/media_screens.html")
        script = self.read("static/media_campaigns.js")
        for marker in (
            'name="playback_policy"', 'value="DEDICATED"',
            'value="SHARED_PAUSE_ON_HUMAN_ACTIVITY"',
            "Pantalla dedicada a contenido", "Pantalla compartida con una persona",
            "no depende de una sesión remota", "Las sesiones remotas administrativas no cambian esta elección",
            'name="target_kind"', "sesión gráfica Wayland local",
        ):
            self.assertIn(marker, screens)
        # The selected capability's privacy-safe output identity must travel
        # with the form; otherwise backend uniqueness would only protect a
        # connector label and a monitor replacement could be misrouted.
        self.assertIn('name="output_identity"', screens)
        self.assertIn("identity.can('audit.view')", screens)
        for marker in (
            "data-output-identity", "dataset.outputIdentity", "data-target-kind",
            "dataset.targetKind", "selectTarget",
        ):
            self.assertIn(marker, script)

    def test_screen_change_republishes_only_a_signed_resolved_manifest_in_background(self):
        app = self.read("app.py")
        for marker in (
            "def publish_media_manifest_for_agent(",
            "def publish_media_manifests_for_agents(",
            "def queue_screen_manifest_refresh(",
            "SCREEN_CONFIGURATION_CHANGED",
            "reconcile_screen_capabilities",
            "capability_result.manifest_agent_ids",
            "SCREEN_OUTPUT_AUTO_RECONCILED",
            "media.player_manifest.refresh_queued",
            "manifest_refresh_required",
        ):
            self.assertIn(marker, app)
        # A screen form POST is not allowed to synchronously block Marketing on
        # Gateway I/O; the background publisher still signs the resolved state.
        self.assertIn('name="gideon-player-screen-manifest-refresh"', app)
        self.assertIn("daemon=True", app)

    def test_library_has_safe_video_edit_and_logical_delete_paths(self):
        library = self.read("templates/media_library.html")
        edit = self.read("templates/media_asset_edit.html")
        app = self.read("app.py")
        store = self.read("media_campaigns.py")
        for marker in (
            "/media/assets/{{ asset.asset_id }}/edit", "Eliminar de biblioteca",
            "Elimina el video de la biblioteca de forma lógica",
        ):
            self.assertIn(marker, library)
        for marker in (
            "data-localized-date-picker", "data-localized-date-value",
            "El archivo, su integridad y su historial no se modifican.",
            "Guardar cambios",
        ):
            self.assertIn(marker, edit)
        for marker in (
            '@app.get("/media/assets/{asset_id}/edit"', '@app.post("/media/assets/{asset_id}/edit")',
            "campaigns.update_media_asset", "campaigns.media_asset_references",
        ):
            self.assertIn(marker, app)
        for marker in (
            "def update_media_asset", "def media_asset_references", "media.assets.edit",
            "El video todavía está asignado",
        ):
            self.assertIn(marker, store)

    def test_screen_inventory_exposes_permitted_logical_archive_and_safe_restore(self):
        screens = self.read("templates/media_screens.html")
        app = self.read("app.py")
        for marker in (
            "identity.can('screens.manage')", "Acciones", "/archive", "/restore",
            "Editar", "Eliminar lógico", "Restaurar para corregir", "no reanuda contenido por sí sola",
        ):
            self.assertIn(marker, screens)
        for marker in (
            '@app.post("/media/screens/{screen_id}/archive")',
            '@app.post("/media/screens/{screen_id}/restore")',
            '@app.patch("/api/v1/media/screens/{screen_id}", response_class=JSONResponse)',
            '@app.delete("/api/v1/media/screens/{screen_id}", response_class=JSONResponse)',
            '@app.post("/api/v1/media/screens/{screen_id}/restore", response_class=JSONResponse)',
            'require(request, "screens.manage")', 'validate_csrf(request, identity)',
            '"LogicalDeletion": True',
        ):
            self.assertIn(marker, app)

    def test_screen_restore_is_metadata_only_and_storage_guard_stays_on_uploads(self):
        """A low upload reserve must never turn a Screen restore into a blank 507 page."""
        app = self.read("app.py")
        tree = ast.parse(app)
        upload_paths = next(
            ast.literal_eval(node.value)
            for node in tree.body
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "UPLOAD_RECEIVING_PERMISSIONS" for target in node.targets)
        )
        for path in (
            "/transfers", "/media/assets/upload", "/scripts/upload", "/system-updates/upload",
            "/security/assets/signing/import", "/security/assets/ca/upload",
            "/security/assets/yara/upload", "/security/assets/ssh-public/upload",
            "/security/assets/ssh-identity/upload", "/security/assets/ssh-identity/folder-upload",
            "/security/assets/guacamole-client/upload",
        ):
            self.assertIn(path, upload_paths)
        self.assertFalse(any(path.startswith("/media/screens") for path in upload_paths))
        for marker in (
            "def _requires_storage_reserve_preflight(request_path: str)",
            "if _requires_storage_reserve_preflight(request.url.path):",
            "uploads.storage_preflight",
            '"title": "Espacio temporal insuficiente"',
            'page_error = str(request.query_params.get("error") or "")',
        ):
            self.assertIn(marker, app)
        restore_start = app.index('@app.post("/media/screens/{screen_id}/restore")')
        restore_end = app.index('@app.get("/media/schedule"', restore_start)
        restore = app[restore_start:restore_end]
        self.assertIn("return RedirectResponse(", restore)
        self.assertIn('"/media/screens?error=', restore)
        self.assertNotIn("raise HTTPException(409, str(exc)) from exc", restore)
        self.assertIn("neither receives nor stages MediaAsset bytes", restore)

    def test_catalogues_are_lazy_and_campaign_pages_do_not_reconcile_deliveries(self):
        """Large libraries cannot turn a campaign page into an N×M payload."""
        wizard = self.read("templates/media_campaign_wizard.html")
        script = self.read("static/media_campaigns.js")
        app = self.read("app.py")
        self.assertIn('data-media-asset-catalog-url="/api/v1/media/assets"', wizard)
        self.assertNotIn("for asset in available_assets", wizard)
        for marker in (
            "initLazyAssetPickers", "requestCatalog", "pageSize = 24",
            "avoids rendering the former screens × assets option matrix",
        ):
            self.assertIn(marker, script)
        self.assertIn('@app.get("/api/v1/media/assets", response_class=JSONResponse)', app)
        self.assertIn("def _media_distribution_cycle()", app)
        detail_start = app.index('@app.get("/media/campaigns/{campaign_id}"')
        detail_end = app.index('@app.get("/media/campaigns/{campaign_id}/revise"', detail_start)
        detail_route = app[detail_start:detail_end]
        self.assertNotIn("reconcile_media_distribution(", detail_route)

    def test_upload_analysis_refreshes_and_silent_video_is_explained(self):
        library = self.read("templates/media_library.html")
        wizard = self.read("templates/media_campaign_wizard.html")
        script = self.read("static/media_campaigns.js")
        validation = self.read("media_validation.py")
        store = self.read("media_campaigns.py")
        app = self.read("app.py")
        self.assertIn('data-media-status-url-template="/api/v1/media/assets/{asset_id}"', library)
        self.assertIn('data-media-refresh-on-terminal="true"', library)
        self.assertIn("initLibraryAssetPolling", script)
        self.assertIn("window.location.reload()", script)
        self.assertNotIn('audio_codec="aac",', validation)
        self.assertIn("audio_codec=audio_codec", validation)
        for template in (library, wizard):
            self.assertIn("El audio es opcional", template)
        for marker in ("has_audio", "playback_warning"):
            self.assertIn(marker, store)
            self.assertIn(marker, app)

    def test_campaign_preselection_and_first_screen_page_are_immediately_usable(self):
        wizard = self.read("templates/media_campaign_wizard.html")
        script = self.read("static/media_campaigns.js")
        for marker in (
            "data-campaign-selected-asset", "data-suggested-asset-name",
            "adoptCampaignAsset", "asset.state || asset.status",
            "void loadPage(1);",
        ):
            self.assertIn(marker, wizard if marker.startswith("data-") else script)
        self.assertNotIn("{% if not screens %}disabled{% endif %}", wizard)

    def test_campaign_screen_picker_is_server_paged_and_selected_only(self):
        """Opening a campaign must not hydrate every Screen in the inventory."""
        wizard = self.read("templates/media_campaign_wizard.html")
        script = self.read("static/media_campaigns.js")
        styles = self.read("static/media_campaigns.css")
        app = self.read("app.py")
        store = self.read("media_campaigns.py")
        for marker in (
            'data-screen-catalog-url="/api/v1/media/screens"',
            "data-screen-catalog-search", "data-screen-catalog-pagination",
            "data-screen-selected-list", "for screen in selected_screens",
        ):
            self.assertIn(marker, wizard)
        self.assertNotIn("for screen in screens", wizard)
        for marker in (
            "createCampaignScreenCard", "initLazyScreenCatalog", "data-screen-catalog-add",
            'url.searchParams.set("page_size"', "gideon-screen-selection-change",
        ):
            self.assertIn(marker, script)
        for marker in ("media-screen-catalog-controls", "media-screen-catalog-result", "media-screen-selection-head"):
            self.assertIn(marker, styles)
        for marker in (
            "def media_wizard_context(", "include_screens=False", "campaigns.screens_by_ids(",
            '@app.get("/api/v1/media/screens", response_class=JSONResponse)',
            "campaigns.list_screens_page(",
        ):
            self.assertIn(marker, app)
        for marker in ("def list_screens_page(", "def screens_by_ids(", "def count_screens("):
            self.assertIn(marker, store)

    def test_campaign_screen_configuration_groups_shared_video_and_uses_peru_clock(self):
        """Shared creatives use one editor while exceptions remain opt-in."""
        wizard = self.read("templates/media_campaign_wizard.html")
        script = self.read("static/media_campaigns.js")
        styles = self.read("static/media_campaigns.css")
        app = self.read("app.py")
        for marker in (
            'data-screen-group-mode="grouped"', 'data-screen-group-mode="individual"',
            "Agrupar por video", "Configurar una por una", "data-screen-group-mode-control",
            'id="timezone" name="timezone" value="America/Lima"', "Perú · America/Lima",
        ):
            self.assertIn(marker, wizard)
        for marker in (
            "renderScreenGroups", "copyGroupConfiguration", "screenGroupMode",
            "groupKeyFor", "const peruToday", "timeZone: \"America/Lima\"",
        ):
            self.assertIn(marker, script)
        for marker in ("media-screen-group-mode", "media-screen-group-summary", "is-screen-group-representative"):
            self.assertIn(marker, styles)
        self.assertIn('"timezone": "America/Lima"', app)

    def test_global_timestamp_display_converts_utc_to_peru_without_mutating_audit_data(self):
        """Visible ISO timestamps use Lima while hidden/API values remain untouched."""
        base = self.read("templates/base.html")
        script = self.read("static/timezone_display.js")
        self.assertIn("static_url('timezone_display.js')", base)
        for marker in (
            'America/Lima', 'UTC original:', 'MutationObserver',
            'formatToParts', 'text nodes', 'INPUT', 'TEXTAREA',
        ):
            self.assertIn(marker, script)
        # Display conversion must not be implemented by rewriting server/API
        # fields in templates; the raw values remain available for audit and
        # optimistic concurrency checks.
        self.assertIn('expected_updated_at', self.read("templates/media_screens.html"))

    def test_gideon_rx_public_branding_has_original_spacecraft_identity(self):
        branding_path = LINUX.parent / "config" / "branding.json"
        windows_branding_path = WINDOWS.parent / "config" / "branding.json"
        self.assertTrue(branding_path.is_file(), branding_path)
        self.assertTrue(windows_branding_path.is_file(), windows_branding_path)
        self.assertEqual(branding_path.read_bytes(), windows_branding_path.read_bytes())
        branding = branding_path.read_text(encoding="utf-8-sig")
        defaults_path = LINUX.parent / "gideon_branding.py"
        windows_defaults_path = WINDOWS.parent / "gideon_branding.py"
        self.assertTrue(defaults_path.is_file(), defaults_path)
        self.assertTrue(windows_defaults_path.is_file(), windows_defaults_path)
        self.assertEqual(defaults_path.read_bytes(), windows_defaults_path.read_bytes())
        defaults = defaults_path.read_text(encoding="utf-8-sig")
        base = self.read("templates/base.html")
        auth = self.read("templates/auth_base.html")
        logo = self.read("static/gideon-rx-logo.svg")
        legacy_brand = "D" + "PP"
        for source in (branding, defaults, base, auth):
            self.assertIn("Gideon Rx", source)
            self.assertNotIn(legacy_brand, source)
        for marker in ("<svg", "Silueta original", "Gideon Rx", "<path"):
            self.assertIn(marker, logo)
        self.assertIn("static_url('gideon-rx-logo.svg')", base)
        self.assertIn('"bundle_id": "org.gideonrx.agent"', branding)

    def test_media_edits_carry_optimistic_version_tokens(self):
        """Concurrent Marketing edits must fail explicitly rather than overwrite."""
        app = self.read("app.py")
        store = self.read("media_campaigns.py")
        asset_edit = self.read("templates/media_asset_edit.html")
        screens = self.read("templates/media_screens.html")
        for template in (asset_edit, screens):
            self.assertIn('name="version_token"', template)
            self.assertIn('name="expected_updated_at"', template)
        for marker in (
            "def _request_version_token(", "expected_version_token=_request_version_token(request, payload)",
            '"ETag":', "expected_updated_at=str(form.get(\"expected_updated_at\") or \"\")",
        ):
            self.assertIn(marker, app)
        for marker in (
            "_assert_expected_version(", "def update_media_asset", "def update_screen",
            "def save_campaign_revision", "version_token",
        ):
            self.assertIn(marker, store)


if __name__ == "__main__":
    unittest.main(verbosity=2)
