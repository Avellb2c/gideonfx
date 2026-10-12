"""Regression checks for the capability-led remote-control intent picker.

The picker must describe the real transport/session consequences before a
ticket is issued.  These checks deliberately inspect both installable app
trees: a clean Windows OneClick install must not silently lose a safety or UX
rule which is present in the Linux/cloud source tree.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = (
    Path(os.environ["GIDEON_TEST_ROOT"]).resolve()
    if os.environ.get("GIDEON_TEST_ROOT")
    else Path(__file__).resolve().parents[2]
)
LINUX_APP = Path(os.environ.get("GIDEON_TEST_APP") or (ROOT / "payload/linux/app")).resolve()
WINDOWS_APP = Path(
    os.environ.get("GIDEON_TEST_WINDOWS_APP") or (ROOT / "payload/windows/GIDEON Remote Control/app")
).resolve()
sys.path.insert(0, str(LINUX_APP))


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"No se pudo cargar {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


remote_sessions_module = _load_module(
    "gideon_test_remote_sessions_intent", LINUX_APP / "gideon_web_admin/remote_sessions.py"
)
RemoteSessionPolicy = remote_sessions_module.RemoteSessionPolicy
RemoteSessionStore = remote_sessions_module.RemoteSessionStore


class RemoteIntentPickerTests(unittest.TestCase):
    def test_linux_and_windows_guided_intent_assets_are_mirrored(self):
        """The cloud source and clean Windows install must present one contract."""
        for relative in (
            "gideon_web_admin/app.py",
            "gideon_web_admin/remote_sessions.py",
            "gideon_web_admin/static/remote_page.js",
            "gideon_web_admin/static/remote_viewer.js",
            "gideon_web_admin/static/ui_hardening.css",
            "gideon_web_admin/static/remote_viewer.css",
            "gideon_web_admin/static/workflow_forms.css",
            "gideon_web_admin/static/table_controls.css",
            "gideon_web_admin/static/table_controls.js",
            "gideon_web_admin/templates/base.html",
            "gideon_web_admin/templates/remote.html",
            "gideon_web_admin/templates/remote_viewer.html",
            "gideon_web_admin/templates/remote_window.html",
        ):
            self.assertEqual(
                (LINUX_APP / relative).read_bytes(),
                (WINDOWS_APP / relative).read_bytes(),
                f"Las copias Linux/Windows difieren: {relative}",
            )

    def test_picker_offers_clear_source_and_capability_filters(self):
        for app_root in (LINUX_APP, WINDOWS_APP):
            template = (app_root / "gideon_web_admin/templates/remote.html").read_text(encoding="utf-8-sig")
            self.assertIn("Equipo con Agent", template)
            self.assertIn("Host directo", template)
            self.assertIn('id="remotePlatformFilter"', template)
            self.assertIn('id="remoteAvailabilityFilter"', template)
            self.assertIn('id="remoteTunnelFilter"', template)
            self.assertIn('placeholder="Buscar por sede, código, equipo, SO o IP"', template)
            for attribute in (
                "data-source-type=",
                "data-source-platform=",
                "data-source-ready=",
                "data-source-tunnel=",
                "data-source-status=",
                "data-active-console-user=",
                "data-rdp-concurrent=",
            ):
                self.assertIn(attribute, template)

    def test_agent_detail_quick_action_preselects_without_hiding_inventory(self):
        """``/remote?agent_id=...`` must not turn the picker into a one-row view."""
        for app_root in (LINUX_APP, WINDOWS_APP):
            backend = (app_root / "gideon_web_admin/app.py").read_text(encoding="utf-8-sig")
            template = (app_root / "gideon_web_admin/templates/remote.html").read_text(encoding="utf-8-sig")
            self.assertIn('agent_filter = str(request.query_params.get("agent_id") or "").strip()', backend)
            self.assertIn('"selected_agent_id": agent_filter', backend)
            self.assertIn("agents.append(item)", backend)
            self.assertNotIn(
                'if not agent_filter or str(item.get("agent_id") or "") == agent_filter:',
                backend,
            )
            self.assertIn("GIDEON muestra todos los Agents enrolados", template)

    def test_default_picker_recovers_all_rows_after_browser_form_restore(self):
        """A restored hidden attribute must not turn the default inventory into zero rows."""
        for app_root in (LINUX_APP, WINDOWS_APP):
            js = (app_root / "gideon_web_admin/static/remote_page.js").read_text(encoding="utf-8-sig")
            template = (app_root / "gideon_web_admin/templates/remote.html").read_text(encoding="utf-8-sig")
            self.assertIn("const defaultInventoryView=selectedSourceFilter==='ALL'", js)
            self.assertIn("sourceRows.forEach(row=>{row.hidden=false;});", js)
            self.assertIn("section.hidden=false;", js)
            self.assertIn("window.addEventListener('pageshow',()=>{filterRemoteSources();});", js)
            self.assertIn("static_url('remote_page.js')", template)

    def test_picker_requires_an_explicit_operator_acknowledgement(self):
        """The preflight is not decorative: the operator must acknowledge it."""
        for app_root in (LINUX_APP, WINDOWS_APP):
            template = (app_root / "gideon_web_admin/templates/remote.html").read_text(encoding="utf-8-sig")
            js = (app_root / "gideon_web_admin/static/remote_page.js").read_text(encoding="utf-8-sig")
            backend = (app_root / "gideon_web_admin/app.py").read_text(encoding="utf-8-sig")

            self.assertIn('id="remoteIntentPicker"', template)
            self.assertIn('id="remoteIntentAcknowledged"', template)
            self.assertIn('name="intent_acknowledged"', template)
            for intent in ("PHYSICAL_CONSOLE", "INDEPENDENT_SESSION", "ADMIN_CONSOLE"):
                self.assertIn(f'name="connection_intent" value="{intent}"', template)
            self.assertIn("renderIntentPicker", js)
            self.assertIn("remoteIntentAcknowledged", js)
            self.assertIn("renderPreflight", js)
            self.assertIn("REMOTE_INTENT_ACK_REQUIRED", backend)
            self.assertIn("intent_acknowledged", backend)
            self.assertIn("IntentAcknowledged=", backend)
            self.assertIn("connection_intent", backend)
            for intent in ("PHYSICAL_CONSOLE", "INDEPENDENT_SESSION", "ADMIN_CONSOLE"):
                self.assertIn(f'"{intent}"', backend)

    def test_preflight_uses_reported_capabilities_and_never_fakes_screen_share(self):
        """Physical-console control is offered only if the Agent actually reports it."""
        for app_root in (LINUX_APP, WINDOWS_APP):
            js = (app_root / "gideon_web_admin/static/remote_page.js").read_text(encoding="utf-8-sig")
            backend = (app_root / "gideon_web_admin/app.py").read_text(encoding="utf-8-sig")

            self.assertIn("physical-console", js)
            self.assertIn("activeUser", js)
            self.assertIn("SEPARATE", js)
            self.assertIn("SHARE", js)
            self.assertIn("REMOTE_INTERACTIVE_SHARE_UNAVAILABLE", backend)
            # A Linux-only UI gate would make future Windows/Raspberry physical
            # console transports invisible even when the Agent announces them.
            self.assertNotIn("const linuxAgent=", js)

    def test_vault_identity_is_used_when_estimating_a_windows_handoff(self):
        """A Vault credential must receive the same accurate impact preflight as interactive RDP."""
        for app_root in (LINUX_APP, WINDOWS_APP):
            backend = (app_root / "gideon_web_admin/app.py").read_text(encoding="utf-8-sig")
            self.assertIn("selected_vault_credential", backend)
            self.assertIn("rdp_identity_matches_console", backend)
            self.assertIn("session_switch_expected", backend)

    def test_selected_session_mode_persists_through_a_ticket_retry(self):
        """The stored ticket remains the server-side record of the chosen intent."""
        policy = RemoteSessionPolicy(
            clipboard_enabled=True,
            file_transfer_enabled=True,
            max_clipboard_bytes=1024 * 1024,
            max_file_transfer_bytes=1024 * 1024,
        )
        with tempfile.TemporaryDirectory(prefix="gideon-remote-intent-") as td:
            store = RemoteSessionStore(Path(td), policy)
            first, _ = store.issue(
                user_id=7,
                web_session_id=11,
                username="operator",
                source_type="AGENT",
                source_id="agent-1",
                source_label="Equipo con Agent",
                target_host="127.0.0.1",
                target_port=3389,
                protocol="RDP",
                credential_id="ephemeral-1",
                client_ip="190.0.2.10",
                credential_mode="INTERACTIVE",
                max_attempts=3,
                rdp_session_mode="SEPARATE",
                connection_intent="INDEPENDENT_SESSION",
                local_session_impact="INDEPENDENT_SESSION",
                operator_acknowledged=True,
                consent_state="NOT_APPLICABLE",
            )
            self.assertEqual("SEPARATE", first["rdp_session_mode"])
            self.assertEqual("INDEPENDENT_SESSION", first["connection_intent"])
            self.assertEqual("INDEPENDENT_SESSION", first["local_session_impact"])
            self.assertEqual(1, first["operator_acknowledged"])
            self.assertGreater(first["operator_ack_unix"], 0)
            store.close(first["session_id"])
            retry, _ = store.issue_retry(
                previous_session_id=first["session_id"],
                user_id=7,
                web_session_id=11,
                username="operator",
                credential_id="ephemeral-2",
                client_ip="190.0.2.10",
            )
            self.assertEqual("SEPARATE", retry["rdp_session_mode"])
            visible = store.get_for_user(retry["session_id"], 7)
            self.assertIsNotNone(visible)
            self.assertEqual("SEPARATE", visible["rdp_session_mode"])
            self.assertEqual("INDEPENDENT_SESSION", visible["connection_intent"])
            self.assertEqual("INDEPENDENT_SESSION", visible["local_session_impact"])
            self.assertEqual(1, visible["operator_acknowledged"])
            self.assertNotIn("credential_id", visible)


if __name__ == "__main__":
    unittest.main()
