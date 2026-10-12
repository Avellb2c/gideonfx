"""Regression checks for remote keyboard focus, clipboard and file transfer."""
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


guacamole_module = _load_module(
    "gideon_test_guacamole_transfer", LINUX_APP / "gideon_web_admin/guacamole.py"
)
remote_sessions_module = _load_module(
    "gideon_test_remote_sessions_transfer", LINUX_APP / "gideon_web_admin/remote_sessions.py"
)
GuacdClient = guacamole_module.GuacdClient
GuacdConfig = guacamole_module.GuacdConfig
RemoteSessionPolicy = remote_sessions_module.RemoteSessionPolicy
RemoteSessionStore = remote_sessions_module.RemoteSessionStore


class RemoteClipboardTransferTests(unittest.TestCase):
    def test_linux_and_windows_remote_assets_are_mirrored(self):
        for relative in (
            "gideon_web_admin/guacamole.py",
            "gideon_web_admin/app.py",
            "gideon_web_admin/remote_sessions.py",
            "gideon_web_admin/static/remote_page.js",
            "gideon_web_admin/static/remote_viewer.js",
            "gideon_web_admin/static/ui_hardening.css",
            "gideon_web_admin/templates/remote.html",
            "gideon_web_admin/templates/remote_viewer.html",
        ):
            self.assertEqual(
                (LINUX_APP / relative).read_bytes(),
                (WINDOWS_APP / relative).read_bytes(),
                f"Las copias Linux/Windows difieren: {relative}",
            )

    def test_keyboard_is_scoped_to_remote_surface_and_modal_can_receive_text(self):
        for app_root in (LINUX_APP, WINDOWS_APP):
            js = (app_root / "gideon_web_admin/static/remote_viewer.js").read_text(encoding="utf-8-sig")
            self.assertIn("new Guacamole.Keyboard(displayRoot)", js)
            self.assertNotIn("new Guacamole.Keyboard(doc)", js)
            self.assertIn("retryUsername?.value.trim()?retryPassword:retryUsername", js)

    def test_rdp_values_authorize_clipboard_and_isolated_temporary_drive(self):
        client = GuacdClient(GuacdConfig())
        values = client._connection_values(
            "rdp",
            target_host="127.0.0.1",
            target_port=3389,
            credential={"username": "operator", "password": "temporary"},
            width=1440,
            height=900,
            dpi=96,
            session_id="rs_safe/../name",
            clipboard_enabled=True,
            file_transfer_enabled=True,
        )
        self.assertEqual("false", values["disable-copy"])
        self.assertEqual("false", values["disable-paste"])
        self.assertEqual("true", values["enable-drive"])
        self.assertEqual("true", values["create-drive-path"])
        self.assertEqual("GIDEON Transfer", values["drive-name"])
        self.assertEqual("/tmp/gideon-transfer-rs_safename", values["drive-path"])

    def test_rdp_profile_is_lean_for_constrained_windows_hosts(self):
        client = GuacdClient(GuacdConfig())
        values = client._connection_values(
            "rdp",
            target_host="127.0.0.1",
            target_port=3389,
            credential={"username": "operator", "password": "temporary"},
            width=1440,
            height=900,
            dpi=96,
            clipboard_enabled=True,
            file_transfer_enabled=False,
        )
        self.assertEqual("16", values["color-depth"])
        self.assertEqual("false", values["enable-desktop-composition"])
        self.assertEqual("false", values["force-lossless"])
        self.assertEqual("true", values["disable-audio"])
        self.assertEqual("false", values["enable-drive"])
        self.assertEqual("false", values["disable-bitmap-caching"])

    def test_vnc_uses_local_cursor_to_avoid_pointer_redraw_floods(self):
        client = GuacdClient(GuacdConfig())
        values = client._connection_values(
            "vnc",
            target_host="127.0.0.1",
            target_port=5900,
            credential={"username": "physical-console", "password": ""},
            width=1280,
            height=768,
            dpi=96,
        )
        self.assertNotIn("cursor", values)
        self.assertEqual("false", values["read-only"])
        # Browser-side fit is intentional.  The physical WayVNC output must
        # never be resized by a Guacamole VNC client.
        self.assertEqual("true", values["disable-display-resize"])

    def test_remote_page_makes_file_transfer_explicit_and_server_honors_selection(self):
        for app_root in (LINUX_APP, WINDOWS_APP):
            template = (app_root / "gideon_web_admin/templates/remote.html").read_text(encoding="utf-8-sig")
            app = (app_root / "gideon_web_admin/app.py").read_text(encoding="utf-8-sig")
            self.assertIn('name="clipboard_enabled" value="1" checked', template)
            self.assertIn('name="file_transfer_enabled" id="remoteFileTransferEnabled" value="1"', template)
            self.assertNotIn('name="file_transfer_enabled" id="remoteFileTransferEnabled" value="1" checked', template)
            self.assertIn("clipboard_enabled=clipboard_enabled", app)
            self.assertIn("file_transfer_enabled=file_transfer_enabled", app)
            self.assertIn("and protocol == \"RDP\"", app)

    def test_rdp_security_is_explicit_per_session(self):
        client = GuacdClient(GuacdConfig(rdp_security="nla"))
        common = {
            "target_host": "127.0.0.1",
            "target_port": 3389,
            "credential": {"username": "operator", "password": "temporary"},
            "width": 1440,
            "height": 900,
            "dpi": 96,
        }
        self.assertEqual("nla", client._connection_values("rdp", **common)["security"])
        self.assertEqual("any", client._connection_values("rdp", rdp_security="any", **common)["security"])
        self.assertEqual("tls", client._connection_values("rdp", rdp_security="tls", **common)["security"])

    def test_rdp_session_modes_are_explicit_and_capability_gated(self):
        client = GuacdClient(GuacdConfig())
        common = {
            "target_host": "127.0.0.1",
            "target_port": 3389,
            "credential": {"username": "operator", "password": "temporary"},
            "width": 1440,
            "height": 900,
            "dpi": 96,
        }
        self.assertEqual("true", client._connection_values("rdp", rdp_session_mode="ADMIN", **common)["console"])
        for mode in ("STANDARD", "RESUME", "SEPARATE"):
            self.assertEqual("false", client._connection_values("rdp", rdp_session_mode=mode, **common)["console"])
        for app_root in (LINUX_APP, WINDOWS_APP):
            template = (app_root / "gideon_web_admin/templates/remote.html").read_text(encoding="utf-8-sig")
            app = (app_root / "gideon_web_admin/app.py").read_text(encoding="utf-8-sig")
            self.assertIn('name="rdp_session_mode"', template)
            self.assertIn("RDP_SEPARATE_SESSION_UNAVAILABLE", app)
            self.assertIn("concurrent_sessions_possible", app)

    def test_session_capabilities_survive_retry_and_have_bounded_limits(self):
        policy = RemoteSessionPolicy(
            clipboard_enabled=True,
            file_transfer_enabled=True,
            max_clipboard_bytes=1024 * 1024,
            max_file_transfer_bytes=100 * 1024 * 1024,
        )
        with tempfile.TemporaryDirectory(prefix="gideon-remote-transfer-") as td:
            store = RemoteSessionStore(Path(td), policy)
            first, _ = store.issue(
                user_id=7,
                web_session_id=11,
                username="operator",
                source_type="AGENT",
                source_id="agent-1",
                source_label="Agent",
                target_host="127.0.0.1",
                target_port=3389,
                protocol="RDP",
                credential_id="ephemeral-1",
                client_ip="190.0.2.10",
                credential_mode="INTERACTIVE",
                max_attempts=3,
                rdp_security="nla",
                rdp_session_mode="ADMIN",
            )
            self.assertEqual(1, first["clipboard_enabled"])
            self.assertEqual(1, first["file_transfer_enabled"])
            store.close(first["session_id"])
            retry, _ = store.issue_retry(
                previous_session_id=first["session_id"],
                user_id=7,
                web_session_id=11,
                username="operator",
                credential_id="ephemeral-2",
                client_ip="190.0.2.10",
                rdp_security="any",
            )
            self.assertEqual(1, retry["clipboard_enabled"])
            self.assertEqual(1, retry["file_transfer_enabled"])
            self.assertEqual("nla", first["rdp_security"])
            self.assertEqual("any", retry["rdp_security"])
            self.assertEqual("ADMIN", first["rdp_session_mode"])
            self.assertEqual("ADMIN", retry["rdp_session_mode"])

    def test_viewer_distinguishes_security_negotiation_from_bad_password(self):
        for app_root in (LINUX_APP, WINDOWS_APP):
            viewer = (app_root / "gideon_web_admin/static/remote_viewer.js").read_text(encoding="utf-8-sig")
            app = (app_root / "gideon_web_admin/app.py").read_text(encoding="utf-8-sig")
            self.assertIn("RDP_SECURITY_NEGOTIATION", viewer)
            self.assertIn("next_rdp_security", viewer)
            self.assertIn('"RDP_SECURITY_NEGOTIATION"', app)
            self.assertIn('"next_rdp_security": next_security', app)
            self.assertIn('/remote/session/{session_id}/auto-retry', app)
            self.assertIn('/remote/session/{session_id}/handoff-reconnect', app)
            self.assertIn('handoff_reconnect_eligible', viewer)
            self.assertIn('windows-session-handoff-probe', viewer)
            self.assertIn("RDP_SESSION_STALL", viewer)
            self.assertIn("handoffReconnectTimer=setTimeout(()=>void probeAutomaticHandoffReconnect(),18000)", viewer)
            self.assertIn("REMOTE_AUTOMATIC_SECURITY_CLASSIFICATIONS", app)
            self.assertIn("normalize_rdp_identity", app)

    def test_viewer_exposes_explicit_transfer_controls_and_server_limits_streams(self):
        for app_root in (LINUX_APP, WINDOWS_APP):
            template = (app_root / "gideon_web_admin/templates/remote_viewer.html").read_text(encoding="utf-8-sig")
            js = (app_root / "gideon_web_admin/static/remote_viewer.js").read_text(encoding="utf-8-sig")
            app = (app_root / "gideon_web_admin/app.py").read_text(encoding="utf-8-sig")
            for marker in ('id="remoteCopy"', 'id="remotePaste"', 'id="remoteSendFile"', 'id="remoteFileInput"'):
                self.assertIn(marker, template)
            self.assertIn("createClipboardStream('text/plain')", js)
            self.assertIn("createFileStream(file.type||'application/octet-stream',safeName)", js)
            self.assertIn("MAX_FILE_BYTES=100*1024*1024", js)
            self.assertIn('"remote.session.file_upload"', app)
            self.assertIn('"remote.session.file_download"', app)
            self.assertIn("max_file_transfer_bytes", app)


if __name__ == "__main__":
    unittest.main()
