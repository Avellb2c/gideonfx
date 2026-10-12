"""Regression checks for interactive remote sessions and durable MFA reuse."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
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


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"No se pudo cargar {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


remote_credentials_module = _load_module(
    "gideon_test_remote_credentials", LINUX_APP / "gideon_web_admin/remote_credentials.py"
)
step_up_module = _load_module(
    "gideon_test_step_up_cache", LINUX_APP / "gideon_web_admin/step_up_cache.py"
)
RemoteCredentialError = remote_credentials_module.RemoteCredentialError
RemoteCredentialVault = remote_credentials_module.RemoteCredentialVault
PersistentStepUpCache = step_up_module.PersistentStepUpCache
build_remote_scope_key = step_up_module.build_remote_scope_key


class RemoteInteractiveMfaTests(unittest.TestCase):
    def test_remote_mfa_scope_survives_short_client_ip_changes(self):
        common = {"user_id": 7, "client_id": "6cc7f358-85df-4e25-a628-09995174b4cb", "user_agent": "GIDEON Test Browser"}
        first = build_remote_scope_key(remote_ip="190.0.2.10", **common)
        second = build_remote_scope_key(remote_ip="2001:db8::10", **common)
        self.assertEqual(first, second)
        self.assertNotEqual(
            first,
            build_remote_scope_key(
                user_id=7,
                client_id="31ffef16-6e58-46ec-9a3a-9997b9a959e9",
                remote_ip="190.0.2.10",
                user_agent="GIDEON Test Browser",
            ),
        )

    def test_remote_mfa_authorization_is_durable_but_totp_is_not_stored(self):
        with tempfile.TemporaryDirectory(prefix="gideon-remote-stepup-") as td:
            db = Path(td) / "step-up.sqlite3"
            first = PersistentStepUpCache(db)
            scope = build_remote_scope_key(
                user_id=7,
                client_id="6cc7f358-85df-4e25-a628-09995174b4cb",
                remote_ip="190.0.2.10",
                user_agent="GIDEON Test Browser",
            )
            first.remote_mark(scope_key=scope, user_id=7, issued_session_id=11, ttl_seconds=900, now_unix=1000)
            restarted = PersistentStepUpCache(db)
            status = restarted.remote_status(scope_key=scope, user_id=7, ttl_seconds=900, now_unix=1010)
            self.assertTrue(status["active"])
            self.assertEqual(890, status["remaining_seconds"])
            self.assertNotIn(b"123456", db.read_bytes())

    def test_linux_fallback_uses_the_systemd_writable_state_directory(self):
        source = (LINUX_APP / "gideon_web_admin/step_up_cache.py").read_text(encoding="utf-8-sig")
        self.assertIn('return Path("/var/lib/gideon/web") / _DB_FILENAME', source)
        self.assertNotIn('return Path("/var/lib/gideon-web-admin") / _DB_FILENAME', source)

    def test_interactive_rdp_allows_os_login_but_vnc_still_requires_password(self):
        with tempfile.TemporaryDirectory(prefix="gideon-remote-credential-") as td:
            vault = RemoteCredentialVault(Path(td))
            credential_id = vault.create_ephemeral(
                protocol="RDP",
                username="operator",
                password="",
                user_id=7,
                web_session_id=11,
            )
            revealed = vault.reveal_for_session(
                credential_id,
                protocol="RDP",
                user_id=7,
                web_session_id=11,
            )
            self.assertEqual("operator", revealed["username"])
            self.assertEqual("", revealed["password"])
            with self.assertRaises(RemoteCredentialError):
                vault.create_ephemeral(
                    protocol="VNC",
                    username="",
                    password="",
                    user_id=7,
                    web_session_id=11,
                )

    def test_one_password_is_reused_only_in_memory_for_four_security_modes(self):
        with tempfile.TemporaryDirectory(prefix="gideon-remote-credential-cycle-") as td:
            root = Path(td)
            vault = RemoteCredentialVault(root)
            secret = "NotPersisted-Password-1!"
            credential_id = vault.create_ephemeral(
                protocol="RDP",
                username="operator",
                password=secret,
                domain="WORKSTATION",
                user_id=7,
                web_session_id=11,
                max_uses=4,
                ttl_seconds=600,
            )
            self.assertTrue(vault.ephemeral_available(
                credential_id, protocol="RDP", user_id=7, web_session_id=11
            ))
            self.assertFalse(vault.ephemeral_available(
                credential_id, protocol="RDP", user_id=7, web_session_id=12
            ))
            for expected_remaining in (3, 2, 1, 0):
                revealed = vault.reveal_for_session(
                    credential_id, protocol="RDP", user_id=7, web_session_id=11
                )
                self.assertEqual(secret, revealed["password"])
                self.assertEqual("WORKSTATION", revealed["domain"])
                self.assertEqual(expected_remaining > 0, vault.ephemeral_available(
                    credential_id, protocol="RDP", user_id=7, web_session_id=11
                ))
            with self.assertRaises(RemoteCredentialError):
                vault.reveal_for_session(
                    credential_id, protocol="RDP", user_id=7, web_session_id=11
                )
            self.assertNotIn(secret.encode("utf-8"), (vault.metadata_path).read_bytes())
            self.assertEqual([], list(root.rglob("credential-*.fernet")))

    def test_ephemeral_password_allows_one_extra_in_memory_handoff_read(self):
        with tempfile.TemporaryDirectory(prefix="gideon-remote-credential-handoff-") as td:
            vault = RemoteCredentialVault(Path(td))
            secret = "Memory-Only-Handoff-1!"
            credential_id = vault.create_ephemeral(
                protocol="RDP", username="operator", password=secret,
                user_id=7, web_session_id=11, max_uses=5, ttl_seconds=600,
            )
            for _ in range(5):
                revealed = vault.reveal_for_session(
                    credential_id, protocol="RDP", user_id=7, web_session_id=11
                )
                self.assertEqual(secret, revealed["password"])
                revealed.clear()
            self.assertFalse(vault.ephemeral_available(
                credential_id, protocol="RDP", user_id=7, web_session_id=11
            ))
            self.assertNotIn(secret.encode("utf-8"), vault.metadata_path.read_bytes())

    def test_browser_uses_durable_client_id_and_only_remembers_username(self):
        for app in (LINUX_APP, WINDOWS_APP):
            js = (app / "gideon_web_admin/static/remote_page.js").read_text(encoding="utf-8-sig")
            viewer_js = (app / "gideon_web_admin/static/remote_viewer.js").read_text(encoding="utf-8-sig")
            template = (app / "gideon_web_admin/templates/remote.html").read_text(encoding="utf-8-sig")
            app_source = (app / "gideon_web_admin/app.py").read_text(encoding="utf-8-sig")
            self.assertIn("localStorage.getItem(key)", js)
            self.assertIn("interactiveUsernameKey", js)
            self.assertNotIn("localStorage.setItem('interactive_password'", js)
            self.assertIn("protocol.value==='VNC'&&!interactivePassword.value", js)
            self.assertIn('id="remoteInteractiveCompatibility"', template)
            self.assertIn("static_url('remote_page.js')", template)
            self.assertIn('id="remoteMfaReuseNotice"', template)
            self.assertIn("obligatoria para el ciclo automático RDP o VNC", template)
            self.assertIn("renderMfaRequirement(stepUpActive)", js)
            self.assertIn("protocol.value==='RDP'&&!interactivePassword.value", js)
            self.assertIn("RDP_NLA_PASSWORD_REQUIRED", app_source)
            self.assertIn("RDP_PASSWORD_REQUIRED", app_source)
            self.assertIn("RDP_NLA_PASSWORD_REQUIRED", viewer_js)
            self.assertIn("gideon.remote.interactive.username.v1", viewer_js)


if __name__ == "__main__":
    unittest.main()
