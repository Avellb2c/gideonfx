"""Regression checks for the persistent WebAdmin site catalog."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
LINUX_APP = ROOT / "payload/linux/app"
WINDOWS_APP = ROOT / "payload/windows/GIDEON Remote Control/app"
APP_ROOTS = (LINUX_APP, WINDOWS_APP)


class SiteCatalogContractTests(unittest.TestCase):
    def test_security_schema_and_api_exist_in_both_payloads(self):
        for app_root in APP_ROOTS:
            source = (app_root / "gideon_web_admin/auth.py").read_text(encoding="utf-8-sig")
            self.assertIn("CREATE TABLE IF NOT EXISTS web_sites", source)
            self.assertIn("def list_sites(", source)
            self.assertIn("def create_site(", source)
            self.assertIn('"sites.create"', source)

    def test_builder_uses_managed_and_detected_sites(self):
        for app_root in APP_ROOTS:
            source = (app_root / "gideon_web_admin/agent_installers.py").read_text(encoding="utf-8-sig")
            self.assertIn("for raw in self.gateway.agents()", source)
            self.assertIn('getattr(self.security, "list_sites", None)', source)
            self.assertIn('"managed": True', source)
            self.assertIn("catálogo de Sedes de WebAdmin", source)

    def test_sites_page_exposes_create_route_and_installer_link(self):
        for app_root in APP_ROOTS:
            app_source = (app_root / "gideon_web_admin/app.py").read_text(encoding="utf-8-sig")
            template = (app_root / "gideon_web_admin/templates/sites.html").read_text(encoding="utf-8-sig")
            self.assertIn('@app.post("/sites/create"', app_source)
            self.assertIn("security.create_site(", app_source)
            self.assertIn('action="/sites/create"', template)
            self.assertIn('href="/installers"', template)
            self.assertIn("Disponible en instaladores", template)

    @unittest.skipUnless(os.name == "nt", "bundled Windows WebAdmin runtime")
    def test_real_store_round_trip_and_builder_merge(self):
        python = ROOT / "payload/windows/GIDEON Remote Control/venv/Scripts/python.exe"
        if not python.exists():
            self.skipTest("Windows WebAdmin venv is not bundled")
        script = textwrap.dedent(
            """
            from pathlib import Path
            import tempfile
            from gideon_web_admin.auth import SecurityStore
            from gideon_web_admin.agent_installers import WebAgentInstallerManager

            class Gateway:
                def agents(self):
                    return [
                        {"site_code": "18601", "site_name": "OLD", "platform": "windows"},
                        {"site_code": "18610", "site_name": "SURCO", "platform": "windows"},
                    ]

            with tempfile.TemporaryDirectory(prefix="gideon-sites-") as td:
                root = Path(td)
                store = SecurityStore(root / "security.sqlite3")
                code = store.create_site("18601", "SISTEMAS", "Principal", actor="test")
                assert code == "18601"
                assert store.list_sites()[0]["site_name"] == "SISTEMAS"
                manager = WebAgentInstallerManager.__new__(WebAgentInstallerManager)
                manager.app_root = root
                manager.security = store
                manager.gateway = Gateway()
                rows = manager.sites()
                assert [(x["code"], x["name"]) for x in rows] == [
                    ("18601", "SISTEMAS"), ("18610", "SURCO")
                ]
                assert manager.resolve_site("18601") == ("18601", "SISTEMAS")
            print("SITE_CATALOG_RUNTIME=PASS")
            """
        )
        env = dict(os.environ)
        env["PYTHONPATH"] = str(WINDOWS_APP)
        env["GIDEON_WEB_TOTP_ENCRYPTION_KEY"] = ""
        result = subprocess.run(
            [str(python), "-c", script], cwd=str(ROOT), env=env,
            capture_output=True, text=True, timeout=60, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("SITE_CATALOG_RUNTIME=PASS", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
