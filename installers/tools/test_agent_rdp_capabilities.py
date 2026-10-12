"""Regression checks for Agent-driven RDP negotiation selection."""
from __future__ import annotations

import datetime as dt
import importlib.util
import os
from pathlib import Path
import sys
import unittest


ROOT = Path(os.environ.get("GIDEON_TEST_ROOT") or Path(__file__).resolve().parents[2]).resolve()
LINUX_APP = Path(os.environ.get("GIDEON_TEST_APP") or (ROOT / "payload/linux/app")).resolve()
WINDOWS_APP = Path(os.environ.get("GIDEON_TEST_WINDOWS_APP") or (ROOT / "payload/windows/GIDEON Remote Control/app")).resolve()


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


agent_cap = _load("gideon_test_agent_rdp_capability", LINUX_APP / "gideon_agent_rdp_capability.py")
web_cap = _load("gideon_test_web_rdp_capability", LINUX_APP / "gideon_web_admin/rdp_capabilities.py")


class AgentRdpCapabilityTests(unittest.TestCase):
    def _windows(self, *, edition="Education", nla=1, layer=1, ready=True):
        return agent_cap.detect_rdp_capability(
            system_name="windows",
            registry_snapshot={
                "edition_id": edition,
                "product_name": "Windows 10 Education",
                "display_version": "1909",
                "build": "18363",
                "deny_connections": 0,
                "nla_required": nla,
                "security_layer": layer,
                "min_encryption_level": 3,
                "listener_port": 3389,
                "certificate_thumbprint": "AABBCC",
            },
            service_running=True,
            socket_ready=ready,
        )

    def test_windows_registry_selects_nla_tls_and_explicit_legacy(self):
        nla = self._windows(nla=1, layer=1)
        self.assertEqual("nla", nla["RecommendedSecurity"])
        self.assertFalse(nla["AllowLegacyRdp"])
        tls = self._windows(nla=0, layer=2)
        self.assertEqual("tls", tls["RecommendedSecurity"])
        legacy = self._windows(nla=0, layer=0)
        self.assertEqual("rdp", legacy["RecommendedSecurity"])
        self.assertTrue(legacy["AllowLegacyRdp"])

    def test_windows_home_is_reported_unsupported_without_third_party_fallback(self):
        home = self._windows(edition="CoreSingleLanguage", nla=0, layer=1)
        self.assertFalse(home["Supported"])
        self.assertFalse(home["Usable"])
        self.assertEqual("", home["RecommendedSecurity"])

    def test_windows_session_model_does_not_promise_desktop_concurrency(self):
        workstation = self._windows()
        self.assertEqual("single-interactive-session", workstation["SessionModel"]["Kind"])
        self.assertFalse(workstation["SessionModel"]["ConcurrentSessionsPossible"])
        self.assertFalse(workstation["SessionModel"]["InteractiveScreenSharing"])
        self.assertIsInstance(workstation["SessionModel"]["Sessions"], list)
        self.assertIn("DisconnectedSessionCount", workstation["SessionModel"])
        server = agent_cap.detect_rdp_capability(
            system_name="windows",
            registry_snapshot={
                "edition_id": "ServerStandard",
                "product_name": "Windows Server 2025 Standard",
                "product_type": "ServerNT",
                "deny_connections": 0,
                "nla_required": 1,
                "security_layer": 1,
                "listener_port": 3389,
            },
            service_running=True,
            socket_ready=True,
        )
        self.assertEqual("multi-session-capable", server["SessionModel"]["Kind"])
        self.assertTrue(server["SessionModel"]["ConcurrentSessionsPossible"])

    def test_webadmin_accepts_only_fresh_capability_from_online_tunnel(self):
        now = 2_000_000_000
        stamp = dt.datetime.fromtimestamp(now - 20, tz=dt.timezone.utc).isoformat()
        row = {
            "last_seen": stamp,
            "reverse_tunnel_online": True,
            "Capabilities": {"RemoteAccess": {"RDP": self._windows(nla=0, layer=2)}},
        }
        selected = web_cap.select_agent_rdp_profile(row, now_unix=now)
        self.assertTrue(selected["valid"])
        self.assertEqual("tls", selected["preferred_security"])
        self.assertIsInstance(selected["sessions"], list)
        row["last_seen"] = dt.datetime.fromtimestamp(now - 1000, tz=dt.timezone.utc).isoformat()
        stale = web_cap.select_agent_rdp_profile(row, now_unix=now, fallback_security="nla")
        self.assertFalse(stale["valid"])
        self.assertEqual("nla", stale["preferred_security"])

    def test_runtime_and_web_sources_are_mirrored_and_packaged(self):
        for relative in ("gideon_agent_rdp_capability.py", "gideon_web_admin/rdp_capabilities.py"):
            self.assertEqual((LINUX_APP / relative).read_bytes(), (WINDOWS_APP / relative).read_bytes())
        for root in (LINUX_APP, WINDOWS_APP):
            payload = (root / "gideon_agent_payload.py").read_text(encoding="utf-8-sig")
            agent = (root / "gideon_agent.py").read_text(encoding="utf-8-sig")
            app = (root / "gideon_web_admin/app.py").read_text(encoding="utf-8-sig")
            self.assertIn('"gideon_agent_rdp_capability.py"', payload)
            self.assertIn("detect_rdp_capability", agent)
            self.assertIn("select_agent_rdp_profile", app)
            self.assertIn("rdp_security_plan=security_modes", app)


if __name__ == "__main__":
    unittest.main()
