"""Regression checks for installer-owned Gateway migration on every Agent OS."""
from __future__ import annotations

from pathlib import Path
import hashlib
import unittest


ROOT = Path(__file__).resolve().parents[2]
LINUX_APP = ROOT / "payload/linux/app"
WINDOWS_APP = ROOT / "payload/windows/GIDEON Remote Control/app"


class AgentGatewayMigrationTests(unittest.TestCase):
    def _pair(self, relative: str) -> tuple[str, str]:
        linux_copy = (LINUX_APP / relative).read_text(encoding="utf-8-sig")
        windows_copy = (WINDOWS_APP / relative).read_text(encoding="utf-8-sig")
        self.assertEqual(
            hashlib.sha256(linux_copy.encode()).hexdigest(),
            hashlib.sha256(windows_copy.encode()).hexdigest(),
            f"Las copias Linux/Windows difieren: {relative}",
        )
        return linux_copy, windows_copy

    def test_windows_package_gateway_wins_over_previous_install(self):
        setup, _ = self._pair("deploy/agent/windows/gideon-agent-setup.ps1")
        self.assertIn("PACKAGE_GATEWAY_AUTHORITY", setup)
        self.assertIn("GATEWAY_MIGRATION_REENROLL", setup)
        self.assertIn("if([string]::IsNullOrWhiteSpace($Gateway)){ $Gateway=$PackagedGateway }", setup)
        self.assertNotIn("$Gateway=$existingGateway", setup)
        self.assertIn("Reset-GideonStaleTokenForReenrollment $config $Enroll", setup)
        self.assertIn("Gateway: {3}", setup)

    def test_linux_package_gateway_migrates_token_safely(self):
        setup, _ = self._pair("deploy/agent/linux/gideon-agent-setup")
        self.assertIn("PACKAGE_GATEWAY_AUTHORITY", setup)
        self.assertIn("GATEWAY_MIGRATION_REENROLL", setup)
        self.assertIn('if [[ -z "$gateway" ]]; then gateway="$package_gateway"; fi', setup)
        self.assertIn('if [[ -s "$CONFIG" && "$gateway_changed" -eq 1 ]]', setup)
        self.assertIn('cfg.pop("agent_token",None)', setup)
        self.assertIn('r.pop(k,None)', setup)
        self.assertNotIn('"$STATE/agent.runtime.json" "$secret"', setup)

    def test_macos_package_gateway_migrates_token_safely(self):
        setup, _ = self._pair("deploy/agent/macos/gideon-agent-setup")
        self.assertIn("PACKAGE_GATEWAY_AUTHORITY", setup)
        self.assertIn("GATEWAY_MIGRATION_REENROLL", setup)
        self.assertIn('if [[ -z "$gateway" ]]; then gateway="$package_gateway"; fi', setup)
        self.assertIn('if [[ -s "$CONFIG" && "$gateway_changed" -eq 1 ]]', setup)
        self.assertIn('cfg.pop("agent_token",None)', setup)
        self.assertIn('r.pop(k,None)', setup)
        self.assertNotIn('"$STATE/agent.runtime.json" "$secret"', setup)


if __name__ == "__main__":
    unittest.main()
