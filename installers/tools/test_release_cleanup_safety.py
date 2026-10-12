"""Regression checks for the two-phase WebAdmin release cleanup."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
APP_ROOT = ROOT / "payload" / "linux" / "app"
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from gideon_web_admin.gateway import WebAgentReleaseManager  # noqa: E402


class ReleaseCleanupSafetyTests(unittest.TestCase):
    def _manager_with_rows(self, root: Path) -> tuple[WebAgentReleaseManager, list[dict[str, object]]]:
        manager = WebAgentReleaseManager(APP_ROOT, root, gateway=None, security_assets=None)
        rows: list[dict[str, object]] = []
        for version in ("1.0.0", "1.1.0", "1.2.0"):
            bundle = manager.artifacts / f"agent-{version}.zip"
            bundle.write_bytes(version.encode("ascii"))
            rows.append({
                "platform": "linux", "architecture": "x86_64", "channel": "stable",
                "version": version, "sha256": version.replace(".", "a"),
                "bundle": str(bundle), "created_at": f"2026-09-15T00:00:{version[2:3]}0+00:00",
            })
        manager.release_file.write_text(json.dumps(rows), encoding="utf-8")
        return manager, rows

    def test_dry_run_does_not_mutate_bundles_or_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            manager, rows = self._manager_with_rows(Path(td))
            allowed = {manager.release_key(row) for row in rows}
            result = manager.cleanup(keep_per_target=1, allowed_releases=allowed, dry_run=True)
            self.assertTrue(result["Ok"])
            self.assertTrue(result["DryRun"])
            self.assertEqual(2, result["DeletedCount"])
            self.assertGreater(result["DeletedBytes"], 0)
            self.assertEqual(3, len(manager.local_releases()))
            self.assertTrue(all(Path(str(row["bundle"])).is_file() for row in rows))

    def test_gateway_protection_wins_and_only_confirmed_remote_deletions_prune_local(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            manager, rows = self._manager_with_rows(Path(td))
            protected = {manager.release_key(rows[0])}
            allowed = {manager.release_key(rows[0]), manager.release_key(rows[1])}
            result = manager.cleanup(
                keep_per_target=1,
                protected_releases=protected,
                allowed_releases=allowed,
            )
            self.assertTrue(result["Ok"])
            self.assertEqual(1, result["DeletedCount"])
            self.assertEqual("1.1.0", result["Deleted"][0]["version"])
            self.assertTrue(Path(str(rows[0]["bundle"])).is_file())
            self.assertFalse(Path(str(rows[1]["bundle"])).exists())
            self.assertTrue(Path(str(rows[2]["bundle"])).is_file())
            self.assertEqual({"1.0.0", "1.2.0"}, {str(row["version"]) for row in manager.local_releases()})

    def test_cleanup_route_plans_gateway_before_touching_local_artifacts(self) -> None:
        source = (APP_ROOT / "gideon_web_admin" / "app.py").read_text(encoding="utf-8-sig")
        route = source[source.index('async def releases_cleanup'):source.index('def installers_context')]
        self.assertLess(route.index("dry_run=True"), route.index("dry_run=False"))
        self.assertLess(route.index("dry_run=False"), route.index("release_manager.cleanup"))

    def test_reverse_tunnel_uses_advertised_service_port_on_start_and_retry(self) -> None:
        source = (APP_ROOT / "gideon_web_admin" / "app.py").read_text(encoding="utf-8-sig")
        start = source[source.index('async def remote_start'):source.index('def _remote_session_audit_rows')]
        retry = source[source.index('async def _remote_retry_target'):source.index('@app.get("/remote/session/{session_id}/diagnostics.json")')]
        self.assertIn("target_port=target_port", start)
        self.assertIn("select_agent_remote_profile(agent)", retry)
        self.assertIn("target_port=advertised_port", retry)


if __name__ == "__main__":
    unittest.main(verbosity=2)
