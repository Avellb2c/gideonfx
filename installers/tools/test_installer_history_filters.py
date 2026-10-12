"""Regression checks for the concise, server-side installer history controls."""
from __future__ import annotations

import os
from pathlib import Path
import sys
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
if str(LINUX_APP) not in sys.path:
    sys.path.insert(0, str(LINUX_APP))

from gideon_web_admin.installer_history import filter_installer_history  # noqa: E402


class InstallerHistoryFilterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rows = [
            {
                "build_id": "older-ready", "status": "READY", "target_id": "linux-arm64",
                "artifact_name": "gideon-linux.tar.gz", "display_version": "2.4.31 · build 0001",
                "requested_by": "ana", "created_at": "2026-09-15T08:00:00+00:00",
            },
            {
                "build_id": "active", "status": "BUILDING", "target_id": "windows-x64",
                "artifact_name": "gideon-windows.exe", "display_version": "2.4.31 · build 0002",
                "requested_by": "bruno", "created_at": "2026-09-15T09:00:00+00:00",
            },
            {
                "build_id": "failed", "status": "INTERRUPTED", "target_id": "raspberry-arm64",
                "artifact_name": "gideon-pi.deb", "display_version": "2.4.30 · build 0003",
                "requested_by": "ana", "created_at": "2026-09-15T10:00:00+00:00",
            },
        ]

    def test_status_and_text_filters_are_applied_on_the_server_data(self) -> None:
        rows, query, status, sort = filter_installer_history(
            self.rows, query="PI ANA", status="failed", sort="created_desc",
        )
        self.assertEqual(("PI ANA", "failed", "created_desc"), (query, status, sort))
        self.assertEqual(["failed"], [row["build_id"] for row in rows])

    def test_invalid_controls_are_normalized_and_newest_is_the_default(self) -> None:
        rows, query, status, sort = filter_installer_history(
            self.rows, query="  ", status="not-a-state", sort="not-a-sort",
        )
        self.assertEqual(("", "all", "created_desc"), (query, status, sort))
        self.assertEqual(["failed", "active", "older-ready"], [row["build_id"] for row in rows])

    def test_target_order_keeps_the_latest_row_as_a_stable_tiebreaker(self) -> None:
        rows, _, _, sort = filter_installer_history(self.rows, sort="target")
        self.assertEqual("target", sort)
        self.assertEqual(["older-ready", "failed", "active"], [row["build_id"] for row in rows])

    def test_clean_windows_package_keeps_the_same_filter_contract(self) -> None:
        for relative in (
            "gideon_web_admin/app.py",
            "gideon_web_admin/installer_history.py",
            "gideon_web_admin/templates/installers.html",
            "gideon_web_admin/static/table_controls.js",
            "gideon_web_admin/static/table_controls.css",
        ):
            self.assertEqual(
                (LINUX_APP / relative).read_bytes(),
                (WINDOWS_APP / relative).read_bytes(),
                f"Las copias Linux/Windows difieren: {relative}",
            )

    def test_route_and_template_keep_filters_server_side_and_persistent(self) -> None:
        for app_root in (LINUX_APP, WINDOWS_APP):
            source = (app_root / "gideon_web_admin/app.py").read_text(encoding="utf-8-sig")
            template = (app_root / "gideon_web_admin/templates/installers.html").read_text(encoding="utf-8-sig")
            self.assertIn("filter_installer_history(", source)
            self.assertIn('build_query=str(request.query_params.get("q") or "")', source)
            self.assertIn('data-gideon-persist-query="installers.builds.v1"', template)
            self.assertIn('name="status"', template)
            self.assertIn('name="sort"', template)


if __name__ == "__main__":
    unittest.main(verbosity=2)
