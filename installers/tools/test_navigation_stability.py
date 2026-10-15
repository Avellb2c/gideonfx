"""Regression contracts for contextual, non-stale sidebar navigation."""
from __future__ import annotations

import os
from pathlib import Path
import unittest


ROOT = Path(os.environ.get("GIDEON_TEST_ROOT") or Path(__file__).resolve().parents[2]).resolve()
LINUX = ROOT / "payload/linux/app/gideon_web_admin"
WINDOWS = ROOT / "payload/windows/GIDEON Remote Control/app/gideon_web_admin"


class NavigationStabilityTests(unittest.TestCase):
    def read_mirrored(self, relative: str) -> str:
        linux = LINUX / relative
        windows = WINDOWS / relative
        self.assertTrue(linux.is_file(), linux)
        self.assertTrue(windows.is_file(), windows)
        self.assertEqual(linux.read_bytes(), windows.read_bytes(), f"Mirror differs: {relative}")
        return linux.read_text(encoding="utf-8-sig")

    def test_groups_are_contextual_instead_of_hardcoded_open(self):
        base = self.read_mirrored("templates/base.html")
        self.assertNotIn('data-nav-group="operate" open>', base)
        self.assertNotIn('data-nav-group="content" open>', base)
        self.assertIn("active_path.startswith('/execute')", base)
        self.assertIn("active_path.startswith('/media')", base)

    def test_navigation_does_not_restore_stale_local_storage_expansions(self):
        script = self.read_mirrored("static/navigation_groups.js")
        self.assertIn("const activeGroup = groups.find", script)
        self.assertIn("group.open = Boolean(activeGroup && group === activeGroup)", script)
        self.assertNotIn("localStorage", script)
        self.assertNotIn("navigation.groups.v1", script)

    def test_soft_navigation_closes_all_groups_when_no_group_is_active(self):
        script = self.read_mirrored("static/app.js")
        self.assertIn("let activeSidebar = null", script)
        self.assertIn("if (link.matches('.sidebar .nav-link')) activeSidebar = link", script)
        self.assertIn("const activeGroup = activeSidebar?.closest('.nav-group')", script)
        self.assertIn("group.open = Boolean(activeGroup && group === activeGroup)", script)
        self.assertNotIn("group.open = !activeGroup || group === activeGroup", script)

    def test_closed_groups_are_hidden_before_javascript_runs(self):
        css = self.read_mirrored("static/app.css")
        self.assertIn(".nav-group:not([open])>.nav-group-links{display:none}", css)
        self.assertIn(".nav-group[open]>.nav-group-links{display:flex", css)

    def test_disclosure_state_namespace_is_migrated_after_layout_change(self):
        script = self.read_mirrored("static/ui_state.js")
        self.assertIn("const PREFIX = 'gideon.ui.v5'", script)
        self.assertNotIn("const PREFIX = 'gideon.ui.v4'", script)

    def test_disclosure_state_does_not_control_sidebar_navigation_groups(self):
        script = self.read_mirrored("static/ui_state.js")
        self.assertIn("el.matches('.nav-group[data-nav-group]')", script)


if __name__ == "__main__":
    unittest.main()
