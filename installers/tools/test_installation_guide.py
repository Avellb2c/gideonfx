"""Offline contract tests for the public installation guide."""
from __future__ import annotations

import ast
import os
from pathlib import Path
import unittest


ROOT = Path(os.environ.get("GIDEON_TEST_ROOT") or Path(__file__).resolve().parents[2]).resolve()
LINUX = ROOT / "payload/linux/app/gideon_web_admin"
WINDOWS = ROOT / "payload/windows/GIDEON Remote Control/app/gideon_web_admin"


class InstallationGuideTests(unittest.TestCase):
    def test_web_guide_and_static_asset_are_mirrored(self):
        for relative in ("templates/installation_guide.html", "static/installation_guide.css", "templates/base.html"):
            left = LINUX / relative
            right = WINDOWS / relative
            self.assertTrue(left.is_file(), left)
            self.assertTrue(right.is_file(), right)
            self.assertEqual(left.read_bytes(), right.read_bytes(), relative)

    def test_guide_contains_four_deployment_paths_and_safety_rules(self):
        guide = (LINUX / "templates/installation_guide.html").read_text(encoding="utf-8")
        for marker in ("id=\"windows\"", "id=\"ubuntu\"", "id=\"aws\"", "id=\"azure\"", "GIDEON_ALLOW_ONLINE_INSTALL=0", "túnel inverso mTLS", "Guacamole sólo interno"):
            self.assertIn(marker, guide)
        self.assertIn("/guide/installation", (LINUX / "templates/base.html").read_text(encoding="utf-8"))

    def test_installation_route_is_registered(self):
        module = (LINUX / "app.py").read_text(encoding="utf-8")
        tree = ast.parse(module)
        routes = {
            decorator.args[0].value
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            for decorator in node.decorator_list
            if isinstance(decorator, ast.Call)
            and isinstance(decorator.func, ast.Attribute)
            and decorator.func.attr == "get"
            and decorator.args
            and isinstance(decorator.args[0], ast.Constant)
        }
        self.assertIn("/guide", routes)
        self.assertIn("/guide/installation", routes)


if __name__ == "__main__":
    unittest.main()
