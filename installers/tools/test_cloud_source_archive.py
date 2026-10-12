"""Policy checks for source-only cloud overlays."""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "work" / "build_cloud_source_archive.py"


def load_module():
    spec = importlib.util.spec_from_file_location("gideon_cloud_source_archive_test", SOURCE)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"No se pudo cargar {SOURCE}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class CloudSourceArchiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.archive = load_module()

    def test_ephemeral_files_and_caches_are_excluded(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-cloud-archive-") as raw:
            root = Path(raw)
            cases = {
                "gideon_web_admin/app.py": True,
                "gideon_web_admin/__pycache__/app.cpython-312.pyc": False,
                "gideon_web_admin/static/remote_page.js.bak": False,
                "gideon_web_admin/static/write.tmp": False,
                "gideon_web_admin/static/patch.orig": False,
                "gideon_web_admin/static/swap~": False,
                ".pytest_cache/state": False,
                "data/users.json": False,
            }
            for relative, expected in cases.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("x", encoding="utf-8")
                self.assertEqual(expected, self.archive.include(path, path.relative_to(root)), relative)

    def test_release_named_source_is_retained_but_runtime_releases_are_protected(self) -> None:
        """Do not turn cache cleanup into a broad release/artifact exclusion."""
        with tempfile.TemporaryDirectory(prefix="gideon-cloud-archive-") as raw:
            root = Path(raw)
            cases = {
                # These are regular source assets and must remain deployable.
                "gideon_web_admin/static/release-notes.json": True,
                "gideon_web_admin/assets/artifact-manifest.json": True,
                # The live release catalogue is operational state; an overlay must
                # preserve it in place instead of replacing it from source.
                "releases/stable/GIDEONAgent.zip": False,
            }
            for relative, expected in cases.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("x", encoding="utf-8")
                self.assertEqual(expected, self.archive.include(path, path.relative_to(root)), relative)


if __name__ == "__main__":
    unittest.main(verbosity=2)
