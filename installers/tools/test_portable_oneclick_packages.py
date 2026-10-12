"""Focused integrity checks for the portable OneClick package builder."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BUILDER_PATH = ROOT / "installers" / "tools" / "build_portable_oneclick_packages.py"


def load_builder():
    spec = importlib.util.spec_from_file_location("gideon_portable_oneclick_test_builder", BUILDER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"No se pudo cargar {BUILDER_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PortableOneClickIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.builder = load_builder()

    def _write_common_archive(self, path: Path, *, clone_state: bool) -> None:
        with tarfile.open(path, "w:gz") as archive:
            entries = {"installers/sentinel.txt": b"clean"}
            if clone_state:
                entries["payload/data/state.json"] = b'{"clone":true}\n'
            for name, payload in entries.items():
                info = tarfile.TarInfo(name)
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))

    def _build_fake_kits(self, output: Path, *, clone_state: bool):
        modules = self.builder.module_catalog(clone_state)
        store = output / ".modules"
        store.mkdir(parents=True)
        module_info = {}
        for number, (key, module) in enumerate(modules.items(), start=1):
            archive = store / module.filename
            if key == "common":
                self._write_common_archive(archive, clone_state=clone_state)
            else:
                archive.write_bytes(f"module-{key}-{number}".encode("ascii"))
            module_info[key] = {
                "filename": module.filename,
                "description": module.description,
                "source_paths": list(module.paths),
                "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                "size_bytes": archive.stat().st_size,
            }
        report = self.builder.build_kits(
            output,
            module_info,
            False,
            modules=modules,
            include_clone_state=clone_state,
        )
        return modules, module_info, report

    def test_clean_kit_verifies_and_excludes_clone_state(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-portable-clean-") as raw:
            output = Path(raw)
            modules, module_info, report = self._build_fake_kits(output, clone_state=False)
            self.assertNotIn("payload/data", modules["common"].paths)
            self.builder.verify_built_kits(
                output,
                module_info,
                report,
                modules=modules,
                include_clone_state=False,
            )
            for kit_name in self.builder.KITS:
                self.assertFalse((output / kit_name / "CLONE_STATE_INCLUDED.txt").exists())

    def test_verification_fails_closed_when_a_module_changes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-portable-tamper-") as raw:
            output = Path(raw)
            modules, module_info, report = self._build_fake_kits(output, clone_state=False)
            kit_name = "GIDEON-WINDOWS-HOME-ONECLICK"
            archive = output / kit_name / modules["windows"].filename
            with archive.open("ab") as stream:
                stream.write(b"tampered")
            with self.assertRaisesRegex(RuntimeError, "Tamaño real distinto|SHA-256 real distinto"):
                self.builder.verify_built_kits(
                    output,
                    module_info,
                    report,
                    modules=modules,
                    include_clone_state=False,
                )

    def test_clone_kit_is_explicitly_marked_and_verified(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-portable-clone-") as raw:
            output = Path(raw)
            modules, module_info, report = self._build_fake_kits(output, clone_state=True)
            self.builder.verify_built_kits(
                output,
                module_info,
                report,
                modules=modules,
                include_clone_state=True,
            )
            for kit_name in self.builder.KITS:
                self.assertTrue((output / kit_name / "CLONE_STATE_INCLUDED.txt").is_file())

    def test_second_process_cannot_take_the_same_output_lock(self) -> None:
        child = r'''
import importlib.util
import sys
from pathlib import Path

source = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("gideon_portable_lock_child", source)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
try:
    with module.exclusive_output_build_lock(Path(sys.argv[2])):
        pass
except RuntimeError:
    raise SystemExit(0)
raise SystemExit(1)
'''
        with tempfile.TemporaryDirectory(prefix="gideon-portable-lock-") as raw:
            output = Path(raw) / "output"
            with self.builder.exclusive_output_build_lock(output):
                child_result = subprocess.run(
                    [sys.executable, "-c", child, str(BUILDER_PATH), str(output)],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
            self.assertEqual(0, child_result.returncode, child_result.stdout + child_result.stderr)

    def test_packager_rejects_backup_and_ephemeral_build_outputs(self) -> None:
        """Clean installers must not ship developer backups or Python/cache residue."""
        source = BUILDER_PATH.read_text(encoding="utf-8-sig")
        for rule in (
            "--exclude=__pycache__",
            "--exclude=.pytest_cache",
            "--exclude=*.pyc",
            "--exclude=*.pyo",
            "--exclude=*.bak",
            "--exclude=*.partial",
            "--exclude=*.tmp",
            "--exclude=*.orig",
            "--exclude=*~",
        ):
            self.assertIn(rule, source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
