"""Regression tests for Windows EXE generation from a Linux Control Plane."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile


ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / "payload/linux/app"
WINDOWS_APP = ROOT / "payload/windows/GIDEON Remote Control/app"
sys.path.insert(0, str(APP))

from gideon_branding import BrandingRepository  # noqa: E402
from gideon_agent_archive import prune_generated_nonruntime_files, write_verified_deflated_zip  # noqa: E402
from gideon_agent_installer_contract import verify_artifact_sanity  # noqa: E402
from gideon_packaging.windows_exe import (  # noqa: E402
    PREBUILT_SFX_MAGIC,
    WindowsExeBuildError,
    WindowsExePackager,
)
from gideon_version import AGENT_VERSION  # noqa: E402


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_overlay(path: Path) -> tuple[bytes, bytes]:
    data = path.read_bytes()
    trailer_size = 16 + 64 + 64 + len(PREBUILT_SFX_MAGIC)
    trailer = data[-trailer_size:]
    payload_length, bootstrap_length = struct.unpack("<QQ", trailer[:16])
    assert trailer[-len(PREBUILT_SFX_MAGIC):] == PREBUILT_SFX_MAGIC
    overlay_start = len(data) - trailer_size - payload_length - bootstrap_length
    payload = data[overlay_start:overlay_start + payload_length]
    bootstrap = data[overlay_start + payload_length:overlay_start + payload_length + bootstrap_length]
    assert sha256(payload) == trailer[16:80].decode("ascii")
    assert sha256(bootstrap) == trailer[80:144].decode("ascii")
    return payload, bootstrap


class CrossPlatformWindowsSfxTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="gideon-windows-sfx-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.packager = WindowsExePackager(APP)
        self.brand = BrandingRepository(APP).load()

    def test_linux_and_windows_prebuilt_files_are_identical_and_valid(self):
        for tool in ("sfx_stub", "service_host"):
            path = self.packager._validated_prebuilt(tool, expected_version=AGENT_VERSION)
            self.assertTrue(path.is_file())
        for name in (
            "GIDEONAgentSfxStub.cs",
            "GIDEONAgentSfxStub.manifest",
            "GIDEONAgentSfxStub.exe",
            "GIDEONAgentServiceHost.exe",
            "manifest.json",
        ):
            linux = APP / "deploy/agent/windows/prebuilt" / name
            windows = WINDOWS_APP / "deploy/agent/windows/prebuilt" / name
            self.assertEqual(hashlib.sha256(linux.read_bytes()).digest(), hashlib.sha256(windows.read_bytes()).digest())

    def test_prebuilt_metadata_tracks_the_current_agent_version(self):
        """A Linux release builder has no csc.exe, so stale checked-in helpers fail closed."""
        expected = f"{AGENT_VERSION}.0"
        for app in (APP, WINDOWS_APP):
            self.assertEqual(
                AGENT_VERSION,
                re.search(
                    r'(?m)^AGENT_VERSION\s*=\s*["\']([^"\']+)["\']\s*$',
                    (app / "gideon_version.py").read_text(encoding="utf-8-sig"),
                ).group(1),
            )
            service_source = app / "deploy/agent/windows/GIDEONAgentServiceHost.cs"
            sfx_source = app / "deploy/agent/windows/prebuilt/GIDEONAgentSfxStub.cs"
            for source in (service_source, sfx_source):
                self.assertEqual(
                    [expected, expected],
                    re.findall(
                        r'(?m)^\[assembly:\s*Assembly(?:File)?Version\("([^"\']+)"\)\]\s*$',
                        source.read_text(encoding="utf-8-sig"),
                    ),
                )
            document = json.loads(
                (app / "deploy/agent/windows/prebuilt/manifest.json").read_text(encoding="utf-8-sig")
            )
            self.assertEqual(AGENT_VERSION, document["agent_version"])

    def test_overlay_contains_hash_verified_payload_and_bootstrap(self):
        payload = self.root / "payload"
        stage = self.root / "stage"
        payload.mkdir()
        (payload / "sentinel.txt").write_text("cross-platform-windows", encoding="utf-8")
        stub = self.packager._validated_prebuilt("sfx_stub", expected_version=AGENT_VERSION)

        built = self.packager._build_prebuilt_sfx(
            stub=str(stub),
            payload_dir=payload,
            source_dir=stage,
            version=AGENT_VERSION,
            brand=self.brand,
        )

        self.assertEqual(b"MZ", built.read_bytes()[:2])
        payload_zip, bootstrap = read_overlay(built)
        zip_path = self.root / "payload.zip"
        zip_path.write_bytes(payload_zip)
        with zipfile.ZipFile(zip_path) as archive:
            self.assertEqual("cross-platform-windows", archive.read("sentinel.txt").decode("utf-8"))
            self.assertIn("gideon-agent-postinstall.ps1", archive.namelist())
        self.assertIn(sha256(payload_zip).encode("ascii"), bootstrap)

    def test_payload_zip_maximizes_compatible_compression_and_rejects_caches(self):
        payload = self.root / "payload-compression"
        payload.mkdir()
        repeated = b"GIDEON-Agent-runtime-data\n" * 65536
        (payload / "runtime.txt").write_bytes(repeated)
        optimized = self.root / "optimized.zip"
        baseline = self.root / "baseline-level-1.zip"

        self.packager._zip_payload(payload, optimized)
        with zipfile.ZipFile(
            baseline, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=1
        ) as archive:
            archive.write(payload / "runtime.txt", "runtime.txt")
        self.assertLess(optimized.stat().st_size, baseline.stat().st_size)
        with zipfile.ZipFile(optimized) as archive:
            self.assertIsNone(archive.testzip())
            self.assertEqual(repeated, archive.read("runtime.txt"))

        cache = payload / "__pycache__"
        cache.mkdir()
        (cache / "debug.pyc").write_bytes(b"not-runtime")
        with self.assertRaisesRegex(WindowsExeBuildError, "AGENT_ARCHIVE_NONRUNTIME_MEMBER"):
            self.packager._zip_payload(payload, self.root / "rejected.zip")

    def test_builder_stage_cleanup_excludes_generated_caches_before_signing(self):
        """A staged private-runtime smoke test must not leak caches into a release."""
        stage = self.root / "stage-cleanup"
        payload = stage / "payload"
        cache = payload / "__pycache__"
        cache.mkdir(parents=True)
        runtime_file = payload / "runtime.txt"
        runtime_file.write_text("declared runtime", encoding="utf-8")
        generated_pyc = cache / "gideon_agent.cpython-311.pyc"
        generated_pyc.write_bytes(b"generated-cache")
        metadata = stage / "Thumbs.db"
        metadata.write_bytes(b"desktop-metadata")

        removed = prune_generated_nonruntime_files(stage)
        self.assertEqual(
            ("Thumbs.db", "payload/__pycache__/gideon_agent.cpython-311.pyc"),
            removed,
        )
        self.assertTrue(runtime_file.is_file())
        self.assertFalse(generated_pyc.exists())
        self.assertFalse(metadata.exists())
        self.assertFalse(cache.exists())

        archive_path = self.root / "stage-cleanup.zip"
        self.assertEqual(("payload/runtime.txt",), write_verified_deflated_zip(stage, archive_path))
        with zipfile.ZipFile(archive_path) as archive:
            self.assertEqual(["payload/runtime.txt"], archive.namelist())
            self.assertEqual("declared runtime", archive.read("payload/runtime.txt").decode("utf-8"))

        builder_source = (APP / "gideon_agent_builder.py").read_text(encoding="utf-8-sig")
        self.assertIn("prune_generated_nonruntime_files(stage)", builder_source)

    def test_tampered_prebuilt_binary_is_rejected(self):
        fake_app = self.root / "app"
        source = APP / "deploy/agent/windows"
        target = fake_app / "deploy/agent/windows"
        shutil.copytree(source, target)
        binary = target / "prebuilt/GIDEONAgentSfxStub.exe"
        content = bytearray(binary.read_bytes())
        content[1024] ^= 0x01
        binary.write_bytes(content)

        with self.assertRaisesRegex(WindowsExeBuildError, "WINDOWS_PREBUILT_BINARY_INVALID"):
            WindowsExePackager(fake_app)._validated_prebuilt("sfx_stub", expected_version=AGENT_VERSION)

    def test_overlay_contract_survives_trailing_authenticode_data(self):
        payload = self.root / "signed-payload"
        stage = self.root / "signed-stage"
        payload.mkdir()
        contract = b'{"schema":"gideon-agent-installer-contract/v2","status":"PASS"}\n'
        (payload / "installer.contract.json").write_bytes(contract)
        stub = self.packager._validated_prebuilt("sfx_stub", expected_version=AGENT_VERSION)
        built = self.packager._build_prebuilt_sfx(
            stub=str(stub), payload_dir=payload, source_dir=stage,
            version=AGENT_VERSION, brand=self.brand,
        )
        with built.open("ab") as stream:
            stream.write(b"SIMULATED_AUTHENTICODE_CERTIFICATE_TABLE" * 8)

        result = verify_artifact_sanity(
            built,
            package_type="exe",
            expected_version=AGENT_VERSION,
            expected_contract_sha256=sha256(contract),
            require_exe_embedded_contract=True,
        )
        self.assertTrue(result["embedded_contract_verified"])

    def test_backend_falls_back_to_verified_prebuilt_sfx(self):
        with (
            patch.object(WindowsExePackager, "inno_executable", return_value=None),
            patch.object(WindowsExePackager, "csc_executable", return_value=None),
            patch.object(WindowsExePackager, "iexpress_executable", return_value=None),
        ):
            backend, executable = WindowsExePackager.preferred_backend()
        self.assertEqual("prebuilt_sfx", backend)
        self.assertEqual(
            self.packager._validated_prebuilt("sfx_stub"),
            Path(str(executable)).resolve(),
        )


if __name__ == "__main__":
    unittest.main()
