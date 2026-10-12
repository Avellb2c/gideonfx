"""Contract tests for the local-only VLC offline catalog intake tool.

The fixtures are deliberately inert byte files: no VLC binary, APT command,
desktop session, network request, package install, or Authenticode check runs
in this suite.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = ROOT / "installers" / "tools" / "build_vlc_offline_catalog.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("gideon_test_vlc_offline_catalog", TOOL_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("No se pudo cargar build_vlc_offline_catalog.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


tool = _load_tool()


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write(root: Path, relative: str, data: bytes) -> dict[str, object]:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return {"SourcePath": relative, "SizeBytes": len(data), "Sha256": _digest(data)}


class VlcOfflineCatalogToolTests(unittest.TestCase):
    def setUp(self) -> None:
        # Unit fixtures contain inert signature bytes.  Integration review
        # exercises the real gpgv path against the signed candidate repo.
        patcher = mock.patch.object(tool, "_verify_apt_repository_signature", autospec=True)
        self.addCleanup(patcher.stop)
        self.apt_signature_verify = patcher.start()

    def _fixture(self, root: Path) -> tuple[Path, Path, dict[str, object]]:
        source = root / "source"
        source.mkdir()
        gpl = _write(source, "legal/GPL-2.0.txt", b"GNU GENERAL PUBLIC LICENSE\nVersion 2, June 1991\n")
        notice = _write(source, "legal/VLC-NOTICE.md", b"VideoLAN VLC is distributed under the GPL.\n")
        offer = _write(source, "legal/SOURCE-OFFER.md", b"GIDEON provides VLC corresponding source on written offer.\n")
        msi = _write(source, "windows/vlc-3.0.23-win64.msi", b"inert-test-msi-vlc")
        deb_bytes = b"!<arch>\nnot-a-real-deb-fixture"
        deb = _write(source, "apt/pool/vlc_3.0.23_amd64.deb", deb_bytes)
        key = _write(source, "apt/keys/gideon-vlc.gpg", b"inert-pgp-key")
        release = _write(source, "apt/Release", b"Origin: GIDEON VLC Offline\nSuite: test\n")
        release_sig = _write(source, "apt/Release.gpg", b"inert-release-signature")
        packages_data = (
            "Package: vlc\n"
            "Version: 3.0.23\n"
            "Architecture: amd64\n"
            "Filename: pool/vlc_3.0.23_amd64.deb\n"
            f"Size: {len(deb_bytes)}\n"
            f"SHA256: {_digest(deb_bytes)}\n"
            "Depends: libfixture (>= 1.0)\n\n"
        ).encode("utf-8")
        packages = _write(source, "apt/Packages", packages_data)
        materials = {
            "Schema": "gideon-vlc-source-materials/v1",
            "Product": "VLC media player",
            "License": "GPL-2.0-or-later",
            "SourceOffer": {"Method": "written-offer", "Contact": "legal@example.invalid", "ValidUntil": "2099-01-01"},
            "Sources": [{
                "SourceId": "vlc-3.0.23", "Version": "3.0.23",
                "SourceUrl": "https://example.invalid/vlc-3.0.23.tar.xz",
                "ChecksumUrl": "https://example.invalid/vlc-3.0.23.tar.xz.sha256",
                "SignatureUrl": "https://example.invalid/vlc-3.0.23.tar.xz.asc",
                "SourceSha256": "a" * 64,
            }],
            "Artifacts": [
                {
                    "VariantId": "vlc-win-x64", "Path": "variants/windows/x86_64/vlc-3.0.23-win64.msi",
                    "SourceId": "vlc-3.0.23", "ArtifactUrl": "https://example.invalid/vlc.msi",
                    "ChecksumUrl": "https://example.invalid/vlc.msi.sha256", "UpstreamSha256": msi["Sha256"],
                    "RetrievedAt": "2026-09-21T00:00:00+00:00",
                },
                {
                    "VariantId": "vlc-ubuntu-amd64", "Path": "variants/linux/ubuntu/test/repo/pool/vlc_3.0.23_amd64.deb",
                    "SourceId": "vlc-3.0.23", "ArtifactUrl": "https://example.invalid/vlc.deb",
                    "ChecksumUrl": "https://example.invalid/vlc.deb.sha256", "UpstreamSha256": deb["Sha256"],
                    "RetrievedAt": "2026-09-21T00:00:00+00:00",
                },
            ],
        }
        materials_bytes = (json.dumps(materials, sort_keys=True) + "\n").encode("utf-8")
        source_materials = _write(source, "legal/SOURCE-MATERIALS.json", materials_bytes)
        legal = []
        for path, source_row in (
            ("legal/GPL-2.0.txt", gpl), ("legal/VLC-NOTICE.md", notice),
            ("legal/SOURCE-OFFER.md", offer), ("legal/SOURCE-MATERIALS.json", source_materials),
        ):
            legal.append({"Path": path, **source_row})
        win_file = {"Path": "variants/windows/x86_64/vlc-3.0.23-win64.msi", "Role": "installer", **msi,
                    "Authenticode": {"Subject": "CN=VideoLAN", "Thumbprint": "A" * 40}}
        repo = "variants/linux/ubuntu/test/repo"
        linux_files = [
            {"Path": f"{repo}/keys/gideon-vlc.gpg", "Role": "apt-key", **key},
            {"Path": f"{repo}/Release", "Role": "apt-release", **release},
            {"Path": f"{repo}/Release.gpg", "Role": "apt-release-signature", **release_sig},
            {"Path": f"{repo}/Packages", "Role": "apt-packages-index", **packages},
            {"Path": f"{repo}/pool/vlc_3.0.23_amd64.deb", "Role": "deb", **deb,
             "Package": "vlc", "Version": "3.0.23", "DebArchitecture": "amd64"},
        ]
        intake = {
            "Schema": "gideon-vlc-offline-intake/v1", "CatalogVersion": "vlc-3.0.23-gideon-test",
            "Vendor": {"Name": "VideoLAN", "Product": "VLC media player", "ProjectUrl": "https://www.videolan.org/", "SourceUrl": "https://get.videolan.org/"},
            "Legal": {"License": "GPL-2.0-or-later", "Files": legal},
            "Variants": [
                {"VariantId": "vlc-win-x64", "Platform": "windows", "Architecture": "x86_64",
                 "Install": {"Mode": "windows-msi"}, "DependencyClosure": {"Complete": True, "EntryPackages": []},
                 "Files": [win_file]},
                {"VariantId": "vlc-ubuntu-amd64", "Platform": "linux", "Architecture": "x86_64", "Distribution": "ubuntu", "Codename": "test",
                 "Install": {"Mode": "apt-local-deb-repository", "RepositoryPath": repo, "AptSigningKeyPath": f"{repo}/keys/gideon-vlc.gpg"},
                 "DependencyClosure": {"Complete": True, "EntryPackages": ["vlc"], "PackageClosure": ["vlc"], "BaseSystemPackages": ["libfixture"]},
                 "Files": linux_files},
            ],
        }
        intake_path = root / "intake.json"
        intake_path.write_text(json.dumps(intake, indent=2), encoding="utf-8")
        return intake_path, source, intake

    @staticmethod
    def _rewrite_source_materials(
        intake_path: Path,
        source: Path,
        intake: dict[str, object],
        materials: dict[str, object],
    ) -> None:
        """Persist a mutated evidence document and keep its intake hash exact."""
        materials_bytes = (json.dumps(materials, sort_keys=True) + "\n").encode("utf-8")
        (source / "legal/SOURCE-MATERIALS.json").write_bytes(materials_bytes)
        materials_row = next(
            row for row in intake["Legal"]["Files"]
            if row["Path"] == "legal/SOURCE-MATERIALS.json"
        )
        materials_row["SizeBytes"] = len(materials_bytes)
        materials_row["Sha256"] = _digest(materials_bytes)
        intake_path.write_text(json.dumps(intake, indent=2), encoding="utf-8")

    @staticmethod
    def _use_bundled_source(
        intake_path: Path,
        source: Path,
        intake: dict[str, object],
        *,
        add_second_source: bool = False,
        declared_hash: str | None = None,
    ) -> bytes:
        """Switch the fixture to physical GPL source with consistent hashes."""
        archive_bytes = b"inert-vlc-corresponding-source-archive"
        archive = _write(source, "review/vlc-3.0.23.tar.xz", archive_bytes)
        materials_path = source / "legal/SOURCE-MATERIALS.json"
        materials = json.loads(materials_path.read_text(encoding="utf-8"))
        materials["SourceOffer"] = {
            "Method": "bundled-source",
        }
        materials["Sources"][0]["SourceSha256"] = declared_hash or archive["Sha256"]
        if add_second_source:
            materials["Sources"].append({
                "SourceId": "vlc-contrib-3.0.23",
                "Version": "3.0.23",
                "SourceUrl": "https://example.invalid/vlc-contrib-3.0.23.tar.xz",
                "ChecksumUrl": "https://example.invalid/vlc-contrib-3.0.23.tar.xz.sha256",
                "SignatureUrl": "https://example.invalid/vlc-contrib-3.0.23.tar.xz.asc",
                "SourceSha256": "b" * 64,
            })
        materials_bytes = (json.dumps(materials, sort_keys=True) + "\n").encode("utf-8")
        materials_path.write_bytes(materials_bytes)
        materials_row = next(
            row for row in intake["Legal"]["Files"]
            if row["Path"] == "legal/SOURCE-MATERIALS.json"
        )
        materials_row["SizeBytes"] = len(materials_bytes)
        materials_row["Sha256"] = _digest(materials_bytes)
        intake["Legal"]["BundledFiles"] = [{
            "Path": "legal/sources/vlc-3.0.23.tar.xz",
            "Role": "source-archive",
            "SourceId": "vlc-3.0.23",
            **archive,
        }]
        intake_path.write_text(json.dumps(intake, indent=2), encoding="utf-8")
        return archive_bytes

    @staticmethod
    def _use_multipart_bundled_source(
        intake_path: Path,
        source: Path,
        intake: dict[str, object],
    ) -> list[bytes]:
        """Switch the fixture to an exact, two-file Debian-style source set."""
        archive_payloads = [b"inert-upstream-source", b"inert-debian-patch"]
        archive_names = ["fixture_1.0.orig.tar.xz", "fixture_1.0-1.debian.tar.xz"]
        archive_rows = []
        bundled_rows = []
        for name, payload in zip(archive_names, archive_payloads, strict=True):
            archive = _write(source, f"review/{name}", payload)
            archive_rows.append({
                "Filename": name,
                "SizeBytes": archive["SizeBytes"],
                "Sha256": archive["Sha256"],
                "SourceUrl": f"https://example.invalid/{name}",
            })
            bundled_rows.append({
                "Path": f"legal/sources/{name}",
                "Role": "source-archive",
                "SourceId": "vlc-3.0.23",
                **archive,
            })
        materials_path = source / "legal/SOURCE-MATERIALS.json"
        materials = json.loads(materials_path.read_text(encoding="utf-8"))
        materials["SourceOffer"] = {"Method": "bundled-source"}
        materials["Sources"][0].pop("SourceSha256")
        materials["Sources"][0]["Archives"] = archive_rows
        materials_bytes = (json.dumps(materials, sort_keys=True) + "\n").encode("utf-8")
        materials_path.write_bytes(materials_bytes)
        materials_row = next(
            row for row in intake["Legal"]["Files"]
            if row["Path"] == "legal/SOURCE-MATERIALS.json"
        )
        materials_row["SizeBytes"] = len(materials_bytes)
        materials_row["Sha256"] = _digest(materials_bytes)
        intake["Legal"]["BundledFiles"] = bundled_rows
        intake_path.write_text(json.dumps(intake, indent=2), encoding="utf-8")
        return archive_payloads

    def test_bundled_source_without_contact_is_copied_and_catalogued(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-vlc-catalog-") as temp:
            root = Path(temp)
            intake_path, source, intake = self._fixture(root)
            archive_bytes = self._use_bundled_source(intake_path, source, intake)
            output = root / "output"

            result = tool.build_catalog(intake_path, source, output_root=output)

            self.assertEqual("VALID", result["Status"])
            bundled_path = output / "legal/sources/vlc-3.0.23.tar.xz"
            self.assertEqual(archive_bytes, bundled_path.read_bytes())
            catalog = json.loads((output / "catalog.json").read_text(encoding="utf-8"))
            self.assertIn("legal/sources/vlc-3.0.23.tar.xz", catalog["Legal"]["RequiredFiles"])
            self.assertEqual([{
                "Path": "legal/sources/vlc-3.0.23.tar.xz",
                "Role": "source-archive",
                "SourceId": "vlc-3.0.23",
                "SizeBytes": len(archive_bytes),
                "Sha256": _digest(archive_bytes),
            }], catalog["Legal"]["BundledSources"])
            self.assertNotIn("SourcePath", json.dumps(catalog, sort_keys=True))

    def test_written_offer_requires_a_real_contact_field(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-vlc-catalog-") as temp:
            root = Path(temp)
            intake_path, source, intake = self._fixture(root)
            materials_path = source / "legal/SOURCE-MATERIALS.json"
            materials = json.loads(materials_path.read_text(encoding="utf-8"))
            del materials["SourceOffer"]["Contact"]
            materials_bytes = (json.dumps(materials, sort_keys=True) + "\n").encode("utf-8")
            materials_path.write_bytes(materials_bytes)
            materials_row = next(
                row for row in intake["Legal"]["Files"]
                if row["Path"] == "legal/SOURCE-MATERIALS.json"
            )
            materials_row["SizeBytes"] = len(materials_bytes)
            materials_row["Sha256"] = _digest(materials_bytes)
            intake_path.write_text(json.dumps(intake), encoding="utf-8")

            with self.assertRaisesRegex(
                tool.VlcOfflineCatalogBuildError,
                "VLC_INTAKE_SOURCE_OFFER_CONTACT_REQUIRED",
            ):
                tool.build_catalog(intake_path, source)

    def test_bundled_source_method_requires_a_physical_source_archive(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-vlc-catalog-") as temp:
            root = Path(temp)
            intake_path, source, intake = self._fixture(root)
            self._use_bundled_source(intake_path, source, intake)
            del intake["Legal"]["BundledFiles"]
            intake_path.write_text(json.dumps(intake), encoding="utf-8")

            with self.assertRaisesRegex(tool.VlcOfflineCatalogBuildError, "VLC_INTAKE_BUNDLED_SOURCES_REQUIRED"):
                tool.build_catalog(intake_path, source)

    def test_bundled_source_archive_must_match_declared_corresponding_source_hash(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-vlc-catalog-") as temp:
            root = Path(temp)
            intake_path, source, intake = self._fixture(root)
            self._use_bundled_source(intake_path, source, intake, declared_hash="f" * 64)

            with self.assertRaisesRegex(tool.VlcOfflineCatalogBuildError, "VLC_INTAKE_BUNDLED_SOURCE_ARCHIVE_HASH_MISMATCH"):
                tool.build_catalog(intake_path, source)

    def test_multipart_bundled_source_requires_and_copies_the_exact_archive_set(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-vlc-catalog-") as temp:
            root = Path(temp)
            intake_path, source, intake = self._fixture(root)
            expected_payloads = self._use_multipart_bundled_source(intake_path, source, intake)
            output = root / "output"

            result = tool.build_catalog(intake_path, source, output_root=output)

            self.assertEqual("VALID", result["Status"])
            catalog = json.loads((output / "catalog.json").read_text(encoding="utf-8"))
            archives = [
                row for row in catalog["Legal"]["BundledSources"]
                if row["SourceId"] == "vlc-3.0.23" and row["Role"] == "source-archive"
            ]
            self.assertEqual(2, len(archives))
            self.assertEqual(
                sorted(_digest(payload) for payload in expected_payloads),
                sorted(row["Sha256"] for row in archives),
            )

    def test_multipart_bundled_source_rejects_a_missing_archive(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-vlc-catalog-") as temp:
            root = Path(temp)
            intake_path, source, intake = self._fixture(root)
            self._use_multipart_bundled_source(intake_path, source, intake)
            intake["Legal"]["BundledFiles"].pop()
            intake_path.write_text(json.dumps(intake), encoding="utf-8")

            with self.assertRaisesRegex(
                tool.VlcOfflineCatalogBuildError,
                "VLC_INTAKE_BUNDLED_SOURCE_ARCHIVE_HASH_MISMATCH",
            ):
                tool.build_catalog(intake_path, source)

    def test_multipart_bundled_source_rejects_an_unexpected_duplicate_archive(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-vlc-catalog-") as temp:
            root = Path(temp)
            intake_path, source, intake = self._fixture(root)
            self._use_multipart_bundled_source(intake_path, source, intake)
            original = intake["Legal"]["BundledFiles"][0]
            duplicate = _write(source, "review/duplicate-orig.tar.xz", b"inert-upstream-source")
            intake["Legal"]["BundledFiles"].append({
                "Path": "legal/sources/duplicate-orig.tar.xz",
                "Role": "source-archive",
                "SourceId": "vlc-3.0.23",
                **duplicate,
            })
            self.assertEqual(original["Sha256"], duplicate["Sha256"])
            intake_path.write_text(json.dumps(intake), encoding="utf-8")

            with self.assertRaisesRegex(
                tool.VlcOfflineCatalogBuildError,
                "VLC_INTAKE_BUNDLED_SOURCE_ARCHIVE_UNEXPECTED",
            ):
                tool.build_catalog(intake_path, source)

    def test_every_declared_source_requires_exactly_one_bundled_archive(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-vlc-catalog-") as temp:
            root = Path(temp)
            intake_path, source, intake = self._fixture(root)
            self._use_bundled_source(intake_path, source, intake, add_second_source=True)

            with self.assertRaisesRegex(tool.VlcOfflineCatalogBuildError, "VLC_INTAKE_BUNDLED_SOURCE_ARCHIVE_REQUIRED"):
                tool.build_catalog(intake_path, source)

    def test_builds_targeted_catalog_without_network_or_source_paths(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-vlc-catalog-") as temp:
            root = Path(temp)
            intake_path, source, _intake = self._fixture(root)
            output = root / "output" / "third_party" / "vlc-offline"
            with mock.patch.object(socket, "socket", side_effect=AssertionError("network is prohibited")):
                result = tool.build_catalog(intake_path, source, output_root=output)
            self.assertEqual("VALID", result["Status"])
            self.assertFalse(result["NetworkDownloads"])
            catalog = json.loads((output / "catalog.json").read_text(encoding="utf-8"))
            self.assertEqual(2, len(catalog["Variants"]))
            self.assertEqual(
                [["vlc-3.0.23"], ["vlc-3.0.23"]],
                [row["CorrespondingSourceIds"] for row in catalog["Variants"]],
            )
            self.assertTrue((output / "variants/windows/x86_64/vlc-3.0.23-win64.msi").is_file())
            self.assertTrue((output / "variants/linux/ubuntu/test/repo/Packages").is_file())
            serialized = (output / "catalog.json").read_text(encoding="utf-8")
            self.assertNotIn("SourcePath", serialized)
            self.assertNotIn(str(source), serialized)

    def test_rejects_empty_or_unknown_artifact_source_id(self) -> None:
        cases = (
            ("", "VLC_INTAKE_ARTIFACT_SOURCE_ID_INVALID"),
            ("source-not-declared", "VLC_INTAKE_ARTIFACT_SOURCE_UNKNOWN"),
        )
        for source_id, expected_error in cases:
            with self.subTest(source_id=source_id), tempfile.TemporaryDirectory(prefix="gideon-vlc-catalog-") as temp:
                root = Path(temp)
                intake_path, source, intake = self._fixture(root)
                materials = json.loads((source / "legal/SOURCE-MATERIALS.json").read_text(encoding="utf-8"))
                materials["Artifacts"][0]["SourceId"] = source_id
                self._rewrite_source_materials(intake_path, source, intake, materials)

                with self.assertRaisesRegex(tool.VlcOfflineCatalogBuildError, expected_error):
                    tool.build_catalog(intake_path, source)

    def test_rejects_altered_artifact_to_variant_mapping(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-vlc-catalog-") as temp:
            root = Path(temp)
            intake_path, source, intake = self._fixture(root)
            materials = json.loads((source / "legal/SOURCE-MATERIALS.json").read_text(encoding="utf-8"))
            materials["Artifacts"][0]["Path"] = "variants/windows/x86_64/not-the-reviewed-installer.msi"
            self._rewrite_source_materials(intake_path, source, intake, materials)

            with self.assertRaisesRegex(
                tool.VlcOfflineCatalogBuildError,
                "VLC_INTAKE_ARTIFACT_EVIDENCE_MISSING",
            ):
                tool.build_catalog(intake_path, source)

    def test_build_verifies_the_embedded_apt_release_signature(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-vlc-catalog-") as temp:
            root = Path(temp)
            intake_path, source, _intake = self._fixture(root)

            tool.build_catalog(intake_path, source)

            self.apt_signature_verify.assert_called_once()
            call = self.apt_signature_verify.call_args.kwargs
            self.assertEqual("gideon-vlc.gpg", call["key"].name)
            self.assertEqual("Release.gpg", call["signature"].name)
            self.assertEqual("Release", call["release"].name)

    def test_authenticode_path_with_spaces_is_passed_as_process_environment(self) -> None:
        target = Path(r"C:\review material\vlc signed.msi")
        expected = {"Subject": "CN=VideoLAN", "Thumbprint": "A" * 40}
        completed = tool.subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps({
                "Status": "Valid",
                "Subject": expected["Subject"],
                "Thumbprint": expected["Thumbprint"],
            }),
            stderr="",
        )
        with (
            mock.patch.object(tool, "os") as mocked_os,
            mock.patch.object(tool.shutil, "which", return_value="powershell.exe"),
            mock.patch.object(tool.subprocess, "run", return_value=completed) as run,
        ):
            mocked_os.name = "nt"
            mocked_os.environ.copy.return_value = {"PATH": "fixture"}
            tool._optional_authenticode_verify(target, expected)

        command = run.call_args.args[0]
        environment = run.call_args.kwargs["env"]
        self.assertNotIn(str(target), command)
        self.assertIn("$env:GIDEON_AUTHENTICODE_TARGET", command[-1])
        self.assertIn("Import-Module Microsoft.PowerShell.Security", command[-1])
        self.assertEqual(str(target), environment["GIDEON_AUTHENTICODE_TARGET"])
        self.assertEqual(str(Path("powershell.exe").parent / "Modules"), environment["PSModulePath"])

    def test_bad_apt_release_signature_prevents_catalog_publication(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-vlc-catalog-") as temp:
            root = Path(temp)
            intake_path, source, _intake = self._fixture(root)
            output = root / "output"
            self.apt_signature_verify.side_effect = tool.VlcOfflineCatalogBuildError(
                "VLC_INTAKE_APT_SIGNATURE_VERIFY_FAILED"
            )

            with self.assertRaisesRegex(
                tool.VlcOfflineCatalogBuildError,
                "VLC_INTAKE_APT_SIGNATURE_VERIFY_FAILED",
            ):
                tool.build_catalog(intake_path, source, output_root=output)
            self.assertFalse(output.exists())

    def test_rejects_linux_dependency_not_declared_as_bundled_or_base(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-vlc-catalog-") as temp:
            root = Path(temp)
            intake_path, source, intake = self._fixture(root)
            intake["Variants"][1]["DependencyClosure"]["BaseSystemPackages"] = []
            intake_path.write_text(json.dumps(intake), encoding="utf-8")
            with self.assertRaisesRegex(tool.VlcOfflineCatalogBuildError, "VLC_INTAKE_APT_DEPENDENCY_UNDECLARED"):
                tool.build_catalog(intake_path, source)

    def test_rejects_duplicate_effective_variant_selector(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-vlc-catalog-") as temp:
            root = Path(temp)
            intake_path, source, intake = self._fixture(root)
            duplicate = copy.deepcopy(intake["Variants"][0])
            duplicate["VariantId"] = "vlc-win-x64-secondary"
            duplicate["Files"][0]["Path"] = "variants/windows/x86_64/vlc-3.0.23-win64-secondary.msi"
            intake["Variants"].append(duplicate)
            intake_path.write_text(json.dumps(intake), encoding="utf-8")
            with self.assertRaisesRegex(
                tool.VlcOfflineCatalogBuildError,
                "VLC_INTAKE_VARIANT_SELECTOR_DUPLICATE",
            ):
                tool.build_catalog(intake_path, source)

    def test_rejects_dists_layout_for_flat_local_apt_repository(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-vlc-catalog-") as temp:
            root = Path(temp)
            intake_path, source, intake = self._fixture(root)
            repo = intake["Variants"][1]["Install"]["RepositoryPath"]
            for role, nested_relative in (
                ("apt-packages-index", "dists/test/main/binary-amd64/Packages"),
                ("apt-release", "dists/test/Release"),
            ):
                with self.subTest(role=role):
                    altered = copy.deepcopy(intake)
                    row = next(item for item in altered["Variants"][1]["Files"] if item["Role"] == role)
                    row["Path"] = f"{repo}/{nested_relative}"
                    intake_path.write_text(json.dumps(altered), encoding="utf-8")
                    with self.assertRaisesRegex(
                        tool.VlcOfflineCatalogBuildError,
                        "VLC_INTAKE_APT_FLAT_REPOSITORY_LAYOUT_REQUIRED",
                    ):
                        tool.build_catalog(intake_path, source)

    def test_rejects_wrong_local_hash_before_any_output_is_published(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-vlc-catalog-") as temp:
            root = Path(temp)
            intake_path, source, intake = self._fixture(root)
            intake["Variants"][0]["Files"][0]["Sha256"] = "0" * 64
            intake_path.write_text(json.dumps(intake), encoding="utf-8")
            output = root / "output"
            with self.assertRaisesRegex(tool.VlcOfflineCatalogBuildError, "VLC_INTAKE_ARTIFACT_HASH_MISMATCH"):
                tool.build_catalog(intake_path, source, output_root=output)
            self.assertFalse(output.exists())

    def test_refuses_to_replace_nonempty_reviewed_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-vlc-catalog-") as temp:
            root = Path(temp)
            intake_path, source, _intake = self._fixture(root)
            output = root / "existing"; output.mkdir()
            (output / "catalog.json").write_text("reviewed", encoding="utf-8")
            with self.assertRaisesRegex(tool.VlcOfflineCatalogBuildError, "VLC_INTAKE_OUTPUT_NOT_EMPTY"):
                tool.build_catalog(intake_path, source, output_root=output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
