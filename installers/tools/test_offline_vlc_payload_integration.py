from __future__ import annotations

"""Regression checks for target-aware, offline VLC Agent payload staging.

The tests intentionally contain no VLC binary and never access a network.  They
cover the safe default (a signed-install-only profile with no catalog) and make
sure a later Windows EXE contract refresh cannot discard the profile hash.
"""

import json
import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest
import hashlib


ROOT = (
    Path(os.environ["GIDEON_TEST_ROOT"]).resolve()
    if os.environ.get("GIDEON_TEST_ROOT")
    else Path(__file__).resolve().parents[2]
)
APP = Path(os.environ.get("GIDEON_TEST_APP") or (ROOT / "payload/linux/app")).resolve()
WINDOWS_APP = Path(
    os.environ.get("GIDEON_TEST_WINDOWS_APP") or (ROOT / "payload/windows/GIDEON Remote Control/app")
).resolve()
sys.path.insert(0, str(APP))

from gideon_agent_installer_contract import (  # noqa: E402
    COMMON_REQUIRED,
    PLATFORM_REQUIRED,
    REPAIR_MARKERS,
    refresh_installer_contract,
    verify_installer_contract,
    write_installer_contract,
)
from gideon_agent_payload import RUNTIME_FILES, copy_agent_runtime_payload  # noqa: E402
from gideon_agent_security import ensure_ed25519_keypair  # noqa: E402
from gideon_agent_vlc_offline import (  # noqa: E402
    OFFLINE_PROFILE_SCHEMA,
    stage_offline_vlc_bundle,
)


class OfflineVlcPayloadIntegrationTests(unittest.TestCase):
    VERSION = "2.4.32"

    def _minimal_contract_payload(self, root: Path) -> Path:
        payload = root / "payload"
        payload.mkdir(parents=True)
        for relative in COMMON_REQUIRED:
            path = payload / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if relative == "gideon_agent.py":
                path.write_text(f'VERSION = "{self.VERSION}"\n', encoding="utf-8")
            elif relative == "agent.template.json":
                path.write_text(
                    json.dumps({"agent_version": self.VERSION, "control_plane": {"base_url": "https://gateway.example"}}),
                    encoding="utf-8",
                )
            elif relative == "runtime.contract.json":
                path.write_text(json.dumps({"agent_version": self.VERSION}), encoding="utf-8")
            else:
                path.write_text("required\n", encoding="utf-8")
        for relative in PLATFORM_REQUIRED["linux"]:
            path = payload / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if relative == "gideon-agent-setup":
                path.write_text("\n".join(REPAIR_MARKERS["linux"]) + "\n", encoding="utf-8")
            else:
                path.write_text("required\n", encoding="utf-8")
        return payload

    def test_mirrors_and_runtime_closure_include_offline_modules(self) -> None:
        for name in ("gideon_agent_vlc_offline.py", "gideon_agent_vlc_offline_control.py"):
            self.assertIn(name, RUNTIME_FILES)
            self.assertEqual((APP / name).read_bytes(), (WINDOWS_APP / name).read_bytes(), name)
        for name in ("gideon_agent_payload.py", "gideon_agent_catalog.py", "gideon_agent_builder.py", "gideon_agent_installer_contract.py"):
            self.assertEqual((APP / name).read_bytes(), (WINDOWS_APP / name).read_bytes(), name)

    def test_default_payload_is_explicitly_offline_and_contract_hashed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-vlc-offline-stage-") as td:
            root = Path(td)
            source_without_catalog = root / "source"
            source_without_catalog.mkdir()
            payload = self._minimal_contract_payload(root)
            private = root / "keys" / "private.pem"
            public = root / "keys" / "public.pem"
            ensure_ed25519_keypair(private, public)

            staged = stage_offline_vlc_bundle(
                source_without_catalog,
                payload,
                platform_name="linux",
                architecture="arm64",
                signing_private_key=private,
                required=False,
            )
            self.assertFalse(staged["Bundled"])
            self.assertEqual(["third_party/vlc-offline/gideon-vlc-offline-profile.json"], staged["RequiredFiles"])
            profile_path = payload / staged["RequiredFiles"][0]
            profile = json.loads(profile_path.read_text(encoding="utf-8"))
            self.assertEqual(OFFLINE_PROFILE_SCHEMA, profile["Schema"])
            self.assertFalse(profile["Bundled"])
            self.assertFalse(profile["NetworkDownloads"])

            contract = write_installer_contract(
                payload,
                target_id="linux_arm64",
                platform_name="linux",
                architecture="arm64",
                version=self.VERSION,
                package_type="deb",
                extra_required=staged["RequiredFiles"],
            )
            self.assertIn(staged["RequiredFiles"][0], contract["required_file_sha256"])
            self.assertEqual("PASS", verify_installer_contract(payload, expected_version=self.VERSION)["status"])

            # The Windows EXE backend refreshes its contract after creating the
            # service host.  Preserve existing offline requirements as well.
            service_host = payload / "GIDEONAgentServiceHost.exe"
            service_host.write_bytes(b"offline-vlc-contract-test")
            refreshed = refresh_installer_contract(payload, extra_required=("GIDEONAgentServiceHost.exe",))
            self.assertIn(staged["RequiredFiles"][0], refreshed["required_file_sha256"])
            self.assertIn("GIDEONAgentServiceHost.exe", refreshed["required_file_sha256"])
            self.assertEqual("PASS", verify_installer_contract(payload, expected_version=self.VERSION)["status"])

            profile_path.write_text("tampered\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "INSTALLER_CONTRACT_HASH_MISMATCH"):
                verify_installer_contract(payload, expected_version=self.VERSION)

    def test_reviewed_catalog_stages_only_the_exact_target_variant(self) -> None:
        """A Windows installer must not accidentally carry Linux APT payloads."""
        with tempfile.TemporaryDirectory(prefix="gideon-vlc-offline-target-") as td:
            root = Path(td)
            source = root / "source" / "third_party" / "vlc-offline"
            source.mkdir(parents=True)
            files: list[dict[str, object]] = []

            def put(relative: str, content: bytes, role: str, **extra: object) -> dict[str, object]:
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
                row: dict[str, object] = {
                    "Path": relative,
                    "SizeBytes": len(content),
                    "Sha256": hashlib.sha256(content).hexdigest(),
                    "Role": role,
                }
                row.update(extra)
                return row

            legal_required = (
                "legal/GPL-2.0.txt",
                "legal/VLC-NOTICE.md",
                "legal/SOURCE-OFFER.md",
                "legal/SOURCE-MATERIALS.json",
            )
            for relative in legal_required:
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("legal material\n", encoding="utf-8")
            windows_installer = put(
                "windows/vlc-test.msi", b"windows-vlc", "installer",
                Authenticode={"Subject": "CN=VideoLAN", "Thumbprint": "A" * 40},
            )
            linux_files = [
                put("linux/repo/key.gpg", b"key", "apt-key"),
                put("linux/repo/InRelease", b"release", "apt-inrelease"),
                put("linux/repo/Packages", b"packages", "apt-packages-index"),
                put(
                    "linux/repo/pool/vlc.deb", b"deb", "deb",
                    Package="vlc", Version="3.0.0", DebArchitecture="arm64",
                ),
            ]
            windows_source = put(
                "legal/sources/windows/vlc-source.tar.xz", b"windows-source", "source-archive",
                SourceId="windows-corresponding-source",
            )
            linux_source = put(
                "legal/sources/linux/vlc-source.tar.xz", b"linux-source", "source-archive",
                SourceId="linux-corresponding-source",
            )
            source_materials = {
                "Schema": "gideon-vlc-source-materials/v1",
                "Product": "VLC media player",
                "License": "GPL-2.0-or-later",
                "SourceOffer": {"Method": "bundled-source"},
                "Sources": [
                    {"SourceId": "windows-corresponding-source"},
                    {"SourceId": "linux-corresponding-source"},
                ],
                "Artifacts": [
                    {
                        "VariantId": "windows-x64", "Path": windows_installer["Path"],
                        "SourceId": "windows-corresponding-source",
                        "UpstreamSha256": windows_installer["Sha256"],
                    },
                    {
                        "VariantId": "linux-arm64", "Path": linux_files[-1]["Path"],
                        "SourceId": "linux-corresponding-source",
                        "UpstreamSha256": linux_files[-1]["Sha256"],
                    },
                ],
            }
            (source / "legal/SOURCE-MATERIALS.json").write_text(
                json.dumps(source_materials, sort_keys=True), encoding="utf-8",
            )
            all_legal = list(legal_required) + [windows_source["Path"], linux_source["Path"]]
            legal_materials = [{
                "Path": relative,
                "SizeBytes": (source / relative).stat().st_size,
                "Sha256": hashlib.sha256((source / relative).read_bytes()).hexdigest(),
            } for relative in all_legal]
            catalog = {
                "Schema": "gideon-vlc-offline-catalog/v1",
                "CatalogVersion": "test-1",
                "Vendor": {
                    "Name": "VideoLAN", "Product": "VLC media player",
                    "ProjectUrl": "https://www.videolan.org/", "SourceUrl": "https://get.videolan.org/",
                },
                "Legal": {
                    "License": "GPL-2.0-or-later",
                    "RequiredFiles": all_legal,
                    "Materials": legal_materials,
                    "BundledSources": [windows_source, linux_source],
                },
                "Variants": [
                    {
                        "VariantId": "windows-x64", "Platform": "windows", "Architecture": "x86_64",
                        "Distribution": "", "Codename": "",
                        "Install": {"Mode": "windows-msi"},
                        "DependencyClosure": {"Complete": True, "EntryPackages": []},
                        "CorrespondingSourceIds": ["windows-corresponding-source"],
                        "Files": [windows_installer],
                    },
                    {
                        "VariantId": "linux-arm64", "Platform": "linux", "Architecture": "arm64",
                        "Distribution": "ubuntu", "Codename": "test",
                        "Install": {
                            "Mode": "apt-local-deb-repository", "RepositoryPath": "linux/repo",
                            "AptSigningKeyPath": "linux/repo/key.gpg",
                        },
                        "DependencyClosure": {"Complete": True, "EntryPackages": ["vlc"]},
                        "CorrespondingSourceIds": ["linux-corresponding-source"],
                        "Files": linux_files,
                    },
                ],
            }
            def publish_source_baseline(catalog_document: dict[str, object]) -> None:
                catalog_path = source / "catalog.json"
                catalog_path.write_text(json.dumps(catalog_document), encoding="utf-8")
                expected_files = 1 + len(catalog_document["Legal"]["RequiredFiles"]) + sum(
                    len(variant["Files"]) for variant in catalog_document["Variants"]
                )
                (root / "source" / "VLC-SOURCE-BASELINE.json").write_text(json.dumps({
                    "Schema": "gideon-vlc-source-baseline/v1",
                    "SourceRoot": "third_party/vlc-offline",
                    "CatalogPath": "third_party/vlc-offline/catalog.json",
                    "CatalogVersion": catalog_document["CatalogVersion"],
                    "CatalogSizeBytes": catalog_path.stat().st_size,
                    "CatalogSha256": hashlib.sha256(catalog_path.read_bytes()).hexdigest(),
                    "ExpectedFiles": expected_files,
                }), encoding="utf-8")

            publish_source_baseline(catalog)
            private = root / "keys" / "private.pem"
            public = root / "keys" / "public.pem"
            ensure_ed25519_keypair(private, public)
            payload = root / "payload"
            result = stage_offline_vlc_bundle(
                root / "source", payload, platform_name="windows", architecture="amd64", signing_private_key=private,
            )
            self.assertTrue(result["Bundled"])
            target = payload / "third_party" / "vlc-offline"
            selected = json.loads((target / "catalog.json").read_text(encoding="utf-8"))
            self.assertEqual(["windows-x64"], [row["VariantId"] for row in selected["Variants"]])
            self.assertTrue((target / "windows/vlc-test.msi").is_file())
            self.assertFalse((target / "linux/repo/pool/vlc.deb").exists())
            self.assertTrue((target / windows_source["Path"]).is_file())
            self.assertFalse((target / linux_source["Path"]).exists())
            targeted_materials = json.loads((target / "legal/SOURCE-MATERIALS.json").read_text(encoding="utf-8"))
            self.assertEqual(
                ["windows-corresponding-source"],
                [row["SourceId"] for row in targeted_materials["Sources"]],
            )
            self.assertIn("third_party/vlc-offline/windows/vlc-test.msi", result["RequiredFiles"])
            self.assertNotIn("third_party/vlc-offline/linux/repo/pool/vlc.deb", result["RequiredFiles"])

            def publish_fixture(
                catalog_document: dict[str, object],
                materials_document: dict[str, object],
            ) -> None:
                materials_bytes = json.dumps(materials_document, sort_keys=True).encode("utf-8")
                (source / "legal/SOURCE-MATERIALS.json").write_bytes(materials_bytes)
                material_row = next(
                    row for row in catalog_document["Legal"]["Materials"]
                    if row["Path"] == "legal/SOURCE-MATERIALS.json"
                )
                material_row["SizeBytes"] = len(materials_bytes)
                material_row["Sha256"] = hashlib.sha256(materials_bytes).hexdigest()
                publish_source_baseline(catalog_document)

            invalid_empty = copy.deepcopy(catalog)
            invalid_empty["Variants"][0]["CorrespondingSourceIds"] = []
            publish_fixture(invalid_empty, copy.deepcopy(source_materials))
            with self.assertRaisesRegex(RuntimeError, "VLC_OFFLINE_VARIANT_SOURCE_IDS_INVALID"):
                stage_offline_vlc_bundle(
                    root / "source", root / "payload-empty-source-ids",
                    platform_name="windows", architecture="amd64", signing_private_key=private,
                )

            missing_source = copy.deepcopy(catalog)
            missing_source["Variants"][0]["CorrespondingSourceIds"] = ["source-not-declared"]
            publish_fixture(missing_source, copy.deepcopy(source_materials))
            with self.assertRaisesRegex(RuntimeError, "VLC_OFFLINE_VARIANT_SOURCE_MISSING"):
                stage_offline_vlc_bundle(
                    root / "source", root / "payload-missing-source",
                    platform_name="windows", architecture="amd64", signing_private_key=private,
                )

            altered_mapping = copy.deepcopy(source_materials)
            windows_evidence = next(
                row for row in altered_mapping["Artifacts"]
                if row["VariantId"] == "windows-x64"
            )
            windows_evidence["SourceId"] = "linux-corresponding-source"
            publish_fixture(copy.deepcopy(catalog), altered_mapping)
            with self.assertRaisesRegex(RuntimeError, "VLC_OFFLINE_SOURCE_ARTIFACT_MAPPING_INVALID"):
                stage_offline_vlc_bundle(
                    root / "source", root / "payload-altered-mapping",
                    platform_name="windows", architecture="amd64", signing_private_key=private,
                )

    def test_catalog_builder_stages_before_contract_generation(self) -> None:
        for app in (APP, WINDOWS_APP):
            source = (app / "gideon_agent_catalog.py").read_text(encoding="utf-8-sig")
            self.assertIn("offline_vlc_bundle = stage_offline_vlc_bundle(", source)
            self.assertIn("offline_python_bundle = self._stage_debian_offline_wheelhouse(", source)
            self.assertIn("*list(offline_python_bundle.get(\"RequiredFiles\") or []),", source)
            self.assertIn("*list(offline_vlc_bundle[\"RequiredFiles\"]),", source)
            self.assertLess(
                source.index("offline_python_bundle = self._stage_debian_offline_wheelhouse("),
                source.index("write_installer_contract("),
            )
            self.assertLess(
                source.index("offline_vlc_bundle = stage_offline_vlc_bundle("),
                source.index("write_installer_contract("),
            )

    def test_runtime_payload_closure_copies_offline_modules_without_catalog(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-vlc-offline-runtime-") as td:
            payload = Path(td) / "payload"
            copy_agent_runtime_payload(APP, payload)
            self.assertTrue((payload / "gideon_agent_vlc_offline.py").is_file())
            self.assertTrue((payload / "gideon_agent_vlc_offline_control.py").is_file())
            self.assertFalse((payload / "third_party/vlc-offline/catalog.json").exists())


if __name__ == "__main__":
    unittest.main()
