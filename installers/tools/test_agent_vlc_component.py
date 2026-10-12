"""Focused contract for the small Agent core / signed VLC component split."""
from __future__ import annotations

import hashlib
import inspect
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(os.environ.get("GIDEON_TEST_ROOT") or Path(__file__).resolve().parents[2]).resolve()
APP = ROOT / "payload/linux/app"
WINDOWS_APP = ROOT / "payload/windows/GIDEON Remote Control/app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import gideon_agent_component as component  # noqa: E402
import gideon_agent_vlc_offline as offline  # noqa: E402
from gideon_agent_catalog import AgentDownloadCatalog  # noqa: E402
from gideon_agent_builder import AgentBuilder  # noqa: E402


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_keypair(root: Path) -> tuple[Path, Path]:
    private = Ed25519PrivateKey.generate()
    private_path = root / "private.pem"
    public_path = root / "public.pem"
    private_path.write_bytes(private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    public_path.write_bytes(private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    return private_path, public_path


def _write_reviewed_windows_catalog(app_root: Path) -> None:
    """Create a deliberately tiny, but structurally complete, reviewed kit."""
    kit = app_root / "third_party/vlc-offline"
    kit.mkdir(parents=True)
    installer_path = "variants/windows/x86_64/vlc-test.exe"
    installer_bytes = b"not-an-executable; fixture only\n"
    source_path = "legal/sources/vlc-test-source.tar.xz"
    source_bytes = b"corresponding source fixture\n"
    source_id = "vlc-test-source"
    source_materials = {
        "Schema": "gideon-vlc-source-materials/v1",
        "Product": "VLC media player",
        "License": "GPL-2.0-or-later",
        "SourceOffer": {"Method": "bundled-source"},
        "Sources": [{"SourceId": source_id, "Paths": [source_path]}],
        "Artifacts": [{
            "VariantId": "windows-x64-test",
            "Path": installer_path,
            "SourceId": source_id,
            "UpstreamSha256": _hash(installer_bytes),
        }],
    }
    legal_bytes = {
        "legal/GPL-2.0.txt": b"GPL test material\n",
        "legal/VLC-NOTICE.md": b"VideoLAN test notice\n",
        "legal/SOURCE-OFFER.md": b"Corresponding source offer\n",
        "legal/SOURCE-MATERIALS.json": (
            json.dumps(source_materials, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        ).encode("utf-8"),
        source_path: source_bytes,
    }
    for relative, data in legal_bytes.items():
        target = kit / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    installer = kit / installer_path
    installer.parent.mkdir(parents=True, exist_ok=True)
    installer.write_bytes(installer_bytes)
    catalog = {
        "Schema": offline.OFFLINE_CATALOG_SCHEMA,
        "CatalogVersion": "vlc-component-test-1",
        "Vendor": {
            "Name": "VideoLAN",
            "Product": "VLC media player",
            "ProjectUrl": "https://www.videolan.org/",
            "SourceUrl": "https://get.videolan.org/",
        },
        "Legal": {
            "License": "GPL-2.0-or-later",
            "RequiredFiles": [*offline.REQUIRED_LEGAL_FILES, source_path],
            "Materials": [
                {"Path": relative, "SizeBytes": len(data), "Sha256": _hash(data)}
                for relative, data in legal_bytes.items()
            ],
            "BundledSources": [{
                "Path": source_path,
                "Role": "source-archive",
                "SourceId": source_id,
                "SizeBytes": len(source_bytes),
                "Sha256": _hash(source_bytes),
            }],
        },
        "Variants": [{
            "VariantId": "windows-x64-test",
            "Platform": "windows",
            "Architecture": "x86_64",
            "CorrespondingSourceIds": [source_id],
            "Install": {"Mode": "windows-nsis-exe"},
            "DependencyClosure": {"Complete": True, "EntryPackages": []},
            "Files": [{
                "Path": installer_path,
                "Role": "installer",
                "SizeBytes": len(installer_bytes),
                "Sha256": _hash(installer_bytes),
                "Authenticode": {"Subject": "CN=VideoLAN", "Thumbprint": "A" * 40},
            }],
        }],
    }
    catalog_path = kit / offline.CATALOG_NAME
    catalog_path.write_text(json.dumps(catalog), encoding="utf-8")
    expected_files = 1 + len(catalog["Legal"]["RequiredFiles"]) + sum(
        len(variant["Files"]) for variant in catalog["Variants"]
    )
    (app_root / offline.SOURCE_BASELINE_NAME).write_text(json.dumps({
        "Schema": offline.SOURCE_BASELINE_SCHEMA,
        "SourceRoot": str(offline.CATALOG_DIR_RELATIVE),
        "CatalogPath": str(offline.CATALOG_DIR_RELATIVE / offline.CATALOG_NAME),
        "CatalogVersion": catalog["CatalogVersion"],
        "CatalogSizeBytes": catalog_path.stat().st_size,
        "CatalogSha256": _hash(catalog_path.read_bytes()),
        "ExpectedFiles": expected_files,
    }), encoding="utf-8")


class AgentVlcComponentTests(unittest.TestCase):
    def test_download_catalog_keeps_compatible_default_and_blocks_unpublished_core(self) -> None:
        parameter = inspect.signature(AgentDownloadCatalog.generate).parameters["vlc_delivery"]
        self.assertEqual("bundled", parameter.default)
        direct_builder = inspect.signature(AgentBuilder.generate).parameters["vlc_delivery"]
        self.assertEqual("bundled", direct_builder.default)
        catalog_source = (APP / "gideon_agent_catalog.py").read_text(encoding="utf-8-sig")
        builder_source = (APP / "gideon_agent_builder.py").read_text(encoding="utf-8-sig")
        self.assertIn("AGENT_VLC_COMPONENT_DELIVERY_UNAVAILABLE", catalog_source)
        self.assertIn("AGENT_VLC_COMPONENT_DELIVERY_UNAVAILABLE", builder_source)
        self.assertIn("required=platform_target in", catalog_source)
        self.assertIn("required=True", builder_source)

    def test_public_agent_generation_rejects_component_mode(self) -> None:
        catalog_source = (APP / "gideon_agent_catalog.py").read_text(encoding="utf-8-sig")
        builder_source = (APP / "gideon_agent_builder.py").read_text(encoding="utf-8-sig")
        self.assertNotIn("stage_vlc_core_profile(", catalog_source)
        self.assertNotIn("stage_vlc_core_profile(", builder_source)
        template = (APP / "gideon_web_admin/templates/installers.html").read_text(encoding="utf-8-sig")
        self.assertIn('value="component" disabled', template)

    def test_core_profile_is_small_and_declares_only_the_signed_component_contract(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-core-profile-") as temporary:
            payload = Path(temporary) / "payload"
            profile = component.stage_vlc_core_profile(
                payload,
                platform_name="windows",
                architecture="amd64",
            )
            root = payload / "third_party/vlc-offline"
            self.assertFalse(profile["Bundled"])
            self.assertEqual(component.COMPONENT_DELIVERY, profile["Delivery"])
            self.assertTrue((root / offline.PROFILE_NAME).is_file())
            self.assertFalse((root / offline.CATALOG_NAME).exists())
            self.assertFalse((root / "legal").exists())
            capability = offline.offline_vlc_catalog_capability(payload)
            self.assertEqual("COMPONENT_REQUIRED", capability["State"])
            self.assertEqual(component.COMPONENT_KIND, capability["ComponentKind"])

    def test_build_verify_and_stage_one_exact_component(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-vlc-component-") as temporary:
            root = Path(temporary)
            app_root = root / "app"
            _write_reviewed_windows_catalog(app_root)
            source_report = offline.validate_offline_vlc_source_baseline(
                app_root, verify_payload=True,
            )
            self.assertEqual("VERIFIED", source_report["State"])
            self.assertTrue(source_report["PayloadVerified"])
            private, public = _write_keypair(root)
            archive = root / "vlc-windows-x64.zip"
            built = component.build_vlc_offline_component(
                app_root,
                archive,
                platform_name="windows",
                architecture="x64",
                signing_private_key=private,
            )
            self.assertTrue(archive.is_file())
            self.assertEqual(component.COMPONENT_KIND, built["Kind"])
            with mock.patch.object(offline, "_runtime_variant", side_effect=lambda catalog: catalog["Variants"][0]):
                verified = component.verify_vlc_offline_component(archive, public)
                staged = root / "staged"
                staged_result = component.stage_verified_vlc_component_payload(archive, public, staged)
            self.assertEqual(built["CatalogSha256"], verified["CatalogSha256"])
            self.assertEqual(verified["Sha256"], staged_result["Sha256"])
            self.assertTrue((staged / "third_party/vlc-offline/catalog.json").is_file())
            with zipfile.ZipFile(archive) as zip_file:
                manifest = json.loads(zip_file.read(component.COMPONENT_MANIFEST_NAME))
                self.assertEqual("GPL-2.0-or-later", manifest["Legal"]["License"])
                self.assertEqual(component.COMPONENT_DELIVERY, manifest["Delivery"]["Mode"])
                self.assertTrue(all(name.startswith("payload/third_party/vlc-offline/") for name in manifest["Payload"]["Files"]))
                self.assertFalse(any("client.key" in name.casefold() for name in zip_file.namelist()))

    def test_source_baseline_rejects_unlisted_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-vlc-source-baseline-") as temporary:
            app_root = Path(temporary) / "app"
            _write_reviewed_windows_catalog(app_root)
            source = app_root / "third_party/vlc-offline"
            (source / "unlisted-file.bin").write_bytes(b"not part of reviewed source")
            with self.assertRaisesRegex(
                offline.OfflineVlcCatalogError,
                "VLC_OFFLINE_SOURCE_FILESET_MISMATCH",
            ):
                offline.validate_offline_vlc_source_baseline(app_root)

    def test_tampered_component_fails_before_staging(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-vlc-component-tamper-") as temporary:
            root = Path(temporary)
            app_root = root / "app"
            _write_reviewed_windows_catalog(app_root)
            private, public = _write_keypair(root)
            original = root / "original.zip"
            component.build_vlc_offline_component(
                app_root, original, platform_name="windows", architecture="x86_64", signing_private_key=private,
            )
            tampered = root / "tampered.zip"
            with zipfile.ZipFile(original) as source, zipfile.ZipFile(tampered, "w", zipfile.ZIP_DEFLATED) as target:
                for name in source.namelist():
                    data = source.read(name)
                    if name.endswith("legal/GPL-2.0.txt"):
                        data = b"tampered GPL material\n"
                    target.writestr(name, data)
            with self.assertRaisesRegex(component.AgentComponentError, "AGENT_COMPONENT_(FILE_HASH_MISMATCH|ARCHIVE_INVALID)"):
                component.verify_vlc_offline_component(tampered, public)

    def test_source_companion_is_content_addressed_and_reused_without_rebuild(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-vlc-source-companion-") as temporary:
            root = Path(temporary)
            app_root = root / "app"
            cache = root / "source-cache"
            _write_reviewed_windows_catalog(app_root)
            private, public = _write_keypair(root)

            first = component.resolve_vlc_source_companion(
                app_root,
                platform_name="windows",
                architecture="x64",
                signing_private_key=private,
                signing_public_key=public,
                source_companion_dir=cache,
            )
            archive = Path(first["artifact"])
            self.assertEqual(f"{first['sha256']}.zip", archive.name)
            self.assertTrue((cache / f"{first['sha256']}.source-companion.json").is_file())
            before = archive.stat().st_mtime_ns

            with mock.patch.object(
                component,
                "build_vlc_source_companion",
                side_effect=AssertionError("the immutable source companion must be reused"),
            ):
                second = component.resolve_vlc_source_companion(
                    app_root,
                    platform_name="windows",
                    architecture="amd64",
                    signing_private_key=private,
                    signing_public_key=public,
                    source_companion_dir=cache,
                )
            self.assertEqual(first["sha256"], second["sha256"])
            self.assertEqual(before, archive.stat().st_mtime_ns)

            payload = root / "payload"
            staged = offline.stage_offline_vlc_bundle(
                app_root,
                payload,
                platform_name="windows",
                architecture="x86_64",
                signing_private_key=private,
                required=True,
                source_delivery="detached",
                source_companion=second["catalog_reference"],
            )
            kit = payload / offline.CATALOG_DIR_RELATIVE
            self.assertEqual("detached", staged["Delivery"])
            self.assertTrue((kit / "variants/windows/x86_64/vlc-test.exe").is_file())
            self.assertFalse((kit / "legal/sources/vlc-test-source.tar.xz").exists())
            self.assertTrue((kit / offline.SOURCE_MATERIALS_PATH).is_file())
            runtime_offer = (kit / offline.SOURCE_OFFER_PATH).read_text(encoding="utf-8")
            self.assertIn(first["artifact_name"], runtime_offer)
            self.assertIn("provide this exact Source Companion", runtime_offer)
            signed_catalog = json.loads((kit / offline.CATALOG_NAME).read_text(encoding="utf-8"))
            self.assertEqual(first["sha256"], signed_catalog["Legal"]["SourceCompanion"]["Sha256"])

    def test_source_companion_explicit_bad_signature_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-vlc-source-companion-bad-") as temporary:
            root = Path(temporary)
            app_root = root / "app"
            cache = root / "source-cache"
            _write_reviewed_windows_catalog(app_root)
            private, public = _write_keypair(root)
            built = component.resolve_vlc_source_companion(
                app_root,
                platform_name="windows",
                architecture="x86_64",
                signing_private_key=private,
                signing_public_key=public,
                source_companion_dir=cache,
            )
            tampered = dict(built)
            tampered["signature"] = "AAAA"
            with self.assertRaisesRegex(component.AgentComponentError, "ARCHIVE_SIGNATURE_INVALID"):
                component.resolve_vlc_source_companion(
                    app_root,
                    platform_name="windows",
                    architecture="x86_64",
                    signing_private_key=private,
                    signing_public_key=public,
                    source_companion_dir=cache,
                    existing_descriptor=tampered,
                )

    def test_runtime_mirrors_are_byte_identical(self) -> None:
        for relative in (
            "gideon_agent_component.py",
            "gideon_agent_security.py",
            "gideon_agent_archive.py",
            "gideon_agent_vlc_offline.py",
            "gideon_agent_payload.py",
            "gideon_agent_installer_contract.py",
            "gideon_agent_builder.py",
            "gideon_agent_catalog.py",
        ):
            self.assertEqual((APP / relative).read_bytes(), (WINDOWS_APP / relative).read_bytes(), relative)


if __name__ == "__main__":
    unittest.main()
