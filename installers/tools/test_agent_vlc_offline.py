"""Focused safety checks for the verified offline VLC installer boundary.

These checks deliberately do not install VLC or contact an APT repository. They
guard the two properties that make the endpoint workflow safe: a catalog must
describe a signed, closed local repository, and the generated APT command must
be able to consume file:// packages without exposing a network source.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(os.environ.get("GIDEON_TEST_ROOT") or Path(__file__).resolve().parents[2]).resolve()
APP = Path(os.environ.get("GIDEON_TEST_APP") or (ROOT / "payload/linux/app")).resolve()
sys.path.insert(0, str(APP))

import gideon_agent_vlc_offline as offline  # noqa: E402
import gideon_agent_vlc_offline_control as offline_control  # noqa: E402
import gideon_agent  # noqa: E402


def _file(path: str, role: str, *, package: str = "", version: str = "", architecture: str = "") -> dict[str, object]:
    row: dict[str, object] = {
        "Path": path,
        "Role": role,
        "SizeBytes": 1,
        "Sha256": "0" * 64,
    }
    if role == "deb":
        row.update({"Package": package, "Version": version, "DebArchitecture": architecture})
    return row


def _linux_catalog() -> dict[str, object]:
    legal_materials = [
        {"Path": path, "SizeBytes": 1, "Sha256": "0" * 64}
        for path in offline.REQUIRED_LEGAL_FILES
    ]
    return {
        "Schema": offline.OFFLINE_CATALOG_SCHEMA,
        "CatalogVersion": "vlc-test-1",
        "Vendor": {
            "Name": "VideoLAN",
            "Product": "VLC media player",
            "ProjectUrl": "https://www.videolan.org/",
            "SourceUrl": "https://get.videolan.org/",
        },
        "Legal": {
            "License": "GPL-2.0-or-later",
            "RequiredFiles": list(offline.REQUIRED_LEGAL_FILES),
            "Materials": legal_materials,
        },
        "Variants": [{
            "VariantId": "ubuntu-test-amd64",
            "Platform": "linux",
            "Architecture": "x86_64",
            "Distribution": "ubuntu",
            "Codename": "test",
            "Install": {
                "Mode": "apt-local-deb-repository",
                "RepositoryPath": "repo",
                "AptSigningKeyPath": "repo/videolan-archive-keyring.gpg",
            },
            "DependencyClosure": {"Complete": True, "EntryPackages": ["vlc"]},
            "Files": [
                _file("repo/videolan-archive-keyring.gpg", "apt-key"),
                _file("repo/InRelease", "apt-inrelease"),
                _file("repo/Packages", "apt-packages-index"),
                _file("repo/pool/vlc_3.0.0_amd64.deb", "deb", package="vlc", version="3.0.0", architecture="amd64"),
            ],
        }],
    }


class OfflineVlcCatalogTests(unittest.TestCase):
    def test_targeted_source_preflight_authenticates_original_manifest_bytes(self) -> None:
        original = b'{"scope":"all-reviewed-platforms"}\n'
        filtered = b'{"scope":"debian-bookworm-arm64"}\n'
        catalog = {
            "Legal": {
                "Materials": [{
                    "Path": offline.SOURCE_MATERIALS_PATH,
                    "SizeBytes": len(original),
                    "Sha256": hashlib.sha256(original).hexdigest(),
                }],
            },
        }
        targeted = {
            "License": "GPL-2.0-or-later",
            "RequiredFiles": [offline.SOURCE_MATERIALS_PATH],
            "Materials": [{
                "Path": offline.SOURCE_MATERIALS_PATH,
                "SizeBytes": len(filtered),
                "Sha256": hashlib.sha256(filtered).hexdigest(),
            }],
            "BundledSources": [],
        }

        preflight = offline._source_preflight_legal(catalog, targeted, filtered)

        self.assertEqual(len(original), preflight["Materials"][0]["SizeBytes"])
        self.assertEqual(hashlib.sha256(original).hexdigest(), preflight["Materials"][0]["Sha256"])
        self.assertEqual(len(filtered), targeted["Materials"][0]["SizeBytes"])

    def test_agent_reports_linux_distribution_without_credentials_or_network(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-os-release-") as td:
            os_release = Path(td) / "os-release"
            os_release.write_text(
                'NAME="Debian GNU/Linux"\nID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\n',
                encoding="utf-8",
            )
            with mock.patch.object(gideon_agent, "normalize_platform", return_value="linux"):
                identity = gideon_agent.operating_system_identity(os_release)
            self.assertEqual({
                "Family": "linux",
                "Distribution": "debian",
                "Codename": "bookworm",
                "VersionId": "12",
            }, identity)

    def test_installed_catalog_rejects_tampered_bundled_corresponding_source(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-vlc-runtime-source-") as td:
            agent_root = Path(td) / "agent"
            kit = agent_root / "third_party/vlc-offline"
            kit.mkdir(parents=True)
            source_bytes = b"reviewed-corresponding-source"
            installer_bytes = b"inert-windows-installer"
            legal_bytes = b"reviewed-legal-material"
            source_rel = "legal/sources/vlc-test.tar.xz"
            installer_rel = "variants/windows/x86_64/vlc-test.msi"
            catalog = {
                "Schema": offline.OFFLINE_CATALOG_SCHEMA,
                "CatalogVersion": "vlc-runtime-source-test",
                "Vendor": {
                    "Name": "VideoLAN",
                    "Product": "VLC media player",
                    "ProjectUrl": "https://www.videolan.org/",
                    "SourceUrl": "https://get.videolan.org/",
                },
                "Legal": {
                    "License": "GPL-2.0-or-later",
                    "RequiredFiles": [*offline.REQUIRED_LEGAL_FILES, source_rel],
                    "Materials": [
                        *[{
                            "Path": path,
                            "SizeBytes": len(legal_bytes),
                            "Sha256": hashlib.sha256(legal_bytes).hexdigest(),
                        } for path in offline.REQUIRED_LEGAL_FILES],
                        {
                            "Path": source_rel,
                            "SizeBytes": len(source_bytes),
                            "Sha256": hashlib.sha256(source_bytes).hexdigest(),
                        },
                    ],
                    "BundledSources": [{
                        "Path": source_rel,
                        "Role": "source-archive",
                        "SourceId": "vlc-test",
                        "SizeBytes": len(source_bytes),
                        "Sha256": hashlib.sha256(source_bytes).hexdigest(),
                    }],
                },
                "Variants": [{
                    "VariantId": "windows-test-amd64",
                    "Platform": "windows",
                    "Architecture": "x86_64",
                    "Install": {"Mode": "windows-msi"},
                    "DependencyClosure": {"Complete": True, "EntryPackages": []},
                    "Files": [{
                        "Path": installer_rel,
                        "Role": "installer",
                        "SizeBytes": len(installer_bytes),
                        "Sha256": hashlib.sha256(installer_bytes).hexdigest(),
                        "Authenticode": {"Subject": "CN=VideoLAN", "Thumbprint": "A" * 40},
                    }],
                }],
            }
            for relative in offline.REQUIRED_LEGAL_FILES:
                path = kit / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(legal_bytes)
            source_path = kit / source_rel
            source_path.parent.mkdir(parents=True, exist_ok=True)
            source_path.write_bytes(source_bytes)
            installer_path = kit / installer_rel
            installer_path.parent.mkdir(parents=True, exist_ok=True)
            installer_path.write_bytes(installer_bytes)
            catalog_path = kit / offline.CATALOG_NAME
            catalog_path.write_text(json.dumps(catalog, sort_keys=True), encoding="utf-8")

            private_key = Ed25519PrivateKey.generate()
            private_path = Path(td) / "private.pem"
            public_path = agent_root / "gideon_agent_signing_public.pem"
            private_path.write_bytes(private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
            public_path.write_bytes(private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
            (kit / offline.CATALOG_SIGNATURE_NAME).write_text(
                offline.sign_file(catalog_path, private_path),
                encoding="ascii",
            )
            (kit / offline.PROFILE_NAME).write_text(json.dumps({
                "Schema": offline.OFFLINE_PROFILE_SCHEMA,
                "Bundled": True,
                "CatalogSha256": offline.sha256_file(catalog_path),
            }), encoding="utf-8")

            # The signed catalog remains intact, but the corresponding source
            # shipped next to it is no longer the reviewed byte sequence.
            source_path.write_bytes(b"tampered-corresponding-source")
            with mock.patch.object(offline, "_runtime_variant", side_effect=lambda value: value["Variants"][0]):
                with self.assertRaisesRegex(
                    offline.OfflineVlcCatalogError,
                    "VLC_OFFLINE_LEGAL_MATERIAL_(SIZE|HASH)_MISMATCH",
                ):
                    offline._load_installed_catalog(agent_root, public_path)

    def test_agent_maintenance_gate_blocks_jobs_and_quiesces_tunnel(self) -> None:
        class _Tunnel:
            def __init__(self) -> None:
                self.cancelled = 0

            def begin_update_quiesce(self) -> bool:
                return True

            def cancel_update_quiesce(self) -> None:
                self.cancelled += 1

        class _Client:
            def json(self, *_args, **_kwargs):
                raise AssertionError("Job queue must not be polled during VLC maintenance")

        agent = object.__new__(gideon_agent.Agent)
        agent.reverse_tunnel = _Tunnel()
        agent._offline_vlc_maintenance = False
        agent._offline_vlc_tunnel_quiesced = False
        agent.client = _Client()
        agent._log_event = lambda *_args, **_kwargs: None

        self.assertTrue(agent._begin_offline_vlc_maintenance(require_tunnel=True))
        self.assertTrue(agent._offline_vlc_maintenance)
        self.assertIsNone(agent.next_job())
        agent._end_offline_vlc_maintenance()
        self.assertFalse(agent._offline_vlc_maintenance)
        self.assertEqual(1, agent.reverse_tunnel.cancelled)

    def test_absent_reviewed_catalog_stays_explicitly_not_bundled_and_fails_closed_when_required(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-vlc-offline-stage-") as td:
            root = Path(td)
            app = root / "app"; app.mkdir()
            payload = root / "payload"
            result = offline.stage_offline_vlc_bundle(
                app, payload, platform_name="linux", architecture="x86_64",
                signing_private_key=root / "unused-private-key.pem", required=False,
            )
            self.assertFalse(result["Bundled"])
            capability = offline.offline_vlc_catalog_capability(payload)
            self.assertEqual("NOT_BUNDLED", capability["State"])
            self.assertEqual(offline._normal_platform(), capability["Target"]["Platform"])
            self.assertEqual(offline._normal_arch(), capability["Target"]["Architecture"])
            self.assertIn("Distribution", capability["Target"])
            self.assertIn("Codename", capability["Target"])
            with self.assertRaisesRegex(offline.OfflineVlcCatalogError, "VLC_OFFLINE_CATALOG_REQUIRED_BUT_MISSING"):
                offline.stage_offline_vlc_bundle(
                    app, root / "required-payload", platform_name="linux", architecture="x86_64",
                    signing_private_key=root / "unused-private-key.pem", required=True,
                )

    def test_unreviewed_target_is_explicitly_not_bundled_unless_required(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-vlc-offline-target-") as td:
            root = Path(td)
            app = root / "app"
            kit = app / Path(*offline.CATALOG_DIR_RELATIVE.parts)
            kit.mkdir(parents=True)
            (kit / offline.CATALOG_NAME).write_text(json.dumps(_linux_catalog()), encoding="utf-8")

            payload = root / "payload"
            result = offline.stage_offline_vlc_bundle(
                app,
                payload,
                platform_name="linux",
                architecture="arm64",
                distribution="ubuntu",
                codename="noble",
                signing_private_key=root / "unused-private-key.pem",
                required=False,
            )
            self.assertFalse(result["Bundled"])
            profile = json.loads(
                (payload / "third_party/vlc-offline/gideon-vlc-offline-profile.json").read_text(encoding="utf-8")
            )
            self.assertEqual("VLC_OFFLINE_TARGET_VARIANT_UNAVAILABLE", profile["Reason"])
            self.assertEqual("ubuntu", profile["RequestedTarget"]["Distribution"])
            self.assertEqual("noble", profile["RequestedTarget"]["Codename"])

            with self.assertRaisesRegex(
                offline.OfflineVlcCatalogError,
                "VLC_OFFLINE_TARGET_VARIANT_UNAVAILABLE",
            ):
                offline.stage_offline_vlc_bundle(
                    app,
                    root / "required-payload",
                    platform_name="linux",
                    architecture="arm64",
                    distribution="ubuntu",
                    codename="noble",
                    signing_private_key=root / "unused-private-key.pem",
                    required=True,
                )

    def test_linux_catalog_requires_a_pinned_signed_local_repository(self) -> None:
        valid = _linux_catalog()
        normalized = offline.validate_catalog(valid)
        install = normalized["Variants"][0]["Install"]
        self.assertEqual("repo", install["RepositoryPath"])
        self.assertEqual("repo/videolan-archive-keyring.gpg", install["AptSigningKeyPath"])

        missing_key = copy.deepcopy(valid)
        missing_key["Variants"][0]["Files"] = [
            item for item in missing_key["Variants"][0]["Files"] if item["Role"] != "apt-key"
        ]
        with self.assertRaisesRegex(offline.OfflineVlcCatalogError, "VLC_OFFLINE_APT_REPOSITORY_INCOMPLETE"):
            offline.validate_catalog(missing_key)

        unsigned = copy.deepcopy(valid)
        unsigned["Variants"][0]["Files"] = [
            item for item in unsigned["Variants"][0]["Files"] if item["Role"] != "apt-inrelease"
        ]
        with self.assertRaisesRegex(offline.OfflineVlcCatalogError, "VLC_OFFLINE_APT_RELEASE_SIGNATURE_REQUIRED"):
            offline.validate_catalog(unsigned)

        escaped = copy.deepcopy(valid)
        escaped["Variants"][0]["Files"][2]["Path"] = "outside/Packages"
        with self.assertRaisesRegex(offline.OfflineVlcCatalogError, "VLC_OFFLINE_APT_FILE_OUTSIDE_REPOSITORY"):
            offline.validate_catalog(escaped)

    def test_runtime_catalog_accepts_multipart_sources_for_one_source_id(self) -> None:
        """The builder may bind a Debian .dsc plus multiple source archives.

        Runtime treats SOURCE-MATERIALS.json as an authenticated legal payload
        and validates each expanded catalog row independently.  More than one
        ``source-archive`` row for the same logical SourceId must therefore stay
        valid, while every part remains size/hash bound by ``Materials``.
        """
        catalog = _linux_catalog()
        source_id = "vlc-debian-source"
        parts = (
            ("legal/sources/vlc_3.0.23.dsc", "source-checksum", "1" * 64),
            ("legal/sources/vlc_3.0.23.orig.tar.xz", "source-archive", "2" * 64),
            ("legal/sources/vlc_3.0.23.debian.tar.xz", "source-archive", "3" * 64),
        )
        catalog["Legal"]["RequiredFiles"].extend(path for path, _role, _digest in parts)
        catalog["Legal"]["Materials"].extend(
            {"Path": path, "SizeBytes": 1, "Sha256": digest}
            for path, _role, digest in parts
        )
        catalog["Legal"]["BundledSources"] = [
            {
                "Path": path,
                "Role": role,
                "SourceId": source_id,
                "SizeBytes": 1,
                "Sha256": digest,
            }
            for path, role, digest in parts
        ]

        normalized = offline.validate_catalog(catalog)
        bundled = normalized["Legal"]["BundledSources"]
        self.assertEqual(3, len(bundled))
        self.assertEqual({source_id}, {row["SourceId"] for row in bundled})
        self.assertEqual(2, sum(row["Role"] == "source-archive" for row in bundled))

    def test_linux_catalog_requires_flat_repository_metadata_at_repository_root(self) -> None:
        valid = _linux_catalog()
        cases = (
            (2, "repo/dists/test/main/binary-amd64/Packages"),
            (1, "repo/dists/test/InRelease"),
        )
        for index, path in cases:
            with self.subTest(path=path):
                nested = copy.deepcopy(valid)
                nested["Variants"][0]["Files"][index]["Path"] = path
                with self.assertRaisesRegex(
                    offline.OfflineVlcCatalogError,
                    "VLC_OFFLINE_APT_FLAT_REPOSITORY_LAYOUT_REQUIRED",
                ):
                    offline.validate_catalog(nested)

    def test_catalog_rejects_duplicate_effective_variant_selector(self) -> None:
        duplicate = _linux_catalog()
        second = copy.deepcopy(duplicate["Variants"][0])
        second["VariantId"] = "ubuntu-test-amd64-secondary"
        duplicate["Variants"].append(second)
        with self.assertRaisesRegex(
            offline.OfflineVlcCatalogError,
            "VLC_OFFLINE_VARIANT_SELECTOR_DUPLICATE",
        ):
            offline.validate_catalog(duplicate)

    def test_apt_command_uses_only_signed_file_repository_and_can_read_embedded_debs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-vlc-offline-test-") as td:
            root = Path(td)
            repo = root / "repo"; repo.mkdir()
            key = repo / "videolan-archive-keyring.gpg"; key.write_bytes(b"test-key")
            scratch = root / "scratch"
            with mock.patch.object(offline.shutil, "which", return_value="/usr/bin/apt-get"):
                update = offline._linux_apt_command(repo, key, ["vlc"], scratch, update=True)
                install = offline._linux_apt_command(repo, key, ["vlc"], scratch, update=False)

            source = (scratch / "sources.list").read_text(encoding="utf-8")
            self.assertIn(repo.resolve().as_uri(), source)
            self.assertIn(f"signed-by={key.resolve()}", source)
            self.assertNotIn("trusted=yes", source)
            self.assertIn("Dir::Etc::sourceparts=-", update)
            self.assertIn("Acquire::AllowInsecureRepositories=false", update)
            self.assertIn("APT::Get::AllowUnauthenticated=false", update)
            self.assertNotIn("--no-download", install)
            self.assertEqual("install", install[-2])
            self.assertEqual("vlc", install[-1])

    def test_controller_removes_authorization_when_recovered_child_is_missing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-vlc-controller-test-") as td:
            root = Path(td)
            agent_root = root / "agent"; agent_root.mkdir()
            state_root = root / "state"; state_root.mkdir()
            controller = offline_control.OfflineVlcInstallController(
                agent_root=agent_root,
                state_root=state_root,
                agent_id="agt-offline-vlc-test",
            )
            request_id = "vlc-request-test-0001"
            authorization_path = controller._authorization_path(request_id)
            authorization_path.write_text("{}", encoding="utf-8")
            controller._write_state(
                request_id=request_id,
                state="RUNNING",
                detail="VLC_OFFLINE_INSTALL_STARTED",
                pid=987654321,
            )
            self.assertTrue(authorization_path.is_file())

            with mock.patch.object(offline_control, "_pid_alive", return_value=False):
                report = controller._observe_child(request_id)

            self.assertEqual("FAILED", report["State"])
            self.assertEqual("VLC_OFFLINE_INSTALL_PROCESS_MISSING", report["Detail"])
            self.assertFalse(authorization_path.exists())


if __name__ == "__main__":
    unittest.main()
