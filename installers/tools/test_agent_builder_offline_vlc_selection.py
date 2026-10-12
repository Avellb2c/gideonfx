"""Focused contracts for distribution-specific offline VLC Agent builds."""
from __future__ import annotations

import inspect
import os
from pathlib import Path
import sys
import types
import unittest


ROOT = Path(os.environ.get("GIDEON_TEST_ROOT") or Path(__file__).resolve().parents[2]).resolve()
APP = (ROOT / "payload/linux/app").resolve()
WINDOWS_APP = (ROOT / "payload/windows/GIDEON Remote Control/app").resolve()
sys.path.insert(0, str(APP))

from gideon_agent_catalog import AgentDownloadCatalog  # noqa: E402
import gideon_agent_vlc_offline as offline  # noqa: E402
from gideon_web_admin.agent_builder_profiles import build_catalog, resolve_choice  # noqa: E402

# installer_orchestration only needs the domain error type from the concrete
# service.  Stub that dependency so this focused unit test does not require the
# Web runtime's optional Argon2 package.
_installer_module_name = "gideon_web_admin.agent_installers"
_previous_installer_module = sys.modules.get(_installer_module_name)
_installer_stub = types.ModuleType(_installer_module_name)
_installer_stub.AgentInstallerError = type("AgentInstallerError", (RuntimeError,), {})
sys.modules[_installer_module_name] = _installer_stub
try:
    from gideon_web_admin.installer_orchestration import InstallerBuildOrchestrator  # noqa: E402
finally:
    if _previous_installer_module is None:
        sys.modules.pop(_installer_module_name, None)
    else:
        sys.modules[_installer_module_name] = _previous_installer_module


def _builder_catalog() -> dict[str, object]:
    return build_catalog([{
        "target_id": "linux_x64",
        "label": "Linux x64",
        "architecture": "x86_64",
        "profile": "linux-default",
        "package_options": [{"value": "native", "resolved": "deb", "ready": True}],
        "ready_any": True,
    }])


class _Installers:
    def __init__(self) -> None:
        self.started: dict[str, object] = {}

    def resolve_builder_selection(self, **kwargs: object) -> dict[str, str]:
        choice = dict(kwargs)
        choice.pop("builder_profile", None)
        selected = resolve_choice(_builder_catalog(), **choice)
        selected["builder_profile"] = "custom"
        return selected

    def start_build(self, **kwargs: object) -> dict[str, object]:
        self.started = dict(kwargs)
        return {"build_id": "test"}


class _Endpoints:
    def endpoints(self) -> list[dict[str, object]]:
        return []

    def resolve_selection(self, endpoint_id: str, gateway_input: str, gateway_mode: str) -> tuple[str, str]:
        return "https://gateway.example.test", "production"


class AgentBuilderOfflineVlcSelectionTests(unittest.TestCase):
    def test_builder_choices_pin_the_reviewed_linux_distribution(self) -> None:
        catalog = _builder_catalog()
        ubuntu = resolve_choice(
            catalog, os_family="linux", os_variant="ubuntu",
            architecture="x86_64", package_choice="native",
        )
        debian = resolve_choice(
            catalog, os_family="linux", os_variant="debian",
            architecture="x86_64", package_choice="native",
        )
        aws = resolve_choice(
            catalog, os_family="linux", os_variant="aws_ubuntu",
            architecture="x86_64", package_choice="native",
        )
        self.assertEqual(("ubuntu", "noble"), (
            ubuntu["offline_vlc_distribution"], ubuntu["offline_vlc_codename"],
        ))
        self.assertEqual(("debian", "bookworm"), (
            debian["offline_vlc_distribution"], debian["offline_vlc_codename"],
        ))
        self.assertEqual(("ubuntu", "noble"), (
            aws["offline_vlc_distribution"], aws["offline_vlc_codename"],
        ))

        raspberry_catalog = build_catalog([{
            "target_id": "linux_arm64",
            "label": "Linux ARM64",
            "architecture": "arm64",
            "profile": "raspberry_pi_64",
            "package_options": [{"value": "native", "resolved": "deb", "ready": True}],
            "ready_any": True,
        }])
        debian_arm = resolve_choice(
            raspberry_catalog, os_family="raspberry", os_variant="debian_bookworm_arm64",
            architecture="arm64", package_choice="native",
        )
        raspbian = resolve_choice(
            raspberry_catalog, os_family="raspberry", os_variant="raspberry_os_64",
            architecture="arm64", package_choice="native",
        )
        self.assertEqual(("debian", "bookworm"), (
            debian_arm["offline_vlc_distribution"], debian_arm["offline_vlc_codename"],
        ))
        self.assertEqual(("raspbian", "bookworm"), (
            raspbian["offline_vlc_distribution"], raspbian["offline_vlc_codename"],
        ))

    def test_orchestrator_preserves_selector_until_build_queue(self) -> None:
        installers = _Installers()
        orchestrator = InstallerBuildOrchestrator(installers=installers, endpoints=_Endpoints())
        orchestrator.queue({
            "os_family": "linux",
            "os_variant": "debian",
            "architecture": "x86_64",
            "package_choice": "native",
            "builder_profile": "custom",
            "channel": "pilot",
            "vlc_delivery": "bundled",
        }, actor="tester", remote_ip="127.0.0.1")
        self.assertEqual("debian", installers.started["offline_vlc_distribution"])
        self.assertEqual("bookworm", installers.started["offline_vlc_codename"])
        self.assertEqual("bundled", installers.started["vlc_delivery"])

    def test_orchestrator_rejects_component_before_start_build(self) -> None:
        installers = _Installers()
        orchestrator = InstallerBuildOrchestrator(installers=installers, endpoints=_Endpoints())
        with self.assertRaisesRegex(RuntimeError, "AGENT_VLC_COMPONENT_DELIVERY_UNAVAILABLE"):
            orchestrator.queue({
                "os_family": "linux",
                "os_variant": "debian",
                "architecture": "x86_64",
                "package_choice": "native",
                "builder_profile": "custom",
                "channel": "pilot",
                "vlc_delivery": "component",
            }, actor="tester", remote_ip="127.0.0.1")
        self.assertEqual({}, installers.started)

    def test_staging_selects_only_the_exact_linux_release(self) -> None:
        catalog = {"Variants": [
            {
                "VariantId": "ubuntu-noble-amd64", "Platform": "linux", "Architecture": "x86_64",
                "Distribution": "ubuntu", "Codename": "noble",
            },
            {
                "VariantId": "debian-bookworm-amd64", "Platform": "linux", "Architecture": "x86_64",
                "Distribution": "debian", "Codename": "bookworm",
            },
        ]}
        selected = offline._selected_variants(
            catalog, platform_name="linux", architecture="amd64",
            distribution="Debian", codename="BOOKWORM",
        )
        self.assertEqual(["debian-bookworm-amd64"], [row["VariantId"] for row in selected])
        self.assertEqual(2, len(offline._selected_variants(
            catalog, platform_name="linux", architecture="x86_64",
        )))
        with self.assertRaisesRegex(offline.OfflineVlcCatalogError, "VLC_OFFLINE_TARGET_SELECTOR_INCOMPLETE"):
            offline._selected_variants(
                catalog, platform_name="linux", architecture="x86_64", distribution="debian",
            )
        with self.assertRaisesRegex(offline.OfflineVlcCatalogError, "VLC_OFFLINE_TARGET_VARIANT_UNAVAILABLE"):
            offline._selected_variants(
                catalog, platform_name="linux", architecture="x86_64",
                distribution="ubuntu", codename="jammy",
            )

    def test_all_build_layers_accept_the_explicit_selector(self) -> None:
        self.assertIn("offline_vlc_distribution", inspect.signature(AgentDownloadCatalog.generate).parameters)
        self.assertIn("vlc_delivery", inspect.signature(AgentDownloadCatalog.generate).parameters)
        self.assertIn("distribution", inspect.signature(offline.stage_offline_vlc_bundle).parameters)
        self.assertIn("codename", inspect.signature(offline.stage_offline_vlc_bundle).parameters)
        installers_source = (APP / "gideon_web_admin/agent_installers.py").read_text(encoding="utf-8-sig")
        self.assertGreaterEqual(installers_source.count("offline_vlc_distribution"), 7)
        self.assertIn("offline_vlc_distribution=offline_vlc_distribution", installers_source)
        self.assertIn("vlc_delivery=vlc_delivery", installers_source)

    def test_runtime_mirrors_remain_byte_identical(self) -> None:
        relatives = (
            "gideon_agent_vlc_offline.py",
            "gideon_agent_catalog.py",
            "gideon_web_admin/agent_builder_profiles.py",
            "gideon_web_admin/installer_orchestration.py",
            "gideon_web_admin/agent_installers.py",
        )
        for relative in relatives:
            with self.subTest(relative=relative):
                self.assertEqual((APP / relative).read_bytes(), (WINDOWS_APP / relative).read_bytes())


if __name__ == "__main__":
    unittest.main()
