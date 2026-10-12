"""Regression checks for DEB generation on Ubuntu build hosts and ARM targets."""
from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile
from types import SimpleNamespace


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

from gideon_agent_catalog import (  # noqa: E402
    AgentDownloadCatalog,
    DEBIAN_AGENT_REQUIREMENTS,
    DEBIAN_SYSTEM_PYTHON_DEPENDENCIES,
    TARGETS,
)
from gideon_agent_installer_contract import verify_artifact_sanity  # noqa: E402
import gideon_agent_update  # noqa: E402


class LinuxDebBuilderContractTests(unittest.TestCase):
    def test_catalog_mirrors_are_byte_identical(self):
        self.assertEqual(
            (APP / "gideon_agent_catalog.py").read_bytes(),
            (WINDOWS_APP / "gideon_agent_catalog.py").read_bytes(),
        )

    def test_native_linux_build_scripts_use_the_validated_runtime_closure(self):
        """Legacy DEB/RPM builders must not silently omit the isolated Player.

        The Python catalog is the usual package path, but the standalone native
        scripts are still supported for controlled offline builds.  They must
        consume the same import-validated payload closure, including the GPL
        notice, rather than carrying a second hand-maintained module list.
        """
        relative = "deploy/agent/linux"
        for app in (APP, WINDOWS_APP):
            for name in ("build-deb.sh", "build-rpm.sh"):
                text = (app / relative / name).read_text(encoding="utf-8-sig")
                self.assertIn("from gideon_agent_payload import copy_agent_runtime_payload", text)
                self.assertIn("copy_agent_runtime_payload(root, target)", text)
                self.assertNotIn("for f in gideon_agent.py", text)
            deb = (app / relative / "build-deb.sh").read_text(encoding="utf-8-sig")
            self.assertIn("THIRD_PARTY_VLC_NOTICE.txt", deb)

    def test_player_launcher_is_signed_campaign_non_root_desktop_boundary(self):
        """Linux/Raspberry playback is automatic only for a signed campaign.

        This is intentionally a package/launcher contract instead of an
        integration test: CI hosts normally have neither a physical X11/Wayland
        session nor an installed external VLC. It guards the security boundary:
        the root timer is not playback authorization, VLC runs as the physical
        desktop account, and an explicit local-admin disable remains available.
        """
        relative = "deploy/agent/linux/gideon-agent-player-launch"
        for app in (APP, WINDOWS_APP):
            launcher = app / relative
            self.assertTrue(launcher.is_file(), launcher)
            text = launcher.read_text(encoding="utf-8-sig")
            self.assertIn("PLAYER_DISABLED_BY_LOCAL_ADMIN", text)
            self.assertIn("State=AUTOMATIC", text)
            self.assertIn("GIDEON_PLAYER_PILOT_ENABLED=1", text)
            self.assertIn("runuser -u", text)
            self.assertIn("setfacl", text)
            self.assertIn("PlayerManifestStore", text)
            self.assertIn("require_safe_agent_root", text)
            self.assertIn("--list-outputs", text)
            self.assertIn("--map-output", text)
            self.assertIn("write_output_map", text)
            self.assertIn("PATH=/usr/sbin:/usr/bin:/sbin:/bin", text)
            self.assertNotIn('GIDEON_AGENT_ROOT:-', text)
            self.assertNotIn('GIDEON_AGENT_STATE:-', text)
            self.assertNotIn('GIDEON_MEDIA_ROOT:-', text)
            self.assertNotIn("agent.runtime.json", text)
            self.assertNotIn("client.key", text)
            self.assertNotIn("agent_token", text)
            self.assertNotIn("apt-get", text)
            self.assertNotIn("chmod 777", text)
            self.assertNotIn("systemctl restart", text)

    def test_multimonitor_player_mapping_requires_local_administrator_confirmation(self):
        """Never use connector/DRM order as a hidden VLC monitor selector."""
        for app in (APP, WINDOWS_APP):
            player = (app / "gideon_agent_player.py").read_text(encoding="utf-8-sig")
            tray = (app / "gideon_agent_tray.py").read_text(encoding="utf-8-sig")
            mapper = app / "deploy/agent/windows/gideon-agent-player-map.ps1"
            self.assertIn("PLAYER_OUTPUT_MAPPING_REQUIRED", player)
            self.assertIn("--qt-fullscreen-screennumber=", player)
            self.assertIn("_read_local_output_map", player)
            self.assertIn("Configurar salidas físicas de Player", tray)
            self.assertTrue(mapper.is_file())
            source = mapper.read_text(encoding="utf-8-sig")
            self.assertIn("PLAYER_OUTPUT_MAPPING_ADMIN_REQUIRED", source)
            self.assertIn("PLAYER_OUTPUT_MAPPING_OUTPUT_NOT_CURRENT", source)
            self.assertIn("PLAYER_OUTPUT_MAPPING_ACL_DIRECTORY_FAILED", source)
            if os.name == "posix" and shutil.which("bash"):
                subprocess.run(
                    ["bash", "-n", str(app / "deploy/agent/linux/gideon-agent-player-launch")],
                    check=True,
                    capture_output=True,
                    text=True,
                )

        for app in (APP, WINDOWS_APP):
            catalog = (app / "gideon_agent_catalog.py").read_text(encoding="utf-8-sig")
            updater = (app / "gideon_agent_update_builder.py").read_text(encoding="utf-8-sig")
            contract = (app / "gideon_agent_installer_contract.py").read_text(encoding="utf-8-sig")
            self.assertIn('"gideon-agent-player-launch"', catalog)
            self.assertIn("gideon-agent-player-launch", updater)
            self.assertIn('"gideon-agent-player-launch"', contract)

    def test_deb_uses_system_crypto_pillow_and_pure_python_tray(self):
        self.assertEqual("pystray>=0.19,<1\n", DEBIAN_AGENT_REQUIREMENTS)
        self.assertEqual(
            ("python3-cryptography", "python3-pil", "python3-six", "python3-xlib"),
            DEBIAN_SYSTEM_PYTHON_DEPENDENCIES,
        )
        self.assertNotIn("cryptography", DEBIAN_AGENT_REQUIREMENTS.casefold())
        self.assertNotIn("pillow", DEBIAN_AGENT_REQUIREMENTS.casefold())
        for app in (APP, WINDOWS_APP):
            catalog = (app / "gideon_agent_catalog.py").read_text(encoding="utf-8-sig")
            setup = (app / "deploy/agent/linux/gideon-agent-setup").read_text(encoding="utf-8-sig")
            updater = (app / "gideon_agent_update.py").read_text(encoding="utf-8-sig")
            update_builder = (app / "gideon_agent_update_builder.py").read_text(encoding="utf-8-sig")
            self.assertIn("iproute2", catalog)
            self.assertIn("python3 -m venv --clear --system-site-packages \\\"$ROOT/venv\\\"", catalog)
            self.assertIn("--no-index --find-links=\\\"$ROOT/vendor\\\" --disable-pip-version-check --only-binary=:all: --no-deps", catalog)
            self.assertIn("python3 -m venv --system-site-packages \"$ROOT/venv\"", setup)
            self.assertIn("--no-index --find-links=\"$ROOT/vendor\"", setup)
            self.assertIn("requirements-agent-debian.txt", updater)
            self.assertIn("requirements-agent-debian.txt", update_builder)
            self.assertIn("_stage_debian_offline_wheelhouse(", catalog)
            self.assertIn("vendor/wheelhouse.json", catalog)

    def test_debian_offline_wheelhouse_is_cached_verified_and_staged(self):
        """The build host may download once; the endpoint must never need PyPI."""
        with tempfile.TemporaryDirectory(prefix="gideon-deb-wheelhouse-") as td:
            root = Path(td)
            payload = root / "payload"
            payload.mkdir()
            (payload / "requirements-agent.txt").write_text(
                DEBIAN_AGENT_REQUIREMENTS,
                encoding="utf-8",
            )
            catalog = object.__new__(AgentDownloadCatalog)
            catalog.builder = SimpleNamespace(state_dir=root / "builder-state")
            calls: list[list[str]] = []

            def fake_download(argv, **_kwargs):
                calls.append([str(value) for value in argv])
                destination = Path(argv[argv.index("--dest") + 1])
                destination.mkdir(parents=True, exist_ok=True)
                wheel = destination / "pystray-0.19.5-py2.py3-none-any.whl"
                with zipfile.ZipFile(wheel, "w") as archive:
                    archive.writestr("pystray-0.19.5.dist-info/WHEEL", "Wheel-Version: 1.0\n")
                return subprocess.CompletedProcess(argv, 0, "", "")

            with mock.patch("gideon_agent_catalog.subprocess.run", side_effect=fake_download):
                staged = catalog._stage_debian_offline_wheelhouse(payload, allow_download=True)

            self.assertEqual(1, len(calls))
            self.assertIn("--only-binary=:all:", calls[0])
            self.assertIn("--no-deps", calls[0])
            self.assertEqual(
                [
                    "vendor/wheelhouse.json",
                    "vendor/pystray-0.19.5-py2.py3-none-any.whl",
                ],
                staged["RequiredFiles"],
            )
            self.assertTrue((payload / "vendor/wheelhouse.json").is_file())
            self.assertTrue((payload / "vendor/pystray-0.19.5-py2.py3-none-any.whl").is_file())

            # A reproducible/no-network build consumes the cache and must not
            # call pip again.
            second_payload = root / "payload-from-cache"
            second_payload.mkdir()
            (second_payload / "requirements-agent.txt").write_text(
                DEBIAN_AGENT_REQUIREMENTS,
                encoding="utf-8",
            )
            with mock.patch("gideon_agent_catalog.subprocess.run") as no_download:
                cached = catalog._stage_debian_offline_wheelhouse(second_payload, allow_download=False)
            no_download.assert_not_called()
            self.assertEqual(staged, cached)

    def test_raspberry_targets_describe_desktop_and_headless_boundary(self):
        for target_id in ("linux_arm64", "linux_armhf"):
            row = TARGETS[target_id]
            self.assertIn("Desktop", row["label"])
            self.assertIn("UNSUPPORTED", row["notes"])
            self.assertIn("Agent y SSH", row["notes"])

    def test_fresh_headless_postinst_remains_pending(self):
        for app in (APP, WINDOWS_APP):
            catalog = (app / "gideon_agent_catalog.py").read_text(encoding="utf-8-sig")
            setup = (app / "deploy/agent/linux/gideon-agent-setup").read_text(encoding="utf-8-sig")
            self.assertIn("PENDING|Instalación base completa; identificación/enrolamiento pendiente", catalog)
            self.assertIn("GIDEON Agent instalado pero aún NO configurado", catalog)
            self.assertIn("UNSUPPORTED_HEADLESS_NO_DESKTOP", setup)
            self.assertIn("AGENT_CORE_ACCEPTANCE PASS", setup)

    def test_update_xrdp_rewrite_is_loopback_uri_and_section_scoped(self):
        original = (
            "[Globals]\naddress=0.0.0.0\nport=3389\nsecurity_layer=negotiate\n"
            "[Xorg]\nport=-1\nparam=Xorg\n"
        )
        updated = gideon_agent_update._rewrite_xrdp_loopback(original)
        self.assertIn("[Globals]\nport=tcp://127.0.0.1:3389\n", updated)
        self.assertNotIn("address=0.0.0.0", updated)
        self.assertEqual(1, updated.count("port=tcp://127.0.0.1:3389"))
        self.assertIn("[Xorg]\nport=-1", updated)
        with self.assertRaisesRegex(RuntimeError, "XRDP_GLOBALS_SECTION_MISSING"):
            gideon_agent_update._rewrite_xrdp_loopback("[Xorg]\nport=-1\n")

    def test_xrdp_desktop_isolated_from_physical_wayland_session(self):
        wrapper = gideon_agent_update._xrdp_isolated_startwm()
        self.assertIn("unset DBUS_SESSION_BUS_ADDRESS", wrapper)
        self.assertIn("unset WAYLAND_DISPLAY", wrapper)
        self.assertIn("XDG_RUNTIME_DIR=\"/tmp/gideon-xrdp-", wrapper)
        self.assertIn("dbus-run-session", wrapper)
        self.assertIn("startlxde-pi", wrapper)
        for app in (APP, WINDOWS_APP):
            setup = (app / "deploy/agent/linux/gideon-agent-setup").read_text(encoding="utf-8-sig")
            updater = (app / "gideon_agent_update.py").read_text(encoding="utf-8-sig")
            self.assertIn("REMOTE_ACCESS_SESSION_ISOLATION", setup)
            self.assertIn("_configure_xrdp_session_isolation(log)", updater)

    def test_arm_xorgxrdp_uses_software_buffers_without_disabling_module(self):
        original = '''Section "ServerFlags"
    Option "AutoAddDevices" "off"
EndSection
Section "Module"
    Load "glamoregl"
    Load "xorgxrdp"
EndSection
Section "Device"
    Identifier "Video Card (xrdpdev)"
    Driver "xrdpdev"
    Option "DRMDevice" "/dev/dri/renderD128"
    Option "DRI3" "1"
EndSection
'''
        updated = gideon_agent_update._rewrite_xorgxrdp_arm_software(original)
        self.assertIn('Load "glamoregl"', updated)
        self.assertIn('Option "AutoAddGPU" "off"', updated)
        self.assertIn('Option "DRMDevice" ""', updated)
        self.assertIn('Option "DRI" "0"', updated)
        self.assertIn('Option "DRI3" "0"', updated)
        self.assertIn('Option "Glamor" "off"', updated)
        self.assertNotIn('/dev/dri/renderD128', updated)
        self.assertEqual(updated, gideon_agent_update._rewrite_xorgxrdp_arm_software(updated))

    def test_update_listener_observation_does_not_treat_global_as_loopback(self):
        global_ss = subprocess.CompletedProcess(
            ["ss", "-H", "-ltn"], 0, "LISTEN 0 32 0.0.0.0:3389 0.0.0.0:*\n", ""
        )
        with mock.patch.object(gideon_agent_update.shutil, "which", return_value="/usr/bin/ss"), mock.patch.object(
            gideon_agent_update, "_run", return_value=global_ss
        ):
            self.assertEqual("0.0.0.0:3389", gideon_agent_update._linux_rdp_listener())
        source = (APP / "gideon_agent_update.py").read_text(encoding="utf-8-sig")
        self.assertIn("observed=='127.0.0.1:3389'", source)
        self.assertIn("global listener is rejected", source)

    def test_linux_update_restores_signed_campaign_launcher_and_fixed_timer(self):
        """A signed ZIP update restores +x and the fixed Player retry timer.

        The timer never authorizes arbitrary media: the launcher still requires
        the signed manifest, verified media and a local physical desktop. The
        update profile is an exact signed contract and no bundle value reaches
        a generated command or unit name.
        """
        profile = {
            "PlayerLauncher": {
                "Schema": "gideon-agent-player-launch/v1",
                "Delivery": "install-root-and-systemd",
                "RelativePath": "gideon-agent-player-launch",
                "Activation": "signed-campaign-auto",
                "AutoEnable": True,
                "SystemdUnits": "signed-update-or-native-installer",
            }
        }
        with tempfile.TemporaryDirectory(prefix="gideon-player-update-") as td:
            root = Path(td) / "agent-root"
            data = Path(td) / "data"
            root.mkdir()
            launcher = root / "gideon-agent-player-launch"
            launcher.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            os.chmod(launcher, 0o644)  # expected after Python ZIP extraction
            log = data / "update.log"
            with mock.patch.object(gideon_agent_update, "_platform_id", return_value="linux"), mock.patch.object(
                gideon_agent_update.os, "chmod"
            ) as chmod, mock.patch.object(
                gideon_agent_update, "PLAYER_LAUNCHER_ALLOWED_ROOTS", set()
            ):
                gideon_agent_update._restore_linux_player_launcher(profile, root, log)
            chmod.assert_called_once_with(launcher, 0o755)
            self.assertIn("PLAYER_LAUNCHER_READY activation=SIGNED_CAMPAIGN_AUTO", log.read_text(encoding="utf-8"))

        for app in (APP, WINDOWS_APP):
            builder = (app / "gideon_agent_update_builder.py").read_text(encoding="utf-8-sig")
            updater = (app / "gideon_agent_update.py").read_text(encoding="utf-8-sig")
            self.assertIn("profile['PlayerLauncher']=dict(PLAYER_LAUNCHER_PROFILE)", builder)
            self.assertIn("_restore_linux_player_launcher(profile,root,log)", updater)
            self.assertNotIn("/usr/local/bin", updater)
            self.assertIn("PLAYER_SYSTEMD_UNIT_DIR=Path('/etc/systemd/system')", updater)
            self.assertIn("systemctl','enable','--now','gideon-agent-player-launch.timer", updater)

    def test_linux_host_forces_portable_gzip_deb_payload(self):
        for app in (APP, WINDOWS_APP):
            text = (app / "gideon_agent_catalog.py").read_text(encoding="utf-8-sig")
            self.assertIn('"--root-owner-group", "-Zgzip"', text)

    def test_failed_web_build_revokes_one_time_grant(self):
        for app in (APP, WINDOWS_APP):
            text = (app / "gideon_web_admin/agent_installers.py").read_text(encoding="utf-8-sig")
            self.assertIn("installer-build-failed:{build_id}", text)
            self.assertIn("grant_revoked_at=grant_revoked_at", text)

    @unittest.skipUnless(os.name == "posix" and shutil.which("dpkg-deb"), "dpkg-deb POSIX regression check")
    def test_deb_permissions_ignore_hardened_umask(self):
        with tempfile.TemporaryDirectory(prefix="gideon-deb-modes-") as td:
            root = Path(td) / "deb-root"
            old_umask = os.umask(0o027)
            try:
                debian = root / "DEBIAN"
                setup = root / "opt/gideon-agent/gideon-agent-setup"
                bootstrap = root / "opt/gideon-agent/bootstrap.enrollment"
                control = debian / "control"
                postinst = debian / "postinst"
                debian.mkdir(parents=True)
                setup.parent.mkdir(parents=True)
                setup.write_text("#!/bin/sh\n", encoding="utf-8")
                bootstrap.write_text("temporary", encoding="utf-8")
                control.write_text(
                    "Package: gideon-agent\nVersion: 2.4.16\nArchitecture: all\n"
                    "Maintainer: GIDEON\nDescription: mode test\n",
                    encoding="utf-8",
                )
                postinst.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            finally:
                os.umask(old_umask)

            self.assertEqual(0o750, debian.stat().st_mode & 0o777)
            AgentDownloadCatalog._normalize_deb_tree_permissions(root, debian)
            self.assertEqual(0o755, debian.stat().st_mode & 0o777)
            self.assertEqual(0o755, setup.stat().st_mode & 0o777)
            self.assertEqual(0o600, bootstrap.stat().st_mode & 0o777)
            self.assertEqual(0o644, control.stat().st_mode & 0o777)
            self.assertEqual(0o755, postinst.stat().st_mode & 0o777)

            package = Path(td) / "gideon-agent.deb"
            extracted = Path(td) / "extracted"
            extracted_control = Path(td) / "extracted-control"
            subprocess.run(
                ["dpkg-deb", "--build", "--root-owner-group", "-Zgzip", str(root), str(package)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(["dpkg-deb", "--extract", str(package), str(extracted)], check=True)
            subprocess.run(["dpkg-deb", "--control", str(package), str(extracted_control)], check=True)
            self.assertEqual(0o755, (extracted / "opt/gideon-agent").stat().st_mode & 0o777)
            self.assertEqual(0o755, (extracted / "opt/gideon-agent/gideon-agent-setup").stat().st_mode & 0o777)
            self.assertEqual(0o600, (extracted / "opt/gideon-agent/bootstrap.enrollment").stat().st_mode & 0o777)
            self.assertEqual(0o644, (extracted_control / "control").stat().st_mode & 0o777)
            self.assertEqual(0o755, (extracted_control / "postinst").stat().st_mode & 0o777)

    def test_python_deb_backend_embeds_and_verifies_contract(self):
        with tempfile.TemporaryDirectory(prefix="gideon-deb-contract-") as td:
            root = Path(td) / "root"
            debian = root / "DEBIAN"
            payload = root / "opt/gideon-agent"
            output = Path(td) / "GIDEONAgent-linux_arm64-test.deb"
            debian.mkdir(parents=True)
            payload.mkdir(parents=True)
            (debian / "control").write_text(
                "Package: gideon-agent\nVersion: 2.4.16\nArchitecture: arm64\n"
                "Maintainer: GIDEON\nDescription: test\n",
                encoding="utf-8",
            )
            contract = {"schema": "gideon-agent-installer-contract/v2", "status": "PASS"}
            contract_path = payload / "installer.contract.json"
            contract_path.write_text(json.dumps(contract) + "\n", encoding="utf-8")
            (payload / "runtime-test.bin").write_bytes(
                b"".join(hashlib.sha256(str(i).encode()).digest() for i in range(512))
            )
            AgentDownloadCatalog._build_deb_python(root, debian, output)
            result = verify_artifact_sanity(
                output,
                package_type="deb",
                expected_version="2.4.16",
                expected_contract_sha256=hashlib.sha256(contract_path.read_bytes()).hexdigest(),
            )
            self.assertEqual("PASS", result["status"])
            self.assertTrue(result["embedded_contract_verified"])


if __name__ == "__main__":
    unittest.main()
