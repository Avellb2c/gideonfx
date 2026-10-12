"""Regression contract for Linux Player delivery through signed Agent updates."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock
import zipfile


ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / "payload/linux/app"
WINDOWS_APP = ROOT / "payload/windows/GIDEON Remote Control/app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import gideon_agent_update  # noqa: E402
from gideon_agent import safe_extract  # noqa: E402
from gideon_agent_update_builder import (  # noqa: E402
    AgentUpdateBundleBuilder,
    MAX_SELF_UPDATE_BUNDLE_BYTES,
)


PLAYER_LAUNCHER = {
    "Schema": "gideon-agent-player-launch/v1",
    "Delivery": "install-root-and-systemd",
    "RelativePath": "gideon-agent-player-launch",
    "Activation": "signed-campaign-auto",
    "AutoEnable": True,
    "SystemdUnits": "signed-update-or-native-installer",
}


class AgentPlayerUpdateContractTests(unittest.TestCase):
    def test_linux_mirrors_match_for_player_update_delivery(self) -> None:
        for relative in (
            "gideon_agent_update.py",
            "gideon_agent_update_builder.py",
            "deploy/agent/linux/gideon-agent-player-launch",
            "deploy/agent/linux/packaging/postinst",
            "deploy/agent/linux/packaging/gideon-agent-player-launch.service",
            "deploy/agent/linux/packaging/gideon-agent-player-launch.timer",
        ):
            self.assertEqual(
                (APP / relative).read_bytes(),
                (WINDOWS_APP / relative).read_bytes(),
                relative,
            )

    def test_launcher_defaults_to_signed_campaign_auto_and_keeps_local_disable(self) -> None:
        for app in (APP, WINDOWS_APP):
            source = (app / "deploy/agent/linux/gideon-agent-player-launch").read_text(encoding="utf-8")
            self.assertIn('config_disabled(){', source)
            self.assertIn('PLAYER_DISABLED_BY_LOCAL_ADMIN', source)
            self.assertIn('State=AUTOMATIC', source)
            self.assertNotIn('if [[ "$ENABLE_PILOT" -eq 0 ]] && ! config_enabled', source)
            self.assertIn('systemctl enable --now gideon-agent-player-launch.timer', (
                app / "deploy/agent/linux/packaging/postinst"
            ).read_text(encoding="utf-8"))

    def test_runtime_directory_accepts_only_the_managed_named_user_acl_exception(self) -> None:
        """The runtime ACL may be writable only through its named-user mask."""
        for app in (APP, WINDOWS_APP):
            source = (app / "deploy/agent/linux/gideon-agent-player-launch").read_text(encoding="utf-8")
            start = source.index("is_safe_player_runtime_directory(){")
            end = source.index("require_safe_player_runtime_directory(){", start)
            validator = source[start:end]
            self.assertIn("getfacl -cpE", validator)
            self.assertIn("default:*) return 1", validator)
            self.assertIn("group:*:*) return 1", validator)
            self.assertIn('[[ "$permissions" != *w* ]] || return 1', validator)
            self.assertIn("(8#$mode & 0002)", validator)
            self.assertNotIn("(8#$mode & 0022)", validator)
            self.assertIn('require_safe_player_runtime_directory "$RUNTIME_DIR" || exit 0', source)
            self.assertNotIn('require_safe_root_directory "$RUNTIME_DIR" || exit 0', source)

    def test_linux_launcher_selects_environment_from_the_physical_session_only(self) -> None:
        """A same-user XRDP session must never be mistaken for the real monitor."""
        for app in (APP, WINDOWS_APP):
            source = (app / "deploy/agent/linux/gideon-agent-player-launch").read_text(encoding="utf-8")
            self.assertIn('/proc/[0-9]*', source)
            self.assertIn('"/session-${session}.scope"', source)
            self.assertIn("candidate_wayland", source)
            self.assertIn("wayland-[0-9]*", source)
            self.assertIn('${#wayland_sockets[@]} == 1', source)
            self.assertNotIn('pgrep -u "$uid" -n -f', source)

    def test_linux_launcher_passes_verified_session_into_transient_user_unit(self) -> None:
        """The user manager environment must not replace the physical session."""
        for app in (APP, WINDOWS_APP):
            source = (app / "deploy/agent/linux/gideon-agent-player-launch").read_text(encoding="utf-8")
            transient = source[source.index("systemd-run --user"):source.index("command -v runuser", source.index("systemd-run --user"))]
            self.assertIn('/usr/bin/env "${run_env[@]}"', transient)
            self.assertIn('systemctl --user is-active --quiet gideon-agent-player', transient)
            self.assertIn('read_recorded_runtime_sha', source)
            self.assertIn('RuntimeSha256', source)
            self.assertIn('recorded_runtime_sha" == "$PLAYER_RUNTIME_SHA', source)
            self.assertIn('systemctl --user stop gideon-agent-player', source)
            self.assertIn('PLAYER_LOCAL_COMPANION_RUNTIME_CHANGED', source)
            self.assertIn('PLAYER_LOCAL_COMPANION_EXITED_DURING_START', transient)

    def test_launcher_tracks_a_runtime_closure_and_never_uses_untracked_nohup_fallback(self) -> None:
        """Updates may retire only the exact GIDEON desktop runtime they launched."""
        for app in (APP, WINDOWS_APP):
            source = (app / "deploy/agent/linux/gideon-agent-player-launch").read_text(encoding="utf-8")
            self.assertIn("runtime_closure_sha(){", source)
            for module in ("gideon_agent_player.py", "gideon_agent_display_capability.py", "gideon_agent_bootstrap.py"):
                self.assertIn(module, source)
            self.assertIn("FALLBACK_RECORD=", source)
            self.assertIn("player_process_record(){", source)
            self.assertIn("ProcStartTicks", source)
            self.assertIn("find_verified_player_records", source)
            self.assertIn("start-stop-daemon --start --background --make-pidfile", source)
            self.assertIn("--startas /usr/bin/setsid", source)
            self.assertIn("PLAYER_LOCAL_COMPANION_LEGACY_STOP_TIMEOUT", source)
            self.assertNotIn('nohup "$PY" "$ROOT/gideon_agent_player.py"', source)

    def test_desktop_runtime_handles_controlled_term_without_touching_manual_vlc(self) -> None:
        for app in (APP, WINDOWS_APP):
            source = (app / "gideon_agent_player.py").read_text(encoding="utf-8-sig")
            runtime = source[source.index("class DesktopPlayerRuntime"):source.index("class PlayerAgentBridge")]
            self.assertIn("self._shutdown_requested = False", runtime)
            self.assertIn("signal.SIGTERM", runtime)
            self.assertIn("self._shutdown_requested = True", runtime)
            self.assertIn("self._stop_removed(set())", runtime)

    def test_linux_bundle_declares_signed_campaign_launcher_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with mock.patch.dict(
                os.environ,
                {"GIDEON_AGENT_BUILDER_STATE_DIR": str(root / "builder-state")},
                clear=False,
            ):
                row = AgentUpdateBundleBuilder(APP).build(
                    version="9.9.9",
                    platform="linux",
                    architecture="arm64",
                    output_dir=root / "bundles",
                )
            with zipfile.ZipFile(Path(row["bundle"])) as archive:
                self.assertIn("payload/gideon-agent-player-launch", archive.namelist())
                self.assertFalse(any(name.startswith("payload/third_party/") for name in archive.namelist()))
                profile = json.loads(archive.read("payload/update-profile.json").decode("utf-8-sig"))
                manifest = json.loads(archive.read("release-manifest.json").decode("utf-8-sig"))
            self.assertEqual(PLAYER_LAUNCHER, profile["PlayerLauncher"])
            self.assertFalse(profile["OfflineVlc"]["Bundled"])
            self.assertEqual("VLC_OFFLINE_EXCLUDED_FROM_CORE_SELF_UPDATE", profile["OfflineVlc"]["Reason"])
            self.assertEqual("preserved", profile["OfflineVlc"]["ExistingKit"])
            self.assertLessEqual(Path(row["bundle"]).stat().st_size, MAX_SELF_UPDATE_BUNDLE_BYTES)
            self.assertEqual(profile["OfflineVlc"], manifest["OfflineVlc"])
            self.assertIn("gideon-agent-player-launch", manifest["Files"])
            self.assertFalse(any(name.startswith("third_party/") for name in manifest["Files"]))
            self.assertFalse(any(name.startswith("payload/player-systemd/") for name in archive.namelist()))

    def test_core_update_preserves_existing_reviewed_component_kit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install_root = root / "installed-agent"
            component = install_root / "third_party" / "vlc-offline" / "catalog.json"
            component.parent.mkdir(parents=True)
            component.write_text('{"reviewed":true}\n', encoding="utf-8")
            (install_root / "gideon_agent.py").write_text("old\n", encoding="utf-8")
            payload = root / "payload"; payload.mkdir()
            (payload / "gideon_agent.py").write_text("new\n", encoding="utf-8")
            backup = root / "backup"

            gideon_agent_update._backup(install_root, backup)
            gideon_agent_update._copy(payload, install_root, preserve=gideon_agent_update.PRESERVE_TOP_LEVEL)
            gideon_agent_update._restore(install_root, backup)

            self.assertTrue(component.is_file())
            self.assertEqual('{"reviewed":true}\n', component.read_text(encoding="utf-8"))
            self.assertFalse((backup / "third_party").exists())

    def test_agent_requires_gateway_reported_small_update_size(self) -> None:
        for app in (APP, WINDOWS_APP):
            source = (app / "gideon_agent.py").read_text(encoding="utf-8-sig")
            self.assertIn("UPDATE_BUNDLE_SIZE_MISSING", source)
            self.assertIn("UPDATE_BUNDLE_TOO_LARGE", source)
            self.assertIn("MAX_SELF_UPDATE_BUNDLE_BYTES = 256 * 1024 * 1024", source)

    def test_core_update_only_probes_remote_access_without_mutating_services(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "update.log"
            with mock.patch.object(gideon_agent_update, "_tcp", return_value=False):
                gideon_agent_update.record_remote_state_after_core_update(
                    {"RemoteAccess": {"Host": "127.0.0.1", "Port": 3389}}, log
                )
            self.assertIn("CORE_UPDATE_NO_SERVICE_MUTATION", log.read_text(encoding="utf-8"))
        for app in (APP, WINDOWS_APP):
            source = (app / "gideon_agent_update.py").read_text(encoding="utf-8-sig")
            apply_start = source.index("def apply_update")
            apply_body = source[apply_start:source.index("def main", apply_start)]
            self.assertIn("record_remote_state_after_core_update", apply_body)
            self.assertNotIn("ensure_remote(profile", apply_body)

    @unittest.skipUnless(os.name == "posix", "ZIP executable-mode behavior is verified in Linux/WSL")
    def test_zip_extract_copy_restores_linux_launcher_mode_inside_install_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source-launcher"
            source.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            os.chmod(source, 0o755)
            bundle = root / "agent-update.zip"
            with zipfile.ZipFile(bundle, "w") as archive:
                archive.write(source, "payload/gideon-agent-player-launch")
                archive.writestr("payload/update-profile.json", json.dumps({"PlayerLauncher": PLAYER_LAUNCHER}))

            extracted = root / "extracted"
            safe_extract(bundle, extracted)
            payload = extracted / "payload"
            extracted_launcher = payload / "gideon-agent-player-launch"
            self.assertEqual(0, extracted_launcher.stat().st_mode & stat.S_IXUSR)

            install_root = root / "installed-agent"
            gideon_agent_update._copy(payload, install_root)
            log = root / "state" / "update.log"
            with mock.patch.object(gideon_agent_update, "_platform_id", return_value="linux"):
                gideon_agent_update._restore_linux_player_launcher(
                    {"PlayerLauncher": PLAYER_LAUNCHER}, install_root, log
                )
            self.assertEqual(0o755, (install_root / "gideon-agent-player-launch").stat().st_mode & 0o777)
            self.assertIn("PLAYER_LAUNCHER_READY", log.read_text(encoding="utf-8"))

    def test_player_update_helper_manages_only_fixed_units_and_never_credentials(self) -> None:
        for app in (APP, WINDOWS_APP):
            source = (app / "gideon_agent_update.py").read_text(encoding="utf-8-sig")
            start = source.index("def _restore_linux_player_launcher")
            end = source.index("def _copy", start)
            helper = source[start:end]
            self.assertIn("os.chmod(launcher,0o755)", helper)
            self.assertIn("systemctl", helper)
            self.assertNotIn("/usr/local/bin", helper)
            self.assertNotIn("client.key", helper)
            self.assertTrue({"agent.json", "client.crt", "client.key", "gideon_gateway_ca.pem"}.issubset(
                gideon_agent_update.PRESERVE_TOP_LEVEL
            ))

    @unittest.skipUnless(os.name == "posix", "systemd unit staging is Linux-only")
    def test_signed_profile_installs_fixed_player_timer_for_supported_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install_root = root / "installed-agent"; install_root.mkdir()
            launcher = install_root / "gideon-agent-player-launch"
            launcher.write_text("#!/bin/bash\nexit 0\n", encoding="utf-8")
            unit_dir = root / "systemd"; log = root / "update.log"
            completed = mock.Mock(returncode=0)
            with (
                mock.patch.object(gideon_agent_update, "_platform_id", return_value="linux"),
                mock.patch.object(gideon_agent_update, "PLAYER_LAUNCHER_ALLOWED_ROOTS", {install_root.resolve()}),
                mock.patch.object(gideon_agent_update, "PLAYER_SYSTEMD_UNIT_DIR", unit_dir),
                mock.patch.object(gideon_agent_update, "_run", return_value=completed) as run,
            ):
                gideon_agent_update._restore_linux_player_launcher(
                    {"PlayerLauncher": PLAYER_LAUNCHER}, install_root, log
                )
            self.assertIn(str(launcher), (unit_dir / "gideon-agent-player-launch.service").read_text(encoding="utf-8"))
            self.assertIn("OnUnitActiveSec=30s", (unit_dir / "gideon-agent-player-launch.timer").read_text(encoding="utf-8"))
            self.assertIn(mock.call(["systemctl", "daemon-reload"], timeout=30), run.call_args_list)
            self.assertIn(
                mock.call(["systemctl", "enable", "--now", "gideon-agent-player-launch.timer"], timeout=60),
                run.call_args_list,
            )


if __name__ == "__main__":
    unittest.main()
