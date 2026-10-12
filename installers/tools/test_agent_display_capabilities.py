"""Contract checks for safe cross-platform Agent display capability telemetry."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(os.environ.get("GIDEON_TEST_ROOT") or Path(__file__).resolve().parents[2]).resolve()
LINUX_APP = Path(os.environ.get("GIDEON_TEST_APP") or (ROOT / "payload/linux/app")).resolve()
WINDOWS_APP = Path(os.environ.get("GIDEON_TEST_WINDOWS_APP") or (ROOT / "payload/windows/GIDEON Remote Control/app")).resolve()


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


display = _load("gideon_test_agent_display_capability", LINUX_APP / "gideon_agent_display_capability.py")
payload = _load("gideon_test_agent_display_payload", LINUX_APP / "gideon_agent_payload.py")
vnc_bridge = _load("gideon_test_agent_vnc_bridge", LINUX_APP / "gideon_agent_vnc_bridge.py")


class AgentDisplayCapabilityTests(unittest.TestCase):
    def _connector(self, root: Path, name: str, status: str, modes: str = "", edid: bytes = b"") -> None:
        connector = root / name
        connector.mkdir()
        (connector / "status").write_text(status + "\n", encoding="utf-8")
        if modes:
            (connector / "modes").write_text(modes, encoding="utf-8")
        if edid:
            (connector / "edid").write_bytes(edid)

    def test_linux_uses_sysfs_and_optional_xrandr_without_sensitive_hardware_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._connector(root, "card0-HDMI-A-1", "connected", "1920x1080\n1280x720\n")
            self._connector(root, "card0-DP-1", "disconnected", "1024x768\n")
            result = display.detect_display_capability(
                system_name="linux",
                sysfs_root=root,
                environ={"DISPLAY": ":0", "XDG_SESSION_TYPE": "x11"},
                xrandr_text="HDMI-1 connected primary 1280x720+0+0 (normal left inverted right x axis y axis)\n",
            )
        self.assertEqual("gideon-display-capability/v1", result["Schema"])
        self.assertTrue(result["Supported"])
        self.assertEqual("READY", result["State"])
        self.assertTrue(result["Session"]["Available"])
        self.assertEqual("x11", result["Session"]["Type"])
        self.assertEqual(2, len(result["Outputs"]))
        hdmi = next(output for output in result["Outputs"] if output["OutputKey"] == "linux-hdmi-1")
        self.assertEqual("linux-hdmi-1", hdmi["OutputKey"])
        self.assertTrue(hdmi["Connected"])
        self.assertTrue(hdmi["Primary"])
        self.assertEqual(1280, hdmi["Width"])
        self.assertEqual(720, hdmi["Height"])
        self.assertEqual("xrandr", hdmi["ResolutionSource"])
        dp = next(output for output in result["Outputs"] if output["OutputKey"] == "linux-dp-1")
        self.assertFalse(dp["Connected"])
        body = json.dumps(result, ensure_ascii=False).casefold()
        for prohibited in ("edid", "serial", "deviceid", "devicekey", "username", "password"):
            self.assertNotIn(prohibited, body)

    def test_windows_test_seam_is_bounded_and_normalized(self):
        result = display.detect_display_capability(
            system_name="windows",
            windows_outputs=[
                {
                    "Connector": r"\\.\DISPLAY1",
                    "Connected": True,
                    "Enabled": True,
                    "Primary": True,
                    "Width": 1920,
                    "Height": 1080,
                    "RefreshHz": 60,
                    "Orientation": 0,
                },
                {
                    "Connector": r"\\.\DISPLAY2",
                    "Connected": True,
                    "Enabled": True,
                    "Width": 1080,
                    "Height": 1920,
                    "Orientation": 1,
                },
            ],
        )
        self.assertEqual("READY", result["State"])
        self.assertEqual(2, len(result["Outputs"]))
        self.assertEqual("windows-display1", result["Outputs"][0]["OutputKey"])
        self.assertEqual(1, result["Outputs"][0]["Index"])
        self.assertEqual(2, result["Outputs"][1]["Index"])
        self.assertEqual("landscape", result["Outputs"][0]["Orientation"])
        self.assertEqual("portrait", result["Outputs"][1]["Orientation"])

    def test_linux_uses_hashed_monitor_identity_without_leaking_edid(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw_edid = bytes(range(128))
            self._connector(root, "card0-HDMI-A-1", "connected", "1920x1080\n", raw_edid)
            first = display.detect_display_capability(system_name="linux", sysfs_root=root, environ={})
            second = display.detect_display_capability(system_name="linux", sysfs_root=root, environ={})
        output = first["Outputs"][0]
        self.assertEqual(output["OutputIdentity"], second["Outputs"][0]["OutputIdentity"])
        self.assertTrue(output["OutputIdentity"].startswith("linux-hdmi-1:monitor-"))
        self.assertEqual("connector+hardware-fingerprint", output["OutputIdentitySource"])
        serialized = json.dumps(first, ensure_ascii=False).casefold()
        self.assertNotIn(raw_edid.hex(), serialized)
        self.assertNotIn("edid", serialized)

    def test_wayland_outputs_are_explicit_virtual_session_targets(self):
        wlr = """NOOP-1 \"Headless output 2\"
  Enabled: yes
  Modes:
    1920x1080 px, 60.000000 Hz (preferred, current)
  Transform: normal
HDMI-A-2 \"Second compositor target\"
  Enabled: no
  Modes:
    1280x720 px, 60.000000 Hz (preferred)
"""
        with tempfile.TemporaryDirectory() as temporary:
            result = display.detect_display_capability(
                system_name="linux",
                sysfs_root=Path(temporary),
                environ={"WAYLAND_DISPLAY": "wayland-0", "XDG_SESSION_TYPE": "wayland"},
                wlr_randr_text=wlr,
            )
        noop = next(output for output in result["Outputs"] if output["Connector"] == "NOOP-1")
        self.assertEqual("linux-wayland-noop-1", noop["OutputKey"])
        self.assertEqual("LOCAL_WAYLAND_SESSION", noop["TargetKind"])
        self.assertFalse(noop["Physical"])
        self.assertTrue(noop["Virtual"])
        self.assertTrue(noop["Connected"])
        self.assertTrue(noop["Enabled"])
        self.assertEqual((1920, 1080), (noop["Width"], noop["Height"]))
        disabled = next(output for output in result["Outputs"] if output["Connector"] == "HDMI-A-2")
        self.assertTrue(disabled["Connected"])
        self.assertFalse(disabled["Enabled"])

    def test_wayland_probe_is_bounded_read_only_and_requires_current_session_environment(self):
        completed = mock.Mock(returncode=0, stdout="NOOP-1\n  Enabled: yes\n")
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(display.shutil, "which", return_value="/usr/bin/wlr-randr"), \
                mock.patch.object(display.subprocess, "run", return_value=completed) as run:
            display.detect_display_capability(
                system_name="linux",
                sysfs_root=Path(temporary),
                environ={"WAYLAND_DISPLAY": "wayland-0", "XDG_SESSION_TYPE": "wayland"},
            )
            self.assertEqual(["wlr-randr"], run.call_args.args[0])
            self.assertEqual(3, run.call_args.kwargs["timeout"])
            self.assertNotIn("shell", run.call_args.kwargs)

            run.reset_mock()
            display.detect_display_capability(
                system_name="linux", sysfs_root=Path(temporary), environ={},
            )
            run.assert_not_called()

    def test_service_bridge_adds_wayland_target_without_claiming_hdmi(self):
        bridge = vnc_bridge.LocalWaylandConsoleBridge()
        wayvnc = Path("/run/user/1000/rpi-connect-wayvnc.sock")
        bridge._outputs = lambda _source: [{
            "OutputKey": "linux-wayland-noop-1", "OutputIdentity": "linux-wayland-noop-1",
            "TargetKind": "LOCAL_WAYLAND_SESSION", "Connector": "NOOP-1",
            "Connected": True, "Enabled": True, "Physical": False, "Virtual": True,
        }]
        with mock.patch.object(vnc_bridge, "find_local_wayland_vnc_socket", return_value=wayvnc):
            enriched = bridge.enrich_display_capability({
                "Supported": True, "State": "READY", "Session": {"Available": False},
                "Outputs": [{
                    "OutputKey": "linux-hdmi-1", "OutputIdentity": "linux-hdmi-1",
                    "TargetKind": "PHYSICAL_CONNECTOR", "Connected": False,
                    "Enabled": False, "Physical": True, "Virtual": False,
                }],
            })
        self.assertEqual(2, len(enriched["Outputs"]))
        local = next(row for row in enriched["Outputs"] if row["TargetKind"] == "LOCAL_WAYLAND_SESSION")
        self.assertFalse(local["Physical"])
        self.assertTrue(local["Virtual"])
        self.assertEqual("wayland", enriched["Session"]["Type"])

    def test_failure_and_unsupported_platform_are_nonfatal(self):
        unavailable = display.detect_display_capability(
            system_name="linux", sysfs_root=Path("/definitely/not/a/gideon/display/root"), environ={},
        )
        self.assertEqual("UNAVAILABLE", unavailable["State"])
        self.assertFalse(unavailable["Supported"])
        other = display.detect_display_capability(system_name="plan9", environ={})
        self.assertEqual("UNSUPPORTED_PLATFORM", other["State"])
        self.assertEqual([], other["Outputs"])

    def test_runtime_payload_and_mirrors_include_display_capability(self):
        for relative in (
            "gideon_agent_display_capability.py",
            "gideon_agent_vnc_bridge.py",
            "gideon_agent.py",
            "gideon_agent_payload.py",
        ):
            self.assertEqual((LINUX_APP / relative).read_bytes(), (WINDOWS_APP / relative).read_bytes())
        self.assertIn("gideon_agent_display_capability.py", payload.RUNTIME_FILES)
        self.assertIn(
            ("deploy/agent/windows/gideon-agent-player-map.ps1", "gideon-agent-player-map.ps1"),
            payload.RUNTIME_ASSETS,
        )
        mapper = LINUX_APP / "deploy/agent/windows/gideon-agent-player-map.ps1"
        self.assertTrue(mapper.is_file())
        mapper_text = mapper.read_text(encoding="utf-8-sig")
        self.assertIn("PLAYER_OUTPUT_MAPPING_ADMIN_REQUIRED", mapper_text)
        self.assertIn("gideon-player-output-map/v1", mapper_text)
        self.assertIn("icacls.exe", mapper_text)
        self.assertNotIn("Invoke-WebRequest", mapper_text)
        self.assertNotIn("https://", mapper_text)
        payload.validate_agent_runtime_sources(LINUX_APP)
        for root in (LINUX_APP, WINDOWS_APP):
            agent_text = (root / "gideon_agent.py").read_text(encoding="utf-8-sig")
            self.assertIn("detect_display_capability", agent_text)
            self.assertIn("display = self._cached_display_capability()", agent_text)
            self.assertIn('"Display": display', agent_text)


if __name__ == "__main__":
    unittest.main()
