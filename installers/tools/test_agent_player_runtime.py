"""Portable Phase 3 checks for the isolated Agent-side GIDEON Player runtime.

No real VLC, desktop session, Agent service, Gateway, or video decoder is
started.  The suite signs temporary manifests with an ephemeral Ed25519 key and
uses a fake VLC process, exercising the same cache/signature/isolation contract
on Windows, Ubuntu/Debian and Raspberry/ARM build hosts.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(os.environ.get("GIDEON_TEST_ROOT") or Path(__file__).resolve().parents[2]).resolve()
APP = Path(os.environ.get("GIDEON_TEST_APP") or (ROOT / "payload/linux/app")).resolve()
sys.path.insert(0, str(APP))
MODULE_PATH = APP / "gideon_agent_player.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("gideon_test_agent_player", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"No se pudo cargar {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


player = _load_module()


class FakeVlcProcess:
    next_pid = 81000

    def __init__(self) -> None:
        type(self).next_pid += 1
        self.pid = type(self).next_pid
        self.dead = False
        self.terminated = False

    def poll(self):
        return 1 if self.dead else None

    def terminate(self) -> None:
        self.terminated = True
        self.dead = True


class FakeVlcFactory:
    def __init__(self) -> None:
        self.calls: list[tuple[list[str], dict[str, object]]] = []
        self.processes: list[FakeVlcProcess] = []

    def __call__(self, command, **kwargs):
        self.calls.append((list(command), dict(kwargs)))
        proc = FakeVlcProcess()
        self.processes.append(proc)
        return proc


class FakeClient:
    def __init__(self, envelope: dict[str, object]) -> None:
        self.envelope = envelope
        self.calls: list[tuple[str, str, object]] = []
        self.timeout = 10.0

    def json(self, method: str, path: str, payload=None, **kwargs):
        self.calls.append((method, path, payload))
        if method == "GET":
            return dict(self.envelope)
        return {"Ok": True}


def _canonical(value: dict[str, object]) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


class PlayerRuntimeTests(unittest.TestCase):
    agent_id = "agt-player-test-01"

    def test_vlc_version_parser_never_accepts_warnings_or_failures(self) -> None:
        refusal = "VLC is not supposed to be run as root. Sorry."
        self.assertEqual("", player._parse_vlc_cli_version("", refusal, returncode=1))
        self.assertEqual("", player._parse_vlc_cli_version("", refusal, returncode=0))
        self.assertEqual("", player._parse_vlc_cli_version("Traceback: failed", "", returncode=0))
        self.assertEqual(
            "VLC media player 3.0.21 Vetinari",
            player._parse_vlc_cli_version(
                "warning: ignored\nVLC media player 3.0.21 Vetinari\n",
                "",
                returncode=0,
            ),
        )

    def test_linux_package_version_is_local_strict_and_root_discovery_skips_cli(self) -> None:
        original_candidates = player._vlc_candidates
        original_linux = player._is_linux_host
        original_root = player._running_as_root
        original_which = player.shutil.which
        original_run = player.subprocess.run
        commands: list[list[str]] = []
        try:
            player._vlc_candidates = lambda: ["/usr/bin/vlc"]
            player._is_linux_host = lambda: True
            player._running_as_root = lambda: True
            player.shutil.which = lambda command: "/usr/bin/dpkg-query" if command == "dpkg-query" else None

            def fake_run(command, **kwargs):
                commands.append(list(command))
                return SimpleNamespace(
                    returncode=0,
                    stdout="install ok installed\t3.0.21-0+deb12u1+rpt1\n",
                    stderr="",
                )

            player.subprocess.run = fake_run
            result = player.discover_vlc()
            self.assertEqual("VLC package 3.0.21-0+deb12u1+rpt1", result["Version"])
            self.assertEqual(1, len(commands))
            self.assertEqual("dpkg-query", Path(commands[0][0]).name)
            self.assertNotIn("--version", commands[0])

            # A successful command with malformed/error metadata is not a
            # version either; rpm is absent in this fixture.
            commands.clear()
            player.subprocess.run = lambda command, **kwargs: SimpleNamespace(
                returncode=0,
                stdout="install ok installed\tVLC is not supposed to be run as root. Sorry.\n",
                stderr="",
            )
            self.assertEqual("version-unavailable", player.discover_vlc()["Version"])
        finally:
            player._vlc_candidates = original_candidates
            player._is_linux_host = original_linux
            player._running_as_root = original_root
            player.shutil.which = original_which
            player.subprocess.run = original_run

    def _keypair(self, root: Path):
        private = Ed25519PrivateKey.generate()
        public = root / "agent-signing-public.pem"
        public.write_bytes(private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
        return private, public

    def _envelope(
        self,
        private,
        *,
        file_name: str,
        digest: str,
        size: int,
        version: int = 1,
        output_identity: str = "",
        output_key: str = "linux-hdmi-1",
        target_kind: str = "PHYSICAL_CONNECTOR",
        policy: dict[str, object] | None = None,
    ) -> dict[str, object]:
        now = dt.datetime.now(dt.timezone.utc)
        payload: dict[str, object] = {
            "AgentId": self.agent_id,
            "IssuedAt": now.isoformat(),
            "ExpiresAt": (now + dt.timedelta(days=1)).isoformat(),
            "Screens": [{
                "ScreenId": "screen-caja-01",
                "OutputKey": output_key,
                "TargetKind": target_kind,
                "OutputLabel": "Pantalla Caja",
                "Orientation": "landscape",
                "Resolution": "1920x1080",
                "CampaignId": "campaign-01",
                "RevisionNo": 2,
                "Policy": {"Fullscreen": True, "Kiosk": True, "Volume": 65, **dict(policy or {})},
                "Playlist": [{
                    "AssetId": "asset-01",
                    "Sha256": digest,
                    "FileName": file_name,
                    "SizeBytes": size,
                    "DurationMs": 12000,
                }],
            }],
        }
        if output_identity:
            payload["Screens"][0]["OutputIdentity"] = output_identity
        body = _canonical(payload)
        return {
            "Schema": player.PLAYER_MANIFEST_SCHEMA,
            "ManifestVersion": version,
            "ManifestSha256": hashlib.sha256(body).hexdigest(),
            "KeyId": "gideon-agent-ed25519-1",
            "Signature": base64.b64encode(private.sign(body)).decode("ascii"),
            "Payload": payload,
        }

    def test_signed_manifest_is_verified_and_published_to_public_companion_exchange(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-player-") as td:
            root = Path(td)
            media_root = root / "media"
            media_root.mkdir()
            video = media_root / "campaign-01.mp4"
            video.write_bytes(b"h264-aac-test-content")
            private, public = self._keypair(root)
            envelope = self._envelope(private, file_name=video.name, digest=hashlib.sha256(video.read_bytes()).hexdigest(), size=video.stat().st_size)
            store = player.PlayerManifestStore(agent_root=root / "agent", agent_id=self.agent_id, public_key_path=public, media_root=media_root)
            result = store.apply(envelope)
            self.assertEqual(1, result.manifest_version)
            self.assertTrue(store.paths.current_manifest.is_file())
            self.assertTrue(store.paths.public_manifest.is_file())
            # Interactive users receive only write access to this transient
            # directory after explicit installer ACL/group provisioning.  The
            # signed manifest remains one directory above it, service-owned.
            self.assertEqual(store.paths.public_root, store.paths.public_manifest.parent)
            self.assertEqual(store.paths.public_runtime, store.paths.public_status.parent)
            self.assertEqual(store.paths.public_runtime, store.paths.desktop_lock.parent)
            self.assertNotEqual(store.paths.public_manifest.parent, store.paths.public_status.parent)
            # The companion must read the public signed exchange, never private
            # Agent state such as token/config material.
            store.paths.current_manifest.unlink()
            self.assertEqual(1, store.load_desktop_manifest().manifest_version)
            public_json = json.loads(store.paths.public_manifest.read_text(encoding="utf-8"))
            self.assertNotIn("agent_token", json.dumps(public_json))

    def test_bad_signature_path_escape_and_missing_asset_are_rejected_without_replacing_last_valid(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-player-") as td:
            root = Path(td)
            media_root = root / "media"; media_root.mkdir()
            video = media_root / "campaign-01.mp4"; video.write_bytes(b"video-one")
            private, public = self._keypair(root)
            digest = hashlib.sha256(video.read_bytes()).hexdigest()
            good = self._envelope(private, file_name=video.name, digest=digest, size=video.stat().st_size)
            store = player.PlayerManifestStore(agent_root=root / "agent", agent_id=self.agent_id, public_key_path=public, media_root=media_root)
            store.apply(good)
            original = store.paths.public_manifest.read_bytes()

            bad_signature = dict(good); bad_signature["Signature"] = "AAAA"
            with self.assertRaises(player.PlayerManifestError):
                store.apply(bad_signature)
            self.assertEqual(original, store.paths.public_manifest.read_bytes())

            escaped = self._envelope(private, file_name=video.name, digest=digest, size=video.stat().st_size, version=2)
            escaped["Payload"] = dict(escaped["Payload"])
            screens = list(escaped["Payload"]["Screens"])
            screens[0] = dict(screens[0]); screens[0]["Playlist"] = [dict(screens[0]["Playlist"][0], FileName="../outside.mp4")]
            escaped["Payload"]["Screens"] = screens
            body = _canonical(escaped["Payload"])
            escaped["ManifestSha256"] = hashlib.sha256(body).hexdigest()
            escaped["Signature"] = base64.b64encode(private.sign(body)).decode("ascii")
            with self.assertRaises(player.PlayerManifestError):
                store.apply(escaped)
            self.assertEqual(original, store.paths.public_manifest.read_bytes())

            missing = self._envelope(private, file_name="missing.mp4", digest=digest, size=video.stat().st_size, version=2)
            with self.assertRaises(player.PlayerAssetPending):
                store.apply(missing)
            self.assertEqual(original, store.paths.public_manifest.read_bytes())

    def test_local_wayland_target_plays_only_in_verified_local_wayland_session(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-player-wayland-") as td:
            root = Path(td); media_root = root / "media"; media_root.mkdir()
            video = media_root / "campaign-01.mp4"; video.write_bytes(b"wayland-video")
            private, public = self._keypair(root)
            output_key = "linux-wayland-noop-1"
            envelope = self._envelope(
                private, file_name=video.name, digest=hashlib.sha256(video.read_bytes()).hexdigest(),
                size=video.stat().st_size, output_key=output_key,
                output_identity=output_key, target_kind="LOCAL_WAYLAND_SESSION",
                policy={
                    "TargetKind": "LOCAL_WAYLAND_SESSION", "PhysicalOutput": False,
                    "SessionIndependence": "LOCAL_WAYLAND_SESSION", "OutputIdentity": output_key,
                },
            )
            store = player.PlayerManifestStore(
                agent_root=root / "agent", agent_id=self.agent_id,
                public_key_path=public, media_root=media_root,
            )
            verified = store.apply(envelope)
            self.assertEqual("LOCAL_WAYLAND_SESSION", verified.assignments[0].target_kind)
            factory = FakeVlcFactory()
            original_discover = player.discover_vlc
            original_candidates = player._vlc_candidates
            original_display = player.detect_display_capability
            original_session = player.physical_session_context
            original_interactive = player._interactive_desktop_available
            try:
                player._interactive_desktop_available = lambda: True
                player.discover_vlc = lambda: {"Installed": True, "Version": "VLC test", "License": "GPL-2.0-or-later"}
                player._vlc_candidates = lambda: ["vlc-test"]
                player.physical_session_context = lambda: {
                    "Available": True, "Physical": True, "Type": "wayland", "Source": "test-logind",
                    "HumanActivityKnown": True, "HumanActive": False,
                }
                player.detect_display_capability = lambda: {
                    "State": "READY", "Session": {"Available": True, "Type": "wayland"},
                    "Outputs": [{
                        "OutputKey": output_key, "OutputIdentity": output_key,
                        "TargetKind": "LOCAL_WAYLAND_SESSION", "Physical": False,
                        "Virtual": True, "Connected": True, "Enabled": True, "Index": 1,
                    }],
                }
                runtime = player.DesktopPlayerRuntime(
                    agent_root=root / "agent", agent_id=self.agent_id, public_key_path=public,
                    media_root=media_root, popen_factory=factory,
                )
                result = runtime.refresh_once()
                self.assertEqual("PLAYING", result["State"])
                self.assertEqual("LOCAL_WAYLAND_SESSION", result["Screens"][0]["TargetKind"])
                self.assertIn("--fullscreen", factory.calls[0][0])
                self.assertIn("--qt-fullscreen-screennumber=0", factory.calls[0][0])
            finally:
                player.discover_vlc = original_discover
                player._vlc_candidates = original_candidates
                player.detect_display_capability = original_display
                player.physical_session_context = original_session
                player._interactive_desktop_available = original_interactive

    def test_desktop_runtime_uses_external_vlc_per_output_and_preserves_backoff(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-player-") as td:
            root = Path(td)
            media_root = root / "media"; media_root.mkdir()
            video = media_root / "campaign-01.mp4"; video.write_bytes(b"video-one")
            private, public = self._keypair(root)
            envelope = self._envelope(private, file_name=video.name, digest=hashlib.sha256(video.read_bytes()).hexdigest(), size=video.stat().st_size)
            store = player.PlayerManifestStore(agent_root=root / "agent", agent_id=self.agent_id, public_key_path=public, media_root=media_root)
            store.apply(envelope)

            factory = FakeVlcFactory()
            original_discover = player.discover_vlc
            original_candidates = player._vlc_candidates
            original_display = player.detect_display_capability
            original_physical = player.physical_session_context
            original_interactive = player._interactive_desktop_available
            try:
                player._interactive_desktop_available = lambda: True
                player.discover_vlc = lambda: {"Installed": True, "Version": "VLC test", "License": "GPL-2.0-or-later"}
                player._vlc_candidates = lambda: ["vlc-test"]
                player.physical_session_context = lambda: {
                    "Available": True, "Physical": True, "Type": "x11", "Source": "test",
                    "HumanActivityKnown": True, "HumanActive": False,
                }
                player.detect_display_capability = lambda: {
                    "State": "READY",
                    "Session": {"Available": True, "Interactive": True},
                    "Outputs": [{"OutputKey": "linux-hdmi-1", "Connected": True, "Enabled": True, "Index": 1}],
                }
                runtime = player.DesktopPlayerRuntime(
                    agent_root=root / "agent", agent_id=self.agent_id, public_key_path=public,
                    media_root=media_root, popen_factory=factory,
                )
                first = runtime.refresh_once()
                self.assertEqual("PLAYING", first["State"])
                self.assertEqual(1, len(factory.calls))
                command = factory.calls[0][0]
                self.assertEqual("vlc-test", command[0])
                self.assertIn("--fullscreen", command)
                self.assertIn("--autoscale", command)
                self.assertIn("qt", command)
                self.assertNotIn("dummy", command)
                self.assertIn(str(video), command)
                self.assertNotIn("shell", factory.calls[0][1])

                # A dead external player must not spin/restart every two-second
                # supervisor refresh.  The retry record survives process cleanup.
                factory.processes[0].dead = True
                retry = runtime.refresh_once()
                self.assertEqual("DEGRADED", retry["State"])
                self.assertEqual("RETRY_BACKOFF", retry["Screens"][0]["State"])
                self.assertEqual(1, len(factory.calls))

                player.detect_display_capability = lambda: {"State": "READY", "Session": {}, "Outputs": []}
                offline = runtime.refresh_once()
                self.assertEqual("SCREEN_DISCONNECTED", offline["Screens"][0]["State"])
            finally:
                player.discover_vlc = original_discover
                player._vlc_candidates = original_candidates
                player.detect_display_capability = original_display
                player.physical_session_context = original_physical
                player._interactive_desktop_available = original_interactive

    def test_player_never_uses_rdp_or_nonphysical_session(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-player-physical-") as td:
            root = Path(td); media_root = root / "media"; media_root.mkdir()
            video = media_root / "campaign-01.mp4"; video.write_bytes(b"video-one")
            private, public = self._keypair(root)
            envelope = self._envelope(private, file_name=video.name, digest=hashlib.sha256(video.read_bytes()).hexdigest(), size=video.stat().st_size)
            store = player.PlayerManifestStore(agent_root=root / "agent", agent_id=self.agent_id, public_key_path=public, media_root=media_root)
            store.apply(envelope)
            factory = FakeVlcFactory()
            original_interactive = player._interactive_desktop_available
            original_physical = player.physical_session_context
            try:
                player._interactive_desktop_available = lambda: True
                player.physical_session_context = lambda: {
                    "Available": True, "Physical": False, "Type": "rdp", "Source": "test-rdp",
                    "HumanActivityKnown": False, "HumanActive": None,
                }
                runtime = player.DesktopPlayerRuntime(
                    agent_root=root / "agent", agent_id=self.agent_id, public_key_path=public,
                    media_root=media_root, popen_factory=factory,
                )
                result = runtime.refresh_once()
                self.assertEqual("WAITING_FOR_PHYSICAL_SESSION", result["State"])
                self.assertEqual("PLAYER_PHYSICAL_SESSION_REQUIRED", result["Reason"])
                self.assertTrue(runtime._exit_for_session_change)
                self.assertEqual([], factory.calls)
            finally:
                player.physical_session_context = original_physical
                player._interactive_desktop_available = original_interactive

    def test_output_identity_and_shared_screen_policy_are_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-player-policy-") as td:
            root = Path(td); media_root = root / "media"; media_root.mkdir()
            video = media_root / "campaign-01.mp4"; video.write_bytes(b"video-one")
            private, public = self._keypair(root)
            digest = hashlib.sha256(video.read_bytes()).hexdigest()
            identity = "linux-hdmi-1:edid-expected"
            shared_policy = {
                "PhysicalOutput": True,
                "SessionIndependence": "PERSISTENT_PHYSICAL_OUTPUT",
                "ScreenMode": "SHARED_PAUSE_ON_HUMAN_ACTIVITY",
                "PauseOnHumanActivity": True,
                "EmergencyTakeover": False,
                "OutputIdentity": identity,
            }
            envelope = self._envelope(
                private, file_name=video.name, digest=digest, size=video.stat().st_size,
                policy=shared_policy,
            )
            store = player.PlayerManifestStore(agent_root=root / "agent", agent_id=self.agent_id, public_key_path=public, media_root=media_root)
            store.apply(envelope)
            factory = FakeVlcFactory()
            original_discover = player.discover_vlc
            original_candidates = player._vlc_candidates
            original_display = player.detect_display_capability
            original_interactive = player._interactive_desktop_available
            original_physical = player.physical_session_context
            try:
                player._interactive_desktop_available = lambda: True
                player.discover_vlc = lambda: {"Installed": True, "Version": "VLC test", "License": "GPL-2.0-or-later"}
                player._vlc_candidates = lambda: ["vlc-test"]
                player.physical_session_context = lambda: {
                    "Available": True, "Physical": True, "Type": "x11", "Source": "test",
                    "HumanActivityKnown": True, "HumanActive": True,
                }
                player.detect_display_capability = lambda: {
                    "State": "READY", "Session": {"Available": True, "Interactive": True},
                    "Outputs": [{"OutputKey": "linux-hdmi-1", "OutputIdentity": identity, "Physical": True,
                                 "Connected": True, "Enabled": True, "Index": 1}],
                }
                runtime = player.DesktopPlayerRuntime(
                    agent_root=root / "agent", agent_id=self.agent_id, public_key_path=public,
                    media_root=media_root, popen_factory=factory,
                )
                paused = runtime.refresh_once()
                self.assertEqual("PAUSED_FOR_HUMAN_ACTIVITY", paused["State"])
                self.assertEqual("PAUSED_FOR_HUMAN_ACTIVITY", paused["Screens"][0]["State"])
                self.assertEqual([], factory.calls)

                emergency_policy = dict(shared_policy); emergency_policy["EmergencyTakeover"] = True
                emergency = self._envelope(
                    private, file_name=video.name, digest=digest, size=video.stat().st_size, version=2,
                    policy=emergency_policy,
                )
                store.apply(emergency)
                playing = runtime.refresh_once()
                self.assertEqual("PLAYING", playing["State"])
                self.assertEqual(1, len(factory.calls))

                player.detect_display_capability = lambda: {
                    "State": "READY", "Session": {},
                    "Outputs": [{"OutputKey": "linux-hdmi-1", "OutputIdentity": "linux-hdmi-1:edid-other", "Physical": True,
                                 "Connected": True, "Enabled": True, "Index": 1}],
                }
                mismatch = runtime.refresh_once()
                self.assertEqual("SCREEN_DISCONNECTED", mismatch["Screens"][0]["State"])
                self.assertEqual("PLAYER_OUTPUT_IDENTITY_NOT_CONNECTED", mismatch["Screens"][0]["Error"])

                # A pre-normalization raw DRM connector remains a safe exact
                # alias for the same OutputKey, but never for another monitor
                # fingerprint (verified immediately above).
                legacy = self._envelope(
                    private, file_name=video.name, digest=digest, size=video.stat().st_size, version=3,
                    policy=dict(emergency_policy, OutputIdentity="card1-HDMI-A-1"),
                )
                store.apply(legacy)
                player.detect_display_capability = lambda: {
                    "State": "READY", "Session": {},
                    "Outputs": [{"OutputKey": "linux-hdmi-1", "OutputIdentity": "linux-hdmi-1",
                                 "Connector": "card1-HDMI-A-1", "Physical": True,
                                 "Connected": True, "Enabled": True, "Index": 1}],
                }
                legacy_playing = runtime.refresh_once()
                self.assertEqual("PLAYING", legacy_playing["Screens"][0]["State"])
            finally:
                player.discover_vlc = original_discover
                player._vlc_candidates = original_candidates
                player.detect_display_capability = original_display
                player.physical_session_context = original_physical
                player._interactive_desktop_available = original_interactive

    def test_multi_monitor_requires_local_mapping_before_vlc_is_started(self) -> None:
        """Never guess that a DRM/XRandR connector order matches Qt/VLC order."""
        with tempfile.TemporaryDirectory(prefix="gideon-player-output-map-") as td:
            root = Path(td); media_root = root / "media"; media_root.mkdir()
            video = media_root / "campaign-01.mp4"; video.write_bytes(b"video-one")
            private, public = self._keypair(root)
            identity = "linux-hdmi-1:monitor-map"
            envelope = self._envelope(
                private, file_name=video.name, digest=hashlib.sha256(video.read_bytes()).hexdigest(),
                size=video.stat().st_size,
                policy={"PhysicalOutput": True, "SessionIndependence": "PERSISTENT_PHYSICAL_OUTPUT",
                        "OutputIdentity": identity},
            )
            store = player.PlayerManifestStore(agent_root=root / "agent", agent_id=self.agent_id, public_key_path=public, media_root=media_root)
            store.apply(envelope)
            factory = FakeVlcFactory()
            original_discover = player.discover_vlc
            original_candidates = player._vlc_candidates
            original_display = player.detect_display_capability
            original_physical = player.physical_session_context
            original_interactive = player._interactive_desktop_available
            try:
                player._interactive_desktop_available = lambda: True
                player.discover_vlc = lambda: {"Installed": True, "Version": "VLC test", "License": "GPL-2.0-or-later"}
                player._vlc_candidates = lambda: ["vlc-test"]
                player.physical_session_context = lambda: {
                    "Available": True, "Physical": True, "Type": "x11", "Source": "test",
                    "HumanActivityKnown": True, "HumanActive": False,
                }
                player.detect_display_capability = lambda: {
                    "State": "READY", "Session": {"Available": True, "Interactive": True}, "Outputs": [
                        {"OutputKey": "linux-hdmi-1", "OutputIdentity": identity, "Physical": True, "Connected": True, "Enabled": True},
                        {"OutputKey": "linux-dp-1", "OutputIdentity": "linux-dp-1:monitor-other", "Physical": True, "Connected": True, "Enabled": True},
                    ],
                }
                runtime = player.DesktopPlayerRuntime(
                    agent_root=root / "agent", agent_id=self.agent_id, public_key_path=public,
                    media_root=media_root, popen_factory=factory,
                )
                blocked = runtime.refresh_once()
                self.assertEqual("OUTPUT_MAPPING_REQUIRED", blocked["Screens"][0]["State"])
                self.assertEqual([], factory.calls)

                runtime.store.paths.public_output_map.write_text(
                    json.dumps({"Schema": "gideon-player-output-map/v1", "Outputs": [
                        {"OutputIdentity": identity, "VlcScreenNumber": 2},
                    ]}), encoding="utf-8",
                )
                playing = runtime.refresh_once()
                self.assertEqual("PLAYING", playing["State"])
                self.assertIn("--qt-fullscreen-screennumber=1", factory.calls[0][0])
            finally:
                player.discover_vlc = original_discover
                player._vlc_candidates = original_candidates
                player.detect_display_capability = original_display
                player.physical_session_context = original_physical
                player._interactive_desktop_available = original_interactive

    def test_agent_bridge_uses_existing_authenticated_control_plane_only_for_manifest_and_report(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-player-") as td:
            root = Path(td)
            media_root = root / "media"; media_root.mkdir()
            video = media_root / "campaign-01.mp4"; video.write_bytes(b"video-one")
            private, public = self._keypair(root)
            envelope = self._envelope(private, file_name=video.name, digest=hashlib.sha256(video.read_bytes()).hexdigest(), size=video.stat().st_size)
            client = FakeClient(envelope)
            bridge = player.PlayerAgentBridge(agent_root=root / "agent", agent_id=self.agent_id, public_key_path=public, media_root=media_root)
            # This control-plane test must not spawn a real desktop companion
            # merely because the Windows build host has a physical console.
            bridge._ensure_desktop_runtime = lambda: None
            applied = bridge.sync_from_gateway(client, force=True)
            self.assertEqual("MANIFEST_APPLIED", applied["State"])
            report = bridge.report_to_gateway(client, force=True)
            self.assertEqual("REPORTED", report["State"])
            paths = [(method, path) for method, path, _ in client.calls]
            self.assertIn(("GET", "/api/v1/agent/media/manifest"), paths)
            self.assertIn(("POST", "/api/v1/agent/media/report"), paths)
            self.assertFalse(any("asset" in path for _, path in paths))
            payload = bridge.status_for_report()
            self.assertNotIn("agent_token", json.dumps(payload))
            self.assertNotIn(str(media_root), json.dumps(payload))

    def test_public_desktop_status_is_bounded_telemetry_not_manifest_authority(self) -> None:
        """A local desktop ACL may not change service-owned campaign state."""
        with tempfile.TemporaryDirectory(prefix="gideon-player-status-") as td:
            root = Path(td)
            media_root = root / "media"; media_root.mkdir()
            video = media_root / "campaign-01.mp4"; video.write_bytes(b"video-one")
            private, public = self._keypair(root)
            envelope = self._envelope(private, file_name=video.name, digest=hashlib.sha256(video.read_bytes()).hexdigest(), size=video.stat().st_size)
            bridge = player.PlayerAgentBridge(agent_root=root / "agent", agent_id=self.agent_id, public_key_path=public, media_root=media_root)
            bridge._ensure_desktop_runtime = lambda: None
            bridge.sync_from_gateway(FakeClient(envelope), force=True)
            self.assertFalse(bridge.store.paths.public_status.exists())

            # A mismatched public status must never move the Agent to a bogus
            # manifest, even though the desktop user has narrow write access
            # to the observable runtime directory.
            bridge.store.paths.public_status.write_text(json.dumps({
                "ManifestVersion": 999,
                "ManifestSha256": "f" * 64,
                "State": "PLAYING",
            }), encoding="utf-8")
            self.assertEqual(1, bridge.status_for_report()["ManifestVersion"])

            # Matching-manifest desktop telemetry remains useful, but malformed
            # counters cannot throw inside the regular Agent heartbeat.
            bridge.store.paths.public_status.write_text(json.dumps({
                "ManifestVersion": 1,
                "ManifestSha256": envelope["ManifestSha256"],
                "State": "PLAYING",
                "FreeBytes": "not-a-number",
                "Graphics": {"State": "READY", "OutputCount": "not-a-number"},
                "Screens": [{
                    "ScreenId": "screen-caja-01", "OutputKey": "linux-hdmi-1",
                    "CampaignId": "campaign-01", "RevisionNo": "bad",
                    "CurrentVideo": video.name, "PlaylistItems": "bad", "State": "PLAYING",
                }],
            }), encoding="utf-8")
            report = bridge.status_for_report()
            self.assertEqual("READY", report["Graphics"]["State"])
            self.assertEqual(0, report["Graphics"]["OutputCount"])
            self.assertEqual(0, report["FreeBytes"])
            self.assertEqual(0, report["Screens"][0]["RevisionNo"])
            self.assertEqual(0, report["Screens"][0]["PlaylistItems"])

            # A later service-side manifest poll updates only private control
            # state and must not erase matching desktop telemetry.
            bridge._write_bridge_status("MANIFEST_APPLIED", manifest=bridge.store.load_current())
            public_after_poll = json.loads(bridge.store.paths.public_status.read_text(encoding="utf-8"))
            self.assertEqual("PLAYING", public_after_poll["State"])

    def test_runtime_payload_includes_isolated_module_and_never_embeds_vlc(self) -> None:
        payload = (APP / "gideon_agent_payload.py").read_text(encoding="utf-8")
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertIn('"gideon_agent_player.py"', payload)
        self.assertIn("ExternalVlcOnly", source)
        self.assertNotIn("shell=True", source)
        self.assertNotIn("apt-get install", source)
        self.assertNotIn("pip install vlc", source.casefold())

    def test_agent_initialization_does_not_require_vlc_or_a_writable_media_cache(self) -> None:
        """A Player failure cannot make normal Agent/tunnel startup fail."""
        with tempfile.TemporaryDirectory(prefix="gideon-player-agent-") as td:
            root = Path(td)
            _, public = self._keypair(root)
            cfg = {
                "site_code": "18601",
                "site_name": "Prueba",
                "agent_name": "Agent Player Test",
                "data_dir": str(root / "agent-data"),
                "security": {"trusted_signing_public_key": str(public)},
                "control_plane": {
                    "base_url": "https://gateway.invalid",
                    "connectivity_mode": "production",
                    "endpoints": [{"url": "https://gateway.invalid", "role": "primary", "priority": 10}],
                    "require_https": True,
                    "verify_tls": False,
                    "timeout_seconds": 2,
                },
            }
            cfg_path = root / "agent.json"
            cfg_path.write_text(json.dumps(cfg), encoding="utf-8")
            import gideon_agent
            agent = gideon_agent.Agent(cfg_path)
            self.assertTrue(agent.player_bridge.store.paths.root.is_dir())
            # The fixed production media location remains untouched until a
            # signed manifest is actually accepted after Phase-2 transfer.
            self.assertFalse(agent.player_bridge.store.paths.public_root.exists())
            self.assertTrue(agent.player_bridge.capability()["Supported"])

    def test_optional_player_import_failure_degrades_without_stopping_core_agent(self) -> None:
        """A partial Player payload may not disable tunnels/jobs/control."""
        import gideon_agent
        original = gideon_agent._PlayerAgentBridge
        try:
            gideon_agent._PlayerAgentBridge = None
            bridge = gideon_agent._new_player_bridge(
                agent_root=Path(tempfile.gettempdir()) / "gideon-player-disabled",
                agent_id=self.agent_id,
                public_key_path=None,
            )
            self.assertEqual("RUNTIME_UNAVAILABLE", bridge.capability()["State"])
            self.assertEqual("RUNTIME_UNAVAILABLE", bridge.sync_from_gateway(object())["State"])
            report = bridge.status_for_report()
            self.assertFalse(report["Screens"])
            self.assertNotIn("token", json.dumps(report).casefold())
        finally:
            gideon_agent._PlayerAgentBridge = original

    def test_player_initialization_failure_does_not_block_agent_heartbeat(self) -> None:
        """The optional bridge must not take mTLS/jobs/tunnel heartbeat down."""
        with tempfile.TemporaryDirectory(prefix="gideon-player-core-") as td:
            root = Path(td)
            _, public = self._keypair(root)
            cfg_path = root / "agent.json"
            cfg_path.write_text(json.dumps({
                "site_code": "18601",
                "site_name": "Prueba",
                "agent_name": "Agent Player Failure Test",
                "data_dir": str(root / "agent-data"),
                "security": {"trusted_signing_public_key": str(public)},
                "control_plane": {
                    "base_url": "https://gateway.invalid",
                    "connectivity_mode": "production",
                    "endpoints": [{"url": "https://gateway.invalid", "role": "primary", "priority": 10}],
                    "require_https": True,
                    "verify_tls": False,
                    "timeout_seconds": 2,
                },
            }), encoding="utf-8")
            import gideon_agent

            class FailingPlayer:
                def __init__(self, **_kwargs):
                    raise RuntimeError("test-only-player-init-failure")

            class HeartbeatClient:
                timeout = 2.0

                def __init__(self):
                    self.calls: list[tuple[str, str]] = []

                def json(self, method, path, _payload=None, **_kwargs):
                    self.calls.append((method, path))
                    return {}

            original = gideon_agent._PlayerAgentBridge
            try:
                gideon_agent._PlayerAgentBridge = FailingPlayer
                agent = gideon_agent.Agent(cfg_path)
                self.assertEqual("RUNTIME_UNAVAILABLE", agent.player_bridge.capability()["State"])
                client = HeartbeatClient()
                agent.client = client
                agent._ensure_reverse_tunnel = lambda: None
                agent._record_gateway_success = lambda: None
                agent.sync_central_config = lambda: None
                agent.heartbeat()
                self.assertIn(("POST", "/api/v1/agent/heartbeat"), client.calls)
                self.assertTrue(agent.status_path.is_file())
            finally:
                gideon_agent._PlayerAgentBridge = original


if __name__ == "__main__":
    unittest.main(verbosity=2)
