"""Regression tests for fleet-visible, cross-platform Agent updates."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
LINUX_APP = ROOT / "payload/linux/app"
WINDOWS_APP = ROOT / "payload/windows/GIDEON Remote Control/app"
if str(LINUX_APP) not in sys.path:
    sys.path.insert(0, str(LINUX_APP))

from gideon_agent import Agent  # noqa: E402
from gideon_agent_gateway import GatewayDB, now_iso  # noqa: E402
from gideon_agent_update_builder import stable_release_targets  # noqa: E402
from gideon_reverse_tunnel import AgentReverseTunnelClient  # noqa: E402
from gideon_web_admin.app import _decorate_agent_update  # noqa: E402


class _ReleaseClient:
    def __init__(self, response: dict) -> None:
        self.response = response
        self.requests: list[tuple[str, str]] = []

    def json(self, method: str, path: str) -> dict:
        self.requests.append((method, path))
        return self.response


class AgentUpdateControlTests(unittest.TestCase):
    def test_reverse_tunnel_quiesce_blocks_new_streams_atomically(self) -> None:
        tunnel = AgentReverseTunnelClient(
            base_url="http://127.0.0.1",
            bearer_token="test",
            agent_id="agt-test",
        )
        with tunnel._streams_lock:
            tunnel._opening_streams.add("a" * 32)
        self.assertFalse(tunnel.begin_update_quiesce())
        with tunnel._streams_lock:
            tunnel._opening_streams.clear()
        self.assertTrue(tunnel.begin_update_quiesce())
        self.assertEqual(tunnel.active_stream_count, 0)

        class _Ws:
            def __init__(self) -> None:
                self.messages: list[dict] = []

            def send_json(self, value: dict) -> None:
                self.messages.append(value)

        ws = _Ws()
        tunnel._open_stream(ws, {
            "stream_id": "b" * 32,
            "purpose": "RDP",
            "target_host": "127.0.0.1",
            "target_port": 3389,
        })
        self.assertEqual(ws.messages[-1]["type"], "open_failed")
        self.assertIn("AGENT_UPDATE_QUIESCING", ws.messages[-1]["error"])

    def test_update_is_deferred_while_remote_session_is_active(self) -> None:
        class _Tunnel:
            active_stream_count = 1

        agent = object.__new__(Agent)
        agent.reverse_tunnel = _Tunnel()
        agent.update_install_started = False
        agent.active_job_id = ""
        agent.update_channel = "stable"
        agent._force_update_once = False
        agent.next_version_check = 0.0
        changes: list[dict] = []
        agent._status_update = lambda **kwargs: changes.append(kwargs)
        self.assertFalse(agent._schedule_update({
            "version": "9.9.9",
            "approval_state": "APPROVED",
        }))
        self.assertEqual(changes[-1]["update_state"], "UPDATE_DEFERRED_BUSY")
        self.assertEqual(changes[-1]["update_deferred_reason"], "ACTIVE_REMOTE_SESSION")
        self.assertEqual(changes[-1]["active_remote_streams"], 1)
        self.assertTrue(agent._force_update_once)

    def test_runtime_and_control_plane_are_identical_in_both_installers(self) -> None:
        names = (
            "gideon_agent.py",
            "gideon_agent_update.py",
            "gideon_agent_update_builder.py",
            "gideon_agent_gateway.py",
            "gideon_gateway_schema.py",
            "gideon_web_admin/app.py",
            "gideon_web_admin/gateway.py",
            "gideon_web_admin/diagnostics.py",
            "gideon_web_admin/templates/updates.html",
            "gideon_web_admin/templates/agents.html",
            "gideon_web_admin/templates/agent_detail.html",
        )
        for relative in names:
            linux = (LINUX_APP / relative).read_bytes()
            windows = (WINDOWS_APP / relative).read_bytes()
            self.assertEqual(hashlib.sha256(linux).digest(), hashlib.sha256(windows).digest(), relative)

    def test_release_catalog_covers_desktop_linux_and_raspberry(self) -> None:
        targets = {(row["platform"], row["architecture"]) for row in stable_release_targets()}
        self.assertTrue({
            ("windows", "x86_64"),
            ("linux", "x86_64"),
            ("linux", "arm64"),
            ("linux", "armv7l"),
            ("darwin", "x86_64"),
            ("darwin", "arm64"),
        }.issubset(targets))

    def test_release_builder_uses_packaged_profile_catalog(self) -> None:
        from gideon_agent_update_builder import AgentUpdateBundleBuilder

        builder = AgentUpdateBundleBuilder(LINUX_APP)
        self.assertEqual(
            builder.builder.profiles.path.resolve(),
            (LINUX_APP / "deploy/web/default-host-profiles.json").resolve(),
        )

    def test_durable_request_lifecycle_is_visible_in_fleet(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = GatewayDB(Path(tmp))
            agent_id = "agt-update-regression"
            db.enroll_agent(
                "18601", "SISTEMAS", "host-one", "2.4.17",
                agent_id=agent_id, agent_name="host-one", platform_name="windows", architecture="x86_64",
            )
            with db.connect() as con:
                con.execute(
                    """INSERT INTO agent_releases(
                       platform,architecture,channel,version,protocol_version,bundle_path,bundle_sha256,
                       signature,key_id,notes,created_at,approval_state,approved_at,approved_by,approval_note
                       ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    ("windows", "x86_64", "stable", "2.4.18", "2.0", "release.zip", "a" * 64,
                     "signature", "test-key", "test", now_iso(), "APPROVED", now_iso(), "test", "test"),
                )

            requested = db.request_agent_update(agent_id, actor="tester")
            self.assertEqual(requested["status"], "REQUESTED")
            fleet = db.list_agents()
            self.assertEqual(fleet[0]["UpdateRequest"]["request_id"], requested["request_id"])
            delivered = db.observe_agent_update_request(agent_id, "2.4.17", update_state="CHECKING")
            self.assertEqual(delivered["status"], "DELIVERED")
            completed = db.observe_agent_update_request(agent_id, "2.4.18", update_state="CURRENT")
            self.assertEqual(completed["status"], "COMPLETED")
            self.assertEqual(completed["current_version"], "2.4.18")

    def test_rollback_marks_durable_request_failed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = GatewayDB(Path(tmp))
            agent_id = "agt-update-rollback"
            db.enroll_agent(
                "18601", "SISTEMAS", "host-two", "2.4.17",
                agent_id=agent_id, platform_name="linux", architecture="x86_64",
            )
            with db.connect() as con:
                con.execute(
                    """INSERT INTO agent_releases(
                       platform,architecture,channel,version,protocol_version,bundle_path,bundle_sha256,
                       signature,key_id,notes,created_at,approval_state
                       ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    ("linux", "x86_64", "stable", "2.4.18", "2.0", "release.zip", "a" * 64,
                     "signature", "test-key", "test", now_iso(), "APPROVED"),
                )
            db.request_agent_update(agent_id, actor="tester")
            failed = db.observe_agent_update_request(agent_id, "2.4.17", update_state="ROLLED_BACK")
            self.assertEqual(failed["status"], "FAILED")
            self.assertIn("ROLLED_BACK", failed["detail"])

    @staticmethod
    def _minimal_agent(response: dict) -> tuple[Agent, list[dict]]:
        agent = object.__new__(Agent)
        agent._force_update_once = False
        agent.next_version_check = 0.0
        agent.update_cfg = {"check_seconds": 60, "auto_install_approved": False, "require_approved": True}
        agent.update_channel = "stable"
        agent.version_state = {}
        agent.client = _ReleaseClient(response)
        changes: list[dict] = []
        agent._status_update = lambda **kwargs: changes.append(kwargs)
        agent._log_event = lambda *_args, **_kwargs: None
        agent._schedule_update = lambda _release: False
        return agent, changes

    def test_forced_check_clears_stale_updating_after_restart(self) -> None:
        agent, changes = self._minimal_agent({
            "Status": "CURRENT",
            "Release": {"version": "2.4.18", "approval_state": "APPROVED"},
        })
        agent.check_version(force=True)
        self.assertEqual(changes[0]["update_state"], "CHECKING")
        self.assertEqual(changes[-1]["update_state"], "CURRENT")
        self.assertEqual(changes[-1]["update_error"], "")
        self.assertTrue(changes[-1]["update_completed_at"])

    def test_forced_request_overrides_disabled_automatic_install(self) -> None:
        agent, changes = self._minimal_agent({
            "Status": "UPDATE_AVAILABLE",
            "Release": {"version": "2.4.18", "approval_state": "APPROVED"},
        })
        scheduled: list[str] = []
        agent._schedule_update = lambda release: scheduled.append(str(release["version"])) or False
        agent.check_version(force=True)
        self.assertEqual(scheduled, ["2.4.18"])
        self.assertEqual(changes[-1]["update_state"], "UPDATE_DEFERRED_BUSY")
        self.assertTrue(agent._force_update_once)

    def test_web_status_prefers_confirmed_current_version(self) -> None:
        decorated = _decorate_agent_update({
            "agent_version": "2.4.18",
            "Diagnostics": {"update": {"state": "UPDATING", "target_version": "2.4.18"}},
            "UpdateRequest": {"status": "DELIVERED", "target_version": "2.4.18"},
        }, {"version": "2.4.18"})
        self.assertEqual(decorated["_update_state"], "CURRENT")
        self.assertEqual(decorated["_update_label"], "Al día")

    def test_console_exposes_force_update_controls(self) -> None:
        for relative in ("gideon_web_admin/templates/updates.html", "gideon_web_admin/templates/agent_detail.html"):
            source = (LINUX_APP / relative).read_text(encoding="utf-8-sig")
            self.assertIn("/update", source)
            self.assertIn("Forzar", source)

    def test_gateway_advertises_durable_update_control(self) -> None:
        source = (LINUX_APP / "gideon_agent_gateway.py").read_text(encoding="utf-8-sig")
        self.assertIn('"AgentUpdateRequest": True', source)
        self.assertIn('"AgentUpdateRequestEndpoint": "/api/v1/admin/agents/{agent_id}/update"', source)


if __name__ == "__main__":
    unittest.main()
