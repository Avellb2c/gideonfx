"""Regression coverage for the durable, bounded Web Agent build queue."""
from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest


ROOT = Path(os.environ.get("GIDEON_TEST_ROOT") or Path(__file__).resolve().parents[2]).resolve()
LINUX_APP = (ROOT / "payload/linux/app").resolve()
WINDOWS_APP = (ROOT / "payload/windows/GIDEON Remote Control/app").resolve()
if str(LINUX_APP) not in sys.path:
    sys.path.insert(0, str(LINUX_APP))

from gideon_web_admin.agent_installers import AgentInstallerError, WebAgentInstallerManager  # noqa: E402


class _Security:
    def __init__(self) -> None:
        self.events: list[tuple[object, ...]] = []

    def audit(self, *args: object, **kwargs: object) -> None:
        self.events.append((*args, kwargs))


class _Gateway:
    def __init__(self) -> None:
        self.issued: list[dict[str, object]] = []
        self.revoked: list[tuple[str, str]] = []

    def issue_enrollment_grant(self, **kwargs: object) -> dict[str, str]:
        self.issued.append(dict(kwargs))
        ordinal = len(self.issued)
        return {
            "GrantId": f"grant-{ordinal}",
            "EnrollmentGrant": f"temporary-secret-{ordinal}",
            "ExpiresAt": "2030-01-01T00:00:00+00:00",
        }

    def revoke_enrollment_grant(self, grant_id: str, *, reason: str) -> dict[str, str]:
        self.revoked.append((grant_id, reason))
        return {"RevokedAt": "2030-01-01T00:01:00+00:00"}


class _SecurityAssets:
    def signing_status(self) -> dict[str, object]:
        return {"usable": True, "key_id": "test-key", "fingerprint": "test-fingerprint"}


class _HeldThread:
    """Thread substitute that lets the test inspect scheduler decisions."""

    def __init__(self, build_id: str) -> None:
        self.build_id = build_id
        self.started = False

    def start(self) -> None:
        self.started = True


class AgentInstallerBuildQueueTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="gideon-installer-queue-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ca_path = self.root / "gateway-ca.pem"
        self.ca_path.write_text("test-ca\n", encoding="utf-8")

    def _manager(self, *, limit: object = 1) -> WebAgentInstallerManager:
        manager = WebAgentInstallerManager.__new__(WebAgentInstallerManager)
        manager.app_root = LINUX_APP
        manager.data_dir = self.root
        manager.config = {
            "gateway_ca_file": str(self.ca_path),
            "agent_installer_max_concurrent_builds": limit,
        }
        manager.security = _Security()
        manager.gateway = _Gateway()
        manager.security_assets = _SecurityAssets()
        manager.root = self.root / "agent-installers"
        manager.artifacts_dir = manager.root / "artifacts"
        manager.history_path = manager.root / "builds.json"
        manager.root.mkdir(parents=True, exist_ok=True)
        manager.artifacts_dir.mkdir(parents=True, exist_ok=True)
        manager._lock = threading.RLock()
        manager._threads = {}
        manager._cap_cache = None
        manager._resolve_package_type = lambda target_id, package_choice: "exe"  # type: ignore[method-assign]
        manager.connection_endpoints = lambda url, mode: [  # type: ignore[method-assign]
            {"url": url, "role": "primary", "priority": 10, "label": "Seleccionado"}
        ]
        manager.resolve_site = lambda code, name="": ("", "")  # type: ignore[method-assign]
        return manager

    @staticmethod
    def _row(build_id: str, number: int, status: str = "QUEUED", *, actor: str = "ana") -> dict[str, object]:
        return {
            "build_id": build_id,
            "build_number": number,
            "status": status,
            "target_id": "windows_x64",
            "package_type": "exe",
            "requested_by": actor,
            "requested_from": "127.0.0.1",
            "gateway_url": "https://gateway.example.test",
            "gateway_mode": "production",
            "gateway_endpoints": [{"url": "https://gateway.example.test", "role": "primary", "priority": 10}],
            "channel": "stable",
            "grant_ttl_hours": 24,
            "grant_max_uses": 1,
            "grant_id": "",
            "grant_revoked_at": "",
            "created_at": f"2026-09-29T00:00:0{number}+00:00",
        }

    def _queue_request(
        self, manager: WebAgentInstallerManager, *, actor: str, vlc_delivery: str = "bundled",
    ) -> dict[str, object]:
        return manager.start_build(
            target_id="windows_x64",
            package_choice="native",
            gateway_url="https://gateway.example.test",
            gateway_mode="production",
            channel="stable",
            ttl_hours=24,
            max_uses=1,
            actor=actor,
            remote_ip="127.0.0.1",
            enrollment_mode="individual",
            agent_name_mode="automatic",
            vlc_delivery=vlc_delivery,
        )

    def test_same_operator_duplicate_joins_active_request_without_grant(self) -> None:
        manager = self._manager()
        manager._schedule_pending_builds = lambda: None  # type: ignore[method-assign]

        first = self._queue_request(manager, actor="ana")
        duplicate = self._queue_request(manager, actor="ANA")

        self.assertEqual(first["build_id"], duplicate["build_id"])
        self.assertTrue(duplicate["request_deduplicated"])
        self.assertEqual(1, len(manager.history(20)))
        row = manager.get(str(first["build_id"])) or {}
        self.assertEqual("", row.get("grant_id"))
        self.assertEqual(1, row.get("duplicate_requests"))
        self.assertEqual([], manager.gateway.issued)
        self.assertTrue(any(event[1] == "agent_installer.queue_deduplicated" for event in manager.security.events))

    def test_identical_request_by_other_operator_creates_separate_queue_record(self) -> None:
        manager = self._manager()
        manager._schedule_pending_builds = lambda: None  # type: ignore[method-assign]

        first = self._queue_request(manager, actor="ana")
        second = self._queue_request(manager, actor="bruno")

        self.assertNotEqual(first["build_id"], second["build_id"])
        self.assertFalse(second["request_deduplicated"])
        self.assertEqual(2, len(manager.history(20)))
        self.assertEqual([], manager.gateway.issued)

    def test_component_delivery_is_rejected_before_queue_or_grant(self) -> None:
        manager = self._manager()
        manager._schedule_pending_builds = lambda: None  # type: ignore[method-assign]

        compatible = self._queue_request(manager, actor="ana", vlc_delivery="bundled")
        with self.assertRaisesRegex(AgentInstallerError, "AGENT_VLC_COMPONENT_DELIVERY_UNAVAILABLE"):
            self._queue_request(manager, actor="ana", vlc_delivery="component")

        rows = {str(row["build_id"]): row for row in manager.history(20)}
        self.assertEqual("bundled", rows[str(compatible["build_id"])]["vlc_delivery"])
        self.assertEqual(1, len(rows))
        self.assertEqual([], manager.gateway.issued)

    def test_fifo_scheduler_holds_remaining_heavy_builds_and_reports_positions(self) -> None:
        manager = self._manager(limit=1)
        manager._write_history([
            self._row("three", 3), self._row("two", 2), self._row("one", 1),
        ])
        held: list[_HeldThread] = []

        def build_thread(build_id: str) -> _HeldThread:
            thread = _HeldThread(build_id)
            held.append(thread)
            return thread

        manager._new_build_thread = build_thread  # type: ignore[method-assign]
        manager._schedule_pending_builds()
        rows = {str(row["build_id"]): row for row in manager.history(20)}
        self.assertEqual("BUILDING", rows["one"]["status"])
        self.assertEqual("QUEUED", rows["two"]["status"])
        self.assertEqual(1, rows["two"]["queue_position"])
        self.assertEqual(2, rows["three"]["queue_position"])
        self.assertEqual({"status": "BUILDING", "limit": 1, "active": 1, "waiting": 2}, manager.queue_status())
        self.assertEqual(["one"], [thread.build_id for thread in held if thread.started])

        manager._threads.pop("one", None)
        manager._patch_record("one", status="READY")
        manager._schedule_pending_builds()
        rows = {str(row["build_id"]): row for row in manager.history(20)}
        self.assertEqual("BUILDING", rows["two"]["status"])
        self.assertEqual(1, rows["three"]["queue_position"])

    def test_queued_record_gets_grant_only_after_scheduler_claims_slot(self) -> None:
        manager = self._manager()
        manager._write_history([self._row("one", 1, status="BUILDING")])
        captured: dict[str, object] = {}
        manager._run_build = lambda **kwargs: captured.update(kwargs)  # type: ignore[method-assign]
        manager._schedule_pending_builds = lambda: None  # type: ignore[method-assign]

        manager._run_queued_build(build_id="one")

        self.assertEqual(1, len(manager.gateway.issued))
        self.assertEqual("temporary-secret-1", captured["enrollment_grant"])
        row = manager.get("one") or {}
        self.assertEqual("grant-1", row["grant_id"])
        self.assertEqual("ISSUED", row["grant_state"])

    def test_restart_interrupts_active_build_and_resumes_safe_queued_work(self) -> None:
        manager = self._manager()
        active = self._row("active", 1, status="BUILDING")
        active.update({"grant_id": "legacy-active", "grant_state": "ISSUED"})
        queued = self._row("queued", 2)
        queued.update({"grant_id": "legacy-queued", "grant_state": "ISSUED"})
        manager._write_history([queued, active])

        manager._recover_interrupted_builds()

        rows = {str(row["build_id"]): row for row in manager.history(20)}
        self.assertEqual("INTERRUPTED", rows["active"]["status"])
        self.assertEqual("QUEUED", rows["queued"]["status"])
        self.assertEqual("", rows["queued"]["grant_id"])
        self.assertEqual("PENDING", rows["queued"]["grant_state"])
        self.assertEqual({"legacy-active", "legacy-queued"}, {grant_id for grant_id, _ in manager.gateway.revoked})

    def test_limit_is_safe_and_configurable(self) -> None:
        self.assertEqual(1, self._manager(limit="invalid")._build_concurrency_limit())
        self.assertEqual(1, self._manager(limit=0)._build_concurrency_limit())
        self.assertEqual(3, self._manager(limit=3)._build_concurrency_limit())
        self.assertEqual(4, self._manager(limit=99)._build_concurrency_limit())

    def test_runtime_mirrors_are_identical(self) -> None:
        relative = "gideon_web_admin/agent_installers.py"
        self.assertEqual((LINUX_APP / relative).read_bytes(), (WINDOWS_APP / relative).read_bytes())


if __name__ == "__main__":
    unittest.main(verbosity=2)
