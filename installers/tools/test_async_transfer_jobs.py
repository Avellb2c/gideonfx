from __future__ import annotations

import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
APP_ROOT = ROOT / "payload" / "linux" / "app"
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from gideon_web_admin.operations import WebOperations  # noqa: E402


class AsyncTransferJobTests(unittest.TestCase):
    def _operations(self, root: Path) -> WebOperations:
        operations = WebOperations.__new__(WebOperations)
        operations.app_root = APP_ROOT
        operations.data_dir = root
        operations.config = {
            "max_transfer_upload_bytes": 1024 * 1024,
            "require_malware_scan_for_transfers": True,
            "require_malware_scan_for_scripts": True,
            "malware_scan_timeout_seconds": 300,
        }
        operations.transfer_dir = root / "transfers"
        operations.transfer_job_dir = root / "transfer-jobs"
        operations.transfer_dir.mkdir(parents=True)
        operations.transfer_job_dir.mkdir(parents=True)
        operations._malware_scan_lock = threading.Lock()
        operations._transfer_jobs_lock = threading.RLock()
        operations._scheduled_transfer_jobs = set()
        operations._start_transfer_job = lambda _job_id: None  # type: ignore[method-assign]
        return operations

    def test_upload_returns_persistent_job_before_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            operations = self._operations(Path(td))
            upload = operations.transfer_dir / ".upload.part"
            upload.write_bytes(b"safe payload")
            job = operations.enqueue_transfer(
                filename="sample.txt", source_path=upload, destination_dir=r"C:\Temp",
                agent_ids=["agt-1"], actor="admin",
            )
            self.assertEqual(job["Status"], "QUEUED_FOR_ANALYSIS")
            self.assertFalse(upload.exists())
            self.assertTrue(Path(job["StagedPath"]).is_file())
            self.assertEqual(operations.transfer_job(job["JobId"])["Status"], "QUEUED_FOR_ANALYSIS")

    def test_background_worker_does_not_block_enqueue(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            operations = self._operations(Path(td))
            operations._start_transfer_job = WebOperations._start_transfer_job.__get__(operations, WebOperations)  # type: ignore[method-assign]
            self.addCleanup(operations.shutdown_transfer_workers, wait=True)
            operations.scan_script = lambda _path: (time.sleep(0.25) or ("CLEAN", "clean"))  # type: ignore[method-assign]

            def queue_transfer(**kwargs):
                row = {"JobId": "file-agt-1", "AgentId": "agt-1", "SiteCode": "18601"}
                kwargs["on_queued"](row)
                return [row]

            operations.queue_transfer = queue_transfer  # type: ignore[method-assign]
            upload = operations.transfer_dir / ".upload.part"
            upload.write_bytes(b"safe payload")
            started = time.monotonic()
            job = operations.enqueue_transfer(
                filename="sample.txt", source_path=upload, destination_dir=r"C:\Temp",
                agent_ids=["agt-1"], actor="admin",
            )
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 0.15)
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                current = operations.transfer_job(job["JobId"])
                if current and current["Status"] == "COMPLETED":
                    break
                time.sleep(0.03)
            self.assertEqual(operations.transfer_job(job["JobId"])["Status"], "COMPLETED")

    def test_bounded_scheduler_persists_jobs_when_workers_are_busy(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            operations = self._operations(Path(td))
            operations.config.update({"transfer_worker_count": 1, "transfer_queue_limit": 1})
            operations._start_transfer_job = WebOperations._start_transfer_job.__get__(operations, WebOperations)  # type: ignore[method-assign]
            started = threading.Event()
            release = threading.Event()
            processed: list[str] = []

            def process(job_id: str) -> None:
                processed.append(job_id)
                if len(processed) == 1:
                    started.set()
                    self.assertTrue(release.wait(2.0))
                operations._update_transfer_job(job_id, status="COMPLETED", phase="COMPLETED")

            operations._process_transfer_job = process  # type: ignore[method-assign]
            # Cleanups run in reverse order: release a blocked worker before
            # waiting for the executor to shut down when an assertion fails.
            self.addCleanup(operations.shutdown_transfer_workers, wait=True)
            self.addCleanup(release.set)
            jobs = []
            for number in range(3):
                upload = operations.transfer_dir / f".upload-{number}.part"
                upload.write_bytes(f"payload-{number}".encode("ascii"))
                jobs.append(operations.enqueue_transfer(
                    filename=f"sample-{number}.txt", source_path=upload, destination_dir=r"C:\Temp",
                    agent_ids=["agt-1"], actor="admin",
                ))
            self.assertTrue(started.wait(1.0))
            third = operations.transfer_job(jobs[2]["JobId"])
            self.assertEqual(third["Status"], "QUEUED_FOR_ANALYSIS")
            self.assertEqual(third["QueueState"], "WAITING")
            self.assertLessEqual(len(operations._scheduled_transfer_jobs), 2)
            release.set()
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline and len(processed) < 3:
                time.sleep(0.02)
            self.assertEqual(3, len(processed))
            self.assertTrue(all(
                operations.transfer_job(job["JobId"])["Status"] == "COMPLETED"
                for job in jobs
            ))

    def test_clean_file_is_dispatched_and_quarantine_is_removed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            operations = self._operations(Path(td))
            upload = operations.transfer_dir / ".upload.part"
            upload.write_bytes(b"safe payload")
            job = operations.enqueue_transfer(
                filename="sample.txt", source_path=upload, destination_dir=r"C:\Temp",
                agent_ids=["agt-1", "agt-2"], actor="admin",
            )
            operations.scan_script = lambda _path: ("CLEAN", "clean")  # type: ignore[method-assign]

            def queue_transfer(**kwargs):
                rows = []
                for agent_id in kwargs["agent_ids"]:
                    row = {"JobId": f"file-{agent_id}", "AgentId": agent_id, "SiteCode": "18601"}
                    rows.append(row)
                    kwargs["on_queued"](row)
                return rows

            operations.queue_transfer = queue_transfer  # type: ignore[method-assign]
            operations._process_transfer_job(job["JobId"])
            final = operations.transfer_job(job["JobId"])
            self.assertEqual(final["Status"], "COMPLETED")
            self.assertEqual(final["QueuedCount"], 2)
            self.assertEqual(final["ScanStatus"], "CLEAN")
            self.assertIsInstance(final["ScanEngine"], str)
            self.assertIsInstance(final["ScanDurationMs"], int)
            self.assertIsNotNone(final["ScanStartedAt"])
            self.assertIsNotNone(final["ScanCompletedAt"])
            self.assertFalse(Path(job["StagedPath"]).exists())

    def test_scan_failure_blocks_dispatch_and_becomes_job_error(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            operations = self._operations(Path(td))
            upload = operations.transfer_dir / ".upload.part"
            upload.write_bytes(b"unknown payload")
            job = operations.enqueue_transfer(
                filename="sample.bin", source_path=upload, destination_dir=r"C:\Temp",
                agent_ids=["agt-1"], actor="admin",
            )
            operations.scan_script = lambda _path: ("SCAN_TIMEOUT", "scanner timed out")  # type: ignore[method-assign]
            operations.queue_transfer = lambda **_kwargs: self.fail("A blocked file must never be dispatched")  # type: ignore[method-assign]
            operations._process_transfer_job(job["JobId"])
            final = operations.transfer_job(job["JobId"])
            self.assertEqual(final["Status"], "FAILED")
            self.assertIn("SCAN_TIMEOUT", final["Error"])
            self.assertFalse(Path(job["StagedPath"]).exists())

    def test_clamscan_timeout_is_a_controlled_status(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            operations = self._operations(Path(td))
            candidate = operations.transfer_dir / "sample.txt"
            candidate.write_text("safe", encoding="utf-8")
            with patch("gideon_web_admin.operations.shutil.which", return_value="/usr/bin/clamscan"), patch(
                "gideon_web_admin.operations.subprocess.run",
                side_effect=subprocess.TimeoutExpired(["clamscan"], 300),
            ):
                status, detail = operations.scan_script(candidate)
            self.assertEqual(status, "SCAN_TIMEOUT")
            self.assertIn("no fue enviado", detail)

    def test_private_clamd_stream_is_preferred_without_path_access(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            operations = self._operations(Path(td))
            candidate = operations.transfer_dir / "sample.txt"
            candidate.write_text("safe", encoding="utf-8")
            command = (["/usr/bin/clamdscan", "--config-file=/etc/gideon/security/clamd.conf", "--stream", "--no-summary"], "")
            completed = subprocess.CompletedProcess(command[0] + [str(candidate)], 0, "stream: OK\n", "")
            with patch.object(operations, "_clamd_stream_command", return_value=command), patch(
                "gideon_web_admin.operations.subprocess.run", return_value=completed,
            ) as runner:
                status, detail = operations.scan_script(candidate)
            self.assertEqual(status, "CLEAN")
            self.assertIn("Engine=clamd-stream", detail)
            invoked = runner.call_args.args[0]
            self.assertIn("--stream", invoked)
            self.assertNotIn("--database=/var/lib/gideon/security/clamav", invoked)

    def test_private_clamd_timeout_fails_closed_without_slow_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            operations = self._operations(Path(td))
            candidate = operations.transfer_dir / "sample.txt"
            candidate.write_text("safe", encoding="utf-8")
            command = (["/usr/bin/clamdscan", "--config-file=/etc/gideon/security/clamd.conf", "--stream", "--no-summary"], "")
            with patch.object(operations, "_clamd_stream_command", return_value=command), patch(
                "gideon_web_admin.operations.subprocess.run",
                side_effect=subprocess.TimeoutExpired(command[0], 180),
            ) as runner:
                status, detail = operations.scan_script(candidate)
            self.assertEqual(status, "SCAN_TIMEOUT")
            self.assertIn("Engine=clamd-stream", detail)
            self.assertEqual(runner.call_count, 1)

    def test_portable_destination_is_resolved_below_each_gideon_root(self) -> None:
        expected = {
            "windows": r"C:\GIDEON\Distribucion\Videos\menu.mp4",
            "linux": "/opt/gideon/Distribucion/Videos/menu.mp4",
            "ubuntu": "/opt/gideon/Distribucion/Videos/menu.mp4",
            "raspberry_pi": "/opt/gideon/Distribucion/Videos/menu.mp4",
            "darwin": "/Library/Application Support/GIDEON/Distribucion/Videos/menu.mp4",
        }
        for platform, path in expected.items():
            self.assertEqual(WebOperations._remote_join(platform, "Distribucion/Videos", "menu.mp4"), path)
        self.assertEqual(
            WebOperations._remote_join("linux", r"C:\GIDEON\Distribucion\Videos", "menu.mp4"),
            "/opt/gideon/Distribucion/Videos/menu.mp4",
        )

    def test_portable_destination_rejects_traversal_and_drive_escape(self) -> None:
        for destination in ("../etc", "Distribucion/../etc", "Z:/fuera"):
            with self.assertRaises(ValueError):
                WebOperations._remote_join("linux", destination, "menu.mp4")

    def test_linux_and_windows_sources_stay_identical(self) -> None:
        linux = APP_ROOT / "gideon_web_admin"
        windows = ROOT / "payload" / "windows" / "GIDEON Remote Control" / "app" / "gideon_web_admin"
        for relative in (
            "operations.py", "gateway.py", "app.py", "templates/transfer_job_detail.html",
            "templates/transfers.html", "templates/jobs.html", "templates/base.html",
            "static/job_live.js", "static/workflow_simplify.js",
        ):
            self.assertEqual((linux / relative).read_bytes(), (windows / relative).read_bytes(), relative)


if __name__ == "__main__":
    unittest.main(verbosity=2)
