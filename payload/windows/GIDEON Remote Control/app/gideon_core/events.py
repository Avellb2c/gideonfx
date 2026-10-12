from __future__ import annotations

import datetime as dt
import json
import os
import threading
from pathlib import Path
from typing import Any

from gideon_io import InterProcessFileLock
from .protocol import EVENT_SCHEMA_VERSION


class JobEventJournal:
    """Append-only audit journal. It is observability, not the source of truth."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def path(self, job_id: str) -> Path:
        return self.root / f"{job_id}.events.jsonl"

    def append(self, job_id: str, event_type: str, payload: dict[str, Any]) -> None:
        path = self.path(job_id)
        lock = InterProcessFileLock(path, timeout=1.0)
        event = {
            "SchemaVersion": EVENT_SCHEMA_VERSION,
            "At": dt.datetime.now().astimezone().isoformat(timespec="milliseconds"),
            "Pid": os.getpid(),
            "Thread": threading.get_ident(),
            "JobId": str(job_id),
            "Type": str(event_type),
            "Data": payload,
        }
        line = json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n"
        try:
            with lock:
                with path.open("a", encoding="utf-8", newline="") as fh:
                    fh.write(line)
                    fh.flush()
        except Exception:
            # Observability must never break orchestration.
            return

    def record_manifest_changes(
        self,
        job_id: str,
        before: dict[str, Any] | None,
        after: dict[str, Any],
    ) -> None:
        """Journal útil para troubleshooting, sin convertirse en source-of-truth."""
        before = before or {}

        old_job = str(before.get("Status") or "")
        new_job = str(after.get("Status") or "")
        if old_job != new_job:
            self.append(job_id, "JOB_STATE_CHANGED", {"From": old_job, "To": new_job})

        old_py = before.get("ControllerLastPythonError")
        new_py = after.get("ControllerLastPythonError")
        if isinstance(new_py, dict) and new_py != old_py:
            self.append(job_id, "PYTHON_RUNTIME_ERROR", {
                "Type": new_py.get("Type"),
                "Message": new_py.get("Message"),
                "At": new_py.get("At"),
                "TracebackTail": new_py.get("TracebackTail"),
                "RestartCount": after.get("ControllerMonitorRestartCount"),
                "RuntimeState": after.get("ControllerRuntimeState"),
            })

        old_conn = str(before.get("ControllerConnectivityState") or "")
        new_conn = str(after.get("ControllerConnectivityState") or "")
        old_mode = str(before.get("ControllerConnectionMode") or "")
        new_mode = str(after.get("ControllerConnectionMode") or "")
        if old_conn != new_conn or old_mode != new_mode:
            self.append(job_id, "CONNECTIVITY_CHANGED", {
                "FromState": old_conn,
                "ToState": new_conn,
                "FromMode": old_mode,
                "Mode": new_mode,
                "SourceIPs": after.get("ControllerSourceIPs") or [],
                "CheckedAt": after.get("ControllerConnectivityCheckedAt"),
            })

        old_attempted = int(before.get("DispatchAttempted", 0) or 0)
        new_attempted = int(after.get("DispatchAttempted", 0) or 0)
        old_ok = int(before.get("DispatchOk", 0) or 0)
        new_ok = int(after.get("DispatchOk", 0) or 0)
        if old_attempted != new_attempted or old_ok != new_ok:
            self.append(job_id, "DISPATCH_PROGRESS", {
                "Attempted": new_attempted,
                "Ok": new_ok,
                "Failed": int(after.get("DispatchFailed", 0) or 0),
                "Total": int(after.get("TotalCount", 0) or 0),
            })

        old_round = int(before.get("MonitorRound", 0) or 0)
        new_round = int(after.get("MonitorRound", 0) or 0)
        old_processed = int(before.get("MonitorRoundProcessedCount", 0) or 0)
        new_processed = int(after.get("MonitorRoundProcessedCount", 0) or 0)
        new_target = int(after.get("MonitorRoundTargetCount", 0) or 0)
        if (
            new_round != old_round
            or (
                new_target > 0
                and new_processed == new_target
                and old_processed != new_processed
            )
        ):
            self.append(job_id, "MONITOR_ROUND", {
                "Round": new_round,
                "Processed": new_processed,
                "Target": new_target,
                "Success": int(after.get("MonitorRoundSuccessCount", 0) or 0),
                "Failure": int(after.get("MonitorRoundFailureCount", 0) or 0),
                "Collected": int(after.get("MonitorRoundCollectedCount", 0) or 0),
            })

        old_sites = before.get("Sites") or {}
        new_sites = after.get("Sites") or {}

        for code, new_entry in new_sites.items():
            new_entry = new_entry or {}
            old_entry = old_sites.get(code) or {}
            site_name = new_entry.get("SiteName")

            def transition(field: str, event_type: str) -> None:
                old_value = str(old_entry.get(field) or "")
                new_value = str(new_entry.get(field) or "")
                if old_value != new_value:
                    self.append(job_id, event_type, {
                        "SiteCode": code,
                        "SiteName": site_name,
                        "From": old_value,
                        "To": new_value,
                    })

            transition("TransferStatus", "TRANSFER_STATE_CHANGED")
            transition("StartStatus", "START_STATE_CHANGED")
            transition("DispatchStatus", "DISPATCH_STATE_CHANGED")
            transition("TaskState", "TASK_STATE_CHANGED")

            old_state = str(old_entry.get("RemoteState") or "")
            new_state = str(new_entry.get("RemoteState") or "")
            if old_state != new_state:
                self.append(job_id, "SITE_STATE_CHANGED", {
                    "SiteCode": code,
                    "SiteName": site_name,
                    "From": old_state,
                    "To": new_state,
                })

            old_collect = str(old_entry.get("CollectionStatus") or "")
            new_collect = str(new_entry.get("CollectionStatus") or "")
            if old_collect != new_collect:
                self.append(job_id, "COLLECTION_STATE_CHANGED", {
                    "SiteCode": code,
                    "SiteName": site_name,
                    "From": old_collect,
                    "To": new_collect,
                })

            old_progress = old_entry.get("Progress")
            new_progress = new_entry.get("Progress")
            old_progress = old_progress if isinstance(old_progress, dict) else {}
            new_progress = new_progress if isinstance(new_progress, dict) else {}

            old_index = int(
                old_progress.get("CurrentScriptIndex", old_entry.get("CurrentScriptIndex", 0)) or 0
            )
            new_index = int(
                new_progress.get("CurrentScriptIndex", new_entry.get("CurrentScriptIndex", 0)) or 0
            )
            old_name = str(
                old_progress.get("CurrentScriptName", old_entry.get("CurrentScriptName", "")) or ""
            )
            new_name = str(
                new_progress.get("CurrentScriptName", new_entry.get("CurrentScriptName", "")) or ""
            )
            old_phase = str(old_progress.get("Phase") or "")
            new_phase = str(new_progress.get("Phase") or "")

            if old_index != new_index or old_name != new_name or old_phase != new_phase:
                self.append(job_id, "SCRIPT_STATE_CHANGED", {
                    "SiteCode": code,
                    "SiteName": site_name,
                    "Index": new_index,
                    "Count": int(
                        new_progress.get("ScriptCount", new_entry.get("ScriptCount", 0)) or 0
                    ),
                    "Name": new_name,
                    "Phase": new_phase,
                    "ChildPid": new_progress.get("ChildPid"),
                    "ExecutionMode": new_progress.get("ExecutionMode"),
                })

            old_dirs = int(old_progress.get("Directories", 0) or 0)
            new_dirs = int(new_progress.get("Directories", 0) or 0)
            old_bak = int(old_progress.get("BackupFolders", 0) or 0)
            new_bak = int(new_progress.get("BackupFolders", 0) or 0)

            if (
                (old_dirs == 0 and new_dirs > 0)
                or (new_dirs - old_dirs) >= 1000
                or old_bak != new_bak
            ):
                self.append(job_id, "SCRIPT_PROGRESS", {
                    "SiteCode": code,
                    "SiteName": site_name,
                    "Index": new_index,
                    "Name": new_name,
                    "Directories": new_dirs,
                    "DirectoriesPerSecond": new_progress.get("DirectoriesPerSecond"),
                    "BackupFolders": new_bak,
                    "BakFilesSeen": new_progress.get("BakFilesSeen"),
                    "ElapsedSec": new_progress.get("ElapsedSec"),
                    "CurrentPath": new_progress.get("CurrentPath"),
                })

            old_error = str(
                old_entry.get("Error")
                or old_entry.get("DispatchError")
                or old_entry.get("LastPollError")
                or ""
            )
            new_error = str(
                new_entry.get("Error")
                or new_entry.get("DispatchError")
                or new_entry.get("LastPollError")
                or ""
            )
            if new_error and new_error != old_error:
                self.append(job_id, "SITE_ERROR", {
                    "SiteCode": code,
                    "SiteName": site_name,
                    "RemoteState": new_state,
                    "DispatchStatus": new_entry.get("DispatchStatus"),
                    "Error": new_error,
                })

            old_layer = str(old_entry.get("ExecutionLayer") or "")
            new_layer = str(new_entry.get("ExecutionLayer") or "")
            old_code = str(old_entry.get("ExecutionErrorCode") or "")
            new_code = str(new_entry.get("ExecutionErrorCode") or "")
            if (
                new_layer
                and new_layer != "REMOTE_OK"
                and (new_layer != old_layer or new_code != old_code)
            ):
                self.append(job_id, "POWERSHELL_RUNTIME_ERROR", {
                    "SiteCode": code,
                    "SiteName": site_name,
                    "Layer": new_layer,
                    "Code": new_entry.get("ExecutionErrorCode"),
                    "Detail": new_entry.get("ExecutionErrorDetail"),
                    "TaskState": new_entry.get("TaskState"),
                    "LastTaskResult": new_entry.get("LastTaskResult"),
                    "TaskResultMeaning": new_entry.get("TaskResultMeaning"),
                })
