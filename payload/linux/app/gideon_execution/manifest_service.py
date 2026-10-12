from __future__ import annotations

"""Manifest lifecycle for fan-out jobs.

The orchestration facade delegates creation, counter recalculation, runtime policy
freezing and terminal-state resolution to this module.  It intentionally knows
nothing about SSH process execution.
"""

from pathlib import Path
from typing import Any

from gideon_admin import Site, now_iso
from gideon_core.protocol import ARCHITECTURE_ID, MANIFEST_SCHEMA_VERSION, PROTOCOL_VERSION
from gideon_core.transport_profiles import DEFAULT_TRANSPORT_PROFILE, get_transport_profile, normalize_transport_profile
from gideon_execution.package_service import script_definition_from_path
from gideon_execution.runtime_service import safe_component
from gideon_version import PRODUCT_VERSION


def site_entry(
    site: Site,
    job_root: str,
    task_name: str,
    *,
    upload_folder: str | None = None,
    collection_folder: str | None = None,
) -> dict[str, Any]:
    return {
        "SiteCode": site.code,
        "SiteName": site.name,
        "AgentId": getattr(site, "agent_id", "") or "",
        "AgentName": getattr(site, "agent_name", "") or "",
        "Hostname": getattr(site, "hostname", "") or "",
        "ServerIP": site.ip,
        "DispatchStatus": "PENDING",
        "TransferStatus": "PENDING",
        "StartStatus": "PENDING",
        "CollectionStatus": "PENDING",
        "CollectionVerified": False,
        "CollectionWarnings": [],
        "RemoteState": "PENDING",
        "TaskName": task_name,
        "RemoteJobRoot": job_root,
        "UploadFolderName": upload_folder,
        "CollectionFolderName": collection_folder,
        "DispatchAttempts": 0,
        "SftpAttempts": 0,
        "SshStartAttempts": 0,
        "DispatchError": None,
        "TaskState": None,
        "LastTaskResult": None,
        "Progress": None,
        "CurrentScriptIndex": 0,
        "CurrentScriptName": None,
        "ScriptCount": 0,
        "ScriptFailures": 0,
        "ScriptSkipped": 0,
        "RawDir": None,
        "RawFile": None,
        "ScriptResultFiles": [],
        "CollectedFiles": [],
        "CollectedAt": None,
        "Error": None,
        "LastCheckedAt": None,
        "CleanedRemote": False,
        "PackageVerified": False,
        "PackageBytes": 0,
    }


def make_manifest(
    *,
    job_id: str,
    script_paths: list[Path],
    sites: list[Site],
    remote_root: str,
    task_prefix: str,
    export_format: str,
    results_dir: Path,
    raw_dir: Path,
    poll_interval: int,
    continue_on_error: bool,
    transport_profile: str = DEFAULT_TRANSPORT_PROFILE,
) -> dict[str, Any]:
    site_map: dict[str, Any] = {}
    for site in sites:
        job_root = remote_root.rstrip("\\") + "\\" + job_id
        target_key = str(getattr(site, "agent_id", "") or site.code)
        task_suffix = safe_component(target_key, fallback=site.code)
        task_name = f"{task_prefix}_{job_id}_{task_suffix}"
        collection_folder = f"GIDEONSSH_RESULT_{safe_component(job_id)}"
        site_map[target_key] = site_entry(
            site,
            job_root,
            task_name,
            collection_folder=collection_folder,
        )

    output_base = results_dir / f"GIDEON-Fanout-{job_id}"
    scripts = []
    for i, p in enumerate(script_paths, 1):
        script_def = script_definition_from_path(p, i)
        script_def["Path"] = str(p)
        scripts.append(script_def)

    return {
        "JobId": job_id,
        "SchemaVersion": MANIFEST_SCHEMA_VERSION,
        "ProtocolVersion": PROTOCOL_VERSION,
        "ApplicationVersion": PRODUCT_VERSION,
        "Architecture": ARCHITECTURE_ID,
        "TransportProfile": normalize_transport_profile(transport_profile),
        "Transport": get_transport_profile(transport_profile).manifest_transport(),
        "Status": "CREATED",
        "CreatedAt": now_iso(),
        "UpdatedAt": now_iso(),
        "FinishedAt": None,
        "Scripts": scripts,
        "ScriptCount": len(scripts),
        "ContinueOnError": bool(continue_on_error),
        "ExportFormat": export_format,
        "OutputBase": str(output_base),
        "RawDir": str(raw_dir / job_id),
        "PollIntervalSeconds": poll_interval,
        "TotalCount": len(sites),
        "DispatchOk": 0,
        "DispatchFailed": 0,
        "DispatchAttempted": 0,
        "DispatchStartedAt": None,
        "DispatchCompletedAt": None,
        "WaitingRemoteCount": 0,
        "CollectedCount": 0,
        "CollectedWithErrorsCount": 0,
        "FailedCount": 0,
        "CancelledCount": 0,
        "InterruptedCount": 0,
        "ControllerConnectivityState": "UNKNOWN",
        "ControllerConnectionMode": "UNKNOWN",
        "ConnectionRecoveryCount": 0,
        "ResultFiles": [],
        "Sites": site_map,
    }


def recalc_manifest(manifest: dict[str, Any]) -> None:
    sites = list((manifest.get("Sites") or {}).values())
    manifest["DispatchOk"] = sum(1 for s in sites if s.get("DispatchStatus") == "DISPATCHED")
    manifest["DispatchFailed"] = sum(1 for s in sites if s.get("DispatchStatus") == "FAILED")
    manifest["DispatchDeferred"] = sum(1 for s in sites if s.get("DispatchStatus") == "DEFERRED")
    manifest["DispatchIgnored"] = sum(1 for s in sites if s.get("DispatchStatus") == "IGNORED")
    manifest["RetryEligibleCount"] = sum(
        1 for s in sites if bool(s.get("RetryEligible")) and s.get("DispatchStatus") in {"FAILED", "DEFERRED"}
    )
    manifest["CollectedCount"] = sum(1 for s in sites if s.get("RemoteState") == "COLLECTED")
    manifest["CollectedWithErrorsCount"] = sum(1 for s in sites if s.get("RemoteState") == "COLLECTED_WITH_ERRORS")
    manifest["FailedCount"] = sum(1 for s in sites if s.get("RemoteState") == "FAILED")
    manifest["CancelledRemoteCount"] = sum(1 for s in sites if s.get("RemoteState") == "CANCELLED")
    manifest["CancelledNotStartedCount"] = sum(1 for s in sites if s.get("RemoteState") == "CANCELLED_NOT_STARTED")
    manifest["CancelledCount"] = manifest["CancelledRemoteCount"] + manifest["CancelledNotStartedCount"]
    manifest["InterruptedCount"] = sum(1 for s in sites if s.get("RemoteState") == "INTERRUPTED")
    manifest["CancelFailedCount"] = sum(1 for s in sites if s.get("RemoteState") == "CANCEL_FAILED")
    manifest["UpdatedAt"] = now_iso()


def apply_runtime_policy(manifest: dict[str, Any], fanout_cfg: dict[str, Any]) -> None:
    """Freeze the monitor policy used by this Job for resume/retry consistency."""
    current = dict(manifest.get("RuntimePolicy") or {})
    current.setdefault("MonitorSitePollDeadlineSeconds", float(fanout_cfg.get("monitor_site_poll_deadline_seconds", 45.0)))
    current.setdefault("MonitorCollectionDeadlineSeconds", float(fanout_cfg.get("monitor_collection_deadline_seconds", 195.0)))
    current.setdefault("PollFailureWaitingThreshold", int(fanout_cfg.get("monitor_poll_failure_waiting_threshold", 2)))
    current.setdefault("TelemetryHardTimeoutSeconds", float(fanout_cfg.get("telemetry_hard_timeout_seconds", 12.0)))
    current.setdefault("TelemetryMode", str(fanout_cfg.get("telemetry_mode", "TRANSPORT_MIRROR_FIRST")))
    current.setdefault("ControlHardTimeoutSeconds", float(fanout_cfg.get("control_hard_timeout_seconds", 20.0)))
    current.setdefault("TransferHardTimeoutSeconds", float(fanout_cfg.get("transfer_hard_timeout_seconds", 90.0)))
    current.setdefault("CollectionHardTimeoutSeconds", float(fanout_cfg.get("collection_hard_timeout_seconds", 180.0)))
    current["IoWatchdogEnabled"] = bool(fanout_cfg.get("monitor_io_watchdog_enabled", True))
    manifest["RuntimePolicy"] = current


def terminal_site(entry: dict[str, Any]) -> bool:
    if entry.get("DispatchStatus") in {"FAILED", "DEFERRED", "IGNORED"}:
        return True
    return entry.get("RemoteState") in {
        "COLLECTED", "COLLECTED_WITH_ERRORS", "FAILED", "CANCELLED",
        "CANCELLED_NOT_STARTED", "CANCEL_FAILED", "INTERRUPTED",
    }


def finalize_manifest(manifest: dict[str, Any], store: Any) -> None:
    recalc_manifest(manifest)

    if manifest.get("CancelRequested"):
        failures = int(manifest.get("CancelFailureCount", 0) or 0)
        if manifest.get("CancelCompletedAt"):
            manifest["Status"] = "CANCELLED" if failures == 0 else "CANCELLED_WITH_ERRORS"
            manifest["FinishedAt"] = manifest.get("CancelCompletedAt") or manifest.get("FinishedAt") or now_iso()
        else:
            manifest["Status"] = "CANCEL_REQUESTED"
        store.write(manifest)
        return

    if all(terminal_site(x) for x in manifest["Sites"].values()):
        retryable = int(manifest.get("RetryEligibleCount", 0) or 0)
        ignored = int(manifest.get("DispatchIgnored", 0) or 0)
        errors = (
            manifest["FailedCount"]
            + manifest.get("CollectedWithErrorsCount", 0)
            + manifest["CancelledCount"]
            + manifest["InterruptedCount"]
            + manifest.get("CancelFailedCount", 0)
        )
        if retryable > 0 and not manifest.get("UnresolvedSitesIgnored"):
            manifest["Status"] = "ACTION_REQUIRED"
            manifest["ActionRequired"] = "RETRY_OR_IGNORE_SITES"
            manifest["FinishedAt"] = None
        elif ignored > 0 and errors == 0:
            manifest["Status"] = "COMPLETED_WITH_SKIPPED"
            manifest["FinishedAt"] = now_iso()
        else:
            errors += int(manifest.get("DispatchFailed", 0) or 0)
            manifest["Status"] = "COMPLETED" if errors == 0 else "COMPLETED_WITH_ERRORS"
            manifest["FinishedAt"] = now_iso()

    store.write(manifest)


__all__ = [
    "apply_runtime_policy", "finalize_manifest", "make_manifest", "recalc_manifest",
    "site_entry", "terminal_site",
]
