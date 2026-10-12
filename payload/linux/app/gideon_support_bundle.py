from __future__ import annotations

from gideon_common.clock import now_iso
from gideon_common.redaction import redact, redact_text
import datetime as dt
import json
import logging
import os
import platform
from pathlib import Path
import shutil
import sys
import tempfile
import zipfile
from typing import Any, Iterable


_LOG = logging.getLogger(__name__)




def copy_if_exists(src: Path, dst: Path) -> bool:
    """Copy support evidence while redacting text/config credentials."""
    src=Path(src)
    if not src.exists() or not src.is_file():
        return False
    dst.parent.mkdir(parents=True,exist_ok=True)
    text_ext={".log",".txt",".json",".jsonl",".csv",".md",".out",".err"}
    if src.suffix.lower() in text_ext:
        try:
            raw=src.read_text(encoding="utf-8-sig",errors="replace")
            if src.suffix.lower()==".json":
                try:
                    value=json.loads(raw)
                    dst.write_text(json.dumps(redact(value),ensure_ascii=False,indent=2),encoding="utf-8")
                    return True
                except Exception:
                    pass
            dst.write_text(redact_text(raw),encoding="utf-8")
            return True
        except Exception as exc:
            _LOG.warning("SupportBundle: no se pudo sanitizar %s: %s", src, exc)
            return False
    shutil.copy2(src,dst)
    return True


def copy_tree_filtered(src: Path, dst: Path, *, max_file_bytes: int = 8*1024*1024) -> int:
    src=Path(src)
    if not src.exists():
        return 0
    allowed={".log",".txt",".json",".jsonl",".csv",".md",".out",".err"}
    count=0
    for f in src.rglob("*"):
        if not f.is_file():
            continue
        if f.suffix.lower() not in allowed:
            continue
        try:
            if f.stat().st_size > max_file_bytes:
                continue
            target=dst/f.relative_to(src)
            if copy_if_exists(f,target):
                count+=1
        except Exception as exc:
            _LOG.warning("SupportBundle: no se pudo copiar %s: %s", f, exc)
    return count


class SupportBundleExporter:
    def __init__(
        self,
        *,
        app_root: Path,
        jobs_dir: Path,
        gui_logs_dir: Path,
        results_dir: Path,
        raw_dir: Path,
        packages_dir: Path,
        config_path: Path,
    ) -> None:
        self.app_root=Path(app_root)
        self.jobs_dir=Path(jobs_dir)
        self.gui_logs_dir=Path(gui_logs_dir)
        self.results_dir=Path(results_dir)
        self.raw_dir=Path(raw_dir)
        self.packages_dir=Path(packages_dir)
        self.config_path=Path(config_path)

    def _manifest(self, job_id: str) -> dict[str,Any]:
        path=self.jobs_dir/f"{job_id}.json"
        if not path.exists(): return {}
        try:return json.loads(path.read_text(encoding="utf-8-sig"))
        except Exception:return {}

    def export(
        self,
        job_id: str,
        target_zip: Path,
        *,
        include_local_results: bool = True,
        include_recent_gui_logs: bool = True,
        current_backend_log: Path | None = None,
        active_sites_file: Path | None = None,
        active_group: dict[str,Any] | None = None,
    ) -> Path:
        job_id=str(job_id).strip()
        if not job_id:
            raise ValueError("Job ID requerido.")
        target_zip=Path(target_zip)
        target_zip.parent.mkdir(parents=True,exist_ok=True)
        manifest=self._manifest(job_id)

        with tempfile.TemporaryDirectory(prefix="gideon-support-") as td:
            root=Path(td)/f"GIDEON-Support-{job_id}"
            root.mkdir(parents=True)

            # Core state
            copy_if_exists(self.jobs_dir/f"{job_id}.json",root/"job"/"manifest.json")
            copy_if_exists(self.jobs_dir/"events"/f"{job_id}.events.jsonl",root/"job"/"events.jsonl")
            copy_if_exists(self.jobs_dir/"runtime"/f"{job_id}.controller.json",root/"python"/"controller_runtime.json")

            # Runtime backend log from sidecar/manifest/current GUI.
            backend_candidates=[]
            manifest_backend = manifest.get("BackendLog")
            if manifest_backend:
                backend_candidates.append(Path(str(manifest_backend)))
            runtime_path=self.jobs_dir/"runtime"/f"{job_id}.controller.json"
            if runtime_path.exists():
                try:
                    runtime=json.loads(runtime_path.read_text(encoding="utf-8-sig"))
                    if runtime.get("BackendLog"): backend_candidates.append(Path(str(runtime["BackendLog"])))
                except Exception as exc:
                    _LOG.warning("SupportBundle: runtime.json inválido %s: %s", runtime_path, exc)
            if current_backend_log: backend_candidates.append(Path(current_backend_log))
            seen=set()
            for i,p in enumerate(backend_candidates,1):
                key=str(p)
                if key in seen: continue
                seen.add(key)
                copy_if_exists(p,root/"python"/f"backend_{i}_{p.name}")

            # Recent GUI logs are useful when backend sidecar was never created.
            if include_recent_gui_logs and self.gui_logs_dir.exists():
                recent=sorted(
                    [p for p in self.gui_logs_dir.glob("*.log") if p.is_file()],
                    key=lambda p:p.stat().st_mtime,
                    reverse=True,
                )[:8]
                for p in recent:
                    copy_if_exists(p,root/"python"/"recent_gui_logs"/p.name)

            # Remote diagnostics embedded by the monitor.
            remote={}
            for code,entry in (manifest.get("Sites") or {}).items():
                diag=entry.get("RemoteDiagnostics")
                layer=entry.get("ExecutionLayer")
                if diag or layer or entry.get("Error") or entry.get("DispatchError"):
                    remote[code]={
                        "SiteName":entry.get("SiteName"),
                        "ServerIP":entry.get("ServerIP"),
                        "RemoteState":entry.get("RemoteState"),
                        "TaskState":entry.get("TaskState"),
                        "LastTaskResult":entry.get("LastTaskResult"),
                        "TaskResultMeaning":entry.get("TaskResultMeaning"),
                        "ExecutionLayer":layer,
                        "ExecutionErrorCode":entry.get("ExecutionErrorCode"),
                        "ExecutionErrorDetail":entry.get("ExecutionErrorDetail"),
                        "TelemetryState":entry.get("TelemetryState"),
                        "TelemetrySource":entry.get("TelemetrySource"),
                        "TelemetryTransport":entry.get("TelemetryTransport"),
                        "TaskStateSource":entry.get("TaskStateSource"),
                        "WorkerStartupObservationCount":entry.get("WorkerStartupObservationCount"),
                        "CleanupState":entry.get("CleanupState"),
                        "JobObjectAssignments":entry.get("JobObjectAssignments"),
                        "JobObjectFallbacks":entry.get("JobObjectFallbacks"),
                        "ResidualProcessesKilled":entry.get("ResidualProcessesKilled"),
                        "ProcessObjectsDisposed":entry.get("ProcessObjectsDisposed"),
                        "PollFailureCount":entry.get("PollFailureCount"),
                        "LastPollError":entry.get("LastPollError"),
                        "LastCheckedAt":entry.get("LastCheckedAt"),
                        "MonitorWatchdogTrips":entry.get("MonitorWatchdogTrips"),
                        "CollectionWatchdogTrips":entry.get("CollectionWatchdogTrips"),
                        "Error":entry.get("Error"),
                        "DispatchError":entry.get("DispatchError"),
                        "RemoteDiagnostics":diag,
                    }
            (root/"powershell").mkdir(parents=True,exist_ok=True)
            (root/"powershell"/"remote_diagnostics.json").write_text(
                json.dumps(redact(remote),ensure_ascii=False,indent=2),
                encoding="utf-8",
            )

            # Collected raw/logs, if already present.
            if include_local_results:
                copy_tree_filtered(self.raw_dir/job_id,root/"collected"/"raw")
                copy_tree_filtered(self.results_dir/job_id,root/"collected"/"results")
                copy_tree_filtered(self.packages_dir/job_id,root/"package_metadata")
                # Algunos exports finales viven directamente en results_dir.
                if self.results_dir.exists():
                    for f in self.results_dir.glob(f"*{job_id}*"):
                        if f.is_file() and f.suffix.lower() in {".log",".txt",".json",".jsonl",".csv",".xlsx"}:
                            try:
                                if f.stat().st_size <= 15*1024*1024:
                                    copy_if_exists(f,root/"collected"/"final_exports"/f.name)
                            except Exception as exc:
                                _LOG.warning("SupportBundle: no se pudo evaluar/capturar %s: %s", f, exc)

            # Sanitized local config.
            try:
                cfg=json.loads(self.config_path.read_text(encoding="utf-8-sig"))
                (root/"local").mkdir(parents=True,exist_ok=True)
                (root/"local"/"config.redacted.json").write_text(
                    json.dumps(redact(cfg),ensure_ascii=False,indent=2),
                    encoding="utf-8",
                )
            except Exception as exc:
                _LOG.warning("SupportBundle: no se pudo redactar config local: %s", exc)

            # Inventario exacto usado por el Job, si el manifest lo registró.
            manifest_sites_file=manifest.get("SitesFile")
            if manifest_sites_file:
                copy_if_exists(Path(str(manifest_sites_file)),root/"local"/"job_sites.csv")
            elif active_sites_file:
                copy_if_exists(Path(active_sites_file),root/"local"/"active_sites.csv")
            if active_group:
                (root/"local").mkdir(parents=True,exist_ok=True)
                (root/"local"/"active_group.json").write_text(
                    json.dumps(active_group,ensure_ascii=False,indent=2),
                    encoding="utf-8",
                )

            system_info={
                "GeneratedAt":now_iso(),
                "ApplicationRoot":str(self.app_root),
                "JobId":job_id,
                "Platform":platform.platform(),
                "PythonVersion":sys.version,
                "PythonExecutable":sys.executable,
                "Hostname":platform.node(),
            }
            (root/"system_info.json").write_text(
                json.dumps(system_info,ensure_ascii=False,indent=2),
                encoding="utf-8",
            )

            # Human-readable summary.
            status=str(manifest.get("Status") or "UNKNOWN")
            sites=manifest.get("Sites") or {}
            layer_counts={}
            errors=[]
            for code,entry in sites.items():
                layer=str(entry.get("ExecutionLayer") or "NONE")
                if layer!="NONE":
                    layer_counts[layer]=layer_counts.get(layer,0)+1
                err=entry.get("ExecutionErrorDetail") or entry.get("Error") or entry.get("DispatchError")
                if err:
                    errors.append(
                        f"- {code}_{entry.get('SiteName') or ''}: "
                        f"{layer}/{entry.get('ExecutionErrorCode') or '-'} :: {err}"
                    )
            summary=[
                "GIDEON SSH ADMIN · SUPPORT BUNDLE",
                "="*78,
                f"Job: {job_id}",
                f"Status: {status}",
                f"Generated: {now_iso()}",
                f"LaunchStage: {manifest.get('LaunchStage') or '-'}",
                f"LaunchReturnCode: {manifest.get('LaunchReturnCode')}",
                f"LaunchError: {manifest.get('LaunchError') or '-'}",
                "",
                "CONTROLLER PYTHON",
                "-"*78,
            ]
            runtime={}
            if runtime_path.exists():
                try:runtime=json.loads(runtime_path.read_text(encoding="utf-8-sig"))
                except Exception:runtime={}
            summary += [
                f"State: {runtime.get('State') or manifest.get('ControllerRuntimeState') or '-'}",
                f"Phase: {runtime.get('Phase') or '-'}",
                f"PID: {runtime.get('Pid') or manifest.get('ControllerPid') or '-'}",
                f"Python: {runtime.get('PythonVersion') or '-'}",
                f"LastException: {runtime.get('LastExceptionType') or '-'} :: {runtime.get('LastExceptionMessage') or '-'}",
                "",
                "MONITOR / I-O WATCHDOG",
                "-"*78,
                (
                    "Round: "
                    f"{manifest.get('MonitorRound') or 0} · "
                    f"processed {manifest.get('MonitorRoundProcessedCount') or 0}/"
                    f"{manifest.get('MonitorRoundTargetCount') or 0}"
                ),
                f"Round started: {manifest.get('MonitorRoundStartedAt') or '-'}",
                f"Round finished: {manifest.get('MonitorRoundFinishedAt') or '-'}",
                f"Last monitor progress: {manifest.get('MonitorLastProgressAt') or '-'}",
                f"Monitor watchdog trips: {manifest.get('MonitorWatchdogTripCount') or 0}",
                f"Collection watchdog trips: {manifest.get('CollectionWatchdogTripCount') or 0}",
                f"Runtime policy: {json.dumps(manifest.get('RuntimePolicy') or {},ensure_ascii=False)}",
                "",
                "POWERSHELL / REMOTE",
                "-"*78,
                f"Layer counts: {json.dumps(layer_counts,ensure_ascii=False)}",
                *errors[:80],
                "",
                "CONTENIDO",
                "-"*78,
                "- manifest y timeline del Job",
                "- runtime/traceback Python",
                "- logs backend/GUI disponibles",
                "- diagnóstico Task/worker/payload PowerShell",
                "- lifecycle: Job Object, handles liberados y procesos residuales",
                "- worker.log/starter.log tails capturados en manifest",
                "- resultados/logs locales ya recolectados",
                "- config local REDACTADA",
                "",
                "Puede adjuntar este ZIP directamente para diagnóstico técnico.",
            ]
            (root/"SUPPORT-SUMMARY.txt").write_text("\n".join(summary),encoding="utf-8")

            if target_zip.exists():
                target_zip.unlink()
            with zipfile.ZipFile(target_zip,"w",zipfile.ZIP_DEFLATED) as z:
                for f in root.rglob("*"):
                    if f.is_file():
                        z.write(f,arcname=str(f.relative_to(root.parent)))
        return target_zip
