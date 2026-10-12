#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
GIDEON Fan-Out Controller v6.2.0

Arquitectura multi-transporte v5.0.2:
  SFTP PACKAGE -> SSH START -> WORKER -> SFTP COLLECT
  SCP ZIP      -> SSH START -> WORKER -> SCP ZIP COLLECT
  SSH/STDIN    -> SSH START -> WORKER -> SCP ZIP COLLECT

El trabajo remoto NO depende de mantener abierta la sesión SSH. El perfil de
transporte queda persistido por Job y se reutiliza en resume/retry/status/cancel.

Compatible con servidores:
- Windows Server 2016 Standard
- Windows Server 2022 Standard
- Windows PowerShell 5.1
- Windows en español o inglés
"""

from __future__ import annotations

from gideon_version import PRODUCT_VERSION
from gideon_common.hashing import sha256_file
from gideon_common.process import windows_hidden_kwargs
import argparse
import asyncio
import base64
import csv
import datetime as dt
import json
import hashlib
import re
import os
import shutil
import subprocess
import sys
import time
import traceback
import uuid
import zipfile
from pathlib import Path
from typing import Any, Optional

from gideon_io import atomic_write_json as io_atomic_write_json, atomic_write_json_nolock, read_json_retry, update_json_atomic
from gideon_core.protocol import (
    ARCHITECTURE_ID, MANIFEST_SCHEMA_VERSION, REMOTE_PACKAGE_SCHEMA_VERSION, PROTOCOL_VERSION,
)
from gideon_core.states import (
    JOB_CANCEL_STATES, JOB_TERMINAL_STATES, SITE_TERMINAL_STATES,
)
from gideon_core.config import require_valid_config
from gideon_core.events import JobEventJournal
from gideon_core.connectivity import ConnectivityGate
from gideon_execution.connectivity_service import (
    _run_local_powershell_json,
    measure_vpn_health,
    print_vpn_health,
    recommend_vpn_concurrency,
)
from gideon_execution.runtime_service import (
    FanoutStore,
    LocalProcessRegistry,
    _is_gideon_controller_process,
    _is_tracked_transport_process,
    _terminate_windows_tree,
    _windows_process_exists,
    _windows_process_info,
    safe_component,
)
from gideon_execution.report_service import format_job, parse_script_result
from gideon_execution.logging_utils import fail, log, ok, warn
from gideon_execution.shell_utils import powershell_stdin_payload, ps_single_quote, utf8_bom_base64
from gideon_execution.transport_service import RemoteTransport
from gideon_execution.package_service import (
    build_site_package,
    load_script_execution_metadata,
    script_definition_from_path,
)
from gideon_execution.manifest_service import (
    apply_runtime_policy,
    finalize_manifest,
    make_manifest,
    recalc_manifest,
    site_entry,
    terminal_site,
)
from gideon_host_profiles import HostProfileStore
from gideon_core.runtime_diag import (
    start_runtime,
    update_runtime,
    report_runtime_exception,
    finish_runtime,
)
from gideon_core.transport_profiles import (
    SFTP_SSH_SFTP,
    SCP_SSH_SCP,
    STDIN_SSH_SCP,
    DEFAULT_TRANSPORT_PROFILE,
    VALID_TRANSPORT_PROFILES,
    get_transport_profile,
    normalize_transport_profile,
    profile_from_manifest,
)

from gideon_admin import (
    Inventory,
    Site,
    SSHAgent,
    classify_failure,
    command_exists,
    ensure_dir,
    expand_path,
    load_config,
    now_iso,
)

VERSION = PRODUCT_VERSION
SCRIPT_DIR = Path(__file__).resolve().parent

# Protección secundaria: los backends creados por la GUI trabajan con stdout/
# stderr redirigidos. En Windows no dependemos de la página de códigos ANSI.
if os.environ.get("GIDEON_FORCE_UTF8_STDIO") == "1":
    for _stream in (sys.stdout, sys.stderr):
        try:
            if hasattr(_stream, "reconfigure"):
                _stream.reconfigure(
                    encoding="utf-8",
                    errors="backslashreplace",
                )
        except Exception as exc:
            # La observabilidad nunca debe impedir la ejecución del Job.
            print(f"[GIDEON][WARN] No se pudo forzar UTF-8 en stdio: {exc}", file=sys.stderr)
DEFAULT_CONFIG = SCRIPT_DIR / "config" / "config.json"
DEFAULT_SITES = SCRIPT_DIR / "config" / "sites.csv"
DEFAULT_WORKER = SCRIPT_DIR / "scripts" / "remote_job_worker.ps1"
DEFAULT_STARTER = SCRIPT_DIR / "scripts" / "start_job.ps1"
DEFAULT_SCRIPT_HOST = SCRIPT_DIR / "scripts" / "gideon_script_host.ps1"












def safe_job_id() -> str:
    return dt.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]


def parse_targets_text(value: Optional[str]) -> list[str]:
    if not value:
        return []
    return [x.strip() for x in value.split(",") if x.strip()]






def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    # Interproceso + tmp único + retry Windows sharing/AV.
    io_atomic_write_json(path, payload, lock_timeout=2.0, retries=8)


# ---------------------------------------------------------------------------
# VPN HEALTH / CONCURRENCIA ADAPTATIVA
# ---------------------------------------------------------------------------

























def release_local_job_runtime(
    *,
    manifest: dict[str, Any],
    store: FanoutStore,
    registry: LocalProcessRegistry,
    reason: str,
    exclude_pids: Optional[set[int]] = None,
) -> dict[str, Any]:
    """Libera procesos/controladores y conexiones SSH/SFTP SOLO del Job.

    No descarga la clave del ssh-agent y no toca sesiones SSH de otros Jobs.
    """
    exclude = set(exclude_pids or set())
    exclude.add(os.getpid())

    report: dict[str, Any] = {
        "RequestedAt": now_iso(),
        "Reason": reason,
        "ControllerPids": [],
        "ControllerTerminated": [],
        "TransportPids": [],
        "TransportTerminated": [],
        "Errors": [],
    }

    controller_candidates: list[int] = []
    for key in ("MonitorPid", "ControllerPid", "DispatchPid"):
        try:
            pid = int(manifest.get(key) or 0)
        except Exception:
            pid = 0
        if pid > 0 and pid not in exclude and pid not in controller_candidates:
            controller_candidates.append(pid)

    # Primero cortar el coordinador original; /T también cierra sus hijos.
    for pid in controller_candidates:
        report["ControllerPids"].append(pid)
        info = _windows_process_info(pid)
        if info is None:
            report["ControllerTerminated"].append(pid)
            continue
        if not _is_gideon_controller_process(
            info,
            job_id=str(manifest.get("JobId") or ""),
        ):
            report["Errors"].append(
                f"PID {pid} no coincide con un controlador GIDEON; no se terminó."
            )
            continue
        ok_kill, detail = _terminate_windows_tree(pid)
        if ok_kill:
            report["ControllerTerminated"].append(pid)
        else:
            report["Errors"].append(f"Controller PID {pid}: {detail}")

    # Segunda pasada: cualquier SSH/SFTP que hubiese quedado huérfano se
    # identifica por el registro exacto del Job.
    for row in registry.entries():
        try:
            pid = int(row.get("Pid") or 0)
        except Exception:
            pid = 0
        if pid <= 0 or pid in exclude:
            continue
        report["TransportPids"].append(pid)
        info = _windows_process_info(pid)
        if info is None:
            registry.unregister(pid)
            report["TransportTerminated"].append(pid)
            continue
        if not _is_tracked_transport_process(info):
            report["Errors"].append(
                f"PID {pid} registrado como transporte ya no es ssh/sftp/scp; no se tocó."
            )
            registry.unregister(pid)
            continue
        ok_kill, detail = _terminate_windows_tree(pid)
        if ok_kill:
            report["TransportTerminated"].append(pid)
            registry.unregister(pid)
        else:
            report["Errors"].append(f"Transport PID {pid}: {detail}")

    remaining: list[int] = []
    for row in registry.entries():
        try:
            pid = int(row.get("Pid") or 0)
        except Exception:
            continue
        if pid > 0 and _windows_process_exists(pid):
            remaining.append(pid)
        else:
            registry.unregister(pid)

    report["RemainingTransportPids"] = remaining
    report["ConnectionsReleased"] = len(remaining) == 0
    report["CompletedAt"] = now_iso()

    manifest["LocalRuntimeCleanup"] = report
    manifest["LocalConnectionsReleased"] = bool(report["ConnectionsReleased"])
    manifest["LocalRuntimeReleasedAt"] = report["CompletedAt"]
    _safe_cancel_store_write(
        store, manifest, context="liberación local de procesos/conexiones"
    )
    return report








def sftp_quote(value: str) -> str:
    # OpenSSH sftp batch parser supports double quoted paths. The generated
    # internal paths do not contain quotes, but escape defensively.
    return '"' + str(value).replace('\\', '/').replace('"', '\\"') + '"'


def local_sftp_path(path: Path) -> str:
    # Path.as_posix() on Windows produces C:/..., accepted by OpenSSH client.
    return path.resolve().as_posix()







def _update_connectivity_manifest(manifest: dict[str, Any], snapshot: Any, *, phase: str) -> None:
    previous = str(manifest.get("ControllerConnectivityState") or "UNKNOWN")
    current = str(snapshot.State)
    manifest["ControllerConnectivityState"] = current
    manifest["ControllerConnectionMode"] = str(snapshot.Mode)
    manifest["ControllerSourceIPs"] = list(snapshot.SourceIPs)
    manifest["ControllerReachableTargets"] = list(snapshot.ReachableTargets)
    manifest["ControllerFailedTargets"] = list(snapshot.FailedTargets)
    manifest["ControllerConnectivitySuccessCount"] = int(snapshot.SuccessCount)
    manifest["ControllerConnectivityTargetCount"] = int(snapshot.TargetCount)
    manifest["ControllerConnectivitySuccessRatio"] = float(getattr(snapshot, "SuccessRatio", 0.0) or 0.0)
    manifest["ControllerConnectivityRequiredSuccesses"] = int(getattr(snapshot, "RequiredSuccesses", 1) or 1)
    manifest["ControllerConnectivityCheckedAt"] = snapshot.CheckedAt
    manifest["ControllerConnectivityPhase"] = phase
    if not snapshot.Reachable:
        manifest["ConnectionLostAt"] = manifest.get("ConnectionLostAt") or now_iso()
    elif previous == "OFFLINE":
        manifest["ConnectionRecoveredAt"] = now_iso()
        manifest["ConnectionRecoveryCount"] = int(manifest.get("ConnectionRecoveryCount", 0) or 0) + 1
        manifest["ConnectionLostAt"] = None


async def wait_for_controller_connectivity(
    *, gate: ConnectivityGate | None, targets: list[str], manifest: dict[str, Any],
    store: FanoutStore, phase: str, restore_status: str,
) -> bool:
    """Pausa solo el controlador local; los jobs remotos siguen independientes."""
    if gate is None:
        return True
    first_offline_log = True
    while True:
        if manifest.get("CancelRequested") or store.cancel_requested(str(manifest.get("JobId") or "")):
            return False
        snap = await gate.probe(targets)
        _update_connectivity_manifest(manifest, snap, phase=phase)
        if snap.Reachable:
            if manifest.get("Status") == "WAITING_CONNECTION":
                manifest["Status"] = restore_status
                ok(
                    f"Conexión restablecida ({snap.Mode}); se retoma {phase}. "
                    f"Origen={','.join(snap.SourceIPs) or 'N/D'}"
                )
            store.write(manifest)
            return True
        manifest["Status"] = "WAITING_CONNECTION"
        manifest["WaitingConnectionSince"] = manifest.get("WaitingConnectionSince") or now_iso()
        store.write(manifest)
        if first_offline_log:
            warn(
                f"Sin ruta TCP/22 hacia servidores GIDEON durante {phase}. "
                "Se pausa el controlador; los jobs ya iniciados continúan en los servidores. "
                "Se reanudará automáticamente al volver la red empresarial o VPN."
            )
            first_offline_log = False
        await asyncio.sleep(gate.check_every)




def make_sftp_upload_batch(package: dict[str, Any]) -> str:
    upload = str(package["UploadFolderName"])
    package_dir = Path(str(package["PackageDir"]))
    lines = [
        f"-mkdir {sftp_quote(upload)}",
        f"-mkdir {sftp_quote(upload + '/scripts')}",
        (
            f"put {sftp_quote(local_sftp_path(package_dir / 'job.json'))} "
            f"{sftp_quote(upload + '/job.json')}"
        ),
        (
            f"put {sftp_quote(local_sftp_path(package_dir / 'start_job.ps1'))} "
            f"{sftp_quote(upload + '/start_job.ps1')}"
        ),
        (
            f"put {sftp_quote(local_sftp_path(package_dir / 'remote_job_worker.ps1'))} "
            f"{sftp_quote(upload + '/remote_job_worker.ps1')}"
        ),
        (
            f"put {sftp_quote(local_sftp_path(package_dir / 'gideon_script_host.ps1'))} "
            f"{sftp_quote(upload + '/gideon_script_host.ps1')}"
        ),
    ]

    for script in package.get("Scripts", []):
        name = str(script["RemoteName"])
        lines.append(
            f"put {sftp_quote(local_sftp_path(package_dir / 'scripts' / name))} "
            f"{sftp_quote(upload + '/scripts/' + name)}"
        )

    lines.append("quit")
    return "\n".join(lines) + "\n"


def make_package_transport_zip(package: dict[str, Any]) -> Path:
    """Crea un ZIP determinista del package dir para SCP/STDIN."""
    package_dir = Path(str(package["PackageDir"])).resolve()
    archive = package_dir.parent / f"{package_dir.name}.transport.zip"
    if archive.exists():
        archive.unlink()

    with zipfile.ZipFile(
        archive,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=6,
    ) as zf:
        for file_path in sorted(package_dir.rglob("*")):
            if not file_path.is_file():
                continue
            zf.write(
                file_path,
                arcname=file_path.relative_to(package_dir).as_posix(),
            )
    return archive


def make_scp_unpack_code(
    package: dict[str, Any],
    remote_archive_name: str,
) -> str:
    q_upload = ps_single_quote(str(package["UploadFolderName"]))
    q_archive = ps_single_quote(remote_archive_name)
    return rf"""
$ErrorActionPreference = 'Stop'
$zip = Join-Path $HOME '{q_archive}'
$dst = Join-Path $HOME '{q_upload}'
if (-not (Test-Path -LiteralPath $zip -PathType Leaf)) {{
    throw "SCP archive not found: $zip"
}}
if (Test-Path -LiteralPath $dst) {{
    Remove-Item -LiteralPath $dst -Recurse -Force
}}
New-Item -ItemType Directory -Path $dst -Force | Out-Null
Expand-Archive -LiteralPath $zip -DestinationPath $dst -Force
Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
[pscustomobject]@{{Success=$true;Mode='SCP'}} | ConvertTo-Json -Compress
"""


def make_start_code(package: dict[str, Any]) -> str:
    q_upload = ps_single_quote(str(package["UploadFolderName"]))
    q_manifest_hash = ps_single_quote(str(package["ManifestSha256"]))
    q_starter_hash = ps_single_quote(str(package["StarterSha256"]))

    return rf"""
$ErrorActionPreference = 'Stop'
$uploadFolder = '{q_upload}'
$starter = Join-Path (Join-Path $HOME $uploadFolder) 'start_job.ps1'
if (-not (Test-Path -LiteralPath $starter -PathType Leaf)) {{
    throw "Remote starter not found: $starter"
}}
& $starter `
    -UploadFolderName $uploadFolder `
    -ManifestSha256 '{q_manifest_hash}' `
    -StarterSha256 '{q_starter_hash}'
"""


def make_status_query(job_root: str, task_name: str) -> str:
    q_root = ps_single_quote(job_root)
    q_task = ps_single_quote(task_name)

    return rf"""
$ErrorActionPreference = 'Stop'
$jobRoot = '{q_root}'
$taskName = '{q_task}'
$statusPath = Join-Path $jobRoot 'status.json'
$progressPath = Join-Path $jobRoot 'progress.json'
$jobPath = Join-Path $jobRoot 'job.json'
$workerPath = Join-Path $jobRoot 'remote_job_worker.ps1'
$scriptHostPath = Join-Path $jobRoot 'gideon_script_host.ps1'
$status = $null
$progress = $null
$statusReadError = $null
$progressReadError = $null

if (Test-Path -LiteralPath $statusPath) {{
    try {{
        $status = Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json
    }}
    catch {{
        $statusReadError = $_.Exception.Message
        $status = [pscustomobject]@{{State='STATUS_READ_ERROR';Error=$statusReadError}}
    }}
}}

if (Test-Path -LiteralPath $progressPath) {{
    try {{
        $progress = Get-Content -LiteralPath $progressPath -Raw | ConvertFrom-Json
    }}
    catch {{
        $progressReadError = $_.Exception.Message
        $progress = $null
    }}
}}

$collectionRoot = $null
$jobResultExists = $false
$finalStatusExists = $false
$collectionReady = $false
$workerLogTail = @()
$starterLogTail = @()

if ($null -ne $status) {{
    try {{
        if ($status.PSObject.Properties.Name -contains 'CollectionRoot') {{
            $collectionRoot = [string]$status.CollectionRoot
        }}
    }} catch {{}}
}}

# Fallback: job.json también conoce CollectionRoot una vez preparado por starter.
if ([string]::IsNullOrWhiteSpace($collectionRoot) -and (Test-Path -LiteralPath $jobPath)) {{
    try {{
        $jobDef = Get-Content -LiteralPath $jobPath -Raw | ConvertFrom-Json
        if ($jobDef.PSObject.Properties.Name -contains 'CollectionRoot') {{
            $collectionRoot = [string]$jobDef.CollectionRoot
        }}
    }} catch {{}}
}}

if (-not [string]::IsNullOrWhiteSpace($collectionRoot)) {{
    $jobResultPath = Join-Path $collectionRoot 'job_result.json'
    $finalStatusPath = Join-Path $collectionRoot 'status.final.json'
    $workerLogPath = Join-Path $collectionRoot 'worker.log'
    $starterLogPath = Join-Path $collectionRoot 'starter.log'
    $jobResultExists = Test-Path -LiteralPath $jobResultPath
    $finalStatusExists = Test-Path -LiteralPath $finalStatusPath
    $collectionReady = ($jobResultExists -and $finalStatusExists)
}}

$taskState = $null
$lastTaskResult = $null
$lastRunTime = $null
$taskActionExecute = $null
$taskActionArguments = $null
$taskActionWorkingDirectory = $null
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($null -ne $task) {{
    $taskState = $task.State.ToString()
    try {{
        $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction Stop
        $lastTaskResult = $taskInfo.LastTaskResult
        $lastRunTime = $taskInfo.LastRunTime.ToString('o')
    }} catch {{ $lastTaskResult = $null }}

    try {{
        $action = @($task.Actions) | Select-Object -First 1
        if ($null -ne $action) {{
            $taskActionExecute = [string]$action.Execute
            $taskActionArguments = [string]$action.Arguments
            $taskActionWorkingDirectory = [string]$action.WorkingDirectory
        }}
    }} catch {{}}
}}

$lastTaskResultHex = $null
$taskResultMeaning = $null
if ($null -ne $lastTaskResult) {{
    try {{ $lastTaskResultHex = ('0x{{0:X8}}' -f ([uint32]$lastTaskResult)) }} catch {{}}
    switch ([int64]$lastTaskResult) {{
        0 {{ $taskResultMeaning = 'GIDEON_OK' }}
        20 {{ $taskResultMeaning = 'GIDEON_PAYLOAD_ERROR' }}
        30 {{ $taskResultMeaning = 'GIDEON_WORKER_FATAL' }}
        40 {{ $taskResultMeaning = 'GIDEON_CANCELLED' }}
        267009 {{ $taskResultMeaning = 'TASK_RUNNING' }}
        267008 {{ $taskResultMeaning = 'TASK_READY' }}
        2 {{ $taskResultMeaning = 'LEGACY_OR_OS_CODE_2_CHECK_WORKER_LOG' }}
        default {{ $taskResultMeaning = 'TASK_EXIT_CODE' }}
    }}
}}

$statusAgeSec = $null
if ($null -ne $status) {{
    try {{
        if ($status.PSObject.Properties.Name -contains 'UpdatedAt' -and -not [string]::IsNullOrWhiteSpace([string]$status.UpdatedAt)) {{
            $updated = [datetimeoffset]::Parse([string]$status.UpdatedAt)
            $statusAgeSec = [math]::Round(([datetimeoffset]::Now - $updated).TotalSeconds,1)
        }}
    }} catch {{}}
}}

$suspicious = $false
$statusState = $null
if ($null -ne $status) {{
    try {{ $statusState = [string]$status.State }} catch {{}}
}}
if ($null -eq $status) {{ $suspicious = $true }}
elseif ($statusState -eq 'STATUS_READ_ERROR') {{ $suspicious = $true }}
elseif (-not [string]::IsNullOrWhiteSpace([string]$status.Error)) {{ $suspicious = $true }}
elseif ($taskState -notin @('Running','Queued') -and $statusState -in @('DISPATCHED','RUNNING')) {{ $suspicious = $true }}
elseif ($statusState -eq 'DISPATCHED' -and $null -ne $statusAgeSec -and $statusAgeSec -ge 60) {{ $suspicious = $true }}

if ($suspicious -and -not [string]::IsNullOrWhiteSpace($collectionRoot)) {{
    try {{
        $workerLogPath = Join-Path $collectionRoot 'worker.log'
        if (Test-Path -LiteralPath $workerLogPath) {{
            $workerLogTail = @(Get-Content -LiteralPath $workerLogPath -Tail 14 -ErrorAction SilentlyContinue)
        }}
    }} catch {{}}
    try {{
        $starterLogPath = Join-Path $collectionRoot 'starter.log'
        if (Test-Path -LiteralPath $starterLogPath) {{
            $starterLogTail = @(Get-Content -LiteralPath $starterLogPath -Tail 10 -ErrorAction SilentlyContinue)
        }}
    }} catch {{}}
}}

$diag = [ordered]@{{
    Suspicious=[bool]$suspicious
    JobRootExists=[bool](Test-Path -LiteralPath $jobRoot -PathType Container)
    JobJsonExists=[bool](Test-Path -LiteralPath $jobPath -PathType Leaf)
    WorkerExists=[bool](Test-Path -LiteralPath $workerPath -PathType Leaf)
    ScriptHostExists=[bool](Test-Path -LiteralPath $scriptHostPath -PathType Leaf)
    StatusExists=[bool](Test-Path -LiteralPath $statusPath -PathType Leaf)
    ProgressExists=[bool](Test-Path -LiteralPath $progressPath -PathType Leaf)
    StatusReadError=$statusReadError
    ProgressReadError=$progressReadError
    StatusAgeSec=$statusAgeSec
    TaskActionExecute=$taskActionExecute
    TaskActionArguments=$taskActionArguments
    TaskActionWorkingDirectory=$taskActionWorkingDirectory
    LastRunTime=$lastRunTime
    LastTaskResultHex=$lastTaskResultHex
    TaskResultMeaning=$taskResultMeaning
    WorkerLogTail=@($workerLogTail)
    StarterLogTail=@($starterLogTail)
}}

[pscustomobject]@{{
    Exists=(Test-Path -LiteralPath $jobRoot)
    TaskState=$taskState
    LastTaskResult=$lastTaskResult
    Status=$status
    Progress=$progress
    CollectionRoot=$collectionRoot
    JobResultExists=[bool]$jobResultExists
    FinalStatusExists=[bool]$finalStatusExists
    CollectionReady=[bool]$collectionReady
    Diagnostics=$diag
}} | ConvertTo-Json -Depth 20 -Compress
"""


def mark_cancel_requested(
    manifest: dict[str, Any],
    *,
    source: str = "administrator",
) -> None:
    """Marca el estado local inmediatamente sin esperar a la red."""
    stamp = now_iso()
    manifest["CancelRequested"] = True
    manifest["CancelRequestedAt"] = manifest.get("CancelRequestedAt") or stamp
    manifest["CancelRequestSource"] = source
    manifest["Status"] = "CANCEL_REQUESTED"

    for entry in (manifest.get("Sites") or {}).values():
        if (
            entry.get("DispatchStatus") == "DISPATCHED"
            and not terminal_site(entry)
        ):
            previous = entry.get("RemoteState")
            if previous != "CANCEL_REQUESTED":
                entry["RemoteStateBeforeCancel"] = previous
            entry["RemoteState"] = "CANCEL_REQUESTED"
            entry["CancelRequestedAt"] = stamp
            entry["Error"] = None

    recalc_manifest(manifest)


def cancellation_completed(manifest: dict[str, Any]) -> bool:
    return bool(manifest.get("CancelCompletedAt")) or str(
        manifest.get("Status") or ""
    ).upper() in {"CANCELLED", "CANCELLED_WITH_ERRORS"}


def make_cancel_script(job_root: str, task_name: str) -> str:
    q_root = ps_single_quote(job_root)
    q_task = ps_single_quote(task_name)
    return rf"""
$ErrorActionPreference = 'Continue'
$jobRoot = '{q_root}'
$taskName = '{q_task}'
$statusPath = Join-Path $jobRoot 'status.json'
$progressPath = Join-Path $jobRoot 'progress.json'
$workerPid = $null
$workerTerminated = $false
$workerVerificationError = $null

if (Test-Path -LiteralPath $statusPath) {{
    try {{
        $statusBeforeCancel = Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json
        if ($statusBeforeCancel.PSObject.Properties.Name -contains 'PID') {{
            $workerPid = [int]$statusBeforeCancel.PID
        }}
    }} catch {{ }}
}}

$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
$stateBefore = $null
if ($null -ne $task) {{ $stateBefore = $task.State.ToString() }}

# Cancelación cooperativa primero: worker y payloads v3.2 observan este token.
$cancelPath = Join-Path $jobRoot 'cancel.request'
try {{
    $encoding=New-Object System.Text.UTF8Encoding($true)
    [IO.File]::WriteAllText($cancelPath,('RequestedAt=' + (Get-Date).ToString('o')),$encoding)
}} catch {{ }}

if ($null -ne $task -and $stateBefore -eq 'Running') {{
    # Dar hasta ~5 s al payload/worker para cerrar, persistir progreso parcial y salir.
    for ($i=0; $i -lt 20; $i++) {{
        Start-Sleep -Milliseconds 250
        $cooperativeProbe = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($null -eq $cooperativeProbe -or $cooperativeProbe.State.ToString() -ne 'Running') {{ break }}
    }}

    $cooperativeProbe = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($null -ne $cooperativeProbe -and $cooperativeProbe.State.ToString() -eq 'Running') {{
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    }}

    for ($i=0; $i -lt 20; $i++) {{
        Start-Sleep -Milliseconds 250
        $probe = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($null -eq $probe -or $probe.State.ToString() -ne 'Running') {{ break }}
    }}

    $probe = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($null -ne $probe -and $probe.State.ToString() -eq 'Running') {{
        & "$env:SystemRoot\\System32\\schtasks.exe" /End /TN $taskName 2>$null | Out-Null
        for ($i=0; $i -lt 20; $i++) {{
            Start-Sleep -Milliseconds 250
            $probe = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if ($null -eq $probe -or $probe.State.ToString() -ne 'Running') {{ break }}
        }}
    }}
}}

# Verificación adicional del proceso PowerShell del worker. Esto cubre casos
# donde Task Scheduler dejó un proceso huérfano. Solo se termina si PID, nombre
# y CommandLine coinciden con ESTE remote_job_worker.ps1 y ESTE JobRoot.
if ($null -ne $workerPid -and $workerPid -gt 0) {{
    $workerProc = Get-CimInstance Win32_Process -Filter ("ProcessId = " + $workerPid) -ErrorAction SilentlyContinue
    if ($null -ne $workerProc) {{
        $workerName = ([string]$workerProc.Name).ToLowerInvariant()
        $workerCmd = ([string]$workerProc.CommandLine).ToLowerInvariant()
        $expectedRoot = $jobRoot.ToLowerInvariant()
        $verifiedWorker = (
            ($workerName -eq 'powershell.exe' -or $workerName -eq 'pwsh.exe') -and
            $workerCmd.Contains('remote_job_worker.ps1') -and
            $workerCmd.Contains($expectedRoot)
        )

        if ($verifiedWorker) {{
            & "$env:SystemRoot\System32\taskkill.exe" /PID $workerPid /T /F 2>$null | Out-Null
            for ($i=0; $i -lt 20; $i++) {{
                Start-Sleep -Milliseconds 200
                $workerProbe = Get-CimInstance Win32_Process -Filter ("ProcessId = " + $workerPid) -ErrorAction SilentlyContinue
                if ($null -eq $workerProbe) {{ break }}
            }}
            $workerProbe = Get-CimInstance Win32_Process -Filter ("ProcessId = " + $workerPid) -ErrorAction SilentlyContinue
            $workerTerminated = ($null -eq $workerProbe)
        }} else {{
            $workerVerificationError = 'Worker PID exists but Name/CommandLine did not match this GIDEON Job; process was not killed.'
        }}
    }} else {{
        $workerTerminated = $true
    }}
}}

$taskAfter = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
$stateAfter = $null
if ($null -ne $taskAfter) {{ $stateAfter = $taskAfter.State.ToString() }}

$workerStillRunning = $false
if ($null -ne $workerPid -and $workerPid -gt 0 -and $null -eq $workerVerificationError -and -not $workerTerminated) {{
    $workerFinalProbe = Get-CimInstance Win32_Process -Filter ("ProcessId = " + $workerPid) -ErrorAction SilentlyContinue
    if ($null -ne $workerFinalProbe) {{
        $finalName = ([string]$workerFinalProbe.Name).ToLowerInvariant()
        $finalCmd = ([string]$workerFinalProbe.CommandLine).ToLowerInvariant()
        $workerStillRunning = (
            ($finalName -eq 'powershell.exe' -or $finalName -eq 'pwsh.exe') -and
            $finalCmd.Contains('remote_job_worker.ps1') -and
            $finalCmd.Contains($jobRoot.ToLowerInvariant())
        )
    }}
}}

if ($stateAfter -eq 'Running' -or $workerStillRunning) {{
    [pscustomobject]@{{
        Success=$false
        State='CANCEL_FAILED'
        TaskName=$taskName
        TaskState=$stateAfter
        Error=('Scheduled Task/worker remained active after cancellation. ' + [string]$workerVerificationError)
        WorkerPid=$workerPid
        WorkerTerminated=$workerTerminated
        WorkerStillRunning=$workerStillRunning
    }} | ConvertTo-Json -Compress
    exit 2
}}

$status = $null
if (Test-Path -LiteralPath $statusPath) {{
    try {{ $status = Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json }} catch {{ $status=$null }}
}}
if ($null -eq $status) {{ $status=[pscustomobject]@{{State='CANCELLED'}} }}
$status.State='CANCELLED'
if ($status.PSObject.Properties.Name -contains 'Phase') {{ $status.Phase='CANCELLED' }}
if ($status.PSObject.Properties.Name -contains 'UpdatedAt') {{ $status.UpdatedAt=(Get-Date).ToString('o') }}
if ($status.PSObject.Properties.Name -contains 'FinishedAt') {{ $status.FinishedAt=(Get-Date).ToString('o') }}
if ($status.PSObject.Properties.Name -contains 'Error') {{ $status.Error='Cancelled by GIDEON administrator.' }}
$encoding=New-Object System.Text.UTF8Encoding($true)
[IO.File]::WriteAllText($statusPath,($status|ConvertTo-Json -Depth 16),$encoding)

if (Test-Path -LiteralPath $progressPath) {{
    try {{
        $progress = Get-Content -LiteralPath $progressPath -Raw | ConvertFrom-Json
        if ($progress.PSObject.Properties.Name -contains 'Type') {{ $progress.Type='CANCELLED' }}
        if ($progress.PSObject.Properties.Name -contains 'Phase') {{ $progress.Phase='CANCELLED' }}
        if ($progress.PSObject.Properties.Name -contains 'UpdatedAt') {{ $progress.UpdatedAt=(Get-Date).ToString('o') }}
        [IO.File]::WriteAllText($progressPath,($progress|ConvertTo-Json -Depth 16),$encoding)
    }} catch {{ }}
}}

[pscustomobject]@{{
    Success=$true
    State='CANCELLED'
    TaskName=$taskName
    TaskState=$stateAfter
    StateBefore=$stateBefore
    WorkerPid=$workerPid
    WorkerTerminated=$workerTerminated
    WorkerStillRunning=$workerStillRunning
    WorkerVerificationError=$workerVerificationError
}} | ConvertTo-Json -Compress
"""


def make_cleanup_script(
    job_root: str,
    task_name: str,
    upload_folder: Optional[str] = None,
    collection_folder: Optional[str] = None,
) -> str:
    q_root = ps_single_quote(job_root)
    q_task = ps_single_quote(task_name)
    q_upload = ps_single_quote(upload_folder or "")
    q_collection = ps_single_quote(collection_folder or "")
    return rf"""
$ErrorActionPreference = 'Continue'
$jobRoot = '{q_root}'
$taskName = '{q_task}'
$uploadFolder = '{q_upload}'
$collectionFolder = '{q_collection}'
Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

# Final process hygiene. Never kill generic PowerShell processes: only
# powershell/pwsh instances whose command line explicitly contains this JobRoot.
try {{
    $jobRootLower = $jobRoot.ToLowerInvariant()

    $owned = @(
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object {{
            $name = ([string]$_.Name).ToLowerInvariant()
            $cmd = ([string]$_.CommandLine).ToLowerInvariant()

            (
                $name -eq 'powershell.exe' -or
                $name -eq 'pwsh.exe'
            ) -and
            -not [string]::IsNullOrWhiteSpace($cmd) -and
            $cmd.Contains($jobRootLower)
        }}
    )

    foreach ($proc in $owned) {{
        try {{
            & "$env:SystemRoot\System32\taskkill.exe" `
                /PID ([int]$proc.ProcessId) `
                /T `
                /F `
                2>$null |
                Out-Null
        }}
        catch {{
        }}
    }}
}}
catch {{
}}

if (Test-Path -LiteralPath $jobRoot) {{ Remove-Item -LiteralPath $jobRoot -Recurse -Force -ErrorAction SilentlyContinue }}
if (-not [string]::IsNullOrWhiteSpace($uploadFolder)) {{
    $uploadRoot=Join-Path $HOME $uploadFolder
    if (Test-Path -LiteralPath $uploadRoot) {{ Remove-Item -LiteralPath $uploadRoot -Recurse -Force -ErrorAction SilentlyContinue }}
}}
if (-not [string]::IsNullOrWhiteSpace($collectionFolder)) {{
    $collectionRoot=Join-Path $HOME $collectionFolder
    if (Test-Path -LiteralPath $collectionRoot) {{ Remove-Item -LiteralPath $collectionRoot -Recurse -Force -ErrorAction SilentlyContinue }}
}}
[pscustomobject]@{{Success=$true;Cleaned=$true;TaskName=$taskName}} | ConvertTo-Json -Compress
"""










async def dispatch_site(
    *,
    transport: RemoteTransport,
    site: Site,
    package: dict[str, Any],
) -> dict[str, Any]:
    result = site_entry(
        site,
        str(package["RemoteJobRoot"]),
        str(package["TaskName"]),
        upload_folder=str(package["UploadFolderName"]),
        collection_folder=str(package["CollectionFolderName"]),
    )
    result["ScriptCount"] = len(package.get("Scripts", []))
    result["PackageBytes"] = int(package.get("PackageBytes", 0) or 0)
    result["TransportProfile"] = transport.transport_profile
    result["TransportMethod"] = transport.transport_profile

    # --------------------------------------------------------------
    # FASE A · DISTRIBUCIÓN
    # --------------------------------------------------------------
    if transport.transport_profile == SFTP_SSH_SFTP:
        batch = make_sftp_upload_batch(package)
        rc, stdout, stderr, attempts = await transport.sftp_batch(
            site,
            batch,
            operation="SFTP_UPLOAD",
        )
        result["SftpAttempts"] = attempts
        result["DispatchAttempts"] += attempts
        if rc != 0:
            result["TransferStatus"] = "FAILED"
            result["DispatchStatus"] = "FAILED"
            result["RemoteState"] = "DISPATCH_FAILED"
            result["DispatchError"] = (
                stderr.strip() or stdout.strip() or f"SFTP ExitCode={rc}"
            )
            return result
        result["TransferStatus"] = "SFTP_UPLOADED"

    elif transport.transport_profile == SCP_SSH_SCP:
        archive = make_package_transport_zip(package)
        remote_archive = (
            f"{safe_component(str(package['UploadFolderName']))}.zip"
        )
        rc, stdout, stderr, attempts = await transport.scp_file(
            site,
            local_path=archive,
            remote_path=remote_archive,
            upload=True,
            operation="SCP_UPLOAD",
        )
        result["ScpAttempts"] = attempts
        result["DispatchAttempts"] += attempts
        if rc != 0:
            result["TransferStatus"] = "FAILED"
            result["DispatchStatus"] = "FAILED"
            result["RemoteState"] = "DISPATCH_FAILED"
            result["DispatchError"] = (
                stderr.strip() or stdout.strip() or f"SCP ExitCode={rc}"
            )
            return result

        unpack_code = make_scp_unpack_code(package, remote_archive)
        rc, stdout, stderr, unpack_attempts = await transport.run_ps(
            site,
            unpack_code,
            operation="SSH_UNPACK_SCP",
        )
        result["SshUnpackAttempts"] = unpack_attempts
        result["DispatchAttempts"] += unpack_attempts
        if rc != 0:
            result["TransferStatus"] = "FAILED"
            result["DispatchStatus"] = "FAILED"
            result["RemoteState"] = "DISPATCH_FAILED"
            result["DispatchError"] = (
                stderr.strip()
                or stdout.strip()
                or f"SSH unpack ExitCode={rc}"
            )
            return result
        result["TransferStatus"] = "SCP_UPLOADED"

    elif transport.transport_profile == STDIN_SSH_SCP:
        archive = make_package_transport_zip(package)
        rc, stdout, stderr, attempts = await transport.stdin_archive(
            site,
            archive_path=archive,
            upload_folder=str(package["UploadFolderName"]),
            operation="STDIN_UPLOAD",
        )
        result["StdinAttempts"] = attempts
        result["DispatchAttempts"] += attempts
        if rc != 0:
            result["TransferStatus"] = "FAILED"
            result["DispatchStatus"] = "FAILED"
            result["RemoteState"] = "DISPATCH_FAILED"
            result["DispatchError"] = (
                stderr.strip()
                or stdout.strip()
                or f"SSH/STDIN ExitCode={rc}"
            )
            return result
        result["TransferStatus"] = "STDIN_UPLOADED"

    else:
        result["TransferStatus"] = "FAILED"
        result["DispatchStatus"] = "FAILED"
        result["RemoteState"] = "DISPATCH_FAILED"
        result["DispatchError"] = (
            f"TransportProfile no soportado: {transport.transport_profile}"
        )
        return result

    # --------------------------------------------------------------
    # FASE B · SSH START
    # El control remoto es idéntico para los tres perfiles Agentless.
    # --------------------------------------------------------------
    start_code = make_start_code(package)
    rc, stdout, stderr, ssh_attempts = await transport.run_ps(
        site,
        start_code,
        operation="SSH_START",
    )
    result["SshStartAttempts"] = ssh_attempts
    result["DispatchAttempts"] += ssh_attempts

    if rc != 0:
        result["StartStatus"] = "FAILED"
        result["DispatchStatus"] = "FAILED"
        result["RemoteState"] = "DISPATCH_FAILED"
        result["DispatchError"] = (
            stderr.strip() or stdout.strip() or f"SSH ExitCode={rc}"
        )
        return result

    try:
        payload = json.loads(stdout.strip().splitlines()[-1])
    except Exception:
        payload = None

    if not isinstance(payload, dict) or not payload.get("Success"):
        result["StartStatus"] = "FAILED"
        result["DispatchStatus"] = "FAILED"
        result["RemoteState"] = "DISPATCH_FAILED"
        result["DispatchError"] = (
            stderr.strip()
            or stdout.strip()
            or "El servidor no confirmó el inicio del job."
        )
        return result

    result["StartStatus"] = "SSH_STARTED"
    result["DispatchStatus"] = "DISPATCHED"
    result["RemoteState"] = "DISPATCHED"
    result["TaskState"] = payload.get("TaskState")
    result["TaskStateSource"] = "DISPATCH_SNAPSHOT"
    result["TelemetryState"] = "PENDING"
    result["TelemetrySource"] = "NONE"
    result["PackageVerified"] = bool(payload.get("PackageVerified"))
    return result

async def dispatch_job(
    *,
    manifest: dict[str, Any], store: FanoutStore, transport: RemoteTransport,
    inventory_sites: list[Site], script_paths: list[Path], worker_path: Path,
    starter_path: Path, packages_root: Path, remote_root: str, task_prefix: str,
    workers: int, stagger_ms: int, continue_on_error: bool,
    adaptive_vpn_cfg: Optional[dict[str, Any]] = None,
    connectivity_cfg: Optional[dict[str, Any]] = None,
    site_deadline_seconds: float = 45.0,
) -> None:
    """Scheduler continuo: una sede lenta ocupa solo su slot."""
    from collections import deque

    total = len(inventory_sites)
    max_workers = max(1, min(int(workers), total))
    adaptive_cfg = dict(adaptive_vpn_cfg or {})
    adaptive_enabled = bool(adaptive_cfg.get("enabled", True))
    connectivity_enabled = bool((connectivity_cfg or {}).get("enabled", True))
    connectivity_gate = ConnectivityGate(connectivity_cfg or {}) if connectivity_enabled else None
    connectivity_targets = [s.ip for s in inventory_sites]

    manifest.update({
        "Status":"DISPATCHING", "DispatchStartedAt":now_iso(), "DispatchCompletedAt":None,
        "DispatchAttempted":0, "WaitingRemoteCount":0, "AdaptiveVpnEnabled":adaptive_enabled,
        "DispatchScheduler":"CONTINUOUS_SLOTS", "DispatchInFlight":0, "DispatchPending":total,
        "DispatchConcurrencyCurrent":0, "DispatchConcurrencyReason":"Inicializando",
    })
    manifest.setdefault("VpnHealthHistory", [])
    store.write(manifest)

    print(); print("="*78); print(
        f"FASE 1/4 - {transport.transport_spec.distribution} PACKAGE + SSH START"
    ); print("="*78)
    print(f"Sedes objetivo          : {total}")
    print(f"Scripts en paquete      : {len(script_paths)}")
    print(f"Máximo conexiones       : {max_workers}")
    print(f"VPN adaptativa          : {'SI' if adaptive_enabled else 'NO'}")
    print("Scheduler               : CONTINUOUS SLOTS")
    print("Una sede lenta consume solo un slot; las demás continúan.")
    print("="*78); print()

    static_meta: dict[str, dict[str, Any]] = {}
    host_path = worker_path.parent / "gideon_script_host.ps1"
    for source in [worker_path, starter_path, host_path, *script_paths]:
        key = str(source.resolve())
        if key not in static_meta:
            static_meta[key] = {"Sha256":sha256_file(source), "SizeBytes":source.stat().st_size}

    packages: dict[str, dict[str, Any]] = {}
    host_profiles = HostProfileStore(SCRIPT_DIR / "config" / "host_profiles.json")
    for site in inventory_sites:
        profile = host_profiles.resolve(site.code)
        agentless = profile.get("agentless", {}) if isinstance(profile.get("agentless"), dict) else {}
        if not bool(agentless.get("supported", False)):
            raise RuntimeError(
                f"HOST_PROFILE_AGENTLESS_UNSUPPORTED: {site.label} profile={profile.get('id')}"
            )
        site_remote_root = str(agentless.get("remote_job_root") or remote_root)
        package = build_site_package(
            site=site, job_id=str(manifest["JobId"]), script_paths=script_paths,
            worker_path=worker_path, starter_path=starter_path, packages_root=packages_root,
            remote_job_root=site_remote_root, task_prefix=task_prefix,
            continue_on_error=continue_on_error, static_meta=static_meta,
        )
        packages[site.code]=package
        entry=manifest["Sites"].get(site.code) or {}
        entry.update({
            "UploadFolderName":package["UploadFolderName"],
            "CollectionFolderName":package["CollectionFolderName"],
            "RemoteJobRoot":package["RemoteJobRoot"], "TaskName":package["TaskName"],
            "HostProfile": profile.get("id"),
            "TargetPlatform": profile.get("platform"),
            "AgentlessTemplate": True,
            "ScriptCount":len(package.get("Scripts",[])), "PackageBytes":package.get("PackageBytes",0),
        })
        manifest["Sites"][site.code]=entry
    store.write(manifest)

    if not await wait_for_controller_connectivity(
        gate=connectivity_gate, targets=connectivity_targets, manifest=manifest,
        store=store, phase="DISPATCH", restore_status="DISPATCHING"):
        return

    pending=deque((i+1,s,False) for i,s in enumerate(inventory_sites))
    active: dict[asyncio.Task, tuple[int,Site,bool]]={}
    attempted_codes:set[str]=set()
    vpn_failures=0; vpn_disabled=False
    vpn_failure_limit=max(1,int(adaptive_cfg.get("dispatch_failure_limit",2)))
    fallback_workers=max(1,min(int(adaptive_cfg.get("dispatch_fallback_workers",4)),max_workers))
    measure_every=max(10.0,float(adaptive_cfg.get("dispatch_measure_every_seconds",30)))
    last_measure=0.0; current_limit=fallback_workers if adaptive_enabled else max_workers
    current_reason="FALLBACK INICIAL" if adaptive_enabled else "CONCURRENCIA FIJA"
    recent_timeouts=0; measure_seq=0; offline_retry_codes:set[str]=set()

    async def select_concurrency(force: bool=False) -> int:
        nonlocal vpn_failures,vpn_disabled,last_measure,current_limit,current_reason,recent_timeouts,measure_seq
        mode=str(manifest.get("ControllerConnectionMode") or "UNKNOWN").upper()
        if mode=="DIRECT":
            current_limit=max(1,min(int(adaptive_cfg.get("normal_workers",4)),max_workers))
            current_reason="RED EMPRESARIAL DIRECTA"
        elif not adaptive_enabled:
            current_limit=max_workers; current_reason="CONCURRENCIA FIJA"
        elif vpn_disabled:
            current_limit=fallback_workers; current_reason="VPN TELEMETRÍA OMITIDA · FALLBACK"
        else:
            due=force or last_measure<=0 or (time.monotonic()-last_measure)>=measure_every or recent_timeouts>0
            if due:
                try:
                    health=await measure_vpn_health(adaptive_cfg,[x[1].ip for x in list(pending)[:12]] or connectivity_targets)
                    selected,reason=recommend_vpn_concurrency(health,adaptive_cfg,max_workers=max_workers,recent_timeouts=recent_timeouts)
                    current_limit=max(1,min(int(selected),max_workers)); current_reason=str(reason)
                    vpn_failures=0; last_measure=time.monotonic(); measure_seq+=1
                    manifest["VpnHealthHistory"].append({
                        "Cycle":measure_seq,"Phase":"SFTP_SSH_DISPATCH_CONTINUOUS",
                        "SelectedWorkers":current_limit,"Reason":current_reason,
                        "Timeouts":recent_timeouts,"Health":health})
                    print_vpn_health(health,current_limit,current_reason,phase=f"DISPATCH CONTINUO {measure_seq}")
                    recent_timeouts=0
                except Exception as exc:
                    vpn_failures+=1; last_measure=time.monotonic(); current_limit=fallback_workers
                    short=str(exc).replace("\r"," ").replace("\n"," ").strip()
                    if len(short)>170: short=short[:167]+"..."
                    if vpn_failures>=vpn_failure_limit:
                        vpn_disabled=True; current_reason="VPN TELEMETRÍA OMITIDA · FALLBACK"
                        warn(f"Telemetría VPN omitida tras {vpn_failures} fallos. Dispatch CONTINÚA con {current_limit} slots.")
                    else:
                        current_reason=f"VPN MÉTRICA NO DISPONIBLE {vpn_failures}/{vpn_failure_limit}"
                        warn(f"VPN/PATH metric no disponible; Dispatch continúa con {current_limit} slots. {short}")
        manifest["DispatchConcurrencyCurrent"]=current_limit
        manifest["DispatchConcurrencyReason"]=current_reason
        store.write(manifest)
        return current_limit

    async def run_one(ordinal:int,site:Site,retrying:bool):
        if stagger_ms>0: await asyncio.sleep(min(max(stagger_ms/1000.0,0.0),1.0))
        tag="RETRY" if retrying else "DISPATCH"
        log(
            f"[{tag} {ordinal}/{total}] {site.label} - "
            f"{transport.transport_spec.distribution} package -> SSH start."
        )
        try:
            result=await asyncio.wait_for(
                dispatch_site(transport=transport,site=site,package=packages[site.code]),
                timeout=max(10.0,float(site_deadline_seconds)),
            )
        except asyncio.TimeoutError:
            result=site_entry(site,str(packages[site.code]["RemoteJobRoot"]),str(packages[site.code]["TaskName"]),collection_folder=str(packages[site.code]["CollectionFolderName"]))
            result.update({
                "DispatchStatus":"DEFERRED","RemoteState":"PENDING_RETRY","RetryEligible":True,
                "DeferReason":f"SITE_DEADLINE_{float(site_deadline_seconds):.0f}s",
                "DispatchError":"La sede superó el tiempo máximo de Dispatch; se liberó el slot y continuará el resto."
            })
        except asyncio.CancelledError: raise
        except Exception as exc:
            result=site_entry(site,str(packages[site.code]["RemoteJobRoot"]),str(packages[site.code]["TaskName"]),collection_folder=str(packages[site.code]["CollectionFolderName"]))
            result.update({"TransferStatus":"FAILED","DispatchStatus":"FAILED","RemoteState":"DISPATCH_FAILED","DispatchError":f"{type(exc).__name__}: {exc}","RetryEligible":True})
        return ordinal,site,retrying,result

    await select_concurrency(True)

    while pending or active:
        latest,cancelled=_reload_external_cancel_state(manifest,store)
        if cancelled:
            for t in list(active): t.cancel()
            if active: await asyncio.gather(*active.keys(),return_exceptions=True)
            manifest.clear(); manifest.update(latest)
            if not manifest.get("CancelRequested"): mark_cancel_requested(manifest,source="dispatch cancel sidecar")
            store.write(manifest); warn("Dispatch continuo detenido por cancelación."); return

        await select_concurrency(False)
        while pending and len(active)<current_limit:
            ordinal,site,retrying=pending.popleft()
            if store.site_skip_requested(str(manifest["JobId"]),site.code):
                entry=manifest["Sites"].get(site.code) or site_entry(site,str(packages[site.code]["RemoteJobRoot"]),str(packages[site.code]["TaskName"]),collection_folder=str(packages[site.code]["CollectionFolderName"]))
                entry.update({"DispatchStatus":"DEFERRED","RemoteState":"PENDING_RETRY","RetryEligible":True,"DeferReason":"MANUAL_SKIP_BEFORE_START","DispatchError":"Sede pasada manualmente; reintentar al final."})
                manifest["Sites"][site.code]=entry; attempted_codes.add(site.code); manifest["DispatchAttempted"]=len(attempted_codes)
                store.clear_site_skip(str(manifest["JobId"]),site.code); recalc_manifest(manifest); store.write(manifest)
                warn(f"[PASAR {ordinal}/{total}] {site.label} - diferida; el slot continúa.")
                continue
            t=asyncio.create_task(run_one(ordinal,site,retrying)); active[t]=(ordinal,site,retrying)
            manifest["DispatchInFlight"]=len(active); manifest["DispatchPending"]=len(pending)

        if not active:
            if pending: await asyncio.sleep(0.25); continue
            break

        for running_task,meta in list(active.items()):
            _,active_site,_=meta
            if store.site_skip_requested(str(manifest["JobId"]),active_site.code) and transport.process_registry is not None:
                transport.process_registry.terminate_site_transports(active_site.code)
        done,_=await asyncio.wait(list(active.keys()),timeout=1.0,return_when=asyncio.FIRST_COMPLETED)
        if not done: continue
        timeout_failures=[]
        for task in done:
            ordinal,site,retrying=active.pop(task)
            try: ordinal,site,retrying,result=task.result()
            except asyncio.CancelledError:
                pending.appendleft((ordinal,site,True)); continue
            skip_requested=store.site_skip_requested(str(manifest["JobId"]),site.code)
            if skip_requested and result.get("DispatchStatus")!="DISPATCHED":
                result.update({"DispatchStatus":"DEFERRED","RemoteState":"PENDING_RETRY","RetryEligible":True,"DeferReason":result.get("DeferReason") or "MANUAL_SKIP"})
                store.clear_site_skip(str(manifest["JobId"]),site.code)
            elif result.get("DispatchStatus")=="DISPATCHED":
                result["RetryEligible"]=False; store.clear_site_skip(str(manifest["JobId"]),site.code)
            elif result.get("DispatchStatus")=="FAILED":
                result["RetryEligible"]=True
            manifest["Sites"][site.code]=result
            if site.code not in attempted_codes:
                attempted_codes.add(site.code); manifest["DispatchAttempted"]=len(attempted_codes)
            err=str(result.get("DispatchError") or result.get("Error") or "").lower()
            is_timeout=any(x in err for x in ("timeout","timed out","banner exchange","network is unreachable","connection reset","connection refused"))
            if is_timeout:
                recent_timeouts+=1; timeout_failures.append((ordinal,site))
            recalc_manifest(manifest)
            manifest["WaitingRemoteCount"]=sum(1 for x in manifest["Sites"].values() if x.get("DispatchStatus")=="DISPATCHED" and not terminal_site(x))
            manifest["DispatchInFlight"]=len(active); manifest["DispatchPending"]=len(pending); manifest["DispatchLastProgressAt"]=now_iso()
            store.write(manifest)
            if result.get("DispatchStatus")=="DISPATCHED":
                ok(
                    f"[DISPATCH {ordinal}/{total}] {site.label} - "
                    f"{result.get('TransferStatus')} + SSH_STARTED; slot liberado."
                )
                offline_retry_codes.discard(site.code)
            else:
                warn(f"[DISPATCH {ordinal}/{total}] {site.label} - DISPATCH_FAILED - {result.get('DispatchError')}")

        if timeout_failures and connectivity_gate is not None:
            snap=await connectivity_gate.probe(connectivity_targets)
            _update_connectivity_manifest(manifest,snap,phase="DISPATCH_CONTINUOUS_CHECK"); store.write(manifest)
            if not snap.Reachable:
                # reencolar active sin contarlos como fallo definitivo
                metas=list(active.values())
                for t in list(active): t.cancel()
                if active: await asyncio.gather(*active.keys(),return_exceptions=True)
                active.clear()
                for ordinal,site,_ in reversed(metas): pending.appendleft((ordinal,site,True))
                for ordinal,site in timeout_failures:
                    if site.code not in offline_retry_codes:
                        offline_retry_codes.add(site.code)
                        entry=manifest["Sites"].get(site.code) or {}
                        entry.update({"DispatchStatus":"WAITING_CONNECTION","RemoteState":"WAITING_CONNECTION","DispatchError":"Controller connectivity lost; automatic retry pending."})
                        manifest["Sites"][site.code]=entry; pending.appendleft((ordinal,site,True))
                manifest["DispatchInFlight"]=0; manifest["DispatchPending"]=len(pending); store.write(manifest)
                recovered=await wait_for_controller_connectivity(gate=connectivity_gate,targets=connectivity_targets,manifest=manifest,store=store,phase="DISPATCH",restore_status="DISPATCHING")
                if not recovered: return
                ok("Conectividad restablecida; scheduler continuo retoma pendientes.")

    recalc_manifest(manifest)
    attempted=len(attempted_codes); manifest["DispatchAttempted"]=attempted
    if attempted!=total: raise RuntimeError(f"Dispatch incompleto: se intentaron {attempted}/{total} sedes.")
    manifest.update({"DispatchCompletedAt":now_iso(),"DispatchInFlight":0,"DispatchPending":0})
    manifest["WaitingRemoteCount"]=sum(1 for x in manifest["Sites"].values() if x.get("DispatchStatus")=="DISPATCHED" and not terminal_site(x))
    manifest["Status"]="WAITING_REMOTE_REPORTS"; store.write(manifest)
    print(); print("="*78); print("DISTRIBUCION GENERAL FINALIZADA"); print("="*78)
    print(f"Sedes objetivo          : {total}")
    print(f"Dispatch intentados     : {attempted}/{total}")
    print(f"Dispatch correctos      : {manifest['DispatchOk']}/{total}")
    print(f"Dispatch fallidos       : {manifest['DispatchFailed']}")
    print(f"Dispatch diferidos      : {manifest.get('DispatchDeferred',0)}")
    print(f"Reintentables al final  : {manifest.get('RetryEligibleCount',0)}")
    print(f"Jobs remotos en espera  : {manifest['WaitingRemoteCount']}")
    print("Scheduler continuo: una sede lenta no bloquea las demás.")
    print("="*78); print(); print_status_table(manifest)


def make_fast_status_query(job_root: str) -> str:
    """Consulta ligera de estado.

    Deliberadamente NO carga ScheduledTasks ni ejecuta diagnósticos profundos.
    Su objetivo es leer únicamente archivos de telemetría para que el monitor
    normal sea barato y predecible.
    """
    q_root = ps_single_quote(job_root)
    return rf"""
$ErrorActionPreference = 'Stop'
$jobRoot = '{q_root}'
$statusPath = Join-Path $jobRoot 'status.json'
$progressPath = Join-Path $jobRoot 'progress.json'
$jobPath = Join-Path $jobRoot 'job.json'

$status = $null
$progress = $null
$collectionRoot = $null

if (Test-Path -LiteralPath $statusPath -PathType Leaf) {{
    try {{ $status = Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json }} catch {{}}
}}
if (Test-Path -LiteralPath $progressPath -PathType Leaf) {{
    try {{ $progress = Get-Content -LiteralPath $progressPath -Raw | ConvertFrom-Json }} catch {{}}
}}

if ($null -ne $status) {{
    try {{
        if ($status.PSObject.Properties.Name -contains 'CollectionRoot') {{
            $collectionRoot = [string]$status.CollectionRoot
        }}
    }} catch {{}}
}}

if ([string]::IsNullOrWhiteSpace($collectionRoot) -and (Test-Path -LiteralPath $jobPath -PathType Leaf)) {{
    try {{
        $job = Get-Content -LiteralPath $jobPath -Raw | ConvertFrom-Json
        if ($job.PSObject.Properties.Name -contains 'CollectionRoot') {{
            $collectionRoot = [string]$job.CollectionRoot
        }}
    }} catch {{}}
}}

$jobResultExists = $false
$finalStatusExists = $false
if (-not [string]::IsNullOrWhiteSpace($collectionRoot)) {{
    $jobResultExists = Test-Path -LiteralPath (Join-Path $collectionRoot 'job_result.json') -PathType Leaf
    $finalStatusExists = Test-Path -LiteralPath (Join-Path $collectionRoot 'status.final.json') -PathType Leaf
}}

[pscustomobject]@{{
    Exists=(Test-Path -LiteralPath $jobRoot -PathType Container)
    Status=$status
    Progress=$progress
    CollectionRoot=$collectionRoot
    JobResultExists=[bool]$jobResultExists
    FinalStatusExists=[bool]$finalStatusExists
    CollectionReady=[bool]($jobResultExists -and $finalStatusExists)
    Diagnostics=[ordered]@{{
        Source='SSH_FAST'
        DeepDiagnosticExecuted=$false
    }}
}} | ConvertTo-Json -Depth 14 -Compress
"""


def _read_json_optional(path: Path) -> dict[str, Any] | None:
    try:
        if not path.exists() or not path.is_file():
            return None
        value = json.loads(path.read_text(encoding="utf-8-sig"))
        return value if isinstance(value, dict) else None
    except Exception:
        return None


def _tail_text_file(path: Path, max_lines: int) -> list[str]:
    try:
        if not path.exists() or not path.is_file():
            return []
        lines = path.read_text(
            encoding="utf-8-sig",
            errors="replace",
        ).splitlines()
        return lines[-max(1, int(max_lines)) :]
    except Exception:
        return []


def make_sftp_telemetry_batch(
    *,
    collection_folder: str,
    local_dir: Path,
) -> str:
    """Descarga telemetría pequeña sin exigir que cada archivo exista."""
    ensure_dir(local_dir)

    files = (
        "status.live.json",
        "progress.live.json",
        "status.final.json",
        "progress.final.json",
        "job_result.json",
        "worker.log",
        "starter.log",
    )

    lines: list[str] = []
    for name in files:
        remote_path = f"{collection_folder}/{name}"
        local_path = local_dir / name
        lines.append(
            f"-get {sftp_quote(remote_path)} "
            f"{sftp_quote(local_sftp_path(local_path))}"
        )

    lines.append("quit")
    return "\n".join(lines) + "\n"


def infer_status_from_worker_log(
    *,
    entry: dict[str, Any],
    worker_lines: list[str],
    starter_lines: list[str],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Compatibilidad con Jobs ya distribuidos antes de status.live.json."""
    if not worker_lines and not starter_lines:
        return None, None

    script_count = int(entry.get("ScriptCount", 0) or 0)
    state = "DISPATCHED"
    phase = "SSH_START_CONFIRMED"
    current_index = int(entry.get("CurrentScriptIndex", 0) or 0)
    current_name = entry.get("CurrentScriptName")
    error: str | None = None

    worker_text = "\n".join(worker_lines)

    if "REMOTE WORKER STARTED" in worker_text:
        state = "RUNNING"
        phase = "WORKER_START"

    matches = list(
        re.finditer(
            r"SCRIPT START\s+(\d+)/(\d+):\s*([^;]+)",
            worker_text,
            flags=re.IGNORECASE,
        )
    )
    if matches:
        last = matches[-1]
        current_index = int(last.group(1))
        script_count = max(script_count, int(last.group(2)))
        current_name = last.group(3).strip()
        state = "RUNNING"
        phase = "SCRIPT_RUNNING"

    if "JOB RESULT READY" in worker_text:
        state = "RESULT_READY"
        phase = "JOB_RESULT_READY"

    failed_matches = list(
        re.finditer(
            r"WORKER FAILED:\s*(.+)$",
            worker_text,
            flags=re.IGNORECASE | re.MULTILINE,
        )
    )
    if failed_matches:
        state = "RESULT_READY_WITH_ERRORS"
        phase = "WORKER_FAILED"
        error = failed_matches[-1].group(1).strip()

    status: dict[str, Any] = {
        "State": state,
        "Phase": phase,
        "CurrentScriptIndex": current_index,
        "CurrentScriptName": current_name,
        "ScriptCount": script_count,
        "Error": error,
    }
    progress: dict[str, Any] = {
        "Type": phase,
        "CurrentScriptIndex": current_index,
        "CurrentScriptName": current_name,
        "ScriptCount": script_count,
    }
    return status, progress


async def pull_sftp_telemetry(
    *,
    transport: RemoteTransport,
    site: Site,
    entry: dict[str, Any],
    telemetry_root: Path,
) -> tuple[dict[str, Any] | None, str | None]:
    """Canal de telemetría primario para SFTP_SSH_SFTP.

    No ejecuta PowerShell remoto. Solo descarga archivos pequeños publicados
    por Starter/Worker. También entiende Jobs v5.0.1 mediante worker.log.
    """
    collection_folder = str(entry.get("CollectionFolderName") or "").strip()
    if not collection_folder:
        return None, "CollectionFolderName missing."

    local_dir = ensure_dir(
        telemetry_root
        / f"{site.code}_{safe_component(site.name)}"
    )

    for name in (
        "status.live.json",
        "progress.live.json",
        "status.final.json",
        "progress.final.json",
        "job_result.json",
        "worker.log",
        "starter.log",
    ):
        try:
            (local_dir / name).unlink(missing_ok=True)
        except Exception as exc:
            warn(f"TELEMETRY_CLEANUP_WARNING: no se pudo limpiar {name}: {exc}")

    batch = make_sftp_telemetry_batch(
        collection_folder=collection_folder,
        local_dir=local_dir,
    )

    # Telemetría no reintenta dentro de la misma ronda. El scheduler volverá a
    # consultar en la ronda siguiente; así una sede no monopoliza un slot.
    rc, stdout, stderr = await transport.sftp_batch_once(
        site,
        batch,
        operation="TELEMETRY",
    )

    if rc != 0:
        return None, (
            stderr.strip()
            or stdout.strip()
            or f"SFTP telemetry ExitCode={rc}"
        )

    final_status = _read_json_optional(local_dir / "status.final.json")
    live_status = _read_json_optional(local_dir / "status.live.json")
    final_progress = _read_json_optional(local_dir / "progress.final.json")
    live_progress = _read_json_optional(local_dir / "progress.live.json")
    job_result = _read_json_optional(local_dir / "job_result.json")
    worker_lines = _tail_text_file(local_dir / "worker.log", 20)
    starter_lines = _tail_text_file(local_dir / "starter.log", 14)

    status = final_status or live_status
    progress = final_progress or live_progress

    if status is None:
        inferred_status, inferred_progress = infer_status_from_worker_log(
            entry=entry,
            worker_lines=worker_lines,
            starter_lines=starter_lines,
        )
        status = inferred_status
        progress = progress or inferred_progress

    if (
        status is None
        and progress is None
        and not worker_lines
        and not starter_lines
    ):
        return None, "TELEMETRY_EMPTY: no existen artefactos todavía."

    collection_ready = bool(final_status and job_result)

    return {
        "Exists": True,
        "TaskState": None,
        "LastTaskResult": None,
        "Status": status,
        "Progress": progress,
        "CollectionReady": collection_ready,
        "JobResultExists": bool(job_result),
        "FinalStatusExists": bool(final_status),
        "Diagnostics": {
            "Source": "SFTP_MIRROR",
            "DeepDiagnosticExecuted": False,
            "WorkerLogTail": worker_lines,
            "StarterLogTail": starter_lines,
            "WorkerLogExists": bool(worker_lines),
            "StarterLogExists": bool(starter_lines),
        },
    }, None


def apply_remote_snapshot(
    *,
    update: dict[str, Any],
    remote: dict[str, Any],
) -> dict[str, Any]:
    """Aplica un snapshot normalizado, venga de SFTP mirror o SSH fast."""
    if remote.get("TaskState") is not None:
        update["TaskState"] = remote.get("TaskState")
        update["TaskStateSource"] = (
            (remote.get("Diagnostics") or {}).get("Source")
            if isinstance(remote.get("Diagnostics"), dict)
            else "SSH"
        )

    if remote.get("LastTaskResult") is not None:
        update["LastTaskResult"] = remote.get("LastTaskResult")

    diagnostics = remote.get("Diagnostics")
    if not isinstance(diagnostics, dict):
        diagnostics = {}

    previous_diag = update.get("RemoteDiagnostics")
    if isinstance(previous_diag, dict):
        merged_diag = dict(previous_diag)
        merged_diag.update(diagnostics)
        diagnostics = merged_diag

    update["RemoteDiagnostics"] = diagnostics or None
    update["TaskResultMeaning"] = diagnostics.get("TaskResultMeaning")
    update["TaskResultHex"] = diagnostics.get("LastTaskResultHex")

    progress = remote.get("Progress")
    status = remote.get("Status")

    if not isinstance(progress, dict):
        progress = {}

    if isinstance(status, dict):
        state = str(status.get("State") or "UNKNOWN").upper()
        update["RemoteState"] = state
        update["Error"] = status.get("Error")
        update["CurrentScriptIndex"] = int(
            status.get("CurrentScriptIndex") or 0
        )
        update["CurrentScriptName"] = status.get("CurrentScriptName")
        update["ScriptCount"] = int(
            status.get("ScriptCount")
            or update.get("ScriptCount")
            or 0
        )

        # Process lifecycle telemetry published by Worker v3.9+.
        update["CleanupState"] = status.get(
            "CleanupState",
            update.get("CleanupState"),
        )
        update["JobObjectAssignments"] = int(
            status.get("JobObjectAssignments")
            or update.get("JobObjectAssignments")
            or 0
        )
        update["JobObjectFallbacks"] = int(
            status.get("JobObjectFallbacks")
            or update.get("JobObjectFallbacks")
            or 0
        )
        update["ResidualProcessesKilled"] = int(
            status.get("ResidualProcessesKilled")
            or update.get("ResidualProcessesKilled")
            or 0
        )
        update["ProcessObjectsDisposed"] = int(
            status.get("ProcessObjectsDisposed")
            or update.get("ProcessObjectsDisposed")
            or 0
        )

        progress.setdefault(
            "CurrentScriptIndex",
            update.get("CurrentScriptIndex", 0),
        )
        progress.setdefault(
            "CurrentScriptName",
            update.get("CurrentScriptName"),
        )
        progress.setdefault(
            "ScriptCount",
            update.get("ScriptCount", 0),
        )
        progress.setdefault("Phase", status.get("Phase"))
    elif not remote.get("Exists"):
        update["RemoteState"] = "NOT_FOUND"
        update["Error"] = "Remote job directory not found."

    update["Progress"] = progress or None

    if bool(remote.get("CollectionReady")) and update.get("RemoteState") not in {
        "RESULT_READY",
        "RESULT_READY_WITH_ERRORS",
        "COLLECTED",
        "COLLECTED_WITH_ERRORS",
    }:
        update["RemoteState"] = "RESULT_READY"
        update["TelemetryFallback"] = "COLLECTION_FILES_READY"
        update["Error"] = None

    worker_tail = diagnostics.get("WorkerLogTail")
    if not isinstance(worker_tail, list):
        worker_tail = []
    worker_tail_text = "\n".join(str(x) for x in worker_tail[-14:])

    execution_layer = "REMOTE_OK"
    execution_code: str | None = None
    execution_detail: str | None = None

    if "WORKER FAILED:" in worker_tail_text:
        execution_layer = "POWERSHELL_WORKER"
        execution_code = "WORKER_FATAL"
        execution_detail = worker_tail_text.split(
            "WORKER FAILED:", 1
        )[-1].strip()

        # worker.log is newer evidence than a stale status.live.json left by
        # Starter. Do not keep the UI misleadingly in DISPATCHED.
        update["RemoteState"] = "RESULT_READY_WITH_ERRORS"
        update["Error"] = execution_detail
        update["TelemetryState"] = "ONLINE"
        update["WorkerTerminalEvidence"] = True

    elif "SCRIPT FAILED" in worker_tail_text:
        execution_layer = "POWERSHELL_PAYLOAD"
        execution_code = "SCRIPT_FAILED"
        execution_detail = worker_tail_text.split(
            "SCRIPT FAILED", 1
        )[-1].strip()

    # Si la telemetría por archivos funciona pero únicamente vemos que Starter
    # pidió arrancar la tarea y Worker aún no publicó ni una línea, ya sabemos
    # que el problema está DESPUÉS del SSH START y ANTES del payload.
    starter_tail = diagnostics.get("StarterLogTail")
    if not isinstance(starter_tail, list):
        starter_tail = []
    starter_text = "\n".join(str(x) for x in starter_tail[-10:])

    if (
        str(update.get("RemoteState") or "").upper() == "DISPATCHED"
        and starter_tail
        and not worker_tail
        and not bool(update.get("WorkerTerminalEvidence"))
    ):
        startup_observations = int(
            update.get("WorkerStartupObservationCount", 0) or 0
        ) + 1
        update["WorkerStartupObservationCount"] = startup_observations

        if "TASK START REQUESTED" in starter_text:
            execution_layer = "POWERSHELL_WORKER_STARTUP"
            execution_code = (
                "WORKER_STARTUP_STALLED"
                if startup_observations >= 2
                else "WORKER_STARTUP_PENDING"
            )
            execution_detail = (
                "Starter confirmó Start-ScheduledTask pero worker.log/status "
                "todavía no muestran inicio del remote_job_worker.ps1."
            )
    else:
        update["WorkerStartupObservationCount"] = 0

    update["ExecutionLayer"] = execution_layer
    update["ExecutionErrorCode"] = execution_code
    update["ExecutionErrorDetail"] = execution_detail

    return update


async def poll_site(
    *,
    transport: RemoteTransport,
    site: Site,
    entry: dict[str, Any],
    telemetry_root: Path | None = None,
    failure_waiting_threshold: int = 2,
) -> dict[str, Any]:
    update = dict(entry)
    update["LastCheckedAt"] = now_iso()

    # -----------------------------------------------------------------
    # 1) Canal primario: archivos de telemetría por el mismo transporte
    #    de recolección. Para SFTP evita ejecutar PowerShell remoto.
    # -----------------------------------------------------------------
    telemetry_error: str | None = None

    if (
        getattr(
            transport,
            "transport_profile",
            DEFAULT_TRANSPORT_PROFILE,
        ) == SFTP_SSH_SFTP
        and telemetry_root is not None
    ):
        try:
            remote, telemetry_error = await pull_sftp_telemetry(
                transport=transport,
                site=site,
                entry=entry,
                telemetry_root=telemetry_root,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            remote = None
            telemetry_error = (
                f"{type(exc).__name__}: {exc}"
            )

        if isinstance(remote, dict):
            update["PollFailureCount"] = 0
            update["LastPollError"] = None
            update["LastPollSuccessAt"] = now_iso()
            update["TelemetryState"] = "ONLINE"
            update["TelemetrySource"] = "SFTP_MIRROR"
            update["TelemetryTransport"] = "SFTP"
            update = apply_remote_snapshot(
                update=update,
                remote=remote,
            )
            return update

    # -----------------------------------------------------------------
    # 2) Fallback: consulta SSH mínima. No ScheduledTasks, no logs, no
    #    cmdlets pesados. Una sola tentativa por ronda.
    # -----------------------------------------------------------------
    query = make_fast_status_query(
        str(entry["RemoteJobRoot"])
    )

    if hasattr(transport, "run_ps_once"):
        rc, stdout, stderr = await transport.run_ps_once(
            site,
            query,
            operation="FAST_STATUS",
        )
    else:
        rc, stdout, stderr, _attempts = await transport.run_ps(
            site,
            query,
            operation="FAST_STATUS",
        )

    if rc != 0:
        update["PollFailureCount"] = int(
            update.get("PollFailureCount", 0) or 0
        ) + 1

        detail_parts = [
            value
            for value in (
                telemetry_error,
                stderr.strip(),
                stdout.strip(),
            )
            if value
        ]
        update["LastPollError"] = (
            " | ".join(detail_parts)
            or f"ExitCode={rc}"
        )
        update["LastPollErrorAt"] = now_iso()
        update["Error"] = update["LastPollError"]
        update["ExecutionLayer"] = "TELEMETRY_TRANSPORT"
        update["ExecutionErrorCode"] = (
            "TELEMETRY_IO_DEADLINE"
            if rc == 124
            else "TELEMETRY_UNAVAILABLE"
        )
        update["ExecutionErrorDetail"] = update["LastPollError"]
        update["TelemetryState"] = (
            "WAITING_CONNECTION"
            if int(update["PollFailureCount"])
            >= max(1, int(failure_waiting_threshold))
            else "DEGRADED"
        )
        update["TelemetrySource"] = "SFTP_MIRROR+SSH_FAST"
        update["TaskStateSource"] = (
            update.get("TaskStateSource")
            or "DISPATCH_SNAPSHOT"
        )
        return update

    try:
        remote = json.loads(
            stdout.strip().splitlines()[-1]
        )
    except Exception as exc:
        update["PollFailureCount"] = int(
            update.get("PollFailureCount", 0) or 0
        ) + 1
        update["LastPollError"] = (
            f"FAST_STATUS_JSON_ERROR: {exc}"
        )
        update["LastPollErrorAt"] = now_iso()
        update["TelemetryState"] = "DEGRADED"
        update["TelemetrySource"] = "SSH_FAST"
        update["ExecutionLayer"] = "TELEMETRY_PARSER"
        update["ExecutionErrorCode"] = "FAST_STATUS_JSON_ERROR"
        update["ExecutionErrorDetail"] = update["LastPollError"]
        return update

    if not isinstance(remote, dict):
        update["LastPollError"] = "FAST_STATUS_INVALID_PAYLOAD"
        update["TelemetryState"] = "DEGRADED"
        return update

    update["PollFailureCount"] = 0
    update["LastPollError"] = None
    update["LastPollSuccessAt"] = now_iso()
    update["TelemetryState"] = "ONLINE"
    update["TelemetrySource"] = "SSH_FAST"
    update["TelemetryTransport"] = "SSH"

    return apply_remote_snapshot(
        update=update,
        remote=remote,
    )

def make_sftp_collect_batch(
    *,
    collection_folder: str,
    local_dir: Path,
    scripts: list[dict[str, Any]],
) -> tuple[str, list[Path], list[Path]]:
    """Construye una recolección robusta.

    Archivos de control imprescindibles usan `get` normal. Los artefactos
    auxiliares y resultados por script usan `-get`, por lo que un archivo
    opcional ausente no aborta la descarga de los demás.
    """
    ensure_dir(local_dir)
    local_scripts = ensure_dir(local_dir / "scripts")

    required: list[tuple[str, Path]] = [
        (
            f"{collection_folder}/job.definition.json",
            local_dir / "job.definition.json",
        ),
        (
            f"{collection_folder}/job_result.json",
            local_dir / "job_result.json",
        ),
        (
            f"{collection_folder}/status.final.json",
            local_dir / "status.final.json",
        ),
    ]

    optional: list[tuple[str, Path]] = [
        (
            f"{collection_folder}/progress.final.json",
            local_dir / "progress.final.json",
        ),
        (
            f"{collection_folder}/worker.log",
            local_dir / "worker.log",
        ),
        (
            f"{collection_folder}/starter.log",
            local_dir / "starter.log",
        ),
    ]

    for script in scripts:
        result_name = str(script.get("ResultName") or "")
        if result_name:
            optional.append(
                (
                    f"{collection_folder}/scripts/{result_name}",
                    local_scripts / result_name,
                )
            )

    lines: list[str] = []
    required_local: list[Path] = []
    optional_local: list[Path] = []

    for remote_path, local_path in required:
        lines.append(
            f"get {sftp_quote(remote_path)} "
            f"{sftp_quote(local_sftp_path(local_path))}"
        )
        required_local.append(local_path)

    # '-' delante del comando indica a OpenSSH sftp batch que continúe aunque
    # ese archivo concreto no exista. Después Python valida qué debía existir.
    for remote_path, local_path in optional:
        lines.append(
            f"-get {sftp_quote(remote_path)} "
            f"{sftp_quote(local_sftp_path(local_path))}"
        )
        optional_local.append(local_path)

    lines.append("quit")
    return (
        "\n".join(lines) + "\n",
        required_local,
        optional_local,
    )


def safe_extract_transport_zip(archive: Path, destination: Path) -> None:
    """Extrae ZIP rechazando rutas que salgan del destino."""
    destination = Path(destination).resolve()
    ensure_dir(destination)
    with zipfile.ZipFile(archive, "r") as zf:
        for info in zf.infolist():
            candidate = (destination / info.filename).resolve()
            try:
                candidate.relative_to(destination)
            except ValueError as exc:
                raise RuntimeError(
                    f"ZIP_UNSAFE_PATH: {info.filename}"
                ) from exc
        zf.extractall(destination)


def make_remote_collection_zip_code(
    collection_folder: str,
    remote_archive_name: str,
) -> str:
    q_collection = ps_single_quote(collection_folder)
    q_archive = ps_single_quote(remote_archive_name)
    return rf"""
$ErrorActionPreference = 'Stop'
$src = Join-Path $HOME '{q_collection}'
$zip = Join-Path $HOME '{q_archive}'
if (-not (Test-Path -LiteralPath $src -PathType Container)) {{
    throw "Collection folder not found: $src"
}}
if (Test-Path -LiteralPath $zip) {{
    Remove-Item -LiteralPath $zip -Force
}}
Compress-Archive -Path (Join-Path $src '*') -DestinationPath $zip -CompressionLevel Optimal -Force
[pscustomobject]@{{Success=$true;Archive='{q_archive}'}} | ConvertTo-Json -Compress
"""


def make_remote_archive_cleanup_code(remote_archive_name: str) -> str:
    q_archive = ps_single_quote(remote_archive_name)
    return rf"""
$zip = Join-Path $HOME '{q_archive}'
Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
"""


async def collect_site(
    *,
    transport: RemoteTransport,
    site: Site,
    entry: dict[str, Any],
    local_raw_dir: Path,
    script_defs: list[dict[str, Any]],
) -> dict[str, Any]:
    result = dict(entry)
    collection_folder = str(
        entry.get("CollectionFolderName") or ""
    )

    if not collection_folder:
        result["Error"] = (
            "COLLECT_ERROR: CollectionFolderName missing."
        )
        result["CollectionStatus"] = "FAILED"
        return result

    local_site_dir = ensure_dir(
        local_raw_dir
        / f"{site.code}_{safe_component(site.name)}"
    )

    # Evitar que archivos de una recolección previa del mismo JobId oculten
    # faltantes del intento actual.
    local_scripts_dir = ensure_dir(local_site_dir / "scripts")
    for stale in [
        local_site_dir / "job.definition.json",
        local_site_dir / "job_result.json",
        local_site_dir / "status.final.json",
        local_site_dir / "progress.final.json",
        local_site_dir / "worker.log",
        local_site_dir / "starter.log",
        local_site_dir / "collection.transport.zip",
    ]:
        try:
            if stale.exists():
                stale.unlink()
        except Exception as exc:
            warn(f"COLLECT_CLEANUP_WARNING: no se pudo limpiar {stale}: {exc}")

    for stale in local_scripts_dir.glob("*.json"):
        try:
            stale.unlink()
        except Exception as exc:
            warn(f"COLLECT_CLEANUP_WARNING: no se pudo limpiar {stale}: {exc}")

    batch, required_files, optional_files = make_sftp_collect_batch(
        collection_folder=collection_folder,
        local_dir=local_site_dir,
        scripts=script_defs,
    )

    if transport.transport_profile == SFTP_SSH_SFTP:
        rc, stdout, stderr, attempts = await transport.sftp_batch(
            site,
            batch,
            operation="SFTP_COLLECT",
        )
        result["CollectionAttempts"] = attempts
        result["CollectionTransport"] = "SFTP"

        if rc != 0:
            result["CollectionStatus"] = "FAILED"
            result["CollectionVerified"] = False
            result["Error"] = "COLLECT_ERROR: " + (
                stderr.strip()
                or stdout.strip()
                or f"SFTP ExitCode={rc}"
            )
            return result

    else:
        # SCP y STDIN comparten recolección SCP. Se comprime una sola vez
        # en el servidor para evitar abrir una sesión SCP por cada artefacto.
        remote_archive = (
            f"{safe_component(collection_folder)}_"
            f"{safe_component(site.code)}.collect.zip"
        )
        local_archive = local_site_dir / "collection.transport.zip"

        zip_code = make_remote_collection_zip_code(
            collection_folder,
            remote_archive,
        )
        rc, stdout, stderr, zip_attempts = await transport.run_ps(
            site,
            zip_code,
            operation="SSH_PREPARE_SCP_COLLECT",
        )
        if rc != 0:
            result["CollectionStatus"] = "FAILED"
            result["CollectionVerified"] = False
            result["Error"] = "COLLECT_PREPARE_ERROR: " + (
                stderr.strip()
                or stdout.strip()
                or f"SSH ExitCode={rc}"
            )
            return result

        rc, stdout, stderr, attempts = await transport.scp_file(
            site,
            local_path=local_archive,
            remote_path=remote_archive,
            upload=False,
            operation="SCP_COLLECT",
        )
        result["CollectionAttempts"] = attempts
        result["CollectionTransport"] = "SCP"
        result["CollectionPrepareAttempts"] = zip_attempts

        # Best effort: no bloquear por cleanup del ZIP temporal.
        try:
            await transport.run_ps(
                site,
                make_remote_archive_cleanup_code(remote_archive),
                operation="SSH_CLEANUP_SCP_ARCHIVE",
            )
        except Exception as exc:
            warn(f"REMOTE_ARCHIVE_CLEANUP_WARNING {site.label}: {exc}")

        if rc != 0:
            result["CollectionStatus"] = "FAILED"
            result["CollectionVerified"] = False
            result["Error"] = "COLLECT_ERROR: " + (
                stderr.strip()
                or stdout.strip()
                or f"SCP ExitCode={rc}"
            )
            return result

        try:
            safe_extract_transport_zip(local_archive, local_site_dir)
        except Exception as exc:
            result["CollectionStatus"] = "FAILED"
            result["CollectionVerified"] = False
            result["Error"] = f"COLLECT_ZIP_ERROR: {exc}"
            return result
        finally:
            try:
                local_archive.unlink(missing_ok=True)
            except Exception as exc:
                warn(f"LOCAL_ARCHIVE_CLEANUP_WARNING {local_archive}: {exc}")

    missing_required = [
        str(path)
        for path in required_files
        if not path.exists()
    ]

    if missing_required:
        result["CollectionStatus"] = "FAILED"
        result["CollectionVerified"] = False
        result["Error"] = (
            "COLLECT_ERROR: faltan archivos de control: "
            + "; ".join(missing_required)
        )
        return result

    job_result_path = local_site_dir / "job_result.json"

    try:
        job_result = json.loads(
            job_result_path.read_text(
                encoding="utf-8-sig"
            )
        )
    except Exception as exc:
        result["CollectionStatus"] = "FAILED"
        result["CollectionVerified"] = False
        result["Error"] = (
            f"COLLECT_PARSE_ERROR: {exc}"
        )
        return result

    warnings: list[str] = []

    # Validar todos los resultados que el worker declara haber publicado.
    expected_by_worker: dict[str, str] = {}

    raw_summaries = job_result.get("Scripts") or []
    if isinstance(raw_summaries, dict):
        raw_summaries = [raw_summaries]

    for summary in raw_summaries:
        if not isinstance(summary, dict):
            continue

        result_name = str(
            summary.get("ResultName") or ""
        ).strip()

        expected_hash = str(
            summary.get("ResultSha256") or ""
        ).strip().lower()

        if result_name:
            expected_by_worker[result_name] = expected_hash

    verified_results = True

    for result_name, expected_hash in expected_by_worker.items():
        path = local_scripts_dir / result_name

        if not path.exists():
            verified_results = False
            warnings.append(
                f"RESULT_MISSING: {result_name}"
            )
            continue

        if expected_hash:
            actual_hash = sha256_file(path)
            if actual_hash != expected_hash:
                verified_results = False
                warnings.append(
                    "RESULT_SHA256_MISMATCH: "
                    f"{result_name}"
                )

    # Si el worker terminó normalmente, deben existir resultados explícitos
    # para todos los scripts (incluidos SKIPPED cuando StopOnError está activo).
    declared_script_count = int(
        job_result.get("ScriptCount", 0) or 0
    )

    if (
        declared_script_count > 0
        and len(expected_by_worker) < declared_script_count
    ):
        verified_results = False
        warnings.append(
            "RESULT_INDEX_INCOMPLETE: "
            f"declarados={declared_script_count}; "
            f"indexados={len(expected_by_worker)}"
        )

    missing_optional = [
        str(path)
        for path in optional_files
        if not path.exists()
    ]

    # progress/log son diagnóstico. Su ausencia se informa pero no invalida un
    # job cuyo resultado e índices sí están íntegros.
    for path_text in missing_optional:
        name = Path(path_text).name
        if name in {"progress.final.json", "worker.log"}:
            warnings.append(
                f"OPTIONAL_FILE_MISSING: {name}"
            )

    script_result_files = [
        str(local_scripts_dir / result_name)
        for result_name in expected_by_worker
        if (local_scripts_dir / result_name).exists()
    ]

    existing_files = [
        path
        for path in (
            required_files + optional_files
        )
        if path.exists()
    ]

    result["RawDir"] = str(local_site_dir)
    result["RawFile"] = str(job_result_path)
    result["ScriptResultFiles"] = script_result_files
    result["CollectedFiles"] = [
        str(path)
        for path in existing_files
    ]
    result["CollectedAt"] = now_iso()
    result["ScriptFailures"] = int(
        job_result.get("ScriptsFailed", 0) or 0
    )
    result["ScriptSkipped"] = int(
        job_result.get("ScriptsSkipped", 0) or 0
    )

    metrics = job_result.get("Metrics")
    if isinstance(metrics, dict):
        final_progress = result.get("Progress")
        if not isinstance(final_progress, dict):
            final_progress = {}
        final_progress = dict(final_progress)
        final_progress.update({
            "Type": "JOB_COMPLETE",
            "Directories": metrics.get("Directories", final_progress.get("Directories", 0)),
            "BackupFolders": metrics.get("BackupFolders", final_progress.get("BackupFolders", 0)),
            "AccessErrors": metrics.get("AccessErrors", final_progress.get("AccessErrors", 0)),
            "CurrentScriptIndex": result.get("CurrentScriptIndex", final_progress.get("CurrentScriptIndex", 0)),
            "CurrentScriptName": result.get("CurrentScriptName", final_progress.get("CurrentScriptName")),
            "ScriptCount": result.get("ScriptCount", final_progress.get("ScriptCount", 0)),
            "UpdatedAt": now_iso(),
        })
        result["Progress"] = final_progress

    result["CollectionWarnings"] = warnings
    result["CollectionVerified"] = bool(
        verified_results
    )

    if verified_results:
        prefix = (
            "SFTP"
            if transport.transport_profile == SFTP_SSH_SFTP
            else "SCP"
        )
        result["CollectionStatus"] = (
            f"{prefix}_COLLECTED"
            if not warnings
            else f"{prefix}_COLLECTED_WITH_WARNINGS"
        )
    else:
        # Se conserva el job_result local para diagnóstico, pero un conjunto de
        # resultados incompleto/corrupto no se marca como recolección válida.
        prefix = (
            "SFTP"
            if transport.transport_profile == SFTP_SSH_SFTP
            else "SCP"
        )
        result["CollectionStatus"] = (
            f"{prefix}_COLLECTED_INCOMPLETE"
        )
        result["RemoteState"] = "FAILED"
        result["Error"] = (
            "COLLECT_INTEGRITY_ERROR: "
            + "; ".join(warnings)
        )
        return result

    result["RemoteState"] = (
        "COLLECTED"
        if bool(job_result.get("Success"))
        else "COLLECTED_WITH_ERRORS"
    )

    result["Error"] = job_result.get("Error")

    if warnings and not result["Error"]:
        result["Error"] = "; ".join(warnings)

    return result


async def cleanup_site(
    *,
    transport: RemoteTransport,
    site: Site,
    entry: dict[str, Any],
) -> bool:
    code = make_cleanup_script(
        str(entry["RemoteJobRoot"]),
        str(entry["TaskName"]),
        upload_folder=str(entry.get("UploadFolderName") or ""),
        collection_folder=str(entry.get("CollectionFolderName") or ""),
    )
    rc, _, _, _ = await transport.run_ps(
        site,
        code,
        operation="CLEANUP",
    )
    return rc == 0

def format_progress(entry: dict[str, Any]) -> str:
    progress = entry.get("Progress")
    if not isinstance(progress, dict):
        idx = int(entry.get("CurrentScriptIndex") or 0)
        total = int(entry.get("ScriptCount") or 0)
        name = entry.get("CurrentScriptName") or "-"
        return f"Script={idx}/{total} {name}" if total else "-"

    dirs = progress.get("Directories", 0)
    bak = progress.get("BackupFolders", 0)
    drive = progress.get("Drive", "-")
    elapsed = progress.get("ElapsedSec", 0)
    idx = progress.get("CurrentScriptIndex", entry.get("CurrentScriptIndex", 0))
    total = progress.get("ScriptCount", entry.get("ScriptCount", 0))
    name = progress.get("CurrentScriptName", entry.get("CurrentScriptName")) or "-"
    return (
        f"Script={idx}/{total} {name} | "
        f"Drive={drive} | Dirs={dirs} | BAK={bak} | {elapsed}s"
    )

def print_status_table(manifest: dict[str, Any]) -> None:
    rows = list(
        (manifest.get("Sites") or {}).values()
    )

    print()
    try:
        spec = get_transport_profile(profile_from_manifest(manifest))
        upload_label = f"{spec.distribution} UP"
        collect_label = f"{spec.collection} GET"
    except Exception:
        upload_label = "UPLOAD"
        collect_label = "COLLECT"

    print(
        f"{'SEDE':<24} "
        f"{upload_label:<15} "
        f"{'SSH START':<12} "
        f"{'REMOTE':<22} "
        f"{collect_label:<24} "
        f"{'INTEGRIDAD':<17} "
        f"PROGRESO"
    )
    print("-" * 160)

    for entry in rows:
        label = (
            f"{entry.get('SiteCode')}_"
            f"{entry.get('SiteName')}"
        )

        package_text = (
            "PKG OK"
            if entry.get("PackageVerified") is True
            else (
                "PKG !"
                if entry.get("DispatchStatus") == "FAILED"
                else "PKG -"
            )
        )

        collection_status = str(
            entry.get("CollectionStatus")
            or "PENDING"
        )

        result_text = (
            "RES -"
            if collection_status == "PENDING"
            else (
                "RES OK"
                if entry.get("CollectionVerified") is True
                else "RES !"
            )
        )

        integrity = (
            f"{package_text}/{result_text}"
        )

        print(
            f"{label:<24} "
            f"{str(entry.get('TransferStatus') or '-'):<15} "
            f"{str(entry.get('StartStatus') or '-'):<12} "
            f"{str(entry.get('RemoteState') or '-'):<22} "
            f"{collection_status:<24} "
            f"{integrity:<17} "
            f"{format_progress(entry)}"
        )

    recalc_manifest(manifest)

    terminal = sum(
        1
        for entry in rows
        if terminal_site(entry)
    )

    waiting = sum(
        1
        for entry in rows
        if entry.get("DispatchStatus") == "DISPATCHED"
        and not terminal_site(entry)
    )

    collected = (
        manifest["CollectedCount"]
        + manifest.get(
            "CollectedWithErrorsCount",
            0,
        )
    )

    errors = (
        manifest["FailedCount"]
        + manifest["DispatchFailed"]
        + manifest.get(
            "CollectedWithErrorsCount",
            0,
        )
    )

    print()
    print(
        f"Objetivo {manifest['TotalCount']} | "
        f"Despachados {manifest['DispatchOk']} | "
        f"Esperando reportes {waiting} | "
        f"Terminales {terminal}/{manifest['TotalCount']} | "
        f"Recolectados {collected} | "
        f"Errores {errors} | "
        f"Cancelados {manifest['CancelledCount']} | "
        f"Interrumpidos {manifest['InterruptedCount']}"
    )
    print()


def _reload_external_cancel_state(
    manifest: dict[str, Any],
    store: FanoutStore,
) -> tuple[dict[str, Any], bool]:
    """Devuelve el manifest más reciente y si hay solicitud de cancelación."""
    job_id = str(manifest.get("JobId") or "")
    try:
        latest = store.read(job_id)
    except Exception:
        latest = manifest

    requested = bool(
        latest.get("CancelRequested")
        or store.cancel_requested(job_id)
    )
    return latest, requested


async def _cancel_aware_sleep(
    *,
    manifest: dict[str, Any],
    store: FanoutStore,
    seconds: int,
) -> bool:
    """Espera en pasos de 1s y retorna True si aparece cancel request."""
    total = max(1, int(seconds))
    for _ in range(total):
        await asyncio.sleep(1)
        latest, requested = _reload_external_cancel_state(manifest, store)
        if cancellation_completed(latest) or requested:
            return True
    return False



def _safe_monitor_store_write(
    store: FanoutStore,
    manifest: dict[str, Any],
    *,
    context: str,
) -> bool:
    """Un problema local de persistencia no debe detener monitoreo/recolección."""
    try:
        store.write(manifest)
        return True
    except Exception as exc:
        text = str(exc).replace("\r", " ").replace("\n", " ").strip()
        if len(text) > 180:
            text = text[:177] + "..."
        manifest["MonitorPersistenceWarningCount"] = int(
            manifest.get("MonitorPersistenceWarningCount", 0) or 0
        ) + 1
        manifest["MonitorPersistenceLastError"] = text
        manifest["MonitorPersistenceLastErrorAt"] = now_iso()
        warn(
            f"Persistencia local del monitor no disponible ({context}): "
            f"{text}. El monitoreo remoto CONTINÚA."
        )
        return False


async def poll_and_collect(
    *,
    manifest: dict[str, Any],
    store: FanoutStore,
    inventory: Inventory,
    transport: RemoteTransport,
    poll_workers: int,
    poll_interval: int,
    cleanup_after_collect: bool,
    until_done: bool,
    adaptive_vpn_cfg: Optional[dict[str, Any]] = None,
    connectivity_cfg: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    local_raw_dir = ensure_dir(Path(manifest["RawDir"]))
    telemetry_root = ensure_dir(local_raw_dir / "_telemetry")

    # Watchdogs por sede. Evitan que una conexión SSH establecida pero colgada
    # consuma un slot indefinidamente y deje sin sondeo al resto de las sedes.
    fanout_runtime_cfg = dict(manifest.get("RuntimePolicy") or {})
    monitor_poll_deadline = max(
        10.0,
        float(
            fanout_runtime_cfg.get(
                "MonitorSitePollDeadlineSeconds",
                max(
                    30.0,
                    (transport.control_hard_timeout_seconds * transport.attempts)
                    + sum(transport.retry_delays[: max(0, transport.attempts - 1)])
                    + 5.0,
                ),
            )
        ),
    )
    monitor_collect_deadline = max(
        monitor_poll_deadline,
        float(
            fanout_runtime_cfg.get(
                "MonitorCollectionDeadlineSeconds",
                transport.collection_hard_timeout_seconds + 15.0,
            )
        ),
    )
    poll_failure_waiting_threshold = max(
        1,
        int(
            fanout_runtime_cfg.get(
                "PollFailureWaitingThreshold",
                2,
            )
        ),
    )

    connectivity_enabled = bool((connectivity_cfg or {}).get("enabled", True))
    connectivity_gate = ConnectivityGate(connectivity_cfg or {}) if connectivity_enabled else None
    connectivity_targets = [s.ip for s in inventory.sites if s.code in (manifest.get("Sites") or {})]

    if manifest.get("Status") not in {"MONITORING", "COLLECTING", "WAITING_CONNECTION"}:
        manifest["Status"] = "MONITORING"
        store.write(manifest)

    print()
    print("=" * 78)
    print("FASE 2/4 - MONITOR DE REPORTES REMOTOS")
    print("=" * 78)
    print(f"Total sedes             : {manifest.get('TotalCount', 0)}")
    print(f"Dispatch correctos      : {manifest.get('DispatchOk', 0)}")
    print(f"Polling simultaneo      : {max(1, poll_workers)}")
    print(f"Intervalo entre rondas  : {poll_interval}s")
    print(f"Deadline status/sede    : {monitor_poll_deadline:.0f}s")
    print(f"Deadline collect/sede   : {monitor_collect_deadline:.0f}s")
    print("Polling simultaneo NO limita los jobs remotos: todos siguen trabajando.")
    print("=" * 78)
    print()

    # Circuit breaker del automonitor VPN:
    # si falla varias veces consecutivas, se omite para el resto del job.
    acfg = adaptive_vpn_cfg or {}
    vpn_monitor_enabled = bool(
        acfg
        and acfg.get("enabled", True)
        and acfg.get("monitor_enabled", True)
    )
    vpn_failure_limit = max(
        1,
        int(acfg.get("monitor_failure_limit", 3)),
    )
    vpn_fallback_workers = max(
        1,
        min(
            int(acfg.get("monitor_fallback_workers", acfg.get("normal_workers", 4))),
            max(1, poll_workers),
        ),
    )
    vpn_monitor_failures = int(
        manifest.get("VpnAutoMonitorFailures", 0) or 0
    )
    vpn_monitor_disabled = bool(
        manifest.get("VpnAutoMonitorDisabled", False)
    )

    vpn_monitor_measure_every = max(15.0, float(
        acfg.get("monitor_measure_every_seconds", 60)
    ))
    vpn_last_measure_monotonic = 0.0
    vpn_cached_workers = vpn_fallback_workers
    vpn_cached_reason = "VPN CACHE INICIAL"

    if vpn_monitor_disabled:
        vpn_monitor_enabled = False
        log(
            "VPN auto monitor ya estaba omitido para este job. "
            f"Se continuará con {vpn_fallback_workers} consultas simultáneas."
        )

    while True:
        # Control externo robusto: el sidecar .cancel no puede ser sobrescrito
        # por el monitor que mantiene un manifest en memoria.
        latest_manifest, cancel_requested = _reload_external_cancel_state(
            manifest,
            store,
        )

        if cancellation_completed(latest_manifest):
            log(
                "Cancelación completada por otro proceso; "
                "el monitor deja de sondear y conserva ese estado."
            )
            return latest_manifest

        if cancel_requested:
            manifest = latest_manifest
            if not manifest.get("CancelRequested"):
                mark_cancel_requested(
                    manifest,
                    source="monitor-sidecar",
                )
                store.write(manifest)

            log(
                "Solicitud de cancelación detectada. "
                "El monitor sale de forma cooperativa; fanout cancel coordina la detención remota."
            )
            # No esperar 60 s aquí: salir permite que asyncio cierre pipes SSH/SFTP
            # sin ser terminado a la fuerza por otro proceso.
            return manifest

        # Adoptar cualquier actualización externa legítima antes de la ronda.
        manifest = latest_manifest

        if not await wait_for_controller_connectivity(
            gate=connectivity_gate,
            targets=connectivity_targets,
            manifest=manifest,
            store=store,
            phase="MONITOR/COLLECT",
            restore_status="MONITORING",
        ):
            return manifest

        site_lookup = {s.code: s for s in inventory.sites}
        pending_codes = [
            code
            for code, entry in manifest["Sites"].items()
            if entry.get("DispatchStatus") == "DISPATCHED"
            and not terminal_site(entry)
        ]

        if not pending_codes:
            break

        round_workers = vpn_fallback_workers if vpn_monitor_disabled else max(1, poll_workers)
        connection_mode = str(manifest.get("ControllerConnectionMode") or "UNKNOWN").upper()
        adaptive_poll = (
            vpn_monitor_enabled
            and not vpn_monitor_disabled
            and connection_mode in {"VPN", "MIXED", "UNKNOWN"}
        )
        if connection_mode == "DIRECT":
            round_workers = max(
                1,
                min(int(acfg.get("normal_workers", 4)), max(1, poll_workers)),
            )

        if adaptive_poll:
            need_vpn_measure = (
                vpn_last_measure_monotonic <= 0
                or (time.monotonic() - vpn_last_measure_monotonic) >= vpn_monitor_measure_every
            )
            if need_vpn_measure:
                try:
                    health = await measure_vpn_health(
                        acfg,
                        [
                            site_lookup[c].ip
                            for c in pending_codes
                            if c in site_lookup
                        ],
                    )
                    base, reason = recommend_vpn_concurrency(
                        health,
                        acfg,
                        max_workers=max(1, poll_workers),
                    )
                    round_workers = min(
                        max(1, poll_workers),
                        max(
                            1,
                            base + int(acfg.get("poll_worker_bonus", 1)),
                        ),
                    )
                    vpn_last_measure_monotonic = time.monotonic()
                    vpn_cached_workers = round_workers
                    vpn_cached_reason = reason

                    # Una medición correcta reinicia fallos consecutivos.
                    vpn_monitor_failures = 0
                    manifest["VpnAutoMonitorFailures"] = 0
                    manifest["VpnAutoMonitorDisabled"] = False
                    manifest.pop("VpnAutoMonitorDisabledReason", None)
                    manifest["VpnAutoMonitorLastSuccessAt"] = now_iso()

                    print_vpn_health(
                        health,
                        round_workers,
                        reason,
                        phase="MONITOR/COLLECT",
                    )
                    manifest.setdefault("VpnHealthHistory", []).append(
                        {
                            "Phase": "MONITOR",
                            "SelectedWorkers": round_workers,
                            "Reason": reason,
                            "Health": health,
                        }
                    )

                except Exception as exc:
                    vpn_monitor_failures += 1
                    vpn_last_measure_monotonic = time.monotonic()
                    round_workers = vpn_fallback_workers
                    vpn_cached_workers = round_workers

                    short_error = str(exc).replace("\r", " ").replace("\n", " ").strip()
                    if len(short_error) > 180:
                        short_error = short_error[:177] + "..."

                    manifest["VpnAutoMonitorFailures"] = vpn_monitor_failures
                    manifest["VpnAutoMonitorLastError"] = short_error
                    manifest["VpnAutoMonitorLastErrorAt"] = now_iso()

                    if vpn_monitor_failures >= vpn_failure_limit:
                        vpn_monitor_disabled = True
                        vpn_monitor_enabled = False
                        manifest["VpnAutoMonitorDisabled"] = True
                        manifest["VpnAutoMonitorDisabledReason"] = short_error
                        manifest["VpnAutoMonitorDisabledAt"] = now_iso()
                        vpn_cached_reason = "VPN OMITIDA"

                        warn(
                            "VPN auto monitor OMITIDO para este job tras "
                            f"{vpn_monitor_failures}/{vpn_failure_limit} intentos fallidos. "
                            f"Se continuará normalmente con {round_workers} consultas simultáneas. "
                            "SFTP/SSH y el job remoto NO se detienen."
                        )
                    else:
                        vpn_cached_reason = f"VPN NO DISPONIBLE {vpn_monitor_failures}/{vpn_failure_limit}"
                        warn(
                            "VPN auto monitor no disponible "
                            f"(intento {vpn_monitor_failures}/{vpn_failure_limit}). "
                            f"Se continuará con {round_workers} consultas simultáneas. "
                            f"Detalle: {short_error}"
                        )

                    store.write(manifest)
            else:
                round_workers = max(1, min(vpn_cached_workers, max(1, poll_workers)))
        io_semaphore = asyncio.Semaphore(round_workers)

        monitor_round = int(
            manifest.get("MonitorRound", 0) or 0
        ) + 1
        manifest["MonitorRound"] = monitor_round
        manifest["MonitorRoundTargetCount"] = len(pending_codes)
        manifest["MonitorRoundProcessedCount"] = 0
        manifest["MonitorRoundSuccessCount"] = 0
        manifest["MonitorRoundFailureCount"] = 0
        manifest["MonitorRoundCollectedCount"] = 0
        manifest["MonitorRoundStartedAt"] = now_iso()
        manifest["MonitorRoundFinishedAt"] = None

        _safe_monitor_store_write(
            store,
            manifest,
            context=f"inicio ronda {monitor_round}",
        )

        async def site_cycle(code: str):
            """Sondea y, si corresponde, recolecta ESTA sede inmediatamente."""
            site = site_lookup.get(code)
            original = dict(manifest["Sites"][code])

            if not site:
                updated = dict(original)
                updated["LastCheckedAt"] = now_iso()
                updated["PollFailureCount"] = int(
                    updated.get("PollFailureCount", 0) or 0
                ) + 1
                updated["LastPollError"] = "Site not found in inventory"
                updated["Error"] = updated["LastPollError"]
                return code, updated, False, True

            try:
                async with io_semaphore:
                    updated = await asyncio.wait_for(
                        poll_site(
                            transport=transport,
                            site=site,
                            entry=original,
                            telemetry_root=telemetry_root,
                            failure_waiting_threshold=poll_failure_waiting_threshold,
                        ),
                        timeout=monitor_poll_deadline,
                    )
            except asyncio.CancelledError:
                raise
            except TimeoutError:
                updated = dict(original)
                updated["LastCheckedAt"] = now_iso()
                updated["PollFailureCount"] = int(
                    updated.get("PollFailureCount", 0) or 0
                ) + 1
                updated["LastPollError"] = (
                    "MONITOR_SITE_TIMEOUT: la sede no completó el sondeo "
                    f"dentro de {monitor_poll_deadline:.0f}s."
                )
                updated["LastPollErrorAt"] = now_iso()
                updated["Error"] = updated["LastPollError"]
                updated["TelemetryState"] = "WAITING_CONNECTION"
                updated["MonitorWatchdogTrips"] = int(
                    updated.get("MonitorWatchdogTrips", 0) or 0
                ) + 1
                return code, updated, False, True
            except Exception as exc:
                updated = dict(original)
                updated["LastCheckedAt"] = now_iso()
                updated["PollFailureCount"] = int(
                    updated.get("PollFailureCount", 0) or 0
                ) + 1
                updated["LastPollError"] = (
                    f"{type(exc).__name__}: {exc}"
                )
                updated["LastPollErrorAt"] = now_iso()
                updated["Error"] = updated["LastPollError"]
                if int(updated.get("PollFailureCount", 0) or 0) >= poll_failure_waiting_threshold:
                    updated["TelemetryState"] = "WAITING_CONNECTION"
                else:
                    updated["TelemetryState"] = "DEGRADED"
                return code, updated, False, True

            poll_failed = bool(updated.get("LastPollError"))
            if poll_failed:
                if int(updated.get("PollFailureCount", 0) or 0) >= poll_failure_waiting_threshold:
                    updated["TelemetryState"] = "WAITING_CONNECTION"
                else:
                    updated["TelemetryState"] = "DEGRADED"
            else:
                updated["TelemetryState"] = "ONLINE"
                updated["TelemetryRecoveredAt"] = now_iso()
            collected_now = False

            # No esperar al resto de las sedes: apenas esté RESULT_READY,
            # iniciar SFTP GET de esta sede usando el mismo límite global.
            if updated.get("RemoteState") in {
                "RESULT_READY",
                "RESULT_READY_WITH_ERRORS",
            }:
                try:
                    async with io_semaphore:
                        updated = await asyncio.wait_for(
                            collect_site(
                                transport=transport,
                                site=site,
                                entry=updated,
                                local_raw_dir=local_raw_dir,
                                script_defs=list(manifest.get("Scripts") or []),
                            ),
                            timeout=monitor_collect_deadline,
                        )
                    collected_now = updated.get("RemoteState") in {
                        "COLLECTED",
                        "COLLECTED_WITH_ERRORS",
                    }

                    if collected_now and cleanup_after_collect:
                        try:
                            async with io_semaphore:
                                cleaned = await cleanup_site(
                                    transport=transport,
                                    site=site,
                                    entry=updated,
                                )
                            updated["CleanedRemote"] = cleaned
                        except Exception as exc:
                            updated["CleanupWarning"] = (
                                f"{type(exc).__name__}: {exc}"
                            )
                except asyncio.CancelledError:
                    raise
                except TimeoutError:
                    updated["CollectionStatus"] = "PENDING_RETRY"
                    updated["CollectionVerified"] = False
                    updated["TelemetryState"] = "WAITING_CONNECTION"
                    updated["CollectionWatchdogTrips"] = int(
                        updated.get("CollectionWatchdogTrips", 0) or 0
                    ) + 1
                    updated["Error"] = (
                        "COLLECT_TIMEOUT: la recolección no terminó dentro de "
                        f"{monitor_collect_deadline:.0f}s; se reintentará."
                    )
                except Exception as exc:
                    updated["CollectionStatus"] = "FAILED"
                    updated["CollectionVerified"] = False
                    updated["Error"] = (
                        f"COLLECT_EXCEPTION: {type(exc).__name__}: {exc}"
                    )

            return code, updated, collected_now, poll_failed

        round_tasks = [
            asyncio.create_task(site_cycle(code))
            for code in pending_codes
        ]

        processed = 0
        successful_polls = 0
        failed_polls = 0
        collected_this_round = 0
        last_persist_at = 0.0

        for task in asyncio.as_completed(round_tasks):
            code, updated, collected_now, poll_failed = await task
            processed += 1

            previous = manifest["Sites"][code]
            previous_state = previous.get("RemoteState")
            previous_progress = previous.get("Progress")
            previous_collect = previous.get("CollectionStatus")

            manifest["Sites"][code] = updated

            if poll_failed:
                failed_polls += 1
            else:
                successful_polls += 1

            if collected_now:
                collected_this_round += 1
                ok(
                    f"{code}_{updated.get('SiteName')} - REPORT_RECEIVED "
                    f"- {updated.get('RawFile')}"
                )

            manifest["MonitorRoundProcessedCount"] = processed
            manifest["MonitorRoundSuccessCount"] = successful_polls
            manifest["MonitorRoundFailureCount"] = failed_polls
            manifest["MonitorRoundCollectedCount"] = collected_this_round
            manifest["MonitorLastProgressAt"] = now_iso()
            manifest["MonitorWatchdogTripCount"] = sum(
                int(x.get("MonitorWatchdogTrips", 0) or 0)
                for x in manifest["Sites"].values()
            )
            manifest["CollectionWatchdogTripCount"] = sum(
                int(x.get("CollectionWatchdogTrips", 0) or 0)
                for x in manifest["Sites"].values()
            )

            recalc_manifest(manifest)
            manifest["WaitingRemoteCount"] = sum(
                1
                for x in manifest["Sites"].values()
                if x.get("DispatchStatus") == "DISPATCHED"
                and not terminal_site(x)
            )

            state_changed = (
                updated.get("RemoteState") != previous_state
                or updated.get("Progress") != previous_progress
                or updated.get("CollectionStatus") != previous_collect
            )

            # Persistencia incremental: la GUI recibe avances sin esperar las
            # otras 27 sedes. Se limita a ~2 sedes o 0.75 s para no saturar disco.
            now_mono = time.monotonic()
            should_persist = (
                processed == 1
                or processed == len(pending_codes)
                or processed % 2 == 0
                or collected_now
                or state_changed
                or (now_mono - last_persist_at) >= 0.75
            )

            if should_persist:
                _safe_monitor_store_write(
                    store,
                    manifest,
                    context=(
                        f"ronda {monitor_round} "
                        f"{processed}/{len(pending_codes)}"
                    ),
                )
                last_persist_at = now_mono

            if state_changed:
                p = updated.get("Progress")
                if isinstance(p, dict):
                    log(
                        f"{code}_{updated.get('SiteName')} - "
                        f"{updated.get('RemoteState')} - "
                        f"Drive={p.get('Drive')} "
                        f"Dirs={p.get('Directories')} "
                        f"BAK={p.get('BackupFolders')} "
                        f"Elapsed={p.get('ElapsedSec')}s "
                        f"Current={p.get('CurrentPath')}"
                    )
                else:
                    log(
                        f"{code}_{updated.get('SiteName')} - "
                        f"{updated.get('RemoteState')}"
                    )

        manifest["MonitorRoundFinishedAt"] = now_iso()
        _safe_monitor_store_write(
            store,
            manifest,
            context=f"fin ronda {monitor_round}",
        )

        # Antes de escribir, revisar nuevamente el canal de control externo.
        latest_external, external_cancel = _reload_external_cancel_state(
            manifest,
            store,
        )
        if cancellation_completed(latest_external):
            return latest_external
        if external_cancel:
            manifest = latest_external
            if not manifest.get("CancelRequested"):
                mark_cancel_requested(
                    manifest,
                    source="monitor-before-write",
                )
            store.write(manifest)
            continue

        recalc_manifest(manifest)
        manifest["WaitingRemoteCount"] = sum(
            1 for x in manifest["Sites"].values()
            if x.get("DispatchStatus") == "DISPATCHED" and not terminal_site(x)
        )
        _safe_monitor_store_write(
            store,
            manifest,
            context=f"cierre ronda {monitor_round}",
        )

        print_status_table(manifest)

        if not until_done:
            return manifest

        if all(terminal_site(x) for x in manifest["Sites"].values()):
            break

        log(f"Esperando {poll_interval}s antes del siguiente sondeo.")
        cancel_seen = await _cancel_aware_sleep(
            manifest=manifest,
            store=store,
            seconds=max(3, poll_interval),
        )
        if cancel_seen:
            continue

    recalc_manifest(manifest)
    return manifest






def _cancel_remote_evidence(entry: dict[str, Any]) -> bool:
    """Detecta si el Job pudo haberse iniciado remotamente.

    Si el paquete se subió y hubo al menos un intento SSH START, se intenta
    cancelar aunque el START terminara en timeout/error.
    """
    dispatch = str(entry.get("DispatchStatus") or "").upper()
    transfer = str(entry.get("TransferStatus") or "").upper()
    start = str(entry.get("StartStatus") or "").upper()
    remote = str(entry.get("RemoteState") or "").upper()
    task_state = str(entry.get("TaskState") or "").upper()
    try:
        ssh_attempts = int(entry.get("SshStartAttempts") or 0)
    except Exception:
        ssh_attempts = 0
    if dispatch == "DISPATCHED" or start == "SSH_STARTED":
        return True
    if task_state in {"RUNNING", "READY", "QUEUED"}:
        return True
    if remote in {
        "DISPATCHED", "RUNNING", "RESULT_READY", "RESULT_READY_WITH_ERRORS",
        "CANCEL_REQUESTED", "CANCELLING", "CANCEL_FAILED",
    }:
        return True
    if transfer == "SFTP_UPLOADED" and ssh_attempts > 0:
        return True
    return False


def _cancel_already_terminal(entry: dict[str, Any]) -> bool:
    return str(entry.get("RemoteState") or "").upper() in {
        "COLLECTED", "COLLECTED_WITH_ERRORS", "FAILED", "CANCELLED",
        "CANCELLED_NOT_STARTED", "INTERRUPTED",
    }


def _cancel_persistence_error_text(exc: BaseException) -> str:
    text = str(exc).replace("\r", " ").replace("\n", " ").strip()
    winerror = getattr(exc, "winerror", None)
    if winerror == 5 or "WinError 5" in text or "Access is denied" in text:
        return (
            "WinError 5 / Access denied al persistir el manifest local. "
            "La cancelación remota CONTINÚA y el guardado será reintentado."
        )
    if len(text) > 220:
        text = text[:217] + "..."
    return text or type(exc).__name__


def _safe_cancel_store_write(store: FanoutStore, manifest: dict[str, Any], *, context: str) -> bool:
    """Un fallo local de JSON nunca corta la cancelación remota."""
    try:
        store.write(manifest)
        return True
    except Exception as exc:
        message = _cancel_persistence_error_text(exc)
        warnings = manifest.setdefault("CancelPersistenceWarnings", [])
        warnings.append({"At": now_iso(), "Context": context, "Error": message})
        if len(warnings) > 20:
            del warnings[:-20]
        manifest["CancelPersistenceWarningCount"] = int(manifest.get("CancelPersistenceWarningCount", 0) or 0) + 1
        manifest["CancelPersistenceLastError"] = message
        manifest["CancelPersistenceLastErrorAt"] = now_iso()
        warn(
            f"Persistencia local de cancelación no disponible ({context}): "
            f"{message} Se seguirá cancelando el resto de sedes."
        )
        return False


async def cancel_remote_job(
    *,
    manifest: dict[str, Any],
    store: FanoutStore,
    inventory: Inventory,
    transport: RemoteTransport,
    workers: int,
) -> None:
    """Cancela todas las sedes aunque el manifest local tenga contención I/O."""
    site_lookup = {s.code: s for s in inventory.sites}
    semaphore = asyncio.Semaphore(max(1, workers))

    if not manifest.get("CancelRequested"):
        mark_cancel_requested(manifest, source="cancel_remote_job")

    manifest["Status"] = "CANCELLING"
    manifest["CancelStartedAt"] = manifest.get("CancelStartedAt") or now_iso()
    manifest["CancelCoordinatorPid"] = os.getpid()

    sites = manifest.get("Sites") or {}
    manifest["CancelTargetCount"] = len(sites)

    remote_candidates: list[str] = []
    not_started: list[str] = []
    already_terminal: list[str] = []

    for code, entry in sites.items():
        if _cancel_already_terminal(entry):
            already_terminal.append(code)
        elif _cancel_remote_evidence(entry):
            remote_candidates.append(code)
        else:
            not_started.append(code)

    manifest["CancelRemoteCandidateCount"] = len(remote_candidates)
    manifest["CancelNotStartedCount"] = len(not_started)
    manifest["CancelAlreadyTerminalCount"] = len(already_terminal)

    log(
        "Plan de cancelación: "
        f"objetivo={len(sites)} | remotas={len(remote_candidates)} | "
        f"no iniciadas={len(not_started)} | ya terminales={len(already_terminal)}."
    )

    for code in not_started:
        entry = sites[code]
        entry["RemoteState"] = "CANCELLED_NOT_STARTED"
        entry["CancelConfirmed"] = True
        entry["CancelMode"] = "NOT_STARTED"
        entry["CancelCompletedAt"] = now_iso()
        entry["TaskState"] = entry.get("TaskState") or "NotStarted"
        entry["Error"] = None

    recalc_manifest(manifest)
    _safe_cancel_store_write(store, manifest, context="inicio/plan de cancelación")

    async def one(code: str):
        # Una sede nunca puede abortar la cancelación de las demás.
        try:
            site = site_lookup.get(code)
            if site is None:
                return code, 3, "", "Site not found in inventory", None
            entry = manifest["Sites"][code]
            script = make_cancel_script(str(entry["RemoteJobRoot"]), str(entry["TaskName"]))
            async with semaphore:
                rc, stdout, stderr, _ = await transport.run_ps(site, script, operation="CANCEL")
            payload = None
            try:
                payload = json.loads(stdout.strip().splitlines()[-1])
            except Exception:
                payload = None
            return code, rc, stdout, stderr, payload
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return code, 99, "", f"{type(exc).__name__}: {exc}", None

    tasks = [asyncio.create_task(one(code)) for code in remote_candidates]
    success_count = 0
    failure_count = 0
    processed_remote = 0
    last_persist_at = 0.0

    for task in asyncio.as_completed(tasks):
        code, rc, stdout, stderr, payload = await task
        processed_remote += 1
        entry = manifest["Sites"][code]
        confirmed = (
            rc == 0 and isinstance(payload, dict) and bool(payload.get("Success"))
            and str(payload.get("State") or "").upper() == "CANCELLED"
        )

        if confirmed:
            entry["RemoteState"] = "CANCELLED"
            entry["TaskState"] = payload.get("TaskState") or "Ready"
            entry["CancelCompletedAt"] = now_iso()
            entry["CancelConfirmed"] = True
            entry["CancelMode"] = "REMOTE"
            entry["RemoteWorkerPid"] = payload.get("WorkerPid")
            entry["RemoteWorkerTerminated"] = payload.get("WorkerTerminated")
            entry["RemoteWorkerStillRunning"] = payload.get("WorkerStillRunning")
            entry["RemoteWorkerVerificationError"] = payload.get("WorkerVerificationError")
            entry["Error"] = None
            success_count += 1
            ok(f"{code}_{entry['SiteName']} - CANCELLED ({processed_remote}/{len(remote_candidates)})")
        else:
            entry["RemoteState"] = "CANCEL_FAILED"
            entry["CancelConfirmed"] = False
            entry["CancelMode"] = "REMOTE"
            entry["CancelCompletedAt"] = now_iso()
            entry["Error"] = (
                (payload or {}).get("Error") if isinstance(payload, dict) else None
            ) or stderr.strip() or stdout.strip() or f"ExitCode={rc}"
            entry["TaskState"] = (
                (payload or {}).get("TaskState") if isinstance(payload, dict)
                else entry.get("TaskState")
            )
            if isinstance(payload, dict):
                entry["RemoteWorkerPid"] = payload.get("WorkerPid")
                entry["RemoteWorkerTerminated"] = payload.get("WorkerTerminated")
                entry["RemoteWorkerStillRunning"] = payload.get("WorkerStillRunning")
                entry["RemoteWorkerVerificationError"] = payload.get("WorkerVerificationError")
            failure_count += 1
            warn(
                f"{code}_{entry['SiteName']} - CANCEL_FAILED "
                f"({processed_remote}/{len(remote_candidates)}). {entry['Error']}"
            )

        recalc_manifest(manifest)
        manifest["CancelSuccessCount"] = success_count
        manifest["CancelFailureCount"] = failure_count
        manifest["CancelRemoteProcessedCount"] = processed_remote
        covered = success_count + len(not_started) + len(already_terminal)
        manifest["CancelCoveredCount"] = covered
        manifest["CancelRemainingCount"] = max(0, len(sites) - covered - failure_count)

        now_mono = time.monotonic()
        if (
            processed_remote == len(remote_candidates)
            or processed_remote % 3 == 0
            or (now_mono - last_persist_at) >= 1.0
        ):
            _safe_cancel_store_write(
                store, manifest,
                context=f"progreso {processed_remote}/{len(remote_candidates)}",
            )
            last_persist_at = now_mono

    manifest["CancelSuccessCount"] = success_count
    manifest["CancelFailureCount"] = failure_count
    manifest["CancelRemoteProcessedCount"] = processed_remote
    manifest["CancelCompletedAt"] = now_iso()
    manifest["FinishedAt"] = manifest["CancelCompletedAt"]
    covered = success_count + len(not_started) + len(already_terminal)
    manifest["CancelCoveredCount"] = covered
    manifest["CancelRemainingCount"] = max(0, len(sites) - covered - failure_count)
    manifest["Status"] = "CANCELLED" if failure_count == 0 else "CANCELLED_WITH_ERRORS"
    recalc_manifest(manifest)

    final_persisted = False
    for attempt in range(1, 4):
        if _safe_cancel_store_write(store, manifest, context=f"persistencia final {attempt}/3"):
            final_persisted = True
            break
        await asyncio.sleep(0.15 * attempt)
    manifest["CancelFinalPersistenceOk"] = final_persisted

    if not final_persisted:
        recovery_path = store.root / f"{manifest['JobId']}.cancel-recovery"
        try:
            atomic_write_json_nolock(recovery_path, manifest, retries=12)
            warn(
                "Manifest principal bloqueado después de cancelar; "
                f"se guardó recuperación en {recovery_path.name}."
            )
        except Exception as exc:
            fail(
                "Cancelación remota finalizada, pero falló también el archivo "
                f"de recuperación local: {exc}"
            )

    ok(
        "Cobertura de cancelación: "
        f"{covered + failure_count}/{len(sites)} procesadas | "
        f"remotas={success_count}/{len(remote_candidates)} | "
        f"no iniciadas={len(not_started)} | "
        f"ya terminales={len(already_terminal)} | fallidas={failure_count}."
    )


async def cleanup_job(
    *,
    manifest: dict[str, Any],
    store: FanoutStore,
    inventory: Inventory,
    transport: RemoteTransport,
    workers: int,
) -> None:
    site_lookup = {s.code: s for s in inventory.sites}
    semaphore = asyncio.Semaphore(max(1, workers))

    async def one(code: str):
        site = site_lookup[code]
        entry = manifest["Sites"][code]
        async with semaphore:
            cleaned = await cleanup_site(
                transport=transport,
                site=site,
                entry=entry,
            )
        return code, cleaned

    tasks = [
        asyncio.create_task(one(code))
        for code, entry in manifest["Sites"].items()
        if entry.get("DispatchStatus") == "DISPATCHED"
        and not entry.get("CleanedRemote")
    ]

    for task in asyncio.as_completed(tasks):
        code, cleaned = await task
        manifest["Sites"][code]["CleanedRemote"] = cleaned
        if cleaned:
            ok(f"{code}_{manifest['Sites'][code]['SiteName']} - CLEANED")
        else:
            warn(f"{code}_{manifest['Sites'][code]['SiteName']} - CLEANUP_FAILED")

    recalc_manifest(manifest)
    store.write(manifest)


def prepare(
    args: argparse.Namespace,
) -> tuple[
    dict[str, Any], Inventory, str, Path, Path, Path, Path, Path, FanoutStore
]:
    cfg = load_config(expand_path(args.config))
    require_valid_config(cfg)
    inventory = Inventory(expand_path(args.sites_file))

    ssh_cfg = cfg["ssh"]
    paths = cfg["paths"]
    fanout_cfg = cfg.get("fanout", {})

    user = ssh_cfg.get("user", "damautapp")
    key = expand_path(ssh_cfg["key_path"])
    known_hosts = expand_path(paths["known_hosts"])
    results_dir = ensure_dir(expand_path(paths["results_dir"]))
    raw_dir = ensure_dir(expand_path(paths["raw_dir"]))

    fanout_jobs_dir = ensure_dir(
        expand_path(
            paths.get(
                "fanout_jobs_dir",
                "%LOCALAPPDATA%\\GIDEONSSH\\fanout_jobs",
            )
        )
    )

    return (
        cfg,
        inventory,
        user,
        key,
        known_hosts,
        results_dir,
        raw_dir,
        (
            expand_path(
                SCRIPT_DIR
                / str(fanout_cfg["remote_worker"]).replace("\\", os.sep)
            )
            if fanout_cfg.get("remote_worker")
            and not Path(
                str(fanout_cfg["remote_worker"]).replace("\\", os.sep)
            ).is_absolute()
            else expand_path(
                fanout_cfg.get("remote_worker", DEFAULT_WORKER)
            )
        ),
        FanoutStore(fanout_jobs_dir),
    )


def build_transport(
    cfg: dict[str, Any],
    user: str,
    key: Path,
    known_hosts: Path,
    *,
    transport_profile: str | None = None,
) -> RemoteTransport:
    ssh_cfg = cfg["ssh"]
    fanout_cfg = cfg.get("fanout", {})

    strict = ssh_cfg.get("strict_host_key_checking", "accept-new")
    selected_profile = normalize_transport_profile(
        transport_profile
        or fanout_cfg.get("transport_profile")
        or DEFAULT_TRANSPORT_PROFILE
    )

    return RemoteTransport(
        user=user,
        key=key,
        known_hosts=known_hosts,
        port=int(ssh_cfg.get("port", 22)),
        timeout=int(fanout_cfg.get(
            "connect_timeout_seconds",
            ssh_cfg.get("connect_timeout_seconds", 30),
        )),
        strict=strict,
        attempts=int(fanout_cfg.get(
            "retry_attempts",
            ssh_cfg.get("retry_attempts", 3),
        )),
        retry_delays=list(fanout_cfg.get(
            "retry_delays_seconds",
            ssh_cfg.get("retry_delays_seconds", [3, 5]),
        )),
        transport_profile=selected_profile,
        telemetry_hard_timeout_seconds=float(
            fanout_cfg.get("telemetry_hard_timeout_seconds", 12.0)
        ),
        control_hard_timeout_seconds=float(
            fanout_cfg.get("control_hard_timeout_seconds", 20.0)
        ),
        transfer_hard_timeout_seconds=float(
            fanout_cfg.get("transfer_hard_timeout_seconds", 90.0)
        ),
        collection_hard_timeout_seconds=float(
            fanout_cfg.get("collection_hard_timeout_seconds", 180.0)
        ),
    )


def select_sites(
    inventory: Inventory,
    *,
    targets: Optional[str],
    all_sites: bool,
    confirm_all: bool,
) -> list[Site]:
    if all_sites and not confirm_all:
        raise ValueError("--all requiere --confirm-all.")

    requested = ["ALL"] if all_sites else parse_targets_text(targets)

    if not requested:
        raise ValueError("Debe indicar --targets o --all.")

    return inventory.resolve(requested, allow_all=confirm_all)




async def command_dispatch(args: argparse.Namespace) -> int:
    (
        cfg, inventory, user, key, known_hosts,
        results_dir, raw_dir, worker_path, store,
    ) = prepare(args)

    sites = select_sites(
        inventory,
        targets=args.targets,
        all_sites=args.all,
        confirm_all=args.confirm_all,
    )

    host_profiles = HostProfileStore(SCRIPT_DIR / "config" / "host_profiles.json")
    unsupported_agentless = []
    for site in sites:
        profile = host_profiles.resolve(site.code)
        if not bool(profile.get("agentless", {}).get("supported", False)):
            unsupported_agentless.append(f"{site.label}→{profile.get('id')}")
    if unsupported_agentless:
        raise RuntimeError(
            "HOST_PROFILE_AGENTLESS_UNSUPPORTED: "
            + ", ".join(unsupported_agentless[:10])
            + ". Use AGENTE HTTPS/PULL for those hosts."
        )

    raw_scripts = getattr(args, "script", None) or []
    if isinstance(raw_scripts, (str, Path)):
        raw_scripts = [raw_scripts]
    script_paths = [expand_path(x) for x in raw_scripts]
    if not script_paths:
        raise ValueError("Debe indicar al menos un --script.")
    for script_path in script_paths:
        if not script_path.exists():
            raise FileNotFoundError(f"No existe script: {script_path}")
        if script_path.suffix.lower() != ".ps1":
            raise ValueError(f"Solo se permiten scripts .ps1: {script_path}")

    worker_path = expand_path(worker_path)
    if not worker_path.exists():
        raise FileNotFoundError(f"No existe worker remoto: {worker_path}")

    fanout_cfg = cfg.get("fanout", {})

    transport_profile = normalize_transport_profile(
        getattr(args, "transport_profile", None)
        or fanout_cfg.get("transport_profile")
        or DEFAULT_TRANSPORT_PROFILE
    )
    transport_spec = get_transport_profile(transport_profile)
    log(
        "Perfil de transporte seleccionado: "
        f"{transport_spec.label} · "
        f"{transport_spec.distribution}/{transport_spec.control}/{transport_spec.collection}"
    )

    starter_cfg = fanout_cfg.get(
        "remote_starter",
        str(DEFAULT_STARTER),
    )
    starter_text = str(starter_cfg or DEFAULT_STARTER).replace(
        "\\",
        os.sep,
    )
    starter_path = (
        expand_path(SCRIPT_DIR / starter_text)
        if starter_text
        and not Path(starter_text).is_absolute()
        else expand_path(starter_text or DEFAULT_STARTER)
    )
    if not starter_path.exists():
        raise FileNotFoundError(f"No existe starter remoto: {starter_path}")

    SSHAgent(key).load()

    adaptive_cfg = dict(cfg.get("adaptive_vpn", {}) or {})
    if getattr(args, "fixed_concurrency", False):
        adaptive_cfg["enabled"] = False

    job_id = getattr(args, "job_id", None) or safe_job_id()
    runtime_cfg = cfg.get("runtime_diagnostics", {}) or {}
    start_runtime(
        store.root,
        job_id,
        phase="DISPATCH",
        heartbeat_seconds=float(runtime_cfg.get("heartbeat_seconds", 5)),
    )

    if bool(getattr(args, "stop_on_error", False)):
        continue_on_error = False
    elif bool(getattr(args, "continue_on_error", False)):
        continue_on_error = True
    else:
        continue_on_error = bool(
            fanout_cfg.get("continue_on_error", True)
        )

    manifest = make_manifest(
        job_id=job_id,
        script_paths=script_paths,
        sites=sites,
        remote_root=str(
            fanout_cfg.get("remote_job_root", r"C:\ProgramData\GIDEONSSH\jobs")
        ),
        task_prefix=str(fanout_cfg.get("task_prefix", "GIDEONSSH")),
        export_format=args.export,
        results_dir=results_dir,
        raw_dir=raw_dir,
        poll_interval=int(
            args.poll_interval
            or fanout_cfg.get("poll_interval_seconds", 15)
        ),
        continue_on_error=continue_on_error,
        transport_profile=transport_profile,
    )

    packages_root = ensure_dir(
        expand_path(
            cfg.get("paths", {}).get(
                "packages_dir",
                "%LOCALAPPDATA%\\GIDEONSSH\\packages",
            )
        )
    )
    manifest["PackagesDir"] = str(packages_root / job_id)
    manifest["SitesFile"] = str(expand_path(args.sites_file))
    manifest["SiteGroupId"] = os.environ.get("GIDEON_SITE_GROUP_ID") or None
    manifest["SiteGroupName"] = os.environ.get("GIDEON_SITE_GROUP_NAME") or None
    manifest["ControllerPid"] = os.getpid()
    manifest["DispatchPid"] = os.getpid()
    manifest["ControllerVersion"] = VERSION
    manifest["ControllerStartedAt"] = now_iso()
    manifest["LocalProcessRegistryEnabled"] = True
    apply_runtime_policy(manifest, fanout_cfg)
    store.write(manifest)

    process_registry = LocalProcessRegistry(store.root, job_id)
    process_registry.clear_stale_files()
    transport = build_transport(
        cfg,
        user,
        key,
        known_hosts,
        transport_profile=transport_profile,
    )
    transport.attach_registry(process_registry)

    update_runtime(
        phase="DISPATCH",
        state="RUNNING",
        DispatchTargetCount=len(sites),
    )
    await dispatch_job(
        manifest=manifest,
        store=store,
        transport=transport,
        inventory_sites=sites,
        script_paths=script_paths,
        worker_path=worker_path,
        starter_path=starter_path,
        packages_root=packages_root,
        remote_root=str(
            fanout_cfg.get("remote_job_root", r"C:\ProgramData\GIDEONSSH\jobs")
        ),
        task_prefix=str(fanout_cfg.get("task_prefix", "GIDEONSSH")),
        workers=int(
            args.dispatch_workers
            or fanout_cfg.get("dispatch_workers", 6)
        ),
        stagger_ms=int(
            args.stagger_ms
            if args.stagger_ms is not None
            else fanout_cfg.get("dispatch_stagger_ms", 150)
        ),
        continue_on_error=continue_on_error,
        adaptive_vpn_cfg=adaptive_cfg,
        connectivity_cfg=dict(cfg.get("connectivity", {}) or {}),
        site_deadline_seconds=float(fanout_cfg.get("dispatch_site_deadline_seconds",45)),
    )

    manifest = store.read(job_id)
    runtime_cfg = cfg.get("runtime_diagnostics", {}) or {}
    start_runtime(
        store.root,
        job_id,
        phase="MONITOR",
        heartbeat_seconds=float(runtime_cfg.get("heartbeat_seconds", 5)),
    )
    if manifest.get("CancelRequested") or store.cancel_requested(job_id):
        warn("Job cancelado durante dispatch; no se iniciará la fase de monitor.")
        return 2

    print(f"JOB ID: {job_id}")
    print(f"Scripts en el paquete: {len(script_paths)}")
    print(f"Para continuar luego: py gideon_admin.py fanout resume {job_id}")

    if args.wait:
        return await command_resume_id(
            args=args,
            job_id=job_id,
            prepared=(
                cfg, inventory, user, key, known_hosts,
                results_dir, raw_dir, worker_path, store,
            ),
        )

    return 0 if manifest["DispatchFailed"] == 0 else 2

async def command_resume_id(
    *,
    args: argparse.Namespace,
    job_id: str,
    prepared=None,
) -> int:
    if prepared is None:
        prepared = prepare(args)

    (
        cfg, inventory, user, key, known_hosts,
        results_dir, raw_dir, worker_path, store,
    ) = prepared

    manifest = store.read(job_id)
    if manifest.get("CancelRequested") or store.cancel_requested(job_id):
        warn(f"Job {job_id} tiene cancelación solicitada; no se reanudará el monitor.")
        return 2

    manifest["MonitorPid"] = os.getpid()
    manifest["MonitorStartedAt"] = now_iso()
    manifest["ControllerPid"] = manifest.get("ControllerPid") or os.getpid()
    apply_runtime_policy(manifest, dict(cfg.get("fanout", {}) or {}))
    store.write(manifest)

    SSHAgent(key).load()
    process_registry = LocalProcessRegistry(store.root, job_id)
    transport = build_transport(
        cfg, user, key, known_hosts,
        transport_profile=profile_from_manifest(manifest),
    )
    transport.attach_registry(process_registry)

    fanout_cfg = cfg.get("fanout", {})
    poll_workers = int(
        getattr(args, "poll_workers", None)
        or fanout_cfg.get("poll_workers", 8)
    )
    poll_interval = int(
        getattr(args, "poll_interval", None)
        or manifest.get("PollIntervalSeconds")
        or fanout_cfg.get("poll_interval_seconds", 15)
    )
    cleanup_after = bool(
        fanout_cfg.get("cleanup_remote_after_collect", True)
    )

    manifest["Status"] = "MONITORING"
    store.write(manifest)

    # Supervisor del monitor Python:
    # una excepción transitoria ya no mata silenciosamente todo el controlador.
    runtime_cfg = cfg.get("runtime_diagnostics", {}) or {}
    max_monitor_restarts = max(
        0, int(runtime_cfg.get("monitor_supervisor_restarts", 4) or 4)
    )
    restart_delays = list(
        runtime_cfg.get("monitor_restart_delays_seconds", [2, 5, 10, 20])
        or [2, 5, 10, 20]
    )
    monitor_restart_count = 0

    while True:
        update_runtime(
            phase="MONITOR",
            state="RUNNING",
            restart_count=monitor_restart_count,
        )
        try:
            manifest = await poll_and_collect(
                manifest=manifest,
                store=store,
                inventory=inventory,
                transport=transport,
                poll_workers=poll_workers,
                poll_interval=poll_interval,
                cleanup_after_collect=cleanup_after,
                until_done=True,
                adaptive_vpn_cfg=(dict(cfg.get("adaptive_vpn", {}) or {}) if manifest.get("AdaptiveVpnEnabled", True) else {"enabled": False}),
                connectivity_cfg=dict(cfg.get("connectivity", {}) or {}),
            )
            manifest["ControllerRuntimeState"] = "RUNNING"
            manifest["ControllerMonitorRestartCount"] = monitor_restart_count
            manifest["ControllerLastPythonError"] = None
            store.write(manifest)
            break

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            monitor_restart_count += 1
            tb = traceback.format_exc()
            report_runtime_exception(
                exc,
                phase="MONITOR",
                recovering=(monitor_restart_count <= max_monitor_restarts),
                restart_count=monitor_restart_count,
            )

            try:
                latest = store.read(job_id)
            except Exception:
                latest = manifest

            latest["ControllerRuntimeState"] = (
                "ERROR_RECOVERING"
                if monitor_restart_count <= max_monitor_restarts
                else "FAILED"
            )
            latest["ControllerMonitorRestartCount"] = monitor_restart_count
            latest["ControllerLastPythonError"] = {
                "Type": type(exc).__name__,
                "Message": str(exc),
                "At": now_iso(),
                "TracebackTail": "\n".join(tb.strip().splitlines()[-18:]),
            }
            try:
                store.write(latest)
            except Exception as persist_exc:
                fail(f"MONITOR_PERSIST_ERROR: no se pudo persistir el fallo del monitor: {persist_exc}")

            fail(
                f"MONITOR PYTHON ERROR {type(exc).__name__}: {exc}. "
                f"Recovery {monitor_restart_count}/{max_monitor_restarts}."
            )

            if monitor_restart_count > max_monitor_restarts:
                finish_runtime("FAILED")
                raise

            delay = float(
                restart_delays[
                    min(monitor_restart_count - 1, len(restart_delays) - 1)
                ]
            )
            warn(
                f"Supervisor reiniciará el monitor en {delay:.0f}s sin "
                "re-ejecutar payloads remotos."
            )
            await asyncio.sleep(max(0.5, delay))

            manifest = store.read(job_id)
            manifest["Status"] = "MONITORING"
            manifest["ControllerRuntimeState"] = "RECOVERING"
            manifest["ControllerMonitorRestartCount"] = monitor_restart_count
            store.write(manifest)

            # Rehacer transporte local; los Jobs remotos no cambian.
            try:
                process_registry.clear_stale_files()
            except Exception as cleanup_exc:
                warn(f"PROCESS_REGISTRY_CLEANUP_WARNING: {cleanup_exc}")
            transport = build_transport(
                cfg, user, key, known_hosts,
                transport_profile=profile_from_manifest(manifest),
            )
            transport.attach_registry(process_registry)

    if manifest.get("CancelRequested") or store.cancel_requested(job_id):
        latest = store.read(job_id)
        log("Monitor finalizado por cancelación; se omite formateo/recolección adicional.")
        return 2

    finalize_manifest(manifest, store)

    log("Todos los jobs remotos alcanzaron un estado terminal.")
    log("Generando documento final EXCLUSIVAMENTE en la PC administrativa.")

    created = format_job(
        manifest,
        export_format=getattr(args, "export", None),
    )

    manifest["ResultFiles"] = [str(x) for x in created]
    finalize_manifest(manifest, store)

    for path in created:
        ok(f"Resultado local: {path}")

    print_status_table(manifest)
    finish_runtime(
        "COMPLETED"
        if manifest.get("Status") in {"COMPLETED", "COMPLETED_WITH_SKIPPED"}
        else str(manifest.get("Status") or "EXITED")
    )

    return 0 if manifest["Status"] == "COMPLETED" else 2


async def command_skip_site(args: argparse.Namespace) -> int:
    cfg,inventory,user,key,known_hosts,_,_,_,store=prepare(args)
    manifest=store.read(args.job_id); code=str(args.site_code)
    entry=(manifest.get("Sites") or {}).get(code)
    if not isinstance(entry,dict): raise ValueError(f"La sede {code} no pertenece al Job {args.job_id}.")
    dispatch=str(entry.get("DispatchStatus") or "").upper(); remote=str(entry.get("RemoteState") or "").upper()
    if dispatch=="DISPATCHED" or remote in {"RUNNING","RESULT_READY","RESULT_READY_WITH_ERRORS","COLLECTED","COLLECTED_WITH_ERRORS"}:
        raise ValueError("La sede ya inició el Job remoto; PASAR SEDE solo aplica antes de confirmar SSH_STARTED.")
    store.request_site_skip(args.job_id,code,requested_by="GIDEON administrator",source="fanout skip-site")
    registry=LocalProcessRegistry(store.root,args.job_id); report=registry.terminate_site_transports(code)
    ok(f"PASAR SEDE {code}: SFTP/controles liberados={len(report['Terminated'])}; SSH_START protegidos={len(report['Protected'])}.")
    return 0


def _retryable_site_codes(manifest:dict[str,Any])->list[str]:
    return [str(code) for code,e in (manifest.get("Sites") or {}).items() if e.get("DispatchStatus") in {"FAILED","DEFERRED"} or bool(e.get("RetryEligible"))]


async def command_retry_failed(args: argparse.Namespace) -> int:
    cfg,inventory,user,key,known_hosts,results_dir,raw_dir,worker_path,store=prepare(args)
    manifest=store.read(args.job_id); codes=_retryable_site_codes(manifest)
    if not codes: log("No hay sedes reintentables."); return 0
    lookup={s.code:s for s in inventory.sites}; sites=[lookup[c] for c in codes if c in lookup]
    SSHAgent(key).load()
    registry=LocalProcessRegistry(store.root,args.job_id)
    transport=build_transport(
        cfg,user,key,known_hosts,
        transport_profile=profile_from_manifest(manifest),
    )
    transport.attach_registry(registry)
    truly=[]
    for site in sites:
        old=dict(manifest["Sites"][site.code])
        try: checked=await asyncio.wait_for(poll_site(transport=transport,site=site,entry=old),timeout=12.0)
        except Exception: checked=old
        remote=str(checked.get("RemoteState") or "").upper()
        if remote in {"DISPATCHED","RUNNING","RESULT_READY","RESULT_READY_WITH_ERRORS","COLLECTED","COLLECTED_WITH_ERRORS"}:
            checked["DispatchStatus"]="DISPATCHED"; checked["RetryEligible"]=False; checked["RetryReconciledRemote"]=True; manifest["Sites"][site.code]=checked
            ok(f"{site.label}: reconciliado; Job remoto ya existe y NO se reenvía.")
        else: truly.append(site)
    manifest["RetryRound"]=int(manifest.get("RetryRound",0) or 0)+1; manifest["RetryStartedAt"]=now_iso(); manifest["Status"]="DISPATCHING"; manifest["ActionRequired"]=None; manifest["UnresolvedSitesIgnored"]=False
    for site in truly:
        e=manifest["Sites"][site.code]; e.update({"RetryGeneration":int(e.get("RetryGeneration",0) or 0)+1,"DispatchStatus":"PENDING","RemoteState":"PENDING_RETRY","TransferStatus":"PENDING","StartStatus":"PENDING","RetryEligible":False,"DispatchError":None,"Error":None}); store.clear_site_skip(args.job_id,site.code)
    recalc_manifest(manifest); store.write(manifest)
    if truly:
        script_paths=[Path(str(x.get("Path"))) for x in (manifest.get("Scripts") or []) if x.get("Path")]
        missing=[x for x in script_paths if not x.exists()]
        if missing: raise FileNotFoundError("Scripts originales no disponibles: "+", ".join(map(str,missing)))
        fanout_cfg=cfg.get("fanout",{}); packages_root=ensure_dir(expand_path(cfg.get("paths",{}).get("packages_dir","%LOCALAPPDATA%\\GIDEONSSH\\packages")))
        starter_cfg=fanout_cfg.get("remote_starter",str(DEFAULT_STARTER)); starter_text=str(starter_cfg or DEFAULT_STARTER).replace("\\",os.sep)
        starter_path=expand_path(SCRIPT_DIR/starter_text) if starter_text and not Path(starter_text).is_absolute() else expand_path(starter_text or DEFAULT_STARTER)
        await dispatch_job(manifest=manifest,store=store,transport=transport,inventory_sites=truly,script_paths=script_paths,worker_path=worker_path,starter_path=starter_path,packages_root=packages_root,remote_root=str(fanout_cfg.get("remote_job_root",r"C:\ProgramData\GIDEONSSH\jobs")),task_prefix=str(fanout_cfg.get("task_prefix","GIDEONSSH")),workers=int(fanout_cfg.get("dispatch_workers",6)),stagger_ms=int(fanout_cfg.get("dispatch_stagger_ms",150)),continue_on_error=bool(manifest.get("ContinueOnError",True)),adaptive_vpn_cfg=dict(cfg.get("adaptive_vpn",{}) or {}),connectivity_cfg=dict(cfg.get("connectivity",{}) or {}),site_deadline_seconds=float(fanout_cfg.get("dispatch_site_deadline_seconds",45)))
        manifest=store.read(args.job_id); manifest["DispatchAttempted"]=sum(1 for e in manifest["Sites"].values() if e.get("DispatchStatus") not in {None,"","PENDING"}); recalc_manifest(manifest); store.write(manifest)
    return await command_resume_id(args=args,job_id=args.job_id,prepared=(cfg,inventory,user,key,known_hosts,results_dir,raw_dir,worker_path,store))


async def command_ignore_failed(args: argparse.Namespace) -> int:
    cfg,inventory,user,key,known_hosts,_,_,_,store=prepare(args); manifest=store.read(args.job_id); codes=_retryable_site_codes(manifest)
    if not codes: log("No hay sedes reintentables para omitir."); finalize_manifest(manifest,store); return 0
    for code in codes:
        e=manifest["Sites"][code]; e.update({"DispatchStatus":"IGNORED","RemoteState":"IGNORED","RetryEligible":False,"IgnoredAt":now_iso(),"IgnoredBy":"GIDEON administrator","Error":None}); store.clear_site_skip(args.job_id,code)
    manifest["UnresolvedSitesIgnored"]=True; manifest["ActionRequired"]=None; recalc_manifest(manifest); finalize_manifest(manifest,store)
    ok(f"{len(codes)} sede(s) omitidas. Estado={manifest.get('Status')}"); return 0


async def command_status(args: argparse.Namespace) -> int:
    (
        cfg, inventory, user, key, known_hosts,
        _, _, _, store,
    ) = prepare(args)

    manifest = store.read(args.job_id)
    manifest["StatusCommandPid"] = os.getpid()
    store.write(manifest)
    SSHAgent(key).load()
    process_registry = LocalProcessRegistry(store.root, args.job_id)
    transport = build_transport(
        cfg, user, key, known_hosts,
        transport_profile=profile_from_manifest(manifest),
    )
    transport.attach_registry(process_registry)

    fanout_cfg = cfg.get("fanout", {})

    manifest = await poll_and_collect(
        manifest=manifest,
        store=store,
        inventory=inventory,
        transport=transport,
        poll_workers=int(
            args.poll_workers
            or fanout_cfg.get("poll_workers", 8)
        ),
        poll_interval=3,
        cleanup_after_collect=False,
        until_done=False,
        adaptive_vpn_cfg=(dict(cfg.get("adaptive_vpn", {}) or {}) if manifest.get("AdaptiveVpnEnabled", True) else {"enabled": False}),
        connectivity_cfg=dict(cfg.get("connectivity", {}) or {}),
    )

    store.write(manifest)
    return 0


async def command_cancel(args: argparse.Namespace) -> int:
    (
        cfg, inventory, user, key, known_hosts,
        _, _, _, store,
    ) = prepare(args)

    # Sidecar primero: el monitor activo lo detecta aunque tenga un manifest
    # antiguo en memoria.
    store.request_cancel(
        args.job_id,
        requested_by="GIDEON administrator",
        source="fanout cancel",
    )

    manifest = store.read(args.job_id)
    mark_cancel_requested(
        manifest,
        source="fanout cancel",
    )
    manifest["CancelCommandPid"] = os.getpid()

    # Compatibilidad con jobs creados por una versión anterior: la GUI puede
    # pasar el PID del backend que inició/monitorea este Job. El PID SIEMPRE se
    # valida por Name+CommandLine antes de terminarlo.
    supplied_controller_pid = int(getattr(args, "controller_pid", 0) or 0)
    if supplied_controller_pid > 0 and not manifest.get("MonitorPid"):
        manifest["MonitorPid"] = supplied_controller_pid
    if supplied_controller_pid > 0 and not manifest.get("ControllerPid"):
        manifest["ControllerPid"] = supplied_controller_pid

    _safe_cancel_store_write(
        store, manifest, context="solicitud inicial de cancelación"
    )

    process_registry = LocalProcessRegistry(store.root, args.job_id)

    # FASE LOCAL COOPERATIVA: dar al monitor/controlador oportunidad de ver
    # el sidecar y salir limpiamente antes de aplicar taskkill. Primero cerramos
    # transportes registrados si siguen activos; eso desbloquea communicate().
    graceful_wait = max(0.5, float(cfg.get("fanout", {}).get(
        "cancel_graceful_controller_seconds", 2.5
    )))
    controller_pids = []
    for key_name in ("MonitorPid", "ControllerPid", "DispatchPid"):
        try:
            candidate = int(manifest.get(key_name) or 0)
        except Exception:
            candidate = 0
        if candidate > 0 and candidate != os.getpid() and candidate not in controller_pids:
            controller_pids.append(candidate)

    deadline = time.monotonic() + graceful_wait
    while controller_pids and time.monotonic() < deadline:
        alive = [pid for pid in controller_pids if _windows_process_exists(pid)]
        if not alive:
            break
        await asyncio.sleep(0.20)
        controller_pids = alive

    # Si el controlador está atrapado en un SSH/SFTP, cerrar SOLO esos hijos
    # registrados y esperar un breve segundo tramo cooperativo.
    for row in process_registry.entries():
        try:
            pid = int(row.get("Pid") or 0)
        except Exception:
            pid = 0
        if pid > 0 and _windows_process_exists(pid):
            info = _windows_process_info(pid)
            if info and _is_tracked_transport_process(info):
                _terminate_windows_tree(pid)
                process_registry.unregister(pid)

    second_deadline = time.monotonic() + max(0.5, graceful_wait / 2.0)
    while controller_pids and time.monotonic() < second_deadline:
        alive = [pid for pid in controller_pids if _windows_process_exists(pid)]
        if not alive:
            break
        await asyncio.sleep(0.20)
        controller_pids = alive

    # Fallback final: release_local_job_runtime fuerza solo PIDs validados del Job.
    local_cleanup_initial = release_local_job_runtime(
        manifest=manifest,
        store=store,
        registry=process_registry,
        reason="Cancel Job - cierre cooperativo + fallback de procesos/conexiones",
        exclude_pids={os.getpid()},
    )
    log(
        "Cancel local: controladores cerrados="
        f"{len(local_cleanup_initial.get('ControllerTerminated', []))}; "
        "SSH/SFTP cerrados="
        f"{len(local_cleanup_initial.get('TransportTerminated', []))}; "
        "restantes="
        f"{len(local_cleanup_initial.get('RemainingTransportPids', []))}."
    )

    # Si ya estaba totalmente cancelado, la fase local anterior aún garantiza
    # la liberación de conexiones/procesos residuales.
    if cancellation_completed(manifest):
        return 0

    SSHAgent(key).load()
    transport = build_transport(
        cfg, user, key, known_hosts,
        transport_profile=profile_from_manifest(manifest),
    )
    transport.attach_registry(process_registry)
    cancel_cfg = cfg.get("fanout", {})
    transport.timeout = max(3, int(
        cancel_cfg.get("cancel_connect_timeout_seconds", 8)
    ))
    transport.attempts = max(1, int(
        cancel_cfg.get("cancel_retry_attempts", 2)
    ))

    await cancel_remote_job(
        manifest=manifest,
        store=store,
        inventory=inventory,
        transport=transport,
        workers=int(
            cfg.get("fanout", {}).get(
                "cancel_workers",
                cfg.get("fanout", {}).get("poll_workers", 8),
            )
        ),
    )

    try:
        persisted_after_cancel = store.read(args.job_id)
    except Exception:
        persisted_after_cancel = {}

    if str(persisted_after_cancel.get("Status") or "").upper() in {
        "CANCELLED", "CANCELLED_WITH_ERRORS"
    }:
        final = persisted_after_cancel
    else:
        final = dict(manifest)

    # FASE LOCAL FINAL: cualquier ssh/sftp que haya quedado colgado durante la
    # cancelación se cierra por PID registrado. No se toca ssh-agent ni
    # conexiones pertenecientes a otros Jobs.
    final_cleanup = release_local_job_runtime(
        manifest=final,
        store=store,
        registry=process_registry,
        reason="Cancel Job - barrido final de conexiones/procesos",
        exclude_pids={os.getpid()},
    )
    final["LocalRuntimeCleanupInitial"] = local_cleanup_initial
    final["LocalRuntimeCleanupFinal"] = final_cleanup
    final["LocalConnectionsReleased"] = bool(
        final_cleanup.get("ConnectionsReleased")
    )
    _safe_cancel_store_write(
        store, final, context="barrido local final"
    )

    # Guardia de compatibilidad: un backend antiguo (v2.9.x) que haya
    # iniciado el Job antes de actualizar la aplicación puede escribir un
    # manifest viejo después de la cancelación. Durante una ventana corta
    # re-afirmamos el estado terminal para evitar que visualmente "reviva".
    guard_seconds = max(0, int(
        cfg.get("fanout", {}).get("cancel_guard_seconds", 2)
    ))
    terminal_snapshot = dict(final)
    for _ in range(guard_seconds):
        await asyncio.sleep(1)
        try:
            current = store.read(args.job_id)
        except Exception:
            break
        if str(current.get("Status") or "").upper() not in {
            "CANCELLED", "CANCELLED_WITH_ERRORS"
        }:
            terminal_snapshot["UpdatedAt"] = now_iso()
            terminal_snapshot["CancelGuardReassertedAt"] = now_iso()
            _safe_cancel_store_write(
                store, terminal_snapshot,
                context="guardia terminal de compatibilidad",
            )

    try:
        final_disk = store.read(args.job_id)
        if str(final_disk.get("Status") or "").upper() in {
            "CANCELLED", "CANCELLED_WITH_ERRORS"
        }:
            final = final_disk
    except Exception as exc:
        warn(f"CANCEL_FINAL_READ_WARNING {args.job_id}: {exc}")

    return 0 if final.get("Status") == "CANCELLED" else 2


async def command_cleanup(args: argparse.Namespace) -> int:
    (
        cfg, inventory, user, key, known_hosts,
        _, _, _, store,
    ) = prepare(args)

    manifest = store.read(args.job_id)
    SSHAgent(key).load()
    process_registry = LocalProcessRegistry(store.root, args.job_id)
    transport = build_transport(
        cfg, user, key, known_hosts,
        transport_profile=profile_from_manifest(manifest),
    )
    transport.attach_registry(process_registry)

    await cleanup_job(
        manifest=manifest,
        store=store,
        inventory=inventory,
        transport=transport,
        workers=int(
            cfg.get("fanout", {}).get(
                "cancel_workers",
                cfg.get("fanout", {}).get("poll_workers", 8),
            )
        ),
    )
    return 0


async def command_shutdown(args: argparse.Namespace) -> int:
    (
        cfg, inventory, user, key, known_hosts,
        _, _, _, store,
    ) = prepare(args)

    active = [
        job
        for job in store.list()
        if job.get("Status") not in {
            "COMPLETED",
            "COMPLETED_WITH_ERRORS",
            "CANCELLED",
        }
    ]

    if not active:
        print("No hay fan-out jobs activos.")
        return 0

    if not args.confirm_all:
        print("Fan-out jobs activos:")
        for job in active:
            print(f"  {job.get('JobId')}  {job.get('Status')}")
        raise ValueError(
            "fanout shutdown requiere --confirm-all."
        )

    SSHAgent(key).load()

    for manifest in active:
        transport = build_transport(
            cfg, user, key, known_hosts,
            transport_profile=profile_from_manifest(manifest),
        )
        print(f"Cancelando fan-out job {manifest['JobId']}...")
        await cancel_remote_job(
            manifest=manifest,
            store=store,
            inventory=inventory,
            transport=transport,
            workers=int(
                cfg.get("fanout", {}).get("poll_workers", 8)
            ),
        )

    return 0


async def command_vpn_status(args:argparse.Namespace)->int:
    cfg,inventory,user,key,known_hosts,results_dir,raw_dir,worker_path,store=prepare(args)
    acfg=dict(cfg.get("adaptive_vpn",{}) or {})
    if args.sample_seconds is not None:acfg["sample_seconds"]=float(args.sample_seconds)
    sites=inventory.resolve(parse_targets_text(args.targets),allow_all=False) if args.targets else inventory.sites[:max(1,int(acfg.get("ping_targets",3)))]
    health=await measure_vpn_health(acfg,[s.ip for s in sites],sample_seconds=args.sample_seconds);maximum=int(cfg.get("fanout",{}).get("dispatch_workers",6));workers,reason=recommend_vpn_concurrency(health,acfg,max_workers=maximum);print_vpn_health(health,workers,reason,phase="STATUS LOCAL")
    print('Targets de latencia:')
    for row in health.get("Ping",[]):print(f"  {row.get('Target'):<16} lat={row.get('AvgLatencyMs')}ms loss={row.get('LossPct')}% recv={row.get('Received')}/{row.get('Sent')}")
    print();print(f"Recomendación actual de dispatch : {workers} conexiones simultáneas");print(f"Motivo                           : {reason}");print();print('LinkSpeed del adaptador virtual es informativo; la decisión usa tráfico observado, latencia, pérdida y SSH activos.')
    return 0

def command_jobs(args: argparse.Namespace) -> int:
    *_, store = prepare(args)
    jobs = store.list()[:args.limit]

    if not jobs:
        print("No hay fan-out jobs.")
        return 0

    print(
        f"{'JOB ID':<24} {'STATUS':<24} "
        f"{'DISPATCH':<12} {'COLLECTED':<12} CREATED"
    )
    print("-" * 100)

    for job in jobs:
        print(
            f"{str(job.get('JobId','')):<24} "
            f"{str(job.get('Status','')):<24} "
            f"{str(job.get('DispatchOk',0)) + '/' + str(job.get('TotalCount',0)):<12} "
            f"{str(job.get('CollectedCount',0)) + '/' + str(job.get('TotalCount',0)):<12} "
            f"{job.get('CreatedAt','')}"
        )

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gideon_admin.py fanout",
        description=(
            "GIDEON Fan-Out v6.2.0: transporte Agentless seleccionable por Job: "
            "SFTP→SSH→SFTP, SCP→SSH→SCP o STDIN/SSH→SSH→SCP."
        ),
    )

    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--sites-file", type=Path, default=DEFAULT_SITES)
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    sub = parser.add_subparsers(dest="action", required=True)

    def targets(p):
        g = p.add_mutually_exclusive_group(required=True)
        g.add_argument("--targets")
        g.add_argument("--all", action="store_true")
        p.add_argument("--confirm-all", action="store_true")

    dispatch = sub.add_parser(
        "dispatch",
        help="Distribuye el script y retorna cuando cada servidor inició su job.",
    )
    targets(dispatch)
    dispatch.add_argument("--script", type=Path, action="append", required=True, help="Puede repetirse. Todos los scripts viajan en un único paquete por sede.")
    dispatch.add_argument("--job-id", help=argparse.SUPPRESS)
    dispatch.add_argument(
        "--transport-profile",
        choices=sorted(VALID_TRANSPORT_PROFILES),
        default=None,
        help=(
            "Perfil Agentless del Job. Si se omite, usa fanout.transport_profile "
            "o SFTP_SSH_SFTP."
        ),
    )
    dispatch.add_argument("--sites-file", type=Path, default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    dispatch.add_argument("--export", choices=["xlsx","csv","json","txt","none"], default="xlsx")
    dispatch.add_argument("--dispatch-workers", type=int)
    dispatch.add_argument("--stagger-ms", type=int)
    dispatch.add_argument("--poll-interval", type=int)
    dispatch.add_argument("--fixed-concurrency", action="store_true", help="Desactiva ajuste automático por salud de VPN.")
    dispatch_error = dispatch.add_mutually_exclusive_group()
    dispatch_error.add_argument(
        "--stop-on-error",
        action="store_true",
        help="Detiene los scripts siguientes de una sede si uno falla.",
    )
    dispatch_error.add_argument(
        "--continue-on-error",
        action="store_true",
        help="Continúa con los scripts siguientes aunque uno falle.",
    )
    dispatch.add_argument(
        "--wait",
        action="store_true",
        help="Después del dispatch, espera, recolecta y genera el reporte.",
    )

    run = sub.add_parser(
        "run",
        help="Dispatch general + espera + recolección + formato local.",
    )
    targets(run)
    run.add_argument("--script", type=Path, action="append", required=True, help="Puede repetirse. Todos los scripts viajan en un único paquete por sede.")
    run.add_argument("--job-id", help=argparse.SUPPRESS)
    run.add_argument(
        "--transport-profile",
        choices=sorted(VALID_TRANSPORT_PROFILES),
        default=None,
        help=(
            "Perfil Agentless del Job. Si se omite, usa fanout.transport_profile "
            "o SFTP_SSH_SFTP."
        ),
    )
    run.add_argument("--sites-file", type=Path, default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    run.add_argument("--export", choices=["xlsx","csv","json","txt","none"], default="xlsx")
    run.add_argument("--dispatch-workers", type=int)
    run.add_argument("--poll-workers", type=int)
    run.add_argument("--stagger-ms", type=int)
    run.add_argument("--poll-interval", type=int)
    run.add_argument("--fixed-concurrency", action="store_true", help="Desactiva ajuste automático por salud de VPN.")
    run_error = run.add_mutually_exclusive_group()
    run_error.add_argument(
        "--stop-on-error",
        action="store_true",
        help="Detiene los scripts siguientes de una sede si uno falla.",
    )
    run_error.add_argument(
        "--continue-on-error",
        action="store_true",
        help="Continúa con los scripts siguientes aunque uno falle.",
    )

    resume = sub.add_parser(
        "resume",
        help="Retoma monitoreo/recolección de un fan-out job.",
    )
    resume.add_argument("job_id")
    resume.add_argument("--poll-workers", type=int)
    resume.add_argument("--poll-interval", type=int)
    resume.add_argument("--export", choices=["xlsx","csv","json","txt","none"])

    skip_site=sub.add_parser("skip-site",help="Pasa una sede durante Dispatch sin detener las demás.")
    skip_site.add_argument("job_id"); skip_site.add_argument("site_code")
    retry_failed=sub.add_parser("retry-failed",help="Reintenta solo sedes fallidas/diferidas.")
    retry_failed.add_argument("job_id"); retry_failed.add_argument("--poll-workers",type=int); retry_failed.add_argument("--poll-interval",type=int); retry_failed.add_argument("--export",choices=["xlsx","csv","json","txt","none"])
    ignore_failed=sub.add_parser("ignore-failed",help="Omite sedes fallidas/diferidas y finaliza.")
    ignore_failed.add_argument("job_id")

    status = sub.add_parser(
        "status",
        help="Hace un sondeo inmediato y muestra estados remotos.",
    )
    status.add_argument("job_id")
    status.add_argument("--poll-workers", type=int)

    jobs = sub.add_parser("jobs", help="Lista fan-out jobs.")
    jobs.add_argument("--limit", type=int, default=20)

    cancel = sub.add_parser(
        "cancel",
        help="Detiene las tareas programadas remotas del fan-out job.",
    )
    cancel.add_argument("job_id")
    cancel.add_argument(
        "--controller-pid",
        type=int,
        help=argparse.SUPPRESS,
    )

    cleanup = sub.add_parser(
        "cleanup",
        help="Elimina tareas y carpetas remotas de un fan-out job.",
    )
    cleanup.add_argument("job_id")

    vpn = sub.add_parser("vpn-status", help="Detecta la interfaz/ruta activa, mide tráfico y recomienda concurrencia segura.")
    vpn.add_argument("--sample-seconds", type=float)
    vpn.add_argument("--targets", help="Códigos/IPs separados por coma para medir latencia.")

    shutdown = sub.add_parser(
        "shutdown",
        help="Cancela todos los fan-out jobs activos.",
    )
    shutdown.add_argument("--confirm-all", action="store_true")

    return parser


async def async_main(args: argparse.Namespace) -> int:
    if args.action == "dispatch":
        return await command_dispatch(args)

    if args.action == "run":
        # run = dispatch --wait
        args.wait = True
        return await command_dispatch(args)

    if args.action == "resume":
        return await command_resume_id(
            args=args,
            job_id=args.job_id,
        )

    if args.action == "skip-site": return await command_skip_site(args)
    if args.action == "retry-failed": return await command_retry_failed(args)
    if args.action == "ignore-failed": return await command_ignore_failed(args)
    if args.action == "status":
        return await command_status(args)

    if args.action == "cancel":
        return await command_cancel(args)

    if args.action == "cleanup":
        return await command_cleanup(args)

    if args.action == "shutdown":
        return await command_shutdown(args)

    if args.action == "vpn-status":
        return await command_vpn_status(args)

    if args.action == "jobs":
        return command_jobs(args)

    raise ValueError(f"Acción no soportada: {args.action}")


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        return asyncio.run(async_main(args))
    except KeyboardInterrupt:
        finish_runtime("INTERRUPTED")
        print("\nInterrumpido en la PC. Los jobs remotos NO se cancelan automáticamente.")
        print("Para retomarlos use: py gideon_admin.py fanout resume <JOB_ID>")
        return 130
    except Exception as exc:
        report_runtime_exception(
            exc,
            phase="CONTROLLER_MAIN",
            recovering=False,
        )
        finish_runtime("FAILED")
        raise


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        fail(str(exc))
        raise SystemExit(1)
