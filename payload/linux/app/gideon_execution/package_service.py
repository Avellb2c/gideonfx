from __future__ import annotations

"""Build immutable per-target execution packages.

This module owns the package contract that is transferred to an Agentless host.
Keeping it outside ``gideon_fanout`` prevents the CLI orchestration layer from also
being responsible for hashing, copying and serialising executable payloads.
"""

import json
import shutil
import uuid
from pathlib import Path
from typing import Any, Optional

from gideon_admin import Site, ensure_dir, now_iso
from gideon_common.hashing import sha256_file
from gideon_core.protocol import ARCHITECTURE_ID, PROTOCOL_VERSION, REMOTE_PACKAGE_SCHEMA_VERSION
from gideon_execution.logging_utils import warn
from gideon_execution.runtime_service import safe_component
from gideon_io import atomic_write_json as io_atomic_write_json


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    io_atomic_write_json(path, payload, lock_timeout=2.0, retries=8)


def load_script_execution_metadata(source: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load ``<script>.execution.json`` with bounded, safe defaults."""
    execution = {
        "Isolation": "Process",
        "TimeoutSeconds": 1800,
        "CancelGraceSeconds": 5,
        "PartialResults": True,
    }
    parameters: dict[str, Any] = {}
    sidecar = source.with_suffix(".execution.json")
    if sidecar.exists():
        try:
            value = json.loads(sidecar.read_text(encoding="utf-8-sig"))
            if isinstance(value, dict):
                if isinstance(value.get("Execution"), dict):
                    execution.update(value["Execution"])
                if isinstance(value.get("Parameters"), dict):
                    parameters.update(value["Parameters"])
        except Exception as exc:
            warn(f"Sidecar de ejecución inválido {sidecar.name}: {exc}; usando defaults.")
    execution["Isolation"] = "Process"
    execution["TimeoutSeconds"] = max(30, min(int(execution.get("TimeoutSeconds", 1800) or 1800), 86400))
    execution["CancelGraceSeconds"] = max(1, min(int(execution.get("CancelGraceSeconds", 5) or 5), 30))
    execution["PartialResults"] = bool(execution.get("PartialResults", True))
    return execution, parameters


def script_definition_from_path(
    source: Path,
    index: int,
    *,
    sha256: str | None = None,
    size_bytes: int | None = None,
) -> dict[str, Any]:
    stem = safe_component(source.stem, fallback=f"script_{index}")
    execution, parameters = load_script_execution_metadata(source)
    return {
        "Index": index,
        "Name": source.stem,
        "RemoteName": f"{index:02d}_{stem}.ps1",
        "ResultName": f"{index:02d}_{stem}.json",
        "Sha256": sha256 or sha256_file(source),
        "SizeBytes": int(size_bytes or source.stat().st_size),
        "Execution": execution,
        "Parameters": parameters,
    }


def build_site_package(
    *,
    site: Site,
    job_id: str,
    script_paths: list[Path],
    worker_path: Path,
    starter_path: Path,
    packages_root: Path,
    remote_job_root: str,
    task_prefix: str,
    continue_on_error: bool,
    static_meta: Optional[dict[str, dict[str, Any]]] = None,
) -> dict[str, Any]:
    package_dir = ensure_dir(packages_root / job_id / site.code)
    scripts_dir = ensure_dir(package_dir / "scripts")

    for old in scripts_dir.glob("*"):
        if old.is_file():
            old.unlink()

    local_worker = package_dir / "remote_job_worker.ps1"
    local_starter = package_dir / "start_job.ps1"
    local_host = package_dir / "gideon_script_host.ps1"
    shutil.copy2(worker_path, local_worker)
    shutil.copy2(starter_path, local_starter)
    host_path = worker_path.parent / "gideon_script_host.ps1"
    if not host_path.exists():
        raise FileNotFoundError(f"Script Execution Host no encontrado: {host_path}")
    shutil.copy2(host_path, local_host)
    static_meta = static_meta or {}

    script_defs: list[dict[str, Any]] = []
    for index, source in enumerate(script_paths, 1):
        stem = safe_component(source.stem, fallback=f"script_{index}")
        remote_name = f"{index:02d}_{stem}.ps1"
        result_name = f"{index:02d}_{stem}.json"
        copied = scripts_dir / remote_name
        shutil.copy2(source, copied)
        source_key = str(source.resolve())
        meta = static_meta.get(source_key) or {}
        script_def = script_definition_from_path(
            source,
            index,
            sha256=meta.get("Sha256") or sha256_file(copied),
            size_bytes=int(meta.get("SizeBytes") or copied.stat().st_size),
        )
        script_def["RemoteName"] = remote_name
        script_def["ResultName"] = result_name
        script_defs.append(script_def)

    remote_root = remote_job_root.rstrip("\\") + "\\" + job_id
    task_name = f"{task_prefix}_{job_id}_{site.code}"
    collection_folder = f"GIDEONSSH_RESULT_{safe_component(job_id)}"
    upload_folder = (
        f"GIDEONSSH_UPLOAD_{safe_component(job_id)}_"
        f"{safe_component(site.code)}_{uuid.uuid4().hex[:6]}"
    )

    payload = {
        "SchemaVersion": REMOTE_PACKAGE_SCHEMA_VERSION,
        "ProtocolVersion": PROTOCOL_VERSION,
        "Architecture": ARCHITECTURE_ID,
        "JobId": job_id,
        "SiteCode": site.code,
        "SiteName": site.name,
        "AgentId": getattr(site, "agent_id", "") or "",
        "AgentName": getattr(site, "agent_name", "") or "",
        "Hostname": getattr(site, "hostname", "") or "",
        "ServerIP": site.ip,
        "TaskName": task_name,
        "RemoteJobRoot": remote_root,
        "CollectionFolderName": collection_folder,
        "ContinueOnError": bool(continue_on_error),
        "ScriptCount": len(script_defs),
        "CreatedAt": now_iso(),
        "WorkerSha256": (static_meta.get(str(worker_path.resolve())) or {}).get("Sha256") or sha256_file(local_worker),
        "ScriptHostSha256": (static_meta.get(str(host_path.resolve())) or {}).get("Sha256") or sha256_file(local_host),
        "WorkerSizeBytes": int((static_meta.get(str(worker_path.resolve())) or {}).get("SizeBytes") or local_worker.stat().st_size),
        "Scripts": script_defs,
    }

    job_json = package_dir / "job.json"
    _atomic_write_json(job_json, payload)

    return {
        "PackageDir": str(package_dir),
        "JobJson": str(job_json),
        "Worker": str(local_worker),
        "Starter": str(local_starter),
        "ScriptHost": str(local_host),
        "ScriptsDir": str(scripts_dir),
        "Scripts": script_defs,
        "ManifestSha256": sha256_file(job_json),
        "StarterSha256": (static_meta.get(str(starter_path.resolve())) or {}).get("Sha256") or sha256_file(local_starter),
        "UploadFolderName": upload_folder,
        "CollectionFolderName": collection_folder,
        "RemoteJobRoot": remote_root,
        "TaskName": task_name,
        "PackageBytes": (
            job_json.stat().st_size
            + local_worker.stat().st_size
            + local_starter.stat().st_size
            + local_host.stat().st_size
            + sum((scripts_dir / x["RemoteName"]).stat().st_size for x in script_defs)
        ),
    }


__all__ = [
    "build_site_package",
    "load_script_execution_metadata",
    "script_definition_from_path",
]
