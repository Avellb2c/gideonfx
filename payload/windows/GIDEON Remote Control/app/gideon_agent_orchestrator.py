#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GIDEON Agent HTTPS/PULL orchestrator v2.0.

Optional alternative to the existing SSH/SFTP fan-out.
It writes the same local fanout manifest family so the existing GUI/Control Center
can visualize Jobs from either execution method.
"""
from __future__ import annotations

from gideon_common.observability import best_effort_warning

import argparse
import asyncio
import datetime as dt
import hashlib
import json
import os
import secrets
import sys
from pathlib import Path
import shutil
import time
import zipfile
from typing import Any, Optional

from gideon_agent_http import AgentHttpClient, AgentHttpError
from gideon_agent_runtime import agent_gateway_connection_label, merged_agent_control_plane
from gideon_host_profiles import HostProfileStore
from gideon_agent_builder import AgentBuilder
from gideon_agent_security import sign_file, sign_file_bytes
from gideon_agent_job_contract import AGENT_WORKER_VERSION, build_job_envelope
from gideon_admin import Inventory, load_config, expand_path
from gideon_fanout import (
    DEFAULT_CONFIG,
    DEFAULT_SITES,
    DEFAULT_WORKER,
    DEFAULT_STARTER,
    FanoutStore,
    Site,
    build_site_package,
    ensure_dir,
    make_manifest,
    recalc_manifest,
    finalize_manifest,
    format_job,
    select_sites,
    sha256_file,
    now_iso,
    safe_component,
)


# UTF-8 defensivo para backend Agent iniciado por GUI.
if os.environ.get("GIDEON_FORCE_UTF8_STDIO") == "1":
    for _stream in (sys.stdout, sys.stderr):
        try:
            if hasattr(_stream, "reconfigure"):
                _stream.reconfigure(encoding="utf-8", errors="backslashreplace")
        except Exception as exc:
            best_effort_warning("No se pudo forzar UTF-8 en stdio del orquestador Agent", exc)

VERSION = "2.2.0"
METHOD = "AGENT_HTTPS_PULL"


def zip_directory(source: Path, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    if tmp.exists():
        tmp.unlink()
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as z:
        for p in source.rglob("*"):
            if p.is_file():
                z.write(p, arcname=str(p.relative_to(source)))
    os.replace(tmp, dest)
    return dest


def safe_extract(zip_path: Path, target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    root = target.resolve()
    with zipfile.ZipFile(zip_path, "r") as z:
        for info in z.infolist():
            dest = (target / info.filename).resolve()
            if root not in dest.parents and dest != root:
                raise RuntimeError(f"Unsafe zip entry: {info.filename}")
        z.extractall(target)


def load_runtime(args: argparse.Namespace):
    cfg = load_config(args.config)
    inventory = Inventory(args.sites_file)
    paths = cfg["paths"]
    jobs_dir = expand_path(paths["fanout_jobs_dir"])
    results_dir = expand_path(paths["results_dir"])
    raw_dir = expand_path(paths["raw_dir"])
    packages_dir = expand_path(paths.get("packages_dir", "%LOCALAPPDATA%\\GIDEONSSH\\packages"))
    store = FanoutStore(jobs_dir)

    acfg = merged_agent_control_plane(cfg)
    base_url = str(acfg.get("base_url") or "").strip().rstrip("/")
    if not base_url:
        raise RuntimeError("agent_control_plane.base_url is not configured")
    token = str(acfg.get("admin_api_key") or os.environ.get(str(acfg.get("admin_api_key_env", "GIDEON_AGENT_ADMIN_TOKEN")), ""))
    if not token:
        raise RuntimeError("Agent admin token missing. Set GIDEON_AGENT_ADMIN_TOKEN or config admin_api_key.")
    client = AgentHttpClient(
        base_url,
        bearer_token=token,
        timeout=float(acfg.get("timeout_seconds", 20)),
        verify_tls=bool(acfg.get("verify_tls", True)),
        ca_file=acfg.get("ca_file"),
        require_https=bool(acfg.get("require_https", True)),
    )
    return cfg, inventory, store, results_dir, raw_dir, packages_dir, client


def health(client: AgentHttpClient) -> dict[str, Any]:
    return client.json("GET", "/api/v1/admin/health")


def agents(client: AgentHttpClient) -> list[dict[str, Any]]:
    data = client.json("GET", "/api/v1/admin/agents")
    rows = data.get("Agents") or []
    return [x for x in rows if isinstance(x, dict)]


def agent_is_online(row: dict[str, Any], ttl_seconds: int) -> bool:
    value = row.get("last_seen")
    if not value:
        return False
    try:
        stamp = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        now = dt.datetime.now(stamp.tzinfo) if stamp.tzinfo else dt.datetime.now()
        return (now - stamp).total_seconds() <= ttl_seconds
    except Exception:
        return False


def resolve_agent_profile(
    profiles: HostProfileStore,
    site: Site,
    registered_row: dict[str, Any],
    *,
    override: str | None = None,
    allow_profile_mismatch: bool = False,
) -> dict[str, Any]:
    """Resolve the Job profile with the enrolled Agent as AUTO source of truth.

    Static site assignments describe Agentless/server administration.  An Agent
    may intentionally run a different profile (for example ``windows_generic``
    on a workstation while the store server is Server 2022).  In AUTO mode the
    profile reported by the enrolled Agent therefore wins.  A manual override is
    still honored and mismatch protection remains active.
    """

    registered_profile = str(registered_row.get("host_profile") or "").strip()
    inventory_profile = str(getattr(site, "host_profile", "") or "").strip()
    explicit = str(override or "").strip()

    selected_id = explicit or registered_profile or inventory_profile
    try:
        profile = profiles.resolve(site.code, override=(selected_id or None))
    except KeyError as exc:
        source = "Agent" if registered_profile and selected_id == registered_profile else "inventario/override"
        raise RuntimeError(
            f"HOST_PROFILE_UNKNOWN: {site.label} reporta/selecciona {selected_id or '<vacío>'} "
            f"desde {source}, pero esa plantilla no existe en host_profiles.json."
        ) from exc

    resolved_id = str(profile.get("id") or "").strip()
    if registered_profile and resolved_id != registered_profile and not allow_profile_mismatch:
        raise RuntimeError(
            f"HOST_PROFILE_MISMATCH: Agent {site.label} reporta {registered_profile}, "
            f"Job intenta {resolved_id}. En AUTO se usa el perfil del Agent; "
            "si fuerza otro perfil, corríjalo o use --allow-profile-mismatch solo para diagnóstico."
        )
    return profile


def normalize_agent_site(site: Site, registered_row: dict[str, Any], cfg: dict[str, Any]) -> Site:
    """Return a Site whose routing fields accurately describe Agent transport.

    Older deployment groups can legitimately contain the store/server address in
    ``ServerIP`` because that field was originally shared with Agentless SSH.
    Agent HTTPS/PULL never connects to that address: the enrolled Agent opens the
    outbound HTTPS session to the Gateway and is addressed by ``SiteCode``.

    Preserve the old address only as an explicit Agentless fallback so a user can
    still force SSH/SFTP later without allowing it to leak into Agent dispatch.
    """

    remote_ip = str(registered_row.get("last_remote_ip") or "").strip()
    agentless_ip = str(getattr(site, "agentless_ip", "") or site.ip or "").strip()
    reported_profile = str(registered_row.get("host_profile") or "").strip()
    reported_platform = str(registered_row.get("platform") or "").strip()
    reported_agent_name = str(
        registered_row.get("agent_name") or registered_row.get("hostname") or getattr(site, "agent_name", "") or ""
    ).strip()
    return Site(
        code=site.code,
        name=site.name or str(registered_row.get("site_name") or "").strip(),
        ip="",
        platform=reported_platform or site.platform,
        host_profile=reported_profile or site.host_profile,
        agent_id=str(registered_row.get("agent_id") or getattr(site, "agent_id", "") or "").strip(),
        agent_name=reported_agent_name,
        hostname=str(registered_row.get("hostname") or getattr(site, "hostname", "") or "").strip(),
        agent_connection=agent_gateway_connection_label(cfg, observed_ip=remote_ip),
        agent_remote_ip=remote_ip,
        agentless_ip=agentless_ip,
        source="gateway-agent",
    )


def agent_target_key(site: Site) -> str:
    return str(getattr(site, "agent_id", "") or site.code).strip()


def index_registered_agents(rows: list[dict[str, Any]]) -> tuple[dict[str, dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    by_id: dict[str, dict[str, Any]] = {}
    by_site: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        agent_id = str(row.get("agent_id") or "").strip()
        code = str(row.get("site_code") or "").strip()
        if agent_id:
            by_id[agent_id] = row
        if code:
            by_site.setdefault(code, []).append(row)
    return by_id, by_site


def registered_for_site(site: Site, by_id: dict[str, dict[str, Any]], by_site: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    agent_id = str(getattr(site, "agent_id", "") or "").strip()
    if agent_id:
        return by_id.get(agent_id) or {}
    candidates = by_site.get(site.code) or []
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        raise RuntimeError(
            f"AGENT_TARGET_AMBIGUOUS: {site.code}_{site.name} tiene {len(candidates)} Agents. "
            "Seleccione el equipo/AgentId concreto; SiteCode identifica la sede, no la máquina."
        )
    return {}


def create_agent_manifest(
    *,
    job_id: str,
    scripts: list[Path],
    sites: list[Site],
    cfg: dict[str, Any],
    results_dir: Path,
    raw_dir: Path,
    export_format: str,
    continue_on_error: bool,
    sites_file: str | Path,
) -> dict[str, Any]:
    manifest = make_manifest(
        job_id=job_id,
        script_paths=scripts,
        sites=sites,
        remote_root=r"C:\ProgramData\GIDEONAgent\jobs",
        task_prefix="GIDEONAGENT",
        export_format=export_format,
        results_dir=results_dir,
        raw_dir=raw_dir,
        poll_interval=int(cfg.get("agent_control_plane", {}).get("poll_interval_seconds", 5)),
        continue_on_error=continue_on_error,
    )
    manifest["ExecutionMethod"] = METHOD
    manifest["TransportProfile"] = METHOD
    manifest["SitesFile"] = str(Path(sites_file).resolve())
    manifest["SiteGroupId"] = os.environ.get("GIDEON_SITE_GROUP_ID") or None
    manifest["SiteGroupName"] = os.environ.get("GIDEON_SITE_GROUP_NAME") or None
    manifest["Architecture"] = "GIDEON_DUAL_MODE_AGENT_HTTPS_PULL"
    manifest["Transport"] = {"Distribution": "HTTPS_QUEUE", "Control": "AGENT_PULL", "Collection": "HTTPS_UPLOAD"}
    manifest["ControllerVersion"] = VERSION
    manifest["ControllerPid"] = os.getpid()
    manifest["ControllerStartedAt"] = now_iso()
    manifest["AgentControlPlane"] = str(cfg.get("agent_control_plane", {}).get("base_url") or "")
    by_target = {agent_target_key(site): site for site in sites}
    for target_key, entry in manifest["Sites"].items():
        site = by_target.get(str(target_key))
        # Never publish a server/store IP as the Agent route in a Job manifest.
        # AgentRemoteIP is observational telemetry only and may be NAT/public.
        entry["ServerIP"] = ""
        entry["TargetKey"] = str(target_key)
        entry["AgentId"] = getattr(site, "agent_id", "") if site else entry.get("AgentId", "")
        entry["AgentName"] = getattr(site, "agent_name", "") if site else entry.get("AgentName", "")
        entry["Hostname"] = getattr(site, "hostname", "") if site else entry.get("Hostname", "")
        entry["AgentConnection"] = getattr(site, "agent_connection", "") if site else ""
        entry["AgentRemoteIP"] = getattr(site, "agent_remote_ip", "") if site else ""
        entry["AgentlessIP"] = getattr(site, "agentless_ip", "") if site else ""
        entry["TransportMethod"] = METHOD
        entry["TransferStatus"] = "PENDING"
        entry["StartStatus"] = "PENDING"
        entry["CollectionStatus"] = "PENDING"
        entry["TaskState"] = "Queued"
    return manifest


def _script_execution_meta(path: Path) -> dict[str, Any]:
    sidecars = [
        path.with_suffix(".execution.json"),
        path.parent / f"{path.stem}.execution.json",
    ]
    for sidecar in sidecars:
        if not sidecar.exists():
            continue
        try:
            value = json.loads(sidecar.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except Exception:
            return {}
    return {}


def build_agent_package(
    *,
    site: Site,
    job_id: str,
    scripts: list[Path],
    cfg: dict[str, Any],
    packages_dir: Path,
    continue_on_error: bool,
    profile: dict[str, Any],
    signing_private_key: Path | None,
    signing_key_id: str,
    signing_private_key_bytes: bytes | None = None,
) -> dict[str, Any]:
    """Construye un package neutral de plataforma para GIDEON Agent v2."""
    target_key = safe_component(agent_target_key(site), fallback=site.code)
    package_dir = packages_dir / job_id / f"{target_key}.agent.package"
    if package_dir.exists():
        shutil.rmtree(package_dir, ignore_errors=True)
    (package_dir / "scripts").mkdir(parents=True, exist_ok=True)

    allowed = {str(x).lower() for x in profile.get("allowed_extensions", [])}
    script_rows = []
    for idx, source in enumerate(scripts, 1):
        ext = source.suffix.lower()
        if allowed and ext not in allowed:
            raise RuntimeError(
                f"HOST_PROFILE_SCRIPT_MISMATCH: {site.label} profile={profile.get('id')} "
                f"no permite {ext} ({source.name})"
            )
        result_stem = safe_component(source.stem, fallback=f"script_{idx}")
        packaged_name = f"{idx:02d}_{safe_component(source.name, fallback=f'script_{idx}{ext}')}"
        target = package_dir / "scripts" / packaged_name
        shutil.copy2(source, target)
        meta = _script_execution_meta(source)
        execution = meta.get("Execution") if isinstance(meta.get("Execution"), dict) else {}
        script_rows.append({
            "Index": idx,
            "Name": source.name,
            "Path": str(Path("scripts") / packaged_name),
            "ResultName": f"{idx:02d}_{result_stem}.json",
            "Sha256": sha256_file(target),
            "TimeoutSeconds": int(execution.get("TimeoutSeconds", cfg.get("script_execution", {}).get("default_timeout_seconds", 1800)) or 1800),
            "Arguments": list(meta.get("Arguments") or []),
            "Parameters": dict(meta.get("Parameters") or {}),
            "Environment": dict(meta.get("Environment") or {}),
        })

    # Runtime support files are part of the signed Job contract, not optional
    # conveniences.  RC22 silently skipped gideon_script_host.ps1 when an installed
    # Control Plane was missing that asset, producing a package that the endpoint
    # could only reject after CLAIMED.  Fail before queueing instead.
    support_sources = {
        "gideon_agent_worker.py": Path(__file__).resolve().parent / "gideon_agent_worker.py",
        "gideon_agent_job_contract.py": Path(__file__).resolve().parent / "gideon_agent_job_contract.py",
        "gideon_script_host.ps1": Path(__file__).resolve().parent / "gideon_script_host.ps1",
    }
    missing_support = [name for name, source in support_sources.items() if not source.is_file()]
    if missing_support:
        raise RuntimeError(
            "SCRIPT_PACKAGE_SUPPORT_MISSING: faltan assets obligatorios del Control Plane: "
            + ", ".join(missing_support)
            + ". Repare/actualice GIDEON antes de distribuir el Job."
        )
    for name, source in support_sources.items():
        shutil.copy2(source, package_dir / name)
    (package_dir / "host_profile.json").write_text(
        json.dumps(profile, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    ttl_seconds = max(300, min(int(cfg.get("agent_control_plane", {}).get("job_package_ttl_seconds", 86400) or 86400), 7 * 86400))
    agent_job = build_job_envelope(
        job_id=job_id,
        job_type="SCRIPT_EXECUTION",
        agent_id=getattr(site, "agent_id", "") or "",
        agent_name=getattr(site, "agent_name", "") or "",
        hostname=getattr(site, "hostname", "") or "",
        site_code=site.code,
        site_name=site.name,
        host_profile=profile,
        scripts=script_rows,
        continue_on_error=bool(continue_on_error),
        default_timeout_seconds=int(cfg.get("script_execution", {}).get("default_timeout_seconds", 1800) or 1800),
        ttl_seconds=ttl_seconds,
        required_capabilities=("SIGNED_JOBS", "SCRIPT_EXECUTION", "RESULT_UPLOAD", "CANCELLATION"),
    )
    (package_dir / "agent_job.json").write_text(
        json.dumps(agent_job, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    archive = packages_dir / job_id / f"{target_key}.agent.zip"
    zip_directory(package_dir, archive)
    if signing_private_key_bytes is not None:
        signature = sign_file_bytes(archive, signing_private_key_bytes)
    elif signing_private_key is not None:
        signature = sign_file(archive, signing_private_key)
    else:
        raise RuntimeError("No existe clave privada Ed25519 para firmar el package.")
    return {
        "Archive": archive,
        "Signature": signature,
        "KeyId": signing_key_id,
        "Profile": profile,
        "ScriptCount": len(script_rows),
    }


def apply_gateway_row(entry: dict[str, Any], row: dict[str, Any]) -> dict[str, Any]:
    result = dict(entry)
    gateway_status = str(row.get("status") or "").upper()
    result["TransportMethod"] = METHOD
    result["AgentGatewayStatus"] = gateway_status
    result["AgentLastUpdate"] = row.get("updated_at")
    result["AgentClaimedAt"] = row.get("claimed_at")
    result["AgentCancelRequested"] = bool(row.get("cancel_requested"))

    if gateway_status in {"QUEUED"}:
        result["TransferStatus"] = "HTTPS_UPLOADED"
        result["StartStatus"] = "AGENT_WAITING"
        result["DispatchStatus"] = "DISPATCHED"
        result["RemoteState"] = "DISPATCHED"
        result["TaskState"] = "Queued"
    elif gateway_status in {"CLAIMED", "RUNNING"}:
        result["TransferStatus"] = "HTTPS_UPLOADED"
        result["StartStatus"] = "AGENT_STARTED"
        result["DispatchStatus"] = "DISPATCHED"
        result["RemoteState"] = "RUNNING"
        result["TaskState"] = "Running"
    elif gateway_status == "RESULT_READY":
        result["TransferStatus"] = "HTTPS_UPLOADED"
        result["StartStatus"] = "AGENT_STARTED"
        result["DispatchStatus"] = "DISPATCHED"
        result["RemoteState"] = "RESULT_READY"
        result["TaskState"] = "Ready"
    elif gateway_status == "FAILED":
        result["RemoteState"] = "FAILED"
        result["TaskState"] = "Ready"
        result["Error"] = row.get("error") or "Agent execution failed"
    elif gateway_status == "CANCELLED":
        result["RemoteState"] = "CANCELLED"
        result["TaskState"] = "Ready"

    agent_status = row.get("AgentStatus")
    if isinstance(agent_status, dict):
        status = agent_status.get("Status") if isinstance(agent_status.get("Status"), dict) else {}
        progress = agent_status.get("Progress") if isinstance(agent_status.get("Progress"), dict) else {}
        state = str(agent_status.get("State") or status.get("State") or "").upper()
        if state:
            if state in {"RESULT_READY", "RESULT_READY_WITH_ERRORS"}:
                result["RemoteState"] = state
            elif state == "FAILED":
                result["RemoteState"] = "FAILED"
            elif state == "CANCELLED":
                result["RemoteState"] = "CANCELLED"
            else:
                result["RemoteState"] = "RUNNING"
        if progress:
            result["Progress"] = progress
            result["CurrentScriptIndex"] = int(progress.get("CurrentScriptIndex", result.get("CurrentScriptIndex", 0)) or 0)
            result["CurrentScriptName"] = progress.get("CurrentScriptName") or result.get("CurrentScriptName")
        result["Error"] = agent_status.get("Error") or status.get("Error") or result.get("Error")
        result["TaskState"] = agent_status.get("TaskState") or result.get("TaskState")
    return result


def materialize_result(
    *,
    client: AgentHttpClient,
    job_id: str,
    site: Site,
    entry: dict[str, Any],
    raw_root: Path,
    packages_dir: Path,
) -> dict[str, Any]:
    result = dict(entry)
    target_key = agent_target_key(site)
    safe_target = safe_component(target_key, fallback=site.code)
    archive = packages_dir / job_id / f"{safe_target}.result.zip"
    client.download_file(f"/api/v1/admin/jobs/{job_id}/{target_key}/result", archive, timeout=120)
    local_site_dir = raw_root / f"{site.code}_{safe_component(site.name)}_{safe_target}"
    if local_site_dir.exists():
        shutil.rmtree(local_site_dir, ignore_errors=True)
    extract_dir = packages_dir / job_id / f"{safe_target}.result.extract"
    if extract_dir.exists():
        shutil.rmtree(extract_dir, ignore_errors=True)
    safe_extract(archive, extract_dir)
    collection = extract_dir / "collection"
    if not collection.exists():
        result["CollectionStatus"] = "FAILED"
        result["RemoteState"] = "FAILED"
        result["Error"] = "Agent result archive missing collection/"
        return result
    shutil.copytree(collection, local_site_dir, dirs_exist_ok=True)
    job_result = local_site_dir / "job_result.json"
    if not job_result.exists():
        result["CollectionStatus"] = "FAILED"
        result["RemoteState"] = "FAILED"
        result["Error"] = "Agent result missing job_result.json"
        return result
    try:
        payload = json.loads(job_result.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        result["CollectionStatus"] = "FAILED"
        result["RemoteState"] = "FAILED"
        result["Error"] = f"Agent result parse error: {exc}"
        return result

    result["RawDir"] = str(local_site_dir)
    result["RawFile"] = str(job_result)
    result["AgentId"] = str(payload.get("AgentId") or getattr(site, "agent_id", "") or "")
    result["AgentName"] = str(payload.get("AgentName") or getattr(site, "agent_name", "") or "")
    result["Hostname"] = str(payload.get("Hostname") or getattr(site, "hostname", "") or "")
    scripts_dir = local_site_dir / "scripts"
    result["ScriptResultFiles"] = [str(x) for x in sorted(scripts_dir.glob("*.json"))] if scripts_dir.exists() else []
    result["CollectionStatus"] = "HTTPS_COLLECTED"
    result["CollectionVerified"] = True
    result["CollectedAt"] = now_iso()
    result["RemoteState"] = "COLLECTED" if bool(payload.get("Success")) else "COLLECTED_WITH_ERRORS"
    result["ScriptFailures"] = int(payload.get("ScriptsFailed", 0) or 0)
    result["ScriptSkipped"] = int(payload.get("ScriptsSkipped", 0) or 0)
    metrics = payload.get("Metrics") if isinstance(payload.get("Metrics"), dict) else {}
    if metrics:
        progress = dict(result.get("Progress") or {})
        progress.update({
            "Type": "JOB_COMPLETE",
            "Directories": metrics.get("Directories", 0),
            "BackupFolders": metrics.get("BackupFolders", 0),
            "AccessErrors": metrics.get("AccessErrors", 0),
            "UpdatedAt": now_iso(),
        })
        result["Progress"] = progress
    return result


async def run_job(args: argparse.Namespace) -> int:
    cfg, inventory, store, results_dir, raw_dir, packages_dir, client = load_runtime(args)
    health(client)
    selected = select_sites(inventory, targets=args.targets, all_sites=args.all, confirm_all=args.confirm_all)
    scripts = [expand_path(x) for x in (args.script or [])]
    if not scripts:
        raise ValueError("At least one --script is required")
    for p in scripts:
        if not p.exists() or p.suffix.lower() not in {".ps1", ".py", ".sh", ".command", ".cmd", ".bat"}:
            raise ValueError(f"Unsupported script type: {p}")

    acfg = cfg.get("agent_control_plane", {})
    ttl = int(acfg.get("agent_online_ttl_seconds", 90))
    registered_rows = agents(client)
    registered_by_id, registered_by_site = index_registered_agents(registered_rows)
    online = {agent_id: row for agent_id, row in registered_by_id.items() if agent_is_online(row, ttl)}
    profiles = HostProfileStore(Path(__file__).resolve().parent / "config" / "host_profiles.json")
    builder = AgentBuilder(Path(__file__).resolve().parent)
    # Asegura par Ed25519; la clave privada permanece SOLO en la estación de control.
    from gideon_agent_security import ensure_ed25519_keypair
    ensure_ed25519_keypair(builder.private_key, builder.public_key)
    signing_key_id = str(cfg.get("agent_control_plane", {}).get("signing_key_id", "gideon-agent-ed25519-1"))

    matched_rows: dict[str, dict[str, Any]] = {}
    missing_agent: list[Site] = []
    for site in selected:
        row = registered_for_site(site, registered_by_id, registered_by_site)
        if not row:
            missing_agent.append(site)
        matched_rows[agent_target_key(site)] = row
    if missing_agent and not args.allow_unregistered_agents:
        names = ", ".join(s.label for s in missing_agent[:10])
        raise RuntimeError(
            "Selected targets do not have an enrolled GIDEON Agent: " + names +
            ". Use AGENTLESS for those machines or refresh the Gateway agents."
        )

    # AgentId is the machine identity. SiteCode is only the location and may repeat.
    normalized: list[Site] = []
    for site in selected:
        row = matched_rows.get(agent_target_key(site)) or {}
        normalized.append(normalize_agent_site(site, row, cfg))
    selected = normalized
    matched_rows = {agent_target_key(site): registered_by_id.get(agent_target_key(site), {}) for site in selected}

    job_id = args.job_id or dt.datetime.now().strftime("%Y%m%d-%H%M%S") + "-agent"
    continue_on_error = not bool(args.stop_on_error)
    manifest = create_agent_manifest(
        job_id=job_id,
        scripts=scripts,
        sites=selected,
        cfg=cfg,
        results_dir=results_dir,
        raw_dir=raw_dir,
        export_format=args.export,
        continue_on_error=continue_on_error,
        sites_file=args.sites_file,
    )
    manifest["PackagesDir"] = str(packages_dir / job_id)
    manifest["Status"] = "DISPATCHING"
    store.write(manifest)
    raw_root = ensure_dir(raw_dir / job_id)

    # Queue every site. Offline agents may remain queued; they will pick it up when back online.
    for idx, site in enumerate(selected, 1):
        target_key = agent_target_key(site)
        entry = manifest["Sites"][target_key]
        try:
            registered_row = matched_rows.get(target_key) or registered_by_id.get(target_key) or {}
            profile = resolve_agent_profile(
                profiles,
                site,
                registered_row,
                override=args.host_profile,
                allow_profile_mismatch=bool(args.allow_profile_mismatch),
            )
            package_info = build_agent_package(
                site=site,
                job_id=job_id,
                scripts=scripts,
                cfg=cfg,
                packages_dir=packages_dir,
                continue_on_error=continue_on_error,
                profile=profile,
                signing_private_key=builder.private_key,
                signing_key_id=signing_key_id,
            )
            archive = Path(package_info["Archive"])
            response = client.upload_file(
                "PUT",
                f"/api/v1/admin/jobs/{job_id}/{target_key}",
                archive,
                headers={
                    "X-GIDEON-Site-Code": site.code,
                    "X-GIDEON-Site-Name": site.name,
                    "X-GIDEON-SHA256": sha256_file(archive),
                    "X-GIDEON-Signature": str(package_info["Signature"]),
                    "X-GIDEON-Key-Id": str(package_info["KeyId"]),
                    "X-GIDEON-Host-Profile": str(profile.get("id")),
                },
                timeout=max(120.0, float(acfg.get("timeout_seconds", 20))),
            )
            entry["TransferStatus"] = "HTTPS_UPLOADED"
            entry["StartStatus"] = "AGENT_WAITING"
            entry["DispatchStatus"] = "DISPATCHED"
            entry["RemoteState"] = "DISPATCHED"
            entry["TaskState"] = "Queued"
            entry["PackageVerified"] = True
            entry["PackageBytes"] = archive.stat().st_size
            entry["PackageSignature"] = "ED25519"
            entry["PackageKeyId"] = signing_key_id
            entry["HostProfile"] = profile.get("id")
            entry["TargetPlatform"] = profile.get("platform")
            entry["TargetArchitectures"] = profile.get("architectures")
            entry["ScriptCount"] = len(scripts)
            entry["AgentOnlineAtDispatch"] = target_key in online
            entry["AgentGatewayStatus"] = response.get("Status", "QUEUED")
        except Exception as exc:
            entry["TransferStatus"] = "FAILED"
            entry["DispatchStatus"] = "FAILED"
            entry["RemoteState"] = "FAILED"
            entry["DispatchError"] = f"AGENT_QUEUE_ERROR: {exc}"
        manifest["DispatchAttempted"] = idx
        recalc_manifest(manifest)
        store.write(manifest)

    manifest["DispatchCompletedAt"] = now_iso()
    manifest["Status"] = "MONITORING"
    recalc_manifest(manifest)
    store.write(manifest)

    if args.dispatch_only:
        return 0

    site_map = {agent_target_key(s): s for s in selected}
    poll = max(2, int(acfg.get("poll_interval_seconds", 5)))
    while True:
        try:
            rows = client.json("GET", f"/api/v1/admin/jobs/{job_id}").get("Sites") or []
        except AgentHttpError as exc:
            manifest["Status"] = "WAITING_CONNECTION"
            manifest["ControllerConnectivityState"] = "OFFLINE"
            manifest["ControllerConnectionMode"] = "HTTPS"
            manifest["AgentControlPlaneError"] = str(exc)
            store.write(manifest)
            await asyncio.sleep(min(15, poll))
            continue

        manifest["ControllerConnectivityState"] = "ONLINE"
        manifest["ControllerConnectionMode"] = "HTTPS"
        if manifest.get("Status") == "WAITING_CONNECTION":
            manifest["Status"] = "MONITORING"

        by_target = {str(x.get("agent_id") or x.get("site_code")): x for x in rows if isinstance(x, dict)}
        for target_key, entry in list(manifest["Sites"].items()):
            row = by_target.get(target_key)
            if not row:
                continue
            updated = apply_gateway_row(entry, row)
            if bool(row.get("ResultReady")) and updated.get("CollectionStatus") != "HTTPS_COLLECTED":
                try:
                    updated = materialize_result(
                        client=client,
                        job_id=job_id,
                        site=site_map[target_key],
                        entry=updated,
                        raw_root=raw_root,
                        packages_dir=packages_dir,
                    )
                except Exception as exc:
                    updated["CollectionStatus"] = "FAILED"
                    updated["Error"] = f"AGENT_RESULT_DOWNLOAD_ERROR: {exc}"
            manifest["Sites"][target_key] = updated

        recalc_manifest(manifest)
        store.write(manifest)

        terminal = True
        for entry in manifest["Sites"].values():
            if entry.get("RemoteState") not in {"COLLECTED", "COLLECTED_WITH_ERRORS", "FAILED", "CANCELLED"}:
                terminal = False
                break
        if terminal:
            break
        await asyncio.sleep(poll)

    finalize_manifest(manifest, store)
    outputs = format_job(manifest, args.export)
    manifest["ResultFiles"] = [str(p) for p in outputs]
    store.write(manifest)
    return 0 if manifest.get("Status") == "COMPLETED" else 2


async def resume_job(args: argparse.Namespace) -> int:
    cfg, inventory, store, _, _, _, client = load_runtime(args)
    manifest = store.read(args.job_id)
    if str(manifest.get("ExecutionMethod") or "") != METHOD:
        raise RuntimeError("Job is not AGENT_HTTPS_PULL")
    # Reuse run monitor by reconstructing a namespace and existing manifest is handled by monitor helper below.
    return await monitor_existing(args, cfg, inventory, store, client, manifest)


async def monitor_existing(args, cfg, inventory, store, client, manifest) -> int:
    job_id = manifest["JobId"]
    acfg = cfg.get("agent_control_plane", {})
    raw_root = ensure_dir(Path(manifest["RawDir"]))
    packages_dir = Path(manifest.get("PackagesDir") or expand_path(cfg["paths"].get("packages_dir", "%LOCALAPPDATA%\\GIDEONSSH\\packages")))
    site_map = {agent_target_key(s): s for s in inventory.sites}
    for target_key, entry in manifest.get("Sites", {}).items():
        if target_key not in site_map:
            site_map[target_key] = Site(
                code=str(entry.get("SiteCode") or ""),
                name=str(entry.get("SiteName") or ""),
                ip="",
                platform=str(entry.get("TargetPlatform") or ""),
                host_profile=str(entry.get("HostProfile") or ""),
                agent_id=str(entry.get("AgentId") or target_key),
                agent_name=str(entry.get("AgentName") or ""),
                hostname=str(entry.get("Hostname") or ""),
                agent_connection=str(entry.get("AgentConnection") or ""),
                agent_remote_ip=str(entry.get("AgentRemoteIP") or ""),
                agentless_ip=str(entry.get("AgentlessIP") or ""),
                source="manifest",
            )
    poll = max(2, int(acfg.get("poll_interval_seconds", 5)))
    manifest["Status"] = "MONITORING"
    store.write(manifest)
    while True:
        try:
            rows = client.json("GET", f"/api/v1/admin/jobs/{job_id}").get("Sites") or []
            manifest["ControllerConnectivityState"] = "ONLINE"
            manifest["ControllerConnectionMode"] = "HTTPS"
        except Exception as exc:
            manifest["Status"] = "WAITING_CONNECTION"
            manifest["AgentControlPlaneError"] = str(exc)
            store.write(manifest)
            await asyncio.sleep(poll)
            continue
        by_target = {str(x.get("agent_id") or x.get("site_code")): x for x in rows if isinstance(x, dict)}
        for target_key, entry in list(manifest["Sites"].items()):
            row = by_target.get(target_key)
            if not row:
                continue
            updated = apply_gateway_row(entry, row)
            if bool(row.get("ResultReady")) and updated.get("CollectionStatus") != "HTTPS_COLLECTED":
                try:
                    updated = materialize_result(client=client, job_id=job_id, site=site_map[target_key], entry=updated, raw_root=raw_root, packages_dir=packages_dir)
                except Exception as exc:
                    updated["CollectionStatus"] = "FAILED"
                    updated["Error"] = str(exc)
            manifest["Sites"][target_key] = updated
        recalc_manifest(manifest)
        store.write(manifest)
        if all(x.get("RemoteState") in {"COLLECTED", "COLLECTED_WITH_ERRORS", "FAILED", "CANCELLED"} for x in manifest["Sites"].values()):
            break
        await asyncio.sleep(poll)
    finalize_manifest(manifest, store)
    outputs = format_job(manifest, args.export or manifest.get("ExportFormat"))
    manifest["ResultFiles"] = [str(x) for x in outputs]
    store.write(manifest)
    return 0 if manifest.get("Status") == "COMPLETED" else 2


async def cancel_job(args: argparse.Namespace) -> int:
    cfg, _, store, _, _, _, client = load_runtime(args)
    manifest = store.read(args.job_id)
    if str(manifest.get("ExecutionMethod") or "") != METHOD:
        raise RuntimeError("Job is not AGENT_HTTPS_PULL")
    manifest["Status"] = "CANCEL_REQUESTED"
    manifest["CancelRequested"] = True
    manifest["CancelRequestedAt"] = now_iso()
    for code, entry in manifest["Sites"].items():
        if entry.get("RemoteState") in {"COLLECTED", "COLLECTED_WITH_ERRORS", "FAILED", "CANCELLED"}:
            continue
        try:
            client.json("POST", f"/api/v1/admin/jobs/{args.job_id}/{code}/cancel", {})
            entry["RemoteState"] = "CANCEL_REQUESTED"
        except Exception as exc:
            entry["Error"] = f"AGENT_CANCEL_REQUEST_ERROR: {exc}"
    store.write(manifest)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="GIDEON Agent HTTPS/PULL Orchestrator")
    p.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    p.add_argument("--sites-file", type=Path, default=DEFAULT_SITES)
    sub = p.add_subparsers(dest="action", required=True)

    run = sub.add_parser("run")
    target = run.add_mutually_exclusive_group(required=True)
    target.add_argument("--targets", help="AgentId(s) separados por coma en modo Agent. SiteCode solo se acepta si existe un único Agent en esa sede.")
    target.add_argument("--all", action="store_true")
    run.add_argument("--confirm-all", action="store_true")
    run.add_argument("--script", type=Path, action="append", required=True)
    run.add_argument("--job-id")
    run.add_argument("--sites-file", type=Path, default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    run.add_argument("--export", choices=["xlsx", "csv", "json", "txt", "none"], default="xlsx")
    run.add_argument("--stop-on-error", action="store_true")
    run.add_argument("--allow-unregistered-agents", action="store_true", help="Lab only: queue even if the site has never enrolled an Agent.")
    run.add_argument("--dispatch-only", action="store_true")
    run.add_argument("--host-profile", help="Override host profile para todas las sedes seleccionadas. Por defecto usa asignación por sede.")
    run.add_argument("--allow-profile-mismatch", action="store_true", help="Diagnóstico: permite publicar a un Agent que reporta otro host profile.")

    resume = sub.add_parser("resume")
    resume.add_argument("job_id")
    resume.add_argument("--export", choices=["xlsx", "csv", "json", "txt", "none"])

    cancel = sub.add_parser("cancel")
    cancel.add_argument("job_id")

    healthp = sub.add_parser("health")
    agentsp = sub.add_parser("agents")
    return p


async def async_main(args: argparse.Namespace) -> int:
    if args.action == "run":
        return await run_job(args)
    if args.action == "resume":
        return await resume_job(args)
    if args.action == "cancel":
        return await cancel_job(args)
    cfg, _, _, _, _, _, client = load_runtime(args)
    if args.action == "health":
        print(json.dumps(health(client), indent=2, ensure_ascii=False))
        return 0
    if args.action == "agents":
        print(json.dumps({"Agents": agents(client)}, indent=2, ensure_ascii=False))
        return 0
    return 2


def main_from_args(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return asyncio.run(async_main(args))
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"[ERROR] {type(exc).__name__}: {exc}")
        return 2


def main() -> int:
    return main_from_args(None)


if __name__ == "__main__":
    raise SystemExit(main())
