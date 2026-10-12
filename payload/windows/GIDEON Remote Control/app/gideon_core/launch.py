from __future__ import annotations

from gideon_common.clock import now_iso as _common_now_iso
import datetime as dt
import json
import os
import re
import shlex
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

from gideon_io import atomic_write_json, read_json_retry
from gideon_core.transport_profiles import (
    DEFAULT_TRANSPORT_PROFILE, VALID_TRANSPORT_PROFILES,
    get_transport_profile, normalize_transport_profile,
)

AGENTLESS = "AGENTLESS_SSH_SFTP"
AGENT = "AGENT_HTTPS_PULL"
VALID_METHODS = {AGENTLESS, AGENT}
SAFE_JOB_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{5,95}$")




def _site_payload(site: Any) -> dict[str, Any]:
    code = str(getattr(site, "code", None) or getattr(site, "SiteCode", "") or "").strip()
    name = str(getattr(site, "name", None) or getattr(site, "SiteName", "") or "").strip()
    ip = str(
        getattr(site, "ip", None)
        or getattr(site, "address", None)
        or getattr(site, "ServerIP", "")
        or ""
    ).strip()
    agent_id = str(getattr(site, "agent_id", None) or getattr(site, "AgentId", "") or "").strip()
    agent_name = str(getattr(site, "agent_name", None) or getattr(site, "AgentName", "") or "").strip()
    hostname = str(getattr(site, "hostname", None) or getattr(site, "Hostname", "") or "").strip()
    if isinstance(site, dict):
        code = str(site.get("SiteCode") or site.get("code") or code).strip()
        name = str(site.get("SiteName") or site.get("name") or name).strip()
        ip = str(site.get("ServerIP") or site.get("ip") or ip).strip()
        agent_id = str(site.get("AgentId") or site.get("agent_id") or agent_id).strip()
        agent_name = str(site.get("AgentName") or site.get("agent_name") or agent_name).strip()
        hostname = str(site.get("Hostname") or site.get("hostname") or hostname).strip()
    return {
        "SiteCode": code, "SiteName": name, "ServerIP": ip,
        "AgentId": agent_id, "AgentName": agent_name, "Hostname": hostname,
    }


@dataclass(frozen=True, slots=True)
class LaunchRequest:
    job_id: str
    method: str
    sites_file: Path
    sites: tuple[Any, ...]
    scripts: tuple[Path, ...]
    export_format: str = "xlsx"
    continue_on_error: bool = True
    host_profile: Optional[str] = None
    transport_profile: str = DEFAULT_TRANSPORT_PROFILE
    group_id: Optional[str] = None
    group_name: Optional[str] = None

    @property
    def target_codes(self) -> tuple[str, ...]:
        return tuple(_site_payload(s)["SiteCode"] for s in self.sites)

    @property
    def target_agent_ids(self) -> tuple[str, ...]:
        # v2.1 prefers AgentId. SiteCode remains a compatibility target only
        # when the Gateway can prove that the site has a single Agent.
        return tuple((_site_payload(s)["AgentId"] or _site_payload(s)["SiteCode"]) for s in self.sites)


@dataclass(slots=True)
class PreflightReport:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    checks: list[dict[str, Any]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def add(self, name: str, ok: bool, detail: str, *, warning: bool = False) -> None:
        self.checks.append({"Name": name, "Ok": bool(ok), "Detail": detail, "Warning": warning})
        if not ok:
            (self.warnings if warning else self.errors).append(f"{name}: {detail}")

    def as_dict(self) -> dict[str, Any]:
        return {
            "Ok": self.ok,
            "Errors": list(self.errors),
            "Warnings": list(self.warnings),
            "Checks": list(self.checks),
        }


@dataclass(frozen=True, slots=True)
class LaunchPlan:
    request: LaunchRequest
    command: tuple[str, ...]
    log_path: Path
    manifest_path: Path
    preflight: PreflightReport

    def command_text(self) -> str:
        try:
            return subprocess.list2cmdline(list(self.command)) if os.name == "nt" else shlex.join(self.command)
        except Exception:
            return " ".join(self.command)


class LaunchService:
    """Single source of truth for GUI -> backend launch contracts.

    The GUI must not hand-build the fanout/orchestrator CLI.  This class owns
    argument ordering, preflight, bootstrap manifest and launch failure state.
    """

    def __init__(
        self,
        *,
        app_root: Path,
        jobs_dir: Path,
        logs_dir: Path,
        python_exe: str,
        version: str,
        config_path: Path | None = None,
    ) -> None:
        self.app_root = Path(app_root).resolve()
        self.jobs_dir = Path(jobs_dir).resolve()
        self.logs_dir = Path(logs_dir).resolve()
        self.python_exe = str(python_exe)
        self.version = str(version)
        self.config_path = Path(config_path).resolve() if config_path is not None else None
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)

    def validate(self, request: LaunchRequest) -> PreflightReport:
        r = PreflightReport()
        method = str(request.method).upper()
        r.add("Método", method in VALID_METHODS, method if method in VALID_METHODS else f"No soportado: {method}")

        transport_profile = normalize_transport_profile(request.transport_profile)
        if method == AGENTLESS:
            r.add(
                "Perfil de transporte",
                transport_profile in VALID_TRANSPORT_PROFILES,
                get_transport_profile(transport_profile).label,
            )
        else:
            r.add(
                "Perfil de transporte",
                True,
                "HTTPS/PULL administrado por Agent",
            )

        r.add(
            "Job ID",
            bool(SAFE_JOB_RE.match(request.job_id)),
            request.job_id if SAFE_JOB_RE.match(request.job_id) else "formato inválido",
        )
        manifest = self.jobs_dir / f"{request.job_id}.json"
        r.add("Job único", not manifest.exists(), "Disponible" if not manifest.exists() else f"Ya existe {manifest.name}")

        sites_file = Path(request.sites_file).resolve()
        r.add("Inventario", sites_file.is_file(), str(sites_file))

        sites = [_site_payload(x) for x in request.sites]
        r.add("Hosts", bool(sites), f"{len(sites)} seleccionado(s)" if sites else "sin hosts")
        seen: set[str] = set()
        duplicates: list[str] = []
        invalid_sites: list[str] = []
        for s in sites:
            code = s["SiteCode"]
            agent_id = s.get("AgentId") or ""
            # Agent HTTPS/PULL is addressed by a persistent AgentId. SiteCode is
            # the organizational location and may legitimately repeat when a
            # store has two or more managed computers.
            missing_required = (not code) or (method == AGENTLESS and not s["ServerIP"])
            if missing_required:
                invalid_sites.append(agent_id or code or "<sin identidad>")
            identity = (agent_id or code) if method == AGENT else code
            if identity in seen:
                duplicates.append(identity)
            seen.add(identity)
        if method == AGENT:
            invalid_detail = f"sin SiteCode: {', '.join(invalid_sites[:5])}"
            unique_label = "Destinos Agent únicos"
        else:
            invalid_detail = f"sin IP/código: {', '.join(invalid_sites[:5])}"
            unique_label = "Códigos únicos"
        r.add("Inventario seleccionado", not invalid_sites, "OK" if not invalid_sites else invalid_detail)
        r.add(unique_label, not duplicates, "OK" if not duplicates else f"duplicados: {', '.join(sorted(set(duplicates))[:5])}")

        scripts = [Path(x).resolve() for x in request.scripts]
        r.add("Scripts", bool(scripts), f"{len(scripts)} seleccionado(s)" if scripts else "sin scripts")
        missing = [str(p) for p in scripts if not p.is_file()]
        r.add("Archivos script", not missing, "OK" if not missing else f"no existen: {', '.join(missing[:3])}")
        if method == AGENTLESS:
            unsupported = [p.name for p in scripts if p.suffix.lower() != ".ps1"]
            r.add(
                "Compatibilidad Agentless",
                not unsupported,
                "PowerShell .ps1" if not unsupported else f"Agentless solo acepta .ps1: {', '.join(unsupported[:5])}",
            )
        else:
            supported = {".ps1", ".py", ".sh", ".command", ".cmd", ".bat"}
            unsupported = [p.name for p in scripts if p.suffix.lower() not in supported]
            r.add("Compatibilidad Agent", not unsupported, "OK" if not unsupported else f"extensión no soportada: {', '.join(unsupported[:5])}")

        r.add(
            "Formato export",
            request.export_format in {"xlsx", "csv", "json", "txt", "none"},
            request.export_format,
        )
        return r

    def build_plan(self, request: LaunchRequest) -> LaunchPlan:
        preflight = self.validate(request)
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        purpose = "agent-job" if request.method == AGENT else "fanout-job"
        log_path = self.logs_dir / f"{stamp}-{request.job_id}-{purpose}.log"
        manifest_path = self.jobs_dir / f"{request.job_id}.json"

        target_args: list[str]
        # Agentless remains keyed by SiteCode. Agent mode is keyed by persistent
        # AgentId so two computers in the same site can be selected independently.
        if request.method == AGENT:
            target_args = ["--targets", ",".join(request.target_agent_ids)]
        else:
            target_args = ["--targets", ",".join(request.target_codes)]

        script_args: list[str] = []
        for script in request.scripts:
            script_args.extend(["--script", str(Path(script).resolve())])

        behavior = ["--continue-on-error"] if request.continue_on_error else ["--stop-on-error"]

        if request.method == AGENTLESS:
            # IMPORTANT: --sites-file is a FANOUT GLOBAL option, therefore it
            # must be placed before the `run` subcommand.
            command = [
                self.python_exe,
                str(self.app_root / "gideon_admin.py"),
                "fanout",
                *(["--config", str(self.config_path)] if self.config_path is not None else []),
                "--sites-file",
                str(Path(request.sites_file).resolve()),
                "run",
                "--transport-profile",
                normalize_transport_profile(request.transport_profile),
                "--job-id",
                request.job_id,
                *target_args,
                *script_args,
                "--export",
                request.export_format,
                *behavior,
            ]
        elif request.method == AGENT:
            # Same rule for agent orchestrator: global options precede `run`.
            command = [
                self.python_exe,
                str(self.app_root / "gideon_agent_orchestrator.py"),
                "--sites-file",
                str(Path(request.sites_file).resolve()),
                "run",
                "--job-id",
                request.job_id,
                *target_args,
                *script_args,
                "--export",
                request.export_format,
            ]
            if not request.continue_on_error:
                command.append("--stop-on-error")
            if request.host_profile and request.host_profile.upper() != "AUTO":
                command.extend(["--host-profile", request.host_profile])
        else:
            command = [self.python_exe, "-c", "raise SystemExit(2)"]

        return LaunchPlan(
            request=request,
            command=tuple(command),
            log_path=log_path,
            manifest_path=manifest_path,
            preflight=preflight,
        )

    def bootstrap_manifest(self, plan: LaunchPlan) -> dict[str, Any]:
        req = plan.request
        created = _common_now_iso(timespec="milliseconds")
        sites: dict[str, Any] = {}
        for raw in req.sites:
            s = _site_payload(raw)
            code = s["SiteCode"]
            target_key = str(s.get("AgentId") or code) if req.method == AGENT else code
            if req.method == AGENT:
                # Defensive boundary: an Agent bootstrap manifest must not leak
                # a legacy store/server address into the Agent route model.
                s["ServerIP"] = ""
            sites[target_key] = {
                **s,
                "TargetKey": target_key,
                "AgentConnection": "HTTPS/PULL → Gateway" if req.method == AGENT else "",
                "TransferStatus": "PENDING",
                "StartStatus": "PENDING",
                "DispatchStatus": "PENDING",
                "RemoteState": "PENDING",
                "CollectionStatus": "PENDING",
                "TaskState": None,
                "CurrentScriptIndex": 0,
                "CurrentScriptName": None,
                "UpdatedAt": created,
            }
        payload: dict[str, Any] = {
            "SchemaVersion": 4,
            "JobId": req.job_id,
            "Status": "STARTING",
            "LaunchStage": "VALIDATED",
            "ExecutionMethod": req.method,
            "TransportProfile": (
                normalize_transport_profile(req.transport_profile)
                if req.method == AGENTLESS
                else "AGENT_HTTPS_PULL"
            ),
            "Transport": (
                get_transport_profile(req.transport_profile).manifest_transport()
                if req.method == AGENTLESS
                else {
                    "Distribution": "HTTPS_QUEUE",
                    "Control": "HTTPS_PULL",
                    "Collection": "HTTPS_RESULT",
                }
            ),
            "ApplicationVersion": self.version,
            "CreatedAt": created,
            "UpdatedAt": created,
            "TotalCount": len(sites),
            "DispatchAttempted": 0,
            "DispatchOk": 0,
            "DispatchFailed": 0,
            "CollectedCount": 0,
            "CollectedWithErrorsCount": 0,
            "FailedCount": 0,
            "CancelledCount": 0,
            "InterruptedCount": 0,
            "ScriptCount": len(req.scripts),
            "Scripts": [
                {"Index": i, "Name": Path(p).name, "LocalPath": str(Path(p).resolve())}
                for i, p in enumerate(req.scripts, 1)
            ],
            "SitesFile": str(Path(req.sites_file).resolve()),
            "SiteGroupId": req.group_id,
            "SiteGroupName": req.group_name,
            "ExportFormat": req.export_format,
            "ContinueOnError": bool(req.continue_on_error),
            "BackendLog": str(plan.log_path),
            "LaunchCommand": plan.command_text(),
            "LaunchPreflight": plan.preflight.as_dict(),
            "ControllerPid": None,
            "LaunchPid": None,
            "LaunchReturnCode": None,
            "LaunchError": None,
            "Sites": sites,
        }
        atomic_write_json(plan.manifest_path, payload, retries=8)
        return payload

    def mark_started(self, plan: LaunchPlan, pid: int) -> dict[str, Any]:
        payload = read_json_retry(plan.manifest_path, retries=4, delay=0.02)
        if not isinstance(payload, dict):
            payload = self.bootstrap_manifest(plan)
        payload["LaunchStage"] = "BACKEND_STARTED"
        payload["LaunchPid"] = int(pid)
        payload["ControllerPid"] = int(pid)
        payload["BackendLog"] = str(plan.log_path)
        payload["UpdatedAt"] = _common_now_iso(timespec="milliseconds")
        atomic_write_json(plan.manifest_path, payload, retries=8)
        return payload

    def mark_failed(
        self,
        plan: LaunchPlan,
        *,
        return_code: Optional[int],
        error: str,
        log_tail: Optional[str] = None,
    ) -> dict[str, Any]:
        try:
            payload = read_json_retry(plan.manifest_path, retries=3, delay=0.02)
        except Exception:
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        payload.setdefault("JobId", plan.request.job_id)
        payload.setdefault("Sites", {})
        payload.setdefault("TotalCount", len(plan.request.sites))
        payload["Status"] = "LAUNCH_FAILED"
        payload["LaunchStage"] = "FAILED"
        payload["LaunchReturnCode"] = return_code
        payload["LaunchError"] = str(error)
        payload["LaunchErrorTail"] = log_tail
        payload["BackendLog"] = str(plan.log_path)
        payload["FinishedAt"] = _common_now_iso(timespec="milliseconds")
        payload["UpdatedAt"] = _common_now_iso(timespec="milliseconds")
        atomic_write_json(plan.manifest_path, payload, retries=8)
        return payload


def tail_text(path: Path, *, max_lines: int = 35, max_chars: int = 12000) -> str:
    path = Path(path)
    if not path.exists():
        return ""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""
    lines = text.splitlines()[-max_lines:]
    out = "\n".join(lines)
    return out[-max_chars:]
