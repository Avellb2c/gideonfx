from __future__ import annotations

"""Canonical signed-job contract shared by WebAdmin, Gateway packages and Agent.

The Agent previously had two producers (script execution and file transfer) that
built envelopes independently.  That made it possible for one path to omit a
security field that the endpoint already required.  This module is deliberately
small and dependency-free so it can travel inside every standalone Agent runtime.
"""

import datetime as dt
import secrets
from pathlib import PurePosixPath
from typing import Any, Iterable, Mapping

JOB_SCHEMA_VERSION = 4
JOB_PROTOCOL_VERSION = "2.1"
AGENT_WORKER_VERSION = "2.2.0"
SUPPORTED_JOB_TYPES = frozenset({"SCRIPT_EXECUTION", "FILE_TRANSFER"})
TERMINAL_STATES = frozenset({"RESULT_READY", "RESULT_READY_WITH_ERRORS", "FAILED", "CANCELLED"})


def now_local() -> dt.datetime:
    return dt.datetime.now().astimezone()


def _iso(value: dt.datetime) -> str:
    return value.isoformat(timespec="seconds")


def build_job_envelope(
    *,
    job_id: str,
    agent_id: str,
    site_code: str,
    site_name: str,
    agent_name: str = "",
    hostname: str = "",
    host_profile: Mapping[str, Any] | None = None,
    scripts: Iterable[Mapping[str, Any]] = (),
    job_type: str = "SCRIPT_EXECUTION",
    continue_on_error: bool = True,
    default_timeout_seconds: int = 1800,
    ttl_seconds: int = 86400,
    artifact: Mapping[str, Any] | None = None,
    required_capabilities: Iterable[str] = (),
    issued_at: dt.datetime | None = None,
) -> dict[str, Any]:
    """Return a complete, freshness-bound Agent job envelope.

    All producers must call this function instead of assembling security fields
    by hand.  Identity binding is mandatory because signed jobs are never
    broadcast payloads.
    """
    jid = str(job_id or "").strip()
    aid = str(agent_id or "").strip()
    scode = str(site_code or "").strip()
    jtype = str(job_type or "").strip().upper()
    if not jid:
        raise ValueError("JOB_ID_REQUIRED")
    if not aid:
        raise ValueError("JOB_AGENT_ID_REQUIRED")
    if not scode:
        raise ValueError("JOB_SITE_CODE_REQUIRED")
    if jtype not in SUPPORTED_JOB_TYPES:
        raise ValueError(f"JOB_TYPE_UNSUPPORTED: {jtype or '<vacío>'}")

    stamp = issued_at or now_local()
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=dt.timezone.utc)
    ttl = max(300, min(int(ttl_seconds or 86400), 7 * 86400))
    script_rows = [dict(x) for x in scripts]
    if not script_rows:
        raise ValueError("JOB_SCRIPTS_REQUIRED")

    envelope: dict[str, Any] = {
        "SchemaVersion": JOB_SCHEMA_VERSION,
        "ProtocolVersion": JOB_PROTOCOL_VERSION,
        "AgentWorkerVersion": AGENT_WORKER_VERSION,
        "JobId": jid,
        "JobType": jtype,
        "AgentId": aid,
        "AgentName": str(agent_name or ""),
        "Hostname": str(hostname or ""),
        "SiteCode": scode,
        "SiteName": str(site_name or ""),
        "HostProfile": dict(host_profile or {}),
        "ContinueOnError": bool(continue_on_error),
        "DefaultTimeoutSeconds": max(1, int(default_timeout_seconds or 1800)),
        "Scripts": script_rows,
        "RequiredCapabilities": sorted({str(x).strip() for x in required_capabilities if str(x).strip()}),
        "CreatedAt": _iso(stamp),
        "IssuedAt": _iso(stamp),
        "ExpiresAt": _iso(stamp + dt.timedelta(seconds=ttl)),
        "Nonce": secrets.token_urlsafe(24),
    }
    if artifact is not None:
        envelope["Artifact"] = dict(artifact)
    return envelope


def _parse_iso(name: str, raw: Any) -> dt.datetime:
    text = str(raw or "").strip()
    if not text:
        raise RuntimeError(f"JOB_{name.upper()}_REQUIRED")
    try:
        value = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuntimeError(f"JOB_{name.upper()}_INVALID") from exc
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)
    return value


def _safe_rel_path(raw: Any) -> str:
    text = str(raw or "").replace("\\", "/").strip()
    path = PurePosixPath(text)
    if not text or path.is_absolute() or ".." in path.parts:
        raise RuntimeError(f"JOB_SCRIPT_PATH_UNSAFE: {text or '<vacío>'}")
    return path.as_posix()


def validate_job_envelope(
    value: Mapping[str, Any],
    *,
    expected_job_id: str,
    expected_agent_id: str,
    expected_site_code: str,
    expected_host_profile: str = "",
    freshness_required: bool = True,
    now: dt.datetime | None = None,
    future_skew_seconds: int = 300,
) -> dict[str, Any]:
    """Validate identity, freshness, job type and script descriptors.

    Replay persistence remains the responsibility of the Agent because it owns
    the completed-job database.  This validator intentionally performs every
    deterministic contract check shared by package types.
    """
    job = dict(value)
    if str(job.get("JobId") or "") != str(expected_job_id):
        raise RuntimeError("JOB_ID_BINDING_MISMATCH")
    if str(job.get("AgentId") or "").strip() != str(expected_agent_id or "").strip():
        raise RuntimeError("JOB_AGENT_BINDING_MISMATCH")
    if str(job.get("SiteCode") or "").strip() != str(expected_site_code or "").strip():
        raise RuntimeError("JOB_SITE_BINDING_MISMATCH")

    jtype = str(job.get("JobType") or "SCRIPT_EXECUTION").upper().strip()
    if jtype not in SUPPORTED_JOB_TYPES:
        raise RuntimeError(f"JOB_TYPE_UNSUPPORTED: {jtype or '<vacío>'}")
    job["JobType"] = jtype

    profile = job.get("HostProfile") if isinstance(job.get("HostProfile"), Mapping) else {}
    package_profile = str((profile or {}).get("id") or "").strip()
    expected_profile = str(expected_host_profile or "").strip()
    if expected_profile and package_profile and package_profile != expected_profile:
        raise RuntimeError(
            f"JOB_HOST_PROFILE_MISMATCH: package={package_profile} agent={expected_profile}"
        )

    nonce = str(job.get("Nonce") or "").strip()
    issued_raw = job.get("IssuedAt") or job.get("CreatedAt")
    expires_raw = job.get("ExpiresAt")
    if freshness_required and (not nonce or not issued_raw or not expires_raw):
        raise RuntimeError("JOB_FRESHNESS_FIELDS_REQUIRED")
    if freshness_required:
        issued = _parse_iso("issued_at", issued_raw)
        expires = _parse_iso("expires_at", expires_raw)
        current = now or dt.datetime.now(dt.timezone.utc)
        if current.tzinfo is None:
            current = current.replace(tzinfo=dt.timezone.utc)
        current = current.astimezone(dt.timezone.utc)
        if issued.astimezone(dt.timezone.utc) - current > dt.timedelta(seconds=max(0, int(future_skew_seconds))):
            raise RuntimeError("JOB_ISSUED_IN_FUTURE")
        if current > expires.astimezone(dt.timezone.utc):
            raise RuntimeError("JOB_EXPIRED")
        if expires <= issued:
            raise RuntimeError("JOB_EXPIRY_INVALID")

    scripts = job.get("Scripts")
    if not isinstance(scripts, list) or not scripts:
        raise RuntimeError("JOB_SCRIPTS_REQUIRED")
    normalized: list[dict[str, Any]] = []
    for index, raw in enumerate(scripts, 1):
        if not isinstance(raw, Mapping):
            raise RuntimeError(f"JOB_SCRIPT_DESCRIPTOR_INVALID: index={index}")
        row = dict(raw)
        row["Path"] = _safe_rel_path(row.get("Path") or row.get("FileName"))
        sha = str(row.get("Sha256") or "").strip().lower()
        # Security-created script jobs must bind the content hash.  FILE_TRANSFER
        # runs a generated worker whose payload integrity is bound by Artifact.
        if jtype == "SCRIPT_EXECUTION" and len(sha) != 64:
            raise RuntimeError(f"JOB_SCRIPT_SHA256_REQUIRED: index={index}")
        normalized.append(row)
    job["Scripts"] = normalized

    if jtype == "FILE_TRANSFER":
        artifact = job.get("Artifact") if isinstance(job.get("Artifact"), Mapping) else {}
        if not str((artifact or {}).get("Sha256") or "").strip() or not str((artifact or {}).get("DestinationPath") or "").strip():
            raise RuntimeError("JOB_FILE_ARTIFACT_INVALID")
    return job


__all__ = [
    "JOB_SCHEMA_VERSION",
    "JOB_PROTOCOL_VERSION",
    "AGENT_WORKER_VERSION",
    "SUPPORTED_JOB_TYPES",
    "TERMINAL_STATES",
    "build_job_envelope",
    "validate_job_envelope",
]
