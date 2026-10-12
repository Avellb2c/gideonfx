from __future__ import annotations

from typing import Any
from .states import SITE_ERROR_STATES, SITE_SUCCESS_STATES, SITE_WARNING_STATES, norm


def summarize_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    sites = list((manifest.get("Sites") or {}).values())
    total = len(sites)
    success = sum(1 for s in sites if norm(s.get("RemoteState")) in SITE_SUCCESS_STATES)
    warnings = sum(1 for s in sites if norm(s.get("RemoteState")) in SITE_WARNING_STATES)
    errors = sum(1 for s in sites if norm(s.get("RemoteState")) in SITE_ERROR_STATES)
    job_status = norm(manifest.get("Status"))
    active = max(0, total - success - warnings - errors)
    if job_status == "LAUNCH_FAILED":
        # No remote site was started; count the launch as a job-level failure
        # rather than misleadingly showing every PENDING site as active.
        errors = max(errors, total if total else 1)
        active = 0
    coverage = 0.0 if total == 0 else round(min(total, success + warnings + errors) * 100.0 / total, 1)
    return {
        "Total": total,
        "Success": success,
        "Warnings": warnings,
        "Errors": errors,
        "Active": active,
        "TerminalCoveragePct": coverage,
        "JobStatus": job_status,
    }
