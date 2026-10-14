"""Small, dependency-free Executive license verifier.

Open Source installations remain unrestricted.  Executive deployments may
provide a JSON document through ``GIDEON_EXECUTIVE_LICENSE`` or the
``executive_license``/``license_file`` WebAdmin configuration keys.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
from pathlib import Path
from typing import Any


class GideonLicenseError(RuntimeError):
    """Raised when an Executive license is missing, malformed, or expired."""


def _load_document(config: dict[str, Any], data_dir: Path) -> dict[str, Any]:
    raw: Any = os.environ.get("GIDEON_EXECUTIVE_LICENSE")
    if not raw:
        raw = config.get("executive_license")
    if not raw:
        raw = config.get("license_file")
    if isinstance(raw, dict):
        return dict(raw)
    if not raw:
        candidate = data_dir / "executive-license.json"
    else:
        candidate = Path(os.path.expandvars(str(raw))).expanduser()
        if not candidate.is_absolute():
            candidate = data_dir / candidate
    try:
        return json.loads(candidate.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise GideonLicenseError("EXECUTIVE_LICENSE_MISSING") from exc
    except (OSError, ValueError, TypeError) as exc:
        raise GideonLicenseError("EXECUTIVE_LICENSE_INVALID") from exc


def enforce_executive_license(config: dict[str, Any], data_dir: str | Path) -> dict[str, Any]:
    """Validate the Executive document and return its normalized metadata."""
    document = _load_document(dict(config or {}), Path(data_dir))
    customer = str(document.get("Customer") or document.get("customer") or "").strip()
    expires = str(document.get("ExpiresAt") or document.get("expires_at") or "").strip()
    if not customer or not expires:
        raise GideonLicenseError("EXECUTIVE_LICENSE_INVALID")
    try:
        expiry = _dt.datetime.fromisoformat(expires.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GideonLicenseError("EXECUTIVE_LICENSE_INVALID") from exc
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=_dt.timezone.utc)
    now = _dt.datetime.now(_dt.timezone.utc)
    days = (expiry - now).total_seconds() / 86400
    if days < 0:
        raise GideonLicenseError("EXECUTIVE_LICENSE_EXPIRED")
    return {"Customer": customer, "ExpiresAt": expiry.isoformat(), "_DaysRemaining": max(0, int(days))}
