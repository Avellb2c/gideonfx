from __future__ import annotations

"""Transactional central configuration for the GIDEON Agent.

The static ``agent.json`` remains the bootstrap/identity-safe baseline.  Gateway
configuration is stored separately under the Agent data directory as
``config.current.json`` and ``config.previous.json``.  Only a small allow-list of
runtime settings can be changed remotely; identity, tokens, PKI trust material
and local filesystem paths are deliberately excluded.
"""

import copy
import datetime as dt
import json
from pathlib import Path
from typing import Any, Callable, Mapping

from gideon_agent_bootstrap import PRIVATE_FILE_MODE, atomic_json as _atomic_json, enforce_path_mode
from gideon_agent_connectivity import normalize_endpoints, normalize_mode

CONFIG_SCHEMA = "gideon-agent-central-config/v1"
CONFIG_STORE_SCHEMA = "gideon-agent-config-store/v1"

_ALLOWED_SETTINGS = {"control_plane", "poll_seconds", "status_seconds", "update"}
_ALLOWED_CONTROL_PLANE = {
    "base_url",
    "connectivity_mode",
    "endpoints",
    "timeout_seconds",
    "network_check_seconds",
}
_ALLOWED_UPDATE = {
    "channel",
    "check_seconds",
    "auto_install_approved",
    "require_approved",
}


class CentralConfigError(ValueError):
    pass


def now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    return value if isinstance(value, dict) else {}


def _int_range(value: Any, *, name: str, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise CentralConfigError(f"{name} debe ser entero") from exc
    if number < minimum or number > maximum:
        raise CentralConfigError(f"{name} fuera de rango ({minimum}..{maximum})")
    return number


def _float_range(value: Any, *, name: str, minimum: float, maximum: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise CentralConfigError(f"{name} debe ser numérico") from exc
    if number < minimum or number > maximum:
        raise CentralConfigError(f"{name} fuera de rango ({minimum}..{maximum})")
    return number


def sanitize_settings(settings: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and normalize the remotely configurable subset.

    Security invariants intentionally cannot be changed remotely.  In
    particular ``verify_tls``, CA paths/fingerprints, mTLS material, AgentId,
    site identity, bearer token and bootstrap credentials are not accepted.
    """
    if not isinstance(settings, Mapping):
        raise CentralConfigError("settings debe ser un objeto JSON")
    unknown = sorted(set(settings) - _ALLOWED_SETTINGS)
    if unknown:
        raise CentralConfigError("settings no permitidos: " + ", ".join(unknown))

    out: dict[str, Any] = {}

    if "poll_seconds" in settings:
        out["poll_seconds"] = _int_range(settings["poll_seconds"], name="poll_seconds", minimum=2, maximum=3600)
    if "status_seconds" in settings:
        out["status_seconds"] = _int_range(settings["status_seconds"], name="status_seconds", minimum=2, maximum=3600)

    if "update" in settings:
        raw_update = settings.get("update")
        if not isinstance(raw_update, Mapping):
            raise CentralConfigError("update debe ser un objeto")
        unknown_update = sorted(set(raw_update) - _ALLOWED_UPDATE)
        if unknown_update:
            raise CentralConfigError("update contiene campos no permitidos: " + ", ".join(unknown_update))
        update: dict[str, Any] = {}
        if "channel" in raw_update:
            channel = str(raw_update.get("channel") or "").strip().lower()
            if not channel or len(channel) > 40 or any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789-_." for ch in channel):
                raise CentralConfigError("update.channel inválido")
            update["channel"] = channel
        if "check_seconds" in raw_update:
            update["check_seconds"] = _int_range(raw_update["check_seconds"], name="update.check_seconds", minimum=60, maximum=86400)
        for key in ("auto_install_approved", "require_approved"):
            if key in raw_update:
                if not isinstance(raw_update[key], bool):
                    raise CentralConfigError(f"update.{key} debe ser booleano")
                update[key] = bool(raw_update[key])
        out["update"] = update

    if "control_plane" in settings:
        raw_cp = settings.get("control_plane")
        if not isinstance(raw_cp, Mapping):
            raise CentralConfigError("control_plane debe ser un objeto")
        unknown_cp = sorted(set(raw_cp) - _ALLOWED_CONTROL_PLANE)
        if unknown_cp:
            raise CentralConfigError("control_plane contiene campos no permitidos: " + ", ".join(unknown_cp))
        cp: dict[str, Any] = {}
        mode = normalize_mode(raw_cp.get("connectivity_mode"))
        if "connectivity_mode" in raw_cp:
            cp["connectivity_mode"] = mode
        if "timeout_seconds" in raw_cp:
            cp["timeout_seconds"] = _float_range(raw_cp["timeout_seconds"], name="control_plane.timeout_seconds", minimum=1.0, maximum=120.0)
        if "network_check_seconds" in raw_cp:
            cp["network_check_seconds"] = _int_range(raw_cp["network_check_seconds"], name="control_plane.network_check_seconds", minimum=2, maximum=300)

        # Reuse the P3 endpoint policy, including HTTPS normalization and the
        # LOCAL_TEST loopback isolation rule.  We deliberately require at least
        # one usable endpoint whenever endpoint routing is being changed.
        routing_requested = "base_url" in raw_cp or "endpoints" in raw_cp
        if routing_requested:
            candidate = {
                "connectivity_mode": mode,
                "base_url": str(raw_cp.get("base_url") or "").strip(),
                "endpoints": list(raw_cp.get("endpoints") or []) if isinstance(raw_cp.get("endpoints"), list) else [],
            }
            try:
                endpoints = normalize_endpoints(candidate)
            except Exception as exc:
                raise CentralConfigError(f"control_plane endpoints inválidos: {exc}") from exc
            if not endpoints:
                raise CentralConfigError("control_plane debe conservar al menos un endpoint válido")
            cp["base_url"] = endpoints[0].url
            cp["endpoints"] = [x.as_dict() for x in endpoints]
        out["control_plane"] = cp

    return out


def build_document(
    *,
    version: int,
    settings: Mapping[str, Any],
    updated_by: str = "gateway",
    updated_at: str | None = None,
    note: str = "",
) -> dict[str, Any]:
    version = _int_range(version, name="version", minimum=1, maximum=2_147_483_647)
    return {
        "schema": CONFIG_SCHEMA,
        "version": version,
        "settings": sanitize_settings(settings),
        "updated_at": str(updated_at or now_iso()),
        "updated_by": str(updated_by or "gateway")[:120],
        "note": str(note or "")[:500],
    }


def validate_document(document: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(document, Mapping):
        raise CentralConfigError("La configuración central debe ser un objeto JSON")
    if str(document.get("schema") or "") != CONFIG_SCHEMA:
        raise CentralConfigError("schema de configuración central no soportado")
    return build_document(
        version=document.get("version"),
        settings=document.get("settings") if isinstance(document.get("settings"), Mapping) else {},
        updated_by=str(document.get("updated_by") or "gateway"),
        updated_at=str(document.get("updated_at") or now_iso()),
        note=str(document.get("note") or ""),
    )


def merge_effective_config(base_cfg: Mapping[str, Any], document: Mapping[str, Any] | None) -> dict[str, Any]:
    """Overlay a validated central document on the static Agent config."""
    result = copy.deepcopy(dict(base_cfg))
    if not document:
        return result
    doc = validate_document(document)
    settings = doc["settings"]
    for key in ("poll_seconds", "status_seconds"):
        if key in settings:
            result[key] = settings[key]
    if "update" in settings:
        merged = dict(result.get("update") or {})
        merged.update(dict(settings["update"]))
        result["update"] = merged
    if "control_plane" in settings:
        # Security/PKI keys from the local baseline remain untouched because the
        # central allow-list only contains routing/performance keys.
        merged = dict(result.get("control_plane") or {})
        merged.update(copy.deepcopy(dict(settings["control_plane"])))
        result["control_plane"] = merged
    return result


class CentralConfigStore:
    """Durable two-generation config store with crash-safe rollback markers."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.current_path = self.root / "config.current.json"
        self.previous_path = self.root / "config.previous.json"
        self.pending_path = self.root / "config.pending.json"
        self.rejected_path = self.root / "config.rejected.json"
        self.status_path = self.root / "config.status.json"
        self.root.mkdir(parents=True, exist_ok=True)
        # Central routing documents do not contain bearer tokens by contract,
        # but still expose management topology. Repair files written by older
        # releases before reading or rotating either generation.
        for path in (
            self.current_path,
            self.previous_path,
            self.pending_path,
            self.rejected_path,
            self.status_path,
        ):
            if path.is_file():
                enforce_path_mode(path, PRIVATE_FILE_MODE)

    def load_current(self) -> dict[str, Any]:
        raw = _read_json(self.current_path)
        return validate_document(raw) if raw else {}

    def load_previous(self) -> dict[str, Any]:
        raw = _read_json(self.previous_path)
        return validate_document(raw) if raw else {}

    def current_version(self) -> int:
        try:
            return int(self.load_current().get("version") or 0)
        except Exception:
            return 0

    def status(self) -> dict[str, Any]:
        return _read_json(self.status_path)

    def _status(self, state: str, **extra: Any) -> dict[str, Any]:
        value = {
            "schema": CONFIG_STORE_SCHEMA,
            "state": state,
            "time": now_iso(),
            "current_version": self.current_version(),
        }
        value.update(extra)
        _atomic_json(self.status_path, value)
        return value

    def recover_interrupted(self) -> dict[str, Any] | None:
        """Rollback a transaction that was committed but never finalized.

        A process/power loss cannot leave a newly committed routing config as the
        only boot source.  The pending journal records whether a prior central
        config existed and is resolved before ``config.current`` is ever merged.
        """
        pending = _read_json(self.pending_path)
        if not pending:
            return None
        phase = str(pending.get("phase") or "staged")
        candidate = pending.get("candidate") if isinstance(pending.get("candidate"), Mapping) else {}
        version = int(candidate.get("version") or 0) if isinstance(candidate, Mapping) else 0
        if phase == "committed":
            had_current = bool(pending.get("had_current"))
            if had_current and self.previous_path.is_file():
                previous = _read_json(self.previous_path)
                if previous:
                    _atomic_json(self.current_path, previous)
            elif not had_current:
                try:
                    self.current_path.unlink()
                except FileNotFoundError:
                    pass
            rejected = {
                "schema": CONFIG_STORE_SCHEMA,
                "candidate": dict(candidate),
                "reason": "RECOVERED_INTERRUPTED_TRANSACTION",
                "time": now_iso(),
            }
            _atomic_json(self.rejected_path, rejected)
            try:
                self.pending_path.unlink()
            except FileNotFoundError:
                pass
            return self._status("ROLLED_BACK", rejected_version=version, reason="RECOVERED_INTERRUPTED_TRANSACTION")
        # A merely staged candidate never replaced current and can be safely discarded.
        try:
            self.pending_path.unlink()
        except FileNotFoundError:
            pass
        return self._status("STAGED_DISCARDED", rejected_version=version, reason="PROCESS_RESTART_BEFORE_COMMIT")

    def stage(self, candidate: Mapping[str, Any]) -> dict[str, Any]:
        doc = validate_document(candidate)
        current = self.load_current()
        current_version = int(current.get("version") or 0) if current else 0
        if int(doc["version"]) <= current_version:
            raise CentralConfigError(f"La versión candidata {doc['version']} no supera la versión local {current_version}")
        journal = {
            "schema": CONFIG_STORE_SCHEMA,
            "phase": "staged",
            "had_current": bool(current),
            "previous_version": current_version,
            "candidate": doc,
            "staged_at": now_iso(),
        }
        _atomic_json(self.pending_path, journal)
        self._status("STAGED", candidate_version=int(doc["version"]), previous_version=current_version)
        return doc

    def commit_staged(self) -> dict[str, Any]:
        journal = _read_json(self.pending_path)
        if not journal or str(journal.get("phase")) != "staged":
            raise CentralConfigError("No existe una configuración staged para commit")
        candidate = validate_document(journal.get("candidate") if isinstance(journal.get("candidate"), Mapping) else {})
        current = self.load_current()
        if current:
            _atomic_json(self.previous_path, current)
        else:
            # A stale previous generation from an old transaction must not be
            # mistaken as the rollback target for an initial central config.
            try:
                self.previous_path.unlink()
            except FileNotFoundError:
                pass
        _atomic_json(self.current_path, candidate)
        journal["phase"] = "committed"
        journal["committed_at"] = now_iso()
        _atomic_json(self.pending_path, journal)
        self._status(
            "COMMITTED_PENDING_VALIDATION",
            candidate_version=int(candidate["version"]),
            previous_version=int(current.get("version") or 0) if current else 0,
        )
        return candidate

    def finalize(self) -> dict[str, Any]:
        journal = _read_json(self.pending_path)
        candidate = journal.get("candidate") if isinstance(journal.get("candidate"), Mapping) else self.load_current()
        version = int(candidate.get("version") or 0) if isinstance(candidate, Mapping) else self.current_version()
        try:
            self.pending_path.unlink()
        except FileNotFoundError:
            pass
        return self._status("APPLIED", applied_version=version)

    def reject_staged(self, reason: str) -> dict[str, Any]:
        journal = _read_json(self.pending_path)
        candidate = journal.get("candidate") if isinstance(journal.get("candidate"), Mapping) else {}
        rejected = {
            "schema": CONFIG_STORE_SCHEMA,
            "candidate": dict(candidate),
            "reason": str(reason or "VALIDATION_FAILED")[:4000],
            "time": now_iso(),
        }
        _atomic_json(self.rejected_path, rejected)
        try:
            self.pending_path.unlink()
        except FileNotFoundError:
            pass
        return self._status("REJECTED", rejected_version=int(candidate.get("version") or 0), reason=rejected["reason"])

    def rollback_committed(self, reason: str) -> dict[str, Any]:
        journal = _read_json(self.pending_path)
        candidate = journal.get("candidate") if isinstance(journal.get("candidate"), Mapping) else self.load_current()
        had_current = bool(journal.get("had_current")) if journal else self.previous_path.is_file()
        failed_version = int(candidate.get("version") or 0) if isinstance(candidate, Mapping) else self.current_version()
        failed_copy = dict(candidate) if isinstance(candidate, Mapping) else {}
        if had_current and self.previous_path.is_file():
            previous = self.load_previous()
            if not previous:
                raise CentralConfigError("Rollback solicitado pero config.previous no es válida")
            _atomic_json(self.current_path, previous)
        elif not had_current:
            try:
                self.current_path.unlink()
            except FileNotFoundError:
                pass
        rejected = {
            "schema": CONFIG_STORE_SCHEMA,
            "candidate": failed_copy,
            "reason": str(reason or "POST_APPLY_VALIDATION_FAILED")[:4000],
            "time": now_iso(),
        }
        _atomic_json(self.rejected_path, rejected)
        try:
            self.pending_path.unlink()
        except FileNotFoundError:
            pass
        return self._status(
            "ROLLED_BACK",
            rejected_version=failed_version,
            restored_version=self.current_version(),
            reason=rejected["reason"],
        )


__all__ = [
    "CONFIG_SCHEMA",
    "CONFIG_STORE_SCHEMA",
    "CentralConfigError",
    "CentralConfigStore",
    "build_document",
    "merge_effective_config",
    "sanitize_settings",
    "validate_document",
]
