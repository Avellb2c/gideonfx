from __future__ import annotations

"""Small, isolated controller for an explicitly authorised offline VLC install.

The GIDEON Agent service owns tunnels, jobs and heartbeat.  Installing a third
party package must never be allowed to block any of those responsibilities, so
this controller starts a separate, short-lived process only after all of these
conditions are true:

* WebAdmin has sent an Ed25519-signed, Agent-bound authorisation;
* the embedded offline catalog has passed its own signature and hash checks;
* the Agent has no running Job or remote stream; and
* the service account is already elevated by the platform service manager.

No network request, package source, command text, or untrusted path is accepted
from the control plane.  The child invokes the fixed CLI in
``gideon_agent_vlc_offline`` and writes its local audit before the next heartbeat
reports the bounded result.
"""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Mapping

from gideon_agent_bootstrap import PRIVATE_FILE_MODE, atomic_json, enforce_path_mode
from gideon_agent_vlc_offline import (
    OfflineVlcAuthorizationError,
    OfflineVlcCatalogError,
    OfflineVlcInstaller,
    offline_vlc_catalog_capability,
    verify_install_authorization,
)


_REQUEST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,159}$")
_TERMINAL = frozenset({"INSTALLED", "FAILED", "CANCELLED", "EXPIRED", "SUPERSEDED"})


def _bounded(value: Any, maximum: int = 240) -> str:
    return str(value or "").replace("\x00", " ").strip()[:maximum]


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        return dict(value) if isinstance(value, Mapping) else {}
    except Exception:
        return {}


def _pid_alive(pid: Any) -> bool:
    """Return whether a recorded child still exists without accepting a command.

    A service restart loses the in-memory ``Popen`` handle.  We must not start
    the one-shot package operation a second time in that case, but we also must
    not report it as running forever if it already died.  ``pid`` is written by
    this controller only and is parsed as an integer before it is used.
    """
    try:
        value = int(pid)
    except (TypeError, ValueError):
        return False
    if value <= 0:
        return False
    if os.name == "nt":
        try:
            completed = subprocess.run(
                ["tasklist", "/FI", f"PID eq {value}", "/NH"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=3,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            return str(value).encode("ascii") in completed.stdout
        except Exception:
            # A transient process-inspection problem must be conservative: do
            # not risk a second package installation while recovery is unclear.
            return True
    try:
        stat_path = Path("/proc") / str(value) / "stat"
        if stat_path.is_file():
            fields = stat_path.read_text(encoding="utf-8", errors="ignore").split()
            if len(fields) > 2 and fields[2] == "Z":
                return False
        os.kill(value, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except Exception:
        # As above, an inconclusive inspection must not launch a duplicate.
        return True


class OfflineVlcInstallController:
    """Dispatch and observe one local offline VLC installation at a time."""

    def __init__(self, *, agent_root: Path, state_root: Path, agent_id: str, public_key_path: Path | None = None) -> None:
        self.agent_root = Path(agent_root).resolve()
        self.state_root = Path(state_root).resolve()
        self.agent_id = _bounded(agent_id, 160)
        self.public_key_path = Path(public_key_path) if public_key_path else self.agent_root / "gideon_agent_signing_public.pem"
        self.root = self.state_root / "player" / "vlc-offline"
        self.state_path = self.root / "dispatch.json"
        self.authorization_dir = self.root / "authorizations"
        self.log_dir = self.root / "logs"
        self._process: subprocess.Popen[Any] | None = None
        self._ensure_paths()

    def _ensure_paths(self) -> None:
        for path in (self.root, self.authorization_dir, self.log_dir):
            path.mkdir(parents=True, exist_ok=True)
            enforce_path_mode(path, 0o700)

    def capability(self) -> dict[str, Any]:
        return offline_vlc_catalog_capability(self.agent_root, self.public_key_path)

    def _state(self) -> dict[str, Any]:
        return _read_json(self.state_path)

    def _write_state(self, *, request_id: str, state: str, detail: str = "", pid: int = 0) -> None:
        self._ensure_paths()
        payload = {
            "Schema": "gideon-vlc-offline-dispatch/v1",
            "RequestId": _bounded(request_id, 160),
            "State": _bounded(state, 80).upper(),
            "Detail": _bounded(detail, 240),
            "Pid": max(0, int(pid or 0)),
        }
        atomic_json(self.state_path, payload, mode=PRIVATE_FILE_MODE)
        enforce_path_mode(self.state_path, PRIVATE_FILE_MODE)
        if payload["State"] in _TERMINAL:
            self._remove_authorization(payload["RequestId"])

    def _audit(self) -> dict[str, Any]:
        return _read_json(self.state_root / "player" / "vlc-offline-install.json")

    def _authorization_path(self, request_id: str) -> Path:
        if not _REQUEST_ID.fullmatch(request_id):
            raise OfflineVlcAuthorizationError("VLC_OFFLINE_REQUEST_ID_INVALID")
        return self.authorization_dir / f"{request_id}.json"

    def _remove_authorization(self, request_id: str) -> None:
        """Best-effort removal for every terminal path, including recovery."""
        try:
            self._authorization_path(request_id).unlink(missing_ok=True)
        except (OSError, OfflineVlcAuthorizationError):
            pass

    def _terminal_report(self, request_id: str, *, fallback: str = "") -> dict[str, Any] | None:
        audit = self._audit()
        if _bounded(audit.get("RequestId"), 160) != request_id:
            return None
        state = _bounded(audit.get("State"), 80).upper()
        if state not in {"INSTALLED", "FAILED"}:
            return None
        detail = _bounded(audit.get("Detail"), 240) or _bounded(fallback, 240)
        self._write_state(request_id=request_id, state=state, detail=detail)
        return {"RequestId": request_id, "State": state, "Detail": detail}

    def _observe_child(self, request_id: str) -> dict[str, Any] | None:
        process = self._process
        if process is not None:
            exit_code = process.poll()
            if exit_code is None:
                return {"RequestId": request_id, "State": "RUNNING", "Detail": "VLC_OFFLINE_INSTALL_RUNNING"}
            self._process = None
            terminal = self._terminal_report(request_id, fallback=f"VLC_OFFLINE_CHILD_EXIT_{int(exit_code)}")
            if terminal is not None:
                return terminal
            self._write_state(request_id=request_id, state="FAILED", detail=f"VLC_OFFLINE_CHILD_EXIT_{int(exit_code)}")
            return {"RequestId": request_id, "State": "FAILED", "Detail": f"VLC_OFFLINE_CHILD_EXIT_{int(exit_code)}"}
        state = self._state()
        if _bounded(state.get("RequestId"), 160) != request_id:
            return None
        current = _bounded(state.get("State"), 80).upper()
        if current in _TERMINAL:
            return {"RequestId": request_id, "State": current, "Detail": _bounded(state.get("Detail"), 240)}
        terminal = self._terminal_report(request_id)
        if terminal is not None:
            return terminal
        if current == "RUNNING":
            # A service restart lost the in-memory Popen handle.  Do not launch a
            # duplicate installer.  If the recorded child has gone away and no
            # signed local audit proves success/failure, end this request rather
            # than leaving it in RUNNING indefinitely.
            if _pid_alive(state.get("Pid")):
                return {"RequestId": request_id, "State": "RUNNING", "Detail": "VLC_OFFLINE_INSTALL_RECOVERY_PENDING"}
            self._write_state(request_id=request_id, state="FAILED", detail="VLC_OFFLINE_INSTALL_PROCESS_MISSING")
            return {"RequestId": request_id, "State": "FAILED", "Detail": "VLC_OFFLINE_INSTALL_PROCESS_MISSING"}
        return None

    def _validate_request(self, request: Mapping[str, Any]) -> tuple[str, dict[str, Any], dict[str, Any]]:
        request_id = _bounded(request.get("RequestId"), 160)
        if not _REQUEST_ID.fullmatch(request_id):
            raise OfflineVlcAuthorizationError("VLC_OFFLINE_REQUEST_ID_INVALID")
        authorization = request.get("Authorization")
        if not isinstance(authorization, Mapping):
            raise OfflineVlcAuthorizationError("VLC_OFFLINE_AUTHORIZATION_REQUIRED")
        plan = OfflineVlcInstaller(
            agent_root=self.agent_root, state_root=self.state_root, agent_id=self.agent_id,
            public_key_path=self.public_key_path,
        ).plan()
        approved = verify_install_authorization(
            dict(authorization), public_key_path=self.public_key_path, agent_id=self.agent_id,
            catalog_sha256=str(plan["CatalogSha256"]),
        )
        if approved["RequestId"] != request_id:
            raise OfflineVlcAuthorizationError("VLC_OFFLINE_REQUEST_BINDING_MISMATCH")
        return request_id, dict(authorization), plan

    def _launch(self, request_id: str, authorization: Mapping[str, Any]) -> dict[str, Any]:
        auth_path = self._authorization_path(request_id)
        atomic_json(auth_path, dict(authorization), mode=PRIVATE_FILE_MODE)
        enforce_path_mode(auth_path, PRIVATE_FILE_MODE)
        stdout_path = self.log_dir / f"{request_id}.stdout.log"
        stderr_path = self.log_dir / f"{request_id}.stderr.log"
        module = self.agent_root / "gideon_agent_vlc_offline.py"
        if not module.is_file():
            raise OfflineVlcCatalogError("VLC_OFFLINE_RUNTIME_MODULE_MISSING")
        command = [
            sys.executable, str(module), "--agent-root", str(self.agent_root),
            "--state-root", str(self.state_root), "--agent-id", self.agent_id,
            "--authorization", str(auth_path), "--install", "--accept-vlc-gpl",
        ]
        kwargs: dict[str, Any] = {
            "cwd": str(self.agent_root), "stdin": subprocess.DEVNULL,
        }
        if os.name == "nt":
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "DETACHED_PROCESS", 0)
        else:
            kwargs["start_new_session"] = True
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            self._process = subprocess.Popen(command, stdout=stdout, stderr=stderr, **kwargs)
        self._write_state(request_id=request_id, state="RUNNING", detail="VLC_OFFLINE_INSTALL_STARTED", pid=int(self._process.pid))
        return {"RequestId": request_id, "State": "RUNNING", "Detail": "VLC_OFFLINE_INSTALL_STARTED"}

    def synchronize(self, request: Mapping[str, Any] | None, *, busy_reason: str = "") -> dict[str, Any] | None:
        """Safely react to the current Gateway request, if any.

        The returned small record is intentionally safe to POST back to the
        Gateway. It never includes the signed authorization, paths, command, or
        process output.
        """
        if not isinstance(request, Mapping):
            return None
        request_id = _bounded(request.get("RequestId"), 160)
        if not _REQUEST_ID.fullmatch(request_id):
            return {"RequestId": request_id[:160], "State": "FAILED", "Detail": "VLC_OFFLINE_REQUEST_ID_INVALID"}
        observed = self._observe_child(request_id)
        if observed is not None:
            return observed
        state = _bounded(request.get("State"), 80).upper()
        if state not in {"REQUESTED", "DELIVERED", "DEFERRED"}:
            return None
        if busy_reason:
            detail = "VLC_OFFLINE_DEFERRED_" + _bounded(busy_reason, 120).upper()
            self._write_state(request_id=request_id, state="DEFERRED", detail=detail)
            return {"RequestId": request_id, "State": "DEFERRED", "Detail": detail}
        try:
            checked_request_id, authorization, _plan = self._validate_request(request)
            return self._launch(checked_request_id, authorization)
        except (OfflineVlcAuthorizationError, OfflineVlcCatalogError) as exc:
            detail = _bounded(exc, 240)
            self._write_state(request_id=request_id, state="FAILED", detail=detail)
            return {"RequestId": request_id, "State": "FAILED", "Detail": detail}
        except Exception:
            self._write_state(request_id=request_id, state="FAILED", detail="VLC_OFFLINE_DISPATCH_UNAVAILABLE")
            return {"RequestId": request_id, "State": "FAILED", "Detail": "VLC_OFFLINE_DISPATCH_UNAVAILABLE"}


__all__ = ["OfflineVlcInstallController"]
