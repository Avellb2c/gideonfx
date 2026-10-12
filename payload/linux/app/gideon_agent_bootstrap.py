from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import threading
import time
from typing import Any, Mapping


PRIVATE_FILE_MODE = 0o600
PUBLIC_STATUS_MODE = 0o644
PRIVATE_DIRECTORY_MODE = 0o700
_ATOMIC_JSON_LOCK = threading.RLock()


def enforce_path_mode(path: Path, mode: int) -> bool:
    """Apply a POSIX mode without replacing the Windows ACL security model.

    POSIX failures are fatal because continuing could leave credentials readable
    by another local account.  Windows only exposes the read-only bit through
    ``chmod``; its installer-owned ACL remains authoritative, so chmod is best
    effort there and must never prevent the Agent from starting.
    """

    try:
        Path(path).chmod(mode)
        return True
    except (NotImplementedError, OSError):
        if os.name != "nt":
            raise
        return False


def atomic_json(path: Path, value: Mapping[str, Any], *, mode: int = PRIVATE_FILE_MODE) -> None:
    """Atomically persist JSON, tolerating short-lived Windows file locks."""

    with _ATOMIC_JSON_LOCK:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}.{time.time_ns()}")
        payload = json.dumps(dict(value), ensure_ascii=False, indent=2) + "\n"
        descriptor: int | None = None
        try:
            descriptor = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                descriptor = None
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            # The explicit chmod both defeats a permissive umask on the temporary
            # inode and repairs an existing target that previously had mode 0644.
            enforce_path_mode(tmp, mode)
            deadline = time.monotonic() + 2.0
            while True:
                try:
                    os.replace(tmp, path)
                    break
                except PermissionError:
                    # Antivirus, Explorer and the GIDEON tray may briefly open the
                    # public status file without FILE_SHARE_DELETE on Windows.
                    # Retrying preserves atomicity and prevents that harmless
                    # reader race from terminating the Agent/tunnel loop.
                    if os.name != "nt" or time.monotonic() >= deadline:
                        raise
                    time.sleep(0.05)
            enforce_path_mode(path, mode)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass


@dataclass(frozen=True, slots=True)
class AgentPaths:
    """Filesystem layout owned by one GIDEON Agent instance."""

    root: Path
    jobs: Path
    packages: Path
    security: Path
    replay: Path
    runtime_config: Path
    status: Path
    log: Path

    @classmethod
    def from_root(cls, root: Path) -> "AgentPaths":
        root = Path(root)
        security = root / "security"
        return cls(
            root=root,
            jobs=root / "jobs",
            packages=root / "packages",
            security=security,
            replay=security / "replay_state.json",
            runtime_config=root / "agent.runtime.json",
            status=root / "agent.status.json",
            log=root / "agent.log",
        )

    def ensure(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.jobs.mkdir(exist_ok=True)
        self.packages.mkdir(exist_ok=True)
        self.security.mkdir(mode=PRIVATE_DIRECTORY_MODE, exist_ok=True)
        enforce_path_mode(self.security, PRIVATE_DIRECTORY_MODE)

        # Repair permissions left by older Agent releases at every startup.
        for private_path in (self.runtime_config, self.replay):
            if private_path.is_file():
                enforce_path_mode(private_path, PRIVATE_FILE_MODE)
        if self.status.is_file():
            # The tray may run in the signed-in desktop session while the Agent
            # runs as a service.  This document is deliberately secret-free.
            enforce_path_mode(self.status, PUBLIC_STATUS_MODE)


@dataclass(frozen=True, slots=True)
class AgentTimingPolicy:
    """Validated timing values used by the Agent runtime loop."""

    network_check_seconds: int
    poll_seconds: int
    status_seconds: int
    cancel_grace_seconds: int
    config_check_seconds: int

    @classmethod
    def from_config(
        cls,
        config: Mapping[str, Any],
        base_config: Mapping[str, Any],
    ) -> "AgentTimingPolicy":
        control_plane = dict(config.get("control_plane", {}) or {})
        return cls(
            network_check_seconds=max(2, int(control_plane.get("network_check_seconds", 3))),
            poll_seconds=max(2, int(config.get("poll_seconds", 5))),
            status_seconds=max(2, int(config.get("status_seconds", 5))),
            cancel_grace_seconds=max(2, int(config.get("cancel_grace_seconds", 8))),
            config_check_seconds=max(15, int(base_config.get("config_check_seconds", 30) or 30)),
        )
