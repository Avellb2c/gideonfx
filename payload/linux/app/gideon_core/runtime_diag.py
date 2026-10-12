from __future__ import annotations

from gideon_common.observability import best_effort_warning

import datetime as dt
import json
import os
import platform
import sys
import threading
import traceback
from pathlib import Path
from typing import Any, Optional

from gideon_io import atomic_write_json


def _now() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="milliseconds")


class ControllerRuntimeWatchdog:
    """Heartbeat independiente del asyncio/event-loop del FAN-OUT.

    El hilo puede seguir actualizando el sidecar aunque el monitor asyncio esté
    temporalmente detenido, lo que permite distinguir:
      - proceso Python muerto;
      - proceso Python vivo pero monitor sin avance;
      - excepción Python en recuperación.
    """

    def __init__(
        self,
        root: Path,
        job_id: str,
        *,
        phase: str,
        backend_log: Optional[str] = None,
        heartbeat_seconds: float = 5.0,
    ) -> None:
        self.root = Path(root)
        self.runtime_dir = self.root / "runtime"
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.job_id = str(job_id)
        self.path = self.runtime_dir / f"{self.job_id}.controller.json"
        self.phase = str(phase)
        self.backend_log = str(backend_log or "")
        self.heartbeat_seconds = max(1.0, float(heartbeat_seconds))
        self.started_at = _now()
        self.state = "RUNNING"
        self.restart_count = 0
        self.last_exception_type: Optional[str] = None
        self.last_exception_message: Optional[str] = None
        self.last_traceback_tail: Optional[str] = None
        self.last_exception_at: Optional[str] = None
        self.extra: dict[str, Any] = {}
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._loop,
            name=f"GIDEONControllerHeartbeat-{self.job_id}",
            daemon=True,
        )
        self._write()
        self._thread.start()

    def _payload(self) -> dict[str, Any]:
        with self._lock:
            payload = {
                "SchemaVersion": 1,
                "JobId": self.job_id,
                "Pid": os.getpid(),
                "ParentPid": os.getppid(),
                "State": self.state,
                "Phase": self.phase,
                "StartedAt": self.started_at,
                "HeartbeatAt": _now(),
                "PythonVersion": sys.version.split()[0],
                "PythonImplementation": platform.python_implementation(),
                "Executable": sys.executable,
                "Platform": platform.platform(),
                "BackendLog": self.backend_log,
                "MonitorRestartCount": self.restart_count,
                "LastExceptionType": self.last_exception_type,
                "LastExceptionMessage": self.last_exception_message,
                "LastTracebackTail": self.last_traceback_tail,
                "LastExceptionAt": self.last_exception_at,
            }
            payload.update(self.extra)
            return payload

    def _write(self) -> None:
        try:
            atomic_write_json(
                self.path,
                self._payload(),
                lock_timeout=0.5,
                retries=4,
            )
        except Exception as exc:
            # El diagnóstico jamás debe romper la orquestación.
            best_effort_warning("No se pudo persistir heartbeat de diagnóstico del controlador", exc)

    def _loop(self) -> None:
        while not self._stop.wait(self.heartbeat_seconds):
            self._write()

    def update(
        self,
        *,
        phase: Optional[str] = None,
        state: Optional[str] = None,
        restart_count: Optional[int] = None,
        **extra: Any,
    ) -> None:
        with self._lock:
            if phase is not None:
                self.phase = str(phase)
            if state is not None:
                self.state = str(state)
            if restart_count is not None:
                self.restart_count = int(restart_count)
            self.extra.update(extra)
        self._write()

    def exception(
        self,
        exc: BaseException,
        *,
        phase: Optional[str] = None,
        recovering: bool = False,
        restart_count: Optional[int] = None,
    ) -> None:
        tb = traceback.format_exc()
        lines = tb.strip().splitlines()
        tail = "\n".join(lines[-18:]) if lines else str(exc)
        with self._lock:
            if phase is not None:
                self.phase = str(phase)
            self.state = "ERROR_RECOVERING" if recovering else "FAILED"
            if restart_count is not None:
                self.restart_count = int(restart_count)
            self.last_exception_type = type(exc).__name__
            self.last_exception_message = str(exc)
            self.last_traceback_tail = tail
            self.last_exception_at = _now()
        self._write()

    def finish(self, state: str = "EXITED") -> None:
        with self._lock:
            self.state = str(state)
        self._write()
        self._stop.set()


_current: Optional[ControllerRuntimeWatchdog] = None
_current_lock = threading.RLock()


def start_runtime(
    root: Path,
    job_id: str,
    *,
    phase: str,
    heartbeat_seconds: float = 5.0,
) -> ControllerRuntimeWatchdog:
    global _current
    backend_log = os.environ.get("GIDEON_BACKEND_LOG", "")
    with _current_lock:
        if _current is not None and _current.job_id == str(job_id):
            _current.update(phase=phase, state="RUNNING")
            return _current
        if _current is not None:
            try:
                _current.finish("REPLACED")
            except Exception as exc:
                best_effort_warning("No se pudo cerrar el watchdog de runtime anterior", exc)
        _current = ControllerRuntimeWatchdog(
            root,
            str(job_id),
            phase=phase,
            backend_log=backend_log,
            heartbeat_seconds=heartbeat_seconds,
        )
        return _current


def update_runtime(**kwargs: Any) -> None:
    with _current_lock:
        if _current is not None:
            _current.update(**kwargs)


def report_runtime_exception(
    exc: BaseException,
    *,
    phase: Optional[str] = None,
    recovering: bool = False,
    restart_count: Optional[int] = None,
) -> None:
    with _current_lock:
        if _current is not None:
            _current.exception(
                exc,
                phase=phase,
                recovering=recovering,
                restart_count=restart_count,
            )


def finish_runtime(state: str = "EXITED") -> None:
    global _current
    with _current_lock:
        if _current is not None:
            try:
                _current.finish(state)
            finally:
                _current = None
