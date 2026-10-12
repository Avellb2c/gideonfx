from __future__ import annotations

"""Cross-platform single-writer lock for GIDEON product updates."""

import os
import time
from pathlib import Path


class UpdateLockBusy(RuntimeError):
    pass


class UpdateExecutionLock:
    def __init__(self, path: Path, *, timeout_seconds: float = 0.0) -> None:
        self.path = Path(path)
        self.timeout_seconds = max(0.0, float(timeout_seconds))
        self._handle = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.path.open("a+b")
        self._handle = handle
        deadline = time.monotonic() + self.timeout_seconds
        while True:
            try:
                if os.name == "nt":
                    import msvcrt
                    handle.seek(0, os.SEEK_END)
                    if handle.tell() == 0:
                        handle.write(b"0")
                        handle.flush()
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    handle.seek(0)
                    handle.truncate()
                    handle.write(f"pid={os.getpid()}\n".encode("ascii"))
                    handle.flush()
                    try:
                        os.fsync(handle.fileno())
                    except OSError:
                        pass
                return self
            except (BlockingIOError, OSError):
                if time.monotonic() >= deadline:
                    handle.close()
                    self._handle = None
                    raise UpdateLockBusy("UPDATE_BUSY: ya existe otra actualización GIDEON en ejecución.")
                time.sleep(0.1)

    def __exit__(self, exc_type, exc, tb):
        handle = self._handle
        self._handle = None
        if handle is None:
            return False
        try:
            if os.name == "nt":
                import msvcrt
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()
        return False
