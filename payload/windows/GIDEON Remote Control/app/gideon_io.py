#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GIDEON local I/O primitives.

Objetivos:
- escritura atómica con temporales únicos;
- lock interproceso corto para writers GIDEON;
- retry ante sharing violations/antivirus en Windows;
- lectura JSON tolerante a replace atómico.
"""
from __future__ import annotations

import errno
import json
import logging
import os
import random
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Optional


def _retryable_os_error(exc: BaseException) -> bool:
    if isinstance(exc, PermissionError):
        return True
    winerror = getattr(exc, 'winerror', None)
    if winerror in {5, 32, 33}:  # ACCESS_DENIED / SHARING / LOCK
        return True
    eno = getattr(exc, 'errno', None)
    return eno in {errno.EACCES, errno.EBUSY, errno.EPERM}


_LOG = logging.getLogger(__name__)

class InterProcessFileLock:
    """Lock corto que se libera automáticamente al morir el proceso."""
    def __init__(self, target: Path, timeout: float = 2.0, poll: float = 0.025):
        self.path = Path(str(target) + '.lock')
        self.timeout = max(0.1, float(timeout))
        self.poll = max(0.005, float(poll))
        self._fh = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.path, 'a+b', buffering=0)
        self._fh.seek(0, os.SEEK_END)
        if self._fh.tell() == 0:
            self._fh.write(b'0')
            self._fh.flush()
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                self._fh.seek(0)
                if os.name == 'nt':
                    import msvcrt
                    msvcrt.locking(self._fh.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except (OSError, BlockingIOError):
                if time.monotonic() >= deadline:
                    self.release()
                    raise TimeoutError(f'No se pudo adquirir lock local: {self.path}')
                time.sleep(self.poll)

    def release(self) -> None:
        fh = self._fh
        self._fh = None
        if fh is None:
            return
        try:
            fh.seek(0)
            if os.name == 'nt':
                import msvcrt
                try:
                    msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
            else:
                import fcntl
                try:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
        finally:
            try:
                fh.close()
            except Exception as exc:
                _LOG.debug("No se pudo cerrar el lock file: %s", exc)

    def __enter__(self):
        self.acquire(); return self
    def __exit__(self, exc_type, exc, tb):
        self.release(); return False


def _unique_tmp(path: Path) -> Path:
    return path.with_name(
        f'.{path.name}.{os.getpid()}.{threading.get_ident()}.{uuid.uuid4().hex[:10]}.tmp'
    )


def _replace_with_retry(tmp: Path, path: Path, retries: int = 8) -> None:
    delays = [0.02, 0.04, 0.08, 0.12, 0.20, 0.32, 0.50, 0.75]
    last = None
    for attempt in range(max(1, retries)):
        try:
            os.replace(tmp, path)
            return
        except OSError as exc:
            last = exc
            if not _retryable_os_error(exc) or attempt >= retries - 1:
                raise
            base = delays[min(attempt, len(delays)-1)]
            time.sleep(base + random.uniform(0, min(0.025, base/4)))
    if last:
        raise last


def _atomic_write_bytes_unlocked(path: Path, data: bytes, retries: int = 8) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = _unique_tmp(path)
    try:
        with open(tmp, 'wb') as fh:
            fh.write(data)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass
        _replace_with_retry(tmp, path, retries=retries)
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except Exception as exc:
            _LOG.debug("No se pudo retirar temporal %s: %s", tmp, exc)


def atomic_write_text(path: Path, text: str, *, encoding: str='utf-8', lock_timeout: float=2.0, retries: int=8) -> None:
    path = Path(path)
    with InterProcessFileLock(path, timeout=lock_timeout):
        _atomic_write_bytes_unlocked(path, text.encode(encoding), retries=retries)


def atomic_write_json(path: Path, payload: Any, *, lock_timeout: float=2.0, retries: int=8) -> None:
    text = json.dumps(payload, indent=2, ensure_ascii=False, default=str)
    atomic_write_text(path, text, encoding='utf-8', lock_timeout=lock_timeout, retries=retries)


def atomic_write_json_nolock(path: Path, payload: Any, *, retries: int=8) -> None:
    """Atomic write with unique temp but without a persistent lock sidecar.

    Use only when the target filename is owned by a single writer (for example
    `<JOB>.<PID>.proc`). This avoids accumulating thousands of `.lock` files.
    """
    path = Path(path)
    text = json.dumps(payload, indent=2, ensure_ascii=False, default=str)
    _atomic_write_bytes_unlocked(path, text.encode('utf-8'), retries=retries)


def read_json_retry(path: Path, *, retries: int=5, delay: float=0.025, encoding: str='utf-8-sig') -> Any:
    path = Path(path)
    last = None
    for attempt in range(max(1, retries)):
        try:
            return json.loads(path.read_text(encoding=encoding))
        except (PermissionError, FileNotFoundError, json.JSONDecodeError, OSError) as exc:
            last = exc
            if isinstance(exc, OSError) and not isinstance(exc, (PermissionError, FileNotFoundError)) and not _retryable_os_error(exc):
                raise
            if attempt >= retries - 1:
                raise
            time.sleep(delay * (attempt + 1))
    if last:
        raise last


def update_json_atomic(
    path: Path,
    updater: Callable[[Any], Any],
    *,
    default: Any=None,
    lock_timeout: float=2.0,
    retries: int=8,
) -> Any:
    """Read-modify-write bajo el MISMO lock interproceso."""
    path = Path(path)
    with InterProcessFileLock(path, timeout=lock_timeout):
        if path.exists():
            try:
                current = read_json_retry(path, retries=3)
            except Exception:
                if default is None:
                    raise
                current = default
        else:
            current = default
        new_value = updater(current)
        text = json.dumps(new_value, indent=2, ensure_ascii=False, default=str)
        _atomic_write_bytes_unlocked(path, text.encode('utf-8'), retries=retries)
        return new_value
