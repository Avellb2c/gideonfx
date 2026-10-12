from __future__ import annotations

import time
from collections.abc import Callable

from PySide6.QtCore import QObject, QTimer


class RefreshCoordinator(QObject):
    """Refresh only the visible page and keep one timer for the whole console."""

    def __init__(self, parent: QObject | None = None, *, tick_ms: int = 1000) -> None:
        super().__init__(parent)
        self._entries: dict[str, tuple[Callable[[], None], float]] = {}
        self._last_run: dict[str, float] = {}
        self._active: str | None = None
        self.timer = QTimer(self)
        self.timer.setInterval(max(250, int(tick_ms)))
        self.timer.timeout.connect(self._tick)
        self.timer.start()

    def register(self, key: str, callback: Callable[[], None], interval_seconds: float) -> None:
        self._entries[str(key)] = (callback, max(0.5, float(interval_seconds)))

    def set_interval(self, key: str, interval_seconds: float) -> None:
        if key not in self._entries:
            return
        callback, _old = self._entries[key]
        self._entries[key] = (callback, max(0.5, float(interval_seconds)))

    def set_active(self, key: str, *, refresh_now: bool = False) -> None:
        self._active = key if key in self._entries else None
        if refresh_now and self._active:
            self.run_now(self._active)

    def run_now(self, key: str) -> None:
        entry = self._entries.get(key)
        if entry is None:
            return
        callback, _interval = entry
        callback()
        self._last_run[key] = time.monotonic()

    def mark_fresh(self, key: str) -> None:
        self._last_run[key] = time.monotonic()

    def _tick(self) -> None:
        key = self._active
        if not key or key not in self._entries:
            return
        callback, interval = self._entries[key]
        now = time.monotonic()
        if now - self._last_run.get(key, 0.0) < interval:
            return
        callback()
        self._last_run[key] = now
