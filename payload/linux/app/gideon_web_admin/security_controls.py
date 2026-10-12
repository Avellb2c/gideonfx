from __future__ import annotations

import collections
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from threading import Lock


@dataclass(slots=True)
class RateDecision:
    allowed: bool
    retry_after: int = 0


class SlidingWindowLimiter:
    """Small in-process limiter for the single Web Admin worker.

    It intentionally avoids Redis or another daemon: GIDEON Web Admin runs a single
    worker by design on the headless appliance. Entries are pruned opportunistically
    so memory use remains bounded.
    """

    def __init__(self, *, window_seconds: int, max_failures: int, ban_seconds: int, max_keys: int = 4096) -> None:
        self.window = max(30, int(window_seconds))
        self.max_failures = max(3, int(max_failures))
        self.ban_seconds = max(60, int(ban_seconds))
        self.max_keys = max(128, int(max_keys))
        self._events: dict[str, collections.deque[int]] = {}
        self._banned: dict[str, int] = {}
        self._lock = Lock()

    def _prune(self, now: int) -> None:
        cutoff = now - self.window
        expired_bans = [k for k, until in self._banned.items() if until <= now]
        for key in expired_bans:
            self._banned.pop(key, None)
        stale = []
        for key, dq in self._events.items():
            while dq and dq[0] <= cutoff:
                dq.popleft()
            if not dq:
                stale.append(key)
        for key in stale:
            self._events.pop(key, None)
        if len(self._events) > self.max_keys:
            ranked = sorted(self._events.items(), key=lambda kv: kv[1][-1] if kv[1] else 0)
            for key, _ in ranked[: len(self._events) - self.max_keys]:
                self._events.pop(key, None)

    def check(self, key: str) -> RateDecision:
        clean = str(key or "unknown")[:256]
        now = int(time.time())
        with self._lock:
            self._prune(now)
            until = int(self._banned.get(clean) or 0)
            if until > now:
                return RateDecision(False, until - now)
            return RateDecision(True, 0)

    def failure(self, key: str) -> RateDecision:
        clean = str(key or "unknown")[:256]
        now = int(time.time())
        with self._lock:
            self._prune(now)
            dq = self._events.setdefault(clean, collections.deque())
            dq.append(now)
            if len(dq) >= self.max_failures:
                until = now + self.ban_seconds
                self._banned[clean] = until
                dq.clear()
                return RateDecision(False, self.ban_seconds)
            return RateDecision(True, 0)

    def success(self, key: str) -> None:
        clean = str(key or "unknown")[:256]
        with self._lock:
            self._events.pop(clean, None)
            self._banned.pop(clean, None)


def build_security_logger(path: str | Path | None) -> logging.Logger:
    logger = logging.getLogger("gideon.web.security")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if path:
        target = Path(path).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(target, encoding="utf-8")
    else:
        handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
    return logger
