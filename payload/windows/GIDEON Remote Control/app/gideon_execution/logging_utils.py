from __future__ import annotations

import datetime as dt


def log(message: str, level: str = "INFO") -> None:
    stamp = dt.datetime.now().strftime("%H:%M:%S")
    print(f"[{stamp}] [{level}] {message}", flush=True)


def ok(message: str) -> None:
    log(message, "OK")


def warn(message: str) -> None:
    log(message, "WARN")


def fail(message: str) -> None:
    log(message, "ERROR")
