from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path


class SystemClock:
    def now_iso(self) -> str:
        return datetime.now(UTC).astimezone().isoformat(timespec="seconds")


class SHA256HashProvider:
    def sha256_file(self, path: Path) -> str:
        digest = hashlib.sha256()
        with Path(path).open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()


class ConsoleLogger:
    def info(self, message: str) -> None:
        print(f"[INFO] {message}")

    def warning(self, message: str) -> None:
        print(f"[WARN] {message}")

    def error(self, message: str) -> None:
        print(f"[ERROR] {message}")
