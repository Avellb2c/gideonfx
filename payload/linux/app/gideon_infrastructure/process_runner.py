from __future__ import annotations

import asyncio
import os
import subprocess
from dataclasses import dataclass
from typing import Sequence

from gideon_domain import ConnectivityError, RemoteCommandResult


@dataclass(frozen=True, slots=True)
class ProcessInvocation:
    args: tuple[str, ...]
    site_code: str
    operation: str
    timeout_seconds: int


class AsyncProcessRunner:
    def __init__(self) -> None:
        self._active: dict[int, tuple[str, asyncio.subprocess.Process]] = {}
        self._lock: asyncio.Lock = asyncio.Lock()

    async def run(
        self,
        args: Sequence[str],
        *,
        site_code: str,
        operation: str,
        timeout_seconds: int,
        stdin_data: bytes | None = None,
    ) -> RemoteCommandResult:
        creationflags: int = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        process: asyncio.subprocess.Process = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE if stdin_data is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            creationflags=creationflags,
        )
        async with self._lock:
            self._active[int(process.pid)] = (site_code, process)

        try:
            stdout_raw, stderr_raw = await asyncio.wait_for(
                process.communicate(stdin_data),
                timeout=max(1, int(timeout_seconds)),
            )
        except TimeoutError as exc:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            await process.wait()
            raise ConnectivityError(f"Timeout {operation} para {site_code}") from exc
        except asyncio.CancelledError:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            await process.wait()
            raise
        finally:
            async with self._lock:
                self._active.pop(int(process.pid), None)

        return RemoteCommandResult(
            exit_code=int(process.returncode or 0),
            stdout=stdout_raw.decode("utf-8", errors="replace"),
            stderr=stderr_raw.decode("utf-8", errors="replace"),
        )

    async def cancel_site(self, site_code: str) -> int:
        async with self._lock:
            matches: list[asyncio.subprocess.Process] = [
                proc for code, proc in self._active.values() if code == site_code
            ]
        cancelled: int = 0
        for proc in matches:
            if proc.returncode is not None:
                continue
            try:
                proc.kill()
                cancelled += 1
            except ProcessLookupError:
                continue
        return cancelled
