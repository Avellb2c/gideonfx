from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class ManifestRepository(Protocol):
    def write(self, payload: dict[str, Any]) -> None: ...
    def read(self, job_id: str) -> dict[str, Any]: ...
    def list(self) -> list[dict[str, Any]]: ...


@runtime_checkable
class TransportGateway(Protocol):
    async def run_ps(self, site: Any, code: str, operation: str = "CONTROL") -> tuple[int, str, str, int]: ...
    async def sftp_batch(self, site: Any, batch_text: str, operation: str = "SFTP") -> tuple[int, str, str, int]: ...
    async def scp_file(
        self,
        site: Any,
        *,
        local_path: Path,
        remote_path: str,
        upload: bool,
        operation: str,
    ) -> tuple[int, str, str, int]: ...
    async def stdin_archive(
        self,
        site: Any,
        *,
        archive_path: Path,
        upload_folder: str,
        operation: str,
    ) -> tuple[int, str, str, int]: ...


@runtime_checkable
class EventSink(Protocol):
    def append(self, job_id: str, event_type: str, payload: dict[str, Any]) -> None: ...
