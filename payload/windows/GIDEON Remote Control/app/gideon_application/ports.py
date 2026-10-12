from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Protocol, Sequence, runtime_checkable

from gideon_core.launch import LaunchPlan, LaunchRequest
from gideon_domain import ArtifactDescriptor, HostTarget, JobRecord, Outcome, TransferResult, TransportProfile


@runtime_checkable
class ClockPort(Protocol):
    def now_iso(self) -> str: ...


@runtime_checkable
class HashPort(Protocol):
    def sha256_file(self, path: Path) -> str: ...


@runtime_checkable
class LoggerPort(Protocol):
    def info(self, message: str) -> None: ...
    def warning(self, message: str) -> None: ...
    def error(self, message: str) -> None: ...


@runtime_checkable
class JobRepositoryPort(Protocol):
    def save(self, job: JobRecord) -> None: ...
    def get(self, job_id: str) -> JobRecord: ...
    def exists(self, job_id: str) -> bool: ...
    def delete(self, job_id: str) -> None: ...
    def list_jobs(self) -> list[JobRecord]: ...


@dataclass(frozen=True, slots=True)
class ScriptInteractionFinding:
    code: str
    label: str
    line: int


@runtime_checkable
class ScriptInteractionAnalyzerPort(Protocol):
    def analyze(self, path: Path) -> tuple[ScriptInteractionFinding, ...]: ...


@runtime_checkable
class ScriptLaunchPort(Protocol):
    def build_plan(self, request: LaunchRequest) -> LaunchPlan: ...
    def bootstrap_manifest(self, plan: LaunchPlan) -> dict[str, object]: ...
    def mark_started(self, plan: LaunchPlan, pid: int) -> dict[str, object]: ...
    def mark_failed(
        self,
        plan: LaunchPlan,
        *,
        error: str,
        return_code: int | None = None,
        log_tail: str | None = None,
    ) -> dict[str, object]: ...


@dataclass(frozen=True, slots=True)
class FileTransportCapabilities:
    profile: TransportProfile
    supports_upload: bool
    supports_download: bool
    supports_large_files: bool
    recommended_for_video: bool
    max_upload_bytes: int | None = None


ProgressCallback = Callable[[str, float, str, int, int], None]


@runtime_checkable
class FileTransferPort(Protocol):
    @property
    def profile(self) -> TransportProfile: ...

    @property
    def capabilities(self) -> FileTransportCapabilities: ...

    async def preflight(self, site: HostTarget) -> Outcome[None]: ...

    async def upload(
        self,
        site: HostTarget,
        artifact: ArtifactDescriptor,
        *,
        progress: ProgressCallback | None = None,
    ) -> Outcome[TransferResult]: ...

    async def download(
        self,
        site: HostTarget,
        remote_path: str,
        local_path: Path,
        *,
        progress: ProgressCallback | None = None,
    ) -> Outcome[TransferResult]: ...

    async def cancel_site(self, site: HostTarget) -> Outcome[None]: ...


@runtime_checkable
class FileTransportFactoryPort(Protocol):
    def get(self, profile: TransportProfile) -> FileTransferPort: ...
    def available(self) -> Mapping[TransportProfile, FileTransportCapabilities]: ...
