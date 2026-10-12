from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .enums import ArtifactKind, HostState, JobKind, JobState, RiskLevel, TransportProfile


@dataclass(frozen=True, slots=True)
class HostTarget:
    code: str
    name: str
    address: str
    platform: str = "windows"
    host_profile: str = "windows_generic"
    agent_id: str = ""
    agent_name: str = ""
    hostname: str = ""

    @property
    def label(self) -> str:
        return f"{self.code}_{self.name}"


@dataclass(frozen=True, slots=True)
class ScriptManifest:
    script_id: str
    name: str
    version: str
    path: Path
    risk: RiskLevel
    minimum_powershell: str = "5.1"
    requires_admin: bool = True
    requires_network: bool = False
    requires_reboot: bool = False
    timeout_seconds: int = 1800
    continue_on_error: bool = True
    supported_platforms: tuple[str, ...] = ("windows",)
    host_profiles: tuple[str, ...] = ()
    description: str = ""


@dataclass(frozen=True, slots=True)
class ArtifactDescriptor:
    local_path: Path
    remote_path: str
    kind: ArtifactKind
    size_bytes: int
    sha256: str


@dataclass(frozen=True, slots=True)
class RemoteCommandResult:
    exit_code: int
    stdout: str
    stderr: str


@dataclass(frozen=True, slots=True)
class TransferResult:
    bytes_transferred: int
    remote_path: str
    sha256: str | None = None
    elapsed_seconds: float = 0.0


@dataclass(slots=True)
class HostExecutionState:
    site_code: str
    site_name: str
    address: str
    target_key: str = ""
    agent_id: str = ""
    agent_name: str = ""
    hostname: str = ""
    state: HostState = HostState.PENDING
    attempts: int = 0
    progress_percent: float = 0.0
    current_operation: str = ""
    current_script: str = ""
    bytes_sent: int = 0
    bytes_received: int = 0
    started_at: str | None = None
    updated_at: str | None = None
    finished_at: str | None = None
    remote_pid: int | None = None
    exit_code: int | None = None
    error_code: str | None = None
    error_detail: str | None = None


@dataclass(slots=True)
class JobRecord:
    job_id: str
    kind: JobKind
    transport_profile: TransportProfile
    state: JobState
    created_at: str
    updated_at: str
    targets: dict[str, HostExecutionState]
    scripts: list[str] = field(default_factory=list)
    source_file: str | None = None
    destination_path: str | None = None
    controller_pid: int | None = None
    backend_log: str | None = None
    continue_on_error: bool = True
    cancel_requested: bool = False
    error_code: str | None = None
    error_detail: str | None = None
