from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from gideon_application import ArtifactService, BandwidthPolicy, ConnectivityRecoveryPolicy, FileTransferService, RemoteControlController, ScriptRegistry
from gideon_application.ports import JobRepositoryPort, ScriptLaunchPort
from gideon_core.launch import LaunchService
from gideon_domain import TransportProfile
from gideon_infrastructure.agent_file_transport import AgentHttpsPullFileTransport
from gideon_infrastructure.file_transports import (
    FileTransportFactory,
    NativeSCPFileTransport,
    NativeSFTPFileTransport,
    NativeSTDINFileTransport,
    SSHClientConfig,
)
from gideon_infrastructure.job_repository import AtomicJsonJobRepository
from gideon_infrastructure.launch_adapter import LegacyScriptLaunchAdapter
from gideon_infrastructure.process_runner import AsyncProcessRunner
from gideon_infrastructure.powershell_analysis import PowerShellInteractiveAnalyzer
from gideon_infrastructure.system import ConsoleLogger, SHA256HashProvider, SystemClock


@dataclass(frozen=True, slots=True)
class ApplicationContainer:
    controller: RemoteControlController
    script_launch: ScriptLaunchPort
    transfer_repository: JobRepositoryPort
    clock: SystemClock
    hash_provider: SHA256HashProvider
    logger: ConsoleLogger
    process_runner: AsyncProcessRunner


def _as_mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, dict) else {}


def _int(mapping: Mapping[str, object], key: str, default: int) -> int:
    try:
        return int(mapping.get(key, default))
    except (TypeError, ValueError):
        return default


def build_application(
    *,
    app_root: Path,
    cfg: Mapping[str, object],
    jobs_dir: Path,
    logs_dir: Path,
    transfer_jobs_dir: Path,
    python_exe: str,
    version: str,
    key_path: Path,
    known_hosts: Path,
) -> ApplicationContainer:
    """Composition Root: único lugar donde se crean dependencias concretas."""
    root: Path = Path(app_root).resolve()
    ssh_cfg: Mapping[str, object] = _as_mapping(cfg.get("ssh"))
    transfer_cfg: Mapping[str, object] = _as_mapping(cfg.get("file_transfer"))

    clock = SystemClock()
    hash_provider = SHA256HashProvider()
    logger = ConsoleLogger()
    process_runner = AsyncProcessRunner()

    script_registry = ScriptRegistry(root / "scripts")
    launch_service = LaunchService(
        app_root=root,
        jobs_dir=Path(jobs_dir),
        logs_dir=Path(logs_dir),
        python_exe=str(python_exe),
        version=str(version),
    )
    interaction_analyzer = PowerShellInteractiveAnalyzer()
    script_launch: ScriptLaunchPort = LegacyScriptLaunchAdapter(
        launch_service,
        script_registry,
        interaction_analyzer,
    )

    repository: JobRepositoryPort = AtomicJsonJobRepository(Path(transfer_jobs_dir), clock)

    ssh_client = SSHClientConfig(
        username=str(ssh_cfg.get("user") or "damautapp"),
        key_path=Path(key_path),
        known_hosts=Path(known_hosts),
        port=_int(ssh_cfg, "port", 22),
        connect_timeout_seconds=_int(ssh_cfg, "connect_timeout_seconds", 20),
        strict_host_key_checking=str(ssh_cfg.get("strict_host_key_checking") or "accept-new"),
    )

    sftp = NativeSFTPFileTransport(ssh_client, process_runner, hash_provider)
    scp = NativeSCPFileTransport(ssh_client, process_runner, hash_provider)
    stdin = NativeSTDINFileTransport(ssh_client, process_runner, hash_provider)
    agent_https = AgentHttpsPullFileTransport(app_root=root, cfg=cfg)
    transport_factory = FileTransportFactory({
        TransportProfile.SFTP_SSH_SFTP: sftp,
        TransportProfile.SCP_SSH_SCP: scp,
        TransportProfile.STDIN_SSH_SCP: stdin,
        TransportProfile.AGENT_HTTPS_PULL: agent_https,
    })

    bandwidth = BandwidthPolicy(
        normal_workers=_int(transfer_cfg, "normal_workers", 4),
        large_file_workers=_int(transfer_cfg, "large_file_workers", 2),
        critical_workers=_int(transfer_cfg, "critical_workers", 1),
        large_file_threshold_bytes=_int(transfer_cfg, "large_file_threshold_bytes", 500 * 1024 * 1024),
        critical_file_threshold_bytes=_int(transfer_cfg, "critical_file_threshold_bytes", 2 * 1024 * 1024 * 1024),
    )
    recovery = ConnectivityRecoveryPolicy(
        retry_seconds=_int(transfer_cfg, "retry_seconds", 15),
        max_wait_seconds=_int(transfer_cfg, "max_wait_seconds", 3600),
    )
    artifact_service = ArtifactService(hash_provider)
    file_transfer = FileTransferService(
        repository=repository,
        transport_factory=transport_factory,
        artifact_service=artifact_service,
        clock=clock,
        logger=logger,
        bandwidth_policy=bandwidth,
        recovery_policy=recovery,
    )
    controller = RemoteControlController(
        script_launch=script_launch,
        file_transfer=file_transfer,
        transfer_repository=repository,
        transport_factory=transport_factory,
        script_registry=script_registry,
    )
    return ApplicationContainer(
        controller=controller,
        script_launch=script_launch,
        transfer_repository=repository,
        clock=clock,
        hash_provider=hash_provider,
        logger=logger,
        process_runner=process_runner,
    )
