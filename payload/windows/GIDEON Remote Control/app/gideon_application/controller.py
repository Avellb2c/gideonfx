from __future__ import annotations

from pathlib import Path
from typing import Mapping

from gideon_application.file_transfer import FileTransferService
from gideon_application.ports import FileTransportCapabilities, FileTransportFactoryPort, JobRepositoryPort, ProgressCallback, ScriptLaunchPort
from gideon_application.script_registry import ScriptRegistry
from gideon_domain import ArtifactDescriptor, HostTarget, JobRecord, TransportProfile


class RemoteControlController:
    """Fachada de aplicación usada por GUI/CLI.

    La UI no necesita conocer subprocess, SFTP, SCP, manifest locking ni hashes.
    """

    def __init__(
        self,
        *,
        script_launch: ScriptLaunchPort,
        file_transfer: FileTransferService,
        transfer_repository: JobRepositoryPort,
        transport_factory: FileTransportFactoryPort,
        script_registry: ScriptRegistry,
    ) -> None:
        self.script_launch: ScriptLaunchPort = script_launch
        self._file_transfer: FileTransferService = file_transfer
        self._transfer_repository: JobRepositoryPort = transfer_repository
        self._transport_factory: FileTransportFactoryPort = transport_factory
        self.script_registry: ScriptRegistry = script_registry

    def file_transport_capabilities(self) -> Mapping[TransportProfile, FileTransportCapabilities]:
        return self._transport_factory.available()

    def create_file_upload_job(
        self,
        *,
        source: Path,
        destination_dir: str,
        sites: list[HostTarget],
        transport_profile: TransportProfile,
    ) -> tuple[JobRecord, ArtifactDescriptor]:
        return self._file_transfer.create_upload_job(
            source=source,
            destination_dir=destination_dir,
            sites=sites,
            transport_profile=transport_profile,
        )

    async def execute_file_upload(
        self,
        *,
        job: JobRecord,
        artifact: ArtifactDescriptor,
        sites: Mapping[str, HostTarget],
        vpn_workers: int | None = None,
        progress: ProgressCallback | None = None,
    ) -> JobRecord:
        return await self._file_transfer.execute_upload(
            job=job,
            artifact=artifact,
            sites=sites,
            vpn_workers=vpn_workers,
            progress=progress,
        )

    async def resume_file_upload(
        self,
        *,
        job_id: str,
        sites: Mapping[str, HostTarget],
        vpn_workers: int | None = None,
        progress: ProgressCallback | None = None,
    ) -> JobRecord:
        return await self._file_transfer.resume_upload(
            job_id=job_id,
            sites=sites,
            vpn_workers=vpn_workers,
            progress=progress,
        )

    async def cancel_file_job(self, job_id: str, sites: Mapping[str, HostTarget]) -> JobRecord:
        return await self._file_transfer.cancel(job_id, sites)

    def get_file_job(self, job_id: str) -> JobRecord:
        return self._transfer_repository.get(job_id)

    def list_file_jobs(self) -> list[JobRecord]:
        return self._transfer_repository.list_jobs()

    def delete_file_job(self, job_id: str) -> None:
        self._transfer_repository.delete(job_id)
