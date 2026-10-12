from __future__ import annotations

import asyncio
import os
import uuid
from pathlib import Path
from typing import Mapping

from gideon_application.artifacts import ArtifactService
from gideon_application.policies import BandwidthPolicy, ConnectivityRecoveryPolicy
from gideon_application.ports import (
    ClockPort,
    FileTransportFactoryPort,
    JobRepositoryPort,
    LoggerPort,
    ProgressCallback,
)
from gideon_domain import (
    ArtifactDescriptor,
    ArtifactKind,
    HostExecutionState,
    HostState,
    HostTarget,
    JobKind,
    JobRecord,
    JobState,
    Outcome,
    TransferResult,
    TransportProfile,
    ValidationError,
)


class FileTransferService:
    def __init__(
        self,
        *,
        repository: JobRepositoryPort,
        transport_factory: FileTransportFactoryPort,
        artifact_service: ArtifactService,
        clock: ClockPort,
        logger: LoggerPort,
        bandwidth_policy: BandwidthPolicy,
        recovery_policy: ConnectivityRecoveryPolicy,
    ) -> None:
        self._repository: JobRepositoryPort = repository
        self._transport_factory: FileTransportFactoryPort = transport_factory
        self._artifact_service: ArtifactService = artifact_service
        self._clock: ClockPort = clock
        self._logger: LoggerPort = logger
        self._bandwidth_policy: BandwidthPolicy = bandwidth_policy
        self._recovery_policy: ConnectivityRecoveryPolicy = recovery_policy
        self._cancel_events: dict[str, asyncio.Event] = {}

    @staticmethod
    def _job_id() -> str:
        from datetime import datetime
        return datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]

    @staticmethod
    def _target_key(site: HostTarget, profile: TransportProfile) -> str:
        if profile == TransportProfile.AGENT_HTTPS_PULL:
            return str(getattr(site, "agent_id", "") or site.code).strip()
        return site.code

    def create_upload_job(
        self,
        *,
        source: Path,
        destination_dir: str,
        sites: list[HostTarget],
        transport_profile: TransportProfile,
    ) -> tuple[JobRecord, ArtifactDescriptor]:
        if not sites:
            raise ValidationError("Debe seleccionar al menos un host.")
        destination: str = str(destination_dir).strip().rstrip("\\/")
        if not destination:
            raise ValidationError("El directorio remoto es obligatorio.")

        source_path: Path = Path(source).resolve()
        remote_path: str = destination + "\\" + source_path.name
        artifact: ArtifactDescriptor = self._artifact_service.build(source_path, remote_path)

        transport = self._transport_factory.get(transport_profile)
        capabilities = transport.capabilities
        if not capabilities.supports_upload:
            raise ValidationError(f"{transport_profile.value} no permite upload.")
        if capabilities.max_upload_bytes is not None and artifact.size_bytes > capabilities.max_upload_bytes:
            raise ValidationError(
                f"{transport_profile.value} admite máximo {capabilities.max_upload_bytes // (1024 * 1024)} MB; "
                "use SFTP o SCP para archivos grandes/videos."
            )

        now: str = self._clock.now_iso()
        targets: dict[str, HostExecutionState] = {}
        for site in sites:
            target_key = self._target_key(site, transport_profile)
            if target_key in targets:
                raise ValidationError(
                    f"Destino duplicado: {target_key}. En modo Agent cada equipo debe tener un AgentId distinto."
                )
            targets[target_key] = HostExecutionState(
                site_code=site.code,
                site_name=site.name,
                address=site.address,
                target_key=target_key,
                agent_id=str(getattr(site, "agent_id", "") or ""),
                agent_name=str(getattr(site, "agent_name", "") or ""),
                hostname=str(getattr(site, "hostname", "") or ""),
                state=HostState.PENDING,
                updated_at=now,
            )
        job = JobRecord(
            job_id=self._job_id(),
            kind=JobKind.VIDEO_TRANSFER if artifact.kind == ArtifactKind.VIDEO else JobKind.FILE_TRANSFER,
            transport_profile=transport_profile,
            state=JobState.CREATED,
            created_at=now,
            updated_at=now,
            targets=targets,
            source_file=str(artifact.local_path),
            destination_path=destination,
            controller_pid=os.getpid(),
        )
        self._repository.save(job)
        return job, artifact

    async def _wait_for_connectivity(
        self,
        *,
        job: JobRecord,
        site: HostTarget,
        execution: HostExecutionState,
        progress: ProgressCallback | None,
    ) -> bool:
        transport = self._transport_factory.get(job.transport_profile)
        deadline: float = asyncio.get_running_loop().time() + self._recovery_policy.max_wait_seconds
        while asyncio.get_running_loop().time() < deadline:
            cancel_event = self._cancel_events.get(job.job_id)
            if cancel_event is not None and cancel_event.is_set():
                return False
            execution.state = HostState.WAITING_CONNECTIVITY
            wait_label = (
                "Esperando Internet/Gateway · VPN no requerida"
                if job.transport_profile == TransportProfile.AGENT_HTTPS_PULL
                else "Esperando red/VPN"
            )
            execution.current_operation = wait_label
            execution.updated_at = self._clock.now_iso()
            self._repository.save(job)
            if progress:
                progress(execution.target_key or site.code, execution.progress_percent, wait_label, execution.bytes_sent, 0)
            await asyncio.sleep(max(1, self._recovery_policy.retry_seconds))
            probe = await transport.preflight(site)
            if probe.ok:
                return True
        return False

    async def execute_upload(
        self,
        *,
        job: JobRecord,
        artifact: ArtifactDescriptor,
        sites: Mapping[str, HostTarget],
        vpn_workers: int | None = None,
        progress: ProgressCallback | None = None,
    ) -> JobRecord:
        transport = self._transport_factory.get(job.transport_profile)
        workers: int = self._bandwidth_policy.workers_for(artifact.size_bytes, vpn_workers)
        semaphore = asyncio.Semaphore(workers)
        cancel_event = asyncio.Event()
        self._cancel_events[job.job_id] = cancel_event
        job.state = JobState.DISPATCHING
        self._repository.save(job)

        async def one(execution: HostExecutionState) -> None:
            target_key = execution.target_key or execution.agent_id or execution.site_code
            site: HostTarget | None = sites.get(target_key)
            if site is None and target_key != execution.site_code:
                # Compatibility for callers that still key a one-Agent site by SiteCode.
                site = sites.get(execution.site_code)
            if site is None:
                execution.state = HostState.FAILED
                execution.error_code = "HOST_NOT_FOUND"
                execution.error_detail = execution.site_code
                self._repository.save(job)
                return

            async with semaphore:
                if cancel_event.is_set() or job.cancel_requested:
                    execution.state = HostState.CANCELLED
                    self._repository.save(job)
                    return

                execution.state = HostState.PREFLIGHT
                execution.started_at = execution.started_at or self._clock.now_iso()
                execution.updated_at = self._clock.now_iso()
                execution.current_operation = "Preflight"
                execution.attempts += 1
                self._repository.save(job)
                if progress:
                    progress(target_key, 2.0, "Preflight", 0, artifact.size_bytes)

                probe = await transport.preflight(site)
                if not probe.ok:
                    if probe.error_code == "CONNECTIVITY_ERROR":
                        recovered = await self._wait_for_connectivity(
                            job=job,
                            site=site,
                            execution=execution,
                            progress=progress,
                        )
                        if not recovered:
                            execution.state = HostState.CANCELLED if cancel_event.is_set() else HostState.WAITING_CONNECTIVITY
                            execution.error_code = probe.error_code or "CONNECTIVITY_ERROR"
                            execution.error_detail = probe.error_message
                            execution.updated_at = self._clock.now_iso()
                            self._repository.save(job)
                            return
                    else:
                        execution.state = HostState.FAILED
                        execution.error_code = probe.error_code or "PREFLIGHT_FAILED"
                        execution.error_detail = probe.error_message
                        execution.updated_at = self._clock.now_iso()
                        execution.finished_at = execution.updated_at
                        self._repository.save(job)
                        return

                execution.state = HostState.UPLOADING
                execution.current_operation = f"Upload {job.transport_profile.value}"
                execution.updated_at = self._clock.now_iso()
                self._repository.save(job)

                def site_progress(code: str, percent: float, operation: str, sent: int, total: int) -> None:
                    execution.progress_percent = float(percent)
                    execution.current_operation = operation
                    execution.bytes_sent = int(sent)
                    execution.updated_at = self._clock.now_iso()
                    try:
                        self._repository.save(job)
                    except Exception as exc:
                        self._logger.warning(f"No se pudo persistir progreso {code}: {exc}")
                    if progress:
                        progress(target_key, percent, operation, sent, total)

                outcome: Outcome[TransferResult] = await transport.upload(site, artifact, progress=site_progress)
                if cancel_event.is_set():
                    execution.state = HostState.CANCELLED
                elif outcome.ok and outcome.value is not None:
                    execution.state = HostState.COLLECTED
                    execution.progress_percent = 100.0
                    execution.bytes_sent = outcome.value.bytes_transferred
                    execution.error_code = None
                    execution.error_detail = None
                else:
                    execution.state = HostState.FAILED
                    execution.error_code = outcome.error_code or "TRANSFER_FAILED"
                    execution.error_detail = outcome.error_message or "Transferencia fallida"
                execution.finished_at = self._clock.now_iso()
                execution.updated_at = execution.finished_at
                self._repository.save(job)

        try:
            await asyncio.gather(*(one(execution) for execution in job.targets.values()))
        finally:
            self._cancel_events.pop(job.job_id, None)

        states: list[HostState] = [x.state for x in job.targets.values()]
        if states and all(state == HostState.COLLECTED for state in states):
            job.state = JobState.COMPLETED
        elif states and all(state == HostState.CANCELLED for state in states):
            job.state = JobState.CANCELLED
        elif any(state == HostState.COLLECTED for state in states):
            job.state = JobState.PARTIAL
        elif any(state == HostState.WAITING_CONNECTIVITY for state in states):
            job.state = JobState.WAITING_CONNECTIVITY
        elif any(state == HostState.CANCELLED for state in states):
            job.state = JobState.CANCELLED
        else:
            job.state = JobState.FAILED
        self._repository.save(job)
        return job

    async def resume_upload(
        self,
        *,
        job_id: str,
        sites: Mapping[str, HostTarget],
        vpn_workers: int | None = None,
        progress: ProgressCallback | None = None,
    ) -> JobRecord:
        job: JobRecord = self._repository.get(job_id)
        if not job.source_file or not job.destination_path:
            raise ValidationError("El Job no contiene source/destination para reanudar.")
        source: Path = Path(job.source_file)
        artifact = self._artifact_service.build(source, job.destination_path.rstrip("\\/") + "\\" + source.name)
        for execution in job.targets.values():
            if execution.state != HostState.COLLECTED:
                execution.state = HostState.PENDING
                execution.error_code = None
                execution.error_detail = None
        job.cancel_requested = False
        return await self.execute_upload(
            job=job,
            artifact=artifact,
            sites=sites,
            vpn_workers=vpn_workers,
            progress=progress,
        )

    async def cancel(self, job_id: str, sites: Mapping[str, HostTarget]) -> JobRecord:
        job: JobRecord = self._repository.get(job_id)
        job.cancel_requested = True
        job.state = JobState.CANCEL_REQUESTED
        self._repository.save(job)
        event = self._cancel_events.get(job_id)
        if event is not None:
            event.set()
        transport = self._transport_factory.get(job.transport_profile)
        await asyncio.gather(
            *(transport.cancel_site(site) for target_key, site in sites.items() if target_key in job.targets),
            return_exceptions=True,
        )
        for execution in job.targets.values():
            if execution.state != HostState.COLLECTED:
                execution.state = HostState.CANCELLED
                execution.updated_at = self._clock.now_iso()
        job.state = JobState.CANCELLED
        self._repository.save(job)
        return job
