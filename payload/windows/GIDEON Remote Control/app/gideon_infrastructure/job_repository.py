from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Mapping

from gideon_application.ports import ClockPort
from gideon_domain import (
    HostExecutionState,
    HostState,
    JobKind,
    JobRecord,
    JobState,
    PersistenceError,
    TransportProfile,
)
from gideon_io import atomic_write_json, read_json_retry


class AtomicJsonJobRepository:
    """Repositorio para Jobs de aplicación (transferencias/reportes).

    Usa los primitives endurecidos existentes del proyecto: lock interproceso,
    temporal único y retry de os.replace ante antivirus/sharing violations.
    """

    def __init__(self, root: Path, clock: ClockPort) -> None:
        self._root: Path = Path(root).resolve()
        self._clock: ClockPort = clock
        self._root.mkdir(parents=True, exist_ok=True)

    def _path(self, job_id: str) -> Path:
        return self._root / f"{job_id}.json"

    @staticmethod
    def _serialize(job: JobRecord) -> dict[str, object]:
        return asdict(job)

    @staticmethod
    def _target_from_dict(raw: Mapping[str, object]) -> HostExecutionState:
        return HostExecutionState(
            site_code=str(raw.get("site_code") or ""),
            site_name=str(raw.get("site_name") or ""),
            address=str(raw.get("address") or ""),
            target_key=str(raw.get("target_key") or raw.get("agent_id") or raw.get("site_code") or ""),
            agent_id=str(raw.get("agent_id") or ""),
            agent_name=str(raw.get("agent_name") or ""),
            hostname=str(raw.get("hostname") or ""),
            state=HostState(str(raw.get("state") or HostState.PENDING)),
            attempts=int(raw.get("attempts") or 0),
            progress_percent=float(raw.get("progress_percent") or 0.0),
            current_operation=str(raw.get("current_operation") or ""),
            current_script=str(raw.get("current_script") or ""),
            bytes_sent=int(raw.get("bytes_sent") or 0),
            bytes_received=int(raw.get("bytes_received") or 0),
            started_at=str(raw.get("started_at")) if raw.get("started_at") else None,
            updated_at=str(raw.get("updated_at")) if raw.get("updated_at") else None,
            finished_at=str(raw.get("finished_at")) if raw.get("finished_at") else None,
            remote_pid=int(raw.get("remote_pid")) if raw.get("remote_pid") is not None else None,
            exit_code=int(raw.get("exit_code")) if raw.get("exit_code") is not None else None,
            error_code=str(raw.get("error_code")) if raw.get("error_code") else None,
            error_detail=str(raw.get("error_detail")) if raw.get("error_detail") else None,
        )

    @classmethod
    def _deserialize(cls, raw: Mapping[str, object]) -> JobRecord:
        raw_targets: object = raw.get("targets")
        targets: dict[str, HostExecutionState] = {}
        if isinstance(raw_targets, dict):
            for code, value in raw_targets.items():
                if isinstance(value, dict):
                    targets[str(code)] = cls._target_from_dict(value)

        raw_scripts: object = raw.get("scripts")
        scripts: list[str] = [str(x) for x in raw_scripts] if isinstance(raw_scripts, list) else []

        return JobRecord(
            job_id=str(raw.get("job_id") or ""),
            kind=JobKind(str(raw.get("kind") or JobKind.FILE_TRANSFER)),
            transport_profile=TransportProfile(str(raw.get("transport_profile") or TransportProfile.SFTP_SSH_SFTP)),
            state=JobState(str(raw.get("state") or JobState.CREATED)),
            created_at=str(raw.get("created_at") or ""),
            updated_at=str(raw.get("updated_at") or ""),
            targets=targets,
            scripts=scripts,
            source_file=str(raw.get("source_file")) if raw.get("source_file") else None,
            destination_path=str(raw.get("destination_path")) if raw.get("destination_path") else None,
            controller_pid=int(raw.get("controller_pid")) if raw.get("controller_pid") is not None else None,
            backend_log=str(raw.get("backend_log")) if raw.get("backend_log") else None,
            continue_on_error=bool(raw.get("continue_on_error", True)),
            cancel_requested=bool(raw.get("cancel_requested", False)),
            error_code=str(raw.get("error_code")) if raw.get("error_code") else None,
            error_detail=str(raw.get("error_detail")) if raw.get("error_detail") else None,
        )

    def save(self, job: JobRecord) -> None:
        job.updated_at = self._clock.now_iso()
        try:
            atomic_write_json(self._path(job.job_id), self._serialize(job), lock_timeout=3.0, retries=10)
        except Exception as exc:
            raise PersistenceError(f"No se pudo guardar Job {job.job_id}: {exc}") from exc

    def get(self, job_id: str) -> JobRecord:
        path: Path = self._path(job_id)
        if not path.exists():
            raise PersistenceError(f"Job no encontrado: {job_id}")
        try:
            raw: object = read_json_retry(path, retries=6)
        except Exception as exc:
            raise PersistenceError(f"No se pudo leer Job {job_id}: {exc}") from exc
        if not isinstance(raw, dict):
            raise PersistenceError(f"Manifest inválido para Job {job_id}")
        return self._deserialize(raw)

    def exists(self, job_id: str) -> bool:
        return self._path(job_id).exists()

    def delete(self, job_id: str) -> None:
        try:
            self._path(job_id).unlink(missing_ok=True)
        except OSError as exc:
            raise PersistenceError(f"No se pudo eliminar Job {job_id}: {exc}") from exc

    def list_jobs(self) -> list[JobRecord]:
        result: list[JobRecord] = []
        for path in sorted(self._root.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                result.append(self.get(path.stem))
            except PersistenceError:
                continue
        return result
