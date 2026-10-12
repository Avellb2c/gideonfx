from __future__ import annotations

from gideon_common.observability import best_effort_warning

import base64
import asyncio
import json
import os
import shutil
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from gideon_application.ports import FileTransportCapabilities, FileTransferPort, HashPort, ProgressCallback
from gideon_domain import (
    ArtifactDescriptor,
    ConnectivityError,
    HostTarget,
    Outcome,
    TransferResult,
    TransportProfile,
    ValidationError,
)
from gideon_infrastructure.process_runner import AsyncProcessRunner


@dataclass(frozen=True, slots=True)
class SSHClientConfig:
    username: str
    key_path: Path
    known_hosts: Path
    port: int = 22
    connect_timeout_seconds: int = 20
    strict_host_key_checking: str = "accept-new"


def _ps_quote(value: str) -> str:
    return str(value).replace("'", "''")


def _parse_json_tail(stdout: str) -> dict[str, object]:
    for line in reversed(stdout.splitlines()):
        candidate: str = line.strip()
        if not candidate:
            continue
        try:
            parsed: object = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return dict(parsed)
    return {}


def _classify_openssh_failure(stderr: str, stdout: str) -> tuple[str, str]:
    detail: str = (stderr.strip() or stdout.strip() or "OpenSSH operation failed")
    low: str = detail.lower()
    if "permission denied" in low or "authentication failed" in low:
        return "AUTH_FAILED", detail
    connectivity_tokens: tuple[str, ...] = (
        "connection timed out",
        "connection timeout",
        "connection refused",
        "connection reset",
        "no route to host",
        "network is unreachable",
        "could not resolve hostname",
        "operation timed out",
        "connection closed",
    )
    if any(token in low for token in connectivity_tokens):
        return "CONNECTIVITY_ERROR", detail
    if "host key verification failed" in low:
        return "HOST_KEY_FAILED", detail
    return "OPENSSH_FAILED", detail


class NativeOpenSSHFileTransportBase:
    def __init__(
        self,
        config: SSHClientConfig,
        runner: AsyncProcessRunner,
        hash_provider: HashPort,
    ) -> None:
        self._config: SSHClientConfig = config
        self._runner: AsyncProcessRunner = runner
        self._hash_provider: HashPort = hash_provider
        self._ssh: str = shutil.which("ssh.exe") or shutil.which("ssh") or "ssh"
        self._sftp: str = shutil.which("sftp.exe") or shutil.which("sftp") or "sftp"
        self._scp: str = shutil.which("scp.exe") or shutil.which("scp") or "scp"

    def _ssh_common(self) -> list[str]:
        return [
            "-o", "BatchMode=yes",
            "-o", "IdentitiesOnly=yes",
            "-o", f"ConnectTimeout={self._config.connect_timeout_seconds}",
            "-o", "ConnectionAttempts=1",
            "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=2",
            "-o", f"StrictHostKeyChecking={self._config.strict_host_key_checking}",
            "-o", f"UserKnownHostsFile={self._config.known_hosts}",
            "-i", str(self._config.key_path),
        ]

    def _ssh_args(self, site: HostTarget, powershell_code: str) -> list[str]:
        encoded: str = base64.b64encode(powershell_code.encode("utf-16le")).decode("ascii")
        return [
            self._ssh,
            "-T",
            "-p", str(self._config.port),
            *self._ssh_common(),
            f"{self._config.username}@{site.address}",
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy", "Bypass",
            "-EncodedCommand", encoded,
        ]

    async def _run_ps(
        self,
        site: HostTarget,
        code: str,
        *,
        operation: str,
        timeout_seconds: int = 60,
        stdin_data: bytes | None = None,
    ) -> Outcome[dict[str, object]]:
        try:
            result = await self._runner.run(
                self._ssh_args(site, code),
                site_code=site.code,
                operation=operation,
                timeout_seconds=timeout_seconds,
                stdin_data=stdin_data,
            )
        except ConnectivityError as exc:
            return Outcome.failure("CONNECTIVITY_ERROR", str(exc))
        except OSError as exc:
            return Outcome.failure("PROCESS_ERROR", str(exc))

        if result.exit_code != 0:
            code, detail = _classify_openssh_failure(result.stderr, result.stdout)
            if code == "OPENSSH_FAILED":
                code = "REMOTE_POWERSHELL_FAILED"
            return Outcome.failure(code, detail or f"ExitCode={result.exit_code}")
        return Outcome.success(_parse_json_tail(result.stdout))

    async def preflight(self, site: HostTarget) -> Outcome[None]:
        code: str = "[pscustomobject]@{Ok=$true;Host=$env:COMPUTERNAME}|ConvertTo-Json -Compress"
        outcome = await self._run_ps(site, code, operation="FILE_PREFLIGHT", timeout_seconds=self._config.connect_timeout_seconds)
        if not outcome.ok:
            return Outcome.failure(outcome.error_code or "PREFLIGHT_FAILED", outcome.error_message or "Sin conectividad")
        return Outcome.success(None)

    async def _finalize_upload(
        self,
        site: HostTarget,
        *,
        stage_name: str,
        artifact: ArtifactDescriptor,
    ) -> Outcome[TransferResult]:
        destination: str = _ps_quote(artifact.remote_path)
        stage_q: str = _ps_quote(stage_name)
        expected: str = _ps_quote(artifact.sha256.lower())
        code: str = f"""
$ErrorActionPreference='Stop'
$src=Join-Path $HOME '{stage_q}'
$dst='{destination}'
if(-not (Test-Path -LiteralPath $src -PathType Leaf)){{ throw 'Staging file missing' }}
$parent=Split-Path -Parent $dst
if($parent -and -not (Test-Path -LiteralPath $parent)){{ New-Item -ItemType Directory -Path $parent -Force|Out-Null }}
$hash=(Get-FileHash -LiteralPath $src -Algorithm SHA256).Hash.ToLowerInvariant()
if($hash -ne '{expected}'){{ throw ('SHA256 staging mismatch: '+$hash) }}
Move-Item -LiteralPath $src -Destination $dst -Force
$item=Get-Item -LiteralPath $dst
$hash2=(Get-FileHash -LiteralPath $dst -Algorithm SHA256).Hash.ToLowerInvariant()
[pscustomobject]@{{Ok=$true;Path=$dst;Length=$item.Length;Sha256=$hash2}}|ConvertTo-Json -Compress
"""
        outcome = await self._run_ps(site, code, operation="FILE_FINALIZE_UPLOAD", timeout_seconds=180)
        if not outcome.ok or outcome.value is None:
            return Outcome.failure(outcome.error_code or "FINALIZE_FAILED", outcome.error_message or "No se pudo finalizar upload")
        remote_sha: str = str(outcome.value.get("Sha256") or "").lower()
        remote_len: int = int(outcome.value.get("Length") or 0)
        if remote_sha != artifact.sha256.lower() or remote_len != artifact.size_bytes:
            return Outcome.failure(
                "REMOTE_INTEGRITY_MISMATCH",
                f"Esperado {artifact.size_bytes}/{artifact.sha256}; remoto {remote_len}/{remote_sha}",
            )
        return Outcome.success(
            TransferResult(
                bytes_transferred=artifact.size_bytes,
                remote_path=artifact.remote_path,
                sha256=remote_sha,
            )
        )

    async def _prepare_download(
        self,
        site: HostTarget,
        *,
        remote_path: str,
        stage_name: str,
    ) -> Outcome[dict[str, object]]:
        source: str = _ps_quote(remote_path)
        stage_q: str = _ps_quote(stage_name)
        code: str = f"""
$ErrorActionPreference='Stop'
$src='{source}'
if(-not (Test-Path -LiteralPath $src -PathType Leaf)){{ throw 'Remote source missing' }}
$dst=Join-Path $HOME '{stage_q}'
Copy-Item -LiteralPath $src -Destination $dst -Force
$item=Get-Item -LiteralPath $dst
$hash=(Get-FileHash -LiteralPath $dst -Algorithm SHA256).Hash.ToLowerInvariant()
[pscustomobject]@{{Ok=$true;Length=$item.Length;Sha256=$hash}}|ConvertTo-Json -Compress
"""
        return await self._run_ps(site, code, operation="FILE_PREPARE_DOWNLOAD", timeout_seconds=180)

    async def _cleanup_stage(self, site: HostTarget, stage_name: str) -> None:
        stage_q: str = _ps_quote(stage_name)
        code: str = f"$p=Join-Path $HOME '{stage_q}';Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue;[pscustomobject]@{{Ok=$true}}|ConvertTo-Json -Compress"
        try:
            await self._run_ps(site, code, operation="FILE_STAGE_CLEANUP", timeout_seconds=30)
        except Exception as exc:
            best_effort_warning(f"No se pudo limpiar staging remoto en {site.site_code}", exc)

    async def cancel_site(self, site: HostTarget) -> Outcome[None]:
        try:
            await self._runner.cancel_site(site.code)
            return Outcome.success(None)
        except Exception as exc:
            return Outcome.failure("LOCAL_CANCEL_FAILED", str(exc))


class NativeSFTPFileTransport(NativeOpenSSHFileTransportBase):
    @property
    def profile(self) -> TransportProfile:
        return TransportProfile.SFTP_SSH_SFTP

    @property
    def capabilities(self) -> FileTransportCapabilities:
        return FileTransportCapabilities(
            profile=self.profile,
            supports_upload=True,
            supports_download=True,
            supports_large_files=True,
            recommended_for_video=True,
        )

    async def _sftp_batch(self, site: HostTarget, batch: str, operation: str, timeout_seconds: int) -> Outcome[None]:
        args: list[str] = [
            self._sftp,
            "-b", "-",
            "-P", str(self._config.port),
            *self._ssh_common(),
            f"{self._config.username}@{site.address}",
        ]
        try:
            result = await self._runner.run(
                args,
                site_code=site.code,
                operation=operation,
                timeout_seconds=timeout_seconds,
                stdin_data=batch.encode("utf-8"),
            )
        except ConnectivityError as exc:
            return Outcome.failure("CONNECTIVITY_ERROR", str(exc))
        except OSError as exc:
            return Outcome.failure("SFTP_CLIENT_ERROR", str(exc))
        if result.exit_code != 0:
            code, detail = _classify_openssh_failure(result.stderr, result.stdout)
            return Outcome.failure("SFTP_FAILED" if code == "OPENSSH_FAILED" else code, detail)
        return Outcome.success(None)

    async def upload(
        self,
        site: HostTarget,
        artifact: ArtifactDescriptor,
        *,
        progress: ProgressCallback | None = None,
    ) -> Outcome[TransferResult]:
        started: float = time.monotonic()
        stage: str = f"gideon_{uuid.uuid4().hex}_{artifact.local_path.name}"
        if progress:
            progress(site.code, 10.0, "SFTP upload", 0, artifact.size_bytes)
        local: str = artifact.local_path.as_posix().replace('"', '\\"')
        batch: str = f'put "{local}" "{stage}"\n'
        outcome = await self._sftp_batch(site, batch, "SFTP_FILE_UPLOAD", max(120, int(artifact.size_bytes / 100_000)))
        if not outcome.ok:
            return Outcome.failure(outcome.error_code or "SFTP_UPLOAD_FAILED", outcome.error_message or "SFTP upload falló")
        if progress:
            progress(site.code, 80.0, "Verificando SHA-256 remoto", artifact.size_bytes, artifact.size_bytes)
        finalized = await self._finalize_upload(site, stage_name=stage, artifact=artifact)
        if finalized.ok and finalized.value is not None:
            value = finalized.value
            if progress:
                progress(site.code, 100.0, "Completado", artifact.size_bytes, artifact.size_bytes)
            return Outcome.success(
                TransferResult(value.bytes_transferred, value.remote_path, value.sha256, time.monotonic() - started)
            )
        await self._cleanup_stage(site, stage)
        return finalized

    async def download(
        self,
        site: HostTarget,
        remote_path: str,
        local_path: Path,
        *,
        progress: ProgressCallback | None = None,
    ) -> Outcome[TransferResult]:
        stage: str = f"gideon_{uuid.uuid4().hex}_{Path(remote_path).name or 'download.bin'}"
        prep = await self._prepare_download(site, remote_path=remote_path, stage_name=stage)
        if not prep.ok or prep.value is None:
            return Outcome.failure(prep.error_code or "PREPARE_DOWNLOAD_FAILED", prep.error_message or "No se pudo preparar descarga")
        remote_len: int = int(prep.value.get("Length") or 0)
        remote_sha: str = str(prep.value.get("Sha256") or "").lower()
        Path(local_path).parent.mkdir(parents=True, exist_ok=True)
        local: str = Path(local_path).as_posix().replace('"', '\\"')
        if progress:
            progress(site.code, 20.0, "SFTP download", 0, remote_len)
        batch: str = f'get "{stage}" "{local}"\n'
        result = await self._sftp_batch(site, batch, "SFTP_FILE_DOWNLOAD", max(120, int(max(remote_len, 1) / 100_000)))
        await self._cleanup_stage(site, stage)
        if not result.ok:
            return Outcome.failure(result.error_code or "SFTP_DOWNLOAD_FAILED", result.error_message or "SFTP download falló")
        local_sha: str = self._hash_provider.sha256_file(Path(local_path)).lower()
        local_len: int = Path(local_path).stat().st_size
        if local_sha != remote_sha or local_len != remote_len:
            return Outcome.failure("DOWNLOAD_INTEGRITY_MISMATCH", f"Remoto {remote_len}/{remote_sha}; local {local_len}/{local_sha}")
        if progress:
            progress(site.code, 100.0, "Completado", local_len, remote_len)
        return Outcome.success(TransferResult(local_len, remote_path, local_sha))


class NativeSCPFileTransport(NativeOpenSSHFileTransportBase):
    @property
    def profile(self) -> TransportProfile:
        return TransportProfile.SCP_SSH_SCP

    @property
    def capabilities(self) -> FileTransportCapabilities:
        return FileTransportCapabilities(
            profile=self.profile,
            supports_upload=True,
            supports_download=True,
            supports_large_files=True,
            recommended_for_video=True,
        )

    async def _scp(self, site: HostTarget, local: Path, remote_stage: str, upload: bool, operation: str, timeout_seconds: int) -> Outcome[None]:
        remote_spec: str = f"{self._config.username}@{site.address}:{remote_stage}"
        args: list[str] = [self._scp, "-P", str(self._config.port), *self._ssh_common()]
        if upload:
            args.extend([str(local), remote_spec])
        else:
            args.extend([remote_spec, str(local)])
        try:
            result = await self._runner.run(
                args,
                site_code=site.code,
                operation=operation,
                timeout_seconds=timeout_seconds,
            )
        except ConnectivityError as exc:
            return Outcome.failure("CONNECTIVITY_ERROR", str(exc))
        except OSError as exc:
            return Outcome.failure("SCP_CLIENT_ERROR", str(exc))
        if result.exit_code != 0:
            code, detail = _classify_openssh_failure(result.stderr, result.stdout)
            return Outcome.failure("SCP_FAILED" if code == "OPENSSH_FAILED" else code, detail)
        return Outcome.success(None)

    async def upload(self, site: HostTarget, artifact: ArtifactDescriptor, *, progress: ProgressCallback | None = None) -> Outcome[TransferResult]:
        started: float = time.monotonic()
        stage: str = f"gideon_{uuid.uuid4().hex}_{artifact.local_path.name}"
        if progress:
            progress(site.code, 10.0, "SCP upload", 0, artifact.size_bytes)
        outcome = await self._scp(site, artifact.local_path, stage, True, "SCP_FILE_UPLOAD", max(120, int(artifact.size_bytes / 100_000)))
        if not outcome.ok:
            return Outcome.failure(outcome.error_code or "SCP_UPLOAD_FAILED", outcome.error_message or "SCP upload falló")
        if progress:
            progress(site.code, 80.0, "Verificando SHA-256 remoto", artifact.size_bytes, artifact.size_bytes)
        finalized = await self._finalize_upload(site, stage_name=stage, artifact=artifact)
        if finalized.ok and finalized.value is not None:
            value = finalized.value
            if progress:
                progress(site.code, 100.0, "Completado", artifact.size_bytes, artifact.size_bytes)
            return Outcome.success(TransferResult(value.bytes_transferred, value.remote_path, value.sha256, time.monotonic() - started))
        await self._cleanup_stage(site, stage)
        return finalized

    async def download(self, site: HostTarget, remote_path: str, local_path: Path, *, progress: ProgressCallback | None = None) -> Outcome[TransferResult]:
        stage: str = f"gideon_{uuid.uuid4().hex}_{Path(remote_path).name or 'download.bin'}"
        prep = await self._prepare_download(site, remote_path=remote_path, stage_name=stage)
        if not prep.ok or prep.value is None:
            return Outcome.failure(prep.error_code or "PREPARE_DOWNLOAD_FAILED", prep.error_message or "No se pudo preparar descarga")
        remote_len: int = int(prep.value.get("Length") or 0)
        remote_sha: str = str(prep.value.get("Sha256") or "").lower()
        Path(local_path).parent.mkdir(parents=True, exist_ok=True)
        if progress:
            progress(site.code, 20.0, "SCP download", 0, remote_len)
        outcome = await self._scp(site, Path(local_path), stage, False, "SCP_FILE_DOWNLOAD", max(120, int(max(remote_len, 1) / 100_000)))
        await self._cleanup_stage(site, stage)
        if not outcome.ok:
            return Outcome.failure(outcome.error_code or "SCP_DOWNLOAD_FAILED", outcome.error_message or "SCP download falló")
        local_sha: str = self._hash_provider.sha256_file(Path(local_path)).lower()
        local_len: int = Path(local_path).stat().st_size
        if local_sha != remote_sha or local_len != remote_len:
            return Outcome.failure("DOWNLOAD_INTEGRITY_MISMATCH", f"Remoto {remote_len}/{remote_sha}; local {local_len}/{local_sha}")
        if progress:
            progress(site.code, 100.0, "Completado", local_len, remote_len)
        return Outcome.success(TransferResult(local_len, remote_path, local_sha))


class NativeSTDINFileTransport(NativeOpenSSHFileTransportBase):
    _MAX_BYTES: int = 64 * 1024 * 1024

    @property
    def profile(self) -> TransportProfile:
        return TransportProfile.STDIN_SSH_SCP

    @property
    def capabilities(self) -> FileTransportCapabilities:
        return FileTransportCapabilities(
            profile=self.profile,
            supports_upload=True,
            supports_download=True,
            supports_large_files=False,
            recommended_for_video=False,
            max_upload_bytes=self._MAX_BYTES,
        )

    async def upload(self, site: HostTarget, artifact: ArtifactDescriptor, *, progress: ProgressCallback | None = None) -> Outcome[TransferResult]:
        if artifact.size_bytes > self._MAX_BYTES:
            return Outcome.failure(
                "STDIN_FILE_TOO_LARGE",
                f"STDIN está limitado a {self._MAX_BYTES // (1024 * 1024)} MB para archivos. Use SFTP o SCP para videos/archivos grandes.",
            )
        stage: str = f"gideon_{uuid.uuid4().hex}_{artifact.local_path.name}"
        # This compatibility transport is intentionally capped at 64 MiB, but
        # reading and Base64-encoding that payload is still CPU/disk work. Keep
        # it off the shared asyncio loop so other sites and UI events continue.
        payload: bytes = await asyncio.to_thread(
            lambda: base64.b64encode(artifact.local_path.read_bytes())
        )
        stage_q: str = _ps_quote(stage)
        expected: str = _ps_quote(artifact.sha256.lower())
        code: str = f"""
$ErrorActionPreference='Stop'
$b=[Console]::In.ReadToEnd()
$dst=Join-Path $HOME '{stage_q}'
[IO.File]::WriteAllBytes($dst,[Convert]::FromBase64String($b))
$hash=(Get-FileHash -LiteralPath $dst -Algorithm SHA256).Hash.ToLowerInvariant()
if($hash -ne '{expected}'){{ throw ('SHA256 staging mismatch: '+$hash) }}
[pscustomobject]@{{Ok=$true;Length=(Get-Item -LiteralPath $dst).Length;Sha256=$hash}}|ConvertTo-Json -Compress
"""
        if progress:
            progress(site.code, 15.0, "SSH/STDIN upload Base64", 0, artifact.size_bytes)
        try:
            result = await self._runner.run(
                self._ssh_args(site, code),
                site_code=site.code,
                operation="STDIN_FILE_UPLOAD",
                timeout_seconds=max(120, int(artifact.size_bytes / 50_000)),
                stdin_data=payload,
            )
        except ConnectivityError as exc:
            return Outcome.failure("CONNECTIVITY_ERROR", str(exc))
        except OSError as exc:
            return Outcome.failure("SSH_CLIENT_ERROR", str(exc))
        if result.exit_code != 0:
            code_name, detail = _classify_openssh_failure(result.stderr, result.stdout)
            return Outcome.failure("STDIN_UPLOAD_FAILED" if code_name == "OPENSSH_FAILED" else code_name, detail)
        if progress:
            progress(site.code, 80.0, "Finalizando archivo", artifact.size_bytes, artifact.size_bytes)
        finalized = await self._finalize_upload(site, stage_name=stage, artifact=artifact)
        if finalized.ok and progress:
            progress(site.code, 100.0, "Completado", artifact.size_bytes, artifact.size_bytes)
        return finalized

    async def download(self, site: HostTarget, remote_path: str, local_path: Path, *, progress: ProgressCallback | None = None) -> Outcome[TransferResult]:
        # Para descarga usamos SCP; evita inflar Base64 desde el servidor.
        scp = NativeSCPFileTransport(self._config, self._runner, self._hash_provider)
        return await scp.download(site, remote_path, local_path, progress=progress)


class FileTransportFactory:
    def __init__(self, transports: Mapping[TransportProfile, FileTransferPort]) -> None:
        self._transports: dict[TransportProfile, FileTransferPort] = dict(transports)

    def get(self, profile: TransportProfile) -> FileTransferPort:
        transport: FileTransferPort | None = self._transports.get(profile)
        if transport is None:
            raise ValidationError(f"El transporte {profile.value} no está disponible para archivos.")
        return transport

    def available(self) -> Mapping[TransportProfile, FileTransportCapabilities]:
        return {profile: transport.capabilities for profile, transport in self._transports.items()}
