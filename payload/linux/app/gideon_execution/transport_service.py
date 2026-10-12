from __future__ import annotations

import asyncio
import logging
import base64
import os
import subprocess
from pathlib import Path
from typing import Any, Optional

from gideon_admin import Site, classify_failure, command_exists, ensure_dir
from gideon_core.transport_profiles import DEFAULT_TRANSPORT_PROFILE, get_transport_profile, normalize_transport_profile
from gideon_execution.logging_utils import warn
from gideon_execution.runtime_service import LocalProcessRegistry
from gideon_execution.shell_utils import powershell_stdin_payload, ps_single_quote

_LOG = logging.getLogger(__name__)

class RemoteTransport:
    """Transporte nativo OpenSSH: SSH para control y SFTP para archivos."""

    def __init__(
        self,
        *,
        user: str,
        key: Path,
        known_hosts: Path,
        port: int,
        timeout: int,
        strict: str,
        attempts: int,
        retry_delays: list[int],
        transport_profile: str = DEFAULT_TRANSPORT_PROFILE,
        telemetry_hard_timeout_seconds: float = 12.0,
        control_hard_timeout_seconds: float = 20.0,
        transfer_hard_timeout_seconds: float = 90.0,
        collection_hard_timeout_seconds: float = 180.0,
    ) -> None:
        self.user = user
        self.key = key
        self.known_hosts = known_hosts
        self.port = int(port)
        self.timeout = int(timeout)
        self.strict = strict
        self.attempts = max(1, int(attempts))
        self.retry_delays = retry_delays or [3, 5]
        self.transport_profile = normalize_transport_profile(transport_profile)
        self.transport_spec = get_transport_profile(self.transport_profile)

        # Watchdog externo de Python. OpenSSH ConnectTimeout protege el handshake,
        # pero NO garantiza que un canal ya conectado o un PowerShell remoto no
        # quede esperando indefinidamente.
        self.telemetry_hard_timeout_seconds = max(
            5.0, float(telemetry_hard_timeout_seconds)
        )
        self.control_hard_timeout_seconds = max(
            self.telemetry_hard_timeout_seconds,
            float(control_hard_timeout_seconds),
        )
        self.transfer_hard_timeout_seconds = max(
            self.control_hard_timeout_seconds,
            float(transfer_hard_timeout_seconds),
        )
        self.collection_hard_timeout_seconds = max(
            self.transfer_hard_timeout_seconds,
            float(collection_hard_timeout_seconds),
        )

        self.ssh = command_exists("ssh.exe") or command_exists("ssh")
        self.sftp = command_exists("sftp.exe") or command_exists("sftp")
        self.scp = command_exists("scp.exe") or command_exists("scp")

        if not self.ssh:
            raise RuntimeError("No se encontró ssh.exe.")

        required = set(self.transport_spec.required_clients)
        if "sftp" in required and not self.sftp:
            raise RuntimeError(
                "El perfil SFTP requiere sftp.exe. Instale/active el cliente OpenSSH."
            )
        if "scp" in required and not self.scp:
            raise RuntimeError(
                "El perfil seleccionado requiere scp.exe. Instale/active el cliente OpenSSH."
            )

        ensure_dir(self.known_hosts.parent)
        self.known_hosts.touch(exist_ok=True)
        self.process_registry: Optional[LocalProcessRegistry] = None

    def attach_registry(self, registry: LocalProcessRegistry) -> None:
        self.process_registry = registry

    def ssh_options(self) -> list[str]:
        return [
            "-p", str(self.port),
            "-o", "BatchMode=yes",
            "-o", "IdentitiesOnly=yes",
            "-o", f"ConnectTimeout={self.timeout}",
            "-o", "ConnectionAttempts=1",
            "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=2",
            "-o", f"StrictHostKeyChecking={self.strict}",
            "-o", f"UserKnownHostsFile={self.known_hosts}",
            "-i", str(self.key),
        ]

    def sftp_options(self) -> list[str]:
        return [
            "-P", str(self.port),
            "-o", "BatchMode=yes",
            "-o", "IdentitiesOnly=yes",
            "-o", f"ConnectTimeout={self.timeout}",
            "-o", "ConnectionAttempts=1",
            "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=2",
            "-o", f"StrictHostKeyChecking={self.strict}",
            "-o", f"UserKnownHostsFile={self.known_hosts}",
            "-i", str(self.key),
        ]

    def scp_options(self) -> list[str]:
        return [
            "-P", str(self.port),
            "-o", "BatchMode=yes",
            "-o", "IdentitiesOnly=yes",
            "-o", f"ConnectTimeout={self.timeout}",
            "-o", "ConnectionAttempts=1",
            "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=2",
            "-o", f"StrictHostKeyChecking={self.strict}",
            "-o", f"UserKnownHostsFile={self.known_hosts}",
            "-i", str(self.key),
        ]

    def operation_hard_timeout(self, operation: str) -> float:
        name = str(operation or "").upper()
        if "TELEMETRY" in name or "FAST_STATUS" in name:
            return self.telemetry_hard_timeout_seconds
        if "COLLECT" in name or "DOWNLOAD" in name or "GET" in name:
            return self.collection_hard_timeout_seconds
        if (
            "UPLOAD" in name
            or "SFTP" in name
            or "SCP" in name
            or "STDIN" in name
        ):
            return self.transfer_hard_timeout_seconds
        return self.control_hard_timeout_seconds

    async def _terminate_process(
        self,
        proc: asyncio.subprocess.Process,
    ) -> None:
        if proc.returncode is not None:
            return
        try:
            proc.terminate()
        except ProcessLookupError:
            return
        except Exception as exc:
            _LOG.debug("terminate() falló para PID %s: %s", getattr(proc, "pid", "?"), exc)

        try:
            await asyncio.wait_for(proc.wait(), timeout=1.5)
            return
        except Exception as exc:
            _LOG.debug("wait tras terminate() falló para PID %s: %s", getattr(proc, "pid", "?"), exc)

        try:
            proc.kill()
        except ProcessLookupError:
            return
        except Exception as exc:
            _LOG.debug("kill() falló para PID %s: %s", getattr(proc, "pid", "?"), exc)

        try:
            await asyncio.wait_for(proc.wait(), timeout=1.5)
        except Exception as exc:
            _LOG.debug("wait tras kill() falló para PID %s: %s", getattr(proc, "pid", "?"), exc)

    async def _communicate_with_deadline(
        self,
        *,
        proc: asyncio.subprocess.Process,
        input_data: bytes | None,
        site: Site,
        operation: str,
    ) -> tuple[int, bytes, bytes]:
        timeout_seconds = self.operation_hard_timeout(operation)

        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(input_data),
                timeout=timeout_seconds,
            )
            return int(proc.returncode or 0), stdout_b, stderr_b

        except TimeoutError:
            await self._terminate_process(proc)
            detail = (
                f"GIDEON_OPERATION_TIMEOUT: {operation} excedió "
                f"{timeout_seconds:.1f}s en {site.label}. "
                "El proceso OpenSSH local fue liberado."
            )
            return 124, b"", detail.encode("utf-8")

        except asyncio.CancelledError:
            await self._terminate_process(proc)
            raise

    async def scp_once(
        self,
        site: Site,
        *,
        local_path: Path,
        remote_path: str,
        upload: bool,
        operation: str,
    ) -> tuple[int, str, str]:
        if not self.scp:
            raise RuntimeError("scp.exe no está disponible.")

        remote_spec = f"{self.user}@{site.ip}:{remote_path}"
        if upload:
            args = [self.scp, *self.scp_options(), str(local_path), remote_spec]
        else:
            args = [self.scp, *self.scp_options(), remote_spec, str(local_path)]

        proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            creationflags=(
                getattr(subprocess, "CREATE_NO_WINDOW", 0)
                if os.name == "nt" else 0
            ),
        )
        if self.process_registry is not None:
            self.process_registry.register(
                pid=proc.pid,
                kind="SCP",
                site=site,
                operation=operation,
            )
        try:
            rc, stdout_b, stderr_b = await self._communicate_with_deadline(
                proc=proc,
                input_data=None,
                site=site,
                operation=operation,
            )
        finally:
            if self.process_registry is not None:
                self.process_registry.unregister(proc.pid)

        return (
            rc,
            stdout_b.decode("utf-8", errors="replace"),
            stderr_b.decode("utf-8", errors="replace"),
        )

    async def scp_file(
        self,
        site: Site,
        *,
        local_path: Path,
        remote_path: str,
        upload: bool,
        operation: str,
    ) -> tuple[int, str, str, int]:
        last = (255, "", "")
        for attempt in range(1, self.attempts + 1):
            rc, stdout, stderr = await self.scp_once(
                site,
                local_path=local_path,
                remote_path=remote_path,
                upload=upload,
                operation=operation,
            )
            last = (rc, stdout, stderr)
            if rc == 0:
                return rc, stdout, stderr, attempt

            failure_type, retryable, _ = classify_failure(
                exit_code=rc,
                stderr=stderr,
                stdout=stdout,
                remote_error=None,
            )
            if not retryable or attempt >= self.attempts:
                return rc, stdout, stderr, attempt

            delay_index = min(attempt - 1, len(self.retry_delays) - 1)
            delay = max(0, int(self.retry_delays[delay_index]))
            warn(
                f"{site.label} - {operation}: {failure_type}; "
                f"reintento {attempt + 1}/{self.attempts} en {delay}s."
            )
            await asyncio.sleep(delay)
        return (*last, self.attempts)

    async def stdin_archive_once(
        self,
        site: Site,
        *,
        archive_path: Path,
        upload_folder: str,
        operation: str,
    ) -> tuple[int, str, str]:
        """Envía un ZIP como Base64 ASCII por STDIN de ssh.exe."""
        folder_q = ps_single_quote(upload_folder)
        remote_ps = (
            "$ErrorActionPreference='Stop';"
            f"$n='{folder_q}';"
            "$zip=Join-Path $HOME ($n+'.zip');"
            "$dst=Join-Path $HOME $n;"
            "$b=[Console]::In.ReadToEnd();"
            "[IO.File]::WriteAllBytes($zip,[Convert]::FromBase64String($b));"
            "if(Test-Path -LiteralPath $dst){Remove-Item -LiteralPath $dst -Recurse -Force};"
            "New-Item -ItemType Directory -Path $dst -Force|Out-Null;"
            "Expand-Archive -LiteralPath $zip -DestinationPath $dst -Force;"
            "Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue;"
            "[pscustomobject]@{Success=$true;Mode='STDIN'}|ConvertTo-Json -Compress"
        )
        remote = (
            "powershell.exe -NoLogo -NoProfile -NonInteractive "
            "-ExecutionPolicy Bypass -Command "
            + '"' + remote_ps.replace('"', '`"') + '"'
        )

        args = [
            self.ssh,
            "-T",
            *self.ssh_options(),
            f"{self.user}@{site.ip}",
            remote,
        ]
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            creationflags=(
                getattr(subprocess, "CREATE_NO_WINDOW", 0)
                if os.name == "nt" else 0
            ),
        )
        if self.process_registry is not None:
            self.process_registry.register(
                pid=proc.pid,
                kind="SSH",
                site=site,
                operation=operation,
            )

        payload = base64.b64encode(Path(archive_path).read_bytes())
        try:
            rc, stdout_b, stderr_b = await self._communicate_with_deadline(
                proc=proc,
                input_data=payload,
                site=site,
                operation=operation,
            )
        finally:
            if self.process_registry is not None:
                self.process_registry.unregister(proc.pid)

        return (
            rc,
            stdout_b.decode("utf-8", errors="replace"),
            stderr_b.decode("utf-8", errors="replace"),
        )

    async def stdin_archive(
        self,
        site: Site,
        *,
        archive_path: Path,
        upload_folder: str,
        operation: str,
    ) -> tuple[int, str, str, int]:
        last = (255, "", "")
        for attempt in range(1, self.attempts + 1):
            rc, stdout, stderr = await self.stdin_archive_once(
                site,
                archive_path=archive_path,
                upload_folder=upload_folder,
                operation=operation,
            )
            last = (rc, stdout, stderr)
            if rc == 0:
                return rc, stdout, stderr, attempt

            failure_type, retryable, _ = classify_failure(
                exit_code=rc,
                stderr=stderr,
                stdout=stdout,
                remote_error=None,
            )
            if not retryable or attempt >= self.attempts:
                return rc, stdout, stderr, attempt

            delay_index = min(attempt - 1, len(self.retry_delays) - 1)
            delay = max(0, int(self.retry_delays[delay_index]))
            warn(
                f"{site.label} - {operation}: {failure_type}; "
                f"reintento {attempt + 1}/{self.attempts} en {delay}s."
            )
            await asyncio.sleep(delay)
        return (*last, self.attempts)

    async def run_ps_once(
        self,
        site: Site,
        code: str,
        operation: str,
    ) -> tuple[int, str, str]:
        # Se usa únicamente para comandos cortos de control/estado. Los scripts de
        # trabajo nunca viajan por stdin: se distribuyen físicamente por SFTP.
        remote = (
            'powershell.exe -NoLogo -NoProfile -NonInteractive '
            '-ExecutionPolicy Bypass -Command '
            '"$b=[Console]::In.ReadToEnd();'
            '$s=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b));'
            'Invoke-Expression $s"'
        )

        args = [
            self.ssh,
            "-T",
            *self.ssh_options(),
            f"{self.user}@{site.ip}",
            remote,
        ]

        proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            creationflags=(
                getattr(subprocess, "CREATE_NO_WINDOW", 0)
                if os.name == "nt" else 0
            ),
        )

        if self.process_registry is not None:
            self.process_registry.register(
                pid=proc.pid,
                kind="SSH",
                site=site,
                operation=operation,
            )

        payload = powershell_stdin_payload(code).encode("ascii")
        try:
            rc, stdout_b, stderr_b = await self._communicate_with_deadline(
                proc=proc,
                input_data=payload,
                site=site,
                operation=operation,
            )
        finally:
            if self.process_registry is not None:
                self.process_registry.unregister(proc.pid)

        return (
            rc,
            stdout_b.decode("utf-8", errors="replace"),
            stderr_b.decode("utf-8", errors="replace"),
        )

    async def run_ps(
        self,
        site: Site,
        code: str,
        *,
        operation: str,
    ) -> tuple[int, str, str, int]:
        last = (255, "", "")

        for attempt in range(1, self.attempts + 1):
            code_rc, stdout, stderr = await self.run_ps_once(
                site, code, operation
            )
            last = (code_rc, stdout, stderr)

            if code_rc == 0:
                return code_rc, stdout, stderr, attempt

            failure_type, retryable, _ = classify_failure(
                exit_code=code_rc,
                stderr=stderr,
                stdout=stdout,
                remote_error=None,
            )

            if not retryable or attempt >= self.attempts:
                return code_rc, stdout, stderr, attempt

            delay_index = min(attempt - 1, len(self.retry_delays) - 1)
            delay = max(0, int(self.retry_delays[delay_index]))
            warn(
                f"{site.label} - {operation}: {failure_type}; "
                f"reintento {attempt + 1}/{self.attempts} en {delay}s."
            )
            await asyncio.sleep(delay)

        return (*last, self.attempts)

    async def sftp_batch_once(
        self,
        site: Site,
        batch_text: str,
        operation: str,
    ) -> tuple[int, str, str]:
        args = [
            self.sftp,
            "-b", "-",
            *self.sftp_options(),
            f"{self.user}@{site.ip}",
        ]

        proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            creationflags=(
                getattr(subprocess, "CREATE_NO_WINDOW", 0)
                if os.name == "nt" else 0
            ),
        )
        if self.process_registry is not None:
            self.process_registry.register(
                pid=proc.pid,
                kind="SFTP",
                site=site,
                operation=operation,
            )
        try:
            rc, stdout_b, stderr_b = await self._communicate_with_deadline(
                proc=proc,
                input_data=batch_text.encode("utf-8"),
                site=site,
                operation=operation,
            )
        finally:
            if self.process_registry is not None:
                self.process_registry.unregister(proc.pid)
        return (
            rc,
            stdout_b.decode("utf-8", errors="replace"),
            stderr_b.decode("utf-8", errors="replace"),
        )

    async def sftp_batch(
        self,
        site: Site,
        batch_text: str,
        *,
        operation: str,
    ) -> tuple[int, str, str, int]:
        last = (255, "", "")
        for attempt in range(1, self.attempts + 1):
            rc, stdout, stderr = await self.sftp_batch_once(
                site, batch_text, operation
            )
            last = (rc, stdout, stderr)
            if rc == 0:
                return rc, stdout, stderr, attempt

            failure_type, retryable, _ = classify_failure(
                exit_code=rc,
                stderr=stderr,
                stdout=stdout,
                remote_error=None,
            )
            if not retryable or attempt >= self.attempts:
                return rc, stdout, stderr, attempt

            delay_index = min(attempt - 1, len(self.retry_delays) - 1)
            delay = max(0, int(self.retry_delays[delay_index]))
            warn(
                f"{site.label} - {operation}: {failure_type}; "
                f"reintento {attempt + 1}/{self.attempts} en {delay}s."
            )
            await asyncio.sleep(delay)

        return (*last, self.attempts)
