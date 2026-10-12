#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
GIDEON CORP - SSH Python Admin v6.2.0

Python = capa de administración/orquestación.
PowerShell = motor remoto de administración Windows.

Características:
- Inventario de sedes en config/sites.csv.
- Autenticación con identidad privada GIDEON; ssh-agent externo es opcional y solo se consulta.
- La passphrase NO se recibe por argumento ni se almacena.
- Ejecución de comandos PowerShell o scripts .ps1.
- Transporte de scripts grandes por STDIN/Base64 (sin límite práctico de línea de comandos).
- Ejecución paralela por ThreadPoolExecutor.
- Reintentos automáticos solo para fallos SSH transitorios.
- Clasificación de errores: timeout, autenticación, host key, red y script remoto.
- Progreso persistente de jobs: completadas/total, porcentaje, éxitos y errores.
- Ejecución opcional en segundo plano (--background).
- Jobs persistentes en %LOCALAPPDATA%\GIDEONSSH\jobs.
- Resultados Structured (JSON -> objetos) o Text.
- Exportación a XLSX/CSV/JSON/TXT.
- known_hosts dedicado al proyecto.
- Seguridad: BatchMode, IdentitiesOnly, StrictHostKeyChecking=accept-new.
"""

from __future__ import annotations

from gideon_version import PRODUCT_VERSION
from gideon_common.clock import now_iso
from gideon_common.process import windows_hidden_kwargs
import argparse
import asyncio
import base64
import csv
import dataclasses
import datetime as dt
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from gideon_io import atomic_write_json as io_atomic_write_json, read_json_retry, update_json_atomic
from typing import Any, Iterable, Optional

APP_NAME = "GIDEONSSH"
VERSION = PRODUCT_VERSION
SCRIPT_DIR = Path(__file__).resolve().parent

# Protección secundaria: los backends creados por la GUI trabajan con stdout/
# stderr redirigidos. En Windows no dependemos de la página de códigos ANSI.
if os.environ.get("GIDEON_FORCE_UTF8_STDIO") == "1":
    for _stream in (sys.stdout, sys.stderr):
        try:
            if hasattr(_stream, "reconfigure"):
                _stream.reconfigure(
                    encoding="utf-8",
                    errors="backslashreplace",
                )
        except Exception as exc:
            print(f"[GIDEON][WARN] No se pudo forzar UTF-8 en stdio: {exc}", file=sys.stderr)
DEFAULT_CONFIG = SCRIPT_DIR / "config" / "config.json"
DEFAULT_SITES = SCRIPT_DIR / "config" / "sites.csv"

_print_lock = threading.Lock()


# ---------------------------------------------------------------------------
# MODELOS
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class Site:
    code: str
    name: str
    ip: str
    platform: str = ""
    host_profile: str = ""
    agent_id: str = ""
    agent_name: str = ""
    hostname: str = ""
    agent_connection: str = ""
    agent_remote_ip: str = ""
    agentless_ip: str = ""
    source: str = ""

    @property
    def label(self) -> str:
        return f"{self.code}_{self.name}"


@dataclasses.dataclass
class RunResult:
    site_code: str
    site_name: str
    server_ip: str
    started_at: str
    finished_at: str
    duration_sec: float
    exit_code: int
    success: bool
    stdout: str
    stderr: str
    data: list[dict[str, Any]]
    remote_error: Optional[str] = None
    failure_type: str = "SUCCESS"
    retryable: bool = False
    attempts: int = 1

@dataclasses.dataclass
class RemoteArtifact:
    site_code: str
    site_name: str
    server_ip: str
    remote_path: str
    local_raw_path: str
    status: str
    failure_type: str
    attempts: int
    exit_code: int
    duration_sec: float
    stderr: str
    remote_error: Optional[str] = None





# ---------------------------------------------------------------------------
# UTILIDADES
# ---------------------------------------------------------------------------



def log(message: str, level: str = "INFO") -> None:
    with _print_lock:
        stamp = dt.datetime.now().strftime("%H:%M:%S")
        print(f"[{stamp}] [{level}] {message}", flush=True)


def ok(message: str) -> None:
    log(message, "OK")


def warn(message: str) -> None:
    log(message, "WARN")


def fail(message: str) -> None:
    log(message, "ERROR")


def expand_path(value: str | Path) -> Path:
    text = os.path.expandvars(str(value))
    text = os.path.expanduser(text)
    return Path(text).resolve()


def load_config(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8-sig") as f:
        return json.load(f)


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def command_exists(name: str) -> Optional[str]:
    return shutil.which(name)


def powershell_stdin_payload(code: str) -> str:
    """Codifica PowerShell como Base64 UTF-16LE para enviarlo por STDIN.

    IMPORTANTE:
    El payload NO se coloca en -EncodedCommand. Viaja por stdin de ssh.exe,
    evitando el límite de longitud de la línea de comandos de Windows.
    """
    return base64.b64encode(code.encode("utf-16le")).decode("ascii")


# ---------------------------------------------------------------------------
# INVENTARIO
# ---------------------------------------------------------------------------

class Inventory:
    def __init__(self, csv_path: Path) -> None:
        self.csv_path = csv_path
        self.sites = self._load()

    def _load(self) -> list[Site]:
        if not self.csv_path.exists():
            raise FileNotFoundError(f"No existe inventario: {self.csv_path}")

        result: list[Site] = []
        with self.csv_path.open("r", encoding="utf-8-sig", newline="") as f:
            for row in csv.DictReader(f):
                result.append(
                    Site(
                        code=str(row.get("SiteCode") or "").strip(),
                        name=str(row.get("SiteName") or "").strip(),
                        ip=str(row.get("ServerIP") or "").strip(),
                        platform=str(row.get("Platform") or "").strip(),
                        host_profile=str(row.get("HostProfile") or "").strip(),
                        agent_id=str(row.get("AgentId") or row.get("AgentID") or "").strip(),
                        agent_name=str(row.get("AgentName") or "").strip(),
                        hostname=str(row.get("Hostname") or "").strip(),
                        agent_connection=str(row.get("AgentConnection") or "").strip(),
                        agent_remote_ip=str(row.get("AgentRemoteIP") or "").strip(),
                        agentless_ip=str(row.get("AgentlessIP") or "").strip(),
                        source=str(row.get("Source") or "").strip(),
                    )
                )
        return result

    def resolve(self, requested: list[str], allow_all: bool) -> list[Site]:
        if not requested:
            raise ValueError("Debe indicar al menos un target.")

        normalized = [x.strip() for x in requested if x.strip()]
        if any(x.upper() == "ALL" for x in normalized):
            if not allow_all:
                raise ValueError("Target ALL requiere --confirm-all.")
            return list(self.sites)

        output: list[Site] = []
        seen: set[str] = set()

        for item in normalized:
            matches = [
                s for s in self.sites
                if s.code.lower() == item.lower()
                or s.name.lower() == item.lower()
                or s.label.lower() == item.lower()
                or s.ip == item
                or s.agentless_ip == item
                or s.agent_id.lower() == item.lower()
                or s.agent_name.lower() == item.lower()
                or s.hostname.lower() == item.lower()
            ]

            if not matches:
                try:
                    socket.inet_aton(item)
                except OSError as exc:
                    raise ValueError(f"Target no encontrado: {item}") from exc
                matches = [Site("CUSTOM", "CUSTOM", item)]

            for site in matches:
                # Agent inventories intentionally have an empty ServerIP because
                # HTTPS/PULL addresses the enrolled SiteCode, not a server IP.
                # Deduplicate by stable identity so multiple Agent rows are not
                # collapsed into the same empty-IP bucket.
                identity = (site.agent_id.lower() if site.agent_id else site.code.lower()) if site.code and site.code != "CUSTOM" else f"custom:{site.ip}"
                if identity not in seen:
                    seen.add(identity)
                    output.append(site)

        if not output:
            raise ValueError("No se resolvió ningún target.")
        return output


# ---------------------------------------------------------------------------
# SSH AGENT
# ---------------------------------------------------------------------------

class SSHAgent:
    def __init__(self, key_path: Path) -> None:
        self.key_path = key_path
        self.ssh_add = command_exists("ssh-add.exe") or command_exists("ssh-add")
        self.ssh_keygen = command_exists("ssh-keygen.exe") or command_exists("ssh-keygen")

        if not self.ssh_keygen:
            raise RuntimeError("No se encontró ssh-keygen.")

    def fingerprint(self) -> str:
        cp = subprocess.run(
            [self.ssh_keygen, "-lf", str(self.key_path)],
            text=True,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            **windows_hidden_kwargs(),
        )
        if cp.returncode != 0:
            raise RuntimeError(f"No se pudo leer fingerprint: {cp.stderr.strip()}")

        match = re.search(r"SHA256:\S+", cp.stdout)
        if not match:
            raise RuntimeError("No se pudo extraer fingerprint SHA256.")
        return match.group(0)

    def _list(self) -> str:
        if not self.ssh_add:
            return ""
        cp = subprocess.run(
            [self.ssh_add, "-l"],
            text=True,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            **windows_hidden_kwargs(),
        )
        return (cp.stdout or "") + (cp.stderr or "")

    def is_loaded(self) -> bool:
        fp = self.fingerprint()
        return fp in self._list()

    def validate(self) -> None:
        """Validate the configured GIDEON identity without mutating ssh-agent."""
        if not self.key_path.exists():
            raise FileNotFoundError(f"No existe clave privada: {self.key_path}")
        fingerprint = self.fingerprint()
        if self.is_loaded():
            ok(f"Identidad GIDEON validada; ssh-agent externo ya contiene {fingerprint}. GIDEON no lo modificó.")
        else:
            ok(f"Identidad GIDEON validada desde archivo: {fingerprint}. GIDEON no inicia/configura/modifica ssh-agent.")

    def load(self) -> None:
        """Backward-compatible alias: P8C validates only and never calls ssh-add."""
        self.validate()

    def remove(self) -> None:
        raise RuntimeError("P8C no modifica ssh-agent. Retire claves externamente si el operador lo requiere.")

    def status(self) -> dict[str, Any]:
        return {
            "key": str(self.key_path),
            "fingerprint": self.fingerprint(),
            "loaded": self.is_loaded(),
        }


# ---------------------------------------------------------------------------
# POWER SHELL REMOTO
# ---------------------------------------------------------------------------

def build_structured_wrapper(user_code: str) -> str:
    # Structured exige que el script devuelva objetos, no Write-Host.
    return rf"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

try {{
    $data = @(
        & {{
{user_code}
        }} 3>$null 4>$null 5>$null 6>$null
    )

    [pscustomobject]@{{
        Success = $true
        Error   = $null
        Data    = $data
    }} | ConvertTo-Json -Depth 12 -Compress
}}
catch {{
    [pscustomobject]@{{
        Success = $false
        Error   = $_.Exception.Message
        Data    = @()
    }} | ConvertTo-Json -Depth 12 -Compress
    exit 1
}}
"""


def build_text_wrapper(user_code: str) -> str:
    return rf"""
$ErrorActionPreference = 'Continue'
& {{
{user_code}
}}
if ($null -ne $LASTEXITCODE) {{ exit $LASTEXITCODE }}
"""


def classify_failure(
    *,
    exit_code: int,
    stderr: str,
    stdout: str,
    remote_error: Optional[str],
) -> tuple[str, bool, str]:
    """Clasifica un fallo y decide si vale la pena reintentar.

    retryable=True se reserva para fallos transitorios de transporte/red.
    Errores de autenticación, host key o del propio script NO se reintentan.
    """
    if exit_code == 0 and not remote_error:
        return "SUCCESS", False, ""

    combined = " ".join(
        x for x in [stderr or "", stdout or "", remote_error or ""] if x
    ).lower()

    # Deadline impuesto por el propio controlador. No equivale necesariamente
    # a un fallo del handshake TCP/SSH: puede ser un comando remoto que quedó
    # esperando. Reintentarlo inmediatamente duplica la congestión y oculta la
    # capa real del problema.
    if exit_code == 124 and "gideon_operation_timeout" in combined:
        return (
            "IO_DEADLINE",
            False,
            "La operación remota excedió el deadline del controlador.",
        )

    # SSH / red
    if (
        "connection timed out" in combined
        or "operation timed out" in combined
        or "timed out" in combined
        or "timeout" in combined
        or "server " in combined and "not responding" in combined
    ):
        return "CONNECT_TIMEOUT", True, "El servidor no respondió dentro del tiempo de conexión."

    if (
        "connection refused" in combined
        or "actively refused" in combined
        or "conexión rechazada" in combined
        or "conexion rechazada" in combined
    ):
        return "CONNECTION_REFUSED", True, "TCP/SSH rechazó temporalmente la conexión."

    if (
        "connection reset" in combined
        or "connection closed" in combined
        or "connection aborted" in combined
        or "software caused connection abort" in combined
    ):
        return "CONNECTION_RESET", True, "La conexión SSH se cerró o reinició."

    if (
        "no route to host" in combined
        or "network is unreachable" in combined
        or "destination host unreachable" in combined
        or "network unreachable" in combined
    ):
        return "NETWORK_UNREACHABLE", True, "No hubo ruta de red hacia el servidor."

    if (
        "could not resolve hostname" in combined
        or "name or service not known" in combined
    ):
        return "NAME_RESOLUTION_ERROR", False, "No se pudo resolver el destino."

    # Seguridad / autenticación
    if (
        "permission denied" in combined
        or "authentication failed" in combined
        or "no more authentication methods" in combined
    ):
        return "AUTH_FAILED", False, "SSH rechazó la autenticación."

    if (
        "remote host identification has changed" in combined
        or "host key verification failed" in combined
        or "offending" in combined and "known_hosts" in combined
    ):
        return "HOST_KEY_ERROR", False, "La host key no coincide o no pudo validarse."

    # PowerShell remoto / Structured
    if remote_error:
        return "REMOTE_SCRIPT_ERROR", False, remote_error

    # Código 255 suele ser transporte SSH. Si no encaja en los anteriores,
    # se deja como SSH_ERROR y no se reintenta a ciegas.
    if exit_code == 255:
        return "SSH_ERROR", False, (stderr.strip() or stdout.strip() or "Error SSH no clasificado.")

    return "REMOTE_COMMAND_ERROR", False, (
        remote_error or stderr.strip() or stdout.strip() or f"ExitCode={exit_code}"
    )


def retry_delay_for(attempt_number: int, delays: list[int]) -> int:
    """Devuelve la espera antes del siguiente intento.

    attempt_number es el intento que acaba de fallar (1, 2, ...).
    Con delays=[3,5]:
      tras intento 1 -> 3s
      tras intento 2 -> 5s
      intentos posteriores -> último valor.
    """
    if not delays:
        return 0
    idx = max(0, min(attempt_number - 1, len(delays) - 1))
    return max(0, int(delays[idx]))


class RemoteExecutor:
    """Ejecutor asíncrono SSH/SCP.

    Flujo por sede:
      1. Python envía el script PowerShell por STDIN.
      2. PowerShell ejecuta TODO en el servidor.
      3. PowerShell guarda un archivo de texto plano en el servidor.
      4. Cuando termina, SSH devuelve solo un pequeño manifiesto JSON.
      5. Python descarga el archivo con SCP.
      6. El formateo XLSX/CSV/JSON se hace exclusivamente en la PC.
    """

    def __init__(
        self,
        *,
        user: str,
        key_path: Path,
        known_hosts: Path,
        port: int,
        timeout: int,
        strict_host_key_checking: str,
        max_attempts: int,
        retry_delays: list[int],
        raw_dir: Path,
        remote_results_root: str = r"C:\ProgramData\GIDEONSSH\results",
        delete_remote_after_download: bool = True,
    ) -> None:
        self.user = user
        self.key_path = key_path
        self.known_hosts = known_hosts
        self.port = port
        self.timeout = timeout
        self.strict = strict_host_key_checking
        self.max_attempts = max(1, int(max_attempts))
        self.retry_delays = [max(0, int(x)) for x in retry_delays]
        self.raw_dir = ensure_dir(raw_dir)
        self.remote_results_root = remote_results_root
        self.delete_remote_after_download = delete_remote_after_download

        self.ssh = command_exists("ssh.exe") or command_exists("ssh")
        self.scp = command_exists("scp.exe") or command_exists("scp")

        if not self.ssh:
            raise RuntimeError("No se encontró ssh.exe.")
        if not self.scp:
            raise RuntimeError("No se encontró scp.exe.")

        ensure_dir(self.known_hosts.parent)
        self.known_hosts.touch(exist_ok=True)

    def _common_ssh_options(self) -> list[str]:
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
            "-i", str(self.key_path),
        ]

    def _ssh_args(self, site: Site) -> list[str]:
        # Comando remoto corto. El código real viaja por STDIN.
        remote = (
            'powershell.exe -NoLogo -NoProfile -NonInteractive '
            '-ExecutionPolicy Bypass -Command '
            '"[Console]::Error.WriteLine(\'[GIDEON_STAGE] SSH_ESTABLISHED\');'
            '$b=[Console]::In.ReadToEnd();'
            '$s=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b));'
            'Invoke-Expression $s"'
        )
        return [
            self.ssh,
            "-T",
            *self._common_ssh_options(),
            f"{self.user}@{site.ip}",
            remote,
        ]

    def _scp_args(self, site: Site, remote_path: str, local_path: Path) -> list[str]:
        # scp usa -P mayúscula para el puerto.
        opts = [
            "-P", str(self.port),
            "-o", "BatchMode=yes",
            "-o", "IdentitiesOnly=yes",
            "-o", f"ConnectTimeout={self.timeout}",
            "-o", f"StrictHostKeyChecking={self.strict}",
            "-o", f"UserKnownHostsFile={self.known_hosts}",
            "-i", str(self.key_path),
        ]

        # La ruta remota se pasa entre comillas para conservar espacios.
        remote_spec = f'{self.user}@{site.ip}:"{remote_path}"'
        return [
            self.scp,
            *opts,
            remote_spec,
            str(local_path),
        ]

    def _delete_remote_args(self, site: Site, remote_path: str) -> list[str]:
        escaped = remote_path.replace("'", "''")
        remote = (
            "powershell.exe -NoLogo -NoProfile -NonInteractive "
            "-ExecutionPolicy Bypass -Command "
            f"\"Remove-Item -LiteralPath '{escaped}' -Force -ErrorAction SilentlyContinue\""
        )
        return [
            self.ssh,
            "-T",
            *self._common_ssh_options(),
            f"{self.user}@{site.ip}",
            remote,
        ]

    def build_remote_file_wrapper(
        self,
        *,
        site: Site,
        user_code: str,
        mode: str,
        job_id: str,
    ) -> tuple[str, str]:
        safe_site = re.sub(r"[^A-Za-z0-9_-]", "_", site.label)
        ext = "txt"
        remote_filename = f"{job_id}_{safe_site}.{ext}"
        remote_path = self.remote_results_root.rstrip("\\") + "\\" + remote_filename

        escaped_root = self.remote_results_root.replace("'", "''")
        escaped_path = remote_path.replace("'", "''")

        if mode == "structured":
            # Se escribe JSON en un .txt: sigue siendo texto plano, pero permite
            # reconstruir objetos localmente sin cargar Excel en el servidor.
            wrapper = rf"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$remoteRoot = '{escaped_root}'
$resultPath = '{escaped_path}'
New-Item -ItemType Directory -Path $remoteRoot -Force | Out-Null

[Console]::Error.WriteLine("[GIDEON_STAGE] SCRIPT_RUNNING")
$started = Get-Date
$payload = $null

try {{
    $data = @(
        & {{
{user_code}
        }} 3>$null 4>$null 5>$null 6>$null
    )

    $payload = [pscustomobject]@{{
        Success    = $true
        Error      = $null
        Hostname   = $env:COMPUTERNAME
        StartedAt  = $started
        FinishedAt = Get-Date
        Data       = $data
    }}
    $exitCode = 0
}}
catch {{
    $payload = [pscustomobject]@{{
        Success    = $false
        Error      = $_.Exception.Message
        Hostname   = $env:COMPUTERNAME
        StartedAt  = $started
        FinishedAt = Get-Date
        Data       = @()
    }}
    $exitCode = 1
}}

$payload |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $resultPath -Encoding UTF8

[Console]::Error.WriteLine("[GIDEON_STAGE] TXT_READY|$resultPath")

[pscustomobject]@{{
    ResultPath = $resultPath
    ExitCode   = $exitCode
    Success    = ($exitCode -eq 0)
}} | ConvertTo-Json -Compress

exit $exitCode
"""
        else:
            wrapper = rf"""
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$remoteRoot = '{escaped_root}'
$resultPath = '{escaped_path}'
New-Item -ItemType Directory -Path $remoteRoot -Force | Out-Null

[Console]::Error.WriteLine("[GIDEON_STAGE] SCRIPT_RUNNING")
$started = Get-Date
$lines = New-Object System.Collections.Generic.List[string]
$exitCode = 0
$errorText = $null

try {{
    $output = & {{
{user_code}
    }} 2>&1

    foreach ($line in @($output)) {{
        [void]$lines.Add("$line")
    }}

    if ($null -ne $LASTEXITCODE) {{
        $exitCode = [int]$LASTEXITCODE
    }}
}}
catch {{
    $exitCode = 1
    $errorText = $_.Exception.Message
    [void]$lines.Add("[ERROR] " + $errorText)
}}

@(
    "Hostname=$env:COMPUTERNAME"
    "StartedAt=$($started.ToString('o'))"
    "FinishedAt=$((Get-Date).ToString('o'))"
    "ExitCode=$exitCode"
    "----- OUTPUT -----"
    $lines
) | Set-Content -LiteralPath $resultPath -Encoding UTF8

[Console]::Error.WriteLine("[GIDEON_STAGE] TXT_READY|$resultPath")

[pscustomobject]@{{
    ResultPath = $resultPath
    ExitCode   = $exitCode
    Success    = ($exitCode -eq 0)
}} | ConvertTo-Json -Compress

exit $exitCode
"""

        return wrapper, remote_path

    def _emit_stage(
        self,
        *,
        site: Site,
        stage: str,
        detail: str,
        attempt: int,
        stage_callback=None,
    ) -> None:
        """Muestra y persiste un cambio de etapa por sede."""
        log(
            f"{site.label} ({site.ip}) - [{stage}] "
            f"{detail} (intento {attempt}/{self.max_attempts})"
        )

        if stage_callback:
            try:
                stage_callback(
                    "stage",
                    site,
                    0,
                    0,
                    {
                        "Stage": stage,
                        "Detail": detail,
                        "Attempt": attempt,
                        "At": now_iso(),
                    },
                )
            except Exception as exc:
                warn(f"No se pudo persistir etapa {stage} para {site.label}: {exc}")

    async def _run_ssh_staged(
        self,
        *,
        site: Site,
        args: list[str],
        input_text: str,
        attempt: int,
        stage_callback=None,
    ) -> tuple[int, str, str]:
        """Ejecuta SSH con estados reales y visibles.

        Secuencia:
          CONNECTING
          SSH_ESTABLISHED  <- confirmado por PowerShell remoto
          SCRIPT_SENT      <- payload entregado por STDIN a ssh.exe
          SCRIPT_RUNNING   <- confirmado por wrapper remoto
          WAITING_REMOTE_TXT
          SCAN_START / DRIVE_START / SCAN_PROGRESS / BAK_FOUND
          DRIVE_COMPLETE / SCAN_COMPLETE
          TXT_READY        <- confirmado por servidor
        """
        self._emit_stage(
            site=site,
            stage="CONNECTING",
            detail="Abriendo conexión SSH.",
            attempt=attempt,
            stage_callback=stage_callback,
        )

        proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        connected_event = asyncio.Event()
        stdout_chunks: list[bytes] = []
        stderr_lines: list[str] = []

        async def read_stdout() -> None:
            assert proc.stdout is not None
            while True:
                chunk = await proc.stdout.read(65536)
                if not chunk:
                    break
                stdout_chunks.append(chunk)

        async def read_stderr() -> None:
            assert proc.stderr is not None
            while True:
                raw = await proc.stderr.readline()
                if not raw:
                    break

                line = raw.decode("utf-8", errors="replace").rstrip("\r\n")

                if line.startswith("[GIDEON_STAGE] "):
                    marker = line[len("[GIDEON_STAGE] "):]

                    if marker == "SSH_ESTABLISHED":
                        connected_event.set()
                        self._emit_stage(
                            site=site,
                            stage="SSH_ESTABLISHED",
                            detail="Conexión SSH confirmada; PowerShell remoto está disponible.",
                            attempt=attempt,
                            stage_callback=stage_callback,
                        )
                        continue

                    if marker == "SCRIPT_RUNNING":
                        self._emit_stage(
                            site=site,
                            stage="SCRIPT_RUNNING",
                            detail="El script se está ejecutando en el servidor.",
                            attempt=attempt,
                            stage_callback=stage_callback,
                        )
                        continue

                    if marker.startswith("TXT_READY|"):
                        remote_path = marker.split("|", 1)[1]
                        self._emit_stage(
                            site=site,
                            stage="TXT_READY",
                            detail=f"El servidor generó el TXT: {remote_path}",
                            attempt=attempt,
                            stage_callback=stage_callback,
                        )
                        continue

                if line.startswith("[GIDEON_PROGRESS] "):
                    raw_progress = line[len("[GIDEON_PROGRESS] "):]
                    fields: dict[str, str] = {}

                    for token in raw_progress.split(";"):
                        if "=" not in token:
                            continue
                        key_name, value = token.split("=", 1)
                        fields[key_name.strip()] = value.strip()

                    progress_type = fields.get("Type", "SCAN_PROGRESS")
                    drive = fields.get("Drive", "-")
                    directories = fields.get("Directories", "0")
                    drive_directories = fields.get("DriveDirectories", "0")
                    backup_folders = fields.get("BackupFolders", "0")
                    access_errors = fields.get("AccessErrors", "0")
                    elapsed = fields.get("ElapsedSec", "0")
                    current_b64 = fields.get("CurrentB64", "")

                    current_path = ""
                    if current_b64:
                        try:
                            current_path = base64.b64decode(
                                current_b64.encode("ascii"),
                                validate=False,
                            ).decode("utf-8", errors="replace")
                        except Exception:
                            current_path = "<ruta no decodificable>"

                    stage_map = {
                        "SCAN_START": "SCAN_START",
                        "DRIVE_START": "DRIVE_START",
                        "SCAN_PROGRESS": "SCAN_PROGRESS",
                        "BAK_FOUND": "BAK_FOUND",
                        "DRIVE_COMPLETE": "DRIVE_COMPLETE",
                        "SCAN_COMPLETE": "SCAN_COMPLETE",
                    }
                    stage_name = stage_map.get(progress_type, "SCAN_PROGRESS")

                    detail = (
                        f"Drive={drive} | Dirs={directories} "
                        f"(unidad={drive_directories}) | "
                        f"BAK folders={backup_folders} | "
                        f"AccessErrors={access_errors} | "
                        f"Elapsed={elapsed}s"
                    )
                    if current_path:
                        detail += f" | Current={current_path}"

                    self._emit_stage(
                        site=site,
                        stage=stage_name,
                        detail=detail,
                        attempt=attempt,
                        stage_callback=stage_callback,
                    )
                    continue

                stderr_lines.append(line)

        stdout_task = asyncio.create_task(read_stdout())
        stderr_task = asyncio.create_task(read_stderr())
        wait_task = asyncio.create_task(proc.wait())
        connect_task = asyncio.create_task(connected_event.wait())

        # Esperar confirmación real del proceso remoto o terminación temprana.
        done, _ = await asyncio.wait(
            {connect_task, wait_task},
            timeout=max(5, self.timeout + 5),
            return_when=asyncio.FIRST_COMPLETED,
        )

        if connect_task not in done or not connected_event.is_set():
            # Puede haber terminado por timeout/auth/host-key antes de establecerse.
            if not wait_task.done():
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                await proc.wait()

            try:
                if proc.stdin:
                    proc.stdin.close()
            except Exception as exc:
                warn(f"STDIN_CLOSE_WARNING {site.label}: {exc}")

            await stdout_task
            await stderr_task

            if not connect_task.done():
                connect_task.cancel()

            stdout = b"".join(stdout_chunks).decode("utf-8", errors="replace")
            stderr = "\n".join(stderr_lines)
            return proc.returncode if proc.returncode is not None else 255, stdout, stderr

        # Con SSH confirmado, recién entregamos el script por STDIN.
        payload_bytes = input_text.encode("utf-8")
        assert proc.stdin is not None

        proc.stdin.write(payload_bytes)
        await proc.stdin.drain()
        proc.stdin.close()

        try:
            await proc.stdin.wait_closed()
        except (AttributeError, ConnectionResetError, BrokenPipeError):
            pass

        self._emit_stage(
            site=site,
            stage="SCRIPT_SENT",
            detail=(
                f"Contenido del .ps1 enviado por SSH/STDIN "
                f"({len(payload_bytes) / 1024:.1f} KB)."
            ),
            attempt=attempt,
            stage_callback=stage_callback,
        )

        self._emit_stage(
            site=site,
            stage="WAITING_REMOTE_TXT",
            detail="Servidor procesando; a la espera del archivo TXT de resultado.",
            attempt=attempt,
            stage_callback=stage_callback,
        )

        await wait_task
        await stdout_task
        await stderr_task

        if not connect_task.done():
            connect_task.cancel()

        stdout = b"".join(stdout_chunks).decode("utf-8", errors="replace")
        stderr = "\n".join(stderr_lines)
        return proc.returncode, stdout, stderr

    async def _create_process(
        self,
        *args: str,
        input_text: Optional[str] = None,
    ) -> tuple[int, str, str]:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE if input_text is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdin_bytes = input_text.encode("utf-8") if input_text is not None else None
        stdout_b, stderr_b = await proc.communicate(stdin_bytes)

        stdout = stdout_b.decode("utf-8", errors="replace")
        stderr = stderr_b.decode("utf-8", errors="replace")
        return proc.returncode, stdout, stderr

    async def _download_result_file(
        self,
        site: Site,
        remote_path: str,
        local_path: Path,
        *,
        attempt: int,
        stage_callback=None,
    ) -> tuple[bool, str]:
        ensure_dir(local_path.parent)

        self._emit_stage(
            site=site,
            stage="SCP_DOWNLOADING",
            detail=f"Descargando TXT remoto hacia {local_path}.",
            attempt=attempt,
            stage_callback=stage_callback,
        )

        code, stdout, stderr = await self._create_process(
            *self._scp_args(site, remote_path, local_path)
        )

        if code != 0 or not local_path.exists():
            return False, (stderr.strip() or stdout.strip() or f"SCP ExitCode={code}")

        self._emit_stage(
            site=site,
            stage="RAW_DOWNLOADED",
            detail=f"TXT recibido correctamente en la PC: {local_path}",
            attempt=attempt,
            stage_callback=stage_callback,
        )

        if self.delete_remote_after_download:
            try:
                await self._create_process(
                    *self._delete_remote_args(site, remote_path)
                )
            except Exception as exc:
                # La descarga ya fue exitosa; una limpieza fallida no invalida el job.
                warn(f"REMOTE_RESULT_CLEANUP_WARNING {site.label}: {exc}")

        return True, ""

    async def run_one_attempt(
        self,
        site: Site,
        user_code: str,
        mode: str,
        job_id: str,
        attempt: int,
        stage_callback=None,
    ) -> RunResult:
        wrapper, expected_remote_path = self.build_remote_file_wrapper(
            site=site,
            user_code=user_code,
            mode=mode,
            job_id=job_id,
        )

        stdin_payload = powershell_stdin_payload(wrapper)
        args = self._ssh_args(site)

        started = dt.datetime.now().astimezone()
        t0 = time.perf_counter()

        exit_code, stdout, stderr = await self._run_ssh_staged(
            site=site,
            args=args,
            input_text=stdin_payload,
            attempt=attempt,
            stage_callback=stage_callback,
        )

        duration = round(time.perf_counter() - t0, 2)
        finished = dt.datetime.now().astimezone()

        manifest = None
        remote_error: Optional[str] = None

        if stdout.strip():
            try:
                manifest = json.loads(stdout.strip().splitlines()[-1])
            except json.JSONDecodeError:
                manifest = None

        # Si el remoto alcanzó a escribir el archivo, intentamos descargarlo
        # incluso si el script devolvió ExitCode=1.
        remote_path = (
            manifest.get("ResultPath")
            if isinstance(manifest, dict) and manifest.get("ResultPath")
            else expected_remote_path
        )

        raw_name = (
            f"{site.code}_{site.name}_{job_id}_attempt{attempt}.txt"
        )
        local_raw = self.raw_dir / raw_name

        downloaded = False
        download_error = ""

        # Solo intentamos SCP si existe evidencia de que PowerShell remoto se ejecutó.
        if manifest is not None:
            downloaded, download_error = await self._download_result_file(
                site,
                remote_path,
                local_raw,
                attempt=attempt,
                stage_callback=stage_callback,
            )

        # Si se descargó un archivo structured, el error real del script se
        # determina leyendo ese archivo local, no consultando SQL ni formateando remoto.
        data: list[dict[str, Any]] = []
        if downloaded and mode == "structured":
            try:
                payload = json.loads(local_raw.read_text(encoding="utf-8-sig"))
                raw_data = payload.get("Data", [])
                remote_error = payload.get("Error")
                if isinstance(raw_data, dict):
                    raw_data = [raw_data]
                elif raw_data is None:
                    raw_data = []

                for item in raw_data:
                    if isinstance(item, dict):
                        data.append(item)
                    else:
                        data.append({"Value": item})
            except Exception as exc:
                remote_error = f"No se pudo interpretar archivo TXT/JSON local: {exc}"

        if manifest is None:
            failure_type, retryable, classified = classify_failure(
                exit_code=exit_code,
                stderr=stderr,
                stdout=stdout,
                remote_error=None,
            )
            remote_error = classified or None

        elif not downloaded:
            failure_type = "RESULT_DOWNLOAD_ERROR"
            retryable = True
            remote_error = download_error or "No se pudo descargar el archivo de resultado."

        elif remote_error:
            failure_type = "REMOTE_SCRIPT_ERROR"
            retryable = False

        elif exit_code != 0:
            # El archivo remoto fue descargado. El script pudo haber devuelto error
            # sin que exista problema SSH.
            failure_type = "REMOTE_COMMAND_ERROR"
            retryable = False
            remote_error = (
                remote_error
                or f"El script remoto terminó con ExitCode={exit_code}."
            )

        else:
            failure_type = "SUCCESS"
            retryable = False

        return RunResult(
            site_code=site.code,
            site_name=site.name,
            server_ip=site.ip,
            started_at=started.isoformat(timespec="seconds"),
            finished_at=finished.isoformat(timespec="seconds"),
            duration_sec=duration,
            exit_code=exit_code,
            success=(failure_type == "SUCCESS"),
            stdout=str(local_raw) if downloaded else "",
            stderr=stderr,
            data=data,
            remote_error=remote_error,
            failure_type=failure_type,
            retryable=retryable,
            attempts=attempt,
        )

    async def run_with_retries(
        self,
        site: Site,
        user_code: str,
        mode: str,
        job_id: str,
        attempt_callback=None,
    ) -> RunResult:
        first_started: Optional[str] = None
        total_duration = 0.0
        last_result: Optional[RunResult] = None

        for attempt in range(1, self.max_attempts + 1):
            if attempt_callback:
                attempt_callback("attempt_start", site, attempt, self.max_attempts, None)

            result = await self.run_one_attempt(
                site=site,
                user_code=user_code,
                mode=mode,
                job_id=job_id,
                attempt=attempt,
                stage_callback=attempt_callback,
            )
            last_result = result

            if first_started is None:
                first_started = result.started_at

            total_duration += result.duration_sec
            result.started_at = first_started
            result.duration_sec = round(total_duration, 2)

            if result.success:
                if attempt_callback:
                    attempt_callback("attempt_success", site, attempt, self.max_attempts, result)
                return result

            if attempt_callback:
                attempt_callback("attempt_failure", site, attempt, self.max_attempts, result)

            if not result.retryable or attempt >= self.max_attempts:
                return result

            delay = retry_delay_for(attempt, self.retry_delays)
            warn(
                f"{site.label} ({site.ip}) - intento {attempt}/{self.max_attempts} "
                f"{result.failure_type}; reintento en {delay}s."
            )
            if delay > 0:
                await asyncio.sleep(delay)

        assert last_result is not None
        return last_result

    async def run_many_async(
        self,
        sites: list[Site],
        user_code: str,
        mode: str,
        workers: int,
        job_id: str,
        progress_callback=None,
    ) -> list[RunResult]:
        total = len(sites)
        semaphore = asyncio.Semaphore(max(1, workers))
        results: list[RunResult] = []
        completed = 0

        log(f"Ejecutando {total} sede(s) en modo ASYNC con concurrencia máxima={workers}.")
        log(
            f"SSH: ConnectTimeout={self.timeout}s | "
            f"Intentos máximos={self.max_attempts} | "
            f"Pausas={self.retry_delays or [0]}"
        )
        log("Flujo: servidor ejecuta -> TXT remoto -> SCP a PC -> formato local.")

        if progress_callback:
            progress_callback("run_start", None, 0, total, None)

        async def worker(site: Site) -> tuple[Site, RunResult]:
            async with semaphore:
                result = await self.run_with_retries(
                    site=site,
                    user_code=user_code,
                    mode=mode,
                    job_id=job_id,
                    attempt_callback=progress_callback,
                )
                return site, result

        tasks = [asyncio.create_task(worker(site)) for site in sites]

        for task in asyncio.as_completed(tasks):
            site, result = await task
            results.append(result)
            completed += 1
            pct = round((completed / total) * 100, 1) if total else 100.0

            if result.success:
                ok(
                    f"[{completed}/{total} {pct:.1f}%] {site.label} ({site.ip}) "
                    f"- OK - TXT={result.stdout}"
                )
            else:
                warn(
                    f"[{completed}/{total} {pct:.1f}%] {site.label} ({site.ip}) "
                    f"- {result.failure_type} - intentos={result.attempts} "
                    f"- {result.remote_error or result.stderr.strip()[:160]}"
                )

            if progress_callback:
                progress_callback("site_complete", site, completed, total, result)

        order = {site.ip: idx for idx, site in enumerate(sites)}
        results.sort(key=lambda r: order.get(r.server_ip, 9999))

        if progress_callback:
            progress_callback("run_complete", None, total, total, None)

        return results

    def run_many(
        self,
        sites: list[Site],
        user_code: str,
        mode: str,
        workers: int,
        job_id: str,
        progress_callback=None,
    ) -> list[RunResult]:
        # Punto de entrada síncrono para el CLI actual.
        return asyncio.run(
            self.run_many_async(
                sites=sites,
                user_code=user_code,
                mode=mode,
                workers=workers,
                job_id=job_id,
                progress_callback=progress_callback,
            )
        )


# ---------------------------------------------------------------------------
# TEST TCP
# ---------------------------------------------------------------------------

def tcp_test(site: Site, port: int, timeout: int) -> dict[str, Any]:
    t0 = time.perf_counter()
    try:
        with socket.create_connection((site.ip, port), timeout=timeout):
            success = True
            error = None
    except Exception as exc:
        success = False
        error = str(exc)

    return {
        "SiteCode": site.code,
        "SiteName": site.name,
        "ServerIP": site.ip,
        "Port": port,
        "Success": success,
        "DurationSec": round(time.perf_counter() - t0, 2),
        "Error": error,
    }


# ---------------------------------------------------------------------------
# EXPORTACIÓN
# ---------------------------------------------------------------------------

def flatten_rows(results: list[RunResult], mode: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    summary: list[dict[str, Any]] = []
    data: list[dict[str, Any]] = []

    for r in results:
        summary.append({
            "SiteCode": r.site_code,
            "SiteName": r.site_name,
            "ServerIP": r.server_ip,
            "Success": r.success,
            "FailureType": r.failure_type,
            "Attempts": r.attempts,
            "ExitCode": r.exit_code,
            "DurationSec": r.duration_sec,
            "StartedAt": r.started_at,
            "FinishedAt": r.finished_at,
            "RemoteError": r.remote_error,
            "RawTextFile": r.stdout,
            "StdErr": r.stderr.strip(),
        })

        if mode == "structured":
            for item in r.data:
                row = {
                    "SiteCode": r.site_code,
                    "SiteName": r.site_name,
                    "ServerIP": r.server_ip,
                }
                row.update(item)
                data.append(row)
        else:
            raw_text = ""
            raw_file = Path(r.stdout) if r.stdout else None
            if raw_file and raw_file.exists():
                try:
                    raw_text = raw_file.read_text(encoding="utf-8-sig", errors="replace")
                except Exception:
                    raw_text = ""

            data.append({
                "SiteCode": r.site_code,
                "SiteName": r.site_name,
                "ServerIP": r.server_ip,
                "RawTextFile": r.stdout,
                "TextContent": raw_text,
                "StdErr": r.stderr,
            })

    return summary, data


def union_columns(rows: list[dict[str, Any]]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for key in row:
            if key not in seen:
                seen.add(key)
                result.append(key)
    return result


def scalarize(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool, dt.datetime, dt.date)):
        return value
    return json.dumps(value, ensure_ascii=False, default=str)


def export_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    ensure_dir(path.parent)
    columns = union_columns(rows) or ["Info"]
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        w.writeheader()
        if rows:
            for row in rows:
                w.writerow({k: scalarize(row.get(k)) for k in columns})


def export_xlsx(path: Path, summary: list[dict[str, Any]], data: list[dict[str, Any]]) -> None:
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font
        from openpyxl.utils import get_column_letter
    except ImportError as exc:
        raise RuntimeError(
            "Falta openpyxl. Instale: py -m pip install openpyxl"
        ) from exc

    ensure_dir(path.parent)
    wb = Workbook()

    def write_sheet(ws, rows: list[dict[str, Any]]) -> None:
        cols = union_columns(rows) or ["Info"]
        ws.append(cols)
        for cell in ws[1]:
            cell.font = Font(bold=True)

        for row in rows:
            ws.append([scalarize(row.get(c)) for c in cols])

        ws.freeze_panes = "A2"
        ws.auto_filter.ref = ws.dimensions

        for idx, col in enumerate(cols, start=1):
            max_len = len(str(col))
            for cell in ws.iter_cols(min_col=idx, max_col=idx, min_row=2, max_row=min(ws.max_row, 300)):
                for x in cell:
                    max_len = max(max_len, len(str(x.value or "")))
            ws.column_dimensions[get_column_letter(idx)].width = min(max_len + 2, 60)

    ws1 = wb.active
    ws1.title = "Summary"
    write_sheet(ws1, summary)

    ws2 = wb.create_sheet("Data")
    write_sheet(ws2, data)

    wb.save(path)


def export_results(
    results: list[RunResult],
    mode: str,
    export_format: str,
    output: Path,
) -> list[Path]:
    summary, data = flatten_rows(results, mode)
    ensure_dir(output.parent)
    created: list[Path] = []

    if export_format == "none":
        return created

    if export_format == "auto":
        export_format = "xlsx" if mode == "structured" else "txt"

    if export_format == "xlsx":
        try:
            export_xlsx(output.with_suffix(".xlsx"), summary, data)
            created.append(output.with_suffix(".xlsx"))
            return created
        except RuntimeError as exc:
            warn(str(exc))
            warn("Se usará CSV como fallback.")
            export_format = "csv"

    if export_format == "csv":
        summary_path = output.with_name(output.name + "_summary").with_suffix(".csv")
        data_path = output.with_name(output.name + "_data").with_suffix(".csv")
        export_csv(summary_path, summary)
        export_csv(data_path, data)
        created.extend([summary_path, data_path])

    elif export_format == "json":
        path = output.with_suffix(".json")
        path.write_text(
            json.dumps(
                {
                    "GeneratedAt": now_iso(),
                    "Summary": summary,
                    "Data": data,
                },
                indent=2,
                ensure_ascii=False,
                default=str,
            ),
            encoding="utf-8",
        )
        created.append(path)

    elif export_format == "txt":
        path = output.with_suffix(".txt")
        parts: list[str] = []
        for r in results:
            parts.extend([
                "=" * 80,
                f"{r.site_code}_{r.site_name} - {r.server_ip}",
                f"Success={r.success} FailureType={r.failure_type} Attempts={r.attempts} ExitCode={r.exit_code} DurationSec={r.duration_sec}",
                "-" * 80,
                (
                    Path(r.stdout).read_text(encoding="utf-8-sig", errors="replace")
                    if r.stdout and Path(r.stdout).exists()
                    else r.stdout
                ),
            ])
            if r.stderr:
                parts.extend(["", "[SSH STDERR]", r.stderr])
            parts.append("")
        path.write_text("\n".join(parts), encoding="utf-8-sig")
        created.append(path)

    return created


# ---------------------------------------------------------------------------
# JOBS
# ---------------------------------------------------------------------------

class JobStore:
    def __init__(self, jobs_dir: Path, logs_dir: Path) -> None:
        self.jobs_dir = ensure_dir(jobs_dir)
        self.logs_dir = ensure_dir(logs_dir)
        self._lock = threading.Lock()

    def job_path(self, job_id: str) -> Path:
        return self.jobs_dir / f"{job_id}.json"

    def log_path(self, job_id: str) -> Path:
        return self.logs_dir / f"{job_id}.log"

    def write(self, job_id: str, payload: dict[str, Any]) -> None:
        with self._lock:
            path = self.job_path(job_id)
            io_atomic_write_json(path, payload, lock_timeout=2.0, retries=8)

    def update(self, job_id: str, **fields: Any) -> dict[str, Any]:
        with self._lock:
            path = self.job_path(job_id)
            if not path.exists():
                raise FileNotFoundError(f"Job no encontrado: {job_id}")
            def updater(current):
                payload = dict(current or {})
                payload.update(fields)
                return payload
            return update_json_atomic(
                path, updater, default={}, lock_timeout=2.0, retries=8
            )

    def update_site_stage(
        self,
        job_id: str,
        site_label: str,
        stage: str,
        detail: str,
        attempt: int,
        at: Optional[str] = None,
    ) -> dict[str, Any]:
        """Actualiza la etapa sin perder cambios de otro proceso."""
        with self._lock:
            path = self.job_path(job_id)
            if not path.exists():
                raise FileNotFoundError(f"Job no encontrado: {job_id}")
            timestamp = at or now_iso()
            def updater(current):
                payload = dict(current or {})
                stages = dict(payload.get("SiteStages") or {})
                stages[site_label] = {
                    "Stage": stage,
                    "Detail": detail,
                    "Attempt": attempt,
                    "At": timestamp,
                }
                payload["SiteStages"] = stages
                payload["LastStage"] = stage
                payload["LastStageSite"] = site_label
                payload["LastStageAt"] = timestamp
                return payload
            return update_json_atomic(
                path, updater, default={}, lock_timeout=2.0, retries=8
            )

    def read(self, job_id: str) -> dict[str, Any]:
        path = self.job_path(job_id)
        if not path.exists():
            raise FileNotFoundError(f"Job no encontrado: {job_id}")
        return read_json_retry(path, retries=4)

    def list(self) -> list[dict[str, Any]]:
        jobs: list[dict[str, Any]] = []
        for path in sorted(
            self.jobs_dir.glob("*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        ):
            try:
                jobs.append(read_json_retry(path, retries=2))
            except Exception:
                continue
        return jobs


def spawn_background(args: argparse.Namespace, agent: SSHAgent, store: JobStore, total_count: int) -> str:
    # La clave debe quedar cargada en el agente antes de desprender el worker.
    agent.load()

    job_id = dt.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
    log_path = store.log_path(job_id)

    worker_args = [
        sys.executable,
        str(Path(__file__).resolve()),
        "run",
    ]

    if args.targets:
        worker_args += ["--targets", args.targets]
    if args.all:
        worker_args += ["--all", "--confirm-all"]

    if args.command is not None:
        worker_args += ["--command", args.command]
    else:
        worker_args += ["--script", str(args.script)]

    worker_args += [
        "--mode", args.mode,
        "--export", args.export_format,
        "--workers", str(args.workers),
        "--timeout", str(args.timeout),
        "--attempts", str(args.attempts),
        "--retry-delays", ",".join(str(x) for x in args.retry_delays),
        "--user", args.user,
        "--key", str(args.key),
        "--_worker-job", job_id,
    ]

    if args.output:
        worker_args += ["--output", str(args.output)]
    if args.strict:
        worker_args += ["--strict"]

    payload = {
        "JobId": job_id,
        "Status": "QUEUED",
        "CreatedAt": now_iso(),
        "StartedAt": None,
        "FinishedAt": None,
        "Pid": None,
        "Targets": args.targets if args.targets else "ALL",
        "Mode": args.mode,
        "Export": args.export_format,
        "Output": str(args.output) if args.output else None,
        "Log": str(log_path),
        "Error": None,
        "RawDir": None,
        "TotalCount": total_count,
        "CompletedCount": 0,
        "SuccessCount": 0,
        "ErrorCount": 0,
        "RetryCount": 0,
        "ProgressPct": 0.0,
        "LastCompleted": None,
        "LastFailureType": None,
        "FailureBreakdown": {},
        "CancelRequestedAt": None,
        "CancelledAt": None,
        "CancelReason": None,
        "PreviousStatus": None,
        "LastStage": "QUEUED",
        "LastStageSite": None,
        "LastStageAt": now_iso(),
        "SiteStages": {},
    }
    store.write(job_id, payload)

    ensure_dir(log_path.parent)
    log_handle = log_path.open("a", encoding="utf-8", buffering=1)

    creationflags = 0
    if os.name == "nt":
        creationflags = (
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            | getattr(subprocess, "CREATE_NO_WINDOW", 0)
        )

    proc = subprocess.Popen(
        worker_args,
        stdin=subprocess.DEVNULL,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        cwd=str(SCRIPT_DIR),
        creationflags=creationflags,
        close_fds=True,
    )

    payload["Status"] = "RUNNING"
    payload["StartedAt"] = now_iso()
    payload["Pid"] = proc.pid
    store.write(job_id, payload)
    log_handle.close()

    ok(f"Job lanzado en background: {job_id} (PID {proc.pid})")
    log(f"Log: {log_path}")
    return job_id


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_targets_text(value: str) -> list[str]:
    return [x.strip() for x in value.split(",") if x.strip()]



def parse_retry_delays(value: Any) -> list[int]:
    if value is None:
        return []
    if isinstance(value, list):
        raw = value
    else:
        raw = [x.strip() for x in str(value).split(",") if x.strip()]

    result: list[int] = []
    for item in raw:
        number = int(item)
        if number < 0 or number > 300:
            raise ValueError("Cada retry delay debe estar entre 0 y 300 segundos.")
        result.append(number)
    return result

def config_objects(config_path: Path, sites_path: Path, args: argparse.Namespace):
    cfg = load_config(config_path)
    inventory = Inventory(sites_path)

    ssh_cfg = cfg["ssh"]
    paths = cfg["paths"]

    user = getattr(args, "user", None) or ssh_cfg["user"]
    key_arg = getattr(args, "key", None)
    key = expand_path(key_arg or ssh_cfg["key_path"])

    known_hosts = expand_path(paths["known_hosts"])
    jobs_dir = expand_path(paths["jobs_dir"])
    logs_dir = expand_path(paths["logs_dir"])
    results_dir = expand_path(paths["results_dir"])
    raw_dir = expand_path(paths.get("raw_dir", str(results_dir / "raw")))

    return cfg, inventory, user, key, known_hosts, jobs_dir, logs_dir, results_dir, raw_dir


def add_common_run_args(p: argparse.ArgumentParser) -> None:
    target_group = p.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "--targets",
        help="18600,18604,SUCRE,10.155.176.2",
    )
    target_group.add_argument(
        "--all",
        action="store_true",
        help="Todas las sedes.",
    )

    p.add_argument("--confirm-all", action="store_true")
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument("--command", help="Código PowerShell.")
    source.add_argument("--script", type=Path, help="Archivo .ps1 local.")

    p.add_argument("--mode", choices=["structured", "text"], default="structured")
    p.add_argument(
        "--export",
        dest="export_format",
        choices=["auto", "xlsx", "csv", "json", "txt", "none"],
        default="auto",
    )
    p.add_argument("--output", type=Path)
    p.add_argument("--workers", type=int, default=None)
    p.add_argument("--timeout", type=int, default=None)
    p.add_argument(
        "--attempts",
        type=int,
        default=None,
        help="Número máximo TOTAL de intentos SSH por sede. Default: 3.",
    )
    p.add_argument(
        "--retry-delays",
        default=None,
        help='Pausas entre reintentos, en segundos. Ejemplo: "3,5".',
    )
    p.add_argument("--user", default=None)
    p.add_argument("--key", type=Path, default=None)
    p.add_argument(
        "--strict",
        action="store_true",
        help="Exige host key ya conocida; no acepta host keys nuevas.",
    )
    p.add_argument(
        "--background",
        action="store_true",
        help="Ejecuta como job Python desprendido.",
    )
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--_worker-job", help=argparse.SUPPRESS)



# ---------------------------------------------------------------------------
# CANCELACIÓN / CIERRE SEGURO DE CONEXIONES
# ---------------------------------------------------------------------------

ACTIVE_JOB_STATES = {"QUEUED", "RUNNING", "CANCEL_REQUESTED"}


def _run_local_powershell_json(script: str) -> Any:
    """Ejecuta PowerShell LOCAL y devuelve JSON.

    Solo se usa para inspeccionar procesos del PC administrativo.
    """
    ps = command_exists("powershell.exe") or command_exists("powershell")
    if not ps:
        raise RuntimeError("No se encontró powershell.exe para inspeccionar procesos locales.")

    cp = subprocess.run(
        [
            ps,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy", "Bypass",
            "-Command", script,
        ],
        text=True,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        **windows_hidden_kwargs(),
    )

    if cp.returncode != 0:
        raise RuntimeError(cp.stderr.strip() or cp.stdout.strip() or "PowerShell local falló.")

    out = cp.stdout.strip()
    if not out:
        return None

    return json.loads(out)


def get_windows_process_info(pid: int) -> Optional[dict[str, Any]]:
    """Obtiene PID, PPID, nombre y CommandLine de un proceso Windows."""
    if os.name != "nt":
        return None

    script = rf"""
$p = Get-CimInstance Win32_Process -Filter "ProcessId={int(pid)}" -ErrorAction SilentlyContinue
if ($null -eq $p) {{
    exit 0
}}
$p |
    Select-Object ProcessId,ParentProcessId,Name,CommandLine |
    ConvertTo-Json -Compress
"""
    try:
        data = _run_local_powershell_json(script)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def pid_exists(pid: Optional[int]) -> bool:
    if not pid:
        return False

    if os.name == "nt":
        return get_windows_process_info(int(pid)) is not None

    try:
        os.kill(int(pid), 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def verify_job_worker_process(job_id: str, pid: int) -> tuple[bool, str]:
    """Evita matar un PID reutilizado por Windows.

    El proceso debe ser Python y su CommandLine debe contener:
      - gideon_admin
      - --_worker-job
      - el JobId exacto
    """
    if os.name != "nt":
        return True, "Verificación específica de Windows omitida."

    info = get_windows_process_info(pid)
    if not info:
        return False, "El PID ya no existe."

    name = str(info.get("Name") or "").lower()
    cmd = str(info.get("CommandLine") or "")
    cmd_lower = cmd.lower()

    is_python = name in {"python.exe", "pythonw.exe", "py.exe"} or "python" in name
    owns_job = (
        "gideon_admin" in cmd_lower
        and "--_worker-job" in cmd_lower
        and job_id.lower() in cmd_lower
    )

    if not is_python or not owns_job:
        return (
            False,
            f"PID {pid} existe, pero NO corresponde al worker verificado del job {job_id}. "
            "No se terminará por seguridad."
        )

    return True, ""


def terminate_process_tree_windows(pid: int, grace_seconds: int = 3) -> tuple[bool, str]:
    """Termina PID + descendientes.

    1) taskkill /T sin /F.
    2) espera breve.
    3) si sigue vivo, taskkill /T /F.
    """
    if os.name != "nt":
        try:
            os.kill(pid, 15)
            return True, "Proceso terminado."
        except Exception as exc:
            return False, str(exc)

    taskkill = command_exists("taskkill.exe") or command_exists("taskkill")
    if not taskkill:
        return False, "No se encontró taskkill.exe."

    first = subprocess.run(
        [taskkill, "/PID", str(pid), "/T"],
        text=True,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        **windows_hidden_kwargs(),
    )

    deadline = time.time() + max(0, grace_seconds)
    while time.time() < deadline:
        if not pid_exists(pid):
            return True, (first.stdout.strip() or "Árbol de procesos cerrado.")
        time.sleep(0.25)

    forced = subprocess.run(
        [taskkill, "/PID", str(pid), "/T", "/F"],
        text=True,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        **windows_hidden_kwargs(),
    )

    # Dar un instante a Windows para liberar los sockets.
    time.sleep(0.5)

    if not pid_exists(pid):
        return True, (forced.stdout.strip() or first.stdout.strip() or "Árbol de procesos cerrado forzosamente.")

    return False, (
        forced.stderr.strip()
        or first.stderr.strip()
        or f"No se pudo terminar PID {pid}."
    )


def cancel_job(
    store: JobStore,
    job_id: str,
    *,
    reason: str = "Cancelado por el administrador.",
    grace_seconds: int = 3,
) -> tuple[bool, str]:
    """Cancela un job GIDEON verificando antes que el PID le pertenezca."""
    job = store.read(job_id)
    status = str(job.get("Status") or "")
    pid_value = job.get("Pid")

    if status in {"COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED", "CANCELLED"}:
        return True, f"Job {job_id} ya está en estado {status}; no hay proceso activo que cancelar."

    previous = status
    store.update(
        job_id,
        Status="CANCEL_REQUESTED",
        PreviousStatus=previous,
        CancelRequestedAt=now_iso(),
        CancelReason=reason,
    )

    # Un job QUEUED puede todavía no tener PID. Al quedar CANCEL_REQUESTED,
    # el worker v1.4 se negará a iniciar si llega a arrancar.
    if not pid_value:
        store.update(
            job_id,
            Status="CANCELLED",
            CancelledAt=now_iso(),
            FinishedAt=now_iso(),
        )
        return True, f"Job {job_id} cancelado antes de iniciar conexiones SSH."

    try:
        pid = int(pid_value)
    except Exception:
        return False, f"PID inválido registrado en job {job_id}: {pid_value!r}"

    verified, detail = verify_job_worker_process(job_id, pid)

    if not verified:
        # Si el PID ya no existe, el job se puede marcar cancelado sin matar nada.
        if not pid_exists(pid):
            store.update(
                job_id,
                Status="CANCELLED",
                CancelledAt=now_iso(),
                FinishedAt=now_iso(),
            )
            return True, f"Job {job_id}: el worker ya no existe; registro marcado CANCELLED."

        # PID existe pero no es el worker esperado: no tocar.
        store.update(
            job_id,
            Status="CANCEL_REQUESTED",
            Error=detail,
        )
        return False, detail

    terminated, message = terminate_process_tree_windows(
        pid,
        grace_seconds=grace_seconds,
    )

    if terminated:
        store.update(
            job_id,
            Status="CANCELLED",
            CancelledAt=now_iso(),
            FinishedAt=now_iso(),
            Pid=pid,
        )
        return True, f"Job {job_id} cancelado. {message}"

    store.update(
        job_id,
        Status="CANCEL_REQUESTED",
        Error=message,
    )
    return False, f"Job {job_id}: {message}"


def handle_cancel(
    store: JobStore,
    job_id: str,
    grace_seconds: int,
) -> int:
    success, message = cancel_job(
        store,
        job_id,
        grace_seconds=grace_seconds,
    )

    if success:
        ok(message)
        return 0

    warn(message)
    return 2


def handle_shutdown(
    *,
    store: JobStore,
    grace_seconds: int,
) -> int:
    """Cancel only GIDEON jobs whose process trees were registered by GIDEON.

    P8C deliberately removed residual/global process scans and all ssh-agent mutation. A process that is not owned by a registered GIDEON Job is never
    selected or terminated by this command.
    """
    jobs = store.list()
    active_jobs = [
        job for job in jobs
        if str(job.get("Status") or "") in ACTIVE_JOB_STATES
    ]

    print("=== GIDEON SAFE SHUTDOWN ===")
    print(f"Jobs GIDEON activos detectados: {len(active_jobs)}")
    cancelled = 0
    cancel_errors = 0
    for job in active_jobs:
        job_id = str(job.get("JobId") or "")
        if not job_id:
            continue
        success, message = cancel_job(
            store,
            job_id,
            reason="Cancelado por gideon_admin.py shutdown.",
            grace_seconds=grace_seconds,
        )
        if success:
            cancelled += 1
            ok(message)
        else:
            cancel_errors += 1
            warn(message)

    print()
    print(f"Jobs cancelados: {cancelled}/{len(active_jobs)}")
    print("Procesos SSH ajenos/no registrados: NO TOCADOS")
    print("ssh-agent: NO MODIFICADO")
    if cancel_errors:
        return 2
    ok("Shutdown GIDEON completado.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="gideon_admin.py",
        description="GIDEON SSH Python Admin - control plane para servidores de tiendas.",
    )
    p.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    p.add_argument("--sites-file", type=Path, default=DEFAULT_SITES)
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    sub = p.add_subparsers(dest="action", required=True)

    s_sites = sub.add_parser("sites", help="Lista inventario de sedes.")

    s_agent = sub.add_parser("agent", help="Consulta/valida identidad SSH GIDEON sin modificar ssh-agent.")
    s_agent.add_argument("operation", choices=["status", "validate"])
    s_agent.add_argument("--key", type=Path, default=None)

    s_test = sub.add_parser("test", help="Prueba TCP/22 sin autenticarse.")
    tg = s_test.add_mutually_exclusive_group(required=True)
    tg.add_argument("--targets")
    tg.add_argument("--all", action="store_true")
    s_test.add_argument("--confirm-all", action="store_true")
    s_test.add_argument("--port", type=int, default=22)
    s_test.add_argument("--timeout", type=int, default=3)
    s_test.add_argument("--workers", type=int, default=10)
    s_test.add_argument("--export", choices=["none", "csv", "json", "xlsx"], default="none")
    s_test.add_argument("--output", type=Path)

    s_run = sub.add_parser("run", help="Ejecuta PowerShell remoto por SSH.")
    add_common_run_args(s_run)

    s_jobs = sub.add_parser("jobs", help="Lista jobs en background.")
    s_jobs.add_argument("--limit", type=int, default=20)

    s_job = sub.add_parser("job", help="Muestra detalle de un job.")
    s_job.add_argument("job_id")
    s_job.add_argument("--tail", type=int, default=40)

    s_cancel = sub.add_parser(
        "cancel",
        help="Cancela de forma segura un job GIDEON y su árbol SSH/SCP.",
    )
    s_cancel.add_argument("job_id")
    s_cancel.add_argument(
        "--grace-seconds",
        type=int,
        default=3,
        help="Espera antes de forzar el cierre del árbol de procesos. Default: 3.",
    )

    s_shutdown = sub.add_parser(
        "shutdown",
        help="Cancela todos los jobs GIDEON y cierra conexiones SSH/SCP GIDEON residuales.",
    )
    s_shutdown.add_argument(
        "--grace-seconds",
        type=int,
        default=3,
        help="Espera antes de forzar cada árbol de procesos. Default: 3.",
    )

    s_fanout = sub.add_parser(
        "fanout",
        add_help=False,
        help="Fan-Out: dispatch remoto desacoplado, monitor, collect y resume.",
    )
    s_fanout.add_argument(
        "fanout_args",
        nargs=argparse.REMAINDER,
        help="Argumentos para gideon_fanout.py.",
    )

    sub.add_parser(
        "backup-scan",
        add_help=False,
        help="Backup Finder FAN-OUT (recomendado para todas las sedes).",
    )
    sub.add_parser("vpn-status", add_help=False, help="Mide Fortinet VPN y recomienda concurrencia segura.")
    sub.add_parser(
        "gui",
        add_help=False,
        help="Abre GIDEON SSH Admin Desktop y libera la consola.",
    )
    sub.add_parser(
        "selfcheck",
        add_help=False,
        help="Autodiagnóstico local de Python/OpenSSH/configuración v6.2.0.",
    )

    return p


def handle_sites(inventory: Inventory) -> int:
    print(f"{'CODE':<8} {'SEDE':<24} IP")
    print("-" * 52)
    for s in inventory.sites:
        print(f"{s.code:<8} {s.name:<24} {s.ip}")
    return 0


def handle_agent(agent: SSHAgent, operation: str) -> int:
    if operation == "status":
        print(json.dumps(agent.status(), indent=2, ensure_ascii=False))
    elif operation == "validate":
        agent.validate()
    return 0


def handle_test(
    inventory: Inventory,
    args: argparse.Namespace,
    results_dir: Path,
) -> int:
    requested = ["ALL"] if args.all else parse_targets_text(args.targets)
    sites = inventory.resolve(requested, allow_all=args.confirm_all)

    rows: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(tcp_test, site, args.port, args.timeout): site
            for site in sites
        }
        for future in as_completed(futures):
            row = future.result()
            rows.append(row)
            msg = f"{row['SiteCode']}_{row['SiteName']} {row['ServerIP']}:{row['Port']}"
            if row["Success"]:
                ok(msg)
            else:
                warn(f"{msg} - {row['Error']}")

    order = {s.ip: i for i, s in enumerate(sites)}
    rows.sort(key=lambda r: order.get(r["ServerIP"], 999))

    if args.export != "none":
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        base = args.output or (results_dir / f"GIDEON-TCP-Test-{stamp}")
        ensure_dir(base.parent)

        if args.export == "csv":
            export_csv(base.with_suffix(".csv"), rows)
            ok(f"Exportado: {base.with_suffix('.csv')}")
        elif args.export == "json":
            path = base.with_suffix(".json")
            path.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
            ok(f"Exportado: {path}")
        elif args.export == "xlsx":
            export_xlsx(base.with_suffix(".xlsx"), rows, rows)
            ok(f"Exportado: {base.with_suffix('.xlsx')}")

    return 0 if all(r["Success"] for r in rows) else 2


def load_user_code(args: argparse.Namespace) -> str:
    if args.command is not None:
        return args.command

    script_path = args.script.resolve()
    if not script_path.exists():
        raise FileNotFoundError(f"No existe script: {script_path}")
    return script_path.read_text(encoding="utf-8-sig")


def handle_run(
    cfg: dict[str, Any],
    inventory: Inventory,
    args: argparse.Namespace,
    user: str,
    key: Path,
    known_hosts: Path,
    results_dir: Path,
    raw_dir: Path,
    store: JobStore,
) -> int:
    if args.all and not args.confirm_all:
        raise ValueError("--all requiere --confirm-all.")

    requested = ["ALL"] if args.all else parse_targets_text(args.targets)
    sites = inventory.resolve(requested, allow_all=args.confirm_all)
    code = load_user_code(args)

    if args.dry_run:
        print("TARGETS:")
        for s in sites:
            print(f"  {s.label} {s.ip}")
        print("\nPOWER SHELL:")
        print(code)
        return 0

    agent = SSHAgent(key)

    # Background: el proceso padre carga la clave y desprende un worker.
    if args.background and not args._worker_job:
        spawn_background(args, agent, store, total_count=len(sites))
        return 0

    # Worker o foreground: debe existir clave cargada.
    agent.load()

    if args._worker_job:
        job = store.read(args._worker_job)

        # Si fue cancelado entre QUEUED y el inicio real del worker,
        # no se inicia ninguna conexión SSH.
        if job.get("Status") in {"CANCEL_REQUESTED", "CANCELLED"}:
            warn(f"Job {args._worker_job} cancelado antes de iniciar.")
            return 130

        job["Status"] = "RUNNING"
        job["StartedAt"] = job.get("StartedAt") or now_iso()
        job["Pid"] = os.getpid()
        job["LastStage"] = "WORKER_STARTED"
        job["LastStageSite"] = None
        job["LastStageAt"] = now_iso()
        job["TotalCount"] = len(sites)
        job["CompletedCount"] = int(job.get("CompletedCount", 0))
        job["ProgressPct"] = round((job["CompletedCount"] / len(sites)) * 100, 1) if sites else 100.0
        store.write(args._worker_job, job)

    strict_value = "yes" if args.strict else cfg["ssh"].get("strict_host_key_checking", "accept-new")
    active_job_id = (
        args._worker_job
        if args._worker_job
        else dt.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
    )

    job_raw_dir = ensure_dir(raw_dir / active_job_id)

    executor = RemoteExecutor(
        user=user,
        key_path=key,
        known_hosts=known_hosts,
        port=int(cfg["ssh"].get("port", 22)),
        timeout=args.timeout,
        strict_host_key_checking=strict_value,
        max_attempts=args.attempts,
        retry_delays=args.retry_delays,
        raw_dir=job_raw_dir,
        remote_results_root=cfg["ssh"].get(
            "remote_results_root",
            r"C:\ProgramData\GIDEONSSH\results"
        ),
        delete_remote_after_download=bool(
            cfg["ssh"].get("delete_remote_result_after_download", True)
        ),
    )

    if args._worker_job:
        try:
            store.update(args._worker_job, RawDir=str(job_raw_dir))
        except Exception as exc:
            warn(f"JOB_PROGRESS_INIT_WARNING {args._worker_job}: {exc}")

    def job_progress(event, site, current, total, result):
        if not args._worker_job:
            return

        try:
            if event == "stage" and site is not None and isinstance(result, dict):
                store.update_site_stage(
                    args._worker_job,
                    site.label,
                    str(result.get("Stage") or "UNKNOWN"),
                    str(result.get("Detail") or ""),
                    int(result.get("Attempt") or 0),
                    str(result.get("At") or now_iso()),
                )
                return

            if event == "site_complete" and result is not None:
                job = store.read(args._worker_job)

                # Un cancel externo tiene prioridad sobre el avance del worker.
                if job.get("Status") in {"CANCEL_REQUESTED", "CANCELLED"}:
                    return

                completed = int(job.get("CompletedCount", 0)) + 1
                successes = int(job.get("SuccessCount", 0)) + (1 if result.success else 0)
                errors = int(job.get("ErrorCount", 0)) + (0 if result.success else 1)
                retries = int(job.get("RetryCount", 0)) + max(0, result.attempts - 1)
                breakdown = dict(job.get("FailureBreakdown") or {})

                if not result.success:
                    breakdown[result.failure_type] = int(breakdown.get(result.failure_type, 0)) + 1

                store.update(
                    args._worker_job,
                    CompletedCount=completed,
                    SuccessCount=successes,
                    ErrorCount=errors,
                    RetryCount=retries,
                    ProgressPct=round((completed / total) * 100, 1) if total else 100.0,
                    LastCompleted=(site.label if site else None),
                    LastFailureType=(None if result.success else result.failure_type),
                    FailureBreakdown=breakdown,
                )
        except Exception as progress_exc:
            warn(f"No se pudo actualizar progreso del job: {progress_exc}")

    try:
        results = executor.run_many(
            sites=sites,
            user_code=code,
            mode=args.mode,
            workers=max(1, args.workers),
            job_id=active_job_id,
            progress_callback=job_progress,
        )

        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        base = args.output or (results_dir / f"GIDEON-SSH-Results-{stamp}")

        if args._worker_job:
            store.update(
                args._worker_job,
                LastStage="LOCAL_FORMATTING",
                LastStageSite="LOCAL_PC",
                LastStageAt=now_iso(),
            )

        log("[LOCAL_FORMATTING] Todos los resultados disponibles se procesarán LOCALMENTE en esta PC.")
        created = export_results(
            results=results,
            mode=args.mode,
            export_format=args.export_format,
            output=base,
        )
        for path in created:
            ok(f"Resultado: {path}")

        success_count = sum(1 for r in results if r.success)
        log(f"Resumen: {success_count}/{len(results)} exitosos.")

        if args._worker_job:
            job = store.read(args._worker_job)

            if job.get("Status") in {"CANCEL_REQUESTED", "CANCELLED"}:
                # No convertir un cancel solicitado en COMPLETED por una carrera
                # de milisegundos al final del job.
                job["Status"] = "CANCELLED"
                job["CancelledAt"] = job.get("CancelledAt") or now_iso()
                job["FinishedAt"] = job.get("FinishedAt") or now_iso()
            else:
                job["Status"] = "COMPLETED" if success_count == len(results) else "COMPLETED_WITH_ERRORS"
                job["FinishedAt"] = now_iso()

            job["SuccessCount"] = success_count
            job["ErrorCount"] = len(results) - success_count
            job["TotalCount"] = len(results)
            job["CompletedCount"] = len(results)
            job["ProgressPct"] = 100.0
            job["ResultFiles"] = [str(x) for x in created]
            job["FailureBreakdown"] = {
                failure_type: sum(1 for r in results if (not r.success and r.failure_type == failure_type))
                for failure_type in sorted({r.failure_type for r in results if not r.success})
            }
            job["LastStage"] = "FINISHED"
            job["LastStageSite"] = "LOCAL_PC"
            job["LastStageAt"] = now_iso()
            store.write(args._worker_job, job)

        return 0 if success_count == len(results) else 2

    except Exception as exc:
        if args._worker_job:
            job = store.read(args._worker_job)
            if job.get("Status") in {"CANCEL_REQUESTED", "CANCELLED"}:
                job["Status"] = "CANCELLED"
                job["CancelledAt"] = job.get("CancelledAt") or now_iso()
                job["FinishedAt"] = job.get("FinishedAt") or now_iso()
            else:
                job["Status"] = "FAILED"
                job["FinishedAt"] = now_iso()
                job["Error"] = str(exc)
            store.write(args._worker_job, job)
        raise


def handle_jobs(store: JobStore, limit: int) -> int:
    jobs = store.list()[:limit]
    if not jobs:
        print("No hay jobs.")
        return 0

    print(f"{'JOB ID':<24} {'STATUS':<21} {'PROGRESS':<16} {'LAST STAGE':<22} {'PID':<8} CREATED")
    print("-" * 135)
    for job in jobs:
        done = int(job.get("CompletedCount", 0) or 0)
        total = int(job.get("TotalCount", 0) or 0)
        pct = float(job.get("ProgressPct", 0.0) or 0.0)
        progress = f"{done}/{total} ({pct:.1f}%)" if total else "-"
        stage = str(job.get("LastStage") or "-")
        print(
            f"{str(job.get('JobId','')):<24} "
            f"{str(job.get('Status','')):<21} "
            f"{progress:<16} "
            f"{stage:<22} "
            f"{str(job.get('Pid','')):<8} "
            f"{str(job.get('CreatedAt',''))}"
        )
    return 0


def handle_job(store: JobStore, job_id: str, tail: int) -> int:
    job = store.read(job_id)

    done = int(job.get("CompletedCount", 0) or 0)
    total = int(job.get("TotalCount", 0) or 0)
    pct = float(job.get("ProgressPct", 0.0) or 0.0)

    print("=== JOB STATUS ===")
    print(f"JobId       : {job.get('JobId')}")
    print(f"Status      : {job.get('Status')}")
    print(f"Progress    : {done}/{total} ({pct:.1f}%)" if total else "Progress    : -")
    print(f"Success     : {job.get('SuccessCount', 0)}")
    print(f"Errors      : {job.get('ErrorCount', 0)}")
    print(f"Retries     : {job.get('RetryCount', 0)}")
    print(f"Last        : {job.get('LastCompleted')}")
    print(f"LastFailure : {job.get('LastFailureType')}")
    print(f"LastStage   : {job.get('LastStage')}")
    print(f"StageSite   : {job.get('LastStageSite')}")
    print(f"StageAt     : {job.get('LastStageAt')}")
    print(f"PID         : {job.get('Pid')}")
    if job.get("CancelRequestedAt") or job.get("CancelledAt"):
        print(f"CancelReq   : {job.get('CancelRequestedAt')}")
        print(f"Cancelled   : {job.get('CancelledAt')}")
        print(f"CancelReason: {job.get('CancelReason')}")
    print()

    stages = job.get("SiteStages") or {}
    if stages:
        print("\n--- SITE STAGES ---")
        for site_label in sorted(stages):
            item = stages[site_label] or {}
            print(
                f"{site_label:<28} "
                f"{str(item.get('Stage','-')):<22} "
                f"attempt={item.get('Attempt','-')} "
                f"{item.get('Detail','')}"
            )

    print("\n--- JOB JSON ---")
    print(json.dumps(job, indent=2, ensure_ascii=False))

    log_path = Path(job.get("Log", ""))
    if log_path.exists() and tail > 0:
        print("\n--- LOG ---")
        lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        for line in lines[-tail:]:
            print(line)
    return 0



def launch_gui_detached() -> int:
    """Abre GIDEON SSH Admin Desktop y devuelve inmediatamente la consola."""
    gui_script = SCRIPT_DIR / "gideon_gui.py"

    if not gui_script.exists():
        raise FileNotFoundError(f"No existe GUI: {gui_script}")

    executable = Path(sys.executable)

    if os.name == "nt":
        pythonw = executable.with_name("pythonw.exe")
        if not pythonw.exists():
            found = command_exists("pythonw.exe")
            pythonw = Path(found) if found else executable

        creationflags = (
            getattr(subprocess, "DETACHED_PROCESS", 0)
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        )

        subprocess.Popen(
            [str(pythonw), str(gui_script)],
            cwd=str(SCRIPT_DIR),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creationflags,
            close_fds=False,
        )
    else:
        subprocess.Popen(
            [str(executable), str(gui_script)],
            cwd=str(SCRIPT_DIR),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

    print("GIDEON SSH Admin Desktop iniciado. La consola queda libre.")
    return 0


def main() -> int:
    # Sin argumentos: abrir interfaz gráfica y liberar la consola.
    if len(sys.argv) == 1:
        return launch_gui_detached()

    # GUI explícita.
    if len(sys.argv) >= 2 and sys.argv[1].lower() == "gui":
        return launch_gui_detached()

    # FAN-OUT tiene su propio parser. Se delega ANTES de argparse principal
    # para permitir comandos como:
    # Optional Agent HTTPS/PULL method:
    #   py gideon_admin.py agent-mode health
    #   py gideon_admin.py agent-mode agents
    #   py gideon_admin.py agent-mode run --targets 18600 --script scripts\audit_server.ps1
    if len(sys.argv) >= 2 and sys.argv[1].lower() == "agent-mode":
        import gideon_agent_orchestrator
        return gideon_agent_orchestrator.main_from_args(sys.argv[2:])

    #   py gideon_admin.py fanout --help
    #   py gideon_admin.py fanout run --all ...
    if len(sys.argv) >= 2 and sys.argv[1].lower() == "fanout":
        import gideon_fanout
        return gideon_fanout.main(sys.argv[2:])

    if len(sys.argv) >= 2 and sys.argv[1].lower() == "vpn-status":
        import gideon_fanout
        return gideon_fanout.main(["vpn-status", *sys.argv[2:]])

    if len(sys.argv) >= 2 and sys.argv[1].lower() == "selfcheck":
        import gideon_selfcheck
        return gideon_selfcheck.main(sys.argv[2:])

    if len(sys.argv) >= 2 and sys.argv[1].lower() == "transfer":
        import gideon_transfer
        return gideon_transfer.main(sys.argv[2:])

    if len(sys.argv) >= 2 and sys.argv[1].lower() == "backup-scan":
        import gideon_fanout
        forwarded = ["run"]
        remaining = sys.argv[2:]
        if not any(arg == "--script" or arg.startswith("--script=") for arg in remaining):
            forwarded.extend(["--script", str(SCRIPT_DIR / "scripts" / "find_backup_folders.ps1")])
        if not any(arg == "--export" or arg.startswith("--export=") for arg in remaining):
            forwarded.extend(["--export", "xlsx"])
        forwarded.extend(remaining)
        return gideon_fanout.main(forwarded)

    parser = build_parser()
    args = parser.parse_args()

    config_path = expand_path(args.config)
    sites_path = expand_path(args.sites_file)
    cfg, inventory, user, key, known_hosts, jobs_dir, logs_dir, results_dir, raw_dir = config_objects(
        config_path, sites_path, args
    )
    store = JobStore(jobs_dir, logs_dir)

    if args.action == "sites":
        return handle_sites(inventory)

    if args.action == "agent":
        return handle_agent(SSHAgent(key), args.operation)

    if args.action == "test":
        return handle_test(inventory, args, results_dir)

    if args.action == "run":
        # Defaults desde config si el usuario no cambió los valores de CLI.
        if args.user is None:
            args.user = user
        if args.key is None:
            args.key = key

        # Perfil conservador automático para el buscador de backups.
        is_backup_scan = bool(
            args.script
            and args.script.name.lower() == "find_backup_folders.ps1"
        )

        if args.workers is None:
            if is_backup_scan:
                args.workers = int(cfg["ssh"].get("backup_scan_workers", 2))
            else:
                args.workers = int(cfg["ssh"].get("max_workers", 5))

        if args.timeout is None:
            args.timeout = int(cfg["ssh"].get("connect_timeout_seconds", 30))

        if args.attempts is None:
            args.attempts = int(cfg["ssh"].get("retry_attempts", 3))

        if args.attempts < 1 or args.attempts > 10:
            raise ValueError("--attempts debe estar entre 1 y 10.")

        if args.retry_delays is None:
            args.retry_delays = parse_retry_delays(
                cfg["ssh"].get("retry_delays_seconds", [3, 5])
            )
        else:
            args.retry_delays = parse_retry_delays(args.retry_delays)

        if is_backup_scan:
            log(
                f"Perfil de bajo impacto detectado para find_backup_folders.ps1: "
                f"workers={args.workers}, timeout={args.timeout}s."
            )

        return handle_run(
            cfg, inventory, args, args.user, Path(args.key), known_hosts,
            results_dir, raw_dir, store
        )

    if args.action == "jobs":
        return handle_jobs(store, args.limit)

    if args.action == "job":
        return handle_job(store, args.job_id, args.tail)

    if args.action == "cancel":
        if args.grace_seconds < 0 or args.grace_seconds > 30:
            raise ValueError("--grace-seconds debe estar entre 0 y 30.")
        return handle_cancel(store, args.job_id, args.grace_seconds)

    if args.action == "shutdown":
        if args.grace_seconds < 0 or args.grace_seconds > 30:
            raise ValueError("--grace-seconds debe estar entre 0 y 30.")

        return handle_shutdown(
            store=store,
            grace_seconds=args.grace_seconds,
        )

    if args.action == "fanout":
        import gideon_fanout
        return gideon_fanout.main(args.fanout_args)

    parser.error("Acción no soportada.")
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nCancelado por usuario.", file=sys.stderr)
        raise SystemExit(130)
    except Exception as exc:
        fail(str(exc))
        raise SystemExit(1)
