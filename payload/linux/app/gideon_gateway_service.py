from __future__ import annotations

"""Gateway application services.

The module intentionally contains no Qt code.  UI pages depend on these small
services instead of invoking PowerShell/network/TLS operations directly.  This
keeps navigation fast and separates configuration, runtime and diagnostics
responsibilities (SRP/DIP).
"""

from dataclasses import dataclass, field
import json
import logging
import os
from pathlib import Path
import socket
import shutil
import ssl
import subprocess
import sys
import threading
import time
from typing import Any, Protocol
from urllib.parse import urlparse

from gideon_common.tls import gideon_private_ca_context

from gideon_agent_http import AgentHttpClient
from gideon_version import GATEWAY_VERSION
from gideon_dependency_manager import SystemDependencyManager
from gideon_gateway_bootstrap import (
    GATEWAY_CONFIG_PATH,
    TLS_DIR,
    NETWORK_MODE_INTERNAL,
    NETWORK_MODE_PRODUCTION,
    ensure_gateway_configuration,
    gateway_network_snapshot,
    gateway_status,
    is_public_ipv4,
    local_ipv4_addresses,
)
from gideon_infrastructure.subprocess_utils import popen_hidden, run_hidden
from gideon_gateway_tls import GatewayTLSLifecycle, probe_tls_endpoint, probe_tls_peer


_LOG = logging.getLogger(__name__)

@dataclass(frozen=True)
class GatewayCheck:
    name: str
    ok: bool
    detail: str
    # Non-blocking checks are diagnostic context only.  They must never turn a
    # healthy HTTPS/API endpoint into a false negative (for example when the
    # Gateway is supervised by another process/service or loopback is filtered).
    blocking: bool = True


@dataclass(frozen=True)
class GatewayResult:
    ok: bool
    title: str
    message: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    checks: tuple[GatewayCheck, ...] = ()


class GatewayRepository(Protocol):
    def read_gateway(self) -> dict[str, Any]: ...
    def write_gateway(self, value: dict[str, Any]) -> None: ...


class JsonGatewayRepository:
    """Atomic persistence only; it never probes the network or starts processes."""

    def __init__(self, path: Path = GATEWAY_CONFIG_PATH) -> None:
        self.path = Path(path)

    def read_gateway(self) -> dict[str, Any]:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8-sig"))
            return value if isinstance(value, dict) else {}
        except Exception:
            return {}

    def write_gateway(self, value: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, self.path)


class GatewayNetworkService:
    def __init__(self, repository: GatewayRepository | None = None) -> None:
        self.repository = repository or JsonGatewayRepository()

    def quick_snapshot(self) -> dict[str, Any]:
        """Persisted state only: guaranteed not to launch PowerShell."""
        return gateway_network_snapshot(self.repository.read_gateway(), include_local_ipv4s=False)

    def detect_local_ipv4s(self) -> list[str]:
        return local_ipv4_addresses(force=True)

    def apply(self, *, mode: str, host: str, port: int, force_tls: bool = False) -> GatewayResult:
        host = str(host or "").strip().strip("[]")
        if mode not in {NETWORK_MODE_INTERNAL, NETWORK_MODE_PRODUCTION}:
            return GatewayResult(False, "Modo de Gateway inválido", f"Modo no soportado: {mode}")
        if not host:
            return GatewayResult(False, "Falta dirección del Gateway", "Seleccione una IPv4 local para TEST o indique la IPv4 pública para producción.")
        if mode == NETWORK_MODE_PRODUCTION and not is_public_ipv4(host):
            return GatewayResult(
                False,
                "IPv4 pública inválida",
                "Producción acepta exclusivamente una IPv4 pública real. Para LAN utilice Test red interna.",
            )
        if not 1 <= int(port) <= 65535:
            return GatewayResult(False, "Puerto inválido", "El puerto HTTPS debe estar entre 1 y 65535.")

        gw = self.repository.read_gateway()
        before = gateway_network_snapshot(gw, include_local_ipv4s=False)
        previous_host = str(before.get("active_host") or "")
        previous_mode = str(before.get("mode") or NETWORK_MODE_INTERNAL)
        previous_port = int(gw.get("listen_port") or 8443)
        gw.update({
            "network_mode": mode,
            "listen_host": "0.0.0.0",
            "listen_port": int(port),
            "hot_reload_enabled": True,
            "public_url": "",
            "advertised_endpoint": "",
        })
        if mode == NETWORK_MODE_INTERNAL:
            gw["test_host"] = host
        else:
            gw["production_host"] = host
        self.repository.write_gateway(gw)

        tls_requested = bool(force_tls or previous_host != host)
        info = ensure_gateway_configuration(force_tls=tls_requested)
        # The TLS lifecycle may renew an invalid/expiring leaf even when the host
        # itself did not change.  A running TLS listener cannot hot-reload that
        # certificate, so any leaf reissue requires a listener restart.
        tls_changed = bool(tls_requested or info.get("cert_reissued"))
        listener_restart = bool(previous_port != int(port) or tls_changed or previous_mode != mode)
        return GatewayResult(
            True,
            "Configuración del Gateway aplicada",
            "Configuración persistida de forma atómica.",
            data={**info, "listener_restart": listener_restart, "tls_changed": tls_changed},
        )


class GatewayRuntimeService:
    """Owns only the local Gateway process lifecycle."""

    def __init__(self, app_root: Path) -> None:
        self.app_root = Path(app_root).resolve()
        self.log_path = self.app_root / "logs" / "gateway-runtime.log"
        self._process: subprocess.Popen[str] | None = None
        self._lock = threading.RLock()

    @property
    def process(self) -> subprocess.Popen[str] | None:
        return self._process

    def is_running(self) -> bool:
        with self._lock:
            return self._process is not None and self._process.poll() is None

    def restart(self) -> GatewayResult:
        """Restart only the Gateway subprocess managed by this facade."""
        stopped = self.stop()
        if not stopped.ok:
            return stopped
        return self.start()

    @staticmethod
    def _windows_listener_processes(port: int) -> list[dict[str, Any]]:
        if os.name != "nt":
            return []
        ps = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        script = (
            "$ErrorActionPreference='SilentlyContinue';"
            f"$rows=@(Get-NetTCPConnection -State Listen -LocalPort {int(port)} | ForEach-Object {{"
            "$ownerPid=[int]$_.OwningProcess;$p=Get-CimInstance Win32_Process -Filter ('ProcessId='+$ownerPid);"
            "[pscustomobject]@{Pid=$ownerPid;CommandLine=[string]$p.CommandLine;ExecutablePath=[string]$p.ExecutablePath;LocalAddress=[string]$_.LocalAddress}"
            "});$rows|ConvertTo-Json -Compress"
        )
        try:
            cp = run_hidden(
                [str(ps), "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script],
                check=False, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10,
            )
            raw = (cp.stdout or "").strip()
            if cp.returncode != 0 or not raw:
                return []
            value = json.loads(raw)
            rows = value if isinstance(value, list) else [value]
            return [row for row in rows if isinstance(row, dict)]
        except Exception:
            return []

    @staticmethod
    def _linux_listener_processes(port: int) -> list[dict[str, Any]]:
        if os.name == "nt":
            return []
        ss = shutil.which("ss")
        if not ss:
            return []
        try:
            cp = run_hidden([ss, "-ltnp", f"sport = :{int(port)}"], check=False, capture_output=True, text=True, timeout=5)
            rows: list[dict[str, Any]] = []
            import re
            for line in (cp.stdout or "").splitlines():
                for match in re.finditer(r"pid=(\d+)", line):
                    pid = int(match.group(1))
                    cmd = ""
                    try:
                        cmd = (Path("/proc") / str(pid) / "cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", errors="replace")
                    except Exception as exc:
                        _LOG.debug("No se pudo leer cmdline de PID %s: %s", pid, exc)
                    rows.append({"Pid": pid, "CommandLine": cmd, "ExecutablePath": "", "LocalAddress": ""})
            return rows
        except Exception:
            return []

    def _listener_processes(self, port: int) -> list[dict[str, Any]]:
        return self._windows_listener_processes(port) if os.name == "nt" else self._linux_listener_processes(port)

    @staticmethod
    def _public_gateway_health(base_url: str, ca_file: str) -> dict[str, Any]:
        if not base_url or not ca_file:
            return {}
        try:
            client = AgentHttpClient(
                base_url, verify_tls=True, ca_file=ca_file, require_https=True, timeout=2.0
            )
            payload = client.json("GET", "/health", timeout=2.0)
            return payload if isinstance(payload, dict) else {}
        except Exception as exc:
            _LOG.debug("No se pudo consultar /health del Gateway existente: %s", exc)
            return {}

    def _reconcile_existing_listener(self, info: dict[str, Any]) -> GatewayResult | None:
        """Adopt a healthy Gateway or replace only a stale GIDEON Gateway listener.

        A listener owned by an unrelated process is never terminated.  This keeps
        process lifecycle safe while fixing the common upgrade case where a
        Gateway from an older GIDEON version is still serving an obsolete TLS leaf/CA.
        """
        base_url = str(info.get("advertised_endpoint") or info.get("public_url") or "").strip().rstrip("/")
        ca_file = str(info.get("ca_file") or "").strip()
        port = int(info.get("port") or 8443)
        health: dict[str, Any] = {}
        live = None
        if base_url and ca_file:
            live = probe_tls_endpoint(base_url, ca_file=ca_file, timeout=0.8)
            if live.ok:
                health = self._public_gateway_health(base_url, ca_file)
                live_version = str(health.get("Version") or "").strip()
                schema_ready = bool(health.get("SchemaReady", True))
                # Do not adopt an older GIDEON Gateway merely because TLS is healthy.
                # This was the root cause of v6.1.2 continuing to serve legacy
                # SQLite code after the desktop console itself had been upgraded.
                capabilities = health.get("Capabilities") if isinstance(health.get("Capabilities"), dict) else {}
                approval_ready = bool(capabilities.get("ReleaseApproval"))
                if live_version == GATEWAY_VERSION and schema_ready and approval_ready:
                    return GatewayResult(
                        True,
                        "Gateway ya ejecutándose",
                        f"Endpoint HTTPS activo · Gateway {live_version} · esquema listo · API releases lista.",
                        data={**info, "external_endpoint": True, "tls_probe": live.detail, "gateway_health": health},
                    )

        listeners = self._listener_processes(port)
        if not listeners:
            return None
        gideon_rows: list[dict[str, Any]] = []
        foreign_rows: list[dict[str, Any]] = []
        for row in listeners:
            cmd = (str(row.get("CommandLine") or "") + " " + str(row.get("ExecutablePath") or "")).casefold()
            if "gideon_agent_gateway.py" in cmd:
                gideon_rows.append(row)
            else:
                foreign_rows.append(row)
        if foreign_rows:
            detail = ", ".join(f"PID {row.get('Pid')}" for row in foreign_rows)
            return GatewayResult(
                False,
                "Puerto del Gateway ocupado",
                f"TCP {port} está ocupado por un proceso que no es GIDEON ({detail}). No se terminará automáticamente.",
                data=info,
            )
        if not gideon_rows:
            return None

        # A GIDEON listener exists but either failed TLS verification, reports an
        # older Gateway build, or reports a non-ready DB schema.  It is safe to
        # replace that stale GIDEON process; unrelated listeners are never killed.
        for row in gideon_rows:
            try:
                pid = int(row.get("Pid") or 0)
            except Exception:
                pid = 0
            if pid <= 0 or pid == os.getpid():
                continue
            if os.name == "nt":
                run_hidden(["taskkill.exe", "/PID", str(pid), "/T", "/F"], check=False, capture_output=True, timeout=10)
            else:
                try:
                    os.kill(pid, 15)
                except OSError:
                    pass
        time.sleep(0.25)
        return None

    def start(self) -> GatewayResult:
        with self._lock:
            if self.is_running():
                return GatewayResult(True, "Gateway ejecutándose", "El proceso ya estaba activo.", data={"pid": self._process.pid if self._process else None})
            ready, deps = SystemDependencyManager(self.app_root).gateway_ready()
            if not ready:
                missing = [d for d in deps if not d.installed]
                return GatewayResult(False, "Faltan requisitos del Gateway", "\n".join(f"{d.name}: {d.detail or d.install_hint}" for d in missing))
            info = ensure_gateway_configuration()
            cfg = JsonGatewayRepository().read_gateway()
            reconciled = self._reconcile_existing_listener(info)
            if reconciled is not None:
                return reconciled
            env = os.environ.copy()
            env["GIDEON_AGENT_ADMIN_TOKEN"] = str(cfg.get("admin_api_key") or "")
            env["GIDEON_AGENT_ENROLL_SECRET"] = str(cfg.get("enrollment_secret") or "")
            try:
                self.log_path.parent.mkdir(parents=True, exist_ok=True)
                with self.log_path.open("a", encoding="utf-8") as log_stream:
                    log_stream.write(f"\n--- Gateway start {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")
                    log_stream.flush()
                    proc = popen_hidden(
                        [sys.executable, str(self.app_root / "gideon_agent_gateway.py"), "--config", str(GATEWAY_CONFIG_PATH)],
                        cwd=str(self.app_root), env=env,
                        stdout=log_stream, stderr=subprocess.STDOUT, text=True,
                    )
                self._process = proc
            except Exception as exc:
                return GatewayResult(False, "No se pudo iniciar el Gateway", f"{type(exc).__name__}: {exc}\nLog: {self.log_path}")

        # The wait is performed by the caller worker, never by the UI thread.
        # In TEST/LAN mode the selected LAN address is the primary readiness
        # target.  127.0.0.1 is only a fallback because some Windows/network
        # policies may make loopback behave differently from the bound LAN NIC.
        port = int(info.get("port") or 8443)
        snapshot = gateway_network_snapshot(cfg, include_local_ipv4s=False)
        mode = str(snapshot.get("mode") or NETWORK_MODE_INTERNAL)
        active_host = str(snapshot.get("active_host") or "").strip()
        probe_hosts: list[str] = []
        if mode == NETWORK_MODE_INTERNAL and active_host:
            probe_hosts.append(active_host)
        probe_hosts.append("127.0.0.1")
        probe_hosts = list(dict.fromkeys(probe_hosts))

        deadline = time.monotonic() + 2.5
        last_errors: list[str] = []
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                return GatewayResult(False, "Gateway se detuvo durante el inicio", f"El proceso terminó con código {proc.returncode}. Revise: {self.log_path}")
            last_errors.clear()
            for probe_host in probe_hosts:
                try:
                    with socket.create_connection((probe_host, port), timeout=0.20):
                        pass
                    probe_url = f"https://{probe_host}:{port}"
                    verified = probe_tls_endpoint(
                        probe_url,
                        ca_file=str(info.get("ca_file") or ""),
                        timeout=0.40,
                    )
                    expected_fp = str(info.get("cert_fingerprint") or "").strip().upper()
                    if verified.ok and (not expected_fp or verified.peer_fingerprint.upper() == expected_fp):
                        return GatewayResult(
                            True,
                            "Gateway iniciado",
                            f"HTTPS/TLS verificado en {probe_host}:{port}.",
                            data={"pid": proc.pid, "readiness_host": probe_host, "tls_probe": verified.detail, **info},
                        )
                    raw = probe_tls_peer(probe_url, timeout=0.40)
                    detail = verified.detail
                    if raw.ok and expected_fp and raw.peer_fingerprint.upper() != expected_fp:
                        detail += (
                            f" · certificado servido {raw.peer_fingerprint[:16]}… "
                            f"!= esperado {expected_fp[:16]}…"
                        )
                    last_errors.append(f"{probe_host}:{port} -> TLS: {detail}")
                except OSError as exc:
                    last_errors.append(f"{probe_host}:{port} -> {type(exc).__name__}: {exc}")
            time.sleep(0.10)
        return GatewayResult(
            False,
            "Gateway no abrió el puerto",
            "El proceso sigue activo, pero ninguna ruta local de readiness respondió dentro del tiempo esperado. "
            + " | ".join(last_errors[-4:])
            + f". Revise: {self.log_path}",
            data={"pid": proc.pid, **info},
        )

    def stop(self) -> GatewayResult:
        with self._lock:
            proc = self._process
            if proc is None or proc.poll() is not None:
                self._process = None
                return GatewayResult(True, "Gateway detenido", "No había un proceso local activo administrado por esta consola.")
            try:
                proc.terminate()
                proc.wait(timeout=4)
            except Exception:
                try:
                    proc.kill()
                    proc.wait(timeout=2)
                except Exception as exc:
                    _LOG.warning("No se pudo finalizar el proceso Gateway: %s", exc)
            self._process = None
            return GatewayResult(True, "Gateway detenido", "El subproceso local fue detenido.")


class GatewayFirewallService:
    """Windows LAN-test firewall policy; diagnosis and mutation are separate."""

    @staticmethod
    def _rule_name(host: str, port: int) -> str:
        return f"GIDEON Gateway TEST {host} {int(port)}"

    @staticmethod
    def _powershell() -> str:
        ps = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        return str(ps) if ps.is_file() else "powershell.exe"

    def internal_test_status(self, *, host: str, port: int) -> GatewayResult:
        if os.name != "nt":
            return GatewayResult(True, "Firewall TEST", "Validación automática específica de Windows no aplica en este sistema.")
        host = str(host or "").strip()
        if not host:
            return GatewayResult(False, "Firewall TEST", "Seleccione primero una IPv4 local.")
        name = self._rule_name(host, port)
        escaped = name.replace("'", "''")
        script = (
            "$ErrorActionPreference='Stop';"
            f"$r=Get-NetFirewallRule -DisplayName '{escaped}' -ErrorAction SilentlyContinue | "
            "Where-Object {$_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow'} | Select-Object -First 1;"
            "if(-not $r){exit 3};"
            "$pf=$r | Get-NetFirewallPortFilter -ErrorAction Stop;"
            f"if([string]$pf.Protocol -ne 'TCP' -or [string]$pf.LocalPort -ne '{int(port)}'){{exit 4}};"
            "'OK'"
        )
        try:
            result = run_hidden(
                [self._powershell(), "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script],
                capture_output=True, text=True, timeout=10,
            )
        except Exception as exc:
            return GatewayResult(False, "Firewall TEST", f"No se pudo validar la regla: {type(exc).__name__}: {exc}")
        if result.returncode == 0 and "OK" in (result.stdout or ""):
            return GatewayResult(True, "Firewall TEST listo", f"Regla activa: {name}")
        return GatewayResult(False, "Firewall TEST pendiente", f"No existe una regla GIDEON válida para {host}:{int(port)}. Use 'Preparar Firewall TEST'.")

    def prepare_internal_test(self, *, host: str, port: int) -> GatewayResult:
        if os.name != "nt":
            return GatewayResult(True, "Firewall TEST", "En este sistema el firewall debe administrarse con la herramienta nativa de la distribución.")
        host = str(host or "").strip()
        if not host:
            return GatewayResult(False, "Firewall TEST", "Seleccione primero una IPv4 local.")
        rule_name = self._rule_name(host, port)
        # RemoteAddress=LocalSubnet permits Public-profile LAN tests without exposing
        # the port to Internet peers. LocalAddress further scopes the listener rule.
        script = (
            "$ErrorActionPreference='Stop';"
            f"$n='{rule_name.replace("'", "''")}';"
            "$existing=Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue;"
            "if($existing){Remove-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue};"
            "$args=@('-NoProfile','-NonInteractive','-WindowStyle','Hidden','-Command',"
            f"\"New-NetFirewallRule -DisplayName '{rule_name.replace("'", "''")}' -Direction Inbound -Action Allow -Protocol TCP -LocalPort {int(port)} -LocalAddress {host} -RemoteAddress LocalSubnet -Profile Any | Out-Null\");"
            "$p=Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $args -WindowStyle Hidden -Wait -PassThru; exit $p.ExitCode"
        )
        try:
            result = run_hidden(
                [self._powershell(), "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-Command", script],
                capture_output=True, text=True, timeout=120,
            )
        except Exception as exc:
            return GatewayResult(False, "Firewall TEST", f"{type(exc).__name__}: {exc}")
        detail = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
        if result.returncode == 0:
            verified = self.internal_test_status(host=host, port=port)
            if verified.ok:
                return GatewayResult(True, "Firewall TEST preparado", f"TCP {port} permitido solo hacia {host} desde LocalSubnet.\nRegla: {rule_name}")
            return verified
        return GatewayResult(False, "No se pudo preparar Firewall TEST", detail[-6000:] or f"Código {result.returncode}")

    def ensure_internal_test(self, *, host: str, port: int) -> GatewayResult:
        current = self.internal_test_status(host=host, port=port)
        if current.ok:
            return current
        return self.prepare_internal_test(host=host, port=port)


class GatewayHealthService:
    def __init__(self, app_root: Path, runtime: GatewayRuntimeService | None = None) -> None:
        self.app_root = Path(app_root).resolve()
        self.runtime = runtime

    @staticmethod
    def _tcp_check(host: str, port: int, timeout: float = 1.0) -> tuple[bool, str]:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True, f"TCP {host}:{port} responde"
        except Exception as exc:
            return False, f"{type(exc).__name__}: {exc}"

    @staticmethod
    def _tls_check(host: str, port: int, ca_file: str | None, timeout: float = 1.5) -> tuple[bool, str]:
        try:
            if ca_file:
                context = gideon_private_ca_context(ca_file)
            else:
                context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2 if hasattr(ssl, "TLSVersion") else context.minimum_version
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with context.wrap_socket(raw, server_hostname=host) as tls:
                    cipher = tls.cipher()
                    return True, f"TLS {tls.version()} · {cipher[0] if cipher else '-'}"
        except Exception as exc:
            return False, f"{type(exc).__name__}: {exc}"

    def run(self) -> GatewayResult:
        cfg = JsonGatewayRepository().read_gateway()
        status = gateway_status()
        base_url = str(cfg.get("advertised_endpoint") or cfg.get("public_url") or status.get("advertised_endpoint") or status.get("public_url") or "").strip().rstrip("/")
        token = str(cfg.get("admin_api_key") or "").strip()
        ca_file = str(cfg.get("ca_file") or status.get("ca_file") or "").strip() or None
        checks: list[GatewayCheck] = []

        ready, deps = SystemDependencyManager(self.app_root).gateway_ready()
        missing = [d.name for d in deps if not d.installed]
        checks.append(GatewayCheck("Requisitos", ready, "Listos" if ready else "Faltan: " + ", ".join(missing)))

        parsed = urlparse(base_url) if base_url else None
        https_ok = bool(parsed and parsed.scheme.lower() == "https" and parsed.hostname)
        checks.append(GatewayCheck("URL HTTPS", https_ok, base_url or "No configurada"))
        checks.append(GatewayCheck("Credencial administrativa", bool(token), "Disponible" if token else "Falta admin_api_key"))
        ca_ok = bool(ca_file and Path(ca_file).is_file())
        ca_detail = (
            f"{ca_file} · CA privada GIDEON embebida; no requiere Trusted Root del sistema"
            if ca_ok else "No configurada"
        )
        checks.append(GatewayCheck("CA privada GIDEON (embebida)", ca_ok, ca_detail))
        if https_ok and parsed:
            local_material = GatewayTLSLifecycle(TLS_DIR).validate_material(str(parsed.hostname))
            checks.append(GatewayCheck("Coherencia TLS local", local_material.ok, local_material.detail, blocking=False))
        process_ok = bool(self.runtime and self.runtime.is_running())
        checks.append(
            GatewayCheck(
                "Proceso administrado por esta consola",
                process_ok,
                "Activo" if process_ok else "No administrado por esta ventana; puede estar ejecutándose como servicio u otra instancia",
                blocking=False,
            )
        )

        network_mode = str(cfg.get("network_mode") or status.get("network_mode") or NETWORK_MODE_INTERNAL)
        if os.name == "nt" and network_mode == NETWORK_MODE_INTERNAL and https_ok and parsed:
            fw = GatewayFirewallService().internal_test_status(host=str(parsed.hostname), port=int(parsed.port or 443))
            checks.append(GatewayCheck("Firewall TEST", fw.ok, fw.message or fw.title))

        if https_ok and parsed:
            host = str(parsed.hostname)
            port = int(parsed.port or 443)
            local_tcp_ok, local_tcp_detail = self._tcp_check("127.0.0.1", port)
            checks.append(
                GatewayCheck(
                    "Loopback local 127.0.0.1",
                    local_tcp_ok,
                    local_tcp_detail if local_tcp_ok else local_tcp_detail + " · informativo: no bloquea si el endpoint LAN/HTTPS responde",
                    blocking=False,
                )
            )
            advertised_tcp_ok, advertised_tcp_detail = self._tcp_check(host, port)
            checks.append(GatewayCheck("Ruta al endpoint anunciado", advertised_tcp_ok, advertised_tcp_detail))
            expected_cert_fp = str(cfg.get("tls_cert_fingerprint") or "").strip().upper()
            raw_peer = probe_tls_peer(base_url, timeout=1.0) if advertised_tcp_ok else None
            if expected_cert_fp and raw_peer and raw_peer.ok:
                same_leaf = raw_peer.peer_fingerprint.upper() == expected_cert_fp
                checks.append(GatewayCheck(
                    "Certificado servido = certificado activo",
                    same_leaf,
                    "Coincide" if same_leaf else (
                        f"STALE_TLS: listener {raw_peer.peer_fingerprint[:16]}… != activo "
                        f"{expected_cert_fp[:16]}…. Se requiere reiniciar solo el Gateway."
                    ),
                ))
            tls_ok, tls_detail = self._tls_check(host, port, ca_file) if advertised_tcp_ok and ca_ok else (False, "TCP/CA no disponibles")
            checks.append(GatewayCheck("TLS y certificado", tls_ok, tls_detail))
            endpoint_ok = False
            endpoint_detail = "No ejecutado"
            if tls_ok and token:
                try:
                    client = AgentHttpClient(base_url, bearer_token=token, verify_tls=True, ca_file=ca_file, require_https=True)
                    payload = client.json("GET", "/api/v1/admin/health", timeout=3)
                    endpoint_ok = bool(isinstance(payload, dict) and payload.get("Ok", True))
                    endpoint_detail = f"HTTP OK · versión {payload.get('Version', '-')} · protocolo {payload.get('ProtocolVersion', '-')}" if isinstance(payload, dict) else "Respuesta recibida"
                    if isinstance(payload, dict):
                        live_version = str(payload.get("Version") or "").strip()
                        checks.append(GatewayCheck(
                            "Versión Gateway",
                            live_version == GATEWAY_VERSION,
                            f"Activa {live_version or '-'} · requerida {GATEWAY_VERSION}" + ("" if live_version == GATEWAY_VERSION else " · reinicio/actualización requerida"),
                        ))
                        schema = payload.get("Schema") if isinstance(payload.get("Schema"), dict) else {}
                        if schema:
                            schema_ok = bool(schema.get("Ready"))
                            checks.append(GatewayCheck(
                                "Esquema Gateway",
                                schema_ok,
                                f"Schema v{schema.get('SchemaVersion', '-')} · {'listo' if schema_ok else 'requiere reparación'}",
                            ))
                        capabilities = payload.get("Capabilities") if isinstance(payload.get("Capabilities"), dict) else {}
                        release_approval_ok = bool(capabilities.get("ReleaseApproval"))
                        checks.append(GatewayCheck(
                            "API aprobación de releases",
                            release_approval_ok,
                            (
                                f"Disponible · API v{capabilities.get('ReleaseApprovalApiVersion', '-')}"
                                if release_approval_ok else
                                "No disponible en el Gateway activo; se requiere reinicio/actualización."
                            ),
                        ))
                except Exception as exc:
                    endpoint_detail = f"{type(exc).__name__}: {exc}"
            checks.append(GatewayCheck("API /health", endpoint_ok, endpoint_detail))

        # Availability is defined by blocking capabilities (HTTPS route, TLS and
        # authenticated /health), not by ownership of a child process nor by the
        # optional loopback path.  This prevents false negatives when the Gateway
        # is supervised by another instance/service or Windows treats loopback
        # differently from the selected LAN interface.
        overall = all(c.ok for c in checks if c.blocking)
        title = "Gateway funcionando" if overall else "Gateway requiere atención"
        if overall:
            informational = [c for c in checks if not c.blocking and not c.ok]
            message = "La prueba integral del Gateway HTTPS fue satisfactoria."
            if informational:
                message += " Los avisos [INFO] no afectan la disponibilidad del Gateway."
        else:
            message = "La prueba detectó uno o más puntos bloqueantes pendientes."
        return GatewayResult(overall, title, message, data={"public_url": base_url}, checks=tuple(checks))


class GatewayCoordinator:
    """Facade used by UI workers; composes independent services via dependency injection."""

    def __init__(self, app_root: Path, repository: GatewayRepository | None = None) -> None:
        self.repository = repository or JsonGatewayRepository()
        self.network = GatewayNetworkService(self.repository)
        self.runtime = GatewayRuntimeService(app_root)
        self.firewall = GatewayFirewallService()
        self.health = GatewayHealthService(app_root, self.runtime)
        self.app_root = Path(app_root).resolve()

    def test_and_repair(self) -> GatewayResult:
        """Run health checks and safely reconcile stale local TLS once.

        The persistent root CA is never rotated here.  The operation may only
        reissue the server leaf and restart/adopt a GIDEON Gateway listener.
        """
        first = self.health.run()
        if first.ok:
            return first
        cfg = self.repository.read_gateway()
        base_url = str(cfg.get("advertised_endpoint") or cfg.get("public_url") or "").strip().rstrip("/")
        expected_fp = str(cfg.get("tls_cert_fingerprint") or "").strip().upper()
        ca_file = str(cfg.get("ca_file") or "").strip()
        if not base_url or not ca_file:
            return first
        raw = probe_tls_peer(base_url, timeout=1.0)
        verified = probe_tls_endpoint(base_url, ca_file=ca_file, timeout=1.0)
        blocking_version_or_schema = any(
            (not check.ok) and check.name in {"Versión Gateway", "Esquema Gateway", "API aprobación de releases"}
            for check in first.checks
        )
        needs_repair = bool(
            (raw.ok and expected_fp and raw.peer_fingerprint.upper() != expected_fp)
            or not verified.ok
            or blocking_version_or_schema
        )
        if not needs_repair:
            return first
        try:
            ensure_gateway_configuration(force_tls=True)
            if self.runtime.is_running():
                restarted = self.runtime.restart()
            else:
                restarted = self.runtime.start()
            if not restarted.ok:
                return GatewayResult(
                    False,
                    "Gateway requiere atención",
                    restarted.message or restarted.title,
                    checks=first.checks,
                )
            second = self.health.run()
            if second.ok:
                return GatewayResult(
                    True,
                    "Gateway funcionando",
                    "Gateway reconciliado automáticamente: versión/runtime, esquema y TLS sincronizados sin rotar la CA persistente.",
                    data=second.data,
                    checks=second.checks,
                )
            return second
        except Exception as exc:
            return GatewayResult(
                False,
                "Gateway requiere atención",
                f"La reparación TLS automática no pudo completarse: {type(exc).__name__}: {exc}",
                checks=first.checks,
            )

    def bootstrap(self) -> GatewayResult:
        try:
            info = ensure_gateway_configuration()
            ready, deps = SystemDependencyManager(self.app_root).gateway_ready()
            return GatewayResult(ready, "Gateway preparado" if ready else "Gateway con requisitos pendientes", data={**info, "dependencies": deps})
        except Exception as exc:
            return GatewayResult(False, "No se pudo preparar el Gateway", f"{type(exc).__name__}: {exc}")

    def activate_internal_test(self, *, host: str, port: int) -> GatewayResult:
        """One-click LAN test: firewall policy + TLS/config + local runtime."""
        firewall = self.firewall.ensure_internal_test(host=host, port=port)
        if not firewall.ok:
            return firewall
        return self.activate(mode=NETWORK_MODE_INTERNAL, host=host, port=port, force_tls=False, ensure_started=True)

    def activate(self, *, mode: str, host: str, port: int, force_tls: bool = False, ensure_started: bool = True) -> GatewayResult:
        applied = self.network.apply(mode=mode, host=host, port=port, force_tls=force_tls)
        if not applied.ok:
            return applied
        restart = bool(applied.data.get("listener_restart"))
        if self.runtime.is_running() and restart:
            self.runtime.stop()
        if ensure_started and not self.runtime.is_running():
            started = self.runtime.start()
            if not started.ok:
                return GatewayResult(False, started.title, started.message, data={**applied.data, **started.data})
        return GatewayResult(True, "Gateway activo", "Configuración aplicada y proceso sincronizado.", data=applied.data)
