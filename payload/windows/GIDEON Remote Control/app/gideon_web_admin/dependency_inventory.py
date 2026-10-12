"""GIDEON Remote Control dependency inventory.

This module intentionally uses only the Python standard library so the
Dependencies page can render even when one of the optional/runtime packages is
missing.  It does not modify the host.  Remediation is delegated to explicit
administrator/root scripts shipped under app/tools/dependencies.
"""
from __future__ import annotations

import importlib.metadata as metadata
import importlib.util
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable


@dataclass
class DependencyRow:
    id: str
    name: str
    category: str
    scope: str
    required: bool
    status: str
    version: str = ""
    detail: str = ""
    remediation: str = ""
    capability: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _run(args: list[str], timeout: int = 7) -> tuple[int, str]:
    try:
        flags = 0
        if os.name == "nt":
            flags = int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
        cp = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            timeout=timeout,
            creationflags=flags,
            check=False,
        )
        return int(cp.returncode), (cp.stdout or "").strip()
    except Exception as exc:
        return 127, f"{type(exc).__name__}: {exc}"


def _command_version(command: str, args: Iterable[str] = ("--version",)) -> tuple[bool, str, str]:
    path = shutil.which(command)
    if not path:
        return False, "", ""
    rc, out = _run([path, *list(args)])
    first = next((x.strip() for x in out.splitlines() if x.strip()), "")
    return rc == 0, first[:220], path


def _pkg_version(dist_name: str) -> str:
    try:
        return metadata.version(dist_name)
    except Exception:
        return ""


def _module_status(module: str, dist_name: str, *, required: bool, capability: str) -> DependencyRow:
    available = importlib.util.find_spec(module) is not None
    return DependencyRow(
        id=f"py-{dist_name.lower().replace('_','-')}",
        name=dist_name,
        category="Python / WebAdmin",
        scope="Control Plane",
        required=required,
        status="OK" if available else ("MISSING" if required else "OPTIONAL"),
        version=_pkg_version(dist_name) if available else "",
        detail=f"Módulo Python `{module}` {'disponible' if available else 'no disponible'} en el runtime GIDEON: {sys.executable}",
        remediation=("Instalar/reparar con el script de dependencias del Control Plane." if not available else ""),
        capability=capability,
    )


def _read_os_release() -> dict[str, str]:
    result: dict[str, str] = {}
    p = Path("/etc/os-release")
    if p.is_file():
        try:
            for raw in p.read_text(encoding="utf-8", errors="replace").splitlines():
                if "=" not in raw:
                    continue
                k, v = raw.split("=", 1)
                result[k.strip()] = v.strip().strip('"')
        except Exception:
            pass
    return result


def _windows_edition() -> str:
    if os.name != "nt":
        return ""
    try:
        rc, out = _run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "(Get-CimInstance Win32_OperatingSystem).Caption"], 10)
        return out.strip() if rc == 0 else platform.platform()
    except Exception:
        return platform.platform()


def _windows_feature(name: str) -> tuple[bool, str]:
    if os.name != "nt":
        return False, ""
    script = f"$f=Get-WindowsOptionalFeature -Online -FeatureName '{name}' -ErrorAction SilentlyContinue;if($f){{$f.State}}else{{'UNKNOWN'}}"
    rc, out = _run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], 15)
    return rc == 0 and "Enabled" in out, out.strip()


def _docker_rows(system: str) -> list[DependencyRow]:
    rows: list[DependencyRow] = []
    docker = shutil.which("docker")
    docker_ok, docker_ver, _ = _command_version("docker", ("--version",))
    compose_ok = False
    compose_ver = ""
    daemon_ok = False
    daemon_detail = ""
    if docker:
        rc, out = _run([docker, "compose", "version"], 10)
        compose_ok = rc == 0
        compose_ver = next((x.strip() for x in out.splitlines() if x.strip()), "")[:220]
        rc, out = _run([docker, "info", "--format", "{{.ServerVersion}}"], 8)
        daemon_ok = rc == 0
        daemon_detail = out.strip()[:220]
        if not daemon_ok and system == "Linux":
            # WebAdmin intentionally has no access to docker.sock: membership in
            # the docker group is effectively root.  A running systemd unit is
            # sufficient for this read-only inventory and preserves isolation.
            systemctl = shutil.which("systemctl")
            if systemctl:
                service_rc, service_out = _run([systemctl, "is-active", "docker.service"], 8)
                if service_rc == 0 and service_out.strip() == "active":
                    daemon_ok = True
                    daemon_detail = "docker.service activo; socket Docker no delegado a WebAdmin por seguridad"
    rows.append(DependencyRow(
        id="docker-cli", name="Docker Engine / CLI", category="Containers / Guacamole", scope="Control Plane",
        required=True, status="OK" if docker_ok else "MISSING", version=docker_ver,
        detail=(f"CLI: {docker}" if docker else "No se encontró `docker` en PATH."),
        remediation="Windows: instalar Docker Desktop. Linux: instalar Docker Engine/CLI desde el script GIDEON.",
        capability="Ejecutar guacd/servicios containerizados de GIDEON.",
    ))
    rows.append(DependencyRow(
        id="docker-compose", name="Docker Compose v2", category="Containers / Guacamole", scope="Control Plane",
        required=True, status="OK" if compose_ok else "MISSING", version=compose_ver,
        detail="Se valida con `docker compose version` (plugin v2).",
        remediation="Instalar/actualizar el Docker Compose plugin v2.",
        capability="Levantar el stack Guacamole mediante docker compose.",
    ))
    rows.append(DependencyRow(
        id="docker-daemon", name="Docker daemon", category="Containers / Guacamole", scope="Control Plane",
        required=True, status="OK" if daemon_ok else ("DEGRADED" if docker_ok else "MISSING"), version=daemon_detail,
        detail=("Servicio Docker confirmado sin otorgar acceso privilegiado al socket." if daemon_ok and system == "Linux" else "El CLI puede existir aunque Docker Desktop/daemon todavía no esté iniciado."),
        remediation="Iniciar Docker Desktop o el servicio docker y revalidar.",
        capability="Crear/ejecutar el contenedor guacd.",
    ))
    if system == "Windows":
        desktop_candidates = [
            Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Docker" / "Docker" / "Docker Desktop.exe",
            Path(os.environ.get("LOCALAPPDATA", "")) / "Docker" / "Docker Desktop.exe",
        ]
        dd = next((p for p in desktop_candidates if p.is_file()), None)
        edition = _windows_edition()
        is_server = "server" in edition.casefold()
        rows.append(DependencyRow(
            id="docker-desktop", name="Docker Desktop", category="Containers / Guacamole", scope="Windows Control Plane",
            required=not is_server,
            status=("NOT_APPLICABLE" if is_server else ("OK" if dd else "MISSING")),
            detail=("Windows Server detectado: Docker Desktop no se usa; ejecute Docker Engine en Linux/WSL2/VM o un host Linux de Guacamole." if is_server else (str(dd) if dd else "Docker Desktop no detectado.")),
            remediation=("Usar el instalador Windows GIDEON (winget Docker.DockerDesktop) y reiniciar si se solicita." if not is_server else "Provisionar Docker Engine en Linux/WSL2/VM/host Linux."),
            capability="Backend local de contenedores en Windows cliente.",
        ))
    return rows


class DependencyInventory:
    """Read-only dependency inventory for the current Control Plane host."""

    PYTHON_REQUIREMENTS = (
        ("fastapi", "fastapi", True, "API/WebAdmin"),
        ("uvicorn", "uvicorn", True, "Servidor ASGI HTTPS/WebSocket"),
        ("starlette", "starlette", True, "HTTP/WebSocket base"),
        ("jinja2", "Jinja2", True, "Plantillas WebAdmin"),
        ("multipart", "python-multipart", True, "Carga de formularios/archivos"),
        ("cryptography", "cryptography", True, "PKI, Fernet, firmas y claves SSH"),
        ("bcrypt", "bcrypt", True, "Descifrado de claves OpenSSH protegidas con bcrypt"),
        ("pydantic", "pydantic", True, "Modelos/validación"),
        ("anyio", "anyio", True, "Runtime async"),
        ("websockets", "websockets", True, "Canal WebSocket del WebAdmin"),
        ("PySide6", "PySide6", False, "Interfaz de escritorio del Control Plane"),
        ("openpyxl", "openpyxl", False, "Exportaciones Excel/inventario"),
    )

    def __init__(self, app_root: Path, data_dir: Path) -> None:
        self.app_root = Path(app_root).resolve()
        self.data_dir = Path(data_dir).resolve()

    def _python_rows(self) -> list[DependencyRow]:
        rows = [_module_status(m, d, required=req, capability=cap) for m, d, req, cap in self.PYTHON_REQUIREMENTS]
        req_file = self.app_root / "requirements-web.txt"
        if req_file.is_file():
            try:
                known = {r.name.casefold() for r in rows}
                for raw in req_file.read_text(encoding="utf-8", errors="replace").splitlines():
                    line = raw.strip()
                    if not line or line.startswith("#") or line.startswith(("-r", "--")):
                        continue
                    name = re.split(r"[<>=!~\[\s]", line, 1)[0].strip()
                    if not name or name.casefold() in known:
                        continue
                    ver = _pkg_version(name)
                    rows.append(DependencyRow(
                        id=f"req-{re.sub('[^a-z0-9]+','-',name.casefold()).strip('-')}", name=name,
                        category="Python / requirements-web.txt", scope="Control Plane", required=True,
                        status="OK" if ver else "MISSING", version=ver,
                        detail=f"Declarado por {req_file.name}: {line}",
                        remediation="Ejecutar el remediador Python GIDEON.", capability="Dependencia declarada por el proyecto.",
                    ))
                    known.add(name.casefold())
            except Exception:
                pass
        return rows

    def _system_rows(self, system: str) -> list[DependencyRow]:
        rows: list[DependencyRow] = []
        if system == "Windows":
            ps_ok, ps_ver, ps_path = _command_version("powershell.exe", ("-NoProfile", "-Command", "$PSVersionTable.PSVersion.ToString()"))
            rows.append(DependencyRow("powershell", "Windows PowerShell", "Sistema operativo", "Control Plane", True, "OK" if ps_ok else "MISSING", ps_ver, ps_path, "Habilitar Windows PowerShell 5.1+.", "Instalación, servicios y automatización GIDEON."))
            ssh_ok, ssh_ver, ssh_path = _command_version("ssh.exe", ("-V",))
            rows.append(DependencyRow("openssh-client", "OpenSSH Client", "SSH / SFTP", "Control Plane", True, "OK" if ssh_ok else "MISSING", ssh_ver, ssh_path or "ssh.exe no encontrado", "Add-WindowsCapability OpenSSH.Client o usar el remediador GIDEON.", "Administración agentless SSH/SFTP."))
            sftp_path = shutil.which("sftp.exe")
            sftp_ok = bool(sftp_path)
            rows.append(DependencyRow("sftp-client", "OpenSSH SFTP Client", "SSH / SFTP", "Control Plane", True, "OK" if sftp_ok else "MISSING", "OpenSSH SFTP" if sftp_ok else "", sftp_path or "sftp.exe no encontrado", "Add-WindowsCapability OpenSSH.Client o usar el remediador GIDEON.", "Transferencia y recolección Agentless SFTP."))
            wsl_path = shutil.which("wsl.exe")
            rc, wsl_out = _run([wsl_path, "--status"], 10) if wsl_path else (127, "")
            rows.append(DependencyRow("wsl2", "WSL2 + distribución Linux", "Build toolchains", "Windows Control Plane", False, "OK" if wsl_path and rc == 0 else "OPTIONAL", detail=(wsl_out[:300] if wsl_out else "Requerido para generar RPM desde Windows y útil para Docker Desktop/CLI Linux."), remediation="`wsl --install -d Ubuntu` y abrir la distro una vez.", capability="Toolchain RPM y backend Linux local."))
            csc_candidates = [
                Path(os.environ.get("WINDIR", r"C:\Windows")) / "Microsoft.NET" / "Framework64" / "v4.0.30319" / "csc.exe",
                Path(os.environ.get("WINDIR", r"C:\Windows")) / "Microsoft.NET" / "Framework" / "v4.0.30319" / "csc.exe",
            ]
            csc = next((p for p in csc_candidates if p.is_file()), None) or (Path(shutil.which("csc.exe")) if shutil.which("csc.exe") else None)
            rows.append(DependencyRow("csc", ".NET Framework C# compiler (csc.exe)", "Build toolchains", "Windows Control Plane", True, "OK" if csc else "MISSING", detail=str(csc or "No detectado"), remediation="Habilitar/instalar .NET Framework compatible; el generador Windows usa GIDEON SFX compilado con csc.exe.", capability="Generación de GIDEONAgent-windows_x64-*.exe."))
            defender = shutil.which("MpCmdRun.exe")
            if not defender:
                for p in [Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Windows Defender" / "MpCmdRun.exe"]:
                    if p.is_file(): defender = str(p); break
            rows.append(DependencyRow("defender", "Microsoft Defender CLI", "Seguridad", "Windows Control Plane", False, "OK" if defender else "OPTIONAL", detail=defender or "No detectado; GIDEON puede usar otro escáner autorizado.", remediation="Habilitar Microsoft Defender o configurar ClamAV según política.", capability="Escaneo de transferencias/artefactos."))
            vmp_ok, vmp_detail = _windows_feature("VirtualMachinePlatform")
            rows.append(DependencyRow("virtualmachineplatform", "Virtual Machine Platform", "Containers / WSL", "Windows Control Plane", False, "OK" if vmp_ok else "OPTIONAL", detail=vmp_detail or "Estado no determinado", remediation="Requerida por WSL2/Docker Desktop en configuraciones WSL2.", capability="Virtualización WSL2/Docker Desktop."))
        elif system == "Linux":
            osrel = _read_os_release()
            distro = osrel.get("PRETTY_NAME") or osrel.get("NAME") or platform.platform()
            ssh_version = ""
            for cmd, label, req, cap, version_args, presence_only in [
                ("ssh", "OpenSSH Client", True, "Agentless SSH/SFTP", ("-V",), False),
                ("sftp", "OpenSSH SFTP Client", True, "Transferencia/recolección Agentless SFTP", (), True),
                ("curl", "curl", True, "Descargas/health checks", ("--version",), False),
                ("openssl", "OpenSSL CLI", True, "Diagnóstico TLS/PKI", ("version",), False),
                ("ip", "iproute2 (ip)", True, "Rutas/interfaces", ("-Version",), False),
                ("ss", "iproute2 (ss)", True, "Listeners/sockets", ("--version",), False),
                ("tar", "tar", True, "Empaquetado", ("--version",), False),
                ("gzip", "gzip", True, "Empaquetado", ("--version",), False),
                ("unzip", "unzip", False, "Soporte/diagnóstico", ("-v",), False),
                ("systemctl", "systemd", True, "Servicios GIDEON", (), True),
            ]:
                if presence_only:
                    path = shutil.which(cmd) or ""
                    ok = bool(path)
                    ver = ssh_version if cmd == "sftp" and ssh_version else ("systemd" if cmd == "systemctl" and ok else "")
                else:
                    ok, ver, path = _command_version(cmd, version_args)
                if cmd == "ssh" and ok:
                    ssh_version = ver
                rows.append(DependencyRow(f"linux-{cmd}", label, "Sistema operativo", "Linux Control Plane", req, "OK" if ok else ("MISSING" if req else "OPTIONAL"), ver, f"{distro} · {path or 'no encontrado'}", "Instalar mediante el gestor de paquetes de la distribución.", cap))
            rpm_tools = ["rpmbuild", "file", "tar", "gzip"]
            missing = [x for x in rpm_tools if not shutil.which(x)]
            rows.append(DependencyRow("rpm-toolchain", "RPM build toolchain", "Build toolchains", "Linux Control Plane", False, "OK" if not missing else "OPTIONAL", detail=("Completo" if not missing else "Faltan: " + ", ".join(missing)), remediation="Instalar rpm-build/rpm, file, binutils, tar y gzip.", capability="Generación de Agents RPM Fedora/RHEL/Rocky/Alma/SUSE."))
            dpkg = shutil.which("dpkg-deb")
            rows.append(DependencyRow("deb-toolchain", "DEB build toolchain", "Build toolchains", "Linux Control Plane", False, "OK" if dpkg else "OPTIONAL", detail=dpkg or "GIDEON puede usar builder Python en algunos escenarios.", remediation="Instalar dpkg-dev/dpkg-deb si desea toolchain nativo.", capability="Generación DEB Debian/Ubuntu/Raspberry Pi OS."))
        elif system == "Darwin":
            pkgbuild = shutil.which("pkgbuild")
            xcode = shutil.which("xcode-select")
            rows.append(DependencyRow("pkgbuild", "pkgbuild / Xcode Command Line Tools", "Build toolchains", "macOS Control Plane", True, "OK" if pkgbuild else "MISSING", detail=pkgbuild or "No detectado", remediation="`xcode-select --install`", capability="Generación nativa de Agents .pkg para macOS."))
            rows.append(DependencyRow("xcode-select", "xcode-select", "Build toolchains", "macOS Control Plane", False, "OK" if xcode else "OPTIONAL", detail=xcode or "No detectado", remediation="Instalar Xcode Command Line Tools.", capability="Toolchain Apple."))
        return rows

    def _project_rows(self, system: str) -> list[DependencyRow]:
        rows: list[DependencyRow] = []
        guac_candidates = [
            self.data_dir / "remote-client" / "guacamole-common.min.js",
            self.data_dir / "security-assets" / "guacamole-client" / "guacamole-common.min.js",
        ]
        guac = next((p for p in guac_candidates if p.is_file()), None)
        rows.append(DependencyRow("guacamole-js", "guacamole-common-js", "Apache Guacamole", "WebAdmin", True, "OK" if guac else "MISSING", detail=str(guac or "Cliente Web Guacamole no detectado."), remediation="Provisionar el bundle aprobado desde Claves y secretos.", capability="Render del escritorio remoto en navegador."))
        rows.append(DependencyRow("guacd", "Apache Guacamole guacd", "Apache Guacamole", "Control Plane", True, "CHECK", detail="GIDEON lo ejecuta preferentemente en contenedor; debe permanecer en loopback/privado y no exponerse a Internet.", remediation="Levantar con Docker Compose y validar el health desde Control remoto.", capability="Backend RDP/VNC de las sesiones WebAdmin."))
        rows.append(DependencyRow("linux-agent-xrdp", "xrdp + xorgxrdp", "Agents / acceso remoto", "Linux/Raspberry endpoint", False, "ENDPOINT", detail="Se valida/instala en el endpoint Linux cuando se requiere escritorio remoto; no es dependencia del servidor central.", remediation="apt/dnf/zypper/pacman según distro; el Agent debe restringir listener según política GIDEON.", capability="Escritorio remoto Linux detrás del reverse tunnel."))
        rows.append(DependencyRow("windows-rdp", "Microsoft RDP host", "Agents / acceso remoto", "Windows endpoint", False, "ENDPOINT", detail="Windows Pro/Enterprise/Education/Server: soportado. Windows Home/Core: capability UNSUPPORTED, no debe abortar el Agent.", remediation="No instalar servidores RDP/VNC de terceros automáticamente.", capability="Escritorio remoto Windows."))
        rows.append(DependencyRow("macos-launchd", "launchd", "Agents / servicio", "macOS endpoint", True, "ENDPOINT", detail="Servicio nativo del Agent macOS.", remediation="Incluido por macOS; el instalador GIDEON registra/repara LaunchDaemon.", capability="Persistencia/reinicio del Agent macOS."))
        return rows

    def scan(self) -> dict[str, Any]:
        system = platform.system() or os.name
        rows: list[DependencyRow] = []
        rows.extend(self._python_rows())
        rows.extend(self._system_rows(system))
        rows.extend(_docker_rows(system))
        rows.extend(self._project_rows(system))

        counts: dict[str, int] = {"OK": 0, "MISSING": 0, "DEGRADED": 0, "OPTIONAL": 0, "CHECK": 0, "ENDPOINT": 0, "NOT_APPLICABLE": 0}
        for row in rows:
            counts[row.status] = counts.get(row.status, 0) + 1
        required_missing = [r.to_dict() for r in rows if r.required and r.status in {"MISSING", "DEGRADED"}]
        osrel = _read_os_release() if system == "Linux" else {}
        return {
            "schema": "gideon-dependency-inventory/v1",
            "system": system,
            "platform": platform.platform(),
            "architecture": platform.machine(),
            "python": sys.version.split()[0],
            "python_executable": sys.executable,
            "distro": osrel.get("PRETTY_NAME", ""),
            "rows": [r.to_dict() for r in rows],
            "counts": counts,
            "required_missing": required_missing,
            "ready": not required_missing,
            "app_root": str(self.app_root),
            "data_dir": str(self.data_dir),
            "notes": [
                "La página es de solo lectura: WebAdmin no ejecuta gestores de paquetes con privilegios del servicio.",
                "Use los remediadores descargables y ejecútelos explícitamente como Administrador/root.",
                "GIDEON valida compatibilidad funcional; no afirma que una versión sea la más reciente sin consultar repositorios externos.",
            ],
        }
