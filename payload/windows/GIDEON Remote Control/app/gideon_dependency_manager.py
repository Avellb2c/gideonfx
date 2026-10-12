from __future__ import annotations

import importlib.util
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from gideon_infrastructure.subprocess_utils import run_hidden
from gideon_platform import detect_platform, display_session_available
from gideon_branding import BrandingRepository
from gideon_packaging import WindowsExePackager, WindowsCodeSigningService
from gideon_gateway_bootstrap import GATEWAY_CONFIG_PATH


@dataclass(frozen=True)
class DependencyStatus:
    key: str
    name: str
    category: str
    required_for: str
    installed: bool
    version: str = ""
    detail: str = ""
    install_hint: str = ""
    installable: bool = True


class SystemDependencyManager:
    """Validador e instalador de dependencias de GIDEON Remote Control.

    Detecta únicamente las capacidades que cada plataforma necesita para
    ejecutar GIDEON y producir paquetes nativos. Los instaladores Windows se
    generan como EXE directo mediante Inno Setup (preferido) o IExpress de contingencia, sin MSI.
    """

    def __init__(self, app_root: Path):
        self.app_root = Path(app_root).resolve()
        self.platform = detect_platform()

    @staticmethod
    def _run(command: list[str], timeout: int = 120) -> tuple[int, str]:
        try:
            env = os.environ.copy()
            env["PYTHONUTF8"] = "1"
            proc = run_hidden(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                env=env,
            )
            output = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
            return proc.returncode, output.strip()
        except FileNotFoundError:
            return 127, f"No se encontró el ejecutable: {command[0]}"
        except subprocess.TimeoutExpired as exc:
            return 124, f"Tiempo agotado ejecutando {' '.join(command)}: {exc}"
        except Exception as exc:
            return 1, f"{type(exc).__name__}: {exc}"

    @staticmethod
    def _which(*names: str) -> str | None:
        for name in names:
            value = shutil.which(name)
            if value:
                return value
        return None

    def _version(self, executable: str, args: list[str] | None = None) -> str:
        rc, output = self._run([executable, *(args or ["--version"])], timeout=20)
        if rc == 0:
            return output.splitlines()[0].strip()[:200]
        return ""

    def scan(self) -> list[DependencyStatus]:
        rows: list[DependencyStatus] = []

        supported = self.platform.family in {"windows", "linux"}
        rows.append(DependencyStatus(
            "platform", "Sistema operativo detectado", "Plataforma", "Selección automática de módulos y dependencias",
            supported, self.platform.label,
            f"Perfil: {self.platform.family}; familia Linux: {self.platform.distro_family or '-'}; gestor: {self.platform.package_manager or '-'}",
            "GIDEON Remote Control Desktop soporta Windows/Windows Server con escritorio y Linux con sesión gráfica.", False,
        ))
        if self.platform.family == "linux":
            gui_ok = display_session_available(self.platform)
            rows.append(DependencyStatus(
                "platform:desktop", "Sesión gráfica Linux", "Plataforma", "Interfaz Qt y Remmina", gui_ok,
                os.environ.get("XDG_SESSION_TYPE", "") or ("Wayland" if os.environ.get("WAYLAND_DISPLAY") else "X11" if os.environ.get("DISPLAY") else ""),
                "Se requiere DISPLAY o WAYLAND_DISPLAY para la edición Desktop.",
                "Inicie GIDEON dentro de una sesión gráfica de usuario.", False,
            ))
            rows.append(DependencyStatus(
                "platform:pkg", "Gestor de paquetes Linux", "Plataforma", "Reparación automática de dependencias",
                bool(self.platform.package_manager), self.platform.package_manager,
                f"Distribución detectada: {self.platform.distro_name or self.platform.distro_id}",
                "APT, DNF/YUM, Pacman, Zypper, APK, XBPS o Portage.", False,
            ))
        elif self.platform.family == "windows" and self.platform.windows_server:
            rows.append(DependencyStatus(
                "platform:server-desktop", "Windows Server con Desktop Experience", "Plataforma", "Interfaz Qt + MSTSC",
                not self.platform.windows_server_core, "Desktop Experience" if not self.platform.windows_server_core else "Server Core",
                "Server Core puede ejecutar componentes backend, pero no la interfaz Desktop Qt/RDP.",
                "Use Windows Server con Desktop Experience para la consola gráfica.", False,
            ))

        python_ok = sys.version_info >= (3, 11)
        rows.append(DependencyStatus(
            "python", "Python", "Runtime", "GUI, backend y agentes", python_ok,
            platform.python_version(), f"Plataforma detectada: {self.platform.label}", "Instalar Python 3.11+", False,
        ))

        python_modules = (
            ("PySide6", "PySide6", "Interfaz Qt6 / panel de administración"),
            ("cryptography", "cryptography", "Gateway TLS, certificados, firma de paquetes y seguridad"),
            ("openpyxl", "openpyxl", "Exportación y reportes Excel"),
        )
        for module, name, required_for in python_modules:
            ok = importlib.util.find_spec(module) is not None
            rows.append(DependencyStatus(
                f"python:{module}", name, "Python", required_for, ok,
                "instalado" if ok else "", "Módulo Python requerido por el proyecto",
                f"{_python_cmd()} -m pip install {module}", True,
            ))

        rows.extend(self.gateway_dependencies())
        rows.extend(self.remote_access_dependencies())

        ssh = self._which("ssh.exe", "ssh")
        sftp = self._which("sftp.exe", "sftp")
        scp = self._which("scp.exe", "scp")
        rows.append(DependencyStatus("openssh", "OpenSSH Client", "Sistema", "SSH / SFTP / SCP", bool(ssh and sftp and scp),
                                     self._version(ssh) if ssh else "", "Se requieren ssh, sftp y scp", "Instalar OpenSSH Client", True))

        if self.platform.family == "windows":
            iexpress = self._which("iexpress.exe", "iexpress")
            if not iexpress:
                candidate = Path(os.environ.get("SystemRoot", r"C:\\Windows")) / "System32" / "iexpress.exe"
                if candidate.exists():
                    iexpress = str(candidate)
            inno = WindowsExePackager.inno_executable()
            rows.append(DependencyStatus(
                "inno-setup", "Inno Setup 6", "Compilación", "EXE Windows comercial con metadatos/version info/icono", bool(inno),
                str(inno or ""),
                "Backend recomendado para distribución comercial. Genera EXE directo; nunca MSI.",
                "Instale Inno Setup 6. Si winget está disponible, GIDEON puede instalar JRSoftware.InnoSetup.", True,
            ))
            rows.append(DependencyStatus(
                "iexpress", "Windows EXE packager (IExpress)", "Compilación", "Instalador GIDEON Agent .EXE", bool(iexpress),
                "incluido en Windows" if iexpress else "",
                "Genera directamente el instalador EXE autocontenido (payload ZIP + bootstrap elevado), sin instaladores intermedios.",
                "Componente integrado de Windows 10/11/Server Desktop Experience.", False,
            ))
            brand = BrandingRepository(self.app_root).load()
            signer = WindowsCodeSigningService()
            sign_tool = signer.signtool_executable()
            rows.append(DependencyStatus(
                "signtool", "Windows SDK SignTool", "Firma y marca", "Firma Authenticode del agente .EXE", bool(sign_tool),
                str(sign_tool or ""),
                "Firma SHA-256 y timestamp del ejecutable final. La firma mejora la confianza del editor, pero no sustituye la reputación del certificado.",
                "Instale Windows SDK / Windows 10-11 SDK y configure SignTool. También puede definir GIDEON_SIGNTOOL_PATH.", False,
            ))
            sign_ready = signer.readiness(brand, self.app_root)
            identity_ok = sign_ready.status in {"ready", "disabled"} or (not brand.signing.required and sign_ready.status == "missing-certificate")
            rows.append(DependencyStatus(
                "code-signing-identity", "Identidad de firma Authenticode", "Firma y marca", "Publisher confiable del EXE", identity_ok,
                brand.publisher_name, sign_ready.detail,
                "Configuración > Marca blanca y firma. Use preferentemente certificado corporativo/EV en almacén Windows; nunca se incluye la clave privada en el paquete.", False,
            ))
            winget = self._which("winget.exe", "winget")
            rows.append(DependencyStatus("winget", "Windows Package Manager (winget)", "Sistema", "Instalación automática de dependencias Windows",
                                         bool(winget), self._version(winget) if winget else "", "Proveedor de paquetes Windows",
                                         "Instalación de App Installer desde Microsoft Store", False))
            powershell = self._which("powershell.exe", "pwsh.exe", "powershell", "pwsh")
            rows.append(DependencyStatus("powershell", "PowerShell", "Sistema", "Instalación y administración de agentes Windows",
                                         bool(powershell), self._version(powershell) if powershell else "", "Requerido por scripts de instalación Windows",
                                         "Instalar PowerShell 7 / usar Windows PowerShell 5.1", False))
            wsl = self._which("wsl.exe", "wsl")
            wsl_ready = False
            wsl_detail = "WSL no está instalado. Solo se necesita para generar RPM desde Windows; DEB usa el backend Python nativo."
            if wsl:
                rc, out = self._run([wsl, "-l", "-q"], timeout=30)
                distros = [line.strip().replace("\x00", "") for line in out.splitlines() if line.strip().replace("\x00", "")]
                wsl_ready = rc == 0 and bool(distros)
                wsl_detail = ("Distribución WSL: " + distros[0]) if wsl_ready else "WSL está instalado, pero falta inicializar una distribución Linux."
            rows.append(DependencyStatus("wsl-linux-builder", "WSL Linux Builder", "Compilación", "Generación RPM desde Windows",
                                         wsl_ready, self._version(wsl) if wsl else "", wsl_detail,
                                         "Opcional: wsl --install -d Ubuntu. Las comprobaciones WSL se ejecutan ocultas, sin abrir consola.", False))
        elif self.platform.family == "linux":
            dpkg = self._which("dpkg-deb")
            rows.append(DependencyStatus(
                "deb-builder", "DEB builder adaptativo", "Compilación", "Generación DEB", True,
                self._version(dpkg) if dpkg else "Python nativo",
                "Usa dpkg-deb cuando existe; en cualquier otra distribución utiliza el constructor DEB Python incluido.",
                "Incluido con GIDEON Remote Control.", False,
            ))
            rpm_cmd = self._which("rpmbuild")
            file_cmd = self._which("file")
            rpm_ready = bool(rpm_cmd and file_cmd)
            missing_rpm = [name for name, present in (("rpmbuild", rpm_cmd), ("file", file_cmd)) if not present]
            rpm_detail = (
                f"Toolchain RPM listo para {self.platform.distro_name or 'Linux'}; gestor: {self.package_manager() or 'ninguno'}"
                if rpm_ready else
                "Faltan: " + ", ".join(missing_rpm) + ". GIDEON instalará también binutils/tar/gzip cuando corresponda."
            )
            rows.append(DependencyStatus("rpmbuild", "RPM build toolchain", "Compilación", "Generación RPM", rpm_ready,
                                         self._version(rpm_cmd or "rpmbuild"), rpm_detail,
                                         "Instalar rpm/rpm-build + file + binutils + tar + gzip", True))
            venv = self._which("python3") and importlib.util.find_spec("venv") is not None
            rows.append(DependencyStatus("python-venv", "Python venv", "Sistema", "Instaladores de agentes Linux/macOS", bool(venv), "",
                                         "Permite crear el entorno virtual del agente", "sudo apt-get install -y python3-venv", True))
        elif self.platform.family == "darwin":
            pkgbuild = self._which("pkgbuild")
            rows.append(DependencyStatus("pkgbuild", "pkgbuild", "Compilación", "Generación PKG", bool(pkgbuild),
                                         self._version(pkgbuild) if pkgbuild else "", "Parte de las herramientas de Apple",
                                         "xcode-select --install", True))

        return rows


    def remote_access_dependencies(self) -> list[DependencyStatus]:
        """Dependencies for VPN-only RDP access on Windows/Linux."""
        rows: list[DependencyStatus] = []
        try:
            from gideon_remote_access import SecureRdpLauncher
            status = SecureRdpLauncher().status()
        except Exception as exc:
            status = None
            detail = f"No se pudo validar el cliente RDP: {type(exc).__name__}: {exc}"
        else:
            detail = status.detail

        if self.platform.family == "windows":
            rows.append(DependencyStatus(
                "remote_access:client", "Microsoft Remote Desktop (MSTSC)", "Acceso remoto",
                "RDP seguro por VPN", bool(status and status.installed),
                status.executable if status and status.installed else "",
                detail,
                "mstsc.exe forma parte de Windows 10/11; repare los componentes del sistema si falta.", False,
            ))
            powershell = self._which("powershell.exe", "pwsh.exe", "powershell", "pwsh")
            route_ok = False
            route_detail = "PowerShell no disponible"
            if powershell:
                rc_route, out_route = self._run([
                    powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
                    "-Command", "$c=Get-Command Find-NetRoute -ErrorAction SilentlyContinue; if($c){'OK'} else {exit 3}",
                ], timeout=15)
                route_ok = rc_route == 0 and "OK" in out_route
                route_detail = "Find-NetRoute disponible" if route_ok else "El módulo NetTCPIP/Find-NetRoute no está disponible."
            rows.append(DependencyStatus(
                "remote_access:vpn-route", "NetTCPIP / Find-NetRoute", "Acceso remoto",
                "Verificación obligatoria de ruta por VPN", route_ok,
                self._version(powershell) if powershell else "",
                route_detail + " GIDEON lo usa para impedir conexiones RDP fuera de la VPN.",
                "Windows PowerShell + módulo NetTCPIP requerido.", False,
            ))
        elif self.platform.family == "linux":
            rows.append(DependencyStatus(
                "remote_access:client", "Remmina + plugin RDP", "Acceso remoto",
                "RDP seguro por VPN", bool(status and status.installed),
                status.executable if status and status.installed else "",
                detail,
                "Instalar remmina y el plugin RDP desde el gestor de paquetes.", True,
            ))
            ip_cmd = self._which("ip")
            rows.append(DependencyStatus(
                "remote_access:vpn-route", "iproute2", "Acceso remoto",
                "Verificación obligatoria de ruta por VPN", bool(ip_cmd),
                self._version(ip_cmd) if ip_cmd else "",
                "GIDEON usa 'ip route get' para verificar la interfaz VPN del destino.",
                "Instalar iproute2.", True,
            ))
        return rows


    def gateway_dependencies(self) -> list[DependencyStatus]:
        """Dependencias mínimas del Gateway Central HTTPS.

        El Gateway no requiere Apache, IIS ni PHP: usa el servidor HTTP de la
        biblioteca estándar de Python, TLS de OpenSSL y SQLite local.
        """
        rows: list[DependencyStatus] = []

        http_ok = importlib.util.find_spec("http.server") is not None
        rows.append(DependencyStatus(
            "gateway:http", "HTTP/HTTPS runtime (Python http.server)", "Gateway",
            "API HTTPS/PULL para agentes", http_ok,
            platform.python_version() if http_ok else "",
            "Servidor HTTP nativo de Python; no requiere PHP/Apache/IIS.",
            "Se instala junto con Python.", False,
        ))

        try:
            import ssl as ssl_module
            ssl_ok = hasattr(ssl_module, "SSLContext") and bool(getattr(ssl_module, "OPENSSL_VERSION", ""))
            tls12_ok = not hasattr(ssl_module, "TLSVersion") or hasattr(ssl_module.TLSVersion, "TLSv1_2")
            ssl_ok = bool(ssl_ok and tls12_ok)
            ssl_version = getattr(ssl_module, "OPENSSL_VERSION", "")
        except Exception:
            ssl_ok = False
            ssl_version = ""
        rows.append(DependencyStatus(
            "gateway:ssl", "TLS / OpenSSL", "Gateway",
            "HTTPS seguro entre Gateway y agentes", ssl_ok,
            ssl_version,
            "Se requiere SSLContext con soporte TLS 1.2 o superior.",
            "Reinstalar/actualizar Python con soporte OpenSSL.", False,
        ))

        try:
            import sqlite3 as sqlite_module
            sqlite_ok = True
            sqlite_version = sqlite_module.sqlite_version
        except Exception:
            sqlite_ok = False
            sqlite_version = ""
        rows.append(DependencyStatus(
            "gateway:sqlite", "SQLite", "Gateway",
            "Inventario de agentes, colas, releases y resultados", sqlite_ok,
            sqlite_version,
            "Motor embebido; no requiere instalar un servidor SQL adicional.",
            "Se instala junto con Python.", False,
        ))

        gateway_script = self.app_root / "gideon_agent_gateway.py"
        gateway_config = GATEWAY_CONFIG_PATH
        # The Gateway config is version-independent runtime state and may not
        # exist until the first bootstrap.  Only the service code is a packaged
        # dependency; configuration is created/migrated automatically.
        files_ok = gateway_script.is_file()
        rows.append(DependencyStatus(
            "gateway:files", "Componentes del Gateway GIDEON", "Gateway",
            "Servicio central y configuración", files_ok,
            "incluidos" if files_ok else "",
            f"Servicio: {gateway_script.name}; configuración: {gateway_config}",
            "Restaurar los archivos del paquete GIDEON Remote Control.", False,
        ))
        return rows

    def gateway_ready(self) -> tuple[bool, list[DependencyStatus]]:
        """Valida solo lo necesario para iniciar el Gateway, sin escanear toolchains."""
        deps = self.gateway_dependencies()
        python_ok = sys.version_info >= (3, 11)
        deps.insert(0, DependencyStatus(
            "python", "Python 3.11+", "Gateway",
            "Runtime del servicio Gateway", python_ok, platform.python_version(),
            "GIDEON Remote Control requiere Python 3.11 o superior.",
            "Instalar Python 3.11+.", False,
        ))
        crypto_ok = importlib.util.find_spec("cryptography") is not None
        deps.insert(1, DependencyStatus(
            "python:cryptography", "cryptography", "Gateway",
            "Generación de CA/certificado TLS y seguridad", crypto_ok,
            "instalado" if crypto_ok else "",
            "Módulo externo requerido para el bootstrap TLS.",
            f"{_python_cmd()} -m pip install cryptography", True,
        ))
        return all(item.installed for item in deps), deps

    def install_python_dependencies(self) -> tuple[bool, str]:
        requirements = self.app_root / "requirements-runtime.txt"
        pip = [sys.executable, "-m", "pip", "install", "-r", str(requirements)]
        rc, output = self._run(pip, timeout=600)
        return rc == 0, output[-8000:]

    def install_dependency(self, key: str) -> tuple[bool, str]:
        family = self.platform.family
        if key == "remote_access:client" and family == "linux":
            return self.install_remmina()
        if key == "remote_access:vpn-route" and family == "linux":
            return self._install_linux("iproute2")
        if key.startswith("python:"):
            return self.install_python_dependencies()
        if key == "inno-setup" and family == "windows":
            # Idempotent dependency installation: never ask winget to upgrade a tool
            # that GIDEON can already use.  This avoids treating winget's
            # "No available upgrade found" as an installation failure.
            existing = WindowsExePackager.inno_executable()
            if existing:
                return True, f"Inno Setup ya está instalado y disponible para GIDEON: {existing}"

            winget = self._which("winget.exe", "winget")
            if not winget:
                return False, (
                    "Winget no está disponible y GIDEON no encontró ISCC.exe. "
                    "Instale Inno Setup 6 o defina GIDEON_INNO_ISCC_PATH con la ruta completa a ISCC.exe."
                )

            rc, out = self._run([
                winget, "install", "--id", "JRSoftware.InnoSetup", "-e", "--source", "winget",
                "--accept-package-agreements", "--accept-source-agreements", "--silent",
                "--disable-interactivity"
            ], timeout=1200)

            # Always re-discover after winget.  Some winget versions return a non-zero
            # status when the requested package is already at the newest version.
            detected = WindowsExePackager.inno_executable()
            if detected:
                prefix = "Inno Setup quedó disponible" if rc == 0 else "Inno Setup ya estaba instalado"
                return True, f"{prefix}: {detected}\n\n{out}".strip()

            normalized = out.casefold()
            already_installed = any(marker in normalized for marker in (
                "existing package already installed",
                "no available upgrade found",
                "no newer package versions are available",
                "ya está instalado",
                "no hay ninguna actualización disponible",
            ))
            if already_installed:
                return False, (
                    "Winget confirma que Inno Setup está instalado, pero GIDEON no pudo localizar ISCC.exe. "
                    "Abra Configuración > Marca blanca/firma o defina GIDEON_INNO_ISCC_PATH con la ruta completa, "
                    "por ejemplo C:\\Program Files (x86)\\Inno Setup 6\\ISCC.exe.\n\n" + out
                )
            return rc == 0, out
        if key == "openssh":
            if family == "windows":
                powershell = self._which("powershell.exe", "pwsh.exe", "powershell", "pwsh")
                if not powershell:
                    return False, "PowerShell no está disponible para instalar OpenSSH."
                rc, out = self._run([
                    powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
                    "-ExecutionPolicy", "Bypass", "-Command",
                    "Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0 | Out-String",
                ], timeout=600)
                return rc == 0, out
            if family == "linux":
                manager = self.package_manager()
                package_by_manager = {
                    "apt-get": "openssh-client",
                    "dnf": "openssh-clients",
                    "yum": "openssh-clients",
                    "pacman": "openssh",
                    "zypper": "openssh-clients",
                    "apk": "openssh-client-default",
                    "xbps-install": "openssh",
                    "emerge": "net-misc/openssh",
                }
                package = package_by_manager.get(manager or "")
                if not package:
                    return False, "No se pudo resolver el paquete OpenSSH para esta distribución."
                return self._install_linux(package)
        if key == "dpkg-deb" and family == "linux":
            manager = self.package_manager()
            pkg = "dpkg-dev" if manager == "apt-get" else "dpkg"
            return self._install_linux(pkg)
        if key == "rpmbuild" and family == "linux":
            manager = self.package_manager()
            packages_by_manager = {
                "apt-get": ["rpm", "file", "binutils", "tar", "gzip"],
                "dnf": ["rpm-build", "file", "binutils", "tar", "gzip"],
                "yum": ["rpm-build", "file", "binutils", "tar", "gzip"],
                "zypper": ["rpm-build", "file", "binutils", "tar", "gzip"],
                "pacman": ["rpm-tools", "file", "binutils", "tar", "gzip"],
                "apk": ["rpm", "file", "binutils", "tar", "gzip"],
                "xbps-install": ["rpm", "file", "binutils", "tar", "gzip"],
                "emerge": ["app-arch/rpm", "sys-apps/file", "sys-devel/binutils", "app-arch/tar", "app-arch/gzip"],
            }
            packages = packages_by_manager.get(manager or "")
            if not packages:
                return False, "No se pudo resolver el toolchain RPM para esta distribución."
            return self._install_linux(packages)
        if key == "python-venv" and family == "linux":
            manager = self.package_manager()
            pkg = {
                "apt-get": "python3-venv", "dnf": "python3", "yum": "python3",
                "pacman": "python", "zypper": "python3", "apk": "python3",
                "xbps-install": "python3", "emerge": "dev-lang/python",
            }.get(manager or "", "python3")
            return self._install_linux(pkg)
        if key == "pkgbuild" and family == "darwin":
            return self._run(["xcode-select", "--install"], timeout=60)[0:2]
        return False, "No existe un instalador automático para esta dependencia en este sistema."

    def install_remmina(self) -> tuple[bool, str]:
        """Install the Linux RDP client using the native distribution manager.

        No terminal emulator is opened. Package managers run in the background;
        privilege escalation is delegated to sudo/pkexec when available.
        """
        manager = self.package_manager()
        package_sets: dict[str, list[str]] = {
            "apt-get": ["remmina", "remmina-plugin-rdp"],
            "dnf": ["remmina", "freerdp"],
            "yum": ["remmina", "freerdp"],
            "pacman": ["remmina", "freerdp"],
            "zypper": ["remmina", "freerdp"],
            "apk": ["remmina", "freerdp"],
            "xbps-install": ["remmina", "freerdp"],
            "emerge": ["net-misc/remmina"],
        }
        packages = package_sets.get(manager or "")
        if not manager or not packages:
            # Last-resort cross-distro path when Flatpak is already managed by IT.
            flatpak = self._which("flatpak")
            if flatpak:
                rc, out = self._run([flatpak, "install", "-y", "flathub", "org.remmina.Remmina"], timeout=1200)
                return rc == 0, out
            return False, "No se encontró un gestor compatible (APT/DNF/YUM/Pacman/Zypper/APK/XBPS/Portage) ni Flatpak."
        if manager == "apt-get":
            rc, out = self._run_privileged(["apt-get", "update"], timeout=900)
            if rc != 0:
                return False, out
        command = self._package_install_command(manager, packages)
        rc, out = self._run_privileged(command, timeout=1200)
        return rc == 0, out

    def package_manager(self) -> str | None:
        detected = getattr(self, "platform", None)
        if detected and detected.package_manager:
            return detected.package_manager
        for name in ("apt-get", "dnf", "yum", "pacman", "zypper", "apk", "xbps-install", "emerge"):
            if self._which(name):
                return name
        return None

    @staticmethod
    def _package_install_command(manager: str, packages: list[str]) -> list[str]:
        if manager == "apt-get":
            return ["apt-get", "install", "-y", *packages]
        if manager in {"dnf", "yum"}:
            return [manager, "install", "-y", *packages]
        if manager == "pacman":
            return ["pacman", "-Sy", "--noconfirm", "--needed", *packages]
        if manager == "zypper":
            return ["zypper", "--non-interactive", "install", *packages]
        if manager == "apk":
            return ["apk", "add", "--no-progress", *packages]
        if manager == "xbps-install":
            return ["xbps-install", "-Sy", *packages]
        if manager == "emerge":
            return ["emerge", "--quiet-build=y", *packages]
        return [manager, *packages]

    def _run_privileged(self, command: list[str], *, timeout: int = 900) -> tuple[int, str]:
        """Run a system package command without opening a terminal window.

        On Linux an existing root session is used directly. Otherwise GIDEON first
        prefers passwordless sudo; if unavailable it uses pkexec, whose graphical
        authentication dialog may be shown by the OS but no shell/terminal is opened.
        """
        if os.name == "nt" or getattr(os, "geteuid", lambda: 1)() == 0:
            return self._run(command, timeout=timeout)
        sudo = self._which("sudo")
        if sudo:
            rc, _ = self._run([sudo, "-n", "true"], timeout=10)
            if rc == 0:
                return self._run([sudo, "-n", *command], timeout=timeout)
        pkexec = self._which("pkexec")
        if pkexec:
            return self._run([pkexec, *command], timeout=timeout)
        return 126, "Se requieren privilegios administrativos. Configure sudo no interactivo para GIDEON o instale polkit/pkexec."

    def _run_sudo(self, command: list[str]) -> tuple[int, str]:
        # Compatibility alias used by older code paths.
        return self._run_privileged(command, timeout=900)

    def _install_linux(self, package: str | list[str]) -> tuple[bool, str]:
        manager = self.package_manager()
        if not manager:
            return False, f"No se encontró gestor de paquetes para instalar {package}."
        packages = [package] if isinstance(package, str) else list(package)
        rc, out = self._run_privileged(self._package_install_command(manager, packages), timeout=1200)
        return rc == 0, out


def _python_cmd() -> str:
    return sys.executable
