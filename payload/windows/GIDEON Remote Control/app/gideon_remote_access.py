from __future__ import annotations

from gideon_common.observability import best_effort_warning

import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol

from gideon_infrastructure.subprocess_utils import popen_hidden, run_hidden


DEFAULT_VPN_PATTERNS: tuple[str, ...] = (
    "vpn",
    "forti",
    "fortinet",
    "anyconnect",
    "secure client",
    "globalprotect",
    "palo alto",
    "wireguard",
    "openvpn",
    "tap",
    "tun",
    "pulse",
    "juniper",
    "check point",
    "sonicwall",
    "zscaler",
)

DEFAULT_ALLOWED_CIDRS: tuple[str, ...] = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "fc00::/7",
)


@dataclass(frozen=True)
class ClientStatus:
    platform: str
    client: str
    installed: bool
    executable: str = ""
    detail: str = ""


@dataclass(frozen=True)
class VpnStatus:
    active: bool
    interfaces: tuple[str, ...] = ()
    detail: str = ""


@dataclass(frozen=True)
class NetworkInterfaceInfo:
    alias: str
    description: str = ""
    status: str = ""
    interface_index: int = 0
    addresses: tuple[str, ...] = ()
    vpn_candidate: bool = False


@dataclass(frozen=True)
class RouteStatus:
    valid: bool
    interface: str = ""
    source_address: str = ""
    resolved_address: str = ""
    detail: str = ""
    interface_index: int = 0
    interface_description: str = ""


@dataclass(frozen=True)
class RemoteHostSettings:
    rdp_port: int = 3389
    username: str = ""
    domain: str = ""
    mode: str = "vpn_rdp"  # vpn_rdp | vpn_ssh_rdp
    fullscreen: bool = True
    clipboard: bool = False
    printers: bool = False
    drives: bool = False
    smartcards: bool = False


@dataclass(frozen=True)
class SecurityPolicy:
    require_vpn: bool = True
    require_route_over_vpn: bool = True
    block_public_targets: bool = True
    allowed_cidrs: tuple[str, ...] = DEFAULT_ALLOWED_CIDRS
    vpn_interface_patterns: tuple[str, ...] = DEFAULT_VPN_PATTERNS
    trusted_vpn_interfaces: tuple[str, ...] = ()
    default_rdp_port: int = 3389
    connect_timeout_seconds: int = 5


@dataclass(frozen=True)
class SshTunnelConfig:
    enabled: bool = True
    jump_host: str = ""
    jump_port: int = 22
    username: str = ""
    private_key: str = ""
    known_hosts: str = ""
    strict_host_key_checking: bool = True
    identities_only: bool = True
    server_alive_interval: int = 30
    server_alive_count_max: int = 3


@dataclass(frozen=True)
class AccessConfig:
    schema_version: int = 1
    policy: SecurityPolicy = field(default_factory=SecurityPolicy)
    ssh_tunnel: SshTunnelConfig = field(default_factory=SshTunnelConfig)
    defaults: RemoteHostSettings = field(default_factory=RemoteHostSettings)
    host_overrides: dict[str, dict[str, Any]] = field(default_factory=dict)


class RemoteAccessRepository(Protocol):
    def load(self) -> AccessConfig: ...
    def save(self, config: AccessConfig) -> None: ...


class JsonRemoteAccessRepository:
    """Atomic JSON repository. It never stores passwords or session secrets."""

    def __init__(self, path: Path):
        self.path = Path(path)

    @staticmethod
    def _policy(raw: dict[str, Any]) -> SecurityPolicy:
        defaults = SecurityPolicy()
        return SecurityPolicy(
            # Security invariants: these three controls are intentionally not configurable.
            require_vpn=True,
            require_route_over_vpn=True,
            block_public_targets=True,
            allowed_cidrs=tuple(str(x).strip() for x in raw.get("allowed_cidrs", defaults.allowed_cidrs) if str(x).strip()),
            vpn_interface_patterns=tuple(str(x).strip().lower() for x in raw.get("vpn_interface_patterns", defaults.vpn_interface_patterns) if str(x).strip()),
            trusted_vpn_interfaces=tuple(str(x).strip().lower() for x in raw.get("trusted_vpn_interfaces", defaults.trusted_vpn_interfaces) if str(x).strip()),
            default_rdp_port=max(1, min(65535, int(raw.get("default_rdp_port", defaults.default_rdp_port)))),
            connect_timeout_seconds=max(1, min(30, int(raw.get("connect_timeout_seconds", defaults.connect_timeout_seconds)))),
        )

    @staticmethod
    def _ssh(raw: dict[str, Any]) -> SshTunnelConfig:
        defaults = SshTunnelConfig()
        return SshTunnelConfig(
            enabled=bool(raw.get("enabled", defaults.enabled)),
            jump_host=str(raw.get("jump_host") or "").strip(),
            jump_port=max(1, min(65535, int(raw.get("jump_port", defaults.jump_port)))),
            username=str(raw.get("username") or "").strip(),
            private_key=str(raw.get("private_key") or "").strip(),
            known_hosts=str(raw.get("known_hosts") or "").strip(),
            strict_host_key_checking=True,
            identities_only=True,
            server_alive_interval=max(10, min(300, int(raw.get("server_alive_interval", defaults.server_alive_interval)))),
            server_alive_count_max=max(1, min(10, int(raw.get("server_alive_count_max", defaults.server_alive_count_max)))),
        )

    @staticmethod
    def _host_settings(raw: dict[str, Any]) -> RemoteHostSettings:
        defaults = RemoteHostSettings()
        mode = str(raw.get("mode") or defaults.mode).strip().lower()
        if mode not in {"vpn_rdp", "vpn_ssh_rdp"}:
            mode = defaults.mode
        return RemoteHostSettings(
            rdp_port=max(1, min(65535, int(raw.get("rdp_port", defaults.rdp_port)))),
            username=str(raw.get("username") or "").strip(),
            domain=str(raw.get("domain") or "").strip(),
            mode=mode,
            fullscreen=bool(raw.get("fullscreen", defaults.fullscreen)),
            clipboard=bool(raw.get("clipboard", defaults.clipboard)),
            printers=bool(raw.get("printers", defaults.printers)),
            drives=bool(raw.get("drives", defaults.drives)),
            smartcards=bool(raw.get("smartcards", defaults.smartcards)),
        )

    def load(self) -> AccessConfig:
        if not self.path.exists():
            config = AccessConfig()
            self.save(config)
            return config
        raw = json.loads(self.path.read_text(encoding="utf-8-sig"))
        if not isinstance(raw, dict):
            raise RuntimeError("remote_access.json inválido")
        overrides = raw.get("host_overrides") or {}
        if not isinstance(overrides, dict):
            overrides = {}
        return AccessConfig(
            schema_version=int(raw.get("schema_version") or 1),
            policy=self._policy(dict(raw.get("policy") or {})),
            ssh_tunnel=self._ssh(dict(raw.get("ssh_tunnel") or {})),
            defaults=self._host_settings(dict(raw.get("defaults") or {})),
            host_overrides={str(k): dict(v) for k, v in overrides.items() if isinstance(v, dict)},
        )

    def save(self, config: AccessConfig) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = asdict(config)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.path)


class VpnDetector:
    """Detects active VPN interfaces and the interface chosen for a target route."""

    def __init__(self, policy: SecurityPolicy):
        self.policy = policy

    def _is_vpn_name(self, name: str) -> bool:
        normalized = str(name or "").strip().lower()
        if not normalized:
            return False
        if normalized in self.policy.trusted_vpn_interfaces:
            return True
        return any(pattern and pattern in normalized for pattern in self.policy.vpn_interface_patterns)

    @staticmethod
    def _run(command: list[str], timeout: int = 10) -> tuple[int, str]:
        try:
            proc = run_hidden(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
            return proc.returncode, ((proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")).strip()
        except Exception as exc:
            return 1, f"{type(exc).__name__}: {exc}"

    def interfaces(self) -> tuple[NetworkInterfaceInfo, ...]:
        """Enumerate interfaces and expose what GIDEON actually detected.

        The UI consumes this list so operators can select a detected adapter
        instead of typing aliases by hand. Manual aliases remain a contingency.
        """
        rows: list[NetworkInterfaceInfo] = []
        if os.name == "nt":
            powershell = shutil.which("powershell.exe") or shutil.which("pwsh.exe") or shutil.which("powershell")
            if not powershell:
                return ()
            script = r'''$ErrorActionPreference='SilentlyContinue'
$out=@()
$adapters=@(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue)
foreach($a in $adapters){
  $ips=@(Get-NetIPAddress -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue | Where-Object {$_.AddressState -eq 'Preferred'} | Select-Object -ExpandProperty IPAddress)
  $out += [PSCustomObject]@{
    InterfaceAlias=[string]$a.Name;
    InterfaceDescription=[string]$a.InterfaceDescription;
    Status=[string]$a.Status;
    InterfaceIndex=[int]$a.ifIndex;
    Addresses=@($ips)
  }
}
if($out.Count -eq 0){
  $cfg=@(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction SilentlyContinue)
  foreach($c in $cfg){
    $name=[string]$c.Description
    $out += [PSCustomObject]@{InterfaceAlias=$name;InterfaceDescription=$name;Status='Up';InterfaceIndex=[int]$c.InterfaceIndex;Addresses=@($c.IPAddress)}
  }
}
@($out) | ConvertTo-Json -Compress -Depth 4'''
            rc, out = self._run([powershell, "-NoProfile", "-NonInteractive", "-Command", script])
            if rc != 0:
                return ()
            try:
                data = json.loads(out or "[]")
                raw_rows = [data] if isinstance(data, dict) else list(data or [])
            except Exception:
                return ()
            for row in raw_rows:
                if not isinstance(row, dict):
                    continue
                alias = str(row.get("InterfaceAlias") or "").strip()
                desc = str(row.get("InterfaceDescription") or "").strip()
                status = str(row.get("Status") or "").strip()
                try:
                    idx = int(row.get("InterfaceIndex") or 0)
                except Exception:
                    idx = 0
                addrs_raw = row.get("Addresses") or []
                if isinstance(addrs_raw, str):
                    addrs_raw = [addrs_raw]
                addrs = tuple(str(x).strip() for x in addrs_raw if str(x).strip())
                if alias:
                    rows.append(NetworkInterfaceInfo(alias, desc, status, idx, addrs, self._is_vpn_name(alias) or self._is_vpn_name(desc)))
        elif sys.platform.startswith("linux"):
            ip = shutil.which("ip")
            if not ip:
                return ()
            rc, out = self._run([ip, "-j", "address", "show"], timeout=10)
            if rc == 0:
                try:
                    raw_rows = json.loads(out or "[]")
                except Exception:
                    raw_rows = []
                for row in raw_rows if isinstance(raw_rows, list) else []:
                    alias = str(row.get("ifname") or "").strip()
                    status = str(row.get("operstate") or "").strip()
                    try:
                        idx = int(row.get("ifindex") or 0)
                    except Exception:
                        idx = 0
                    addrs = tuple(str(x.get("local") or "").strip() for x in row.get("addr_info", []) if isinstance(x, dict) and str(x.get("local") or "").strip())
                    if alias:
                        rows.append(NetworkInterfaceInfo(alias, alias, status, idx, addrs, self._is_vpn_name(alias)))
        return tuple(sorted(rows, key=lambda x: (not x.vpn_candidate, x.alias.casefold())))

    def active(self) -> VpnStatus:
        interfaces = self.interfaces()
        vpns = tuple(sorted({row.alias for row in interfaces if row.vpn_candidate and row.status.casefold() not in {"down", "disabled", "notpresent"}}))
        detail = "VPN activa" if vpns else "No se detectó una interfaz VPN permitida."
        if interfaces:
            detail += " Interfaces detectadas: " + ", ".join(row.alias for row in interfaces[:8])
        return VpnStatus(bool(vpns), vpns, detail)

    def route_to(self, address: str) -> RouteStatus:
        description = ""
        interface_index = 0
        if os.name == "nt":
            powershell = shutil.which("powershell.exe") or shutil.which("pwsh.exe") or shutil.which("powershell")
            if not powershell:
                return RouteStatus(False, detail="PowerShell no está disponible.")
            safe = address.replace("'", "''")
            script = (
                "$ErrorActionPreference='Stop'; "
                f"$r=Find-NetRoute -RemoteIPAddress '{safe}' | Select-Object -First 1; "
                "if(-not $r){throw 'Find-NetRoute no devolvió una ruta'}; "
                "$idx=0;$a='';$d='';$src=''; "
                "try{$idx=[int]$r.NetRoute.InterfaceIndex}catch{}; "
                "if(-not $idx){try{$idx=[int]$r.InterfaceIndex}catch{}}; "
                "try{$a=[string]$r.NetRoute.InterfaceAlias}catch{}; "
                "if(-not $a){try{$a=[string]$r.InterfaceAlias}catch{}}; "
                "try{$src=[string]$r.IPAddress.IPAddress}catch{}; "
                "if(-not $src){try{$src=[string]$r.IPAddress}catch{}}; "
                "if($idx){ "
                "  $ipif=Get-NetIPInterface -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1; "
                "  if((-not $a) -and $ipif){$a=[string]$ipif.InterfaceAlias}; "
                "  $ad=Get-NetAdapter -InterfaceIndex $idx -ErrorAction SilentlyContinue | Select-Object -First 1; "
                "  if((-not $a) -and $ad){$a=[string]$ad.Name}; if($ad){$d=[string]$ad.InterfaceDescription}; "
                "}; "
                "if((-not $src) -and $idx){$src=(Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 -AddressState Preferred -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty IPAddress)}; "
                "$o=[PSCustomObject]@{InterfaceAlias=$a;InterfaceDescription=$d;InterfaceIndex=$idx;SourceAddress=$src}; "
                "$o | ConvertTo-Json -Compress"
            )
            rc, out = self._run([powershell, "-NoProfile", "-NonInteractive", "-Command", script])
            if rc != 0:
                return RouteStatus(False, resolved_address=address, detail=out or "No se pudo resolver la ruta.")
            try:
                data = json.loads(out)
                interface = str(data.get("InterfaceAlias") or "").strip()
                description = str(data.get("InterfaceDescription") or "").strip()
                source = str(data.get("SourceAddress") or "").strip()
                interface_index = int(data.get("InterfaceIndex") or 0)
            except Exception:
                return RouteStatus(False, resolved_address=address, detail="Respuesta de ruta Windows inválida.")
        elif sys.platform.startswith("linux"):
            ip = shutil.which("ip")
            if not ip:
                return RouteStatus(False, resolved_address=address, detail="El comando ip no está disponible.")
            rc, out = self._run([ip, "route", "get", address])
            if rc != 0:
                return RouteStatus(False, resolved_address=address, detail=out)
            match_dev = re.search(r"\bdev\s+(\S+)", out)
            match_src = re.search(r"\bsrc\s+(\S+)", out)
            interface = match_dev.group(1) if match_dev else ""
            source = match_src.group(1) if match_src else ""
            for row in self.interfaces():
                if row.alias == interface:
                    interface_index = row.interface_index
                    description = row.description
                    break
        else:
            return RouteStatus(False, resolved_address=address, detail="Plataforma no soportada.")

        detected_match = None
        if interface_index:
            detected_match = next((row for row in self.interfaces() if row.interface_index == interface_index), None)
            if detected_match:
                interface = interface or detected_match.alias
                description = description or detected_match.description
        valid = self._is_vpn_name(interface) or self._is_vpn_name(description) or bool(detected_match and detected_match.vpn_candidate)
        detail = f"Ruta por {interface or ('ifIndex '+str(interface_index) if interface_index else 'interfaz desconocida')}"
        if description and description.casefold() != interface.casefold():
            detail += f" ({description})"
        if not valid:
            detail += "; no coincide con la política VPN. Seleccione la interfaz detectada como confiable si corresponde realmente a su VPN."
        return RouteStatus(valid, interface, source, address, detail, interface_index, description)


class SecureRdpLauncher:
    """Platform client adapter: MSTSC on Windows, Remmina on Linux."""

    def status(self) -> ClientStatus:
        if os.name == "nt":
            exe = shutil.which("mstsc.exe") or shutil.which("mstsc")
            if not exe:
                system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
                candidate = system_root / "System32" / "mstsc.exe"
                if candidate.exists():
                    exe = str(candidate)
            return ClientStatus("windows", "Microsoft Remote Desktop (MSTSC)", bool(exe), str(exe or ""),
                                "Cliente RDP integrado de Windows." if exe else "mstsc.exe no está disponible.")
        if sys.platform.startswith("linux"):
            exe = shutil.which("remmina")
            if exe:
                try:
                    proc = run_hidden(
                        [exe, "--full-version"], capture_output=True, text=True, encoding="utf-8",
                        errors="replace", timeout=10,
                    )
                    details = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
                    plugin_ok = bool(re.search(r"\bRDP\b", details, flags=re.IGNORECASE))
                except Exception as exc:
                    return ClientStatus("linux", "Remmina", False, str(exe), f"No se pudo validar el plugin RDP: {exc}")
                if not plugin_ok:
                    return ClientStatus("linux", "Remmina", False, str(exe), "Remmina está instalado, pero no se detectó el plugin RDP.")
                return ClientStatus("linux", "Remmina + RDP", True, str(exe), "Cliente Remmina con plugin RDP disponible.")

            flatpak = shutil.which("flatpak")
            if flatpak:
                try:
                    probe = run_hidden(
                        [flatpak, "info", "org.remmina.Remmina"], capture_output=True, text=True,
                        encoding="utf-8", errors="replace", timeout=15,
                    )
                    if probe.returncode == 0:
                        return ClientStatus(
                            "linux", "Remmina + RDP (Flatpak)", True, str(flatpak),
                            "Remmina se ejecutará mediante Flatpak; útil en distribuciones sin paquete nativo.",
                        )
                except Exception as exc:
                    best_effort_warning("No se pudo inspeccionar disponibilidad Flatpak/Remmina", exc)
            return ClientStatus("linux", "Remmina", False, "", "Remmina no está instalado (paquete nativo o Flatpak).")
        return ClientStatus(sys.platform, "RDP", False, "", "Solo Windows (MSTSC) y Linux (Remmina) están soportados.")

    @staticmethod
    def _delayed_delete(path: Path, delay: float = 15.0) -> None:
        def cleanup() -> None:
            time.sleep(delay)
            try:
                path.unlink(missing_ok=True)
            except Exception as exc:
                best_effort_warning(f"No se pudo limpiar perfil RDP temporal {path}", exc)
        threading.Thread(target=cleanup, name="gideon-rdp-profile-cleanup", daemon=True).start()

    def launch(self, host: str, settings: RemoteHostSettings) -> subprocess.Popen[str]:
        status = self.status()
        if not status.installed:
            raise RuntimeError(status.detail)
        if os.name == "nt":
            return self._launch_mstsc(status.executable, host, settings)
        if sys.platform.startswith("linux"):
            return self._launch_remmina(status.executable, host, settings)
        raise RuntimeError("Plataforma RDP no soportada.")

    def _launch_mstsc(self, executable: str, host: str, settings: RemoteHostSettings) -> subprocess.Popen[str]:
        temp_dir = Path(tempfile.gettempdir()) / "gideon-remote-access"
        temp_dir.mkdir(parents=True, exist_ok=True)
        profile = temp_dir / f"gideon-{os.getpid()}-{int(time.time() * 1000)}.rdp"
        username = settings.username
        if settings.domain and username and "\\" not in username and "@" not in username:
            username = f"{settings.domain}\\{username}"
        lines = [
            f"full address:s:{host}:{settings.rdp_port}",
            f"screen mode id:i:{2 if settings.fullscreen else 1}",
            "authentication level:i:2",
            "enablecredsspsupport:i:1",
            "negotiate security layer:i:1",
            "prompt for credentials:i:1",
            "promptcredentialonce:i:0",
            "disableconnectionsharing:i:1",
            "gatewayusagemethod:i:0",
            f"redirectclipboard:i:{1 if settings.clipboard else 0}",
            f"redirectprinters:i:{1 if settings.printers else 0}",
            f"redirectsmartcards:i:{1 if settings.smartcards else 0}",
            "redirectcomports:i:0",
            "redirectposdevices:i:0",
            f"drivestoredirect:s:{'*' if settings.drives else ''}",
        ]
        if username:
            lines.append(f"username:s:{username}")
        profile.write_text("\r\n".join(lines) + "\r\n", encoding="utf-8")
        self._delayed_delete(profile)
        return subprocess.Popen([executable, str(profile)], creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))

    def _launch_remmina(self, executable: str, host: str, settings: RemoteHostSettings) -> subprocess.Popen[str]:
        temp_dir = Path(tempfile.gettempdir()) / "gideon-remote-access"
        temp_dir.mkdir(parents=True, exist_ok=True)
        profile = temp_dir / f"gideon-{os.getpid()}-{int(time.time() * 1000)}.remmina"
        profile.write_text(
            "\n".join([
                "[remmina]",
                "name=GIDEON Remote Access",
                "protocol=RDP",
                f"server={host}:{settings.rdp_port}",
                f"username={settings.username}",
                f"domain={settings.domain}",
                "password=",
                "security=nla",
                "cert_ignore=0",
                "network=lan",
                "colordepth=32",
                f"disableclipboard={0 if settings.clipboard else 1}",
                f"shareprinter={1 if settings.printers else 0}",
                f"sharesmartcard={1 if settings.smartcards else 0}",
                "sharefolder=" if not settings.drives else "sharefolder=$HOME",
                f"viewmode={1 if settings.fullscreen else 0}",
                "",
            ]),
            encoding="utf-8",
        )
        try:
            profile.chmod(0o600)
        except Exception as exc:
            best_effort_warning(f"No se pudo restringir permisos del perfil RDP {profile}", exc)
        self._delayed_delete(profile)
        if Path(executable).name.casefold().startswith("flatpak"):
            return subprocess.Popen([executable, "run", "org.remmina.Remmina", "-c", str(profile)], start_new_session=True)
        return subprocess.Popen([executable, "-c", str(profile)], start_new_session=True)


class SshTunnelService:
    """OpenSSH local forward with key-only authentication and pinned host keys."""

    def __init__(self, config: SshTunnelConfig):
        self.config = config

    @staticmethod
    def _free_local_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])

    @staticmethod
    def _wait_port(port: int, process: subprocess.Popen[str], timeout: float = 8.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if process.poll() is not None:
                return False
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.4):
                    return True
            except OSError:
                time.sleep(0.2)
        return False

    def open(self, target_host: str, target_port: int) -> tuple[subprocess.Popen[str], int]:
        cfg = self.config
        ssh = shutil.which("ssh.exe") or shutil.which("ssh")
        if not ssh:
            raise RuntimeError("OpenSSH Client no está instalado.")
        if not cfg.enabled:
            raise RuntimeError("El túnel SSH está deshabilitado por configuración.")
        if not cfg.jump_host or not cfg.username:
            raise RuntimeError("Configure Jump Host y usuario SSH.")
        key = Path(os.path.expandvars(os.path.expanduser(cfg.private_key))) if cfg.private_key else None
        known_hosts = Path(os.path.expandvars(os.path.expanduser(cfg.known_hosts))) if cfg.known_hosts else None
        if not key or not key.is_file():
            raise RuntimeError("La clave privada SSH configurada no existe.")
        if not known_hosts or not known_hosts.is_file():
            raise RuntimeError("known_hosts no existe. Registre y verifique previamente la huella del Jump Host.")
        ssh_keygen = shutil.which("ssh-keygen.exe") or shutil.which("ssh-keygen")
        if not ssh_keygen:
            raise RuntimeError("ssh-keygen no está disponible para verificar known_hosts.")
        lookup = cfg.jump_host if cfg.jump_port == 22 else f"[{cfg.jump_host}]:{cfg.jump_port}"
        verify = run_hidden(
            [ssh_keygen, "-F", lookup, "-f", str(known_hosts)],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10,
        )
        if verify.returncode != 0 or not (verify.stdout or "").strip():
            raise RuntimeError("El Jump Host no tiene una huella previamente verificada en known_hosts. GIDEON bloquea TOFU/accept-new para este módulo.")

        local_port = self._free_local_port()
        command = [
            ssh,
            "-N",
            "-T",
            "-p", str(cfg.jump_port),
            "-i", str(key),
            "-L", f"127.0.0.1:{local_port}:{target_host}:{target_port}",
            "-o", "BatchMode=yes",
            "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            "-o", "PubkeyAuthentication=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={known_hosts}",
            "-o", "IdentitiesOnly=yes",
            "-o", "ExitOnForwardFailure=yes",
            "-o", "ClearAllForwardings=yes",
            "-o", f"ServerAliveInterval={cfg.server_alive_interval}",
            "-o", f"ServerAliveCountMax={cfg.server_alive_count_max}",
            "-o", "LogLevel=ERROR",
            f"{cfg.username}@{cfg.jump_host}",
        ]
        process = popen_hidden(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if not self._wait_port(local_port, process):
            stderr = ""
            try:
                _, stderr = process.communicate(timeout=1)
            except Exception:
                process.terminate()
            raise RuntimeError((stderr or "El túnel SSH no pudo abrir el puerto local.").strip())
        return process, local_port


class RemoteAccessManager:
    """Application service coordinating policy, VPN, SSH tunnel and RDP client.

    Responsibilities are intentionally split into repository, VPN detector, tunnel
    service and platform launcher so the UI does not contain security logic.
    """

    def __init__(self, app_root: Path, *, known_hosts: Path | None = None, default_key: Path | None = None):
        self.app_root = Path(app_root).resolve()
        self.repository: RemoteAccessRepository = JsonRemoteAccessRepository(self.app_root / "config" / "remote_access.json")
        self._known_hosts = Path(known_hosts).resolve() if known_hosts else None
        self._default_key = Path(default_key).resolve() if default_key else None
        self._interface_cache: tuple[NetworkInterfaceInfo, ...] = ()
        self._interface_cache_at: float = 0.0
        self._ensure_defaults()

    def _ensure_defaults(self) -> None:
        cfg = self.repository.load()
        ssh = cfg.ssh_tunnel
        changed = False
        if not ssh.known_hosts and self._known_hosts:
            ssh = SshTunnelConfig(**{**asdict(ssh), "known_hosts": str(self._known_hosts)})
            changed = True
        if not ssh.private_key and self._default_key:
            ssh = SshTunnelConfig(**{**asdict(ssh), "private_key": str(self._default_key)})
            changed = True
        if changed:
            self.repository.save(AccessConfig(cfg.schema_version, cfg.policy, ssh, cfg.defaults, cfg.host_overrides))

    def config(self) -> AccessConfig:
        return self.repository.load()

    def save_config(self, config: AccessConfig) -> None:
        self.repository.save(config)

    def client_status(self) -> ClientStatus:
        return SecureRdpLauncher().status()

    def network_interfaces(self, *, force: bool = False) -> tuple[NetworkInterfaceInfo, ...]:
        """Return detected interfaces with a short TTL cache.

        PowerShell/Get-NetAdapter and Linux `ip -j` are external probes. Caching
        prevents the UI from launching them repeatedly while the operator moves
        between pages. A manual "Detectar de nuevo" can request force=True.
        """
        now = time.monotonic()
        if not force and self._interface_cache and now - self._interface_cache_at < 15.0:
            return self._interface_cache
        cfg = self.config()
        rows = VpnDetector(cfg.policy).interfaces()
        self._interface_cache = rows
        self._interface_cache_at = now
        return rows

    def vpn_status(self, *, force: bool = False) -> VpnStatus:
        cfg = self.config()
        interfaces = self.network_interfaces(force=force)
        vpns = tuple(sorted({
            row.alias for row in interfaces
            if row.vpn_candidate and row.status.casefold() not in {"down", "disabled", "notpresent"}
        }))
        detail = "VPN activa" if vpns else "No se detectó una interfaz VPN permitida."
        if interfaces:
            detail += " Interfaces detectadas: " + ", ".join(row.alias for row in interfaces[:8])
        return VpnStatus(bool(vpns), vpns, detail)

    def invalidate_network_cache(self) -> None:
        self._interface_cache = ()
        self._interface_cache_at = 0.0

    @staticmethod
    def ssh_private_key_candidates() -> tuple[str, ...]:
        ssh_dir = Path.home() / ".ssh"
        if not ssh_dir.is_dir():
            return ()
        candidates: list[str] = []
        for name in ("id_ed25519", "id_ecdsa", "id_rsa"):
            candidate = ssh_dir / name
            if candidate.is_file():
                candidates.append(str(candidate))
        for candidate in sorted(ssh_dir.iterdir(), key=lambda x: x.name.casefold()):
            if not candidate.is_file() or candidate.name.endswith((".pub", ".cert")) or candidate.name in {"known_hosts", "known_hosts.old", "config", "authorized_keys"}:
                continue
            if candidate.name.startswith("id_") or candidate.suffix.casefold() in {".pem", ".key", ".ppk"}:
                value = str(candidate)
                if value not in candidates:
                    candidates.append(value)
        return tuple(candidates)

    @staticmethod
    def known_hosts_candidates() -> tuple[str, ...]:
        ssh_dir = Path.home() / ".ssh"
        values: list[str] = []
        for name in ("known_hosts", "known_hosts2"):
            candidate = ssh_dir / name
            if candidate.is_file():
                values.append(str(candidate))
        return tuple(values)

    @staticmethod
    def _resolve_addresses(host: str) -> list[str]:
        value = str(host or "").strip()
        if not value:
            return []
        try:
            ipaddress.ip_address(value)
            return [value]
        except ValueError:
            pass
        addresses: list[str] = []
        try:
            for item in socket.getaddrinfo(value, None, type=socket.SOCK_STREAM):
                addr = str(item[4][0])
                if addr not in addresses:
                    addresses.append(addr)
        except socket.gaierror:
            return []
        return addresses

    @staticmethod
    def _in_allowed_cidrs(address: str, cidrs: tuple[str, ...]) -> bool:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        for raw in cidrs:
            try:
                if ip in ipaddress.ip_network(raw, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def validate_target(self, host: str, *, require_port: int | None = None) -> tuple[bool, str, RouteStatus]:
        cfg = self.config()
        policy = cfg.policy
        addresses = self._resolve_addresses(host)
        if not addresses:
            return False, "No se pudo resolver el host.", RouteStatus(False, detail="Sin resolución DNS/IP")
        if policy.block_public_targets:
            invalid = [addr for addr in addresses if not self._in_allowed_cidrs(addr, policy.allowed_cidrs)]
            if invalid:
                return False, f"Destino bloqueado por política: {', '.join(invalid)} no pertenece a las redes privadas permitidas.", RouteStatus(False, resolved_address=invalid[0])

        vpn = VpnDetector(policy)
        if policy.require_vpn:
            status = vpn.active()
            if not status.active:
                return False, "VPN requerida: no se detectó una interfaz VPN permitida activa.", RouteStatus(False, detail=status.detail)

        route = RouteStatus(True, resolved_address=addresses[0], detail="Ruta no requerida")
        if policy.require_route_over_vpn:
            route = vpn.route_to(addresses[0])
            if not route.valid:
                return False, f"La ruta hacia {addresses[0]} no pasa por una interfaz VPN autorizada. {route.detail}", route

        if require_port:
            try:
                with socket.create_connection((host, int(require_port)), timeout=policy.connect_timeout_seconds):
                    pass
            except OSError as exc:
                return False, f"VPN/ruta válidas, pero TCP {require_port} no responde en {host}: {exc}", route
        return True, "Acceso permitido por política.", route

    def host_settings(self, site_code: str) -> RemoteHostSettings:
        cfg = self.config()
        merged = asdict(cfg.defaults)
        merged.update(cfg.host_overrides.get(str(site_code), {}))
        return JsonRemoteAccessRepository._host_settings(merged)

    def save_host_settings(self, site_code: str, settings: RemoteHostSettings) -> None:
        cfg = self.config()
        overrides = dict(cfg.host_overrides)
        overrides[str(site_code)] = asdict(settings)
        self.save_config(AccessConfig(cfg.schema_version, cfg.policy, cfg.ssh_tunnel, cfg.defaults, overrides))

    def clear_host_settings(self, site_code: str) -> None:
        cfg = self.config()
        overrides = dict(cfg.host_overrides)
        overrides.pop(str(site_code), None)
        self.save_config(AccessConfig(cfg.schema_version, cfg.policy, cfg.ssh_tunnel, cfg.defaults, overrides))

    def save_policy_and_ssh(self, *, policy: SecurityPolicy, ssh_tunnel: SshTunnelConfig, defaults: RemoteHostSettings | None = None) -> None:
        cfg = self.config()
        self.save_config(AccessConfig(cfg.schema_version, policy, ssh_tunnel, defaults or cfg.defaults, cfg.host_overrides))

    @staticmethod
    def _terminate_with_client(client: subprocess.Popen[str], tunnel: subprocess.Popen[str]) -> None:
        def watcher() -> None:
            try:
                client.wait()
            finally:
                if tunnel.poll() is None:
                    tunnel.terminate()
                    try:
                        tunnel.wait(timeout=3)
                    except Exception:
                        tunnel.kill()
        threading.Thread(target=watcher, name="gideon-ssh-tunnel-watch", daemon=True).start()

    def connect(self, site_code: str, host: str) -> tuple[bool, str]:
        settings = self.host_settings(site_code)
        cfg = self.config()
        try:
            if settings.mode == "vpn_ssh_rdp":
                # VPN remains mandatory for the jump host as well as the target.
                if not cfg.ssh_tunnel.jump_host:
                    return False, "El modo VPN + SSH requiere configurar un Jump Host."
                ok_jump, detail_jump, _ = self.validate_target(cfg.ssh_tunnel.jump_host, require_port=cfg.ssh_tunnel.jump_port)
                if not ok_jump:
                    return False, f"Jump Host rechazado: {detail_jump}"
                ok_target, detail_target, route = self.validate_target(host, require_port=None)
                if not ok_target:
                    return False, detail_target
                tunnel, local_port = SshTunnelService(cfg.ssh_tunnel).open(host, settings.rdp_port)
                local_settings = RemoteHostSettings(**{**asdict(settings), "rdp_port": local_port})
                client = SecureRdpLauncher().launch("127.0.0.1", local_settings)
                self._terminate_with_client(client, tunnel)
                return True, f"RDP iniciado por VPN + túnel SSH. Ruta VPN: {route.interface or '-'} · puerto local {local_port}."

            ok, detail, route = self.validate_target(host, require_port=settings.rdp_port)
            if not ok:
                return False, detail
            SecureRdpLauncher().launch(host, settings)
            return True, f"RDP seguro iniciado por VPN. Ruta: {route.interface or '-'} · NLA/TLS obligatorio · credenciales no almacenadas."
        except Exception as exc:
            return False, f"{type(exc).__name__}: {exc}"

    def test(self, site_code: str, host: str) -> tuple[bool, str]:
        settings = self.host_settings(site_code)
        if settings.mode == "vpn_ssh_rdp":
            cfg = self.config()
            ok_jump, detail_jump, route_jump = self.validate_target(cfg.ssh_tunnel.jump_host, require_port=cfg.ssh_tunnel.jump_port)
            if not ok_jump:
                return False, f"SSH: {detail_jump}"
            ok_target, detail_target, _ = self.validate_target(host, require_port=None)
            if not ok_target:
                return False, detail_target
            return True, f"VPN OK · Jump SSH {cfg.ssh_tunnel.jump_host}:{cfg.ssh_tunnel.jump_port} accesible por {route_jump.interface}."
        ok, detail, route = self.validate_target(host, require_port=settings.rdp_port)
        if ok:
            return True, f"VPN OK · Ruta {route.interface} · TCP {settings.rdp_port} disponible."
        return False, detail
