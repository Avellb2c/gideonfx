from __future__ import annotations

import os
import platform
import re
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class PlatformProfile:
    family: str
    name: str
    version: str
    architecture: str
    distro_id: str = ""
    distro_name: str = ""
    distro_version: str = ""
    distro_family: str = ""
    package_manager: str = ""
    windows_server: bool = False
    windows_server_core: bool = False

    @property
    def label(self) -> str:
        if self.family == "windows":
            suffix = "Windows Server" if self.windows_server else "Windows"
            return f"{suffix} {self.version} · {self.architecture}".strip()
        if self.family == "linux":
            base = self.distro_name or self.distro_id or "Linux"
            return f"{base} {self.distro_version} · {self.architecture}".strip()
        return f"{self.name} {self.version} · {self.architecture}".strip()

    @property
    def supports_gui(self) -> bool:
        return not (self.family == "windows" and self.windows_server_core) and self.family in {"windows", "linux"}

    @property
    def rdp_client_name(self) -> str:
        return "Microsoft Remote Desktop (MSTSC)" if self.family == "windows" else "Remmina + RDP"


def _read_os_release() -> dict[str, str]:
    result: dict[str, str] = {}
    for candidate in (Path("/etc/os-release"), Path("/usr/lib/os-release")):
        if not candidate.is_file():
            continue
        try:
            for line in candidate.read_text(encoding="utf-8", errors="replace").splitlines():
                if not line or line.lstrip().startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                result[key.strip()] = value.strip().strip('"').strip("'")
            break
        except OSError:
            continue
    return result


def _linux_family(os_release: dict[str, str]) -> str:
    tokens = " ".join((os_release.get("ID", ""), os_release.get("ID_LIKE", ""))).lower()
    families = (
        ("debian", ("debian", "ubuntu", "mint", "kali", "pop", "elementary", "zorin", "raspbian")),
        ("rhel", ("rhel", "fedora", "centos", "rocky", "almalinux", "oracle", "amzn", "scientific")),
        ("suse", ("suse", "opensuse", "sles")),
        ("arch", ("arch", "manjaro", "endeavouros", "garuda")),
        ("alpine", ("alpine",)),
        ("gentoo", ("gentoo",)),
        ("void", ("void",)),
    )
    for family, names in families:
        if any(re.search(rf"(^|\s){re.escape(name)}(\s|$)", tokens) for name in names):
            return family
    return "generic"


def _package_manager() -> str:
    for name in ("apt-get", "dnf", "yum", "zypper", "pacman", "apk", "xbps-install", "emerge"):
        if shutil.which(name):
            return name
    return ""


def _windows_product_name() -> str:
    if os.name != "nt":
        return ""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
            value, _ = winreg.QueryValueEx(key, "ProductName")
            return str(value or "")
    except Exception:
        return platform.platform()


def detect_platform() -> PlatformProfile:
    arch = platform.machine() or "unknown"
    if os.name == "nt":
        product = _windows_product_name()
        server = "server" in product.casefold()
        # Avoid false Server-Core positives in services/remote sessions: only explicit Core SKU text is used.
        server_core = server and "core" in product.casefold()
        return PlatformProfile(
            family="windows",
            name=product or "Windows",
            version=platform.version(),
            architecture=arch,
            windows_server=server,
            windows_server_core=server_core,
        )
    if sys.platform.startswith("linux"):
        rel = _read_os_release()
        return PlatformProfile(
            family="linux",
            name="Linux",
            version=platform.release(),
            architecture=arch,
            distro_id=rel.get("ID", "").lower(),
            distro_name=rel.get("PRETTY_NAME") or rel.get("NAME", "Linux"),
            distro_version=rel.get("VERSION_ID", ""),
            distro_family=_linux_family(rel),
            package_manager=_package_manager(),
        )
    if sys.platform == "darwin":
        return PlatformProfile("darwin", "macOS", platform.mac_ver()[0], arch)
    return PlatformProfile("other", platform.system(), platform.release(), arch)


def display_session_available(profile: PlatformProfile | None = None) -> bool:
    profile = profile or detect_platform()
    if profile.family == "windows":
        return not profile.windows_server_core
    if profile.family == "linux":
        return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    return False
