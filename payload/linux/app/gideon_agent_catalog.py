from __future__ import annotations

from gideon_version import GATEWAY_VERSION

from gideon_common.observability import best_effort_warning

from gideon_common.clock import now_iso
import datetime as dt
import hashlib
import json
import os
import re
from pathlib import Path

from gideon_infrastructure.subprocess_utils import run_hidden
import shutil
import subprocess
import sys
import tempfile
import zipfile
import tarfile
import time
from typing import Any, Mapping

from gideon_agent_http import AgentHttpClient
from gideon_agent_builder import AgentBuilder, AGENT_VERSION, AGENT_PROTOCOL
from gideon_agent_component import resolve_vlc_source_companion
from gideon_agent_payload import copy_agent_runtime_payload
from gideon_agent_vlc_offline import stage_offline_vlc_bundle
from gideon_agent_windows_runtime import DEFAULT_REQUIREMENTS, prepare_windows_private_runtime, validate_windows_private_runtime_payload
from gideon_gateway_bootstrap import GATEWAY_CONFIG_PATH, ensure_gateway_configuration
from gideon_agent_security import ensure_ed25519_keypair, sha256_file, sign_file
from gideon_dependency_manager import SystemDependencyManager
from gideon_packaging import WindowsExePackager
from gideon_agent_installer_contract import write_installer_contract, verify_installer_contract, verify_artifact_sanity
from gideon_branding import BrandingRepository, BrandProfile
from gideon_host_profiles import HostProfileStore
from gideon_gateway_tls import file_sha256, probe_tls_endpoint


# Debian and Raspberry Pi OS provide architecture-matched wheels/modules for
# the two native dependencies that are expensive (and sometimes impossible) to
# compile on ARMHF.  DEB installers expose those packages inside the venv and
# pip installs only pystray's pure-Python wheel.
DEBIAN_SYSTEM_PYTHON_DEPENDENCIES = (
    "python3-cryptography",
    "python3-pil",
    "python3-six",
    "python3-xlib",
)
DEBIAN_AGENT_REQUIREMENTS = "pystray>=0.19,<1\n"


TARGETS = {
    "windows_x64": {
        "label":"Windows x64",
        "platform":"windows",
        "architecture":"x86_64",
        "package_type":"exe",
        "profile":"windows_generic",
        "installer":"Install-GIDEONAgent.ps1",
        "notes":f"Windows 10/11 y Windows Server. Agent {AGENT_VERSION} autocontenido; servicio nativo Windows SCM + Reverse Tunnel universal. Windows Home/Core instala el Agent normalmente, pero acceso remoto RDP queda UNSUPPORTED sin instalar terceros.",
    },
    "windows_server_2016": {
        "label":"Windows Server 2016 · Pulse",
        "platform":"windows",
        "architecture":"x86_64",
        "package_type":"exe",
        "profile":"windows_server_2016_pulse",
        "installer":"Install-GIDEONAgent.ps1",
        "notes":f"Windows Server 2016 / Pulse. Agent {AGENT_VERSION} autocontenido; servicio nativo Windows SCM.",
    },
    "windows_server_2022": {
        "label":"Windows Server 2022 · Pulse",
        "platform":"windows",
        "architecture":"x86_64",
        "package_type":"exe",
        "profile":"windows_server_2022_pulse",
        "installer":"Install-GIDEONAgent.ps1",
        "notes":f"Windows Server 2022 / Pulse. Agent {AGENT_VERSION} autocontenido; servicio nativo Windows SCM.",
    },
    "linux_x64": {
        "label":"Linux x64 / AWS",
        "platform":"linux",
        "architecture":"x86_64",
        "profile":"linux_aws_x64",
        "package_type":"deb",
        "installer":"install-gideon-agent.sh",
        "notes":"systemd · Bash/Python/pwsh.",
    },
    "ubuntu_debian_desktop_x64": {
        "label":"Ubuntu / Debian Desktop x64 · DEB",
        "platform":"linux",
        "architecture":"x86_64",
        "profile":"linux_aws_x64",
        "package_type":"deb",
        "installer":"install-gideon-agent.sh",
        "native_desktop_ui":True,
        "notes":"Ubuntu/Debian/Mint/Pop!_OS Desktop x64. Primer enrolamiento con GUI nativa GTK.",
    },
    "ubuntu_debian_desktop_arm64": {
        "label":"Ubuntu / Debian Desktop ARM64 · DEB",
        "platform":"linux",
        "architecture":"arm64",
        "profile":"raspberry_pi_64",
        "package_type":"deb",
        "installer":"install-gideon-agent.sh",
        "native_desktop_ui":True,
        "notes":"Ubuntu/Debian Desktop ARM64. Primer enrolamiento con GUI nativa GTK.",
    },
    "linux_rhel_x64": {
        "label":"Linux x64 / RHEL · Rocky · Alma",
        "platform":"linux",
        "architecture":"x86_64",
        "profile":"linux_aws_x64",
        "package_type":"rpm",
        "installer":"gideon-agent.service",
        "notes":"systemd · RPM nativo.",
    },
    "fedora_rhel_desktop_x64": {
        "label":"Fedora / RHEL / Rocky / Alma Desktop x64 · RPM",
        "platform":"linux",
        "architecture":"x86_64",
        "profile":"linux_aws_x64",
        "package_type":"rpm",
        "installer":"gideon-agent.service",
        "native_desktop_ui":True,
        "notes":"RPM Desktop x64. Primer enrolamiento con GUI nativa GTK/KDE.",
    },
    "fedora_rhel_desktop_arm64": {
        "label":"Fedora / RHEL / Rocky / Alma Desktop ARM64 · RPM",
        "platform":"linux",
        "architecture":"arm64",
        "profile":"raspberry_pi_64",
        "package_type":"rpm",
        "installer":"gideon-agent.service",
        "native_desktop_ui":True,
        "notes":"RPM Desktop ARM64. Primer enrolamiento con GUI nativa GTK/KDE.",
    },
    "linux_arm64": {
        "label":"Raspberry Pi OS Desktop / Ubuntu Desktop ARM64 · DEB",
        "platform":"linux",
        "architecture":"arm64",
        "profile":"raspberry_pi_64",
        "package_type":"deb",
        "installer":"install-gideon-agent.sh",
        "native_desktop_ui":True,
        "notes":"Raspberry Pi OS Desktop 64-bit / Ubuntu Desktop ARM64. RDP requiere escritorio; en Lite/headless el Agent y SSH pueden enrolarse por consola, pero RDP se reporta UNSUPPORTED.",
    },
    "linux_armhf": {
        "label":"Raspberry Pi OS Desktop 32-bit · DEB",
        "platform":"linux",
        "architecture":"armv7l",
        "profile":"raspberry_pi_32",
        "package_type":"deb",
        "installer":"install-gideon-agent.sh",
        "native_desktop_ui":True,
        "notes":"Raspberry Pi OS Desktop 32-bit. RDP requiere escritorio; en Lite/headless el Agent y SSH pueden enrolarse por consola, pero RDP se reporta UNSUPPORTED.",
    },
    "linux_rhel_arm64": {
        "label":"Linux ARM64 / Fedora · RHEL · Rocky · Alma · RPM",
        "platform":"linux",
        "architecture":"arm64",
        "profile":"raspberry_pi_64",
        "package_type":"rpm",
        "installer":"gideon-agent.service",
        "notes":"RPM para Fedora/RHEL/Rocky/Alma ARM64. No usar en Raspberry Pi OS basado en Debian.",
    },
    "linux_x64_portable": {
        "label":"Linux genérico x64 · Portable TAR.GZ",
        "platform":"linux",
        "architecture":"x86_64",
        "profile":"linux_aws_x64",
        "package_type":"tar.gz",
        "installer":"install-gideon-agent.sh",
        "notes":"Portable systemd para otras distribuciones Linux x64.",
    },
    "linux_arm64_portable": {
        "label":"Linux genérico ARM64 · Portable TAR.GZ",
        "platform":"linux",
        "architecture":"arm64",
        "profile":"raspberry_pi_64",
        "package_type":"tar.gz",
        "installer":"install-gideon-agent.sh",
        "notes":"Portable systemd para otras distribuciones Linux ARM64.",
    },
    "linux_armhf_portable": {
        "label":"Linux genérico ARMHF · Portable TAR.GZ",
        "platform":"linux",
        "architecture":"armv7l",
        "profile":"raspberry_pi_32",
        "package_type":"tar.gz",
        "installer":"install-gideon-agent.sh",
        "notes":"Portable systemd para Linux ARMv7/ARMHF.",
    },
    "macos_arm64": {
        "label":"macOS Apple Silicon",
        "platform":"darwin",
        "architecture":"arm64",
        "profile":"macos_arm64",
        "installer":"install-gideon-agent.sh",
        "notes":"launchd · Apple Silicon.",
    },
    "macos_x64": {
        "label":"macOS Intel",
        "platform":"darwin",
        "architecture":"x86_64",
        "profile":"macos_x64",
        "installer":"install-gideon-agent.sh",
        "notes":"launchd · Intel.",
    },
    "macos_arm64_portable": {
        "label":"macOS Apple Silicon · Portable TAR.GZ",
        "platform":"darwin",
        "architecture":"arm64",
        "profile":"macos_arm64",
        "package_type":"tar.gz",
        "installer":"install-gideon-agent.sh",
        "notes":"Portable generable desde Windows/Linux. launchd · Apple Silicon.",
    },
    "macos_x64_portable": {
        "label":"macOS Intel · Portable TAR.GZ",
        "platform":"darwin",
        "architecture":"x86_64",
        "profile":"macos_x64",
        "package_type":"tar.gz",
        "installer":"install-gideon-agent.sh",
        "notes":"Portable generable desde Windows/Linux. launchd · Intel.",
    },
}




CONFIGURATOR = r'''#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,os
from pathlib import Path


p=argparse.ArgumentParser()
p.add_argument("--template",type=Path,default=Path("agent.template.json"))
p.add_argument("--out",type=Path,default=Path("agent.json"))
p.add_argument("--site-code",required=True)
p.add_argument("--site-name",required=True)
p.add_argument("--agent-name",required=True)
p.add_argument("--gateway")
p.add_argument("--enrollment-secret")
p.add_argument("--enrollment-secret-file",type=Path)
a=p.parse_args()

enrollment_secret=str(a.enrollment_secret or os.environ.get("GIDEON_AGENT_ENROLL_SECRET") or "")
if a.enrollment_secret_file:
    try:
        enrollment_secret=a.enrollment_secret_file.read_text(encoding="utf-8").strip()
    finally:
        try:a.enrollment_secret_file.unlink(missing_ok=True)
        except Exception:pass

cfg=json.loads(a.template.read_text(encoding="utf-8"))
cfg["site_code"]=a.site_code.strip()
cfg["site_name"]=a.site_name.strip()
cfg["agent_name"]=a.agent_name.strip()
if a.gateway:
    cp=cfg["control_plane"]; old=str(cp.get("base_url") or "").rstrip("/"); new=a.gateway.rstrip("/")
    cp["base_url"]=new
    rows=cp.get("endpoints") if isinstance(cp.get("endpoints"),list) else []
    replaced=False
    for row in rows:
        if isinstance(row,dict) and not replaced and (str(row.get("role") or "").lower()=="primary" or str(row.get("url") or "").rstrip("/")==old):
            row["url"]=new; row["role"]="primary"; row["priority"]=10; replaced=True
    if not replaced: rows.insert(0,{"url":new,"role":"primary","priority":10,"label":"Configurado en instalación"})
    cp["endpoints"]=rows
if enrollment_secret: cfg["enrollment_secret"]=enrollment_secret
a.out.write_text(json.dumps(cfg,ensure_ascii=False,indent=2),encoding="utf-8")
print(a.out)
'''







class AgentDownloadCatalog:
    def __init__(self, app_root: Path) -> None:
        self.app_root=Path(app_root)
        self.builder=AgentBuilder(self.app_root)
        self.profiles=HostProfileStore(self.app_root/"config"/"host_profiles.json")
        self.branding=BrandingRepository(self.app_root)
        state_override=os.environ.get("GIDEON_AGENT_DOWNLOAD_STATE_DIR","").strip()
        self.state_dir=Path(state_override).expanduser() if state_override else (self.builder.state_dir/"downloads")
        self.state_dir.mkdir(parents=True,exist_ok=True)
        self.registry=self.state_dir/"catalog.json"
        self._capability_cache: dict[str, tuple[float, dict[str, object]]] = {}
        self.last_installer_contract: dict[str, object] | None = None
        self.last_artifact_validation: dict[str, object] | None = None
        self.last_vlc_source_companion: dict[str, Any] | None = None

    def _gateway_bootstrap_secret(self, gateway_url: str) -> str:
        """Issue a temporary enrollment grant for the matching local Gateway.

        Persistent state is preferred, while the version-local path remains a
        migration/test fallback.  The long-lived enrollment secret is never
        copied into an installer.  The long-lived Gateway ``enrollment_secret`` is deliberately never copied.
        """
        requested = str(gateway_url or "").strip().rstrip("/")
        candidates = [GATEWAY_CONFIG_PATH, self.app_root / "config" / "agent_gateway.json"]
        seen: set[str] = set()
        for path in candidates:
            try:
                key = str(Path(path).resolve()).casefold()
                if key in seen:
                    continue
                seen.add(key)
                if not Path(path).is_file():
                    continue
                data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
                configured = str(data.get("public_url") or "").strip().rstrip("/")
                if not configured or not requested or configured != requested:
                    continue
                ttl = int(data.get("installer_enrollment_ttl_seconds") or 7 * 86400)
                uses = int(data.get("installer_enrollment_max_uses") or 64)
                from gideon_agent_gateway import GatewayDB, resolve_gateway_data_dir
                data_dir = resolve_gateway_data_dir(data, Path(path))
                return GatewayDB(data_dir).issue_enrollment_grant(
                    ttl_seconds=ttl, max_uses=uses, label=f"installer:{requested}"
                )
            except Exception:
                continue
        return ""

    def _ensure_local_gateway_tls_ready(self, gateway_url: str, local_info: dict[str, object]) -> None:
        """Make local installer generation fail-safe against stale Gateway TLS.

        Only the Gateway configured by this same console is touched.  External
        gateways are never started/restarted implicitly.  For the local Gateway
        we may renew the *leaf* certificate and reconcile a stale GIDEON listener,
        but the stable root CA is never rotated here.
        """
        requested = str(gateway_url or "").strip().rstrip("/")
        configured = str(local_info.get("public_url") or "").strip().rstrip("/")
        ca_file = str(local_info.get("ca_file") or "").strip()
        if not requested or requested != configured or not ca_file:
            return
        probe = probe_tls_endpoint(requested, ca_file=ca_file, timeout=1.2)
        health: dict[str, object] = {}
        if probe.ok:
            try:
                health = AgentHttpClient(
                    requested, verify_tls=True, ca_file=ca_file, require_https=True, timeout=2.0
                ).json("GET", "/health", timeout=2.0)
            except Exception:
                health = {}
        live_version = str(health.get("Version") or "").strip() if isinstance(health, dict) else ""
        schema_ready = bool(health.get("SchemaReady", False)) if isinstance(health, dict) else False
        capabilities = health.get("Capabilities") if isinstance(health, dict) and isinstance(health.get("Capabilities"), dict) else {}
        approval_ready = bool(capabilities.get("ReleaseApproval"))
        if probe.ok and live_version == GATEWAY_VERSION and schema_ready and approval_ready:
            return
        try:
            from gideon_gateway_service import GatewayCoordinator
            repaired = GatewayCoordinator(self.app_root).test_and_repair()
            if not repaired.ok:
                raise RuntimeError(repaired.message or repaired.title)
            # Re-verify the actual listener after repair.  Installer generation
            # must never continue against a stale Gateway just because TLS works.
            post = AgentHttpClient(
                requested, verify_tls=True, ca_file=ca_file, require_https=True, timeout=2.0
            ).json("GET", "/health", timeout=2.0)
            post_version = str(post.get("Version") or "").strip()
            post_caps = post.get("Capabilities") if isinstance(post.get("Capabilities"), dict) else {}
            if post_version != GATEWAY_VERSION or not bool(post.get("SchemaReady")) or not bool(post_caps.get("ReleaseApproval")):
                raise RuntimeError(
                    f"Gateway activo {post_version or '-'} / schema={post.get('SchemaReady')} / "
                    f"release_approval={bool(post_caps.get('ReleaseApproval'))} no coincide con "
                    f"Gateway requerido {GATEWAY_VERSION}."
                )
        except Exception as exc:
            raise RuntimeError(
                "El Gateway local no pudo sincronizar versión/esquema/TLS antes de generar el agente. "
                f"Diagnóstico inicial: {probe.category}: {probe.detail}. "
                f"Reparación: {type(exc).__name__}: {exc}"
            ) from exc
        refreshed = ensure_gateway_configuration(force_tls=False)
        ca_file = str(refreshed.get("ca_file") or ca_file)
        second = probe_tls_endpoint(requested, ca_file=ca_file, timeout=2.5)
        if not second.ok:
            raise RuntimeError(
                "No se generará un agente con TLS inconsistente. "
                f"{second.category}: {second.detail}. "
                "Abra Gateway central > Probar Gateway y corrija los puntos TLS antes de compilar el instalador."
            )

    @staticmethod
    def _native_package_type(target: dict) -> str:
        return str(target.get("package_type") or {"windows":"exe", "linux":"deb", "darwin":"pkg"}.get(target.get("platform"), "zip"))

    @staticmethod
    def _deb_architecture(architecture: str) -> str:
        arch = str(architecture or "").strip().lower()
        mapping = {
            "x86_64": "amd64", "amd64": "amd64",
            "arm64": "arm64", "aarch64": "arm64",
            "armv7l": "armhf", "armv7": "armhf", "armhf": "armhf",
            "i386": "i386", "i686": "i386",
        }
        if arch not in mapping:
            raise ValueError(f"Arquitectura DEB no soportada: {architecture}")
        return mapping[arch]

    @staticmethod
    def _rpm_required_commands() -> tuple[str, ...]:
        return ("rpmbuild", "file", "tar", "gzip")

    @staticmethod
    def _rpm_spec(version: str, target_architecture: str, brand: BrandProfile | None = None, native_desktop_ui: bool = False) -> str:
        target_arch = str(target_architecture or "").strip().lower()
        if target_arch in {"arm64", "aarch64"}:
            arch_guard = "case \"$(uname -m)\" in aarch64|arm64) ;; *) echo 'Este paquete GIDEON requiere Linux ARM64/aarch64.' >&2; exit 1 ;; esac"
        elif target_arch in {"x86_64", "amd64"}:
            arch_guard = "case \"$(uname -m)\" in x86_64|amd64) ;; *) echo 'Este paquete GIDEON requiere Linux x86_64.' >&2; exit 1 ;; esac"
        else:
            arch_guard = ":"
        brand = brand or BrandingRepository(Path.cwd()).load()
        summary = brand.metadata_text(brand.agent_product_name) or "Gideon Rx Agent"
        vendor = brand.metadata_text(brand.company_name) or "Gideon Rx Project"
        description = brand.metadata_text(brand.agent_description) or summary
        rpm_ui_requires = "Requires: zenity\nRequires: polkit\n" if native_desktop_ui else "Recommends: zenity\nRecommends: polkit\n"
        return (
            f"%global debug_package %{{nil}}\n%global _enable_debug_packages 0\n"
            f"Name: gideon-agent\nVersion: {version}\nRelease: 1%{{?dist}}\nSummary: {summary}\n"
            f"Vendor: {vendor}\nPackager: {vendor}\nLicense: Proprietary\nBuildArch: noarch\nSource0: gideon-agent-payload.tar.gz\n"
            f"Requires: python3\nRequires: python3-pip\nRequires: systemd\nRequires: xdg-utils\nRequires: acl\n{rpm_ui_requires}\n"
            f"%description\n{description}.\n\n%prep\n%setup -q -n gideon-agent\n\n"
            "%install\nmkdir -p %{buildroot}/opt/gideon-agent %{buildroot}/usr/bin %{buildroot}/usr/share/applications %{buildroot}/etc/xdg/autostart %{buildroot}/lib/systemd/system\ncp -a . %{buildroot}/opt/gideon-agent/\n"
            "find %{buildroot}/opt/gideon-agent -type d -exec chmod 0755 {} +\nfind %{buildroot}/opt/gideon-agent -type f -exec chmod 0644 {} +\nchmod 0755 %{buildroot}/opt/gideon-agent/gideon-agent-setup %{buildroot}/opt/gideon-agent/gideon-agent-first-run-launch %{buildroot}/opt/gideon-agent/gideon-agent-first-run-native %{buildroot}/opt/gideon-agent/gideon-agent-player-launch\n"
            f"echo '{target_arch}' > %{{buildroot}}/opt/gideon-agent/target-architecture.txt\n"
            "cat > %{buildroot}/usr/bin/gideon-agent-configure <<'EOF'\n#!/bin/sh\nset -eu\nexec /opt/gideon-agent/venv/bin/python /opt/gideon-agent/configure-agent.py --template /opt/gideon-agent/agent.template.json --out /opt/gideon-agent/agent.json \"$@\"\nEOF\nchmod 0755 %{buildroot}/usr/bin/gideon-agent-configure\n"
            "cat > %{buildroot}/usr/bin/gideon-agent-setup <<'EOF'\n#!/bin/sh\nset -eu\nexec /opt/gideon-agent/gideon-agent-setup \"$@\"\nEOF\nchmod 0755 %{buildroot}/usr/bin/gideon-agent-setup\n"
            "cat > %{buildroot}/usr/bin/gideon-agent-first-run <<'EOF'\n#!/bin/sh\nset -eu\nexec /opt/gideon-agent/gideon-agent-first-run-native \"$@\"\nEOF\nchmod 0755 %{buildroot}/usr/bin/gideon-agent-first-run\n"
            "cat > %{buildroot}/usr/bin/gideon-agent-player-launch <<'EOF'\n#!/bin/sh\nset -eu\nexec /opt/gideon-agent/gideon-agent-player-launch \"$@\"\nEOF\nchmod 0755 %{buildroot}/usr/bin/gideon-agent-player-launch\n"
            "cat > %{buildroot}/usr/share/applications/gideon-agent-first-run.desktop <<'EOF'\n[Desktop Entry]\nType=Application\nName=Gideon Rx Agent · Configurar\nExec=/usr/bin/gideon-agent-first-run\nTerminal=false\nCategories=System;Settings;\nEOF\n"
            "cat > %{buildroot}/etc/xdg/autostart/gideon-agent-first-run.desktop <<'EOF'\n[Desktop Entry]\nType=Application\nName=Gideon Rx Agent · Primer inicio\nExec=/usr/bin/gideon-agent-first-run --auto\nTerminal=false\nNoDisplay=true\nX-GNOME-Autostart-enabled=true\nEOF\n"
            "cat > %{buildroot}/opt/gideon-agent/gideon-agent.service <<'EOF'\n"
            "[Unit]\nDescription=GIDEON Cross-Platform Agent\nAfter=network-online.target\nWants=network-online.target\n"
            "[Service]\nType=simple\nExecStart=/opt/gideon-agent/venv/bin/python /opt/gideon-agent/gideon_agent.py --config /opt/gideon-agent/agent.json\n"
            "WorkingDirectory=/opt/gideon-agent\nRestart=always\nRestartSec=5\n[Install]\nWantedBy=multi-user.target\nEOF\n\n"
            "cat > %{buildroot}/lib/systemd/system/gideon-agent-player-launch.service <<'EOF'\n[Unit]\nDescription=GIDEON Player physical-screen launcher\nAfter=graphical.target gideon-agent.service\nConditionPathExists=/opt/gideon-agent/gideon-agent-player-launch\n\n[Service]\nType=oneshot\nExecStart=/usr/bin/gideon-agent-player-launch\nEOF\n"
            "cat > %{buildroot}/lib/systemd/system/gideon-agent-player-launch.timer <<'EOF'\n[Unit]\nDescription=Retry GIDEON Player physical-screen launch\n\n[Timer]\nOnBootSec=30s\nOnUnitActiveSec=30s\nPersistent=true\n\n[Install]\nWantedBy=timers.target\nEOF\n\n"
            f"%pre\n{arch_guard}\n\n"
            "%post\nROOT=/opt/gideon-agent\nSTATE=/var/lib/gideon-agent\nCFG=/etc/gideon-agent\n# GIDEON_PLAYER_ROOT_OWNED_RUNTIME_REQUIRED: root keeps code, venv, launcher and Agent state authoritative.\ninstall -d -o root -g root -m 0750 \"$STATE\" \"$CFG\"\nchown root:root \"$STATE\" \"$CFG\"\nchmod 0750 \"$STATE\" \"$CFG\"\n[ -d \"$ROOT\" ] && [ ! -L \"$ROOT\" ] || { echo 'GIDEON_PACKAGE_SECURITY_ERROR: app root inválido.' >&2; exit 1; }\n[ ! -e \"$ROOT/venv\" ] || [ ! -L \"$ROOT/venv\" ] || { echo 'GIDEON_PACKAGE_SECURITY_ERROR: venv symlink rechazado.' >&2; exit 1; }\n[ -d \"$ROOT/vendor\" ] && [ ! -L \"$ROOT/vendor\" ] || { echo 'GIDEON_DEPENDENCY_ERROR: faltan dependencias offline.' >&2; exit 1; }\nchown -R root:root \"$ROOT\"\nfind \"$ROOT\" -xdev -type d -exec chmod 0755 {} +\nfind \"$ROOT\" -xdev -type f -exec chmod 0644 {} +\nfor executable in \"$ROOT/gideon-agent-setup\" \"$ROOT/gideon-agent-first-run-launch\" \"$ROOT/gideon-agent-first-run-native\" \"$ROOT/gideon-agent-player-launch\"; do [ ! -e \"$executable\" ] || chmod 0755 \"$executable\"; done\nfor private_file in \"$ROOT/agent.json\" \"$ROOT/bootstrap.enrollment\"; do [ ! -f \"$private_file\" ] || chmod 0600 \"$private_file\"; done\npython3 -m venv --clear --system-site-packages \"$ROOT/venv\"\ngrep -Eiq '^include-system-site-packages[[:space:]]*=[[:space:]]*true$' \"$ROOT/venv/pyvenv.cfg\" || { echo 'GIDEON_DEPENDENCY_ERROR: el venv no expone paquetes Python del sistema.' >&2; exit 1; }\n\"$ROOT/venv/bin/pip\" install --no-index --find-links=\"$ROOT/vendor\" --disable-pip-version-check --only-binary=:all: --no-deps -r \"$ROOT/requirements-agent.txt\"\nchown -R root:root \"$ROOT\"\nfind \"$ROOT\" -xdev -type d -exec chmod 0755 {} +\nfind \"$ROOT\" -xdev -type f -exec chmod 0644 {} +\nfind \"$ROOT/venv/bin\" -xdev -type f -exec chmod 0755 {} +\nfor executable in \"$ROOT/gideon-agent-setup\" \"$ROOT/gideon-agent-first-run-launch\" \"$ROOT/gideon-agent-first-run-native\" \"$ROOT/gideon-agent-player-launch\"; do [ ! -e \"$executable\" ] || chmod 0755 \"$executable\"; done\nfor private_file in \"$ROOT/agent.json\" \"$ROOT/bootstrap.enrollment\"; do [ ! -f \"$private_file\" ] || chmod 0600 \"$private_file\"; done\n"
            "\"$ROOT/venv/bin/python\" -c \"import sys;sys.path.insert(0,'/opt/gideon-agent');import gideon_agent,gideon_reverse_tunnel,gideon_agent_http,gideon_agent_security,gideon_agent_worker,gideon_common;print(gideon_agent.VERSION)\"\n"
            "install -m 0644 /opt/gideon-agent/gideon-agent.service /etc/systemd/system/gideon-agent.service\nsystemctl daemon-reload\nsystemctl enable --now gideon-agent-player-launch.timer >/dev/null 2>&1 || true\n"
            "mkdir -p /var/lib/gideon-agent\nif [ -s /opt/gideon-agent/agent.json ]; then echo 'RUNNING|Detectando instalación anterior y migrando configuración…' >/var/lib/gideon-agent/package-ui.state; nohup /opt/gideon-agent/gideon-agent-first-run-launch --package-progress >>/var/lib/gideon-agent/first-run-launch.log 2>&1 </dev/null & echo 'GIDEON Agent previo detectado: reparación/migración integral.'; set +e; /opt/gideon-agent/gideon-agent-setup --non-interactive >/var/lib/gideon-agent/package-repair.log 2>&1; repair_rc=$?; set -e; if [ $repair_rc -eq 0 ]; then echo 'SUCCESS|GIDEON Remote Control Agent quedó actualizado, migrado y validado correctamente.' >/var/lib/gideon-agent/package-ui.state; echo 'GIDEON Agent actualizado, migrado y validado.'; else diag=$(sed -n 's/^GIDEON_DIAGNOSTIC_FILE=//p' /var/lib/gideon-agent/package-repair.log | tail -n1); echo \"ERROR|La reparación terminó con error $repair_rc. DIAG=$diag\" >/var/lib/gideon-agent/package-ui.state; cat /var/lib/gideon-agent/package-repair.log; exit $repair_rc; fi; else chmod 0755 /opt/gideon-agent/gideon-agent-first-run-launch /opt/gideon-agent/gideon-agent-first-run-native >/dev/null 2>&1 || true; nohup /opt/gideon-agent/gideon-agent-first-run-launch >>/var/lib/gideon-agent/first-run-launch.log 2>&1 </dev/null & echo 'GIDEON Agent instalado; asistente gráfico solicitado.'; fi\n\n"
            "%preun\nif [ $1 -eq 0 ]; then systemctl disable --now gideon-agent.service gideon-agent-player-launch.timer >/dev/null 2>&1 || true; fi\n\n"
            "%files\n%defattr(-,root,root,-)\n/opt/gideon-agent\n%attr(0755,root,root) /opt/gideon-agent/gideon-agent-player-launch\n/usr/bin/gideon-agent-configure\n/usr/bin/gideon-agent-setup\n/usr/bin/gideon-agent-first-run\n/usr/bin/gideon-agent-player-launch\n/lib/systemd/system/gideon-agent-player-launch.service\n/lib/systemd/system/gideon-agent-player-launch.timer\n/usr/share/applications/gideon-agent-first-run.desktop\n/etc/xdg/autostart/gideon-agent-first-run.desktop\n"
        )

    @staticmethod
    def _wsl_executable() -> str | None:
        if os.name != "nt":
            return None
        return shutil.which("wsl.exe") or shutil.which("wsl")

    @classmethod
    def _wsl_distros(cls) -> list[str]:
        wsl = cls._wsl_executable()
        if not wsl:
            return []
        try:
            proc = run_hidden([wsl, "-l", "-q"], check=False, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
            return [line.replace("\x00", "").strip() for line in proc.stdout.splitlines() if line.replace("\x00", "").strip()]
        except Exception:
            return []

    @classmethod
    def _wsl_run(
        cls,
        args: list[str],
        *,
        timeout: int = 1800,
        as_root: bool = False,
        distro: str | None = None,
    ) -> subprocess.CompletedProcess:
        wsl = cls._wsl_executable()
        if not wsl:
            raise RuntimeError(
                "WSL no está instalado. Para generar DEB/RPM desde Windows instale Ubuntu "
                "(PowerShell administrador: wsl --install -d Ubuntu) y reinicie si Windows lo solicita."
            )
        if not cls._wsl_distros():
            raise RuntimeError(
                "WSL está instalado pero no hay una distribución Linux inicializada. "
                "Instale/inicie Ubuntu una vez antes de generar DEB/RPM."
            )
        cmd = [wsl]
        if distro:
            cmd += ["-d", distro]
        if as_root:
            cmd += ["-u", "root"]
        cmd += ["--exec", *args]
        return run_hidden(cmd, check=False, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)

    @classmethod
    def _choose_wsl_distro(cls, package_type: str) -> str:
        distros = [d for d in cls._wsl_distros() if d and "docker-desktop" not in d.casefold()]
        if not distros:
            raise RuntimeError(
                "No hay una distribución WSL de usuario disponible. Instale Ubuntu con 'wsl --install -d Ubuntu', "
                "reinicie si Windows lo solicita y abra Ubuntu una vez."
            )
        checks = (
            "command -v dpkg-deb >/dev/null 2>&1 || command -v apt-get >/dev/null 2>&1"
            if package_type == "deb"
            else "command -v rpmbuild >/dev/null 2>&1 || command -v apt-get >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1 || command -v zypper >/dev/null 2>&1"
        )
        preferred = sorted(
            distros,
            key=lambda d: (
                0 if (package_type == "deb" and any(x in d.casefold() for x in ("ubuntu", "debian"))) else 1,
                d.casefold(),
            ),
        )
        for distro in preferred:
            try:
                probe = cls._wsl_run(["sh", "-lc", checks], timeout=30, distro=distro)
                if probe.returncode == 0:
                    return distro
            except Exception:
                continue
        raise RuntimeError(
            "Ninguna distribución WSL instalada tiene un backend compatible para "
            + package_type.upper()
            + ". Para DEB instale/inicialice Ubuntu o Debian."
        )

    @classmethod
    def _wsl_path(cls, path: Path, *, distro: str | None = None) -> str:
        proc = cls._wsl_run(["wslpath", "-a", "-u", str(Path(path).resolve())], timeout=30, distro=distro)
        if proc.returncode != 0 or not proc.stdout.strip():
            detail = (proc.stdout or "") + "\n" + (proc.stderr or "")
            raise RuntimeError("WSL no pudo convertir la ruta de compilación.\n" + detail[-4000:])
        return proc.stdout.strip().splitlines()[-1].strip()

    @staticmethod
    def _write_text_lf(path: Path, text: str) -> None:
        normalized = str(text).replace("\r\n", "\n").replace("\r", "\n")
        path.write_bytes(normalized.encode("utf-8"))

    @classmethod
    def _ensure_wsl_tool(cls, package_type: str, *, allow_install: bool = True) -> str:
        distro = cls._choose_wsl_distro(package_type)
        if package_type == "deb":
            required = ("dpkg-deb",)
            install_script = (
                "set -e; "
                "if command -v apt-get >/dev/null 2>&1; then "
                "export DEBIAN_FRONTEND=noninteractive; apt-get update; apt-get install -y dpkg-dev; "
                "else echo 'Esta distribución WSL no es Debian/Ubuntu.' >&2; exit 9; fi"
            )
        else:
            # rpmbuild invokes distribution post-processing helpers even for a
            # Python-only payload. `file` and binutils are therefore real build
            # dependencies; checking rpmbuild alone caused find-debuginfo/brp-*
            # to fail on minimal WSL installations.
            required = cls._rpm_required_commands()
            install_script = (
                "set -e; "
                "if command -v apt-get >/dev/null 2>&1; then export DEBIAN_FRONTEND=noninteractive; apt-get update; apt-get install -y rpm file binutils tar gzip; "
                "elif command -v dnf >/dev/null 2>&1; then dnf install -y rpm-build file binutils tar gzip; "
                "elif command -v yum >/dev/null 2>&1; then yum install -y rpm-build file binutils tar gzip; "
                "elif command -v zypper >/dev/null 2>&1; then zypper --non-interactive install rpm-build file binutils tar gzip; "
                "else echo 'No se encontró un gestor compatible para preparar el toolchain RPM.' >&2; exit 9; fi"
            )
        check = " && ".join(f"command -v {name} >/dev/null 2>&1" for name in required)
        probe = cls._wsl_run(["sh", "-lc", check], timeout=30, distro=distro)
        if probe.returncode == 0:
            return distro
        if not allow_install:
            missing = cls._wsl_run(
                ["sh", "-lc", 'for c in ' + " ".join(required) + '; do command -v "$c" >/dev/null 2>&1 || echo "$c"; done'],
                timeout=30, distro=distro,
            )
            missing_names = ", ".join(x.strip() for x in (missing.stdout or "").splitlines() if x.strip()) or "dependencias de build"
            raise RuntimeError(
                f"El toolchain {package_type.upper()} no está preparado dentro de WSL '{distro}'. "
                f"Faltan: {missing_names}. Por política Web GIDEON no instala paquetes del sistema automáticamente; "
                "prepare el toolchain de forma explícita y vuelva a generar."
            )
        proc = cls._wsl_run(["sh", "-lc", install_script], timeout=1800, as_root=True, distro=distro)
        if proc.returncode != 0:
            detail = (proc.stdout or "") + "\n" + (proc.stderr or "")
            raise RuntimeError(f"No se pudo preparar el toolchain {package_type.upper()} dentro de WSL '{distro}'.\n{detail[-8000:]}")
        verify = cls._wsl_run(["sh", "-lc", check], timeout=30, distro=distro)
        if verify.returncode != 0:
            missing = cls._wsl_run(
                ["sh", "-lc", "for c in " + " ".join(required) + "; do command -v \"$c\" >/dev/null 2>&1 || echo \"$c\"; done"],
                timeout=30,
                distro=distro,
            )
            missing_names = ", ".join(x.strip() for x in (missing.stdout or "").splitlines() if x.strip()) or "dependencias desconocidas"
            raise RuntimeError(f"WSL '{distro}' terminó la preparación pero aún faltan: {missing_names}.")
        return distro

    @staticmethod
    def _write_ar_member(stream, name: str, payload: bytes, *, mode: int = 0o100644) -> None:
        ident = (name + "/")[:16].ljust(16)
        header = (
            ident
            + str(int(time.time())).ljust(12)
            + "0".ljust(6)
            + "0".ljust(6)
            + format(mode, "o").ljust(8)
            + str(len(payload)).ljust(10)
            + "`\n"
        ).encode("ascii")
        stream.write(header)
        stream.write(payload)
        if len(payload) % 2:
            stream.write(b"\n")

    @classmethod
    def _build_deb_python(cls, root: Path, debian: Path, final: Path) -> None:
        # Build a valid .deb with Python only, so Windows does not require WSL.
        stage = final.parent / (final.stem + "-debpy")
        stage.mkdir(parents=True, exist_ok=True)
        control_tar = stage / "control.tar.gz"
        data_tar = stage / "data.tar.gz"

        def normalize(info: tarfile.TarInfo) -> tarfile.TarInfo:
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            info.mtime = int(time.time())
            if info.isdir():
                info.mode = 0o755
            elif (
                info.name.endswith("/postinst") or info.name == "./postinst" or
                info.name.endswith("/prerm") or info.name == "./prerm" or
                info.name.endswith("/postrm") or info.name == "./postrm" or
                info.name.endswith("/usr/local/bin/gideon-agent-configure") or
                info.name.endswith("/usr/local/bin/gideon-agent-setup") or
                info.name.endswith("/usr/local/bin/gideon-agent-first-run") or
                 info.name.endswith("/usr/local/bin/gideon-agent-player-launch") or
                info.name.endswith("/opt/gideon-agent/gideon-agent-setup") or
                info.name.endswith("/opt/gideon-agent/gideon-agent-first-run-launch") or
                 info.name.endswith("/opt/gideon-agent/gideon-agent-first-run-native") or
                 info.name.endswith("/opt/gideon-agent/gideon-agent-player-launch")
            ):
                info.mode = 0o755
            elif info.name.endswith("/opt/gideon-agent/bootstrap.enrollment"):
                info.mode = 0o600
            else:
                info.mode = 0o644
            return info

        with tarfile.open(control_tar, "w:gz", format=tarfile.GNU_FORMAT) as tar:
            for item in sorted(debian.iterdir(), key=lambda x: x.name):
                tar.add(item, arcname=f"./{item.name}", recursive=True, filter=normalize)
        with tarfile.open(data_tar, "w:gz", format=tarfile.GNU_FORMAT) as tar:
            for item in sorted(root.iterdir(), key=lambda x: x.name):
                if item.name == "DEBIAN":
                    continue
                tar.add(item, arcname=f"./{item.name}", recursive=True, filter=normalize)

        final.parent.mkdir(parents=True, exist_ok=True)
        with final.open("wb") as stream:
            stream.write(b"!<arch>\n")
            cls._write_ar_member(stream, "debian-binary", b"2.0\n")
            cls._write_ar_member(stream, "control.tar.gz", control_tar.read_bytes())
            cls._write_ar_member(stream, "data.tar.gz", data_tar.read_bytes())

    @staticmethod
    def _normalize_deb_tree_permissions(root: Path, debian: Path) -> None:
        """Make native dpkg output deterministic under a hardened service umask.

        systemd runs WebAdmin with UMask=0027.  Without explicit normalization,
        DEBIAN/ and the payload roots become 0750; dpkg-deb rejects the control
        directory and desktop users cannot traverse /opt/gideon-agent for first run.
        """
        executable_relatives = {
            "DEBIAN/preinst", "DEBIAN/postinst", "DEBIAN/prerm", "DEBIAN/postrm",
            "opt/gideon-agent/gideon-agent-setup",
            "opt/gideon-agent/gideon-agent-first-run-launch",
            "opt/gideon-agent/gideon-agent-first-run-native",
             "opt/gideon-agent/gideon-agent-player-launch",
            "usr/local/bin/gideon-agent-configure",
            "usr/local/bin/gideon-agent-setup",
            "usr/local/bin/gideon-agent-first-run",
             "usr/local/bin/gideon-agent-player-launch",
        }
        root = Path(root)
        debian = Path(debian)
        root.chmod(0o755)
        debian.chmod(0o755)
        for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
            if path.is_symlink():
                continue
            relative = path.relative_to(root).as_posix()
            if path.is_dir():
                path.chmod(0o755)
            elif relative == "opt/gideon-agent/bootstrap.enrollment":
                path.chmod(0o600)
            elif relative in executable_relatives:
                path.chmod(0o755)
            else:
                path.chmod(0o644)

    def _compute_build_capability(self, target_id: str) -> dict[str, object]:
        if target_id not in TARGETS:
            return {"ready": False, "backend": "unknown", "detail": "Plataforma objetivo desconocida."}
        target = TARGETS[target_id]
        package_type = self._native_package_type(target)
        platform_name = str(target.get("platform") or "")
        if package_type == "exe":
            backend, executable = WindowsExePackager.preferred_backend()
            brand = self.branding.load()
            if executable:
                signing = WindowsExePackager(self.app_root).signer.readiness(brand, self.app_root)
                sign_text = "firma lista" if signing.status == "ready" else ("firma deshabilitada" if signing.status == "disabled" else "firma pendiente")
                if backend == "inno":
                    return {
                        "ready": True,
                        "backend": "Windows EXE directo · Inno Setup",
                        "detail": f"EXE directo con metadatos/version info/icono + Authenticode ({sign_text}); sin MSI ni formatos intermedios.",
                    }
                if backend == "gideon_sfx":
                    return {
                        "ready": True,
                        "backend": "Windows EXE directo · GIDEON SFX (.NET)",
                        "detail": f"Backend integrado con .NET Framework csc.exe + payload embebido + Authenticode ({sign_text}); no depende de IExpress.",
                    }
                if backend == "prebuilt_sfx":
                    if brand.signing.required and os.name != "nt":
                        return {
                            "ready": False,
                            "backend": "GIDEON SFX cross-platform · firma requerida",
                            "detail": "El SFX verificado está disponible, pero la política exige Authenticode. Genere en un nodo Windows con SignTool o cambie explícitamente la política de firma.",
                        }
                    return {
                        "ready": True,
                        "backend": "GIDEON SFX cross-platform verificado",
                        "detail": "Ubuntu genera directamente el EXE usando lanzador y servicio Windows precompilados, verificados por SHA-256; no requiere Wine, csc.exe ni IExpress.",
                    }
                return {
                    "ready": True,
                    "backend": "Windows EXE directo · IExpress (última contingencia)",
                    "detail": f"Fallback IExpress endurecido + Authenticode ({sign_text}); usa TEMP/TMP privados y genera diagnóstico automático ante fallo.",
                }
            return {
                "ready": False,
                "backend": "Windows EXE directo",
                "detail": "Falta backend EXE. Restaure el SFX precompilado GIDEON o, en Windows, instale Inno Setup 6/repare csc.exe.",
            }
        if package_type == "deb" and os.name == "nt":
            return {"ready": True, "backend": "Windows · Python DEB", "detail": "Generación DEB nativa sin WSL/dpkg-deb."}
        if package_type in {"deb", "rpm"}:
            tool = "dpkg-deb" if package_type == "deb" else "rpmbuild"
            if sys.platform.startswith("linux"):
                if package_type == "rpm":
                    required = self._rpm_required_commands()
                    missing = [name for name in required if not shutil.which(name)]
                    ready = not missing
                    detail = "Toolchain RPM listo." if ready else "Faltan para RPM: " + ", ".join(missing) + ". Use Configuración > Requisitos del sistema."
                else:
                    ready = bool(shutil.which(tool))
                    detail = f"{tool} disponible." if ready else f"Falta {tool} en este Linux."
                return {"ready": ready, "backend": "Linux local", "detail": detail}
            if os.name == "nt":
                wsl = self._wsl_executable()
                if not wsl:
                    return {"ready": False, "backend": "WSL", "detail": "Falta WSL. Instale una distribución Linux compatible antes de generar RPM."}
                return {"ready": True, "backend": "WSL · validación bajo demanda", "detail": f"WSL está disponible. La distribución y {tool} se validan/preparan en segundo plano únicamente al iniciar el build."}
            return {"ready": False, "backend": "Linux", "detail": f"{package_type.upper()} requiere Linux o WSL en Windows."}
        if package_type == "tar.gz":
            return {
                "ready": True,
                "backend": "Portable TAR.GZ",
                "detail": "Paquete portable generable directamente desde el Control Plane; no requiere toolchain nativo del SO destino.",
            }
        if package_type == "pkg":
            if sys.platform == "darwin" and shutil.which("pkgbuild"):
                return {"ready": True, "backend": "macOS local", "detail": "pkgbuild disponible."}
            if sys.platform == "darwin":
                return {"ready": False, "backend": "macOS local", "detail": "Falta pkgbuild/Xcode Command Line Tools."}
            return {
                "ready": False,
                "backend": "macOS requerido",
                "detail": "Apple PKG debe compilarse en macOS con pkgbuild. En Windows se bloquea el botón para evitar un error inválido.",
            }
        return {"ready": False, "backend": platform_name or "desconocido", "detail": f"Formato {package_type} no soportado."}

    def build_capability(self, target_id: str) -> dict[str, object]:
        """Cached build capability probe.

        Tool discovery (IExpress/WSL/rpmbuild) launches external processes. Re-running
        those probes on every table repaint made sidebar navigation visibly stall.
        Capabilities are shared by package/platform and cached briefly; explicit
        build attempts still perform their own hard validation.
        """
        if target_id not in TARGETS:
            return {"ready": False, "backend": "unknown", "detail": "Plataforma objetivo desconocida."}
        target = TARGETS[target_id]
        package_type = self._native_package_type(target)
        cache_key = f"{target.get('platform','')}:{package_type}"
        now = time.monotonic()
        cached = self._capability_cache.get(cache_key)
        if cached and now - float(cached[0]) < 20.0:
            return dict(cached[1])
        result = self._compute_build_capability(target_id)
        self._capability_cache[cache_key] = (now, dict(result))
        return result

    def invalidate_capability_cache(self) -> None:
        self._capability_cache.clear()

    def rows(self):
        history=[]
        if self.registry.exists():
            try:history=json.loads(self.registry.read_text(encoding="utf-8"))
            except Exception:history=[]
        result=[]
        for tid,target in TARGETS.items():
            builds=[x for x in history if x.get("target_id")==tid]
            latest=builds[0] if builds else None
            result.append({
                "target_id":tid,**target,
                "available_version":(latest or {}).get("version") or AGENT_VERSION,
                "channel":(latest or {}).get("channel") or "source",
                "bundle":(latest or {}).get("bundle"),
                "built_at":(latest or {}).get("built_at"),
            })
        return result

    def versions_for(self,target_id):
        if not self.registry.exists():return []
        try:rows=json.loads(self.registry.read_text(encoding="utf-8"))
        except Exception:return []
        return [x for x in rows if x.get("target_id")==target_id]

    def activity(self,*,target_id: str | None = None, limit: int = 200):
        """Historial de generación de paquetes de agente, más reciente primero.

        Fuente única de verdad para cualquier vista de "actividad" del módulo
        de Agentes: cada elemento corresponde a una ejecución de ``generate``.
        """
        if not self.registry.exists():return []
        try:rows=json.loads(self.registry.read_text(encoding="utf-8"))
        except Exception:return []
        if target_id:
            rows=[row for row in rows if row.get("target_id")==target_id]
        rows=sorted(rows,key=lambda row: str(row.get("built_at") or ""),reverse=True)
        return rows[:max(0,limit)]

    @staticmethod
    def _runtime_string_constant(path: Path, name: str) -> str:
        text = Path(path).read_text(encoding="utf-8-sig")
        match = re.search(
            rf"(?m)^\s*{re.escape(name)}\s*=\s*([\"'])([^\"']+)\1\s*$",
            text,
        )
        if not match:
            raise RuntimeError(f"RUNTIME_CONSTANT_MISSING: {Path(path).name}:{name}")
        return str(match.group(2)).strip()

    @classmethod
    def _validate_universal_runtime_contract(cls, payload: Path) -> dict[str, object]:
        payload = Path(payload)
        agent_path = payload / "gideon_agent.py"
        tunnel_path = payload / "gideon_reverse_tunnel.py"
        if not agent_path.is_file() or not tunnel_path.is_file():
            raise RuntimeError(
                "RUNTIME_BUNDLE_INCOMPLETE: gideon_agent.py + gideon_reverse_tunnel.py "
                "must travel together for Windows, Linux and macOS."
            )

        agent_text = agent_path.read_text(encoding="utf-8-sig")
        tunnel_text = tunnel_path.read_text(encoding="utf-8-sig")
        req = re.search(r"(?m)^REVERSE_TUNNEL_API_REQUIRED\s*=\s*(\d+)\s*$", agent_text)
        got = re.search(r"(?m)^TUNNEL_API_VERSION\s*=\s*(\d+)\s*$", tunnel_text)
        if not req or not got:
            raise RuntimeError("RUNTIME_CONTRACT_MISSING: API constants not found.")
        required = int(req.group(1))
        provided = int(got.group(1))
        if required != provided:
            raise RuntimeError(
                f"RUNTIME_CONTRACT_MISMATCH: Agent requires API {required}; "
                f"ReverseTunnel provides API {provided}. BUILD BLOCKED."
            )

        wire = re.search(r'(?m)^TUNNEL_VERSION\s*=\s*["\']([^"\']+)["\']', tunnel_text)
        manifest = {
            "schema": "gideon-agent-runtime-contract/v1",
            "agent_version": cls._runtime_string_constant(agent_path, "VERSION"),
            "reverse_tunnel_api_required": required,
            "reverse_tunnel_api_provided": provided,
            "reverse_tunnel_wire_version": wire.group(1) if wire else "unknown",
            "platform_independent": True,
            "host_service_model": {
                "windows": "windows-scm-service",
                "linux": "systemd",
                "macos": "launchd",
            },
            "remote_access_policy": {
                "mode": "tunnel-only",
                "windows": "manage-rdp-listener-local-loopback-path",
                "linux": "manage-xrdp-loopback-only",
                "macos": "manage-apple-vnc-with-local-secret",
                "open_inbound_firewall": False,
                "require_ready_before_install_success": True,
            },
            "automatic_release_policy": {
                "source": "same-agent-generator-runtime",
                "site_neutral": True,
                "preserve_identity": True,
                "preserve_site": True,
                "preserve_token": True,
                "match": "platform+architecture",
                "channel": "stable"
            },
            "first_run_enrollment_ui": {
                "windows": "native-installer-window",
                "linux_desktop": "native-gtk-or-kde-dialogs+polkit",
                "linux_headless": "terminal-fallback",
                "macos": "native-applescript-dialogs+administrator-privileges",
                "browser_wizard": False,
                "bootstrap_secret_exposed_to_ui": False,
                "autolaunch_after_package_install": True,
            },
            "installer_interaction_policy": {
                "manual_desktop_install": "always-visible",
                "fresh_install": "native-identification-and-progress",
                "repair_or_orphan": "native-repair-progress-and-result",
                "headless_linux": "terminal-progress",
                "webadmin_automatic_update": "silent-noninteractive",
                "explicit_unattended_install": "silent-only-when-requested",
                "no_success_before_final_acceptance": True,
            },
            "orphan_recovery_policy": {
                "enabled": True,
                "scope": "every-generated-installer",
                "detect": [
                    "legacy-install-root",
                    "missing-or-inactive-native-service",
                    "missing-or-stale-status",
                    "missing-runtime-identity",
                    "broken-service-host",
                    "legacy-task-or-launcher",
                    "configuration-schema-behind-package",
                ],
                "same_site": "preserve-agent-id-when-possible; migrate-config; replace-runtime; repair-host; re-enroll-only-if-token-invalid",
                "different_site": "backup-old-state; purge-old-identity-token; enroll-selected-site",
                "partial_or_corrupt": "backup-quarantine; rebuild-current-config; enroll",
                "success_requires_final_acceptance": True,
                "backup_before_repair": True,
            },
            "final_acceptance_gate": {
                "required": True,
                "checks": [
                    "runtime-integrity",
                    "identity-config",
                    "enrollment-heartbeat-selftest",
                    "os-service-active",
                    "agent-process-status",
                    "remote-access-local-listener",
                ],
                "success_only_after_all_checks": True,
                "full_sanitized_error_report": True,
                "error_report_copyable": True,
            },
            "installation_policy": {
                "generated_manual_installer": "adaptive-reinstall",
                "same_site": "preserve-agentid-token-overwrite-runtime-host",
                "different_site": "backup-purge-identity-reenroll",
                "webadmin_deployed_update": "separate-preserve-identity-in-place",
            },
            "required_common_files": ["gideon_agent.py", "gideon_reverse_tunnel.py"],
            "sha256": {
                "gideon_agent.py": hashlib.sha256(agent_path.read_bytes()).hexdigest(),
                "gideon_reverse_tunnel.py": hashlib.sha256(tunnel_path.read_bytes()).hexdigest(),
            },
        }
        (payload / "runtime.contract.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return manifest

    def _stage_debian_offline_wheelhouse(
        self,
        payload: Path,
        *,
        allow_download: bool,
    ) -> dict[str, object]:
        """Stage the small, architecture-neutral DEB wheelhouse before signing.

        Debian/Raspberry packages intentionally obtain cryptography, Pillow,
        six and Xlib from signed distribution packages. The only PyPI package
        they need is pystray, which is a pure-Python wheel. Downloading it at
        install time would make the advertised offline installer depend on
        PyPI and could turn a transient outage into a half-installed Agent.

        The builder may fetch the wheel once into its local cache. The endpoint
        always uses no-index and the installer contract hashes the cache
        manifest and every staged wheel. A missing cache fails closed when
        downloads were explicitly disabled.
        """
        payload = Path(payload).resolve()
        requirements_path = payload / "requirements-agent.txt"
        requirements_text = requirements_path.read_text(encoding="utf-8-sig")
        if requirements_text != DEBIAN_AGENT_REQUIREMENTS:
            raise RuntimeError("GIDEON_OFFLINE_WHEELHOUSE_REQUIREMENTS_MISMATCH")

        requirements_sha256 = hashlib.sha256(requirements_text.encode("utf-8")).hexdigest()
        cache_base = (Path(self.builder.state_dir) / "runtime-cache" / "linux-deb-wheelhouse").resolve()
        cache_root = (cache_base / requirements_sha256).resolve()
        try:
            cache_root.relative_to(cache_base)
        except ValueError as exc:
            raise RuntimeError("GIDEON_OFFLINE_WHEELHOUSE_CACHE_ESCAPE") from exc
        cache_base.mkdir(parents=True, exist_ok=True)
        wheel_dir = cache_root / "wheels"
        metadata_path = cache_root / "wheelhouse.json"

        def validated_rows() -> list[dict[str, object]]:
            try:
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            except Exception:
                return []
            if not isinstance(metadata, dict):
                return []
            if metadata.get("schema") != "gideon-agent-linux-deb-wheelhouse/v1":
                return []
            if str(metadata.get("requirements_sha256") or "") != requirements_sha256:
                return []
            rows = metadata.get("files")
            if not isinstance(rows, list) or not rows:
                return []
            validated: list[dict[str, object]] = []
            for raw in rows:
                if not isinstance(raw, dict):
                    return []
                name = str(raw.get("name") or "")
                if not name or name != Path(name).name or not name.casefold().endswith(".whl"):
                    return []
                path = wheel_dir / name
                if path.is_symlink() or not path.is_file() or path.stat().st_size < 1 or path.stat().st_size > 64 * 1024 * 1024:
                    return []
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                if digest != str(raw.get("sha256") or "").casefold():
                    return []
                try:
                    with zipfile.ZipFile(path, "r") as archive:
                        if archive.testzip() is not None:
                            return []
                        if not any(member.casefold().endswith(".dist-info/wheel") for member in archive.namelist()):
                            return []
                except (OSError, zipfile.BadZipFile):
                    return []
                validated.append({"name": name, "sha256": digest, "size_bytes": int(path.stat().st_size)})
            if len(validated) != 1 or not str(validated[0]["name"]).casefold().startswith("pystray-"):
                return []
            return validated

        rows = validated_rows()
        if not rows:
            if not allow_download:
                raise RuntimeError(
                    "GIDEON_OFFLINE_WHEELHOUSE_MISSING: no existe una rueda DEB verificada en la caché del Builder."
                )
            cache_root.mkdir(parents=True, exist_ok=True)
            if wheel_dir.exists():
                resolved_wheels = wheel_dir.resolve()
                try:
                    resolved_wheels.relative_to(cache_root)
                except ValueError as exc:
                    raise RuntimeError("GIDEON_OFFLINE_WHEELHOUSE_CACHE_ESCAPE") from exc
                shutil.rmtree(resolved_wheels)
            wheel_dir.mkdir(parents=True, exist_ok=True)
            proc = subprocess.run(
                [
                    sys.executable, "-m", "pip", "download",
                    "--disable-pip-version-check", "--only-binary=:all:", "--no-deps",
                    "--dest", str(wheel_dir), "-r", str(requirements_path),
                ],
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
            if proc.returncode != 0:
                detail = " ".join(((proc.stderr or proc.stdout or "")[-900:]).split())
                raise RuntimeError("GIDEON_OFFLINE_WHEELHOUSE_DOWNLOAD_FAILED" + (": " + detail if detail else ""))
            generated = [path for path in wheel_dir.glob("*.whl") if path.is_file() and not path.is_symlink()]
            if len(generated) != 1 or not generated[0].name.casefold().startswith("pystray-"):
                raise RuntimeError("GIDEON_OFFLINE_WHEELHOUSE_UNEXPECTED_CONTENT")
            generated_path = generated[0]
            try:
                with zipfile.ZipFile(generated_path, "r") as archive:
                    if archive.testzip() is not None or not any(
                        member.casefold().endswith(".dist-info/wheel") for member in archive.namelist()
                    ):
                        raise RuntimeError("GIDEON_OFFLINE_WHEELHOUSE_WHEEL_INVALID")
            except (OSError, zipfile.BadZipFile) as exc:
                raise RuntimeError("GIDEON_OFFLINE_WHEELHOUSE_WHEEL_INVALID") from exc
            record = {
                "schema": "gideon-agent-linux-deb-wheelhouse/v1",
                "requirements_sha256": requirements_sha256,
                "files": [{
                    "name": generated_path.name,
                    "sha256": hashlib.sha256(generated_path.read_bytes()).hexdigest(),
                    "size_bytes": int(generated_path.stat().st_size),
                }],
            }
            temporary_metadata = metadata_path.with_suffix(".tmp")
            temporary_metadata.write_text(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
            os.replace(temporary_metadata, metadata_path)
            rows = validated_rows()
            if not rows:
                raise RuntimeError("GIDEON_OFFLINE_WHEELHOUSE_VALIDATION_FAILED")

        vendor = payload / "vendor"
        vendor.mkdir(parents=True, exist_ok=True)
        required = ["vendor/wheelhouse.json"]
        payload_metadata = {
            "schema": "gideon-agent-linux-deb-wheelhouse/v1",
            "requirements_sha256": requirements_sha256,
            "files": rows,
        }
        (vendor / "wheelhouse.json").write_text(
            json.dumps(payload_metadata, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        for row in rows:
            name = str(row["name"])
            source = wheel_dir / name
            target = vendor / name
            shutil.copy2(source, target)
            if hashlib.sha256(target.read_bytes()).hexdigest() != str(row["sha256"]):
                raise RuntimeError("GIDEON_OFFLINE_WHEELHOUSE_COPY_HASH_MISMATCH")
            required.append(f"vendor/{name}")
        return {"RequiredFiles": required, "Files": rows}

    def generate(
        self, target_id: str, *, version: str, channel: str, gateway_url: str, output_dir: Path,
        package_type: str = "native", gateway_ca_file_override: Path | None = None,
        enrollment_grant: str | None = None, site_code: str = "", site_name: str = "",
        agent_name: str = "", allow_toolchain_install: bool = True,
        connectivity_mode: str = "production", gateway_endpoints: list[dict[str, Any]] | None = None,
        offline_vlc_distribution: str = "", offline_vlc_codename: str = "",
        vlc_delivery: str = "bundled",
        source_companion_dir: Path | None = None,
        source_companion_descriptor: Mapping[str, Any] | None = None,
    ) -> Path:
        if target_id not in TARGETS: raise KeyError(target_id)
        # Antes esta ruta (usada por "Descargas por SO") no exigía HTTPS,
        # a diferencia de AgentBuilder.generate(); permitía generar un
        # paquete productivo apuntando a http:// que recién fallaría en el
        # equipo final. Se alinea con la misma validación.
        gateway_url = str(gateway_url or "").strip()
        if not gateway_url:
            gateway_url = str(ensure_gateway_configuration()["public_url"]).rstrip("/")
        if not gateway_url.lower().startswith("https://"):
            raise ValueError("El Gateway debe ser https:// para generar paquetes de agente.")
        from gideon_agent_connectivity import is_loopback_url, normalize_mode
        connectivity_mode = normalize_mode(connectivity_mode)
        if connectivity_mode != "local_test" and is_loopback_url(gateway_url):
            raise ValueError("Loopback solo está permitido en LOCAL_TEST.")
        if connectivity_mode == "local_test" and not is_loopback_url(gateway_url):
            raise ValueError("LOCAL_TEST debe usar localhost/127.0.0.1.")
        normalized_endpoints: list[dict[str, Any]] = []
        seen_endpoint_urls: set[str] = set()
        raw_candidates = list(gateway_endpoints or [])
        raw_candidates.insert(0, {"url": gateway_url.rstrip("/"), "role": "primary", "priority": 10, "label": "Seleccionado"})
        for index, item in enumerate(raw_candidates):
            if isinstance(item, dict):
                url = str(item.get("url") or "").strip().rstrip("/")
                role = str(item.get("role") or ("primary" if index == 0 else "secondary")).strip().lower()
                try:
                    priority = int(item.get("priority", 10 + index * 10))
                except (TypeError, ValueError):
                    priority = 10 + index * 10
                label = str(item.get("label") or "").strip()
            else:
                url = str(item or "").strip().rstrip("/")
                role = "primary" if index == 0 else "secondary"
                priority = 10 + index * 10
                label = ""
            if not url.lower().startswith("https://"):
                continue
            if connectivity_mode == "local_test" and not is_loopback_url(url):
                continue
            if connectivity_mode != "local_test" and is_loopback_url(url):
                continue
            key = url.casefold()
            if key in seen_endpoint_urls:
                continue
            seen_endpoint_urls.add(key)
            normalized_endpoints.append({"url": url, "role": role, "priority": priority, "label": label})
        if not normalized_endpoints:
            raise ValueError("No existe ningún endpoint válido para el Agent.")
        normalized_endpoints.sort(key=lambda x: (int(x.get("priority") or 100), str(x.get("url") or "")))
        target=TARGETS[target_id]
        # ``detached`` keeps the reviewed VLC runtime inside the operational
        # installer and moves only corresponding-source archives into a signed,
        # content-addressed companion.  The unpublished runtime component mode
        # remains fail-closed; ``bundled`` is the complete-kit fallback.
        vlc_delivery = str(vlc_delivery or "bundled").strip().lower()
        if vlc_delivery == "component":
            raise ValueError(
                "AGENT_VLC_COMPONENT_DELIVERY_UNAVAILABLE: use bundled hasta publicar el canal autenticado."
            )
        if vlc_delivery not in {"bundled", "detached"}:
            raise ValueError("Entrega VLC inválida. Use bundled o detached.")
        if vlc_delivery == "bundled" and source_companion_descriptor is not None:
            raise ValueError("SOURCE_COMPANION_UNEXPECTED_FOR_BUNDLED")
        self.last_vlc_source_companion = None
        profile=self.profiles.get(target["profile"])
        brand=self.branding.load()
        ensure_ed25519_keypair(self.builder.private_key,self.builder.public_key)
        local_gateway_info: dict[str, object] = {}
        if gateway_ca_file_override is not None:
            gateway_ca_file = Path(gateway_ca_file_override).expanduser().resolve()
            if not gateway_ca_file.is_file():
                raise FileNotFoundError(f"CA del Gateway no disponible: {gateway_ca_file}")
        else:
            try:
                local_gateway_info = dict(ensure_gateway_configuration())
            except Exception:
                local_gateway_info = {}
            gateway_ca_file = Path(str(local_gateway_info.get("ca_file") or (self.builder.app_root / "config" / "gateway-tls" / "gideon_gateway_trust_bundle.pem")))
        if local_gateway_info:
            self._ensure_local_gateway_tls_ready(gateway_url, local_gateway_info)
            # The repair path may have renewed the leaf/bundle; re-resolve it.
            try:
                local_gateway_info = dict(ensure_gateway_configuration())
                gateway_ca_file = Path(str(local_gateway_info.get("ca_file") or gateway_ca_file))
            except Exception as exc:
                best_effort_warning("No se pudo resolver la CA desde la configuración local del Gateway", exc)
        if not gateway_ca_file.exists():
            configured_ca = Path(str((self.builder.app_root / "config" / "config.json")))
            try:
                main_cfg=json.loads(configured_ca.read_text(encoding="utf-8-sig"))
                candidate=Path(str(main_cfg.get("agent_control_plane",{}).get("ca_file") or ""))
                if candidate.is_file(): gateway_ca_file=candidate
            except Exception as exc: best_effort_warning("No se pudo resolver la CA desde config/config.json", exc)
        out=Path(output_dir);out.mkdir(parents=True,exist_ok=True)
        native_type = self._native_package_type(target)
        package_type = native_type if package_type == "native" else package_type
        if package_type == "zip":
            raise ValueError("ZIP fue retirado como formato predeterminado; seleccione un instalador nativo.")
        final=out/f"{brand.package_basename()}-{target_id}-v{version}.{package_type}"
        require_exe_embedded_contract = False

        with tempfile.TemporaryDirectory(prefix="gideon-agent-download-") as td:
            stage=Path(td)/"bundle";payload=stage/"payload";payload.mkdir(parents=True)
            copy_agent_runtime_payload(self.app_root, payload)
            # Stamp the runtime VERSION so installer/release metadata matches the executable Agent.
            agent_py = payload / "gideon_agent.py"
            agent_text = agent_py.read_text(encoding="utf-8-sig")
            agent_text = re.sub(r'^VERSION\s*=\s*["\'][^"\']+["\']', f'VERSION = "{version}"', agent_text, count=1, flags=re.M)
            agent_py.write_text(agent_text, encoding="utf-8")
            runtime_contract = self._validate_universal_runtime_contract(payload)
            shutil.copy2(self.builder.public_key,payload/"gideon_agent_signing_public.pem")
            if gateway_ca_file.is_file(): shutil.copy2(gateway_ca_file,payload/"gideon_gateway_ca.pem")
            (payload/"host_profile.json").write_text(json.dumps(profile,ensure_ascii=False,indent=2),encoding="utf-8")
            # A DEB must use distro-native cryptography/Pillow.  In particular,
            # Raspberry Pi OS ARMHF cannot reliably compile their current PyPI
            # source distributions during postinst.  Other package families
            # keep the existing requirements/runtime policy unchanged.
            requirements_text = DEBIAN_AGENT_REQUIREMENTS if package_type == "deb" else DEFAULT_REQUIREMENTS
            (payload/"requirements-agent.txt").write_text(requirements_text,encoding="utf-8")
            (payload/"branding.json").write_text(json.dumps(self.branding.as_dict(brand), ensure_ascii=False, indent=2), encoding="utf-8")
            (payload/"configure-agent.py").write_text(CONFIGURATOR,encoding="utf-8")
            tray_png = self.app_root / "assets" / "gideon_agent_tray.png"
            tray_ico = self.app_root / "assets" / "gideon_agent_tray.ico"
            if tray_png.is_file(): shutil.copy2(tray_png, payload / "gideon_agent_tray.png")
            if tray_ico.is_file(): shutil.copy2(tray_ico, payload / "gideon_agent_tray.ico")
            site_catalog = self.app_root / "config" / "sites.csv"
            if site_catalog.is_file():
                shutil.copy2(site_catalog, payload / "site-catalog.csv")
            platform_target = str(target.get("platform") or "")
            if platform_target == "windows":
                windows_setup = self.app_root / "deploy" / "agent" / "windows" / "gideon-agent-setup.ps1"
                windows_uninstall = self.app_root / "deploy" / "agent" / "windows" / "gideon-agent-uninstall.ps1"
                if windows_setup.is_file():
                    # Windows PowerShell 5.1 treats UTF-8 without BOM as the active ANSI
                    # code page. Re-emit installer scripts as UTF-8 BOM so Spanish UI/log
                    # text is not corrupted (Identificación -> IdentificaciÃ³n) on clean PCs.
                    setup_text = windows_setup.read_text(encoding="utf-8-sig")
                    setup_text = re.sub(
                        r"(?m)^\$TargetAgentVersion='[^']*'",
                        f"$TargetAgentVersion='{version}'",
                        setup_text,
                        count=1,
                    )
                    (payload / "gideon-agent-setup.ps1").write_text(
                        setup_text, encoding="utf-8-sig", newline="\r\n"
                    )
                if windows_uninstall.is_file():
                    (payload / "gideon-agent-uninstall.ps1").write_text(
                        windows_uninstall.read_text(encoding="utf-8-sig"), encoding="utf-8-sig", newline="\r\n"
                    )
                # RC22: every Windows native installer is Python-independent at the endpoint.
                # The build host acquires/caches official CPython + Windows wheels once and
                # expands them inside payload/runtime/python before the EXE is compiled.
                cache_override = str(os.environ.get("GIDEON_AGENT_RUNTIME_CACHE_DIR") or "").strip()
                runtime_cache = (Path(cache_override).expanduser() if cache_override else (self.builder.state_dir / "runtime-cache" / "windows-x64-py311"))
                allow_runtime_download = str(os.environ.get("GIDEON_AGENT_RUNTIME_ALLOW_DOWNLOAD", "1")).strip().lower() not in {"0", "false", "no", "off"}
                prepare_windows_private_runtime(
                    app_root=self.app_root, payload_dir=payload, cache_dir=runtime_cache, allow_download=allow_runtime_download
                )
                validate_windows_private_runtime_payload(payload)
            elif platform_target == "linux":
                linux_setup_source = self.app_root / "deploy" / "agent" / "linux" / "gideon-agent-setup"
                if linux_setup_source.is_file():
                    linux_setup_target = payload / "gideon-agent-setup"
                    setup_text = linux_setup_source.read_text(encoding="utf-8-sig")
                    setup_text = re.sub(
                        r'(?m)^TARGET_VERSION="[^"]*"',
                        f'TARGET_VERSION="{version}"',
                        setup_text,
                        count=1,
                    )
                    linux_setup_target.write_text(setup_text, encoding="utf-8", newline="\n")
                    linux_setup_target.chmod(0o755)
            elif platform_target == "darwin":
                mac_setup_source = self.app_root / "deploy" / "agent" / "macos" / "gideon-agent-setup"
                if mac_setup_source.is_file():
                    mac_setup_target = payload / "gideon-agent-setup"
                    setup_text = mac_setup_source.read_text(encoding="utf-8-sig")
                    setup_text = re.sub(
                        r'(?m)^TARGET_VERSION="[^"]*"',
                        f'TARGET_VERSION="{version}"',
                        setup_text,
                        count=1,
                    )
                    mac_setup_target.write_text(setup_text, encoding="utf-8", newline="\n")
                    mac_setup_target.chmod(0o755)
            if platform_target == "linux":
                first_run_source = self.app_root / "deploy" / "agent" / "linux" / "gideon-agent-first-run-native"
                if not first_run_source.is_file():
                    raise RuntimeError("FIRST_RUN_LINUX_NATIVE_SOURCE_MISSING")
                shutil.copy2(first_run_source, payload / "gideon-agent-first-run-native")
                (payload / "gideon-agent-first-run-native").chmod(0o755)
                launch_source = self.app_root / "deploy" / "agent" / "linux" / "gideon-agent-first-run-launch"
                if not launch_source.is_file():
                    raise RuntimeError("FIRST_RUN_LINUX_LAUNCHER_MISSING")
                shutil.copy2(launch_source, payload / "gideon-agent-first-run-launch")
                (payload / "gideon-agent-first-run-launch").chmod(0o755)
                player_launch_source = self.app_root / "deploy" / "agent" / "linux" / "gideon-agent-player-launch"
                if not player_launch_source.is_file():
                    raise RuntimeError("PLAYER_LINUX_LAUNCHER_MISSING")
                shutil.copy2(player_launch_source, payload / "gideon-agent-player-launch")
                (payload / "gideon-agent-player-launch").chmod(0o755)
            elif platform_target == "darwin":
                first_run_source = self.app_root / "deploy" / "agent" / "macos" / "gideon-agent-first-run-native"
                if not first_run_source.is_file():
                    raise RuntimeError("FIRST_RUN_MACOS_NATIVE_SOURCE_MISSING")
                shutil.copy2(first_run_source, payload / "gideon-agent-first-run-native")
                (payload / "gideon-agent-first-run-native").chmod(0o755)

            # Native DEB targets deliberately use distribution packages for
            # architecture-specific crypto/graphics bindings and an embedded,
            # verified pure-Python wheel for the remaining tray dependency.
            # This must happen before the installer contract is signed so the
            # endpoint can install without reaching PyPI.
            offline_python_bundle: dict[str, object] = {"RequiredFiles": [], "Files": []}
            if platform_target == "linux" and package_type == "deb":
                allow_linux_wheel_download = str(
                    os.environ.get("GIDEON_AGENT_RUNTIME_ALLOW_DOWNLOAD", "1")
                ).strip().lower() not in {"0", "false", "no", "off"}
                offline_python_bundle = self._stage_debian_offline_wheelhouse(
                    payload,
                    allow_download=allow_linux_wheel_download,
                )
            # Windows/Linux Player packages fail closed if the reviewed VLC
            # closure for this exact target is unavailable. Other platforms
            # retain their explicit not-bundled capability report.
            source_companion: dict[str, Any] | None = None
            if vlc_delivery == "detached" and platform_target in {"windows", "linux"}:
                companion_root = Path(source_companion_dir or (out / "source-companions"))
                source_companion = resolve_vlc_source_companion(
                    self.app_root,
                    platform_name=platform_target,
                    architecture=str(target.get("architecture") or ""),
                    distribution=offline_vlc_distribution,
                    codename=offline_vlc_codename,
                    signing_private_key=self.builder.private_key,
                    signing_public_key=self.builder.public_key,
                    source_companion_dir=companion_root,
                    existing_descriptor=source_companion_descriptor,
                )
                self.last_vlc_source_companion = source_companion
            offline_vlc_bundle = stage_offline_vlc_bundle(
                self.app_root,
                payload,
                platform_name=platform_target,
                architecture=str(target.get("architecture") or ""),
                distribution=offline_vlc_distribution,
                codename=offline_vlc_codename,
                signing_private_key=self.builder.private_key,
                required=platform_target in {"windows", "linux"},
                source_delivery=vlc_delivery,
                source_companion=(source_companion or {}).get("catalog_reference"),
            )
            if not offline_vlc_bundle.get("Bundled"):
                offline_vlc_bundle["Delivery"] = "not-bundled"
            cfg={
                "schema_version":2,"agent_version":version,"agent_protocol":AGENT_PROTOCOL,
                "site_code":str(site_code or "").strip(),"site_name":str(site_name or "").strip(),
                "agent_name":str(agent_name or "").strip(),"host_profile":target["profile"],
                "data_dir":profile.get("data_dir"),"poll_seconds":5,"status_seconds":5,
                "tray":{"refresh_seconds":5,"heartbeat_stale_seconds":75},
                "update":{"channel":"stable","check_seconds":3600,"auto_install_approved":True,"require_approved":True},
                "security":{"package_signature_required":True,"trusted_signing_public_key":"gideon_agent_signing_public.pem","job_freshness_required":True,"mtls_required":False},
                "control_plane":{
                    "base_url":gateway_url.rstrip("/"),
                    "connectivity_mode":connectivity_mode,
                    "endpoints":normalized_endpoints,
                    "network_check_seconds":3,
                    "require_https":True,"verify_tls":True,"minimum_tls":"TLSv1.2","prefer_tls13":True,
                    "timeout_seconds":20,"ca_file":"gideon_gateway_ca.pem" if gateway_ca_file.is_file() else None,
                    "ca_sha256":file_sha256(gateway_ca_file) if gateway_ca_file.is_file() else ""
                },
                "enrollment_secret_env":"GIDEON_AGENT_ENROLL_SECRET",
                "remote_access":{
                    "enabled":True,
                    "managed_by_installer":True,
                    "require_ready":True,
                    "mode":"tunnel-only",
                    "protocol":"VNC" if platform_target=="darwin" else "RDP",
                    "target_host":"127.0.0.1",
                    "target_port":5900 if platform_target=="darwin" else 3389,
                    "server":"apple-remote-management" if platform_target=="darwin" else ("xrdp" if platform_target=="linux" else "windows-rdp"),
                    "firewall_policy":"do-not-open-inbound",
                    "credentials":"local-os-account" if platform_target!="darwin" else "managed-vnc-secret",
                    "support_state":"",
                    "support_reason":"",
                    "support_detail":""
                },
                "reverse_tunnel":{
                    "enabled":True,
                    "transport":"websocket-tls",
                    "protocol_version":"1.1",
                    "runtime_api_version":2,
                    "allowed_targets":["127.0.0.1:3389","127.0.0.1:5900"],
                    "outbound_only":True,
                    "platform_independent":True
                },
            }
            (payload/"agent.template.json").write_text(json.dumps(cfg,ensure_ascii=False,indent=2),encoding="utf-8")
            explicit_bootstrap = enrollment_grant is not None
            bootstrap_secret = str(
                enrollment_grant if explicit_bootstrap else self._gateway_bootstrap_secret(gateway_url)
            ).strip()
            bootstrap_path = payload / "bootstrap.enrollment"
            bootstrap_contract = payload / "bootstrap.required.json"

            if explicit_bootstrap and not bootstrap_secret:
                raise RuntimeError(
                    "BOOTSTRAP_GRANT_EMPTY: WebAdmin solicitó un instalador pre-enrolado, "
                    "pero el grant temporal llegó vacío. Build bloqueado."
                )

            if bootstrap_secret:
                temp_bootstrap = payload / ".bootstrap.enrollment.tmp"
                temp_bootstrap.write_text(bootstrap_secret, encoding="utf-8", newline="")
                os.replace(temp_bootstrap, bootstrap_path)
                try:
                    bootstrap_path.chmod(0o600)
                except OSError:
                    pass
                bootstrap_contract.write_text(
                    json.dumps(
                        {
                            "schema": "gideon-agent-bootstrap/v1",
                            "required": True,
                            "present_at_build": True,
                            "source": "explicit-web-grant" if explicit_bootstrap else "local-gateway-grant",
                        },
                        ensure_ascii=False,
                        indent=2,
                    ),
                    encoding="utf-8",
                )
                if bootstrap_path.read_text(encoding="utf-8").strip() != bootstrap_secret:
                    raise RuntimeError("BOOTSTRAP_WRITE_VERIFY_FAILED: grant temporal no pudo persistirse en el payload.")
            elif explicit_bootstrap:
                raise RuntimeError("BOOTSTRAP_REQUIRED_BUT_MISSING")

            # RC30.95.18: WebAdmin fail-closed installer contract.  The staged
            # payload is validated before any native package is produced; every
            # installer carries installer.contract.json and may be published as
            # READY only after the same contract is verified again.
            write_installer_contract(
                payload,
                target_id=target_id,
                platform_name=platform_target,
                architecture=str(target.get("architecture") or ""),
                version=version,
                package_type=package_type,
                extra_required=[
                    *list(offline_python_bundle.get("RequiredFiles") or []),
                    *list(offline_vlc_bundle["RequiredFiles"]),
                ],
            )
            self.last_installer_contract = verify_installer_contract(
                payload, expected_version=version, expected_target_id=target_id
            )

            if final.exists(): final.unlink()
            if package_type == "deb":
                root=stage/"deb-root"; debian=root/"DEBIAN"; install=root/"opt"/"gideon-agent"
                service_dir=root/"lib"/"systemd"/"system"; bin_dir=root/"usr"/"local"/"bin"
                app_dir=root/"usr"/"share"/"applications"; autostart_dir=root/"etc"/"xdg"/"autostart"
                debian.mkdir(parents=True); service_dir.mkdir(parents=True); bin_dir.mkdir(parents=True); app_dir.mkdir(parents=True); autostart_dir.mkdir(parents=True)
                shutil.copytree(payload,install,dirs_exist_ok=True)
                arch=self._deb_architecture(target["architecture"])
                self._write_text_lf(
                    debian/"control",
                    f"Package: gideon-agent\nVersion: {version}\nSection: admin\nPriority: optional\nArchitecture: {arch}\n"
                    f"Maintainer: {brand.metadata_text(brand.company_name)}\n"
                    f"Depends: python3 (>= 3.9), python3-venv, python3-pip, systemd, xdg-utils, iproute2, acl, "
                    + ", ".join(DEBIAN_SYSTEM_PYTHON_DEPENDENCIES)
                    + (", zenity" if bool(target.get("native_desktop_ui")) else "")
                    + "\nRecommends: pkexec | policykit-1, zenity | kdialog\n"
                    f"Description: {brand.metadata_text(brand.agent_product_name)}\n {brand.metadata_text(brand.agent_description)}\n",
                )
                service_text = "[Unit]\nDescription=GIDEON Cross-Platform Agent\nAfter=network-online.target\nWants=network-online.target\n[Service]\nType=simple\nExecStart=/opt/gideon-agent/venv/bin/python /opt/gideon-agent/gideon_agent.py --config /opt/gideon-agent/agent.json\nWorkingDirectory=/opt/gideon-agent\nRestart=always\nRestartSec=5\nNoNewPrivileges=true\nPrivateTmp=true\n[Install]\nWantedBy=multi-user.target\n"
                self._write_text_lf(service_dir/"gideon-agent.service", service_text)
                configure_wrapper = "#!/bin/sh\nset -eu\nexec /opt/gideon-agent/venv/bin/python /opt/gideon-agent/configure-agent.py --template /opt/gideon-agent/agent.template.json --out /opt/gideon-agent/agent.json \"$@\"\n"
                self._write_text_lf(bin_dir/"gideon-agent-configure", configure_wrapper); (bin_dir/"gideon-agent-configure").chmod(0o755)
                setup_wrapper = "#!/bin/sh\nset -eu\nexec /opt/gideon-agent/gideon-agent-setup \"$@\"\n"
                self._write_text_lf(bin_dir/"gideon-agent-setup", setup_wrapper); (bin_dir/"gideon-agent-setup").chmod(0o755)
                first_run_wrapper = "#!/bin/sh\nset -eu\nexec /opt/gideon-agent/gideon-agent-first-run-native \"$@\"\n"
                self._write_text_lf(bin_dir/"gideon-agent-first-run", first_run_wrapper); (bin_dir/"gideon-agent-first-run").chmod(0o755)
                player_launch_wrapper = "#!/bin/sh\nset -eu\nexec /opt/gideon-agent/gideon-agent-player-launch \"$@\"\n"
                self._write_text_lf(bin_dir/"gideon-agent-player-launch", player_launch_wrapper); (bin_dir/"gideon-agent-player-launch").chmod(0o755)
                player_service = "[Unit]\nDescription=GIDEON Player physical-screen launcher\nAfter=graphical.target gideon-agent.service\nConditionPathExists=/opt/gideon-agent/gideon-agent-player-launch\n\n[Service]\nType=oneshot\nExecStart=/usr/local/bin/gideon-agent-player-launch\n"
                player_timer = "[Unit]\nDescription=Retry GIDEON Player physical-screen launch\n\n[Timer]\nOnBootSec=30s\nOnUnitActiveSec=30s\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n"
                self._write_text_lf(service_dir/"gideon-agent-player-launch.service", player_service)
                self._write_text_lf(service_dir/"gideon-agent-player-launch.timer", player_timer)
                self._write_text_lf(app_dir/"gideon-agent-first-run.desktop", "[Desktop Entry]\nType=Application\nName=Gideon Rx Agent · Configurar\nExec=/usr/local/bin/gideon-agent-first-run\nTerminal=false\nCategories=System;Settings;\n")
                self._write_text_lf(autostart_dir/"gideon-agent-first-run.desktop", "[Desktop Entry]\nType=Application\nName=Gideon Rx Agent · Primer inicio\nExec=/usr/local/bin/gideon-agent-first-run --auto\nTerminal=false\nNoDisplay=true\nX-GNOME-Autostart-enabled=true\n")
                preinst = (
                    "#!/bin/sh\nset -eu\nROOT=/opt/gideon-agent\nSTATE=/var/lib/gideon-agent\n"
                    "mkdir -p $STATE\n"
                    "if [ -s $ROOT/agent.json ]; then cp -pf $ROOT/agent.json $STATE/agent.json.preupgrade; fi\n"
                    "systemctl stop gideon-agent.service >/dev/null 2>&1 || true\n"
                )
                self._write_text_lf(debian/"preinst", preinst); (debian/"preinst").chmod(0o755)
                postinst = (
                    "#!/bin/sh\nset -eu\nROOT=/opt/gideon-agent\nSTATE=/var/lib/gideon-agent\n"
                    "if [ ! -s $ROOT/agent.json ] && [ -s $STATE/agent.json.preupgrade ]; then cp -pf $STATE/agent.json.preupgrade $ROOT/agent.json; fi\n"
                    "# GIDEON_PLAYER_ROOT_OWNED_RUNTIME_REQUIRED: root keeps code, venv, launcher and Agent state authoritative.\n"
                    "install -d -o root -g root -m 0750 \"$ROOT\" \"$STATE\" /etc/gideon-agent\n"
                    "chown root:root \"$STATE\" /etc/gideon-agent\n"
                    "chmod 0750 \"$STATE\" /etc/gideon-agent\n"
                    "[ -d \"$ROOT\" ] && [ ! -L \"$ROOT\" ] || { echo 'GIDEON_PACKAGE_SECURITY_ERROR: app root inválido.' >&2; exit 1; }\n"
                    "[ ! -e \"$ROOT/venv\" ] || [ ! -L \"$ROOT/venv\" ] || { echo 'GIDEON_PACKAGE_SECURITY_ERROR: venv symlink rechazado.' >&2; exit 1; }\n"
                    "chown -R root:root \"$ROOT\"\n"
                    "find \"$ROOT\" -xdev -type d -exec chmod 0755 {} +\n"
                    "find \"$ROOT\" -xdev -type f -exec chmod 0644 {} +\n"
                    "for executable in \"$ROOT/gideon-agent-setup\" \"$ROOT/gideon-agent-first-run-launch\" \"$ROOT/gideon-agent-first-run-native\" \"$ROOT/gideon-agent-player-launch\"; do [ ! -e \"$executable\" ] || chmod 0755 \"$executable\"; done\n"
                    "for private_file in \"$ROOT/agent.json\" \"$ROOT/bootstrap.enrollment\"; do [ ! -f \"$private_file\" ] || chmod 0600 \"$private_file\"; done\n"
                    "python3 -m venv --clear --system-site-packages \"$ROOT/venv\"\n"
                    "grep -Eiq '^include-system-site-packages[[:space:]]*=[[:space:]]*true$' $ROOT/venv/pyvenv.cfg || { echo 'GIDEON_DEPENDENCY_ERROR: el venv no expone paquetes Python del sistema.' >&2; exit 1; }\n"
                    "[ -d \"$ROOT/vendor\" ] && [ ! -L \"$ROOT/vendor\" ] || { echo 'GIDEON_DEPENDENCY_ERROR: faltan dependencias offline.' >&2; exit 1; }\n"
                    "$ROOT/venv/bin/pip install --no-index --find-links=\"$ROOT/vendor\" --disable-pip-version-check --only-binary=:all: --no-deps -r $ROOT/requirements-agent.txt\n"
                    "$ROOT/venv/bin/python -c \"import importlib.metadata,sys;sys.path.insert(0,'/opt/gideon-agent');import cryptography,PIL,gideon_agent,gideon_reverse_tunnel,gideon_agent_http,gideon_agent_security,gideon_agent_worker,gideon_common;print(gideon_agent.VERSION, 'cryptography', cryptography.__version__, 'Pillow', PIL.__version__, 'pystray', importlib.metadata.version('pystray'))\"\n"
                    "chown -R root:root \"$ROOT\"\n"
                    "find \"$ROOT\" -xdev -type d -exec chmod 0755 {} +\n"
                    "find \"$ROOT\" -xdev -type f -exec chmod 0644 {} +\n"
                    "find \"$ROOT/venv/bin\" -xdev -type f -exec chmod 0755 {} +\n"
                    "for executable in \"$ROOT/gideon-agent-setup\" \"$ROOT/gideon-agent-first-run-launch\" \"$ROOT/gideon-agent-first-run-native\" \"$ROOT/gideon-agent-player-launch\"; do [ ! -e \"$executable\" ] || chmod 0755 \"$executable\"; done\n"
                    "for private_file in \"$ROOT/agent.json\" \"$ROOT/bootstrap.enrollment\"; do [ ! -f \"$private_file\" ] || chmod 0600 \"$private_file\"; done\n"
                    "systemctl daemon-reload >/dev/null 2>&1 || true\n"
                    "systemctl enable --now gideon-agent-player-launch.timer >/dev/null 2>&1 || true\n"
                    "if [ -s $ROOT/agent.json ]; then\n"
                    "  echo 'RUNNING|Detectando instalación anterior y migrando configuración…' >$STATE/package-ui.state\n"
                    "  nohup $ROOT/gideon-agent-first-run-launch --package-progress >>$STATE/first-run-launch.log 2>&1 </dev/null &\n"
                    "  echo 'Gideon Rx Agent previo detectado: ejecutando reparación/migración integral y recuperación de huérfano si corresponde.'\n"
                    "  set +e\n"
                    "  $ROOT/gideon-agent-setup --non-interactive >$STATE/package-repair.log 2>&1\n"
                    "  repair_rc=$?\n"
                    "  set -e\n"
                    "  if [ $repair_rc -eq 0 ]; then\n"
                    "    echo 'SUCCESS|Gideon Rx Agent quedó actualizado, migrado y validado correctamente.' >$STATE/package-ui.state\n"
                    "    echo 'Gideon Rx Agent actualizado, migrado y validado.'\n"
                    "  else\n"
                    "    diag=$(sed -n 's/^GIDEON_DIAGNOSTIC_FILE=//p' $STATE/package-repair.log | tail -n1)\n"
                    "    echo \"ERROR|La reparación terminó con error $repair_rc. DIAG=$diag\" >$STATE/package-ui.state\n"
                    "    cat $STATE/package-repair.log\n"
                    "    exit $repair_rc\n"
                    "  fi\n"
                    "else\n"
                    "  chmod 0755 $ROOT/gideon-agent-setup $ROOT/gideon-agent-first-run-launch $ROOT/gideon-agent-first-run-native /usr/local/bin/gideon-agent-first-run /usr/local/bin/gideon-agent-setup 2>/dev/null || true\n"
                    "  graphical_session=0\n"
                    "  if [ -n \"${DISPLAY:-}${WAYLAND_DISPLAY:-}\" ]; then graphical_session=1; fi\n"
                    "  if [ $graphical_session -eq 0 ] && command -v loginctl >/dev/null 2>&1; then\n"
                    "    for sid in $(loginctl list-sessions --no-legend 2>/dev/null | awk '{print $1}'); do\n"
                    "      stype=$(loginctl show-session \"$sid\" -p Type --value 2>/dev/null || true)\n"
                    "      active=$(loginctl show-session \"$sid\" -p Active --value 2>/dev/null || true)\n"
                    "      remote=$(loginctl show-session \"$sid\" -p Remote --value 2>/dev/null || true)\n"
                    "      if { [ \"$stype\" = x11 ] || [ \"$stype\" = wayland ]; } && [ \"$active\" = yes ] && [ \"$remote\" != yes ]; then graphical_session=1; break; fi\n"
                    "    done\n"
                    "  fi\n"
                    "  if [ $graphical_session -eq 1 ]; then\n"
                    "    echo 'GIDEON Agent instalado. Solicitando asistente gráfico de identificación/enrolamiento…'\n"
                    "    nohup $ROOT/gideon-agent-first-run-launch >>$STATE/first-run-launch.log 2>&1 </dev/null &\n"
                    "  else\n"
                    "    echo 'PENDING|Instalación base completa; identificación/enrolamiento pendiente. No hay sesión gráfica activa. Ejecute: sudo gideon-agent-setup' >$STATE/package-ui.state\n"
                    "    echo 'GIDEON Agent instalado pero aún NO configurado: no se detectó una sesión gráfica activa. Ejecute: sudo gideon-agent-setup'\n"
                    "  fi\n"
                    "fi\n"
                    "rm -f $STATE/agent.json.preupgrade\n"
                )
                self._write_text_lf(debian/"postinst", postinst); (debian/"postinst").chmod(0o755)
                self._write_text_lf(debian/"prerm", "#!/bin/sh\nset -eu\nif [ \"${1:-}\" = remove ]; then systemctl disable --now gideon-agent.service >/dev/null 2>&1 || true; fi\n"); (debian/"prerm").chmod(0o755)
                self._write_text_lf(debian/"postrm", "#!/bin/sh\nset -eu\nsystemctl daemon-reload >/dev/null 2>&1 || true\n"); (debian/"postrm").chmod(0o755)
                self._normalize_deb_tree_permissions(root, debian)
                if os.name == "nt" or not shutil.which("dpkg-deb"):
                    self._build_deb_python(root, debian, final)
                else:
                    # Force gzip instead of the host default (commonly data.tar.zst
                    # on modern Ubuntu).  GIDEON verifies installer.contract.json
                    # inside the DEB with Python's portable tar reader before the
                    # WebAdmin may publish it; gzip works identically on amd64,
                    # ARM64 and ARMHF and does not require an optional zstd module.
                    run_hidden(
                        ["dpkg-deb", "--build", "--root-owner-group", "-Zgzip", str(root), str(final)],
                        check=True, capture_output=True, text=True,
                    )
            elif package_type == "rpm":
                if os.name != "nt":
                    missing = [name for name in self._rpm_required_commands() if not shutil.which(name)]
                    if missing:
                        raise RuntimeError(
                            "El toolchain RPM local está incompleto. Faltan: " + ", ".join(missing) +
                            ". Abra Configuración > Requisitos del sistema > RPM build toolchain."
                        )
                elif not self._wsl_executable():
                    raise RuntimeError("RPM requiere WSL con una distribución Linux inicializada en Windows.")
                top=stage/"rpmbuild"
                for name in ("BUILD","BUILDROOT","RPMS","SOURCES","SPECS","SRPMS"): (top/name).mkdir(parents=True)
                source=top/"SOURCES"/"gideon-agent-payload.tar.gz"
                with tempfile.TemporaryDirectory() as src_td:
                    src=Path(src_td)/"gideon-agent"; shutil.copytree(payload,src)
                    with tarfile.open(source,"w:gz") as tar: tar.add(src,arcname="gideon-agent")
                target_arch = str(target.get("architecture") or "").strip().lower()
                # The payload is Python/source only: RPM must be noarch. The target
                # architecture remains a runtime guard/profile instead of forcing
                # rpmbuild to manufacture an architecture-specific empty debuginfo.
                spec = self._rpm_spec(version, target_arch, brand, native_desktop_ui=bool(target.get("native_desktop_ui")))
                spec_path=top/"SPECS"/"gideon-agent.spec"; self._write_text_lf(spec_path,spec)
                if os.name == "nt":
                    distro=self._ensure_wsl_tool("rpm", allow_install=allow_toolchain_install)
                    top_u=self._wsl_path(top,distro=distro); spec_u=self._wsl_path(spec_path,distro=distro)
                    proc=self._wsl_run(["rpmbuild","--define",f"_topdir {top_u}","--define","debug_package %{nil}","-bb",spec_u],timeout=900,as_root=True,distro=distro)
                    if proc.returncode != 0:
                        raise RuntimeError("rpmbuild en WSL no pudo generar el paquete.\n" + ((proc.stdout or "") + "\n" + (proc.stderr or ""))[-8000:])
                else:
                    run_hidden(["rpmbuild","--define",f"_topdir {top}","--define","debug_package %{nil}","-bb",str(spec_path)],check=True,capture_output=True,text=True)
                candidates=list((top/"RPMS").rglob("*.rpm"))
                if not candidates: raise RuntimeError("rpmbuild terminó sin producir un RPM.")
                shutil.copy2(candidates[0],final)
            elif package_type == "exe":
                validate_windows_private_runtime_payload(payload)
                win_packager = WindowsExePackager(self.app_root)
                win_packager.build(
                    payload_dir=payload, final=final, stage=stage, version=version, brand=brand,
                    diagnostics_dir=out / "support",
                )
                signing_result = win_packager.last_signing_result
                require_exe_embedded_contract = win_packager.last_backend == "GIDEON SFX precompilado verificado"
            elif package_type == "tar.gz":
                portable = stage / "portable"
                portable.mkdir(parents=True, exist_ok=True)
                shutil.copytree(payload, portable / "payload", dirs_exist_ok=True)
                install_script = portable / "install-gideon-agent.sh"
                platform_name = str(target.get("platform") or "")
                if platform_name == "darwin":
                    install_script.write_text(
                        "#!/bin/zsh\nset -euo pipefail\n"
                        "ROOT=\"${GIDEON_AGENT_ROOT:-/Library/Application Support/GIDEONAgent}\"\n"
                        "SRC=\"$(cd \"$(dirname \"$0\")\" && pwd)/payload\"\n"
                        "[[ \"$(id -u)\" -eq 0 ]] || { echo 'Ejecute: sudo ./install-gideon-agent.sh' >&2; exit 1; }\n"
                        "mkdir -p \"$ROOT\" /usr/local/bin\ncp -a \"$SRC/.\" \"$ROOT/\"\n"
                        "[[ -x \"$ROOT/venv/bin/python\" ]] || python3 -m venv \"$ROOT/venv\"\n"
                        "\"$ROOT/venv/bin/pip\" install --disable-pip-version-check -r \"$ROOT/requirements-agent.txt\"\n"
                        "chmod 0755 \"$ROOT/gideon-agent-setup\" \"$ROOT/gideon-agent-first-run-native\"\n"
                        "cat > /usr/local/bin/gideon-agent-setup <<'EOF'\n#!/bin/zsh\nexec '/Library/Application Support/GIDEONAgent/gideon-agent-setup' \"$@\"\nEOF\nchmod 0755 /usr/local/bin/gideon-agent-setup\n"
                        "cat > /usr/local/bin/gideon-agent-first-run <<'EOF'\n#!/bin/zsh\nexec '/Library/Application Support/GIDEONAgent/gideon-agent-first-run-native' \"$@\"\nEOF\nchmod 0755 /usr/local/bin/gideon-agent-first-run\n"
                        "mkdir -p /Library/LaunchAgents /var/db/gideon-agent\n"
                        "cat > /Library/LaunchAgents/pe.com.gideons.gideonagent.first-run.plist <<'EOF'\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>pe.com.gideons.gideonagent.first-run</string><key>ProgramArguments</key><array><string>/usr/local/bin/gideon-agent-first-run</string><string>--auto</string></array><key>RunAtLoad</key><true/></dict></plist>\nEOF\nchmod 0644 /Library/LaunchAgents/pe.com.gideons.gideonagent.first-run.plist\n"
                        "u=$(stat -f '%Su' /dev/console 2>/dev/null || true)\n"
                        "if [[ -s \"$ROOT/agent.json\" ]]; then \"$ROOT/gideon-agent-setup\" --non-interactive; elif [[ -n \"$u\" && \"$u\" != root && \"$u\" != loginwindow ]]; then uid=$(id -u \"$u\"); launchctl asuser \"$uid\" /usr/bin/sudo -u \"$u\" /usr/local/bin/gideon-agent-first-run --auto >/var/db/gideon-agent/first-run-session.log 2>&1 &\nelse echo 'Ejecute: gideon-agent-setup'; fi\n",
                        encoding="utf-8", newline="\n",
                    )
                    title="macOS portable"
                elif platform_name == "linux":
                    install_script.write_text(
                        "#!/usr/bin/env bash\nset -euo pipefail\n"
                        "ROOT=\"${GIDEON_AGENT_ROOT:-/opt/gideon-agent}\"\nSRC=\"$(cd \"$(dirname \"$0\")\" && pwd)/payload\"\n"
                        "[[ \"$(id -u)\" -eq 0 ]] || { echo 'Ejecute: sudo ./install-gideon-agent.sh' >&2; exit 1; }\n"
                        "mkdir -p \"$ROOT\" /usr/local/bin /var/lib/gideon-agent /etc/xdg/autostart /usr/share/applications\ncp -a \"$SRC/.\" \"$ROOT/\"\n"
                        "[[ -x \"$ROOT/venv/bin/python\" ]] || python3 -m venv \"$ROOT/venv\"\n"
                        "\"$ROOT/venv/bin/pip\" install --disable-pip-version-check -r \"$ROOT/requirements-agent.txt\"\n"
                        "chmod 0755 \"$ROOT/gideon-agent-setup\" \"$ROOT/gideon-agent-first-run-launch\" \"$ROOT/gideon-agent-first-run-native\" \"$ROOT/gideon-agent-player-launch\"\n"
                        "cat > /usr/local/bin/gideon-agent-setup <<'EOF'\n#!/bin/sh\nexec /opt/gideon-agent/gideon-agent-setup \"$@\"\nEOF\nchmod 0755 /usr/local/bin/gideon-agent-setup\n"
                        "cat > /usr/local/bin/gideon-agent-first-run <<'EOF'\n#!/bin/sh\nexec /opt/gideon-agent/gideon-agent-first-run-native \"$@\"\nEOF\nchmod 0755 /usr/local/bin/gideon-agent-first-run\n"
                        "cat > /usr/local/bin/gideon-agent-player-launch <<'EOF'\n#!/bin/sh\nexec /opt/gideon-agent/gideon-agent-player-launch \"$@\"\nEOF\nchmod 0755 /usr/local/bin/gideon-agent-player-launch\n"
                        "cat > /etc/xdg/autostart/gideon-agent-first-run.desktop <<'EOF'\n[Desktop Entry]\nType=Application\nName=Gideon Rx Agent · Primer inicio\nExec=/usr/local/bin/gideon-agent-first-run --auto\nTerminal=false\nNoDisplay=true\nX-GNOME-Autostart-enabled=true\nEOF\n"
                        "cp -f /etc/xdg/autostart/gideon-agent-first-run.desktop /usr/share/applications/gideon-agent-first-run.desktop\n"
                        "if [[ -s \"$ROOT/agent.json\" ]]; then \"$ROOT/gideon-agent-setup\" --non-interactive; else nohup \"$ROOT/gideon-agent-first-run-launch\" >>/var/lib/gideon-agent/first-run-launch.log 2>&1 </dev/null & echo 'Asistente gráfico solicitado. Si no abre, ejecute: sudo gideon-agent-setup'; fi\n",
                        encoding="utf-8", newline="\n",
                    )
                    title="Linux portable"
                else:
                    raise ValueError("TAR.GZ portable sólo soporta Linux/macOS.")
                install_script.chmod(0o755)
                (portable / "LEAME-INSTALACION.txt").write_text(
                    f"Gideon Rx Agent · {title}\n\n"
                    "1. Extraiga el TAR.GZ.\n2. Abra Terminal en la carpeta.\n"
                    "3. Ejecute: sudo ./install-gideon-agent.sh\n"
                    "4. En escritorio se intentará abrir el asistente de identificación/enrolamiento.\n"
                    "5. Si no hay escritorio: sudo gideon-agent-setup\n",
                    encoding="utf-8",
                )
                with tarfile.open(final, "w:gz") as tar:
                    for item in sorted(portable.rglob("*")):
                        rel = item.relative_to(portable)
                        tar.add(item, arcname=rel.as_posix(), recursive=False)
            elif package_type == "pkg":
                if sys.platform != "darwin" or not shutil.which("pkgbuild"):
                    raise RuntimeError("Apple PKG requiere macOS con pkgbuild/Xcode Command Line Tools. Este build se bloquea en Windows/Linux por diseño.")
                # El payload es Python puro; se crea un PackageRoot reproducible y se
                # delega el formato Apple al pkgbuild nativo de macOS.
                root=stage/"pkg-root"; install=root/"Library"/"Application Support"/"GIDEONAgent"
                scripts=stage/"pkg-scripts"; bin_dir=root/"usr"/"local"/"bin"; launch_agents=root/"Library"/"LaunchAgents"
                install.mkdir(parents=True); scripts.mkdir(parents=True); bin_dir.mkdir(parents=True); launch_agents.mkdir(parents=True)
                shutil.copytree(payload,install,dirs_exist_ok=True)
                launch_dir=root/"Library"/"LaunchDaemons"; launch_dir.mkdir(parents=True,exist_ok=True)
                launch_plist=launch_dir/f"{brand.bundle_id}.plist"
                launch_plist.write_text(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                    "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
                    "<plist version=\"1.0\"><dict>\n"
                    f"<key>Label</key><string>{brand.bundle_id}</string>\n"
                    "<key>ProgramArguments</key><array>"
                    "<string>/Library/Application Support/GIDEONAgent/venv/bin/python</string>"
                    "<string>/Library/Application Support/GIDEONAgent/gideon_agent.py</string>"
                    "<string>--config</string>"
                    "<string>/Library/Application Support/GIDEONAgent/agent.json</string>"
                    "</array>\n"
                    "<key>WorkingDirectory</key><string>/Library/Application Support/GIDEONAgent</string>\n"
                    "<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>\n"
                    "</dict></plist>\n",
                    encoding="utf-8",
                )
                setup_wrapper = bin_dir / "gideon-agent-setup"
                setup_wrapper.write_text("#!/bin/zsh\nset -euo pipefail\nexec '/Library/Application Support/GIDEONAgent/gideon-agent-setup' \"$@\"\n", encoding="utf-8")
                setup_wrapper.chmod(0o755)
                first_run_wrapper = bin_dir / "gideon-agent-first-run"
                first_run_wrapper.write_text("#!/bin/zsh\nset -euo pipefail\nexec '/Library/Application Support/GIDEONAgent/gideon-agent-first-run-native' \"$@\"\n", encoding="utf-8")
                first_run_wrapper.chmod(0o755)
                first_run_label = f"{brand.bundle_id}.first-run"
                (launch_agents/f"{first_run_label}.plist").write_text(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                    "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
                    "<plist version=\"1.0\"><dict>\n"
                    f"<key>Label</key><string>{first_run_label}</string>\n"
                    "<key>ProgramArguments</key><array><string>/usr/local/bin/gideon-agent-first-run</string><string>--auto</string></array>\n"
                    "<key>RunAtLoad</key><true/>\n</dict></plist>\n",
                    encoding="utf-8",
                )
                preinstall=scripts/"preinstall"
                preinstall.write_text(
                    "#!/bin/zsh\nset -euo pipefail\nROOT='/Library/Application Support/GIDEONAgent'\nSTATE='/var/db/gideon-agent'\n"
                    "mkdir -p \"$STATE\"\n"
                    "if [[ -s \"$ROOT/agent.json\" ]]; then cp -pf \"$ROOT/agent.json\" \"$STATE/agent.json.preupgrade\"; fi\n"
                    f"launchctl bootout system /Library/LaunchDaemons/{brand.bundle_id}.plist >/dev/null 2>&1 || true\n"
                    "rm -rf \"$ROOT/gideon_common\" \"$ROOT/__pycache__\"\n"
                    "exit 0\n", encoding="utf-8")
                preinstall.chmod(0o755)
                postinstall=scripts/"postinstall"
                postinstall.write_text(
                    "#!/bin/zsh\nset -euo pipefail\nROOT='/Library/Application Support/GIDEONAgent'\nSTATE='/var/db/gideon-agent'\n"
                    "if [[ ! -s \"$ROOT/agent.json\" && -s \"$STATE/agent.json.preupgrade\" ]]; then cp -pf \"$STATE/agent.json.preupgrade\" \"$ROOT/agent.json\"; fi\n"
                    "[[ -x \"$ROOT/venv/bin/python\" ]] || python3 -m venv \"$ROOT/venv\"\n"
                    "\"$ROOT/venv/bin/pip\" install --disable-pip-version-check -r \"$ROOT/requirements-agent.txt\"\n"
                    "\"$ROOT/venv/bin/python\" -c \"import sys;sys.path.insert(0,'/Library/Application Support/GIDEONAgent');import gideon_agent,gideon_reverse_tunnel,gideon_agent_http,gideon_agent_security,gideon_agent_worker,gideon_common;print(gideon_agent.VERSION)\"\n"
                    "chmod 0755 \"$ROOT/gideon-agent-setup\" /usr/local/bin/gideon-agent-setup 2>/dev/null || true\n"
                    f"if [[ -s \"$ROOT/agent.json\" ]]; then echo 'GIDEON Agent previo detectado: reparación/migración integral.'; set +e; \"$ROOT/gideon-agent-setup\" --non-interactive >\"$STATE/package-repair.log\" 2>&1; repair_rc=$?; set -e; if [[ $repair_rc -eq 0 ]]; then echo 'SUCCESS|GIDEON Remote Control Agent quedó actualizado, migrado y validado correctamente.' >\"$STATE/package-ui.state\"; else diag=$(sed -n 's/^GIDEON_DIAGNOSTIC_FILE=//p' \"$STATE/package-repair.log\" | tail -n1); echo \"ERROR|La reparación terminó con error $repair_rc. Diagnóstico: $diag\" >\"$STATE/package-ui.state\"; fi; u=$(stat -f '%Su' /dev/console 2>/dev/null || true); if [[ -n \"$u\" && \"$u\" != root && \"$u\" != loginwindow ]]; then uid=$(id -u \"$u\"); launchctl asuser \"$uid\" /usr/bin/sudo -u \"$u\" /usr/local/bin/gideon-agent-first-run --package-result >>\"$STATE/first-run-session.log\" 2>&1 &\nfi; [[ $repair_rc -eq 0 ]] || {{ cat \"$STATE/package-repair.log\"; exit $repair_rc; }}; echo 'GIDEON Agent actualizado, migrado y validado.'; else chmod 0755 \"$ROOT/gideon-agent-first-run-native\" /usr/local/bin/gideon-agent-first-run 2>/dev/null || true; u=$(stat -f '%Su' /dev/console 2>/dev/null || true); if [[ -n \"$u\" && \"$u\" != root && \"$u\" != loginwindow ]]; then uid=$(id -u \"$u\"); launchctl asuser \"$uid\" /usr/bin/sudo -u \"$u\" /usr/local/bin/gideon-agent-first-run --auto >>\"$STATE/first-run-session.log\" 2>&1 &\nfi; echo 'GIDEON Agent instalado; asistente gráfico solicitado.'; fi\n"
                    "rm -f \"$STATE/agent.json.preupgrade\"\n"
                    "exit 0\n",encoding="utf-8")
                postinstall.chmod(0o755)
                run_hidden(["pkgbuild","--root",str(root),"--scripts",str(scripts),"--identifier",brand.bundle_id,"--version",version,"--install-location","/",str(final)],check=True,capture_output=True,text=True)
            else:
                raise ValueError(f"Formato de paquete no soportado: {package_type}")

            # Re-verify after platform-specific packaging helpers had a chance to
            # add files (notably GIDEONAgentServiceHost.exe on Windows).
            self.last_installer_contract = verify_installer_contract(
                payload, expected_version=version, expected_target_id=target_id
            )
            self.last_artifact_validation = verify_artifact_sanity(
                final,
                package_type=package_type,
                expected_version=version,
                expected_contract_sha256=str(self.last_installer_contract.get("contract_sha256") or ""),
                require_exe_embedded_contract=require_exe_embedded_contract,
            )
            if str(self.last_artifact_validation.get("status") or "") != "PASS":
                raise RuntimeError("INSTALLER_ARTIFACT_VALIDATION_NOT_PASS")

        rows=[]
        if self.registry.exists():
            try:rows=json.loads(self.registry.read_text(encoding="utf-8"))
            except Exception:rows=[]
        row={
            "target_id":target_id,"label":target["label"],"platform":target["platform"],
            "architecture":target["architecture"],"profile":target["profile"],
            "version":version,"channel":channel,"bundle":str(final),
            "sha256":sha256_file(final),"built_at":now_iso(),
            "company": brand.company_name, "product": brand.agent_product_name,
            "signing": (signing_result.status if package_type == "exe" and 'signing_result' in locals() and signing_result else "n/a"),
            "installer_contract_status": str((self.last_installer_contract or {}).get("status") or ""),
            "installer_contract_sha256": str((self.last_installer_contract or {}).get("contract_sha256") or ""),
            "artifact_validation_status": str((self.last_artifact_validation or {}).get("status") or ""),
            "vlc_delivery": str(offline_vlc_bundle.get("Delivery") or vlc_delivery),
            "vlc_bundled": bool(offline_vlc_bundle.get("Bundled")),
            "vlc_source_companion_sha256": str((self.last_vlc_source_companion or {}).get("sha256") or ""),
        }
        rows.insert(0,row);self.registry.write_text(json.dumps(rows[:300],ensure_ascii=False,indent=2),encoding="utf-8")
        return final
