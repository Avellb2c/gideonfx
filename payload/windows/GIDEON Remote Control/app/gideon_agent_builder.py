from __future__ import annotations

from gideon_common.clock import now_iso
import datetime as dt
import json
import os
import re
from pathlib import Path
import shutil
import tempfile
from typing import Any, Optional

from gideon_host_profiles import HostProfileStore
from gideon_agent_security import ensure_ed25519_keypair, sha256_file, sign_file

from gideon_version import AGENT_VERSION, AGENT_PROTOCOL_VERSION
from gideon_agent_payload import copy_agent_runtime_payload
from gideon_agent_archive import prune_generated_nonruntime_files, write_verified_deflated_zip
from gideon_agent_component import build_vlc_offline_component, resolve_vlc_source_companion
from gideon_agent_vlc_offline import stage_offline_vlc_bundle
from gideon_agent_windows_runtime import DEFAULT_REQUIREMENTS, prepare_windows_private_runtime, validate_windows_private_runtime_payload

AGENT_PROTOCOL = AGENT_PROTOCOL_VERSION
SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$")




def safe_name(value: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in str(value))


def validate_version(value: str) -> str:
    version = str(value or "").strip()
    if not SEMVER_RE.match(version):
        raise ValueError("Versión inválida. Use SemVer, por ejemplo 2.0.0, 2.1.0 o 2.1.0-rc.1")
    return version


def _single_profile_architecture(profile: dict[str, Any]) -> str | None:
    """Return an exact architecture only when a legacy profile is unambiguous.

    The modern catalog generates one native installer per platform/architecture.
    This compatibility ZIP builder can still receive broad profiles such as
    ``windows_generic``.  It must never embed only one VLC kit and present the
    result as a universal offline installer, so those profiles intentionally
    remain external-VLC-only until a native target is selected.
    """
    aliases = {
        "amd64": "x86_64", "x64": "x86_64", "x86-64": "x86_64",
        "aarch64": "arm64", "armv8": "arm64", "armv8l": "arm64",
        "armhf": "armv7l", "armv7": "armv7l",
    }
    values: list[str] = []
    rows = profile.get("architectures") if isinstance(profile, dict) else None
    for raw in rows if isinstance(rows, list) else []:
        value = aliases.get(str(raw or "").strip().casefold(), str(raw or "").strip().casefold())
        if value and value not in values:
            values.append(value)
    return values[0] if len(values) == 1 else None


def bump_version(value: str, part: str) -> str:
    version = validate_version(value).split("-", 1)[0].split("+", 1)[0]
    major, minor, patch = [int(x) for x in version.split(".")]
    part = str(part).lower()
    if part == "major":
        major, minor, patch = major + 1, 0, 0
    elif part == "minor":
        minor, patch = minor + 1, 0
    elif part == "patch":
        patch += 1
    else:
        raise ValueError(f"Parte SemVer no válida: {part}")
    return f"{major}.{minor}.{patch}"


def installer_template(app_root: Path, platform_id: str) -> str:
    """Read the compatibility bundle installer from deploy/agent.

    Installer source is no longer embedded in Python, so fixes have one auditable
    file on disk per packaging flow.
    """
    key = str(platform_id or "").strip().lower()
    rel = {
        "windows": Path("deploy/agent/legacy-bundle/Install-GIDEONAgent.ps1"),
        "darwin": Path("deploy/agent/legacy-bundle/install-gideon-agent-macos.sh"),
    }.get(key, Path("deploy/agent/legacy-bundle/install-gideon-agent-linux.sh"))
    path = Path(app_root) / rel
    if not path.is_file():
        raise FileNotFoundError(f"Plantilla de instalador no encontrada: {path}")
    return path.read_text(encoding="utf-8-sig" if path.suffix.lower() == ".ps1" else "utf-8")







class AgentBuilder:
    def __init__(self, app_root: Path, profiles_path: Optional[Path] = None) -> None:
        self.app_root = Path(app_root).resolve()
        self.profiles = HostProfileStore(profiles_path or self.app_root / "config" / "host_profiles.json")
        state_override = os.environ.get("GIDEON_AGENT_BUILDER_STATE_DIR", "").strip()
        if state_override:
            local = Path(os.path.expandvars(state_override)).expanduser()
        elif os.name == "nt":
            local = Path(os.path.expandvars(r"%LOCALAPPDATA%\GIDEONSSH\agent_builder"))
        else:
            local = Path.home() / ".local" / "state" / "gideonssh" / "agent_builder"
        self.state_dir = local
        try:
            self.state_dir.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            # Fallback portable para cuentas de servicio/contenedores.
            self.state_dir = Path(tempfile.gettempdir()) / f"gideonssh-agent-builder-{os.getuid() if hasattr(os,'getuid') else os.getpid()}"
            self.state_dir.mkdir(parents=True, exist_ok=True)
        self.release_file = self.state_dir / "releases.json"
        private_override = os.environ.get("GIDEON_AGENT_SIGNING_PRIVATE_KEY", "").strip()
        public_override = os.environ.get("GIDEON_AGENT_SIGNING_PUBLIC_KEY", "").strip()
        self.private_key = Path(private_override) if private_override else (self.state_dir / "signing" / "agent_ed25519_private.pem")
        self.public_key = Path(public_override) if public_override else (self.state_dir / "signing" / "agent_ed25519_public.pem")
        self.last_vlc_source_companion: dict[str, Any] | None = None

    def release_history(self) -> list[dict[str, Any]]:
        if not self.release_file.exists():
            return []
        try:
            value = json.loads(self.release_file.read_text(encoding="utf-8"))
            return value if isinstance(value, list) else []
        except Exception:
            return []

    def _save_release(self, row: dict[str, Any]) -> None:
        rows = self.release_history()
        rows.insert(0, row)
        self.release_file.write_text(json.dumps(rows[:200], ensure_ascii=False, indent=2), encoding="utf-8")

    def generate(
        self,
        *,
        site_code: str,
        site_name: str,
        profile_id: str,
        gateway_url: str,
        version: str = AGENT_VERSION,
        channel: str = "stable",
        output_dir: Optional[Path] = None,
        require_mtls: bool = False,
        ca_file_name: Optional[str] = None,
        ca_file_path: Optional[Path] = None,
        vlc_delivery: str = "bundled",
    ) -> Path:
        version = validate_version(version)
        if not str(gateway_url or "").strip().lower().startswith("https://"):
            raise ValueError("El Agent Builder requiere Gateway https:// para paquetes productivos.")
        profile = self.profiles.get(profile_id)
        platform_id = str(profile.get("platform") or "").lower()
        offline_architecture = _single_profile_architecture(profile)
        # A direct CLI build follows the same publication boundary as the
        # WebAdmin builder. ``detached`` removes only corresponding-source
        # archives after creating an authenticated companion; VLC operational
        # bytes remain offline in the installer. Component delivery is a
        # different, still-unpublished runtime channel.
        delivery = str(vlc_delivery or "bundled").strip().lower()
        if delivery == "component":
            raise ValueError(
                "AGENT_VLC_COMPONENT_DELIVERY_UNAVAILABLE: use bundled hasta publicar el canal autenticado."
            )
        if delivery not in {"bundled", "detached"}:
            raise ValueError("Entrega VLC inválida. Use bundled o detached.")
        self.last_vlc_source_companion = None
        ensure_ed25519_keypair(self.private_key, self.public_key)
        out_root = Path(output_dir or (self.state_dir / "bundles"))
        out_root.mkdir(parents=True, exist_ok=True)
        final_zip = out_root / f"GIDEONAgent-{safe_name(site_code)}-{safe_name(profile_id)}-v{safe_name(version)}.zip"

        with tempfile.TemporaryDirectory(prefix="gideon-agent-build-") as td:
            stage = Path(td) / "bundle"
            payload = stage / "payload"
            payload.mkdir(parents=True)
            copy_agent_runtime_payload(self.app_root, payload)
            offline_vlc_bundle: dict[str, Any] | None = None
            source_companion: dict[str, Any] | None = None
            if platform_id in {"windows", "linux"} and offline_architecture:
                # A package advertised as Player-capable must contain the
                # complete reviewed/legal closure.  Never downgrade it to a
                # not-bundled profile when the source kit is missing.
                if delivery == "detached":
                    source_companion = resolve_vlc_source_companion(
                        self.app_root,
                        platform_name=platform_id,
                        architecture=offline_architecture,
                        signing_private_key=self.private_key,
                        signing_public_key=self.public_key,
                        source_companion_dir=out_root / "source-companions",
                    )
                offline_vlc_bundle = stage_offline_vlc_bundle(
                    self.app_root,
                    payload,
                    platform_name=platform_id,
                    architecture=offline_architecture,
                    signing_private_key=self.private_key,
                    required=True,
                    source_delivery=delivery,
                    source_companion=(source_companion or {}).get("catalog_reference"),
                )
            # Stamp the runtime VERSION so release metadata and the running Agent cannot diverge.
            agent_py = payload / "gideon_agent.py"
            agent_text = agent_py.read_text(encoding="utf-8-sig")
            agent_text = re.sub(r'^VERSION\s*=\s*["\'][^"\']+["\']', f'VERSION = "{version}"', agent_text, count=1, flags=re.M)
            agent_py.write_text(agent_text, encoding="utf-8")
            shutil.copy2(self.public_key, payload / "gideon_agent_signing_public.pem")
            tray_png = self.app_root / "assets" / "gideon_agent_tray.png"
            tray_ico = self.app_root / "assets" / "gideon_agent_tray.ico"
            if tray_png.is_file(): shutil.copy2(tray_png, payload / "gideon_agent_tray.png")
            if tray_ico.is_file(): shutil.copy2(tray_ico, payload / "gideon_agent_tray.ico")
            uninstall_ps = self.app_root / "deploy" / "agent" / "windows" / "gideon-agent-uninstall.ps1"
            if uninstall_ps.is_file(): shutil.copy2(uninstall_ps, payload / "gideon-agent-uninstall.ps1")
            if ca_file_path and Path(ca_file_path).is_file():
                ca_file_name = ca_file_name or "gideon_gateway_ca.pem"
                shutil.copy2(Path(ca_file_path), payload / ca_file_name)
            (payload / "host_profile.json").write_text(json.dumps(profile, ensure_ascii=False, indent=2), encoding="utf-8")
            (payload / "requirements-agent.txt").write_text(DEFAULT_REQUIREMENTS, encoding="utf-8")

            config = {
                "schema_version": 2,
                "agent_version": version,
                "agent_protocol": AGENT_PROTOCOL,
                "site_code": str(site_code),
                "site_name": str(site_name),
                "host_profile": profile_id,
                "data_dir": profile.get("data_dir"),
                "poll_seconds": 5,
                "status_seconds": 5,
                "update": {"channel": channel, "check_seconds": 3600, "auto_install_approved": True, "require_approved": True},
                "security": {
                    "package_signature_required": True,
                    "trusted_signing_public_key": "gideon_agent_signing_public.pem",
                    "job_freshness_required": True,
                    "mtls_required": bool(require_mtls),
                },
                "control_plane": {
                    "base_url": gateway_url.rstrip('/'),
                    "connectivity_mode": "production",
                    "endpoints": [{"url": gateway_url.rstrip('/'), "role": "primary", "priority": 10, "label": "Principal"}],
                    "network_check_seconds": 3,
                    "require_https": True,
                    "verify_tls": True,
                    "minimum_tls": "TLSv1.2",
                    "prefer_tls13": True,
                    "ca_file": ca_file_name,
                    "ca_sha256": sha256_file(Path(ca_file_path)) if ca_file_path and Path(ca_file_path).is_file() else "",
                    "client_cert": "client.crt" if require_mtls else None,
                    "client_key": "client.key" if require_mtls else None,
                    "timeout_seconds": 20,
                },
                "enrollment_secret_env": "GIDEON_AGENT_ENROLL_SECRET"
            }
            (payload / "agent.json").write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")

            install_readme = f"""GIDEON Agent {version} · {profile_id}

SEGURIDAD
- HTTPS obligatorio en producción.
- TLS 1.3 se negocia cuando está disponible; TLS 1.2 es el mínimo.
- El package de Jobs se valida con Ed25519 + SHA-256.
- mTLS puede habilitarse con client_cert/client_key.
- Si este bundle exige mTLS, coloque client.crt/client.key emitidos por su PKI en payload/ ANTES de instalar.
- El secreto de enrolamiento se usa una sola vez; luego el Agent conserva un token individual.

INSTALACIÓN
Windows:
  .\\Install-GIDEONAgent.ps1 -EnrollmentSecret "<secreto>"
Linux/Raspberry Pi:
  sudo env GIDEON_AGENT_ENROLL_SECRET="<secreto>" ./install-gideon-agent.sh
macOS:
  sudo env GIDEON_AGENT_ENROLL_SECRET="<secreto>" ./install-gideon-agent.sh

Gateway: {gateway_url}
Host profile: {profile_id}
"""
            (stage / "README-INSTALL.txt").write_text(install_readme, encoding="utf-8")

            if platform_id == "windows":
                cache_override = str(os.environ.get("GIDEON_AGENT_RUNTIME_CACHE_DIR") or "").strip()
                runtime_cache = Path(cache_override).expanduser() if cache_override else (self.state_dir / "runtime-cache" / "windows-x64-py311")
                allow_runtime_download = str(os.environ.get("GIDEON_AGENT_RUNTIME_ALLOW_DOWNLOAD", "1")).strip().lower() not in {"0", "false", "no", "off"}
                prepare_windows_private_runtime(
                    app_root=self.app_root,
                    payload_dir=payload,
                    cache_dir=runtime_cache,
                    allow_download=allow_runtime_download,
                )
                validate_windows_private_runtime_payload(payload)
                (stage / "Install-GIDEONAgent.ps1").write_text(installer_template(self.app_root, platform_id), encoding="utf-8-sig")
            elif platform_id == "darwin":
                p = stage / "install-gideon-agent.sh"; p.write_text(installer_template(self.app_root, platform_id), encoding="utf-8"); p.chmod(0o755)
            else:
                p = stage / "install-gideon-agent.sh"; p.write_text(installer_template(self.app_root, platform_id), encoding="utf-8"); p.chmod(0o755)

            # The private-runtime smoke test can compile Python modules in the
            # temporary payload.  Exclude those generated caches before the
            # manifest is hashed/signed so a fresh installer contains only its
            # declared runtime bytes.
            prune_generated_nonruntime_files(stage)
            manifest = {
                "Product": "GIDEON Agent",
                "Version": version,
                "ProtocolVersion": AGENT_PROTOCOL,
                "Channel": channel,
                "SiteCode": str(site_code),
                "SiteName": str(site_name),
                "HostProfile": profile_id,
                "Platform": profile.get("platform"),
                "Architectures": profile.get("architectures"),
                "CreatedAt": now_iso(),
                "Security": {
                    "TLS": "TLS 1.3 preferred; TLS 1.2 minimum",
                    "PackageSigning": "Ed25519",
                    "Digest": "SHA-256",
                    "mTLS": "optional/configurable"
                },
                "OfflineVlc": {
                    "Bundled": bool((offline_vlc_bundle or {}).get("Bundled")),
                    "SourcesBundled": bool((offline_vlc_bundle or {}).get("SourcesBundled")),
                    "Targeted": bool(offline_vlc_bundle is not None),
                    "NetworkDownloads": False,
                    "Delivery": str((offline_vlc_bundle or {}).get("Delivery") or "not-applicable"),
                    "ComponentSchema": str((offline_vlc_bundle or {}).get("ComponentSchema") or ""),
                    "SourceCompanion": dict((offline_vlc_bundle or {}).get("SourceCompanion") or {}),
                },
                "Files": {}
            }
            for f in sorted(payload.rglob("*")):
                if f.is_file():
                    manifest["Files"][f.relative_to(payload).as_posix()] = sha256_file(f)
            manifest_path = stage / "release-manifest.json"
            manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
            (stage / "release-manifest.sig").write_text(sign_file(manifest_path, self.private_key), encoding="ascii")
            if final_zip.exists(): final_zip.unlink()
            write_verified_deflated_zip(stage, final_zip)
            if source_companion is not None:
                self.last_vlc_source_companion = source_companion

        row = {
            "version": version,
            "protocol": AGENT_PROTOCOL,
            "channel": channel,
            "site_code": str(site_code),
            "site_name": str(site_name),
            "profile": profile_id,
            "platform": profile.get("platform"),
            "bundle": str(final_zip),
            "sha256": sha256_file(final_zip),
            "signature": sign_file(final_zip, self.private_key),
            "key_id": "gideon-agent-ed25519-1",
            "architectures": profile.get("architectures", []),
            "created_at": now_iso()
        }
        if self.last_vlc_source_companion:
            row["vlc_source_companion"] = {
                key: value for key, value in self.last_vlc_source_companion.items()
                if key != "catalog_reference"
            }
        self._save_release(row)
        return final_zip

    def generate_vlc_component(
        self,
        *,
        profile_id: str,
        output_dir: Path,
        distribution: str = "",
        codename: str = "",
    ) -> dict[str, Any]:
        """Build the reviewed VLC closure separately from the Agent core.

        The component is intentionally site-neutral: it contains no enrollment
        material, mTLS certificate, Agent token, gateway endpoint, or command.
        It can be deduplicated by SHA-256 and later delivered through the
        authenticated component workflow only.
        """

        profile = self.profiles.get(profile_id)
        platform_id = str(profile.get("platform") or "").lower()
        architecture = _single_profile_architecture(profile)
        if platform_id not in {"windows", "linux"} or not architecture:
            raise ValueError("El perfil debe seleccionar una plataforma y arquitectura VLC exactas.")
        ensure_ed25519_keypair(self.private_key, self.public_key)
        destination = Path(output_dir)
        destination.mkdir(parents=True, exist_ok=True)
        suffix = "-".join(
            safe_name(part) for part in (platform_id, architecture, distribution or "generic", codename or "generic")
        )
        artifact = destination / f"GIDEONAgentComponent-VLC-{suffix}.zip"
        return build_vlc_offline_component(
            self.app_root,
            artifact,
            platform_name=platform_id,
            architecture=architecture,
            distribution=distribution,
            codename=codename,
            signing_private_key=self.private_key,
        )


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="GIDEON Agent Builder")
    parser.add_argument("--app-root", type=Path, default=Path(__file__).resolve().parent)
    sub = parser.add_subparsers(dest="action", required=True)
    gen = sub.add_parser("generate")
    gen.add_argument("--site-code", required=True)
    gen.add_argument("--site-name", required=True)
    gen.add_argument("--profile", required=True)
    gen.add_argument("--gateway", required=True)
    gen.add_argument("--version", default=AGENT_VERSION)
    gen.add_argument("--channel", default="stable")
    gen.add_argument("--output", type=Path)
    gen.add_argument("--require-mtls", action="store_true")
    gen.add_argument("--vlc-delivery", choices=("bundled", "detached"), default="bundled")
    component = sub.add_parser("component")
    component.add_argument("--profile", required=True)
    component.add_argument("--output", type=Path, required=True)
    component.add_argument("--distribution", default="")
    component.add_argument("--codename", default="")
    sub.add_parser("profiles")
    sub.add_parser("releases")
    args = parser.parse_args()
    builder = AgentBuilder(args.app_root)
    if args.action == "profiles":
        print(json.dumps({k:v for k,v in builder.profiles.list_profiles()}, ensure_ascii=False, indent=2))
        return 0
    if args.action == "releases":
        print(json.dumps(builder.release_history(), ensure_ascii=False, indent=2))
        return 0
    if args.action == "component":
        print(json.dumps(builder.generate_vlc_component(
            profile_id=args.profile,
            output_dir=args.output,
            distribution=args.distribution,
            codename=args.codename,
        ), ensure_ascii=False, indent=2))
        return 0
    path = builder.generate(
        site_code=args.site_code,
        site_name=args.site_name,
        profile_id=args.profile,
        gateway_url=args.gateway,
        version=args.version,
        channel=args.channel,
        output_dir=args.output,
        require_mtls=args.require_mtls,
        vlc_delivery=args.vlc_delivery,
    )
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
