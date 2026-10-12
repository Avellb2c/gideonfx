#!/usr/bin/env python3
"""Build transport-friendly, OS-specific Gideon Rx OneClick module kits."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tarfile
from time import sleep, monotonic
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator


ROOT = Path(__file__).resolve().parents[2]
PORTABLE_SOURCE = ROOT / "installers" / "portable"
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class Module:
    filename: str
    paths: tuple[str, ...]
    description: str


MODULES = {
    "common": Module(
        "10-GIDEON-COMMON.tar.gz",
        (
            "deployment.manifest.json",
            "master.config.json",
            "ONECLICK-INSTALL.md",
            "README_INSTALL.txt",
            "SENSITIVE_PRODUCTION_CLONE.txt",
            "installers",
            # Only carry metadata that an installer reads.  The full metadata
            # directory contains workstation diagnostics, legacy manifests and
            # operational logs which are neither installation inputs nor safe
            # to redistribute in a clean portable kit.
            "metadata/hyperv-appliance-build.json",
            "metadata/hyperv-qemu-prevalidation.json",
            "metadata/machine-environment.json",
            "security",
            "offline-cache/containers",
        ),
        "Configuración limpia, seguridad, instaladores, metadatos requeridos y contenedores comunes.",
    ),
    "windows": Module(
        "20-GIDEON-WINDOWS.tar.gz",
        ("payload/windows", "offline-cache/windows"),
        "Runtime y dependencias de Windows.",
    ),
    "hyperv": Module(
        "30-GIDEON-HYPERV.tar.gz",
        (
            "offline-cache/hyperv/README.md",
            "offline-cache/hyperv/bootstrap",
            "offline-cache/hyperv/candidates",
        ),
        "Appliance candidata y bootstrap offline de Hyper-V.",
    ),
    "linux": Module(
        "20-GIDEON-LINUX.tar.gz",
        ("payload/linux", "offline-cache/linux"),
        "Runtime y caché opcional de paquetes Linux.",
    ),
}

CLONE_STATE_PATHS = ("payload/data",)


def module_catalog(include_clone_state: bool) -> dict[str, Module]:
    """Return the clean catalog, or the explicitly requested production clone."""
    if not include_clone_state:
        return MODULES
    common = MODULES["common"]
    return {
        **MODULES,
        "common": Module(
            common.filename,
            (*common.paths, *CLONE_STATE_PATHS),
            "Configuración, estado clonable, seguridad, instaladores y contenedores comunes.",
        ),
    }

PROFILES = {
    "windows-home": ("common", "windows"),
    "windows-hyperv": ("common", "windows", "hyperv"),
    "linux": ("common", "linux"),
}

KITS = {
    "GIDEON-WINDOWS-HOME-ONECLICK": ("windows-home",),
    "GIDEON-WINDOWS-HYPERV-ONECLICK": ("windows-hyperv",),
    "GIDEON-LINUX-ONECLICK": ("linux",),
    "GIDEON-UNIVERSAL-ONECLICK": ("windows-home", "windows-hyperv", "linux"),
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def required_module_paths(module: Module) -> list[str]:
    optional = {"offline-cache/linux"}
    missing = [item for item in module.paths if not (ROOT / item).exists() and item not in optional]
    if missing:
        raise FileNotFoundError(
            f"Faltan rutas obligatorias para {module.filename}: {', '.join(missing)}"
        )
    existing = [item for item in module.paths if (ROOT / item).exists()]
    return existing


def find_tar() -> str:
    candidate = shutil.which("tar.exe") or shutil.which("tar")
    if not candidate:
        raise RuntimeError("No se encontró tar/bsdtar para crear módulos .tar.gz")
    return candidate


@contextlib.contextmanager
def exclusive_output_build_lock(output_root: Path, *, timeout_seconds: float = 0.0) -> Iterator[None]:
    """Hold an OS-backed lock for all mutable work beneath one output root.

    The lock file deliberately remains in the output directory after release.
    Removing a lock file while another process is waiting on its inode can split
    the lock on POSIX.  A persistent, harmless lock file keeps all builders
    synchronized on the same inode and is not included in any generated kit.
    """
    output_root.mkdir(parents=True, exist_ok=True)
    lock_path = output_root / ".portable-build.lock"
    stream = lock_path.open("a+b")
    acquired = False
    deadline = monotonic() + max(0.0, timeout_seconds)

    def try_lock() -> bool:
        if os.name == "nt":
            import msvcrt

            stream.seek(0, os.SEEK_END)
            if stream.tell() == 0:
                stream.write(b"\0")
                stream.flush()
            stream.seek(0)
            try:
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                return True
            except OSError:
                return False

        import fcntl

        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            return False

    try:
        while not acquired:
            acquired = try_lock()
            if acquired:
                break
            if monotonic() >= deadline:
                raise RuntimeError(
                    "Otro build portable ya está usando este --output. "
                    "Espere a que termine o use una carpeta --output nueva."
                )
            sleep(min(0.1, max(0.0, deadline - monotonic())))
        yield
    finally:
        if acquired:
            try:
                if os.name == "nt":
                    import msvcrt

                    stream.seek(0)
                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
            finally:
                stream.close()
        else:
            stream.close()


def build_archive(tar_binary: str, module: Module, destination: Path) -> list[str]:
    paths = required_module_paths(module)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=destination.name + ".", suffix=".partial", dir=destination.parent
    )
    os.close(fd)
    temporary = Path(temporary_name)
    temporary.unlink(missing_ok=True)
    command = [
        tar_binary,
        "-czf",
        str(temporary),
        "--exclude=__pycache__",
        "--exclude=.pytest_cache",
        "--exclude=.mypy_cache",
        "--exclude=.ruff_cache",
        "--exclude=*.pyc",
        "--exclude=*.pyo",
        "--exclude=*.bak",
        "--exclude=*.partial",
        "--exclude=*.tmp",
        "--exclude=*.orig",
        "--exclude=*~",
        "-C",
        str(ROOT),
        *paths,
    ]
    print(f"[BUILD] {module.filename}", flush=True)
    try:
        subprocess.run(command, check=True)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return paths


def ensure_safe_generated_directory(path: Path, output_root: Path) -> None:
    resolved = path.resolve()
    root = output_root.resolve()
    if resolved == root or root not in resolved.parents or path.name not in KITS:
        raise RuntimeError(f"Se rechazó limpiar una ruta no generada: {resolved}")


def reset_generated_directory(path: Path, output_root: Path) -> None:
    ensure_safe_generated_directory(path, output_root)
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)


def link_or_copy(source: Path, destination: Path) -> str:
    destination.unlink(missing_ok=True)
    try:
        os.link(source, destination)
        return "hardlink"
    except OSError:
        shutil.copy2(source, destination)
        return "copy"


def render(source_name: str, profile: str) -> str:
    source = (PORTABLE_SOURCE / source_name).read_text(encoding="utf-8")
    return source.replace("@@PROFILE@@", profile)


def human_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{value:.2f} {unit}"
        value /= 1024
    return f"{value:.2f} GiB"


def kit_readme(
    kit_name: str,
    profiles: tuple[str, ...],
    module_rows: list[dict],
    *,
    include_clone_state: bool,
) -> str:
    profile_text = ", ".join(profiles)
    files = "\n".join(
        f"- `{row['filename']}` — {human_size(row['size_bytes'])}" for row in module_rows
    )
    launchers: list[str] = []
    if any(item.startswith("windows-") for item in profiles):
        launchers.append("Windows: clic derecho en `INSTALL_GIDEON_ONECLICK.cmd` y ejecutar como administrador.")
    if "linux" in profiles:
        linux_name = "INSTALL_GIDEON_ONECLICK.sh" if len(profiles) == 1 else "INSTALL_GIDEON_ONECLICK_LINUX.sh"
        launchers.append(f"Linux: `bash {linux_name}`.")
    launcher_text = "\n".join(f"- {item}" for item in launchers)
    clone_notice = (
        "⚠️ **KIT CLONE:** incluye `payload/data` con estado de producción. "
        "Use exclusivamente un medio cifrado y un flujo de migración autorizado."
        if include_clone_state
        else "Este es un kit limpio: excluye `payload/data` y no transfiere estado operativo ni bases locales."
    )
    return f"""# {kit_name}

Kit modular Gideon Rx listo para transportar. Perfiles incluidos: `{profile_text}`.

## Instalación

{launcher_text}

El launcher detecta el sistema, verifica SHA-256, extrae los módulos una sola vez a una caché local corta y ejecuta el instalador original. En posteriores ejecuciones reutiliza esa caché.

Antes de modificar el sistema valida versión/arquitectura, espacio, metadatos del kit y requisitos del backend. `package.modules.sha256` permite reconstruir perfiles ausentes u obsoletos y bloquea mezclas de versiones.

## Módulos

{files}

No descomprima los `.tar.gz`. Copie esta carpeta completa. Para descargar módulos ausentes desde un servidor HTTP/HTTPS, defina `GIDEON_PACKAGE_BASE_URL` con la URL base que contiene estos mismos nombres de archivo.

{clone_notice}
"""


def write_profile_manifest(
    kit: Path,
    profile: str,
    module_info: dict[str, dict],
    modules: dict[str, Module],
) -> None:
    target = kit / "profiles" / f"{profile}.sha256"
    target.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"{module_info[key]['sha256']} *{modules[key].filename}"
        for key in PROFILES[profile]
    ]
    target.write_text("\n".join(lines) + "\n", encoding="ascii", newline="\n")


def build_kits(
    output_root: Path,
    module_info: dict[str, dict],
    plan_only: bool,
    *,
    modules: dict[str, Module] = MODULES,
    include_clone_state: bool = False,
) -> dict:
    report: dict = {
        "schema_version": 1,
        "product": "Gideon Rx Portable OneClick",
        "source_bundle": ROOT.name,
        "source_bundle_path": str(ROOT),
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "plan_only": plan_only,
        "clone_state_included": include_clone_state,
        "module_storage": "single-store with hardlinks when supported",
        "profiles": {key: list(value) for key, value in PROFILES.items()},
        "modules": module_info,
        "kits": {},
        "excluded_from_deployment": [
            "documentation",
            "FILE_MANIFEST.sha256 (regenerated after Hyper-V promotion)",
            "metadata operational diagnostics, legacy manifests and logs",
            "offline-cache/hyperv/sources (build-only Ubuntu source image)",
            "__pycache__ and *.pyc/*.pyo",
            *([] if include_clone_state else ["payload/data (solo se incluye con --include-clone-state)"]),
        ],
    }
    if plan_only:
        report["kits"] = {key: {"profiles": list(value)} for key, value in KITS.items()}
        return report

    store = output_root / ".modules"
    ps_bootstrap = PORTABLE_SOURCE / "Invoke-GideonPortableOneClick.ps1"
    for kit_name, profiles in KITS.items():
        kit = output_root / kit_name
        reset_generated_directory(kit, output_root)
        needed = tuple(dict.fromkeys(key for profile in profiles for key in PROFILES[profile]))
        transport_methods: dict[str, str] = {}
        rows: list[dict] = []
        for key in needed:
            source = store / modules[key].filename
            transport_methods[modules[key].filename] = link_or_copy(source, kit / source.name)
            rows.append(module_info[key])
        for profile in profiles:
            write_profile_manifest(kit, profile, module_info, modules)
        (kit / "package.modules.sha256").write_text(
            "\n".join(
                f"{module_info[key]['sha256']} *{modules[key].filename}"
                for key in needed
            )
            + "\n",
            encoding="ascii",
            newline="\n",
        )

        windows_profiles = [item for item in profiles if item.startswith("windows-")]
        if windows_profiles:
            (kit / ps_bootstrap.name).write_text(
                ps_bootstrap.read_text(encoding="utf-8"),
                encoding="utf-8-sig",
                newline="\r\n",
            )
            cmd_profile = "auto" if len(windows_profiles) > 1 else windows_profiles[0]
            (kit / "INSTALL_GIDEON_ONECLICK.cmd").write_text(
                render("GIDEON-Portable-OneClick.cmd.tpl", cmd_profile),
                encoding="ascii",
                newline="\r\n",
            )
        if "linux" in profiles:
            shell_name = "INSTALL_GIDEON_ONECLICK.sh" if len(profiles) == 1 else "INSTALL_GIDEON_ONECLICK_LINUX.sh"
            shell_path = kit / shell_name
            shell_path.write_text(
                render("GIDEON-Portable-OneClick.sh.tpl", "linux"), encoding="utf-8", newline="\n"
            )
            try:
                shell_path.chmod(0o755)
            except OSError:
                pass

        readme = kit_readme(kit_name, profiles, rows, include_clone_state=include_clone_state)
        (kit / "LEAME-PRIMERO.md").write_text(readme, encoding="utf-8", newline="\n")
        if include_clone_state:
            (kit / "CLONE_STATE_INCLUDED.txt").write_text(
                "Este kit incluye payload/data y debe tratarse como una clonación de producción confidencial.\n",
                encoding="utf-8",
                newline="\n",
            )
        kit_manifest = {
            "schema_version": 1,
            "kit": kit_name,
            "profiles": list(profiles),
            "source_bundle": ROOT.name,
            "clone_state_included": include_clone_state,
            "modules": rows,
            "local_storage_method": transport_methods,
            "generated_utc": report["generated_utc"],
        }
        (kit / "package.manifest.json").write_text(
            json.dumps(kit_manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        report["kits"][kit_name] = {
            "profiles": list(profiles),
            "logical_size_bytes": sum(item["size_bytes"] for item in rows),
            "directory": str(kit),
            "storage_method": transport_methods,
        }
    return report


def _read_sha256_manifest(path: Path) -> dict[str, str]:
    """Read a strict, flat SHA-256 manifest produced by this builder."""
    if not path.is_file():
        raise RuntimeError(f"Falta el manifiesto de integridad: {path}")
    rows: dict[str, str] = {}
    for line_number, raw_line in enumerate(path.read_text(encoding="ascii").splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        match = re.fullmatch(r"([0-9a-fA-F]{64})\s+\*?([^\\/\s]+)", line)
        if not match:
            raise RuntimeError(f"Manifiesto inválido en {path}:{line_number}")
        digest, filename = match.groups()
        if filename in rows:
            raise RuntimeError(f"Módulo duplicado en {path}: {filename}")
        rows[filename] = digest.lower()
    if not rows:
        raise RuntimeError(f"El manifiesto está vacío: {path}")
    return rows


def _expected_module_rows(
    module_info: dict[str, dict],
    needed: tuple[str, ...],
    modules: dict[str, Module],
) -> dict[str, dict]:
    rows: dict[str, dict] = {}
    for key in needed:
        if key not in module_info:
            raise RuntimeError(f"Falta información del módulo construido: {key}")
        row = module_info[key]
        filename = str(row.get("filename", ""))
        digest = str(row.get("sha256", "")).lower()
        if filename != modules[key].filename or not _SHA256_PATTERN.fullmatch(digest):
            raise RuntimeError(f"Metadatos inválidos para el módulo {key}")
        if filename in rows:
            raise RuntimeError(f"Nombre de módulo duplicado: {filename}")
        rows[filename] = row
    return rows


def verify_kit_integrity(
    kit: Path,
    kit_name: str,
    profiles: tuple[str, ...],
    module_info: dict[str, dict],
    *,
    modules: dict[str, Module] = MODULES,
    include_clone_state: bool = False,
) -> None:
    """Fail closed unless a finished kit exactly matches its generated hashes."""
    needed = tuple(dict.fromkeys(key for profile in profiles for key in PROFILES[profile]))
    expected_rows = _expected_module_rows(module_info, needed, modules)
    expected_hashes = {filename: str(row["sha256"]).lower() for filename, row in expected_rows.items()}

    manifest_path = kit / "package.manifest.json"
    try:
        package_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"No se pudo leer {manifest_path}: {exc}") from exc
    if not isinstance(package_manifest, dict):
        raise RuntimeError(f"El manifiesto no es un objeto JSON: {manifest_path}")
    if package_manifest.get("schema_version") != 1:
        raise RuntimeError(f"Versión de manifiesto no compatible: {manifest_path}")
    if package_manifest.get("kit") != kit_name:
        raise RuntimeError(f"El manifiesto no corresponde al kit {kit_name}")
    if tuple(package_manifest.get("profiles", ())) != profiles:
        raise RuntimeError(f"Perfiles inconsistentes en {manifest_path}")
    if package_manifest.get("clone_state_included") is not include_clone_state:
        raise RuntimeError(f"Marca de estado clonable inconsistente en {manifest_path}")
    manifest_modules = package_manifest.get("modules")
    if not isinstance(manifest_modules, list) or len(manifest_modules) != len(expected_rows):
        raise RuntimeError(f"Módulos inconsistentes en {manifest_path}")

    manifest_rows: dict[str, dict] = {}
    for row in manifest_modules:
        if not isinstance(row, dict):
            raise RuntimeError(f"Fila de módulo inválida en {manifest_path}")
        filename = str(row.get("filename", ""))
        digest = str(row.get("sha256", "")).lower()
        if filename in manifest_rows or filename not in expected_rows or not _SHA256_PATTERN.fullmatch(digest):
            raise RuntimeError(f"Fila de módulo inválida en {manifest_path}: {filename or '<sin nombre>'}")
        if digest != expected_hashes[filename]:
            raise RuntimeError(f"SHA de manifiesto distinto para {filename}")
        try:
            actual_size = int(row.get("size_bytes", -1))
            expected_size = int(expected_rows[filename]["size_bytes"])
        except (TypeError, ValueError) as exc:
            raise RuntimeError(f"Tamaño de módulo inválido en {manifest_path}: {filename}") from exc
        if actual_size != expected_size:
            raise RuntimeError(f"Tamaño de manifiesto distinto para {filename}")
        manifest_rows[filename] = row
    if set(manifest_rows) != set(expected_rows):
        raise RuntimeError(f"Conjunto de módulos distinto en {manifest_path}")

    package_hashes = _read_sha256_manifest(kit / "package.modules.sha256")
    if package_hashes != expected_hashes:
        raise RuntimeError(f"package.modules.sha256 no coincide con {kit_name}")

    for profile in profiles:
        profile_expected = {
            modules[key].filename: expected_hashes[modules[key].filename]
            for key in PROFILES[profile]
        }
        profile_hashes = _read_sha256_manifest(kit / "profiles" / f"{profile}.sha256")
        if profile_hashes != profile_expected:
            raise RuntimeError(f"El perfil {profile} no coincide con los módulos del kit")

    for filename, row in expected_rows.items():
        archive = kit / filename
        if not archive.is_file() or archive.is_symlink():
            raise RuntimeError(f"Módulo ausente o inseguro en el kit: {archive}")
        try:
            expected_size = int(row["size_bytes"])
        except (TypeError, ValueError) as exc:
            raise RuntimeError(f"Tamaño esperado inválido para {archive}") from exc
        if archive.stat().st_size != expected_size:
            raise RuntimeError(f"Tamaño real distinto para {archive}")
        if sha256_file(archive) != expected_hashes[filename]:
            raise RuntimeError(f"SHA-256 real distinto para {archive}")

    common_archive = kit / modules["common"].filename
    try:
        with tarfile.open(common_archive, "r:gz") as archive:
            contains_clone_state = any(
                member.name.replace("\\", "/").lstrip("./").startswith("payload/data/")
                or member.name.replace("\\", "/").lstrip("./") == "payload/data"
                for member in archive
            )
    except (OSError, tarfile.TarError) as exc:
        raise RuntimeError(f"No se pudo inspeccionar el módulo común: {common_archive}: {exc}") from exc
    if contains_clone_state is not include_clone_state:
        expectation = "incluir" if include_clone_state else "excluir"
        raise RuntimeError(f"El módulo común no pudo {expectation} payload/data según el perfil del kit")

    required = {"LEAME-PRIMERO.md", "package.modules.sha256", "package.manifest.json"}
    if any(profile.startswith("windows-") for profile in profiles):
        required.update({"Invoke-GideonPortableOneClick.ps1", "INSTALL_GIDEON_ONECLICK.cmd"})
    if "linux" in profiles:
        linux_name = "INSTALL_GIDEON_ONECLICK.sh" if len(profiles) == 1 else "INSTALL_GIDEON_ONECLICK_LINUX.sh"
        required.add(linux_name)
    clone_notice = kit / "CLONE_STATE_INCLUDED.txt"
    if include_clone_state:
        required.add(clone_notice.name)
    elif clone_notice.exists():
        raise RuntimeError(f"Un kit limpio conserva una marca de clonación: {clone_notice}")
    missing = sorted(item for item in required if not (kit / item).is_file())
    if missing:
        raise RuntimeError(f"El kit {kit_name} está incompleto: {', '.join(missing)}")


def verify_built_kits(
    output_root: Path,
    module_info: dict[str, dict],
    report: dict,
    *,
    modules: dict[str, Module] = MODULES,
    include_clone_state: bool = False,
) -> None:
    """Verify every published kit before the build report announces success."""
    reported_kits = report.get("kits")
    if not isinstance(reported_kits, dict):
        raise RuntimeError("El reporte de build no contiene kits")
    if report.get("clone_state_included") is not include_clone_state:
        raise RuntimeError("El reporte no conserva la marca de estado clonable")
    for kit_name, profiles in KITS.items():
        kit = output_root / kit_name
        if not kit.is_dir():
            raise RuntimeError(f"No se generó el kit esperado: {kit}")
        report_entry = reported_kits.get(kit_name)
        if not isinstance(report_entry, dict) or tuple(report_entry.get("profiles", ())) != profiles:
            raise RuntimeError(f"El reporte no coincide con el kit {kit_name}")
        needed = tuple(dict.fromkeys(key for profile in profiles for key in PROFILES[profile]))
        expected_logical_size = sum(int(module_info[key]["size_bytes"]) for key in needed)
        if int(report_entry.get("logical_size_bytes", -1)) != expected_logical_size:
            raise RuntimeError(f"El tamaño lógico del reporte no coincide con el kit {kit_name}")
        verify_kit_integrity(
            kit,
            kit_name,
            profiles,
            module_info,
            modules=modules,
            include_clone_state=include_clone_state,
        )


def parse_args() -> argparse.Namespace:
    default_output = ROOT.parent / f"{ROOT.name}-PORTABLE"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=default_output)
    parser.add_argument("--plan-only", action="store_true", help="Validar y mostrar el plan sin crear archivos grandes")
    parser.add_argument("--reuse-modules", action="store_true", help="Reutilizar módulos existentes si pasan SHA-256")
    parser.add_argument(
        "--include-clone-state",
        action="store_true",
        help="Incluir payload/data de producción. Solo para una migración interna autorizada; el kit quedará marcado como CLONE.",
    )
    parser.add_argument(
        "--rebuild-module",
        action="append",
        choices=tuple(MODULES),
        default=[],
        help="Reconstruir este módulo aunque --reuse-modules esté activo; se puede repetir",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_root = args.output.resolve()
    module_info: dict[str, dict] = {}
    modules = module_catalog(args.include_clone_state)
    tar_binary = find_tar()

    if args.plan_only:
        for key, module in modules.items():
            paths = required_module_paths(module)
            module_info[key] = {
                "filename": module.filename,
                "description": module.description,
                "source_paths": paths,
                "sha256": "NOT_BUILT",
                "size_bytes": 0,
            }
        report = build_kits(
            output_root,
            module_info,
            True,
            modules=modules,
            include_clone_state=args.include_clone_state,
        )
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0

    with exclusive_output_build_lock(output_root):
        store = output_root / ".modules"
        store.mkdir(parents=True, exist_ok=True)
        for key, module in modules.items():
            destination = store / module.filename
            paths = required_module_paths(module)
            # The common module is intentionally rebuilt every time.  It is the
            # only module that may contain payload/data under the explicit clone
            # switch, so filename-only reuse could accidentally retain state in
            # a later clean build (or omit it from a requested clone build).
            should_reuse = (
                args.reuse_modules
                and key != "common"
                and destination.is_file()
                and key not in args.rebuild_module
            )
            if not should_reuse:
                paths = build_archive(tar_binary, module, destination)
            digest = sha256_file(destination)
            size = destination.stat().st_size
            module_info[key] = {
                "filename": module.filename,
                "description": module.description,
                "source_paths": paths,
                "sha256": digest,
                "size_bytes": size,
            }
            print(f"[PASS] {module.filename} {human_size(size)} sha256={digest}", flush=True)

        report = build_kits(
            output_root,
            module_info,
            False,
            modules=modules,
            include_clone_state=args.include_clone_state,
        )
        verify_built_kits(
            output_root,
            module_info,
            report,
            modules=modules,
            include_clone_state=args.include_clone_state,
        )
        report_path = output_root / "portable-package-build-report.json"
        report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"[PASS] PORTABLE_KIT_INTEGRITY=PASS kits={len(KITS)}")
        print(f"[PASS] PORTABLE_PACKAGES_READY={output_root}")
        print(f"[PASS] REPORT={report_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        raise SystemExit(1)
