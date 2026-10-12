from __future__ import annotations

"""Build a private, self-contained CPython runtime for Windows Agent installers.

The endpoint must not depend on a machine-wide Python installation.  The WebAdmin/
Agent builder acquires the official CPython embeddable distribution once, resolves
Windows wheels for the Agent dependencies, expands everything under the installer
payload, and validates the result on the Windows build host before an EXE is emitted.

No PATH, file association, registry Python registration, global pip or Windows service
outside GIDEON is changed by this module.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from typing import Iterable

PYTHON_VERSION = "3.11.9"
PYTHON_TAG = "311"
PYTHON_ARCHIVE = f"python-{PYTHON_VERSION}-embed-amd64.zip"
PYTHON_URL = f"https://www.python.org/ftp/python/{PYTHON_VERSION}/{PYTHON_ARCHIVE}"
RUNTIME_SCHEMA = "gideon-agent-windows-runtime/v1"

REQUIRED_RUNTIME_RELATIVE_FILES: tuple[str, ...] = (
    "python.exe", "pythonw.exe", f"python{PYTHON_TAG}.dll", f"python{PYTHON_TAG}.zip",
    f"python{PYTHON_TAG}._pth", "vcruntime140.dll", "vcruntime140_1.dll",
)
REQUIRED_RUNTIME_IMPORT_PATHS: tuple[str, ...] = (
    "Lib/site-packages/cryptography/__init__.py",
    "Lib/site-packages/PIL/__init__.py",
    "Lib/site-packages/pystray/__init__.py",
)

DEFAULT_REQUIREMENTS = (
    "cryptography>=45,<48\n"
    "pystray>=0.19,<1\n"
    "Pillow>=10,<12\n"
)


class WindowsRuntimeBuildError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _download(url: str, destination: Path, *, timeout: int = 120) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp = destination.with_suffix(destination.suffix + ".part")
    temp.unlink(missing_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": "GIDEON-Remote-Control-AgentBuilder/6.3.4"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response, temp.open("wb") as out:
            final_url = str(getattr(response, "url", url) or url)
            if not final_url.lower().startswith("https://"):
                raise WindowsRuntimeBuildError(f"Descarga de runtime redirigida fuera de HTTPS: {final_url}")
            shutil.copyfileobj(response, out)
    except Exception as exc:
        temp.unlink(missing_ok=True)
        raise WindowsRuntimeBuildError(f"No se pudo descargar {url}: {exc}") from exc
    if temp.stat().st_size < 1_000_000:
        temp.unlink(missing_ok=True)
        raise WindowsRuntimeBuildError(f"Descarga de runtime sospechosamente pequeña: {url}")
    temp.replace(destination)


def _validate_python_embed_archive(archive: Path) -> None:
    try:
        with zipfile.ZipFile(archive, "r") as zf:
            names = {name.replace("\\", "/").lower() for name in zf.namelist()}
            required = {
                "python.exe",
                "pythonw.exe",
                f"python{PYTHON_TAG}.dll",
                f"python{PYTHON_TAG}.zip",
                f"python{PYTHON_TAG}._pth",
                # CPython embeddable ships the VC runtime needed by python.exe.
                # Requiring it here avoids producing an installer that works only
                # on developer PCs that already happen to have VC++ installed.
                "vcruntime140.dll",
                "vcruntime140_1.dll",
            }
            missing = sorted(required - names)
            if missing:
                raise WindowsRuntimeBuildError(
                    "El runtime oficial de CPython está incompleto. Faltan: " + ", ".join(missing)
                )
            bad = zf.testzip()
            if bad:
                raise WindowsRuntimeBuildError(f"ZIP de CPython corrupto: {bad}")
    except zipfile.BadZipFile as exc:
        raise WindowsRuntimeBuildError(f"Runtime CPython inválido: {archive}") from exc


def _pip_download_windows_wheels(requirements: Path, wheel_cache: Path) -> list[Path]:
    wheel_cache.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable,
        "-m",
        "pip",
        "download",
        "--disable-pip-version-check",
        "--only-binary=:all:",
        "--platform",
        "win_amd64",
        "--implementation",
        "cp",
        "--python-version",
        PYTHON_TAG,
        "--abi",
        f"cp{PYTHON_TAG}",
        "--abi",
        "abi3",
        "--abi",
        "none",
        "--dest",
        str(wheel_cache),
        "-r",
        str(requirements),
    ]
    proc = subprocess.run(command, capture_output=True, text=True, timeout=600, check=False)
    if proc.returncode != 0:
        detail = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
        raise WindowsRuntimeBuildError(
            "No se pudieron resolver las ruedas Windows del Agent. "
            "El WebAdmin necesita acceso a PyPI solo durante la generación inicial del instalador.\n"
            + detail[-8000:]
        )
    wheels = sorted(wheel_cache.glob("*.whl"))
    if not wheels:
        raise WindowsRuntimeBuildError("pip download terminó sin producir ruedas Windows para el Agent.")
    return wheels


def _extract_wheel(wheel: Path, site_packages: Path) -> None:
    """Install a wheel without pip into the private runtime.

    Wheel files are ZIP archives.  Most Agent dependencies place importable content
    at the archive root, but the wheel spec also allows ``*.data/purelib`` and
    ``*.data/platlib``.  Handle those layouts explicitly and reject path traversal.
    Scripts/headers are not needed by the runtime and are intentionally skipped.
    """
    site_packages = Path(site_packages).resolve()
    try:
        with zipfile.ZipFile(wheel, "r") as zf:
            bad = zf.testzip()
            if bad:
                raise WindowsRuntimeBuildError(f"Wheel corrupto {wheel.name}: {bad}")
            for info in zf.infolist():
                raw = info.filename.replace("\\", "/")
                parts = [part for part in raw.split("/") if part not in {"", "."}]
                if not parts or any(part == ".." for part in parts):
                    raise WindowsRuntimeBuildError(f"Ruta insegura en wheel {wheel.name}: {raw}")
                out_parts = parts
                if len(parts) >= 3 and parts[0].endswith(".data"):
                    kind = parts[1].lower()
                    if kind in {"purelib", "platlib"}:
                        out_parts = parts[2:]
                    else:
                        # Runtime-only package: scripts/headers/data outside site-packages
                        # are never executed by GIDEON Agent and are not copied.
                        continue
                if not out_parts:
                    continue
                target = site_packages.joinpath(*out_parts).resolve()
                if target != site_packages and site_packages not in target.parents:
                    raise WindowsRuntimeBuildError(f"Wheel intenta salir de site-packages: {raw}")
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info, "r") as src, target.open("wb") as dst:
                    shutil.copyfileobj(src, dst)
    except zipfile.BadZipFile as exc:
        raise WindowsRuntimeBuildError(f"Wheel inválido: {wheel}") from exc


def _configure_pth(runtime_root: Path) -> Path:
    candidates = sorted(runtime_root.glob("python*._pth"))
    if not candidates:
        raise WindowsRuntimeBuildError("El runtime CPython embebido no contiene python*._pth")
    pth = candidates[0]
    lines = [
        f"python{PYTHON_TAG}.zip",
        ".",
        "Lib",
        r"Lib\site-packages",
        # CPython embeddable uses isolated _pth mode. The private interpreter lives
        # under <InstallRoot>\runtime\python, while GIDEON modules live two levels up.
        # Without this deterministic entry, `python.exe <InstallRoot>\gideon_agent.py`
        # can start but imports such as gideon_agent_http fail on a clean endpoint.
        r"..\..",
        "import site",
        "",
    ]
    pth.write_text("\r\n".join(lines), encoding="ascii", newline="")
    return pth


def _runtime_manifest(runtime_root: Path, wheels: Iterable[Path], python_archive: Path) -> dict[str, object]:
    files: dict[str, str] = {}
    for path in sorted(runtime_root.rglob("*")):
        if path.is_file():
            files[path.relative_to(runtime_root).as_posix()] = _sha256(path)
    return {
        "schema": RUNTIME_SCHEMA,
        "python_version": PYTHON_VERSION,
        "python_distribution": "CPython embeddable x64",
        "python_source_url": PYTHON_URL,
        "python_archive_sha256": _sha256(python_archive),
        "dependency_mode": "wheel-expanded-offline",
        "wheels": [{"name": p.name, "sha256": _sha256(p)} for p in sorted(wheels)],
        "files": files,
    }


def _windows_smoke_test(runtime_root: Path, app_payload: Path) -> None:
    if os.name != "nt":
        return
    python_exe = runtime_root / "python.exe"
    # Deliberately do NOT insert app_payload into sys.path here. This probe must
    # exercise the exact isolated CPython search path used by the installed Agent.
    code = (
        "import sys;"
        "import cryptography,PIL,pystray,gideon_agent,gideon_agent_http,gideon_agent_connectivity,gideon_agent_config,"
        "gideon_agent_security,gideon_agent_bootstrap,gideon_agent_worker,gideon_agent_job_contract,gideon_host_profiles,"
        "gideon_agent_tray,gideon_agent_update,gideon_agent_session_handoff,gideon_common;"
        "from pathlib import Path;"
        "assert Path(r'gideon_script_host.ps1').is_file(), 'gideon_script_host.ps1 missing';"
        "print(sys.version);print(gideon_agent.VERSION)"
    )
    proc = subprocess.run(
        [str(python_exe), "-c", code],
        cwd=str(app_payload),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if proc.returncode != 0:
        detail = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
        raise WindowsRuntimeBuildError("El runtime privado del Agent no pasó el smoke-test.\n" + detail[-8000:])


def validate_windows_private_runtime_payload(payload_dir: Path) -> dict[str, object]:
    """Fail closed unless the private Windows runtime is physically complete.

    Runs on the Control Plane before an EXE is emitted; no endpoint Python is used.
    """
    payload_dir = Path(payload_dir).resolve()
    runtime_dir = payload_dir / "runtime"
    runtime_root = runtime_dir / "python"
    manifest_path = runtime_dir / "runtime-manifest.json"
    if not manifest_path.is_file():
        raise WindowsRuntimeBuildError("AGENT_INSTALLER_INCOMPLETE: falta runtime/runtime-manifest.json")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        raise WindowsRuntimeBuildError(f"AGENT_INSTALLER_INCOMPLETE: runtime-manifest.json inválido: {exc}") from exc
    if str(manifest.get("schema") or "") != RUNTIME_SCHEMA:
        raise WindowsRuntimeBuildError("AGENT_INSTALLER_INCOMPLETE: schema de runtime no reconocido")
    if str(manifest.get("python_version") or "") != PYTHON_VERSION:
        raise WindowsRuntimeBuildError(
            f"AGENT_INSTALLER_INCOMPLETE: runtime Python {manifest.get('python_version')} != {PYTHON_VERSION}"
        )
    missing = [rel for rel in REQUIRED_RUNTIME_RELATIVE_FILES if not (runtime_root / Path(rel)).is_file()]
    missing += [rel for rel in REQUIRED_RUNTIME_IMPORT_PATHS if not (runtime_root / Path(rel)).is_file()]
    if missing:
        raise WindowsRuntimeBuildError(
            "AGENT_INSTALLER_INCOMPLETE: faltan componentes de runtime: " + ", ".join(sorted(set(missing)))
        )
    pth_text = (runtime_root / f"python{PYTHON_TAG}._pth").read_text(encoding="ascii", errors="strict")
    normalized_pth = {line.strip().replace("/", "\\").lower() for line in pth_text.splitlines() if line.strip()}
    if r"..\.." not in normalized_pth:
        raise WindowsRuntimeBuildError(
            "AGENT_INSTALLER_INCOMPLETE: python311._pth no incluye la raíz de la aplicación GIDEON (..\\..)."
        )
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise WindowsRuntimeBuildError("AGENT_INSTALLER_INCOMPLETE: runtime-manifest no declara archivos")
    for rel, expected in files.items():
        rel_text = str(rel).replace("\\", "/")
        rel_path = Path(rel_text)
        if rel_path.is_absolute() or ".." in rel_path.parts:
            raise WindowsRuntimeBuildError(f"AGENT_INSTALLER_INCOMPLETE: ruta insegura en manifest: {rel_text}")
        path = runtime_root / rel_path
        if not path.is_file():
            raise WindowsRuntimeBuildError(f"AGENT_INSTALLER_INCOMPLETE: runtime manifest declara archivo ausente: {rel_text}")
        if _sha256(path).lower() != str(expected or "").strip().lower():
            raise WindowsRuntimeBuildError(f"AGENT_INSTALLER_INCOMPLETE: SHA-256 no coincide: {rel_text}")
    return manifest


def prepare_windows_private_runtime(
    *,
    app_root: Path,
    payload_dir: Path,
    cache_dir: Path,
    allow_download: bool = True,
) -> dict[str, object]:
    """Populate payload/runtime/python with a runnable offline Windows runtime.

    Existing valid cache entries are reused.  If the cache is empty and downloads are
    allowed, only the Windows Agent build host accesses python.org/PyPI.  The generated
    endpoint installer then runs without any machine-wide Python dependency or network.
    """

    app_root = Path(app_root).resolve()
    payload_dir = Path(payload_dir).resolve()
    cache_dir = Path(cache_dir).resolve()
    cache_dir.mkdir(parents=True, exist_ok=True)

    python_archive = cache_dir / PYTHON_ARCHIVE
    if not python_archive.is_file():
        if not allow_download:
            raise WindowsRuntimeBuildError(
                f"Runtime CPython no está cacheado en {python_archive}. Habilite la adquisición automática del builder."
            )
        _download(PYTHON_URL, python_archive)
    _validate_python_embed_archive(python_archive)

    req = payload_dir / "requirements-agent.txt"
    if not req.is_file():
        req.write_text(DEFAULT_REQUIREMENTS, encoding="utf-8")

    wheel_cache = cache_dir / "wheels"
    wheels = sorted(wheel_cache.glob("*.whl"))
    # A requirements fingerprint prevents silently reusing an obsolete dependency set.
    fingerprint = hashlib.sha256(req.read_bytes()).hexdigest()
    fingerprint_file = wheel_cache / ".requirements.sha256"
    cached_fp = fingerprint_file.read_text(encoding="ascii").strip() if fingerprint_file.is_file() else ""
    if not wheels or cached_fp != fingerprint:
        if not allow_download:
            raise WindowsRuntimeBuildError("Las ruedas Windows del Agent no están cacheadas o están desactualizadas.")
        shutil.rmtree(wheel_cache, ignore_errors=True)
        wheel_cache.mkdir(parents=True, exist_ok=True)
        wheels = _pip_download_windows_wheels(req, wheel_cache)
        fingerprint_file.write_text(fingerprint + "\n", encoding="ascii")

    runtime_root = payload_dir / "runtime" / "python"
    shutil.rmtree(runtime_root, ignore_errors=True)
    runtime_root.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(python_archive, "r") as zf:
        zf.extractall(runtime_root)
    site_packages = runtime_root / "Lib" / "site-packages"
    site_packages.mkdir(parents=True, exist_ok=True)
    for wheel in wheels:
        _extract_wheel(wheel, site_packages)
    _configure_pth(runtime_root)

    manifest = _runtime_manifest(runtime_root, wheels, python_archive)
    (payload_dir / "runtime" / "runtime-manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    validate_windows_private_runtime_payload(payload_dir)
    _windows_smoke_test(runtime_root, payload_dir)
    return manifest


__all__ = [
    "PYTHON_VERSION",
    "PYTHON_URL",
    "DEFAULT_REQUIREMENTS",
    "WindowsRuntimeBuildError",
    "prepare_windows_private_runtime",
    "validate_windows_private_runtime_payload",
]
