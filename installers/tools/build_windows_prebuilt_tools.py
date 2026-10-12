#!/usr/bin/env python3
"""Regenerate the versioned, cross-platform Windows prebuilt helper binaries.

The cloud control plane builds Linux releases without ``csc.exe``.  Windows
releases are therefore allowed to use only the checked-in service host and SFX
stub after their source and SHA-256 provenance have been verified.  This tool
is intentionally a build-time maintenance utility: it does not sign, publish,
approve, install, or update an Agent.

Run this on a trusted Windows build workstation whenever ``AGENT_VERSION`` is
advanced.  It produces one canonical binary set and byte-copies it to the
Windows source mirror, so a Linux-hosted release builder sees exactly the same
validated assets.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


SCHEMA = "gideon-windows-prebuilt-tools/v1"
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:\.\d+)?$")
AGENT_VERSION_RE = re.compile(r'(?m)^AGENT_VERSION\s*=\s*["\']([^"\']+)["\']\s*$')
ASSEMBLY_VERSION_RE = re.compile(
    r'(?m)^\[assembly:\s*Assembly(?:File)?Version\("([^"\']+)"\)\]\s*$'
)


class PrebuiltBuildError(RuntimeError):
    """The local prebuilt-tools trust boundary could not be satisfied."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def assembly_version(version: str) -> str:
    if not VERSION_RE.fullmatch(version):
        raise PrebuiltBuildError(f"INVALID_AGENT_VERSION: {version}")
    parts = version.split(".")
    return ".".join((parts + ["0"] * 4)[:4])


def app_version(app_root: Path) -> str:
    version_file = Path(app_root) / "gideon_version.py"
    try:
        match = AGENT_VERSION_RE.search(version_file.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise PrebuiltBuildError(f"AGENT_VERSION_FILE_UNREADABLE: {version_file}") from exc
    if not match or not VERSION_RE.fullmatch(match.group(1)):
        raise PrebuiltBuildError(f"AGENT_VERSION_MISSING_OR_INVALID: {version_file}")
    return match.group(1)


def component_paths(app_root: Path) -> dict[str, Path]:
    windows_root = Path(app_root) / "deploy" / "agent" / "windows"
    prebuilt_root = windows_root / "prebuilt"
    return {
        "windows_root": windows_root,
        "prebuilt_root": prebuilt_root,
        "service_source": windows_root / "GIDEONAgentServiceHost.cs",
        "sfx_source": prebuilt_root / "GIDEONAgentSfxStub.cs",
        "sfx_manifest": prebuilt_root / "GIDEONAgentSfxStub.manifest",
        "service_binary": prebuilt_root / "GIDEONAgentServiceHost.exe",
        "sfx_binary": prebuilt_root / "GIDEONAgentSfxStub.exe",
        "manifest": prebuilt_root / "manifest.json",
    }


def assert_source_versions(app_root: Path, version: str) -> dict[str, Path]:
    if app_version(app_root) != version:
        raise PrebuiltBuildError(
            f"AGENT_VERSION_SOURCE_MISMATCH: app={app_version(app_root)} requested={version}"
        )
    paths = component_paths(app_root)
    wanted = assembly_version(version)
    for label in ("service_source", "sfx_source"):
        path = paths[label]
        if not path.is_file():
            raise PrebuiltBuildError(f"PREBUILT_SOURCE_MISSING: {path}")
        values = ASSEMBLY_VERSION_RE.findall(path.read_text(encoding="utf-8-sig"))
        if values != [wanted, wanted]:
            raise PrebuiltBuildError(
                f"PREBUILT_ASSEMBLY_VERSION_MISMATCH: {path.name} expected={wanted} got={values}"
            )
    if not paths["sfx_manifest"].is_file():
        raise PrebuiltBuildError(f"PREBUILT_SFX_MANIFEST_MISSING: {paths['sfx_manifest']}")
    return paths


def compiler_path(explicit: str = "") -> Path:
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    configured = os.environ.get("GIDEON_CSC_PATH")
    if configured:
        candidates.append(Path(configured))
    windir = Path(os.environ.get("WINDIR") or os.environ.get("SystemRoot") or r"C:\\Windows")
    candidates.extend(
        (
            windir / "Microsoft.NET" / "Framework64" / "v4.0.30319" / "csc.exe",
            windir / "Microsoft.NET" / "Framework" / "v4.0.30319" / "csc.exe",
        )
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise PrebuiltBuildError("WINDOWS_CSC_NOT_FOUND: install .NET Framework 4.x build tools on the trusted Windows builder")


def run_csc(args: list[str], *, cwd: Path) -> None:
    try:
        result = subprocess.run(
            args,
            cwd=str(cwd),
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PrebuiltBuildError(f"WINDOWS_CSC_EXECUTION_FAILED: {exc}") from exc
    if result.returncode != 0:
        detail = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
        raise PrebuiltBuildError(f"WINDOWS_CSC_BUILD_FAILED: exit={result.returncode}; {detail[-2000:]}")


def assert_pe(path: Path) -> None:
    if not path.is_file() or path.stat().st_size < 1024 or path.read_bytes()[:2] != b"MZ":
        raise PrebuiltBuildError(f"WINDOWS_PREBUILT_PE_INVALID: {path}")


def build_canonical(app_root: Path, version: str, compiler: Path) -> dict[str, bytes]:
    paths = assert_source_versions(app_root, version)
    with tempfile.TemporaryDirectory(prefix="gideon-windows-prebuilt-", dir=str(paths["prebuilt_root"])) as raw_stage:
        stage = Path(raw_stage)
        service_binary = stage / "GIDEONAgentServiceHost.exe"
        sfx_binary = stage / "GIDEONAgentSfxStub.exe"
        run_csc(
            [
                str(compiler), "/nologo", "/target:winexe", "/optimize+", "/platform:anycpu",
                "/reference:System.dll", "/reference:System.Core.dll", "/reference:System.ServiceProcess.dll",
                f"/out:{service_binary}", str(paths["service_source"]),
            ],
            cwd=stage,
        )
        run_csc(
            [
                str(compiler), "/nologo", "/target:winexe", "/optimize+", "/platform:anycpu",
                "/reference:System.Windows.Forms.dll", "/reference:System.Drawing.dll",
                f"/win32manifest:{paths['sfx_manifest']}", f"/out:{sfx_binary}", str(paths["sfx_source"]),
            ],
            cwd=stage,
        )
        assert_pe(service_binary)
        assert_pe(sfx_binary)
        document = {
            "schema": SCHEMA,
            "agent_version": version,
            "compiler": ".NET Framework csc.exe 4.8",
            "tools": {
                "sfx_stub": {
                    "binary": "GIDEONAgentSfxStub.exe",
                    "binary_sha256": sha256_file(sfx_binary),
                    "source_sha256": sha256_file(paths["sfx_source"]),
                    "manifest_sha256": sha256_file(paths["sfx_manifest"]),
                },
                "service_host": {
                    "binary": "GIDEONAgentServiceHost.exe",
                    "binary_sha256": sha256_file(service_binary),
                    "source_sha256": sha256_file(paths["service_source"]),
                },
            },
        }
        return {
            "GIDEONAgentServiceHost.exe": service_binary.read_bytes(),
            "GIDEONAgentSfxStub.exe": sfx_binary.read_bytes(),
            "manifest.json": (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
        }


def atomic_write(path: Path, content: bytes) -> None:
    path = Path(path)
    temporary = path.with_name(f".{path.name}.gideon-new")
    try:
        temporary.write_bytes(content)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink(missing_ok=True)


def validate_assets(app_root: Path, version: str) -> None:
    paths = assert_source_versions(app_root, version)
    try:
        document = json.loads(paths["manifest"].read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PrebuiltBuildError(f"WINDOWS_PREBUILT_MANIFEST_INVALID: {paths['manifest']}") from exc
    if not isinstance(document, dict) or document.get("schema") != SCHEMA:
        raise PrebuiltBuildError("WINDOWS_PREBUILT_MANIFEST_SCHEMA_INVALID")
    if str(document.get("agent_version") or "") != version:
        raise PrebuiltBuildError(
            f"WINDOWS_PREBUILT_VERSION_MISMATCH: prebuilt={document.get('agent_version')} requested={version}"
        )
    checks = {
        "service_host": ("service_binary", "service_source", None),
        "sfx_stub": ("sfx_binary", "sfx_source", "sfx_manifest"),
    }
    for tool, (binary_key, source_key, manifest_key) in checks.items():
        row = (document.get("tools") or {}).get(tool)
        if not isinstance(row, dict):
            raise PrebuiltBuildError(f"WINDOWS_PREBUILT_ENTRY_INVALID: {tool}")
        binary, source = paths[binary_key], paths[source_key]
        assert_pe(binary)
        if sha256_file(binary) != str(row.get("binary_sha256") or "").casefold():
            raise PrebuiltBuildError(f"WINDOWS_PREBUILT_BINARY_INVALID: {tool}")
        if sha256_file(source) != str(row.get("source_sha256") or "").casefold():
            raise PrebuiltBuildError(f"WINDOWS_PREBUILT_SOURCE_INVALID: {tool}")
        if manifest_key:
            manifest = paths[manifest_key]
            if sha256_file(manifest) != str(row.get("manifest_sha256") or "").casefold():
                raise PrebuiltBuildError(f"WINDOWS_PREBUILT_RESOURCE_MANIFEST_INVALID: {tool}")


def assert_mirror(canonical: Path, mirror: Path, version: str) -> None:
    if app_version(mirror) != version:
        raise PrebuiltBuildError(f"MIRROR_AGENT_VERSION_MISMATCH: {mirror}")
    canonical_paths = assert_source_versions(canonical, version)
    mirror_paths = assert_source_versions(mirror, version)
    for key in ("service_source", "sfx_source", "sfx_manifest"):
        if canonical_paths[key].read_bytes() != mirror_paths[key].read_bytes():
            raise PrebuiltBuildError(f"MIRROR_SOURCE_DRIFT: {key}")


def install_assets(app_root: Path, assets: dict[str, bytes]) -> None:
    paths = component_paths(app_root)
    for name, content in assets.items():
        atomic_write(paths["prebuilt_root"] / name, content)


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-root", type=Path, default=root / "payload" / "linux" / "app")
    parser.add_argument("--mirror-root", type=Path, default=root / "payload" / "windows" / "GIDEON Remote Control" / "app")
    parser.add_argument("--version", default="", help="Must equal AGENT_VERSION in both mirrors.")
    parser.add_argument("--compiler", default="", help="Explicit trusted .NET Framework csc.exe path.")
    parser.add_argument("--build", action="store_true", help="Compile and atomically refresh the canonical prebuilt assets.")
    parser.add_argument("--check", action="store_true", help="Validate provenance and mirror equality without writing files.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    canonical = args.app_root.resolve()
    mirror = args.mirror_root.resolve()
    version = args.version.strip() or app_version(canonical)
    if not args.build and not args.check:
        raise PrebuiltBuildError("Specify --build or --check")
    assert_mirror(canonical, mirror, version)
    if args.build:
        assets = build_canonical(canonical, version, compiler_path(args.compiler))
        install_assets(canonical, assets)
        install_assets(mirror, assets)
    validate_assets(canonical, version)
    validate_assets(mirror, version)
    for name in ("GIDEONAgentServiceHost.exe", "GIDEONAgentSfxStub.exe", "manifest.json"):
        left = component_paths(canonical)["prebuilt_root"] / name
        right = component_paths(mirror)["prebuilt_root"] / name
        if left.read_bytes() != right.read_bytes():
            raise PrebuiltBuildError(f"MIRROR_PREBUILT_DRIFT: {name}")
    print(f"OK windows-prebuilt version={version} canonical={canonical} mirror={mirror}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PrebuiltBuildError as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        raise SystemExit(2)
