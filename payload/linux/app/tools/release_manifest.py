from __future__ import annotations

"""Build and verify the canonical GIDEON Remote Control release manifest.

P8A/P8B/P8C/P8D/P8E/P8F/P8G/P8H keep ``gideon_version.py`` the authoritative runtime version source.  This
module projects those identifiers into the distribution manifest and verifies
that ``pyproject.toml`` and every packaged file agree with that contract.
"""

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import sys
import tomllib
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from gideon_packaging.runtime_profile import production_payload_files  # noqa: E402

from gideon_version import (  # noqa: E402
    AGENT_PROTOCOL_VERSION,
    AGENT_VERSION,
    FANOUT_PROTOCOL_VERSION,
    GATEWAY_VERSION,
    PRODUCT_VERSION,
)

PRODUCT_NAME = "GIDEON Remote Control"
MANIFEST_NAME = "RELEASE-MANIFEST.json"
RELEASE_LABEL = "RELEASE-6.3.4-RC30-STABILIZATION"

# These namespaces belong to the installation/site, not to a release.  A
# release manifest must remain portable across cloud and local installations;
# hashing branding, credentials or runtime databases would make a valid VM
# look tampered and would tempt an update to overwrite operator state.
PROTECTED_UPDATE_TOP_LEVEL = frozenset({
    "backups", "config", "data", "gateway-data", "logs", "pki",
    "quarantine", "releases", "scripts", "uploads", "users", "web-data",
})


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect_release_paths(root: Path) -> list[Path]:
    return [
        p for p in production_payload_files(root)
        if p.name != MANIFEST_NAME
        and p.relative_to(root).parts[0] not in PROTECTED_UPDATE_TOP_LEVEL
    ]


def manifest_files(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in collect_release_paths(root):
        rows.append(
            {
                "path": path.relative_to(root).as_posix(),
                "size_bytes": path.stat().st_size,
                "sha256": sha256(path),
            }
        )
    return rows


def build_manifest(root: Path, *, tests_passed: int) -> dict[str, Any]:
    return {
        "product": PRODUCT_NAME,
        "version": PRODUCT_VERSION,
        "release": RELEASE_LABEL,
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "version_contract": {
            "source_of_truth": "gideon_version.py:PRODUCT_VERSION",
            "source_pyproject_must_match_when_present": True,
            "runtime_pyproject_required": False,
            "downgrade_policy": "blocked_by_default_even_with_force",
            "web_downgrade_enabled": False,
        },
        "base_contract": {
            "requires_previous_version": False,
            "windows_installer": "INSTALL-GIDEON-WINDOWS.cmd",
            "linux_installer": "INSTALL-GIDEON-UBUNTU-LINUX.sh",
            "future_updates": f"incremental ZIP via Web Admin or console from {PRODUCT_VERSION} onward",
        },
        "components": {
            "application": PRODUCT_VERSION,
            "web_admin": PRODUCT_VERSION,
            "agent": AGENT_VERSION,
            "gateway": GATEWAY_VERSION,
            "agent_protocol": AGENT_PROTOCOL_VERSION,
            "fanout_protocol": FANOUT_PROTOCOL_VERSION,
        },
        "validation": {
            "checkpoint": "P8AE-RC30-STABILIZATION",
            "unittest_discovery_passed": int(tests_passed),
            "python_compileall": "OK",
            "release_contract": "OK",
            "windows_native_scm_runtime": "PENDING_WINDOWS_PILOT",
            "linux_systemd_runtime": "PENDING_LINUX_PILOT",
        },
        "isolation": {
            "defender_policy_modified": False,
            "openssh_server_modified": False,
            "global_firewall_modified_by_default": False,
            "clamav_service_modified": False,
            "clamav_auto_installed": False,
            "aws_ssm_modified": False,
            "nginx_apache_modified": False,
            "third_party_services_modified": False,
            "openssh_agent_modified": False,
            "global_ssh_process_kill_supported": False,
            "windows_service_allowlist": [
                "GIDEONRemoteControl",
                "GIDEONRemoteControlGateway",
                "GIDEONRemoteControlWebAdmin",
                "GIDEONRemoteControlBackup",
                "GIDEONRemoteControlUpdater",
                "GIDEONRemoteControlDiagnostics",
            ],
        },
        "protected_update_state": [
            "config",
            "data",
            "users/identities",
            "pki",
            "scripts",
            "releases",
            "backups",
            "logs",
            "uploads",
            "quarantine",
        ],
        "files": manifest_files(root),
    }


def write_manifest(root: Path, *, tests_passed: int) -> Path:
    root = root.resolve()
    target = root / MANIFEST_NAME
    payload = build_manifest(root, tests_passed=tests_passed)
    target.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return target


def verify_version_contract(root: Path, manifest: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    root = root.resolve()
    pyproject = root / "pyproject.toml"
    pyproject_version: str | None = None
    if pyproject.is_file():
        try:
            project = tomllib.loads(pyproject.read_text(encoding="utf-8-sig"))
            pyproject_version = str(project["project"]["version"])
        except Exception as exc:
            errors.append(f"pyproject.toml inválido: {exc}")

    expected = PRODUCT_VERSION
    observed = {
        "RELEASE-MANIFEST.version": str(manifest.get("version") or ""),
        "RELEASE-MANIFEST.components.application": str((manifest.get("components") or {}).get("application") or ""),
        "RELEASE-MANIFEST.components.web_admin": str((manifest.get("components") or {}).get("web_admin") or ""),
    }
    if pyproject_version is not None:
        observed["pyproject.toml.project.version"] = pyproject_version
    for label, value in observed.items():
        if value != expected:
            errors.append(f"{label}={value!r} no coincide con PRODUCT_VERSION={expected!r}")

    components = manifest.get("components") or {}
    if str(components.get("agent") or "") != AGENT_VERSION:
        errors.append("Versión Agent del manifest no coincide con gideon_version.py")
    if str(components.get("gateway") or "") != GATEWAY_VERSION:
        errors.append("Versión Gateway del manifest no coincide con gideon_version.py")
    if str(manifest.get("release") or "") != RELEASE_LABEL:
        errors.append(f"Release label inesperado: {manifest.get('release')!r}")
    return errors


def verify_manifest(root: Path) -> list[str]:
    root = root.resolve()
    target = root / MANIFEST_NAME
    if not target.is_file():
        return [f"Falta {MANIFEST_NAME}"]
    try:
        manifest = json.loads(target.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        return [f"{MANIFEST_NAME} inválido: {exc}"]
    if not isinstance(manifest, dict):
        return [f"{MANIFEST_NAME} debe contener un objeto JSON"]

    errors = verify_version_contract(root, manifest)
    declared = manifest.get("files") or []
    if not isinstance(declared, list):
        return errors + ["files debe ser una lista"]

    expected_paths = {path.relative_to(root).as_posix() for path in collect_release_paths(root)}
    declared_paths: set[str] = set()
    for index, row in enumerate(declared):
        if not isinstance(row, dict):
            errors.append(f"files[{index}] no es objeto")
            continue
        rel = str(row.get("path") or "")
        if not rel:
            errors.append(f"files[{index}] sin path")
            continue
        if rel in declared_paths:
            errors.append(f"Archivo duplicado en manifest: {rel}")
            continue
        declared_paths.add(rel)
        path = root / rel
        if not path.is_file():
            errors.append(f"Archivo declarado inexistente: {rel}")
            continue
        if int(row.get("size_bytes") or -1) != path.stat().st_size:
            errors.append(f"Tamaño no coincide: {rel}")
        if str(row.get("sha256") or "").lower() != sha256(path):
            errors.append(f"SHA-256 no coincide: {rel}")

    missing = sorted(expected_paths - declared_paths)
    extra = sorted(declared_paths - expected_paths)
    if missing:
        errors.append("Archivos de release no declarados: " + ", ".join(missing))
    if extra:
        errors.append("Archivos declarados fuera del release: " + ", ".join(extra))
    return errors


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build/verify GIDEON canonical release manifest")
    parser.add_argument("action", choices=["build", "check"])
    parser.add_argument("--root", default=str(ROOT))
    parser.add_argument("--tests-passed", type=int, default=0)
    ns = parser.parse_args(list(argv) if argv is not None else None)
    root = Path(ns.root).resolve()
    if ns.action == "build":
        path = write_manifest(root, tests_passed=max(0, ns.tests_passed))
        print(path)
        return 0
    errors = verify_manifest(root)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"OK: {MANIFEST_NAME} coherente con PRODUCT_VERSION={PRODUCT_VERSION}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
