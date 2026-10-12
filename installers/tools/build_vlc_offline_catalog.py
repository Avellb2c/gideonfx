#!/usr/bin/env python3
"""Build a reviewed, offline-only VLC catalog from local intake material.

This tool is deliberately an *intake* step, not a downloader.  It never
contacts VideoLAN, a package repository, or any other network endpoint.  A
release engineer first obtains vendor binaries, checksums, signatures and GPL
source-offer material through the approved procurement process, then supplies
them below ``--source-root`` with an immutable JSON intake manifest.

The output is a fresh ``third_party/vlc-offline`` tree containing only the
target-specific files declared in that manifest and a catalog compatible with
``gideon_agent_vlc_offline.py``.  The normal GIDEON Agent builder signs the filtered
catalog later with the GIDEON release key; this tool intentionally has no access
to release keys or network credentials.

Example (validation only)::

    python installers/tools/build_vlc_offline_catalog.py \
      --intake C:/review/vlc-intake.json --source-root C:/review/material \
      --check

Example (write a new, empty destination)::

    python installers/tools/build_vlc_offline_catalog.py \
      --intake C:/review/vlc-intake.json --source-root C:/review/material \
      --output-root C:/review/vlc-offline

The output directory is refused when it already contains files.  That keeps a
catalog rebuild from silently replacing a reviewed set of binaries.

Linux repository metadata is verified fail-closed with ``gpgv`` and the
public key embedded in that same reviewed repository.  On Windows the tool
uses WSL Debian by default; set ``GIDEON_WSL_GPGV_DISTRO`` to another trusted WSL
distribution when appropriate.  Signature verification never consults a
network keyserver or ambient user trust database.
"""
from __future__ import annotations

import argparse
from collections import Counter
import datetime as dt
import gzip
import hashlib
import importlib
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Iterable, Mapping


ROOT = Path(__file__).resolve().parents[2]
LINUX_APP = ROOT / "payload" / "linux" / "app"
INTAKE_SCHEMA = "gideon-vlc-offline-intake/v1"
SOURCE_MATERIALS_SCHEMA = "gideon-vlc-source-materials/v1"
CATALOG_SCHEMA = "gideon-vlc-offline-catalog/v1"
REQUIRED_LEGAL_PATHS = (
    "legal/GPL-2.0.txt",
    "legal/VLC-NOTICE.md",
    "legal/SOURCE-OFFER.md",
    "legal/SOURCE-MATERIALS.json",
)
MAX_FILE_BYTES = 12 * 1024 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024 * 1024
MAX_FILES = 4096
GPGV_TIMEOUT_SECONDS = 45
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
SAFE_PACKAGE_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]{0,79}$")
SAFE_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,159}$")
SAFE_CODENAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,79}$")
ALLOWED_LINUX_IDS = frozenset({"debian", "ubuntu", "raspbian"})
PLATFORM_ALIASES = {
    "win": "windows", "win32": "windows", "windows": "windows",
    "linux": "linux",
}
ARCH_ALIASES = {
    "amd64": "x86_64", "x64": "x86_64", "x86-64": "x86_64", "x86_64": "x86_64",
    "aarch64": "arm64", "armv8": "arm64", "armv8l": "arm64", "arm64": "arm64",
    "armhf": "armv7l", "armv7": "armv7l", "armv7l": "armv7l",
}
DEB_ARCH_BY_ARCH = {"x86_64": "amd64", "arm64": "arm64", "armv7l": "armhf"}
RESERVED_OUTPUT_PATHS = frozenset({"catalog.json", "catalog.sig", "gideon-vlc-offline-profile.json"})
BUNDLED_SOURCE_PREFIX = "legal/sources/"
BUNDLED_SOURCE_ROLES = frozenset({
    "source-archive",
    "source-signature",
    "source-checksum",
    "build-scripts",
    "build-instructions",
    "source-notice",
})


class VlcOfflineCatalogBuildError(RuntimeError):
    """A reviewed offline VLC intake is malformed, unsafe, or incomplete."""


def _bounded(value: Any, maximum: int = 500) -> str:
    return str(value or "").replace("\x00", " ").strip()[:maximum]


def _safe_relative(value: Any, *, field: str) -> PurePosixPath:
    text = _bounded(value, 500).replace("\\", "/")
    path = PurePosixPath(text)
    if not text or path.is_absolute() or ".." in path.parts or any(part in {"", "."} for part in path.parts):
        raise VlcOfflineCatalogBuildError(f"VLC_INTAKE_{field.upper()}_UNSAFE")
    return path


def _resolve_under(root: Path, relative: Any, *, field: str) -> Path:
    root = Path(root).resolve()
    target = (root / Path(*_safe_relative(relative, field=field).parts)).resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise VlcOfflineCatalogBuildError(f"VLC_INTAKE_{field.upper()}_ESCAPE") from exc
    return target


def _reject_symlink_chain(root: Path, relative: Any, *, field: str) -> None:
    """Reject a file reached through any symlink below the reviewed root."""
    current = Path(root)
    for part in _safe_relative(relative, field=field).parts:
        current = current / part
        if current.is_symlink():
            raise VlcOfflineCatalogBuildError(f"VLC_INTAKE_{field.upper()}_SYMLINK_REFUSED")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb", buffering=1024 * 1024) as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_json(path: Path, *, code: str, maximum: int = 4 * 1024 * 1024) -> dict[str, Any]:
    try:
        raw = Path(path).read_bytes()
        if len(raw) > maximum:
            raise VlcOfflineCatalogBuildError(f"{code}_TOO_LARGE")
        value = json.loads(raw.decode("utf-8-sig"))
    except VlcOfflineCatalogBuildError:
        raise
    except Exception as exc:
        raise VlcOfflineCatalogBuildError(f"{code}_INVALID") from exc
    if not isinstance(value, Mapping):
        raise VlcOfflineCatalogBuildError(f"{code}_OBJECT_REQUIRED")
    return dict(value)


def _require_text(value: Any, *, code: str, maximum: int = 240, pattern: re.Pattern[str] | None = None) -> str:
    text = _bounded(value, maximum)
    if not text or (pattern is not None and not pattern.fullmatch(text)):
        raise VlcOfflineCatalogBuildError(code)
    return text


def _require_sha256(value: Any, *, code: str) -> str:
    digest = _bounded(value, 80).casefold()
    if not SHA256_RE.fullmatch(digest):
        raise VlcOfflineCatalogBuildError(code)
    return digest


def _positive_size(value: Any, *, code: str) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise VlcOfflineCatalogBuildError(code) from exc
    if result <= 0 or result > MAX_FILE_BYTES:
        raise VlcOfflineCatalogBuildError(code)
    return result


def _normal_platform(value: Any) -> str:
    raw = _require_text(value, code="VLC_INTAKE_PLATFORM_INVALID", maximum=32).casefold()
    try:
        return PLATFORM_ALIASES[raw]
    except KeyError as exc:
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_PLATFORM_UNSUPPORTED") from exc


def _normal_arch(value: Any) -> str:
    raw = _require_text(value, code="VLC_INTAKE_ARCHITECTURE_INVALID", maximum=32).casefold()
    try:
        return ARCH_ALIASES[raw]
    except KeyError as exc:
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_ARCHITECTURE_UNSUPPORTED") from exc


def _copy_verified(source_root: Path, stage_root: Path, row: Mapping[str, Any], *, field: str) -> tuple[dict[str, Any], Path]:
    """Validate a local intake file and copy it into the isolated staging tree."""
    if not isinstance(row, Mapping):
        raise VlcOfflineCatalogBuildError(f"VLC_INTAKE_{field.upper()}_OBJECT_REQUIRED")
    target_rel = str(_safe_relative(row.get("Path"), field=f"{field}_path"))
    if target_rel.casefold() in RESERVED_OUTPUT_PATHS:
        raise VlcOfflineCatalogBuildError(f"VLC_INTAKE_{field.upper()}_TARGET_RESERVED")
    source_rel = _safe_relative(row.get("SourcePath"), field=f"{field}_source_path")
    expected_size = _positive_size(row.get("SizeBytes"), code=f"VLC_INTAKE_{field.upper()}_SIZE_INVALID")
    expected_hash = _require_sha256(row.get("Sha256"), code=f"VLC_INTAKE_{field.upper()}_HASH_INVALID")
    _reject_symlink_chain(source_root, source_rel, field=f"{field}_source_path")
    source = _resolve_under(source_root, source_rel, field=f"{field}_source_path")
    if not source.is_file() or source.is_symlink():
        raise VlcOfflineCatalogBuildError(f"VLC_INTAKE_{field.upper()}_SOURCE_MISSING")
    stat = source.stat()
    if stat.st_size != expected_size:
        raise VlcOfflineCatalogBuildError(f"VLC_INTAKE_{field.upper()}_SIZE_MISMATCH")
    if _sha256_file(source) != expected_hash:
        raise VlcOfflineCatalogBuildError(f"VLC_INTAKE_{field.upper()}_HASH_MISMATCH")
    destination = _resolve_under(stage_root, target_rel, field=f"{field}_path")
    if destination.exists() or destination.is_symlink():
        raise VlcOfflineCatalogBuildError(f"VLC_INTAKE_{field.upper()}_TARGET_DUPLICATE")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    os.chmod(destination, 0o644)
    normalized = {"Path": target_rel, "SizeBytes": expected_size, "Sha256": expected_hash}
    return normalized, source


def _parse_iso(value: Any, *, code: str) -> dt.datetime:
    text = _require_text(value, code=code, maximum=80)
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise VlcOfflineCatalogBuildError(code) from exc
    if parsed.tzinfo is None:
        raise VlcOfflineCatalogBuildError(code)
    return parsed.astimezone(dt.timezone.utc)


def _load_runtime_validator():
    """Use the Agent's schema validator so intake cannot drift from runtime."""
    if str(LINUX_APP) not in sys.path:
        sys.path.insert(0, str(LINUX_APP))
    try:
        module = importlib.import_module("gideon_agent_vlc_offline")
        return module.validate_catalog
    except Exception as exc:
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_RUNTIME_SCHEMA_UNAVAILABLE") from exc


def _parse_debian_stanzas(raw: str) -> list[dict[str, str]]:
    """Parse RFC822-style Debian control records without invoking dpkg."""
    entries: list[dict[str, str]] = []
    current: dict[str, str] = {}
    key: str | None = None
    for line in raw.replace("\r\n", "\n").split("\n"):
        if not line:
            if current:
                entries.append(current)
                current = {}
            key = None
            continue
        if line.startswith((" ", "\t")) and key:
            current[key] = current[key] + "\n" + line[1:]
            continue
        if ":" not in line:
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_APT_INDEX_INVALID")
        key, value = line.split(":", 1)
        key = key.strip()
        if not key:
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_APT_INDEX_INVALID")
        current[key] = value.strip()
    if current:
        entries.append(current)
    if not entries:
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_APT_INDEX_EMPTY")
    return entries


def _read_packages_index(path: Path) -> list[dict[str, str]]:
    try:
        raw = path.read_bytes()
        lower = path.name.casefold()
        if lower.endswith(".gz"):
            raw = gzip.decompress(raw)
        elif lower.endswith(".xz"):
            raw = lzma.decompress(raw)
        elif not lower.endswith("packages"):
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_APT_INDEX_NAME_INVALID")
        return _parse_debian_stanzas(raw.decode("utf-8", errors="strict"))
    except VlcOfflineCatalogBuildError:
        raise
    except Exception as exc:
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_APT_INDEX_INVALID") from exc


def _wsl_path(path: Path, *, wsl: str, distribution: str) -> str:
    """Translate a Windows review path for the selected WSL gpgv host."""
    # wsl.exe passes arguments through a Linux command-line parser.  A single
    # Windows backslash would therefore be consumed before wslpath sees it.
    escaped_path = str(path).replace("\\", "\\\\")
    try:
        completed = subprocess.run(
            [wsl, "-d", distribution, "--", "wslpath", "-a", "-u", escaped_path],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=GPGV_TIMEOUT_SECONDS,
            check=False,
        )
    except Exception as exc:
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_APT_GPGV_UNAVAILABLE") from exc
    translated = (completed.stdout or "").strip()
    if completed.returncode or not translated.startswith("/"):
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_APT_GPGV_UNAVAILABLE")
    return translated


def _verify_apt_repository_signature(*, key: Path, signature: Path, release: Path | None = None) -> None:
    """Verify an APT Release signature before cataloguing repository bytes.

    Linux uses the native ``gpgv``.  A Windows release workstation may use a
    specifically selected WSL distribution (Debian by default, override with
    ``GIDEON_WSL_GPGV_DISTRO``).  No trust database or network lookup is used:
    only the public key physically embedded in the reviewed repository is
    accepted.
    """
    direct = shutil.which("gpgv") or shutil.which("gpgv.exe")
    if direct:
        command = [direct, "--keyring", str(key), str(signature)]
        if release is not None:
            command.append(str(release))
    elif os.name == "nt":
        wsl = shutil.which("wsl.exe") or shutil.which("wsl")
        if not wsl:
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_APT_GPGV_UNAVAILABLE")
        distribution = _bounded(os.environ.get("GIDEON_WSL_GPGV_DISTRO") or "Debian", 80)
        if not SAFE_CODENAME_RE.fullmatch(distribution.casefold()):
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_APT_GPGV_DISTRO_INVALID")
        command = [
            wsl, "-d", distribution, "--", "gpgv", "--keyring",
            _wsl_path(key, wsl=wsl, distribution=distribution),
            _wsl_path(signature, wsl=wsl, distribution=distribution),
        ]
        if release is not None:
            command.append(_wsl_path(release, wsl=wsl, distribution=distribution))
    else:
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_APT_GPGV_UNAVAILABLE")
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=GPGV_TIMEOUT_SECONDS,
            check=False,
        )
    except Exception as exc:
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_APT_SIGNATURE_VERIFY_FAILED") from exc
    if completed.returncode:
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_APT_SIGNATURE_VERIFY_FAILED")


def _strip_dep_name(value: str) -> str:
    text = value.strip()
    text = re.sub(r"\s*\([^)]*\)", "", text)
    text = re.sub(r"\s*\[[^]]*\]", "", text)
    text = re.sub(r"\s*<[^>]*>", "", text)
    text = text.strip().split(":", 1)[0].strip()
    return text


def _dependency_alternatives(value: str) -> Iterable[list[str]]:
    for group in value.split(","):
        alternatives = [_strip_dep_name(item) for item in group.split("|")]
        names = [name for name in alternatives if SAFE_PACKAGE_RE.fullmatch(name)]
        if names:
            yield names


def _validate_linux_repository(variant: dict[str, Any], *, stage_root: Path) -> None:
    install = variant["Install"]
    repo_rel = str(_safe_relative(install.get("RepositoryPath"), field="repository_path"))
    key_rel = str(_safe_relative(install.get("AptSigningKeyPath"), field="apt_signing_key_path"))
    if not key_rel.startswith(repo_rel + "/"):
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_APT_KEY_OUTSIDE_REPOSITORY")
    rows = variant["Files"]
    roles: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        if not str(row["Path"]).startswith(repo_rel + "/"):
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_APT_FILE_OUTSIDE_REPOSITORY")
        roles.setdefault(str(row["Role"]), []).append(row)
    if len(roles.get("apt-key", [])) != 1 or roles["apt-key"][0]["Path"] != key_rel:
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_APT_KEY_REQUIRED")
    if len(roles.get("apt-packages-index", [])) != 1:
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_APT_INDEX_REQUIRED")
    index_row = roles["apt-packages-index"][0]
    allowed_indexes = {
        f"{repo_rel}/Packages",
        f"{repo_rel}/Packages.gz",
        f"{repo_rel}/Packages.xz",
    }
    if str(index_row["Path"]) not in allowed_indexes:
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_APT_FLAT_REPOSITORY_LAYOUT_REQUIRED")
    apt_key_path = _resolve_under(stage_root, key_rel, field="apt_signing_key_path")
    if len(roles.get("apt-inrelease", [])) == 1:
        if roles.get("apt-release") or roles.get("apt-release-signature"):
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_APT_SIGNATURE_AMBIGUOUS")
        if str(roles["apt-inrelease"][0]["Path"]) != f"{repo_rel}/InRelease":
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_APT_FLAT_REPOSITORY_LAYOUT_REQUIRED")
        _verify_apt_repository_signature(
            key=apt_key_path,
            signature=_resolve_under(stage_root, roles["apt-inrelease"][0]["Path"], field="apt_inrelease_path"),
        )
    elif len(roles.get("apt-release", [])) == 1 and len(roles.get("apt-release-signature", [])) == 1:
        if (
            str(roles["apt-release"][0]["Path"]) != f"{repo_rel}/Release"
            or str(roles["apt-release-signature"][0]["Path"]) != f"{repo_rel}/Release.gpg"
        ):
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_APT_FLAT_REPOSITORY_LAYOUT_REQUIRED")
        _verify_apt_repository_signature(
            key=apt_key_path,
            signature=_resolve_under(stage_root, roles["apt-release-signature"][0]["Path"], field="apt_release_signature_path"),
            release=_resolve_under(stage_root, roles["apt-release"][0]["Path"], field="apt_release_path"),
        )
    else:
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_APT_SIGNATURE_REQUIRED")
    debs = roles.get("deb", [])
    if not debs:
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_APT_DEBS_REQUIRED")
    index_path = _resolve_under(stage_root, index_row["Path"], field="apt_packages_index")
    indexed = _read_packages_index(index_path)
    by_filename = {str(row.get("Filename") or "").lstrip("./"): row for row in indexed}
    if len(by_filename) != len(indexed):
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_APT_INDEX_DUPLICATE_FILENAME")
    package_names: set[str] = set()
    provides: set[str] = set()
    indexed_by_name: dict[str, list[dict[str, str]]] = {}
    for stanza in indexed:
        package = _bounded(stanza.get("Package"), 80)
        version = _bounded(stanza.get("Version"), 160)
        architecture = _bounded(stanza.get("Architecture"), 32).casefold()
        if not SAFE_PACKAGE_RE.fullmatch(package) or not SAFE_VERSION_RE.fullmatch(version) or not architecture:
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_APT_INDEX_PACKAGE_INVALID")
        package_names.add(package)
        indexed_by_name.setdefault(package, []).append(stanza)
        for raw_provide in _dependency_alternatives(stanza.get("Provides", "")):
            provides.update(raw_provide)
    for row in debs:
        rel_in_repo = str(row["Path"])[len(repo_rel) + 1:]
        stanza = by_filename.get(rel_in_repo)
        if not stanza:
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_DEB_NOT_IN_INDEX")
        if _bounded(stanza.get("SHA256"), 80).casefold() != row["Sha256"]:
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_DEB_INDEX_HASH_MISMATCH")
        if _bounded(stanza.get("Size"), 30) != str(row["SizeBytes"]):
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_DEB_INDEX_SIZE_MISMATCH")
        if stanza.get("Package") != row["Package"] or stanza.get("Version") != row["Version"] or stanza.get("Architecture", "").casefold() != row["DebArchitecture"]:
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_DEB_INDEX_METADATA_MISMATCH")
    closure = variant["DependencyClosure"]
    closure_names = set(closure["PackageClosure"])
    if closure_names != package_names:
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_APT_CLOSURE_NOT_EXACT")
    base_names = set(closure["BaseSystemPackages"])
    if closure_names & base_names:
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_APT_BASE_PACKAGE_DUPLICATE")
    unresolved: list[str] = []
    available = closure_names | base_names | provides
    for stanza in indexed:
        for field in ("Pre-Depends", "Depends"):
            for alternatives in _dependency_alternatives(stanza.get(field, "")):
                if not set(alternatives).intersection(available):
                    unresolved.append("|".join(alternatives))
    if unresolved:
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_APT_DEPENDENCY_UNDECLARED:" + ",".join(sorted(set(unresolved))[:8]))


def _source_offer_method(path: Path) -> str:
    """Return the declared GPL source-distribution method from reviewed data."""
    materials = _read_json(path, code="VLC_INTAKE_SOURCE_MATERIALS")
    offer = materials.get("SourceOffer")
    if not isinstance(offer, Mapping):
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_SOURCE_OFFER_REQUIRED")
    method = _bounded(offer.get("Method"), 40)
    if method not in {"written-offer", "bundled-source"}:
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_SOURCE_OFFER_METHOD_INVALID")
    return method


def _validate_source_materials(
    path: Path,
    *,
    catalog: Mapping[str, Any],
    bundled_sources: list[dict[str, Any]],
    stage_root: Path,
) -> dict[str, list[str]]:
    materials = _read_json(path, code="VLC_INTAKE_SOURCE_MATERIALS")
    if _bounded(materials.get("Schema"), 100) != SOURCE_MATERIALS_SCHEMA:
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_SOURCE_MATERIALS_SCHEMA_INVALID")
    if _bounded(materials.get("Product"), 120) != "VLC media player" or _bounded(materials.get("License"), 80) != "GPL-2.0-or-later":
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_SOURCE_MATERIALS_LICENSE_INVALID")
    offer = materials.get("SourceOffer")
    if not isinstance(offer, Mapping):
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_SOURCE_OFFER_REQUIRED")
    method = _bounded(offer.get("Method"), 40)
    if method not in {"written-offer", "bundled-source"}:
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_SOURCE_OFFER_METHOD_INVALID")
    if method == "written-offer":
        _require_text(offer.get("Contact"), code="VLC_INTAKE_SOURCE_OFFER_CONTACT_REQUIRED", maximum=500)
        try:
            valid_until = dt.date.fromisoformat(_require_text(offer.get("ValidUntil"), code="VLC_INTAKE_SOURCE_OFFER_VALIDITY_REQUIRED", maximum=20))
        except ValueError as exc:
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_SOURCE_OFFER_VALIDITY_REQUIRED") from exc
        if valid_until < dt.date.today() + dt.timedelta(days=365 * 3):
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_SOURCE_OFFER_TOO_SHORT")
    sources_raw = materials.get("Sources")
    if not isinstance(sources_raw, list) or not sources_raw:
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_SOURCES_REQUIRED")
    source_ids: set[str] = set()
    source_archive_hashes: dict[str, Counter[str]] = {}
    multipart_source_ids: set[str] = set()
    for row in sources_raw:
        if not isinstance(row, Mapping):
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_SOURCE_OBJECT_REQUIRED")
        source_id = _require_text(row.get("SourceId"), code="VLC_INTAKE_SOURCE_ID_INVALID", maximum=160, pattern=SAFE_ID_RE)
        if source_id in source_ids:
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_SOURCE_DUPLICATE")
        source_ids.add(source_id)
        _require_text(row.get("Version"), code="VLC_INTAKE_SOURCE_VERSION_INVALID", maximum=160)
        for field in ("SourceUrl", "ChecksumUrl", "SignatureUrl"):
            if not _require_text(row.get(field), code=f"VLC_INTAKE_SOURCE_{field.upper()}_INVALID", maximum=500).startswith("https://"):
                raise VlcOfflineCatalogBuildError(f"VLC_INTAKE_SOURCE_{field.upper()}_INVALID")
        legacy_hash = _bounded(row.get("SourceSha256"), 80)
        archives_raw = row.get("Archives")
        if legacy_hash and archives_raw is not None:
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_SOURCE_ARCHIVE_DECLARATION_AMBIGUOUS")
        if legacy_hash:
            source_archive_hashes[source_id] = Counter({
                _require_sha256(legacy_hash, code="VLC_INTAKE_SOURCE_HASH_INVALID"): 1,
            })
        else:
            if not isinstance(archives_raw, list) or not archives_raw or len(archives_raw) > MAX_FILES:
                raise VlcOfflineCatalogBuildError("VLC_INTAKE_SOURCE_ARCHIVES_INVALID")
            multipart_source_ids.add(source_id)
            expected_hashes: Counter[str] = Counter()
            archive_names: set[str] = set()
            for archive in archives_raw:
                if not isinstance(archive, Mapping):
                    raise VlcOfflineCatalogBuildError("VLC_INTAKE_SOURCE_ARCHIVE_OBJECT_REQUIRED")
                archive_name = _require_text(
                    archive.get("Filename"),
                    code="VLC_INTAKE_SOURCE_ARCHIVE_FILENAME_INVALID",
                    maximum=240,
                )
                safe_name = _safe_relative(archive_name, field="source_archive_filename")
                if len(safe_name.parts) != 1 or archive_name in archive_names:
                    raise VlcOfflineCatalogBuildError("VLC_INTAKE_SOURCE_ARCHIVE_FILENAME_INVALID")
                archive_names.add(archive_name)
                archive_size = archive.get("SizeBytes")
                if not isinstance(archive_size, int) or isinstance(archive_size, bool) or archive_size <= 0 or archive_size > MAX_FILE_BYTES:
                    raise VlcOfflineCatalogBuildError("VLC_INTAKE_SOURCE_ARCHIVE_SIZE_INVALID")
                archive_url = _require_text(
                    archive.get("SourceUrl"),
                    code="VLC_INTAKE_SOURCE_ARCHIVE_URL_INVALID",
                    maximum=500,
                )
                if not archive_url.startswith("https://"):
                    raise VlcOfflineCatalogBuildError("VLC_INTAKE_SOURCE_ARCHIVE_URL_INVALID")
                expected_hashes.update([
                    _require_sha256(archive.get("Sha256"), code="VLC_INTAKE_SOURCE_ARCHIVE_HASH_INVALID")
                ])
            source_archive_hashes[source_id] = expected_hashes
    bundled_by_source: dict[str, list[dict[str, Any]]] = {}
    for row in bundled_sources:
        source_id = _require_text(
            row.get("SourceId"),
            code="VLC_INTAKE_BUNDLED_SOURCE_ID_INVALID",
            maximum=160,
            pattern=SAFE_ID_RE,
        )
        if source_id not in source_ids:
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_BUNDLED_SOURCE_UNKNOWN")
        path_value = str(_safe_relative(row.get("Path"), field="bundled_source_path"))
        if not path_value.startswith(BUNDLED_SOURCE_PREFIX):
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_BUNDLED_SOURCE_PATH_INVALID")
        staged = _resolve_under(stage_root, path_value, field="bundled_source_path")
        if not staged.is_file() or staged.is_symlink():
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_BUNDLED_SOURCE_MISSING")
        if staged.stat().st_size != int(row["SizeBytes"]):
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_BUNDLED_SOURCE_SIZE_MISMATCH")
        if _sha256_file(staged) != str(row["Sha256"]):
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_BUNDLED_SOURCE_HASH_MISMATCH")
        bundled_by_source.setdefault(source_id, []).append(row)
    if method == "bundled-source":
        if not bundled_sources:
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_BUNDLED_SOURCES_REQUIRED")
        for source_id, expected_hashes in source_archive_hashes.items():
            archives = [
                row for row in bundled_by_source.get(source_id, [])
                if row.get("Role") == "source-archive"
            ]
            if not archives:
                raise VlcOfflineCatalogBuildError("VLC_INTAKE_BUNDLED_SOURCE_ARCHIVE_REQUIRED")
            actual_hashes = Counter(str(row["Sha256"]) for row in archives)
            if source_id in multipart_source_ids and actual_hashes - expected_hashes:
                raise VlcOfflineCatalogBuildError("VLC_INTAKE_BUNDLED_SOURCE_ARCHIVE_UNEXPECTED")
            if expected_hashes - actual_hashes:
                raise VlcOfflineCatalogBuildError("VLC_INTAKE_BUNDLED_SOURCE_ARCHIVE_HASH_MISMATCH")
    elif bundled_sources:
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_BUNDLED_SOURCES_NOT_ALLOWED")
    evidence_raw = materials.get("Artifacts")
    if not isinstance(evidence_raw, list) or not evidence_raw:
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_ARTIFACT_EVIDENCE_REQUIRED")
    declared_variants = {str(row["VariantId"]) for row in catalog["Variants"]}
    evidence: dict[tuple[str, str], Mapping[str, Any]] = {}
    source_ids_by_variant: dict[str, set[str]] = {variant_id: set() for variant_id in declared_variants}
    for row in evidence_raw:
        if not isinstance(row, Mapping):
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_ARTIFACT_EVIDENCE_OBJECT_REQUIRED")
        variant_id = _require_text(row.get("VariantId"), code="VLC_INTAKE_ARTIFACT_VARIANT_INVALID", maximum=160, pattern=SAFE_ID_RE)
        if variant_id not in declared_variants:
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_ARTIFACT_VARIANT_UNKNOWN")
        artifact_path = str(_safe_relative(row.get("Path"), field="artifact_evidence_path"))
        key = (variant_id, artifact_path)
        if key in evidence:
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_ARTIFACT_EVIDENCE_DUPLICATE")
        evidence[key] = row
        source_id = _require_text(row.get("SourceId"), code="VLC_INTAKE_ARTIFACT_SOURCE_ID_INVALID", maximum=160, pattern=SAFE_ID_RE)
        if source_id not in source_ids:
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_ARTIFACT_SOURCE_UNKNOWN")
        source_ids_by_variant[variant_id].add(source_id)
        for field in ("ArtifactUrl", "ChecksumUrl"):
            if not _require_text(row.get(field), code=f"VLC_INTAKE_ARTIFACT_{field.upper()}_INVALID", maximum=500).startswith("https://"):
                raise VlcOfflineCatalogBuildError(f"VLC_INTAKE_ARTIFACT_{field.upper()}_INVALID")
        _parse_iso(row.get("RetrievedAt"), code="VLC_INTAKE_ARTIFACT_RETRIEVED_INVALID")
        _require_sha256(row.get("UpstreamSha256"), code="VLC_INTAKE_ARTIFACT_UPSTREAM_HASH_INVALID")
    for variant in catalog["Variants"]:
        for item in variant["Files"]:
            if item["Role"] not in {"installer", "deb"}:
                continue
            row = evidence.get((variant["VariantId"], item["Path"]))
            if row is None:
                raise VlcOfflineCatalogBuildError("VLC_INTAKE_ARTIFACT_EVIDENCE_MISSING")
            if _require_sha256(row.get("UpstreamSha256"), code="VLC_INTAKE_ARTIFACT_UPSTREAM_HASH_INVALID") != item["Sha256"]:
                raise VlcOfflineCatalogBuildError("VLC_INTAKE_ARTIFACT_UPSTREAM_HASH_MISMATCH")
        if not source_ids_by_variant.get(str(variant["VariantId"])):
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_VARIANT_SOURCE_IDS_REQUIRED")
    return {
        variant_id: sorted(source_ids)
        for variant_id, source_ids in sorted(source_ids_by_variant.items())
    }


def _verify_legal_content(legal_paths: Mapping[str, Path]) -> None:
    try:
        gpl = legal_paths["legal/GPL-2.0.txt"].read_text(encoding="utf-8", errors="replace")
        notice = legal_paths["legal/VLC-NOTICE.md"].read_text(encoding="utf-8", errors="replace")
        offer = legal_paths["legal/SOURCE-OFFER.md"].read_text(encoding="utf-8", errors="replace")
    except KeyError as exc:
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_LEGAL_FILE_MISSING") from exc
    if "GNU GENERAL PUBLIC LICENSE" not in gpl or "Version 2" not in gpl:
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_GPL_TEXT_INVALID")
    if "VideoLAN" not in notice or "GPL" not in notice:
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_VLC_NOTICE_INVALID")
    if "VLC" not in offer or "source" not in offer.casefold():
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_SOURCE_OFFER_TEXT_INVALID")


def _optional_authenticode_verify(path: Path, expected: Mapping[str, Any]) -> None:
    if os.name != "nt":
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_AUTHENTICODE_WINDOWS_REQUIRED")
    shell = shutil.which("powershell.exe") or shutil.which("powershell")
    if not shell:
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_AUTHENTICODE_TOOL_UNAVAILABLE")
    script = (
        "$ErrorActionPreference='Stop';"
        "Import-Module Microsoft.PowerShell.Security -ErrorAction Stop;"
        "$s=Get-AuthenticodeSignature -LiteralPath $env:GIDEON_AUTHENTICODE_TARGET;"
        "[pscustomobject]@{Status=[string]$s.Status;Subject=[string]$s.SignerCertificate.Subject;"
        "Thumbprint=[string]$s.SignerCertificate.Thumbprint}|ConvertTo-Json -Compress"
    )
    environment = os.environ.copy()
    # Passing a path after powershell.exe -Command appends it to the command
    # expression instead of reliably populating $args.  Use a process-scoped
    # environment variable so paths containing spaces remain a single literal
    # value and are never interpolated into PowerShell source.
    environment["GIDEON_AUTHENTICODE_TARGET"] = str(path)
    # A builder launched from PowerShell 7 can otherwise pass its PSModulePath
    # into Windows PowerShell 5.1.  Loading the built-in Security module from
    # that mixed module path produces duplicate TypeData errors and makes a
    # valid VideoLAN signature look unverifiable.  Restrict the child process
    # to the built-in module directory next to the selected powershell.exe.
    environment["PSModulePath"] = str(Path(shell).parent / "Modules")
    try:
        completed = subprocess.run(
            [shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            env=environment,
        )
        actual = json.loads(completed.stdout or "{}")
    except Exception as exc:
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_AUTHENTICODE_VERIFY_FAILED") from exc
    expected_thumbprint = _bounded(expected.get("Thumbprint"), 80).replace(" ", "").upper()
    if completed.returncode or _bounded(actual.get("Status"), 40) != "Valid" or _bounded(actual.get("Subject"), 500) != _bounded(expected.get("Subject"), 500) or _bounded(actual.get("Thumbprint"), 80).replace(" ", "").upper() != expected_thumbprint:
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_AUTHENTICODE_MISMATCH")


def _prepare_variant(raw: Mapping[str, Any], *, source_root: Path, stage_root: Path, target_paths: set[str], verify_authenticode: bool) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_VARIANT_OBJECT_REQUIRED")
    variant_id = _require_text(raw.get("VariantId"), code="VLC_INTAKE_VARIANT_ID_INVALID", maximum=160, pattern=SAFE_ID_RE)
    platform_name = _normal_platform(raw.get("Platform"))
    architecture = _normal_arch(raw.get("Architecture"))
    install_raw = raw.get("Install")
    if not isinstance(install_raw, Mapping):
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_INSTALL_OBJECT_REQUIRED")
    mode = _bounded(install_raw.get("Mode"), 80)
    if platform_name == "windows" and mode != "windows-msi":
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_WINDOWS_MSI_REQUIRED")
    if platform_name == "linux" and mode != "apt-local-deb-repository":
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_LINUX_APT_REQUIRED")
    if platform_name == "linux":
        distro = _bounded(raw.get("Distribution"), 40).casefold()
        codename = _bounded(raw.get("Codename"), 80).casefold()
        if distro not in ALLOWED_LINUX_IDS or not SAFE_CODENAME_RE.fullmatch(codename):
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_LINUX_DISTRIBUTION_INVALID")
    else:
        distro = ""
        codename = ""
    closure_raw = raw.get("DependencyClosure")
    if not isinstance(closure_raw, Mapping) or closure_raw.get("Complete") is not True:
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_DEPENDENCY_CLOSURE_INCOMPLETE")
    entries_raw = closure_raw.get("EntryPackages", [])
    if platform_name == "linux":
        if not isinstance(entries_raw, list) or not entries_raw:
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_ENTRY_PACKAGES_REQUIRED")
        entries = [_require_text(value, code="VLC_INTAKE_ENTRY_PACKAGE_INVALID", maximum=80, pattern=SAFE_PACKAGE_RE) for value in entries_raw]
        if "vlc" not in entries or len(entries) != len(set(entries)):
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_VLC_ENTRY_REQUIRED")
        closure_list = closure_raw.get("PackageClosure")
        base_list = closure_raw.get("BaseSystemPackages")
        if not isinstance(closure_list, list) or not closure_list or not isinstance(base_list, list):
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_APT_CLOSURE_DECLARATION_REQUIRED")
        closure_names = [_require_text(value, code="VLC_INTAKE_CLOSURE_PACKAGE_INVALID", maximum=80, pattern=SAFE_PACKAGE_RE) for value in closure_list]
        base_names = [_require_text(value, code="VLC_INTAKE_BASE_PACKAGE_INVALID", maximum=80, pattern=SAFE_PACKAGE_RE) for value in base_list]
        if len(closure_names) != len(set(closure_names)) or len(base_names) != len(set(base_names)) or not set(entries).issubset(closure_names):
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_APT_CLOSURE_DECLARATION_INVALID")
    else:
        entries = []
        closure_names = []
        base_names = []
    files_raw = raw.get("Files")
    if not isinstance(files_raw, list) or not files_raw or len(files_raw) > MAX_FILES:
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_VARIANT_FILES_REQUIRED")
    files: list[dict[str, Any]] = []
    total = 0
    for file_raw in files_raw:
        normalized, source = _copy_verified(source_root, stage_root, file_raw, field="artifact")
        if normalized["Path"] in target_paths:
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_TARGET_PATH_DUPLICATE")
        target_paths.add(normalized["Path"])
        role = _require_text(file_raw.get("Role"), code="VLC_INTAKE_FILE_ROLE_INVALID", maximum=80)
        normalized["Role"] = role
        total += normalized["SizeBytes"]
        if total > MAX_TOTAL_BYTES:
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_VARIANT_TOO_LARGE")
        if platform_name == "windows" and role == "installer":
            if not normalized["Path"].casefold().endswith(".msi"):
                raise VlcOfflineCatalogBuildError("VLC_INTAKE_WINDOWS_MSI_REQUIRED")
            signature = file_raw.get("Authenticode")
            if not isinstance(signature, Mapping):
                raise VlcOfflineCatalogBuildError("VLC_INTAKE_AUTHENTICODE_REQUIRED")
            subject = _require_text(signature.get("Subject"), code="VLC_INTAKE_AUTHENTICODE_SUBJECT_INVALID", maximum=500)
            thumbprint = _bounded(signature.get("Thumbprint"), 80).replace(" ", "").upper()
            if not re.fullmatch(r"[0-9A-F]{40}", thumbprint):
                raise VlcOfflineCatalogBuildError("VLC_INTAKE_AUTHENTICODE_THUMBPRINT_INVALID")
            normalized["Authenticode"] = {"Subject": subject, "Thumbprint": thumbprint}
            if verify_authenticode:
                _optional_authenticode_verify(source, normalized["Authenticode"])
        if platform_name == "linux" and role == "deb":
            normalized["Package"] = _require_text(file_raw.get("Package"), code="VLC_INTAKE_DEB_PACKAGE_INVALID", maximum=80, pattern=SAFE_PACKAGE_RE)
            normalized["Version"] = _require_text(file_raw.get("Version"), code="VLC_INTAKE_DEB_VERSION_INVALID", maximum=160, pattern=SAFE_VERSION_RE)
            deb_arch = _bounded(file_raw.get("DebArchitecture"), 32).casefold()
            if deb_arch not in {DEB_ARCH_BY_ARCH[architecture], "all"}:
                raise VlcOfflineCatalogBuildError("VLC_INTAKE_DEB_ARCH_INVALID")
            normalized["DebArchitecture"] = deb_arch
        files.append(normalized)
    roles = [row["Role"] for row in files]
    if platform_name == "windows":
        if roles.count("installer") != 1:
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_WINDOWS_INSTALLER_REQUIRED")
        install = {"Mode": "windows-msi"}
    else:
        repo_path = str(_safe_relative(install_raw.get("RepositoryPath"), field="repository_path"))
        key_path = str(_safe_relative(install_raw.get("AptSigningKeyPath"), field="apt_signing_key_path"))
        install = {"Mode": "apt-local-deb-repository", "RepositoryPath": repo_path, "AptSigningKeyPath": key_path}
    variant = {
        "VariantId": variant_id, "Platform": platform_name, "Architecture": architecture,
        "Distribution": distro, "Codename": codename, "Install": install,
        "DependencyClosure": {"Complete": True, "EntryPackages": entries}, "Files": files,
    }
    if platform_name == "linux":
        variant["DependencyClosure"].update({"PackageClosure": closure_names, "BaseSystemPackages": base_names})
        _validate_linux_repository(variant, stage_root=stage_root)
    return variant


def build_catalog(intake_path: Path, source_root: Path, *, output_root: Path | None = None, verify_authenticode: bool = False) -> dict[str, Any]:
    """Validate an immutable local intake and optionally build a new catalog.

    ``output_root=None`` performs the same validation without writing output.
    Any actual output is built under a private temporary directory, validated
    once more against the Agent runtime schema, then atomically published only
    if the destination did not already contain a catalog.
    """
    intake = _read_json(Path(intake_path), code="VLC_INTAKE")
    if _bounded(intake.get("Schema"), 100) != INTAKE_SCHEMA:
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_SCHEMA_INVALID")
    version = _require_text(intake.get("CatalogVersion"), code="VLC_INTAKE_CATALOG_VERSION_INVALID", maximum=160)
    vendor_raw = intake.get("Vendor")
    if not isinstance(vendor_raw, Mapping):
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_VENDOR_OBJECT_REQUIRED")
    vendor = {
        "Name": _require_text(vendor_raw.get("Name"), code="VLC_INTAKE_VENDOR_NAME_INVALID", maximum=80),
        "Product": _require_text(vendor_raw.get("Product"), code="VLC_INTAKE_VENDOR_PRODUCT_INVALID", maximum=120),
        "ProjectUrl": _require_text(vendor_raw.get("ProjectUrl"), code="VLC_INTAKE_VENDOR_URL_INVALID", maximum=500),
        "SourceUrl": _require_text(vendor_raw.get("SourceUrl"), code="VLC_INTAKE_VENDOR_URL_INVALID", maximum=500),
    }
    if vendor["Name"] != "VideoLAN" or vendor["Product"] != "VLC media player" or not vendor["ProjectUrl"].startswith("https://") or not vendor["SourceUrl"].startswith("https://"):
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_VENDOR_UNEXPECTED")
    legal_raw = intake.get("Legal")
    if not isinstance(legal_raw, Mapping) or _bounded(legal_raw.get("License"), 80) != "GPL-2.0-or-later":
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_LICENSE_INVALID")
    legal_rows = legal_raw.get("Files")
    if not isinstance(legal_rows, list) or len(legal_rows) != len(REQUIRED_LEGAL_PATHS):
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_LEGAL_FILES_REQUIRED")
    variants_raw = intake.get("Variants")
    if not isinstance(variants_raw, list) or not variants_raw or len(variants_raw) > 128:
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_VARIANTS_REQUIRED")
    source_argument = Path(source_root)
    if source_argument.is_symlink():
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_SOURCE_ROOT_INVALID")
    source_root = source_argument.resolve()
    if not source_root.is_dir():
        raise VlcOfflineCatalogBuildError("VLC_INTAKE_SOURCE_ROOT_INVALID")

    with tempfile.TemporaryDirectory(prefix="gideon-vlc-offline-catalog-") as temporary:
        stage = Path(temporary) / "vlc-offline"
        stage.mkdir(parents=True)
        target_paths: set[str] = set()
        legal_paths: dict[str, Path] = {}
        legal_materials: list[dict[str, Any]] = []
        for row in legal_rows:
            normalized, _source = _copy_verified(source_root, stage, row, field="legal")
            if normalized["Path"] in target_paths:
                raise VlcOfflineCatalogBuildError("VLC_INTAKE_TARGET_PATH_DUPLICATE")
            target_paths.add(normalized["Path"])
            legal_paths[normalized["Path"]] = _resolve_under(stage, normalized["Path"], field="legal_path")
            legal_materials.append(dict(normalized))
        if tuple(sorted(legal_paths)) != tuple(sorted(REQUIRED_LEGAL_PATHS)):
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_LEGAL_FILES_INCOMPLETE")
        _verify_legal_content(legal_paths)
        source_offer_method = _source_offer_method(legal_paths["legal/SOURCE-MATERIALS.json"])
        bundled_raw = legal_raw.get("BundledFiles", [])
        if not isinstance(bundled_raw, list) or len(bundled_raw) > MAX_FILES:
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_BUNDLED_SOURCES_INVALID")
        if source_offer_method == "bundled-source" and not bundled_raw:
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_BUNDLED_SOURCES_REQUIRED")
        if source_offer_method == "written-offer" and bundled_raw:
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_BUNDLED_SOURCES_NOT_ALLOWED")
        bundled_sources: list[dict[str, Any]] = []
        for raw in bundled_raw:
            normalized, _source = _copy_verified(source_root, stage, raw, field="bundled_source")
            path_value = str(normalized["Path"])
            if not path_value.startswith(BUNDLED_SOURCE_PREFIX):
                raise VlcOfflineCatalogBuildError("VLC_INTAKE_BUNDLED_SOURCE_PATH_INVALID")
            if path_value in target_paths:
                raise VlcOfflineCatalogBuildError("VLC_INTAKE_TARGET_PATH_DUPLICATE")
            target_paths.add(path_value)
            role = _require_text(
                raw.get("Role"),
                code="VLC_INTAKE_BUNDLED_SOURCE_ROLE_INVALID",
                maximum=80,
            )
            if role not in BUNDLED_SOURCE_ROLES:
                raise VlcOfflineCatalogBuildError("VLC_INTAKE_BUNDLED_SOURCE_ROLE_INVALID")
            normalized.update({
                "Role": role,
                "SourceId": _require_text(
                    raw.get("SourceId"),
                    code="VLC_INTAKE_BUNDLED_SOURCE_ID_INVALID",
                    maximum=160,
                    pattern=SAFE_ID_RE,
                ),
            })
            bundled_sources.append(normalized)
            legal_materials.append({
                "Path": normalized["Path"],
                "SizeBytes": normalized["SizeBytes"],
                "Sha256": normalized["Sha256"],
            })
        variants: list[dict[str, Any]] = []
        variant_ids: set[str] = set()
        variant_selectors: set[tuple[str, ...]] = set()
        for raw in variants_raw:
            variant = _prepare_variant(raw, source_root=source_root, stage_root=stage, target_paths=target_paths, verify_authenticode=verify_authenticode)
            if variant["VariantId"] in variant_ids:
                raise VlcOfflineCatalogBuildError("VLC_INTAKE_VARIANT_DUPLICATE")
            variant_ids.add(variant["VariantId"])
            selector = (variant["Platform"], variant["Architecture"])
            if variant["Platform"] == "linux":
                selector += (variant["Distribution"], variant["Codename"])
            if selector in variant_selectors:
                raise VlcOfflineCatalogBuildError("VLC_INTAKE_VARIANT_SELECTOR_DUPLICATE")
            variant_selectors.add(selector)
            variants.append(variant)
        total_bytes = (
            sum(int(row["SizeBytes"]) for item in variants for row in item["Files"])
            + sum(int(row["SizeBytes"]) for row in bundled_sources)
        )
        if total_bytes > MAX_TOTAL_BYTES:
            raise VlcOfflineCatalogBuildError("VLC_INTAKE_CATALOG_TOO_LARGE")
        catalog = {
            "Schema": CATALOG_SCHEMA, "CatalogVersion": version, "Vendor": vendor,
            "Legal": {
                "License": "GPL-2.0-or-later",
                "RequiredFiles": list(REQUIRED_LEGAL_PATHS) + [row["Path"] for row in bundled_sources],
                "Materials": legal_materials,
                "BundledSources": bundled_sources,
            },
            "Variants": variants,
        }
        source_ids_by_variant = _validate_source_materials(
            legal_paths["legal/SOURCE-MATERIALS.json"],
            catalog=catalog,
            bundled_sources=bundled_sources,
            stage_root=stage,
        )
        for variant in catalog["Variants"]:
            variant["CorrespondingSourceIds"] = source_ids_by_variant[str(variant["VariantId"])]
        # The Agent owns the canonical schema.  This protects the hand-off
        # from an otherwise innocuous intake-tool change that runtime rejects.
        _load_runtime_validator()(catalog)
        catalog_path = stage / "catalog.json"
        catalog_path.write_text(json.dumps(catalog, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")
        result = {
            "Schema": "gideon-vlc-offline-intake-result/v1", "Status": "VALID",
            "CatalogVersion": version, "Variants": [{
                "VariantId": item["VariantId"], "Platform": item["Platform"], "Architecture": item["Architecture"],
                "Distribution": item["Distribution"], "Codename": item["Codename"], "Files": len(item["Files"]),
                "Bytes": sum(int(row["SizeBytes"]) for row in item["Files"]),
            } for item in variants],
            "NetworkDownloads": False, "CatalogSha256": _sha256_file(catalog_path),
        }
        if output_root is not None:
            output_argument = Path(output_root)
            if output_argument.is_symlink():
                raise VlcOfflineCatalogBuildError("VLC_INTAKE_OUTPUT_SYMLINK_REFUSED")
            output = output_argument.resolve()
            if output.exists() and (not output.is_dir() or output.is_symlink() or any(output.iterdir())):
                raise VlcOfflineCatalogBuildError("VLC_INTAKE_OUTPUT_NOT_EMPTY")
            output.parent.mkdir(parents=True, exist_ok=True)
            if output.exists():
                output.rmdir()
            try:
                os.replace(stage, output)
            except OSError:
                shutil.copytree(stage, output)
            result["OutputRoot"] = str(output)
        return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Construye un catálogo VLC offline GIDEON desde material local revisado")
    parser.add_argument("--intake", required=True, type=Path, help="JSON intake local e inmutable")
    parser.add_argument("--source-root", required=True, type=Path, help="Raíz local que contiene los artefactos declarados")
    parser.add_argument("--output-root", type=Path, help="Nuevo directorio third_party/vlc-offline a crear")
    parser.add_argument("--check", action="store_true", help="Validar solamente; no crear salida")
    parser.add_argument("--verify-windows-authenticode", action="store_true", help="Verificar Authenticode de MSI durante la intake (requiere Windows)")
    args = parser.parse_args(argv)
    if args.check and args.output_root:
        parser.error("--check y --output-root son excluyentes")
    if not args.check and not args.output_root:
        parser.error("Use --check o indique --output-root")
    try:
        result = build_catalog(args.intake, args.source_root, output_root=None if args.check else args.output_root,
                               verify_authenticode=bool(args.verify_windows_authenticode))
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    except VlcOfflineCatalogBuildError as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
