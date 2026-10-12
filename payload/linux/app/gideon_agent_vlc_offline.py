from __future__ import annotations

"""Verified, offline-only VLC catalog support for GIDEON Agent installers.

This module intentionally does *not* download software, add package
repositories, or start a player while the Agent is running.  A release builder
may copy a reviewed, platform-specific VLC kit into an Agent installer and
sign the resulting catalog with the existing GIDEON Ed25519 release key.  At the
endpoint, installation is a separately authorised, auditable action:

* Windows validates the pinned VideoLAN Authenticode identity before starting
  a fixed silent installer command.
* Debian/Ubuntu/Raspberry Pi use only an embedded local APT repository.  APT
  is invoked with a temporary source list and ``--no-download`` so it cannot
  contact public repositories.
* The Agent service never calls :class:`OfflineVlcInstaller` by itself.  A
  short-lived GIDEON-signed authorisation and an explicit GPL acknowledgement are
  required for every install attempt.

The catalog is deliberately an import/publish boundary: vendor binaries and
source materials are supplied by a separate reviewed intake process.  This
source tree contains no pretend hashes and no unverified VLC binaries.
"""

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Iterable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from gideon_agent_bootstrap import PRIVATE_FILE_MODE, atomic_json, enforce_path_mode
from gideon_agent_security import sha256_file, sign_file, verify_file


OFFLINE_CATALOG_SCHEMA = "gideon-vlc-offline-catalog/v1"
OFFLINE_PROFILE_SCHEMA = "gideon-vlc-offline-profile/v1"
OFFLINE_AUTHORIZATION_SCHEMA = "gideon-vlc-offline-install-authorization/v1"
SOURCE_COMPANION_SCHEMA = "gideon-vlc-source-companion/v1"
SOURCE_COMPANION_KEY_ID = "gideon-agent-ed25519-1"
SOURCE_COMPANION_SIGNATURE_SCHEME = "ed25519-domain-sha256-v1"
SOURCE_COMPANION_SIGNATURE_DOMAIN = b"GIDEON-SOURCE-COMPANION-SHA256-V1\x00"
CATALOG_DIR_RELATIVE = PurePosixPath("third_party/vlc-offline")
CATALOG_NAME = "catalog.json"
CATALOG_SIGNATURE_NAME = "catalog.sig"
PROFILE_NAME = "gideon-vlc-offline-profile.json"
SOURCE_BASELINE_SCHEMA = "gideon-vlc-source-baseline/v1"
SOURCE_BASELINE_NAME = "VLC-SOURCE-BASELINE.json"
SOURCE_MATERIALS_PATH = "legal/SOURCE-MATERIALS.json"
SOURCE_OFFER_PATH = "legal/SOURCE-OFFER.md"
MAX_CATALOG_BYTES = 2 * 1024 * 1024
MAX_CATALOG_FILES = 4_096
MAX_ARTIFACT_BYTES = 12 * 1024 * 1024 * 1024
MAX_CATALOG_TOTAL_BYTES = 32 * 1024 * 1024 * 1024
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,159}$")
_SAFE_PACKAGE = re.compile(r"^[a-z0-9][a-z0-9+.-]{0,79}$")
_SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,159}$")
_SAFE_ARTIFACT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,239}\.zip$")
_ALLOWED_LINUX_IDS = frozenset({"debian", "ubuntu", "raspbian"})
REQUIRED_LEGAL_FILES = (
    "legal/GPL-2.0.txt",
    "legal/VLC-NOTICE.md",
    "legal/SOURCE-OFFER.md",
    "legal/SOURCE-MATERIALS.json",
)
_BUNDLED_SOURCE_PREFIX = "legal/sources/"
_BUNDLED_SOURCE_ROLES = frozenset({
    "source-archive", "source-signature", "source-checksum",
    "build-scripts", "build-instructions", "source-notice",
})


class OfflineVlcCatalogError(RuntimeError):
    """The offline kit is missing, untrusted, incompatible, or incomplete."""


class OfflineVlcAuthorizationError(OfflineVlcCatalogError):
    """The explicit, signed installation authorisation was invalid."""


def _bounded(value: Any, maximum: int = 240) -> str:
    return str(value or "").replace("\x00", " ").strip()[:maximum]


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def _normal_platform(value: str | None = None) -> str:
    raw = _bounded(value or ("windows" if os.name == "nt" else sys.platform), 40).casefold()
    if raw.startswith("win"):
        return "windows"
    if raw.startswith("linux"):
        return "linux"
    if raw.startswith("darwin") or raw.startswith("mac"):
        return "darwin"
    return raw


def _normal_arch(value: str | None = None) -> str:
    raw = _bounded(value or platform.machine(), 40).casefold()
    aliases = {
        "amd64": "x86_64", "x64": "x86_64", "x86-64": "x86_64",
        "aarch64": "arm64", "armv8": "arm64", "armv8l": "arm64",
        "armhf": "armv7l", "armv7": "armv7l", "armv7l": "armv7l",
    }
    return aliases.get(raw, raw)


def _safe_relative(value: Any, *, name: str = "path") -> PurePosixPath:
    text = _bounded(value, 500).replace("\\", "/")
    path = PurePosixPath(text)
    if not text or path.is_absolute() or ".." in path.parts or any(part in {"", "."} for part in path.parts):
        raise OfflineVlcCatalogError(f"VLC_OFFLINE_{name.upper()}_UNSAFE")
    return path


def _resolve_under(root: Path, relative: Any, *, name: str = "path") -> Path:
    rel = _safe_relative(relative, name=name)
    target = (Path(root).resolve() / Path(*rel.parts)).resolve()
    try:
        target.relative_to(Path(root).resolve())
    except ValueError as exc:
        raise OfflineVlcCatalogError(f"VLC_OFFLINE_{name.upper()}_ESCAPE") from exc
    return target


def _json_file(path: Path, *, code: str) -> dict[str, Any]:
    try:
        raw = Path(path).read_bytes()
        if len(raw) > MAX_CATALOG_BYTES:
            raise OfflineVlcCatalogError(f"{code}_TOO_LARGE")
        value = json.loads(raw.decode("utf-8-sig"))
    except OfflineVlcCatalogError:
        raise
    except Exception as exc:
        raise OfflineVlcCatalogError(f"{code}_INVALID") from exc
    if not isinstance(value, Mapping):
        raise OfflineVlcCatalogError(f"{code}_OBJECT_REQUIRED")
    return dict(value)


def _require_text(value: Any, *, code: str, maximum: int = 240, pattern: re.Pattern[str] | None = None) -> str:
    text = _bounded(value, maximum)
    if not text or (pattern is not None and not pattern.fullmatch(text)):
        raise OfflineVlcCatalogError(code)
    return text


def _require_sha256(value: Any, *, code: str) -> str:
    digest = _bounded(value, 80).casefold()
    if not _SHA256.fullmatch(digest):
        raise OfflineVlcCatalogError(code)
    return digest


def _positive_size(value: Any, *, code: str) -> int:
    try:
        size = int(value)
    except (TypeError, ValueError) as exc:
        raise OfflineVlcCatalogError(code) from exc
    if size <= 0 or size > MAX_ARTIFACT_BYTES:
        raise OfflineVlcCatalogError(code)
    return size


def catalog_source_root(app_root: Path) -> Path:
    return Path(app_root).resolve() / Path(*CATALOG_DIR_RELATIVE.parts)


def _legal_required(catalog: Mapping[str, Any]) -> tuple[str, ...]:
    legal = catalog.get("Legal")
    if not isinstance(legal, Mapping):
        raise OfflineVlcCatalogError("VLC_OFFLINE_LEGAL_OBJECT_REQUIRED")
    license_id = _bounded(legal.get("License"), 80)
    if license_id != "GPL-2.0-or-later":
        raise OfflineVlcCatalogError("VLC_OFFLINE_LICENSE_INVALID")
    rows = legal.get("RequiredFiles")
    if not isinstance(rows, list):
        raise OfflineVlcCatalogError("VLC_OFFLINE_LEGAL_FILES_REQUIRED")
    required = tuple(str(_safe_relative(item, name="legal_file")) for item in rows)
    if len(required) != len(set(required)):
        raise OfflineVlcCatalogError("VLC_OFFLINE_LEGAL_FILES_INCOMPLETE")
    required_set = set(required)
    if not set(REQUIRED_LEGAL_FILES).issubset(required_set):
        raise OfflineVlcCatalogError("VLC_OFFLINE_LEGAL_FILES_INCOMPLETE")
    if any(path not in REQUIRED_LEGAL_FILES and not path.startswith(_BUNDLED_SOURCE_PREFIX) for path in required):
        raise OfflineVlcCatalogError("VLC_OFFLINE_BUNDLED_SOURCE_PATH_INVALID")
    return required


def _legal_bundled_sources(catalog: Mapping[str, Any], required: tuple[str, ...]) -> list[dict[str, Any]]:
    legal = catalog.get("Legal") if isinstance(catalog.get("Legal"), Mapping) else {}
    rows = legal.get("BundledSources", [])
    if not isinstance(rows, list):
        raise OfflineVlcCatalogError("VLC_OFFLINE_BUNDLED_SOURCES_INVALID")
    expected = {path for path in required if path.startswith(_BUNDLED_SOURCE_PREFIX)}
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in rows:
        if not isinstance(raw, Mapping):
            raise OfflineVlcCatalogError("VLC_OFFLINE_BUNDLED_SOURCE_OBJECT_REQUIRED")
        path = str(_safe_relative(raw.get("Path"), name="bundled_source"))
        if not path.startswith(_BUNDLED_SOURCE_PREFIX) or path in seen:
            raise OfflineVlcCatalogError("VLC_OFFLINE_BUNDLED_SOURCE_PATH_INVALID")
        seen.add(path)
        role = _require_text(raw.get("Role"), code="VLC_OFFLINE_BUNDLED_SOURCE_ROLE_INVALID", maximum=80)
        if role not in _BUNDLED_SOURCE_ROLES:
            raise OfflineVlcCatalogError("VLC_OFFLINE_BUNDLED_SOURCE_ROLE_INVALID")
        normalized.append({
            "Path": path,
            "Role": role,
            "SourceId": _require_text(raw.get("SourceId"), code="VLC_OFFLINE_BUNDLED_SOURCE_ID_INVALID", maximum=160, pattern=_SAFE_ID),
            "SizeBytes": _positive_size(raw.get("SizeBytes"), code="VLC_OFFLINE_BUNDLED_SOURCE_SIZE_INVALID"),
            "Sha256": _require_sha256(raw.get("Sha256"), code="VLC_OFFLINE_BUNDLED_SOURCE_HASH_INVALID"),
        })
    if seen != expected:
        raise OfflineVlcCatalogError("VLC_OFFLINE_BUNDLED_SOURCES_INCOMPLETE")
    return normalized


def _legal_materials(catalog: Mapping[str, Any], required: tuple[str, ...]) -> list[dict[str, Any]]:
    """Bind every shipped legal/source file to the signed catalog."""
    legal = catalog.get("Legal") if isinstance(catalog.get("Legal"), Mapping) else {}
    rows = legal.get("Materials")
    if not isinstance(rows, list):
        raise OfflineVlcCatalogError("VLC_OFFLINE_LEGAL_MATERIALS_REQUIRED")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in rows:
        if not isinstance(raw, Mapping):
            raise OfflineVlcCatalogError("VLC_OFFLINE_LEGAL_MATERIAL_OBJECT_REQUIRED")
        path = str(_safe_relative(raw.get("Path"), name="legal_material"))
        if path in seen:
            raise OfflineVlcCatalogError("VLC_OFFLINE_LEGAL_MATERIAL_DUPLICATE")
        seen.add(path)
        normalized.append({
            "Path": path,
            "SizeBytes": _positive_size(raw.get("SizeBytes"), code="VLC_OFFLINE_LEGAL_MATERIAL_SIZE_INVALID"),
            "Sha256": _require_sha256(raw.get("Sha256"), code="VLC_OFFLINE_LEGAL_MATERIAL_HASH_INVALID"),
        })
    if seen != set(required):
        raise OfflineVlcCatalogError("VLC_OFFLINE_LEGAL_MATERIALS_INCOMPLETE")
    return normalized


def _source_companion_reference(
    legal: Mapping[str, Any], *, catalog_version: str,
) -> dict[str, Any] | None:
    """Validate the immutable signed archive that carries detached GPL source.

    The reference lives inside the signed runtime catalog.  Consequently an
    endpoint or WebAdmin can authenticate the companion archive without
    trusting its filename or storage location.
    """
    raw = legal.get("SourceCompanion")
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_COMPANION_OBJECT_REQUIRED")
    if _bounded(raw.get("Schema"), 100) != SOURCE_COMPANION_SCHEMA:
        raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_COMPANION_SCHEMA_INVALID")
    artifact_name = _require_text(
        raw.get("ArtifactName"),
        code="VLC_OFFLINE_SOURCE_COMPANION_NAME_INVALID",
        maximum=244,
        pattern=_SAFE_ARTIFACT_NAME,
    )
    if PurePosixPath(artifact_name).name != artifact_name:
        raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_COMPANION_NAME_INVALID")
    companion_version = _require_text(
        raw.get("CatalogVersion"),
        code="VLC_OFFLINE_SOURCE_COMPANION_VERSION_INVALID",
        maximum=160,
    )
    if companion_version != catalog_version:
        raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_COMPANION_VERSION_MISMATCH")
    try:
        size = int(raw.get("SizeBytes"))
    except (TypeError, ValueError) as exc:
        raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_COMPANION_SIZE_INVALID") from exc
    if size <= 0 or size > MAX_CATALOG_TOTAL_BYTES:
        raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_COMPANION_SIZE_INVALID")
    signature = _require_text(
        raw.get("Signature"), code="VLC_OFFLINE_SOURCE_COMPANION_SIGNATURE_INVALID", maximum=512,
    )
    try:
        decoded_signature = base64.b64decode(signature, validate=True)
    except Exception as exc:
        raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_COMPANION_SIGNATURE_INVALID") from exc
    if len(decoded_signature) != 64:
        raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_COMPANION_SIGNATURE_INVALID")
    key_id = _require_text(
        raw.get("KeyId"), code="VLC_OFFLINE_SOURCE_COMPANION_KEY_INVALID", maximum=120,
    )
    if key_id != SOURCE_COMPANION_KEY_ID:
        raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_COMPANION_KEY_INVALID")
    signature_scheme = _require_text(
        raw.get("SignatureScheme"),
        code="VLC_OFFLINE_SOURCE_COMPANION_SIGNATURE_SCHEME_INVALID",
        maximum=120,
    )
    if signature_scheme != SOURCE_COMPANION_SIGNATURE_SCHEME:
        raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_COMPANION_SIGNATURE_SCHEME_INVALID")
    source_rows = raw.get("SourceIds")
    if not isinstance(source_rows, list) or not source_rows:
        raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_COMPANION_SOURCE_IDS_INVALID")
    source_ids = [
        _require_text(
            item, code="VLC_OFFLINE_SOURCE_COMPANION_SOURCE_ID_INVALID", maximum=160, pattern=_SAFE_ID,
        )
        for item in source_rows
    ]
    if len(source_ids) != len(set(source_ids)):
        raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_COMPANION_SOURCE_IDS_DUPLICATE")
    return {
        "Schema": SOURCE_COMPANION_SCHEMA,
        "ArtifactName": artifact_name,
        "CatalogVersion": companion_version,
        "SourceIds": sorted(source_ids),
        "SizeBytes": size,
        "Sha256": _require_sha256(
            raw.get("Sha256"), code="VLC_OFFLINE_SOURCE_COMPANION_HASH_INVALID",
        ),
        "Signature": signature,
        "SignatureScheme": signature_scheme,
        "KeyId": key_id,
    }


def _validate_vendor(catalog: Mapping[str, Any]) -> dict[str, str]:
    vendor = catalog.get("Vendor")
    if not isinstance(vendor, Mapping):
        raise OfflineVlcCatalogError("VLC_OFFLINE_VENDOR_OBJECT_REQUIRED")
    name = _require_text(vendor.get("Name"), code="VLC_OFFLINE_VENDOR_NAME_INVALID", maximum=80)
    product = _require_text(vendor.get("Product"), code="VLC_OFFLINE_VENDOR_PRODUCT_INVALID", maximum=120)
    project_url = _require_text(vendor.get("ProjectUrl"), code="VLC_OFFLINE_VENDOR_URL_INVALID", maximum=500)
    source_url = _require_text(vendor.get("SourceUrl"), code="VLC_OFFLINE_SOURCE_URL_INVALID", maximum=500)
    if name != "VideoLAN" or product != "VLC media player":
        raise OfflineVlcCatalogError("VLC_OFFLINE_VENDOR_UNEXPECTED")
    if not project_url.startswith("https://") or not source_url.startswith("https://"):
        raise OfflineVlcCatalogError("VLC_OFFLINE_VENDOR_URL_INVALID")
    return {"Name": name, "Product": product, "ProjectUrl": project_url, "SourceUrl": source_url}


def _validate_variant(row: Mapping[str, Any]) -> dict[str, Any]:
    variant_id = _require_text(row.get("VariantId"), code="VLC_OFFLINE_VARIANT_ID_INVALID", maximum=160, pattern=_SAFE_ID)
    platform_name = _normal_platform(_require_text(row.get("Platform"), code="VLC_OFFLINE_VARIANT_PLATFORM_INVALID", maximum=32))
    architecture = _normal_arch(_require_text(row.get("Architecture"), code="VLC_OFFLINE_VARIANT_ARCH_INVALID", maximum=32))
    if platform_name not in {"windows", "linux"} or architecture not in {"x86_64", "arm64", "armv7l"}:
        raise OfflineVlcCatalogError("VLC_OFFLINE_VARIANT_UNSUPPORTED")
    install = row.get("Install")
    if not isinstance(install, Mapping):
        raise OfflineVlcCatalogError("VLC_OFFLINE_INSTALL_OBJECT_REQUIRED")
    mode = _bounded(install.get("Mode"), 80)
    if platform_name == "windows" and mode not in {"windows-nsis-exe", "windows-msi"}:
        raise OfflineVlcCatalogError("VLC_OFFLINE_WINDOWS_MODE_INVALID")
    if platform_name == "linux" and mode != "apt-local-deb-repository":
        raise OfflineVlcCatalogError("VLC_OFFLINE_LINUX_MODE_INVALID")
    if platform_name == "linux":
        distro = _bounded(row.get("Distribution"), 40).casefold()
        codename = _bounded(row.get("Codename"), 80).casefold()
        if distro not in _ALLOWED_LINUX_IDS or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,79}", codename):
            raise OfflineVlcCatalogError("VLC_OFFLINE_LINUX_DISTRIBUTION_INVALID")
        repo_path = str(_safe_relative(install.get("RepositoryPath"), name="repository"))
        signing_key_path = str(_safe_relative(install.get("AptSigningKeyPath"), name="apt_signing_key"))
    else:
        distro = ""
        codename = ""
        repo_path = ""
        signing_key_path = ""
    dependency = row.get("DependencyClosure")
    if not isinstance(dependency, Mapping) or dependency.get("Complete") is not True:
        raise OfflineVlcCatalogError("VLC_OFFLINE_DEPENDENCY_CLOSURE_INCOMPLETE")
    entry_packages = dependency.get("EntryPackages")
    if platform_name == "linux":
        if not isinstance(entry_packages, list) or not entry_packages:
            raise OfflineVlcCatalogError("VLC_OFFLINE_ENTRY_PACKAGES_REQUIRED")
        entries = [_require_text(item, code="VLC_OFFLINE_ENTRY_PACKAGE_INVALID", maximum=80, pattern=_SAFE_PACKAGE) for item in entry_packages]
        if "vlc" not in entries:
            raise OfflineVlcCatalogError("VLC_OFFLINE_VLC_ENTRY_REQUIRED")
    else:
        entries = []
    source_ids_raw = row.get("CorrespondingSourceIds", [])
    if not isinstance(source_ids_raw, list) or ("CorrespondingSourceIds" in row and not source_ids_raw):
        raise OfflineVlcCatalogError("VLC_OFFLINE_VARIANT_SOURCE_IDS_INVALID")
    source_ids = [
        _require_text(item, code="VLC_OFFLINE_VARIANT_SOURCE_ID_INVALID", maximum=160, pattern=_SAFE_ID)
        for item in source_ids_raw
    ]
    if len(source_ids) != len(set(source_ids)):
        raise OfflineVlcCatalogError("VLC_OFFLINE_VARIANT_SOURCE_IDS_DUPLICATE")
    files = row.get("Files")
    if not isinstance(files, list) or not files or len(files) > MAX_CATALOG_FILES:
        raise OfflineVlcCatalogError("VLC_OFFLINE_VARIANT_FILES_REQUIRED")
    file_rows: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    total = 0
    for item in files:
        if not isinstance(item, Mapping):
            raise OfflineVlcCatalogError("VLC_OFFLINE_FILE_OBJECT_REQUIRED")
        rel = str(_safe_relative(item.get("Path"), name="artifact"))
        if rel in seen_paths:
            raise OfflineVlcCatalogError("VLC_OFFLINE_FILE_DUPLICATE")
        seen_paths.add(rel)
        size = _positive_size(item.get("SizeBytes"), code="VLC_OFFLINE_FILE_SIZE_INVALID")
        total += size
        if total > MAX_CATALOG_TOTAL_BYTES:
            raise OfflineVlcCatalogError("VLC_OFFLINE_VARIANT_TOO_LARGE")
        role = _require_text(item.get("Role"), code="VLC_OFFLINE_FILE_ROLE_INVALID", maximum=80)
        digest = _require_sha256(item.get("Sha256"), code="VLC_OFFLINE_FILE_HASH_INVALID")
        normalized: dict[str, Any] = {"Path": rel, "SizeBytes": size, "Role": role, "Sha256": digest}
        if platform_name == "windows" and role == "installer":
            signature = item.get("Authenticode")
            if not isinstance(signature, Mapping):
                raise OfflineVlcCatalogError("VLC_OFFLINE_AUTHENTICODE_REQUIRED")
            subject = _require_text(signature.get("Subject"), code="VLC_OFFLINE_AUTHENTICODE_SUBJECT_INVALID", maximum=500)
            thumbprint = _bounded(signature.get("Thumbprint"), 80).replace(" ", "").upper()
            if not re.fullmatch(r"[0-9A-F]{40}", thumbprint):
                raise OfflineVlcCatalogError("VLC_OFFLINE_AUTHENTICODE_THUMBPRINT_INVALID")
            normalized["Authenticode"] = {"Subject": subject, "Thumbprint": thumbprint}
        if platform_name == "linux" and role == "deb":
            normalized["Package"] = _require_text(item.get("Package"), code="VLC_OFFLINE_DEB_PACKAGE_INVALID", maximum=80, pattern=_SAFE_PACKAGE)
            normalized["Version"] = _require_text(item.get("Version"), code="VLC_OFFLINE_DEB_VERSION_INVALID", maximum=160, pattern=_SAFE_VERSION)
            deb_arch = _bounded(item.get("DebArchitecture"), 32).casefold()
            expected_arch = {"x86_64": "amd64", "arm64": "arm64", "armv7l": "armhf"}[architecture]
            if deb_arch not in {expected_arch, "all"}:
                raise OfflineVlcCatalogError("VLC_OFFLINE_DEB_ARCH_INVALID")
            normalized["DebArchitecture"] = deb_arch
        file_rows.append(normalized)
    roles = {str(item["Role"]) for item in file_rows}
    if platform_name == "windows":
        installers = [item for item in file_rows if item["Role"] == "installer"]
        if len(installers) != 1 or not str(installers[0]["Path"]).casefold().endswith((".exe", ".msi")):
            raise OfflineVlcCatalogError("VLC_OFFLINE_WINDOWS_INSTALLER_REQUIRED")
    else:
        # The endpoint must consume an actual, signed, *local* APT repository.
        # GIDEON's catalog signature protects the kit intake, while APT verifies the
        # embedded repository metadata with this embedded public key.  Do not
        # use ``trusted=yes`` here: doing so would turn a malformed repository
        # into a trusted package source at the endpoint.
        if not {"deb", "apt-packages-index", "apt-key"}.issubset(roles):
            raise OfflineVlcCatalogError("VLC_OFFLINE_APT_REPOSITORY_INCOMPLETE")
        repo_prefix = repo_path + "/"
        if any(not str(item["Path"]).startswith(repo_prefix) for item in file_rows):
            raise OfflineVlcCatalogError("VLC_OFFLINE_APT_FILE_OUTSIDE_REPOSITORY")
        indexes = [item for item in file_rows if item["Role"] == "apt-packages-index"]
        inrelease = [item for item in file_rows if item["Role"] == "apt-inrelease"]
        releases = [item for item in file_rows if item["Role"] == "apt-release"]
        release_signatures = [item for item in file_rows if item["Role"] == "apt-release-signature"]
        keys = [item for item in file_rows if item["Role"] == "apt-key"]
        debs = [item for item in file_rows if item["Role"] == "deb"]
        if len(keys) != 1 or str(keys[0]["Path"]) != signing_key_path:
            raise OfflineVlcCatalogError("VLC_OFFLINE_APT_SIGNING_KEY_INVALID")
        allowed_indexes = {
            f"{repo_path}/Packages",
            f"{repo_path}/Packages.gz",
            f"{repo_path}/Packages.xz",
        }
        if len(indexes) != 1 or str(indexes[0]["Path"]) not in allowed_indexes:
            raise OfflineVlcCatalogError("VLC_OFFLINE_APT_FLAT_REPOSITORY_LAYOUT_REQUIRED")
        if inrelease:
            if len(inrelease) != 1 or releases or release_signatures:
                raise OfflineVlcCatalogError("VLC_OFFLINE_APT_RELEASE_SIGNATURE_INVALID")
            if str(inrelease[0]["Path"]) != f"{repo_path}/InRelease":
                raise OfflineVlcCatalogError("VLC_OFFLINE_APT_FLAT_REPOSITORY_LAYOUT_REQUIRED")
        elif len(releases) != 1 or len(release_signatures) != 1:
            raise OfflineVlcCatalogError("VLC_OFFLINE_APT_RELEASE_SIGNATURE_REQUIRED")
        elif (
            str(releases[0]["Path"]) != f"{repo_path}/Release"
            or str(release_signatures[0]["Path"]) != f"{repo_path}/Release.gpg"
        ):
            raise OfflineVlcCatalogError("VLC_OFFLINE_APT_FLAT_REPOSITORY_LAYOUT_REQUIRED")
        if not debs:
            raise OfflineVlcCatalogError("VLC_OFFLINE_APT_REPOSITORY_EMPTY")
        packaged_names = {str(item.get("Package") or "") for item in debs}
        if not set(entries).issubset(packaged_names):
            raise OfflineVlcCatalogError("VLC_OFFLINE_ENTRY_PACKAGE_NOT_BUNDLED")
        normalized_install = dict(install)
        normalized_install["RepositoryPath"] = repo_path
        normalized_install["AptSigningKeyPath"] = signing_key_path
        install = normalized_install
    normalized_variant = {
        "VariantId": variant_id,
        "Platform": platform_name,
        "Architecture": architecture,
        "Distribution": distro,
        "Codename": codename,
        "Install": dict(install),
        "DependencyClosure": {"Complete": True, "EntryPackages": entries},
        "Files": file_rows,
    }
    if source_ids:
        normalized_variant["CorrespondingSourceIds"] = sorted(source_ids)
    return normalized_variant


def validate_catalog(catalog: Mapping[str, Any]) -> dict[str, Any]:
    if _bounded(catalog.get("Schema"), 80) != OFFLINE_CATALOG_SCHEMA:
        raise OfflineVlcCatalogError("VLC_OFFLINE_CATALOG_SCHEMA_INVALID")
    version = _require_text(catalog.get("CatalogVersion"), code="VLC_OFFLINE_CATALOG_VERSION_INVALID", maximum=160)
    vendor = _validate_vendor(catalog)
    legal_object = catalog.get("Legal")
    if not isinstance(legal_object, Mapping):
        raise OfflineVlcCatalogError("VLC_OFFLINE_LEGAL_OBJECT_REQUIRED")
    legal = _legal_required(catalog)
    bundled_sources = _legal_bundled_sources(catalog, legal)
    legal_materials = _legal_materials(catalog, legal)
    source_companion = _source_companion_reference(legal_object, catalog_version=version)
    if source_companion is not None and (
        bundled_sources or any(path.startswith(_BUNDLED_SOURCE_PREFIX) for path in legal)
    ):
        raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_COMPANION_MIXED_DELIVERY")
    materials_by_path = {row["Path"]: row for row in legal_materials}
    for source in bundled_sources:
        material = materials_by_path.get(source["Path"])
        if material is None or material["SizeBytes"] != source["SizeBytes"] or material["Sha256"] != source["Sha256"]:
            raise OfflineVlcCatalogError("VLC_OFFLINE_BUNDLED_SOURCE_MATERIAL_MISMATCH")
    variants_raw = catalog.get("Variants")
    if not isinstance(variants_raw, list) or not variants_raw or len(variants_raw) > 128:
        raise OfflineVlcCatalogError("VLC_OFFLINE_VARIANTS_REQUIRED")
    variants: list[dict[str, Any]] = []
    seen: set[str] = set()
    selectors: set[tuple[str, ...]] = set()
    for item in variants_raw:
        if not isinstance(item, Mapping):
            raise OfflineVlcCatalogError("VLC_OFFLINE_VARIANT_OBJECT_REQUIRED")
        variant = _validate_variant(item)
        if variant["VariantId"] in seen:
            raise OfflineVlcCatalogError("VLC_OFFLINE_VARIANT_DUPLICATE")
        seen.add(variant["VariantId"])
        selector = (variant["Platform"], variant["Architecture"])
        if variant["Platform"] == "linux":
            selector += (variant["Distribution"], variant["Codename"])
        if selector in selectors:
            raise OfflineVlcCatalogError("VLC_OFFLINE_VARIANT_SELECTOR_DUPLICATE")
        selectors.add(selector)
        variants.append(variant)
    if source_companion is not None:
        declared_source_ids = {
            str(source_id)
            for variant in variants
            for source_id in (variant.get("CorrespondingSourceIds") or [])
        }
        if not declared_source_ids or declared_source_ids != set(source_companion["SourceIds"]):
            raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_COMPANION_SOURCE_IDS_MISMATCH")
    normalized = {
        "Schema": OFFLINE_CATALOG_SCHEMA,
        "CatalogVersion": version,
        "Vendor": vendor,
        "Legal": {
            "License": "GPL-2.0-or-later",
            "RequiredFiles": list(legal),
            "Materials": legal_materials,
            "BundledSources": bundled_sources,
        },
        "Variants": variants,
    }
    if source_companion is not None:
        normalized["Legal"]["SourceCompanion"] = source_companion
    return normalized


def _validate_source_files(root: Path, catalog: Mapping[str, Any]) -> None:
    total = 0
    materials = {
        str(row["Path"]): row for row in (catalog.get("Legal", {}).get("Materials", []) or [])
        if isinstance(row, Mapping)
    }
    for legal in catalog["Legal"]["RequiredFiles"]:
        path = _resolve_under(root, legal, name="legal_file")
        if not path.is_file() or path.is_symlink() or path.stat().st_size <= 0:
            raise OfflineVlcCatalogError("VLC_OFFLINE_LEGAL_FILE_MISSING")
        material = materials.get(str(legal))
        if material is None:
            raise OfflineVlcCatalogError("VLC_OFFLINE_LEGAL_MATERIALS_INCOMPLETE")
        if path.stat().st_size != int(material["SizeBytes"]):
            raise OfflineVlcCatalogError("VLC_OFFLINE_LEGAL_MATERIAL_SIZE_MISMATCH")
        if sha256_file(path).casefold() != str(material["Sha256"]).casefold():
            raise OfflineVlcCatalogError("VLC_OFFLINE_LEGAL_MATERIAL_HASH_MISMATCH")
        total += path.stat().st_size
        if total > MAX_CATALOG_TOTAL_BYTES:
            raise OfflineVlcCatalogError("VLC_OFFLINE_CATALOG_TOO_LARGE")
    for variant in catalog["Variants"]:
        for row in variant["Files"]:
            path = _resolve_under(root, row["Path"], name="artifact")
            if not path.is_file() or path.is_symlink():
                raise OfflineVlcCatalogError("VLC_OFFLINE_ARTIFACT_MISSING")
            stat = path.stat()
            if stat.st_size != int(row["SizeBytes"]):
                raise OfflineVlcCatalogError("VLC_OFFLINE_ARTIFACT_SIZE_MISMATCH")
            total += stat.st_size
            if total > MAX_CATALOG_TOTAL_BYTES:
                raise OfflineVlcCatalogError("VLC_OFFLINE_CATALOG_TOO_LARGE")
            if sha256_file(path).casefold() != str(row["Sha256"]).casefold():
                raise OfflineVlcCatalogError("VLC_OFFLINE_ARTIFACT_HASH_MISMATCH")


def _source_expected_file_paths(catalog: Mapping[str, Any]) -> set[str]:
    """Return the exact reviewed source-tree file set for one catalog."""
    expected = {CATALOG_NAME}

    def add(relative: Any) -> None:
        path = str(_safe_relative(relative, name="source_file"))
        if path in expected:
            raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_FILE_PATH_DUPLICATE")
        expected.add(path)

    for relative in catalog["Legal"]["RequiredFiles"]:
        add(relative)
    for variant in catalog["Variants"]:
        for row in variant["Files"]:
            add(row["Path"])
    return expected


def _load_reviewed_source_catalog(app_root: Path) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    """Load the cloud-reviewed source catalog anchored by the core baseline.

    The large source closure is deliberately not part of an Agent core package.
    The small root baseline is part of the immutable core manifest, so it pins
    the otherwise mutable source catalog before any selected vendor byte is
    copied into a signed component.
    """
    root = Path(app_root).resolve()
    source = catalog_source_root(root)
    try:
        source.resolve().relative_to(root)
    except ValueError as exc:
        raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_ROOT_ESCAPE") from exc
    if source.is_symlink():
        raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_ROOT_INVALID")
    catalog_path = source / CATALOG_NAME
    if not catalog_path.is_file() or catalog_path.is_symlink():
        raise OfflineVlcCatalogError("VLC_OFFLINE_CATALOG_REQUIRED_BUT_MISSING")
    baseline_path = root / SOURCE_BASELINE_NAME
    if not baseline_path.is_file() or baseline_path.is_symlink():
        raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_BASELINE_MISSING")
    baseline = _json_file(baseline_path, code="VLC_OFFLINE_SOURCE_BASELINE")
    if _bounded(baseline.get("Schema"), 80) != SOURCE_BASELINE_SCHEMA:
        raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_BASELINE_SCHEMA_INVALID")
    if _bounded(baseline.get("SourceRoot"), 300) != str(CATALOG_DIR_RELATIVE):
        raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_BASELINE_ROOT_INVALID")
    if _bounded(baseline.get("CatalogPath"), 300) != str(CATALOG_DIR_RELATIVE / CATALOG_NAME):
        raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_BASELINE_PATH_INVALID")
    try:
        expected_size = int(baseline.get("CatalogSizeBytes"))
        expected_files = int(baseline.get("ExpectedFiles"))
    except (TypeError, ValueError) as exc:
        raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_BASELINE_METADATA_INVALID") from exc
    if expected_size <= 0 or expected_size > MAX_CATALOG_BYTES or not 1 <= expected_files <= MAX_CATALOG_FILES:
        raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_BASELINE_METADATA_INVALID")
    expected_hash = _require_sha256(
        baseline.get("CatalogSha256"), code="VLC_OFFLINE_SOURCE_BASELINE_HASH_INVALID"
    )
    if catalog_path.stat().st_size != expected_size or sha256_file(catalog_path).casefold() != expected_hash:
        raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_BASELINE_CATALOG_MISMATCH")
    catalog = validate_catalog(_json_file(catalog_path, code="VLC_OFFLINE_CATALOG"))
    if _bounded(baseline.get("CatalogVersion"), 160) != str(catalog["CatalogVersion"]):
        raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_BASELINE_VERSION_MISMATCH")
    expected_paths = _source_expected_file_paths(catalog)
    if expected_files != len(expected_paths):
        raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_BASELINE_FILE_COUNT_MISMATCH")
    return source, catalog, {
        "CatalogPath": str(CATALOG_DIR_RELATIVE / CATALOG_NAME),
        "CatalogVersion": str(catalog["CatalogVersion"]),
        "CatalogSha256": expected_hash,
        "ExpectedFiles": expected_files,
        "ExpectedPaths": expected_paths,
    }


def validate_offline_vlc_source_baseline(
    app_root: Path, *, verify_payload: bool = False,
) -> dict[str, Any]:
    """Verify the separately retained VLC source closure without modifying it.

    ``verify_payload`` performs the deliberate, potentially large one-time
    SHA-256 sweep.  Normal component generation validates only its selected
    target bytes, avoiding a multi-gigabyte scan for every installer.
    """
    root = Path(app_root).resolve()
    source = catalog_source_root(root)
    catalog_path = source / CATALOG_NAME
    if not catalog_path.is_file():
        return {
            "State": "NOT_PROVISIONED",
            "SourceRoot": str(CATALOG_DIR_RELATIVE),
            "PayloadVerified": False,
        }
    source, catalog, baseline = _load_reviewed_source_catalog(root)
    paths = list(source.rglob("*"))
    if any(path.is_symlink() for path in paths):
        raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_SYMLINK_INVALID")
    actual_paths = {
        path.relative_to(source).as_posix()
        for path in paths
        if path.is_file()
    }
    if actual_paths != set(baseline["ExpectedPaths"]):
        raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_FILESET_MISMATCH")
    if verify_payload:
        _validate_source_files(source, catalog)
    return {
        "State": "VERIFIED",
        "SourceRoot": str(CATALOG_DIR_RELATIVE),
        "CatalogVersion": str(baseline["CatalogVersion"]),
        "CatalogSha256": str(baseline["CatalogSha256"]),
        "ExpectedFiles": int(baseline["ExpectedFiles"]),
        "PayloadVerified": bool(verify_payload),
    }


def _selected_variants(
    catalog: Mapping[str, Any], *, platform_name: str, architecture: str,
    distribution: str = "", codename: str = "",
) -> list[dict[str, Any]]:
    platform_id = _normal_platform(platform_name)
    arch = _normal_arch(architecture)
    distro = _bounded(distribution, 40).casefold()
    release = _bounded(codename, 80).casefold()
    if bool(distro) != bool(release):
        raise OfflineVlcCatalogError("VLC_OFFLINE_TARGET_SELECTOR_INCOMPLETE")
    if (distro or release) and platform_id != "linux":
        raise OfflineVlcCatalogError("VLC_OFFLINE_TARGET_SELECTOR_NOT_LINUX")
    variants = [
        dict(item) for item in catalog["Variants"]
        if item["Platform"] == platform_id and item["Architecture"] == arch
    ]
    if distro:
        variants = [
            item for item in variants
            if item["Distribution"] == distro and item["Codename"] == release
        ]
    if not variants:
        code = "VLC_OFFLINE_TARGET_VARIANT_UNAVAILABLE" if distro else "VLC_OFFLINE_TARGET_UNAVAILABLE"
        raise OfflineVlcCatalogError(code)
    return variants


def _targeted_legal_bundle(
    source: Path,
    catalog: Mapping[str, Any],
    variants: list[dict[str, Any]],
) -> tuple[dict[str, Any], bytes | None]:
    """Reduce corresponding source to the variants carried by one installer.

    Older reviewed catalogs did not bind variants to source IDs.  They retain
    the conservative all-source behavior.  New catalogs declare the binding,
    allowing Windows, x86_64 Linux and Raspberry bundles to carry only their
    own complete corresponding-source set.
    """
    declared = [set(item.get("CorrespondingSourceIds") or []) for item in variants]
    if not declared or any(not item for item in declared):
        return dict(catalog["Legal"]), None
    selected_source_ids = set().union(*declared)
    selected_variant_ids = {str(item["VariantId"]) for item in variants}
    source_materials_path = _resolve_under(source, SOURCE_MATERIALS_PATH, name="source_materials")
    materials_document = _json_file(source_materials_path, code="VLC_OFFLINE_SOURCE_MATERIALS")
    if (
        _bounded(materials_document.get("Schema"), 100) != "gideon-vlc-source-materials/v1"
        or _bounded(materials_document.get("Product"), 120) != "VLC media player"
        or _bounded(materials_document.get("License"), 80) != "GPL-2.0-or-later"
        or not isinstance(materials_document.get("SourceOffer"), Mapping)
    ):
        raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_MATERIALS_INVALID")

    source_rows = materials_document.get("Sources")
    artifact_rows = materials_document.get("Artifacts")
    if not isinstance(source_rows, list) or not isinstance(artifact_rows, list):
        raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_MATERIALS_INVALID")
    sources_by_id: dict[str, dict[str, Any]] = {}
    for raw in source_rows:
        if not isinstance(raw, Mapping):
            raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_MATERIAL_OBJECT_INVALID")
        source_id = _require_text(raw.get("SourceId"), code="VLC_OFFLINE_SOURCE_ID_INVALID", maximum=160, pattern=_SAFE_ID)
        if source_id in sources_by_id:
            raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_ID_DUPLICATE")
        sources_by_id[source_id] = dict(raw)
    if not selected_source_ids.issubset(sources_by_id):
        raise OfflineVlcCatalogError("VLC_OFFLINE_VARIANT_SOURCE_MISSING")

    expected_artifacts = {
        (str(variant["VariantId"]), str(item["Path"])): str(item["Sha256"])
        for variant in variants
        for item in variant["Files"]
        if item["Role"] in {"installer", "deb"}
    }
    selected_artifacts: list[dict[str, Any]] = []
    seen_artifacts: set[tuple[str, str]] = set()
    observed_source_ids: set[str] = set()
    for raw in artifact_rows:
        if not isinstance(raw, Mapping):
            raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_ARTIFACT_INVALID")
        variant_id = _bounded(raw.get("VariantId"), 160)
        if variant_id not in selected_variant_ids:
            continue
        artifact_path = str(_safe_relative(raw.get("Path"), name="source_artifact"))
        key = (variant_id, artifact_path)
        if key not in expected_artifacts or key in seen_artifacts:
            raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_ARTIFACT_UNEXPECTED")
        source_id = _require_text(raw.get("SourceId"), code="VLC_OFFLINE_SOURCE_ID_INVALID", maximum=160, pattern=_SAFE_ID)
        if source_id not in selected_source_ids:
            raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_ARTIFACT_MAPPING_INVALID")
        if _require_sha256(raw.get("UpstreamSha256"), code="VLC_OFFLINE_SOURCE_ARTIFACT_HASH_INVALID") != expected_artifacts[key]:
            raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_ARTIFACT_HASH_MISMATCH")
        seen_artifacts.add(key)
        observed_source_ids.add(source_id)
        selected_artifacts.append(dict(raw))
    if seen_artifacts != set(expected_artifacts) or observed_source_ids != selected_source_ids:
        raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_ARTIFACT_MAPPING_INCOMPLETE")

    selected_bundled = [
        dict(row) for row in catalog["Legal"]["BundledSources"]
        if str(row["SourceId"]) in selected_source_ids
    ]
    bundled_ids = {str(row["SourceId"]) for row in selected_bundled}
    archive_ids = {str(row["SourceId"]) for row in selected_bundled if row["Role"] == "source-archive"}
    if bundled_ids != selected_source_ids or archive_ids != selected_source_ids:
        raise OfflineVlcCatalogError("VLC_OFFLINE_VARIANT_SOURCE_BUNDLE_INCOMPLETE")

    filtered_document = dict(materials_document)
    filtered_document["Sources"] = [sources_by_id[source_id] for source_id in sorted(selected_source_ids)]
    filtered_document["Artifacts"] = sorted(
        selected_artifacts,
        key=lambda row: (str(row.get("VariantId") or ""), str(row.get("Path") or "")),
    )
    serialized = (json.dumps(filtered_document, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")

    required = list(REQUIRED_LEGAL_FILES) + [str(row["Path"]) for row in selected_bundled]
    original_materials = {str(row["Path"]): dict(row) for row in catalog["Legal"]["Materials"]}
    selected_materials: list[dict[str, Any]] = []
    for relative in required:
        if relative == SOURCE_MATERIALS_PATH:
            selected_materials.append({
                "Path": relative,
                "SizeBytes": len(serialized),
                "Sha256": hashlib.sha256(serialized).hexdigest(),
            })
            continue
        material = original_materials.get(relative)
        if material is None:
            raise OfflineVlcCatalogError("VLC_OFFLINE_LEGAL_MATERIAL_MISSING")
        selected_materials.append(material)
    return {
        "License": "GPL-2.0-or-later",
        "RequiredFiles": required,
        "Materials": selected_materials,
        "BundledSources": selected_bundled,
    }, serialized


def _source_preflight_legal(
    catalog: Mapping[str, Any],
    targeted_legal: Mapping[str, Any],
    targeted_source_materials: bytes | None,
) -> dict[str, Any]:
    """Describe source bytes before the filtered legal manifest is staged.

    ``_targeted_legal_bundle`` intentionally rewrites SOURCE-MATERIALS.json so
    an endpoint receives only the source offer that corresponds to its target.
    The source tree still contains the complete reviewed document, however.
    Preflight must therefore authenticate that original byte sequence, while
    the final validation authenticates the rewritten document in ``target``.
    """
    legal = {
        "License": str(targeted_legal.get("License") or ""),
        "RequiredFiles": list(targeted_legal.get("RequiredFiles") or []),
        "Materials": [dict(row) for row in (targeted_legal.get("Materials") or []) if isinstance(row, Mapping)],
        "BundledSources": [
            dict(row) for row in (targeted_legal.get("BundledSources") or []) if isinstance(row, Mapping)
        ],
    }
    if targeted_source_materials is None:
        return legal
    original = next(
        (
            dict(row) for row in (catalog.get("Legal", {}).get("Materials", []) or [])
            if isinstance(row, Mapping) and str(row.get("Path") or "") == SOURCE_MATERIALS_PATH
        ),
        None,
    )
    if original is None:
        raise OfflineVlcCatalogError("VLC_OFFLINE_LEGAL_MATERIAL_MISSING")
    legal["Materials"] = [
        original if str(row.get("Path") or "") == SOURCE_MATERIALS_PATH else row
        for row in legal["Materials"]
    ]
    return legal


def _variant_source_ids(variants: Iterable[Mapping[str, Any]]) -> list[str]:
    return sorted({
        str(source_id)
        for variant in variants
        for source_id in (variant.get("CorrespondingSourceIds") or [])
    })


def _detached_legal_bundle(
    *,
    catalog_version: str,
    targeted_legal: Mapping[str, Any],
    targeted_source_materials: bytes | None,
    variants: list[dict[str, Any]],
    source_companion: Mapping[str, Any],
) -> tuple[dict[str, Any], bytes, bytes]:
    """Create the small runtime legal view bound to one signed source ZIP."""
    if targeted_source_materials is None:
        # Old catalogs without artifact-to-source mappings can still use the
        # conservative full bundle, but cannot safely claim a reduced package.
        raise OfflineVlcCatalogError("VLC_OFFLINE_DETACHED_SOURCE_MAPPING_REQUIRED")
    companion = _source_companion_reference(
        {"SourceCompanion": source_companion}, catalog_version=catalog_version,
    )
    if companion is None:
        raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_COMPANION_REQUIRED")
    source_ids = _variant_source_ids(variants)
    if not source_ids or source_ids != list(companion["SourceIds"]):
        raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_COMPANION_SOURCE_IDS_MISMATCH")
    try:
        materials_document = json.loads(targeted_source_materials.decode("utf-8-sig"))
    except Exception as exc:
        raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_MATERIALS_INVALID") from exc
    if not isinstance(materials_document, Mapping):
        raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_MATERIALS_INVALID")
    detached_document = dict(materials_document)
    detached_document["SourceOffer"] = {
        "Method": "signed-source-companion",
        "Schema": SOURCE_COMPANION_SCHEMA,
        "ArtifactName": companion["ArtifactName"],
        "Sha256": companion["Sha256"],
        "SizeBytes": companion["SizeBytes"],
        "KeyId": companion["KeyId"],
        "SignatureScheme": companion["SignatureScheme"],
    }
    serialized = (
        json.dumps(detached_document, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")
    source_offer = (
        "# VLC corresponding source for this GIDEON Agent installer\n\n"
        "This operational installer includes the reviewed VLC runtime and required notices. "
        "The exact corresponding source is supplied alongside it as a separate, signed "
        "GIDEON Source Companion archive.\n\n"
        f"- Artifact: `{companion['ArtifactName']}`\n"
        f"- SHA-256: `{companion['Sha256']}`\n"
        f"- Size: `{companion['SizeBytes']}` bytes\n"
        f"- Signature: `{companion['SignatureScheme']}`\n"
        f"- Key ID: `{companion['KeyId']}`\n\n"
        "When redistributing this installer, provide this exact Source Companion archive "
        "and the included notices with it. The signed runtime catalog binds the installer "
        "to the artifact name, digest, size, source IDs and Ed25519 signature.\n"
    ).encode("utf-8")
    materials_by_path = {
        str(row["Path"]): dict(row)
        for row in (targeted_legal.get("Materials") or [])
        if isinstance(row, Mapping)
    }
    materials: list[dict[str, Any]] = []
    for relative in REQUIRED_LEGAL_FILES:
        if relative == SOURCE_MATERIALS_PATH:
            materials.append({
                "Path": relative,
                "SizeBytes": len(serialized),
                "Sha256": hashlib.sha256(serialized).hexdigest(),
            })
            continue
        if relative == SOURCE_OFFER_PATH:
            materials.append({
                "Path": relative,
                "SizeBytes": len(source_offer),
                "Sha256": hashlib.sha256(source_offer).hexdigest(),
            })
            continue
        row = materials_by_path.get(relative)
        if row is None:
            raise OfflineVlcCatalogError("VLC_OFFLINE_LEGAL_MATERIAL_MISSING")
        materials.append(row)
    return {
        "License": "GPL-2.0-or-later",
        "RequiredFiles": list(REQUIRED_LEGAL_FILES),
        "Materials": materials,
        "BundledSources": [],
        "SourceCompanion": companion,
    }, serialized, source_offer


def stage_offline_vlc_source_materials(
    app_root: Path,
    destination: Path,
    *,
    platform_name: str,
    architecture: str,
    distribution: str = "",
    codename: str = "",
) -> dict[str, Any]:
    """Stage only the reviewed legal/source closure for one exact target.

    No VLC installer, DEB, APT metadata, or executable runtime byte is copied.
    The selected operational artifacts are nevertheless hashed during
    preflight so the source-to-binary mapping cannot be detached from the
    reviewed intake catalog.
    """
    source = catalog_source_root(app_root)
    source_catalog = source / CATALOG_NAME
    if not source_catalog.is_file():
        raise OfflineVlcCatalogError("VLC_OFFLINE_CATALOG_REQUIRED_BUT_MISSING")
    catalog = validate_catalog(_json_file(source_catalog, code="VLC_OFFLINE_CATALOG"))
    variants = _selected_variants(
        catalog,
        platform_name=platform_name,
        architecture=architecture,
        distribution=distribution,
        codename=codename,
    )
    source, catalog, _baseline = _load_reviewed_source_catalog(app_root)
    variants = _selected_variants(
        catalog,
        platform_name=platform_name,
        architecture=architecture,
        distribution=distribution,
        codename=codename,
    )
    targeted_legal, targeted_source_materials = _targeted_legal_bundle(source, catalog, variants)
    if targeted_source_materials is None or not _variant_source_ids(variants):
        raise OfflineVlcCatalogError("VLC_OFFLINE_DETACHED_SOURCE_MAPPING_REQUIRED")
    preflight = validate_catalog({
        "Schema": OFFLINE_CATALOG_SCHEMA,
        "CatalogVersion": catalog["CatalogVersion"],
        "Vendor": catalog["Vendor"],
        "Legal": _source_preflight_legal(catalog, targeted_legal, targeted_source_materials),
        "Variants": variants,
    })
    _validate_source_files(source, preflight)
    target = Path(destination).resolve()
    if target.exists() and any(target.iterdir()):
        raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_COMPANION_STAGE_NOT_EMPTY")
    target.mkdir(parents=True, exist_ok=True)
    if target.is_symlink():
        raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_COMPANION_STAGE_INVALID")
    copied: list[str] = []
    for relative in targeted_legal["RequiredFiles"]:
        dst = _resolve_under(target, relative, name="legal_file")
        dst.parent.mkdir(parents=True, exist_ok=True)
        if relative == SOURCE_MATERIALS_PATH:
            dst.write_bytes(targeted_source_materials)
        else:
            shutil.copy2(_resolve_under(source, relative, name="legal_file"), dst)
        copied.append(str(relative))
    material_rows = {str(row["Path"]): row for row in targeted_legal["Materials"]}
    for relative in targeted_legal["RequiredFiles"]:
        copied_path = _resolve_under(target, relative, name="legal_file")
        material = material_rows[str(relative)]
        if (
            not copied_path.is_file()
            or copied_path.is_symlink()
            or copied_path.stat().st_size != int(material["SizeBytes"])
            or sha256_file(copied_path).casefold() != str(material["Sha256"]).casefold()
        ):
            raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_COMPANION_COPY_INVALID")
    return {
        "CatalogVersion": str(catalog["CatalogVersion"]),
        "SourceIds": _variant_source_ids(variants),
        "RequiredFiles": sorted(copied),
        "Legal": targeted_legal,
        "Variants": variants,
    }


def offline_vlc_source_identity(
    app_root: Path,
    *,
    platform_name: str,
    architecture: str,
    distribution: str = "",
    codename: str = "",
) -> dict[str, Any]:
    """Describe the selected source closure without copying/recompressing it."""
    source = catalog_source_root(app_root)
    source_catalog = source / CATALOG_NAME
    if not source_catalog.is_file():
        raise OfflineVlcCatalogError("VLC_OFFLINE_CATALOG_REQUIRED_BUT_MISSING")
    catalog = validate_catalog(_json_file(source_catalog, code="VLC_OFFLINE_CATALOG"))
    variants = _selected_variants(
        catalog,
        platform_name=platform_name,
        architecture=architecture,
        distribution=distribution,
        codename=codename,
    )
    source, catalog, _baseline = _load_reviewed_source_catalog(app_root)
    variants = _selected_variants(
        catalog,
        platform_name=platform_name,
        architecture=architecture,
        distribution=distribution,
        codename=codename,
    )
    _, targeted_source_materials = _targeted_legal_bundle(source, catalog, variants)
    source_ids = _variant_source_ids(variants)
    if targeted_source_materials is None or not source_ids:
        raise OfflineVlcCatalogError("VLC_OFFLINE_DETACHED_SOURCE_MAPPING_REQUIRED")
    return {
        "CatalogVersion": str(catalog["CatalogVersion"]),
        "SourceIds": source_ids,
        "Target": {
            "Platform": _normal_platform(platform_name),
            "Architecture": _normal_arch(architecture),
            "Distribution": _bounded(distribution, 40).casefold(),
            "Codename": _bounded(codename, 80).casefold(),
        },
    }


def offline_bundle_required() -> bool:
    return _bounded(os.environ.get("GIDEON_OFFLINE_VLC_BUNDLE_REQUIRED"), 20).casefold() in {"1", "true", "yes", "on"}


def _write_not_bundled_profile(
    profile_path: Path,
    *,
    reason: str,
    platform_name: str = "",
    architecture: str = "",
    distribution: str = "",
    codename: str = "",
) -> dict[str, Any]:
    profile = {
        "Schema": OFFLINE_PROFILE_SCHEMA,
        "Bundled": False,
        "ExternalVlcOnly": True,
        "NetworkDownloads": False,
        "InstallRequiresSignedApproval": True,
        "Reason": _bounded(reason, 120),
        "RequestedTarget": {
            "Platform": _normal_platform(platform_name),
            "Architecture": _normal_arch(architecture),
            "Distribution": _bounded(distribution, 40).casefold(),
            "Codename": _bounded(codename, 80).casefold(),
        },
    }
    profile_path.write_text(json.dumps(profile, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {"Bundled": False, "RequiredFiles": [str(CATALOG_DIR_RELATIVE / PROFILE_NAME)]}


def stage_offline_vlc_bundle(
    app_root: Path,
    payload_root: Path,
    *,
    platform_name: str,
    architecture: str,
    distribution: str = "",
    codename: str = "",
    signing_private_key: Path,
    required: bool | None = None,
    source_delivery: str = "bundled",
    source_companion: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Copy a reviewed, target-matched offline kit into a staged installer.

    The build never fetches vendor material.  If the reviewed source catalog is
    absent, a small *not bundled* profile is still embedded so the Agent can
    report that fact.  ``source_delivery='detached'`` keeps the operational VLC
    closure in the installer while placing corresponding-source archives in a
    separately signed companion referenced by this signed catalog.  The
    default ``bundled`` mode remains the conservative all-in-one fallback.

    A release pipeline may set ``GIDEON_OFFLINE_VLC_BUNDLE_REQUIRED=1`` to block
    publication until the complete legal/artifact intake is present.
    """
    source = catalog_source_root(app_root)
    target = Path(payload_root) / Path(*CATALOG_DIR_RELATIVE.parts)
    target.mkdir(parents=True, exist_ok=True)
    profile_path = target / PROFILE_NAME
    must_bundle = offline_bundle_required() if required is None else bool(required)
    source_delivery = _bounded(source_delivery or "bundled", 40).casefold()
    if source_delivery not in {"bundled", "detached"}:
        raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_DELIVERY_INVALID")
    if source_delivery == "bundled" and source_companion is not None:
        raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_COMPANION_UNEXPECTED")
    source_catalog = source / CATALOG_NAME
    if not source_catalog.is_file():
        if must_bundle:
            raise OfflineVlcCatalogError("VLC_OFFLINE_CATALOG_REQUIRED_BUT_MISSING")
        return _write_not_bundled_profile(
            profile_path,
            reason="VLC_OFFLINE_CATALOG_NOT_BUNDLED",
            platform_name=platform_name,
            architecture=architecture,
            distribution=distribution,
            codename=codename,
        )

    source_catalog_data = validate_catalog(_json_file(source_catalog, code="VLC_OFFLINE_CATALOG"))
    try:
        variants = _selected_variants(
            source_catalog_data,
            platform_name=platform_name,
            architecture=architecture,
            distribution=distribution,
            codename=codename,
        )
    except OfflineVlcCatalogError as exc:
        if str(exc) not in {"VLC_OFFLINE_TARGET_UNAVAILABLE", "VLC_OFFLINE_TARGET_VARIANT_UNAVAILABLE"} or must_bundle:
            raise
        return _write_not_bundled_profile(
            profile_path,
            reason=str(exc),
            platform_name=platform_name,
            architecture=architecture,
            distribution=distribution,
            codename=codename,
        )
    source, source_catalog_data, _baseline = _load_reviewed_source_catalog(app_root)
    variants = _selected_variants(
        source_catalog_data,
        platform_name=platform_name,
        architecture=architecture,
        distribution=distribution,
        codename=codename,
    )
    targeted_legal, targeted_source_materials = _targeted_legal_bundle(source, source_catalog_data, variants)
    full_filtered_catalog = {
        "Schema": OFFLINE_CATALOG_SCHEMA,
        "CatalogVersion": source_catalog_data["CatalogVersion"],
        "Vendor": source_catalog_data["Vendor"],
        "Legal": targeted_legal,
        "Variants": variants,
    }
    full_filtered_catalog = validate_catalog(full_filtered_catalog)
    # Validate only the exact target closure.  The reviewed multi-platform
    # source can exceed 3 GB; hashing unrelated operating systems on every
    # Agent build adds latency without increasing the selected bundle's trust.
    source_preflight_catalog = validate_catalog({
        "Schema": OFFLINE_CATALOG_SCHEMA,
        "CatalogVersion": source_catalog_data["CatalogVersion"],
        "Vendor": source_catalog_data["Vendor"],
        "Legal": _source_preflight_legal(
            source_catalog_data, targeted_legal, targeted_source_materials
        ),
        "Variants": variants,
    })
    _validate_source_files(source, source_preflight_catalog)
    staged_source_materials = targeted_source_materials
    staged_source_offer: bytes | None = None
    if source_delivery == "detached":
        if not isinstance(source_companion, Mapping):
            raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_COMPANION_REQUIRED")
        runtime_legal, staged_source_materials, staged_source_offer = _detached_legal_bundle(
            catalog_version=str(source_catalog_data["CatalogVersion"]),
            targeted_legal=targeted_legal,
            targeted_source_materials=targeted_source_materials,
            variants=variants,
            source_companion=source_companion,
        )
        filtered_catalog = validate_catalog({
            "Schema": OFFLINE_CATALOG_SCHEMA,
            "CatalogVersion": source_catalog_data["CatalogVersion"],
            "Vendor": source_catalog_data["Vendor"],
            "Legal": runtime_legal,
            "Variants": variants,
        })
    else:
        filtered_catalog = full_filtered_catalog
    catalog_path = target / CATALOG_NAME
    catalog_path.write_text(json.dumps(filtered_catalog, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    signature_path = target / CATALOG_SIGNATURE_NAME
    signature_path.write_text(sign_file(catalog_path, Path(signing_private_key)), encoding="ascii", newline="\n")
    copied: list[str] = [str(CATALOG_DIR_RELATIVE / CATALOG_NAME), str(CATALOG_DIR_RELATIVE / CATALOG_SIGNATURE_NAME)]
    for legal in filtered_catalog["Legal"]["RequiredFiles"]:
        dst = _resolve_under(target, legal, name="legal_file")
        dst.parent.mkdir(parents=True, exist_ok=True)
        if legal == SOURCE_MATERIALS_PATH and staged_source_materials is not None:
            dst.write_bytes(staged_source_materials)
        elif legal == SOURCE_OFFER_PATH and staged_source_offer is not None:
            dst.write_bytes(staged_source_offer)
        else:
            src = _resolve_under(source, legal, name="legal_file")
            shutil.copy2(src, dst)
        copied.append(str(CATALOG_DIR_RELATIVE / _safe_relative(legal, name="legal_file")))
    for variant in variants:
        for item in variant["Files"]:
            src = _resolve_under(source, item["Path"], name="artifact")
            dst = _resolve_under(target, item["Path"], name="artifact")
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            copied.append(str(CATALOG_DIR_RELATIVE / _safe_relative(item["Path"], name="artifact")))
    _validate_source_files(target, filtered_catalog)
    profile = {
        "Schema": OFFLINE_PROFILE_SCHEMA,
        "Bundled": True,
        "ExternalVlcOnly": True,
        "NetworkDownloads": False,
        "InstallRequiresSignedApproval": True,
        "SourceDelivery": source_delivery,
        "CatalogPath": CATALOG_NAME,
        "CatalogSha256": sha256_file(catalog_path),
        "SignaturePath": CATALOG_SIGNATURE_NAME,
        "Variants": [
            {"VariantId": item["VariantId"], "Platform": item["Platform"], "Architecture": item["Architecture"],
             "Distribution": item["Distribution"], "Codename": item["Codename"]}
            for item in variants
        ],
    }
    profile_path.write_text(json.dumps(profile, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    copied.append(str(CATALOG_DIR_RELATIVE / PROFILE_NAME))
    result = {
        "Bundled": True,
        "SourcesBundled": source_delivery == "bundled",
        "Delivery": source_delivery,
        "CatalogSha256": profile["CatalogSha256"],
        "RequiredFiles": sorted(set(copied)),
        "Variants": profile["Variants"],
    }
    if source_delivery == "detached":
        result["SourceCompanion"] = dict(filtered_catalog["Legal"]["SourceCompanion"])
    return result


def _os_release() -> tuple[str, str]:
    values: dict[str, str] = {}
    try:
        for raw in Path("/etc/os-release").read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" not in raw or raw.lstrip().startswith("#"):
                continue
            key, value = raw.split("=", 1)
            values[key.strip()] = value.strip().strip('"').strip("'")
    except OSError:
        pass
    distro = _bounded(values.get("ID"), 40).casefold()
    codename = _bounded(values.get("VERSION_CODENAME") or values.get("UBUNTU_CODENAME"), 80).casefold()
    return distro, codename


def _runtime_variant(catalog: Mapping[str, Any]) -> dict[str, Any]:
    platform_name = _normal_platform()
    architecture = _normal_arch()
    candidates = [item for item in catalog["Variants"] if item["Platform"] == platform_name and item["Architecture"] == architecture]
    if platform_name == "linux":
        distro, codename = _os_release()
        candidates = [item for item in candidates if item["Distribution"] == distro and item["Codename"] == codename]
    if len(candidates) != 1:
        raise OfflineVlcCatalogError("VLC_OFFLINE_RUNTIME_VARIANT_UNAVAILABLE")
    return dict(candidates[0])


def _load_catalog_metadata(agent_root: Path, public_key_path: Path) -> tuple[Path, dict[str, Any]]:
    """Authenticate the small signed catalog without hashing large payloads."""
    root = Path(agent_root).resolve() / Path(*CATALOG_DIR_RELATIVE.parts)
    profile = _json_file(root / PROFILE_NAME, code="VLC_OFFLINE_PROFILE")
    if profile.get("Schema") != OFFLINE_PROFILE_SCHEMA:
        raise OfflineVlcCatalogError("VLC_OFFLINE_PROFILE_SCHEMA_INVALID")
    if profile.get("Bundled") is not True:
        raise OfflineVlcCatalogError("VLC_OFFLINE_CATALOG_NOT_BUNDLED")
    catalog_path = root / CATALOG_NAME
    if not catalog_path.is_file() or not (root / CATALOG_SIGNATURE_NAME).is_file():
        raise OfflineVlcCatalogError("VLC_OFFLINE_CATALOG_MISSING")
    expected = _require_sha256(profile.get("CatalogSha256"), code="VLC_OFFLINE_PROFILE_HASH_INVALID")
    if sha256_file(catalog_path).casefold() != expected:
        raise OfflineVlcCatalogError("VLC_OFFLINE_CATALOG_HASH_MISMATCH")
    try:
        signature = (root / CATALOG_SIGNATURE_NAME).read_text(encoding="ascii").strip()
    except Exception as exc:
        raise OfflineVlcCatalogError("VLC_OFFLINE_CATALOG_SIGNATURE_INVALID") from exc
    if not signature or not Path(public_key_path).is_file() or not verify_file(catalog_path, signature, Path(public_key_path)):
        raise OfflineVlcCatalogError("VLC_OFFLINE_CATALOG_SIGNATURE_INVALID")
    catalog = validate_catalog(_json_file(catalog_path, code="VLC_OFFLINE_CATALOG"))
    return root, catalog


def _validate_payload_presence(root: Path, catalog: Mapping[str, Any]) -> None:
    """Cheap heartbeat check; cryptographic payload validation happens at install."""
    materials = {str(row["Path"]): row for row in catalog["Legal"]["Materials"]}
    for relative in catalog["Legal"]["RequiredFiles"]:
        path = _resolve_under(root, relative, name="legal_file")
        expected = materials.get(str(relative))
        if expected is None or not path.is_file() or path.is_symlink() or path.stat().st_size != int(expected["SizeBytes"]):
            raise OfflineVlcCatalogError("VLC_OFFLINE_LEGAL_FILE_MISSING")
    for variant in catalog["Variants"]:
        for item in variant["Files"]:
            path = _resolve_under(root, item["Path"], name="artifact")
            if not path.is_file() or path.is_symlink() or path.stat().st_size != int(item["SizeBytes"]):
                raise OfflineVlcCatalogError("VLC_OFFLINE_ARTIFACT_MISSING")


def _load_installed_catalog(agent_root: Path, public_key_path: Path) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    root, catalog = _load_catalog_metadata(agent_root, public_key_path)
    # A valid signature protects catalog metadata, but every payload named by
    # that metadata must still be checked at use time.  This includes GPL
    # corresponding-source archives as well as the installer/packages; an
    # altered source archive must fail closed even when the executable itself
    # has not changed.
    _validate_source_files(root, catalog)
    variant = _runtime_variant(catalog)
    return root, catalog, variant


def validate_installed_offline_vlc_catalog(
    agent_root: Path, public_key_path: Path | None = None,
) -> dict[str, Any]:
    """Validate a complete installed/offline VLC closure without installing it.

    This is the public, read-only verification boundary used by the separate
    component archive contract.  It authenticates the inner catalog signature
    and every vendor/legal byte before a caller can stage the component for a
    later, explicitly-authorised install.  It intentionally has no network,
    process, service, or package-manager side effect.
    """

    root = Path(agent_root).resolve()
    key = Path(public_key_path) if public_key_path else root / "gideon_agent_signing_public.pem"
    catalog_root, catalog, variant = _load_installed_catalog(root, key)
    return {
        "CatalogRoot": str(catalog_root),
        "CatalogSha256": sha256_file(catalog_root / CATALOG_NAME),
        "CatalogVersion": _bounded(catalog.get("CatalogVersion"), 160),
        "Variant": _bounded(variant.get("VariantId"), 160),
        "Target": {
            "Platform": _bounded(variant.get("Platform"), 40),
            "Architecture": _bounded(variant.get("Architecture"), 40),
            "Distribution": _bounded(variant.get("Distribution"), 40),
            "Codename": _bounded(variant.get("Codename"), 80),
        },
    }


def offline_vlc_catalog_capability(agent_root: Path, public_key_path: Path | None = None) -> dict[str, Any]:
    """Return a bounded capability report; a broken kit never affects Agent core."""
    root = Path(agent_root).resolve()
    key = Path(public_key_path) if public_key_path else root / "gideon_agent_signing_public.pem"
    profile_path = root / Path(*CATALOG_DIR_RELATIVE.parts) / PROFILE_NAME
    platform_name = _normal_platform()
    architecture = _normal_arch()
    distribution, codename = _os_release() if platform_name == "linux" else ("", "")
    target = {
        "Platform": platform_name,
        "Architecture": architecture,
        "Distribution": distribution,
        "Codename": codename,
    }
    try:
        profile = _json_file(profile_path, code="VLC_OFFLINE_PROFILE")
        if profile.get("Bundled") is not True:
            delivery = _bounded(profile.get("ComponentDelivery"), 80)
            component_schema = _bounded(profile.get("ComponentSchema"), 80)
            component_kind = _bounded(profile.get("ComponentKind"), 80)
            component_required = delivery == "separate-signed-component"
            return {
                "Bundled": False,
                "State": "COMPONENT_REQUIRED" if component_required else "NOT_BUNDLED",
                "ComponentDelivery": delivery if component_required else "",
                "ComponentSchema": component_schema if component_required else "",
                "ComponentKind": component_kind if component_required else "",
                "RequestedTarget": profile.get("RequestedTarget") if isinstance(profile.get("RequestedTarget"), Mapping) else {},
                "NetworkDownloads": False,
                "InstallRequiresSignedApproval": True, "License": "GPL-2.0-or-later",
                "Target": target,
            }
        _kit_root, catalog = _load_catalog_metadata(root, key)
        _validate_payload_presence(_kit_root, catalog)
        variant = _runtime_variant(catalog)
        return {
            "Bundled": True,
            "State": "READY_FOR_EXPLICIT_INSTALL",
            "NetworkDownloads": False,
            "InstallRequiresSignedApproval": True,
            "License": "GPL-2.0-or-later",
            "Target": target,
            # This is a content digest, not a credential. WebAdmin binds its
            # one-shot approval to precisely this reviewed catalog so an Agent
            # can reject authorization replayed against a different VLC kit.
            "CatalogSha256": sha256_file(_kit_root / CATALOG_NAME),
            "CatalogVersion": _bounded(catalog.get("CatalogVersion"), 160),
            "Variant": _bounded(variant.get("VariantId"), 160),
            "InstallMode": _bounded((variant.get("Install") or {}).get("Mode"), 80),
            "DependencyClosure": bool((variant.get("DependencyClosure") or {}).get("Complete")),
        }
    except OfflineVlcCatalogError as exc:
        return {
            "Bundled": profile_path.is_file(), "State": "CATALOG_INVALID", "Reason": _bounded(exc, 160),
            "NetworkDownloads": False, "InstallRequiresSignedApproval": True, "License": "GPL-2.0-or-later",
            "Target": target,
        }
    except Exception:
        return {
            "Bundled": profile_path.is_file(), "State": "CATALOG_UNAVAILABLE", "Reason": "VLC_OFFLINE_CAPABILITY_UNAVAILABLE",
            "NetworkDownloads": False, "InstallRequiresSignedApproval": True, "License": "GPL-2.0-or-later",
            "Target": target,
        }


def _parse_time(value: Any, *, code: str) -> dt.datetime:
    text = _bounded(value, 80)
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OfflineVlcAuthorizationError(code) from exc
    if parsed.tzinfo is None:
        raise OfflineVlcAuthorizationError(code)
    return parsed.astimezone(dt.timezone.utc)


def verify_install_authorization(
    envelope: Mapping[str, Any], *, public_key_path: Path, agent_id: str, catalog_sha256: str,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    if not isinstance(envelope, Mapping) or _bounded(envelope.get("Schema"), 100) != OFFLINE_AUTHORIZATION_SCHEMA:
        raise OfflineVlcAuthorizationError("VLC_OFFLINE_AUTHORIZATION_SCHEMA_INVALID")
    payload = envelope.get("Payload")
    signature = _bounded(envelope.get("Signature"), 1000)
    if not isinstance(payload, Mapping) or not signature:
        raise OfflineVlcAuthorizationError("VLC_OFFLINE_AUTHORIZATION_INVALID")
    canonical = _canonical_json(payload)
    try:
        key = serialization.load_pem_public_key(Path(public_key_path).read_bytes())
        if not isinstance(key, Ed25519PublicKey):
            raise OfflineVlcAuthorizationError("VLC_OFFLINE_AUTHORIZATION_KEY_INVALID")
        key.verify(base64.b64decode(signature, validate=True), canonical)
    except OfflineVlcAuthorizationError:
        raise
    except (ValueError, TypeError, InvalidSignature) as exc:
        raise OfflineVlcAuthorizationError("VLC_OFFLINE_AUTHORIZATION_SIGNATURE_INVALID") from exc
    except Exception as exc:
        raise OfflineVlcAuthorizationError("VLC_OFFLINE_AUTHORIZATION_KEY_INVALID") from exc
    if _bounded(payload.get("Action"), 32) != "INSTALL":
        raise OfflineVlcAuthorizationError("VLC_OFFLINE_AUTHORIZATION_ACTION_INVALID")
    if _bounded(payload.get("AgentId"), 160) != _bounded(agent_id, 160):
        raise OfflineVlcAuthorizationError("VLC_OFFLINE_AUTHORIZATION_AGENT_MISMATCH")
    if _require_sha256(payload.get("CatalogSha256"), code="VLC_OFFLINE_AUTHORIZATION_CATALOG_HASH_INVALID") != catalog_sha256:
        raise OfflineVlcAuthorizationError("VLC_OFFLINE_AUTHORIZATION_CATALOG_MISMATCH")
    request_id = _require_text(payload.get("RequestId"), code="VLC_OFFLINE_AUTHORIZATION_REQUEST_INVALID", maximum=160, pattern=_SAFE_REQUEST_ID)
    expires_at = _parse_time(payload.get("ExpiresAt"), code="VLC_OFFLINE_AUTHORIZATION_EXPIRY_INVALID")
    current = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    if expires_at <= current or expires_at - current > dt.timedelta(hours=24):
        raise OfflineVlcAuthorizationError("VLC_OFFLINE_AUTHORIZATION_EXPIRED")
    if payload.get("GplAcknowledged") is not True:
        raise OfflineVlcAuthorizationError("VLC_OFFLINE_AUTHORIZATION_GPL_REQUIRED")
    return {"RequestId": request_id, "ExpiresAt": expires_at.isoformat(), "CatalogSha256": catalog_sha256}


def _is_elevated() -> bool:
    if os.name != "nt":
        return hasattr(os, "geteuid") and os.geteuid() == 0
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _verify_windows_authenticode(path: Path, expected: Mapping[str, Any]) -> None:
    shell = shutil.which("powershell.exe") or shutil.which("powershell")
    if not shell:
        raise OfflineVlcCatalogError("VLC_OFFLINE_AUTHENTICODE_TOOL_UNAVAILABLE")
    command = (
        "$ErrorActionPreference='Stop';$s=Get-AuthenticodeSignature -LiteralPath $args[0];"
        "[pscustomobject]@{Status=[string]$s.Status;Subject=[string]$s.SignerCertificate.Subject;"
        "Thumbprint=[string]$s.SignerCertificate.Thumbprint}|ConvertTo-Json -Compress"
    )
    try:
        result = subprocess.run(
            [shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command, str(path)],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30, check=False,
            creationflags=0x08000000,
        )
        actual = json.loads(result.stdout or "{}")
    except Exception as exc:
        raise OfflineVlcCatalogError("VLC_OFFLINE_AUTHENTICODE_VERIFY_FAILED") from exc
    subject = _bounded(actual.get("Subject"), 500)
    thumbprint = _bounded(actual.get("Thumbprint"), 80).replace(" ", "").upper()
    if _bounded(actual.get("Status"), 40) != "Valid" or subject != _bounded(expected.get("Subject"), 500) or thumbprint != _bounded(expected.get("Thumbprint"), 80).replace(" ", "").upper():
        raise OfflineVlcCatalogError("VLC_OFFLINE_AUTHENTICODE_MISMATCH")


def _linux_apt_command(repo: Path, signing_key: Path, packages: Iterable[str], scratch: Path, *, update: bool) -> list[str]:
    apt = shutil.which("apt-get")
    if not apt:
        raise OfflineVlcCatalogError("VLC_OFFLINE_APT_UNAVAILABLE")
    if not repo.is_dir() or repo.is_symlink() or not signing_key.is_file() or signing_key.is_symlink():
        raise OfflineVlcCatalogError("VLC_OFFLINE_APT_REPOSITORY_MISSING")
    scratch.mkdir(parents=True, exist_ok=True)
    source_list = scratch / "sources.list"
    # ``--no-download`` would prohibit APT from copying .deb files from this
    # local repository into its scratch cache.  Network isolation instead comes
    # from the only source list being this file:// repository, sourceparts being
    # disabled, and the repository signature being pinned with signed-by.
    source_list.write_text(
        f"deb [signed-by={signing_key.resolve()}] {repo.resolve().as_uri()} ./\n",
        encoding="utf-8",
    )
    lists = scratch / "lists"; archives = scratch / "archives"
    lists.mkdir(parents=True, exist_ok=True); archives.mkdir(parents=True, exist_ok=True)
    options = [
        apt, "-o", f"Dir::Etc::sourcelist={source_list}", "-o", "Dir::Etc::sourceparts=-",
        "-o", f"Dir::State::lists={lists}", "-o", f"Dir::Cache::archives={archives}",
        "-o", "Acquire::http::Proxy=false", "-o", "Acquire::https::Proxy=false",
        "-o", "Acquire::Retries=0", "-o", "Acquire::AllowInsecureRepositories=false",
        "-o", "Acquire::AllowDowngradeToInsecureRepositories=false",
        "-o", "APT::Get::AllowUnauthenticated=false", "-o", "APT::Get::List-Cleanup=0",
    ]
    if update:
        return options + ["update"]
    return options + ["--yes", "--no-install-recommends", "install", *list(packages)]


class OfflineVlcInstaller:
    """Privileged, explicitly authorised executor for a bundled VLC kit."""

    def __init__(self, *, agent_root: Path, state_root: Path, agent_id: str, public_key_path: Path | None = None) -> None:
        self.agent_root = Path(agent_root).resolve()
        self.state_root = Path(state_root).resolve()
        self.agent_id = _require_text(agent_id, code="VLC_OFFLINE_AGENT_ID_INVALID", maximum=160, pattern=_SAFE_ID)
        self.public_key_path = Path(public_key_path) if public_key_path else self.agent_root / "gideon_agent_signing_public.pem"

    @property
    def audit_path(self) -> Path:
        return self.state_root / "player" / "vlc-offline-install.json"

    def _audit(self) -> dict[str, Any]:
        try:
            return _json_file(self.audit_path, code="VLC_OFFLINE_AUDIT")
        except OfflineVlcCatalogError:
            return {}

    def _write_audit(self, *, request_id: str, catalog_sha256: str, state: str, detail: str, variant: str) -> None:
        payload = {
            "Schema": "gideon-vlc-offline-install-audit/v1", "RequestId": _bounded(request_id, 160),
            "CatalogSha256": _bounded(catalog_sha256, 64).casefold(), "State": _bounded(state, 80),
            "Detail": _bounded(detail, 240), "Variant": _bounded(variant, 160), "UpdatedAt": _now_iso(),
        }
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        atomic_json(self.audit_path, payload, mode=PRIVATE_FILE_MODE)
        enforce_path_mode(self.audit_path, PRIVATE_FILE_MODE)

    def plan(self) -> dict[str, Any]:
        root, _catalog, variant = _load_installed_catalog(self.agent_root, self.public_key_path)
        return {
            "State": "READY_FOR_EXPLICIT_INSTALL", "CatalogRoot": root, "Variant": variant,
            "CatalogSha256": sha256_file(root / CATALOG_NAME),
        }

    def install(self, authorization: Mapping[str, Any], *, gpl_acknowledged: bool, dry_run: bool = False) -> dict[str, Any]:
        if not gpl_acknowledged:
            raise OfflineVlcAuthorizationError("VLC_OFFLINE_GPL_ACKNOWLEDGEMENT_REQUIRED")
        if not _is_elevated():
            raise OfflineVlcAuthorizationError("VLC_OFFLINE_ADMIN_REQUIRED")
        plan = self.plan()
        root = Path(plan["CatalogRoot"])
        variant = dict(plan["Variant"])
        catalog_sha256 = str(plan["CatalogSha256"])
        approved = verify_install_authorization(
            authorization, public_key_path=self.public_key_path, agent_id=self.agent_id, catalog_sha256=catalog_sha256,
        )
        audit = self._audit()
        if _bounded(audit.get("RequestId"), 160) == approved["RequestId"] and _bounded(audit.get("State"), 80) in {"INSTALLING", "INSTALLED"}:
            raise OfflineVlcAuthorizationError("VLC_OFFLINE_AUTHORIZATION_REPLAYED")
        if dry_run:
            return {"State": "DRY_RUN", "Variant": variant["VariantId"], "RequestId": approved["RequestId"]}
        self._write_audit(request_id=approved["RequestId"], catalog_sha256=catalog_sha256, state="INSTALLING", detail="VLC_OFFLINE_EXPLICIT_APPROVED", variant=variant["VariantId"])
        try:
            if variant["Platform"] == "windows":
                self._install_windows(root, variant)
            elif variant["Platform"] == "linux":
                self._install_linux(root, variant)
            else:
                raise OfflineVlcCatalogError("VLC_OFFLINE_PLATFORM_UNSUPPORTED")
        except Exception as exc:
            self._write_audit(request_id=approved["RequestId"], catalog_sha256=catalog_sha256, state="FAILED", detail=type(exc).__name__, variant=variant["VariantId"])
            raise
        self._write_audit(request_id=approved["RequestId"], catalog_sha256=catalog_sha256, state="INSTALLED", detail="VLC_OFFLINE_INSTALL_SUCCESS", variant=variant["VariantId"])
        return {"State": "INSTALLED", "Variant": variant["VariantId"], "RequestId": approved["RequestId"]}

    def _install_windows(self, root: Path, variant: Mapping[str, Any]) -> None:
        installer = next(item for item in variant["Files"] if item["Role"] == "installer")
        path = _resolve_under(root, installer["Path"], name="artifact")
        _verify_windows_authenticode(path, installer["Authenticode"])
        mode = str((variant.get("Install") or {}).get("Mode") or "")
        if mode == "windows-nsis-exe" and path.suffix.casefold() == ".exe":
            command = [str(path), "/S"]
        elif mode == "windows-msi" and path.suffix.casefold() == ".msi":
            msiexec = os.path.join(os.environ.get("SystemRoot", r"C:\\Windows"), "System32", "msiexec.exe")
            command = [msiexec, "/i", str(path), "/qn", "/norestart"]
        else:
            raise OfflineVlcCatalogError("VLC_OFFLINE_WINDOWS_INSTALLER_MODE_MISMATCH")
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=900, check=False, creationflags=0x08000000)
        if result.returncode != 0:
            raise OfflineVlcCatalogError("VLC_OFFLINE_WINDOWS_INSTALL_FAILED")

    def _install_linux(self, root: Path, variant: Mapping[str, Any]) -> None:
        install = dict(variant.get("Install") or {})
        repo = _resolve_under(root, install.get("RepositoryPath"), name="repository")
        if not repo.is_dir() or repo.is_symlink():
            raise OfflineVlcCatalogError("VLC_OFFLINE_APT_REPOSITORY_MISSING")
        signing_key = _resolve_under(root, install.get("AptSigningKeyPath"), name="apt_signing_key")
        if not signing_key.is_file() or signing_key.is_symlink():
            raise OfflineVlcCatalogError("VLC_OFFLINE_APT_SIGNING_KEY_INVALID")
        packages = list((variant.get("DependencyClosure") or {}).get("EntryPackages") or [])
        if not packages:
            raise OfflineVlcCatalogError("VLC_OFFLINE_ENTRY_PACKAGES_REQUIRED")
        with tempfile.TemporaryDirectory(prefix="gideon-vlc-offline-apt-") as temporary:
            scratch = Path(temporary)
            for command in (
                _linux_apt_command(repo, signing_key, packages, scratch, update=True),
                _linux_apt_command(repo, signing_key, packages, scratch, update=False),
            ):
                result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, timeout=900, check=False)
                if result.returncode != 0:
                    raise OfflineVlcCatalogError("VLC_OFFLINE_APT_INSTALL_FAILED")


def _load_authorization(path: Path) -> dict[str, Any]:
    return _json_file(Path(path), code="VLC_OFFLINE_AUTHORIZATION")


def main() -> int:
    parser = argparse.ArgumentParser(description="Instalador VLC offline verificado de GIDEON")
    parser.add_argument("--agent-root", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--install", action="store_true")
    parser.add_argument("--accept-vlc-gpl", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if not args.install:
        parser.error("--install es obligatorio; no se realizan instalaciones implícitas.")
    try:
        result = OfflineVlcInstaller(agent_root=args.agent_root, state_root=args.state_root, agent_id=args.agent_id).install(
            _load_authorization(args.authorization), gpl_acknowledged=bool(args.accept_vlc_gpl), dry_run=bool(args.dry_run),
        )
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    except OfflineVlcCatalogError as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
