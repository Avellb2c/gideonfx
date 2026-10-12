from __future__ import annotations

"""Signed, platform-specific Agent component contracts.

The Agent core is deliberately independent from optional third-party runtime
closures.  This module defines the *offline VLC component* boundary used by
the build and future controlled-delivery paths:

* a core installer receives only a tiny declaration that a signed component
  may be installed later;
* each VLC component contains exactly one reviewed OS/architecture closure,
  including its GPL notices and corresponding-source material;
* the component has an outer Ed25519 manifest in addition to the existing
  signed VLC catalog; and
* verification happens before any payload is staged for a privileged action.

No function here downloads, installs, starts VLC, changes a service, or
contacts a package repository.  The resulting archive is a data artifact that
must still be delivered through the existing authenticated, audited Agent job
flow and explicitly approved before ``OfflineVlcInstaller`` may run.
"""

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tempfile
from typing import Any, Mapping
import zipfile

from gideon_agent_archive import write_verified_deflated_zip
from gideon_agent_security import (
    sha256_file, sign_file, sign_sha256_digest, verify_file, verify_sha256_digest,
)
from gideon_agent_vlc_offline import (
    CATALOG_DIR_RELATIVE,
    CATALOG_NAME,
    CATALOG_SIGNATURE_NAME,
    MAX_CATALOG_BYTES,
    MAX_CATALOG_TOTAL_BYTES,
    OFFLINE_CATALOG_SCHEMA,
    OFFLINE_PROFILE_SCHEMA,
    PROFILE_NAME,
    SOURCE_COMPANION_KEY_ID,
    SOURCE_COMPANION_SCHEMA,
    SOURCE_COMPANION_SIGNATURE_DOMAIN,
    SOURCE_COMPANION_SIGNATURE_SCHEME,
    OfflineVlcCatalogError,
    offline_vlc_source_identity,
    stage_offline_vlc_bundle,
    stage_offline_vlc_source_materials,
    validate_catalog,
    validate_installed_offline_vlc_catalog,
)


COMPONENT_SCHEMA = "gideon-agent-component/v1"
COMPONENT_KIND = "vlc-offline"
COMPONENT_DELIVERY = "separate-signed-component"
COMPONENT_MANIFEST_NAME = "component-manifest.json"
COMPONENT_SIGNATURE_NAME = "component-manifest.sig"
COMPONENT_PAYLOAD_ROOT = PurePosixPath("payload") / CATALOG_DIR_RELATIVE
SOURCE_COMPANION_MANIFEST_NAME = "source-companion-manifest.json"
SOURCE_COMPANION_SIGNATURE_NAME = "source-companion-manifest.sig"
SOURCE_COMPANION_PAYLOAD_ROOT = PurePosixPath("payload")
MAX_COMPONENT_MANIFEST_BYTES = MAX_CATALOG_BYTES
MAX_COMPONENT_ARCHIVE_BYTES = 16 * 1024 * 1024 * 1024
MAX_COMPONENT_MEMBERS = 8_192


class AgentComponentError(RuntimeError):
    """A component archive or its target contract is unsafe or incomplete."""


def _bounded(value: Any, maximum: int = 240) -> str:
    return str(value or "").replace("\x00", " ").strip()[:maximum]


def _normal_platform(value: str) -> str:
    raw = _bounded(value, 40).casefold()
    if raw.startswith("win"):
        return "windows"
    if raw.startswith("linux"):
        return "linux"
    if raw.startswith("darwin") or raw.startswith("mac"):
        return "darwin"
    return raw


def _normal_architecture(value: str) -> str:
    raw = _bounded(value, 40).casefold()
    aliases = {
        "amd64": "x86_64", "x64": "x86_64", "x86-64": "x86_64",
        "aarch64": "arm64", "armv8": "arm64", "armv8l": "arm64",
        "armhf": "armv7l", "armv7": "armv7l",
    }
    return aliases.get(raw, raw)


def _safe_relative(value: str, *, code: str) -> PurePosixPath:
    text = _bounded(value, 500).replace("\\", "/")
    path = PurePosixPath(text)
    if not text or path.is_absolute() or ".." in path.parts or any(part in {"", "."} for part in path.parts):
        raise AgentComponentError(code)
    return path


def _component_target(
    *, platform_name: str, architecture: str, distribution: str = "", codename: str = ""
) -> dict[str, str]:
    platform_key = _normal_platform(platform_name)
    architecture_key = _normal_architecture(architecture)
    if platform_key not in {"windows", "linux"}:
        raise AgentComponentError("AGENT_COMPONENT_PLATFORM_UNSUPPORTED")
    if architecture_key not in {"x86_64", "arm64", "armv7l"}:
        raise AgentComponentError("AGENT_COMPONENT_ARCHITECTURE_UNSUPPORTED")
    distro = _bounded(distribution, 40).casefold()
    release = _bounded(codename, 80).casefold()
    if platform_key != "linux":
        distro = ""
        release = ""
    return {
        "Platform": platform_key,
        "Architecture": architecture_key,
        "Distribution": distro,
        "Codename": release,
    }


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _json_bytes(raw: bytes, *, code: str, maximum: int = MAX_COMPONENT_MANIFEST_BYTES) -> dict[str, Any]:
    if len(raw) > maximum:
        raise AgentComponentError(f"{code}_TOO_LARGE")
    try:
        value = json.loads(raw.decode("utf-8-sig"))
    except Exception as exc:
        raise AgentComponentError(f"{code}_INVALID") from exc
    if not isinstance(value, Mapping):
        raise AgentComponentError(f"{code}_OBJECT_REQUIRED")
    return dict(value)


def _member_is_symlink(info: zipfile.ZipInfo) -> bool:
    return stat.S_ISLNK((int(info.external_attr) >> 16) & 0o177777)


def _safe_members(archive: zipfile.ZipFile) -> dict[str, zipfile.ZipInfo]:
    infos = archive.infolist()
    if not infos or len(infos) > MAX_COMPONENT_MEMBERS:
        raise AgentComponentError("AGENT_COMPONENT_MEMBER_COUNT_INVALID")
    result: dict[str, zipfile.ZipInfo] = {}
    folded: set[str] = set()
    total = 0
    for info in infos:
        if info.is_dir() or _member_is_symlink(info):
            raise AgentComponentError("AGENT_COMPONENT_MEMBER_TYPE_INVALID")
        relative = _safe_relative(info.filename, code="AGENT_COMPONENT_MEMBER_PATH_INVALID")
        name = str(relative)
        if name in result or name.casefold() in folded:
            raise AgentComponentError("AGENT_COMPONENT_MEMBER_DUPLICATE")
        if int(info.file_size) < 0 or int(info.file_size) > MAX_CATALOG_TOTAL_BYTES:
            raise AgentComponentError("AGENT_COMPONENT_MEMBER_SIZE_INVALID")
        total += int(info.file_size)
        if total > MAX_CATALOG_TOTAL_BYTES:
            raise AgentComponentError("AGENT_COMPONENT_TOTAL_SIZE_INVALID")
        result[name] = info
        folded.add(name.casefold())
    return result


def _payload_file_rows(stage: Path) -> dict[str, dict[str, Any]]:
    root = Path(stage).resolve()
    payload_root = root / Path(*COMPONENT_PAYLOAD_ROOT.parts)
    if not payload_root.is_dir() or payload_root.is_symlink():
        raise AgentComponentError("AGENT_COMPONENT_PAYLOAD_MISSING")
    rows: dict[str, dict[str, Any]] = {}
    folded: set[str] = set()
    for candidate in sorted(payload_root.rglob("*")):
        if candidate.is_symlink():
            raise AgentComponentError("AGENT_COMPONENT_PAYLOAD_SYMLINK")
        if candidate.is_dir():
            continue
        if not candidate.is_file():
            raise AgentComponentError("AGENT_COMPONENT_PAYLOAD_MEMBER_INVALID")
        relative = candidate.relative_to(root).as_posix()
        if relative.casefold() in folded:
            raise AgentComponentError("AGENT_COMPONENT_PAYLOAD_CASE_COLLISION")
        folded.add(relative.casefold())
        rows[relative] = {
            "Sha256": sha256_file(candidate),
            "SizeBytes": candidate.stat().st_size,
        }
    if not rows:
        raise AgentComponentError("AGENT_COMPONENT_PAYLOAD_EMPTY")
    return rows


def _tree_file_rows(stage: Path, relative_root: PurePosixPath) -> dict[str, dict[str, Any]]:
    root = Path(stage).resolve()
    payload_root = root / Path(*relative_root.parts)
    if not payload_root.is_dir() or payload_root.is_symlink():
        raise AgentComponentError("AGENT_SOURCE_COMPANION_PAYLOAD_MISSING")
    rows: dict[str, dict[str, Any]] = {}
    folded: set[str] = set()
    for candidate in sorted(payload_root.rglob("*")):
        if candidate.is_symlink():
            raise AgentComponentError("AGENT_SOURCE_COMPANION_PAYLOAD_SYMLINK")
        if candidate.is_dir():
            continue
        if not candidate.is_file():
            raise AgentComponentError("AGENT_SOURCE_COMPANION_PAYLOAD_MEMBER_INVALID")
        relative = candidate.relative_to(root).as_posix()
        if relative.casefold() in folded:
            raise AgentComponentError("AGENT_SOURCE_COMPANION_PAYLOAD_CASE_COLLISION")
        folded.add(relative.casefold())
        rows[relative] = {"Sha256": sha256_file(candidate), "SizeBytes": candidate.stat().st_size}
    if not rows:
        raise AgentComponentError("AGENT_SOURCE_COMPANION_PAYLOAD_EMPTY")
    return rows


def _read_catalog(path: Path) -> dict[str, Any]:
    return validate_catalog(_json_bytes(Path(path).read_bytes(), code="AGENT_COMPONENT_CATALOG"))


def stage_vlc_core_profile(
    payload_root: Path,
    *,
    platform_name: str,
    architecture: str,
    distribution: str = "",
    codename: str = "",
) -> dict[str, Any]:
    """Declare the separate VLC component without shipping VLC/legal bytes.

    This is intentionally tiny and contains neither a vendor binary nor GPL
    source material.  Its only purpose is to let the authenticated Agent report
    that a matching signed component is needed.  Existing full bundles remain
    valid because this function refuses to overwrite a staged reviewed kit.
    """

    target = _component_target(
        platform_name=platform_name,
        architecture=architecture,
        distribution=distribution,
        codename=codename,
    )
    root = Path(payload_root).resolve() / Path(*CATALOG_DIR_RELATIVE.parts)
    if (root / CATALOG_NAME).exists() or (root / CATALOG_SIGNATURE_NAME).exists():
        raise AgentComponentError("AGENT_COMPONENT_CORE_PROFILE_COLLIDES_WITH_BUNDLED_KIT")
    root.mkdir(parents=True, exist_ok=True)
    if root.is_symlink():
        raise AgentComponentError("AGENT_COMPONENT_CORE_PROFILE_PATH_INVALID")
    profile_path = root / PROFILE_NAME
    if profile_path.is_symlink() or any(path.name != PROFILE_NAME for path in root.iterdir()):
        # A core declaration must never silently coexist with pre-staged vendor
        # material.  The caller must explicitly choose the legacy bundled flow
        # or clear its temporary stage before building a small core.
        raise AgentComponentError("AGENT_COMPONENT_CORE_PROFILE_NOT_EMPTY")
    profile = {
        "Schema": OFFLINE_PROFILE_SCHEMA,
        "Bundled": False,
        "ExternalVlcOnly": True,
        "NetworkDownloads": False,
        "InstallRequiresSignedApproval": True,
        "ComponentDelivery": COMPONENT_DELIVERY,
        "ComponentSchema": COMPONENT_SCHEMA,
        "ComponentKind": COMPONENT_KIND,
        "Reason": "VLC_OFFLINE_COMPONENT_REQUIRED",
        "RequestedTarget": target,
    }
    profile_path.write_bytes(_canonical_json(profile))
    return {
        "Bundled": False,
        "Delivery": COMPONENT_DELIVERY,
        "ComponentSchema": COMPONENT_SCHEMA,
        "ComponentKind": COMPONENT_KIND,
        "Target": target,
        "RequiredFiles": [str(CATALOG_DIR_RELATIVE / PROFILE_NAME)],
    }


def _component_id(target: Mapping[str, str], catalog_version: str) -> str:
    parts = [COMPONENT_KIND, target["Platform"], target["Architecture"]]
    if target["Distribution"]:
        parts.extend((target["Distribution"], target["Codename"]))
    parts.append(_bounded(catalog_version, 160))
    return ":".join(parts)


def source_companion_catalog_reference(descriptor: Mapping[str, Any]) -> dict[str, Any]:
    """Return the signed-catalog reference for a built source companion."""
    return {
        "Schema": SOURCE_COMPANION_SCHEMA,
        "ArtifactName": _bounded(descriptor.get("artifact_name"), 244),
        "CatalogVersion": _bounded(descriptor.get("catalog_version"), 160),
        "SourceIds": sorted(str(item) for item in (descriptor.get("source_ids") or [])),
        "SizeBytes": int(descriptor.get("size_bytes") or 0),
        "Sha256": _bounded(descriptor.get("sha256"), 80).casefold(),
        "Signature": _bounded(descriptor.get("signature"), 512),
        "SignatureScheme": _bounded(descriptor.get("signature_scheme"), 120),
        "KeyId": _bounded(descriptor.get("key_id"), 120),
    }


def build_vlc_source_companion(
    app_root: Path,
    output: Path,
    *,
    platform_name: str,
    architecture: str,
    distribution: str = "",
    codename: str = "",
    signing_private_key: Path,
) -> dict[str, Any]:
    """Build a signed source-only archive for one reviewed VLC target.

    This archive intentionally contains no VLC installer or package payload.
    The returned whole-archive signature and digest are embedded into the
    separately signed operational catalog when ``vlc_delivery=detached``.
    """
    target = _component_target(
        platform_name=platform_name,
        architecture=architecture,
        distribution=distribution,
        codename=codename,
    )
    private_key = Path(signing_private_key).resolve()
    if not private_key.is_file():
        raise AgentComponentError("AGENT_SOURCE_COMPANION_SIGNING_KEY_MISSING")
    final = Path(output).resolve()
    if final.suffix.casefold() != ".zip" or final.name != Path(final.name).name:
        raise AgentComponentError("AGENT_SOURCE_COMPANION_ARCHIVE_EXTENSION_INVALID")
    final.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="gideon-agent-vlc-sources-") as temporary:
        stage = Path(temporary) / "source-companion"
        payload = stage / Path(*SOURCE_COMPANION_PAYLOAD_ROOT.parts)
        payload.mkdir(parents=True)
        staged = stage_offline_vlc_source_materials(
            Path(app_root),
            payload,
            platform_name=target["Platform"],
            architecture=target["Architecture"],
            distribution=target["Distribution"],
            codename=target["Codename"],
        )
        files = _tree_file_rows(stage, SOURCE_COMPANION_PAYLOAD_ROOT)
        legal = dict(staged["Legal"])
        manifest = {
            "Schema": SOURCE_COMPANION_SCHEMA,
            "CatalogVersion": str(staged["CatalogVersion"]),
            "Target": target,
            "SourceIds": list(staged["SourceIds"]),
            "Payload": {"Root": str(SOURCE_COMPANION_PAYLOAD_ROOT), "Files": files},
            "Legal": {
                "License": legal["License"],
                "RequiredFiles": list(legal["RequiredFiles"]),
                "Materials": list(legal["Materials"]),
                "BundledSources": list(legal["BundledSources"]),
            },
            "Integrity": {"ManifestSignature": "Ed25519", "Digest": "SHA-256"},
        }
        manifest_path = stage / SOURCE_COMPANION_MANIFEST_NAME
        manifest_path.write_bytes(_canonical_json(manifest))
        (stage / SOURCE_COMPANION_SIGNATURE_NAME).write_text(
            sign_file(manifest_path, private_key), encoding="ascii", newline="\n",
        )
        if final.exists():
            final.unlink()
        write_verified_deflated_zip(stage, final)
    artifact_sha256 = sha256_file(final)
    descriptor = {
        "schema": SOURCE_COMPANION_SCHEMA,
        "artifact": str(final),
        # Logical publication name is content-addressed.  The temporary build
        # filename is intentionally irrelevant so WebAdmin can deduplicate one
        # immutable companion across installer builds.
        "artifact_name": f"{artifact_sha256}.zip",
        "sha256": artifact_sha256,
        "size_bytes": final.stat().st_size,
        "signature": sign_sha256_digest(
            artifact_sha256, private_key, domain=SOURCE_COMPANION_SIGNATURE_DOMAIN,
        ),
        "signature_scheme": SOURCE_COMPANION_SIGNATURE_SCHEME,
        "key_id": SOURCE_COMPANION_KEY_ID,
        "catalog_version": str(manifest["CatalogVersion"]),
        "source_ids": list(manifest["SourceIds"]),
        "target": target,
    }
    descriptor["catalog_reference"] = source_companion_catalog_reference(descriptor)
    return descriptor


def verify_vlc_source_companion(
    archive_path: Path, public_key_path: Path, *, verify_payload: bool = True,
    expected_sha256: str = "",
) -> dict[str, Any]:
    """Verify a source companion without extracting it.

    ``verify_payload=False`` is used only after the content-addressed archive
    hash itself has been authenticated with Ed25519.  It still verifies the
    signed manifest, target and member inventory, but avoids decompressing and
    hashing hundreds of MB on every repeated Agent build.
    """
    archive_file = Path(archive_path).resolve()
    public_key = Path(public_key_path).resolve()
    if not archive_file.is_file() or archive_file.stat().st_size <= 0:
        raise AgentComponentError("AGENT_SOURCE_COMPANION_ARCHIVE_MISSING")
    if archive_file.stat().st_size > MAX_COMPONENT_ARCHIVE_BYTES:
        raise AgentComponentError("AGENT_SOURCE_COMPANION_ARCHIVE_TOO_LARGE")
    if not public_key.is_file():
        raise AgentComponentError("AGENT_SOURCE_COMPANION_PUBLIC_KEY_MISSING")
    try:
        with zipfile.ZipFile(archive_file, "r") as archive:
            members = _safe_members(archive)
            required_top = {SOURCE_COMPANION_MANIFEST_NAME, SOURCE_COMPANION_SIGNATURE_NAME}
            if not required_top.issubset(members):
                raise AgentComponentError("AGENT_SOURCE_COMPANION_MANIFEST_MISSING")
            payload_prefix = str(SOURCE_COMPANION_PAYLOAD_ROOT) + "/"
            if any(name not in required_top and not name.startswith(payload_prefix + "legal/") for name in members):
                raise AgentComponentError("AGENT_SOURCE_COMPANION_LAYOUT_INVALID")
            manifest_bytes = archive.read(members[SOURCE_COMPANION_MANIFEST_NAME])
            signature = archive.read(members[SOURCE_COMPANION_SIGNATURE_NAME]).decode("ascii").strip()
            with tempfile.TemporaryDirectory(prefix="gideon-agent-source-companion-verify-") as temporary:
                manifest_path = Path(temporary) / SOURCE_COMPANION_MANIFEST_NAME
                manifest_path.write_bytes(manifest_bytes)
                if not verify_file(manifest_path, signature, public_key):
                    raise AgentComponentError("AGENT_SOURCE_COMPANION_MANIFEST_SIGNATURE_INVALID")
            manifest = _json_bytes(manifest_bytes, code="AGENT_SOURCE_COMPANION_MANIFEST")
            if _bounded(manifest.get("Schema"), 100) != SOURCE_COMPANION_SCHEMA:
                raise AgentComponentError("AGENT_SOURCE_COMPANION_SCHEMA_INVALID")
            catalog_version = _bounded(manifest.get("CatalogVersion"), 160)
            target = manifest.get("Target")
            payload = manifest.get("Payload")
            legal = manifest.get("Legal")
            source_ids_raw = manifest.get("SourceIds")
            if not all(isinstance(item, Mapping) for item in (target, payload, legal)):
                raise AgentComponentError("AGENT_SOURCE_COMPANION_OBJECT_REQUIRED")
            normalized_target = _component_target(
                platform_name=str(target.get("Platform") or ""),
                architecture=str(target.get("Architecture") or ""),
                distribution=str(target.get("Distribution") or ""),
                codename=str(target.get("Codename") or ""),
            )
            if dict(target) != normalized_target or not catalog_version:
                raise AgentComponentError("AGENT_SOURCE_COMPANION_TARGET_INVALID")
            if not isinstance(source_ids_raw, list) or not source_ids_raw:
                raise AgentComponentError("AGENT_SOURCE_COMPANION_SOURCE_IDS_INVALID")
            source_ids = sorted({_bounded(item, 160) for item in source_ids_raw})
            if "" in source_ids or len(source_ids) != len(source_ids_raw):
                raise AgentComponentError("AGENT_SOURCE_COMPANION_SOURCE_IDS_INVALID")
            if _bounded(payload.get("Root"), 100) != str(SOURCE_COMPANION_PAYLOAD_ROOT):
                raise AgentComponentError("AGENT_SOURCE_COMPANION_PAYLOAD_ROOT_INVALID")
            if not isinstance(payload.get("Files"), Mapping):
                raise AgentComponentError("AGENT_SOURCE_COMPANION_FILES_REQUIRED")
            files = dict(payload["Files"])
            payload_names = {name for name in members if name.startswith(payload_prefix)}
            if set(files) != payload_names:
                raise AgentComponentError("AGENT_SOURCE_COMPANION_MEMBER_MISMATCH")
            for name, metadata in files.items():
                if not isinstance(metadata, Mapping):
                    raise AgentComponentError("AGENT_SOURCE_COMPANION_FILE_METADATA_INVALID")
                try:
                    declared_size = int(metadata.get("SizeBytes"))
                except (TypeError, ValueError) as exc:
                    raise AgentComponentError("AGENT_SOURCE_COMPANION_FILE_METADATA_INVALID") from exc
                declared_sha = _bounded(metadata.get("Sha256"), 80).casefold()
                if declared_size < 0 or len(declared_sha) != 64 or any(ch not in "0123456789abcdef" for ch in declared_sha):
                    raise AgentComponentError("AGENT_SOURCE_COMPANION_FILE_METADATA_INVALID")
                if verify_payload:
                    digest = hashlib.sha256()
                    size = 0
                    with archive.open(members[name], "r") as member_stream:
                        for chunk in iter(lambda: member_stream.read(1024 * 1024), b""):
                            size += len(chunk)
                            digest.update(chunk)
                    if size != declared_size or digest.hexdigest() != declared_sha:
                        raise AgentComponentError("AGENT_SOURCE_COMPANION_FILE_HASH_MISMATCH")
                elif members[name].file_size != declared_size:
                    raise AgentComponentError("AGENT_SOURCE_COMPANION_FILE_HASH_MISMATCH")
            if _bounded(legal.get("License"), 80) != "GPL-2.0-or-later":
                raise AgentComponentError("AGENT_SOURCE_COMPANION_LICENSE_INVALID")
            required_files = legal.get("RequiredFiles")
            materials = legal.get("Materials")
            bundled_sources = legal.get("BundledSources")
            if not all(isinstance(item, list) for item in (required_files, materials, bundled_sources)):
                raise AgentComponentError("AGENT_SOURCE_COMPANION_LEGAL_METADATA_INVALID")
            required_names = {payload_prefix + str(_safe_relative(item, code="AGENT_SOURCE_COMPANION_LEGAL_PATH_INVALID")) for item in required_files}
            if required_names != payload_names:
                raise AgentComponentError("AGENT_SOURCE_COMPANION_LEGAL_MEMBER_MISMATCH")
            material_rows = {
                payload_prefix + str(_safe_relative(row.get("Path"), code="AGENT_SOURCE_COMPANION_MATERIAL_PATH_INVALID")): row
                for row in materials if isinstance(row, Mapping)
            }
            if set(material_rows) != payload_names:
                raise AgentComponentError("AGENT_SOURCE_COMPANION_MATERIALS_INCOMPLETE")
            for name, row in material_rows.items():
                metadata = files[name]
                if (
                    int(row.get("SizeBytes") or -1) != int(metadata.get("SizeBytes") or -2)
                    or _bounded(row.get("Sha256"), 80).casefold() != _bounded(metadata.get("Sha256"), 80).casefold()
                ):
                    raise AgentComponentError("AGENT_SOURCE_COMPANION_MATERIAL_MISMATCH")
            bundled_ids = {
                _bounded(row.get("SourceId"), 160)
                for row in bundled_sources if isinstance(row, Mapping)
            }
            archive_ids = {
                _bounded(row.get("SourceId"), 160)
                for row in bundled_sources
                if isinstance(row, Mapping) and _bounded(row.get("Role"), 80) == "source-archive"
            }
            if bundled_ids != set(source_ids) or archive_ids != set(source_ids):
                raise AgentComponentError("AGENT_SOURCE_COMPANION_SOURCE_CLOSURE_INCOMPLETE")
    except AgentComponentError:
        raise
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        raise AgentComponentError("AGENT_SOURCE_COMPANION_ARCHIVE_INVALID") from exc
    artifact_sha256 = _bounded(expected_sha256, 80).casefold()
    if artifact_sha256:
        if len(artifact_sha256) != 64 or any(ch not in "0123456789abcdef" for ch in artifact_sha256):
            raise AgentComponentError("AGENT_SOURCE_COMPANION_HASH_INVALID")
    else:
        artifact_sha256 = sha256_file(archive_file)
    return {
        "schema": SOURCE_COMPANION_SCHEMA,
        "artifact": str(archive_file),
        "artifact_name": f"{artifact_sha256}.zip",
        "sha256": artifact_sha256,
        "size_bytes": archive_file.stat().st_size,
        "catalog_version": catalog_version,
        "source_ids": source_ids,
        "target": normalized_target,
    }


def resolve_vlc_source_companion(
    app_root: Path,
    *,
    platform_name: str,
    architecture: str,
    distribution: str = "",
    codename: str = "",
    signing_private_key: Path,
    signing_public_key: Path,
    source_companion_dir: Path,
    existing_descriptor: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Reuse a verified content-addressed companion or build it once.

    An explicitly supplied descriptor is fail-closed: it is never replaced by
    a newly built archive when any declared property is invalid.  Directory
    lookup is a convenience for callers that persist only the immutable
    ``<sha256>.zip`` object.
    """
    private_key = Path(signing_private_key).resolve()
    public_key = Path(signing_public_key).resolve()
    cache = Path(source_companion_dir).resolve()
    cache.mkdir(parents=True, exist_ok=True)
    if cache.is_symlink() or not private_key.is_file() or not public_key.is_file():
        raise AgentComponentError("AGENT_SOURCE_COMPANION_CACHE_INVALID")
    expected = offline_vlc_source_identity(
        app_root,
        platform_name=platform_name,
        architecture=architecture,
        distribution=distribution,
        codename=codename,
    )
    expected_target = _component_target(
        platform_name=platform_name,
        architecture=architecture,
        distribution=distribution,
        codename=codename,
    )

    def persist_descriptor(descriptor: Mapping[str, Any]) -> None:
        digest = _bounded(descriptor.get("sha256"), 80).casefold()
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise AgentComponentError("AGENT_SOURCE_COMPANION_HASH_INVALID")
        published = {
            key: value for key, value in dict(descriptor).items()
            if key != "catalog_reference"
        }
        # Keep cache metadata relocatable and free of temporary build paths.
        published["artifact"] = str(descriptor.get("artifact_name") or f"{digest}.zip")
        sidecar = cache / f"{digest}.source-companion.json"
        temporary = cache / f".{digest}.{os.getpid()}.tmp"
        temporary.write_bytes(_canonical_json(published) + b"\n")
        try:
            temporary.chmod(0o640)
        except OSError:
            pass
        os.replace(temporary, sidecar)

    def checked(path: Path, declared: Mapping[str, Any] | None) -> dict[str, Any]:
        candidate = Path(path).resolve()
        try:
            candidate.relative_to(cache)
        except ValueError as exc:
            raise AgentComponentError("AGENT_SOURCE_COMPANION_CACHE_ESCAPE") from exc
        digest = sha256_file(candidate)
        size = candidate.stat().st_size
        signature = ""
        if declared is not None:
            signature = _bounded(declared.get("signature"), 512)
            if not signature or not verify_sha256_digest(
                digest, signature, public_key, domain=SOURCE_COMPANION_SIGNATURE_DOMAIN,
            ):
                raise AgentComponentError("AGENT_SOURCE_COMPANION_ARCHIVE_SIGNATURE_INVALID")
        verified = verify_vlc_source_companion(
            candidate,
            public_key,
            verify_payload=declared is None,
            expected_sha256=digest,
        )
        if (
            verified["target"] != expected_target
            or str(verified["catalog_version"]) != str(expected["CatalogVersion"])
            or list(verified["source_ids"]) != list(expected["SourceIds"])
        ):
            raise AgentComponentError("AGENT_SOURCE_COMPANION_IDENTITY_MISMATCH")
        if declared is not None:
            if (
                _bounded(declared.get("schema"), 100) != SOURCE_COMPANION_SCHEMA
                or _bounded(declared.get("sha256"), 80).casefold() != digest
                or int(declared.get("size_bytes") or -1) != size
                or _bounded(declared.get("artifact_name"), 244) != f"{digest}.zip"
                or _bounded(declared.get("key_id"), 120) != SOURCE_COMPANION_KEY_ID
                or _bounded(declared.get("signature_scheme"), 120) != SOURCE_COMPANION_SIGNATURE_SCHEME
                or _bounded(declared.get("catalog_version"), 160) != str(expected["CatalogVersion"])
                or sorted(str(item) for item in (declared.get("source_ids") or [])) != list(expected["SourceIds"])
                or dict(declared.get("target") or {}) != expected_target
            ):
                raise AgentComponentError("AGENT_SOURCE_COMPANION_DESCRIPTOR_MISMATCH")
        else:
            if candidate.name != f"{digest}.zip":
                raise AgentComponentError("AGENT_SOURCE_COMPANION_CONTENT_NAME_MISMATCH")
            signature = sign_sha256_digest(
                digest, private_key, domain=SOURCE_COMPANION_SIGNATURE_DOMAIN,
            )
            if not verify_sha256_digest(
                digest, signature, public_key, domain=SOURCE_COMPANION_SIGNATURE_DOMAIN,
            ):
                raise AgentComponentError("AGENT_SOURCE_COMPANION_ARCHIVE_SIGNATURE_INVALID")
        descriptor = {
            "schema": SOURCE_COMPANION_SCHEMA,
            "artifact": str(candidate),
            "artifact_name": f"{digest}.zip",
            "sha256": digest,
            "size_bytes": size,
            "signature": signature,
            "signature_scheme": SOURCE_COMPANION_SIGNATURE_SCHEME,
            "key_id": SOURCE_COMPANION_KEY_ID,
            "catalog_version": str(expected["CatalogVersion"]),
            "source_ids": list(expected["SourceIds"]),
            "target": expected_target,
        }
        descriptor["catalog_reference"] = source_companion_catalog_reference(descriptor)
        return descriptor

    if existing_descriptor is not None:
        raw_path = str(
            existing_descriptor.get("artifact")
            or existing_descriptor.get("path")
            or existing_descriptor.get("rel")
            or ""
        ).strip()
        if not raw_path:
            raise AgentComponentError("AGENT_SOURCE_COMPANION_DESCRIPTOR_PATH_MISSING")
        candidate = Path(raw_path)
        if not candidate.is_absolute():
            candidate = cache / candidate
        resolved = checked(candidate, existing_descriptor)
        persist_descriptor(resolved)
        return resolved

    for sidecar in sorted(cache.glob("*.source-companion.json")):
        try:
            if sidecar.is_symlink() or sidecar.stat().st_size > MAX_COMPONENT_MANIFEST_BYTES:
                continue
            declared = _json_bytes(sidecar.read_bytes(), code="AGENT_SOURCE_COMPANION_DESCRIPTOR")
            raw_name = _bounded(declared.get("artifact_name"), 244)
            if not raw_name or raw_name != Path(raw_name).name:
                continue
            resolved = checked(cache / raw_name, declared)
            persist_descriptor(resolved)
            return resolved
        except (AgentComponentError, OSError, ValueError):
            continue

    for candidate in sorted(cache.glob("*.zip")):
        stem = candidate.stem.casefold()
        if len(stem) != 64 or any(char not in "0123456789abcdef" for char in stem):
            continue
        try:
            resolved = checked(candidate, None)
            persist_descriptor(resolved)
            return resolved
        except AgentComponentError:
            continue

    with tempfile.TemporaryDirectory(prefix="gideon-vlc-source-cache-", dir=cache) as temporary:
        temporary_archive = Path(temporary) / "source-companion.zip"
        built = build_vlc_source_companion(
            app_root,
            temporary_archive,
            platform_name=platform_name,
            architecture=architecture,
            distribution=distribution,
            codename=codename,
            signing_private_key=private_key,
        )
        final = cache / str(built["artifact_name"])
        if final.exists():
            built["artifact"] = str(final)
            resolved = checked(final, built)
            persist_descriptor(resolved)
            return resolved
        os.replace(temporary_archive, final)
    built["artifact"] = str(final)
    resolved = checked(final, built)
    persist_descriptor(resolved)
    return resolved


def build_vlc_offline_component(
    app_root: Path,
    output: Path,
    *,
    platform_name: str,
    architecture: str,
    distribution: str = "",
    codename: str = "",
    signing_private_key: Path,
) -> dict[str, Any]:
    """Build one complete, signed offline VLC component for an exact target.

    The reviewed source catalog remains untouched.  The component gets a
    filtered catalog for exactly the requested target, all required legal
    material, and an outer manifest signed by the same Ed25519 release key used
    for Agent installers.  A component can therefore be cached and reused by
    hash across multiple Agents without becoming a mutable package source.
    """

    target = _component_target(
        platform_name=platform_name,
        architecture=architecture,
        distribution=distribution,
        codename=codename,
    )
    private_key = Path(signing_private_key).resolve()
    if not private_key.is_file():
        raise AgentComponentError("AGENT_COMPONENT_SIGNING_KEY_MISSING")
    final = Path(output).resolve()
    if final.suffix.casefold() != ".zip":
        raise AgentComponentError("AGENT_COMPONENT_ARCHIVE_EXTENSION_INVALID")
    with tempfile.TemporaryDirectory(prefix="gideon-agent-vlc-component-") as temporary:
        stage = Path(temporary) / "component"
        payload = stage / "payload"
        payload.mkdir(parents=True)
        staged = stage_offline_vlc_bundle(
            Path(app_root),
            payload,
            platform_name=target["Platform"],
            architecture=target["Architecture"],
            distribution=target["Distribution"],
            codename=target["Codename"],
            signing_private_key=private_key,
            required=True,
        )
        if staged.get("Bundled") is not True:
            raise AgentComponentError("AGENT_COMPONENT_VLC_BUNDLE_REQUIRED")
        kit_root = payload / Path(*CATALOG_DIR_RELATIVE.parts)
        catalog = _read_catalog(kit_root / CATALOG_NAME)
        profile = _json_bytes((kit_root / PROFILE_NAME).read_bytes(), code="AGENT_COMPONENT_PROFILE")
        if profile.get("Schema") != OFFLINE_PROFILE_SCHEMA or profile.get("Bundled") is not True:
            raise AgentComponentError("AGENT_COMPONENT_PROFILE_INVALID")
        selected = [dict(row) for row in catalog["Variants"]]
        if len(selected) != 1:
            raise AgentComponentError("AGENT_COMPONENT_TARGET_VARIANT_AMBIGUOUS")
        variant = selected[0]
        if any(str(variant.get(key) or "") != target[key] for key in ("Platform", "Architecture", "Distribution", "Codename")):
            raise AgentComponentError("AGENT_COMPONENT_TARGET_VARIANT_MISMATCH")
        files = _payload_file_rows(stage)
        expected_catalog_rel = str(COMPONENT_PAYLOAD_ROOT / CATALOG_NAME)
        if files.get(expected_catalog_rel, {}).get("Sha256") != str(profile.get("CatalogSha256") or ""):
            raise AgentComponentError("AGENT_COMPONENT_CATALOG_PROFILE_MISMATCH")
        legal = dict(catalog["Legal"])
        manifest = {
            "Schema": COMPONENT_SCHEMA,
            "Component": {
                "Kind": COMPONENT_KIND,
                "Id": _component_id(target, str(catalog["CatalogVersion"])),
                "CatalogVersion": str(catalog["CatalogVersion"]),
            },
            "Delivery": {
                "Mode": COMPONENT_DELIVERY,
                "NetworkDownloads": False,
                "InstallRequiresSignedApproval": True,
                "InstallIsExplicit": True,
            },
            "Target": target,
            "Payload": {
                "Root": str(COMPONENT_PAYLOAD_ROOT),
                "CatalogSha256": str(profile.get("CatalogSha256") or ""),
                "CatalogSignature": str(CATALOG_SIGNATURE_NAME),
                "Files": files,
            },
            "Legal": {
                "License": legal["License"],
                "RequiredFiles": list(legal["RequiredFiles"]),
                "Materials": list(legal["Materials"]),
                "BundledSources": list(legal["BundledSources"]),
            },
            "Integrity": {"ManifestSignature": "Ed25519", "Digest": "SHA-256"},
        }
        manifest_path = stage / COMPONENT_MANIFEST_NAME
        manifest_path.write_bytes(_canonical_json(manifest))
        (stage / COMPONENT_SIGNATURE_NAME).write_text(sign_file(manifest_path, private_key), encoding="ascii", newline="\n")
        if final.exists():
            final.unlink()
        write_verified_deflated_zip(stage, final)
    return {
        "Schema": COMPONENT_SCHEMA,
        "ComponentId": manifest["Component"]["Id"],
        "Kind": COMPONENT_KIND,
        "Target": target,
        "CatalogSha256": manifest["Payload"]["CatalogSha256"],
        "Artifact": str(final),
        "SizeBytes": final.stat().st_size,
        "Sha256": sha256_file(final),
        "Signature": sign_file(final, private_key),
    }


def _validate_manifest(value: Mapping[str, Any], members: Mapping[str, zipfile.ZipInfo]) -> dict[str, Any]:
    manifest = dict(value)
    if _bounded(manifest.get("Schema"), 80) != COMPONENT_SCHEMA:
        raise AgentComponentError("AGENT_COMPONENT_SCHEMA_INVALID")
    component = manifest.get("Component")
    target = manifest.get("Target")
    payload = manifest.get("Payload")
    delivery = manifest.get("Delivery")
    legal = manifest.get("Legal")
    if not all(isinstance(item, Mapping) for item in (component, target, payload, delivery, legal)):
        raise AgentComponentError("AGENT_COMPONENT_MANIFEST_OBJECT_REQUIRED")
    if _bounded(component.get("Kind"), 80) != COMPONENT_KIND or not _bounded(component.get("Id"), 300):
        raise AgentComponentError("AGENT_COMPONENT_KIND_INVALID")
    normalized_target = _component_target(
        platform_name=str(target.get("Platform") or ""),
        architecture=str(target.get("Architecture") or ""),
        distribution=str(target.get("Distribution") or ""),
        codename=str(target.get("Codename") or ""),
    )
    if dict(target) != normalized_target:
        raise AgentComponentError("AGENT_COMPONENT_TARGET_NOT_NORMALIZED")
    if _bounded(delivery.get("Mode"), 80) != COMPONENT_DELIVERY:
        raise AgentComponentError("AGENT_COMPONENT_DELIVERY_INVALID")
    if delivery.get("NetworkDownloads") is not False or delivery.get("InstallRequiresSignedApproval") is not True:
        raise AgentComponentError("AGENT_COMPONENT_DELIVERY_SECURITY_INVALID")
    if _bounded(payload.get("Root"), 500) != str(COMPONENT_PAYLOAD_ROOT):
        raise AgentComponentError("AGENT_COMPONENT_PAYLOAD_ROOT_INVALID")
    if not isinstance(payload.get("Files"), Mapping):
        raise AgentComponentError("AGENT_COMPONENT_PAYLOAD_FILES_REQUIRED")
    declared = dict(payload["Files"])
    payload_names = {name for name in members if name.startswith(str(COMPONENT_PAYLOAD_ROOT) + "/")}
    if set(declared) != payload_names:
        raise AgentComponentError("AGENT_COMPONENT_PAYLOAD_MEMBER_MISMATCH")
    required = {
        str(COMPONENT_PAYLOAD_ROOT / CATALOG_NAME),
        str(COMPONENT_PAYLOAD_ROOT / CATALOG_SIGNATURE_NAME),
        str(COMPONENT_PAYLOAD_ROOT / PROFILE_NAME),
    }
    if not required.issubset(payload_names):
        raise AgentComponentError("AGENT_COMPONENT_PAYLOAD_REQUIRED_FILE_MISSING")
    catalog_digest = _bounded(payload.get("CatalogSha256"), 80).casefold()
    if len(catalog_digest) != 64 or any(char not in "0123456789abcdef" for char in catalog_digest):
        raise AgentComponentError("AGENT_COMPONENT_CATALOG_HASH_INVALID")
    if _bounded(legal.get("License"), 80) != "GPL-2.0-or-later":
        raise AgentComponentError("AGENT_COMPONENT_LEGAL_LICENSE_INVALID")
    if not isinstance(legal.get("RequiredFiles"), list) or not isinstance(legal.get("Materials"), list):
        raise AgentComponentError("AGENT_COMPONENT_LEGAL_METADATA_INVALID")
    return manifest


def verify_vlc_offline_component(archive_path: Path, public_key_path: Path) -> dict[str, Any]:
    """Verify a component without extracting it into an Agent installation.

    Both the outer component manifest and the embedded VLC catalog must verify
    with the existing GIDEON release key.  Every listed payload byte is SHA-256
    checked before a temporary validation tree is created.
    """

    archive_file = Path(archive_path).resolve()
    public_key = Path(public_key_path).resolve()
    if not archive_file.is_file() or archive_file.stat().st_size <= 0:
        raise AgentComponentError("AGENT_COMPONENT_ARCHIVE_MISSING")
    if archive_file.stat().st_size > MAX_COMPONENT_ARCHIVE_BYTES:
        raise AgentComponentError("AGENT_COMPONENT_ARCHIVE_TOO_LARGE")
    if not public_key.is_file():
        raise AgentComponentError("AGENT_COMPONENT_PUBLIC_KEY_MISSING")
    try:
        with zipfile.ZipFile(archive_file, "r") as archive:
            members = _safe_members(archive)
            required_top = {COMPONENT_MANIFEST_NAME, COMPONENT_SIGNATURE_NAME}
            if not required_top.issubset(members):
                raise AgentComponentError("AGENT_COMPONENT_MANIFEST_MISSING")
            if any(name not in required_top and not name.startswith(str(COMPONENT_PAYLOAD_ROOT) + "/") for name in members):
                raise AgentComponentError("AGENT_COMPONENT_LAYOUT_INVALID")
            manifest_bytes = archive.read(members[COMPONENT_MANIFEST_NAME])
            signature = archive.read(members[COMPONENT_SIGNATURE_NAME]).decode("ascii").strip()
            if not signature or len(signature) > 8_192:
                raise AgentComponentError("AGENT_COMPONENT_MANIFEST_SIGNATURE_INVALID")
            with tempfile.TemporaryDirectory(prefix="gideon-agent-component-verify-") as temporary:
                temporary_root = Path(temporary)
                manifest_path = temporary_root / COMPONENT_MANIFEST_NAME
                manifest_path.write_bytes(manifest_bytes)
                if not verify_file(manifest_path, signature, public_key):
                    raise AgentComponentError("AGENT_COMPONENT_MANIFEST_SIGNATURE_INVALID")
                manifest = _validate_manifest(_json_bytes(manifest_bytes, code="AGENT_COMPONENT_MANIFEST"), members)
                files = dict(manifest["Payload"]["Files"])
                for name, metadata in files.items():
                    if not isinstance(metadata, Mapping):
                        raise AgentComponentError("AGENT_COMPONENT_FILE_METADATA_INVALID")
                    expected_hash = _bounded(metadata.get("Sha256"), 80).casefold()
                    try:
                        expected_size = int(metadata.get("SizeBytes"))
                    except (TypeError, ValueError) as exc:
                        raise AgentComponentError("AGENT_COMPONENT_FILE_SIZE_INVALID") from exc
                    data = archive.read(members[name])
                    if len(data) != expected_size or hashlib.sha256(data).hexdigest() != expected_hash:
                        raise AgentComponentError("AGENT_COMPONENT_FILE_HASH_MISMATCH")
                    output = temporary_root / "agent" / Path(*PurePosixPath(name).parts[1:])
                    output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_bytes(data)
                agent_root = temporary_root / "agent"
                # Validates the filtered catalog, its inner signature, every
                # artifact, and every corresponding GPL material.
                installed = validate_installed_offline_vlc_catalog(agent_root, public_key)
                catalog_rel = str(COMPONENT_PAYLOAD_ROOT / CATALOG_NAME)
                if files[catalog_rel]["Sha256"] != str(manifest["Payload"]["CatalogSha256"]):
                    raise AgentComponentError("AGENT_COMPONENT_CATALOG_HASH_MISMATCH")
    except AgentComponentError:
        raise
    except (OSError, zipfile.BadZipFile, OfflineVlcCatalogError) as exc:
        raise AgentComponentError("AGENT_COMPONENT_ARCHIVE_INVALID") from exc
    return {
        "Schema": COMPONENT_SCHEMA,
        "ComponentId": str(manifest["Component"]["Id"]),
        "Kind": COMPONENT_KIND,
        "Target": dict(manifest["Target"]),
        "CatalogSha256": str(manifest["Payload"]["CatalogSha256"]),
        "Variant": str(installed["Variant"]),
        "CatalogVersion": str(installed["CatalogVersion"]),
        "SizeBytes": archive_file.stat().st_size,
        "Sha256": sha256_file(archive_file),
    }


def stage_verified_vlc_component_payload(
    archive_path: Path, public_key_path: Path, staging_root: Path
) -> dict[str, Any]:
    """Materialize a verified component into an empty caller-owned staging dir.

    This deliberately stops before activation or installation.  A future Agent
    job handler can perform its own audit/maintenance gate and atomically swap
    this prepared ``third_party/vlc-offline`` directory only after receiving a
    signed job.  The function refuses a nonempty destination to prevent a
    component from silently merging with an older kit.
    """

    destination = Path(staging_root).resolve()
    if destination.exists() and any(destination.iterdir()):
        raise AgentComponentError("AGENT_COMPONENT_STAGE_NOT_EMPTY")
    destination.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink():
        raise AgentComponentError("AGENT_COMPONENT_STAGE_PATH_INVALID")
    # Verify an immutable private copy, rather than verifying a source path and
    # later reopening that mutable path for extraction.  Components can be very
    # large, so this streams to disk instead of loading an archive into memory.
    with tempfile.TemporaryDirectory(prefix="gideon-agent-component-stage-") as temporary:
        trusted_copy = Path(temporary) / "component.zip"
        with Path(archive_path).open("rb") as source, trusted_copy.open("wb") as copied:
            shutil.copyfileobj(source, copied, length=1024 * 1024)
        descriptor = verify_vlc_offline_component(trusted_copy, public_key_path)
        with zipfile.ZipFile(trusted_copy, "r") as archive:
            members = _safe_members(archive)
            for name, info in members.items():
                if not name.startswith(str(COMPONENT_PAYLOAD_ROOT) + "/"):
                    continue
                output = destination / Path(*PurePosixPath(name).parts[1:])
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_bytes(archive.read(info))
    expected = destination / Path(*CATALOG_DIR_RELATIVE.parts) / CATALOG_NAME
    if not expected.is_file():
        raise AgentComponentError("AGENT_COMPONENT_STAGE_CATALOG_MISSING")
    return descriptor


__all__ = [
    "AgentComponentError",
    "COMPONENT_DELIVERY",
    "COMPONENT_KIND",
    "COMPONENT_MANIFEST_NAME",
    "COMPONENT_SCHEMA",
    "SOURCE_COMPANION_MANIFEST_NAME",
    "SOURCE_COMPANION_SIGNATURE_NAME",
    "build_vlc_source_companion",
    "build_vlc_offline_component",
    "resolve_vlc_source_companion",
    "source_companion_catalog_reference",
    "stage_verified_vlc_component_payload",
    "stage_vlc_core_profile",
    "verify_vlc_source_companion",
    "verify_vlc_offline_component",
]
