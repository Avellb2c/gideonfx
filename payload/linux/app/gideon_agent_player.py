#!/usr/bin/env python3
from __future__ import annotations

"""Isolated, external-VLC player runtime for GIDEON Agents.

This module intentionally has two very different responsibilities:

* ``PlayerAgentBridge`` runs *inside* the normal Agent only long enough to
  verify a signed campaign manifest, re-verify the already transferred media
  cache, and publish a credential-free local document.
* ``DesktopPlayerRuntime`` is a separate, optional desktop process.  It has no
  Gateway URL, bearer token, mTLS certificate, reverse-tunnel handle, or Job
  executor.  It reads the accepted local manifest and starts only an external
  VLC executable.

Keeping those boundaries explicit is important: a broken media file, a VLC
crash, or the absence of an interactive desktop must never make the Agent
service, transfers, remote support, or reverse tunnel unavailable.

VLC is never linked into or downloaded by this runtime.  A reviewed Agent
installer/update may carry separate, unmodified vendor packages plus their
corresponding GPL source for an explicitly authorised offline installation.
The notice ``THIRD_PARTY_VLC_NOTICE.txt`` documents that external dependency.
"""

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from gideon_agent_bootstrap import PRIVATE_FILE_MODE, PUBLIC_STATUS_MODE, atomic_json, enforce_path_mode
from gideon_agent_display_capability import (
    LOCAL_WAYLAND_SESSION,
    PHYSICAL_CONNECTOR,
    detect_display_capability,
)


PLAYER_RUNTIME_VERSION = "1.2.0"
PLAYER_MANIFEST_SCHEMA = "gideon-media-player-manifest/v1"
PLAYER_STATUS_SCHEMA = "gideon-agent-player-status/v1"
PLAYER_CACHE_SCHEMA = "gideon-agent-player-cache/v1"
MAX_MANIFEST_BYTES = 512 * 1024
MAX_SCREENS = 32
MAX_PLAYLIST_ITEMS = 120
MAX_ASSET_BYTES = 16 * 1024 * 1024 * 1024
REPORT_INTERVAL_SECONDS = 60.0
MANIFEST_SYNC_INTERVAL_SECONDS = 30.0
RESTART_INITIAL_SECONDS = 5.0
RESTART_MAX_SECONDS = 300.0
HUMAN_ACTIVITY_IDLE_SECONDS = 90
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_SAFE_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,179}\.mp4$", re.I)
_VLC_CLI_VERSION = re.compile(
    r"^(?:VLC media player|VLC version)\s+"
    r"[0-9]+(?:\.[0-9]+){1,3}(?:[-+~._A-Za-z0-9]*)?(?:\s+.*)?$",
    re.I,
)
_PACKAGE_VERSION = re.compile(r"^[0-9][0-9A-Za-z.+:~_-]{0,119}$")


class PlayerManifestError(RuntimeError):
    """A signed manifest or its local media references are unsafe/unusable."""


class PlayerAssetPending(PlayerManifestError):
    """A valid manifest arrived before Phase 2 transfer finished."""


class PlayerOutputMappingError(PlayerManifestError):
    """A multi-monitor output has no safe local VLC screen mapping."""


def now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def _bounded(value: Any, limit: int = 240) -> str:
    return str(value or "").replace("\x00", " ").strip()[:limit]


def _safe_error(exc: BaseException | str, limit: int = 320) -> str:
    if isinstance(exc, BaseException):
        return _bounded(f"{type(exc).__name__}: {exc}", limit)
    return _bounded(exc, limit)


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    """Canonical bytes signed by WebAdmin and verified by every Agent."""
    return (json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _parse_iso(value: Any, *, name: str, required: bool = False) -> dt.datetime | None:
    text = _bounded(value, 80)
    if not text:
        if required:
            raise PlayerManifestError(f"PLAYER_MANIFEST_{name.upper()}_MISSING")
        return None
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PlayerManifestError(f"PLAYER_MANIFEST_{name.upper()}_INVALID") from exc
    if parsed.tzinfo is None:
        raise PlayerManifestError(f"PLAYER_MANIFEST_{name.upper()}_TIMEZONE_REQUIRED")
    return parsed.astimezone(dt.timezone.utc)


def _clean_id(value: Any, *, name: str, maximum: int = 160) -> str:
    text = _bounded(value, maximum)
    if not _SAFE_ID.fullmatch(text):
        raise PlayerManifestError(f"PLAYER_MANIFEST_{name.upper()}_INVALID")
    return text


def _positive_int(value: Any, *, name: str, maximum: int, minimum: int = 0) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise PlayerManifestError(f"PLAYER_MANIFEST_{name.upper()}_INVALID") from exc
    if number < minimum or number > maximum:
        raise PlayerManifestError(f"PLAYER_MANIFEST_{name.upper()}_OUT_OF_RANGE")
    return number


def _status_int(value: Any, *, maximum: int, default: int = 0) -> int:
    """Read untrusted desktop-status counters without affecting the Agent.

    The interactive companion may write its observable status through a narrow
    local ACL.  That status is intentionally never a control-plane authority,
    so malformed values must degrade to a bounded counter rather than throw
    inside the Agent heartbeat.
    """
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return max(0, min(number, maximum))


def _policy_bool(value: Any, *, default: bool) -> bool:
    """Read signed policy flags without treating the text ``false`` as true."""
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().casefold() in {"1", "true", "yes", "on", "si", "sí"}


def _media_root_for(platform_name: str | None = None) -> Path:
    platform_id = _bounded(platform_name or ("windows" if os.name == "nt" else sys.platform), 32).casefold()
    if platform_id.startswith("win"):
        # This is intentionally a fixed logical GIDEON cache, not a remote
        # manifest-controlled path.  Phase 2 transfers use the same location.
        return Path(os.environ.get("SystemDrive", "C:") + r"\GIDEON\Distribucion\Videos")
    if platform_id.startswith("darwin") or platform_id.startswith("mac"):
        return Path("/Library/Application Support/GIDEON/Distribucion/Videos")
    return Path("/opt/gideon/Distribucion/Videos")


def _safe_media_path(media_root: Path, file_name: Any) -> Path:
    name = _bounded(file_name, 200)
    if not _SAFE_FILENAME.fullmatch(name) or Path(name).name != name:
        raise PlayerManifestError("PLAYER_MANIFEST_ASSET_FILENAME_INVALID")
    root, _root_stat = _secure_media_root(media_root)
    # ``name`` is a flat allow-listed basename.  Do not resolve this path:
    # resolving would hide an unexpected symlink below MediaRoot from later
    # checks.  The caller validates the final regular file before hashing or
    # passing it to VLC.
    target = root / name
    if target.parent != root:
        raise PlayerManifestError("PLAYER_MANIFEST_ASSET_PATH_ESCAPE")
    return target


def _insecure_posix_mode(mode: int) -> bool:
    """Whether a local group or every local account can replace media."""
    return os.name != "nt" and bool(int(mode) & 0o022)


def _secure_media_root(media_root: Path) -> tuple[Path, os.stat_result]:
    """Return a non-link MediaRoot which cannot be changed by group/world.

    The service verifies an asset before exposing it to a desktop process.  A
    group-writable directory or a symlink would let a local account replace a
    video after that verification, therefore it is an unavailable cache rather
    than a permissive compatibility case.  We intentionally do not require a
    fixed owner here: controlled test roots and supported installations may use
    a dedicated service account, but every asset must match this root's owner.
    """
    root = Path(media_root)
    try:
        root_stat = root.lstat()
    except OSError as exc:
        raise PlayerAssetPending("PLAYER_MEDIA_ROOT_UNAVAILABLE") from exc
    if root.is_symlink() or not stat.S_ISDIR(root_stat.st_mode):
        raise PlayerAssetPending("PLAYER_MEDIA_ROOT_UNSAFE")
    if _insecure_posix_mode(root_stat.st_mode):
        raise PlayerAssetPending("PLAYER_MEDIA_ROOT_GROUP_OR_WORLD_WRITABLE")
    return root.absolute(), root_stat


def _secure_media_file_stat(media_root: Path, file_name: Any) -> tuple[Path, os.stat_result]:
    """Validate a single flat cache asset without following a local symlink."""
    root, root_stat = _secure_media_root(media_root)
    target = _safe_media_path(root, file_name)
    try:
        file_stat = target.lstat()
    except FileNotFoundError as exc:
        raise PlayerAssetPending("PLAYER_MEDIA_FILE_MISSING") from exc
    except OSError as exc:
        raise PlayerAssetPending("PLAYER_MEDIA_FILE_UNAVAILABLE") from exc
    if target.is_symlink() or not stat.S_ISREG(file_stat.st_mode):
        raise PlayerAssetPending("PLAYER_MEDIA_FILE_UNSAFE")
    if _insecure_posix_mode(file_stat.st_mode):
        raise PlayerAssetPending("PLAYER_MEDIA_FILE_GROUP_OR_WORLD_WRITABLE")
    if os.name != "nt":
        if int(file_stat.st_uid) != int(root_stat.st_uid):
            raise PlayerAssetPending("PLAYER_MEDIA_FILE_OWNER_MISMATCH")
        # A hard link could be modified through a second path after the cache
        # has been verified.  Phase-2 transfers publish one private cache file
        # per asset, so links are not required for normal operation.
        if int(file_stat.st_nlink) != 1:
            raise PlayerAssetPending("PLAYER_MEDIA_FILE_LINKED")
    return target, file_stat


def _read_local_output_map(path: Path) -> dict[str, int]:
    """Read the optional root-owned VLC screen map without trusting desktop input.

    The campaign binds a screen to a hardware identity.  Qt/VLC screen ordering
    is OS/session-specific, so a multi-monitor desktop needs one local,
    administrator-confirmed mapping.  The mapping contains no credentials and
    is deliberately not campaign-controlled or writable by the desktop user.
    """
    candidate = Path(path)
    try:
        parent = candidate.parent.lstat()
        media_root = candidate.parent.parent
        media_root_stat = media_root.lstat()
    except OSError as exc:
        raise PlayerOutputMappingError("PLAYER_OUTPUT_MAPPING_PATH_UNAVAILABLE") from exc
    if (
        candidate.parent.is_symlink()
        or media_root.is_symlink()
        or not stat.S_ISDIR(parent.st_mode)
        or not stat.S_ISDIR(media_root_stat.st_mode)
        or _insecure_posix_mode(parent.st_mode)
        or _insecure_posix_mode(media_root_stat.st_mode)
    ):
        raise PlayerOutputMappingError("PLAYER_OUTPUT_MAPPING_PATH_UNSAFE")
    # The exchange directory must be owned by the same protected principal as
    # the managed media root. Otherwise an interactive desktop user could
    # replace a privately permissioned .gideon-player below a writable cache.
    if os.name != "nt" and int(parent.st_uid) != int(media_root_stat.st_uid):
        raise PlayerOutputMappingError("PLAYER_OUTPUT_MAPPING_OWNER_MISMATCH")
    try:
        item = candidate.lstat()
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise PlayerOutputMappingError("PLAYER_OUTPUT_MAPPING_UNAVAILABLE") from exc
    if candidate.is_symlink() or not stat.S_ISREG(item.st_mode) or _insecure_posix_mode(item.st_mode):
        raise PlayerOutputMappingError("PLAYER_OUTPUT_MAPPING_UNSAFE")
    if os.name != "nt" and int(item.st_uid) != int(parent.st_uid):
        raise PlayerOutputMappingError("PLAYER_OUTPUT_MAPPING_OWNER_MISMATCH")
    if int(item.st_size) > 64 * 1024:
        raise PlayerOutputMappingError("PLAYER_OUTPUT_MAPPING_TOO_LARGE")
    try:
        document = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError) as exc:
        raise PlayerOutputMappingError("PLAYER_OUTPUT_MAPPING_INVALID") from exc
    if not isinstance(document, Mapping) or document.get("Schema") != "gideon-player-output-map/v1":
        raise PlayerOutputMappingError("PLAYER_OUTPUT_MAPPING_INVALID")
    outputs = document.get("Outputs")
    if not isinstance(outputs, list) or len(outputs) > 24:
        raise PlayerOutputMappingError("PLAYER_OUTPUT_MAPPING_INVALID")
    mapping: dict[str, int] = {}
    used_numbers: set[int] = set()
    for raw in outputs:
        if not isinstance(raw, Mapping):
            raise PlayerOutputMappingError("PLAYER_OUTPUT_MAPPING_INVALID")
        try:
            identity = _clean_id(raw.get("OutputIdentity"), name="output_mapping_identity").casefold()
            screen_number = _positive_int(raw.get("VlcScreenNumber"), name="output_mapping_screen", minimum=1, maximum=24)
        except PlayerManifestError as exc:
            raise PlayerOutputMappingError("PLAYER_OUTPUT_MAPPING_INVALID") from exc
        if identity in mapping or screen_number in used_numbers:
            raise PlayerOutputMappingError("PLAYER_OUTPUT_MAPPING_DUPLICATE")
        mapping[identity] = screen_number
        used_numbers.add(screen_number)
    return mapping


def _same_media_file(left: os.stat_result, right: os.stat_result) -> bool:
    """Compare the stable fields that matter across an open/hash operation."""
    return (
        int(left.st_dev) == int(right.st_dev)
        and int(left.st_ino) == int(right.st_ino)
        and int(left.st_size) == int(right.st_size)
        and int(left.st_mtime_ns) == int(right.st_mtime_ns)
    )


def _sha256_secure_media_file(path: Path, expected: os.stat_result) -> str:
    """Hash a previously validated asset while rejecting a replacement race."""
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= int(getattr(os, "O_BINARY"))
    # Linux/BSD reject a symlink at open time as well as during lstat. Windows
    # lacks O_NOFOLLOW; the before/open/after identity checks still fail closed
    # if the path was swapped on a supported NTFS filesystem.
    if hasattr(os, "O_NOFOLLOW"):
        flags |= int(getattr(os, "O_NOFOLLOW"))
    if hasattr(os, "O_CLOEXEC"):
        flags |= int(getattr(os, "O_CLOEXEC"))
    try:
        descriptor = os.open(str(path), flags)
    except OSError as exc:
        raise PlayerAssetPending("PLAYER_MEDIA_FILE_OPEN_REJECTED") from exc
    digest = hashlib.sha256()
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode) or _insecure_posix_mode(opened.st_mode) or not _same_media_file(expected, opened):
                raise PlayerAssetPending("PLAYER_MEDIA_FILE_CHANGED_DURING_VERIFY")
            while True:
                block = handle.read(1024 * 1024)
                if not block:
                    break
                digest.update(block)
            finished = os.fstat(handle.fileno())
            if not _same_media_file(opened, finished):
                raise PlayerAssetPending("PLAYER_MEDIA_FILE_CHANGED_DURING_VERIFY")
    except PlayerAssetPending:
        raise
    except OSError as exc:
        raise PlayerAssetPending("PLAYER_MEDIA_FILE_HASH_FAILED") from exc
    return digest.hexdigest()


def _process_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        if os.name == "nt":
            completed = subprocess.run(
                ["tasklist.exe", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                timeout=3,
                creationflags=0x08000000,
                check=False,
            )
            return str(pid) in str(completed.stdout or "")
        stat = Path(f"/proc/{pid}/stat")
        if stat.is_file():
            raw = stat.read_text(encoding="utf-8", errors="replace")
            end = raw.rfind(")")
            fields = raw[end + 2:].split() if end >= 0 else []
            if fields and fields[0] == "Z":
                return False
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def _terminate_owned_process(proc: subprocess.Popen[Any], *, grace_seconds: float = 4.0) -> None:
    """Terminate only a process started by this Player instance."""
    if proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill.exe", "/PID", str(proc.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=max(5.0, grace_seconds + 2.0),
                creationflags=0x08000000,
                check=False,
            )
            return
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        deadline = time.monotonic() + grace_seconds
        while proc.poll() is None and time.monotonic() < deadline:
            time.sleep(0.1)
        if proc.poll() is None:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except Exception:
        try:
            proc.terminate()
        except Exception:
            pass


def _atomic_bytes(path: Path, data: bytes, *, mode: int = PRIVATE_FILE_MODE) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}.{time.time_ns()}")
    try:
        tmp.write_bytes(data)
        enforce_path_mode(tmp, mode)
        os.replace(tmp, path)
        enforce_path_mode(path, mode)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def _read_json(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        if len(raw) > MAX_MANIFEST_BYTES:
            return {}
        value = json.loads(raw.decode("utf-8-sig"))
        return dict(value) if isinstance(value, Mapping) else {}
    except Exception:
        return {}


@dataclass(frozen=True, slots=True)
class PlayerAsset:
    asset_id: str
    sha256: str
    file_name: str
    size_bytes: int
    duration_ms: int


def _checked_media_asset(asset: PlayerAsset, media_root: Path, *, verify_hash: bool) -> tuple[Path, os.stat_result]:
    """Return a safe cache file only after local ownership/mode checks.

    ``verify_hash=False`` is used only by the short desktop refresh cache after
    this function has re-checked the directory/file security boundary.  A
    changed size or mtime invalidates that cache and triggers a fresh hash.
    """
    target, file_stat = _secure_media_file_stat(media_root, asset.file_name)
    if asset.size_bytes and int(file_stat.st_size) != asset.size_bytes:
        raise PlayerAssetPending("PLAYER_MEDIA_SIZE_MISMATCH:" + asset.asset_id)
    if verify_hash:
        digest = _sha256_secure_media_file(target, file_stat).lower()
        if digest != asset.sha256:
            raise PlayerAssetPending("PLAYER_MEDIA_SHA256_MISMATCH:" + asset.asset_id)
    return target, file_stat


@dataclass(frozen=True, slots=True)
class PlayerAssignment:
    screen_id: str
    output_key: str
    output_identity: str
    target_kind: str
    output_label: str
    orientation: str
    resolution: str
    campaign_id: str
    revision_no: int
    playlist: tuple[PlayerAsset, ...]
    fullscreen: bool
    kiosk: bool
    volume: int
    physical_output: bool
    session_independence: str
    screen_mode: str
    pause_on_human_activity: bool
    emergency_takeover: bool


@dataclass(frozen=True, slots=True)
class VerifiedManifest:
    envelope: dict[str, Any]
    manifest_version: int
    manifest_sha256: str
    key_id: str
    issued_at: str
    expires_at: str
    assignments: tuple[PlayerAssignment, ...]


def _read_asset(value: Mapping[str, Any], *, index: int) -> PlayerAsset:
    source = value.get("Asset") if isinstance(value.get("Asset"), Mapping) else value
    if not isinstance(source, Mapping):
        raise PlayerManifestError("PLAYER_MANIFEST_PLAYLIST_ITEM_INVALID")
    asset_id = _clean_id(source.get("AssetId") or source.get("asset_id") or f"asset-{index}", name="asset_id")
    digest = _bounded(source.get("Sha256") or source.get("sha256"), 64).casefold()
    if not _SHA256.fullmatch(digest):
        raise PlayerManifestError("PLAYER_MANIFEST_ASSET_SHA256_INVALID")
    file_name = _bounded(source.get("FileName") or source.get("file_name"), 200)
    if not _SAFE_FILENAME.fullmatch(file_name) or Path(file_name).name != file_name:
        raise PlayerManifestError("PLAYER_MANIFEST_ASSET_FILENAME_INVALID")
    size = _positive_int(source.get("SizeBytes") or source.get("size_bytes") or 0, name="asset_size", maximum=MAX_ASSET_BYTES)
    duration = _positive_int(source.get("DurationMs") or source.get("duration_ms") or 0, name="asset_duration", maximum=24 * 60 * 60 * 1000)
    return PlayerAsset(asset_id=asset_id, sha256=digest, file_name=file_name, size_bytes=size, duration_ms=duration)


def _read_assignment(value: Mapping[str, Any], *, index: int) -> PlayerAssignment:
    if not isinstance(value, Mapping):
        raise PlayerManifestError("PLAYER_MANIFEST_SCREEN_INVALID")
    screen_id = _clean_id(value.get("ScreenId") or value.get("screen_id"), name="screen_id")
    output_key = _clean_id(value.get("OutputKey") or value.get("output_key"), name="output_key")
    raw_identity = value.get("OutputIdentity") or value.get("output_identity") or output_key
    output_identity = _clean_id(raw_identity, name="output_identity")
    output_label = _bounded(value.get("OutputLabel") or value.get("output_label") or f"Pantalla {index + 1}", 100)
    orientation = _bounded(value.get("Orientation") or value.get("orientation") or "landscape", 24).casefold()
    if orientation not in {"landscape", "portrait", "inverted", "unknown"}:
        raise PlayerManifestError("PLAYER_MANIFEST_ORIENTATION_INVALID")
    resolution = _bounded(value.get("Resolution") or value.get("resolution"), 32)
    if resolution and not re.fullmatch(r"\d{2,5}x\d{2,5}", resolution):
        raise PlayerManifestError("PLAYER_MANIFEST_RESOLUTION_INVALID")
    campaign_id = _clean_id(value.get("CampaignId") or value.get("campaign_id"), name="campaign_id")
    revision = _positive_int(value.get("RevisionNo") or value.get("revision_no"), name="revision", minimum=1, maximum=2_147_483_647)
    raw_playlist = value.get("Playlist") if isinstance(value.get("Playlist"), list) else value.get("playlist")
    if not isinstance(raw_playlist, list) or not raw_playlist or len(raw_playlist) > MAX_PLAYLIST_ITEMS:
        raise PlayerManifestError("PLAYER_MANIFEST_PLAYLIST_INVALID")
    playlist = tuple(_read_asset(item, index=item_index) for item_index, item in enumerate(raw_playlist))
    policy = value.get("Policy") if isinstance(value.get("Policy"), Mapping) else value.get("policy")
    policy = dict(policy) if isinstance(policy, Mapping) else {}
    # Newer manifest builders keep display-binding metadata inside Policy;
    # accept the earlier top-level form too so a signed revision remains
    # portable across staged WebAdmin/Agent rollout.
    policy_identity = policy.get("OutputIdentity") or policy.get("output_identity")
    if policy_identity:
        output_identity = _clean_id(policy_identity, name="output_identity")
    target_kind = _bounded(
        value.get("TargetKind")
        or value.get("target_kind")
        or policy.get("TargetKind")
        or policy.get("target_kind")
        or PHYSICAL_CONNECTOR,
        64,
    ).upper()
    if target_kind not in {PHYSICAL_CONNECTOR, LOCAL_WAYLAND_SESSION}:
        raise PlayerManifestError("PLAYER_MANIFEST_TARGET_KIND_INVALID")
    fullscreen = _policy_bool(policy.get("Fullscreen", policy.get("fullscreen")), default=True)
    kiosk = _policy_bool(policy.get("Kiosk", policy.get("kiosk")), default=True)
    volume = _positive_int(policy.get("Volume", policy.get("volume", 100)), name="volume", maximum=100)
    # Legacy signed manifests pre-date explicit physical-screen policy.  They
    # retain the safest compatible semantics: one dedicated physical output,
    # independent of RDP or a named user session.  New manifests make that
    # intent explicit below.
    physical_output = _policy_bool(
        policy.get("PhysicalOutput", policy.get("physical_output")),
        default=target_kind == PHYSICAL_CONNECTOR,
    )
    session_independence = _bounded(
        policy.get(
            "SessionIndependence",
            policy.get(
                "session_independence",
                "LOCAL_WAYLAND_SESSION" if target_kind == LOCAL_WAYLAND_SESSION else "PERSISTENT_PHYSICAL_OUTPUT",
            ),
        ),
        64,
    ).upper()
    valid_session_policies = (
        {"LOCAL_WAYLAND_SESSION"}
        if target_kind == LOCAL_WAYLAND_SESSION
        else {"PERSISTENT_PHYSICAL_OUTPUT", "PHYSICAL_OUTPUT", "PHYSICAL_DISPLAY"}
    )
    if session_independence not in valid_session_policies:
        raise PlayerManifestError("PLAYER_MANIFEST_SESSION_INDEPENDENCE_INVALID")
    if target_kind == PHYSICAL_CONNECTOR and not physical_output:
        raise PlayerManifestError("PLAYER_MANIFEST_PHYSICAL_OUTPUT_REQUIRED")
    if target_kind == LOCAL_WAYLAND_SESSION and physical_output:
        raise PlayerManifestError("PLAYER_MANIFEST_LOCAL_WAYLAND_CANNOT_BE_PHYSICAL")
    screen_mode = _bounded(policy.get("ScreenMode", policy.get("screen_mode", "DEDICATED")), 64).upper()
    if screen_mode not in {"DEDICATED", "SHARED_PAUSE_ON_HUMAN_ACTIVITY"}:
        raise PlayerManifestError("PLAYER_MANIFEST_SCREEN_MODE_INVALID")
    pause_on_human_activity = _policy_bool(policy.get("PauseOnHumanActivity", policy.get("pause_on_human_activity")), default=False)
    # ScreenMode is authoritative for the user-friendly policy.  Keep the
    # explicit boolean as a compatibility alias for early Phase 3 manifests.
    pause_on_human_activity = pause_on_human_activity or screen_mode == "SHARED_PAUSE_ON_HUMAN_ACTIVITY"
    emergency_takeover = _policy_bool(policy.get("EmergencyTakeover", policy.get("emergency_takeover")), default=False)
    return PlayerAssignment(
        screen_id=screen_id,
        output_key=output_key,
        output_identity=output_identity,
        target_kind=target_kind,
        output_label=output_label,
        orientation=orientation,
        resolution=resolution,
        campaign_id=campaign_id,
        revision_no=revision,
        playlist=playlist,
        fullscreen=fullscreen,
        kiosk=kiosk,
        volume=volume,
        physical_output=physical_output,
        session_independence=session_independence,
        screen_mode=screen_mode,
        pause_on_human_activity=pause_on_human_activity,
        emergency_takeover=emergency_takeover,
    )


def verify_manifest_envelope(
    envelope: Mapping[str, Any],
    *,
    expected_agent_id: str,
    public_key_path: Path,
    now: dt.datetime | None = None,
) -> VerifiedManifest:
    """Verify canonical SHA-256 + Ed25519 signature before any local action."""
    if not isinstance(envelope, Mapping):
        raise PlayerManifestError("PLAYER_MANIFEST_OBJECT_REQUIRED")
    if str(envelope.get("Schema") or envelope.get("schema") or "") != PLAYER_MANIFEST_SCHEMA:
        raise PlayerManifestError("PLAYER_MANIFEST_SCHEMA_UNSUPPORTED")
    version = _positive_int(envelope.get("ManifestVersion") or envelope.get("manifest_version"), name="version", minimum=1, maximum=2_147_483_647)
    raw_payload = envelope.get("Payload") if isinstance(envelope.get("Payload"), Mapping) else envelope.get("payload")
    if not isinstance(raw_payload, Mapping):
        raise PlayerManifestError("PLAYER_MANIFEST_PAYLOAD_REQUIRED")
    payload = dict(raw_payload)
    payload_agent = _clean_id(payload.get("AgentId") or payload.get("agent_id"), name="agent_id")
    if payload_agent != _clean_id(expected_agent_id, name="expected_agent_id"):
        raise PlayerManifestError("PLAYER_MANIFEST_AGENT_MISMATCH")
    canonical = _canonical_json(payload)
    if len(canonical) > MAX_MANIFEST_BYTES:
        raise PlayerManifestError("PLAYER_MANIFEST_TOO_LARGE")
    digest = hashlib.sha256(canonical).hexdigest()
    expected_digest = _bounded(envelope.get("ManifestSha256") or envelope.get("manifest_sha256"), 64).casefold()
    if not _SHA256.fullmatch(expected_digest) or expected_digest != digest:
        raise PlayerManifestError("PLAYER_MANIFEST_SHA256_MISMATCH")
    signature = _bounded(envelope.get("Signature") or envelope.get("signature"), 12_000)
    key_id = _clean_id(envelope.get("KeyId") or envelope.get("key_id"), name="key_id")
    if not signature:
        raise PlayerManifestError("PLAYER_MANIFEST_SIGNATURE_REQUIRED")
    try:
        key = serialization.load_pem_public_key(Path(public_key_path).read_bytes())
        if not isinstance(key, Ed25519PublicKey):
            raise PlayerManifestError("PLAYER_MANIFEST_SIGNING_KEY_INVALID")
        key.verify(base64.b64decode(signature, validate=True), canonical)
    except PlayerManifestError:
        raise
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise PlayerManifestError("PLAYER_MANIFEST_SIGNATURE_INVALID") from exc
    except OSError as exc:
        raise PlayerManifestError("PLAYER_MANIFEST_SIGNING_KEY_MISSING") from exc

    issued = _parse_iso(payload.get("IssuedAt") or payload.get("issued_at"), name="issued_at", required=False)
    expires = _parse_iso(payload.get("ExpiresAt") or payload.get("expires_at"), name="expires_at", required=False)
    current = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    if expires is not None:
        if expires <= current:
            raise PlayerManifestError("PLAYER_MANIFEST_EXPIRED")
        if expires > current + dt.timedelta(days=45):
            raise PlayerManifestError("PLAYER_MANIFEST_EXPIRY_TOO_FAR")
    if issued is not None and issued > current + dt.timedelta(minutes=10):
        raise PlayerManifestError("PLAYER_MANIFEST_ISSUED_IN_FUTURE")

    raw_assignments = payload.get("Screens") if isinstance(payload.get("Screens"), list) else payload.get("Assignments")
    if not isinstance(raw_assignments, list) or len(raw_assignments) > MAX_SCREENS:
        raise PlayerManifestError("PLAYER_MANIFEST_SCREENS_INVALID")
    assignments = tuple(_read_assignment(item, index=index) for index, item in enumerate(raw_assignments))
    seen_screens: set[str] = set()
    seen_outputs: set[tuple[str, str]] = set()
    for assignment in assignments:
        if assignment.screen_id in seen_screens:
            raise PlayerManifestError("PLAYER_MANIFEST_SCREEN_DUPLICATE")
        output_binding = (
            assignment.target_kind,
            (assignment.output_identity or assignment.output_key).casefold(),
        )
        if output_binding in seen_outputs:
            raise PlayerManifestError("PLAYER_MANIFEST_OUTPUT_CONFLICT")
        seen_screens.add(assignment.screen_id)
        seen_outputs.add(output_binding)
    return VerifiedManifest(
        envelope=dict(envelope),
        manifest_version=version,
        manifest_sha256=digest,
        key_id=key_id,
        issued_at=issued.isoformat() if issued else "",
        expires_at=expires.isoformat() if expires else "",
        assignments=assignments,
    )


@dataclass(frozen=True, slots=True)
class PlayerPaths:
    root: Path
    manifests: Path
    current_manifest: Path
    cache_index: Path
    status: Path
    log: Path
    public_root: Path
    public_manifest: Path
    public_runtime: Path
    public_status: Path
    desktop_lock: Path
    public_output_map: Path

    @classmethod
    def from_agent_root(cls, agent_root: Path, media_root: Path) -> "PlayerPaths":
        root = Path(agent_root) / "player"
        manifests = root / "manifests"
        # The desktop companion must not read ``/var/lib/gideon-agent`` or a
        # Windows service's private data directory.  This public exchange is
        # deliberately credential-free and stored next to the Phase-2 media
        # cache.  It contains only an Ed25519-signed manifest and observable
        # player state; the companion independently re-verifies both signature
        # and asset SHA-256 before VLC receives a filename.
        public_root = Path(media_root) / ".gideon-player"
        # ``current.json`` stays in a service-owned, read-only exchange
        # directory.  Only transient desktop status/lock files live below the
        # separately ACL-provisioned runtime directory.  An interactive user
        # can therefore never replace a signed campaign manifest merely by
        # having permission to report player status.
        public_runtime = public_root / "runtime"
        return cls(
            root=root,
            manifests=manifests,
            current_manifest=manifests / "current.json",
            cache_index=root / "cache-index.json",
            status=root / "status.json",
            log=root / "player.log",
            public_root=public_root,
            public_manifest=public_root / "current.json",
            public_runtime=public_runtime,
            public_status=public_runtime / "status.json",
            desktop_lock=public_runtime / "desktop-player.lock",
            # It is intentionally distinct from the signed campaign: WebAdmin
            # selects the physical output, while local administration confirms
            # how that OS maps it to a Qt/VLC screen on multi-monitor hardware.
            public_output_map=public_root / "output-map.json",
        )

    def ensure(self, *, desktop_only: bool = False) -> None:
        if not desktop_only:
            self.root.mkdir(parents=True, exist_ok=True)
            self.manifests.mkdir(parents=True, exist_ok=True)
            enforce_path_mode(self.root, 0o700)
            enforce_path_mode(self.manifests, 0o700)
        elif not self.public_root.is_dir():
            raise PlayerManifestError("PLAYER_PUBLIC_EXCHANGE_UNAVAILABLE")

    def ensure_public_exchange(self) -> None:
        self.public_root.mkdir(parents=True, exist_ok=True)
        runtime_created = not self.public_runtime.exists()
        self.public_runtime.mkdir(parents=True, exist_ok=True)
        # This is not a private Agent state directory.  The manifest is signed,
        # status contains no secrets, and the graphical user needs read/write
        # access to run its independently verifiable VLC companion.  The
        # installer supplies a narrow user/group ACL *only* to ``runtime`` for
        # desktop status/locking.  ``current.json`` remains owned by the Agent
        # service and this runtime never falls back to world-writable modes.
        enforce_path_mode(self.public_root, 0o755)
        # Do not repair an existing runtime directory on every heartbeat: an
        # installer may have applied a narrow ``gideon-player`` group/ACL there.
        # Fresh directories start non-writable until that explicit provisioning
        # step occurs.
        if runtime_created:
            enforce_path_mode(self.public_runtime, 0o755)


class PlayerManifestStore:
    """Durable manifest/cache metadata with rollback-safe last-valid behavior."""

    def __init__(
        self,
        *,
        agent_root: Path,
        agent_id: str,
        public_key_path: Path,
        media_root: Path | None = None,
        desktop_only: bool = False,
    ) -> None:
        self.agent_id = _clean_id(agent_id, name="agent_id")
        self.public_key_path = Path(public_key_path)
        self.media_root = Path(media_root) if media_root is not None else _media_root_for()
        self.paths = PlayerPaths.from_agent_root(agent_root, self.media_root)
        self.desktop_only = bool(desktop_only)
        self.paths.ensure(desktop_only=self.desktop_only)

    def _verify_cached(self, path: Path) -> VerifiedManifest | None:
        raw = _read_json(path)
        if not raw:
            return None
        try:
            return verify_manifest_envelope(raw, expected_agent_id=self.agent_id, public_key_path=self.public_key_path)
        except PlayerManifestError:
            # A malformed local cache is never trusted merely because it exists.
            return None

    def load_current(self) -> VerifiedManifest | None:
        if self.desktop_only:
            return self._verify_cached(self.paths.public_manifest)
        return self._verify_cached(self.paths.current_manifest) or self._verify_cached(self.paths.public_manifest)

    def load_desktop_manifest(self) -> VerifiedManifest | None:
        # Desktop must never consume the private Agent copy.  This protects the
        # service boundary and exercises the same exchange available after login.
        return self._verify_cached(self.paths.public_manifest)

    def _record_cache(self, manifest: VerifiedManifest) -> None:
        current = _read_json(self.paths.cache_index)
        assets = current.get("Assets") if isinstance(current.get("Assets"), Mapping) else {}
        updated: dict[str, Any] = dict(assets)
        stamp = now_iso()
        for assignment in manifest.assignments:
            for asset in assignment.playlist:
                updated[asset.sha256] = {
                    "FileName": asset.file_name,
                    "SizeBytes": asset.size_bytes,
                    "LastVerifiedAt": stamp,
                }
        # Bound metadata; retain recently verified entries so offline playback
        # can survive a campaign update without accumulating unbounded state.
        if len(updated) > 2048:
            ordered = sorted(updated.items(), key=lambda item: str((item[1] or {}).get("LastVerifiedAt") or ""), reverse=True)[:2048]
            updated = dict(ordered)
        atomic_json(self.paths.cache_index, {
            "Schema": PLAYER_CACHE_SCHEMA,
            "UpdatedAt": stamp,
            "Assets": updated,
        }, mode=PRIVATE_FILE_MODE)

    def verify_media_assets(self, manifest: VerifiedManifest) -> None:
        if not manifest.assignments:
            return
        missing: list[str] = []
        for assignment in manifest.assignments:
            for asset in assignment.playlist:
                try:
                    _checked_media_asset(asset, self.media_root, verify_hash=True)
                except PlayerAssetPending:
                    missing.append(asset.asset_id)
        if missing:
            raise PlayerAssetPending("PLAYER_MEDIA_PENDING:" + ",".join(missing[:8]))

    def apply(self, envelope: Mapping[str, Any]) -> VerifiedManifest:
        manifest = verify_manifest_envelope(envelope, expected_agent_id=self.agent_id, public_key_path=self.public_key_path)
        current = self.load_current()
        if current is not None:
            if manifest.manifest_version < current.manifest_version:
                raise PlayerManifestError("PLAYER_MANIFEST_DOWNGRADE_REJECTED")
            if manifest.manifest_version == current.manifest_version and manifest.manifest_sha256 != current.manifest_sha256:
                raise PlayerManifestError("PLAYER_MANIFEST_VERSION_CONFLICT")
        self.verify_media_assets(manifest)
        # Only switch after all assets verify.  A partial new campaign can never
        # replace the last playable signed campaign during a network outage.
        encoded = _canonical_json(dict(manifest.envelope))
        try:
            self.paths.ensure_public_exchange()
        except OSError as exc:
            raise PlayerAssetPending("PLAYER_PUBLIC_EXCHANGE_UNAVAILABLE") from exc
        # Publish the public signed copy first.  If permission provisioning is
        # absent, keep the private current manifest unchanged so the previous
        # campaign remains authoritative and playable after it is restored.
        _atomic_bytes(self.paths.public_manifest, encoded, mode=PUBLIC_STATUS_MODE)
        _atomic_bytes(self.paths.current_manifest, encoded, mode=PRIVATE_FILE_MODE)
        self._record_cache(manifest)
        return manifest

    def write_status(self, value: Mapping[str, Any]) -> None:
        clean = dict(value)
        clean.setdefault("Schema", PLAYER_STATUS_SCHEMA)
        clean.setdefault("RuntimeVersion", PLAYER_RUNTIME_VERSION)
        clean["UpdatedAt"] = now_iso()
        # Status intentionally has no Gateway URL, credentials, CA path, local
        # absolute media paths, or arbitrary command lines.
        if not self.desktop_only:
            try:
                atomic_json(self.paths.status, clean, mode=PRIVATE_FILE_MODE)
            except OSError:
                # The public exchange remains enough for the desktop companion;
                # a local metadata write must not terminate VLC.
                pass
            # Service state stays private. The public runtime document belongs
            # exclusively to the desktop companion; otherwise a manifest poll
            # can erase PLAYING or a concrete output error before it is reported.
            return
        try:
            atomic_json(self.paths.public_status, clean, mode=PUBLIC_STATUS_MODE)
        except OSError:
            # A package that has not yet applied its controlled ACL/group cannot
            # report desktop status, but playback itself remains isolated and
            # keeps running.  The Agent reports this as stale/deferred instead
            # of treating it as a tunnel or heartbeat failure.
            pass

    def read_status(self) -> dict[str, Any]:
        private = _read_json(self.paths.status)
        public = _read_json(self.paths.public_status)
        if self.desktop_only:
            return public
        if not private:
            # The service can always write its own state directory.  Do not
            # elevate a console user's status file into a source of truth when
            # that invariant is unexpectedly broken.
            return {}
        if not public:
            return private
        private_version = _status_int(private.get("ManifestVersion"), maximum=2_147_483_647)
        public_version = _status_int(public.get("ManifestVersion"), maximum=2_147_483_647)
        private_digest = _bounded(private.get("ManifestSha256"), 64).casefold()
        public_digest = _bounded(public.get("ManifestSha256"), 64).casefold()
        # A desktop status is telemetry only.  Merge it only when it describes
        # the exact signed manifest accepted by the service; it can never move
        # the Agent to another campaign/version or replace service-owned state.
        if not private_version or private_version != public_version or not _SHA256.fullmatch(private_digest) or public_digest != private_digest:
            return private
        merged = dict(private)
        for key in ("State", "VLC", "Graphics", "FreeBytes", "Screens", "RuntimePid", "UpdatedAt"):
            if key in public:
                merged[key] = public[key]
        return merged


def _vlc_candidates() -> list[str]:
    candidates: list[str] = []
    configured = _bounded(os.environ.get("GIDEON_VLC_PATH"), 1000)
    if configured:
        candidates.append(configured)
    if os.name == "nt":
        for base in (os.environ.get("ProgramFiles", ""), os.environ.get("ProgramFiles(x86)", "")):
            if base:
                candidates.append(str(Path(base) / "VideoLAN" / "VLC" / "vlc.exe"))
        candidates.append("vlc.exe")
    elif sys.platform == "darwin":
        candidates.extend(["/Applications/VLC.app/Contents/MacOS/VLC", "vlc"])
    else:
        # The Player uses VLC's Qt interface for deterministic physical-screen
        # selection.  Prefer the normal executable; ``cvlc`` injects a dummy
        # interface on several distributions and can ignore Qt screen mapping.
        candidates.extend(["vlc", "cvlc"])
    result: list[str] = []
    for candidate in candidates:
        path = Path(candidate)
        if path.is_absolute() and path.is_file():
            resolved = str(path)
        else:
            resolved = shutil.which(candidate) or ""
        if resolved and resolved not in result:
            result.append(resolved)
    return result


def _is_linux_host() -> bool:
    return os.name != "nt" and sys.platform.startswith("linux")


def _running_as_root() -> bool:
    geteuid = getattr(os, "geteuid", None)
    return bool(callable(geteuid) and geteuid() == 0)


def _parse_vlc_cli_version(stdout: Any, stderr: Any, *, returncode: int) -> str:
    """Return only a genuine VLC banner from a successful CLI probe.

    VLC deliberately refuses to run as root on Linux and prints that refusal
    to stderr.  It is diagnostic text, not a version.  Requiring both a zero
    exit status and the documented VLC banner prevents warnings, tracebacks or
    launcher errors from leaking into Agent capability telemetry.
    """
    if int(returncode) != 0:
        return ""
    for stream in (stdout, stderr):
        for raw_line in str(stream or "").splitlines():
            line = _bounded(raw_line, 140)
            if _VLC_CLI_VERSION.fullmatch(line):
                return line
    return ""


def _probe_vlc_cli_version(executable: str) -> str:
    try:
        completed = subprocess.run(
            [executable, "--version"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            check=False,
            creationflags=0x08000000 if os.name == "nt" else 0,
        )
        return _parse_vlc_cli_version(
            completed.stdout,
            completed.stderr,
            returncode=int(completed.returncode),
        )
    except Exception:
        return ""


_WINDOWS_VLC_PROBE_CLEANUP_AT = 0.0


def _cleanup_windows_vlc_version_probe() -> None:
    """Close only legacy VLC version probes left by pre-2.4.45 Agents.

    Older Windows builds spawned ``vlc.exe --version`` on every refresh. Some
    VLC packages leave that console waiting for Enter, so upgrading the Agent
    stops new probes but cannot remove one that is already orphaned. The fixed
    PowerShell query is local-only and matches the exact version flags; the
    normal fullscreen VLC command has neither flag and is never selected.
    """
    global _WINDOWS_VLC_PROBE_CLEANUP_AT
    if os.name != "nt":
        return
    now = time.monotonic()
    if now - _WINDOWS_VLC_PROBE_CLEANUP_AT < 60.0:
        return
    _WINDOWS_VLC_PROBE_CLEANUP_AT = now
    powershell = shutil.which("powershell.exe") or shutil.which("powershell") or r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    script = (
        "$ErrorActionPreference='SilentlyContinue'; "
        "$names=@('vlc.exe','cmd.exe'); "
        "Get-CimInstance Win32_Process | "
        "Where-Object { $names -contains $_.Name -and $_.CommandLine -and "
        "($_.CommandLine -match '(?i)\\bvlc(?:\\.exe)?\\b') -and "
        "($_.CommandLine -match '(?i)(--version|\\s-V(?:\\s|$))') } | "
        "ForEach-Object { Stop-Process -Id ([int]$_.ProcessId) -Force -ErrorAction SilentlyContinue }"
    )
    try:
        subprocess.run(
            [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=4,
            check=False,
            creationflags=0x08000000,
        )
    except Exception:
        # Cleanup is opportunistic; failure must never affect Agent, tunnel or
        # the isolated Player runtime.
        return


def _linux_vlc_package_version() -> str:
    """Read installed package metadata without network or launching VLC."""
    if not _is_linux_host():
        return ""
    dpkg = shutil.which("dpkg-query")
    if dpkg:
        try:
            completed = subprocess.run(
                [dpkg, "-W", "-f=${Status}\t${Version}\\n", "vlc"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
                check=False,
            )
            for line in (completed.stdout or "").splitlines():
                status, separator, version = line.strip().rpartition("\t")
                version = version.strip()
                if (
                    completed.returncode == 0
                    and separator
                    and status.strip() == "install ok installed"
                    and _PACKAGE_VERSION.fullmatch(version)
                ):
                    return f"VLC package {version}"
        except Exception:
            pass
    rpm = shutil.which("rpm")
    if rpm:
        try:
            completed = subprocess.run(
                [rpm, "-q", "--qf", "%{VERSION}-%{RELEASE}\\n", "vlc"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
                check=False,
            )
            version = next((line.strip() for line in (completed.stdout or "").splitlines() if line.strip()), "")
            if completed.returncode == 0 and _PACKAGE_VERSION.fullmatch(version):
                return f"VLC package {version}"
        except Exception:
            pass
    return ""


def discover_vlc() -> dict[str, Any]:
    executable = next(iter(_vlc_candidates()), "")
    if not executable:
        return {
            "Installed": False,
            "Version": "",
            "Provenance": "external-not-installed",
            "License": "GPL-2.0-or-later",
        }
    # The Linux service normally runs as root.  Launching VLC merely to read
    # its version then produces a root-refusal warning, so query the already
    # installed package database first.  Both dpkg-query and rpm operate only
    # on local metadata and cannot contact a repository.
    linux_host = _is_linux_host()
    privileged_linux = linux_host and _running_as_root()
    version = _linux_vlc_package_version() if privileged_linux else ""
    # Do not execute ``vlc.exe --version`` from a Windows service/desktop
    # refresh.  Some VLC Windows distributions are console-subsystem builds
    # (or ship a pause wrapper) and create a visible terminal on every poll.
    # Presence of the signed/installed executable is enough for playback;
    # version remains bounded as ``version-unavailable`` until a non-spawning
    # registry/package probe is available.
    if not version and not privileged_linux and os.name != "nt":
        version = _probe_vlc_cli_version(executable)
    if not version and linux_host and not privileged_linux:
        version = _linux_vlc_package_version()
    if not version:
        version = "version-unavailable"
    return {
        "Installed": True,
        "Version": version,
        "Provenance": "external-system-installation",
        "License": "GPL-2.0-or-later",
        "Executable": Path(executable).name,
    }


def _interactive_desktop_available() -> bool:
    if os.name == "nt":
        # A Windows service runs in Session 0 even when a physical console is
        # logged in.  WTS is the OS authority here; inherited environment
        # markers are not an authorization boundary.
        return bool(_windows_physical_session_context().get("Physical"))
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return False
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return False
    return True


def _windows_active_console_session_id() -> int | None:
    """Return the active local console session, including from Session 0.

    The Agent service normally runs as LocalSystem in Session 0, so its own
    process session is not evidence of a graphical desktop. WTS is the
    Windows authority for the physical console and is queried without
    reading account names or credentials.
    """
    if os.name != "nt":
        return None
    try:
        import ctypes

        session_id = int(ctypes.windll.kernel32.WTSGetActiveConsoleSessionId())
        return None if session_id == 0xFFFFFFFF else session_id
    except Exception:
        return None


_WINDOWS_LAUNCH_DIAGNOSTIC: dict[str, str] = {
    "State": "NOT_ATTEMPTED",
    "Reason": "",
    "SessionId": "",
}


def _windows_launch_diag(state: str, reason: str = "", session_id: int | None = None) -> None:
    """Keep bounded, non-secret evidence for a failed console launch."""
    _WINDOWS_LAUNCH_DIAGNOSTIC.update({
        "State": _bounded(state, 80),
        "Reason": _bounded(reason, 240),
        "SessionId": str(int(session_id)) if session_id is not None else "",
    })


def _launch_windows_interactive_process(command: list[str], *, cwd: Path) -> int | None:
    """Launch the signed GIDEON desktop child in the active console session.

    This is deliberately narrower than a generic remote-execution helper:
    only the local Player command is passed by the caller, the user token is
    obtained from the active console by WTS, and the child still validates the
    signed manifest and physical output before invoking VLC. Failure is
    best-effort and never takes the Agent service offline.
    """
    _windows_launch_diag("NOT_ATTEMPTED")
    if os.name != "nt":
        _windows_launch_diag("UNSUPPORTED", "PLAYER_WINDOWS_CONSOLE_LAUNCH_NOT_WINDOWS")
        return None
    session_id = _windows_active_console_session_id()
    if session_id is None:
        _windows_launch_diag("DEFERRED", "PLAYER_WINDOWS_ACTIVE_CONSOLE_NOT_FOUND")
        return None
    _windows_launch_diag("STARTING", session_id=session_id)
    try:
        import ctypes
        from ctypes import wintypes

        # Explicit signatures are required on x86_64.  ctypes otherwise may
        # truncate HANDLE/LPVOID arguments to 32 bits, making a valid WTS
        # token look like a failed CreateProcessAsUser call.
        wtsapi32 = ctypes.WinDLL("wtsapi32", use_last_error=True)
        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        userenv = ctypes.WinDLL("userenv", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        token = wintypes.HANDLE()
        wtsapi32.WTSQueryUserToken.argtypes = [wintypes.ULONG, ctypes.POINTER(wintypes.HANDLE)]
        wtsapi32.WTSQueryUserToken.restype = wintypes.BOOL
        if not wtsapi32.WTSQueryUserToken(wintypes.DWORD(session_id), ctypes.byref(token)):
            _windows_launch_diag(
                "DEFERRED",
                f"WTSQueryUserToken:{int(ctypes.get_last_error() or 0)}",
                session_id,
            )
            return None
        env = ctypes.c_void_p()
        process_handle = wintypes.HANDLE()
        thread_handle = wintypes.HANDLE()
        try:
            userenv.CreateEnvironmentBlock.argtypes = [ctypes.POINTER(ctypes.c_void_p), wintypes.HANDLE, wintypes.BOOL]
            userenv.CreateEnvironmentBlock.restype = wintypes.BOOL
            if not userenv.CreateEnvironmentBlock(ctypes.byref(env), token, False):
                env = ctypes.c_void_p()

            class STARTUPINFO(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("lpReserved", wintypes.LPWSTR),
                    ("lpDesktop", wintypes.LPWSTR),
                    ("lpTitle", wintypes.LPWSTR),
                    ("dwX", wintypes.DWORD),
                    ("dwY", wintypes.DWORD),
                    ("dwXSize", wintypes.DWORD),
                    ("dwYSize", wintypes.DWORD),
                    ("dwXCountChars", wintypes.DWORD),
                    ("dwYCountChars", wintypes.DWORD),
                    ("dwFillAttribute", wintypes.DWORD),
                    ("dwFlags", wintypes.DWORD),
                    ("wShowWindow", wintypes.WORD),
                    ("cbReserved2", wintypes.WORD),
                    ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
                    ("hStdInput", wintypes.HANDLE),
                    ("hStdOutput", wintypes.HANDLE),
                    ("hStdError", wintypes.HANDLE),
                ]

            class PROCESS_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("hProcess", wintypes.HANDLE),
                    ("hThread", wintypes.HANDLE),
                    ("dwProcessId", wintypes.DWORD),
                    ("dwThreadId", wintypes.DWORD),
                ]

            startup = STARTUPINFO()
            startup.cb = ctypes.sizeof(STARTUPINFO)
            startup.lpDesktop = r"winsta0\default"
            pi = PROCESS_INFORMATION()
            command_line = ctypes.create_unicode_buffer(subprocess.list2cmdline(command))
            flags = 0x00000400 | 0x08000000  # CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW
            advapi32.CreateProcessAsUserW.argtypes = [
                wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPWSTR,
                ctypes.c_void_p, ctypes.c_void_p, wintypes.BOOL,
                wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
                ctypes.POINTER(STARTUPINFO), ctypes.POINTER(PROCESS_INFORMATION),
            ]
            advapi32.CreateProcessAsUserW.restype = wintypes.BOOL
            created = advapi32.CreateProcessAsUserW(
                token, None, command_line, None, None, False, flags, env,
                str(cwd), ctypes.byref(startup), ctypes.byref(pi),
            )
            if not created:
                _windows_launch_diag(
                    "DEFERRED",
                    f"CreateProcessAsUserW:{int(ctypes.get_last_error() or 0)}",
                    session_id,
                )
                return None
            process_handle = pi.hProcess
            thread_handle = pi.hThread
            pid = int(pi.dwProcessId) or None
            if not pid:
                _windows_launch_diag("DEFERRED", "CreateProcessAsUserW:NO_PID", session_id)
                return None
            _windows_launch_diag("STARTED", session_id=session_id)
            return pid
        finally:
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle.restype = wintypes.BOOL
            if process_handle:
                kernel32.CloseHandle(process_handle)
            if thread_handle:
                kernel32.CloseHandle(thread_handle)
            if env:
                try:
                    userenv.DestroyEnvironmentBlock(env)
                except Exception:
                    pass
            if token:
                kernel32.CloseHandle(token)
    except Exception as exc:
        _windows_launch_diag("DEFERRED", f"{type(exc).__name__}:{exc}", session_id)
        return None


def _human_idle_limit_seconds(environ: Mapping[str, str] | None = None) -> int:
    """Return the fixed local inactivity threshold for shared screens.

    A desktop process inherits environment variables from several launch
    layers.  Screen safety must not depend on one of those values, so this is
    intentionally a constant until a signed campaign policy carries a future
    bounded threshold.
    """
    del environ
    return HUMAN_ACTIVITY_IDLE_SECONDS


def _windows_physical_session_context() -> dict[str, Any]:
    """Identify only the active *physical* Windows console session.

    A player launched in RDP must never take over a monitor assigned to a
    Screen.  WTS and GetLastInputInfo run entirely locally and we deliberately
    return no account, domain, client, or input-event data.
    """
    if os.name != "nt":
        return {"Available": False, "Physical": False, "Type": "windows-service", "Source": "windows-wts"}
    try:
        import ctypes
        from ctypes import wintypes

        process_session = wintypes.DWORD()
        kernel32 = ctypes.windll.kernel32
        if not kernel32.ProcessIdToSessionId(wintypes.DWORD(os.getpid()), ctypes.byref(process_session)):
            raise OSError("ProcessIdToSessionId")
        console_session = int(kernel32.WTSGetActiveConsoleSessionId())
        physical = console_session != 0xFFFFFFFF and int(process_session.value) == console_session
        context: dict[str, Any] = {
            "Available": console_session != 0xFFFFFFFF,
            "Physical": physical,
            "Type": "windows-console" if physical else "windows-nonconsole",
            "Source": "windows-wts",
            "HumanActivityKnown": False,
            "HumanActive": None,
        }
        if not physical:
            return context

        class LASTINPUTINFO(ctypes.Structure):
            _fields_ = [("cbSize", wintypes.UINT), ("dwTime", wintypes.DWORD)]

        info = LASTINPUTINFO()
        info.cbSize = ctypes.sizeof(LASTINPUTINFO)
        if ctypes.windll.user32.GetLastInputInfo(ctypes.byref(info)):
            # GetLastInputInfo uses the low 32 bits of tick count.  Modulo
            # subtraction intentionally handles the documented wrap-around.
            now_tick = int(kernel32.GetTickCount()) & 0xFFFFFFFF
            idle_seconds = ((now_tick - int(info.dwTime)) & 0xFFFFFFFF) / 1000.0
            context.update({
                "HumanActivityKnown": True,
                "HumanActive": idle_seconds < _human_idle_limit_seconds(),
                "IdleSeconds": min(int(idle_seconds), 86_400),
            })
        return context
    except Exception:
        return {"Available": False, "Physical": False, "Type": "windows-service", "Source": "windows-wts-failed"}


def _linux_physical_session_context(environ: Mapping[str, str]) -> dict[str, Any]:
    """Read bounded logind facts for this desktop process, never another user.

    The Player accepts a Linux graphical session only when logind confirms the
    exact ``XDG_SESSION_ID`` is active, local, graphical and owned by this
    process' UID.  Environment flags are deliberately ignored: they are
    inherited values, not a local security authority.
    """
    session_id = _bounded(environ.get("XDG_SESSION_ID"), 80)
    if not session_id:
        return {"Available": False, "Physical": False, "Type": "unknown", "Source": "linux-logind-session-missing"}
    if not shutil.which("loginctl"):
        return {"Available": False, "Physical": False, "Type": "unknown", "Source": "linux-logind-unavailable"}
    try:
        completed = subprocess.run(
            [
                "loginctl", "show-session", session_id,
                "-p", "Active", "-p", "Remote", "-p", "Type", "-p", "Class", "-p", "User", "-p", "IdleHint",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=2.0,
            check=False,
            env=dict(environ),
        )
    except (OSError, subprocess.SubprocessError):
        return {"Available": False, "Physical": False, "Type": "unknown", "Source": "linux-logind-query-failed"}
    values: dict[str, str] = {}
    for line in str(completed.stdout or "").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key.strip().casefold()] = value.strip().casefold()
    active = values.get("active", "")
    remote = values.get("remote", "")
    session_type = values.get("type", "")
    session_class = values.get("class", "")
    idle_hint = values.get("idlehint", "")
    try:
        session_uid = int(values.get("user", "-1"))
        process_uid = int(os.geteuid()) if hasattr(os, "geteuid") else -2
    except (TypeError, ValueError):
        session_uid = -1
        process_uid = -2
    verified = (
        completed.returncode == 0
        and active == "yes"
        and remote == "no"
        and session_type in {"x11", "wayland"}
        and session_class == "user"
        and session_uid >= 0
        and session_uid == process_uid
    )
    return {
        "Available": completed.returncode == 0 and active == "yes",
        "Physical": verified,
        "Type": session_type or "unknown",
        "Source": "linux-logind" if completed.returncode == 0 else "linux-logind-query-failed",
        "HumanActivityKnown": verified and idle_hint in {"yes", "no"},
        "HumanActive": False if verified and idle_hint == "yes" else True if verified and idle_hint == "no" else None,
    }


def physical_session_context(environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Return safe physical-session facts for the isolated desktop runtime.

    This intentionally does not create a session, impersonate a user, alter
    display ownership, or access Agent credentials.  It lets the Player exit
    after a console switch so a launcher in the newly active physical desktop
    can own playback instead.
    """
    environment = dict(environ or os.environ)
    if os.name == "nt":
        return _windows_physical_session_context()
    if sys.platform.startswith("linux"):
        return _linux_physical_session_context(environment)
    # macOS is not a Phase 3 pilot target.  Do not turn an inherited launcher
    # marker into a physical-console assertion on an unsupported platform.
    return {
        "Available": False,
        "Physical": False,
        "Type": "unknown",
        "Source": "macos-physical-session-unverified",
        "HumanActivityKnown": False,
        "HumanActive": None,
    }


def _physical_session_report(context: Mapping[str, Any]) -> dict[str, Any]:
    """Bound physical-session telemetry; deliberately omits user/session IDs."""
    idle = context.get("IdleSeconds")
    try:
        idle_value = max(0, min(int(idle), 86_400))
    except (TypeError, ValueError, OverflowError):
        idle_value = None
    human = context.get("HumanActive")
    return {
        "Available": bool(context.get("Available")),
        "Physical": bool(context.get("Physical")),
        "Type": _bounded(context.get("Type"), 32),
        "Source": _bounded(context.get("Source"), 48),
        "HumanActivityKnown": bool(context.get("HumanActivityKnown")),
        "HumanActive": human if isinstance(human, bool) else None,
        "IdleSeconds": idle_value,
    }


@dataclass(slots=True)
class _VlcProcess:
    assignment: PlayerAssignment
    proc: subprocess.Popen[Any]
    started_at: str
    next_retry_at: float = 0.0
    retry_seconds: float = RESTART_INITIAL_SECONDS
    file_signature: tuple[tuple[str, int, int], ...] = field(default_factory=tuple)


@dataclass(slots=True)
class _RetryState:
    next_retry_at: float
    retry_seconds: float


class DesktopInstanceLock:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.acquired = False
        self.failure_reason = ""

    def acquire(self) -> bool:
        self.failure_reason = ""
        for _ in range(2):
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                fd = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, PRIVATE_FILE_MODE)
                with os.fdopen(fd, "w", encoding="ascii") as handle:
                    handle.write(str(os.getpid()))
                self.acquired = True
                return True
            except FileExistsError:
                try:
                    pid = int(self.path.read_text(encoding="ascii").strip() or "0")
                except Exception:
                    pid = 0
                if pid > 0 and _process_alive(pid):
                    self.failure_reason = "PLAYER_RUNTIME_ALREADY_RUNNING"
                    return False
                try:
                    self.path.unlink(missing_ok=True)
                except OSError:
                    self.failure_reason = "PLAYER_RUNTIME_LOCK_UNAVAILABLE"
                    return False
            except OSError:
                # Controlled installer ACL/group provisioning is required for
                # the interactive companion.  Fail closed rather than creating
                # a world-writable cache or running duplicate VLC instances.
                self.failure_reason = "PLAYER_RUNTIME_LOCK_UNAVAILABLE"
                return False
        self.failure_reason = "PLAYER_RUNTIME_LOCK_UNAVAILABLE"
        return False

    def release(self) -> None:
        if not self.acquired:
            return
        try:
            if self.path.is_file() and self.path.read_text(encoding="ascii").strip() == str(os.getpid()):
                self.path.unlink(missing_ok=True)
        except OSError:
            pass
        self.acquired = False


class DesktopPlayerRuntime:
    """Desktop-only external VLC supervisor, deliberately independent of Agent."""

    def __init__(
        self,
        *,
        agent_root: Path,
        agent_id: str,
        public_key_path: Path,
        media_root: Path | None = None,
        popen_factory: Callable[..., subprocess.Popen[Any]] = subprocess.Popen,
    ) -> None:
        self.store = PlayerManifestStore(
            agent_root=agent_root,
            agent_id=agent_id,
            public_key_path=public_key_path,
            media_root=media_root,
            desktop_only=True,
        )
        self.popen_factory = popen_factory
        self.processes: dict[str, _VlcProcess] = {}
        self.retries: dict[str, _RetryState] = {}
        self._last_manifest_sha = ""
        self._verified_files: dict[str, tuple[int, int, str]] = {}
        self._lock = DesktopInstanceLock(self.store.paths.desktop_lock)
        self._exit_for_session_change = False
        self._shutdown_requested = False

    def _asset_path(self, asset: PlayerAsset) -> Path:
        target, file_stat = _checked_media_asset(asset, self.store.media_root, verify_hash=False)
        cached = self._verified_files.get(str(target))
        signature = (int(file_stat.st_size), int(file_stat.st_mtime_ns))
        if cached is not None and cached[:2] == signature and cached[2] == asset.sha256:
            return target
        # The stable directory/file checks above make this small cache safe for
        # the normal two-second desktop refresh.  On a changed file we hash the
        # open descriptor again before VLC sees its name.
        _checked_media_asset(asset, self.store.media_root, verify_hash=True)
        self._verified_files[str(target)] = (signature[0], signature[1], asset.sha256)
        return target

    @staticmethod
    def _output_map(display: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
        outputs = display.get("Outputs") if isinstance(display.get("Outputs"), list) else []
        result: dict[str, dict[str, Any]] = {}
        for item in outputs:
            if not isinstance(item, Mapping):
                continue
            copied = dict(item)
            # Always retain the legacy connector key, then expose the stable
            # identity alias (connector + privacy-safe EDID/device fingerprint)
            # when a new Screen assignment has already been bound to it.
            # Compatibility alias for early records that stored DRM's raw
            # cardN-HDMI-A-N connector before identities were normalized.
            for raw_key in (item.get("OutputKey"), item.get("OutputIdentity"), item.get("Connector")):
                key = _bounded(raw_key, 160).casefold()
                if key and key not in result:
                    result[key] = copied
        return result

    @staticmethod
    def _target_outputs(display: Mapping[str, Any], target_kind: str) -> list[dict[str, Any]]:
        """Return unique enabled outputs for one explicit target kind."""
        raw_outputs = display.get("Outputs") if isinstance(display.get("Outputs"), list) else []
        result: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in raw_outputs:
            if not isinstance(item, Mapping):
                continue
            reported_kind = _bounded(item.get("TargetKind"), 64).upper()
            if not reported_kind:
                reported_kind = LOCAL_WAYLAND_SESSION if bool(item.get("Virtual")) else PHYSICAL_CONNECTOR
            if reported_kind != target_kind or not bool(item.get("Connected")) or not bool(item.get("Enabled")):
                continue
            key = _bounded(item.get("OutputIdentity") or item.get("OutputKey"), 160).casefold()
            if not key or key in seen:
                continue
            seen.add(key)
            result.append(dict(item))
        return result

    def _local_vlc_screen_number(self, assignment: PlayerAssignment, display: Mapping[str, Any]) -> int:
        """Resolve a VLC screen only when the local mapping is unambiguous."""
        targets = self._target_outputs(display, assignment.target_kind)
        if len(targets) <= 1:
            return 0
        mapping = _read_local_output_map(self.store.paths.public_output_map)
        binding = (assignment.output_identity or assignment.output_key).casefold()
        number = mapping.get(binding)
        if number is None:
            raise PlayerOutputMappingError("PLAYER_OUTPUT_MAPPING_REQUIRED")
        if number < 1 or number > len(targets):
            raise PlayerOutputMappingError("PLAYER_OUTPUT_MAPPING_INVALID")
        return number - 1

    @staticmethod
    def _target_error(
        assignment: PlayerAssignment,
        output: Mapping[str, Any] | None,
        session: Mapping[str, Any],
    ) -> tuple[str, str] | None:
        """Fail closed when a signed target and local display kind disagree."""
        if assignment.target_kind == LOCAL_WAYLAND_SESSION:
            if not bool(session.get("Available")) or not bool(session.get("Physical")):
                return "WAYLAND_SESSION_UNAVAILABLE", "PLAYER_LOCAL_WAYLAND_LOGIND_SESSION_REQUIRED"
            if _bounded(session.get("Type"), 32).casefold() != "wayland":
                return "WAYLAND_SESSION_UNAVAILABLE", "PLAYER_LOCAL_WAYLAND_SESSION_REQUIRED"
            if output is None:
                return "SCREEN_DISCONNECTED", "PLAYER_LOCAL_WAYLAND_OUTPUT_NOT_FOUND"
            actual_kind = _bounded(output.get("TargetKind"), 64).upper()
            if actual_kind != LOCAL_WAYLAND_SESSION:
                return "TARGET_KIND_MISMATCH", "PLAYER_LOCAL_WAYLAND_TARGET_KIND_MISMATCH"
            if bool(output.get("Physical")) or not bool(output.get("Virtual")):
                return "TARGET_KIND_MISMATCH", "PLAYER_LOCAL_WAYLAND_VIRTUAL_OUTPUT_REQUIRED"
            if not bool(output.get("Connected")):
                return "SCREEN_DISCONNECTED", "PLAYER_LOCAL_WAYLAND_OUTPUT_NOT_CONNECTED"
            if not bool(output.get("Enabled")):
                return "OUTPUT_DISABLED", "PLAYER_LOCAL_WAYLAND_OUTPUT_NOT_ENABLED"
            return None

        if output is None:
            reason = (
                "PLAYER_OUTPUT_IDENTITY_NOT_CONNECTED"
                if assignment.output_identity != assignment.output_key
                else "PLAYER_PHYSICAL_CONNECTOR_NOT_FOUND"
            )
            return "SCREEN_DISCONNECTED", reason
        actual_kind = _bounded(output.get("TargetKind"), 64).upper() or PHYSICAL_CONNECTOR
        if actual_kind != PHYSICAL_CONNECTOR:
            return "TARGET_KIND_MISMATCH", "PLAYER_PHYSICAL_CONNECTOR_TARGET_KIND_MISMATCH"
        if not bool(output.get("Physical", True)) or bool(output.get("Virtual")):
            return "TARGET_KIND_MISMATCH", "PLAYER_PHYSICAL_CONNECTOR_REQUIRED"
        if not bool(output.get("Connected")):
            return "SCREEN_DISCONNECTED", "PLAYER_PHYSICAL_CONNECTOR_NOT_CONNECTED"
        if not bool(output.get("Enabled")):
            return "OUTPUT_DISABLED", "PLAYER_PHYSICAL_CONNECTOR_NOT_ENABLED"
        return None

    @staticmethod
    def _resolve_output(assignment: PlayerAssignment, outputs: Mapping[str, dict[str, Any]]) -> dict[str, Any] | None:
        # Once WebAdmin binds an assignment to a stable identity, never silently
        # fall back to a same-named connector after a monitor replacement. Older
        # manifests have OutputIdentity == OutputKey and keep connector behavior.
        identity = assignment.output_identity.casefold()
        connector = assignment.output_key.casefold()
        if identity != connector:
            return outputs.get(identity)
        return outputs.get(connector)

    def _command(
        self, executable: str, assignment: PlayerAssignment, output: Mapping[str, Any], *, screen_number: int,
    ) -> tuple[list[str], tuple[tuple[str, int, int], ...]]:
        files = [self._asset_path(asset) for asset in assignment.playlist]
        signature = tuple((str(path), int(path.stat().st_size), int(path.stat().st_mtime_ns)) for path in files)
        # VLC accepts a list of filenames as its playlist.  No shell, custom
        # command text, network URL, plugin argument, or manifest-provided flag
        # is ever permitted here.
        command = [
            executable,
            "--ignore-config",
            "--intf", "qt",
            "--no-video-title-show",
            "--no-osd",
            "--no-one-instance",
            "--loop",
            # Override any per-user VLC preference left on the endpoint.  In
            # fullscreen mode this scales the decoded picture to the selected
            # explicit output target while VLC preserves the source aspect ratio.
            "--autoscale",
            "--volume", str(int(round(assignment.volume * 2.56))),
        ]
        if assignment.fullscreen:
            command.append("--fullscreen")
        if assignment.kiosk:
            command.extend([
                "--no-video-deco",
                "--qt-minimal-view",
                "--no-qt-system-tray",
                "--no-qt-fs-controller",
                "--no-qt-privacy-ask",
                "--qt-notification=0",
            ])
        # ``screen_number`` is 0-based as required by VLC. It is either the
        # only enabled output of that target class or a root-owned local
        # mapping; never a guessed connector/compositor enumeration order.
        command.append(f"--qt-fullscreen-screennumber={max(0, int(screen_number))}")
        command.extend(str(path) for path in files)
        return command, signature

    def _start_assignment(
        self, assignment: PlayerAssignment, output: Mapping[str, Any], executable: str, *, screen_number: int,
    ) -> _VlcProcess:
        command, signature = self._command(executable, assignment, output, screen_number=screen_number)
        log = self.store.paths.root / f"vlc-{assignment.screen_id}.log"
        try:
            if log.is_file() and log.stat().st_size > 1_000_000:
                previous = log.with_suffix(".log.1")
                previous.unlink(missing_ok=True)
                os.replace(log, previous)
            handle = log.open("ab", buffering=0)
        except OSError:
            handle = open(os.devnull, "ab", buffering=0)
        kwargs: dict[str, Any] = {
            "stdin": subprocess.DEVNULL,
            "stdout": handle,
            "stderr": handle,
            "cwd": str(self.store.media_root),
        }
        if os.name == "nt":
            kwargs["creationflags"] = 0x08000000 | 0x00000200
        else:
            kwargs["start_new_session"] = True
        try:
            proc = self.popen_factory(command, **kwargs)
        finally:
            # Popen owns duplicated OS descriptors; do not retain one per retry.
            try:
                handle.close()
            except OSError:
                pass
        return _VlcProcess(
            assignment=assignment,
            proc=proc,
            started_at=now_iso(),
            retry_seconds=RESTART_INITIAL_SECONDS,
            file_signature=signature,
        )

    def _stop_removed(self, active_screen_ids: set[str]) -> None:
        for screen_id, managed in list(self.processes.items()):
            if screen_id not in active_screen_ids:
                _terminate_owned_process(managed.proc)
                self.processes.pop(screen_id, None)
        for screen_id in list(self.retries):
            if screen_id not in active_screen_ids:
                self.retries.pop(screen_id, None)

    def _screen_status(self, managed: _VlcProcess | None, assignment: PlayerAssignment, state: str, error: str = "") -> dict[str, Any]:
        return {
            "ScreenId": assignment.screen_id,
            "OutputKey": assignment.output_key,
            "OutputIdentity": assignment.output_identity,
            "TargetKind": assignment.target_kind,
            "OutputLabel": assignment.output_label,
            "CampaignId": assignment.campaign_id,
            "RevisionNo": assignment.revision_no,
            "CurrentVideo": assignment.playlist[0].file_name if assignment.playlist else "",
            "PlaylistItems": len(assignment.playlist),
            "State": state,
            "VlcPid": int(managed.proc.pid) if managed and managed.proc.poll() is None else 0,
            "LastSuccessAt": managed.started_at if managed and managed.proc.poll() is None else "",
            "Error": _bounded(error, 240),
            "PhysicalOutput": assignment.physical_output,
            "SessionIndependence": assignment.session_independence,
            "ScreenMode": assignment.screen_mode,
            "PauseOnHumanActivity": assignment.pause_on_human_activity,
            "EmergencyTakeover": assignment.emergency_takeover,
        }

    def refresh_once(self) -> dict[str, Any]:
        manifest = self.store.load_desktop_manifest()
        vlc = discover_vlc()
        physical_session = physical_session_context()
        if not _interactive_desktop_available():
            self._stop_removed(set())
            payload = {
                "State": "WAITING_FOR_GRAPHICAL_SESSION",
                "Reason": "PLAYER_INTERACTIVE_DESKTOP_REQUIRED",
                "VLC": vlc,
                "Screens": [],
                "RuntimePid": os.getpid(),
            }
            self.store.write_status(payload)
            return payload
        if not bool(physical_session.get("Physical")):
            # A playback output is never driven from RDP, XRDP or a stale
            # fast-user-switch session. Stop only VLC instances this runtime
            # owns, release the global lock through run(), and let the trusted
            # launcher attach to the next verified local graphical session.
            self._stop_removed(set())
            self._exit_for_session_change = True
            needs_wayland = bool(manifest and any(
                item.target_kind == LOCAL_WAYLAND_SESSION for item in manifest.assignments
            ))
            payload = {
                "State": "WAITING_FOR_LOCAL_WAYLAND_SESSION" if needs_wayland else "WAITING_FOR_PHYSICAL_SESSION",
                "Reason": (
                    "PLAYER_LOCAL_WAYLAND_LOGIND_SESSION_REQUIRED"
                    if needs_wayland else "PLAYER_PHYSICAL_SESSION_REQUIRED"
                ),
                "VLC": vlc,
                "Graphics": {"PhysicalSession": _physical_session_report(physical_session)},
                "Screens": [],
                "RuntimePid": os.getpid(),
            }
            self.store.write_status(payload)
            return payload
        if manifest is None:
            self._stop_removed(set())
            payload = {
                "State": "WAITING_FOR_VALID_MANIFEST",
                "Reason": "PLAYER_NO_SIGNED_MANIFEST",
                "VLC": vlc,
                "Screens": [],
                "RuntimePid": os.getpid(),
            }
            self.store.write_status(payload)
            return payload
        if not vlc.get("Installed"):
            self._stop_removed(set())
            payload = {
                "State": "VLC_NOT_INSTALLED",
                "Reason": "PLAYER_EXTERNAL_VLC_REQUIRED",
                "ManifestVersion": manifest.manifest_version,
                "ManifestSha256": manifest.manifest_sha256,
                "VLC": vlc,
                "Screens": [],
                "RuntimePid": os.getpid(),
            }
            self.store.write_status(payload)
            return payload
        executable = next(iter(_vlc_candidates()), "")
        if not executable:
            payload = {
                "State": "VLC_NOT_INSTALLED",
                "Reason": "PLAYER_EXTERNAL_VLC_REQUIRED",
                "ManifestVersion": manifest.manifest_version,
                "ManifestSha256": manifest.manifest_sha256,
                "VLC": vlc,
                "Screens": [],
                "RuntimePid": os.getpid(),
            }
            self.store.write_status(payload)
            return payload
        display = detect_display_capability()
        outputs = self._output_map(display)
        active = {item.screen_id for item in manifest.assignments}
        self._stop_removed(active)
        rows: list[dict[str, Any]] = []
        now = time.monotonic()
        for assignment in manifest.assignments:
            if assignment.target_kind == PHYSICAL_CONNECTOR and not assignment.physical_output:
                current = self.processes.pop(assignment.screen_id, None)
                if current:
                    _terminate_owned_process(current.proc)
                rows.append(self._screen_status(None, assignment, "ASSIGNMENT_NOT_PHYSICAL_OUTPUT", "PLAYER_PHYSICAL_OUTPUT_REQUIRED"))
                continue
            output = self._resolve_output(assignment, outputs)
            target_error = self._target_error(assignment, output, physical_session)
            if target_error is not None:
                current = self.processes.pop(assignment.screen_id, None)
                if current:
                    _terminate_owned_process(current.proc)
                state, reason = target_error
                rows.append(self._screen_status(None, assignment, state, reason))
                continue
            current = self.processes.get(assignment.screen_id)
            try:
                human_active = physical_session.get("HumanActive")
                if assignment.pause_on_human_activity and not assignment.emergency_takeover and human_active is not False:
                    if current is not None:
                        _terminate_owned_process(current.proc)
                        self.processes.pop(assignment.screen_id, None)
                    reason = "PLAYER_HUMAN_ACTIVITY_ACTIVE" if human_active is True else "PLAYER_HUMAN_ACTIVITY_UNKNOWN"
                    rows.append(self._screen_status(None, assignment, "PAUSED_FOR_HUMAN_ACTIVITY", reason))
                    continue
                # A changed manifest/playlist is restarted only for that output;
                # independent screens continue uninterrupted.
                screen_number = self._local_vlc_screen_number(assignment, display)
                command, desired_signature = self._command(executable, assignment, output, screen_number=screen_number)
                del command
                replacement = (
                    current is None
                    or current.assignment != assignment
                    or current.file_signature != desired_signature
                )
                if replacement and current is not None:
                    _terminate_owned_process(current.proc)
                    self.processes.pop(assignment.screen_id, None)
                    current = None
                if current is not None and current.proc.poll() is not None:
                    previous = self.retries.get(assignment.screen_id)
                    delay = previous.retry_seconds if previous else current.retry_seconds
                    self.retries[assignment.screen_id] = _RetryState(
                        next_retry_at=max(current.next_retry_at, now + delay),
                        retry_seconds=min(RESTART_MAX_SECONDS, max(RESTART_INITIAL_SECONDS, delay * 2.0)),
                    )
                    self.processes.pop(assignment.screen_id, None)
                    current = None
                if current is None:
                    # Keep restart metadata only in the status document.  The
                    # first retry is deliberately bounded; it never blocks the
                    # normal Agent loop because this is a separate process.
                    retry = self.retries.get(assignment.screen_id)
                    if retry is not None and now < retry.next_retry_at:
                        rows.append(self._screen_status(None, assignment, "RETRY_BACKOFF", "PLAYER_VLC_RETRY_BACKOFF"))
                        continue
                    current = self._start_assignment(assignment, output, executable, screen_number=screen_number)
                    self.processes[assignment.screen_id] = current
                    self.retries.pop(assignment.screen_id, None)
                rows.append(self._screen_status(current, assignment, "PLAYING"))
            except PlayerOutputMappingError as exc:
                if current is not None:
                    _terminate_owned_process(current.proc)
                    self.processes.pop(assignment.screen_id, None)
                rows.append(self._screen_status(None, assignment, "OUTPUT_MAPPING_REQUIRED", _safe_error(exc)))
            except PlayerManifestError as exc:
                rows.append(self._screen_status(current, assignment, "PENDING_MEDIA", _safe_error(exc)))
            except Exception as exc:
                rows.append(self._screen_status(current, assignment, "VLC_START_ERROR", _safe_error(exc)))
        states = {str(row.get("State") or "") for row in rows}
        overall = "PLAYING" if rows and states == {"PLAYING"} else "PAUSED_FOR_HUMAN_ACTIVITY" if rows and states == {"PAUSED_FOR_HUMAN_ACTIVITY"} else "DEGRADED"
        payload = {
            "State": overall,
            "ManifestVersion": manifest.manifest_version,
            "ManifestSha256": manifest.manifest_sha256,
            "KeyId": manifest.key_id,
            "VLC": vlc,
            "Graphics": {
                "State": _bounded(display.get("State"), 40),
                "Session": dict(display.get("Session") or {}),
                "PhysicalSession": _physical_session_report(physical_session),
                "OutputCount": len(outputs),
            },
            "FreeBytes": int(shutil.disk_usage(self.store.media_root).free) if self.store.media_root.exists() else 0,
            "Screens": rows,
            "RuntimePid": os.getpid(),
        }
        self.store.write_status(payload)
        return payload

    def run(self, *, interval_seconds: float = 2.0, once: bool = False) -> int:
        if not self._lock.acquire():
            if self._lock.failure_reason == "PLAYER_RUNTIME_ALREADY_RUNNING":
                return 0
            self.store.write_status({
                "State": "RUNTIME_ERROR",
                "Reason": self._lock.failure_reason or "PLAYER_RUNTIME_LOCK_UNAVAILABLE",
                "Screens": [],
                "RuntimePid": os.getpid(),
            })
            return 1
        previous_handlers: dict[int, Any] = {}

        def request_shutdown(_signum: int, _frame: Any) -> None:
            # A signed launcher update may retire this exact Player process.
            # Exit through ``finally`` so only VLC children owned by this
            # runtime are terminated and the desktop lock is released.  Do not
            # use process-name matching or affect a user-launched VLC.
            self._shutdown_requested = True

        try:
            for signal_number in (signal.SIGTERM, signal.SIGINT):
                try:
                    previous_handlers[signal_number] = signal.signal(signal_number, request_shutdown)
                except (ValueError, OSError):
                    # Tests or embedded callers can run away from the main
                    # thread; normal desktop execution is always main-thread.
                    pass
            try:
                while True:
                    if self._shutdown_requested:
                        return 0
                    self.refresh_once()
                    if once:
                        return 0
                    if self._exit_for_session_change or self._shutdown_requested:
                        return 0
                    time.sleep(max(0.5, min(float(interval_seconds), 10.0)))
            except Exception as exc:
                self.store.write_status({
                    "State": "RUNTIME_ERROR",
                    "Reason": f"PLAYER_RUNTIME_UNEXPECTED_ERROR:{type(exc).__name__[:80]}",
                    "Screens": [],
                    "RuntimePid": os.getpid(),
                })
                return 1
        finally:
            self._stop_removed(set())
            self._lock.release()
            for signal_number, previous in previous_handlers.items():
                try:
                    signal.signal(signal_number, previous)
                except (ValueError, OSError):
                    pass


class PlayerAgentBridge:
    """Agent-side manifest/cache bridge with no VLC dependency or blocking work."""

    def __init__(
        self,
        *,
        agent_root: Path,
        agent_id: str,
        public_key_path: Path | None,
        media_root: Path | None = None,
        player_script: Path | None = None,
    ) -> None:
        # Remove a legacy Windows ``vlc --version`` console as soon as the
        # Agent bridge starts.  A pre-2.4.45 probe can outlive both its Agent
        # and desktop Player, so waiting for the next manifest sync leaves a
        # visible "Press Enter" window behind.  The helper is a no-op off
        # Windows and only matches VLC version probes.
        _cleanup_windows_vlc_version_probe()
        self.agent_root = Path(agent_root)
        self.agent_id = _clean_id(agent_id, name="agent_id")
        self.public_key_path = Path(public_key_path) if public_key_path else Path()
        self.media_root = Path(media_root) if media_root is not None else _media_root_for()
        self.player_script = Path(player_script) if player_script else Path(__file__).resolve()
        self.store = PlayerManifestStore(
            agent_root=self.agent_root,
            agent_id=self.agent_id,
            public_key_path=self.public_key_path,
            media_root=self.media_root,
        )
        self.next_sync_at = 0.0
        self.next_report_at = 0.0
        self._last_report_digest = ""
        self._child_pid = 0
        self._last_sync_state = "NOT_CHECKED"
        self._last_sync_error = ""

    def _launcher_status(self) -> dict[str, str]:
        """Expose only bounded, non-sensitive launcher diagnostics."""
        raw = _read_json(self.store.paths.root / "launcher-status.json")
        return {
            "State": _bounded(raw.get("State"), 80),
            "Reason": _bounded(raw.get("Reason"), 240),
            "UpdatedAt": _bounded(raw.get("UpdatedAt"), 80),
        }

    def capability(self, display: Mapping[str, Any] | None = None) -> dict[str, Any]:
        status = self.store.read_status()
        vlc = discover_vlc()
        display_info = dict(display or detect_display_capability())
        return {
            "Supported": bool(self.public_key_path.is_file()),
            "ManifestSchema": PLAYER_MANIFEST_SCHEMA,
            "RuntimeVersion": PLAYER_RUNTIME_VERSION,
            "ExecutionModel": "separate-desktop-process",
            "PhysicalOutputOnly": False,
            "TargetKindsSupported": [PHYSICAL_CONNECTOR, LOCAL_WAYLAND_SESSION],
            "SessionIndependentPlayback": "persistent-physical-output-or-verified-local-wayland-session",
            "PhysicalSessionRequired": True,
            "OutputBinding": "connector-with-edid-or-device-fingerprint-when-available",
            "ScreenModes": ["DEDICATED", "SHARED_PAUSE_ON_HUMAN_ACTIVITY"],
            "EmergencyTakeover": True,
            "ExternalVlcOnly": True,
            "NetworkDownloads": False,
            "MediaCache": "phase2-logical-cache",
            "VLC": vlc,
            "Launcher": self._launcher_status(),
            "Graphics": {
                "Session": dict(display_info.get("Session") or {}),
                "OutputCount": len(display_info.get("Outputs") or []),
                "PhysicalSession": _physical_session_report(physical_session_context()),
            },
            "State": _bounded(status.get("State") or self._last_sync_state, 80),
        }

    def status_for_report(self) -> dict[str, Any]:
        status = self.store.read_status()
        screens = status.get("Screens") if isinstance(status.get("Screens"), list) else []
        safe_screens: list[dict[str, Any]] = []
        for row in screens[:MAX_SCREENS]:
            if not isinstance(row, Mapping):
                continue
            safe_screens.append({
                "ScreenId": _bounded(row.get("ScreenId"), 160),
                "OutputKey": _bounded(row.get("OutputKey"), 160),
                "OutputIdentity": _bounded(row.get("OutputIdentity"), 160),
                "TargetKind": _bounded(row.get("TargetKind"), 64),
                "CampaignId": _bounded(row.get("CampaignId"), 160),
                "RevisionNo": _status_int(row.get("RevisionNo"), maximum=2_147_483_647),
                "CurrentVideo": _bounded(row.get("CurrentVideo"), 200),
                "PlaylistItems": _status_int(row.get("PlaylistItems"), maximum=MAX_PLAYLIST_ITEMS),
                "State": _bounded(row.get("State"), 80),
                "LastSuccessAt": _bounded(row.get("LastSuccessAt"), 80),
                "Error": _bounded(row.get("Error"), 240),
                "PhysicalOutput": bool(row.get("PhysicalOutput")),
                "SessionIndependence": _bounded(row.get("SessionIndependence"), 64),
                "ScreenMode": _bounded(row.get("ScreenMode"), 64),
                "PauseOnHumanActivity": bool(row.get("PauseOnHumanActivity")),
                "EmergencyTakeover": bool(row.get("EmergencyTakeover")),
            })
        vlc = status.get("VLC") if isinstance(status.get("VLC"), Mapping) else discover_vlc()
        graphics = status.get("Graphics") if isinstance(status.get("Graphics"), Mapping) else {}
        return {
            "Schema": PLAYER_STATUS_SCHEMA,
            "RuntimeVersion": PLAYER_RUNTIME_VERSION,
            "State": _bounded(status.get("State") or self._last_sync_state, 80),
            "ManifestVersion": _status_int(status.get("ManifestVersion"), maximum=2_147_483_647),
            "ManifestSha256": _bounded(status.get("ManifestSha256"), 64).casefold(),
            "VLC": {
                "Installed": bool(vlc.get("Installed")),
                "Version": _bounded(vlc.get("Version"), 140),
                "Provenance": _bounded(vlc.get("Provenance"), 80),
                "License": _bounded(vlc.get("License"), 80),
            },
            "Launcher": self._launcher_status(),
            "Graphics": {
                "State": _bounded(graphics.get("State"), 80),
                "OutputCount": _status_int(graphics.get("OutputCount"), maximum=64),
                "PhysicalSession": _physical_session_report(
                    graphics.get("PhysicalSession") if isinstance(graphics.get("PhysicalSession"), Mapping) else {}
                ),
            },
            "FreeBytes": _status_int(status.get("FreeBytes"), maximum=9_223_372_036_854_775_807),
            "Screens": safe_screens,
            "LastSyncState": self._last_sync_state,
            "LastSyncError": _bounded(self._last_sync_error, 240),
        }

    def _write_bridge_status(self, state: str, error: str = "", manifest: VerifiedManifest | None = None) -> None:
        existing = self.store.read_status()
        payload = dict(existing)
        payload.update({
            "State": state,
            "Reason": _bounded(error, 240),
            "BridgeUpdatedAt": now_iso(),
        })
        if manifest is not None:
            payload.update({
                "ManifestVersion": manifest.manifest_version,
                "ManifestSha256": manifest.manifest_sha256,
                "KeyId": manifest.key_id,
            })
        self.store.write_status(payload)

    def sync_from_gateway(self, client: Any, *, force: bool = False) -> dict[str, Any]:
        """Fetch/apply a signed manifest without making the normal heartbeat fail.

        The caller owns mTLS/bearer authentication.  This method has no access to
        those credential values and treats an older Gateway's 404 as a harmless
        compatibility state while retaining the last valid campaign offline.
        """
        now = time.monotonic()
        if not force and now < self.next_sync_at:
            return {"State": "DEFERRED"}
        self.next_sync_at = now + MANIFEST_SYNC_INTERVAL_SECONDS
        if not self.public_key_path.is_file():
            self._last_sync_state = "SIGNING_KEY_MISSING"
            self._last_sync_error = "PLAYER_MANIFEST_SIGNING_KEY_MISSING"
            self._write_bridge_status(self._last_sync_state, self._last_sync_error)
            return {"State": self._last_sync_state}
        try:
            reply = client.json("GET", "/api/v1/agent/media/manifest", timeout=min(20.0, float(getattr(client, "timeout", 20.0))))
            if bool(reply.get("NoManifest")) or bool(reply.get("no_manifest")):
                self._last_sync_state = "NO_MANIFEST"
                self._last_sync_error = ""
                self._write_bridge_status("WAITING_FOR_VALID_MANIFEST")
                return {"State": self._last_sync_state}
            envelope = reply.get("Manifest") if isinstance(reply.get("Manifest"), Mapping) else reply
            manifest = self.store.apply(envelope)
            self._last_sync_state = "MANIFEST_APPLIED"
            self._last_sync_error = ""
            self._write_bridge_status("MANIFEST_APPLIED", manifest=manifest)
            self._ensure_desktop_runtime()
            return {
                "State": self._last_sync_state,
                "ManifestVersion": manifest.manifest_version,
                "ManifestSha256": manifest.manifest_sha256,
            }
        except PlayerAssetPending as exc:
            self._last_sync_state = "PENDING_MEDIA"
            self._last_sync_error = _safe_error(exc)
            self._write_bridge_status("PENDING_MEDIA", self._last_sync_error)
            return {"State": self._last_sync_state, "Error": self._last_sync_error}
        except PlayerManifestError as exc:
            self._last_sync_state = "MANIFEST_REJECTED"
            self._last_sync_error = _safe_error(exc)
            self._write_bridge_status("MANIFEST_REJECTED", self._last_sync_error)
            return {"State": self._last_sync_state, "Error": self._last_sync_error}
        except Exception as exc:
            text = _safe_error(exc)
            # No extra error state is pushed into the Agent's connectivity loop;
            # older Gateways simply do not know this optional endpoint yet.
            self._last_sync_state = "CONTROL_PLANE_UNAVAILABLE" if "HTTP 404" in text else "SYNC_DEFERRED"
            self._last_sync_error = text
            self._write_bridge_status(self._last_sync_state, text)
            return {"State": self._last_sync_state, "Error": text}

    def _ensure_desktop_runtime(self) -> None:
        _cleanup_windows_vlc_version_probe()
        # Windows services run in Session 0. A valid local console is still a
        # safe launch target because the child re-checks WTS/physical output
        # and the signed manifest before starting VLC. Linux keeps the
        # existing same-session guard and tray/desktop launcher behaviour.
        windows_service_launch = os.name == "nt" and _windows_active_console_session_id() is not None
        if (
            (not windows_service_launch and not _interactive_desktop_available())
            or (not windows_service_launch and not bool(physical_session_context().get("Physical")))
            or not self.player_script.is_file()
            or not self.public_key_path.is_file()
        ):
            return
        status = self.store.read_status()
        pid = _status_int(status.get("RuntimePid") or self._child_pid, maximum=2_147_483_647)
        if pid > 0 and _process_alive(pid):
            return
        command = [
            sys.executable,
            str(self.player_script),
            "--run",
            "--agent-root", str(self.agent_root),
            "--agent-id", self.agent_id,
            "--public-key", str(self.public_key_path),
            "--media-root", str(self.media_root),
        ]
        kwargs: dict[str, Any] = {
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
        }
        if os.name == "nt":
            kwargs["creationflags"] = 0x08000000 | 0x00000200
        else:
            kwargs["start_new_session"] = True
        try:
            if windows_service_launch:
                pid = _launch_windows_interactive_process(command, cwd=self.player_script.parent)
                if not pid:
                    diagnostic = _WINDOWS_LAUNCH_DIAGNOSTIC
                    reason = str(diagnostic.get("Reason") or "").strip()
                    self._last_sync_error = "PLAYER_WINDOWS_CONSOLE_LAUNCH_DEFERRED"
                    if reason:
                        self._last_sync_error += ":" + reason
                    self._write_bridge_status("DESKTOP_PLAYER_START_DEFERRED", self._last_sync_error)
                    return
                self._child_pid = pid
            else:
                child = subprocess.Popen(command, **kwargs)
                self._child_pid = int(child.pid)
        except Exception as exc:
            self._last_sync_error = _safe_error(exc)
            self._write_bridge_status("DESKTOP_PLAYER_START_DEFERRED", self._last_sync_error)

    def report_to_gateway(self, client: Any, *, force: bool = False) -> dict[str, Any]:
        now = time.monotonic()
        report = self.status_for_report()
        encoded = _canonical_json(report)
        digest = hashlib.sha256(encoded).hexdigest()
        if not force and now < self.next_report_at and digest == self._last_report_digest:
            return {"State": "DEFERRED"}
        self.next_report_at = now + REPORT_INTERVAL_SECONDS
        try:
            response = client.json("POST", "/api/v1/agent/media/report", {"Player": report}, timeout=min(15.0, float(getattr(client, "timeout", 20.0))))
            self._last_report_digest = digest
            return {"State": "REPORTED", "Response": bool(response)}
        except Exception as exc:
            # Reporting is observational; never fail Agent heartbeats/jobs if a
            # newer WebAdmin endpoint has not reached this Gateway yet.
            return {"State": "REPORT_DEFERRED", "Error": _safe_error(exc)}


def _cli() -> int:
    parser = argparse.ArgumentParser(description="GIDEON isolated desktop media Player")
    parser.add_argument("--run", action="store_true", help="Run the credential-free desktop supervisor.")
    parser.add_argument("--once", action="store_true", help="Run exactly one supervisor refresh (test/diagnostic only).")
    parser.add_argument("--agent-root", type=Path, required=True)
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--media-root", type=Path)
    args = parser.parse_args()
    if not args.run:
        parser.error("--run is required")
    runtime = DesktopPlayerRuntime(
        agent_root=args.agent_root,
        agent_id=args.agent_id,
        public_key_path=args.public_key,
        media_root=args.media_root,
    )
    return runtime.run(once=bool(args.once))


if __name__ == "__main__":
    raise SystemExit(_cli())


__all__ = [
    "PLAYER_RUNTIME_VERSION",
    "PLAYER_MANIFEST_SCHEMA",
    "PLAYER_STATUS_SCHEMA",
    "PlayerManifestError",
    "PlayerOutputMappingError",
    "PlayerAssetPending",
    "PlayerAsset",
    "PlayerAssignment",
    "VerifiedManifest",
    "PlayerManifestStore",
    "PlayerAgentBridge",
    "DesktopPlayerRuntime",
    "discover_vlc",
    "physical_session_context",
    "verify_manifest_envelope",
]
