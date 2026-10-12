"""Persistent screen inventory and campaign planning for GIDEON Media.

This module deliberately contains *planning* data only.  It never opens a
media player, transfers a file, or contacts an Agent.  Agents publish display
capabilities through the existing authenticated heartbeat; WebAdmin consumes
that already-protected data and maps a commercial screen to one explicit
playback target (a physical connector or a verified local Wayland session).

The campaign catalog is kept in a separate SQLite database from authentication
and Gateway state.  That makes the migration additive and ensures a malformed
marketing record cannot affect login, audit, Agents, or reverse tunnels.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import sqlite3
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from gideon_infrastructure.sqlite_connections import SQLiteConnectionFactory, SQLiteConnectionOptions


CAMPAIGN_STATES = (
    "DRAFT",
    "PENDING_APPROVAL",
    "SCHEDULED",
    "ACTIVE",
    "PAUSED",
    "EXPIRED",
    "ARCHIVED",
)
SCREEN_STATES = ("READY", "OFFLINE", "NEEDS_REVIEW", "DISABLED", "ARCHIVED")
ORIENTATIONS = ("LANDSCAPE", "PORTRAIT")
SCREEN_PLAYBACK_MODES = (
    "DEDICATED",
    "SHARED_PAUSE_ON_HUMAN_ACTIVITY",
)
SCREEN_TARGET_KINDS = (
    "PHYSICAL_CONNECTOR",
    "LOCAL_WAYLAND_SESSION",
)
SCHEDULE_PRESETS = ("ALWAYS", "DATE_RANGE", "WEEKDAYS", "WEEKENDS", "CUSTOM")
MEDIA_ASSET_STATES = ("QUARANTINED", "ANALYZING", "READY", "REJECTED", "ERROR", "ARCHIVED")
MEDIA_DISTRIBUTION_STATES = ("PENDING", "SYNCING", "READY", "OFFLINE", "ERROR")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_TIME_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
_DATETIME_LOCAL_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]([01]\d|2[0-3]):[0-5]\d(?::[0-5]\d)?$")
_RESOLUTION_RE = re.compile(r"^\d{2,5}x\d{2,5}$", re.I)
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,119}$")
_LEGACY_SCREEN_OUTPUT_RE = re.compile(r"^SCREEN-\d+$", re.I)
_MAX_SCHEDULE_DAYS = 3660
_CATALOG_MAX_LIMIT = 1000
_CATALOG_MAX_OFFSET = 1_000_000
# Agent display capabilities arrive with an authenticated heartbeat, but the
# Media pages can be opened far more frequently than a heartbeat changes.
# Retaining a short refresh interval keeps "last synchronization" meaningful
# without turning every page view into a SQLite write.
_SCREEN_OBSERVATION_REFRESH_SECONDS = 300


class CampaignStoreError(ValueError):
    """A validated business rule prevented a Media operation."""


class CampaignConflictError(CampaignStoreError):
    """A screen has overlapping programming without a resolvable priority."""

    def __init__(self, conflicts: list[dict[str, Any]]) -> None:
        self.conflicts = conflicts
        labels = ", ".join(str(item.get("screen_name") or item.get("screen_id") or "pantalla") for item in conflicts[:3])
        super().__init__(
            "Existe una programación simultánea sin prioridad explícita para: "
            + (labels or "una pantalla")
            + "."
        )


@dataclass(frozen=True, slots=True)
class ScheduleWindow:
    start_date: str
    end_date: str
    weekdays: tuple[int, ...]
    start_time: str
    end_time: str
    blackout_dates: tuple[str, ...]
    timezone: str


@dataclass(frozen=True, slots=True)
class ScreenCapabilityIngestResult:
    """Bounded effects produced by one authenticated display report."""

    observations_updated: int = 0
    screens_remapped: int = 0
    manifest_agent_ids: tuple[str, ...] = ()


def _now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _from_json(value: Any, fallback: Any) -> Any:
    try:
        return json.loads(str(value or ""))
    except Exception:
        return fallback


def _entity_version_token(kind: str, row: sqlite3.Row | dict[str, Any], fields: Iterable[str]) -> str:
    """Return an opaque optimistic-concurrency token for an editable row.

    The token intentionally covers editable state rather than only
    ``updated_at``.  SQLite timestamps have second precision in this product,
    so two edits by the same actor in one second must still produce distinct
    tokens and not silently overwrite each other.
    """
    source = dict(row)
    payload = {field: source.get(field) for field in fields}
    encoded = (str(kind) + ":" + _json(payload)).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


_ASSET_VERSION_FIELDS = (
    "asset_id", "origin_campaign_id", "owner", "display_name", "sha256", "size_bytes", "duration_ms",
    "container", "video_codec", "video_profile", "audio_codec", "audio_profile", "pixel_format",
    "width", "height", "valid_from", "valid_until", "status", "source_type", "blob_relpath",
    "analysis_job_id", "error_message", "updated_at", "updated_by", "archived_at", "archived_by",
)
_SCREEN_VERSION_FIELDS = (
    "screen_id", "site_code", "commercial_name", "physical_location", "agent_id", "output_key",
    "output_label", "orientation", "resolution", "state", "output_identity", "updated_at", "updated_by",
    "archived_at", "archived_by", "playback_mode", "runtime_output_identity", "pause_on_human_activity",
    "emergency_takeover_enabled", "target_kind",
)
_CAMPAIGN_VERSION_FIELDS = (
    # Campaign revisions are immutable, but the current-revision pointer and
    # lifecycle state are deliberately editable.  Include every field that can
    # change the meaning of an operator action so a stale browser/API request
    # cannot quietly create a revision from an older campaign snapshot.
    "campaign_id", "title", "objective", "state", "current_revision_no",
    "updated_at", "updated_by", "archived_at", "archived_by",
)


def _clean_expected_version_token(value: Any) -> str:
    token = _clean_text(value, "La versión de edición", maximum=64)
    if token and not re.fullmatch(r"[0-9a-f]{64}", token):
        raise CampaignStoreError("La versión de edición no es válida.")
    return token


def _assert_expected_version(
    row: sqlite3.Row | dict[str, Any], *, token: str,
    expected_version_token: Any, expected_updated_at: Any, entity_label: str,
) -> None:
    """Reject a stale form before it can overwrite a newer catalog edit."""
    expected_token = _clean_expected_version_token(expected_version_token)
    expected_stamp = _clean_text(expected_updated_at, "La fecha de edición", maximum=80)
    current = dict(row)
    if expected_stamp and expected_stamp != str(current.get("updated_at") or ""):
        raise CampaignStoreError(
            f"{entity_label} cambió mientras lo editabas. Actualiza la página antes de guardar."
        )
    if expected_token and expected_token != token:
        raise CampaignStoreError(
            f"{entity_label} cambió mientras lo editabas. Actualiza la página antes de guardar."
        )


def _clean_text(value: Any, label: str, *, maximum: int, required: bool = False, multiline: bool = False) -> str:
    text = str(value or "").strip()
    if required and not text:
        raise CampaignStoreError(f"{label} es obligatorio.")
    if len(text) > maximum:
        raise CampaignStoreError(f"{label} supera {maximum} caracteres.")
    allowed_controls = "\r\n\t" if multiline else ""
    if any(ord(ch) < 32 and ch not in allowed_controls for ch in text):
        raise CampaignStoreError(f"{label} contiene caracteres no válidos.")
    return text


def _safe_external_detail(value: Any, *, maximum: int = 500) -> str:
    """Bound untrusted Agent/Gateway diagnostics without rejecting a retry.

    Gateway status messages are operational telemetry, not form input.  They
    can contain a newline, a terminal control character, or an overlong stack
    trace.  A strict form validator here would make reconciliation abort and
    leave a durable delivery stuck.  Keep one printable, human-readable line
    for the audit/UI while preserving the full diagnostic in its source system.
    """
    text = "".join(ch if ch.isprintable() else " " for ch in str(value or ""))
    return " ".join(text.split())[:max(1, int(maximum))]


def _clean_identifier(value: Any, label: str, *, maximum: int = 120, required: bool = True) -> str:
    text = _clean_text(value, label, maximum=maximum, required=required)
    if text and not _ID_RE.fullmatch(text):
        raise CampaignStoreError(f"{label} sólo puede usar letras, números, punto, guion, guion bajo, dos puntos o barra.")
    return text


def _clean_state(value: Any, *, screen: bool = False) -> str:
    state = str(value or ("READY" if screen else "DRAFT")).strip().upper()
    accepted = SCREEN_STATES if screen else CAMPAIGN_STATES
    if state not in accepted:
        raise CampaignStoreError("Estado no válido.")
    return state


def _clean_screen_playback_mode(value: Any) -> str:
    mode = str(value or "DEDICATED").strip().upper()
    aliases = {
        "SHARED": "SHARED_PAUSE_ON_HUMAN_ACTIVITY",
        "SHARED_PAUSE": "SHARED_PAUSE_ON_HUMAN_ACTIVITY",
        "PAUSE_WHEN_HUMAN_ACTIVE": "SHARED_PAUSE_ON_HUMAN_ACTIVITY",
        "DEDICATED_PHYSICAL": "DEDICATED",
    }
    mode = aliases.get(mode, mode)
    if mode not in SCREEN_PLAYBACK_MODES:
        raise CampaignStoreError("El modo de uso de la pantalla no es válido.")
    return mode


def _clean_screen_target_kind(value: Any, *, legacy_default: bool = True) -> str:
    """Return the explicit Player destination class for one Screen.

    Historic rows predate destination classes and are migrated to the safe
    physical-connector behaviour.  Once a value is supplied it is validated
    strictly: a Wayland session is never silently treated as HDMI (or the
    reverse) merely because an output key happens to match.
    """
    text = str(value or "").strip().upper()
    if not text and legacy_default:
        return "PHYSICAL_CONNECTOR"
    aliases = {
        "PHYSICAL": "PHYSICAL_CONNECTOR",
        "HDMI": "PHYSICAL_CONNECTOR",
        "WAYLAND": "LOCAL_WAYLAND_SESSION",
        "LOCAL_WAYLAND": "LOCAL_WAYLAND_SESSION",
    }
    text = aliases.get(text, text)
    if text not in SCREEN_TARGET_KINDS:
        raise CampaignStoreError("El tipo de destino de reproducción no es válido.")
    return text


def _clean_output_identity(value: Any) -> str:
    """Accept a bounded stable connector/EDID identity, never raw EDID data."""
    identity = _clean_text(value, "La identidad física de la salida", maximum=120)
    if identity and not _ID_RE.fullmatch(identity):
        raise CampaignStoreError("La identidad física de la salida no es válida.")
    return identity


def _player_output_binding(
    output_key: Any, output_identity: Any, target_kind: Any = "PHYSICAL_CONNECTOR",
) -> str:
    """Return the one stable Player target used for duplicate protection.

    New Screen records bind an explicit output target using the identity
    reported by the Agent. Older records have only ``OutputKey``;
    retaining that fallback makes the migration compatible without weakening
    the one-campaign-per-output invariant.
    """
    kind = _clean_screen_target_kind(target_kind)
    identity = _clean_output_identity(output_identity)
    if identity:
        return f"{kind.casefold()}:{identity.casefold()}"
    return f"{kind.casefold()}:{_clean_identifier(output_key, 'El destino de reproducción', maximum=120).casefold()}"


def _clean_schedule_preset(value: Any) -> str:
    preset = str(value or "CUSTOM").strip().upper()
    aliases = {
        "ONCE": "DATE_RANGE",
        "DATE": "DATE_RANGE",
        "DATE_TIME": "DATE_RANGE",
        "EVERY_DAY": "ALWAYS",
        "EVERYDAY": "ALWAYS",
        "ALL_DAYS": "ALWAYS",
        "WEEKDAY": "WEEKDAYS",
        "WEEKEND": "WEEKENDS",
    }
    preset = aliases.get(preset, preset)
    if preset not in SCHEDULE_PRESETS:
        raise CampaignStoreError("El tipo de programación no es válido.")
    return preset


def _clean_datetime_local(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if not _DATETIME_LOCAL_RE.fullmatch(text):
        raise CampaignStoreError(f"{label} debe usar fecha y hora local válidas.")
    try:
        parsed = dt.datetime.fromisoformat(text.replace(" ", "T"))
    except ValueError as exc:
        raise CampaignStoreError(f"{label} no es una fecha y hora válida.") from exc
    if parsed.tzinfo is not None:
        raise CampaignStoreError(f"{label} debe ser una hora local sin zona embebida.")
    return parsed.replace(second=0, microsecond=0).isoformat(timespec="minutes")


def _truthy(value: Any, *, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().casefold() in {"1", "true", "yes", "on", "si", "sí"}


def _clean_resolution(value: Any) -> str:
    text = str(value or "").strip().lower().replace("×", "x")
    if not text:
        return ""
    if not _RESOLUTION_RE.fullmatch(text):
        raise CampaignStoreError("La resolución debe usar el formato 1920x1080.")
    width, height = (int(part) for part in text.split("x", 1))
    if width < 16 or height < 16:
        raise CampaignStoreError("La resolución indicada no es válida.")
    return f"{width}x{height}"


def _clean_date(value: Any, label: str, *, required: bool = False) -> str:
    text = str(value or "").strip()
    if not text and not required:
        return ""
    if not _DATE_RE.fullmatch(text):
        raise CampaignStoreError(f"{label} debe usar AAAA-MM-DD.")
    try:
        dt.date.fromisoformat(text)
    except ValueError as exc:
        raise CampaignStoreError(f"{label} no es una fecha válida.") from exc
    return text


def _clean_time(value: Any, label: str, *, required: bool = False) -> str:
    text = str(value or "").strip()
    if not text and not required:
        return ""
    if not _TIME_RE.fullmatch(text):
        raise CampaignStoreError(f"{label} debe usar formato 24 horas HH:MM.")
    return text


def _catalog_limit(value: Any, *, default: int, allow_unbounded: bool = False) -> int:
    """Return a bounded SQLite LIMIT while keeping legacy unbounded callers.

    Catalog endpoints may request a small page, whereas the original
    ``list_campaigns()`` contract returned every matching campaign.  ``-1``
    is SQLite's documented spelling for no limit and lets the latter remain
    backward compatible without interpolating an untrusted value into SQL.
    """
    if value is None and allow_unbounded:
        return -1
    try:
        limit = int(default if value is None else value)
    except (TypeError, ValueError) as exc:
        raise CampaignStoreError("El límite de resultados no es válido.") from exc
    return max(1, min(limit, _CATALOG_MAX_LIMIT))


def _catalog_offset(value: Any) -> int:
    try:
        offset = int(value or 0)
    except (TypeError, ValueError) as exc:
        raise CampaignStoreError("El desplazamiento de resultados no es válido.") from exc
    if offset < 0:
        raise CampaignStoreError("El desplazamiento de resultados no es válido.")
    return min(offset, _CATALOG_MAX_OFFSET)


def _catalog_page_window(
    *, limit: Any, offset: Any, page: Any, page_size: Any,
    default_limit: int, allow_unbounded: bool = False,
) -> tuple[int, int, int]:
    """Normalize legacy offset/limit and API-friendly page/page_size inputs."""
    effective_limit = page_size if page_size is not None else limit
    normalized_limit = _catalog_limit(
        effective_limit, default=default_limit, allow_unbounded=allow_unbounded and page is None,
    )
    if page is None:
        normalized_offset = _catalog_offset(offset)
        current_page = (normalized_offset // normalized_limit) + 1 if normalized_limit > 0 else 1
        return normalized_limit, normalized_offset, current_page
    try:
        current_page = int(page)
    except (TypeError, ValueError) as exc:
        raise CampaignStoreError("La página de resultados no es válida.") from exc
    if current_page < 1:
        raise CampaignStoreError("La página de resultados no es válida.")
    if normalized_limit < 1:
        raise CampaignStoreError("El límite de resultados no es válido.")
    normalized_offset = (current_page - 1) * normalized_limit
    if normalized_offset > _CATALOG_MAX_OFFSET:
        raise CampaignStoreError("La página de resultados supera el límite permitido.")
    return normalized_limit, normalized_offset, current_page


def _catalog_query(search: Any, query: Any) -> str:
    """Keep ``search`` compatibility while exposing ``query`` to HTTP APIs."""
    legacy = _clean_text(search, "La búsqueda", maximum=160)
    modern = _clean_text(query, "La búsqueda", maximum=160)
    if legacy and modern and legacy != modern:
        raise CampaignStoreError("La búsqueda enviada no es consistente.")
    return modern or legacy


def _catalog_search_pattern(value: Any) -> str:
    """Build a literal, bounded LIKE pattern for catalog searches.

    Escaping percent, underscore and backslash avoids treating marketing text
    as a wildcard program.  It also keeps the same search semantics across
    SQLite versions and the Windows/Linux mirrors.
    """
    search = _clean_text(value, "La búsqueda", maximum=160)
    if not search:
        return ""
    escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _parse_days(value: Any) -> tuple[int, ...]:
    if value in (None, "", [], (), set()):
        return tuple(range(7))
    values = value.replace(";", ",").split(",") if isinstance(value, str) else value
    if not isinstance(values, Iterable):
        raise CampaignStoreError("Los días programados no son válidos.")
    result: set[int] = set()
    for raw in values:
        try:
            day = int(raw)
        except (TypeError, ValueError) as exc:
            raise CampaignStoreError("Los días programados deben estar entre 0 y 6.") from exc
        if day < 0 or day > 6:
            raise CampaignStoreError("Los días programados deben estar entre 0 y 6.")
        result.add(day)
    return tuple(sorted(result)) or tuple(range(7))


def _time_ranges(start_time: str, end_time: str) -> tuple[tuple[int, int], ...]:
    """Return same-day minute ranges, correctly handling windows across midnight."""
    start = int(start_time[:2]) * 60 + int(start_time[3:])
    end = int(end_time[:2]) * 60 + int(end_time[3:])
    if start == end:
        return ((0, 24 * 60),)
    if start < end:
        return ((start, end),)
    return ((start, 24 * 60), (0, end))


def _window_active_now(window: ScheduleWindow, now_utc: dt.datetime | None = None) -> bool:
    """Resolve one persisted schedule at issue time, including midnight spans.

    The conflict checker deliberately works on broad calendar ranges.  Player
    publishing needs a different answer: whether an assignment is eligible at
    this instant in the campaign's declared timezone.  Invalid historical
    timezone rows fail closed rather than accidentally activating media.
    """
    try:
        local = (now_utc or dt.datetime.now(dt.timezone.utc)).astimezone(ZoneInfo(window.timezone))
        start = dt.date.fromisoformat(window.start_date)
        end = dt.date.fromisoformat(window.end_date)
    except (ValueError, ZoneInfoNotFoundError):
        return False
    today = local.date()
    if today < start or today > end or today.isoformat() in set(window.blackout_dates):
        return False
    minute = local.hour * 60 + local.minute
    start_minute = int(window.start_time[:2]) * 60 + int(window.start_time[3:])
    end_minute = int(window.end_time[:2]) * 60 + int(window.end_time[3:])
    if start_minute == end_minute:
        return local.weekday() in window.weekdays
    if start_minute < end_minute:
        return local.weekday() in window.weekdays and start_minute <= minute < end_minute
    # After midnight belongs to the schedule day before; its blackout/date and
    # weekday must be evaluated against that origin date, not merely today.
    origin = today if minute >= start_minute else today - dt.timedelta(days=1)
    return (
        start <= origin <= end
        and origin.isoformat() not in set(window.blackout_dates)
        and origin.weekday() in window.weekdays
        and (minute >= start_minute or minute < end_minute)
    )


def _ranges_overlap(left: tuple[tuple[int, int], ...], right: tuple[tuple[int, int], ...]) -> bool:
    return any(max(a0, b0) < min(a1, b1) for a0, a1 in left for b0, b1 in right)


class CampaignStore:
    """Transactional store for screens, campaigns, revisions and schedules."""

    # v1 introduced the planning/inventory catalogue.  v2 added media and
    # delivery state; v3 added a monotonic Player manifest cursor.  v4 keeps
    # physical-display behaviour and human-friendly scheduling additive. v5
    # makes the Agent-reported physical output identity a first-class, unique
    # Screen property, while retaining OutputKey for legacy Agents. v6 adds
    # read-path indexes used by paginated catalogues; it does not rewrite any
    # campaign, media, audit or Player data. v7 records whether the configured
    # destination is a physical connector or the Agent's local Wayland
    # graphical session. Historic rows keep the physical connector default.
    schema_version = 7
    screen_observation_refresh_seconds = _SCREEN_OBSERVATION_REFRESH_SECONDS

    def __init__(self, data_dir: Path, security: Any | None = None) -> None:
        self.security = security
        self.path = (Path(data_dir).resolve() / "media-campaigns.sqlite3")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._connections = SQLiteConnectionFactory(SQLiteConnectionOptions(
            path=self.path,
            timeout_seconds=10,
            isolation_level=None,
            pragmas=(
                "PRAGMA journal_mode=WAL",
                "PRAGMA foreign_keys=ON",
                "PRAGMA busy_timeout=10000",
            ),
        ))
        self.init_schema()

    def connect(self):
        return self._connections.connect()

    def init_schema(self) -> None:
        """Apply only additive, versioned schema changes."""
        with self.connect() as con:
            con.executescript(
                """
                CREATE TABLE IF NOT EXISTS media_schema_versions (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS screens (
                    screen_id TEXT PRIMARY KEY,
                    site_code TEXT NOT NULL COLLATE NOCASE,
                    commercial_name TEXT NOT NULL,
                    physical_location TEXT NOT NULL DEFAULT '',
                    agent_id TEXT NOT NULL,
                    output_key TEXT NOT NULL,
                    output_label TEXT NOT NULL DEFAULT '',
                    orientation TEXT NOT NULL DEFAULT 'LANDSCAPE',
                    resolution TEXT NOT NULL DEFAULT '',
                    state TEXT NOT NULL DEFAULT 'READY',
                    last_sync_at TEXT,
                    created_at TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    updated_by TEXT NOT NULL,
                    archived_at TEXT,
                    archived_by TEXT
                );
                CREATE UNIQUE INDEX IF NOT EXISTS uq_screens_live_site_name
                    ON screens(site_code, commercial_name COLLATE NOCASE)
                    WHERE archived_at IS NULL;
                CREATE UNIQUE INDEX IF NOT EXISTS uq_screens_live_output
                    ON screens(agent_id, output_key)
                    WHERE archived_at IS NULL;
                CREATE INDEX IF NOT EXISTS idx_screens_site_state ON screens(site_code, state, archived_at);
                CREATE INDEX IF NOT EXISTS idx_screens_agent ON screens(agent_id, output_key);
                CREATE TABLE IF NOT EXISTS screen_observations (
                    screen_id TEXT PRIMARY KEY,
                    observed_at TEXT NOT NULL,
                    source TEXT NOT NULL DEFAULT '',
                    connected INTEGER NOT NULL DEFAULT 0,
                    reported_resolution TEXT NOT NULL DEFAULT '',
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    FOREIGN KEY(screen_id) REFERENCES screens(screen_id) ON DELETE RESTRICT
                );
                CREATE TABLE IF NOT EXISTS campaigns (
                    campaign_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    objective TEXT NOT NULL DEFAULT '',
                    state TEXT NOT NULL DEFAULT 'DRAFT',
                    current_revision_no INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    updated_by TEXT NOT NULL,
                    archived_at TEXT,
                    archived_by TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_campaigns_state ON campaigns(state, archived_at, updated_at DESC);
                CREATE TABLE IF NOT EXISTS campaign_revisions (
                    campaign_id TEXT NOT NULL,
                    revision_no INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    objective TEXT NOT NULL DEFAULT '',
                    state TEXT NOT NULL,
                    snapshot_json TEXT NOT NULL,
                    change_note TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    PRIMARY KEY(campaign_id, revision_no),
                    FOREIGN KEY(campaign_id) REFERENCES campaigns(campaign_id) ON DELETE RESTRICT
                );
                CREATE TABLE IF NOT EXISTS playlists (
                    playlist_id TEXT PRIMARY KEY,
                    campaign_id TEXT NOT NULL,
                    revision_no INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(campaign_id, revision_no)
                        REFERENCES campaign_revisions(campaign_id, revision_no) ON DELETE RESTRICT
                );
                CREATE UNIQUE INDEX IF NOT EXISTS uq_playlist_revision_name
                    ON playlists(campaign_id, revision_no, name COLLATE NOCASE);
                CREATE TABLE IF NOT EXISTS playlist_items (
                    item_id TEXT PRIMARY KEY,
                    playlist_id TEXT NOT NULL,
                    sequence_no INTEGER NOT NULL,
                    content_title TEXT NOT NULL,
                    content_note TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(playlist_id) REFERENCES playlists(playlist_id) ON DELETE RESTRICT
                );
                CREATE TABLE IF NOT EXISTS campaign_assignments (
                    assignment_id TEXT PRIMARY KEY,
                    campaign_id TEXT NOT NULL,
                    revision_no INTEGER NOT NULL,
                    screen_id TEXT NOT NULL,
                    playlist_id TEXT NOT NULL,
                    content_title TEXT NOT NULL,
                    content_note TEXT NOT NULL DEFAULT '',
                    priority INTEGER,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(campaign_id, revision_no)
                        REFERENCES campaign_revisions(campaign_id, revision_no) ON DELETE RESTRICT,
                    FOREIGN KEY(screen_id) REFERENCES screens(screen_id) ON DELETE RESTRICT,
                    FOREIGN KEY(playlist_id) REFERENCES playlists(playlist_id) ON DELETE RESTRICT
                );
                CREATE UNIQUE INDEX IF NOT EXISTS uq_assignment_revision_screen
                    ON campaign_assignments(campaign_id, revision_no, screen_id);
                CREATE INDEX IF NOT EXISTS idx_assignment_screen ON campaign_assignments(screen_id, campaign_id, revision_no);
                CREATE TABLE IF NOT EXISTS campaign_schedules (
                    schedule_id TEXT PRIMARY KEY,
                    assignment_id TEXT NOT NULL UNIQUE,
                    timezone TEXT NOT NULL DEFAULT 'America/Lima',
                    start_date TEXT NOT NULL,
                    end_date TEXT NOT NULL,
                    weekdays_json TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT NOT NULL,
                    blackout_dates_json TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(assignment_id) REFERENCES campaign_assignments(assignment_id) ON DELETE RESTRICT
                );
                CREATE INDEX IF NOT EXISTS idx_schedules_dates ON campaign_schedules(start_date, end_date);
                CREATE TABLE IF NOT EXISTS campaign_events (
                    event_id TEXT PRIMARY KEY,
                    entity_type TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    campaign_id TEXT,
                    revision_no INTEGER,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    detail_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS idx_campaign_events_entity ON campaign_events(entity_type, entity_id, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_campaign_events_campaign ON campaign_events(campaign_id, created_at DESC);
                CREATE TRIGGER IF NOT EXISTS campaign_revisions_no_update
                    BEFORE UPDATE ON campaign_revisions
                    BEGIN SELECT RAISE(ABORT, 'campaign revisions are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS campaign_revisions_no_delete
                    BEFORE DELETE ON campaign_revisions
                    BEGIN SELECT RAISE(ABORT, 'campaign revisions are immutable'); END;
                """
            )
            # v1 must remain explicitly recorded for databases created by
            # Phase 2 as well as databases upgraded from Phase 1.
            con.execute(
                "INSERT OR IGNORE INTO media_schema_versions(version,applied_at) VALUES(?,?)",
                (1, _now_iso()),
            )
            versions = {int(row["version"]) for row in con.execute("SELECT version FROM media_schema_versions")}
            if 2 not in versions:
                # Every statement is CREATE IF NOT EXISTS or an additive
                # index/trigger.  If a host loses power part way through, the
                # next boot repeats only idempotent DDL and records v2 last.
                con.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS media_assets (
                        asset_id TEXT PRIMARY KEY,
                        origin_campaign_id TEXT,
                        owner TEXT NOT NULL DEFAULT 'GIDEON',
                        display_name TEXT NOT NULL,
                        sha256 TEXT NOT NULL DEFAULT '',
                        size_bytes INTEGER NOT NULL DEFAULT 0,
                        duration_ms INTEGER NOT NULL DEFAULT 0,
                        container TEXT NOT NULL DEFAULT '',
                        video_codec TEXT NOT NULL DEFAULT '',
                        video_profile TEXT NOT NULL DEFAULT '',
                        audio_codec TEXT NOT NULL DEFAULT '',
                        audio_profile TEXT NOT NULL DEFAULT '',
                        pixel_format TEXT NOT NULL DEFAULT '',
                        width INTEGER NOT NULL DEFAULT 0,
                        height INTEGER NOT NULL DEFAULT 0,
                        valid_from TEXT NOT NULL DEFAULT '',
                        valid_until TEXT NOT NULL DEFAULT '',
                        status TEXT NOT NULL DEFAULT 'QUARANTINED',
                        source_type TEXT NOT NULL DEFAULT 'CAMPAIGN_UPLOAD',
                        blob_relpath TEXT NOT NULL DEFAULT '',
                        analysis_job_id TEXT NOT NULL DEFAULT '',
                        error_message TEXT NOT NULL DEFAULT '',
                        created_at TEXT NOT NULL,
                        created_by TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        updated_by TEXT NOT NULL,
                        archived_at TEXT,
                        archived_by TEXT,
                        FOREIGN KEY(origin_campaign_id) REFERENCES campaigns(campaign_id) ON DELETE RESTRICT
                    );
                    CREATE INDEX IF NOT EXISTS idx_media_assets_status ON media_assets(status, archived_at, updated_at DESC);
                    CREATE INDEX IF NOT EXISTS idx_media_assets_hash ON media_assets(sha256, status);
                    CREATE INDEX IF NOT EXISTS idx_media_assets_campaign ON media_assets(origin_campaign_id, archived_at);
                    CREATE TABLE IF NOT EXISTS media_asset_events (
                        event_id TEXT PRIMARY KEY,
                        asset_id TEXT NOT NULL,
                        action TEXT NOT NULL,
                        actor TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        detail_json TEXT NOT NULL DEFAULT '{}',
                        FOREIGN KEY(asset_id) REFERENCES media_assets(asset_id) ON DELETE RESTRICT
                    );
                    CREATE INDEX IF NOT EXISTS idx_media_asset_events_asset ON media_asset_events(asset_id, created_at DESC);
                    CREATE TABLE IF NOT EXISTS playlist_item_assets (
                        item_id TEXT PRIMARY KEY,
                        asset_id TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY(item_id) REFERENCES playlist_items(item_id) ON DELETE RESTRICT,
                        FOREIGN KEY(asset_id) REFERENCES media_assets(asset_id) ON DELETE RESTRICT
                    );
                    CREATE TABLE IF NOT EXISTS campaign_assignment_assets (
                        assignment_id TEXT PRIMARY KEY,
                        asset_id TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY(assignment_id) REFERENCES campaign_assignments(assignment_id) ON DELETE RESTRICT,
                        FOREIGN KEY(asset_id) REFERENCES media_assets(asset_id) ON DELETE RESTRICT
                    );
                    CREATE TABLE IF NOT EXISTS campaign_assignment_policies (
                        assignment_id TEXT PRIMARY KEY,
                        emergency INTEGER NOT NULL DEFAULT 0,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY(assignment_id) REFERENCES campaign_assignments(assignment_id) ON DELETE RESTRICT
                    );
                    CREATE TABLE IF NOT EXISTS media_agent_assets (
                        agent_id TEXT NOT NULL,
                        sha256 TEXT NOT NULL,
                        size_bytes INTEGER NOT NULL DEFAULT 0,
                        state TEXT NOT NULL DEFAULT 'UNKNOWN',
                        last_confirmed_at TEXT,
                        PRIMARY KEY(agent_id, sha256)
                    );
                    CREATE TABLE IF NOT EXISTS media_agent_deliveries (
                        delivery_id TEXT PRIMARY KEY,
                        agent_id TEXT NOT NULL,
                        asset_id TEXT NOT NULL,
                        sha256 TEXT NOT NULL,
                        preparation_job_id TEXT NOT NULL DEFAULT '',
                        gateway_job_id TEXT NOT NULL DEFAULT '',
                        state TEXT NOT NULL DEFAULT 'PENDING',
                        attempts INTEGER NOT NULL DEFAULT 0,
                        next_retry_at TEXT NOT NULL DEFAULT '',
                        last_error TEXT NOT NULL DEFAULT '',
                        last_sync_at TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        UNIQUE(agent_id, sha256),
                        FOREIGN KEY(asset_id) REFERENCES media_assets(asset_id) ON DELETE RESTRICT
                    );
                    CREATE INDEX IF NOT EXISTS idx_media_deliveries_state ON media_agent_deliveries(state, next_retry_at);
                    CREATE TABLE IF NOT EXISTS media_distribution_targets (
                        target_id TEXT PRIMARY KEY,
                        campaign_id TEXT NOT NULL,
                        revision_no INTEGER NOT NULL,
                        screen_id TEXT NOT NULL,
                        asset_id TEXT NOT NULL,
                        agent_id TEXT NOT NULL,
                        delivery_id TEXT,
                        state TEXT NOT NULL DEFAULT 'PENDING',
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        UNIQUE(campaign_id, revision_no, screen_id, asset_id),
                        FOREIGN KEY(campaign_id, revision_no) REFERENCES campaign_revisions(campaign_id, revision_no) ON DELETE RESTRICT,
                        FOREIGN KEY(screen_id) REFERENCES screens(screen_id) ON DELETE RESTRICT,
                        FOREIGN KEY(asset_id) REFERENCES media_assets(asset_id) ON DELETE RESTRICT,
                        FOREIGN KEY(delivery_id) REFERENCES media_agent_deliveries(delivery_id) ON DELETE RESTRICT
                    );
                    CREATE INDEX IF NOT EXISTS idx_media_distribution_campaign ON media_distribution_targets(campaign_id, revision_no, state);
                    CREATE INDEX IF NOT EXISTS idx_media_distribution_agent ON media_distribution_targets(agent_id, state);
                    CREATE TABLE IF NOT EXISTS media_distribution_events (
                        event_id TEXT PRIMARY KEY,
                        target_id TEXT NOT NULL,
                        action TEXT NOT NULL,
                        state TEXT NOT NULL,
                        actor TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        detail_json TEXT NOT NULL DEFAULT '{}',
                        FOREIGN KEY(target_id) REFERENCES media_distribution_targets(target_id) ON DELETE RESTRICT
                    );
                    CREATE INDEX IF NOT EXISTS idx_media_distribution_events_target ON media_distribution_events(target_id, created_at DESC);
                    CREATE TRIGGER IF NOT EXISTS media_asset_events_no_update
                        BEFORE UPDATE ON media_asset_events
                        BEGIN SELECT RAISE(ABORT, 'media asset events are immutable'); END;
                    CREATE TRIGGER IF NOT EXISTS media_asset_events_no_delete
                        BEFORE DELETE ON media_asset_events
                        BEGIN SELECT RAISE(ABORT, 'media asset events are immutable'); END;
                    CREATE TRIGGER IF NOT EXISTS media_distribution_events_no_update
                        BEFORE UPDATE ON media_distribution_events
                        BEGIN SELECT RAISE(ABORT, 'media distribution events are immutable'); END;
                    CREATE TRIGGER IF NOT EXISTS media_distribution_events_no_delete
                        BEFORE DELETE ON media_distribution_events
                        BEGIN SELECT RAISE(ABORT, 'media distribution events are immutable'); END;
                    """
                )
                con.execute(
                    "INSERT OR IGNORE INTO media_schema_versions(version,applied_at) VALUES(?,?)",
                    (2, _now_iso()),
                )
            versions = {int(row["version"]) for row in con.execute("SELECT version FROM media_schema_versions")}
            if 3 not in versions:
                # This is an operational cursor, not campaign history.  It
                # lets an Agent reject stale/replayed Player manifests while
                # campaign revisions remain immutable in their own tables.
                con.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS media_player_manifest_state (
                        agent_id TEXT PRIMARY KEY,
                        content_sha256 TEXT NOT NULL,
                        manifest_version INTEGER NOT NULL,
                        updated_at TEXT NOT NULL
                    );
                    """
                )
                con.execute(
                    "INSERT OR IGNORE INTO media_schema_versions(version,applied_at) VALUES(?,?)",
                    (3, _now_iso()),
                )
            versions = {int(row["version"]) for row in con.execute("SELECT version FROM media_schema_versions")}
            if 4 not in versions:
                # Screen behaviour belongs to physical inventory rather than
                # a user/RDP session.  Existing screens receive the safe
                # dedicated default lazily through LEFT JOINs, avoiding any
                # destructive rewrite of the installation's inventory.
                #
                # The scheduling presentation is append-only and references
                # the already immutable schedule row.  It stores the intent
                # selected in the calendar UI (for example "weekdays") while
                # the canonical date/time columns remain the runtime source.
                con.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS screen_runtime_policies (
                        screen_id TEXT PRIMARY KEY,
                        playback_mode TEXT NOT NULL DEFAULT 'DEDICATED',
                        output_identity TEXT NOT NULL DEFAULT '',
                        pause_on_human_activity INTEGER NOT NULL DEFAULT 0,
                        emergency_takeover_enabled INTEGER NOT NULL DEFAULT 1,
                        created_at TEXT NOT NULL,
                        created_by TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        updated_by TEXT NOT NULL,
                        FOREIGN KEY(screen_id) REFERENCES screens(screen_id) ON DELETE RESTRICT
                    );
                    CREATE INDEX IF NOT EXISTS idx_screen_runtime_mode
                        ON screen_runtime_policies(playback_mode);
                    CREATE TABLE IF NOT EXISTS campaign_schedule_preferences (
                        schedule_id TEXT PRIMARY KEY,
                        preset TEXT NOT NULL DEFAULT 'CUSTOM',
                        starts_at_local TEXT NOT NULL DEFAULT '',
                        ends_at_local TEXT NOT NULL DEFAULT '',
                        summary TEXT NOT NULL DEFAULT '',
                        created_at TEXT NOT NULL,
                        created_by TEXT NOT NULL,
                        FOREIGN KEY(schedule_id) REFERENCES campaign_schedules(schedule_id) ON DELETE RESTRICT
                    );
                    CREATE TRIGGER IF NOT EXISTS campaign_schedule_preferences_no_update
                        BEFORE UPDATE ON campaign_schedule_preferences
                        BEGIN SELECT RAISE(ABORT, 'campaign schedule preferences are immutable'); END;
                    CREATE TRIGGER IF NOT EXISTS campaign_schedule_preferences_no_delete
                        BEFORE DELETE ON campaign_schedule_preferences
                        BEGIN SELECT RAISE(ABORT, 'campaign schedule preferences are immutable'); END;
                    """
                )
                con.execute(
                    "INSERT OR IGNORE INTO media_schema_versions(version,applied_at) VALUES(?,?)",
                    (4, _now_iso()),
                )
            versions = {int(row["version"]) for row in con.execute("SELECT version FROM media_schema_versions")}
            if 5 not in versions:
                # SQLite cannot create a unique index across ``screens`` and
                # the v4 policy table.  Keep the binding in ``screens`` too,
                # so the uniqueness guarantee survives concurrent WebAdmin
                # edits.  The policy copy remains for old Player manifests.
                columns = {str(row["name"]) for row in con.execute("PRAGMA table_info(screens)")}
                if "output_identity" not in columns:
                    con.execute("ALTER TABLE screens ADD COLUMN output_identity TEXT NOT NULL DEFAULT ''")

                policy_rows = con.execute(
                    """SELECT s.screen_id,s.agent_id,p.output_identity
                         FROM screens s JOIN screen_runtime_policies p ON p.screen_id=s.screen_id
                         WHERE s.archived_at IS NULL AND s.output_identity='' AND p.output_identity<>''
                         ORDER BY s.agent_id,p.output_identity,s.screen_id"""
                ).fetchall()
                claims: dict[tuple[str, str], list[str]] = {}
                for row in policy_rows:
                    identity = str(row["output_identity"] or "")
                    try:
                        binding = _player_output_binding("legacy-output", identity)
                    except CampaignStoreError:
                        # Malformed historical policy remains unbound.  It is
                        # rejected when an operator tries to publish it rather
                        # than making startup or inventory unreadable.
                        continue
                    claims.setdefault((str(row["agent_id"]), binding), []).append(str(row["screen_id"]))
                for (_, _), screen_ids in claims.items():
                    if len(screen_ids) == 1:
                        screen_id = screen_ids[0]
                        row = next(item for item in policy_rows if str(item["screen_id"]) == screen_id)
                        con.execute(
                            "UPDATE screens SET output_identity=? WHERE screen_id=? AND output_identity=''",
                            (str(row["output_identity"]), screen_id),
                        )
                    else:
                        # Do not silently choose one of two historic claims.
                        # They keep legacy OutputKey binding until an operator
                        # resolves the duplicate; the manifest resolver also
                        # fails closed if both are ever selected together.
                        for screen_id in screen_ids:
                            self._event(
                                con, entity_type="SCREEN", entity_id=screen_id,
                                action="screens.output_identity.migration_conflict", actor="system",
                                detail={"reason": "duplicate_legacy_output_identity_requires_review"},
                            )
                con.execute(
                    """CREATE UNIQUE INDEX IF NOT EXISTS uq_screens_live_output_identity
                         ON screens(agent_id,output_identity COLLATE NOCASE)
                         WHERE archived_at IS NULL AND output_identity<>''"""
                )
                con.execute(
                    "INSERT OR IGNORE INTO media_schema_versions(version,applied_at) VALUES(?,?)",
                    (5, _now_iso()),
                )
            versions = {int(row["version"]) for row in con.execute("SELECT version FROM media_schema_versions")}
            if 6 not in versions:
                # These indexes support catalog pagination after the existing
                # state/site filters have narrowed the result.  They are
                # additive, idempotent and deliberately avoid full-text
                # tables so an upgrade cannot rebuild or duplicate catalog
                # records.
                con.executescript(
                    """
                    CREATE INDEX IF NOT EXISTS idx_media_assets_catalog_page
                        ON media_assets(archived_at,updated_at DESC,display_name COLLATE NOCASE,asset_id);
                    CREATE INDEX IF NOT EXISTS idx_campaigns_catalog_page
                        ON campaigns(archived_at,updated_at DESC,title COLLATE NOCASE,campaign_id);
                    """
                )
                con.execute(
                    "INSERT OR IGNORE INTO media_schema_versions(version,applied_at) VALUES(?,?)",
                    (6, _now_iso()),
                )
            versions = {int(row["version"]) for row in con.execute("SELECT version FROM media_schema_versions")}
            if 7 not in versions:
                # A Screen target used to mean "physical connector" by
                # implication. Preserve that meaning for every existing row,
                # then require all new edits/manifests to carry the explicit
                # destination kind. No content or immutable revision changes.
                columns = {str(row["name"]) for row in con.execute("PRAGMA table_info(screens)")}
                if "target_kind" not in columns:
                    con.execute(
                        "ALTER TABLE screens ADD COLUMN target_kind TEXT NOT NULL DEFAULT 'PHYSICAL_CONNECTOR'"
                    )
                # The original unique indexes did not include the target
                # class. Replace them atomically so a compositor output can
                # never be mistaken for (or collide with) a DRM connector
                # having the same display name.
                con.executescript(
                    """
                    DROP INDEX IF EXISTS uq_screens_live_output;
                    DROP INDEX IF EXISTS uq_screens_live_output_identity;
                    CREATE UNIQUE INDEX IF NOT EXISTS uq_screens_live_target_output
                        ON screens(agent_id,target_kind,output_key COLLATE NOCASE)
                        WHERE archived_at IS NULL;
                    CREATE UNIQUE INDEX IF NOT EXISTS uq_screens_live_target_identity
                        ON screens(agent_id,target_kind,output_identity COLLATE NOCASE)
                        WHERE archived_at IS NULL AND output_identity<>'';
                    CREATE INDEX IF NOT EXISTS idx_screens_agent_target
                        ON screens(agent_id,target_kind,output_key);
                    """
                )
                con.execute(
                    "INSERT OR IGNORE INTO media_schema_versions(version,applied_at) VALUES(?,?)",
                    (7, _now_iso()),
                )

    @staticmethod
    def _new_id(prefix: str) -> str:
        return f"{prefix}-{uuid.uuid4().hex}"

    def _audit(self, actor: str, action: str, detail: str, *, resource: str = "", remote_ip: str = "") -> None:
        security = self.security
        if security is None:
            return
        try:
            security.audit(str(actor or "system"), action, "SUCCESS", detail, str(remote_ip or ""), resource=resource)
        except Exception:
            # A secondary audit target must not corrupt the domain transaction.
            pass

    def _event(
        self, con: sqlite3.Connection, *, entity_type: str, entity_id: str, action: str,
        actor: str, detail: dict[str, Any] | None = None, campaign_id: str = "", revision_no: int | None = None,
    ) -> None:
        con.execute(
            """INSERT INTO campaign_events(event_id,entity_type,entity_id,campaign_id,revision_no,action,actor,created_at,detail_json)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                self._new_id("evt"), entity_type, entity_id, campaign_id or None, revision_no,
                action, str(actor or "system"), _now_iso(), _json(detail or {}),
            ),
        )

    def _asset_event(
        self, con: sqlite3.Connection, *, asset_id: str, action: str, actor: str,
        detail: dict[str, Any] | None = None,
    ) -> None:
        con.execute(
            """INSERT INTO media_asset_events(event_id,asset_id,action,actor,created_at,detail_json)
               VALUES(?,?,?,?,?,?)""",
            (self._new_id("mae"), asset_id, action, str(actor or "system"), _now_iso(), _json(detail or {})),
        )

    def _distribution_event(
        self, con: sqlite3.Connection, *, target_id: str, action: str, state: str,
        actor: str, detail: dict[str, Any] | None = None,
    ) -> None:
        con.execute(
            """INSERT INTO media_distribution_events(event_id,target_id,action,state,actor,created_at,detail_json)
               VALUES(?,?,?,?,?,?,?)""",
            (self._new_id("mde"), target_id, action, state, str(actor or "system"), _now_iso(), _json(detail or {})),
        )

    @staticmethod
    def _asset_from_row(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
        item = dict(row)
        item["archived"] = bool(item.get("archived_at"))
        item["version_token"] = _entity_version_token("media-asset", item, _ASSET_VERSION_FIELDS)
        item["has_audio"] = bool(str(item.get("audio_codec") or "").strip())
        item["playback_warning"] = (
            "Este video no contiene audio; se reproducirá en silencio."
            if str(item.get("status") or "").upper() == "READY" and not item["has_audio"]
            else ""
        )
        item["duration_seconds"] = round(max(0, int(item.get("duration_ms") or 0)) / 1000, 3)
        item["resolution"] = (
            f"{int(item.get('width') or 0)}x{int(item.get('height') or 0)}"
            if int(item.get("width") or 0) and int(item.get("height") or 0) else ""
        )
        return item

    @staticmethod
    def _asset_state(value: Any) -> str:
        state = str(value or "QUARANTINED").strip().upper()
        if state not in MEDIA_ASSET_STATES:
            raise CampaignStoreError("Estado del video no válido.")
        return state

    def create_media_asset(
        self, *, display_name: str, actor: str, origin_campaign_id: str = "",
        valid_from: str = "", valid_until: str = "", source_type: str = "CAMPAIGN_UPLOAD",
        remote_ip: str = "",
    ) -> dict[str, Any]:
        """Reserve a MediaAsset before the upload worker starts.

        The reservation is intentionally fast and contains no path, hash or
        codec claim.  Those values are written only after the normal
        quarantine, SHA-256, antivirus and ffprobe worker has succeeded.
        """
        name = _clean_text(display_name, "El nombre del video", maximum=180, required=True)
        origin = _clean_identifier(origin_campaign_id, "La campaña", maximum=120, required=False)
        start = _clean_date(valid_from, "La vigencia inicial")
        end = _clean_date(valid_until, "La vigencia final")
        if start and end and end < start:
            raise CampaignStoreError("La vigencia final no puede ser anterior a la inicial.")
        kind = _clean_identifier(source_type or "CAMPAIGN_UPLOAD", "El origen", maximum=48).upper()
        asset_id = self._new_id("ast")
        stamp = _now_iso()
        with self.connect() as con:
            if origin and con.execute("SELECT 1 FROM campaigns WHERE campaign_id=?", (origin,)).fetchone() is None:
                raise CampaignStoreError("La campaña seleccionada ya no existe.")
            con.execute(
                """INSERT INTO media_assets(asset_id,origin_campaign_id,owner,display_name,valid_from,valid_until,status,
                   source_type,created_at,created_by,updated_at,updated_by)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (asset_id, origin or None, "GIDEON", name, start, end, "QUARANTINED", kind, stamp, actor, stamp, actor),
            )
            self._asset_event(con, asset_id=asset_id, action="media.assets.reserve", actor=actor,
                              detail={"name": name, "source": kind})
        self._audit(actor, "media.assets.reserve", f"Video={name}; Estado=QUARANTINED", resource=asset_id, remote_ip=remote_ip)
        return self.media_asset_detail(asset_id)

    def attach_media_asset_job(self, asset_id: str, job_id: str, *, actor: str = "system") -> dict[str, Any]:
        clean_asset = _clean_identifier(asset_id, "El video", maximum=120)
        clean_job = _clean_text(job_id, "El Job", maximum=180, required=True)
        stamp = _now_iso()
        with self.connect() as con:
            row = con.execute("SELECT asset_id FROM media_assets WHERE asset_id=? AND archived_at IS NULL", (clean_asset,)).fetchone()
            if row is None:
                raise CampaignStoreError("El video ya no está disponible.")
            con.execute(
                "UPDATE media_assets SET analysis_job_id=?,status='ANALYZING',updated_at=?,updated_by=? WHERE asset_id=?",
                (clean_job, stamp, actor, clean_asset),
            )
            self._asset_event(con, asset_id=clean_asset, action="media.assets.analysis_queued", actor=actor,
                              detail={"preparation_job": clean_job})
        return self.media_asset_detail(clean_asset)

    def complete_media_asset(
        self, asset_id: str, *, sha256: str, size_bytes: int, metadata: dict[str, Any],
        blob_relpath: str, actor: str = "system",
    ) -> dict[str, Any]:
        """Mark a reserved asset ready after all server-side controls pass."""
        clean_asset = _clean_identifier(asset_id, "El video", maximum=120)
        digest = str(sha256 or "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise CampaignStoreError("No se pudo confirmar la integridad del video.")
        try:
            size = int(size_bytes)
            duration_ms = int(round(float(metadata.get("duration_seconds") or 0) * 1000))
            width, height = int(metadata.get("width") or 0), int(metadata.get("height") or 0)
        except (TypeError, ValueError) as exc:
            raise CampaignStoreError("La información técnica del video no es válida.") from exc
        if size <= 0 or duration_ms <= 0 or width <= 0 or height <= 0:
            raise CampaignStoreError("La información técnica del video no es válida.")
        relative = _clean_text(blob_relpath, "El almacén del video", maximum=260, required=True)
        if relative.startswith(("/", "\\")) or ".." in Path(relative).parts:
            raise CampaignStoreError("El almacén interno del video no es válido.")
        stamp = _now_iso()
        with self.connect() as con:
            row = con.execute("SELECT * FROM media_assets WHERE asset_id=?", (clean_asset,)).fetchone()
            if row is None:
                raise CampaignStoreError("El video ya no existe.")
            if str(row["status"] or "").upper() == "ARCHIVED":
                raise CampaignStoreError("El video archivado no puede completar análisis.")
            con.execute(
                """UPDATE media_assets SET sha256=?,size_bytes=?,duration_ms=?,container=?,video_codec=?,video_profile=?,
                   audio_codec=?,audio_profile=?,pixel_format=?,width=?,height=?,blob_relpath=?,status='READY',
                   error_message='',updated_at=?,updated_by=? WHERE asset_id=?""",
                (
                    digest, size, duration_ms, str(metadata.get("container") or "MP4"),
                    str(metadata.get("video_codec") or "h264"), str(metadata.get("video_profile") or ""),
                    str(metadata.get("audio_codec") or ""), str(metadata.get("audio_profile") or ""),
                    str(metadata.get("pixel_format") or "yuv420p"), width, height, relative, stamp, actor, clean_asset,
                ),
            )
            self._asset_event(con, asset_id=clean_asset, action="media.assets.ready", actor=actor,
                              detail={"sha256": digest, "size_bytes": size, "duration_ms": duration_ms})
        self._audit(actor, "media.assets.ready", f"Video aprobado; SHA-256={digest[:12]}", resource=clean_asset)
        return self.media_asset_detail(clean_asset)

    def reject_media_asset(self, asset_id: str, *, message: str, actor: str = "system", error: bool = False) -> dict[str, Any]:
        clean_asset = _clean_identifier(asset_id, "El video", maximum=120)
        safe_message = _clean_text(message, "El resultado del análisis", maximum=500, required=True)
        state = "ERROR" if error else "REJECTED"
        stamp = _now_iso()
        with self.connect() as con:
            changed = con.execute(
                "UPDATE media_assets SET status=?,error_message=?,updated_at=?,updated_by=? WHERE asset_id=? AND archived_at IS NULL",
                (state, safe_message, stamp, actor, clean_asset),
            ).rowcount
            if not changed:
                raise CampaignStoreError("El video ya no está disponible.")
            self._asset_event(con, asset_id=clean_asset, action="media.assets.rejected", actor=actor,
                              detail={"state": state, "message": safe_message})
        self._audit(actor, "media.assets.rejected", f"Estado={state}", resource=clean_asset)
        return self.media_asset_detail(clean_asset)

    def media_asset_detail(self, asset_id: str) -> dict[str, Any]:
        clean_asset = _clean_identifier(asset_id, "El video", maximum=120)
        with self.connect() as con:
            row = con.execute("SELECT * FROM media_assets WHERE asset_id=?", (clean_asset,)).fetchone()
            if row is None:
                raise CampaignStoreError("Video no encontrado.")
            events = con.execute(
                "SELECT action,actor,created_at,detail_json FROM media_asset_events WHERE asset_id=? ORDER BY created_at DESC LIMIT 50",
                (clean_asset,),
            ).fetchall()
        item = self._asset_from_row(row)
        safe_events: list[dict[str, Any]] = []
        for event in events:
            event_item = dict(event)
            event_item["detail"] = _from_json(event_item.pop("detail_json", "{}"), {})
            safe_events.append(event_item)
        item["events"] = safe_events
        return item

    def _media_asset_filters(
        self, *, state: str = "", campaign_id: str = "", include_archived: bool = False,
        search: str = "",
    ) -> tuple[str, list[Any]]:
        """Return the shared, parameterized filter for asset list/count APIs."""
        clauses: list[str] = []
        params: list[Any] = []
        if not include_archived:
            clauses.append("archived_at IS NULL")
        if state:
            clauses.append("status=?")
            params.append(self._asset_state(state))
        if campaign_id:
            clauses.append("origin_campaign_id=?")
            params.append(_clean_identifier(campaign_id, "La campaña", maximum=120))
        pattern = _catalog_search_pattern(search)
        if pattern:
            clauses.append(
                "(display_name LIKE ? ESCAPE '\\' OR status LIKE ? ESCAPE '\\' OR container LIKE ? ESCAPE '\\' "
                "OR video_codec LIKE ? ESCAPE '\\' OR audio_codec LIKE ? ESCAPE '\\')"
            )
            params.extend([pattern] * 5)
        return (" WHERE " + " AND ".join(clauses) if clauses else ""), params

    def count_media_assets(
        self, *, state: str = "", campaign_id: str = "", include_archived: bool = False,
        search: str = "",
    ) -> int:
        """Return a server-side catalog total without loading every asset."""
        where, params = self._media_asset_filters(
            state=state, campaign_id=campaign_id, include_archived=include_archived, search=search,
        )
        with self.connect() as con:
            row = con.execute("SELECT COUNT(*) AS total FROM media_assets" + where, params).fetchone()
        return int(row["total"] if row is not None else 0)

    def list_media_assets(
        self, *, state: str = "", campaign_id: str = "", include_archived: bool = False,
        limit: int = 300, offset: int = 0, search: str = "", query: str = "",
        page: int | None = None, page_size: int | None = None,
    ) -> list[dict[str, Any]]:
        """Read one bounded asset page; legacy callers retain the same defaults.

        ``query``/``page``/``page_size`` are the compact HTTP-facing form;
        ``search``/``offset``/``limit`` remain available to existing callers.
        """
        normalized_query = _catalog_query(search, query)
        where, params = self._media_asset_filters(
            state=state, campaign_id=campaign_id, include_archived=include_archived, search=normalized_query,
        )
        page_limit, page_offset, _ = _catalog_page_window(
            limit=limit, offset=offset, page=page, page_size=page_size, default_limit=300,
        )
        params.extend([page_limit, page_offset])
        with self.connect() as con:
            rows = con.execute(
                "SELECT * FROM media_assets" + where
                + " ORDER BY updated_at DESC,display_name COLLATE NOCASE,asset_id LIMIT ? OFFSET ?",
                params,
            ).fetchall()
        return [self._asset_from_row(row) for row in rows]

    def list_media_assets_page(
        self, *, state: str = "", campaign_id: str = "", include_archived: bool = False,
        limit: int = 50, offset: int = 0, search: str = "", query: str = "",
        page: int | None = None, page_size: int | None = None,
    ) -> dict[str, Any]:
        """Return assets and total for API/UI pagination without client-side scans."""
        normalized_query = _catalog_query(search, query)
        page_limit, page_offset, current_page = _catalog_page_window(
            limit=limit, offset=offset, page=page, page_size=page_size, default_limit=50,
        )
        total = self.count_media_assets(
            state=state, campaign_id=campaign_id, include_archived=include_archived, search=normalized_query,
        )
        page_count = max(1, (total + page_limit - 1) // page_limit) if total else 0
        items = self.list_media_assets(
            state=state, campaign_id=campaign_id, include_archived=include_archived,
            limit=page_limit, offset=page_offset, search=normalized_query,
        )
        return {
            "items": items,
            "total": total,
            "limit": page_limit,
            "offset": page_offset,
            "page": current_page,
            "page_size": page_limit,
            "pages": page_count,
            "query": normalized_query,
            "pagination": {
                "page": current_page,
                "page_size": page_limit,
                "total": total,
                "pages": page_count,
                "offset": page_offset,
                "has_previous": current_page > 1,
                "has_next": bool(page_count and current_page < page_count),
            },
        }

    def search_media_assets_compact(
        self, *, query: str = "", state: str = "READY", campaign_id: str = "",
        include_archived: bool = False, page: int = 1, page_size: int = 50,
    ) -> dict[str, Any]:
        """Return only the fields a campaign picker needs, never hashes or paths."""
        page_result = self.list_media_assets_page(
            state=state, campaign_id=campaign_id, include_archived=include_archived,
            query=query, page=page, page_size=page_size,
        )
        page_result["items"] = [
            {
                "asset_id": str(item["asset_id"]),
                "display_name": str(item.get("display_name") or ""),
                "status": str(item.get("status") or ""),
                "duration_seconds": item.get("duration_seconds", 0),
                "resolution": str(item.get("resolution") or ""),
                "valid_from": str(item.get("valid_from") or ""),
                "valid_until": str(item.get("valid_until") or ""),
                "has_audio": bool(item.get("has_audio")),
                "warning": str(item.get("playback_warning") or ""),
                "version_token": str(item.get("version_token") or ""),
            }
            for item in page_result["items"]
        ]
        return page_result

    def media_assets_by_ids(self, asset_ids: Iterable[str], *, include_archived: bool = True) -> dict[str, dict[str, Any]]:
        """Resolve a bounded submitted asset set in one catalog read.

        The Campaign wizard loads video choices lazily.  At submit time it must
        still validate the selected identifiers against the authoritative
        library, but it must not turn 50 screens into 50 SQLite connections.
        This helper intentionally returns no paths or hashes beyond the normal
        domain row; callers decide which fields can reach Marketing.
        """
        clean_ids = list(dict.fromkeys(
            _clean_identifier(value, "El video", maximum=120)
            for value in asset_ids if str(value or "").strip()
        ))
        if not clean_ids:
            return {}
        if len(clean_ids) > 250:
            raise CampaignStoreError("Una campaña no puede resolver más de 250 videos distintos a la vez.")
        clauses = "asset_id IN (%s)" % ",".join("?" for _ in clean_ids)
        if not include_archived:
            clauses += " AND archived_at IS NULL"
        with self.connect() as con:
            rows = con.execute("SELECT * FROM media_assets WHERE " + clauses, clean_ids).fetchall()
        return {str(row["asset_id"]): self._asset_from_row(row) for row in rows}

    def import_transfer_media_asset(
        self, *, display_name: str, sha256: str, size_bytes: int, metadata: dict[str, Any],
        blob_relpath: str, actor: str = "system",
    ) -> dict[str, Any]:
        """Expose a clean, already-promoted MP4 from Transferencias to Marketing.

        It never changes a transfer Job or destination.  A hash-identical
        candidate returns the existing library record, which keeps the
        campaign action idempotent.
        """
        digest = str(sha256 or "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise CampaignStoreError("No se pudo confirmar la integridad del video transferido.")
        with self.connect() as con:
            existing = con.execute(
                "SELECT asset_id FROM media_assets WHERE sha256=? AND status='READY' AND archived_at IS NULL ORDER BY created_at LIMIT 1",
                (digest,),
            ).fetchone()
        if existing is not None:
            return self.media_asset_detail(str(existing["asset_id"]))
        reserved = self.create_media_asset(display_name=display_name, actor=actor, source_type="TRANSFER")
        return self.complete_media_asset(
            str(reserved["asset_id"]), sha256=digest, size_bytes=size_bytes, metadata=metadata,
            blob_relpath=blob_relpath, actor=actor,
        )

    def _assert_assignments_media_ready_in_connection(
        self, con: sqlite3.Connection, assignments: Iterable[dict[str, Any]], *, require_assets: bool = True,
    ) -> list[dict[str, Any]]:
        """Validate a revision while the caller owns its SQLite snapshot.

        Returning the normalized assignments lets the durable outbox build from
        the same revision it validated, instead of a detail read that could be
        superseded by a concurrent revision just before publishing.
        """
        normalized = self._normalize_assignments(assignments, require_schedule=True)
        raw_asset_ids = [str(item.get("asset_id") or "") for item in normalized]
        if require_assets and any(not item for item in raw_asset_ids):
            raise CampaignStoreError("Asigne un video aprobado a cada pantalla antes de publicar.")
        asset_ids = list(dict.fromkeys(item for item in raw_asset_ids if item))
        # ``asset_ids`` deliberately excludes blanks to keep the SQL query
        # bounded; the required check above still rejects an unassigned screen.
        if not asset_ids:
            return normalized
        placeholders = ",".join("?" for _ in asset_ids)
        rows = con.execute(
            "SELECT asset_id,status,valid_from,valid_until,archived_at FROM media_assets WHERE asset_id IN (" + placeholders + ")",
            asset_ids,
        ).fetchall()
        by_id = {str(row["asset_id"]): dict(row) for row in rows}
        for assignment in normalized:
            asset_id = str(assignment.get("asset_id") or "")
            if not asset_id:
                continue
            item = by_id.get(asset_id)
            if item is None or item.get("archived_at"):
                raise CampaignStoreError("Uno de los videos seleccionados ya no está disponible.")
            if str(item.get("status") or "").upper() != "READY":
                raise CampaignStoreError("Espere a que todos los videos terminen el análisis antes de publicar.")
            # A future campaign may legitimately use a future-valid video, but
            # its complete playback range must stay inside that video's
            # declared validity.  Checking only "today" caused campaigns to
            # publish successfully and then run past a video expiry.
            window = assignment.get("schedule") if isinstance(assignment.get("schedule"), dict) else {}
            schedule_start = str(window.get("start_date") or "")
            schedule_end = str(window.get("end_date") or "")
            if str(item.get("valid_from") or "") and schedule_start < str(item["valid_from"]):
                raise CampaignStoreError("La programación de una pantalla inicia antes de la vigencia de su video.")
            if str(item.get("valid_until") or "") and schedule_end > str(item["valid_until"]):
                raise CampaignStoreError("La programación de una pantalla termina después de la vigencia de su video.")
        return normalized

    def assert_assignments_media_ready(self, assignments: Iterable[dict[str, Any]], *, require_assets: bool = True) -> None:
        """Validate that a publishable revision has a ready, in-date asset per screen."""
        with self.connect() as con:
            self._assert_assignments_media_ready_in_connection(con, assignments, require_assets=require_assets)

    def assert_publishable(self, campaign_id: str) -> dict[str, Any]:
        detail = self.campaign_detail(campaign_id)
        self.assert_assignments_media_ready(detail.get("assignments") or [], require_assets=True)
        return detail

    def _media_asset_current_references_in_connection(
        self, con: sqlite3.Connection, asset_id: str,
    ) -> list[dict[str, Any]]:
        """Return only live *current* campaign references for one asset.

        Historical revisions deliberately remain out of this result: they are
        immutable evidence and must never be changed merely because somebody
        corrects a library label.  Current revisions, on the other hand,
        represent an editable campaign plan and protect an asset from being
        silently removed or made invalid underneath that plan.
        """
        rows = con.execute(
            """SELECT c.campaign_id,c.title,c.state,ca.revision_no,ca.assignment_id,
                      COALESCE(s.commercial_name,ca.screen_id) AS screen_name,
                      sch.start_date,sch.end_date
                 FROM campaign_assignment_assets caa
                 JOIN campaign_assignments ca ON ca.assignment_id=caa.assignment_id
                 JOIN campaigns c ON c.campaign_id=ca.campaign_id
                    AND c.current_revision_no=ca.revision_no
                 LEFT JOIN screens s ON s.screen_id=ca.screen_id
                 JOIN campaign_schedules sch ON sch.assignment_id=ca.assignment_id
                WHERE caa.asset_id=? AND c.archived_at IS NULL
                ORDER BY c.updated_at DESC,c.title COLLATE NOCASE,ca.assignment_id""",
            (asset_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def _media_asset_reference_summary_in_connection(
        self, con: sqlite3.Connection, asset_id: str,
    ) -> dict[str, Any]:
        current = self._media_asset_current_references_in_connection(con, asset_id)
        historic = con.execute(
            """SELECT COUNT(*) AS assignment_count,
                      COUNT(DISTINCT ca.campaign_id || ':' || ca.revision_no) AS revision_count
                 FROM campaign_assignment_assets caa
                 JOIN campaign_assignments ca ON ca.assignment_id=caa.assignment_id
                WHERE caa.asset_id=?""",
            (asset_id,),
        ).fetchone()
        active = [
            item for item in current
            if str(item.get("state") or "").upper() in {"SCHEDULED", "ACTIVE"}
        ]
        return {
            "current": current,
            "current_count": len(current),
            "active": active,
            "active_count": len(active),
            "historical_assignment_count": int(historic["assignment_count"] if historic is not None else 0),
            "historical_revision_count": int(historic["revision_count"] if historic is not None else 0),
            # Archiving is intentionally more conservative than playback:
            # even a paused or draft current revision deserves an explicit
            # replacement/revision instead of becoming invalid invisibly.
            "can_archive": not current,
        }

    def media_asset_references(self, asset_id: str) -> dict[str, Any]:
        """Return Marketing-safe usage information for edit/archive guidance."""
        clean_asset = _clean_identifier(asset_id, "El video", maximum=120)
        with self.connect() as con:
            row = con.execute("SELECT asset_id,archived_at FROM media_assets WHERE asset_id=?", (clean_asset,)).fetchone()
            if row is None:
                raise CampaignStoreError("Video no encontrado.")
            summary = self._media_asset_reference_summary_in_connection(con, clean_asset)
        summary["archived"] = bool(row["archived_at"])
        summary["can_archive"] = bool(summary["can_archive"]) and not summary["archived"]
        return summary

    def update_media_asset(
        self, asset_id: str, *, display_name: str, valid_from: str = "", valid_until: str = "",
        actor: str, remote_ip: str = "", expected_updated_at: str = "", expected_version_token: str = "",
    ) -> dict[str, Any]:
        """Edit Marketing metadata without mutating bytes, hashes or history.

        The source media remains immutable after ingestion.  Only the
        human-facing label and validity period may change, and a period cannot
        invalidate any live campaign's current revision.  Every real change is
        recorded in the append-only asset event stream and the main audit log.
        """
        clean_asset = _clean_identifier(asset_id, "El video", maximum=120)
        name = _clean_text(display_name, "El nombre del video", maximum=180, required=True)
        start = _clean_date(valid_from, "La vigencia inicial")
        end = _clean_date(valid_until, "La vigencia final")
        if start and end and end < start:
            raise CampaignStoreError("La vigencia final no puede ser anterior a la inicial.")
        stamp = _now_iso()
        changed_fields: list[str] = []
        with self.connect() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                row = con.execute("SELECT * FROM media_assets WHERE asset_id=?", (clean_asset,)).fetchone()
                if row is None:
                    raise CampaignStoreError("Video no encontrado.")
                if row["archived_at"]:
                    raise CampaignStoreError("El video está archivado. Su historial se conserva y no puede modificarse.")
                _assert_expected_version(
                    row,
                    token=_entity_version_token("media-asset", row, _ASSET_VERSION_FIELDS),
                    expected_version_token=expected_version_token,
                    expected_updated_at=expected_updated_at,
                    entity_label="El video",
                )
                before = {
                    "display_name": str(row["display_name"] or ""),
                    "valid_from": str(row["valid_from"] or ""),
                    "valid_until": str(row["valid_until"] or ""),
                }
                after = {"display_name": name, "valid_from": start, "valid_until": end}
                changed_fields = [key for key in after if before[key] != after[key]]
                if {"valid_from", "valid_until"}.intersection(changed_fields):
                    references = self._media_asset_current_references_in_connection(con, clean_asset)
                    conflicts: list[str] = []
                    for reference in references:
                        schedule_start = str(reference.get("start_date") or "")
                        schedule_end = str(reference.get("end_date") or "")
                        starts_too_early = bool(start and schedule_start and schedule_start < start)
                        ends_too_late = bool(end and schedule_end and schedule_end > end)
                        if starts_too_early or ends_too_late:
                            conflicts.append(str(reference.get("title") or "campaña actual"))
                    if conflicts:
                        labels = ", ".join(dict.fromkeys(conflicts[:3]))
                        raise CampaignStoreError(
                            "La nueva vigencia no cubre la programación actual de " + labels
                            + ". Cree una nueva revisión de esa campaña o conserve sus fechas."
                        )
                if changed_fields:
                    con.execute(
                        """UPDATE media_assets SET display_name=?,valid_from=?,valid_until=?,updated_at=?,updated_by=?
                           WHERE asset_id=? AND archived_at IS NULL""",
                        (name, start, end, stamp, actor, clean_asset),
                    )
                    self._asset_event(
                        con, asset_id=clean_asset, action="media.assets.edit", actor=actor,
                        detail={"changed": changed_fields, "before": before, "after": after},
                    )
                con.commit()
            except Exception:
                con.rollback()
                raise
        if changed_fields:
            self._audit(
                actor, "media.assets.edit", "Video actualizado; Campos=" + ",".join(changed_fields),
                resource=clean_asset, remote_ip=remote_ip,
            )
        return self.media_asset_detail(clean_asset)

    def archive_media_asset(self, asset_id: str, *, actor: str, remote_ip: str = "") -> dict[str, Any]:
        clean_asset = _clean_identifier(asset_id, "El video", maximum=120)
        stamp = _now_iso()
        with self.connect() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                row = con.execute("SELECT asset_id,archived_at FROM media_assets WHERE asset_id=?", (clean_asset,)).fetchone()
                if row is None or row["archived_at"]:
                    raise CampaignStoreError("El video ya fue archivado o no existe.")
                references = self._media_asset_reference_summary_in_connection(con, clean_asset)
                if references["current"]:
                    labels = ", ".join(
                        dict.fromkeys(str(item.get("title") or "campaña actual") for item in references["current"][:3])
                    )
                    raise CampaignStoreError(
                        "El video todavía está asignado a " + labels
                        + ". Reemplácelo o archive esa campaña antes de eliminarlo de la biblioteca."
                    )
                con.execute(
                    "UPDATE media_assets SET status='ARCHIVED',archived_at=?,archived_by=?,updated_at=?,updated_by=? WHERE asset_id=?",
                    (stamp, actor, stamp, actor, clean_asset),
                )
                self._asset_event(
                    con, asset_id=clean_asset, action="media.assets.archive", actor=actor,
                    detail={"historical_assignment_count": references["historical_assignment_count"]},
                )
                con.commit()
            except Exception:
                con.rollback()
                raise
        self._audit(actor, "media.assets.archive", "Archivo lógico del video", resource=clean_asset, remote_ip=remote_ip)
        return self.media_asset_detail(clean_asset)

    def queue_campaign_distribution(self, campaign_id: str, *, actor: str, remote_ip: str = "") -> list[dict[str, Any]]:
        """Create durable screen targets only; dispatch happens outside this transaction.

        This is the outbox boundary: publishing cannot block on a Gateway or
        offline endpoint, and a WebAdmin restart leaves enough information to
        safely resume delivery later.
        """
        clean_campaign = _clean_identifier(campaign_id, "La campaña", maximum=120)
        stamp = _now_iso()
        created: list[str] = []
        with self.connect() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                current = con.execute(
                    "SELECT current_revision_no,state,archived_at FROM campaigns WHERE campaign_id=?", (clean_campaign,)
                ).fetchone()
                if current is None:
                    raise CampaignStoreError("Campaña no encontrada.")
                if current["archived_at"] or str(current["state"] or "").upper() not in {"SCHEDULED", "ACTIVE"}:
                    raise CampaignStoreError("Sólo una campaña programada o activa puede distribuir contenido.")
                revision_no = int(current["current_revision_no"])
                # Read and validate the *current* revision after acquiring the
                # writer lock.  The previous implementation validated an older
                # revision outside this transaction, then could attach those
                # assets to a newer revision during a concurrent edit.
                assignments = self._current_assignment_definitions(con, clean_campaign, revision_no)
                assignments = self._assert_assignments_media_ready_in_connection(con, assignments, require_assets=True)
                for assignment in assignments:
                    asset_id = str(assignment.get("asset_id") or "")
                    screen_id = str(assignment.get("screen_id") or "")
                    screen = con.execute("SELECT agent_id FROM screens WHERE screen_id=?", (screen_id,)).fetchone()
                    asset = con.execute("SELECT sha256,size_bytes FROM media_assets WHERE asset_id=?", (asset_id,)).fetchone()
                    if screen is None or asset is None:
                        raise CampaignStoreError("Una pantalla o video ya no está disponible.")
                    agent_id, digest = str(screen["agent_id"]), str(asset["sha256"])
                    cached = con.execute(
                        "SELECT state FROM media_agent_assets WHERE agent_id=? AND sha256=?", (agent_id, digest)
                    ).fetchone()
                    prior = con.execute(
                        """SELECT d.*,a.status AS delivery_asset_status,a.archived_at AS delivery_asset_archived
                           FROM media_agent_deliveries d
                           LEFT JOIN media_assets a ON a.asset_id=d.asset_id
                           WHERE d.agent_id=? AND d.sha256=?""", (agent_id, digest)
                    ).fetchone()
                    if prior is None:
                        delivery_id = self._new_id("mdl")
                        delivery_state = "READY" if cached is not None and str(cached["state"]).upper() == "READY" else "PENDING"
                        con.execute(
                            """INSERT INTO media_agent_deliveries(delivery_id,agent_id,asset_id,sha256,state,created_at,updated_at)
                               VALUES(?,?,?,?,?,?,?)""",
                            (delivery_id, agent_id, asset_id, digest, delivery_state, stamp, stamp),
                        )
                    else:
                        delivery_id, delivery_state = str(prior["delivery_id"]), str(prior["state"] or "PENDING").upper()
                        # A hash-identical newer asset may be assigned after an
                        # earlier draft asset was archived.  The delivery key is
                        # intentionally Agent+hash, so retarget only an
                        # unavailable source; otherwise the ready newer asset
                        # would never be eligible for retry.
                        if str(prior["asset_id"] or "") != asset_id and (
                            str(prior["delivery_asset_status"] or "").upper() != "READY"
                            or bool(prior["delivery_asset_archived"])
                        ):
                            con.execute(
                                "UPDATE media_agent_deliveries SET asset_id=?,updated_at=? WHERE delivery_id=?",
                                (asset_id, stamp, delivery_id),
                            )
                        if delivery_state == "READY":
                            delivery_state = "READY"
                        elif delivery_state not in MEDIA_DISTRIBUTION_STATES:
                            delivery_state = "PENDING"
                            con.execute(
                                "UPDATE media_agent_deliveries SET state='PENDING',updated_at=? WHERE delivery_id=?",
                                (stamp, delivery_id),
                            )
                    target_id = self._new_id("mdt")
                    inserted = con.execute(
                        """INSERT OR IGNORE INTO media_distribution_targets(target_id,campaign_id,revision_no,screen_id,asset_id,agent_id,delivery_id,state,created_at,updated_at)
                           VALUES(?,?,?,?,?,?,?,?,?,?)""",
                        (target_id, clean_campaign, revision_no, screen_id, asset_id, agent_id, delivery_id, delivery_state, stamp, stamp),
                    ).rowcount
                    # Fetch the actual key because INSERT OR IGNORE may have
                    # reused the same campaign/revision/screen/asset target.
                    existing = con.execute(
                        "SELECT target_id FROM media_distribution_targets WHERE campaign_id=? AND revision_no=? AND screen_id=? AND asset_id=?",
                        (clean_campaign, revision_no, screen_id, asset_id),
                    ).fetchone()
                    actual_target = str(existing["target_id"]) if existing is not None else target_id
                    if inserted:
                        created.append(actual_target)
                        self._distribution_event(con, target_id=actual_target, action="media.distribution.queued",
                                                 state=delivery_state, actor=actor, detail={"revision": revision_no})
                if created:
                    self._event(con, entity_type="CAMPAIGN", entity_id=clean_campaign, campaign_id=clean_campaign,
                                revision_no=revision_no, action="media.distribution.queued", actor=actor,
                                detail={"targets": len(set(created))})
                con.execute("COMMIT")
            except Exception:
                con.execute("ROLLBACK")
                raise
        if created:
            self._audit(actor, "media.distribution.queued", f"Campaña={clean_campaign}; Pantallas={len(set(created))}", resource=clean_campaign, remote_ip=remote_ip)
        return self.list_campaign_distribution(clean_campaign)

    def pending_media_deliveries(self, *, campaign_id: str = "", now: str = "", limit: int = 100) -> list[dict[str, Any]]:
        stamp = now or _now_iso()
        campaign_filter = ""
        # Placeholder order follows the SQL text: optional campaign filter is
        # inside the EXISTS clause before the retry timestamp.  Binding the
        # timestamp first made scoped retry queries silently return no rows.
        params: list[Any] = []
        if campaign_id:
            campaign_filter = " AND t.campaign_id=?"
            params.append(_clean_identifier(campaign_id, "La campaña", maximum=120))
        params.append(stamp)
        params.append(max(1, min(int(limit), 500)))
        with self.connect() as con:
            rows = con.execute(
                """SELECT d.*,a.display_name,a.blob_relpath,a.size_bytes,a.status AS asset_status
                   FROM media_agent_deliveries d JOIN media_assets a ON a.asset_id=d.asset_id
                   WHERE a.status='READY' AND a.archived_at IS NULL
                     AND EXISTS (
                       SELECT 1 FROM media_distribution_targets t
                       JOIN campaigns c ON c.campaign_id=t.campaign_id
                       WHERE t.delivery_id=d.delivery_id
                         AND t.revision_no=c.current_revision_no
                         AND c.archived_at IS NULL
                         AND c.state IN ('SCHEDULED','ACTIVE')""" + campaign_filter + """
                     ) AND (
                      (d.state='PENDING' AND d.preparation_job_id='' AND d.gateway_job_id='')
                      OR (d.state='ERROR' AND (d.next_retry_at='' OR d.next_retry_at<=?))
                    )
                ORDER BY d.updated_at ASC LIMIT ?""",
                params,
            ).fetchall()
        return [dict(row) for row in rows]

    def mark_media_delivery_dispatched(
        self, delivery_id: str, *, preparation_job_id: str, gateway_job_id: str = "", actor: str = "system",
    ) -> bool:
        clean_preparation = _clean_text(preparation_job_id, "El Job", maximum=180, required=True)
        clean_gateway = _clean_text(gateway_job_id, "El Job Gateway", maximum=180)
        stamp = _now_iso()
        with self.connect() as con:
            row = con.execute(
                "SELECT delivery_id,preparation_job_id,gateway_job_id,state FROM media_agent_deliveries WHERE delivery_id=?",
                (delivery_id,),
            ).fetchone()
            if row is None:
                raise CampaignStoreError("Entrega de video no encontrada.")
            # Operations binds the durable outbox before it starts the local
            # worker.  The application also records the same bind afterwards
            # for compatibility, so the second call must not create another
            # attempt or audit event.
            if (
                str(row["state"] or "").upper() == "SYNCING"
                and str(row["preparation_job_id"] or "") == clean_preparation
                and str(row["gateway_job_id"] or "") == clean_gateway
            ):
                return False
            if str(row["state"] or "").upper() not in {"PENDING", "ERROR"}:
                raise CampaignStoreError("La entrega ya está en curso o fue confirmada.")
            con.execute(
                """UPDATE media_agent_deliveries SET preparation_job_id=?,gateway_job_id=?,state='SYNCING',attempts=attempts+1,last_error='',
                   next_retry_at='',updated_at=? WHERE delivery_id=?""",
                (
                    clean_preparation, clean_gateway, stamp, delivery_id,
                ),
            )
            targets = con.execute("SELECT target_id FROM media_distribution_targets WHERE delivery_id=?", (delivery_id,)).fetchall()
            con.execute("UPDATE media_distribution_targets SET state='SYNCING',updated_at=? WHERE delivery_id=?", (stamp, delivery_id))
            for target in targets:
                self._distribution_event(con, target_id=str(target["target_id"]), action="media.distribution.dispatched",
                                         state="SYNCING", actor=actor, detail={"preparation_job": clean_preparation})
        return True

    def set_media_delivery_gateway_job(self, delivery_id: str, gateway_job_id: str, *, actor: str = "system") -> None:
        clean_job = _clean_text(gateway_job_id, "El Job Gateway", maximum=180, required=True)
        stamp = _now_iso()
        with self.connect() as con:
            changed = con.execute(
                "UPDATE media_agent_deliveries SET gateway_job_id=?,updated_at=? WHERE delivery_id=?",
                (clean_job, stamp, delivery_id),
            ).rowcount
            if not changed:
                raise CampaignStoreError("Entrega de video no encontrada.")
            targets = con.execute("SELECT target_id FROM media_distribution_targets WHERE delivery_id=?", (delivery_id,)).fetchall()
            for target in targets:
                self._distribution_event(con, target_id=str(target["target_id"]), action="media.distribution.gateway_queued",
                                         state="SYNCING", actor=actor, detail={"gateway_job": clean_job})

    def reconcile_media_delivery(
        self, delivery_id: str, *, gateway_state: str, agent_online: bool, error: str = "", actor: str = "system",
    ) -> str:
        """Project Gateway state to all screens using the same Agent asset.

        The projection is intentionally conservative: a queued job for a
        stale Agent is ``OFFLINE`` rather than an error, and it is never
        duplicated until Gateway has reported failure/expiry.
        """
        state = str(gateway_state or "").strip().upper()
        if state in {"RESULT_READY", "COMPLETED", "SUCCESS"}:
            next_state = "READY"
        elif state in {"CLAIMED", "RUNNING", "DISPATCHING"}:
            next_state = "SYNCING"
        elif state in {"QUEUED", "PENDING", ""}:
            next_state = "PENDING" if agent_online else "OFFLINE"
        else:
            next_state = "ERROR"
        safe_error = _safe_external_detail(error, maximum=500) if error else ""
        stamp = _now_iso()
        with self.connect() as con:
            row = con.execute(
                """SELECT d.agent_id,d.sha256,a.size_bytes,d.state,d.next_retry_at,d.last_error FROM media_agent_deliveries d
                   JOIN media_assets a ON a.asset_id=d.asset_id WHERE d.delivery_id=?""",
                (delivery_id,),
            ).fetchone()
            if row is None:
                raise CampaignStoreError("Entrega de video no encontrada.")
            previous_state = str(row["state"] or "PENDING").upper()
            previous_retry = str(row["next_retry_at"] or "")
            previous_error = str(row["last_error"] or "")
            retry = ""
            if next_state == "ERROR":
                # Reconciliation is executed repeatedly from a bounded
                # background worker.  Preserve an existing retry deadline for
                # the same failed delivery; otherwise every status refresh
                # would push the deadline forward forever.
                if previous_state == "ERROR" and previous_retry:
                    retry = previous_retry
                    if not safe_error:
                        safe_error = previous_error
                else:
                    attempts_row = con.execute("SELECT attempts FROM media_agent_deliveries WHERE delivery_id=?", (delivery_id,)).fetchone()
                    attempts = int((attempts_row or {"attempts": 0})["attempts"] or 0)
                    delay = min(3600, max(30, 30 * (2 ** min(attempts, 6))))
                    retry = (dt.datetime.now().astimezone() + dt.timedelta(seconds=delay)).isoformat(timespec="seconds")
            semantic_change = previous_state != next_state or previous_retry != retry or previous_error != safe_error
            con.execute(
                "UPDATE media_agent_deliveries SET state=?,last_error=?,last_sync_at=?,next_retry_at=?,updated_at=? WHERE delivery_id=?",
                (next_state, safe_error, stamp, retry, stamp, delivery_id),
            )
            if semantic_change:
                targets = con.execute("SELECT target_id FROM media_distribution_targets WHERE delivery_id=?", (delivery_id,)).fetchall()
                con.execute("UPDATE media_distribution_targets SET state=?,updated_at=? WHERE delivery_id=?", (next_state, stamp, delivery_id))
                for target in targets:
                    self._distribution_event(con, target_id=str(target["target_id"]), action="media.distribution.reconciled",
                                             state=next_state, actor=actor, detail={"gateway_state": state})
            if next_state == "READY":
                con.execute(
                    """INSERT INTO media_agent_assets(agent_id,sha256,size_bytes,state,last_confirmed_at) VALUES(?,?,?,?,?)
                       ON CONFLICT(agent_id,sha256) DO UPDATE SET size_bytes=excluded.size_bytes,state='READY',last_confirmed_at=excluded.last_confirmed_at""",
                    (str(row["agent_id"]), str(row["sha256"]), int(row["size_bytes"] or 0), "READY", stamp),
                )
        return next_state

    def list_campaign_distribution(self, campaign_id: str) -> list[dict[str, Any]]:
        clean_campaign = _clean_identifier(campaign_id, "La campaña", maximum=120)
        with self.connect() as con:
            rows = con.execute(
                """SELECT t.target_id,t.revision_no,t.state,t.created_at,t.updated_at,s.commercial_name AS screen_name,s.site_code,
                          a.asset_id,a.display_name,a.status AS asset_status,a.duration_ms,a.width,a.height,
                          d.preparation_job_id,d.gateway_job_id,d.state AS delivery_state,d.attempts,d.last_error,d.last_sync_at
                   FROM media_distribution_targets t
                   JOIN screens s ON s.screen_id=t.screen_id
                   JOIN media_assets a ON a.asset_id=t.asset_id
                   LEFT JOIN media_agent_deliveries d ON d.delivery_id=t.delivery_id
                   WHERE t.campaign_id=? ORDER BY t.revision_no DESC,s.site_code,s.commercial_name""",
                (clean_campaign,),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["resolution"] = f"{int(item.get('width') or 0)}x{int(item.get('height') or 0)}" if item.get("width") and item.get("height") else ""
            item["duration_seconds"] = round(int(item.get("duration_ms") or 0) / 1000, 3)
            result.append(item)
        return result

    def agent_ids_for_campaign(self, campaign_id: str) -> list[str]:
        """Return every historically targeted live-screen Agent for a campaign.

        The Player publisher uses this after campaign actions as well as after
        transfer reconciliation.  Retaining prior revision targets is
        deliberate: removing a screen from a new revision must publish an
        empty/re-resolved manifest to the old Agent, otherwise it could keep
        showing the last valid campaign offline.  The resolver still evaluates
        only current live assignments, so historical rows never resurrect
        content by themselves.
        """
        clean_campaign = _clean_identifier(campaign_id, "La campaña", maximum=120)
        with self.connect() as con:
            rows = con.execute(
                """SELECT DISTINCT s.agent_id
                   FROM campaign_assignments ca
                   JOIN screens s ON s.screen_id=ca.screen_id
                   WHERE ca.campaign_id=?
                   ORDER BY s.agent_id""",
                (clean_campaign,),
            ).fetchall()
        return [str(row["agent_id"]) for row in rows if str(row["agent_id"] or "").strip()]

    def _player_manifest_version(self, con: sqlite3.Connection, agent_id: str, assignments: list[dict[str, Any]]) -> int:
        """Allocate a monotonic version only when resolved Player content changes."""
        canonical = (_json({"agent_id": agent_id, "assignments": assignments}) + "\n").encode("utf-8")
        digest = hashlib.sha256(canonical).hexdigest()
        row = con.execute(
            "SELECT content_sha256,manifest_version FROM media_player_manifest_state WHERE agent_id=?", (agent_id,)
        ).fetchone()
        if row is not None and str(row["content_sha256"]) == digest:
            return int(row["manifest_version"])
        version = min(2_147_483_647, (int(row["manifest_version"]) + 1) if row is not None else 1)
        if row is not None and version <= int(row["manifest_version"]):
            raise CampaignStoreError("Se agotó el contador seguro de manifiestos Player para este Agent.")
        stamp = _now_iso()
        con.execute(
            """INSERT INTO media_player_manifest_state(agent_id,content_sha256,manifest_version,updated_at)
               VALUES(?,?,?,?) ON CONFLICT(agent_id) DO UPDATE SET
               content_sha256=excluded.content_sha256,manifest_version=excluded.manifest_version,updated_at=excluded.updated_at""",
            (agent_id, digest, version, stamp),
        )
        return version

    def agent_player_manifest_inputs(self, agent_id: str) -> dict[str, Any] | None:
        """Resolve exactly one eligible assignment per explicit playback target.

        ``None`` retains the Agent's prior valid campaign while the selected
        asset is still being verified/delivered. A dictionary with an empty
        assignment list is an intentional, signed stop manifest. Versions are
        monotonic per Agent, protecting against stale manifest replay.
        """
        clean_agent = _clean_identifier(agent_id, "El Agent", maximum=160)
        with self.connect() as con:
            rows = con.execute(
                """SELECT s.screen_id,s.output_key,s.output_label,s.orientation,s.resolution,s.state,s.target_kind,
                          COALESCE(runtime.playback_mode,'DEDICATED') AS playback_mode,
                          COALESCE(NULLIF(s.output_identity,''),runtime.output_identity,'') AS output_identity,
                          COALESCE(runtime.emergency_takeover_enabled,1) AS emergency_takeover_enabled,
                          c.campaign_id,ca.revision_no,COALESCE(ca.priority,0) AS priority,
                          a.asset_id,a.sha256,a.size_bytes,a.duration_ms,a.status AS asset_status,a.archived_at AS asset_archived,
                          COALESCE(cache.state,'') AS cache_state,COALESCE(policy.emergency,0) AS emergency,
                          sch.timezone,sch.start_date,sch.end_date,sch.weekdays_json,sch.start_time,sch.end_time,sch.blackout_dates_json
                   FROM screens s
                   JOIN campaign_assignments ca ON ca.screen_id=s.screen_id
                   JOIN campaigns c ON c.campaign_id=ca.campaign_id AND c.current_revision_no=ca.revision_no
                   JOIN campaign_schedules sch ON sch.assignment_id=ca.assignment_id
                   LEFT JOIN campaign_assignment_assets link ON link.assignment_id=ca.assignment_id
                   LEFT JOIN media_assets a ON a.asset_id=link.asset_id
                   LEFT JOIN media_agent_assets cache ON cache.agent_id=s.agent_id AND cache.sha256=a.sha256
                   LEFT JOIN campaign_assignment_policies policy ON policy.assignment_id=ca.assignment_id
                   LEFT JOIN screen_runtime_policies runtime ON runtime.screen_id=s.screen_id
                   LEFT JOIN screen_observations observation ON observation.screen_id=s.screen_id
                   WHERE s.agent_id=? AND s.archived_at IS NULL
                     AND s.state IN ('READY','OFFLINE')
                     AND (
                         observation.screen_id IS NULL
                         OR observation.connected=1
                         OR (
                             s.state='READY'
                             AND s.target_kind IN ('PHYSICAL_CONNECTOR','LOCAL_WAYLAND_SESSION')
                         )
                     )
                     AND c.archived_at IS NULL AND c.state IN ('SCHEDULED','ACTIVE')
                   ORDER BY s.output_key,s.screen_id,c.campaign_id,ca.revision_no""",
                (clean_agent,),
            ).fetchall()
            candidates: dict[str, list[dict[str, Any]]] = {}
            for row in rows:
                item = dict(row)
                try:
                    window = self._window_from_row(item)
                except (TypeError, ValueError):
                    return None
                if not _window_active_now(window):
                    continue
                candidates.setdefault(str(item["screen_id"]), []).append(item)
            selected: list[dict[str, Any]] = []
            selected_outputs: dict[str, str] = {}
            for screen_id, options in candidates.items():
                # Emergency always wins; otherwise an explicitly higher
                # priority wins. The deterministic tail is only a safety net
                # for historical rows created before conflict validation.
                options.sort(key=lambda row: (
                    -int(bool(row.get("emergency"))), -int(row.get("priority") or 0),
                    str(row.get("campaign_id") or ""), int(row.get("revision_no") or 0),
                ))
                item = options[0]
                if (
                    not str(item.get("asset_id") or "")
                    or str(item.get("asset_status") or "").upper() != "READY"
                    or bool(item.get("asset_archived"))
                    or str(item.get("cache_state") or "").upper() != "READY"
                ):
                    return None
                try:
                    playback_mode = _clean_screen_playback_mode(item.get("playback_mode") or "DEDICATED")
                    target_kind = _clean_screen_target_kind(item.get("target_kind"))
                    output_identity = _clean_output_identity(item.get("output_identity") or "")
                    output_key = str(item["output_key"])
                    binding = _player_output_binding(output_key, output_identity, target_kind)
                    previous_screen = selected_outputs.get(binding)
                    if previous_screen and previous_screen != screen_id:
                        raise CampaignStoreError(
                            "Dos pantallas activas del mismo equipo usan el mismo destino de reproducción. "
                            "Corrija la pantalla duplicada antes de publicar."
                        )
                    selected_outputs[binding] = screen_id
                    selected.append({
                        "screen_id": screen_id, "output_key": output_key,
                        "target_kind": target_kind,
                        "output_label": str(item.get("output_label") or item["output_key"]),
                        "orientation": str(item.get("orientation") or "landscape").lower(),
                        "resolution": str(item.get("resolution") or "").lower(),
                        "campaign_id": str(item["campaign_id"]), "revision_no": int(item["revision_no"]),
                        "asset_id": str(item["asset_id"]), "sha256": str(item["sha256"] or "").lower(),
                        "size_bytes": int(item["size_bytes"] or 0), "duration_ms": int(item["duration_ms"] or 0),
                        # This policy is signed with the content.  The Agent
                        # can therefore distinguish a physical signage output
                        # from an RDP/VNC/administrative session without a
                        # Marketing page ever receiving technical controls.
                        "policy": {
                            "fullscreen": True,
                            "kiosk": True,
                            "volume": 100,
                            "target_kind": target_kind,
                            "physical_output": target_kind == "PHYSICAL_CONNECTOR",
                            "session_independence": (
                                "PERSISTENT_PHYSICAL_OUTPUT"
                                if target_kind == "PHYSICAL_CONNECTOR" else "LOCAL_WAYLAND_SESSION"
                            ),
                            "screen_mode": playback_mode,
                            "pause_on_human_activity": playback_mode == "SHARED_PAUSE_ON_HUMAN_ACTIVITY",
                            "emergency_takeover": bool(item.get("emergency")) and bool(item.get("emergency_takeover_enabled")),
                            "output_identity": output_identity,
                        },
                    })
                except CampaignStoreError:
                    # An ambiguous physical identity is an operator action
                    # item, not a transient cache miss.  Let the publisher
                    # log it and refuse a signed ambiguous manifest.
                    raise
                except (KeyError, TypeError, ValueError):
                    return None
            selected.sort(key=lambda row: (str(row["output_key"]).casefold(), str(row["screen_id"])))
            con.execute("BEGIN IMMEDIATE")
            try:
                version = self._player_manifest_version(con, clean_agent, selected)
                con.commit()
            except Exception:
                con.rollback()
                raise
        return {"manifest_version": version, "assignments": selected}

    @staticmethod
    def _screen_from_row(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
        item = dict(row)
        item["archived"] = bool(item.get("archived_at"))
        item["connected"] = bool(item.get("connected"))
        try:
            playback_mode = _clean_screen_playback_mode(item.get("playback_mode") or "DEDICATED")
        except CampaignStoreError:
            # A malformed legacy optional policy must fail closed only when a
            # Player manifest is issued; it should not make all inventory
            # pages unreadable.  The default is the historic behaviour.
            playback_mode = "DEDICATED"
        try:
            output_identity = _clean_output_identity(
                item.get("output_identity") or item.get("runtime_output_identity") or ""
            )
        except CampaignStoreError:
            output_identity = ""
        item["playback_mode"] = playback_mode
        item["output_identity"] = output_identity
        try:
            target_kind = _clean_screen_target_kind(item.get("target_kind"))
        except CampaignStoreError:
            target_kind = "PHYSICAL_CONNECTOR"
        item["target_kind"] = target_kind
        item["target_kind_label"] = (
            "Sesión Wayland local" if target_kind == "LOCAL_WAYLAND_SESSION" else "HDMI físico"
        )
        # A registered Screen is durable inventory.  A false/absent capability
        # observation means the Agent could not inspect its graphical session
        # at that moment; it must not make the commercial screen disappear or
        # silently turn it into an offline asset.
        if item["connected"]:
            item["availability_label"] = "Conectada"
            item["availability_state"] = "CONNECTED"
        elif item.get("observed_at"):
            item["availability_label"] = "Sin telemetría gráfica reciente"
            item["availability_state"] = "TELEMETRY_UNAVAILABLE"
        else:
            item["availability_label"] = "Pendiente de detección"
            item["availability_state"] = "PENDING_DETECTION"
        item["session_hint"] = (
            "Sesión Wayland local" if target_kind == "LOCAL_WAYLAND_SESSION"
            else "Salida física persistente"
        )
        item["pause_on_human_activity"] = playback_mode == "SHARED_PAUSE_ON_HUMAN_ACTIVITY"
        item["emergency_takeover_enabled"] = bool(item.get("emergency_takeover_enabled", True))
        # ``playback_policy`` is the concise Marketing-facing value used by
        # existing templates.  The richer projection remains explicit for
        # operational/API consumers without exposing Agent implementation.
        item["playback_policy"] = playback_mode
        item["playback_config"] = {
            "mode": playback_mode,
            "target_kind": target_kind,
            "physical_output": target_kind == "PHYSICAL_CONNECTOR",
            "session_independence": (
                "PERSISTENT_PHYSICAL_OUTPUT"
                if target_kind == "PHYSICAL_CONNECTOR" else "LOCAL_WAYLAND_SESSION"
            ),
            "pause_on_human_activity": item["pause_on_human_activity"],
            "emergency_takeover_enabled": item["emergency_takeover_enabled"],
            "output_identity": output_identity,
        }
        item["version_token"] = _entity_version_token("screen", item, _SCREEN_VERSION_FIELDS)
        item["observed_payload"] = _from_json(item.pop("payload_json", "{}"), {})
        return item

    def create_screen(
        self, *, site_code: str, commercial_name: str, physical_location: str = "",
        agent_id: str, output_key: str, output_label: str = "", orientation: str = "LANDSCAPE",
        resolution: str = "", state: str = "READY", actor: str, remote_ip: str = "",
        playback_mode: str = "DEDICATED", output_identity: str = "", emergency_takeover_enabled: Any = True,
        target_kind: str = "PHYSICAL_CONNECTOR",
        valid_site_codes: Iterable[str] | None = None,
    ) -> dict[str, Any]:
        site = _clean_identifier(site_code, "La sede", maximum=32).upper()
        if valid_site_codes is not None:
            known = {str(code or "").strip().upper() for code in valid_site_codes}
            if site not in known:
                raise CampaignStoreError("La sede seleccionada no existe en el catálogo.")
        name = _clean_text(commercial_name, "El nombre comercial", maximum=120, required=True)
        location = _clean_text(physical_location, "La ubicación física", maximum=300)
        agent = _clean_identifier(agent_id, "El equipo asociado", maximum=160)
        output = _clean_identifier(output_key, "El destino de reproducción", maximum=120)
        label = _clean_text(output_label, "El nombre de la salida", maximum=160)
        direction = str(orientation or "LANDSCAPE").strip().upper()
        if direction not in ORIENTATIONS:
            raise CampaignStoreError("La orientación debe ser horizontal o vertical.")
        display_resolution = _clean_resolution(resolution)
        screen_state = _clean_state(state, screen=True)
        mode = _clean_screen_playback_mode(playback_mode)
        kind = _clean_screen_target_kind(target_kind)
        identity = _clean_output_identity(output_identity)
        emergency_enabled = _truthy(emergency_takeover_enabled, default=True)
        stamp = _now_iso()
        screen_id = self._new_id("scr")
        try:
            with self.connect() as con:
                con.execute(
                    """INSERT INTO screens(screen_id,site_code,commercial_name,physical_location,agent_id,output_key,output_label,
                       orientation,resolution,state,output_identity,target_kind,created_at,created_by,updated_at,updated_by)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (screen_id, site, name, location, agent, output, label, direction, display_resolution,
                     screen_state, identity, kind, stamp, actor, stamp, actor),
                )
                con.execute(
                    """INSERT INTO screen_runtime_policies(
                           screen_id,playback_mode,output_identity,pause_on_human_activity,emergency_takeover_enabled,
                           created_at,created_by,updated_at,updated_by
                       ) VALUES(?,?,?,?,?,?,?,?,?)""",
                    (screen_id, mode, identity, int(mode == "SHARED_PAUSE_ON_HUMAN_ACTIVITY"), int(emergency_enabled),
                     stamp, actor, stamp, actor),
                )
                self._event(con, entity_type="SCREEN", entity_id=screen_id, action="screens.create", actor=actor,
                            detail={"site_code": site, "name": name, "state": screen_state,
                                    "playback_mode": mode, "output_identity": identity, "target_kind": kind,
                                    "emergency_takeover_enabled": emergency_enabled})
        except sqlite3.IntegrityError as exc:
            raise CampaignStoreError("Ya existe una pantalla activa con ese nombre o destino de reproducción.") from exc
        self._audit(actor, "screens.create", f"Pantalla={name}; Sede={site}", resource=screen_id, remote_ip=remote_ip)
        return self.screen_detail(screen_id)

    def update_screen(
        self, screen_id: str, *, commercial_name: str, physical_location: str = "", agent_id: str,
        output_key: str, output_label: str = "", orientation: str = "LANDSCAPE", resolution: str = "",
        state: str = "READY", actor: str, remote_ip: str = "", playback_mode: str | None = None,
        output_identity: str | None = None, emergency_takeover_enabled: Any | None = None,
        target_kind: str | None = None,
        expected_updated_at: str = "", expected_version_token: str = "",
    ) -> dict[str, Any]:
        clean_screen = _clean_identifier(screen_id, "La pantalla", maximum=120)
        name = _clean_text(commercial_name, "El nombre comercial", maximum=120, required=True)
        location = _clean_text(physical_location, "La ubicación física", maximum=300)
        agent = _clean_identifier(agent_id, "El equipo asociado", maximum=160)
        output = _clean_identifier(output_key, "El destino de reproducción", maximum=120)
        label = _clean_text(output_label, "El nombre de la salida", maximum=160)
        direction = str(orientation or "LANDSCAPE").strip().upper()
        if direction not in ORIENTATIONS:
            raise CampaignStoreError("La orientación debe ser horizontal o vertical.")
        display_resolution = _clean_resolution(resolution)
        new_state = _clean_state(state, screen=True)
        stamp = _now_iso()
        existing: dict[str, Any] = {}
        mode = "DEDICATED"
        identity = ""
        kind = "PHYSICAL_CONNECTOR"
        emergency_enabled = True
        policy_changed = False
        manifest_refresh_required = False
        screen_changed = False
        try:
            with self.connect() as con:
                con.execute("BEGIN IMMEDIATE")
                try:
                    row = con.execute(
                        """SELECT s.*,runtime.playback_mode,runtime.output_identity AS runtime_output_identity,
                                  runtime.pause_on_human_activity,runtime.emergency_takeover_enabled
                           FROM screens s LEFT JOIN screen_runtime_policies runtime ON runtime.screen_id=s.screen_id
                           WHERE s.screen_id=?""",
                        (clean_screen,),
                    ).fetchone()
                    if row is None:
                        raise CampaignStoreError("Pantalla no encontrada.")
                    existing = self._screen_from_row(row)
                    if existing.get("archived"):
                        raise CampaignStoreError("Una pantalla archivada no se puede editar; duplíquela para reactivarla.")
                    _assert_expected_version(
                        existing,
                        token=_entity_version_token("screen", existing, _SCREEN_VERSION_FIELDS),
                        expected_version_token=expected_version_token,
                        expected_updated_at=expected_updated_at,
                        entity_label="La pantalla",
                    )
                    current_mode = str(existing.get("playback_mode") or "DEDICATED")
                    current_identity = str(existing.get("output_identity") or "")
                    current_kind = _clean_screen_target_kind(existing.get("target_kind"))
                    current_emergency_enabled = bool(existing.get("emergency_takeover_enabled", True))
                    mode = current_mode if playback_mode is None else _clean_screen_playback_mode(playback_mode)
                    identity = current_identity if output_identity is None else _clean_output_identity(output_identity)
                    kind = current_kind if target_kind is None else _clean_screen_target_kind(target_kind)
                    emergency_enabled = current_emergency_enabled if emergency_takeover_enabled is None else _truthy(
                        emergency_takeover_enabled, default=current_emergency_enabled,
                    )
                    policy_changed = (mode, identity, kind, emergency_enabled) != (
                        current_mode, current_identity, current_kind, current_emergency_enabled,
                    )
                    screen_changed = policy_changed or any((
                        str(existing.get("commercial_name") or "") != name,
                        str(existing.get("physical_location") or "") != location,
                        str(existing.get("agent_id") or "") != agent,
                        str(existing.get("output_key") or "") != output,
                        str(existing.get("output_label") or "") != label,
                        str(existing.get("orientation") or "") != direction,
                        str(existing.get("resolution") or "") != display_resolution,
                        str(existing.get("state") or "") != new_state,
                        str(existing.get("output_identity") or "") != identity,
                        str(existing.get("target_kind") or "PHYSICAL_CONNECTOR") != kind,
                    ))
                    manifest_refresh_required = policy_changed or any((
                        str(existing.get("agent_id") or "") != agent,
                        str(existing.get("output_key") or "") != output,
                        str(existing.get("state") or "") != new_state,
                        str(existing.get("orientation") or "") != direction,
                        str(existing.get("resolution") or "") != display_resolution,
                    ))
                    if screen_changed:
                        changed = con.execute(
                            """UPDATE screens SET commercial_name=?,physical_location=?,agent_id=?,output_key=?,output_label=?,
                               orientation=?,resolution=?,state=?,output_identity=?,target_kind=?,updated_at=?,updated_by=?
                               WHERE screen_id=? AND archived_at IS NULL""",
                            (name, location, agent, output, label, direction, display_resolution,
                             new_state, identity, kind, stamp, actor, clean_screen),
                        ).rowcount
                        if changed != 1:
                            raise CampaignStoreError("La pantalla cambió mientras se editaba. Actualiza la página e inténtalo otra vez.")
                        # ``screen_runtime_policies`` was added after the original
                        # inventory.  UPSERT lets an edited pre-v4 screen acquire its
                        # explicit policy without a migration rewriting historic data.
                        if policy_changed:
                            con.execute(
                                """INSERT INTO screen_runtime_policies(
                                       screen_id,playback_mode,output_identity,pause_on_human_activity,emergency_takeover_enabled,
                                       created_at,created_by,updated_at,updated_by
                                   ) VALUES(?,?,?,?,?,?,?,?,?)
                                   ON CONFLICT(screen_id) DO UPDATE SET
                                       playback_mode=excluded.playback_mode,
                                       output_identity=excluded.output_identity,
                                       pause_on_human_activity=excluded.pause_on_human_activity,
                                       emergency_takeover_enabled=excluded.emergency_takeover_enabled,
                                       updated_at=excluded.updated_at,updated_by=excluded.updated_by""",
                                (clean_screen, mode, identity, int(mode == "SHARED_PAUSE_ON_HUMAN_ACTIVITY"), int(emergency_enabled),
                                 stamp, actor, stamp, actor),
                            )
                        self._event(con, entity_type="SCREEN", entity_id=clean_screen, action="screens.edit", actor=actor,
                                    detail={"name": name, "state": new_state, "target_kind": kind,
                                            "manifest_refresh_required": manifest_refresh_required})
                        if policy_changed:
                            self._event(
                                con, entity_type="SCREEN", entity_id=clean_screen,
                                action="screens.playback_policy.edit", actor=actor,
                                detail={"playback_mode": mode, "output_identity": identity, "target_kind": kind,
                                        "emergency_takeover_enabled": emergency_enabled},
                            )
                    con.commit()
                except Exception:
                    con.rollback()
                    raise
        except sqlite3.IntegrityError as exc:
            raise CampaignStoreError("Otra pantalla activa ya usa ese nombre o destino de reproducción.") from exc
        if screen_changed:
            self._audit(actor, "screens.edit", f"Pantalla={name}", resource=clean_screen, remote_ip=remote_ip)
        if policy_changed:
            self._audit(
                actor, "screens.playback_policy.edit", f"Pantalla={name}; Modo={mode}",
                resource=clean_screen, remote_ip=remote_ip,
            )
        result = self.screen_detail(clean_screen)
        # This transient result is intentionally not persisted in campaign
        # history.  The Web route uses it to enqueue a signed replacement
        # manifest after an output/state change, outside the HTTP request.
        result["manifest_refresh_required"] = manifest_refresh_required
        result["previous_agent_id"] = str(existing.get("agent_id") or "")
        return result

    def archive_screen(self, screen_id: str, *, actor: str, remote_ip: str = "") -> dict[str, Any]:
        """Logically remove a Screen while retaining its complete history.

        This is deliberately not a ``DELETE``.  Campaign revisions and audit
        events may still refer to the physical Screen, so the row remains
        durable and is only removed from future targeting.  The returned
        transient metadata lets WebAdmin publish a signed empty/recomputed
        Player manifest in the background; a form submission never waits for
        Gateway I/O.
        """
        screen = self.screen_detail(screen_id)
        if screen.get("archived"):
            screen["manifest_refresh_required"] = False
            screen["previous_agent_id"] = str(screen.get("agent_id") or "")
            return screen
        stamp = _now_iso()
        with self.connect() as con:
            active = con.execute(
                """SELECT c.title FROM campaigns c
                   JOIN campaign_assignments ca ON ca.campaign_id=c.campaign_id AND ca.revision_no=c.current_revision_no
                   WHERE ca.screen_id=? AND c.archived_at IS NULL AND c.state IN ('SCHEDULED','ACTIVE') LIMIT 1""",
                (screen_id,),
            ).fetchone()
            if active is not None:
                raise CampaignStoreError(
                    "La pantalla está asignada a una campaña activa o programada. Pause o cree una nueva revisión antes de archivarla."
                )
            changed = con.execute(
                """UPDATE screens SET state='ARCHIVED',archived_at=?,archived_by=?,updated_at=?,updated_by=?
                   WHERE screen_id=? AND archived_at IS NULL""",
                (stamp, actor, stamp, actor, screen_id),
            ).rowcount
            if changed != 1:
                raise CampaignStoreError("La pantalla cambió mientras se archivaba. Actualice el inventario e inténtelo otra vez.")
            self._event(con, entity_type="SCREEN", entity_id=screen_id, action="screens.archive", actor=actor,
                        detail={"name": screen.get("commercial_name", ""), "previous_state": screen.get("state", "")})
        self._audit(actor, "screens.archive", f"Pantalla={screen.get('commercial_name', '')}", resource=screen_id, remote_ip=remote_ip)
        result = self.screen_detail(screen_id)
        result["manifest_refresh_required"] = True
        result["previous_agent_id"] = str(screen.get("agent_id") or "")
        return result

    def restore_screen(self, screen_id: str, *, actor: str, remote_ip: str = "") -> dict[str, Any]:
        """Restore a logically archived Screen into a fail-closed review state.

        A restored physical mapping can point at a monitor that has since
        changed.  It therefore returns as ``NEEDS_REVIEW`` rather than
        silently re-enabling Player output.  The operator can edit the mapping
        and explicitly mark it ready after checking the physical monitor.
        """
        screen = self.screen_detail(screen_id)
        if not screen.get("archived"):
            screen["manifest_refresh_required"] = False
            screen["previous_agent_id"] = str(screen.get("agent_id") or "")
            return screen
        stamp = _now_iso()
        try:
            with self.connect() as con:
                changed = con.execute(
                    """UPDATE screens
                       SET state='NEEDS_REVIEW',archived_at=NULL,archived_by=NULL,updated_at=?,updated_by=?
                       WHERE screen_id=? AND archived_at IS NOT NULL""",
                    (stamp, actor, screen_id),
                ).rowcount
                if changed != 1:
                    raise CampaignStoreError("La pantalla cambió mientras se restauraba. Actualice el inventario e inténtelo otra vez.")
                self._event(con, entity_type="SCREEN", entity_id=screen_id, action="screens.restore", actor=actor,
                            detail={"name": screen.get("commercial_name", ""), "state": "NEEDS_REVIEW"})
        except sqlite3.IntegrityError as exc:
            raise CampaignStoreError(
                "No se puede restaurar porque otra pantalla activa ya usa ese nombre o destino de reproducción. "
                "Corrija o archive primero el registro duplicado."
            ) from exc
        self._audit(
            actor, "screens.restore",
            f"Pantalla={screen.get('commercial_name', '')}; Estado=NEEDS_REVIEW",
            resource=screen_id, remote_ip=remote_ip,
        )
        result = self.screen_detail(screen_id)
        result["manifest_refresh_required"] = True
        result["previous_agent_id"] = str(screen.get("agent_id") or "")
        result["restored_to_review"] = True
        return result

    def screen_detail(self, screen_id: str) -> dict[str, Any]:
        with self.connect() as con:
            row = con.execute(
                """SELECT s.*,o.observed_at,o.source,o.connected,o.reported_resolution,o.payload_json,
                          runtime.playback_mode,runtime.output_identity AS runtime_output_identity,runtime.pause_on_human_activity,
                          runtime.emergency_takeover_enabled
                   FROM screens s LEFT JOIN screen_observations o ON o.screen_id=s.screen_id
                   LEFT JOIN screen_runtime_policies runtime ON runtime.screen_id=s.screen_id
                   WHERE s.screen_id=?""",
                (str(screen_id or ""),),
            ).fetchone()
        if row is None:
            raise CampaignStoreError("Pantalla no encontrada.")
        return self._screen_from_row(row)

    def _screen_filters(
        self, *, site_code: str = "", group_agent_ids: Iterable[str] | None = None,
        os_name: str = "", state: str = "", agent_platforms: dict[str, str] | None = None,
        include_archived: bool = False, search: str = "",
    ) -> tuple[str, list[Any]] | None:
        """Build one bounded SQL filter shared by Screen lists and counts.

        The first Media implementation filtered operating system after reading
        every Screen.  That was harmless for a handful of displays, but makes
        a paginated picker inaccurate and needlessly loads a large inventory.
        Resolve the Agent platform list before the query so paging, search and
        filtering all operate on the same server-side result set.
        """
        clauses: list[str] = []
        params: list[Any] = []
        if not include_archived:
            clauses.append("s.archived_at IS NULL")
        if str(site_code or "").strip():
            clauses.append("s.site_code=?")
            params.append(str(site_code).strip().upper())
        if str(state or "").strip():
            clauses.append("s.state=?")
            params.append(_clean_state(state, screen=True))
        members = sorted({str(x).strip() for x in (group_agent_ids or []) if str(x).strip()})
        if group_agent_ids is not None:
            if not members:
                return None
            clauses.append("s.agent_id IN (%s)" % ",".join("?" for _ in members))
            params.extend(members)
        normalized_os = str(os_name or "").strip().lower()
        if normalized_os:
            platforms = {str(key): str(value or "").lower() for key, value in (agent_platforms or {}).items()}
            matching_agents = sorted(agent_id for agent_id, platform in platforms.items() if platform == normalized_os)
            if not matching_agents:
                return None
            clauses.append("s.agent_id IN (%s)" % ",".join("?" for _ in matching_agents))
            params.extend(matching_agents)
        pattern = _catalog_search_pattern(search)
        if pattern:
            clauses.append(
                "(s.commercial_name LIKE ? ESCAPE '\\' OR s.site_code LIKE ? ESCAPE '\\' "
                "OR s.physical_location LIKE ? ESCAPE '\\' OR s.output_label LIKE ? ESCAPE '\\')"
            )
            params.extend([pattern] * 4)
        return (" WHERE " + " AND ".join(clauses) if clauses else ""), params

    @staticmethod
    def _screen_select_sql(where: str) -> str:
        return (
            """SELECT s.*,o.observed_at,o.source,o.connected,o.reported_resolution,o.payload_json,
                      runtime.playback_mode,runtime.output_identity AS runtime_output_identity,runtime.pause_on_human_activity,
                      runtime.emergency_takeover_enabled
               FROM screens s LEFT JOIN screen_observations o ON o.screen_id=s.screen_id
               LEFT JOIN screen_runtime_policies runtime ON runtime.screen_id=s.screen_id"""
            + where
        )

    def list_screens(
        self, *, site_code: str = "", group_agent_ids: Iterable[str] | None = None,
        os_name: str = "", state: str = "", agent_platforms: dict[str, str] | None = None,
        include_archived: bool = False, limit: int | None = None, offset: int = 0,
        search: str = "", query: str = "", page: int | None = None, page_size: int | None = None,
    ) -> list[dict[str, Any]]:
        """Return Screen inventory rows without materializing an entire catalog.

        Legacy callers that omit ``page`` and ``limit`` intentionally retain an
        unbounded result. New page/API callers must use the compact paged
        interface below, keeping a large Screen inventory out of a campaign
        editor's initial HTML.
        """
        normalized_query = _catalog_query(search, query)
        filter_result = self._screen_filters(
            site_code=site_code, group_agent_ids=group_agent_ids, os_name=os_name,
            state=state, agent_platforms=agent_platforms, include_archived=include_archived,
            search=normalized_query,
        )
        if filter_result is None:
            return []
        where, params = filter_result
        page_limit, page_offset, _ = _catalog_page_window(
            limit=limit, offset=offset, page=page, page_size=page_size, default_limit=25,
            allow_unbounded=True,
        )
        params.extend([page_limit, page_offset])
        with self.connect() as con:
            rows = con.execute(
                self._screen_select_sql(where)
                + " ORDER BY s.site_code COLLATE NOCASE,s.commercial_name COLLATE NOCASE,s.screen_id LIMIT ? OFFSET ?",
                params,
            ).fetchall()
        platforms = {str(key): str(value or "").lower() for key, value in (agent_platforms or {}).items()}
        result = []
        for row in rows:
            item = self._screen_from_row(row)
            item["platform"] = platforms.get(str(item.get("agent_id") or ""), "")
            result.append(item)
        return result

    def count_screens(
        self, *, site_code: str = "", group_agent_ids: Iterable[str] | None = None,
        os_name: str = "", state: str = "", agent_platforms: dict[str, str] | None = None,
        include_archived: bool = False, search: str = "", query: str = "",
    ) -> int:
        """Return the compact catalog total using exactly the list filters."""
        normalized_query = _catalog_query(search, query)
        filter_result = self._screen_filters(
            site_code=site_code, group_agent_ids=group_agent_ids, os_name=os_name,
            state=state, agent_platforms=agent_platforms, include_archived=include_archived,
            search=normalized_query,
        )
        if filter_result is None:
            return 0
        where, params = filter_result
        with self.connect() as con:
            row = con.execute("SELECT COUNT(*) AS total FROM screens s" + where, params).fetchone()
        return int(row["total"] if row is not None else 0)

    def list_screens_page(
        self, *, site_code: str = "", group_agent_ids: Iterable[str] | None = None,
        os_name: str = "", state: str = "", agent_platforms: dict[str, str] | None = None,
        include_archived: bool = False, limit: int = 25, offset: int = 0,
        search: str = "", query: str = "", page: int | None = None, page_size: int | None = None,
    ) -> dict[str, Any]:
        """Return a Screen page plus stable server-side paging metadata."""
        normalized_query = _catalog_query(search, query)
        page_limit, page_offset, current_page = _catalog_page_window(
            limit=limit, offset=offset, page=page, page_size=page_size, default_limit=25,
        )
        total = self.count_screens(
            site_code=site_code, group_agent_ids=group_agent_ids, os_name=os_name,
            state=state, agent_platforms=agent_platforms, include_archived=include_archived,
            search=normalized_query,
        )
        page_count = max(1, (total + page_limit - 1) // page_limit) if total else 0
        # If an item disappears between the count and select, returning an
        # empty terminal page is safe. The browser can move back one page.
        items = self.list_screens(
            site_code=site_code, group_agent_ids=group_agent_ids, os_name=os_name,
            state=state, agent_platforms=agent_platforms, include_archived=include_archived,
            limit=page_limit, offset=page_offset, search=normalized_query,
        )
        return {
            "items": items,
            "total": total,
            "limit": page_limit,
            "offset": page_offset,
            "page": current_page,
            "page_size": page_limit,
            "pages": page_count,
            "query": normalized_query,
            "pagination": {
                "page": current_page,
                "page_size": page_limit,
                "total": total,
                "pages": page_count,
                "has_previous": current_page > 1,
                "has_next": bool(page_count and current_page < page_count),
            },
        }

    def screens_by_ids(self, screen_ids: Iterable[str], *, include_archived: bool = False) -> list[dict[str, Any]]:
        """Resolve only explicit selected Screens in one query, preserving order.

        A revision can still show its current assignments even though the
        campaign picker no longer loads the whole inventory.  The bounded list
        also gives form validation a current authoritative Screen snapshot.
        """
        ordered: list[str] = []
        seen: set[str] = set()
        for raw in screen_ids:
            screen_id = _clean_identifier(raw, "La pantalla", maximum=120)
            if not screen_id or screen_id in seen:
                continue
            seen.add(screen_id)
            ordered.append(screen_id)
            if len(ordered) > 250:
                raise CampaignStoreError("Seleccione como máximo 250 pantallas por campaña.")
        if not ordered:
            return []
        clauses = ["s.screen_id IN (%s)" % ",".join("?" for _ in ordered)]
        if not include_archived:
            clauses.append("s.archived_at IS NULL")
        where = " WHERE " + " AND ".join(clauses)
        with self.connect() as con:
            rows = con.execute(self._screen_select_sql(where), ordered).fetchall()
        parsed = [self._screen_from_row(row) for row in rows]
        by_id = {str(item.get("screen_id") or ""): item for item in parsed}
        return [by_id[screen_id] for screen_id in ordered if screen_id in by_id]

    @staticmethod
    def normalized_display_outputs(agent: dict[str, Any]) -> list[dict[str, Any]]:
        """Decode a bounded Agent capability report without exposing identifiers to Marketing."""
        capabilities = agent.get("Capabilities") or agent.get("capabilities") or {}
        if not isinstance(capabilities, dict):
            return []
        display_capability = capabilities.get("Displays") or capabilities.get("Display") or {}
        raw_outputs = display_capability.get("Outputs") if isinstance(display_capability, dict) else display_capability
        if not isinstance(raw_outputs, list):
            return []
        outputs: list[dict[str, Any]] = []
        for raw in raw_outputs[:32]:
            if not isinstance(raw, dict):
                continue
            key = str(raw.get("OutputKey") or raw.get("Id") or raw.get("id") or "").strip()
            if not key or len(key) > 120:
                continue
            label = str(raw.get("Label") or raw.get("Name") or key).strip()[:160]
            resolution = str(raw.get("Resolution") or raw.get("resolution") or "").strip().lower().replace("×", "x")
            if not resolution:
                try:
                    width, height = int(raw.get("Width") or raw.get("width") or 0), int(raw.get("Height") or raw.get("height") or 0)
                    resolution = f"{width}x{height}" if width > 0 and height > 0 else ""
                except (TypeError, ValueError):
                    resolution = ""
            if resolution and not _RESOLUTION_RE.fullmatch(resolution):
                resolution = ""
            orientation = str(raw.get("Orientation") or raw.get("orientation") or "LANDSCAPE").strip().upper()
            if orientation not in ORIENTATIONS:
                orientation = "LANDSCAPE"
            try:
                target_kind = _clean_screen_target_kind(
                    raw.get("TargetKind") if "TargetKind" in raw else raw.get("target_kind")
                )
            except CampaignStoreError:
                # An Agent that explicitly reports an unknown target class is
                # not allowed to masquerade as HDMI. Ignore only that output;
                # the rest of the authenticated capability report remains
                # useful to Marketing.
                continue
            # Agents may report a stable identity made from the connector and
            # an EDID *hash*. Never retain an entire EDID blob in WebAdmin.
            connector = str(raw.get("Connector") or raw.get("connector") or "").strip()[:80]
            identity_raw = raw.get("OutputIdentity") or raw.get("output_identity") or raw.get("Identity")
            if not identity_raw:
                edid_hash = str(raw.get("EdidSha256") or raw.get("edid_sha256") or "").strip().lower()
                identity_raw = f"{connector}:{edid_hash}" if connector and re.fullmatch(r"[0-9a-f]{64}", edid_hash) else connector
            try:
                output_identity = _clean_output_identity(identity_raw)
            except CampaignStoreError:
                output_identity = ""
            outputs.append({
                "output_key": key,
                "label": label,
                "connected": bool(raw.get("Connected", raw.get("connected", False))),
                "enabled": bool(raw.get("Enabled", raw.get("enabled", False))),
                "physical": bool(raw.get("Physical", raw.get("physical", target_kind == "PHYSICAL_CONNECTOR"))),
                "virtual": bool(raw.get("Virtual", raw.get("virtual", target_kind == "LOCAL_WAYLAND_SESSION"))),
                "resolution": resolution,
                "orientation": orientation,
                "primary": bool(raw.get("Primary", raw.get("primary", False))),
                "output_identity": output_identity,
                "connector": connector,
                "target_kind": target_kind,
                "target_kind_label": (
                    "Sesión Wayland local" if target_kind == "LOCAL_WAYLAND_SESSION" else "HDMI físico"
                ),
            })
        return outputs

    def _screen_observation_refresh_due(self, observed_at: Any, now: dt.datetime) -> bool:
        """Return whether unchanged capability telemetry is due for refresh."""
        try:
            refresh_seconds = max(0, int(self.screen_observation_refresh_seconds))
        except (TypeError, ValueError):
            # A malformed local override must favour observability rather than
            # suppressing the next authenticated capability report forever.
            refresh_seconds = _SCREEN_OBSERVATION_REFRESH_SECONDS
        text = str(observed_at or "").strip()
        if not text:
            return True
        try:
            parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return True
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=now.tzinfo)
        return (now - parsed.astimezone(now.tzinfo)).total_seconds() >= refresh_seconds

    def reconcile_screen_capabilities(
        self, agents: Iterable[dict[str, Any]], *, actor: str = "system",
    ) -> ScreenCapabilityIngestResult:
        """Persist observations and safely repair one unambiguous legacy binding.

        Early screen records used synthetic ``SCREEN-N`` keys.  They cannot
        address a modern Linux connector such as ``linux-hdmi-1``.  An
        authenticated Agent report may repair that mapping only when it has
        exactly one connected output, exactly one unresolved legacy Screen,
        and no other live Screen already claims the physical key or identity.
        Ambiguous reports remain operator actions and are never guessed.
        """
        by_agent: dict[
            str, tuple[
                dict[tuple[str, str], dict[str, Any]],
                dict[tuple[str, str], dict[str, Any]],
                tuple[dict[str, Any], ...], str,
            ]
        ] = {}
        for agent in agents:
            if not isinstance(agent, dict):
                continue
            agent_id = str(agent.get("AgentId") or agent.get("agent_id") or agent.get("id") or "").strip()
            if not agent_id:
                continue
            capabilities = agent.get("Capabilities") or agent.get("capabilities") or {}
            display = (
                capabilities.get("Displays") or capabilities.get("Display") or {}
                if isinstance(capabilities, dict) else {}
            )
            raw_outputs = display.get("Outputs") if isinstance(display, dict) else None
            if not isinstance(raw_outputs, list):
                # No display report is different from an authoritative report
                # that contains zero matching outputs. Keep legacy Agents
                # untouched until they advertise this capability.
                continue
            source = (
                str(display.get("Source") or display.get("source") or "agent-capability")[:120]
                if isinstance(display, dict) else "agent-capability"
            )
            outputs = tuple(self.normalized_display_outputs(agent))
            by_identity: dict[tuple[str, str], dict[str, Any]] = {}
            by_key: dict[tuple[str, str], dict[str, Any]] = {}
            for output in outputs:
                kind = _clean_screen_target_kind(output.get("target_kind"))
                identity = str(output.get("output_identity") or "")
                if identity:
                    by_identity.setdefault((kind, identity.casefold()), output)
                by_key.setdefault((kind, str(output["output_key"]).casefold()), output)
            connected = tuple(output for output in outputs if bool(output.get("connected")))
            by_agent[agent_id] = (by_identity, by_key, connected, source)
        if not by_agent:
            return ScreenCapabilityIngestResult()

        observation_count = 0
        remapped_outputs: dict[str, dict[str, Any]] = {}
        remapped_audits: list[tuple[str, str, str, str]] = []
        identity_audits: list[tuple[str, str, str, str]] = []
        manifest_agents: set[str] = set()
        now = dt.datetime.now().astimezone()
        stamp = now.isoformat(timespec="seconds")
        with self.connect() as con:
            # Serialize the small mapping decision with screen edits so the
            # uniqueness checks and conditional UPDATE describe one snapshot.
            con.execute("BEGIN IMMEDIATE")
            placeholders = ",".join("?" for _ in by_agent)
            rows = con.execute(
                f"""SELECT s.screen_id,s.agent_id,s.output_key,s.output_label,s.orientation,s.resolution,
                           s.output_identity,s.target_kind,s.last_sync_at,
                           COALESCE(runtime.output_identity,'') AS runtime_output_identity,
                           observation.observed_at,observation.source,observation.connected,
                           observation.reported_resolution,observation.payload_json
                    FROM screens s LEFT JOIN screen_runtime_policies runtime ON runtime.screen_id=s.screen_id
                    LEFT JOIN screen_observations observation ON observation.screen_id=s.screen_id
                    WHERE s.archived_at IS NULL AND s.agent_id IN ({placeholders})""",
                list(by_agent),
            ).fetchall()
            rows_by_agent: dict[str, list[sqlite3.Row]] = {}
            for row in rows:
                rows_by_agent.setdefault(str(row["agent_id"]), []).append(row)

            for agent_id, agent_rows in rows_by_agent.items():
                by_identity, by_key, connected, source = by_agent[agent_id]
                # Releases before normalized display identities stored Linux's
                # raw DRM connector (for example card1-HDMI-A-1) as the stable
                # identity. Repair only an exact raw-connector match for the
                # same authenticated OutputKey; never replace an EDID/device
                # fingerprint or guess between screens.
                for row in agent_rows:
                    row_kind = _clean_screen_target_kind(row["target_kind"])
                    if row_kind != "PHYSICAL_CONNECTOR":
                        continue
                    target = by_key.get((row_kind, str(row["output_key"]).casefold()))
                    if target is None:
                        continue
                    connector = str(target.get("connector") or "")
                    target_identity = str(target.get("output_identity") or "")
                    screen_identity = str(row["output_identity"] or "")
                    runtime_identity = str(row["runtime_output_identity"] or "")
                    stored_identities = {value.casefold() for value in (screen_identity, runtime_identity) if value}
                    if (
                        not connector or not target_identity or not stored_identities
                        or any(value != connector.casefold() for value in stored_identities)
                        or target_identity.casefold() == connector.casefold()
                    ):
                        continue
                    claimed = any(
                        str(other["screen_id"]) != str(row["screen_id"])
                        and _clean_screen_target_kind(other["target_kind"]) == row_kind
                        and target_identity.casefold() in {
                            str(other["output_identity"] or "").casefold(),
                            str(other["runtime_output_identity"] or "").casefold(),
                        }
                        for other in agent_rows
                    )
                    if claimed:
                        continue
                    screen_id = str(row["screen_id"])
                    con.execute(
                        """UPDATE screens SET output_identity=?,updated_at=?,updated_by=?
                           WHERE screen_id=? AND archived_at IS NULL""",
                        (target_identity, stamp, actor, screen_id),
                    )
                    con.execute(
                        """UPDATE screen_runtime_policies
                           SET output_identity=?,updated_at=?,updated_by=? WHERE screen_id=?""",
                        (target_identity, stamp, actor, screen_id),
                    )
                    self._event(
                        con, entity_type="SCREEN", entity_id=screen_id,
                        action="screens.output_identity.auto_reconciled", actor=actor,
                        detail={
                            "old_output_identity": connector,
                            "output_identity": target_identity,
                            "output_key": str(row["output_key"]),
                            "source": source,
                            "manifest_refresh_required": True,
                        },
                    )
                    identity_audits.append((screen_id, connector, target_identity, agent_id))
                    manifest_agents.add(agent_id)
                connected_physical = tuple(
                    output for output in connected
                    if _clean_screen_target_kind(output.get("target_kind")) == "PHYSICAL_CONNECTOR"
                )
                if len(connected_physical) != 1:
                    continue
                legacy = [
                    row for row in agent_rows
                    if _clean_screen_target_kind(row["target_kind"]) == "PHYSICAL_CONNECTOR"
                    and not str(row["output_identity"] or row["runtime_output_identity"] or "")
                    and _LEGACY_SCREEN_OUTPUT_RE.fullmatch(str(row["output_key"] or ""))
                    and ("PHYSICAL_CONNECTOR", str(row["output_key"] or "").casefold()) not in by_key
                ]
                if len(legacy) != 1:
                    continue
                row = legacy[0]
                target = connected_physical[0]
                target_key = str(target["output_key"])
                target_identity = str(target.get("output_identity") or "")
                claimed = any(
                    str(other["screen_id"]) != str(row["screen_id"])
                        and _clean_screen_target_kind(other["target_kind"]) == "PHYSICAL_CONNECTOR"
                    and (
                        str(other["output_key"] or "").casefold() == target_key.casefold()
                        or bool(target_identity) and str(
                            other["output_identity"] or other["runtime_output_identity"] or ""
                        ).casefold() == target_identity.casefold()
                    )
                    for other in agent_rows
                )
                if claimed:
                    continue
                old_key = str(row["output_key"])
                old_label = str(row["output_label"] or "")
                target_label = str(target.get("label") or target_key)
                label = target_label if not old_label or old_label.casefold() == old_key.casefold() else old_label
                resolution = str(target.get("resolution") or row["resolution"] or "")
                orientation = str(target.get("orientation") or row["orientation"] or "LANDSCAPE")
                changed = con.execute(
                    """UPDATE screens SET output_key=?,output_label=?,orientation=?,resolution=?,output_identity=?,
                              last_sync_at=?,updated_at=?,updated_by=?
                       WHERE screen_id=? AND agent_id=? AND output_key=? AND output_identity='' AND archived_at IS NULL""",
                    (target_key, label, orientation, resolution, target_identity, stamp, stamp, actor,
                     row["screen_id"], agent_id, old_key),
                ).rowcount
                if changed != 1:
                    continue
                policy_changed = con.execute(
                    """UPDATE screen_runtime_policies SET output_identity=?,updated_at=?,updated_by=?
                       WHERE screen_id=?""",
                    (target_identity, stamp, actor, row["screen_id"]),
                ).rowcount
                if policy_changed == 0:
                    con.execute(
                        """INSERT INTO screen_runtime_policies(
                               screen_id,playback_mode,output_identity,pause_on_human_activity,
                               emergency_takeover_enabled,created_at,created_by,updated_at,updated_by
                           ) VALUES(?,?,?,?,?,?,?,?,?)""",
                        (row["screen_id"], "DEDICATED", target_identity, 0, 1, stamp, actor, stamp, actor),
                    )
                self._event(
                    con, entity_type="SCREEN", entity_id=str(row["screen_id"]),
                    action="screens.output.auto_reconciled", actor=actor,
                    detail={
                        "old_output_key": old_key, "output_key": target_key,
                        "output_identity": target_identity, "source": source,
                        "manifest_refresh_required": True,
                    },
                )
                remapped_outputs[str(row["screen_id"])] = target
                remapped_audits.append((str(row["screen_id"]), old_key, target_key, agent_id))
                manifest_agents.add(agent_id)

            for row in rows:
                by_identity, by_key, _, source = by_agent[str(row["agent_id"])]
                row_kind = _clean_screen_target_kind(row["target_kind"])
                stable_identity = str(row["output_identity"] or row["runtime_output_identity"] or "")
                output = remapped_outputs.get(str(row["screen_id"]))
                output = output or (
                    by_identity.get((row_kind, stable_identity.casefold())) if stable_identity else None
                )
                output = output or by_key.get((row_kind, str(row["output_key"]).casefold()))
                payload = {
                    "connected": bool(output and output["connected"]),
                    "resolution": str(output.get("resolution") or "") if output else "",
                    "orientation": str(output.get("orientation") or "") if output else "",
                    "primary": bool(output and output["primary"]),
                    "output_identity": (output.get("output_identity") or "") if output else stable_identity,
                    "target_kind": row_kind,
                }
                unchanged = (
                    str(row["source"] or "") == source
                    and bool(row["connected"]) == bool(payload["connected"])
                    and str(row["reported_resolution"] or "") == str(payload["resolution"])
                    and _from_json(row["payload_json"], {}) == payload
                )
                if unchanged and not self._screen_observation_refresh_due(
                    row["observed_at"] or row["last_sync_at"], now,
                ):
                    continue
                con.execute(
                    """INSERT INTO screen_observations(screen_id,observed_at,source,connected,reported_resolution,payload_json)
                       VALUES(?,?,?,?,?,?)
                       ON CONFLICT(screen_id) DO UPDATE SET observed_at=excluded.observed_at,source=excluded.source,
                       connected=excluded.connected,reported_resolution=excluded.reported_resolution,payload_json=excluded.payload_json""",
                    (row["screen_id"], stamp, source, int(payload["connected"]), payload["resolution"], _json(payload)),
                )
                con.execute("UPDATE screens SET last_sync_at=? WHERE screen_id=?", (stamp, row["screen_id"]))
                observation_count += 1

        for screen_id, old_key, target_key, _ in remapped_audits:
            self._audit(
                actor, "screens.output.auto_reconciled",
                f"Salida física reconciliada: {old_key} -> {target_key}", resource=screen_id,
            )
        for screen_id, old_identity, target_identity, _ in identity_audits:
            self._audit(
                actor, "screens.output_identity.auto_reconciled",
                f"Identidad de salida normalizada: {old_identity} -> {target_identity}", resource=screen_id,
            )
        return ScreenCapabilityIngestResult(
            observations_updated=observation_count,
            screens_remapped=len(remapped_audits) + len(identity_audits),
            manifest_agent_ids=tuple(sorted(manifest_agents)),
        )

    def report_screen_capabilities(self, agents: Iterable[dict[str, Any]]) -> int:
        """Backward-compatible observation count for existing callers."""
        return self.reconcile_screen_capabilities(agents).observations_updated

    @staticmethod
    def _normalize_schedule(value: Any, *, required: bool) -> ScheduleWindow:
        raw = dict(value) if isinstance(value, dict) else {}
        preset = _clean_schedule_preset(raw.get("preset") or raw.get("schedule_preset") or "CUSTOM")
        timezone = _clean_text(raw.get("timezone") or "America/Lima", "La zona horaria", maximum=80, required=True)
        try:
            local_zone = ZoneInfo(timezone)
        except ZoneInfoNotFoundError as exc:
            raise CampaignStoreError("La zona horaria seleccionada no es válida.") from exc
        # Retain the IANA key returned by zoneinfo so two equivalent values
        # do not look different merely by casing/formatting in the conflict
        # checker or immutable campaign revision.
        timezone = str(local_zone.key or timezone)

        # Native calendar/time controls post a local ``datetime-local``
        # value.  Convert it once here, then preserve the existing canonical
        # schedule columns for the Player and conflict checker.
        starts_at = _clean_datetime_local(
            raw.get("starts_at_local") or raw.get("start_at") or raw.get("schedule_start_at"),
            "El inicio programado",
        )
        ends_at = _clean_datetime_local(
            raw.get("ends_at_local") or raw.get("end_at") or raw.get("schedule_end_at"),
            "El fin programado",
        )
        duration_raw = raw.get("duration_minutes") or raw.get("schedule_duration_minutes")
        if starts_at and not ends_at and duration_raw not in (None, ""):
            try:
                duration_minutes = int(duration_raw)
            except (TypeError, ValueError) as exc:
                raise CampaignStoreError("La duración debe indicarse en minutos.") from exc
            if duration_minutes < 1 or duration_minutes > _MAX_SCHEDULE_DAYS * 24 * 60:
                raise CampaignStoreError("La duración de la programación no es válida.")
            ends_at = (dt.datetime.fromisoformat(starts_at) + dt.timedelta(minutes=duration_minutes)).isoformat(timespec="minutes")
        if starts_at:
            parsed_start = dt.datetime.fromisoformat(starts_at)
            raw["start_date"], raw["start_time"] = parsed_start.date().isoformat(), parsed_start.strftime("%H:%M")
        if ends_at:
            parsed_end = dt.datetime.fromisoformat(ends_at)
            raw["end_date"], raw["end_time"] = parsed_end.date().isoformat(), parsed_end.strftime("%H:%M")

        # Marketing can choose a human intent rather than manually assembling
        # dates and weekday numbers.  ``ALWAYS`` is intentionally bounded to
        # the existing ten-year safe planning horizon; it can later be renewed
        # by a new immutable revision rather than silently living forever.
        local_today = dt.datetime.now(local_zone).date()
        if preset == "ALWAYS":
            if not str(raw.get("start_date") or "").strip():
                raw["start_date"] = local_today.isoformat()
            if not str(raw.get("end_date") or "").strip():
                raw["end_date"] = (local_today + dt.timedelta(days=_MAX_SCHEDULE_DAYS)).isoformat()
            raw["start_time"], raw["end_time"], raw["weekdays"] = "00:00", "00:00", list(range(7))
        elif preset in {"WEEKDAYS", "WEEKENDS"}:
            if not str(raw.get("start_date") or "").strip():
                raw["start_date"] = local_today.isoformat()
            if not str(raw.get("end_date") or "").strip():
                raw["end_date"] = (local_today + dt.timedelta(days=_MAX_SCHEDULE_DAYS)).isoformat()
            if not str(raw.get("start_time") or "").strip():
                raw["start_time"] = "00:00"
            if not str(raw.get("end_time") or "").strip():
                raw["end_time"] = "00:00"
            raw["weekdays"] = list(range(5)) if preset == "WEEKDAYS" else [5, 6]

        start_date = _clean_date(raw.get("start_date"), "La fecha de inicio", required=required)
        end_date = _clean_date(raw.get("end_date"), "La fecha de fin", required=required)
        start_time = _clean_time(raw.get("start_time"), "La hora de inicio", required=required)
        end_time = _clean_time(raw.get("end_time"), "La hora de fin", required=required)
        if required and dt.date.fromisoformat(end_date) < dt.date.fromisoformat(start_date):
            raise CampaignStoreError("La fecha de fin no puede ser anterior a la fecha de inicio.")
        if required and (dt.date.fromisoformat(end_date) - dt.date.fromisoformat(start_date)).days > _MAX_SCHEDULE_DAYS:
            raise CampaignStoreError("El rango de programación no puede superar diez años.")
        dates_raw = raw.get("blackout_dates") or raw.get("blocked_dates") or []
        if isinstance(dates_raw, str):
            dates_raw = [value.strip() for value in dates_raw.replace(";", ",").split(",") if value.strip()]
        if not isinstance(dates_raw, Iterable):
            raise CampaignStoreError("Las fechas bloqueadas no son válidas.")
        blackouts = tuple(sorted({_clean_date(date, "Una fecha bloqueada", required=True) for date in list(dates_raw)[:366]}))
        return ScheduleWindow(start_date, end_date, _parse_days(raw.get("weekdays")), start_time, end_time, blackouts, timezone)

    @staticmethod
    def _schedule_presentation(value: Any, window: ScheduleWindow) -> dict[str, Any]:
        raw = value if isinstance(value, dict) else {}
        preset = _clean_schedule_preset(raw.get("preset") or raw.get("schedule_preset") or "CUSTOM")
        starts_at = _clean_datetime_local(
            raw.get("starts_at_local") or raw.get("start_at") or raw.get("schedule_start_at"),
            "El inicio programado",
        ) or f"{window.start_date}T{window.start_time}"
        ends_at = _clean_datetime_local(
            raw.get("ends_at_local") or raw.get("end_at") or raw.get("schedule_end_at"),
            "El fin programado",
        ) or f"{window.end_date}T{window.end_time}"
        weekday_names = {
            tuple(range(7)): "todos los días",
            tuple(range(5)): "lunes a viernes",
            (5, 6): "fines de semana",
        }
        days = weekday_names.get(tuple(window.weekdays), "días seleccionados")
        if preset == "ALWAYS":
            summary = f"Siempre · todos los días · zona {window.timezone}"
        else:
            summary = (
                f"{window.start_date} {window.start_time} — {window.end_date} {window.end_time}"
                f" · {days} · zona {window.timezone}"
            )
        return {
            "preset": preset,
            "starts_at_local": starts_at,
            "ends_at_local": ends_at,
            "summary": summary,
        }

    @staticmethod
    def _schedule_dict(window: ScheduleWindow, presentation: dict[str, Any] | None = None) -> dict[str, Any]:
        result = {
            "start_date": window.start_date,
            "end_date": window.end_date,
            "weekdays": list(window.weekdays),
            "start_time": window.start_time,
            "end_time": window.end_time,
            "blackout_dates": list(window.blackout_dates),
            "timezone": window.timezone,
        }
        if presentation:
            result.update({
                "preset": str(presentation.get("preset") or "CUSTOM"),
                "starts_at_local": str(presentation.get("starts_at_local") or ""),
                "ends_at_local": str(presentation.get("ends_at_local") or ""),
                "summary": str(presentation.get("summary") or ""),
            })
        return result

    def _normalize_assignments(self, assignments: Iterable[dict[str, Any]], *, require_schedule: bool) -> list[dict[str, Any]]:
        if not isinstance(assignments, Iterable) or isinstance(assignments, (str, bytes, dict)):
            raise CampaignStoreError("Debe seleccionar al menos una pantalla.")
        result: list[dict[str, Any]] = []
        screen_ids: set[str] = set()
        for raw in assignments:
            if not isinstance(raw, dict):
                raise CampaignStoreError("Una asignación de pantalla no es válida.")
            screen_id = _clean_identifier(raw.get("screen_id"), "La pantalla", maximum=120)
            if screen_id in screen_ids:
                raise CampaignStoreError("Una pantalla sólo puede aparecer una vez por campaña.")
            screen_ids.add(screen_id)
            playlist_name = _clean_text(raw.get("playlist_name") or "Contenido de campaña", "El nombre de lista", maximum=120, required=True)
            content_title = _clean_text(raw.get("content_title"), "El contenido de la pantalla", maximum=180, required=True)
            content_note = _clean_text(raw.get("content_note"), "La nota de contenido", maximum=500, multiline=True)
            asset_id = _clean_identifier(raw.get("asset_id"), "El video de la pantalla", maximum=120, required=False)
            emergency = bool(raw.get("emergency") in {True, 1, "1", "true", "TRUE", "on", "ON"})
            priority_raw = raw.get("priority")
            priority: int | None = None
            if priority_raw not in (None, ""):
                try:
                    priority = int(priority_raw)
                except (TypeError, ValueError) as exc:
                    raise CampaignStoreError("La prioridad debe ser un número entre 1 y 100.") from exc
                if priority < 1 or priority > 100:
                    raise CampaignStoreError("La prioridad debe estar entre 1 y 100.")
            if emergency and priority is None:
                priority = 100
            schedule_raw = raw.get("schedule") if isinstance(raw.get("schedule"), dict) else raw
            schedule = self._normalize_schedule(schedule_raw, required=require_schedule)
            presentation = self._schedule_presentation(schedule_raw, schedule)
            result.append({
                "screen_id": screen_id,
                "playlist_name": playlist_name,
                "content_title": content_title,
                "content_note": content_note,
                "asset_id": asset_id,
                "emergency": emergency,
                "priority": priority,
                "schedule": self._schedule_dict(schedule, presentation),
            })
        if not result:
            raise CampaignStoreError("Debe seleccionar al menos una pantalla.")
        return result

    def _screen_names(self, con: sqlite3.Connection, screen_ids: Iterable[str]) -> dict[str, str]:
        ids = list(screen_ids)
        if not ids:
            return {}
        rows = con.execute(
            "SELECT screen_id,commercial_name FROM screens WHERE screen_id IN (%s)" % ",".join("?" for _ in ids), ids
        ).fetchall()
        names = {str(row["screen_id"]): str(row["commercial_name"]) for row in rows}
        missing = set(ids) - set(names)
        if missing:
            raise CampaignStoreError("Una pantalla seleccionada ya no existe o fue archivada.")
        return names

    def _assert_assignable_screens(self, con: sqlite3.Connection, screen_ids: Iterable[str]) -> None:
        """New revisions may target only current, non-archived inventory records.

        Historical revisions intentionally use :meth:`_screen_names` instead:
        a later logical deletion must not erase their human-readable history.
        """
        ids = list(screen_ids)
        if not ids:
            return
        rows = con.execute(
            "SELECT screen_id FROM screens WHERE archived_at IS NULL AND screen_id IN (%s)" % ",".join("?" for _ in ids), ids
        ).fetchall()
        available = {str(row["screen_id"]) for row in rows}
        if set(ids) - available:
            raise CampaignStoreError("Una pantalla seleccionada fue archivada o ya no existe.")

    @staticmethod
    def _windows_overlap(left: ScheduleWindow, right: ScheduleWindow) -> bool:
        if not left.start_date or not right.start_date:
            return False
        start = max(dt.date.fromisoformat(left.start_date), dt.date.fromisoformat(right.start_date))
        end = min(dt.date.fromisoformat(left.end_date), dt.date.fromisoformat(right.end_date))
        if end < start or not set(left.weekdays).intersection(right.weekdays):
            return False
        left_ranges = _time_ranges(left.start_time, left.end_time)
        right_ranges = _time_ranges(right.start_time, right.end_time)
        if not _ranges_overlap(left_ranges, right_ranges):
            return False
        excluded = set(left.blackout_dates).union(right.blackout_dates)
        days = min((end - start).days + 1, _MAX_SCHEDULE_DAYS + 1)
        for offset in range(days):
            current = start + dt.timedelta(days=offset)
            if current.weekday() not in left.weekdays or current.weekday() not in right.weekdays:
                continue
            if current.isoformat() not in excluded:
                return True
        return False

    @staticmethod
    def _assert_same_timezone_for_conflict(left: ScheduleWindow, right: ScheduleWindow) -> None:
        """Refuse an unsafe recurring-schedule comparison across time zones.

        The current model intentionally stores a human local calendar window,
        not every DST-expanded UTC occurrence.  Pretending that two local
        ``08:00`` values are comparable would create false positives (or miss
        a daylight-saving overlap).  Until a screen/site timezone is made a
        first-class scheduling source, use a deterministic validation error
        rather than manufacturing a conflict.
        """
        try:
            left_zone = str(ZoneInfo(left.timezone).key or left.timezone)
            right_zone = str(ZoneInfo(right.timezone).key or right.timezone)
        except ZoneInfoNotFoundError as exc:
            raise CampaignStoreError(
                "No se puede validar el horario porque una campaña existente tiene una zona horaria no válida."
            ) from exc
        if left_zone != right_zone:
            raise CampaignStoreError(
                "No se puede comparar de forma segura campañas con zonas horarias distintas en la misma pantalla. "
                "Use una sola zona horaria para esa pantalla antes de publicar."
            )

    @staticmethod
    def _window_from_row(row: dict[str, Any]) -> ScheduleWindow:
        return ScheduleWindow(
            str(row.get("start_date") or ""), str(row.get("end_date") or ""),
            tuple(int(value) for value in _from_json(row.get("weekdays_json"), list(range(7))) if int(value) in range(7)),
            str(row.get("start_time") or ""), str(row.get("end_time") or ""),
            tuple(str(value) for value in _from_json(row.get("blackout_dates_json"), [])),
            str(row.get("timezone") or "America/Lima"),
        )

    def _existing_schedule_rows(self, con: sqlite3.Connection, screen_ids: Iterable[str], campaign_id: str = "") -> list[dict[str, Any]]:
        ids = list(screen_ids)
        if not ids:
            return []
        filters = ["ca.screen_id IN (%s)" % ",".join("?" for _ in ids), "c.archived_at IS NULL", "c.state IN ('SCHEDULED','ACTIVE')"]
        params: list[Any] = list(ids)
        if campaign_id:
            filters.append("c.campaign_id<>?")
            params.append(campaign_id)
        rows = con.execute(
            """SELECT ca.screen_id,ca.priority,COALESCE(cap.emergency,0) AS emergency,c.campaign_id,c.title,c.state,cs.start_date,cs.end_date,cs.weekdays_json,
                      cs.start_time,cs.end_time,cs.blackout_dates_json,cs.timezone
               FROM campaigns c
               JOIN campaign_assignments ca ON ca.campaign_id=c.campaign_id AND ca.revision_no=c.current_revision_no
               JOIN campaign_schedules cs ON cs.assignment_id=ca.assignment_id
               LEFT JOIN campaign_assignment_policies cap ON cap.assignment_id=ca.assignment_id
               WHERE """ + " AND ".join(filters),
            params,
        ).fetchall()
        return [dict(row) for row in rows]

    def find_schedule_conflicts(
        self, assignments: Iterable[dict[str, Any]], *, campaign_id: str = "", require_schedule: bool = True,
    ) -> list[dict[str, Any]]:
        candidates = self._normalize_assignments(assignments, require_schedule=require_schedule)
        if not require_schedule:
            return []
        with self.connect() as con:
            screen_names = self._screen_names(con, [item["screen_id"] for item in candidates])
            existing = self._existing_schedule_rows(con, [item["screen_id"] for item in candidates], campaign_id)
        conflicts: list[dict[str, Any]] = []
        for candidate in candidates:
            candidate_window = self._normalize_schedule(candidate["schedule"], required=True)
            for old in existing:
                if str(old["screen_id"]) != candidate["screen_id"]:
                    continue
                old_window = self._window_from_row(old)
                self._assert_same_timezone_for_conflict(candidate_window, old_window)
                if not self._windows_overlap(candidate_window, old_window):
                    continue
                old_priority = old.get("priority")
                priority = candidate.get("priority")
                both_emergency = bool(candidate.get("emergency")) and bool(old.get("emergency"))
                resolvable = not both_emergency and priority is not None and old_priority is not None and int(priority) != int(old_priority)
                conflicts.append({
                    "screen_id": candidate["screen_id"],
                    "screen_name": screen_names.get(candidate["screen_id"], candidate["screen_id"]),
                    "campaign_id": str(old["campaign_id"]),
                    "campaign_title": str(old["title"]),
                    "existing_state": str(old["state"]),
                    "priority": priority,
                    "existing_priority": old_priority,
                    "emergency": bool(candidate.get("emergency")),
                    "existing_emergency": bool(old.get("emergency")),
                    "resolvable": resolvable,
                })
        return conflicts

    def _assert_no_blocking_conflicts(self, assignments: list[dict[str, Any]], campaign_id: str) -> None:
        conflicts = self.find_schedule_conflicts(assignments, campaign_id=campaign_id, require_schedule=True)
        blocking = [item for item in conflicts if not item["resolvable"]]
        if blocking:
            raise CampaignConflictError(blocking)

    def _current_assignment_definitions(self, con: sqlite3.Connection, campaign_id: str, revision_no: int) -> list[dict[str, Any]]:
        rows = con.execute(
            """SELECT ca.screen_id,pl.name AS playlist_name,ca.content_title,ca.content_note,ca.priority,
                      COALESCE(caa.asset_id,'') AS asset_id,COALESCE(cap.emergency,0) AS emergency,
                      cs.schedule_id,cs.timezone,cs.start_date,cs.end_date,cs.weekdays_json,cs.start_time,cs.end_time,cs.blackout_dates_json,
                      COALESCE(pref.preset,'CUSTOM') AS schedule_preset,
                      COALESCE(pref.starts_at_local,'') AS starts_at_local,
                      COALESCE(pref.ends_at_local,'') AS ends_at_local,
                      COALESCE(pref.summary,'') AS schedule_summary
               FROM campaign_assignments ca
               JOIN playlists pl ON pl.playlist_id=ca.playlist_id
               JOIN campaign_schedules cs ON cs.assignment_id=ca.assignment_id
               LEFT JOIN campaign_assignment_assets caa ON caa.assignment_id=ca.assignment_id
               LEFT JOIN campaign_assignment_policies cap ON cap.assignment_id=ca.assignment_id
               LEFT JOIN campaign_schedule_preferences pref ON pref.schedule_id=cs.schedule_id
               WHERE ca.campaign_id=? AND ca.revision_no=? ORDER BY ca.screen_id""",
            (campaign_id, revision_no),
        ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["schedule"] = {
                "timezone": item.pop("timezone"),
                "start_date": item.pop("start_date"),
                "end_date": item.pop("end_date"),
                "weekdays": _from_json(item.pop("weekdays_json"), list(range(7))),
                "start_time": item.pop("start_time"),
                "end_time": item.pop("end_time"),
                "blackout_dates": _from_json(item.pop("blackout_dates_json"), []),
                "preset": item.pop("schedule_preset"),
                "starts_at_local": item.pop("starts_at_local"),
                "ends_at_local": item.pop("ends_at_local"),
                "summary": item.pop("schedule_summary"),
            }
            item["schedule_id"] = item.pop("schedule_id")
            result.append(item)
        return result

    def _insert_revision(
        self, con: sqlite3.Connection, *, campaign_id: str, revision_no: int, title: str, objective: str,
        state: str, assignments: list[dict[str, Any]], change_note: str, actor: str,
    ) -> None:
        stamp = _now_iso()
        snapshot = {
            "schema": "gideon-media-campaign/v3",
            "campaign_id": campaign_id,
            "revision_no": revision_no,
            "title": title,
            "objective": objective,
            "state": state,
            "assignments": assignments,
        }
        con.execute(
            """INSERT INTO campaign_revisions(campaign_id,revision_no,title,objective,state,snapshot_json,change_note,created_at,created_by)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (campaign_id, revision_no, title, objective, state, _json(snapshot), change_note, stamp, actor),
        )
        playlist_ids: dict[str, str] = {}
        for assignment in assignments:
            playlist_name = assignment["playlist_name"]
            playlist_id = playlist_ids.get(playlist_name.casefold())
            if playlist_id is None:
                playlist_id = self._new_id("ply")
                playlist_ids[playlist_name.casefold()] = playlist_id
                con.execute(
                    "INSERT INTO playlists(playlist_id,campaign_id,revision_no,name,created_at) VALUES(?,?,?,?,?)",
                    (playlist_id, campaign_id, revision_no, playlist_name, stamp),
                )
            item_id = self._new_id("pli")
            con.execute(
                "INSERT INTO playlist_items(item_id,playlist_id,sequence_no,content_title,content_note,created_at) VALUES(?,?,?,?,?,?)",
                (item_id, playlist_id, 1, assignment["content_title"], assignment["content_note"], stamp),
            )
            assignment_id = self._new_id("cas")
            con.execute(
                """INSERT INTO campaign_assignments(assignment_id,campaign_id,revision_no,screen_id,playlist_id,content_title,content_note,priority,created_at)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (assignment_id, campaign_id, revision_no, assignment["screen_id"], playlist_id,
                 assignment["content_title"], assignment["content_note"], assignment["priority"], stamp),
            )
            # Optional in Phase 1 data; every new Phase 2 assignment persists
            # its asset and policy separately so historical base tables remain
            # immutable and backwards-compatible.
            if str(assignment.get("asset_id") or ""):
                found_asset = con.execute(
                    "SELECT asset_id FROM media_assets WHERE asset_id=? AND archived_at IS NULL",
                    (str(assignment["asset_id"]),),
                ).fetchone()
                if found_asset is None:
                    raise CampaignStoreError("Uno de los videos seleccionados ya no está disponible.")
                con.execute(
                    "INSERT INTO playlist_item_assets(item_id,asset_id,created_at) VALUES(?,?,?)",
                    (item_id, str(assignment["asset_id"]), stamp),
                )
                con.execute(
                    "INSERT INTO campaign_assignment_assets(assignment_id,asset_id,created_at) VALUES(?,?,?)",
                    (assignment_id, str(assignment["asset_id"]), stamp),
                )
            con.execute(
                "INSERT INTO campaign_assignment_policies(assignment_id,emergency,created_at) VALUES(?,?,?)",
                (assignment_id, 1 if bool(assignment.get("emergency")) else 0, stamp),
            )
            window = self._normalize_schedule(assignment["schedule"], required=True)
            presentation = self._schedule_presentation(assignment["schedule"], window)
            schedule_id = self._new_id("sch")
            con.execute(
                """INSERT INTO campaign_schedules(schedule_id,assignment_id,timezone,start_date,end_date,weekdays_json,start_time,end_time,blackout_dates_json,created_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (schedule_id, assignment_id, window.timezone, window.start_date, window.end_date,
                 _json(list(window.weekdays)), window.start_time, window.end_time, _json(list(window.blackout_dates)), stamp),
            )
            con.execute(
                """INSERT INTO campaign_schedule_preferences(
                       schedule_id,preset,starts_at_local,ends_at_local,summary,created_at,created_by
                   ) VALUES(?,?,?,?,?,?,?)""",
                (schedule_id, presentation["preset"], presentation["starts_at_local"], presentation["ends_at_local"],
                 presentation["summary"], stamp, actor),
            )

    def create_campaign_draft(
        self, *, title: str, objective: str = "", assignments: Iterable[dict[str, Any]], actor: str,
        state: str = "DRAFT", change_note: str = "", remote_ip: str = "",
    ) -> dict[str, Any]:
        campaign_state = _clean_state(state)
        if campaign_state not in {"DRAFT", "PENDING_APPROVAL", "SCHEDULED", "ACTIVE"}:
            raise CampaignStoreError("Una campaña nueva debe iniciar como borrador, pendiente, programada o activa.")
        name = _clean_text(title, "El nombre de la campaña", maximum=160, required=True)
        intent = _clean_text(objective, "El objetivo", maximum=1000, multiline=True)
        normalized = self._normalize_assignments(assignments, require_schedule=True)
        campaign_id = self._new_id("cmp")
        if campaign_state in {"SCHEDULED", "ACTIVE"}:
            self._assert_no_blocking_conflicts(normalized, campaign_id)
        stamp = _now_iso()
        try:
            with self.connect() as con:
                con.execute("BEGIN IMMEDIATE")
                self._assert_assignable_screens(con, [item["screen_id"] for item in normalized])
                # The second check is deliberately inside the writer lock.  Two
                # concurrent publications cannot both win a same-priority slot.
                if campaign_state in {"SCHEDULED", "ACTIVE"}:
                    self._assert_no_blocking_conflicts(normalized, campaign_id)
                con.execute(
                    """INSERT INTO campaigns(campaign_id,title,objective,state,current_revision_no,created_at,created_by,updated_at,updated_by)
                       VALUES(?,?,?,?,?,?,?,?,?)""",
                    (campaign_id, name, intent, campaign_state, 1, stamp, actor, stamp, actor),
                )
                self._insert_revision(con, campaign_id=campaign_id, revision_no=1, title=name, objective=intent,
                                      state=campaign_state, assignments=normalized, change_note=_clean_text(change_note, "La nota de cambio", maximum=500, multiline=True), actor=actor)
                self._event(con, entity_type="CAMPAIGN", entity_id=campaign_id, campaign_id=campaign_id, revision_no=1,
                            action="campaigns.create", actor=actor, detail={"title": name, "state": campaign_state})
                con.execute("COMMIT")
        except Exception:
            try:
                con.execute("ROLLBACK")
            except Exception:
                pass
            raise
        self._audit(actor, "campaigns.create", f"Campaña={name}; Estado={campaign_state}", resource=campaign_id, remote_ip=remote_ip)
        return self.campaign_detail(campaign_id)

    def save_campaign_revision(
        self, campaign_id: str, *, title: str | None = None, objective: str | None = None,
        assignments: Iterable[dict[str, Any]] | None = None, state: str | None = None, change_note: str = "",
        actor: str, remote_ip: str = "", action: str = "campaigns.edit",
        expected_updated_at: str = "", expected_version_token: str = "",
    ) -> dict[str, Any]:
        with self.connect() as con:
            current = con.execute("SELECT * FROM campaigns WHERE campaign_id=?", (campaign_id,)).fetchone()
            if current is None:
                raise CampaignStoreError("Campaña no encontrada.")
            current_item = dict(current)
            current_assignments = self._current_assignment_definitions(con, campaign_id, int(current_item["current_revision_no"]))
        if current_item.get("archived_at") and str(state or "").upper() != "SCHEDULED":
            raise CampaignStoreError("Una campaña archivada se reactiva mediante una nueva revisión programada.")
        new_title = _clean_text(title if title is not None else current_item["title"], "El nombre de la campaña", maximum=160, required=True)
        new_objective = _clean_text(objective if objective is not None else current_item["objective"], "El objetivo", maximum=1000, multiline=True)
        new_state = _clean_state(state if state is not None else current_item["state"])
        normalized = self._normalize_assignments(assignments if assignments is not None else current_assignments, require_schedule=True)
        if new_state in {"SCHEDULED", "ACTIVE"}:
            self._assert_no_blocking_conflicts(normalized, campaign_id)
        stamp = _now_iso()
        with self.connect() as con:
            con.execute("BEGIN IMMEDIATE")
            current = con.execute("SELECT * FROM campaigns WHERE campaign_id=?", (campaign_id,)).fetchone()
            if current is None:
                con.execute("ROLLBACK")
                raise CampaignStoreError("Campaña no encontrada.")
            _assert_expected_version(
                current,
                token=_entity_version_token("campaign", current, _CAMPAIGN_VERSION_FIELDS),
                expected_version_token=expected_version_token,
                expected_updated_at=expected_updated_at,
                entity_label="La campaña",
            )
            revision_no = int(current["current_revision_no"]) + 1
            # A paused/archived historical revision may legitimately reference
            # a screen that was later logically archived.  New targeting and
            # any return to a runnable state must still use live inventory.
            if assignments is not None or new_state in {"SCHEDULED", "ACTIVE"}:
                self._assert_assignable_screens(con, [item["screen_id"] for item in normalized])
            if new_state in {"SCHEDULED", "ACTIVE"}:
                self._assert_no_blocking_conflicts(normalized, campaign_id)
            self._insert_revision(con, campaign_id=campaign_id, revision_no=revision_no, title=new_title,
                                  objective=new_objective, state=new_state, assignments=normalized,
                                  change_note=_clean_text(change_note, "La nota de cambio", maximum=500, multiline=True), actor=actor)
            archived_at = stamp if new_state == "ARCHIVED" else None
            archived_by = actor if new_state == "ARCHIVED" else None
            con.execute(
                """UPDATE campaigns SET title=?,objective=?,state=?,current_revision_no=?,updated_at=?,updated_by=?,
                   archived_at=?,archived_by=? WHERE campaign_id=?""",
                (new_title, new_objective, new_state, revision_no, stamp, actor, archived_at, archived_by, campaign_id),
            )
            self._event(con, entity_type="CAMPAIGN", entity_id=campaign_id, campaign_id=campaign_id, revision_no=revision_no,
                        action=action, actor=actor, detail={"title": new_title, "state": new_state})
            con.execute("COMMIT")
        self._audit(actor, action, f"Campaña={new_title}; Revisión={revision_no}; Estado={new_state}", resource=campaign_id, remote_ip=remote_ip)
        return self.campaign_detail(campaign_id)

    def activate_campaign(
        self, campaign_id: str, *, actor: str, remote_ip: str = "", expected_updated_at: str = "",
        expected_version_token: str = "",
    ) -> dict[str, Any]:
        return self.save_campaign_revision(
            campaign_id, state="ACTIVE", actor=actor, remote_ip=remote_ip, action="campaigns.activate",
            expected_updated_at=expected_updated_at, expected_version_token=expected_version_token,
        )

    def pause_campaign(
        self, campaign_id: str, *, actor: str, remote_ip: str = "", expected_updated_at: str = "",
        expected_version_token: str = "",
    ) -> dict[str, Any]:
        return self.save_campaign_revision(
            campaign_id, state="PAUSED", actor=actor, remote_ip=remote_ip, action="campaigns.pause",
            expected_updated_at=expected_updated_at, expected_version_token=expected_version_token,
        )

    def archive_campaign(
        self, campaign_id: str, *, actor: str, remote_ip: str = "", expected_updated_at: str = "",
        expected_version_token: str = "",
    ) -> dict[str, Any]:
        return self.save_campaign_revision(
            campaign_id, state="ARCHIVED", actor=actor, remote_ip=remote_ip, action="campaigns.archive",
            expected_updated_at=expected_updated_at, expected_version_token=expected_version_token,
        )

    def reactivate_campaign(
        self, campaign_id: str, *, actor: str, remote_ip: str = "", expected_updated_at: str = "",
        expected_version_token: str = "",
    ) -> dict[str, Any]:
        return self.save_campaign_revision(
            campaign_id, state="SCHEDULED", actor=actor, remote_ip=remote_ip, action="campaigns.reactivate",
            expected_updated_at=expected_updated_at, expected_version_token=expected_version_token,
        )

    def duplicate_campaign(
        self, campaign_id: str, *, actor: str, title: str = "", remote_ip: str = "", expected_updated_at: str = "",
        expected_version_token: str = "",
    ) -> dict[str, Any]:
        source = self.campaign_detail(campaign_id)
        _assert_expected_version(
            source,
            token=str(source.get("version_token") or ""),
            expected_version_token=expected_version_token,
            expected_updated_at=expected_updated_at,
            entity_label="La campaña",
        )
        copy_title = _clean_text(title or f"Copia de {source['title']}", "El nombre de la campaña", maximum=160, required=True)
        result = self.create_campaign_draft(
            title=copy_title, objective=source.get("objective", ""), assignments=source.get("assignments", []),
            actor=actor, state="DRAFT", change_note=f"Duplicada desde {source['campaign_id']}", remote_ip=remote_ip,
        )
        self._audit(actor, "campaigns.duplicate", f"Origen={campaign_id}; Destino={result['campaign_id']}", resource=result["campaign_id"], remote_ip=remote_ip)
        return result

    def campaign_detail(self, campaign_id: str) -> dict[str, Any]:
        with self.connect() as con:
            row = con.execute("SELECT * FROM campaigns WHERE campaign_id=?", (campaign_id,)).fetchone()
            if row is None:
                raise CampaignStoreError("Campaña no encontrada.")
            item = dict(row)
            revision_no = int(item["current_revision_no"])
            assignments = self._current_assignment_definitions(con, campaign_id, revision_no)
            screens = self._screen_names(con, [assignment["screen_id"] for assignment in assignments])
            asset_ids = [str(assignment.get("asset_id") or "") for assignment in assignments if str(assignment.get("asset_id") or "")]
            assets_by_id: dict[str, dict[str, Any]] = {}
            if asset_ids:
                rows = con.execute(
                    "SELECT * FROM media_assets WHERE asset_id IN (%s)" % ",".join("?" for _ in asset_ids), asset_ids
                ).fetchall()
                assets_by_id = {str(row["asset_id"]): self._asset_from_row(row) for row in rows}
            for assignment in assignments:
                assignment["screen_name"] = screens.get(assignment["screen_id"], assignment["screen_id"])
                assignment["emergency"] = bool(assignment.get("emergency"))
                asset = assets_by_id.get(str(assignment.get("asset_id") or ""))
                assignment["asset"] = ({
                    "asset_id": asset["asset_id"], "display_name": asset["display_name"], "status": asset["status"],
                    "duration_seconds": asset["duration_seconds"], "resolution": asset["resolution"],
                    "valid_from": asset["valid_from"], "valid_until": asset["valid_until"],
                } if asset else None)
            revisions = con.execute(
                "SELECT campaign_id,revision_no,title,state,change_note,created_at,created_by FROM campaign_revisions WHERE campaign_id=? ORDER BY revision_no DESC",
                (campaign_id,),
            ).fetchall()
        item["assignments"] = assignments
        item["revisions"] = [dict(revision) for revision in revisions]
        item["archived"] = bool(item.get("archived_at"))
        item["version_token"] = _entity_version_token("campaign", item, _CAMPAIGN_VERSION_FIELDS)
        item["distribution"] = self.list_campaign_distribution(campaign_id)
        return item

    def calendar_entries(
        self, *, start_date: str, end_date: str, state: str = "", site_code: str = "",
        screen_id: str = "", search: str = "", include_archived: bool = False,
    ) -> list[dict[str, Any]]:
        """Return one marketing-safe row per scheduled screen assignment.

        The calendar needs the current revision and its schedule, but it must
        not hydrate every campaign detail one by one.  Keep the read in a
        single bounded SQLite query; callers can expand recurring weekdays in
        the browser without exposing Agent identifiers or file hashes.
        """
        clean_start = _clean_date(start_date, "La fecha inicial", required=True)
        clean_end = _clean_date(end_date, "La fecha final", required=True)
        if clean_end < clean_start:
            raise CampaignStoreError("El intervalo del calendario no es válido.")
        clauses = [
            "c.current_revision_no=ca.revision_no",
            "cs.start_date<=?",
            "cs.end_date>=?",
        ]
        params: list[Any] = [clean_end, clean_start]
        if not include_archived:
            clauses.extend(["c.archived_at IS NULL", "s.archived_at IS NULL"])
        if state:
            normalized_state = _clean_state(state)
            clauses.append("c.state=?")
            params.append(normalized_state)
        if site_code:
            clauses.append("s.site_code=?")
            params.append(str(site_code).strip().upper())
        if screen_id:
            clauses.append("s.screen_id=?")
            params.append(_clean_identifier(screen_id, "La pantalla", maximum=120))
        pattern = _catalog_search_pattern(search)
        if pattern:
            clauses.append(
                "(c.title LIKE ? ESCAPE '\\' OR c.objective LIKE ? ESCAPE '\\' "
                "OR s.site_code LIKE ? ESCAPE '\\' OR s.commercial_name LIKE ? ESCAPE '\\' "
                "OR s.physical_location LIKE ? ESCAPE '\\')"
            )
            params.extend([pattern] * 5)
        with self.connect() as con:
            rows = con.execute(
                """SELECT c.campaign_id,c.title,c.objective,c.state,c.current_revision_no,c.updated_at,
                          ca.screen_id,ca.priority,COALESCE(cap.emergency,0) AS emergency,
                          s.site_code,s.commercial_name,s.physical_location,s.orientation,s.resolution,
                          cs.timezone,cs.start_date,cs.end_date,cs.weekdays_json,cs.start_time,cs.end_time,
                          cs.blackout_dates_json,COALESCE(pl.name,'') AS playlist_name,
                          COALESCE(a.display_name,'') AS asset_name
                   FROM campaigns c
                   JOIN campaign_assignments ca
                     ON ca.campaign_id=c.campaign_id AND ca.revision_no=c.current_revision_no
                   JOIN screens s ON s.screen_id=ca.screen_id
                   JOIN campaign_schedules cs ON cs.assignment_id=ca.assignment_id
                   LEFT JOIN playlists pl ON pl.playlist_id=ca.playlist_id
                   LEFT JOIN campaign_assignment_policies cap ON cap.assignment_id=ca.assignment_id
                   LEFT JOIN campaign_assignment_assets caa ON caa.assignment_id=ca.assignment_id
                   LEFT JOIN media_assets a ON a.asset_id=caa.asset_id
                   WHERE """ + " AND ".join(clauses) +
                " ORDER BY cs.start_date,s.site_code,s.commercial_name,cs.start_time,c.title",
                params,
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["weekdays"] = _from_json(item.pop("weekdays_json"), list(range(7)))
            item["blackout_dates"] = _from_json(item.pop("blackout_dates_json"), [])
            item["priority"] = int(item.get("priority") or 0)
            item["emergency"] = bool(item.get("emergency"))
            result.append(item)
        return result

    def _campaign_filters(
        self, *, state: str = "", site_code: str = "", group_agent_ids: Iterable[str] | None = None,
        screen_id: str = "", os_name: str = "", agent_platforms: dict[str, str] | None = None,
        include_archived: bool = False, search: str = "",
    ) -> tuple[str, list[Any]] | None:
        """Build one SQL filter for campaign lists/counts without per-row reads."""
        clauses: list[str] = []
        params: list[Any] = []
        if not include_archived:
            clauses.append("c.archived_at IS NULL")
        if state:
            clauses.append("c.state=?")
            params.append(_clean_state(state))
        if site_code:
            clauses.append("s.site_code=?")
            params.append(str(site_code).strip().upper())
        if screen_id:
            clauses.append("ca.screen_id=?")
            params.append(str(screen_id).strip())
        members = sorted({str(x).strip() for x in (group_agent_ids or []) if str(x).strip()})
        if group_agent_ids is not None:
            if not members:
                return None
            clauses.append("s.agent_id IN (%s)" % ",".join("?" for _ in members))
            params.extend(members)
        wanted_os = str(os_name or "").lower().strip()
        if wanted_os:
            platform_lookup = {str(key): str(value or "").lower() for key, value in (agent_platforms or {}).items()}
            matching_agents = sorted(
                agent_id for agent_id, platform in platform_lookup.items() if platform == wanted_os
            )
            # The old implementation checked this after reading each campaign
            # and opened one SQLite connection per row.  Resolve the current
            # Agent platform map once and let the existing joined query do the
            # filtering instead.
            if not matching_agents:
                return None
            clauses.append("s.agent_id IN (%s)" % ",".join("?" for _ in matching_agents))
            params.extend(matching_agents)
        pattern = _catalog_search_pattern(search)
        if pattern:
            clauses.append(
                "(c.title LIKE ? ESCAPE '\\' OR c.objective LIKE ? ESCAPE '\\' "
                "OR s.site_code LIKE ? ESCAPE '\\' OR s.commercial_name LIKE ? ESCAPE '\\')"
            )
            params.extend([pattern] * 4)
        return (" WHERE " + " AND ".join(clauses) if clauses else ""), params

    def count_campaigns(
        self, *, state: str = "", site_code: str = "", group_agent_ids: Iterable[str] | None = None,
        screen_id: str = "", os_name: str = "", agent_platforms: dict[str, str] | None = None,
        include_archived: bool = False, search: str = "",
    ) -> int:
        """Return a server-side campaign total using the same filters as the list."""
        filter_result = self._campaign_filters(
            state=state, site_code=site_code, group_agent_ids=group_agent_ids, screen_id=screen_id,
            os_name=os_name, agent_platforms=agent_platforms, include_archived=include_archived, search=search,
        )
        if filter_result is None:
            return 0
        where, params = filter_result
        with self.connect() as con:
            row = con.execute(
                "SELECT COUNT(DISTINCT c.campaign_id) AS total FROM campaigns c"
                " LEFT JOIN campaign_assignments ca ON ca.campaign_id=c.campaign_id AND ca.revision_no=c.current_revision_no"
                " LEFT JOIN screens s ON s.screen_id=ca.screen_id" + where,
                params,
            ).fetchone()
        return int(row["total"] if row is not None else 0)

    def list_campaigns(
        self, *, state: str = "", site_code: str = "", group_agent_ids: Iterable[str] | None = None,
        screen_id: str = "", os_name: str = "", agent_platforms: dict[str, str] | None = None,
        include_archived: bool = False, limit: int | None = None, offset: int = 0,
        search: str = "", query: str = "", page: int | None = None, page_size: int | None = None,
    ) -> list[dict[str, Any]]:
        """Return campaigns from one query, including OS filters, in a stable order.

        A legacy call without paging is intentionally unbounded.  New web/API
        consumers should pass ``query``, ``page`` and ``page_size`` to avoid
        shipping the whole campaign catalogue to the browser.
        """
        normalized_query = _catalog_query(search, query)
        filter_result = self._campaign_filters(
            state=state, site_code=site_code, group_agent_ids=group_agent_ids, screen_id=screen_id,
            os_name=os_name, agent_platforms=agent_platforms, include_archived=include_archived,
            search=normalized_query,
        )
        if filter_result is None:
            return []
        where, params = filter_result
        page_limit, page_offset, _ = _catalog_page_window(
            limit=limit, offset=offset, page=page, page_size=page_size, default_limit=50,
            allow_unbounded=True,
        )
        params.extend([page_limit, page_offset])
        with self.connect() as con:
            rows = con.execute(
                """SELECT c.campaign_id,c.title,c.objective,c.state,c.current_revision_no,c.created_at,c.created_by,c.updated_at,c.updated_by,
                          c.archived_at,c.archived_by,COUNT(DISTINCT ca.screen_id) AS screen_count,
                          GROUP_CONCAT(DISTINCT s.site_code) AS site_codes
                   FROM campaigns c
                   LEFT JOIN campaign_assignments ca ON ca.campaign_id=c.campaign_id AND ca.revision_no=c.current_revision_no
                   LEFT JOIN screens s ON s.screen_id=ca.screen_id""" + where +
                " GROUP BY c.campaign_id ORDER BY c.updated_at DESC,c.title COLLATE NOCASE,c.campaign_id LIMIT ? OFFSET ?",
                params,
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["archived"] = bool(item.get("archived_at"))
            item["version_token"] = _entity_version_token("campaign", item, _CAMPAIGN_VERSION_FIELDS)
            result.append(item)
        return result

    def list_campaigns_page(
        self, *, state: str = "", site_code: str = "", group_agent_ids: Iterable[str] | None = None,
        screen_id: str = "", os_name: str = "", agent_platforms: dict[str, str] | None = None,
        include_archived: bool = False, limit: int = 50, offset: int = 0,
        search: str = "", query: str = "", page: int | None = None, page_size: int | None = None,
    ) -> dict[str, Any]:
        """Return campaign rows plus compact pagination metadata for WebAdmin."""
        normalized_query = _catalog_query(search, query)
        page_limit, page_offset, current_page = _catalog_page_window(
            limit=limit, offset=offset, page=page, page_size=page_size, default_limit=50,
        )
        total = self.count_campaigns(
            state=state, site_code=site_code, group_agent_ids=group_agent_ids, screen_id=screen_id,
            os_name=os_name, agent_platforms=agent_platforms, include_archived=include_archived,
            search=normalized_query,
        )
        page_count = max(1, (total + page_limit - 1) // page_limit) if total else 0
        items = self.list_campaigns(
            state=state, site_code=site_code, group_agent_ids=group_agent_ids, screen_id=screen_id,
            os_name=os_name, agent_platforms=agent_platforms, include_archived=include_archived,
            limit=page_limit, offset=page_offset, search=normalized_query,
        )
        return {
            "items": items,
            "total": total,
            "limit": page_limit,
            "offset": page_offset,
            "page": current_page,
            "page_size": page_limit,
            "pages": page_count,
            "query": normalized_query,
            "pagination": {
                "page": current_page,
                "page_size": page_limit,
                "total": total,
                "pages": page_count,
                "offset": page_offset,
                "has_previous": current_page > 1,
                "has_next": bool(page_count and current_page < page_count),
            },
        }

    def list_history(self, *, campaign_id: str = "", limit: int = 300) -> list[dict[str, Any]]:
        clauses = "WHERE campaign_id=?" if campaign_id else ""
        params: tuple[Any, ...] = (campaign_id, max(1, min(int(limit), 1000))) if campaign_id else (max(1, min(int(limit), 1000)),)
        with self.connect() as con:
            rows = con.execute(
                "SELECT * FROM campaign_events " + clauses + " ORDER BY created_at DESC LIMIT ?", params
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["detail"] = _from_json(item.pop("detail_json", "{}"), {})
            result.append(item)
        return result
