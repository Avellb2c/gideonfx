from __future__ import annotations

"""Secret-free physical display discovery for GIDEON Agents.

The Agent normally runs as a service, so this module deliberately does *not*
try to impersonate a logged-in desktop user or inspect another user's process
environment.  It reports safe connector-level facts that a service can obtain
locally and marks whether a live graphical-session reading was available.

The result is designed for the regular authenticated Agent heartbeat.  It is
bounded, contains no EDID, monitor serial, user, filesystem path, or command
output, and a discovery problem can never fail the Agent heartbeat.
"""

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Any, Iterable, Mapping


DISPLAY_CAPABILITY_SCHEMA = "gideon-display-capability/v1"
MAX_OUTPUTS = 24
MAX_MODES_PER_OUTPUT = 8
PHYSICAL_CONNECTOR = "PHYSICAL_CONNECTOR"
LOCAL_WAYLAND_SESSION = "LOCAL_WAYLAND_SESSION"

_WINDOWS_ATTACHED_TO_DESKTOP = 0x00000001
_WINDOWS_PRIMARY_DEVICE = 0x00000004
_WINDOWS_MIRRORING_DRIVER = 0x00000008
_WINDOWS_REMOTE_DEVICE = 0x04000000
_ENUM_CURRENT_SETTINGS = -1


def _now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def _bounded_text(value: Any, limit: int = 96) -> str:
    return "".join(ch for ch in str(value or "") if ch.isprintable())[:limit]


def _positive_int(value: Any, maximum: int = 32_768) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if 0 < parsed <= maximum else None


def _refresh(value: Any) -> float | None:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return round(parsed, 2) if 1.0 <= parsed <= 1_000.0 else None


def _orientation(value: Any, width: int | None, height: int | None) -> str:
    text = str(value if value is not None else "").strip().lower()
    # Windows DEVMODE uses 0/1/2/3 for default/90/180/270.
    if text in {"left", "right", "90", "270", "1", "3", "portrait"}:
        return "portrait"
    if text in {"inverted", "180", "2"}:
        return "landscape-inverted"
    if width and height and height > width:
        return "portrait"
    return "landscape"


def _connector_key(value: Any, prefix: str) -> str:
    token = re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().lower()).strip("-")
    return f"{prefix}-{token}"[:120] if token else f"{prefix}-unknown"


def _display_identity(key: str, fingerprint: str = "", identity_source: str = "") -> tuple[str, str]:
    """Return a stable, non-secret monitor identity without exposing EDID.

    A physical connector alone is normally stable enough for an installed
    display.  When the OS exposes EDID, only a short SHA-256 fingerprint is
    published.  Raw EDID can disclose manufacturer/serial details, so it must
    never leave the endpoint through Agent capabilities.
    """
    clean_key = _bounded_text(key, 120).casefold() or "display-unknown"
    clean_fingerprint = _bounded_text(fingerprint, 40).casefold()
    if clean_fingerprint:
        if ":" in clean_fingerprint:
            # Test/adapter callers may already have a privacy-safe complete
            # identity. Do not accidentally hash or alter it a second time.
            return clean_fingerprint[:160], _bounded_text(identity_source, 48) or "adapter-identity"
        marker = "device" if "device" in str(identity_source).casefold() else "monitor"
        return f"{clean_key}:{marker}-{clean_fingerprint}"[:160], _bounded_text(identity_source, 48) or "connector+hardware-fingerprint"
    return clean_key, "connector"


def _edid_fingerprint(path: Path) -> str:
    """Read only a bounded local EDID blob and return a non-reversible tag."""
    try:
        raw = Path(path).read_bytes()
    except OSError:
        return ""
    if len(raw) < 128 or len(raw) > 4096:
        return ""
    return hashlib.sha256(raw).hexdigest()[:24]


def _mode(value: Any) -> tuple[int | None, int | None]:
    match = re.search(r"(?<!\d)(\d{2,5})\s*x\s*(\d{2,5})(?!\d)", str(value or ""), re.I)
    if not match:
        return None, None
    return _positive_int(match.group(1)), _positive_int(match.group(2))


def _safe_output(
    *,
    key: str,
    connector: str,
    index: int,
    connected: bool,
    enabled: bool,
    primary: bool = False,
    physical: bool = True,
    virtual: bool = False,
    target_kind: str = PHYSICAL_CONNECTOR,
    width: Any = None,
    height: Any = None,
    refresh_hz: Any = None,
    orientation: Any = "",
    resolution_source: str = "",
    modes: Iterable[str] | None = None,
    output_identity: str = "",
    identity_source: str = "",
) -> dict[str, Any]:
    clean_modes: list[str] = []
    for item in modes or ():
        parsed_width, parsed_height = _mode(item)
        if not parsed_width or not parsed_height:
            continue
        normalized = f"{parsed_width}x{parsed_height}"
        if normalized not in clean_modes:
            clean_modes.append(normalized)
        if len(clean_modes) >= MAX_MODES_PER_OUTPUT:
            break
    parsed_width = _positive_int(width)
    parsed_height = _positive_int(height)
    if not parsed_width or not parsed_height:
        parsed_width, parsed_height = _mode(clean_modes[0] if clean_modes else "")
        if parsed_width and parsed_height and not resolution_source:
            resolution_source = "preferred-mode"
    clean_connector = _bounded_text(connector, 80) or f"DISPLAY{index}"
    identity, default_identity_source = _display_identity(key, output_identity, identity_source)
    return {
        "OutputKey": _bounded_text(key, 120),
        "OutputIdentity": identity,
        "OutputIdentitySource": _bounded_text(identity_source, 48) or default_identity_source,
        "Label": f"Pantalla {index}",
        "Connector": clean_connector,
        "Connected": bool(connected),
        "Enabled": bool(enabled),
        "Primary": bool(primary),
        "Physical": bool(physical),
        "Virtual": bool(virtual),
        "TargetKind": LOCAL_WAYLAND_SESSION if target_kind == LOCAL_WAYLAND_SESSION else PHYSICAL_CONNECTOR,
        # Inventory order is useful for diagnosis only. The Player never treats
        # it as a guaranteed VLC/Qt mapping on a multi-monitor desktop.
        "Index": int(index),
        "Width": parsed_width,
        "Height": parsed_height,
        "RefreshHz": _refresh(refresh_hz),
        "Orientation": _orientation(orientation, parsed_width, parsed_height),
        "ResolutionSource": _bounded_text(resolution_source, 40) or "unknown",
        "SupportedModes": clean_modes,
    }


def _session_from_environment(environ: Mapping[str, str]) -> dict[str, Any]:
    display = bool(str(environ.get("DISPLAY") or "").strip())
    wayland = bool(str(environ.get("WAYLAND_DISPLAY") or "").strip())
    session_type = str(environ.get("XDG_SESSION_TYPE") or "").strip().lower()
    if session_type not in {"x11", "wayland"}:
        session_type = "wayland" if wayland else "x11" if display else "unknown"
    return {
        "Available": bool(display or wayland),
        "Type": session_type,
        # A service environment may carry a DISPLAY variable in unusual setups;
        # that does not authorize input/control, it only makes this reading useful.
        "Interactive": bool(display or wayland),
    }


def _windows_session() -> dict[str, Any]:
    """Report only whether a physical Windows console exists; never its user."""
    if os.name != "nt":
        return {"Available": False, "Type": "windows-service", "Interactive": False}
    try:
        import ctypes

        session_id = int(ctypes.windll.kernel32.WTSGetActiveConsoleSessionId())
        available = session_id != 0xFFFFFFFF
        return {
            "Available": available,
            "Type": "windows-console" if available else "windows-service",
            "Interactive": available,
        }
    except Exception:
        return {"Available": False, "Type": "windows-service", "Interactive": False}


def _parse_xrandr(text: str) -> dict[str, dict[str, Any]]:
    """Parse only connector/mode facts from ``xrandr --query`` output."""
    values: dict[str, dict[str, Any]] = {}
    pattern = re.compile(
        r"^([A-Za-z0-9_.-]+)\s+(connected|disconnected)"
        r"(?:\s+(primary))?"
        r"(?:\s+(\d{2,5})x(\d{2,5})\+[-]?\d+\+[-]?\d+)?"
        r"(?:\s+\((normal|left|right|inverted)\b)?",
        re.I,
    )
    for line in str(text or "").splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        connector, state, primary, width, height, rotation = match.groups()
        values[_connector_key(connector, "linux")] = {
            "connector": connector,
            "connected": state.casefold() == "connected",
            "primary": bool(primary),
            "width": _positive_int(width),
            "height": _positive_int(height),
            "orientation": rotation or "",
        }
    return values


def _linux_connector_key(name: str) -> str:
    # DRM calls an HDMI connector HDMI-A-1 while XRandR commonly calls it HDMI-1.
    normalized = re.sub(r"^card\d+-", "", str(name or ""), flags=re.I)
    normalized = re.sub(r"-a-", "-", normalized, flags=re.I)
    return _connector_key(normalized, "linux")


def _optional_xrandr(environ: Mapping[str, str]) -> dict[str, dict[str, Any]]:
    if not str(environ.get("DISPLAY") or "").strip() or not shutil.which("xrandr"):
        return {}
    try:
        completed = subprocess.run(
            ["xrandr", "--query", "--current"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=3,
            check=False,
            env=dict(environ),
        )
        if completed.returncode != 0:
            return {}
        return _parse_xrandr(completed.stdout)
    except (OSError, subprocess.SubprocessError):
        return {}


def _parse_wlr_randr(text: str) -> list[dict[str, Any]]:
    """Parse the bounded, read-only output of ``wlr-randr``.

    wlroots output names describe compositor targets, not proof of an
    electrically connected monitor.  They are therefore always advertised as
    virtual ``LOCAL_WAYLAND_SESSION`` targets.  This is intentional for
    ``NOOP-*``/headless outputs used by Raspberry Pi Connect and WayVNC: the
    Player may target them only when the signed manifest explicitly asks for a
    local Wayland session.
    """
    parsed: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw_line in str(text or "").splitlines():
        line = raw_line.rstrip()
        if not line:
            continue
        if not line[:1].isspace():
            match = re.match(r"^([A-Za-z0-9_.-]{1,80})(?:\s+.*)?$", line)
            if not match:
                current = None
                continue
            connector = match.group(1)
            current = {
                "connector": connector,
                "connected": True,
                "enabled": False,
                "width": None,
                "height": None,
                "refresh_hz": None,
                "orientation": "",
                "modes": [],
            }
            parsed.append(current)
            if len(parsed) >= MAX_OUTPUTS:
                break
            continue
        if current is None:
            continue
        detail = line.strip()
        key, separator, raw_value = detail.partition(":")
        field = key.strip().casefold()
        value = raw_value.strip()
        if separator and field == "enabled":
            current["enabled"] = value.casefold() in {"yes", "true", "1", "enabled"}
            continue
        if separator and field == "transform":
            current["orientation"] = value.split()[0] if value else ""
            continue
        # Mode rows are indented below ``Modes:`` and contain both dimensions
        # and, when active, the literal ``current`` marker.  We never preserve
        # the human-readable output description or any other command text.
        width, height = _mode(detail)
        if width and height:
            normalized = f"{width}x{height}"
            if normalized not in current["modes"] and len(current["modes"]) < MAX_MODES_PER_OUTPUT:
                current["modes"].append(normalized)
            if "current" in detail.casefold():
                current["width"] = width
                current["height"] = height
                refresh = re.search(r"(?:px,|@)\s*([0-9]+(?:\.[0-9]+)?)\s*(?:hz)?", detail, re.I)
                current["refresh_hz"] = _refresh(refresh.group(1)) if refresh else None
    return parsed


def _optional_wlr_randr(environ: Mapping[str, str]) -> list[dict[str, Any]]:
    """Inspect only the caller's Wayland session, never another user's env."""
    if (
        str(environ.get("XDG_SESSION_TYPE") or "").strip().casefold() != "wayland"
        or not str(environ.get("WAYLAND_DISPLAY") or "").strip()
        or not shutil.which("wlr-randr")
    ):
        return []
    try:
        completed = subprocess.run(
            ["wlr-randr"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=3,
            check=False,
            env=dict(environ),
        )
        if completed.returncode != 0:
            return []
        return _parse_wlr_randr(completed.stdout)
    except (OSError, subprocess.SubprocessError):
        return []


def _detect_linux(
    *,
    sysfs_root: Path,
    environ: Mapping[str, str],
    xrandr_text: str | None = None,
    wlr_randr_text: str | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any], str, str]:
    session = _session_from_environment(environ)
    xrandr = _parse_xrandr(xrandr_text) if xrandr_text is not None else _optional_xrandr(environ)
    wayland = _parse_wlr_randr(wlr_randr_text) if wlr_randr_text is not None else _optional_wlr_randr(environ)
    outputs: list[dict[str, Any]] = []
    try:
        connectors = sorted(path for path in sysfs_root.iterdir() if (path / "status").is_file())
    except OSError:
        connectors = []
    for path in connectors[:MAX_OUTPUTS]:
        connector = str(path.name)
        try:
            state = (path / "status").read_text(encoding="utf-8", errors="replace").strip().casefold()
        except OSError:
            state = "unknown"
        connected = state == "connected"
        try:
            modes = (path / "modes").read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            modes = []
        key = _linux_connector_key(connector)
        identity = _edid_fingerprint(path / "edid")
        observed = xrandr.get(key) or {}
        outputs.append(_safe_output(
            key=key,
            connector=connector,
            index=len(outputs) + 1,
            connected=bool(observed.get("connected", connected)),
            enabled=bool(observed.get("connected", connected) and (observed.get("width") or connected)),
            primary=bool(observed.get("primary")),
            width=observed.get("width"),
            height=observed.get("height"),
            orientation=observed.get("orientation") or "",
            resolution_source="xrandr" if observed.get("width") and observed.get("height") else "preferred-mode",
            modes=modes,
            output_identity=identity,
        ))
    for observed in wayland:
        if len(outputs) >= MAX_OUTPUTS:
            break
        connector = _bounded_text(observed.get("connector"), 80)
        if not connector:
            continue
        key = _connector_key(connector, "linux-wayland")
        outputs.append(_safe_output(
            key=key,
            connector=connector,
            index=len(outputs) + 1,
            connected=bool(observed.get("connected")),
            enabled=bool(observed.get("enabled")),
            physical=False,
            virtual=True,
            target_kind=LOCAL_WAYLAND_SESSION,
            width=observed.get("width"),
            height=observed.get("height"),
            refresh_hz=observed.get("refresh_hz"),
            orientation=observed.get("orientation") or "",
            resolution_source="wlr-randr",
            modes=observed.get("modes") if isinstance(observed.get("modes"), list) else [],
        ))
    if outputs:
        return outputs, session, "READY", ""
    if not connectors and not wayland:
        return [], session, "UNAVAILABLE", "DRM_SYSFS_UNAVAILABLE"
    return [], session, "NO_OUTPUTS", ""


def _windows_outputs() -> list[dict[str, Any]]:
    """Use documented User32 APIs and omit monitor make/model/EDID details."""
    if os.name != "nt":
        return []
    try:
        import ctypes
        from ctypes import wintypes

        class DISPLAY_DEVICEW(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("DeviceName", wintypes.WCHAR * 32),
                ("DeviceString", wintypes.WCHAR * 128),
                ("StateFlags", wintypes.DWORD),
                ("DeviceID", wintypes.WCHAR * 128),
                ("DeviceKey", wintypes.WCHAR * 128),
            ]

        class POINTL(ctypes.Structure):
            _fields_ = [("x", wintypes.LONG), ("y", wintypes.LONG)]

        class DEVMODEW(ctypes.Structure):
            _fields_ = [
                ("dmDeviceName", wintypes.WCHAR * 32),
                ("dmSpecVersion", wintypes.WORD),
                ("dmDriverVersion", wintypes.WORD),
                ("dmSize", wintypes.WORD),
                ("dmDriverExtra", wintypes.WORD),
                ("dmFields", wintypes.DWORD),
                ("dmPosition", POINTL),
                ("dmDisplayOrientation", wintypes.DWORD),
                ("dmDisplayFixedOutput", wintypes.DWORD),
                ("dmColor", wintypes.WORD),
                ("dmDuplex", wintypes.WORD),
                ("dmYResolution", wintypes.WORD),
                ("dmTTOption", wintypes.WORD),
                ("dmCollate", wintypes.WORD),
                ("dmFormName", wintypes.WCHAR * 32),
                ("dmLogPixels", wintypes.WORD),
                ("dmBitsPerPel", wintypes.DWORD),
                ("dmPelsWidth", wintypes.DWORD),
                ("dmPelsHeight", wintypes.DWORD),
                ("dmDisplayFlags", wintypes.DWORD),
                ("dmDisplayFrequency", wintypes.DWORD),
                ("dmICMMethod", wintypes.DWORD),
                ("dmICMIntent", wintypes.DWORD),
                ("dmMediaType", wintypes.DWORD),
                ("dmDitherType", wintypes.DWORD),
                ("dmReserved1", wintypes.DWORD),
                ("dmReserved2", wintypes.DWORD),
                ("dmPanningWidth", wintypes.DWORD),
                ("dmPanningHeight", wintypes.DWORD),
            ]

        user32 = ctypes.windll.user32
        enum_device = user32.EnumDisplayDevicesW
        enum_device.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(DISPLAY_DEVICEW), wintypes.DWORD]
        enum_device.restype = wintypes.BOOL
        enum_settings = user32.EnumDisplaySettingsExW
        enum_settings.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(DEVMODEW), wintypes.DWORD]
        enum_settings.restype = wintypes.BOOL

        outputs: list[dict[str, Any]] = []
        for index in range(MAX_OUTPUTS):
            device = DISPLAY_DEVICEW()
            device.cb = ctypes.sizeof(DISPLAY_DEVICEW)
            if not enum_device(None, index, ctypes.byref(device), 0):
                break
            flags = int(device.StateFlags)
            if flags & (_WINDOWS_MIRRORING_DRIVER | _WINDOWS_REMOTE_DEVICE):
                continue
            name = str(device.DeviceName or "").strip()
            if not name:
                continue
            mode = DEVMODEW()
            mode.dmSize = ctypes.sizeof(DEVMODEW)
            mode_ok = bool(enum_settings(name, _ENUM_CURRENT_SETTINGS, ctypes.byref(mode), 0))
            connector = name.rsplit("\\", 1)[-1] or f"DISPLAY{index + 1}"
            identity = hashlib.sha256(str(device.DeviceID or name).encode("utf-8", "replace")).hexdigest()[:24]
            outputs.append(_safe_output(
                key=_connector_key(connector, "windows"),
                connector=connector,
                index=len(outputs) + 1,
                connected=bool(flags & _WINDOWS_ATTACHED_TO_DESKTOP),
                enabled=bool(flags & _WINDOWS_ATTACHED_TO_DESKTOP),
                primary=bool(flags & _WINDOWS_PRIMARY_DEVICE),
                width=int(mode.dmPelsWidth) if mode_ok else None,
                height=int(mode.dmPelsHeight) if mode_ok else None,
                refresh_hz=int(mode.dmDisplayFrequency) if mode_ok else None,
                orientation=int(mode.dmDisplayOrientation) if mode_ok else "",
                resolution_source="windows-api" if mode_ok else "unknown",
                output_identity=identity,
                identity_source="windows-device-fingerprint",
            ))
        return outputs
    except Exception:
        return []


def _detect_macos(environ: Mapping[str, str]) -> tuple[list[dict[str, Any]], dict[str, Any], str, str]:
    session = _session_from_environment(environ)
    executable = "/usr/sbin/system_profiler"
    if not Path(executable).is_file():
        return [], session, "UNAVAILABLE", "SYSTEM_PROFILER_UNAVAILABLE"
    try:
        completed = subprocess.run(
            [executable, "SPDisplaysDataType", "-json"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            check=False,
        )
        if completed.returncode != 0:
            return [], session, "UNAVAILABLE", "SYSTEM_PROFILER_FAILED"
        raw = json.loads(completed.stdout or "{}")
    except (OSError, ValueError, subprocess.SubprocessError):
        return [], session, "UNAVAILABLE", "SYSTEM_PROFILER_FAILED"

    candidates: list[Mapping[str, Any]] = []

    def visit(value: Any) -> None:
        if isinstance(value, Mapping):
            if "spdisplays_resolution" in value or "_name" in value and "spdisplays_main" in value:
                candidates.append(value)
            for nested in value.values():
                visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)

    visit(raw)
    outputs: list[dict[str, Any]] = []
    for candidate in candidates[:MAX_OUTPUTS]:
        resolution = str(candidate.get("spdisplays_resolution") or "")
        width, height = _mode(resolution)
        if not width or not height:
            continue
        rate_match = re.search(r"@\s*([0-9.]+)\s*Hz", resolution, re.I)
        outputs.append(_safe_output(
            key=f"macos-display-{len(outputs) + 1}",
            connector=f"DISPLAY{len(outputs) + 1}",
            index=len(outputs) + 1,
            connected=True,
            enabled=True,
            primary=str(candidate.get("spdisplays_main") or "").strip().casefold() in {"yes", "true", "1"},
            width=width,
            height=height,
            refresh_hz=rate_match.group(1) if rate_match else None,
            resolution_source="system-profiler",
        ))
    return outputs, session, "READY" if outputs else "NO_OUTPUTS", ""


def detect_display_capability(
    *,
    system_name: str | None = None,
    sysfs_root: Path | str = "/sys/class/drm",
    environ: Mapping[str, str] | None = None,
    xrandr_text: str | None = None,
    wlr_randr_text: str | None = None,
    windows_outputs: Iterable[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return a bounded display capability document; never raise on discovery failure.

    ``windows_outputs``, ``xrandr_text`` and ``wlr_randr_text`` are
    intentionally test seams.  They are not populated from remote
    configuration and cannot alter local display state.
    """
    environment = dict(environ or os.environ)
    system = str(system_name or ("windows" if os.name == "nt" else sys.platform)).strip().casefold()
    try:
        if system.startswith("win"):
            session = _windows_session()
            if windows_outputs is None:
                outputs = _windows_outputs()
            else:
                outputs = []
                for index, item in enumerate(windows_outputs):
                    if not isinstance(item, Mapping) or index >= MAX_OUTPUTS:
                        continue
                    connector = str(item.get("Connector") or f"DISPLAY{index + 1}")
                    outputs.append(_safe_output(
                        key=_connector_key(item.get("OutputKey") or connector, "windows"),
                        connector=connector,
                        index=len(outputs) + 1,
                        connected=bool(item.get("Connected")), enabled=bool(item.get("Enabled", item.get("Connected"))),
                        primary=bool(item.get("Primary")), physical=bool(item.get("Physical", True)),
                        virtual=bool(item.get("Virtual", False)),
                        target_kind=str(item.get("TargetKind") or PHYSICAL_CONNECTOR),
                        width=item.get("Width"), height=item.get("Height"), refresh_hz=item.get("RefreshHz"),
                        orientation=item.get("Orientation"), resolution_source="windows-api",
                        output_identity=str(item.get("OutputIdentity") or item.get("output_identity") or ""),
                        identity_source=str(item.get("OutputIdentitySource") or item.get("output_identity_source") or ""),
                    ))
            state = "READY" if outputs else "NO_OUTPUTS"
            error = ""
        elif system.startswith("darwin") or system.startswith("mac"):
            outputs, session, state, error = _detect_macos(environment)
        elif system.startswith("linux"):
            outputs, session, state, error = _detect_linux(
                sysfs_root=Path(sysfs_root), environ=environment, xrandr_text=xrandr_text,
                wlr_randr_text=wlr_randr_text,
            )
        else:
            outputs = []
            session = {"Available": False, "Type": "unknown", "Interactive": False}
            state = "UNSUPPORTED_PLATFORM"
            error = "DISPLAY_DISCOVERY_UNSUPPORTED"
    except Exception:
        outputs = []
        session = {"Available": False, "Type": "unknown", "Interactive": False}
        state = "UNAVAILABLE"
        error = "DISPLAY_DISCOVERY_FAILED"
    return {
        "Schema": DISPLAY_CAPABILITY_SCHEMA,
        "Supported": state not in {"UNSUPPORTED_PLATFORM", "UNAVAILABLE"},
        "State": state,
        "DetectedAt": _now_iso(),
        "Session": session,
        "Outputs": outputs[:MAX_OUTPUTS],
        "Error": error,
    }


__all__ = [
    "DISPLAY_CAPABILITY_SCHEMA",
    "LOCAL_WAYLAND_SESSION",
    "PHYSICAL_CONNECTOR",
    "detect_display_capability",
]
