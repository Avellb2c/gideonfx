from __future__ import annotations

"""Loopback-only bridge to a local Wayland console exposed by WayVNC.

Raspberry Pi Connect exposes a local Wayland compositor through a UNIX RFB
socket.  That proves that a graphical *session* is reachable, but it does not
prove that any DRM/HDMI connector is physically connected.  This module keeps
those two facts separate and publishes only bounded, privacy-safe Wayland
output telemetry.

Guacamole cannot consume UNIX sockets directly, so the authenticated GIDEON
reverse tunnel connects to the socket without creating a TCP listener. mTLS,
one-use tickets and WebAdmin MFA remain the authorization boundary.
"""

import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import time
from typing import Any


MAX_WAYLAND_OUTPUTS = 24
MAX_PROBE_BYTES = 128 * 1024
WAYLAND_TARGET_KIND = "LOCAL_WAYLAND_SESSION"


def _bounded(value: Any, limit: int = 120) -> str:
    return "".join(ch for ch in str(value or "") if ch.isprintable())[:limit]


def _positive_int(value: Any, maximum: int = 32_768) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return parsed if 0 < parsed <= maximum else None


def _wayland_output_key(name: Any) -> str:
    token = re.sub(r"[^a-z0-9]+", "-", str(name or "").strip().casefold()).strip("-")
    return (f"linux-wayland-{token}" if token else "linux-wayland-output")[:120]


def _orientation(value: Any, width: int | None, height: int | None) -> str:
    text = str(value or "").strip().casefold()
    if text in {"90", "270", "left", "right", "flipped-90", "flipped-270"}:
        return "portrait"
    if text in {"180", "inverted", "flipped-180"}:
        return "landscape-inverted"
    if width and height and height > width:
        return "portrait"
    return "landscape"


def _safe_wayland_output(
    *, name: Any, index: int, enabled: Any, width: Any = None, height: Any = None,
    refresh: Any = None, transform: Any = "", primary: Any = False,
) -> dict[str, Any] | None:
    connector = _bounded(name, 80)
    if not connector or not re.fullmatch(r"[A-Za-z0-9_.:-]+", connector):
        return None
    output_key = _wayland_output_key(connector)
    parsed_width = _positive_int(width)
    parsed_height = _positive_int(height)
    try:
        parsed_refresh = round(float(refresh), 2) if refresh not in (None, "") else None
        if parsed_refresh and parsed_refresh > 1_000:
            # wlr-randr JSON commonly reports millihertz.
            parsed_refresh = round(parsed_refresh / 1_000.0, 2)
        if parsed_refresh is not None and not 1.0 <= parsed_refresh <= 1_000.0:
            parsed_refresh = None
    except (TypeError, ValueError, OverflowError):
        parsed_refresh = None
    is_enabled = bool(enabled)
    return {
        "OutputKey": output_key,
        "OutputIdentity": output_key,
        "OutputIdentitySource": "local-wayland-session",
        "TargetKind": WAYLAND_TARGET_KIND,
        "Label": f"Salida Wayland {int(index)}",
        "Connector": connector,
        "Connected": is_enabled,
        "Enabled": is_enabled,
        "Primary": bool(primary),
        "Physical": False,
        "Virtual": True,
        "Index": int(index),
        "Width": parsed_width,
        "Height": parsed_height,
        "Resolution": f"{parsed_width}x{parsed_height}" if parsed_width and parsed_height else "",
        "RefreshHz": parsed_refresh,
        "Orientation": _orientation(transform, parsed_width, parsed_height),
        "ResolutionSource": "wlr-randr",
        # This observation may select a local Wayland session only.  It must
        # never be promoted into proof that a physical DRM connector exists.
        "ObservationTrust": "LOCAL_SESSION_TELEMETRY",
    }


def _parse_wlr_randr_json(text: str) -> list[dict[str, Any]]:
    try:
        document = json.loads(str(text or ""))
    except (TypeError, ValueError):
        return []
    if isinstance(document, dict):
        rows = document.get("outputs") or document.get("Outputs") or []
    else:
        rows = document
    if not isinstance(rows, list):
        return []
    result: list[dict[str, Any]] = []
    for raw in rows[:MAX_WAYLAND_OUTPUTS]:
        if not isinstance(raw, dict):
            continue
        enabled = bool(raw.get("enabled", raw.get("Enabled", False)))
        modes = raw.get("modes") if isinstance(raw.get("modes"), list) else []
        current: dict[str, Any] = {}
        for mode in modes[:32]:
            if isinstance(mode, dict) and bool(mode.get("current")):
                current = mode
                break
        if not current and isinstance(raw.get("current_mode"), dict):
            current = dict(raw.get("current_mode") or {})
        position = raw.get("position") if isinstance(raw.get("position"), (list, tuple)) else []
        primary = bool(enabled and len(position) >= 2 and position[0] == 0 and position[1] == 0)
        row = _safe_wayland_output(
            name=raw.get("name") or raw.get("Name"),
            index=len(result) + 1,
            enabled=enabled,
            width=current.get("width") or raw.get("width"),
            height=current.get("height") or raw.get("height"),
            refresh=current.get("refresh") or raw.get("refresh"),
            transform=raw.get("transform"),
            primary=primary,
        )
        if row is not None and row["OutputKey"] not in {item["OutputKey"] for item in result}:
            result.append(row)
    return result


def _parse_wlr_randr_text(text: str) -> list[dict[str, Any]]:
    """Parse old wlr-randr text without retaining make/model/description."""
    result: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw_line in str(text or "").splitlines():
        line = raw_line.rstrip()
        if line and not line[0].isspace():
            name = line.split(None, 1)[0]
            if re.fullmatch(r"[A-Za-z0-9_.:-]+", name):
                current = {"name": name, "enabled": False, "transform": "", "width": None, "height": None, "refresh": None}
                result.append(current)
            else:
                current = None
            continue
        if current is None:
            continue
        clean = line.strip()
        if clean.casefold().startswith("enabled:"):
            current["enabled"] = clean.split(":", 1)[1].strip().casefold() in {"yes", "true", "1", "enabled"}
        elif clean.casefold().startswith("transform:"):
            current["transform"] = clean.split(":", 1)[1].strip()
        elif "(current" in clean.casefold() or clean.casefold().endswith(" current"):
            match = re.search(r"(?<!\d)(\d{2,5})x(\d{2,5})(?!\d)(?:\s+px,?\s*([0-9.]+)\s*Hz)?", clean, re.I)
            if match:
                current["width"], current["height"], current["refresh"] = match.groups()
    outputs: list[dict[str, Any]] = []
    for item in result[:MAX_WAYLAND_OUTPUTS]:
        row = _safe_wayland_output(
            name=item.get("name"), index=len(outputs) + 1, enabled=item.get("enabled"),
            width=item.get("width"), height=item.get("height"), refresh=item.get("refresh"),
            transform=item.get("transform"), primary=len(outputs) == 0,
        )
        if row is not None:
            outputs.append(row)
    return outputs


def _wayvnc_socket_candidates() -> list[Path]:
    candidates: list[Path] = []
    run_user = Path("/run/user")
    try:
        roots = sorted(path for path in run_user.iterdir() if path.name.isdigit())
    except OSError:
        return candidates
    for root in roots:
        candidates.extend((
            root / "rpi-connect-wayvnc.sock",
            root / "wayvnc.sock",
        ))
    return candidates


def find_local_wayland_vnc_socket() -> Path | None:
    """Return a validated WayVNC RFB socket owned by its runtime user."""
    for candidate in _wayvnc_socket_candidates():
        try:
            info = candidate.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISSOCK(info.st_mode):
                continue
            expected_uid = int(candidate.parent.name)
            if info.st_uid != expected_uid:
                continue
            resolved_parent = candidate.parent.resolve(strict=True)
            if resolved_parent != Path("/run/user") / str(expected_uid):
                continue
            return candidate
        except (OSError, ValueError):
            continue
    return None


def _validated_wayland_sockets(runtime_root: Path, expected_uid: int) -> list[Path]:
    try:
        root_info = runtime_root.lstat()
        if runtime_root.is_symlink() or not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != expected_uid:
            return []
        candidates = sorted(runtime_root.glob("wayland-*"))
    except OSError:
        return []
    result: list[Path] = []
    for candidate in candidates:
        if candidate.name.endswith(".lock") or not re.fullmatch(r"wayland-[A-Za-z0-9_.-]+", candidate.name):
            continue
        try:
            info = candidate.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISSOCK(info.st_mode) or info.st_uid != expected_uid:
                continue
            if candidate.parent.resolve(strict=True) != runtime_root.resolve(strict=True):
                continue
        except OSError:
            continue
        result.append(candidate)
        if len(result) >= 4:
            break
    return result


def _wayland_session_sockets() -> list[tuple[Path, int]]:
    """Return safe per-user Wayland sockets even when WayVNC is not installed.

    Raspberry Pi OS can expose the physical desktop through labwc/Wayland
    without creating the optional Raspberry Pi Connect ``wayvnc`` socket.
    The Agent service still needs a bounded, read-only way to discover that
    session.  We enumerate only canonical ``/run/user/<uid>`` directories,
    validate ownership and socket type, and keep the UID so the probe can run
    as the desktop user.  This never treats the compositor as an HDMI/DRM
    connector; callers publish ``LOCAL_WAYLAND_SESSION`` only.
    """
    result: list[tuple[Path, int]] = []
    run_user = Path("/run/user")
    try:
        roots = sorted(path for path in run_user.iterdir() if path.name.isdigit())
    except OSError:
        return result
    for root in roots:
        try:
            uid = int(root.name)
            info = root.lstat()
            if root.is_symlink() or not stat.S_ISDIR(info.st_mode) or int(info.st_uid) != uid:
                continue
            for socket_path in _validated_wayland_sockets(root, uid):
                result.append((socket_path, uid))
                if len(result) >= 8:
                    return result
        except (OSError, ValueError):
            continue
    return result


def _trusted_wlr_randr() -> Path | None:
    for candidate in (Path("/usr/bin/wlr-randr"), Path("/usr/local/bin/wlr-randr")):
        try:
            info = candidate.lstat()
            if candidate.is_symlink() or not stat.S_ISREG(info.st_mode):
                continue
            if info.st_uid != 0 or info.st_mode & 0o022:
                continue
            return candidate
        except OSError:
            continue
    return None


def _run_wlr_randr_for_socket(executable: Path, wayland_socket: Path, uid: int) -> str:
    """Query one compositor as its owner with a fixed executable and env.

    The compositor response is untrusted session telemetry.  It is bounded and
    sanitized by the parsers above, and can only create
    ``LOCAL_WAYLAND_SESSION`` rows.  It is never used as physical-connector
    authority.
    """
    if os.name == "nt" or not hasattr(os, "geteuid"):
        return ""
    try:
        import pwd

        account = pwd.getpwuid(int(uid))
        effective_uid = int(os.geteuid())
        if effective_uid not in {0, int(uid)}:
            return ""
        kwargs: dict[str, Any] = {}
        if effective_uid == 0 and int(uid) != 0:
            kwargs.update({"user": int(uid), "group": int(account.pw_gid), "extra_groups": ()})
        environment = {
            "HOME": str(account.pw_dir or "/"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/bin:/bin",
            "XDG_RUNTIME_DIR": str(wayland_socket.parent),
            "XDG_SESSION_TYPE": "wayland",
            "WAYLAND_DISPLAY": wayland_socket.name,
        }
        # Prefer structured output but support the older Raspberry package
        # whose wlr-randr only emits text.
        for arguments in ((str(executable), "--json"), (str(executable),)):
            completed = subprocess.run(
                list(arguments), capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=4, check=False, env=environment, **kwargs,
            )
            output = str(completed.stdout or "")
            if completed.returncode == 0 and output and len(output.encode("utf-8", "replace")) <= MAX_PROBE_BYTES:
                return output
    except (KeyError, OSError, ValueError, subprocess.SubprocessError):
        return ""
    return ""


def discover_local_wayland_outputs(source: Path | None = None) -> list[dict[str, Any]]:
    """Return bounded outputs from the visible local Wayland session.

    WayVNC remains the preferred evidence for the reverse-tunnel path.  When
    it is absent, probing the canonical per-user Wayland socket is sufficient
    for screen registration and Player capability telemetry, while retaining
    the explicit ``LOCAL_WAYLAND_SESSION`` target kind.
    """
    candidates: list[tuple[Path, int]] = []
    wayvnc = Path(source) if source is not None else find_local_wayland_vnc_socket()
    if wayvnc is not None:
        try:
            info = wayvnc.lstat()
            expected_uid = int(info.st_uid)
            runtime_root = wayvnc.parent.resolve(strict=True)
            if runtime_root == Path("/run/user") / str(expected_uid):
                candidates.extend((path, expected_uid) for path in _validated_wayland_sockets(runtime_root, expected_uid))
        except (OSError, ValueError):
            candidates = []
    if not candidates:
        candidates = _wayland_session_sockets()
    if not candidates and wayvnc is not None:
        # Raspberry Pi Connect may expose only its verified RFB socket to the
        # service namespace.  It still proves a local Wayland session exists;
        # keep the output logical and leave resolution unknown.
        try:
            candidates = [(wayvnc, int(wayvnc.lstat().st_uid))]
        except (OSError, ValueError):
            candidates = []

    def logical_session_outputs() -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for index, (session_socket, expected_uid) in enumerate(candidates[:MAX_WAYLAND_OUTPUTS], start=1):
            row = _safe_wayland_output(
                name=f"{session_socket.name}-uid-{expected_uid}",
                index=index,
                enabled=True,
                primary=index == 1,
            )
            if row is not None:
                row["ResolutionSource"] = "wayland-session"
                row["Label"] = f"Sesión Wayland {index} (resolución pendiente)"
                result.append(row)
        return result

    executable = _trusted_wlr_randr()
    if executable is None:
        # Some Raspberry Pi images expose Wayland but do not ship wlr-randr.
        # The compositor socket is still verified session evidence.  Publish a
        # conservative logical output (without inventing a resolution) so the
        # control plane can bind the registered screen and the Player can keep
        # its physical-session association.  Resolution is filled when a
        # supported probe becomes available.
        return logical_session_outputs()
    for wayland_socket, expected_uid in candidates:
        raw = _run_wlr_randr_for_socket(executable, wayland_socket, expected_uid)
        if not raw:
            continue
        outputs = _parse_wlr_randr_json(raw) or _parse_wlr_randr_text(raw)
        if outputs:
            return outputs[:MAX_WAYLAND_OUTPUTS]
    # Keep the session visible even if the compositor probe is unavailable or
    # rejects the service user; this is not promoted to physical-connector
    # evidence and is explicitly marked resolution-pending.
    return logical_session_outputs()


def connect_local_wayland_vnc(timeout: float = 8.0) -> socket.socket:
    """Open the local Wayland RFB socket without publishing a TCP listener."""
    source = find_local_wayland_vnc_socket()
    if source is None:
        raise FileNotFoundError("local Wayland VNC socket is not available")
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.settimeout(max(1.0, min(float(timeout), 15.0)))
        client.connect(str(source))
        client.settimeout(None)
        return client
    except Exception:
        client.close()
        raise


class LocalWaylandConsoleBridge:
    """Publish capability metadata for the tunnel-only Wayland console."""

    def __init__(self, host: str = "127.0.0.1", port: int = 5900, agent_id: str = "") -> None:
        self.host = host
        self.port = int(port)
        self.agent_id = str(agent_id or "").strip()
        self._snapshot_cache: tuple[float, Path | None, list[dict[str, Any]]] | None = None
        self._display_session_process: subprocess.Popen[Any] | None = None

    def _start_display_session_helper(self) -> None:
        """Run the capability writer inside the logged-in Wayland session.

        The Agent service must not impersonate a desktop user for control or
        input.  This companion is read-only and writes only a short-lived
        capability document; it is started with the session UID so compositor
        permissions work on Raspberry Pi OS and Ubuntu Wayland.
        """
        if os.name == "nt" or not hasattr(os, "geteuid"):
            return
        process = self._display_session_process
        if process is not None and process.poll() is None:
            return
        sockets = _wayland_session_sockets()
        if not sockets:
            source = find_local_wayland_vnc_socket()
            if source is not None:
                try:
                    sockets = [(source, int(source.lstat().st_uid))]
                except (OSError, ValueError):
                    sockets = []
        if not sockets:
            return
        try:
            import pwd

            socket_path, uid = sockets[0]
            account = pwd.getpwuid(int(uid))
            script = Path(__file__).with_name("gideon_agent_display_session.py")
            if not script.is_file():
                return
            environment = {
                "HOME": str(account.pw_dir or "/"),
                "USER": str(account.pw_name or ""),
                "LOGNAME": str(account.pw_name or ""),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": "/usr/bin:/bin",
                "XDG_RUNTIME_DIR": str(socket_path.parent),
                "WAYLAND_DISPLAY": socket_path.name,
                "XDG_SESSION_TYPE": "wayland",
                "GIDEON_AGENT_ID": self.agent_id,
            }
            kwargs: dict[str, Any] = {
                "env": environment,
                "stdin": subprocess.DEVNULL,
                "stdout": subprocess.DEVNULL,
                "stderr": subprocess.DEVNULL,
                "start_new_session": True,
            }
            if int(os.geteuid()) == 0 and int(uid) != 0:
                kwargs.update({"user": int(uid), "group": int(account.pw_gid), "extra_groups": ()})
            elif int(os.geteuid()) != int(uid):
                return
            self._display_session_process = subprocess.Popen(
                [sys.executable, str(script), "--agent-id", self.agent_id], **kwargs
            )
        except (KeyError, OSError, ValueError, subprocess.SubprocessError):
            self._display_session_process = None

    def ensure_running(self) -> bool:
        # Port 5900 is a virtual reverse-tunnel target.  No TCP listener is
        # opened: gideon_reverse_tunnel connects straight to the protected UNIX
        # socket after an authenticated reservation arrives.
        if os.name == "nt":
            return False
        self._start_display_session_helper()
        return bool(find_local_wayland_vnc_socket() or _wayland_session_sockets())

    def _outputs(self, source: Path | None) -> list[dict[str, Any]]:
        now = time.monotonic()
        cached = self._snapshot_cache
        if cached is not None and cached[1] == source and now - cached[0] <= 45.0:
            return [dict(item) for item in cached[2]]
        # A WayVNC socket is optional: Raspberry Pi Connect and other Wayland
        # sessions can expose only the compositor socket.  Always probe the
        # fallback sockets so capability reporting does not depend on VNC.
        outputs = discover_local_wayland_outputs(source)
        self._snapshot_cache = (now, source, [dict(item) for item in outputs])
        return outputs

    def status(self) -> dict[str, Any]:
        source = find_local_wayland_vnc_socket()
        outputs = self._outputs(source)
        return {
            "Ready": bool(os.name != "nt" and (source or outputs)),
            "TargetHost": self.host,
            "TargetPort": self.port,
            "TunnelOnly": True,
            "SessionKind": "local-wayland-console",
            "TargetKind": WAYLAND_TARGET_KIND,
            "PhysicalConsole": False,
            "Outputs": outputs,
            "Error": "" if source else "local Wayland VNC socket is not available",
        }

    def enrich_display_capability(self, value: dict[str, Any] | None) -> dict[str, Any]:
        """Merge verified local-session outputs without altering DRM facts."""
        display = dict(value or {})
        existing = [dict(item) for item in display.get("Outputs", []) if isinstance(item, dict)]
        status = self.status()
        wayland = status.get("Outputs") if isinstance(status.get("Outputs"), list) else []
        known = {str(item.get("OutputKey") or "") for item in existing}
        for item in wayland:
            if not isinstance(item, dict):
                continue
            key = str(item.get("OutputKey") or "")
            if key and key not in known and len(existing) < MAX_WAYLAND_OUTPUTS:
                existing.append(dict(item))
                known.add(key)
        display["Outputs"] = existing
        if wayland:
            display["Supported"] = True
            if str(display.get("State") or "").upper() in {"", "UNAVAILABLE", "NO_OUTPUTS"}:
                display["State"] = "READY"
            session = dict(display.get("Session") or {})
            if not bool(session.get("Available")):
                session.update({
                    "Available": True,
                    "Type": "wayland",
                    "Interactive": True,
                    "TargetKind": WAYLAND_TARGET_KIND,
                    "ObservationTrust": "LOCAL_SESSION_TELEMETRY",
                })
            display["Session"] = session
        return display

    def stop(self) -> None:
        return None


# Compatibility imports remain for one update cycle.  They are aliases only;
# no capability generated by this module claims that a Wayland/WayVNC session
# is a physical display connector.
PhysicalConsoleBridge = LocalWaylandConsoleBridge
connect_physical_wayvnc = connect_local_wayland_vnc
find_physical_wayvnc_socket = find_local_wayland_vnc_socket


__all__ = [
    "LocalWaylandConsoleBridge",
    "connect_local_wayland_vnc",
    "discover_local_wayland_outputs",
    "find_local_wayland_vnc_socket",
    "PhysicalConsoleBridge",
    "connect_physical_wayvnc",
    "find_physical_wayvnc_socket",
]
