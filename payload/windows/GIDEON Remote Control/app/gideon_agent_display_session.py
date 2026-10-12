from __future__ import annotations

"""Small desktop-session companion for display capability telemetry.

The core Agent normally runs as a service and cannot inherit the graphical
environment of the person using the physical screen.  This companion runs as
that desktop user, reads only bounded Wayland/display capability facts and
publishes a short-lived, secret-free report for the Agent service.  It never
opens a network listener, accepts input, or starts the Player.
"""

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
from typing import Any

from gideon_agent_display_capability import detect_display_capability
from gideon_agent_vnc_bridge import discover_local_wayland_outputs


SCHEMA = "gideon-display-capability/v1"
INTERVAL_SECONDS = 15.0


def _agent_id(value: str) -> str:
    value = str(value or os.environ.get("GIDEON_AGENT_ID") or "").strip()
    if value:
        return value
    for candidate in (
        Path("/var/lib/gideon-agent/agent.runtime.json"),
        Path("/opt/gideon-agent/agent.runtime.json"),
        Path(__file__).with_name("agent.runtime.json"),
    ):
        try:
            document = json.loads(candidate.read_text(encoding="utf-8-sig"))
            if isinstance(document, dict) and str(document.get("agent_id") or "").strip():
                return str(document["agent_id"]).strip()
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            continue
    return "display-session"


def _report_paths(agent_id: str) -> list[Path]:
    digest = hashlib.sha256(agent_id.casefold().encode("utf-8", "ignore")).hexdigest()[:16]
    paths = [Path(tempfile.gettempdir()) / f"gideon-agent-display-{digest}.json"]
    runtime_root = str(os.environ.get("XDG_RUNTIME_DIR") or "").strip()
    if runtime_root.startswith("/run/user/"):
        paths.append(Path(runtime_root) / f"gideon-agent-display-{digest}.json")
    return paths


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def build_report(agent_id: str) -> dict[str, Any]:
    now = _now()
    try:
        detected = detect_display_capability()
    except Exception:
        detected = {
            "Supported": False,
            "State": "UNAVAILABLE",
            "Session": {"Available": False, "Type": "unknown", "Interactive": False},
            "Outputs": [],
            "Error": "DISPLAY_DISCOVERY_FAILED",
        }
    if not isinstance(detected, dict):
        detected = {}
    outputs = [dict(item) for item in (detected.get("Outputs") or []) if isinstance(item, dict)]
    try:
        wayland_outputs = discover_local_wayland_outputs()
    except Exception:
        wayland_outputs = []
    known = {str(item.get("OutputKey") or "") for item in outputs}
    for item in wayland_outputs:
        key = str(item.get("OutputKey") or "")
        if key and key not in known and len(outputs) < 24:
            outputs.append(dict(item))
            known.add(key)
    session = dict(detected.get("Session") or {})
    if wayland_outputs:
        session.update({
            "Available": True,
            "Type": "wayland",
            "Interactive": True,
            "TargetKind": "LOCAL_WAYLAND_SESSION",
            "ObservationTrust": "LOCAL_SESSION_TELEMETRY",
        })
    supported = bool(detected.get("Supported")) or bool(wayland_outputs)
    return {
        "Schema": SCHEMA,
        "Supported": supported,
        "State": "READY" if supported and outputs else str(detected.get("State") or "NO_OUTPUTS")[:32],
        "DetectedAt": str(detected.get("DetectedAt") or now)[:64],
        "UpdatedAt": now,
        "Session": {
            "Available": bool(session.get("Available")),
            "Type": str(session.get("Type") or "unknown")[:48],
            "Interactive": bool(session.get("Interactive")),
            "TargetKind": str(session.get("TargetKind") or "")[:48],
            "ObservationTrust": str(session.get("ObservationTrust") or "")[:64],
        },
        "Outputs": outputs[:24],
        "Error": "" if outputs else str(detected.get("Error") or "DISPLAY_DISCOVERY_FAILED")[:240],
        "Source": "desktop-session-helper",
    }


def write_report(paths: list[Path], report: dict[str, Any]) -> None:
    serialized = json.dumps(report, ensure_ascii=False, separators=(",", ":"))
    for path in paths:
        try:
            temporary = path.with_name(path.name + ".tmp")
            temporary.write_text(serialized, encoding="utf-8")
            os.replace(temporary, path)
        except OSError:
            continue


def main() -> int:
    parser = argparse.ArgumentParser(description="GIDEON display session helper")
    parser.add_argument("--agent-id", default="")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    identity = _agent_id(args.agent_id)
    paths = _report_paths(identity)
    while True:
        try:
            write_report(paths, build_report(identity))
        except Exception:
            # Capability telemetry is best effort and must never disturb the
            # desktop session or the core Agent service.
            pass
        if args.once:
            return 0
        time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    raise SystemExit(main())
