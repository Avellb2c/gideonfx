from __future__ import annotations

"""GIDEON Remote Control coordinator.

The coordinator is an application identity/aggregate-health process.  It never
starts, stops or reconfigures services.  Recovery remains the responsibility of
SCM/systemd for GIDEON-owned units only.
"""

import argparse
import json
from pathlib import Path
import sys
import time
from typing import Sequence

from gideon_diagnostics_service import default_data_root
from gideon_service_health import HealthState, atomic_write_json, read_json, utc_now


def derive_coordinator_status(diagnostics: dict[str, object]) -> dict[str, object]:
    raw = str(diagnostics.get("state") or HealthState.FAILED.value)
    try:
        state = HealthState(raw)
    except ValueError:
        state = HealthState.FAILED
    services = diagnostics.get("services")
    if not isinstance(services, list):
        services = []
    return {
        "schema_version": 1,
        "state": state.value,
        "generated_at_utc": utc_now(),
        "source": "GIDEONRemoteControlDiagnostics",
        "services": services,
    }


def publish_once(data_root: Path) -> tuple[Path, dict[str, object]]:
    data_root = Path(data_root)
    diagnostics_path = data_root / "diagnostics" / "health.json"
    try:
        diagnostics = read_json(diagnostics_path)
        payload = derive_coordinator_status(diagnostics)
    except Exception as exc:
        payload = {
            "schema_version": 1,
            "state": HealthState.STARTING.value if not diagnostics_path.exists() else HealthState.FAILED.value,
            "generated_at_utc": utc_now(),
            "source": "GIDEONRemoteControlDiagnostics",
            "services": [],
            "detail": f"Esperando diagnóstico GIDEON: {type(exc).__name__}: {exc}",
        }
    target = data_root / "coordinator" / "status.json"
    atomic_write_json(target, payload)
    return target, payload


def run_daemon_cycle(data_root: Path) -> tuple[bool, str]:
    try:
        target, _ = publish_once(data_root)
        return True, f"status={target}"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def run_daemon(data_root: Path, interval: float) -> int:
    while True:
        ok, detail = run_daemon_cycle(data_root)
        if not ok:
            print(f"GIDEON Coordinator cycle degraded: {detail}", file=sys.stderr, flush=True)
        time.sleep(max(2.0, interval))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="GIDEON Remote Control application coordinator")
    parser.add_argument("--data-root", type=Path, default=default_data_root())
    parser.add_argument("--interval", type=float, default=5.0)
    parser.add_argument("--daemon", action="store_true")
    ns = parser.parse_args(list(argv) if argv is not None else None)
    if ns.daemon:
        return run_daemon(ns.data_root, ns.interval)
    _, payload = publish_once(ns.data_root)
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if payload.get("state") == HealthState.RUNNING.value else 2


if __name__ == "__main__":
    raise SystemExit(main())
