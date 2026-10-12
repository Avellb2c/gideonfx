from __future__ import annotations

"""Health model and GIDEON-only service probes.

This module is deliberately independent from WebAdmin, Gateway and the Windows/
Linux installers.  It owns the semantic states exposed by Diagnostics and the
Coordinator and never performs start/stop/config operations on any service.
"""

from dataclasses import asdict, dataclass
import datetime as dt
from enum import Enum
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Callable, Iterable, Mapping, Protocol, Sequence


class HealthState(str, Enum):
    RUNNING = "RUNNING"
    STARTING = "STARTING"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"


@dataclass(frozen=True, slots=True)
class ServiceTarget:
    component: str
    windows_service: str
    linux_unit: str
    kind: str = "service"


GIDEON_SERVICE_TARGETS: tuple[ServiceTarget, ...] = (
    ServiceTarget("coordinator", "GIDEONRemoteControl", "gideon-coordinator.service"),
    ServiceTarget("gateway", "GIDEONRemoteControlGateway", "gideon-agent-gateway.service"),
    ServiceTarget("web_admin", "GIDEONRemoteControlWebAdmin", "gideon-web-admin.service"),
    ServiceTarget("backup", "GIDEONRemoteControlBackup", "gideon-backup.timer", "timer"),
    ServiceTarget("updater", "GIDEONRemoteControlUpdater", "gideon-update.path", "path"),
    ServiceTarget("diagnostics", "GIDEONRemoteControlDiagnostics", "gideon-diagnostics.service"),
)

WINDOWS_GIDEON_SERVICES: tuple[str, ...] = tuple(target.windows_service for target in GIDEON_SERVICE_TARGETS)
LINUX_GIDEON_UNITS: tuple[str, ...] = tuple(target.linux_unit for target in GIDEON_SERVICE_TARGETS)


@dataclass(slots=True)
class ServiceObservation:
    component: str
    state: HealthState
    detail: str
    source: str
    checked_at_utc: str

    def as_dict(self) -> dict[str, str]:
        payload = asdict(self)
        payload["state"] = self.state.value
        return payload


@dataclass(slots=True)
class HealthSnapshot:
    state: HealthState
    services: list[ServiceObservation]
    generated_at_utc: str
    schema_version: int = 1

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "state": self.state.value,
            "generated_at_utc": self.generated_at_utc,
            "services": [row.as_dict() for row in self.services],
        }


class CommandRunner(Protocol):
    def __call__(self, args: Sequence[str], timeout: int) -> subprocess.CompletedProcess[str]: ...


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def aggregate_state(states: Iterable[HealthState]) -> HealthState:
    values = list(states)
    if not values:
        return HealthState.FAILED
    if any(state is HealthState.FAILED for state in values):
        return HealthState.FAILED
    if any(state is HealthState.DEGRADED for state in values):
        return HealthState.DEGRADED
    if any(state is HealthState.STARTING for state in values):
        return HealthState.STARTING
    return HealthState.RUNNING


def merge_state(service_state: HealthState, functional_state: HealthState | None) -> HealthState:
    """Combine process-manager state with a functional health result.

    A process manager reporting RUNNING while its HTTP/API check fails is
    DEGRADED rather than healthy.  A manager-level failure remains FAILED.
    """
    if functional_state is None:
        return service_state
    if service_state is HealthState.FAILED:
        return HealthState.FAILED
    if service_state is HealthState.STARTING:
        return HealthState.STARTING
    if functional_state is HealthState.FAILED:
        return HealthState.DEGRADED
    if functional_state is HealthState.DEGRADED:
        return HealthState.DEGRADED
    return service_state


def _default_runner(args: Sequence[str], timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def _combined(cp: subprocess.CompletedProcess[str]) -> str:
    return ((cp.stdout or "") + "\n" + (cp.stderr or "")).strip()


def windows_service_state(name: str, *, runner: CommandRunner = _default_runner) -> tuple[HealthState, str]:
    if name not in WINDOWS_GIDEON_SERVICES:
        raise ValueError(f"Servicio fuera de allowlist GIDEON: {name}")
    cp = runner(["sc.exe", "query", name], 10)
    detail = _combined(cp)
    if cp.returncode != 0:
        return HealthState.FAILED, detail or "Servicio GIDEON no instalado/no consultable"
    # Numeric SCM state is stable even on localized Windows, but TYPE appears
    # before STATE and is normally ``10``.  RC16 used the first numeric field
    # and therefore mistook TYPE for the service state.  Prefer the explicit
    # STATE/ESTADO line and fall back to the first legal SCM state code (1..7).
    match = re.search(r"(?im)^\s*(?:STATE|ESTADO)\s*:\s*(\d+)\b", detail)
    if match:
        code = int(match.group(1))
    else:
        code = -1
        for line in detail.splitlines():
            candidate = re.search(r":\s*(\d+)\b", line)
            if candidate:
                value = int(candidate.group(1))
                if 1 <= value <= 7:
                    code = value
                    break
    if code == 4:
        return HealthState.RUNNING, "SCM RUNNING"
    if code in {2, 3, 5, 6}:
        return HealthState.STARTING, f"SCM transitional state={code}"
    if code == 1:
        return HealthState.FAILED, "SCM STOPPED"
    return HealthState.DEGRADED, f"SCM state desconocido: {detail[-300:]}"


def linux_unit_state(name: str, *, runner: CommandRunner = _default_runner) -> tuple[HealthState, str]:
    if name not in LINUX_GIDEON_UNITS:
        raise ValueError(f"Unidad fuera de allowlist GIDEON: {name}")
    cp = runner(["systemctl", "is-active", name], 10)
    value = (cp.stdout or "").strip().lower()
    detail = _combined(cp)
    if value == "active" and cp.returncode == 0:
        return HealthState.RUNNING, "systemd active"
    if value in {"activating", "reloading"}:
        return HealthState.STARTING, f"systemd {value}"
    if value in {"deactivating"}:
        return HealthState.DEGRADED, f"systemd {value}"
    return HealthState.FAILED, detail or f"systemd {value or 'unknown'}"


def linux_unit_states(
    names: Sequence[str], *, runner: CommandRunner = _default_runner
) -> dict[str, tuple[HealthState, str]]:
    """Read all GIDEON unit states with one systemctl process.

    Diagnostics runs continuously. Spawning one process per unit produced six
    process trees every cycle on Linux. ``systemctl is-active`` accepts multiple
    units and emits one state per line, reducing that fixed overhead by ~83%.
    A conservative per-unit fallback keeps compatibility with older systemd or
    injected test runners that do not return the expected row count.
    """
    clean = [str(name) for name in names]
    for name in clean:
        if name not in LINUX_GIDEON_UNITS:
            raise ValueError(f"Unidad fuera de allowlist GIDEON: {name}")
    if not clean:
        return {}
    cp = runner(["systemctl", "is-active", *clean], 10)
    values = [line.strip().lower() for line in (cp.stdout or "").splitlines() if line.strip()]
    if len(values) != len(clean):
        return {name: linux_unit_state(name, runner=runner) for name in clean}
    result: dict[str, tuple[HealthState, str]] = {}
    for name, value in zip(clean, values):
        if value == "active":
            result[name] = (HealthState.RUNNING, "systemd active")
        elif value in {"activating", "reloading"}:
            result[name] = (HealthState.STARTING, f"systemd {value}")
        elif value == "deactivating":
            result[name] = (HealthState.DEGRADED, f"systemd {value}")
        else:
            result[name] = (HealthState.FAILED, f"systemd {value or 'unknown'}")
    return result


def service_manager_observations(
    *,
    platform: str | None = None,
    runner: CommandRunner = _default_runner,
) -> list[ServiceObservation]:
    platform = (platform or ("windows" if os.name == "nt" else "linux")).lower()
    rows: list[ServiceObservation] = []
    linux_states = (
        linux_unit_states([target.linux_unit for target in GIDEON_SERVICE_TARGETS], runner=runner)
        if platform == "linux"
        else {}
    )
    for target in GIDEON_SERVICE_TARGETS:
        if platform == "windows":
            state, detail = windows_service_state(target.windows_service, runner=runner)
            source = "windows-scm"
        elif platform == "linux":
            state, detail = linux_states[target.linux_unit]
            source = "systemd"
        else:
            raise ValueError(f"Plataforma no soportada para servicios GIDEON: {platform}")
        rows.append(ServiceObservation(target.component, state, detail, source, utc_now()))
    return rows


def atomic_write_json(path: Path, payload: Mapping[str, object]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + f".{os.getpid()}.tmp")
    temp.write_text(json.dumps(dict(payload), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temp, path)


def read_json(path: Path) -> dict[str, object]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON no es objeto: {path}")
    return value
