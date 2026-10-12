from __future__ import annotations

"""SCM manager for the six GIDEON Remote Control Windows services.

The actual SCM host is the isolated .NET executable GIDEONServiceHost.exe compiled
by Install-GIDEON-Windows.ps1. This manager only creates/starts/stops/removes the
allowlisted GIDEONRemoteControl* service names and never touches unrelated services.
"""

import datetime as dt
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Iterable

SERVICE_NAMES = (
    "GIDEONRemoteControl",
    "GIDEONRemoteControlGateway",
    "GIDEONRemoteControlWebAdmin",
    "GIDEONRemoteControlBackup",
    "GIDEONRemoteControlUpdater",
    "GIDEONRemoteControlDiagnostics",
)

# RC13 Windows least-privilege model.
#
# The SCM logon identity and the per-service ACL identity are intentionally
# different concepts:
#   * LocalService is the low-privilege built-in logon account.
#   * NT SERVICE\<service> is the unique Service SID injected into the
#     process token by SERVICE_SID_TYPE_UNRESTRICTED.
#
# ACLs are granted ONLY to the service-specific SID, never to LocalService as a
# shared principal.  This avoids SCM 1057 on hosts that reject NT SERVICE\...
# as obj= while preserving per-service filesystem/PKI isolation.
SERVICE_LOGON_ACCOUNTS = {
    "GIDEONRemoteControl": r"NT AUTHORITY\LocalService",
    "GIDEONRemoteControlGateway": r"NT AUTHORITY\LocalService",
    "GIDEONRemoteControlWebAdmin": r"NT AUTHORITY\LocalService",
    "GIDEONRemoteControlBackup": r"NT AUTHORITY\LocalService",
    "GIDEONRemoteControlUpdater": "LocalSystem",
    "GIDEONRemoteControlDiagnostics": r"NT AUTHORITY\LocalService",
}

SERVICE_SID_PRINCIPALS = {
    name: rf"NT SERVICE\{name}" for name in SERVICE_NAMES
}

LOW_PRIVILEGE_SERVICE_NAMES = tuple(
    name for name in SERVICE_NAMES if SERVICE_LOGON_ACCOUNTS[name] != "LocalSystem"
)

SERVICE_META = {
    "GIDEONRemoteControl": (
        "GIDEON Remote Control",
        "GIDEON Remote Control application coordinator. Does not manage unrelated Windows services.",
    ),
    "GIDEONRemoteControlGateway": (
        "GIDEON Remote Control - Agent Gateway",
        "GIDEON Agent HTTPS/PULL gateway microservice",
    ),
    "GIDEONRemoteControlWebAdmin": (
        "GIDEON Remote Control - Web Admin",
        "GIDEON Remote Control Web Administration microservice",
    ),
    "GIDEONRemoteControlBackup": (
        "GIDEON Remote Control - Backup",
        "GIDEON isolated backup microservice",
    ),
    "GIDEONRemoteControlUpdater": (
        "GIDEON Remote Control - Updater",
        "GIDEON privileged incremental update applicator. Writes only allowlisted GIDEON paths.",
    ),
    "GIDEONRemoteControlDiagnostics": (
        "GIDEON Remote Control - Diagnostics",
        "GIDEON read-only health and diagnostics microservice. Observes only GIDEON components.",
    ),
}

REG_PATH = r"SOFTWARE\GIDEON\RemoteControl"


def _require_windows() -> None:
    if os.name != "nt":
        raise RuntimeError("gideon_windows_service.py solo funciona en Windows.")


def _registry_value(name: str) -> str:
    _require_windows()
    import winreg

    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
        value, _ = winreg.QueryValueEx(key, name)
    return str(value)


def install_root() -> Path:
    return Path(_registry_value("InstallRoot")).resolve()


def data_root() -> Path:
    return Path(_registry_value("DataRoot")).resolve()


def host_exe() -> Path:
    return install_root() / "service-host" / "GIDEONServiceHost.exe"


def _manager_log_path(service_name: str) -> Path:
    path = data_root() / "logs" / "services" / service_name / "scm-manager.log"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _host_log_path(service_name: str) -> Path:
    path = data_root() / "logs" / "services" / service_name / "service-host.log"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _append_log(service_name: str, message: str) -> None:
    stamp = dt.datetime.now().astimezone().isoformat(timespec="seconds")
    try:
        with _manager_log_path(service_name).open("a", encoding="utf-8", errors="replace") as handle:
            handle.write(f"[{stamp}] [scm-manager] {message}\n")
    except OSError:
        pass


def _run(args: Iterable[str], timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args),
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def _combined(cp: subprocess.CompletedProcess[str]) -> str:
    return ((cp.stdout or "") + "\n" + (cp.stderr or "")).strip()


def _exists(name: str) -> bool:
    return _run(["sc.exe", "query", name], timeout=15).returncode == 0


def _is_running_output(text: str) -> bool:
    # sc.exe may localize STATE/ESTADO, but the numeric service state 4 is stable.
    return re.search(r":\s*4\s+", text) is not None


def _is_stopped_output(text: str) -> bool:
    return re.search(r":\s*1\s+", text) is not None


def _delete_service(name: str) -> None:
    if not _exists(name):
        return
    _run(["sc.exe", "stop", name], timeout=20)
    cp = _run(["sc.exe", "delete", name], timeout=20)
    if cp.returncode not in (0, 1060):
        detail = _combined(cp)
        _append_log(name, f"Delete request rc={cp.returncode}: {detail}")
    for _ in range(60):
        if not _exists(name):
            return
        time.sleep(0.5)
    raise RuntimeError(f"SCM no liberó el servicio GIDEON {name} después de delete.")


def _rollback_new_services(created: list[str]) -> None:
    """Fail closed: remove GIDEON services created before a registration failure."""
    for service_name in reversed(created):
        try:
            _delete_service(service_name)
        except Exception as exc:
            _append_log(service_name, f"Rollback cleanup failed: {exc}")


def _install_all() -> int:
    exe = host_exe()
    if not exe.is_file():
        print(f"ERROR: host de servicio GIDEON no existe: {exe}", file=sys.stderr)
        return 2

    created: list[str] = []
    for name in SERVICE_NAMES:
        display, description = SERVICE_META[name]
        _delete_service(name)
        bin_path = f'"{exe}" {name}'
        target_account = SERVICE_LOGON_ACCOUNTS[name]

        # RC13: use a built-in, low-privilege logon account that is valid before
        # service creation. Per-service isolation is provided by the Service SID
        # enabled immediately after creation, not by using NT SERVICE\<name> as
        # the SCM logon account. This avoids ERROR_INVALID_SERVICE_ACCOUNT 1057.
        create_args = [
            "sc.exe", "create", name,
            "binPath=", bin_path,
            "start=", "demand",
            "obj=", target_account,
            "DisplayName=", display,
        ]
        cp = _run(create_args, timeout=30)
        if cp.returncode != 0:
            detail = _combined(cp)
            print(f"ERROR registrando {name} (rc={cp.returncode}):\n{detail}", file=sys.stderr)
            _append_log(name, f"Create failed rc={cp.returncode}: {detail}")
            _rollback_new_services(created)
            return 3
        created.append(name)

        _run(["sc.exe", "description", name, description], timeout=20)

        # Service SID must exist before ACL code resolves NT SERVICE\<name>.
        sid_cp = _run(["sc.exe", "sidtype", name, "unrestricted"], timeout=20)
        if sid_cp.returncode != 0:
            detail = _combined(sid_cp)
            print(f"ERROR configurando Service SID para {name} (rc={sid_cp.returncode}):\n{detail}", file=sys.stderr)
            _append_log(name, f"sidtype failed rc={sid_cp.returncode}: {detail}")
            _rollback_new_services(created)
            return 3

        _run(
            [
                "sc.exe", "failure", name,
                "reset=", "86400",
                "actions=", "restart/5000/restart/15000/restart/60000",
            ],
            timeout=20,
        )
        _run(["sc.exe", "failureflag", name, "1"], timeout=20)
        _append_log(
            name,
            f"Registered with host {exe}; logon={target_account}; "
            f"service_sid={SERVICE_SID_PRINCIPALS[name]}; sidtype=unrestricted; start_mode=demand(staged)",
        )
    return 0


def _set_start_mode(mode: str) -> int:
    if mode not in {"auto", "demand"}:
        raise ValueError("unsupported GIDEON service start mode")
    failures: list[str] = []
    for name in SERVICE_NAMES:
        if not _exists(name):
            failures.append(name)
            _append_log(name, f"Cannot set start mode={mode}: service not installed")
            continue
        cp = _run(["sc.exe", "config", name, "start=", mode], timeout=20)
        if cp.returncode != 0:
            failures.append(name)
            _append_log(name, f"Start mode {mode} failed rc={cp.returncode}: {_combined(cp)}")
    if failures:
        print("No se pudo configurar start mode GIDEON para: " + ", ".join(failures), file=sys.stderr)
        return 5
    return 0


def _arm_auto() -> int:
    """Arm AUTO_START only after Windows isolation validation succeeds."""
    return _set_start_mode("auto")


def _quiesce() -> int:
    """Fail closed after a bad start/health: stop GIDEON and leave DEMAND_START."""
    stop_rc = _stop_all()
    mode_rc = _set_start_mode("demand")
    return 0 if stop_rc == 0 and mode_rc == 0 else 6


def _stop_all() -> int:
    rc = 0
    for name in reversed(SERVICE_NAMES):
        if not _exists(name):
            continue
        cp = _run(["sc.exe", "stop", name], timeout=25)
        if cp.returncode not in (0, 1062):
            detail = _combined(cp)
            _append_log(name, f"Stop rc={cp.returncode}: {detail}")
            rc = 1
    return rc


def _wait_running(name: str, timeout_seconds: float = 20.0) -> tuple[bool, str]:
    deadline = time.monotonic() + timeout_seconds
    last = ""
    while time.monotonic() < deadline:
        cp = _run(["sc.exe", "query", name], timeout=10)
        last = _combined(cp)
        if cp.returncode != 0:
            return False, last
        if _is_running_output(last):
            return True, last
        if _is_stopped_output(last):
            # sc start already returned success. A subsequent STOPPED state means
            # the host/child exited during startup; surface diagnostics immediately
            # instead of hiding the failure behind a 20-second poll loop.
            return False, last
        time.sleep(0.6)
    return False, last


def _start_all() -> int:
    failures: list[str] = []
    for name in SERVICE_NAMES:
        cp = _run(["sc.exe", "start", name], timeout=30)
        detail = _combined(cp)
        if cp.returncode != 0 and "1056" not in detail:  # already running
            failures.append(name)
            print(f"ERROR iniciando {name} (sc rc={cp.returncode}):\n{detail}", file=sys.stderr)
            _append_log(name, f"Start failed rc={cp.returncode}: {detail}")
            continue
        ok, status_detail = _wait_running(name, 20)
        if not ok:
            failures.append(name)
            print(f"ERROR: {name} no alcanzó RUNNING.\n{status_detail}", file=sys.stderr)
            _append_log(name, f"Did not reach RUNNING: {status_detail}")
        else:
            print(f"{name}: RUNNING")
    if failures:
        print("Servicios GIDEON que no iniciaron: " + ", ".join(failures), file=sys.stderr)
        return 4
    return 0



def _fresh_json(path: Path, max_age_seconds: float = 45.0) -> tuple[bool, str]:
    try:
        stat = path.stat()
        age = max(0.0, time.time() - stat.st_mtime)
        if age > max_age_seconds:
            return False, f"stale age={age:.1f}s path={path}"
        value = json.loads(path.read_text(encoding="utf-8-sig"))
        if not isinstance(value, dict):
            return False, f"invalid JSON object path={path}"
        return True, f"fresh age={age:.1f}s state={value.get('state')} path={path}"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc} path={path}"


def _runtime_health(timeout_seconds: float = 45.0) -> int:
    """Verify service liveness plus Diagnostics/Coordinator publication.

    SCM RUNNING alone is insufficient: a daemon can be alive but unable to
    publish its GIDEON state. This gate waits for fresh JSON artifacts written by
    the low-privilege service tokens.
    """
    deadline = time.monotonic() + timeout_seconds
    data = data_root()
    targets = (
        data / "diagnostics" / "health.json",
        data / "coordinator" / "status.json",
    )
    last: list[str] = []
    while time.monotonic() < deadline:
        service_failures = []
        for name in SERVICE_NAMES:
            cp = _run(["sc.exe", "query", name], timeout=10)
            if cp.returncode != 0 or not _is_running_output(_combined(cp)):
                service_failures.append(name)
        checks = [_fresh_json(path) for path in targets]
        last = [detail for _, detail in checks]
        if not service_failures and all(ok for ok, _ in checks):
            for detail in last:
                print("RUNTIME_HEALTH OK: " + detail)
            return 0
        time.sleep(1.0)
    print("RUNTIME_HEALTH FAILED", file=sys.stderr)
    for detail in last:
        print(" - " + detail, file=sys.stderr)
    return 7

def _remove_all() -> int:
    _stop_all()
    for name in reversed(SERVICE_NAMES):
        _delete_service(name)
    return 0


def _status() -> int:
    rc = 0
    for name in SERVICE_NAMES:
        cp = _run(["sc.exe", "query", name], timeout=15)
        detail = _combined(cp)
        if cp.returncode != 0:
            print(f"{name}: NOT_INSTALLED")
            rc = 1
        elif _is_running_output(detail):
            print(f"{name}: RUNNING")
        elif _is_stopped_output(detail):
            print(f"{name}: STOPPED")
            rc = 1
        else:
            print(f"{name}: PENDING/UNKNOWN")
            rc = 1
    return rc


def _tail(path: Path, lines: int = 30) -> str:
    if not path.is_file():
        return "(sin log)"
    try:
        content = path.read_text(encoding="utf-8", errors="replace").splitlines()
        return "\n".join(content[-lines:])
    except OSError as exc:
        return f"(no se pudo leer log: {exc})"


def _localservice_temp_candidates(service_name: str) -> list[Path]:
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    filename = f"GIDEONServiceHost-startup-{service_name}.log"
    return [
        system_root / "ServiceProfiles" / "LocalService" / "AppData" / "Local" / "Temp" / filename,
        Path(os.environ.get("TEMP", ".")) / filename,
    ]


def _diagnostics() -> int:
    exe = host_exe()
    print(f"Host GIDEON: {exe} exists={exe.is_file()}")
    for name in SERVICE_NAMES:
        print(f"\n===== {name} =====")
        for verb in ("queryex", "qc", "qsidtype"):
            cp = _run(["sc.exe", verb, name], timeout=15)
            print(_combined(cp))
        print("--- scm-manager.log ---")
        print(_tail(_manager_log_path(name), 60))
        print("--- service-host.log ---")
        print(_tail(_host_log_path(name), 120))
        for fallback in _localservice_temp_candidates(name):
            if fallback.is_file():
                print(f"--- fallback {fallback} ---")
                print(_tail(fallback, 120))
    return 0


def main(argv: list[str] | None = None) -> int:
    _require_windows()
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        raise SystemExit("Uso: gideon_windows_service.py install-all|arm-auto|quiesce|remove-all|start-all|stop-all|status|runtime-health|diagnostics")
    command = args[0].lower()
    if command == "install-all":
        return _install_all()
    if command == "arm-auto":
        return _arm_auto()
    if command == "quiesce":
        return _quiesce()
    if command == "remove-all":
        return _remove_all()
    if command == "start-all":
        return _start_all()
    if command == "stop-all":
        return _stop_all()
    if command == "status":
        return _status()
    if command == "runtime-health":
        return _runtime_health()
    if command == "diagnostics":
        return _diagnostics()
    raise SystemExit("Uso: gideon_windows_service.py install-all|arm-auto|quiesce|remove-all|start-all|stop-all|status|runtime-health|diagnostics")


if __name__ == "__main__":
    raise SystemExit(main())
