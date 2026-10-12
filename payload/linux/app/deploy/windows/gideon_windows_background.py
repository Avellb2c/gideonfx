from __future__ import annotations

"""Long-running GIDEON-only workers hosted by GIDEONServiceHost.exe on Windows."""

import datetime as dt
import os
from pathlib import Path
import subprocess
import sys
import time
import winreg

REG_PATH = r"SOFTWARE\GIDEON\RemoteControl"


def _registry_value(name: str) -> str:
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
        value, _ = winreg.QueryValueEx(key, name)
    return str(value)


def _roots() -> tuple[Path, Path, Path]:
    # The SCM host injects canonical roots into the child environment. Prefer
    # those values so low-privilege workers do not depend on Registry64 access
    # just to start. Registry64 remains an integrity/fallback source.
    install_env = os.environ.get("GIDEON_INSTALL_ROOT", "").strip()
    app_env = os.environ.get("GIDEON_APP_ROOT", "").strip()
    data_env = os.environ.get("GIDEON_DATA_ROOT", "").strip()
    if install_env and app_env and data_env:
        return Path(install_env).resolve(), Path(app_env).resolve(), Path(data_env).resolve()
    install = Path(_registry_value("InstallRoot")).resolve()
    app = Path(_registry_value("AppRoot")).resolve()
    data = Path(_registry_value("DataRoot")).resolve()
    return install, app, data


def _python() -> Path:
    install, _, _ = _roots()
    return install / "venv" / "Scripts" / "python.exe"


def _log(service: str, message: str) -> None:
    _, _, data = _roots()
    path = data / "logs" / "services" / service / "worker.log"
    path.parent.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().astimezone().isoformat(timespec="seconds")
    with path.open("a", encoding="utf-8", errors="replace") as handle:
        handle.write(f"[{stamp}] [background] {message}\n")


def _run(args: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=str(_roots()[1]),
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def backup_loop() -> int:
    _, app, data = _roots()
    _log("GIDEONRemoteControlBackup", "Backup fallback scheduler started")
    first_cycle = True
    while True:
        now = dt.datetime.now()
        next_run = now.replace(hour=3, minute=17, second=0, microsecond=0)
        if first_cycle and now >= next_run:
            next_run = now
        elif next_run <= now:
            next_run += dt.timedelta(days=1)
        first_cycle = False
        time.sleep(max(1.0, (next_run - now).total_seconds()))
        try:
            cp = _run(
                [
                    str(_python()), str(app / "gideon_backup.py"),
                    "--settings", str(data / "shared" / "runtime_settings.json"),
                    "--root", str(data / "backups" / "local"),
                    "--external-root", str(data / "backups" / "external"),
                    "--gateway-db", str(data / "gateway" / "gateway.sqlite3"),
                    "--web-db", str(data / "web" / "security.sqlite3"),
                ],
                timeout=1800,
            )
            detail = ((cp.stdout or "") + " " + (cp.stderr or "")).strip()
            _log("GIDEONRemoteControlBackup", f"Backup rc={cp.returncode}: {detail[:2000]}")
        except Exception as exc:
            _log("GIDEONRemoteControlBackup", f"Backup error: {type(exc).__name__}: {exc}")


def _ready_signature(data: Path) -> tuple[tuple[str, int, int], ...]:
    inbox = data / "updates" / "inbox"
    if not inbox.is_dir():
        return ()
    rows: list[tuple[str, int, int]] = []
    for path in sorted(inbox.glob("*.ready"), key=lambda item: item.name.casefold()):
        try:
            stat = path.stat()
            rows.append((path.name, int(stat.st_mtime_ns), int(stat.st_size)))
        except OSError:
            continue
    return tuple(rows)


def updater_loop() -> int:
    _, app, data = _roots()
    _log("GIDEONRemoteControlUpdater", "Updater worker started")
    delay_seconds = 1
    failure_streak = 0
    last_processed: tuple[tuple[str, int, int], ...] = ()
    while True:
        signature = _ready_signature(data)
        if not signature or signature == last_processed:
            time.sleep(1)
            continue
        failed = False
        try:
            python = _python()
            if not python.is_file():
                raise FileNotFoundError(f"GIDEON private Python runtime missing: {python}")
            cp = _run(
                [
                    str(python), str(app / "gideon_product_update.py"),
                    "--process-inbox", "--platform", "windows",
                    "--state-root", str(data / "updates"),
                    "--app-root", str(app),
                ],
                timeout=1800,
            )
            if cp.returncode:
                failed = True
                detail = ((cp.stdout or "") + " " + (cp.stderr or "")).strip()
                _log("GIDEONRemoteControlUpdater", f"Update inbox rc={cp.returncode}: {detail[:2000]}")
        except Exception as exc:
            failed = True
            _log("GIDEONRemoteControlUpdater", f"Update inbox error: {type(exc).__name__}: {exc}")

        if failed:
            failure_streak += 1
            # Avoid the historical 3-second log/restart storm observed on a
            # partially installed Windows host. Cap at 5 minutes.
            delay_seconds = min(300, max(15, 3 * (2 ** min(failure_streak, 7))))
        else:
            if failure_streak:
                _log("GIDEONRemoteControlUpdater", "Updater recovered; returning to normal polling")
            failure_streak = 0
            delay_seconds = 1
            last_processed = signature
        time.sleep(delay_seconds)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["backup"]:
        return backup_loop()
    if args == ["updater"]:
        return updater_loop()
    raise SystemExit("Uso: gideon_windows_background.py backup|updater")


if __name__ == "__main__":
    raise SystemExit(main())
