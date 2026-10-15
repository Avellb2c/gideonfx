"""Detached, allow-listed Windows ACME job launched by WebAdmin.

The WebAdmin process never accepts a command or script path from the browser.
It starts this wrapper with fixed paths and validated FQDN/email parameters.
The wrapper records only public job metadata and delegates the privileged work
to the existing Configure-GIDEONWindowsLetsEncrypt.ps1 integrator.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
import subprocess
import sys
from typing import Any


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def _update(path: Path, **changes: Any) -> dict[str, Any]:
    try:
        current = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError, TypeError):
        current = {}
    if not isinstance(current, dict):
        current = {}
    current.update(changes)
    _write(path, current)
    return current


def run(args: argparse.Namespace) -> int:
    install_root = Path(args.install_root).resolve()
    data_root = Path(args.data_root).resolve()
    job_path = Path(args.job_path).resolve()
    log_path = Path(args.log_path).resolve()
    script = install_root / "app" / "deploy" / "windows" / "Configure-GIDEONWindowsLetsEncrypt.ps1"
    _update(job_path, state="RUNNING", started_utc=_now(), finished_utc="", error="")
    command = [
        "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script),
        "-InstallRoot", str(install_root), "-DataRoot", str(data_root),
        "-WebHost", args.web_host, "-GatewayHost", args.gateway_host,
        "-Email", args.email, "-Environment", args.environment,
    ]
    log_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with log_path.open("a", encoding="utf-8", newline="") as log:
            completed = subprocess.run(
                command, cwd=str(install_root), stdin=subprocess.DEVNULL,
                stdout=log, stderr=subprocess.STDOUT, check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        if completed.returncode == 0:
            _update(job_path, state="SUCCEEDED", returncode="0", finished_utc=_now(), error="")
            return 0
        _update(job_path, state="FAILED", returncode=str(completed.returncode), finished_utc=_now(),
                error=f"win-acme/OneClick terminó con código {completed.returncode}. Revise el log.")
        return int(completed.returncode or 1)
    except Exception as exc:
        _update(job_path, state="FAILED", returncode="1", finished_utc=_now(),
                error="Falló el trabajo ACME: " + type(exc).__name__)
        try:
            with log_path.open("a", encoding="utf-8") as log:
                log.write(f"GIDEON_ACME_JOB_FAIL: {type(exc).__name__}\n")
        except OSError:
            pass
        return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the fixed GIDEON Windows ACME OneClick job")
    parser.add_argument("--install-root", required=True)
    parser.add_argument("--data-root", required=True)
    parser.add_argument("--web-host", required=True)
    parser.add_argument("--gateway-host", required=True)
    parser.add_argument("--email", required=True)
    parser.add_argument("--environment", choices=("production", "staging"), required=True)
    parser.add_argument("--job-path", required=True)
    parser.add_argument("--log-path", required=True)
    args = parser.parse_args(argv)
    if sys.platform != "win32":
        _update(Path(args.job_path), state="FAILED", finished_utc=_now(), error="El trabajo ACME de Windows sólo corre en Windows.")
        return 1
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
