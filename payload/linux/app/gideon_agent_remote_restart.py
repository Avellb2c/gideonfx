#!/usr/bin/env python3
"""GIDEON built-in maintenance action: schedule a safe remote restart.

Runs only inside a signed Agent Job.  It never changes firewall, SSH, Defender,
services outside GIDEON, or global Python configuration.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import platform
import subprocess
import sys


def hidden_kwargs() -> dict:
    if os.name != "nt":
        return {}
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    return {"startupinfo": startup, "creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--delay", type=int, default=60)
    ns = ap.parse_args()
    delay = max(30, min(int(ns.delay or 60), 600))
    system = platform.system().lower()
    if system == "windows":
        cmd = [
            os.path.join(os.environ.get("SystemRoot", r"C:\\Windows"), "System32", "shutdown.exe"),
            "/r", "/t", str(delay), "/d", "p:4:1", "/c", "Reinicio programado por GIDEON Remote Control",
        ]
    elif system == "linux":
        minutes = max(1, int(math.ceil(delay / 60.0)))
        cmd = ["/sbin/shutdown", "-r", f"+{minutes}", "Reinicio programado por GIDEON Remote Control"]
    elif system == "darwin":
        minutes = max(1, int(math.ceil(delay / 60.0)))
        cmd = ["/sbin/shutdown", "-r", f"+{minutes}"]
    else:
        print(json.dumps({"Success": False, "Error": f"PLATFORM_RESTART_UNSUPPORTED:{system}"}))
        return 2
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=20, shell=False, **hidden_kwargs())
    except Exception as exc:
        print(json.dumps({"Success": False, "Error": f"RESTART_SCHEDULE_FAILED:{type(exc).__name__}:{exc}"}))
        return 3
    if cp.returncode != 0:
        detail = (cp.stderr or cp.stdout or "").strip()[:2000]
        print(json.dumps({"Success": False, "Error": f"RESTART_SCHEDULE_FAILED:rc={cp.returncode}:{detail}"}))
        return int(cp.returncode or 4)
    print(json.dumps({
        "Success": True,
        "Action": "RESTART_SCHEDULED",
        "DelaySeconds": delay,
        "Platform": system,
        "Message": "El reinicio fue programado; el Agent podrá quedar offline durante el arranque del equipo.",
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
