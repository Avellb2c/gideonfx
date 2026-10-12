#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GIDEON compatibility launcher v4.1 (legacy CLI).

Desde v2.5 múltiples scripts NO generan múltiples FAN-OUT jobs. Este wrapper
conserva el comando histórico gideon_batch.py, pero empaqueta todos los --script en
un único job remoto por sede y delega en `gideon_admin.py fanout run`.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent


def hidden_kwargs() -> dict:
    if os.name != "nt":
        return {}
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = getattr(subprocess, "SW_HIDE", 0)
    return {
        "creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0),
        "startupinfo": startupinfo,
    }


def main() -> int:
    p = argparse.ArgumentParser(
        description=(
            "Compatibilidad v4.1: todos los scripts se envían como un único "
            "paquete SFTP y se ejecutan secuencialmente dentro de cada sede."
        )
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--targets")
    g.add_argument("--all", action="store_true")
    p.add_argument("--confirm-all", action="store_true")
    p.add_argument("--script", action="append", required=True)
    p.add_argument(
        "--export",
        default="xlsx",
        choices=["xlsx", "csv", "json", "txt", "none"],
    )
    behavior = p.add_mutually_exclusive_group()
    behavior.add_argument("--stop-on-error", action="store_true")
    behavior.add_argument("--continue-on-error", action="store_true")
    args = p.parse_args()

    if args.all and not args.confirm_all:
        raise SystemExit("--all requiere --confirm-all")

    cmd = [
        sys.executable,
        str(SCRIPT_DIR / "gideon_admin.py"),
        "fanout",
        "run",
    ]

    if args.all:
        cmd += ["--all", "--confirm-all"]
    else:
        cmd += ["--targets", args.targets]

    for script in args.script:
        cmd += ["--script", str(Path(script).resolve())]

    cmd += ["--export", args.export]
    if args.stop_on_error:
        cmd += ["--stop-on-error"]
    elif args.continue_on_error:
        cmd += ["--continue-on-error"]

    print(
        f"[GIDEON v4.1] 1 paquete · {len(args.script)} script(s) · "
        "SFTP -> SSH -> SFTP",
        flush=True,
    )

    cp = subprocess.run(
        cmd,
        cwd=str(SCRIPT_DIR),
        stdout=sys.stdout,
        stderr=sys.stderr,
        stdin=subprocess.DEVNULL,
        **hidden_kwargs(),
    )
    return int(cp.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
