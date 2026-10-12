#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GIDEON SSH Admin v4.1.1 - Autodiagnóstico local.

No conecta a tiendas. Verifica que la PC administrativa esté preparada para
la arquitectura SFTP -> SSH -> SFTP.
"""
from __future__ import annotations

from gideon_common.observability import best_effort_warning

import argparse
import importlib.util
import ipaddress
import json
import os
import sys
from pathlib import Path
from gideon_core.transport_profiles import get_transport_profile
from typing import Any

from gideon_io import atomic_write_json, read_json_retry
from gideon_core.config import validate_config
from gideon_core.protocol import protocol_metadata
from gideon_core.launch import LaunchRequest, LaunchService, AGENTLESS, AGENT

from gideon_admin import (
    Inventory,
    SSHAgent,
    command_exists,
    expand_path,
    load_config,
)

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG = SCRIPT_DIR / "config" / "config.json"
DEFAULT_SITES = SCRIPT_DIR / "config" / "sites.csv"


def _result(
    name: str,
    status: str,
    detail: str,
    *,
    critical: bool = True,
) -> dict[str, Any]:
    return {
        "Check": name,
        "Status": status,
        "Detail": detail,
        "Critical": bool(critical),
    }


def run_selfcheck(
    config_path: Path = DEFAULT_CONFIG,
    sites_path: Path = DEFAULT_SITES,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    py_ok = sys.version_info >= (3, 10)
    checks.append(
        _result(
            "Python",
            "OK" if py_ok else "FAIL",
            (
                f"{sys.version_info.major}.{sys.version_info.minor}."
                f"{sys.version_info.micro}"
            ),
        )
    )

    tkinter_ok = importlib.util.find_spec("tkinter") is not None
    checks.append(
        _result(
            "Tkinter",
            "OK" if tkinter_ok else "FAIL",
            "Disponible" if tkinter_ok else "No instalado",
        )
    )

    openpyxl_ok = importlib.util.find_spec("openpyxl") is not None
    checks.append(
        _result(
            "openpyxl",
            "OK" if openpyxl_ok else "FAIL",
            "Disponible" if openpyxl_ok else "No instalado",
        )
    )

    ssh = command_exists("ssh.exe") or command_exists("ssh")
    sftp = command_exists("sftp.exe") or command_exists("sftp")
    ssh_add = command_exists("ssh-add.exe") or command_exists("ssh-add")
    powershell = (
        command_exists("powershell.exe")
        or command_exists("powershell")
        or command_exists("pwsh")
    )

    for name, value in [
        ("ssh.exe", ssh),
        ("sftp.exe", sftp),
        ("ssh-add.exe", ssh_add),
        ("PowerShell local", powershell),
    ]:
        checks.append(
            _result(
                name,
                "OK" if value else "FAIL",
                str(value or "No encontrado"),
            )
        )

    cfg: dict[str, Any] | None = None

    try:
        cfg = load_config(expand_path(config_path))
        checks.append(
            _result(
                "config.json",
                "OK",
                str(expand_path(config_path)),
            )
        )
        core_cfg_report = validate_config(cfg)
        checks.append(
            _result(
                "Arquitectura/config schema",
                "OK" if core_cfg_report.ok else "FAIL",
                json.dumps({
                    **protocol_metadata(),
                    "Warnings": core_cfg_report.warnings,
                    "Errors": core_cfg_report.errors,
                }, ensure_ascii=False),
            )
        )
    except Exception as exc:
        checks.append(
            _result(
                "config.json",
                "FAIL",
                str(exc),
            )
        )

    # Escritura local robusta: misma primitiva usada por manifests/cancel sidecars.
    try:
        io_root = Path(os.path.expandvars(r"%LOCALAPPDATA%\GIDEONSSH\fanout_jobs"))
        io_root.mkdir(parents=True, exist_ok=True)
        io_test = io_root / ".selfcheck-atomic.json"
        atomic_write_json(io_test, {"SelfCheck": True, "Pid": os.getpid()})
        io_value = read_json_retry(io_test, retries=3)
        io_ok = isinstance(io_value, dict) and io_value.get("SelfCheck") is True
        checks.append(
            _result(
                "I/O local atómico",
                "OK" if io_ok else "FAIL",
                "lock interproceso + tmp único + replace/retry",
            )
        )
        try:
            io_test.unlink(missing_ok=True)
            Path(str(io_test) + ".lock").unlink(missing_ok=True)
        except Exception as cleanup_exc:
            best_effort_warning("No se pudieron retirar temporales del self-check de I/O", cleanup_exc)
    except Exception as exc:
        checks.append(
            _result(
                "I/O local atómico",
                "FAIL",
                str(exc),
            )
        )

    inventory: Inventory | None = None

    try:
        inventory = Inventory(expand_path(sites_path))
        codes = [x.code for x in inventory.sites]
        ips = [x.ip for x in inventory.sites]

        invalid_ips: list[str] = []
        for value in ips:
            try:
                ipaddress.ip_address(value)
            except ValueError:
                invalid_ips.append(value)

        unique_ok = (
            len(codes) == len(set(codes))
            and len(ips) == len(set(ips))
        )
        count_ok = len(inventory.sites) > 0
        inventory_ok = unique_ok and not invalid_ips and count_ok

        detail = (
            f"{len(inventory.sites)} host(s); "
            f"códigos únicos={'SI' if len(codes) == len(set(codes)) else 'NO'}; "
            f"IPs únicas={'SI' if len(ips) == len(set(ips)) else 'NO'}"
        )

        if invalid_ips:
            detail += "; IP inválidas=" + ",".join(invalid_ips)

        checks.append(
            _result(
                "Inventario de sedes",
                "OK" if inventory_ok else "FAIL",
                detail,
            )
        )
    except Exception as exc:
        checks.append(
            _result(
                "Inventario de sedes",
                "FAIL",
                str(exc),
            )
        )

    if cfg is not None:
        fanout = cfg.get("fanout", {}) or {}
        paths = cfg.get("paths", {}) or {}
        ssh_cfg = cfg.get("ssh", {}) or {}

        try:
            spec = get_transport_profile(
                fanout.get("transport_profile")
            )
            transport_ok = bool(
                fanout.get("multi_script_single_job", False)
            )
            transport_detail = (
                f"profile={spec.id} | "
                f"upload={spec.distribution} | "
                f"control={spec.control} | "
                f"collect={spec.collection} | "
                f"single-job={fanout.get('multi_script_single_job')}"
            )
        except Exception as exc:
            transport_ok = False
            transport_detail = f"TransportProfile inválido: {exc}"

        checks.append(
            _result(
                "Arquitectura configurada",
                "OK" if transport_ok else "FAIL",
                transport_detail,
            )
        )

        key = expand_path(ssh_cfg.get("key_path", ""))
        checks.append(
            _result(
                "Clave privada GIDEON",
                "OK" if key.is_file() else "FAIL",
                str(key),
            )
        )

        if key.is_file() and ssh_add:
            try:
                loaded = SSHAgent(key).is_loaded()
                checks.append(
                    _result(
                        "Clave en ssh-agent",
                        "OK" if loaded else "WARN",
                        "Cargada" if loaded else "No cargada",
                        critical=False,
                    )
                )
            except Exception as exc:
                checks.append(
                    _result(
                        "Clave en ssh-agent",
                        "WARN",
                        str(exc),
                        critical=False,
                    )
                )

        known_hosts = expand_path(
            paths.get(
                "known_hosts",
                "%LOCALAPPDATA%\\GIDEONSSH\\known_hosts",
            )
        )

        try:
            known_hosts.parent.mkdir(
                parents=True,
                exist_ok=True,
            )
            checks.append(
                _result(
                    "known_hosts",
                    "OK",
                    str(known_hosts),
                )
            )
        except Exception as exc:
            checks.append(
                _result(
                    "known_hosts",
                    "FAIL",
                    str(exc),
                )
            )

        worker_cfg = str(
            fanout.get(
                "remote_worker",
                r"scripts\remote_job_worker.ps1",
            )
        ).replace("\\", os.sep)

        starter_cfg = str(
            fanout.get(
                "remote_starter",
                r"scripts\start_job.ps1",
            )
        ).replace("\\", os.sep)

        worker = (
            Path(worker_cfg)
            if Path(worker_cfg).is_absolute()
            else SCRIPT_DIR / worker_cfg
        )
        starter = (
            Path(starter_cfg)
            if Path(starter_cfg).is_absolute()
            else SCRIPT_DIR / starter_cfg
        )

        for name, path in [
            ("Remote worker", worker),
            ("SSH starter", starter),
        ]:
            checks.append(
                _result(
                    name,
                    "OK" if path.is_file() else "FAIL",
                    str(path),
                )
            )

    builtin_scripts = [
        SCRIPT_DIR / "scripts" / "audit_server.ps1",
        SCRIPT_DIR / "scripts" / "disk_inventory.ps1",
        SCRIPT_DIR / "scripts" / "service_inventory.ps1",
        SCRIPT_DIR / "scripts" / "find_backup_folders.ps1",
        SCRIPT_DIR / "scripts" / "start_job.ps1",
        SCRIPT_DIR / "scripts" / "remote_job_worker.ps1",
        SCRIPT_DIR / "scripts" / "gideon_script_host.ps1",
    ]

    for path in builtin_scripts:
        if not path.is_file():
            checks.append(
                _result(
                    f"Script {path.name}",
                    "FAIL",
                    "No existe",
                )
            )
            continue

        try:
            first_line = (
                path.read_text(
                    encoding="utf-8-sig",
                    errors="replace",
                )
                .splitlines()[0]
                .strip()
            )
        except Exception:
            first_line = ""

        compatible = (
            first_line.lower()
            == "#requires -version 5.1"
        )

        checks.append(
            _result(
                f"Script {path.name}",
                "OK" if compatible else "FAIL",
                (
                    "PowerShell 5.1"
                    if compatible
                    else f"Cabecera inesperada: {first_line}"
                ),
            )
        )

    # GUI/backend launch contract: parse exactly the command shape used by v4.1.1.
    # This check prevents regressions such as placing a global --sites-file
    # after the `run` subcommand (the defect that previously produced SIN JOB).
    try:
        import gideon_fanout
        import gideon_agent_orchestrator
        if inventory and inventory.sites:
            sample_site = inventory.sites[0]
            sample_script = SCRIPT_DIR / "scripts" / "find_backup_folders.ps1"
            launch = LaunchService(
                app_root=SCRIPT_DIR,
                jobs_dir=Path(os.path.expandvars(r"%LOCALAPPDATA%\GIDEONSSH\fanout_jobs")),
                logs_dir=Path(os.path.expandvars(r"%LOCALAPPDATA%\GIDEONSSH\gui_logs")),
                python_exe=sys.executable,
                version="4.0",
            )
            req = LaunchRequest(
                job_id="SELFCHECK-000001",
                method=AGENTLESS,
                sites_file=expand_path(sites_path),
                sites=(sample_site,),
                scripts=(sample_script,),
                export_format="none",
            )
            plan = launch.build_plan(req)
            fanout_args = list(plan.command)[list(plan.command).index("fanout") + 1:]
            parsed = gideon_fanout.build_parser().parse_args(fanout_args)
            contract_ok = (
                parsed.action == "run"
                and str(parsed.job_id) == "SELFCHECK-000001"
                and Path(parsed.sites_file).name == Path(sites_path).name
            )
            checks.append(_result(
                "Contrato GUI → FAN-OUT",
                "OK" if contract_ok else "FAIL",
                plan.command_text(),
            ))

            agent_req = LaunchRequest(
                job_id="SELFCHECK-000002",
                method=AGENT,
                sites_file=expand_path(sites_path),
                sites=(sample_site,),
                scripts=(sample_script,),
                export_format="none",
            )
            agent_plan = launch.build_plan(agent_req)
            agent_args = list(agent_plan.command)[2:]
            parsed_agent = gideon_agent_orchestrator.build_parser().parse_args(agent_args)
            agent_ok = (
                parsed_agent.action == "run"
                and str(parsed_agent.job_id) == "SELFCHECK-000002"
                and Path(parsed_agent.sites_file).name == Path(sites_path).name
            )
            checks.append(_result(
                "Contrato GUI → AGENT",
                "OK" if agent_ok else "FAIL",
                agent_plan.command_text(),
            ))
    except Exception as exc:
        checks.append(_result(
            "Contrato de lanzamiento",
            "FAIL",
            f"{type(exc).__name__}: {exc}",
        ))

    critical_failures = [
        x
        for x in checks
        if x["Critical"]
        and x["Status"] == "FAIL"
    ]
    warnings = [
        x
        for x in checks
        if x["Status"] == "WARN"
    ]

    return {
        "Version": "4.0",
        "Architecture": "SFTP_PACKAGE_SSH_CONTROL_SFTP_COLLECT",
        "Ready": len(critical_failures) == 0,
        "CriticalFailures": len(critical_failures),
        "Warnings": len(warnings),
        "Checks": checks,
    }


def print_report(report: dict[str, Any]) -> None:
    print("=" * 88)
    print("GIDEON SSH ADMIN v4.1.1 - AUTODIAGNÓSTICO LOCAL")
    print("=" * 88)

    for item in report["Checks"]:
        status = item["Status"]
        print(
            f"[{status:<4}] "
            f"{item['Check']:<30} "
            f"{item['Detail']}"
        )

    print("-" * 88)
    print(
        "READY="
        + ("SI" if report["Ready"] else "NO")
        + f" | Fallas críticas={report['CriticalFailures']}"
        + f" | Advertencias={report['Warnings']}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG,
    )
    parser.add_argument(
        "--sites-file",
        type=Path,
        default=DEFAULT_SITES,
    )
    parser.add_argument(
        "--json",
        action="store_true",
    )
    args = parser.parse_args(argv)

    report = run_selfcheck(
        args.config,
        args.sites_file,
    )

    if args.json:
        print(
            json.dumps(
                report,
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        print_report(report)

    return 0 if report["Ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
