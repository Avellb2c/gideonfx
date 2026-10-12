from __future__ import annotations

from gideon_common.observability import best_effort_warning

import argparse
import asyncio
import os
from pathlib import Path
from typing import Sequence

from gideon_admin import Inventory, SSHAgent, Site, expand_path, load_config
from gideon_bootstrap import ApplicationContainer, build_application
from gideon_domain import HostTarget, TransportProfile
from gideon_host_profiles import HostProfileStore


SCRIPT_DIR: Path = Path(__file__).resolve().parent


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="GIDEON Enterprise File/Video Transfer")
    parser.add_argument("--config", default=str(SCRIPT_DIR / "config" / "config.json"))
    parser.add_argument("--sites-file", default=str(SCRIPT_DIR / "config" / "sites.csv"))
    sub = parser.add_subparsers(dest="action", required=True)

    upload = sub.add_parser("upload", help="Distribuir un archivo/video a hosts.")
    group = upload.add_mutually_exclusive_group(required=True)
    group.add_argument("--targets", help="Códigos separados por coma.")
    group.add_argument("--all", action="store_true")
    upload.add_argument("--file", type=Path, required=True)
    upload.add_argument("--remote-dir", required=True)
    upload.add_argument(
        "--transport",
        choices=[
            TransportProfile.SFTP_SSH_SFTP.value,
            TransportProfile.SCP_SSH_SCP.value,
            TransportProfile.STDIN_SSH_SCP.value,
        ],
        default=TransportProfile.SFTP_SSH_SFTP.value,
    )
    upload.add_argument("--workers", type=int)

    sub.add_parser("jobs", help="Listar Jobs de transferencia.")

    resume = sub.add_parser("resume", help="Reanudar Job de transferencia.")
    resume.add_argument("job_id")
    resume.add_argument("--workers", type=int)

    cancel = sub.add_parser("cancel", help="Cancelar Job de transferencia.")
    cancel.add_argument("job_id")
    return parser


def _selected(inventory: Inventory, targets: str | None, all_sites: bool) -> list[Site]:
    if all_sites:
        return list(inventory.sites)
    wanted: set[str] = {x.strip() for x in str(targets or "").split(",") if x.strip()}
    return [site for site in inventory.sites if site.code in wanted]


def _host_map(inventory: Inventory, profiles: HostProfileStore) -> dict[str, HostTarget]:
    result: dict[str, HostTarget] = {}
    for site in inventory.sites:
        platform: str = "windows"
        profile_id: str = "windows_generic"
        try:
            profile: dict[str, object] = profiles.resolve(site.code)
            platform = str(profile.get("platform") or platform)
            profile_id = str(profile.get("id") or profile_id)
        except Exception as exc:
            best_effort_warning(f"No se pudo resolver Host Profile para {site.code}", exc)
        result[site.code] = HostTarget(site.code, site.name, site.ip, platform, profile_id)
    return result


def _container(config_path: Path, sites_file: Path) -> tuple[dict[str, object], Inventory, Path, ApplicationContainer]:
    cfg = load_config(config_path)
    inventory = Inventory(sites_file)
    paths = cfg["paths"]
    ssh = cfg["ssh"]
    key = expand_path(ssh["key_path"])
    known_hosts = expand_path(paths["known_hosts"])
    jobs_dir = expand_path(paths["fanout_jobs_dir"])
    logs_dir = Path(os.path.expandvars(cfg.get("gui", {}).get("logs_dir", r"%LOCALAPPDATA%\GIDEONSSH\gui_logs")))
    transfer_jobs_dir = expand_path(paths.get("transfer_jobs_dir", r"%LOCALAPPDATA%\GIDEONSSH\transfer_jobs"))
    app = build_application(
        app_root=SCRIPT_DIR,
        cfg=cfg,
        jobs_dir=jobs_dir,
        logs_dir=logs_dir,
        transfer_jobs_dir=transfer_jobs_dir,
        python_exe=os.environ.get("PYTHON", "python"),
        version="5.0.4",
        key_path=key,
        known_hosts=known_hosts,
    )
    return cfg, inventory, key, app


def _progress(code: str, percent: float, operation: str, sent: int, total: int) -> None:
    print(f"[{code}] {percent:5.1f}% · {operation} · {sent}/{total}")


async def _upload(args: argparse.Namespace) -> int:
    config = expand_path(args.config)
    sites_file = expand_path(args.sites_file)
    _cfg, inventory, key, app = _container(config, sites_file)
    SSHAgent(key).load()
    profiles = HostProfileStore(SCRIPT_DIR / "config" / "host_profiles.json")
    all_hosts = _host_map(inventory, profiles)
    selected_legacy = _selected(inventory, args.targets, bool(args.all))
    selected = [all_hosts[site.code] for site in selected_legacy]
    if not selected:
        print("No hay hosts seleccionados.")
        return 2
    job, artifact = app.controller.create_file_upload_job(
        source=Path(args.file),
        destination_dir=str(args.remote_dir),
        sites=selected,
        transport_profile=TransportProfile(str(args.transport)),
    )
    print(f"JOB {job.job_id} · {job.transport_profile.value} · {len(selected)} host(s)")
    finished = await app.controller.execute_file_upload(
        job=job,
        artifact=artifact,
        sites={x.code: x for x in selected},
        vpn_workers=args.workers,
        progress=_progress,
    )
    print(f"ESTADO FINAL: {finished.state.value}")
    return 0 if finished.state.value in {"COMPLETED", "PARTIAL"} else 1


async def _resume(args: argparse.Namespace) -> int:
    config = expand_path(args.config)
    sites_file = expand_path(args.sites_file)
    _cfg, inventory, key, app = _container(config, sites_file)
    SSHAgent(key).load()
    profiles = HostProfileStore(SCRIPT_DIR / "config" / "host_profiles.json")
    hosts = _host_map(inventory, profiles)
    finished = await app.controller.resume_file_upload(
        job_id=str(args.job_id),
        sites=hosts,
        vpn_workers=args.workers,
        progress=_progress,
    )
    print(f"ESTADO FINAL: {finished.state.value}")
    return 0 if finished.state.value in {"COMPLETED", "PARTIAL"} else 1


async def _cancel(args: argparse.Namespace) -> int:
    config = expand_path(args.config)
    sites_file = expand_path(args.sites_file)
    _cfg, inventory, key, app = _container(config, sites_file)
    SSHAgent(key).load()
    profiles = HostProfileStore(SCRIPT_DIR / "config" / "host_profiles.json")
    hosts = _host_map(inventory, profiles)
    job = await app.controller.cancel_file_job(str(args.job_id), hosts)
    print(f"{job.job_id}: {job.state.value}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(list(argv) if argv is not None else None)
    if args.action == "upload":
        return asyncio.run(_upload(args))
    if args.action == "resume":
        return asyncio.run(_resume(args))
    if args.action == "cancel":
        return asyncio.run(_cancel(args))
    if args.action == "jobs":
        config = expand_path(args.config)
        sites_file = expand_path(args.sites_file)
        _cfg, _inventory, _key, app = _container(config, sites_file)
        for job in app.controller.list_file_jobs():
            print(f"{job.job_id:<24} {job.state.value:<24} {job.transport_profile.value:<20} {job.source_file or '-'}")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
