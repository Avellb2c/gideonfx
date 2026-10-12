#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import sys
import time
import uuid
import zipfile
from pathlib import Path


def load_environment_file(path: Path = Path("/etc/gideon/web/web.env")) -> None:
    """Load deployment secrets when the helper is run outside systemd."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and value:
            os.environ.setdefault(key, value)


def main() -> int:
    load_environment_file()
    parser = argparse.ArgumentParser(description="Dispatch one signed diagnostic script through the live GIDEON Agent Gateway.")
    parser.add_argument("--app-root", type=Path, default=Path("/opt/gideon/web/app"))
    parser.add_argument("--config", type=Path, default=Path("/etc/gideon/web/web_admin.json"))
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--script", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()

    app_root = args.app_root.resolve()
    sys.path.insert(0, str(app_root))

    from gideon_agent_orchestrator import build_agent_package
    from gideon_fanout import Site, sha256_file
    from gideon_web_admin.app import load_web_config, normalize_session_policy
    from gideon_web_admin.services import build_web_admin_services

    config = normalize_session_policy(load_web_config(args.config))
    data_dir = Path(os.path.expandvars(str(config.get("data_dir") or "/var/lib/gideon-web-admin"))).expanduser().resolve()
    services = build_web_admin_services(
        app_root=app_root,
        data_dir=data_dir,
        config_path=args.config,
        config=config,
        default_session_idle_seconds=3600,
    )
    agents = {str(row.get("agent_id") or ""): row for row in services.gateway.agents()}
    row = agents.get(args.agent_id)
    if not row:
        raise RuntimeError(f"AGENT_NOT_FOUND: {args.agent_id}")

    operations = services.operations
    private_key, private_key_bytes, signing_key_id = operations._signing_material()
    profile_id = str(row.get("host_profile") or "").strip()
    if not profile_id:
        raise RuntimeError("AGENT_HOST_PROFILE_MISSING")
    profile = operations.profiles.get(profile_id)
    site = Site(
        code=str(row.get("site_code") or ""),
        name=str(row.get("site_name") or ""),
        ip="",
        platform=str(row.get("platform") or ""),
        host_profile=profile_id,
        agent_id=args.agent_id,
        agent_name=str(row.get("agent_name") or row.get("hostname") or ""),
        hostname=str(row.get("hostname") or ""),
        agent_connection="HTTPS/PULL",
        agent_remote_ip=str(row.get("last_remote_ip") or ""),
        source="live-diagnostic",
    )
    job_id = "rdp-diagnostic-" + dt.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
    package_root = data_dir / "jobs" / job_id / "packages"
    package_info = build_agent_package(
        site=site,
        job_id=job_id,
        scripts=[args.script.resolve()],
        cfg={"script_execution": {"default_timeout_seconds": max(60, args.timeout)}},
        packages_dir=package_root,
        continue_on_error=False,
        profile=profile,
        signing_private_key=private_key,
        signing_key_id=signing_key_id,
        signing_private_key_bytes=private_key_bytes,
    )
    archive = Path(package_info["Archive"])
    client = services.gateway.client()
    response = client.upload_file(
        "PUT",
        f"/api/v1/admin/jobs/{job_id}/{args.agent_id}",
        archive,
        headers={
            "X-GIDEON-Site-Code": site.code,
            "X-GIDEON-Site-Name": site.name,
            "X-GIDEON-SHA256": sha256_file(archive),
            "X-GIDEON-Signature": str(package_info["Signature"]),
            "X-GIDEON-Key-Id": signing_key_id,
            "X-GIDEON-Host-Profile": profile_id,
        },
        timeout=120,
    )
    print(json.dumps({"JobId": job_id, "Queued": response, "Agent": args.agent_id}, ensure_ascii=False), flush=True)

    deadline = time.monotonic() + max(60, args.timeout)
    terminal = {"RESULT_READY", "FAILED", "CANCELLED"}
    current: dict[str, object] = {}
    while time.monotonic() < deadline:
        data = client.json("GET", f"/api/v1/admin/jobs/{job_id}", timeout=15)
        rows = [x for x in (data.get("Sites") or []) if isinstance(x, dict)]
        if rows:
            current = rows[0]
            state = str(current.get("status") or "").upper()
            if state in terminal:
                break
        time.sleep(2)
    else:
        raise TimeoutError(f"JOB_TIMEOUT: {job_id}")

    state = str(current.get("status") or "").upper()
    if state != "RESULT_READY":
        raise RuntimeError(f"JOB_{state or 'UNKNOWN'}: {current.get('error') or ''}")

    result_dir = data_dir / "jobs" / job_id / "diagnostic-result"
    result_dir.mkdir(parents=True, exist_ok=True)
    result_zip = result_dir / f"{args.agent_id}.result.zip"
    # The Gateway can expose RESULT_READY a fraction of a second before the
    # result archive has completed its atomic move into the download store.
    # Treat that short publication window as eventual consistency instead of
    # turning a successful diagnostic into a false 404.
    download_deadline = time.monotonic() + 30
    while True:
        try:
            client.download_file(f"/api/v1/admin/jobs/{job_id}/{args.agent_id}/result", result_zip, timeout=120)
            break
        except Exception as exc:
            if time.monotonic() >= download_deadline or "404" not in str(exc):
                raise
            time.sleep(1)
    extract_dir = result_dir / "extract"
    if extract_dir.exists():
        shutil.rmtree(extract_dir)
    extract_dir.mkdir(parents=True)
    with zipfile.ZipFile(result_zip) as zf:
        zf.extractall(extract_dir)
    script_results = sorted((extract_dir / "collection" / "scripts").glob("*.json"))
    if not script_results:
        raise RuntimeError("DIAGNOSTIC_RESULT_MISSING")
    payload = json.loads(script_results[0].read_text(encoding="utf-8-sig"))
    print(json.dumps({
        "JobId": job_id,
        "Status": state,
        "Success": payload.get("Success"),
        "Error": payload.get("Error"),
        "Data": payload.get("Data") or [],
        "ResultPath": str(script_results[0]),
    }, ensure_ascii=False, indent=2))
    return 0 if payload.get("Success") else 2


if __name__ == "__main__":
    raise SystemExit(main())
