#!/usr/bin/env python3
"""Build and inspect Raspberry Pi DEBs through the production catalog path.

The enrollment value is deliberately an unusable validation fixture.  These
artifacts are acceptance-test outputs and must not be published to end users.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--app", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--gateway", required=True)
    parser.add_argument("--ca", required=True, type=Path)
    args = parser.parse_args()

    app = args.app.resolve()
    output = args.output.resolve()
    ca_file = args.ca.resolve()
    if not shutil.which("dpkg-deb"):
        raise RuntimeError("dpkg-deb no está instalado")
    if not ca_file.is_file():
        raise FileNotFoundError(ca_file)
    sys.path.insert(0, str(app))

    from gideon_agent_catalog import AgentDownloadCatalog  # noqa: PLC0415

    output.mkdir(parents=True, exist_ok=True)
    catalog = AgentDownloadCatalog(app)
    report: dict[str, object] = {"status": "PASS", "targets": {}}
    old_umask = os.umask(0o027)
    try:
        for target_id in ("linux_arm64", "linux_armhf"):
            artifact = catalog.generate(
                target_id,
                version="2.4.18",
                channel="validation",
                gateway_url=args.gateway,
                output_dir=output,
                package_type="deb",
                gateway_ca_file_override=ca_file,
                enrollment_grant="GIDEON-VALIDATION-NOT-FOR-ENROLLMENT",
                site_code="VALIDATION",
                site_name="GIDEON validation only",
                connectivity_mode="production",
            )
            with tempfile.TemporaryDirectory(prefix=f"gideon-{target_id}-inspect-") as td:
                root = Path(td) / "root"
                control = Path(td) / "control"
                subprocess.run(["dpkg-deb", "--extract", str(artifact), str(root)], check=True)
                subprocess.run(["dpkg-deb", "--control", str(artifact), str(control)], check=True)
                template = json.loads((root / "opt/gideon-agent/agent.template.json").read_text(encoding="utf-8"))
                depends = subprocess.run(
                    ["dpkg-deb", "-f", str(artifact), "Depends"],
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout.strip()
                required = ("python3-cryptography", "python3-pil", "python3-six", "python3-xlib")
                missing = [name for name in required if name not in depends]
                if missing:
                    raise RuntimeError(f"{target_id}: dependencias ausentes: {missing}")
                if template["control_plane"]["base_url"] != args.gateway.rstrip("/"):
                    raise RuntimeError(f"{target_id}: Gateway embebido incorrecto")
                modes = {
                    "payload_root": _mode(root / "opt/gideon-agent"),
                    "setup": _mode(root / "opt/gideon-agent/gideon-agent-setup"),
                    "bootstrap": _mode(root / "opt/gideon-agent/bootstrap.enrollment"),
                    "service": _mode(root / "lib/systemd/system/gideon-agent.service"),
                    "control": _mode(control / "control"),
                    "postinst": _mode(control / "postinst"),
                }
                expected_modes = {
                    "payload_root": 0o755,
                    "setup": 0o755,
                    "bootstrap": 0o600,
                    "service": 0o644,
                    "control": 0o644,
                    "postinst": 0o755,
                }
                if modes != expected_modes:
                    raise RuntimeError(f"{target_id}: modos incorrectos {modes!r}")
                report["targets"][target_id] = {
                    "artifact": str(artifact),
                    "architecture": subprocess.run(
                        ["dpkg-deb", "-f", str(artifact), "Architecture"],
                        check=True,
                        capture_output=True,
                        text=True,
                    ).stdout.strip(),
                    "depends": depends,
                    "gateway": template["control_plane"]["base_url"],
                    "modes_octal": {key: format(value, "04o") for key, value in modes.items()},
                    "artifact_validation": dict(catalog.last_artifact_validation or {}),
                }
    finally:
        os.umask(old_umask)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
