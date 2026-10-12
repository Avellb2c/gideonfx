"""Validate generated Agent update archives on Windows or a Linux/WSL host."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile


def validate(bundle: Path, version: str) -> None:
    expected_arch = bundle.name.split("-stable-v", 1)[0].rsplit("-", 1)[-1]
    with tempfile.TemporaryDirectory(prefix="gideon-agent-release-") as temp:
        root = Path(temp)
        with zipfile.ZipFile(bundle, "r") as archive:
            bad = archive.testzip()
            if bad:
                raise RuntimeError(f"ZIP_CRC_INVALID: {bad}")
            archive.extractall(root)
        payload = root / "payload"
        profile = json.loads((payload / "update-profile.json").read_text(encoding="utf-8-sig"))
        if str(profile.get("Version") or "") != version:
            raise RuntimeError(f"VERSION_MISMATCH: {bundle.name}")
        if str(profile.get("Architecture") or "") != expected_arch:
            raise RuntimeError(f"ARCHITECTURE_MISMATCH: {bundle.name}")
        if not bool(profile.get("PreserveIdentity")) or not bool(profile.get("PreserveGatewayTrust")):
            raise RuntimeError(f"PRESERVATION_CONTRACT_MISSING: {bundle.name}")
        remote = profile.get("RemoteAccess") if isinstance(profile.get("RemoteAccess"), dict) else {}
        if str(profile.get("Platform") or "") == "linux" and not bool(remote.get("LoopbackOnly")):
            raise RuntimeError(f"LINUX_REMOTE_NOT_LOOPBACK_ONLY: {bundle.name}")
        for relative in ("gideon_agent.py", "gideon_agent_update.py", "gideon_reverse_tunnel.py"):
            source = (payload / relative).read_text(encoding="utf-8-sig")
            compile(source, str(payload / relative), "exec")
        completed = subprocess.run(
            [sys.executable, str(payload / "gideon_agent.py"), "--version"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if f"GIDEON Agent {version}" not in completed.stdout:
            raise RuntimeError(f"RUNTIME_VERSION_MISMATCH: {completed.stdout.strip()}")
        print(f"VALID {profile['Platform']}/{profile['Architecture']} {completed.stdout.strip()}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--platform", default="linux")
    args = parser.parse_args()
    bundles = sorted(args.directory.glob(f"GIDEONAgent-Update-{args.platform}-*-stable-v{args.version}.zip"))
    if not bundles:
        raise FileNotFoundError(f"No hay bundles {args.platform} {args.version} en {args.directory}")
    for bundle in bundles:
        validate(bundle, args.version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
