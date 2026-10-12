"""Regression checks for local GIDEON Agent credential persistence permissions."""
from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = (
    Path(os.environ["GIDEON_TEST_ROOT"]).resolve()
    if os.environ.get("GIDEON_TEST_ROOT")
    else Path(__file__).resolve().parents[2]
)
LINUX_APP = Path(os.environ.get("GIDEON_TEST_APP") or (ROOT / "payload/linux/app")).resolve()
WINDOWS_APP = Path(
    os.environ.get("GIDEON_TEST_WINDOWS_APP") or (ROOT / "payload/windows/GIDEON Remote Control/app")
).resolve()
sys.path.insert(0, str(LINUX_APP))

import gideon_agent_bootstrap as bootstrap  # noqa: E402
from gideon_agent_config import CentralConfigStore  # noqa: E402


class AgentRuntimePermissionTests(unittest.TestCase):
    def test_runtime_permission_sources_are_mirrored(self) -> None:
        for relative in ("gideon_agent.py", "gideon_agent_bootstrap.py", "gideon_agent_config.py"):
            self.assertEqual(
                (LINUX_APP / relative).read_bytes(),
                (WINDOWS_APP / relative).read_bytes(),
                f"Las copias Linux/Windows difieren: {relative}",
            )
        agent_source = (LINUX_APP / "gideon_agent.py").read_text(encoding="utf-8-sig")
        self.assertIn("enforce_path_mode(self.cfg_path, PRIVATE_FILE_MODE)", agent_source)
        self.assertIn("mode=PUBLIC_STATUS_MODE", agent_source)

    def test_windows_acl_failure_is_best_effort(self) -> None:
        with mock.patch.object(bootstrap.os, "name", "nt"), mock.patch.object(
            bootstrap.Path, "chmod", side_effect=PermissionError("ACL-owned")
        ):
            self.assertFalse(bootstrap.enforce_path_mode(Path("not-created"), 0o600))

    def test_atomic_json_retries_transient_windows_replace_lock(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-agent-atomic-") as td:
            target = Path(td) / "agent.status.json"
            target.write_text("{}\n", encoding="utf-8")
            real_replace = bootstrap.os.replace
            attempts = 0

            def transient_lock(source, destination):
                nonlocal attempts
                attempts += 1
                if attempts < 3:
                    raise PermissionError("simulated Windows reader lock")
                return real_replace(source, destination)

            with mock.patch.object(bootstrap.os, "name", "nt"), mock.patch.object(
                bootstrap.os, "replace", side_effect=transient_lock
            ):
                bootstrap.atomic_json(target, {"status": "ONLINE"}, mode=bootstrap.PUBLIC_STATUS_MODE)
            self.assertEqual(3, attempts)
            self.assertEqual("ONLINE", __import__("json").loads(target.read_text(encoding="utf-8"))["status"])
            self.assertFalse(list(Path(td).glob("*.tmp.*")))

    @unittest.skipUnless(os.name == "posix", "exact permission bits require POSIX")
    def test_secret_files_and_directory_are_private_on_posix(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-agent-permissions-") as td:
            root = Path(td) / "state"
            paths = bootstrap.AgentPaths.from_root(root)
            root.mkdir()
            paths.security.mkdir(mode=0o755)
            paths.runtime_config.write_text("{}\n", encoding="utf-8")
            paths.replay.write_text("{}\n", encoding="utf-8")
            paths.status.write_text("{}\n", encoding="utf-8")
            for path in (paths.runtime_config, paths.replay, paths.status):
                path.chmod(0o666)

            paths.ensure()
            self.assertEqual(0o700, paths.security.stat().st_mode & 0o777)
            self.assertEqual(0o600, paths.runtime_config.stat().st_mode & 0o777)
            self.assertEqual(0o600, paths.replay.stat().st_mode & 0o777)
            self.assertEqual(0o644, paths.status.stat().st_mode & 0o777)

            # A permissive process umask and a pre-existing public inode must not
            # weaken the final token/config/replay files.
            old_umask = os.umask(0)
            try:
                paths.runtime_config.chmod(0o666)
                bootstrap.atomic_json(paths.runtime_config, {"agent_token": "fixture-only"})
                bootstrap.atomic_json(paths.replay, {"schema": 1, "jobs": {}})
                bootstrap.atomic_json(paths.status, {"status": "ONLINE"}, mode=bootstrap.PUBLIC_STATUS_MODE)
            finally:
                os.umask(old_umask)
            self.assertEqual(0o600, paths.runtime_config.stat().st_mode & 0o777)
            self.assertEqual(0o600, paths.replay.stat().st_mode & 0o777)
            self.assertEqual(0o644, paths.status.stat().st_mode & 0o777)
            self.assertFalse(list(root.rglob("*.tmp.*")))

            central = root / "config.current.json"
            central.write_text("{}\n", encoding="utf-8")
            central.chmod(0o644)
            CentralConfigStore(root)
            self.assertEqual(0o600, central.stat().st_mode & 0o777)


if __name__ == "__main__":
    unittest.main()
