"""Regression tests for the cross-platform WebAdmin dependency inventory."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
APP_ROOTS = (
    ROOT / "payload/linux/app",
    ROOT / "payload/windows/GIDEON Remote Control/app",
)


def load_module(app_root: Path, suffix: str):
    sys.path.insert(0, str(app_root))
    try:
        spec = importlib.util.spec_from_file_location(
            f"gideon_dependency_inventory_{suffix}",
            app_root / "gideon_web_admin/dependency_inventory.py",
        )
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(app_root))


MODULES = tuple(
    (str(app_root), load_module(app_root, str(index)))
    for index, app_root in enumerate(APP_ROOTS)
)


class LinuxCommandInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="gideon-dependencies-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    @staticmethod
    def command_path(name: str):
        return f"/usr/bin/{name}" if name else None

    def test_linux_tools_use_supported_version_arguments(self):
        for name, module in MODULES:
            with self.subTest(payload=name):
                calls: list[tuple[str, ...]] = []

                def fake_run(args, timeout=7):
                    calls.append(tuple(args))
                    return 0, f"version for {Path(args[0]).name}"

                with (
                    patch.object(module.shutil, "which", side_effect=self.command_path),
                    patch.object(module, "_run", side_effect=fake_run),
                    patch.object(module, "_read_os_release", return_value={"PRETTY_NAME": "Test Linux"}),
                ):
                    rows = module.DependencyInventory(self.root, self.root)._system_rows("Linux")

                by_id = {row.id: row for row in rows}
                for dependency_id in ("linux-ssh", "linux-sftp", "linux-openssl", "linux-ip"):
                    self.assertEqual("OK", by_id[dependency_id].status)
                self.assertIn(("/usr/bin/ssh", "-V"), calls)
                self.assertIn(("/usr/bin/openssl", "version"), calls)
                self.assertIn(("/usr/bin/ip", "-Version"), calls)
                self.assertFalse(any(call[0] == "/usr/bin/sftp" for call in calls))

    def test_active_docker_service_is_ok_without_socket_access(self):
        for name, module in MODULES:
            with self.subTest(payload=name):
                paths = {
                    "docker": "/usr/bin/docker",
                    "systemctl": "/usr/bin/systemctl",
                }

                def fake_run(args, timeout=7):
                    command = tuple(args)
                    if command == ("/usr/bin/docker", "--version"):
                        return 0, "Docker version 29.1.3"
                    if command == ("/usr/bin/docker", "compose", "version"):
                        return 0, "Docker Compose version 2.40.3"
                    if command[:2] == ("/usr/bin/docker", "info"):
                        return 1, "permission denied while connecting to docker.sock"
                    if command == ("/usr/bin/systemctl", "is-active", "docker.service"):
                        return 0, "active"
                    return 127, "unexpected command"

                with (
                    patch.object(module.shutil, "which", side_effect=lambda command: paths.get(command)),
                    patch.object(module, "_run", side_effect=fake_run),
                ):
                    rows = module._docker_rows("Linux")

                daemon = next(row for row in rows if row.id == "docker-daemon")
                self.assertEqual("OK", daemon.status)
                self.assertIn("socket Docker no delegado", daemon.version)

    def test_inactive_docker_service_remains_degraded(self):
        for name, module in MODULES:
            with self.subTest(payload=name):
                paths = {
                    "docker": "/usr/bin/docker",
                    "systemctl": "/usr/bin/systemctl",
                }

                def fake_run(args, timeout=7):
                    command = tuple(args)
                    if command == ("/usr/bin/docker", "--version"):
                        return 0, "Docker version 29.1.3"
                    if command == ("/usr/bin/docker", "compose", "version"):
                        return 0, "Docker Compose version 2.40.3"
                    if command[:2] == ("/usr/bin/docker", "info"):
                        return 1, "permission denied while connecting to docker.sock"
                    if command == ("/usr/bin/systemctl", "is-active", "docker.service"):
                        return 3, "inactive"
                    return 127, "unexpected command"

                with (
                    patch.object(module.shutil, "which", side_effect=lambda command: paths.get(command)),
                    patch.object(module, "_run", side_effect=fake_run),
                ):
                    rows = module._docker_rows("Linux")

                daemon = next(row for row in rows if row.id == "docker-daemon")
                self.assertEqual("DEGRADED", daemon.status)


if __name__ == "__main__":
    unittest.main()
