"""Regression tests for protected Gateway runtime files in WebAdmin."""
from __future__ import annotations

import importlib.util
import json
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
            f"gideon_gateway_endpoints_{suffix}",
            app_root / "gideon_web_admin/gateway_endpoints.py",
        )
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(app_root))


MODULES = tuple(
    (str(app_root), load_module(app_root, str(index)))
    for index, app_root in enumerate(APP_ROOTS)
)


class ProtectedGatewayConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="gideon-gateway-endpoints-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def registry(self, module, config=None):
        data_dir = self.root / "data"
        data_dir.mkdir(exist_ok=True)
        return module.GatewayEndpointRegistry(
            self.root,
            data_dir,
            dict(config or {}),
            web_config_path=self.root / "web_admin.json",
        )

    @staticmethod
    def deny_path(target: Path):
        original = Path.is_file

        def guarded(path):
            if path == target:
                raise PermissionError(13, "Permission denied", str(path))
            return original(path)

        return patch.object(Path, "is_file", guarded)

    def test_protected_runtime_candidate_is_skipped(self):
        for name, module in MODULES:
            with self.subTest(payload=name):
                protected = self.root / "gateway-protected.json"
                readable = self.root / "gateway-readable.json"
                readable.write_text(
                    json.dumps(
                        {
                            "public_url": "https://agents.example.test",
                            "listen_port": 443,
                        }
                    ),
                    encoding="utf-8",
                )
                registry = self.registry(module)
                registry._runtime_config_candidates = lambda: [
                    (120, "protected", protected),
                    (100, "readable", readable),
                ]

                with self.deny_path(protected):
                    rows = registry.discovered_configs()

                self.assertEqual(["readable"], [row["source"] for row in rows])
                self.assertEqual("https://agents.example.test", rows[0]["advertised_endpoint"])

    def test_public_webadmin_url_survives_protected_runtime_config(self):
        for name, module in MODULES:
            with self.subTest(payload=name):
                protected = self.root / "gateway-protected.json"
                registry = self.registry(
                    module,
                    {"gateway_public_url": "https://agents.example.test"},
                )
                registry._runtime_config_candidates = lambda: [
                    (120, "protected", protected),
                ]

                with self.deny_path(protected):
                    rows = registry.endpoints()

                public = [row for row in rows if row["role"] == "ADVERTISED"]
                self.assertEqual(1, len(public))
                self.assertEqual("https://agents.example.test", public[0]["url"])
                self.assertEqual("web_admin.json", public[0]["source"])

    def test_protected_ca_candidate_is_ignored(self):
        for name, module in MODULES:
            with self.subTest(payload=name):
                config_file = self.root / "gateway-with-ca.json"
                protected_ca = self.root / "gateway-ca.pem"
                config_file.write_text(
                    json.dumps(
                        {
                            "public_url": "https://agents.example.test",
                            "ca_file": str(protected_ca),
                        }
                    ),
                    encoding="utf-8",
                )
                registry = self.registry(module)
                registry._runtime_config_candidates = lambda: [
                    (120, "runtime", config_file),
                ]

                with self.deny_path(protected_ca):
                    ca_file = registry._ca_for_url("https://agents.example.test")

                self.assertEqual("", ca_file)


if __name__ == "__main__":
    unittest.main()
