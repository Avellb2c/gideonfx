"""Regression tests for request-path and transfer performance guarantees."""
from __future__ import annotations

import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from jinja2 import Environment, FileSystemLoader, StrictUndefined


ROOT = Path(__file__).resolve().parents[2]
LINUX_APP = ROOT / "payload/linux/app"
WINDOWS_APP = ROOT / "payload/windows/GIDEON Remote Control/app"
if str(LINUX_APP) not in sys.path:
    sys.path.insert(0, str(LINUX_APP))

from gideon_agent_http import AgentHttpClient  # noqa: E402
from gideon_agent_gateway import GatewayDB, Handler  # noqa: E402
from gideon_service_health import GIDEON_SERVICE_TARGETS, HealthState, service_manager_observations  # noqa: E402
from gideon_diagnostics_service import _health_url  # noqa: E402
from gideon_web_admin.auth import SecurityStore  # noqa: E402
from gideon_web_admin.gateway import GatewayFacade  # noqa: E402
from gideon_web_admin.operations import WebOperations  # noqa: E402
from gideon_web_admin.resource_metrics import ServerResourceMetrics, parse_systemd_show  # noqa: E402
from gideon_web_admin.static_assets import StaticAssetUrls  # noqa: E402


class RuntimePerformanceTests(unittest.TestCase):
    def test_control_plane_health_falls_back_when_coordinator_is_private(self) -> None:
        operations = object.__new__(WebOperations)
        operations.data_dir = Path("/var/lib/gideon/web")
        coordinator = operations.data_dir.parent / "coordinator" / "status.json"
        diagnostics = operations.data_dir.parent / "diagnostics" / "health.json"
        snapshot = json.dumps({
            "state": "RUNNING",
            "generated_at_utc": "2099-01-01T00:00:00+00:00",
            "source": "GIDEONDiagnosticsService",
            "services": [],
        })

        def read_text(path: Path, *_args, **_kwargs) -> str:
            if path == coordinator:
                raise PermissionError("private coordinator state")
            if path == diagnostics:
                return snapshot
            raise FileNotFoundError(path)

        with patch.object(Path, "read_text", new=read_text):
            result = operations.control_plane_health()
        self.assertEqual("RUNNING", result["state"])
        self.assertEqual("GIDEONDiagnosticsService", result["source"])

    def test_dashboard_resource_collector_reports_real_host_capacity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-resource-metrics-") as td:
            collector = ServerResourceMetrics(Path(td), cache_ttl_seconds=1)
            snapshot = collector.snapshot(force=True)
        self.assertTrue(snapshot["available"])
        self.assertGreater(snapshot["host"]["cpu_logical"], 0)
        self.assertGreater(snapshot["host"]["memory_total_bytes"], 0)
        self.assertGreater(snapshot["host"]["disk_total_bytes"], 0)
        self.assertGreaterEqual(snapshot["gideon"]["memory_bytes"], 0)

    def test_dashboard_resource_assets_and_backend_are_mirrored(self) -> None:
        relative_files = (
            "gideon_web_admin/app.py",
            "gideon_web_admin/operations.py",
            "gideon_web_admin/resource_metrics.py",
            "gideon_web_admin/static_assets.py",
            "gideon_web_admin/templates/dashboard.html",
            "gideon_web_admin/static/dashboard.css",
            "gideon_web_admin/static/dashboard.js",
        )
        for relative in relative_files:
            self.assertEqual(
                (LINUX_APP / relative).read_bytes(),
                (WINDOWS_APP / relative).read_bytes(),
                relative,
            )
        template = (LINUX_APP / "gideon_web_admin/templates/dashboard.html").read_text(encoding="utf-8")
        app_source = (LINUX_APP / "gideon_web_admin/app.py").read_text(encoding="utf-8")
        self.assertIn("Consumo de recursos", template)
        self.assertIn("Características del servidor", template)
        self.assertIn('@app.get("/api/dashboard/resources"', app_source)

    def test_content_addressed_static_urls_only_cache_current_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-static-assets-") as td:
            root = Path(td)
            asset = root / "app.js"
            asset.write_text("console.log('one');", encoding="utf-8")
            resolver = StaticAssetUrls(root)
            first = resolver.url("app.js")
            first_fingerprint = first.rsplit("=", 1)[1]
            self.assertTrue(resolver.matches("app.js", first_fingerprint))
            self.assertFalse(resolver.matches("app.js", "0" * 16))
            asset.write_text("console.log('two-extended');", encoding="utf-8")
            second = resolver.url("app.js")
            second_fingerprint = second.rsplit("=", 1)[1]
            self.assertNotEqual(first_fingerprint, second_fingerprint)
            self.assertFalse(resolver.matches("app.js", first_fingerprint))
            self.assertTrue(resolver.matches("app.js", second_fingerprint))

    def test_dashboard_reads_only_the_sanitized_diagnostics_projection(self) -> None:
        linux_installer = LINUX_APP / "deploy/aws/install_gideon_aws.sh"
        windows_installer = WINDOWS_APP / "deploy/aws/install_gideon_aws.sh"
        self.assertEqual(linux_installer.read_bytes(), windows_installer.read_bytes())
        source = linux_installer.read_text(encoding="utf-8")
        self.assertIn(
            "install -d -m 2750 -o gideonmonitor -g gideonweb /var/lib/gideon/diagnostics",
            source,
        )
        self.assertIn(
            "install -d -m 0750 -o gideonmonitor -g gideonmonitor /var/lib/gideon/coordinator",
            source,
        )

    def test_dashboard_template_renders_with_resource_snapshot(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-dashboard-render-") as td:
            resources = ServerResourceMetrics(Path(td), cache_ttl_seconds=1).snapshot(force=True)
        environment = Environment(
            loader=FileSystemLoader(str(LINUX_APP / "gideon_web_admin/templates")),
            undefined=StrictUndefined, autoescape=True,
        )
        # Production renders every static reference through the
        # content-addressed helper.  Keep the isolated Jinja harness faithful
        # to that global instead of weakening templates back to fixed RC
        # query strings merely for this test.
        environment.globals["static_url"] = StaticAssetUrls(
            LINUX_APP / "gideon_web_admin/static"
        ).url
        identity = SimpleNamespace(
            can=lambda _permission: True, display_name="Administrador GIDEON",
            username="admin", role="SUPERADMIN", csrf_token="test-csrf",
        )
        rendered = environment.get_template("dashboard.html").render(
            request=None, title="Inicio", identity=identity, product_version="test", agent_version="test",
            gateway_version="test", active_path="/", now=None, roles=["SUPERADMIN"],
            step_up={"active": False}, gateway_error="", platform_healthy=True,
            health={"Ok": True, "Version": "test", "ProtocolVersion": "test", "Schema": {"Ready": True},
                    "Capabilities": {"ReleaseApproval": True}, "Time": "now"},
            control_plane={"state": "RUNNING", "fresh": True}, resources=resources, jobs=[],
            metrics={"agents": 3, "active_agents": 2, "offline_agents": 1, "active_jobs": 1,
                     "successful_jobs": 4, "incidents": 0, "approved": 2},
        )
        self.assertIn("Plataforma operativa", rendered)
        self.assertIn("RAM usada por GIDEON", rendered)
        self.assertIn("/api/dashboard/resources", rendered)

    def test_systemd_resource_properties_are_parsed_by_unit(self) -> None:
        rows = parse_systemd_show(
            "Id=gideon-web-admin.service\nLoadState=loaded\nActiveState=active\n"
            "MemoryCurrent=52428800\nCPUUsageNSec=1000000000\nTasksCurrent=4\n\n"
            "Id=gideon-clamd.service\nLoadState=loaded\nActiveState=active\n"
            "MemoryCurrent=1073741824\nCPUUsageNSec=2000000000\nTasksCurrent=2\n"
        )
        self.assertEqual(2, len(rows))
        self.assertEqual("52428800", rows[0]["MemoryCurrent"])
        self.assertEqual("gideon-clamd.service", rows[1]["Id"])

    def test_diagnostics_uses_certificate_hostname_for_health(self) -> None:
        url, ca_file = _health_url(
            {
                "public_url": "https://admin.example.test:9443/",
                "listen_port": 9443,
                "ca_file": "/etc/gideon/trust.pem",
            },
            "/healthz",
        )
        self.assertEqual("https://admin.example.test:9443/healthz", url)
        self.assertEqual("/etc/gideon/trust.pem", ca_file)

    def test_session_reads_are_not_written_on_every_request(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-session-touch-") as td:
            store = SecurityStore(Path(td) / "security.sqlite3", session_touch_interval_seconds=30)
            stamp = store.now_iso()
            with store.connect() as con:
                user_id = con.execute(
                    """INSERT INTO users(username,display_name,password_hash,role,active,mfa_enabled,
                       must_change_password,created_at,updated_at) VALUES(?,?,?,?,1,0,0,?,?)""",
                    ("perf", "Performance", "unused", "SUPERADMIN", stamp, stamp),
                ).lastrowid
            token, _ = store.create_session(int(user_id), remote_ip="127.0.0.1", user_agent="test")
            digest = hashlib.sha256(token.encode()).hexdigest()

            with store.connect() as con:
                initial = int(con.execute(
                    "SELECT last_seen_unix FROM sessions WHERE token_hash=?", (digest,)
                ).fetchone()[0])
            self.assertIsNotNone(store.identity_for_session(token))
            self.assertIsNotNone(store.identity_for_session(token))
            with store.connect() as con:
                unchanged = int(con.execute(
                    "SELECT last_seen_unix FROM sessions WHERE token_hash=?", (digest,)
                ).fetchone()[0])
                con.execute(
                    "UPDATE sessions SET last_seen_unix=? WHERE token_hash=?", (initial - 60, digest)
                )
            self.assertEqual(initial, unchanged)

            self.assertIsNotNone(store.identity_for_session(token))
            with store.connect() as con:
                refreshed = int(con.execute(
                    "SELECT last_seen_unix FROM sessions WHERE token_hash=?", (digest,)
                ).fetchone()[0])
            self.assertGreater(refreshed, initial - 60)

    def test_linux_service_probe_uses_one_systemctl_process(self) -> None:
        calls: list[list[str]] = []

        def runner(args, _timeout):
            calls.append(list(args))
            states = "\n".join("active" for _ in GIDEON_SERVICE_TARGETS) + "\n"
            return subprocess.CompletedProcess(args, 0, states, "")

        rows = service_manager_observations(platform="linux", runner=runner)
        self.assertEqual(1, len(calls))
        self.assertEqual("systemctl", calls[0][0])
        self.assertTrue(all(row.state is HealthState.RUNNING for row in rows))

    def test_jobs_page_returns_stale_cache_while_refreshing(self) -> None:
        class Client:
            calls = 0

            def json(self, *_args, **_kwargs):
                self.calls += 1
                time.sleep(0.15)
                return {"Jobs": [{"JobId": "new"}]}

        facade = GatewayFacade({})
        client = Client()
        facade._client_instance = client
        facade._cache["jobs:limit=250"] = (time.monotonic() - 10, [{"JobId": "old"}])
        started = time.monotonic()
        value = facade.jobs_fast()
        self.assertLess(time.monotonic() - started, 0.05)
        self.assertEqual("old", value[0]["JobId"])

        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            with facade._cache_lock:
                current = facade._cache["jobs:limit=250"][1]
            if current[0]["JobId"] == "new":
                break
            time.sleep(0.02)
        self.assertEqual("new", current[0]["JobId"])
        self.assertEqual(1, client.calls)

    def test_agent_http_streams_upload_and_download(self) -> None:
        upload_received = bytearray()
        download_payload = b"gideon-stream-" * (1024 * 128)

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                return

            def do_PUT(self):  # noqa: N802
                remaining = int(self.headers["Content-Length"])
                while remaining:
                    chunk = self.rfile.read(min(65536, remaining))
                    if not chunk:
                        break
                    upload_received.extend(chunk)
                    remaining -= len(chunk)
                body = b'{"ok":true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):  # noqa: N802
                self.send_response(200)
                self.send_header("Content-Length", str(len(download_payload)))
                self.end_headers()
                for offset in range(0, len(download_payload), 65536):
                    self.wfile.write(download_payload[offset:offset + 65536])

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        with tempfile.TemporaryDirectory(prefix="gideon-http-stream-") as td:
            root = Path(td)
            source = root / "source.bin"
            target = root / "target.bin"
            source_payload = b"upload-" * (1024 * 128)
            source.write_bytes(source_payload)
            client = AgentHttpClient(
                f"http://127.0.0.1:{server.server_port}", require_https=False
            )
            with patch.object(Path, "read_bytes", side_effect=AssertionError("whole-file read")):
                self.assertTrue(client.upload_file("PUT", "/upload", source)["ok"])
                client.download_file("/download", target)
            with target.open("rb") as stream:
                downloaded = stream.read()
        self.assertEqual(source_payload, bytes(upload_received))
        self.assertEqual(download_payload, downloaded)

    def test_gateway_streams_request_body_and_enforces_limit(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-gateway-stream-") as td:
            payload = b"gateway-stream-" * (1024 * 64)
            handler = Handler.__new__(Handler)
            handler.headers = {"Content-Length": str(len(payload))}
            handler.rfile = io.BytesIO(payload)
            app = type(
                "App",
                (),
                {
                    "db": type("DB", (), {"incoming_dir": Path(td)})(),
                    "reload_runtime_config": lambda self: None,
                },
            )()
            handler.server = type("Server", (), {"app": app})()
            path, digest, size = Handler.read_body_to_file(
                handler, max_bytes=len(payload)
            )
            try:
                self.assertEqual(len(payload), size)
                self.assertEqual(hashlib.sha256(payload).hexdigest(), digest)
                with path.open("rb") as stream:
                    self.assertEqual(payload, stream.read())
            finally:
                path.unlink(missing_ok=True)

            handler.headers = {"Content-Length": str(len(payload) + 1)}
            handler.rfile = io.BytesIO(payload + b"x")
            with self.assertRaisesRegex(ValueError, "Request too large"):
                Handler.read_body_to_file(handler, max_bytes=len(payload))

    def test_release_upload_hash_is_verified_at_gateway(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gideon-release-hash-") as td:
            db = GatewayDB(Path(td))
            incoming = db.incoming_dir / "release.part"
            incoming.write_bytes(b"signed release payload")
            with self.assertRaisesRegex(ValueError, "SHA256 mismatch"):
                db.put_release_file(
                    "windows", "x86_64", "stable", "9.9.9", incoming,
                    expected_hash="0" * 64,
                )
            self.assertTrue(incoming.exists())

    def test_webadmin_sends_release_hash_with_streamed_upload(self) -> None:
        class Client:
            def upload_file(self, method, path, bundle, *, headers, timeout):
                return {"method": method, "path": path, "headers": headers}

        facade = GatewayFacade({})
        facade._client_instance = Client()
        with tempfile.TemporaryDirectory(prefix="gideon-release-publish-") as td:
            bundle = Path(td) / "release.zip"
            bundle.write_bytes(b"release")
            digest = hashlib.sha256(b"release").hexdigest()
            result = facade.publish_release(
                {
                    "platform": "windows", "architecture": "x86_64",
                    "channel": "stable", "version": "1.2.3",
                    "signature": "signature", "key_id": "key", "sha256": digest,
                },
                bundle,
            )
        self.assertEqual(digest, result["headers"]["X-GIDEON-SHA256"])

    def test_optimized_modules_are_mirrored_in_both_payloads(self) -> None:
        relatives = (
            "gideon_infrastructure/sqlite_connections.py",
            "gideon_web_admin/auth.py",
            "gideon_web_admin/request_security.py",
            "gideon_web_admin/operations.py",
            "gideon_web_admin/app.py",
            "gideon_web_admin/gateway.py",
            "gideon_service_health.py",
            "gideon_diagnostics_service.py",
            "gideon_agent_http.py",
            "gideon_agent_gateway.py",
            "gideon_infrastructure/file_transports.py",
            "deploy/windows/GIDEONServiceHost.cs",
        )
        for relative in relatives:
            self.assertEqual(
                (LINUX_APP / relative).read_bytes(),
                (WINDOWS_APP / relative).read_bytes(),
                relative,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
