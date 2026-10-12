"""Regression checks for release targets, installer builds and Agent RDP routing."""
from __future__ import annotations

import ast
import importlib.util
import inspect
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
from typing import Any


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


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"No se pudo cargar {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _installer_helpers(app_root: Path):
    source = (app_root / "gideon_web_admin/agent_installers.py").read_text(encoding="utf-8-sig")
    tree = ast.parse(source)
    wanted = {"_next_build_number", "_normalize_build_history", "_artifact_with_build_suffix"}
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in wanted]
    namespace: dict[str, Any] = {"Any": Any, "Path": Path}
    exec(compile(ast.Module(body=functions, type_ignores=[]), "agent-installers-helpers", "exec"), namespace)
    return (
        namespace["_next_build_number"],
        namespace["_normalize_build_history"],
        namespace["_artifact_with_build_suffix"],
    )


remote_sessions_module = _load_module(
    "gideon_test_remote_sessions_routing", LINUX_APP / "gideon_web_admin/remote_sessions.py"
)
tunnel_module = _load_module(
    "gideon_test_reverse_tunnel_transport", LINUX_APP / "gideon_reverse_tunnel.py"
)
RemoteSessionPolicy = remote_sessions_module.RemoteSessionPolicy
RemoteSessionStore = remote_sessions_module.RemoteSessionStore
RemoteSessionError = remote_sessions_module.RemoteSessionError
WebSocketPeer = tunnel_module.WebSocketPeer


class _InterruptedSocket:
    """Socket double that can interrupt a frame after arbitrary partial reads."""

    def __init__(self, events):
        self.events = list(events)
        self.sent = bytearray()

    def recv(self, length: int) -> bytes:
        if not self.events:
            return b""
        value = self.events.pop(0)
        if isinstance(value, BaseException):
            raise value
        chunk = bytes(value)
        if len(chunk) > length:
            self.events.insert(0, chunk[length:])
            chunk = chunk[:length]
        return chunk

    def sendall(self, value: bytes) -> None:
        self.sent.extend(value)


class _ShortWritingSocket:
    """Socket double that times out after a partial frame write."""

    def __init__(self, events):
        self.events = list(events)
        self.sent = bytearray()
        self.closed = False

    def send(self, value) -> int:
        event = self.events.pop(0) if self.events else len(value)
        if isinstance(event, BaseException):
            raise event
        count = min(int(event), len(value))
        self.sent.extend(bytes(value[:count]))
        return count

    def shutdown(self, _how) -> None:
        self.closed = True

    def close(self) -> None:
        self.closed = True


class _ReadinessWaitingSocket:
    """Socket double used to assert the reader releases I/O ownership while idle."""

    def __init__(self) -> None:
        self.write_entered = threading.Event()

    def gettimeout(self) -> float:
        return 0.25

    def pending(self) -> int:
        return 0

    def recv(self, _length: int) -> bytes:
        raise AssertionError("recv must not run before readiness is reported")

    def send(self, value) -> int:
        self.write_entered.set()
        return len(value)


def _server_frame(opcode: int, payload: bytes, *, fin: bool = True) -> bytes:
    first = (0x80 if fin else 0) | (opcode & 0x0F)
    length = len(payload)
    if length < 126:
        return bytes((first, length)) + payload
    if length <= 0xFFFF:
        return bytes((first, 126)) + struct.pack("!H", length) + payload
    return bytes((first, 127)) + struct.pack("!Q", length) + payload


class ReleaseBuildAndReverseTunnelTests(unittest.TestCase):
    def test_websocket_writer_can_progress_while_reader_waits_for_readiness(self):
        sock = _ReadinessWaitingSocket()
        peer = WebSocketPeer(sock, client_side=True)
        read_failure: list[BaseException] = []
        reader_waiting = threading.Event()
        release_reader = threading.Event()

        def wait_for_readability(_read, _write, _errors, _timeout):
            reader_waiting.set()
            self.assertTrue(release_reader.wait(2.0))
            return [], [], []

        def read_once() -> None:
            try:
                peer.recv_frame()
            except BaseException as exc:
                read_failure.append(exc)

        with mock.patch.object(tunnel_module.select, "select", side_effect=wait_for_readability):
            reader = threading.Thread(target=read_once)
            reader.start()
            self.assertTrue(reader_waiting.wait(1.0))
            writer = threading.Thread(target=lambda: peer.send_binary(b"mouse"))
            writer.start()
            self.assertTrue(sock.write_entered.wait(0.5))
            release_reader.set()
            reader.join(1.0)
            writer.join(1.0)
        self.assertFalse(reader.is_alive())
        self.assertFalse(writer.is_alive())
        self.assertTrue(sock.write_entered.is_set())
        self.assertTrue(read_failure)
        self.assertIsInstance(read_failure[0], socket.timeout)

    def test_gateway_tunnel_reader_uses_short_waits_without_ping_flooding(self):
        for app_root in (LINUX_APP, WINDOWS_APP):
            source = (app_root / "gideon_agent_gateway.py").read_text(encoding="utf-8-sig")
            self.assertIn("self.connection.settimeout(0.25)", source)
            self.assertIn("last_ping = time.monotonic()", source)
            self.assertIn("time.monotonic() - last_ping >= 20.0", source)

    def test_websocket_writer_finishes_a_partially_sent_frame_after_timeout(self):
        sock = _ShortWritingSocket([2, socket.timeout("backpressure"), 3, 99])
        peer = WebSocketPeer(sock, client_side=False)
        peer.send_binary(b"abcdef")
        self.assertEqual(b"\x82\x06abcdef", bytes(sock.sent))
        self.assertFalse(peer.closed)

    def test_websocket_reader_preserves_partial_frame_across_timeouts(self):
        payload = (b"rdp-graphics-" * 5000) + b"end"
        frame = _server_frame(0x2, payload)
        sock = _InterruptedSocket([
            frame[:1],
            socket.timeout("first pause"),
            frame[1:117],
            socket.timeout("second pause"),
            frame[117:],
        ])
        peer = WebSocketPeer(sock, client_side=True)
        with self.assertRaises(socket.timeout):
            peer.recv_frame()
        with self.assertRaises(socket.timeout):
            peer.recv_frame()
        self.assertEqual((0x2, payload), peer.recv_frame())

    def test_websocket_reader_preserves_fragmented_message_across_timeout(self):
        first = _server_frame(0x2, b"graphics-", fin=False)
        final = _server_frame(0x0, b"continued", fin=True)
        sock = _InterruptedSocket([first, socket.timeout("between fragments"), final])
        peer = WebSocketPeer(sock, client_side=True)
        with self.assertRaises(socket.timeout):
            peer.recv_frame()
        self.assertEqual((0x2, b"graphics-continued"), peer.recv_frame())

    def test_linux_and_windows_routing_sources_are_mirrored(self):
        for relative in (
            "gideon_agent.py",
            "gideon_reverse_tunnel.py",
            "gideon_agent_gateway.py",
            "gideon_agent_update_builder.py",
            "gideon_web_admin/gateway.py",
            "gideon_web_admin/remote_sessions.py",
            "gideon_web_admin/templates/installers.html",
            "gideon_web_admin/templates/releases.html",
            "gideon_web_admin/templates/remote.html",
            "gideon_web_admin/static/remote_page.js",
        ):
            self.assertEqual(
                (LINUX_APP / relative).read_bytes(),
                (WINDOWS_APP / relative).read_bytes(),
                f"Las copias Linux/Windows difieren: {relative}",
            )

    def test_mtls_renewal_preserves_active_reverse_tunnel(self):
        for app_root in (LINUX_APP, WINDOWS_APP):
            agent_source = (app_root / "gideon_agent.py").read_text(encoding="utf-8-sig")
            tunnel_source = (app_root / "gideon_reverse_tunnel.py").read_text(encoding="utf-8-sig")
            self.assertIn("def _certificate_expiry_utc", agent_source)
            self.assertIn("if had_usable_identity and self.reverse_tunnel is not None:", agent_source)
            self.assertIn("self.reverse_tunnel.client_cert = self.client_cert", agent_source)
            self.assertNotIn("reservation.tunnel_id", inspect.getsource(WebSocketPeer.send_close))

    def test_windows_stable_release_passes_version_to_service_host_builder(self):
        for app_root in (LINUX_APP, WINDOWS_APP):
            source = (app_root / "gideon_agent_update_builder.py").read_text(encoding="utf-8-sig")
            tree = ast.parse(source)
            calls = [
                node for node in ast.walk(tree)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "_build_agent_service_host"
            ]
            self.assertEqual(1, len(calls))
            self.assertIn("version", {keyword.arg for keyword in calls[0].keywords})

    def test_release_targets_are_supplied_to_the_template(self):
        for app_root in (LINUX_APP, WINDOWS_APP):
            source = (app_root / "gideon_web_admin/app.py").read_text(encoding="utf-8-sig")
            self.assertIn("from gideon_agent_update_builder import stable_release_targets", source)
            self.assertIn('"release_targets":stable_release_targets()', source)

    def test_installer_build_sequence_and_filename_are_monotonic(self):
        for app_root in (LINUX_APP, WINDOWS_APP):
            next_number, normalize_history, with_suffix = _installer_helpers(app_root)
            self.assertEqual(1, next_number([]))
            self.assertEqual(8, next_number([{"build_number": 7}, {}]))
            legacy = normalize_history([
                {"version": "2.4.16", "build_id": "newer"},
                {"version": "2.4.16", "build_id": "older"},
            ])
            self.assertEqual([2, 1], [row["build_number"] for row in legacy])
            self.assertEqual("2.4.16 · build 0002", legacy[0]["display_version"])
            self.assertEqual(
                "GIDEONAgent-linux-v2.4.16-build0009.tar.gz",
                with_suffix(Path("GIDEONAgent-linux-v2.4.16.tar.gz"), 9).name,
            )
            self.assertEqual(
                "GIDEONAgent-windows-v2.4.16-build0010.exe",
                with_suffix(Path("GIDEONAgent-windows-v2.4.16.exe"), 10).name,
            )

    def test_agent_retry_gets_a_fresh_reverse_tunnel_target(self):
        with tempfile.TemporaryDirectory(prefix="gideon-remote-route-") as td:
            store = RemoteSessionStore(Path(td), RemoteSessionPolicy())
            first, _ = store.issue(
                user_id=7,
                web_session_id=11,
                username="operator",
                source_type="AGENT",
                source_id="agent-1",
                source_label="Sede · Agent",
                target_host="172.29.250.1",
                target_port=40001,
                protocol="RDP",
                credential_id="ephemeral-1",
                client_ip="190.0.2.10",
                credential_mode="INTERACTIVE",
                route_mode="REVERSE_TUNNEL",
                max_attempts=3,
            )
            store.close(first["session_id"])
            retry, _ = store.issue_retry(
                previous_session_id=first["session_id"],
                user_id=7,
                web_session_id=11,
                username="operator",
                credential_id="ephemeral-2",
                client_ip="190.0.2.10",
                target_host="172.29.250.1",
                target_port=40002,
                route_mode="REVERSE_TUNNEL",
            )
            self.assertEqual(40002, retry["target_port"])
            self.assertEqual("REVERSE_TUNNEL", retry["route_mode"])
            self.assertEqual(2, retry["retry_attempt"])

    def test_agent_remote_start_prefers_reverse_tunnel(self):
        for app_root in (LINUX_APP, WINDOWS_APP):
            app_source = (app_root / "gideon_web_admin/app.py").read_text(encoding="utf-8-sig")
            gateway_source = (app_root / "gideon_web_admin/gateway.py").read_text(encoding="utf-8-sig")
            template = (app_root / "gideon_web_admin/templates/remote.html").read_text(encoding="utf-8-sig")
            self.assertIn("gateway.open_reverse_tunnel", app_source)
            self.assertIn('route_mode = "REVERSE_TUNNEL"', app_source)
            self.assertIn('"POST", "/api/v1/admin/tunnels/open"', gateway_source)
            self.assertIn("túnel inverso ONLINE", template)

    def test_security_modes_advance_automatically_before_next_password(self):
        with tempfile.TemporaryDirectory(prefix="gideon-remote-retry-cycle-") as td:
            store = RemoteSessionStore(Path(td), RemoteSessionPolicy())
            current, _ = store.issue(
                user_id=7,
                web_session_id=11,
                username="operator",
                source_type="AGENT",
                source_id="agent-1",
                source_label="Sede · Agent",
                target_host="172.29.250.1",
                target_port=41001,
                protocol="RDP",
                credential_id="ephemeral:same-password",
                client_ip="190.0.2.10",
                credential_mode="INTERACTIVE",
                route_mode="REVERSE_TUNNEL",
                max_attempts=12,
                credential_round=1,
                security_attempt=1,
                max_credential_rounds=3,
                max_security_attempts=4,
                rdp_security="nla",
                rdp_security_plan=("nla", "any", "tls", "rdp"),
            )
            self.assertEqual((1, 1), (current["credential_round"], current["security_attempt"]))
            self.assertEqual("nla,any,tls,rdp", current["rdp_security_plan"])
            for security_attempt, rdp_security in ((2, "any"), (3, "tls"), (4, "rdp")):
                store.close(current["session_id"], reason="RDP_SECURITY_NEGOTIATION")
                current, _ = store.issue_retry(
                    previous_session_id=current["session_id"],
                    user_id=7,
                    web_session_id=11,
                    username="operator",
                    credential_id="",
                    reuse_credential=True,
                    client_ip="190.0.2.10",
                    target_port=41000 + security_attempt,
                    route_mode="REVERSE_TUNNEL",
                    rdp_security=rdp_security,
                )
                self.assertEqual(1, current["credential_round"])
                self.assertEqual(security_attempt, current["security_attempt"])
                self.assertEqual("ephemeral:same-password", current["credential_id"])
                self.assertEqual("nla,any,tls,rdp", current["rdp_security_plan"])
            store.close(current["session_id"], reason="RDP_SECURITY_NEGOTIATION")
            with self.assertRaises(RemoteSessionError):
                store.issue_retry(
                    previous_session_id=current["session_id"],
                    user_id=7,
                    web_session_id=11,
                    username="operator",
                    credential_id="",
                    reuse_credential=True,
                    client_ip="190.0.2.10",
                )
            next_password, _ = store.issue_retry(
                previous_session_id=current["session_id"],
                user_id=7,
                web_session_id=11,
                username="operator",
                credential_id="ephemeral:new-password",
                client_ip="190.0.2.10",
                route_mode="REVERSE_TUNNEL",
                rdp_security="nla",
            )
            self.assertEqual((2, 1), (
                next_password["credential_round"], next_password["security_attempt"]
            ))
            self.assertEqual("ephemeral:new-password", next_password["credential_id"])

    def test_windows_handoff_reconnect_is_one_shot_and_does_not_consume_password_round(self):
        with tempfile.TemporaryDirectory(prefix="gideon-remote-handoff-") as td:
            store = RemoteSessionStore(Path(td), RemoteSessionPolicy())
            first, ticket = store.issue(
                user_id=7,
                web_session_id=11,
                username="operator",
                source_type="AGENT",
                source_id="agent-1",
                source_label="Sede · Agent",
                target_host="127.0.0.1",
                target_port=41001,
                protocol="RDP",
                credential_id="ephemeral:same-password",
                client_ip="190.0.2.10",
                credential_mode="INTERACTIVE",
                route_mode="REVERSE_TUNNEL",
                max_attempts=9,
                credential_round=1,
                security_attempt=1,
                max_credential_rounds=3,
                max_security_attempts=3,
                rdp_security="nla",
                rdp_security_plan=("nla", "any", "tls"),
                max_handoff_reconnects=1,
            )
            store.consume(
                session_id=first["session_id"], raw_ticket=ticket,
                user_id=7, web_session_id=11, username="operator", client_ip="190.0.2.10",
            )
            resumed, _ = store.issue_handoff_reconnect(
                previous_session_id=first["session_id"],
                user_id=7,
                web_session_id=11,
                username="operator",
                client_ip="190.0.2.10",
                target_port=41002,
                route_mode="REVERSE_TUNNEL",
            )
            previous = store.get_for_user(first["session_id"], 7)
            self.assertEqual("RDP_SESSION_HANDOFF_RECONNECT", previous["end_reason"])
            self.assertEqual((1, 1), (resumed["credential_round"], resumed["security_attempt"]))
            self.assertEqual(1, resumed["retry_attempt"])
            self.assertEqual((1, 1), (
                resumed["handoff_reconnect_attempt"], resumed["max_handoff_reconnects"]
            ))
            with self.assertRaises(RemoteSessionError):
                store.issue_handoff_reconnect(
                    previous_session_id=first["session_id"],
                    user_id=7,
                    web_session_id=11,
                    username="operator",
                    client_ip="190.0.2.10",
                )
            store.close(resumed["session_id"], reason="GUACD_REMOTE_DISCONNECT")
            with self.assertRaises(RemoteSessionError):
                store.issue_handoff_reconnect(
                    previous_session_id=resumed["session_id"],
                    user_id=7,
                    web_session_id=11,
                    username="operator",
                    client_ip="190.0.2.10",
                )


if __name__ == "__main__":
    unittest.main()
