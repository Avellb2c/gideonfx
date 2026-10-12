#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GIDEON Reverse Tunnel wire v1.3 · runtime API 2.

A small, stdlib-only reverse TCP tunnel used by GIDEONAgent and GIDEON Agent Gateway.
The Agent initiates one outbound WebSocket/TLS control connection to the Gateway.
When WebAdmin requests an RDP session, the Gateway opens a one-shot local TCP
listener for guacd and asks the Agent to connect ONLY to loopback RDP/VNC.

Security invariants:
- Agent authenticates with its existing bearer token (and mTLS if Gateway requires it).
- Agent never listens on an inbound TCP port.
- The Gateway admin API can request only loopback RDP/VNC targets.
- Stream IDs are random and ephemeral.
- No credentials are carried by this tunnel; RDP credentials remain in Guacamole.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import select
import socket
import ssl
import struct
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from urllib.parse import urlparse

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
TUNNEL_VERSION = "1.3"
TUNNEL_API_VERSION = 2
_STREAM_ID_BYTES = 32
_MAX_FRAME = 2 * 1024 * 1024
_IO_CHUNK = 32 * 1024

LOG = logging.getLogger("gideon.reverse_tunnel")


def _now() -> float:
    return time.time()


def _configure_tcp_keepalive(sock: socket.socket) -> None:
    """Detect a dead Internet/NAT path promptly without platform assumptions."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except (AttributeError, OSError):
        return
    for name, value in (("TCP_KEEPIDLE", 30), ("TCP_KEEPINTVL", 10), ("TCP_KEEPCNT", 3)):
        option = getattr(socket, name, None)
        if option is None:
            continue
        try:
            sock.setsockopt(socket.IPPROTO_TCP, option, value)
        except OSError:
            pass


def _ws_accept(key: str) -> str:
    raw = hashlib.sha1((str(key) + WS_GUID).encode("ascii")).digest()
    return base64.b64encode(raw).decode("ascii")


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    out = bytearray()
    while len(out) < length:
        chunk = sock.recv(length - len(out))
        if not chunk:
            raise ConnectionError("socket closed")
        out.extend(chunk)
    return bytes(out)


class WebSocketPeer:
    """Minimal RFC6455 framing for trusted GIDEON endpoints.

    GIDEON sends only complete non-fragmented text/binary/control frames. The parser
    accepts continuation frames defensively and reassembles them.
    """

    def __init__(self, sock: socket.socket, *, client_side: bool) -> None:
        self.sock = sock
        self.client_side = bool(client_side)
        self._send_lock = threading.RLock()
        # CPython's SSLSocket must not be entered concurrently from separate
        # reader/writer threads. The tunnel has one receive loop plus local
        # stream forwarding threads, so serialize each actual TLS I/O call.
        # Importantly, the reader waits for readiness *before* taking this
        # lock. Holding it across a blocking recv would starve the local VNC/
        # RDP reader which has to write the first server bytes back to Gateway.
        self._io_lock = threading.RLock()
        # recv_frame() may be interrupted by socket.timeout after only part of a
        # WebSocket frame has arrived.  Keep all unread bytes and fragmented
        # message state on the peer itself so the next call resumes exactly
        # where the previous one stopped.  The former stateless parser lost the
        # already-consumed header/payload and interpreted the remaining payload
        # as a new frame, which disconnected busy RDP sessions.
        self._recv_buffer = bytearray()
        self._fragment_buffer = bytearray()
        self._fragment_opcode: Optional[int] = None
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    def send_frame(self, opcode: int, payload: bytes = b"") -> None:
        if self._closed:
            raise ConnectionError("websocket closed")
        payload = bytes(payload or b"")
        if len(payload) > _MAX_FRAME:
            raise ValueError("websocket frame too large")
        fin_opcode = 0x80 | (int(opcode) & 0x0F)
        mask_bit = 0x80 if self.client_side else 0
        n = len(payload)
        if n < 126:
            header = bytes((fin_opcode, mask_bit | n))
        elif n <= 0xFFFF:
            header = bytes((fin_opcode, mask_bit | 126)) + struct.pack("!H", n)
        else:
            header = bytes((fin_opcode, mask_bit | 127)) + struct.pack("!Q", n)
        if self.client_side:
            key = os.urandom(4)
            payload = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
            packet = header + key + payload
        else:
            packet = header + payload
        # The Agent uses a short socket timeout so recv_frame() can emit
        # keepalives.  That timeout also applies to writes.  socket.sendall()
        # gives no indication of how much data was written before a timeout;
        # attempting the next WebSocket frame after such a timeout corrupts
        # the byte stream and the Gateway must close the entire tunnel.  This
        # is especially visible with WayVNC when moving a remotely-rendered
        # cursor produces a burst of framebuffer data.  Track write progress
        # explicitly and either finish the frame or close the socket cleanly.
        with self._send_lock:
            view = memoryview(packet)
            sent = 0
            deadline = time.monotonic() + 30.0
            try:
                while sent < len(view):
                    try:
                        with self._io_lock:
                            count = self.sock.send(view[sent:])
                    except socket.timeout:
                        if time.monotonic() >= deadline:
                            raise TimeoutError("websocket frame send stalled for 30 seconds")
                        continue
                    if count <= 0:
                        raise ConnectionError("socket closed during websocket frame send")
                    sent += count
            except Exception:
                # A partially-written frame cannot be recovered in-band.
                # Closing forces a fresh, correctly-framed control channel.
                self._closed = True
                try:
                    self.sock.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                try:
                    self.sock.close()
                except Exception:
                    pass
                raise

    def send_json(self, value: dict[str, Any]) -> None:
        self.send_frame(0x1, json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))

    def send_binary(self, payload: bytes) -> None:
        self.send_frame(0x2, payload)

    def send_ping(self, payload: bytes = b"gideon") -> None:
        self.send_frame(0x9, payload[:125])

    def send_pong(self, payload: bytes = b"") -> None:
        self.send_frame(0xA, payload[:125])

    def send_close(self, code: int = 1000, reason: str = "") -> None:
        if self._closed:
            return
        try:
            payload = struct.pack("!H", int(code)) + str(reason or "")[:120].encode("utf-8", "replace")
            self.send_frame(0x8, payload)
        except Exception:
            # Closing is best-effort.  In particular, never reference broker
            # reservation state here: this peer is also used by the Agent and
            # does not own a TunnelReservation.
            pass
        self._closed = True

    def _recv_wire_frame(self) -> tuple[bool, int, bytes]:
        """Return one complete RFC6455 frame without losing partial reads."""
        while True:
            if len(self._recv_buffer) >= 2:
                b1, b2 = self._recv_buffer[0], self._recv_buffer[1]
                masked = bool(b2 & 0x80)
                marker = b2 & 0x7F
                ext = 2 if marker == 126 else (8 if marker == 127 else 0)
                header_len = 2 + ext + (4 if masked else 0)
                if len(self._recv_buffer) >= 2 + ext:
                    if marker < 126:
                        payload_len = marker
                    elif marker == 126:
                        payload_len = struct.unpack("!H", self._recv_buffer[2:4])[0]
                    else:
                        payload_len = struct.unpack("!Q", self._recv_buffer[2:10])[0]
                    if payload_len > _MAX_FRAME:
                        raise ValueError("websocket frame exceeds GIDEON limit")
                    total = header_len + payload_len
                    if len(self._recv_buffer) >= total:
                        frame = bytes(self._recv_buffer[:total])
                        del self._recv_buffer[:total]
                        mask_at = 2 + ext
                        payload_at = header_len
                        payload = frame[payload_at:]
                        if masked:
                            mask = frame[mask_at:mask_at + 4]
                            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
                        return bool(b1 & 0x80), b1 & 0x0F, payload

            # socket.timeout intentionally propagates.  Bytes already received
            # remain buffered and will be used by the following recv_frame().
            #
            # Do not take _io_lock until the underlying socket is readable.
            # An Agent has a control-reader thread plus local target reader
            # threads. Taking the lock around a 1s (or Gateway 250ms) blocking
            # recv let the control reader immediately reclaim it on every
            # timeout, starving the target reader and leaving WayVNC's RFB
            # banner/frame trapped on the device side.
            timeout = None
            try:
                timeout = self.sock.gettimeout()
            except (AttributeError, OSError):
                pass
            pending = 0
            try:
                pending = int(self.sock.pending())
            except (AttributeError, OSError, ValueError):
                # Plain sockets and test doubles have no TLS plaintext buffer.
                pending = 0
            if pending <= 0:
                try:
                    readable, _writable, _errors = select.select([self.sock], [], [], timeout)
                except (AttributeError, OSError, TypeError, ValueError):
                    # Preserve compatibility with socket-like test doubles.
                    # Production TCP/SSLSockets always support select().
                    readable = [self.sock]
                if not readable:
                    raise socket.timeout("websocket receive timed out")
            try:
                with self._io_lock:
                    chunk = self.sock.recv(_IO_CHUNK)
            except ssl.SSLWantReadError as exc:
                # A TLS record can be consumed by OpenSSL while it discovers it
                # needs more encrypted bytes. Treat it like the normal bounded
                # receive wait; no framing bytes have been lost.
                raise socket.timeout("websocket TLS receive needs more data") from exc
            if not chunk:
                raise ConnectionError("socket closed")
            self._recv_buffer.extend(chunk)
            if len(self._recv_buffer) > _MAX_FRAME + 32:
                raise ValueError("websocket receive buffer exceeds GIDEON limit")

    def recv_frame(self) -> tuple[int, bytes]:
        while True:
            fin, opcode, payload = self._recv_wire_frame()

            if opcode == 0x9:
                self.send_pong(payload)
                continue
            if opcode == 0xA:
                return opcode, payload
            if opcode == 0x8:
                self._closed = True
                return opcode, payload

            if opcode in (0x1, 0x2):
                if self._fragment_opcode is not None:
                    raise ValueError("new websocket message before fragmented message completed")
                self._fragment_opcode = opcode
                self._fragment_buffer.extend(payload)
            elif opcode == 0x0 and self._fragment_opcode is not None:
                self._fragment_buffer.extend(payload)
            else:
                raise ValueError(f"unsupported websocket opcode {opcode}")

            if len(self._fragment_buffer) > _MAX_FRAME:
                raise ValueError("fragmented websocket message exceeds GIDEON limit")

            if fin:
                message_opcode = int(self._fragment_opcode or opcode)
                message = bytes(self._fragment_buffer)
                self._fragment_buffer.clear()
                self._fragment_opcode = None
                return message_opcode, message

    def close_socket(self) -> None:
        self._closed = True
        self._recv_buffer.clear()
        self._fragment_buffer.clear()
        self._fragment_opcode = None
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass


@dataclass
class _StreamState:
    stream_id: str
    sock: socket.socket
    opened: threading.Event = field(default_factory=threading.Event)
    open_ok: bool = False
    open_error: str = ""
    closed: bool = False


class GatewayAgentChannel:
    def __init__(self, agent_id: str, ws: WebSocketPeer, *, peer_ip: str = "") -> None:
        self.agent_id = str(agent_id)
        self.ws = ws
        self.peer_ip = str(peer_ip or "")
        self.connected_at = _now()
        self.last_seen = _now()
        self._streams: dict[str, _StreamState] = {}
        self._lock = threading.RLock()
        self.closed = False

    def stream(self, stream_id: str) -> Optional[_StreamState]:
        with self._lock:
            return self._streams.get(stream_id)

    def add_stream(self, stream_id: str, sock: socket.socket) -> _StreamState:
        state = _StreamState(stream_id=stream_id, sock=sock)
        with self._lock:
            self._streams[stream_id] = state
        return state

    def pop_stream(self, stream_id: str) -> Optional[_StreamState]:
        with self._lock:
            return self._streams.pop(stream_id, None)

    def mark_open(self, stream_id: str, ok: bool, error: str = "") -> None:
        state = self.stream(stream_id)
        if state is None:
            return
        state.open_ok = bool(ok)
        state.open_error = str(error or "")[:400]
        state.opened.set()

    def send_open(self, stream_id: str, *, purpose: str, target_host: str, target_port: int,
                  session_switch: Optional[dict[str, Any]] = None) -> None:
        self.ws.send_json({
            "type": "open",
            "version": TUNNEL_VERSION,
            "stream_id": stream_id,
            "purpose": str(purpose).upper(),
            "target_host": str(target_host),
            "target_port": int(target_port),
            "session_switch": dict(session_switch or {}),
        })

    def send_stream_data(self, stream_id: str, data: bytes) -> None:
        if not data:
            return
        self.ws.send_binary(stream_id.encode("ascii") + data)

    def send_close(self, stream_id: str, reason: str = "") -> None:
        try:
            self.ws.send_json({"type": "close", "stream_id": stream_id, "reason": str(reason or "")[:200]})
        except Exception:
            pass

    def handle_text(self, payload: bytes) -> None:
        self.last_seen = _now()
        value = json.loads(payload.decode("utf-8"))
        if not isinstance(value, dict):
            return
        typ = str(value.get("type") or "")
        sid = str(value.get("stream_id") or "")
        if typ == "hello":
            return
        if typ == "opened" and sid:
            self.mark_open(sid, True)
            return
        if typ == "open_failed" and sid:
            self.mark_open(sid, False, str(value.get("error") or "Agent could not open local target"))
            return
        if typ == "close" and sid:
            self.close_stream(
                sid,
                notify=False,
                reason=str(value.get("reason") or "AGENT_REQUESTED_CLOSE"),
            )
            return

    def handle_binary(self, payload: bytes) -> None:
        self.last_seen = _now()
        if len(payload) < _STREAM_ID_BYTES:
            return
        try:
            sid = payload[:_STREAM_ID_BYTES].decode("ascii")
        except Exception:
            return
        data = payload[_STREAM_ID_BYTES:]
        state = self.stream(sid)
        if state is None or state.closed:
            return
        try:
            if data:
                state.sock.sendall(data)
        except Exception:
            self.close_stream(sid, notify=True, reason="BROKER_TCP_WRITE_FAILED")

    def close_stream(self, stream_id: str, *, notify: bool, reason: str = "") -> None:
        state = self.pop_stream(stream_id)
        if state is None:
            return
        state.closed = True
        state.opened.set()
        try:
            state.sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            state.sock.close()
        except Exception:
            pass
        if notify:
            self.send_close(stream_id, reason)
        LOG.info(
            "reverse tunnel gateway stream closed agent=%s stream=%s reason=%s",
            self.agent_id,
            str(stream_id)[:12],
            str(reason or "PEER_CLOSED")[:120],
        )

    def close_all(self, reason: str = "CHANNEL_CLOSED") -> None:
        self.closed = True
        with self._lock:
            ids = list(self._streams)
        for sid in ids:
            self.close_stream(sid, notify=False, reason=reason)
        try:
            self.ws.send_close(1000, reason)
        except Exception:
            pass
        self.ws.close_socket()


@dataclass
class TunnelReservation:
    tunnel_id: str
    agent_id: str
    purpose: str
    target_host: str
    target_port: int
    listener: socket.socket
    broker_host: str
    broker_port: int
    expires_unix: int
    broker: "GatewayTunnelBroker"
    session_switch: dict[str, Any] = field(default_factory=dict)
    closed: bool = False

    def close(self, reason: str = "RESERVATION_CLOSED") -> None:
        if self.closed:
            return
        self.closed = True
        try:
            self.listener.close()
        except Exception:
            pass
        self.broker._drop_reservation(self.tunnel_id)


class GatewayTunnelBroker:
    """Agent registry plus one-shot TCP listeners consumed by guacd."""

    def __init__(self, *, enabled: bool = True, listen_host: str = "0.0.0.0",
                 advertised_host: str = "host.docker.internal", open_ttl_seconds: int = 45,
                 max_reservations: int = 64, max_streams_per_agent: int = 4) -> None:
        self.enabled = bool(enabled)
        self.listen_host = str(listen_host or "0.0.0.0")
        self.advertised_host = str(advertised_host or "host.docker.internal")
        self.open_ttl_seconds = max(10, min(int(open_ttl_seconds or 45), 180))
        self.max_reservations = max(1, min(int(max_reservations or 64), 512))
        self.max_streams_per_agent = max(1, min(int(max_streams_per_agent or 4), 16))
        self._agents: dict[str, GatewayAgentChannel] = {}
        self._reservations: dict[str, TunnelReservation] = {}
        self._lock = threading.RLock()

    def reconfigure(self, cfg: dict[str, Any]) -> None:
        self.enabled = bool(cfg.get("reverse_tunnel_enabled", self.enabled))
        self.listen_host = str(cfg.get("reverse_tunnel_listen_host") or self.listen_host)
        self.advertised_host = str(cfg.get("reverse_tunnel_advertised_host") or self.advertised_host)
        self.open_ttl_seconds = max(10, min(int(cfg.get("reverse_tunnel_open_ttl_seconds") or self.open_ttl_seconds), 180))
        self.max_reservations = max(1, min(int(cfg.get("reverse_tunnel_max_reservations") or self.max_reservations), 512))

    def register(self, agent_id: str, ws: WebSocketPeer, *, peer_ip: str = "") -> GatewayAgentChannel:
        agent_id = str(agent_id or "").strip()
        if not agent_id:
            raise ValueError("agent_id required")
        channel = GatewayAgentChannel(agent_id, ws, peer_ip=peer_ip)
        old = None
        with self._lock:
            old = self._agents.get(agent_id)
            self._agents[agent_id] = channel
        if old is not None and old is not channel:
            old.close_all("REPLACED_BY_NEW_AGENT_CHANNEL")
        return channel

    def unregister(self, agent_id: str, channel: GatewayAgentChannel) -> None:
        with self._lock:
            if self._agents.get(agent_id) is channel:
                self._agents.pop(agent_id, None)
        channel.close_all("AGENT_CHANNEL_DISCONNECTED")

    def channel(self, agent_id: str) -> Optional[GatewayAgentChannel]:
        with self._lock:
            ch = self._agents.get(str(agent_id or ""))
            if ch is not None and not ch.closed and not ch.ws.closed:
                return ch
            return None

    def online(self, agent_id: str) -> bool:
        return self.channel(agent_id) is not None

    def status(self, agent_id: str) -> dict[str, Any]:
        ch = self.channel(agent_id)
        return {
            "Online": bool(ch),
            "AgentId": str(agent_id or ""),
            "PeerIP": ch.peer_ip if ch else "",
            "ConnectedAtUnix": int(ch.connected_at) if ch else 0,
            "LastSeenUnix": int(ch.last_seen) if ch else 0,
            "Version": TUNNEL_VERSION,
        }

    def _drop_reservation(self, tunnel_id: str) -> None:
        with self._lock:
            self._reservations.pop(str(tunnel_id), None)

    def _prune_reservations_locked(self) -> None:
        now = int(_now())
        stale = [r for r in self._reservations.values() if r.closed or r.expires_unix <= now]
        for r in stale:
            try:
                r.listener.close()
            except Exception:
                pass
            r.closed = True
            self._reservations.pop(r.tunnel_id, None)

    @staticmethod
    def _validate_target(purpose: str, host: str, port: int) -> tuple[str, int]:
        purpose = str(purpose or "").upper()
        host = str(host or "127.0.0.1").strip().lower()
        port = int(port)
        if host not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("reverse tunnel target must be loopback")
        expected = {"RDP": 3389, "VNC": 5900}.get(purpose)
        if expected is None or port != expected:
            raise ValueError("reverse tunnel permits only loopback RDP:3389 or VNC:5900")
        return "127.0.0.1", port

    def reserve(self, *, agent_id: str, purpose: str = "RDP", target_host: str = "127.0.0.1",
                target_port: int = 3389, session_switch: Optional[dict[str, Any]] = None) -> TunnelReservation:
        if not self.enabled:
            raise RuntimeError("reverse tunnel broker disabled")
        ch = self.channel(agent_id)
        if ch is None:
            raise RuntimeError("agent reverse tunnel is offline")
        target_host, target_port = self._validate_target(purpose, target_host, target_port)
        switch = dict(session_switch or {}) if isinstance(session_switch, dict) else {}
        switch = {
            "enabled": bool(switch.get("enabled")) and str(purpose).upper() == "RDP",
            "request_id": str(switch.get("request_id") or "")[:80],
            "active_user": str(switch.get("active_user") or "")[:128],
            "requested_user": str(switch.get("requested_user") or "")[:128],
            "timeout_seconds": max(5, min(int(switch.get("timeout_seconds") or 35), 45)),
        }
        if not switch["enabled"]:
            switch = {}
        with self._lock:
            self._prune_reservations_locked()
            if len(self._reservations) >= self.max_reservations:
                raise RuntimeError("reverse tunnel reservation capacity reached")

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.listen_host, 0))
        listener.listen(1)
        listener.settimeout(float(self.open_ttl_seconds))
        port = int(listener.getsockname()[1])
        tunnel_id = "tun-" + secrets.token_hex(12)
        reservation = TunnelReservation(
            tunnel_id=tunnel_id,
            agent_id=str(agent_id),
            purpose=str(purpose).upper(),
            target_host=target_host,
            target_port=target_port,
            listener=listener,
            broker_host=self.advertised_host,
            broker_port=port,
            expires_unix=int(_now()) + self.open_ttl_seconds,
            broker=self,
            session_switch=switch,
        )
        with self._lock:
            self._reservations[tunnel_id] = reservation
        threading.Thread(target=self._accept_one, args=(reservation,), name=f"GIDEON-Tunnel-{tunnel_id}", daemon=True).start()
        return reservation

    def _accept_one(self, reservation: TunnelReservation) -> None:
        client: Optional[socket.socket] = None
        stream_id = ""
        channel: Optional[GatewayAgentChannel] = None
        try:
            client, _addr = reservation.listener.accept()
            client.settimeout(None)
            try:
                reservation.listener.close()
            except Exception:
                pass

            channel = self.channel(reservation.agent_id)
            if channel is None:
                raise RuntimeError("agent tunnel went offline before guacd connected")
            with channel._lock:
                if len(channel._streams) >= self.max_streams_per_agent:
                    raise RuntimeError("agent tunnel stream capacity reached")
            stream_id = uuid.uuid4().hex
            state = channel.add_stream(stream_id, client)
            channel.send_open(
                stream_id,
                purpose=reservation.purpose,
                target_host=reservation.target_host,
                target_port=reservation.target_port,
                session_switch=reservation.session_switch,
            )
            if not state.opened.wait(timeout=10.0):
                raise RuntimeError("agent did not acknowledge tunnel open")
            if not state.open_ok:
                raise RuntimeError(state.open_error or "agent rejected tunnel open")

            while True:
                data = client.recv(_IO_CHUNK)
                if not data:
                    break
                channel.send_stream_data(stream_id, data)
        except Exception as exc:
            LOG.warning(
                "reverse tunnel broker stream failed tunnel=%s agent=%s purpose=%s error=%s: %s",
                reservation.tunnel_id,
                reservation.agent_id,
                reservation.purpose,
                type(exc).__name__,
                str(exc)[:300],
            )
        finally:
            if channel is not None and stream_id:
                channel.close_stream(stream_id, notify=True, reason="BROKER_STREAM_CLOSED")
            elif client is not None:
                try:
                    client.close()
                except Exception:
                    pass
            reservation.close("COMPLETE")

    def shutdown(self) -> None:
        with self._lock:
            reservations = list(self._reservations.values())
            channels = list(self._agents.values())
            self._reservations.clear()
            self._agents.clear()
        for r in reservations:
            try:
                r.listener.close()
            except Exception:
                pass
        for ch in channels:
            ch.close_all("BROKER_SHUTDOWN")


class AgentReverseTunnelClient:
    """Outbound-only Agent WebSocket client with loopback target policy."""

    def __init__(self, *, base_url: str, bearer_token: str, agent_id: str,
                 verify_tls: bool = True, ca_file: str | None = None,
                 client_cert: str | None = None, client_key: str | None = None,
                 allowed_targets: Optional[list[str]] = None,
                 status_callback: Optional[Callable[[str, str], None]] = None) -> None:
        self.base_url = str(base_url or "").rstrip("/")
        self.bearer_token = str(bearer_token or "")
        self.agent_id = str(agent_id or "")
        self.verify_tls = bool(verify_tls)
        self.ca_file = str(ca_file or "") or None
        self.client_cert = str(client_cert or "") or None
        self.client_key = str(client_key or "") or None
        self.allowed_targets = self._normalize_allowed_targets(
            allowed_targets or ["127.0.0.1:3389", "127.0.0.1:5900"]
        )
        self.status_callback = status_callback
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._ws: Optional[WebSocketPeer] = None
        self._streams: dict[str, socket.socket] = {}
        self._opening_streams: set[str] = set()
        self._streams_lock = threading.RLock()
        self._update_quiescing = False
        self._state = "STOPPED"
        self._last_error = ""
        self._last_connection_uptime = 0.0

    @property
    def state(self) -> str:
        return self._state

    @property
    def last_error(self) -> str:
        return self._last_error

    @property
    def active_stream_count(self) -> int:
        """Return established plus in-flight remote desktop streams."""
        with self._streams_lock:
            return len(self._streams) + len(self._opening_streams)

    def begin_update_quiesce(self) -> bool:
        """Atomically stop new streams only when no remote session is active.

        The update scheduler calls this immediately before spawning the detached
        updater.  Sharing the same lock with stream reservation closes the race
        where a VNC/RDP connection could start between the last busy check and
        the service restart.
        """
        with self._streams_lock:
            if self._streams or self._opening_streams:
                return False
            self._update_quiescing = True
            return True

    def cancel_update_quiesce(self) -> None:
        """Resume accepting streams when scheduling the updater failed."""
        with self._streams_lock:
            self._update_quiescing = False

    def _status(self, state: str, detail: str = "") -> None:
        changed = state != self._state or (detail and detail != self._last_error)
        self._state = str(state)
        if detail:
            self._last_error = str(detail)[:500]
        elif state == "ONLINE":
            self._last_error = ""
        if changed and self.status_callback:
            try:
                self.status_callback(self._state, self._last_error)
            except Exception:
                pass

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="GIDEONAgent-ReverseTunnel", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        ws = self._ws
        if ws is not None:
            try:
                ws.send_close(1000, "agent stopping")
            except Exception:
                pass
            ws.close_socket()
        self._close_all_streams()
        self._status("STOPPED")

    @staticmethod
    def _normalize_allowed_targets(values: list[str]) -> set[tuple[str, int]]:
        out: set[tuple[str, int]] = set()
        for raw in values or []:
            text = str(raw or "").strip()
            if not text:
                continue
            if text.startswith("[") and "]:" in text:
                host, port_text = text[1:].split("]:", 1)
            elif ":" in text:
                host, port_text = text.rsplit(":", 1)
            else:
                continue
            host = host.strip().lower()
            if host in {"localhost", "::1"}:
                host = "127.0.0.1"
            if host != "127.0.0.1":
                continue
            try:
                port = int(port_text)
            except Exception:
                continue
            if port in {3389, 5900}:
                out.add((host, port))
        if not out:
            out = {("127.0.0.1", 3389), ("127.0.0.1", 5900)}
        return out

    def _validate_open(self, value: dict[str, Any]) -> tuple[str, str, str, int]:
        sid = str(value.get("stream_id") or "")
        purpose = str(value.get("purpose") or "").upper()
        host = str(value.get("target_host") or "").strip().lower()
        port = int(value.get("target_port") or 0)
        if len(sid) != 32 or any(ch not in "0123456789abcdef" for ch in sid.lower()):
            raise ValueError("invalid stream id")
        if host in {"localhost", "::1"}:
            host = "127.0.0.1"
        if host != "127.0.0.1":
            raise ValueError("target must be loopback")
        expected = {"RDP": 3389, "VNC": 5900}.get(purpose)
        if expected is None or port != expected:
            raise ValueError("target is not an allowed remote desktop service")
        if (host, port) not in self.allowed_targets:
            raise PermissionError(f"target {host}:{port} is not enabled in Agent reverse_tunnel.allowed_targets")
        return sid, purpose, host, port

    def _tls_context(self, hostname: str) -> ssl.SSLContext:
        if self.verify_tls:
            ctx = ssl.create_default_context(cafile=self.ca_file)
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            ctx = ssl._create_unverified_context()
        if self.client_cert:
            ctx.load_cert_chain(self.client_cert, self.client_key)
        if hasattr(ssl, "TLSVersion"):
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx

    def _connect_ws(self) -> WebSocketPeer:
        parsed = urlparse(self.base_url)
        scheme = parsed.scheme.lower()
        if scheme not in {"https", "http"}:
            raise ValueError("Gateway URL must be http/https")
        if scheme == "http" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise RuntimeError("Plain HTTP reverse tunnel allowed only on loopback test endpoints")
        host = parsed.hostname or ""
        port = int(parsed.port or (443 if scheme == "https" else 80))
        raw = socket.create_connection((host, port), timeout=10)
        if scheme == "https":
            raw = self._tls_context(host).wrap_socket(raw, server_hostname=host)
        _configure_tcp_keepalive(raw)
        raw.settimeout(30.0)

        key = base64.b64encode(os.urandom(16)).decode("ascii")
        base_path = parsed.path.rstrip("/")
        path = (base_path + "/api/v1/agent/tunnel/ws") if base_path else "/api/v1/agent/tunnel/ws"
        host_hdr = host if (parsed.port is None) else f"{host}:{port}"
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host_hdr}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            f"Authorization: Bearer {self.bearer_token}\r\n"
            "User-Agent: GIDEONAgent-ReverseTunnel/1.0\r\n"
            "\r\n"
        )
        raw.sendall(request.encode("ascii"))
        response = bytearray()
        while b"\r\n\r\n" not in response:
            chunk = raw.recv(4096)
            if not chunk:
                raise ConnectionError("Gateway closed during WebSocket handshake")
            response.extend(chunk)
            if len(response) > 64 * 1024:
                raise ValueError("WebSocket handshake response too large")
        head = bytes(response).split(b"\r\n\r\n", 1)[0].decode("iso-8859-1")
        lines = head.split("\r\n")
        if not lines or " 101 " not in (" " + lines[0] + " "):
            raise ConnectionError(f"Gateway WebSocket upgrade failed: {lines[0] if lines else 'invalid response'}")
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        if headers.get("sec-websocket-accept", "") != _ws_accept(key):
            raise ConnectionError("Gateway WebSocket accept mismatch")
        raw.settimeout(1.0)
        return WebSocketPeer(raw, client_side=True)

    def _close_all_streams(self) -> None:
        with self._streams_lock:
            items = list(self._streams.items())
            self._streams.clear()
            self._opening_streams.clear()
        for _sid, sock in items:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                sock.close()
            except Exception:
                pass

    def _open_stream(self, ws: WebSocketPeer, value: dict[str, Any]) -> None:
        sid = str(value.get("stream_id") or "")
        reserved = False
        sock: socket.socket | None = None
        try:
            sid, purpose, host, port = self._validate_open(value)
            with self._streams_lock:
                if self._update_quiescing:
                    raise RuntimeError("AGENT_UPDATE_QUIESCING: remote session deferred until Agent restart")
                self._opening_streams.add(sid)
                reserved = True
            session_switch = value.get("session_switch")
            if isinstance(session_switch, dict) and bool(session_switch.get("enabled")):
                try:
                    from gideon_agent_session_handoff import spawn_session_switch_watcher
                    spawn_session_switch_watcher(
                        request_id=str(session_switch.get("request_id") or sid),
                        active_user=str(session_switch.get("active_user") or ""),
                        requested_user=str(session_switch.get("requested_user") or ""),
                        timeout_seconds=float(session_switch.get("timeout_seconds") or 35),
                    )
                except Exception:
                    # The transport must remain available even when a platform
                    # lacks the optional interactive-session helper.
                    pass
            if purpose == "VNC":
                try:
                    from gideon_agent_vnc_bridge import connect_local_wayland_vnc
                    sock = connect_local_wayland_vnc(timeout=8)
                except FileNotFoundError:
                    # Generic Linux/macOS Agents may run a normal TCP VNC
                    # service. Raspberry local-Wayland advertisements are
                    # emitted only while the protected UNIX socket exists.
                    sock = socket.create_connection((host, port), timeout=8)
            else:
                sock = socket.create_connection((host, port), timeout=8)
            sock.settimeout(None)
            with self._streams_lock:
                self._opening_streams.discard(sid)
                reserved = False
                if self._update_quiescing:
                    raise RuntimeError("AGENT_UPDATE_QUIESCING: remote session deferred until Agent restart")
                old = self._streams.pop(sid, None)
                self._streams[sid] = sock
            if old:
                try: old.close()
                except Exception: pass
            ws.send_json({"type": "opened", "stream_id": sid})
            threading.Thread(target=self._local_reader, args=(ws, sid, sock), name=f"GIDEONAgent-Tunnel-{sid[:8]}", daemon=True).start()
        except Exception as exc:
            with self._streams_lock:
                if reserved:
                    self._opening_streams.discard(sid)
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
            try:
                ws.send_json({"type": "open_failed", "stream_id": sid, "error": f"{type(exc).__name__}: {exc}"[:300]})
            except Exception:
                pass

    def _local_reader(self, ws: WebSocketPeer, sid: str, sock: socket.socket) -> None:
        close_reason = "LOCAL_TARGET_EOF"
        try:
            while not self._stop.is_set():
                data = sock.recv(_IO_CHUNK)
                if not data:
                    break
                ws.send_binary(sid.encode("ascii") + data)
        except Exception as exc:
            close_reason = f"LOCAL_TARGET_READ_FAILED:{type(exc).__name__}"
            LOG.warning(
                "reverse tunnel agent local stream failed agent=%s stream=%s error=%s: %s",
                self.agent_id,
                str(sid)[:12],
                type(exc).__name__,
                str(exc)[:300],
            )
        finally:
            self._close_stream(sid, notify=True, reason=close_reason)

    def _close_stream(self, sid: str, *, notify: bool, reason: str = "") -> None:
        with self._streams_lock:
            sock = self._streams.pop(sid, None)
        if sock is not None:
            try: sock.shutdown(socket.SHUT_RDWR)
            except Exception: pass
            try: sock.close()
            except Exception: pass
        if notify and self._ws is not None:
            try:
                self._ws.send_json({
                    "type": "close",
                    "stream_id": sid,
                    "reason": str(reason or "AGENT_STREAM_CLOSED")[:200],
                })
            except Exception: pass
        LOG.info(
            "reverse tunnel agent stream closed agent=%s stream=%s reason=%s",
            self.agent_id,
            str(sid)[:12],
            str(reason or "PEER_CLOSED")[:120],
        )

    def _handle_binary(self, payload: bytes) -> None:
        if len(payload) < _STREAM_ID_BYTES:
            return
        try:
            sid = payload[:_STREAM_ID_BYTES].decode("ascii")
        except Exception:
            return
        data = payload[_STREAM_ID_BYTES:]
        with self._streams_lock:
            sock = self._streams.get(sid)
        if sock is None:
            return
        try:
            if data:
                sock.sendall(data)
        except Exception as exc:
            self._close_stream(sid, notify=True, reason=f"LOCAL_TARGET_WRITE_FAILED:{type(exc).__name__}")

    def _run_connection(self) -> None:
        ws = self._connect_ws()
        connected_at = time.monotonic()
        self._last_connection_uptime = 0.0
        self._ws = ws
        self._status("ONLINE")
        ws.send_json({"type": "hello", "version": TUNNEL_VERSION, "agent_id": self.agent_id})
        last_ping = time.monotonic()
        try:
            while not self._stop.is_set():
                if time.monotonic() - last_ping >= 20.0:
                    ws.send_ping(b"gideon")
                    last_ping = time.monotonic()
                try:
                    opcode, payload = ws.recv_frame()
                except socket.timeout:
                    continue
                if opcode == 0x8:
                    break
                if opcode == 0xA:
                    continue
                if opcode == 0x1:
                    value = json.loads(payload.decode("utf-8"))
                    if not isinstance(value, dict):
                        continue
                    typ = str(value.get("type") or "")
                    if typ == "open":
                        self._open_stream(ws, value)
                    elif typ == "close":
                        self._close_stream(
                            str(value.get("stream_id") or ""),
                            notify=False,
                            reason=str(value.get("reason") or "GATEWAY_REQUESTED_CLOSE"),
                        )
                elif opcode == 0x2:
                    self._handle_binary(payload)
        finally:
            self._last_connection_uptime = max(0.0, time.monotonic() - connected_at)
            self._close_all_streams()
            ws.close_socket()
            if self._ws is ws:
                self._ws = None

    def _run(self) -> None:
        delay = 1.0
        while not self._stop.is_set():
            try:
                self._status("CONNECTING")
                self._run_connection()
                if not self._stop.is_set():
                    self._status("DISCONNECTED", "Gateway closed reverse tunnel")
            except Exception as exc:
                LOG.warning(
                    "reverse tunnel control channel failed agent=%s error=%s: %s",
                    self.agent_id,
                    type(exc).__name__,
                    str(exc)[:300],
                )
                self._status("ERROR", f"{type(exc).__name__}: {exc}")
            if self._stop.wait(delay):
                break
            # A channel that stayed healthy was not a repeated startup failure.
            # Reset the retry delay so a transient NAT/proxy reset recovers in
            # one second instead of inheriting a stale 30-second backoff.
            if self._last_connection_uptime >= 20.0:
                delay = 1.0
            else:
                delay = min(delay * 1.7, 30.0)
        self._status("STOPPED")
