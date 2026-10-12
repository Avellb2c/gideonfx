from __future__ import annotations

"""Apache Guacamole (guacd) integration for GIDEON WebAdmin.

Only guacd is required.  The browser talks WSS to WebAdmin; WebAdmin performs
Guacamole's guacd handshake using server-side credentials and then bridges
Guacamole protocol instructions.  Port 4822 is expected to be loopback/private
and is never exposed to the browser.
"""

import asyncio
import codecs
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import socket
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class GuacamoleError(RuntimeError):
    pass


MAX_GUAC_INSTRUCTION_CHARS = 8 * 1024 * 1024
MAX_GUAC_CLIENT_JS_BYTES = 4 * 1024 * 1024


def guac_instruction(*elements: Any) -> str:
    encoded: list[str] = []
    for value in elements:
        text = str(value if value is not None else "")
        encoded.append(f"{len(text)}.{text}")
    return ",".join(encoded) + ";"


def parse_guac_instruction(raw: str) -> list[str]:
    """Parse exactly one Guacamole protocol instruction."""
    text = str(raw or "")
    if not text.endswith(";"):
        raise GuacamoleError("InstrucciÃƒÂ³n Guacamole incompleta.")
    values: list[str] = []
    pos = 0
    limit = len(text)
    while pos < limit:
        dot = text.find(".", pos)
        if dot <= pos:
            raise GuacamoleError("Longitud Guacamole invÃƒÂ¡lida.")
        length_text = text[pos:dot]
        if not length_text.isdigit():
            raise GuacamoleError("Prefijo de longitud Guacamole invÃƒÂ¡lido.")
        length = int(length_text)
        if length > MAX_GUAC_INSTRUCTION_CHARS:
            raise GuacamoleError("Elemento Guacamole demasiado grande.")
        start = dot + 1
        end = start + length
        if end > limit:
            raise GuacamoleError("Elemento Guacamole truncado.")
        values.append(text[start:end])
        if end >= limit:
            raise GuacamoleError("Terminador Guacamole ausente.")
        sep = text[end]
        if sep == ";":
            if end != limit - 1:
                raise GuacamoleError("Datos posteriores al terminador Guacamole.")
            return values
        if sep != ",":
            raise GuacamoleError("Separador Guacamole invÃƒÂ¡lido.")
        pos = end + 1
    raise GuacamoleError("InstrucciÃƒÂ³n Guacamole vacÃƒÂ­a.")


class GuacamoleStreamParser:
    """Incrementally splits a UTF-8 guacd TCP stream into full instructions."""

    def __init__(self) -> None:
        self._decoder = codecs.getincrementaldecoder("utf-8")("strict")
        self._buffer = ""
        self._pending: list[str] = []

    def feed(self, data: bytes) -> list[str]:
        try:
            self._buffer += self._decoder.decode(bytes(data), final=False)
        except UnicodeDecodeError as exc:
            raise GuacamoleError("guacd enviÃƒÂ³ UTF-8 invÃƒÂ¡lido.") from exc
        if len(self._buffer) > MAX_GUAC_INSTRUCTION_CHARS * 2:
            raise GuacamoleError("Buffer Guacamole excediÃƒÂ³ el lÃƒÂ­mite seguro.")
        out: list[str] = []
        while True:
            end = self._instruction_end(self._buffer)
            if end is None:
                break
            raw = self._buffer[:end]
            parse_guac_instruction(raw)
            out.append(raw)
            self._pending.append(raw)
            self._buffer = self._buffer[end:]
        return out

    def pop(self) -> str | None:
        return self._pending.pop(0) if self._pending else None

    def drain_pending(self) -> list[str]:
        rows = list(self._pending)
        self._pending.clear()
        return rows

    @staticmethod
    def _instruction_end(text: str) -> int | None:
        if not text:
            return None
        pos = 0
        limit = len(text)
        while True:
            dot = text.find(".", pos)
            if dot < 0:
                return None
            prefix = text[pos:dot]
            if not prefix or not prefix.isdigit():
                raise GuacamoleError("Prefijo de longitud Guacamole invÃƒÂ¡lido en stream.")
            length = int(prefix)
            if length > MAX_GUAC_INSTRUCTION_CHARS:
                raise GuacamoleError("Elemento Guacamole demasiado grande.")
            end = dot + 1 + length
            if end >= limit:
                return None
            sep = text[end]
            if sep == ";":
                return end + 1
            if sep != ",":
                raise GuacamoleError("Separador Guacamole invÃƒÂ¡lido en stream.")
            pos = end + 1


@dataclass(frozen=True, slots=True)
class GuacdConfig:
    host: str = "127.0.0.1"
    port: int = 4822
    connect_timeout_seconds: float = 5.0
    handshake_timeout_seconds: float = 12.0
    rdp_security: str = "nla"
    rdp_ignore_cert: bool = True
    rdp_disable_copy: bool = True
    rdp_disable_paste: bool = True
    vnc_enabled: bool = False

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> "GuacdConfig":
        raw = dict((config.get("remote_sessions") or {}).get("guacd") or {})
        host = str(raw.get("host") or "127.0.0.1").strip()
        # guacd is infrastructure configuration, never browser-controlled.
        # Reject URLs/control characters and reject a literal public IP. DNS
        # hostnames are resolved again immediately before each connection and
        # all resolved peers must be loopback/private.
        if not host or any(ord(ch) < 32 for ch in host) or "://" in host or "/" in host or "\\" in host:
            raise GuacamoleError("Host guacd invÃƒÂ¡lido.")
        try:
            literal = ipaddress.ip_address(host.split("%", 1)[0])
        except ValueError:
            literal = None
        if literal is not None and not (literal.is_loopback or literal.is_private):
            raise GuacamoleError("GUACD_HOST_MUST_BE_LOOPBACK_OR_PRIVATE")
        security = str(raw.get("rdp_security") or "nla").strip().lower()
        if security not in {"any", "nla", "tls", "rdp"}:
            security = "nla"
        return cls(
            host=host,
            port=max(1, min(int(raw.get("port", 4822)), 65535)),
            connect_timeout_seconds=max(0.5, min(float(raw.get("connect_timeout_seconds", 5.0)), 20.0)),
            handshake_timeout_seconds=max(2.0, min(float(raw.get("handshake_timeout_seconds", 12.0)), 60.0)),
            rdp_security=security,
            rdp_ignore_cert=bool(raw.get("rdp_ignore_cert", False)),
            rdp_disable_copy=bool(raw.get("rdp_disable_copy", True)),
            rdp_disable_paste=bool(raw.get("rdp_disable_paste", True)),
            vnc_enabled=bool(raw.get("vnc_enabled", False)),
        )


class GuacamoleClientAssetStore:
    """Managed, operator-provisioned guacamole-common-js asset.

    The RC package intentionally does not silently download third-party JS at
    runtime.  A SUPERADMIN uploads the pinned upstream asset once; WebAdmin
    validates the expected Guacamole API surface and stores its SHA-256.
    """

    REQUIRED_MARKERS = (b"Guacamole.Client", b"Guacamole.WebSocketTunnel")

    def __init__(self, data_dir: Path) -> None:
        self.root = (Path(data_dir).resolve() / "remote-client").resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.asset = self.root / "guacamole-common.min.js"
        self.metadata = self.root / "metadata.json"
        try:
            os.chmod(self.root, 0o750)
        except OSError:
            pass

    def status(self) -> dict[str, Any]:
        if not self.asset.is_file():
            return {"ready": False, "version": "", "sha256": "", "size_bytes": 0, "path": str(self.asset)}
        data = self.asset.read_bytes()
        meta: dict[str, Any] = {}
        try:
            raw = json.loads(self.metadata.read_text(encoding="utf-8-sig"))
            if isinstance(raw, dict):
                meta = dict(raw)
        except Exception:
            pass
        return {
            "ready": all(marker in data for marker in self.REQUIRED_MARKERS),
            "version": str(meta.get("version") or ""),
            "sha256": hashlib.sha256(data).hexdigest(),
            "size_bytes": len(data),
            "path": str(self.asset),
            "updated_at": str(meta.get("updated_at") or ""),
        }

    def install(self, content: bytes, *, version: str = "", expected_sha256: str = "") -> dict[str, Any]:
        data = bytes(content or b"")
        if not data or len(data) > MAX_GUAC_CLIENT_JS_BYTES:
            raise GuacamoleError("guacamole-common-js estÃƒÂ¡ vacÃƒÂ­o o excede 4 MiB.")
        if not all(marker in data for marker in self.REQUIRED_MARKERS):
            raise GuacamoleError(
                "El archivo no expone Guacamole.Client y Guacamole.WebSocketTunnel; cargue el bundle oficial guacamole-common-js."
            )
        actual = hashlib.sha256(data).hexdigest()
        expected = re.sub(r"[^0-9a-f]", "", str(expected_sha256 or "").lower())
        if expected and (len(expected) != 64 or expected != actual):
            raise GuacamoleError(f"SHA-256 del cliente Guacamole no coincide. Actual={actual}")
        fd, tmp_name = tempfile.mkstemp(prefix=".guacamole-client-", suffix=".js", dir=str(self.root))
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_name, self.asset)
        finally:
            try:
                if os.path.exists(tmp_name):
                    os.unlink(tmp_name)
            except OSError:
                pass
        try:
            os.chmod(self.asset, 0o640)
        except OSError:
            pass
        meta = {
            "version": str(version or "").strip()[:80],
            "sha256": actual,
            "size_bytes": len(data),
            "updated_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        }
        self.metadata.write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        try:
            os.chmod(self.metadata, 0o640)
        except OSError:
            pass
        return self.status()


class GuacdClient:
    def __init__(self, config: GuacdConfig) -> None:
        self.config = config

    def _validate_peer(self) -> None:
        try:
            info = socket.getaddrinfo(self.config.host, self.config.port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise GuacamoleError(f"GUACD_DNS_FAILED: {self.config.host}") from exc
        addresses = []
        for row in info:
            try:
                address = ipaddress.ip_address(str(row[4][0]).split("%", 1)[0])
            except (ValueError, IndexError):
                continue
            if address not in addresses:
                addresses.append(address)
        if not addresses or not all(address.is_loopback or address.is_private for address in addresses):
            raise GuacamoleError("GUACD_HOST_MUST_BE_LOOPBACK_OR_PRIVATE")

    def health(self, timeout: float = 1.5) -> dict[str, Any]:
        started = time.monotonic()
        try:
            self._validate_peer()
            with socket.create_connection((self.config.host, self.config.port), timeout=float(timeout)):
                elapsed = max(0, int((time.monotonic() - started) * 1000))
                return {"online": True, "host": self.config.host, "port": self.config.port, "latency_ms": elapsed}
        except (OSError, GuacamoleError) as exc:
            return {
                "online": False,
                "host": self.config.host,
                "port": self.config.port,
                "error": f"{type(exc).__name__}: {exc}",
            }

    async def connect_and_handshake(
        self,
        *,
        protocol: str,
        target_host: str,
        target_port: int,
        credential: dict[str, str],
        width: int = 1440,
        height: int = 900,
        dpi: int = 96,
        timezone: str = "America/Lima",
        session_id: str = "",
        clipboard_enabled: bool = False,
        file_transfer_enabled: bool = False,
        rdp_security: str = "",
        rdp_session_mode: str = "STANDARD",
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, GuacamoleStreamParser, str]:
        proto = str(protocol or "").strip().lower()
        if proto not in {"rdp", "vnc"}:
            raise GuacamoleError("Protocolo remoto no soportado por GIDEON.")
        if proto == "vnc" and not self.config.vnc_enabled:
            raise GuacamoleError("VNC estÃƒÂ¡ deshabilitado por polÃƒÂ­tica. HabilÃƒÂ­telo explÃƒÂ­citamente si la red es confiable/VPN.")

        try:
            await asyncio.to_thread(self._validate_peer)
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.config.host, self.config.port),
                timeout=self.config.connect_timeout_seconds,
            )
        except Exception as exc:
            raise GuacamoleError(f"GUACD_UNAVAILABLE: no se pudo conectar a guacd: {type(exc).__name__}: {exc}") from exc

        parser = GuacamoleStreamParser()
        try:
            writer.write(guac_instruction("select", proto).encode("utf-8"))
            await writer.drain()
            raw_args = await asyncio.wait_for(self._read_one(reader, parser), timeout=self.config.handshake_timeout_seconds)
            args = parse_guac_instruction(raw_args)
            if not args or args[0] != "args":
                raise GuacamoleError(f"GUACD_HANDSHAKE: se esperaba args y se recibiÃƒÂ³ {args[0] if args else '<vacÃƒÂ­o>'}.")
            arg_names = args[1:]

            # Device redirection stays session-scoped. Clipboard and the
            # temporary RDP drive are enabled only when the signed server-side
            # session row authorizes those capabilities.
            for instruction in (
                guac_instruction("size", max(320, min(int(width), 7680)), max(240, min(int(height), 4320)), max(72, min(int(dpi), 240))),
                guac_instruction("audio", "audio/L8", "audio/L16"),
                guac_instruction("video"),
                guac_instruction("image", "image/png", "image/jpeg", "image/webp"),
                guac_instruction("timezone", str(timezone or "America/Lima")[:80]),
            ):
                writer.write(instruction.encode("utf-8"))
            await writer.drain()

            values = self._connection_values(
                proto,
                target_host=str(target_host),
                target_port=int(target_port),
                credential=credential,
                width=width,
                height=height,
                dpi=dpi,
                session_id=session_id,
                clipboard_enabled=clipboard_enabled,
                file_transfer_enabled=file_transfer_enabled,
                rdp_security=rdp_security,
                rdp_session_mode=rdp_session_mode,
            )
            connect_values = [values.get(name, "") for name in arg_names]
            writer.write(guac_instruction("connect", *connect_values).encode("utf-8"))
            await writer.drain()
            ready_raw = await asyncio.wait_for(self._read_one(reader, parser), timeout=self.config.handshake_timeout_seconds)
            ready = parse_guac_instruction(ready_raw)
            if not ready:
                raise GuacamoleError("GUACD_HANDSHAKE: respuesta ready vacÃƒÂ­a.")
            if ready[0] == "error":
                message = ready[1] if len(ready) > 1 else "guacd rechazÃƒÂ³ la conexiÃƒÂ³n"
                code = ready[2] if len(ready) > 2 else ""
                raise GuacamoleError(f"GUACD_REMOTE_ERROR: {message} ({code})")
            if ready[0] != "ready":
                raise GuacamoleError(f"GUACD_HANDSHAKE: se esperaba ready y se recibiÃƒÂ³ {ready[0]}.")
            connection_id = ready[1] if len(ready) > 1 else ""
            return reader, writer, parser, connection_id
        except Exception:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            raise

    @staticmethod
    async def _read_one(reader: asyncio.StreamReader, parser: GuacamoleStreamParser) -> str:
        pending = parser.pop()
        if pending is not None:
            return pending
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                raise GuacamoleError("guacd cerrÃƒÂ³ la conexiÃƒÂ³n durante el handshake.")
            parser.feed(chunk)
            pending = parser.pop()
            if pending is not None:
                return pending

    def _connection_values(
        self,
        protocol: str,
        *,
        target_host: str,
        target_port: int,
        credential: dict[str, str],
        width: int,
        height: int,
        dpi: int,
        session_id: str = "",
        clipboard_enabled: bool = False,
        file_transfer_enabled: bool = False,
        rdp_security: str = "",
        rdp_session_mode: str = "STANDARD",
    ) -> dict[str, str]:
        common = {
            "hostname": str(target_host),
            "port": str(int(target_port)),
            "username": str(credential.get("username") or ""),
            "password": str(credential.get("password") or ""),
            "domain": str(credential.get("domain") or ""),
            "server-layout": str(credential.get("keyboard_layout") or ""),

            "width": str(max(320, int(width))),
            "height": str(max(240, int(height))),
            "dpi": str(max(72, int(dpi))),
            "read-only": "false",
        }
        if protocol == "rdp":
            safe_session_id = re.sub(r"[^A-Za-z0-9_-]", "", str(session_id or ""))[:96]
            drive_enabled = bool(file_transfer_enabled and safe_session_id)
            effective_security = str(rdp_security or self.config.rdp_security or "nla").strip().lower()
            if effective_security not in {"any", "nla", "tls", "rdp"}:
                effective_security = "nla"
            effective_session_mode = str(rdp_session_mode or "STANDARD").strip().upper()
            if effective_session_mode not in {"STANDARD", "RESUME", "ADMIN", "SEPARATE"}:
                effective_session_mode = "STANDARD"
            # RC13.6 RDP Resilience:
            # - Mantiene seguridad configurable.
            # - Ignora certificados cuando la polÃƒÂ­tica lo habilita.
            # - Mejora compatibilidad con Windows Server/Windows 10/11.
            # - Reduce fallos por certificados autofirmados en sedes.
            common.update({
                "security": effective_security,
                # Guacamole's console parameter selects the administrative
                # console session. Standard/resume/separate all use normal RDP
                # logon semantics; Windows decides whether an existing session
                # is resumed from the supplied account and host policy.
                "console": "true" if effective_session_mode == "ADMIN" else "false",
                "ignore-cert": "true",
                "disable-auth": "false",
                "enable-printing": "false",
                "enable-drive": "true" if drive_enabled else "false",
                "drive-name": "GIDEON Transfer",
                "drive-path": f"/tmp/gideon-transfer-{safe_session_id}" if drive_enabled else "",
                "create-drive-path": "true" if drive_enabled else "false",
                "enable-sftp": "false",
                "disable-audio": "true",
                "enable-audio-input": "false",
                "disable-copy": "false" if clipboard_enabled else "true",
                "disable-paste": "false" if clipboard_enabled else "true",
                "enable-wallpaper": "false",
                "enable-theming": "false",
                "enable-font-smoothing": "false",
                "enable-full-window-drag": "false",
                "enable-desktop-composition": "false",
                "enable-menu-animations": "false",
                # The browser scales the Guacamole display locally.  Asking
                # FreeRDP to resize an existing xorgxrdp desktop can leave the
                # guacd child spinning at 100% CPU after xrdp closes its RDP
                # socket (the browser then keeps showing one frozen frame).
                # Keep the negotiated desktop size stable for the lifetime of
                # the connection; a new session uses the current viewport.
                # Guacamole's documented no-resize mode is omission of the
                # parameter. The literal value "none" is invalid.
                "color-depth": "16",

                # RC30.95.42 constrained-host profile:
                # Keep the broadly-compatible legacy graphics path, but permit
                # FreeRDP's caches and lossy bitmap encoding.  This materially
                # reduces CPU/bandwidth during Windows profile initialization on
                # small VMs while the browser-side image fallback protects sync.
                #
                # Guacd supplies the accepted argument names dynamically. Unknown
                # keys here are never sent because connect_values is built strictly
                # from guacd's "args" response.
                "disable-gfx": "true",
                "disable-bitmap-caching": "false",
                "disable-offscreen-caching": "false",
                "disable-glyph-caching": "false",
                "force-lossless": "false",
            })
        else:
            common.update({
                "color-depth": "16",
                # A physical WayVNC desktop has a real, fixed output owned by
                # the local compositor.  Guacamole otherwise tries to request
                # the browser dimensions over VNC at connection time.  That
                # is not autoscaling: it is a server-side resize request and
                # can destabilize Raspberry Pi Connect's protected WayVNC
                # socket.  GIDEON always fits this surface in the browser, so
                # keep the remote output immutable for the session.
                "disable-display-resize": "true",
                # Omit Guacamole's optional ``cursor=remote`` flag.  The local
                # cursor is the VNC default and avoids asking WayVNC to redraw
                # the framebuffer for every physical-console mouse movement.
                "swap-red-blue": "false",
            })
        return common
