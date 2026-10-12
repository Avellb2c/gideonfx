#!/usr/bin/env python3
from __future__ import annotations

"""Run an operator-authorized, ephemeral RDP probe through the live GIDEON path.

The remote password is read without echo from stdin and is never written to a
file, command line, environment variable, diagnostic record, or program output.
Only Guacamole protocol metadata and timing counters are emitted.
"""

import argparse
import asyncio
import base64
import collections
import getpass
import json
import os
import sys
import time
from pathlib import Path
from typing import Any


def emit(event: str, **fields: Any) -> None:
    print(json.dumps({"event": event, **fields}, ensure_ascii=False), flush=True)


async def run(args: argparse.Namespace) -> int:
    app_root = args.app_root.resolve()
    sys.path.insert(0, str(app_root))

    from gideon_web_admin.app import load_web_config, normalize_session_policy
    from gideon_web_admin.gateway import GatewayFacade
    from gideon_web_admin.guacamole import (
        GuacdClient,
        GuacdConfig,
        guac_instruction,
        parse_guac_instruction,
    )

    config = normalize_session_policy(load_web_config(args.config.resolve()))
    gateway = GatewayFacade(config)
    guacd = GuacdClient(GuacdConfig.from_config(config))

    password = getpass.getpass("Remote Windows password (not stored): ")
    if not password:
        raise RuntimeError("REMOTE_PASSWORD_EMPTY")

    started_wall = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    started = time.monotonic()
    emit(
        "probe.started",
        started_utc=started_wall,
        agent_id=args.agent_id,
        username=args.username,
        domain=args.domain,
        security=args.security,
        session_mode=args.session_mode,
    )

    reservation = await asyncio.to_thread(
        gateway.open_reverse_tunnel,
        args.agent_id,
        protocol="RDP",
    )
    target_host = str(reservation.get("BrokerHost") or "").strip()
    target_port = int(reservation.get("BrokerPort") or 0)
    tunnel_id = str(reservation.get("TunnelId") or "")
    if not target_host or not 1 <= target_port <= 65535:
        raise RuntimeError("INVALID_TUNNEL_RESERVATION")
    emit(
        "tunnel.reserved",
        elapsed_ms=round((time.monotonic() - started) * 1000),
        tunnel_id=tunnel_id,
        broker_host=target_host,
        broker_port=target_port,
    )

    credential = {
        "username": args.username,
        "password": password,
        "domain": args.domain,
        "keyboard_layout": "es-latam-qwerty",
    }
    password = ""
    reader = writer = parser = None
    try:
        reader, writer, parser, connection_id = await guacd.connect_and_handshake(
            protocol="rdp",
            target_host=target_host,
            target_port=target_port,
            credential=credential,
            width=args.width,
            height=args.height,
            dpi=96,
            timezone="America/Lima",
            session_id="diag-" + str(int(time.time())),
            clipboard_enabled=False,
            file_transfer_enabled=False,
            rdp_security=args.security,
            rdp_session_mode=args.session_mode,
        )
    finally:
        credential.clear()

    emit(
        "guacd.ready",
        elapsed_ms=round((time.monotonic() - started) * 1000),
        connection_id=connection_id,
    )

    counts: collections.Counter[str] = collections.Counter()
    graphics = {"first_ms": None, "last_ms": None}
    switch_confirmed = False
    last_progress = 0.0
    last_keepalive = 0.0
    error_detail = ""
    deadline = started + args.duration
    capture_dir = args.capture_dir.resolve() if args.capture_dir else None
    capture_sequence = 0
    capture_streams: dict[str, dict[str, Any]] = {}
    capture_manifest = None
    if capture_dir is not None:
        capture_dir.mkdir(parents=True, exist_ok=True)
        capture_manifest = (capture_dir / "protocol.jsonl").open("w", encoding="utf-8")

    def capture_record(parts: list[str], **extra: Any) -> None:
        nonlocal capture_sequence
        if capture_manifest is None:
            return
        capture_sequence += 1
        capture_manifest.write(json.dumps({
            "sequence": capture_sequence,
            "elapsed_ms": round((time.monotonic() - started) * 1000),
            "parts": parts,
            **extra,
        }, ensure_ascii=False) + "\n")
        capture_manifest.flush()

    async def process(raw: str) -> bool:
        nonlocal switch_confirmed, error_detail
        parts = parse_guac_instruction(raw)
        opcode = parts[0] if parts else ""
        counts[opcode] += 1
        now = time.monotonic()
        if opcode == "img" and len(parts) >= 7 and capture_dir is not None:
            capture_streams[str(parts[1])] = {"parts": parts, "data": bytearray()}
            capture_record(parts)
        elif opcode == "blob" and len(parts) >= 3 and str(parts[1]) in capture_streams:
            try:
                capture_streams[str(parts[1])]["data"].extend(base64.b64decode(parts[2], validate=True))
            except Exception:
                capture_record(["capture-error", "invalid-image-blob", str(parts[1])])
        elif opcode == "end" and len(parts) >= 2 and str(parts[1]) in capture_streams and capture_dir is not None:
            stream = capture_streams.pop(str(parts[1]))
            suffix = ".jpg" if "jpeg" in str(stream["parts"][2]).lower() else ".png"
            filename = f"image-{capture_sequence + 1:06d}{suffix}"
            (capture_dir / filename).write_bytes(bytes(stream["data"]))
            capture_record(["image-data", filename], image_parts=stream["parts"])
        elif opcode not in {"blob", "end", "sync", "nop", "ack", "audio"}:
            # The manifest intentionally excludes arbitrary stream payloads.
            capture_record(parts)
        if opcode in {"size", "rect", "cfill", "copy", "png", "jpeg", "img", "video", "blob"}:
            elapsed_ms = round((now - started) * 1000)
            if graphics["first_ms"] is None:
                graphics["first_ms"] = elapsed_ms
                emit("graphics.first", elapsed_ms=elapsed_ms, opcode=opcode)
            graphics["last_ms"] = elapsed_ms
        if opcode == "sync":
            timestamp = parts[1] if len(parts) > 1 else ""
            writer.write(guac_instruction("sync", timestamp).encode("utf-8"))
            await writer.drain()
        elif opcode == "error":
            message = str(parts[1] if len(parts) > 1 else "guacd remote error")[:500]
            code = str(parts[2] if len(parts) > 2 else "")[:40]
            error_detail = f"{message} ({code})"
            emit("guacd.error", elapsed_ms=round((now - started) * 1000), message=message, code=code)
            return False
        elif opcode == "disconnect":
            emit("guacd.disconnect", elapsed_ms=round((now - started) * 1000))
            return False
        return True

    keep_running = True
    try:
        while keep_running and time.monotonic() < deadline:
            pending = parser.drain_pending()
            if not pending:
                timeout = min(1.0, max(0.05, deadline - time.monotonic()))
                try:
                    chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout)
                except asyncio.TimeoutError:
                    chunk = b""
                if chunk:
                    parser.feed(chunk)
                    pending = parser.drain_pending()
                elif reader.at_eof():
                    emit("guacd.eof", elapsed_ms=round((time.monotonic() - started) * 1000))
                    break

            for raw in pending:
                if not await process(raw):
                    keep_running = False
                    break

            elapsed = time.monotonic() - started
            # Match guacamole-common-js tunnel semantics. A quiet Windows frame
            # may produce no new sync instructions; a client-side nop prevents
            # guacd from treating that perfectly valid idle interval as an
            # unresponsive viewer after roughly 15 seconds.
            if elapsed - last_keepalive >= 4.0:
                writer.write(guac_instruction("nop").encode("utf-8"))
                await writer.drain()
                last_keepalive = elapsed
            # The user explicitly authorized accepting Windows' exact
            # "sign in anyway / switch session" prompt. Wait for a real frame
            # and the configured arbitration interval, then press Return once.
            if (
                not switch_confirmed
                and (graphics["first_ms"] is not None or args.confirm_without_graphics)
                and (
                    (
                        args.confirm_on_late_graphics
                        and graphics["last_ms"] is not None
                        and int(graphics["last_ms"]) >= args.confirm_switch_after * 1000
                    )
                    or (
                        not args.confirm_on_late_graphics
                        and elapsed >= args.confirm_switch_after
                    )
                )
            ):
                method = "RETURN_KEY_ON_AUTHORIZED_WINDOWS_PROMPT"
                if args.confirm_mode == "tab-enter":
                    writer.write(guac_instruction("key", 65289, 1).encode("utf-8"))
                    writer.write(guac_instruction("key", 65289, 0).encode("utf-8"))
                    await writer.drain()
                    await asyncio.sleep(0.5)
                    method = "TAB_THEN_RETURN_ON_AUTHORIZED_WINDOWS_PROMPT"
                writer.write(guac_instruction("key", 65293, 1).encode("utf-8"))
                writer.write(guac_instruction("key", 65293, 0).encode("utf-8"))
                await writer.drain()
                switch_confirmed = True
                emit(
                    "session_switch.confirmed",
                    elapsed_ms=round(elapsed * 1000),
                    method=method,
                )

            if elapsed - last_progress >= 5.0:
                last_progress = elapsed
                emit(
                    "probe.progress",
                    elapsed_ms=round(elapsed * 1000),
                    sync=counts.get("sync", 0),
                    graphics=sum(counts.get(x, 0) for x in ("size", "rect", "cfill", "copy", "png", "jpeg", "img", "video", "blob")),
                    last_graphics_ms=graphics["last_ms"],
                    switch_confirmed=switch_confirmed,
                )
    finally:
        if writer is not None:
            try:
                writer.write(guac_instruction("disconnect").encode("utf-8"))
                await writer.drain()
            except Exception:
                pass
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        if capture_manifest is not None:
            capture_manifest.close()

    emit(
        "probe.finished",
        finished_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        elapsed_ms=round((time.monotonic() - started) * 1000),
        switch_confirmed=switch_confirmed,
        graphics_first_ms=graphics["first_ms"],
        graphics_last_ms=graphics["last_ms"],
        opcodes=dict(sorted(counts.items())),
        error=error_detail,
    )
    return 0 if graphics["first_ms"] is not None and not error_detail else 2


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--app-root", type=Path, default=Path("/opt/gideon/web/app"))
    parser.add_argument("--config", type=Path, default=Path("/etc/gideon/web/web_admin.json"))
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--domain", default="")
    parser.add_argument("--security", choices=("nla", "any", "tls", "rdp"), default="nla")
    parser.add_argument("--session-mode", choices=("STANDARD", "RESUME", "ADMIN", "SEPARATE"), default="RESUME")
    parser.add_argument("--duration", type=int, default=120)
    parser.add_argument("--confirm-switch-after", type=int, default=45)
    parser.add_argument("--confirm-without-graphics", action="store_true")
    parser.add_argument("--confirm-on-late-graphics", action="store_true")
    parser.add_argument("--confirm-mode", choices=("enter", "tab-enter"), default="enter")
    parser.add_argument("--width", type=int, default=1440)
    parser.add_argument("--height", type=int, default=900)
    parser.add_argument("--capture-dir", type=Path)
    args = parser.parse_args()
    return asyncio.run(run(args))


if __name__ == "__main__":
    raise SystemExit(main())
