#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import getpass
import os
from pathlib import Path

import uvicorn

from gideon_web_admin.app import create_app, load_web_config
from gideon_web_admin.auth import SecurityStore
from gideon_version import PRODUCT_VERSION


def _configure_windows_event_loop() -> None:
    """Use SelectorEventLoop on Windows for the WebAdmin socket server.

    Python's Proactor transport can emit noisy unhandled WinError 10054 callback
    tracebacks when browsers/proxies reset TLS connections.  WebAdmin does not
    require asyncio subprocess pipes, so the selector policy is a safer fit for
    this HTTP/WebSocket workload and keeps client disconnects isolated.
    """
    if os.name != "nt":
        return
    policy_type = getattr(asyncio, "WindowsSelectorEventLoopPolicy", None)
    if policy_type is not None:
        asyncio.set_event_loop_policy(policy_type())


def main() -> int:
    parser = argparse.ArgumentParser(description=f"GIDEON Remote Control Web Admin {PRODUCT_VERSION}")
    parser.add_argument("--config", default=os.environ.get("GIDEON_WEB_ADMIN_CONFIG") or str(Path(__file__).resolve().parent / "config" / "web_admin.json"))
    parser.add_argument("--init-admin", action="store_true", help="Crear el primer SuperAdmin desde consola")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--display-name", default="Administrador GIDEON")
    args = parser.parse_args()
    cfg = load_web_config(Path(args.config))
    data_dir = Path(os.path.expandvars(str(cfg.get("data_dir") or "/var/lib/gideon-web-admin"))).expanduser().resolve()
    if args.init_admin:
        store = SecurityStore(data_dir / "security.sqlite3")
        if store.user_count() > 0:
            raise SystemExit("Ya existe al menos un usuario.")
        password = getpass.getpass("Contraseña inicial: ")
        confirm = getpass.getpass("Confirmar contraseña: ")
        if password != confirm:
            raise SystemExit("Las contraseñas no coinciden.")
        store.bootstrap_admin(args.username, password, args.display_name)
        print(f"SuperAdmin creado: {args.username}")
        return 0
    _configure_windows_event_loop()
    app = create_app(args.config)
    certfile = str(cfg.get("tls_certfile") or "").strip() or None
    keyfile = str(cfg.get("tls_keyfile") or "").strip() or None
    direct_tls = bool(certfile and keyfile and Path(certfile).is_file() and Path(keyfile).is_file())
    listen_host = str(cfg.get("listen_host") or "127.0.0.1")
    if not direct_tls:
        if listen_host not in {"127.0.0.1", "::1", "localhost"}:
            raise SystemExit("Web Admin expuesto fuera de loopback requiere tls_certfile/tls_keyfile válidos.")
        certfile = None
        keyfile = None
    uvicorn.run(
        app,
        host=listen_host,
        port=int(cfg.get("listen_port") or 28443),
        proxy_headers=bool(cfg.get("trust_proxy_headers", False)),
        forwarded_allow_ips=str(cfg.get("forwarded_allow_ips") or "127.0.0.1"),
        access_log=bool(cfg.get("access_log", True)),
        server_header=False,
        ssl_certfile=certfile,
        ssl_keyfile=keyfile,
        ssl_ciphers="ECDHE+AESGCM:ECDHE+CHACHA20",
        backlog=int(cfg.get("web_backlog", 512) or 512),
        limit_concurrency=int(cfg.get("web_max_concurrency", 256) or 256),
        timeout_keep_alive=int(cfg.get("web_keepalive_seconds", 10) or 10),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
