#!/usr/bin/env python3
from __future__ import annotations

try:
    from gideon_common.observability import best_effort_warning
except ModuleNotFoundError:
    # Standalone/self-heal fallback: an older installation may be missing the
    # shared desktop package.  The new installer still ships gideon_common, but
    # this keeps network/security startup alive long enough to repair it.
    import logging
    def best_effort_warning(context, exc, *args):
        if args:
            context = str(context).format(*args)
        logging.getLogger("gideon.agent").warning("%s: %s", context, exc)

import json
import os
import shutil
import ssl
import tempfile
from pathlib import Path
from typing import Any, Optional
from urllib import request, error

from gideon_common.tls import gideon_private_ca_context

VERSION = "2.0.0"


class AgentHttpError(RuntimeError):
    pass


def build_ssl_context(
    *,
    verify_tls: bool = True,
    ca_file: Optional[str] = None,
    client_cert: Optional[str] = None,
    client_key: Optional[str] = None,
    minimum_tls: str = "TLSv1.2",
) -> ssl.SSLContext:
    if verify_tls:
        if ca_file:
            # GIDEON private-PKI mode: trust the CA embedded with the agent itself.
            # The GIDEON root is NOT imported into the operating-system Trusted Root
            # store, so deployment does not need that administrative trust step.
            ctx = gideon_private_ca_context(
                ca_file, client_cert=client_cert, client_key=client_key
            )
        else:
            # Public-PKI mode: use the normal operating-system trust store.
            ctx = ssl.create_default_context()
    else:
        ctx = ssl._create_unverified_context()  # noqa: SLF001

    # Baseline moderno ampliamente soportado: TLS 1.2 mínimo y TLS 1.3
    # negociado automáticamente cuando cliente/servidor lo soportan.
    if hasattr(ssl, "TLSVersion"):
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        ctx.set_ciphers(
            "ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!eNULL:!MD5:!3DES:!RC4"
        )
    except Exception as exc:
        best_effort_warning("La política preferida de cifrados TLS no pudo aplicarse; se usan los defaults seguros de Python", exc)

    if client_cert and not (verify_tls and ca_file):
        ctx.load_cert_chain(certfile=client_cert, keyfile=client_key or None)
    return ctx


class AgentHttpClient:
    def __init__(
        self,
        base_url: str,
        *,
        bearer_token: str = "",
        timeout: float = 15.0,
        verify_tls: bool = True,
        ca_file: Optional[str] = None,
        require_https: bool = True,
        client_cert: Optional[str] = None,
        client_key: Optional[str] = None,
        minimum_tls: str = "TLSv1.2",
        user_agent: str = "GIDEON-Agent-Client/2.0",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.bearer_token = bearer_token
        self.timeout = float(timeout)
        self.require_https = bool(require_https)
        self.user_agent = str(user_agent)
        if self.require_https and not self.base_url.lower().startswith("https://"):
            raise AgentHttpError(
                "Agent control plane requires HTTPS. HTTP is allowed only in explicit lab mode."
            )
        if self.base_url.lower().startswith("https://"):
            self.context = build_ssl_context(
                verify_tls=verify_tls,
                ca_file=ca_file,
                client_cert=client_cert,
                client_key=client_key,
                minimum_tls=minimum_tls,
            )
        else:
            self.context = None

    def _headers(self, extra: Optional[dict[str, str]] = None) -> dict[str, str]:
        headers = {
            "User-Agent": self.user_agent,
            "X-GIDEON-Client-Version": VERSION,
        }
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        if extra:
            headers.update(extra)
        return headers

    def request_bytes(
        self,
        method: str,
        path: str,
        *,
        body: Optional[bytes] = None,
        headers: Optional[dict[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> tuple[int, bytes, dict[str, str]]:
        url = self.base_url + (path if path.startswith("/") else "/" + path)
        req = request.Request(
            url,
            data=body,
            method=method.upper(),
            headers=self._headers(headers),
        )
        try:
            with request.urlopen(
                req,
                timeout=timeout or self.timeout,
                context=self.context,
            ) as resp:
                data = resp.read()
                return int(resp.status), data, {k: v for k, v in resp.headers.items()}
        except error.HTTPError as exc:
            data = exc.read() if exc.fp else b""
            try:
                detail = json.loads(data.decode("utf-8"))
            except Exception:
                detail = data.decode("utf-8", errors="replace")
            raise AgentHttpError(
                f"HTTP {exc.code} {method} {path}: {detail}"
            ) from exc
        except Exception as exc:
            raise AgentHttpError(
                f"{method} {path}: {type(exc).__name__}: {exc}"
            ) from exc

    def json(
        self,
        method: str,
        path: str,
        payload: Optional[dict[str, Any]] = None,
        *,
        headers: Optional[dict[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> dict[str, Any]:
        body = None
        h = dict(headers or {})
        if payload is not None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            h["Content-Type"] = "application/json; charset=utf-8"
        _, data, _ = self.request_bytes(
            method, path, body=body, headers=h, timeout=timeout
        )
        if not data:
            return {}
        value = json.loads(data.decode("utf-8"))
        if not isinstance(value, dict):
            raise AgentHttpError(f"Expected JSON object from {path}")
        return value

    def upload_file(
        self,
        method: str,
        path: str,
        file_path: Path,
        *,
        headers: Optional[dict[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> dict[str, Any]:
        source = Path(file_path)
        size = source.stat().st_size
        h = dict(headers or {})
        h.setdefault("Content-Type", "application/zip")
        h["Content-Length"] = str(size)
        url = self.base_url + (path if path.startswith("/") else "/" + path)
        # urllib/http.client streams file-like request bodies in blocks. This
        # preserves proxy/TLS behavior while avoiding a second full-size bytes
        # object for large Agent packages and releases.
        try:
            with source.open("rb") as stream:
                req = request.Request(
                    url,
                    data=stream,
                    method=method.upper(),
                    headers=self._headers(h),
                )
                with request.urlopen(
                    req,
                    timeout=timeout or self.timeout,
                    context=self.context,
                ) as resp:
                    payload = resp.read()
                    if not 200 <= int(resp.status) < 300:
                        raise AgentHttpError(f"HTTP {resp.status} {method} {path}")
        except error.HTTPError as exc:
            payload = exc.read() if exc.fp else b""
            try:
                detail = json.loads(payload.decode("utf-8"))
            except Exception:
                detail = payload.decode("utf-8", errors="replace")
            raise AgentHttpError(f"HTTP {exc.code} {method} {path}: {detail}") from exc
        except AgentHttpError:
            raise
        except Exception as exc:
            raise AgentHttpError(f"{method} {path}: {type(exc).__name__}: {exc}") from exc
        return json.loads(payload.decode("utf-8")) if payload else {}

    def download_file(
        self,
        path: str,
        dest: Path,
        *,
        timeout: Optional[float] = None,
    ) -> Path:
        dest = Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        url = self.base_url + (path if path.startswith("/") else "/" + path)
        fd, tmp_name = tempfile.mkstemp(prefix=f".{dest.name}.", suffix=".tmp", dir=str(dest.parent))
        os.close(fd)
        tmp = Path(tmp_name)
        try:
            req = request.Request(url, method="GET", headers=self._headers())
            with request.urlopen(
                req,
                timeout=timeout or self.timeout,
                context=self.context,
            ) as resp, tmp.open("wb") as out:
                shutil.copyfileobj(resp, out, length=1024 * 1024)
                out.flush()
                os.fsync(out.fileno())
            tmp.replace(dest)
            return dest
        except error.HTTPError as exc:
            payload = exc.read() if exc.fp else b""
            raise AgentHttpError(
                f"HTTP {exc.code} GET {path}: {payload.decode('utf-8', errors='replace')}"
            ) from exc
        except Exception as exc:
            raise AgentHttpError(f"GET {path}: {type(exc).__name__}: {exc}") from exc
        finally:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
