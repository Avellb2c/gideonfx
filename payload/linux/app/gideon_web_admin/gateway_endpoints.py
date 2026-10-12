from __future__ import annotations

"""Gateway endpoint discovery and local-test diagnostics for Web Admin.

Phase 2 deliberately keeps these concerns outside the Agent Builder itself:

* discover the *installed/runtime* Gateway configuration without mutating it;
* distinguish listen/internal/advertised addresses;
* make loopback an explicit local-lab choice only;
* cache connectivity probes so page rendering stays fast;
* persist operator-added manual endpoints under WebAdmin data, never inside the
  Gateway runtime configuration unless a future, explicit Gateway settings flow
  chooses to do so.
"""

import datetime as dt
import hashlib
import json
import os
import socket
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from gideon_agent_http import AgentHttpClient
from gideon_gateway_tls import probe_tls_endpoint
from gideon_infrastructure.subprocess_utils import run_hidden


_LOOPBACK_NAMES = {"localhost", "127.0.0.1", "::1"}


def _now() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return {}


def _is_file(path: Path | str) -> bool:
    """Return False when a service account cannot inspect a candidate path."""
    try:
        return Path(path).is_file()
    except (OSError, TypeError, ValueError):
        return False


def _atomic_json(path: Path, value: Any, *, mode: int = 0o640) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    try:
        os.chmod(tmp, mode)
    except OSError:
        pass
    os.replace(tmp, path)
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def _normalized_url(value: str) -> str:
    raw = str(value or "").strip().rstrip("/")
    parsed = urlsplit(raw)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        return ""
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        return ""
    host = parsed.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    port = parsed.port
    suffix = f":{port}" if port is not None else ""
    path = parsed.path.rstrip("/")
    return f"https://{host}{suffix}{path}"


def _host(value: str) -> str:
    try:
        return str(urlsplit(value).hostname or "").strip().casefold()
    except Exception:
        return ""


def is_loopback_url(value: str) -> bool:
    host = _host(value)
    if host in _LOOPBACK_NAMES:
        return True
    try:
        import ipaddress

        return bool(ipaddress.ip_address(host).is_loopback)
    except ValueError:
        return False


def _id(prefix: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:12]
    return f"{prefix}-{digest}"


class GatewayEndpointRegistry:
    """Read-only runtime discovery plus an isolated WebAdmin endpoint registry."""

    def __init__(
        self,
        app_root: Path,
        data_dir: Path,
        config: dict[str, Any],
        *,
        web_config_path: Path | None = None,
        gateway: Any | None = None,
    ) -> None:
        self.app_root = Path(app_root).resolve()
        self.data_dir = Path(data_dir).resolve()
        self.config = config
        self.web_config_path = Path(web_config_path).resolve() if web_config_path else None
        self.gateway = gateway
        self.registry_path = self.data_dir / "gateway-endpoints.json"
        self.probe_cache_path = self.data_dir / "gateway-endpoint-probes.json"

    def _runtime_config_candidates(self) -> list[tuple[int, str, Path]]:
        rows: list[tuple[int, str, Path]] = []

        def add(priority: int, source: str, raw: str | Path | None) -> None:
            if raw in (None, ""):
                return
            try:
                path = Path(os.path.expandvars(str(raw))).expanduser().resolve()
            except Exception:
                return
            rows.append((priority, source, path))

        add(120, "GIDEON_GATEWAY_CONFIG", os.environ.get("GIDEON_GATEWAY_CONFIG"))
        add(115, "WebAdmin gateway_config_file", self.config.get("gateway_config_file"))
        add(114, "WebAdmin gateway_runtime_config", self.config.get("gateway_runtime_config"))

        # Installed WebAdmin and Gateway configs live next to each other on the
        # supported Windows/AWS installers. This is the strongest filesystem clue
        # because it follows a custom DataRoot as well.
        if self.web_config_path is not None:
            add(110, "Gateway junto a WebAdmin", self.web_config_path.parent / "gateway.json")

        if os.name == "nt":
            program_data = os.environ.get("PROGRAMDATA") or r"C:\ProgramData"
            add(105, "Windows SCM GIDEON", Path(program_data) / "GIDEON Remote Control" / "config" / "gateway.json")
        else:
            add(105, "AWS/Ubuntu GIDEON", Path("/etc/gideon/gateway/gateway.json"))
            add(100, "Linux Gateway GIDEON", Path("/etc/gideon-agent-gateway/gateway.json"))

        # Portable/desktop compatibility. Import lazily so WebAdmin can still run
        # in a minimal headless deployment that intentionally omits desktop state.
        try:
            from gideon_gateway_bootstrap import GATEWAY_CONFIG_PATH

            add(80, "Gateway persistente/desktop", GATEWAY_CONFIG_PATH)
        except Exception:
            pass

        add(70, "Gateway release compatible", self.app_root / "config" / "gateway.json")
        add(60, "Gateway portable legacy", self.app_root / "config" / "agent_gateway.json")

        unique: dict[str, tuple[int, str, Path]] = {}
        for priority, source, path in rows:
            key = str(path).casefold()
            previous = unique.get(key)
            if previous is None or priority > previous[0]:
                unique[key] = (priority, source, path)
        return sorted(unique.values(), key=lambda x: (-x[0], str(x[2]).casefold()))

    @staticmethod
    def _endpoint_from_config(cfg: dict[str, Any]) -> str:
        return _normalized_url(
            str(
                cfg.get("advertised_endpoint")
                or cfg.get("advertised_url")
                or cfg.get("public_url")
                or ""
            )
        )

    @staticmethod
    def _port_from_config(cfg: dict[str, Any]) -> int:
        try:
            port = int(cfg.get("listen_port") or 0)
        except (TypeError, ValueError):
            port = 0
        return port if 1 <= port <= 65535 else 0

    def discovered_configs(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for priority, source, path in self._runtime_config_candidates():
            # Gateway runtime files intentionally belong to the Gateway service.
            # WebAdmin must skip a protected candidate instead of failing the
            # whole /installers or /gateway request with PermissionError.
            if not _is_file(path):
                continue
            cfg = _read_json(path)
            if not cfg:
                continue
            advertised = self._endpoint_from_config(cfg)
            port = self._port_from_config(cfg)
            internal = _normalized_url(str(cfg.get("internal_endpoint") or ""))
            if not internal and port:
                internal = f"https://127.0.0.1:{port}"
            ca_file = str(cfg.get("ca_file") or "").strip()
            result.append(
                {
                    "priority": priority,
                    "source": source,
                    "path": str(path),
                    "config": cfg,
                    "listen_address": str(cfg.get("listen_address") or cfg.get("listen_host") or ""),
                    "listen_port": port,
                    "internal_endpoint": internal,
                    "advertised_endpoint": advertised,
                    "ca_file": ca_file,
                }
            )
        return result

    def _saved_rows(self) -> list[dict[str, Any]]:
        value = _read_json(self.registry_path)
        rows = (value.get("endpoints") or []) if isinstance(value, dict) else []
        return [dict(x) for x in rows if isinstance(x, dict)]

    def _probe_cache(self) -> dict[str, dict[str, Any]]:
        value = _read_json(self.probe_cache_path)
        raw = value.get("probes") if isinstance(value, dict) else {}
        return {str(k): dict(v) for k, v in raw.items() if isinstance(v, dict)} if isinstance(raw, dict) else {}

    def _cache_for(self, url: str) -> dict[str, Any]:
        return dict(self._probe_cache().get(_normalized_url(url)) or {})

    def _ca_for_url(self, url: str) -> str:
        normalized = _normalized_url(url)
        for row in self.discovered_configs():
            if normalized in {row.get("advertised_endpoint"), row.get("internal_endpoint")}:
                ca = str(row.get("ca_file") or "").strip()
                if ca and _is_file(Path(os.path.expandvars(ca)).expanduser()):
                    return str(Path(os.path.expandvars(ca)).expanduser().resolve())
        raw = str(self.config.get("gateway_ca_file") or "").strip()
        if raw:
            path = Path(os.path.expandvars(raw)).expanduser()
            if _is_file(path):
                return str(path.resolve())
        return ""

    def endpoints(self) -> list[dict[str, Any]]:
        """Return endpoint choices without performing network I/O."""
        rows: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()

        def add(*, label: str, url: str, role: str, source: str, selectable: bool, local_test: bool = False, priority: int = 0) -> None:
            normalized = _normalized_url(url)
            if not normalized:
                return
            key = (role, normalized)
            if key in seen:
                return
            seen.add(key)
            cache = self._cache_for(normalized)
            rows.append(
                {
                    "id": _id(role.lower(), normalized),
                    "label": label,
                    "url": normalized,
                    "role": role,
                    "source": source,
                    "selectable": bool(selectable),
                    "local_test": bool(local_test),
                    "priority": priority,
                    "status": str(cache.get("status") or "NO_PROBADO"),
                    "tls": str(cache.get("tls") or "NO_PROBADO"),
                    "latency_ms": cache.get("latency_ms"),
                    "last_checked": str(cache.get("last_checked") or ""),
                    "detail": str(cache.get("detail") or ""),
                }
            )

        # The public URL in WebAdmin is an authorized, non-secret fallback when
        # the Gateway service keeps its runtime configuration private.
        explicit = _normalized_url(str(self.config.get("agent_public_gateway_url") or self.config.get("gateway_public_url") or ""))
        if explicit and not is_loopback_url(explicit):
            add(
                label="Gateway configurado en WebAdmin",
                url=explicit,
                role="ADVERTISED",
                source="web_admin.json",
                selectable=True,
                priority=130,
            )

        configs = self.discovered_configs()
        for index, cfgrow in enumerate(configs):
            advertised = str(cfgrow.get("advertised_endpoint") or "")
            source = str(cfgrow.get("source") or "Gateway instalado")
            if advertised:
                if is_loopback_url(advertised):
                    # A loopback value in public_url is legacy/bad advertised state.
                    # Surface it diagnostically but never offer it as a remote Agent
                    # destination. The explicit LOCAL_TEST entry below is safe.
                    add(
                        label="Anunciado (loopback no válido para remotos)",
                        url=advertised,
                        role="ADVERTISED_INVALID",
                        source=source,
                        selectable=False,
                        priority=90 - index,
                    )
                else:
                    add(
                        label="Gateway principal" if index == 0 else "Gateway alternativo detectado",
                        url=advertised,
                        role="ADVERTISED",
                        source=source,
                        selectable=True,
                        priority=100 - index,
                    )
            internal = str(cfgrow.get("internal_endpoint") or "")
            if internal:
                add(
                    label="Gateway interno WebAdmin → Gateway",
                    url=internal,
                    role="INTERNAL",
                    source=source,
                    selectable=not is_loopback_url(internal),
                    priority=40 - index,
                )

        # WebAdmin's current internal route is useful even when no runtime config
        # file can be read (e.g. locked-down service account).
        web_internal = _normalized_url(str(self.config.get("gateway_base_url") or ""))
        if web_internal:
            add(
                label="Gateway interno configurado en WebAdmin",
                url=web_internal,
                role="INTERNAL",
                source="web_admin.json",
                selectable=not is_loopback_url(web_internal),
                priority=35,
            )

        for saved in self._saved_rows():
            url = _normalized_url(str(saved.get("url") or ""))
            if not url or is_loopback_url(url):
                continue
            add(
                label=str(saved.get("label") or "Gateway guardado"),
                url=url,
                role="SAVED",
                source="WebAdmin · guardado manualmente",
                selectable=True,
                priority=75,
            )

        # Explicit local-lab endpoint. It is never treated as ADVERTISED and is
        # therefore impossible to select accidentally as a remote default.
        local_port = 0
        local_source = "WebAdmin"
        for cfgrow in configs:
            if int(cfgrow.get("listen_port") or 0):
                local_port = int(cfgrow["listen_port"])
                local_source = str(cfgrow.get("source") or local_source)
                break
        if not local_port and web_internal:
            try:
                local_port = int(urlsplit(web_internal).port or 443)
            except ValueError:
                local_port = 0
        if local_port:
            add(
                label="Prueba local - esta PC",
                url=f"https://127.0.0.1:{local_port}",
                role="LOCAL_TEST",
                source=local_source,
                selectable=True,
                local_test=True,
                priority=65,
            )

        rows.sort(key=lambda x: (-int(x.get("priority") or 0), str(x.get("label") or "")))
        return rows

    def default_endpoint(self) -> dict[str, Any] | None:
        # Explicit WebAdmin override wins only if it is not loopback.
        explicit = _normalized_url(str(self.config.get("agent_public_gateway_url") or self.config.get("gateway_public_url") or ""))
        if explicit and not is_loopback_url(explicit):
            return {
                "id": _id("configured", explicit),
                "label": "Gateway configurado en WebAdmin",
                "url": explicit,
                "role": "ADVERTISED",
                "source": "web_admin.json",
                "selectable": True,
                "local_test": False,
                "priority": 130,
                **self._cache_for(explicit),
            }
        return next((x for x in self.endpoints() if x.get("selectable") and x.get("role") in {"ADVERTISED", "SAVED"}), None)

    def resolve_selection(self, endpoint_id: str, manual_url: str, mode: str) -> tuple[str, str]:
        mode = str(mode or "").strip().lower()
        endpoint_id = str(endpoint_id or "").strip()
        if endpoint_id == "manual" or mode == "manual":
            url = _normalized_url(manual_url)
            if not url:
                raise ValueError("Ingrese una URL HTTPS válida para el Gateway manual.")
            if is_loopback_url(url):
                raise ValueError("127.0.0.1/localhost solo está permitido mediante 'Prueba local - esta PC'.")
            return url, "manual"

        row = next((x for x in self.endpoints() if str(x.get("id")) == endpoint_id and bool(x.get("selectable"))), None)
        if row is None:
            # Compatibility with older form posts: a non-loopback gateway_url can
            # still be accepted if the dropdown field did not exist yet.
            fallback = _normalized_url(manual_url)
            if fallback and not is_loopback_url(fallback):
                return fallback, "production"
            raise ValueError("Seleccione un Gateway detectado o introduzca uno manualmente.")
        url = str(row["url"])
        if bool(row.get("local_test")):
            if not is_loopback_url(url):
                raise ValueError("El perfil LOCAL_TEST debe utilizar exclusivamente loopback.")
            return url, "local_test"
        if is_loopback_url(url):
            raise ValueError("Un Agent remoto nunca puede recibir 127.0.0.1/localhost.")
        if row.get("role") == "INTERNAL":
            return url, "lan"
        return url, "production"

    def save_manual(self, url: str, *, label: str = "Gateway manual") -> dict[str, Any]:
        normalized = _normalized_url(url)
        if not normalized:
            raise ValueError("La URL manual debe ser HTTPS y no contener credenciales, query ni fragmentos.")
        if is_loopback_url(normalized):
            raise ValueError("No se guarda loopback como Gateway anunciado. Use el modo de prueba local.")
        label = str(label or "Gateway manual").strip()[:80] or "Gateway manual"
        rows = self._saved_rows()
        rows = [x for x in rows if _normalized_url(str(x.get("url") or "")) != normalized]
        rows.insert(0, {"label": label, "url": normalized, "saved_at": _now()})
        _atomic_json(self.registry_path, {"schema": "gideon-gateway-endpoints/v1", "endpoints": rows[:20]})
        return {"label": label, "url": normalized, "saved_at": rows[0]["saved_at"]}

    def probe(self, url: str, *, local_test: bool = False) -> dict[str, Any]:
        normalized = _normalized_url(url)
        if not normalized:
            raise ValueError("Gateway HTTPS inválido.")
        if is_loopback_url(normalized) and not local_test:
            raise ValueError("Loopback solo puede probarse como 'Prueba local - esta PC'.")
        ca_file = self._ca_for_url(normalized)
        started = time.perf_counter()
        status = "OFFLINE"
        tls = "ERROR"
        detail = ""
        payload: dict[str, Any] = {}
        try:
            client = AgentHttpClient(
                normalized,
                verify_tls=True,
                ca_file=ca_file or None,
                require_https=True,
                timeout=4.0,
                user_agent="GIDEON-WebAdmin-Gateway-Probe/1.0",
            )
            payload = client.json("GET", "/health", timeout=4.0)
            if not bool(payload.get("Ok", True)):
                raise RuntimeError("/health respondió sin Ok=true")
            status = "ONLINE"
            tls = "VALIDO"
            detail = f"/health OK · Gateway {payload.get('Version', '-')} · protocolo {payload.get('ProtocolVersion', '-')}"
        except Exception as exc:
            text = f"{type(exc).__name__}: {exc}"
            detail = text
            low = text.casefold()
            status = "TLS_ERROR" if any(x in low for x in ("ssl", "certificate", "certificado", "hostname")) else "OFFLINE"
            tls = "ERROR" if status == "TLS_ERROR" else "NO_VERIFICADO"
        latency = int(round((time.perf_counter() - started) * 1000))
        result = {
            "url": normalized,
            "status": status,
            "tls": tls,
            "latency_ms": latency,
            "last_checked": _now(),
            "detail": detail,
            "gateway_version": str(payload.get("Version") or ""),
            "protocol_version": str(payload.get("ProtocolVersion") or ""),
            "enrollment_api": bool((payload.get("Capabilities") or {}).get("EnrollmentGrantEndpoint")) if isinstance(payload.get("Capabilities"), dict) else False,
        }
        cache = self._probe_cache()
        cache[normalized] = result
        _atomic_json(self.probe_cache_path, {"schema": "gideon-gateway-probes/v1", "probes": cache})
        return result

    @staticmethod
    def _service_status() -> tuple[bool, str]:
        try:
            if os.name == "nt":
                proc = run_hidden(
                    ["sc.exe", "query", "GIDEONRemoteControlGateway"],
                    capture_output=True,
                    text=True,
                    timeout=8,
                    check=False,
                )
                text = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
                ok = proc.returncode == 0 and "RUNNING" in text.upper()
                return ok, "GIDEONRemoteControlGateway RUNNING" if ok else (text[-500:] or "Servicio no encontrado/activo")
            if sys.platform == "darwin":
                return True, "Diagnóstico automático de servicio no requerido en macOS WebAdmin"
            proc = run_hidden(
                ["systemctl", "is-active", "gideon-agent-gateway.service"],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
            text = ((proc.stdout or "") + " " + (proc.stderr or "")).strip()
            return proc.returncode == 0 and "active" in text.casefold(), text or "inactivo"
        except Exception as exc:
            return False, f"{type(exc).__name__}: {exc}"

    def local_diagnostics(self) -> dict[str, Any]:
        configs = self.discovered_configs()
        cfgrow = configs[0] if configs else {}
        port = int(cfgrow.get("listen_port") or 0)
        if not port:
            internal = _normalized_url(str(self.config.get("gateway_base_url") or ""))
            try:
                port = int(urlsplit(internal).port or 443) if internal else 0
            except ValueError:
                port = 0
        local_url = f"https://127.0.0.1:{port}" if port else ""
        checks: list[dict[str, Any]] = []

        def add(name: str, ok: bool, detail: str) -> None:
            checks.append({"name": name, "ok": bool(ok), "detail": str(detail)})

        config_path = str(cfgrow.get("path") or "")
        add("Gateway instalado/configurado", bool(config_path), config_path or "No se encontró gateway.json runtime")

        service_ok, service_detail = self._service_status()
        add("Servicio Gateway", service_ok, service_detail)

        tcp_ok = False
        tcp_detail = "Puerto no identificado"
        if port:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1.2):
                    pass
                tcp_ok = True
                tcp_detail = f"127.0.0.1:{port} escuchando"
            except OSError as exc:
                tcp_detail = f"127.0.0.1:{port} · {type(exc).__name__}: {exc}"
        add("Puerto local", tcp_ok, tcp_detail)

        ca_file = self._ca_for_url(local_url) if local_url else ""
        tls_ok = False
        tls_detail = "No ejecutado"
        if local_url and ca_file and _is_file(ca_file) and tcp_ok:
            probe = probe_tls_endpoint(local_url, ca_file=ca_file, timeout=2.0)
            tls_ok = bool(probe.ok)
            tls_detail = probe.detail
        elif not ca_file:
            tls_detail = "CA GIDEON no encontrada para verificar TLS local"
        add("TLS local", tls_ok, tls_detail)

        health: dict[str, Any] = {}
        api_ok = False
        api_detail = "No ejecutado"
        if local_url and tcp_ok:
            try:
                health = AgentHttpClient(
                    local_url,
                    verify_tls=True,
                    ca_file=ca_file or None,
                    require_https=True,
                    timeout=3.0,
                ).json("GET", "/health", timeout=3.0)
                api_ok = bool(health.get("Ok", True))
                api_detail = f"/health OK · v{health.get('Version', '-')}"
            except Exception as exc:
                api_detail = f"{type(exc).__name__}: {exc}"
        add("API /health", api_ok, api_detail)

        capabilities = health.get("Capabilities") if isinstance(health.get("Capabilities"), dict) else {}
        enrollment_ok = bool(capabilities.get("EnrollmentGrantEndpoint"))
        if api_ok and not enrollment_ok and self.gateway is not None:
            try:
                admin_health = self.gateway.health()
                caps = admin_health.get("Capabilities") if isinstance(admin_health.get("Capabilities"), dict) else {}
                enrollment_ok = bool(caps.get("EnrollmentGrantEndpoint"))
            except Exception:
                pass
        add("Enrolamiento", enrollment_ok, "API de enrollment grants disponible" if enrollment_ok else "No se confirmó la API de enrollment grants")

        add("WebAdmin", True, "Esta prueba fue ejecutada desde una sesión WebAdmin activa")

        try:
            from gideon_local_agent import inspect_local_agent

            agent = inspect_local_agent(None)
        except Exception as exc:
            agent = {"ok": False, "installed": False, "summary": f"{type(exc).__name__}: {exc}", "checks": []}
        add("Agent local", bool(agent.get("installed")), str(agent.get("summary") or "No encontrado"))
        heartbeat = ""
        for check in agent.get("checks") or []:
            if isinstance(check, dict) and str(check.get("name")) == "Heartbeat local":
                heartbeat = str(check.get("detail") or "")
                break
        add("Heartbeat", bool(heartbeat and heartbeat != "Nunca registrado"), heartbeat or "No disponible")

        failures = [x for x in checks if not x["ok"]]
        return {
            "ok": not failures,
            "mode": "LOCAL_TEST",
            "local_url": local_url,
            "listen_address": str(cfgrow.get("listen_address") or ""),
            "advertised_endpoint": str(cfgrow.get("advertised_endpoint") or ""),
            "config_path": config_path,
            "checks": checks,
            "last_error": failures[0]["detail"] if failures else "",
            "checked_at": _now(),
        }
