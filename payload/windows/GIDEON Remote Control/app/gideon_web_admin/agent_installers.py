from __future__ import annotations

"""Web-safe Agent installer build service.

The Web Admin may build endpoint installers, but it must never persist the
execution signing private key in plaintext and must never auto-install host
packages/toolchains.  Build artifacts live only under the GIDEON Web data root.
"""

import base64
import csv
import datetime as dt
import hashlib
import ipaddress
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import threading
import traceback
import uuid
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from gideon_agent_catalog import AgentDownloadCatalog, TARGETS
from gideon_packaging import WindowsExePackager
from gideon_version import AGENT_VERSION
from gideon_common.redaction import redact_error

from .auth import SecurityStore
from .agent_builder_profiles import build_catalog, resolve_choice, validate_profile, normalize_profile_for_choice, enrollment_policy
from .gateway import GatewayFacade
from .gateway_endpoints import GatewayEndpointRegistry, is_loopback_url
from .security_assets import SecurityAssetManager


class AgentInstallerError(RuntimeError):
    pass


SOURCE_COMPANION_SCHEMA = "gideon-vlc-source-companion/v1"
SOURCE_COMPANION_SIGNATURE_SCHEME = "ed25519-domain-sha256-v1"
SOURCE_COMPANION_SIGNATURE_DOMAIN = b"GIDEON-SOURCE-COMPANION-SHA256-V1\0"


def _package_profile(vlc_delivery: str) -> str:
    """Return the stable product profile exposed by WebAdmin and its API."""
    return "operational-reduced" if str(vlc_delivery or "").casefold() == "detached" else "complete-kit"


def _now() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _chmod(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def _next_build_number(rows: list[dict[str, Any]]) -> int:
    """Return a monotonic display/build correlation number.

    Agent semantic versions describe compatible runtime code and are advanced
    only by an approved release.  Installer generations get this independent
    sequence so two site/grant-specific artifacts are never indistinguishable.
    """
    explicit: list[int] = []
    for row in rows:
        try:
            value = int(row.get("build_number") or 0)
        except (TypeError, ValueError):
            value = 0
        if value > 0:
            explicit.append(value)
    return max([len(rows), *explicit], default=0) + 1


def _normalize_build_history(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Backfill correlation numbers for history created before this feature."""
    used: set[int] = set()
    for row in rows:
        try:
            number = int(row.get("build_number") or 0)
        except (TypeError, ValueError):
            number = 0
        if number > 0:
            used.add(number)
    candidate = 1
    for row in reversed(rows):
        try:
            number = int(row.get("build_number") or 0)
        except (TypeError, ValueError):
            number = 0
        if number <= 0:
            while candidate in used:
                candidate += 1
            number = candidate
            row["build_number"] = number
            used.add(number)
            candidate += 1
        if not str(row.get("display_version") or "").strip():
            row["display_version"] = f"{row.get('version') or AGENT_VERSION} · build {number:04d}"
        delivery = str(row.get("vlc_delivery") or "bundled").strip().casefold()
        if not str(row.get("package_profile") or "").strip():
            # Keep history normalization self-contained for recovery tooling
            # that loads this helper without constructing the Web manager.
            row["package_profile"] = "operational-reduced" if delivery == "detached" else "complete-kit"
        if not isinstance(row.get("source_companion"), dict):
            row["source_companion"] = {
                "schema": "gideon-vlc-source-companion/v1",
                "delivery": delivery,
                "status": "LEGACY_UNKNOWN" if delivery == "detached" else "INCLUDED_IN_INSTALLER",
            }
    return rows


def _artifact_with_build_suffix(path: Path, build_number: int) -> Path:
    path = Path(path)
    name = path.name
    if name.casefold().endswith(".tar.gz"):
        stem, extension = name[:-7], name[-7:]
    else:
        extension = path.suffix
        stem = name[:-len(extension)] if extension else name
    return path.with_name(f"{stem}-build{int(build_number):04d}{extension}")


def _safe_build_error(exc: Exception) -> str:
    """Expose useful compiler output without leaking builder secrets."""
    parts = [f"{type(exc).__name__}: {exc}"]
    if isinstance(exc, subprocess.CalledProcessError):
        for label, raw in (("stderr", exc.stderr), ("stdout", exc.stdout)):
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8", "replace")
            text = redact_error(raw or "", max_chars=2400).strip()
            if text:
                parts.append(f"{label}: {text}")
    return redact_error(" · ".join(parts), max_chars=5000)


def _build_request_fingerprint(*, actor: str, target_id: str, package_type: str,
                               gateway_url: str, gateway_mode: str,
                               gateway_endpoints: list[dict[str, Any]], channel: str,
                               builder_profile: str, os_family: str, os_variant: str,
                               architecture: str, offline_vlc_distribution: str,
                               offline_vlc_codename: str, enrollment_mode: str,
                               agent_name_mode: str, vlc_delivery: str,
                               site_code: str, site_name: str,
                               agent_name: str, ttl_hours: int, max_uses: int) -> str:
    """Return a non-secret identity for one active installer request.

    A generated installer embeds an enrollment grant.  Therefore deduplication
    is deliberately limited to an *active request by the same operator*: a
    second operator must receive a different build and a different grant even
    when all visible options happen to match.
    """
    payload = {
        "schema": "gideon-agent-installer-request/v1",
        "actor": str(actor or "").strip().casefold(),
        "agent_version": str(AGENT_VERSION),
        "target_id": str(target_id or "").strip(),
        "package_type": str(package_type or "").strip(),
        "gateway_url": str(gateway_url or "").strip().rstrip("/").casefold(),
        "gateway_mode": str(gateway_mode or "").strip().casefold(),
        "gateway_endpoints": [
            {
                "url": str(row.get("url") or "").strip().rstrip("/").casefold(),
                "role": str(row.get("role") or "").strip().casefold(),
                "priority": int(row.get("priority") or 0),
            }
            for row in gateway_endpoints
            if isinstance(row, dict)
        ],
        "channel": str(channel or "").strip().casefold(),
        "builder_profile": str(builder_profile or "").strip().casefold(),
        "os_family": str(os_family or "").strip().casefold(),
        "os_variant": str(os_variant or "").strip().casefold(),
        "architecture": str(architecture or "").strip().casefold(),
        "offline_vlc_distribution": str(offline_vlc_distribution or "").strip().casefold(),
        "offline_vlc_codename": str(offline_vlc_codename or "").strip().casefold(),
        # A core-only package and the legacy compatible package are different
        # deployment products; never deduplicate their enrollment grants.
        "vlc_delivery": str(vlc_delivery or "bundled").strip().casefold(),
        "enrollment_mode": str(enrollment_mode or "").strip().casefold(),
        "agent_name_mode": str(agent_name_mode or "").strip().casefold(),
        "site_code": str(site_code or "").strip().casefold(),
        "site_name": str(site_name or "").strip().casefold(),
        "agent_name": str(agent_name or "").strip().casefold(),
        "ttl_hours": int(ttl_hours),
        "max_uses": int(max_uses),
    }
    encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class WebAgentInstallerManager:
    def __init__(
        self,
        app_root: Path,
        data_dir: Path,
        config: dict[str, Any],
        security: SecurityStore,
        gateway: GatewayFacade,
        security_assets: SecurityAssetManager,
    ) -> None:
        self.app_root = Path(app_root).resolve()
        self.data_dir = Path(data_dir).resolve()
        self.config = config
        self.security = security
        self.gateway = gateway
        self.security_assets = security_assets
        self.root = (self.data_dir / "agent-installers").resolve()
        self.artifacts_dir = self.root / "artifacts"
        self.source_companions_dir = self.root / "source-companions"
        self.history_path = self.root / "builds.json"
        self.root.mkdir(parents=True, exist_ok=True)
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.source_companions_dir.mkdir(parents=True, exist_ok=True)
        _chmod(self.root, 0o750)
        _chmod(self.artifacts_dir, 0o750)
        _chmod(self.source_companions_dir, 0o750)
        self._lock = threading.RLock()
        self._threads: dict[str, threading.Thread] = {}
        self._cap_cache: tuple[float, list[dict[str, Any]]] | None = None
        self._recover_interrupted_builds()
        # Builds may include a private Python runtime and an optional offline
        # VLC closure, so they are intentionally serialized by default.  Queue
        # records are durable; only the short-lived enrollment secret stays in
        # memory and is created immediately before a build starts.
        self._schedule_pending_builds()

    def _build_concurrency_limit(self) -> int:
        """Return the bounded heavy-build limit without trusting raw config."""
        raw = self.config.get(
            "agent_installer_max_concurrent_builds",
            self.config.get("agent_installer_build_concurrency", 1),
        )
        try:
            value = int(raw)
        except (TypeError, ValueError):
            value = 1
        # More than four simultaneous native/toolchain builds is operationally
        # unsafe for the WebAdmin VM.  One remains the secure default.
        return max(1, min(value, 4))

    @staticmethod
    def _queue_sort_key(row: dict[str, Any]) -> tuple[int, str, str]:
        try:
            number = int(row.get("build_number") or 0)
        except (TypeError, ValueError):
            number = 0
        return (number if number > 0 else 2**31 - 1, str(row.get("created_at") or ""), str(row.get("build_id") or ""))

    def _decorate_queue_rows(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Add display-only queue metadata while preserving legacy statuses."""
        decorated = [dict(row) for row in rows]
        limit = self._build_concurrency_limit()
        waiting = sorted(
            (row for row in decorated if str(row.get("status") or "").upper() == "QUEUED"),
            key=self._queue_sort_key,
        )
        position_by_id = {str(row.get("build_id") or ""): index + 1 for index, row in enumerate(waiting)}
        active = sum(1 for row in decorated if str(row.get("status") or "").upper() == "BUILDING")
        for row in decorated:
            status = str(row.get("status") or "").upper()
            row["queue_limit"] = limit
            row["queue_active"] = active
            if status == "QUEUED":
                row["queue_position"] = position_by_id.get(str(row.get("build_id") or ""), 0)
                row["queue_state"] = "WAITING"
            elif status == "BUILDING":
                row["queue_position"] = 0
                row["queue_state"] = "BUILDING"
            else:
                row["queue_position"] = 0
                row["queue_state"] = "TERMINAL"
        return decorated

    def queue_status(self) -> dict[str, Any]:
        """Expose a small, backwards-compatible queue snapshot for WebAdmin."""
        with self._lock:
            rows = self._decorate_queue_rows(self._read_history())
        waiting = [row for row in rows if str(row.get("status") or "").upper() == "QUEUED"]
        active = [row for row in rows if str(row.get("status") or "").upper() == "BUILDING"]
        return {
            "status": "BUILDING" if active else "QUEUED" if waiting else "IDLE",
            "limit": self._build_concurrency_limit(),
            "active": len(active),
            "waiting": len(waiting),
        }

    def _new_build_thread(self, build_id: str) -> threading.Thread:
        return threading.Thread(
            target=self._run_queued_build,
            name=f"gideon-agent-build-{build_id}",
            daemon=True,
            kwargs={"build_id": build_id},
        )

    def _schedule_pending_builds(self) -> None:
        """Claim FIFO queue records and start only available heavy-build slots."""
        pending: list[threading.Thread] = []
        with self._lock:
            rows = self._read_history()
            limit = self._build_concurrency_limit()
            active = sum(1 for row in rows if str(row.get("status") or "").upper() == "BUILDING")
            waiting = sorted(
                (row for row in rows if str(row.get("status") or "").upper() == "QUEUED"),
                key=self._queue_sort_key,
            )
            changed = False
            for row in waiting:
                if active >= limit:
                    break
                build_id = str(row.get("build_id") or "").strip()
                if not build_id or build_id in self._threads:
                    continue
                row.update({
                    "status": "BUILDING",
                    "started_at": _now(),
                    "detail": "Preparando credencial temporal y generando instalador…",
                })
                thread = self._new_build_thread(build_id)
                self._threads[build_id] = thread
                pending.append(thread)
                active += 1
                changed = True
            if changed:
                self._write_history(rows)
        for thread in pending:
            thread.start()

    def _read_history(self) -> list[dict[str, Any]]:
        try:
            value = json.loads(self.history_path.read_text(encoding="utf-8-sig"))
            rows = [dict(x) for x in value if isinstance(x, dict)] if isinstance(value, list) else []
            return _normalize_build_history(rows)
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            return []

    def _write_history(self, rows: list[dict[str, Any]]) -> None:
        tmp = self.history_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(rows[:200], ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        _chmod(tmp, 0o640)
        os.replace(tmp, self.history_path)
        _chmod(self.history_path, 0o640)

    def _recover_interrupted_builds(self) -> None:
        revoke_after_restart: list[dict[str, str]] = []
        with self._lock:
            rows = self._read_history()
            changed = False
            for row in rows:
                status = str(row.get("status") or "").upper()
                grant_id = str(row.get("grant_id") or "").strip()
                if status == "BUILDING":
                    row["status"] = "INTERRUPTED"
                    row["detail"] = "La Web Admin se reinició mientras el instalador se estaba generando. Genere un paquete nuevo."
                    row["finished_at"] = _now()
                    row["recovered_at"] = _now()
                    changed = True
                    if grant_id and not str(row.get("grant_revoked_at") or "").strip():
                        revoke_after_restart.append({
                            "build_id": str(row.get("build_id") or ""),
                            "grant_id": grant_id,
                            "actor": str(row.get("requested_by") or "system"),
                            "target_id": str(row.get("target_id") or ""),
                            "status": "INTERRUPTED",
                        })
                elif status == "QUEUED":
                    # A queued record contains no secret in the current design.
                    # Legacy rows may have a pre-issued grant: revoke it before
                    # re-dispatch and issue a new one only when its FIFO slot opens.
                    row["recovered_at"] = _now()
                    row["detail"] = "La Web Admin se reinició; la solicitud se reanudará desde la cola con una credencial temporal nueva."
                    changed = True
                    if grant_id and not str(row.get("grant_revoked_at") or "").strip():
                        revoke_after_restart.append({
                            "build_id": str(row.get("build_id") or ""),
                            "grant_id": grant_id,
                            "actor": str(row.get("requested_by") or "system"),
                            "target_id": str(row.get("target_id") or ""),
                            "status": "QUEUED",
                        })
            if changed:
                self._write_history(rows)

        for item in revoke_after_restart:
            build_id = item["build_id"]
            try:
                result = self.gateway.revoke_enrollment_grant(
                    item["grant_id"], reason=f"installer-build-restart:{build_id}"
                )
                revoked_at = str(result.get("RevokedAt") or _now())
                row = self.get(build_id) or {}
                prior = [str(value) for value in row.get("prior_grant_ids") or [] if str(value)]
                if item["grant_id"] not in prior:
                    prior.append(item["grant_id"])
                values: dict[str, Any] = {"prior_grant_ids": prior, "recovery_grant_revoked_at": revoked_at}
                if item["status"] == "QUEUED":
                    values.update({"grant_id": "", "grant_expires_at": "", "grant_revoked_at": "", "grant_state": "PENDING"})
                else:
                    values.update({"grant_revoked_at": revoked_at, "grant_state": "REVOKED_AFTER_RESTART"})
                self._patch_record(build_id, **values)
                try:
                    self.security.audit(
                        item["actor"], "agent_installer.recovery", "RECOVERED" if item["status"] == "QUEUED" else "INTERRUPTED",
                        f"Build={build_id}; Grant revoked after WebAdmin restart; Status={item['status']}",
                        "", resource=item["target_id"],
                    )
                except Exception:
                    # Recovery of a secure queue must not be rolled back just
                    # because the audit sink is temporarily unavailable.
                    pass
            except Exception as exc:
                detail = "No se pudo revocar la credencial previa tras reinicio: " + _safe_build_error(exc)
                if item["status"] == "QUEUED":
                    # Do not resume an old queued record when its legacy grant
                    # cannot be revoked.  This avoids two live enrollment grants.
                    self._patch_record(
                        build_id, status="INTERRUPTED", finished_at=_now(),
                        detail=detail + " Genere un paquete nuevo.", grant_state="REVOCATION_REVIEW_REQUIRED",
                    )
                else:
                    self._patch_record(build_id, detail=detail, grant_state="REVOCATION_REVIEW_REQUIRED")
                try:
                    self.security.audit(
                        item["actor"], "agent_installer.recovery", "FAILED",
                        f"Build={build_id}; {detail}", "", resource=item["target_id"],
                    )
                except Exception:
                    pass

    def history(self, limit: int = 30) -> list[dict[str, Any]]:
        with self._lock:
            return self._decorate_queue_rows(self._read_history())[: max(1, min(int(limit), 200))]

    def get(self, build_id: str) -> dict[str, Any] | None:
        clean = str(build_id or "").strip()
        with self._lock:
            return next((x for x in self._decorate_queue_rows(self._read_history()) if str(x.get("build_id")) == clean), None)

    @staticmethod
    def validate_gateway_url(value: str) -> str:
        raw = str(value or "").strip().rstrip("/")
        parsed = urlsplit(raw)
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            raise AgentInstallerError("El Gateway del Agent debe ser una URL https:// válida y alcanzable por los endpoints.")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise AgentInstallerError("La URL del Gateway no puede contener credenciales, query string ni fragmentos.")
        return raw

    @staticmethod
    def _gateway_remote_score(url: str, role: str = "") -> tuple[int, int]:
        """Rank remotely deployable Gateway endpoints without network probes.

        A literal IP or FQDN is preferred over a Windows/single-label host name
        (for example DESKTOP-XXXX) because stores often do not share that local
        DNS suffix.  A single-label name remains valid as a fallback for AD/LAN
        environments; it is not rejected.
        """
        raw = str(url or "").strip().rstrip("/")
        if not raw or is_loopback_url(raw):
            return (0, 0)
        try:
            host = str(urlsplit(raw).hostname or "").strip().strip("[]")
        except Exception:
            return (0, 0)
        if not host:
            return (0, 0)
        endpoint_quality = 1
        try:
            ipaddress.ip_address(host)
            endpoint_quality = 3
        except ValueError:
            if "." in host:
                endpoint_quality = 3
            elif host.casefold() not in {"localhost"}:
                endpoint_quality = 1
        role_rank = {"ADVERTISED": 30, "SAVED": 20, "INTERNAL": 10}.get(str(role or "").upper(), 0)
        return (endpoint_quality, role_rank)

    def default_gateway_url(self) -> str:
        # Prefer an endpoint that is realistically resolvable/routable from a
        # remote store.  The registry is filesystem-only here; no network probe
        # is performed while rendering WebAdmin.
        registry_rows: list[dict[str, Any]] = []
        try:
            registry = GatewayEndpointRegistry(
                self.app_root, self.data_dir, self.config, gateway=self.gateway
            )
            registry_rows = [
                dict(row) for row in registry.endpoints()
                if isinstance(row, dict)
                and bool(row.get("selectable"))
                and not bool(row.get("local_test"))
                and str(row.get("url") or "").strip()
                and not is_loopback_url(str(row.get("url") or ""))
            ]
            if registry_rows:
                best = max(
                    enumerate(registry_rows),
                    key=lambda pair: (self._gateway_remote_score(
                        str(pair[1].get("url") or ""), str(pair[1].get("role") or "")
                    ), -pair[0]),
                )[1]
                if self._gateway_remote_score(str(best.get("url") or ""))[0] >= 3:
                    return str(best["url"]).rstrip("/")

            # Preserve the registry's prior default semantics when all available
            # endpoints are single-label LAN names.
            row = registry.default_endpoint()
            if row and row.get("url") and not is_loopback_url(str(row.get("url"))):
                registry_rows.insert(0, dict(row))
        except Exception:
            registry_rows = []

        value = str(self.config.get("agent_public_gateway_url") or self.config.get("gateway_public_url") or "").strip()
        if value and not is_loopback_url(value):
            return value.rstrip("/")

        # If the registry had only single-label endpoints, retain the previous
        # fallback rather than silently breaking legitimate AD/LAN deployments.
        if registry_rows:
            url = str(registry_rows[0].get("url") or "").strip().rstrip("/")
            if url:
                return url

        internal = str(self.config.get("gateway_base_url") or "").strip().rstrip("/")
        return "" if is_loopback_url(internal) else internal

    def connection_endpoints(self, primary_url: str, gateway_mode: str) -> list[dict[str, Any]]:
        """Build the runtime failover list without changing Gateway configuration.

        P3 intentionally reuses the P2 read-only endpoint registry.  The selected
        endpoint is always primary; discovered non-loopback endpoints become
        secondary/LAN/contingency candidates. LOCAL_TEST remains isolated.
        """
        primary = self.validate_gateway_url(primary_url)
        mode = str(gateway_mode or "production").strip().lower()
        if mode == "local_test":
            return [{"url": primary, "role": "primary", "priority": 10, "label": "Prueba local"}]

        result: list[dict[str, Any]] = [
            {"url": primary, "role": "primary", "priority": 10, "label": "Seleccionado"}
        ]
        seen = {primary.casefold()}
        role_map = {
            "ADVERTISED": ("secondary", 20),
            "INTERNAL": ("lan", 30),
            "SAVED": ("contingency", 40),
        }
        try:
            rows = GatewayEndpointRegistry(
                self.app_root, self.data_dir, self.config, gateway=self.gateway
            ).endpoints()
        except Exception:
            rows = []
        for row in rows:
            if not bool(row.get("selectable")) or bool(row.get("local_test")):
                continue
            url = str(row.get("url") or "").strip().rstrip("/")
            if not url or is_loopback_url(url) or url.casefold() in seen:
                continue
            role, priority = role_map.get(str(row.get("role") or "").upper(), ("secondary", 50))
            result.append({
                "url": url,
                "role": role,
                "priority": priority + len(result),
                "label": str(row.get("label") or role),
            })
            seen.add(url.casefold())
        return result

    def gateway_ca_path(self) -> Path | None:
        raw = str(self.config.get("gateway_ca_file") or "").strip()
        if raw:
            path = Path(os.path.expandvars(raw)).expanduser()
            if path.is_file():
                return path.resolve()
        return None

    @staticmethod
    def _native_label(package_type: str) -> str:
        return {
            "exe": "EXE nativo",
            "deb": "DEB nativo",
            "rpm": "RPM nativo",
            "pkg": "PKG nativo",
        }.get(package_type, package_type.upper())

    def _catalog_for_probe(self) -> AgentDownloadCatalog:
        catalog = AgentDownloadCatalog(self.app_root)
        # Capability checks are read-only. Build state is redirected under DataRoot.
        catalog.state_dir = self.root / "catalog-state"
        catalog.state_dir.mkdir(parents=True, exist_ok=True)
        catalog.registry = catalog.state_dir / "catalog.json"
        return catalog

    def targets(self) -> list[dict[str, Any]]:
        import time
        now = time.monotonic()
        with self._lock:
            if self._cap_cache and now - self._cap_cache[0] < 30:
                return [dict(x) for x in self._cap_cache[1]]
        catalog = self._catalog_for_probe()
        result: list[dict[str, Any]] = []
        for target_id, raw in TARGETS.items():
            target = dict(raw)
            native_type = catalog._native_package_type(target)
            cap = dict(catalog.build_capability(target_id))
            # Web builds are deliberately non-invasive: unlike the desktop builder,
            # the Web never installs RPM tools into WSL on the operator's behalf.
            if native_type == "rpm" and os.name == "nt" and bool(cap.get("ready")):
                try:
                    distro = catalog._choose_wsl_distro("rpm")
                    required = catalog._rpm_required_commands()
                    check = " && ".join(f"command -v {name} >/dev/null 2>&1" for name in required)
                    probe = catalog._wsl_run(["sh", "-lc", check], timeout=30, distro=distro)
                    if probe.returncode != 0:
                        cap = {
                            "ready": False,
                            "backend": f"WSL · {distro}",
                            "detail": "El toolchain RPM no está preparado. La Web GIDEON no instala paquetes del sistema automáticamente; instale rpm-build/file/binutils/tar/gzip explícitamente.",
                        }
                except Exception as exc:
                    cap = {"ready": False, "backend": "WSL", "detail": str(exc)}
            options: list[dict[str, Any]] = [{
                "value": "native",
                "resolved": native_type,
                "label": self._native_label(native_type),
                "ready": bool(cap.get("ready")),
                "backend": str(cap.get("backend") or ""),
                "detail": str(cap.get("detail") or ""),
            }]
            # macOS can always be prepared as a portable bootstrap bundle from
            # Windows/Linux. Native PKG remains preferred when a macOS build node exists.
            if str(target.get("platform")) == "darwin":
                options.append({
                    "value": "tar.gz",
                    "resolved": "tar.gz",
                    "label": "TAR.GZ portable",
                    "ready": True,
                    "backend": "Cross-platform",
                    "detail": "Bundle portable macOS; extraer y ejecutar sudo ./install-gideon-agent.sh. No simula una firma Apple PKG.",
                })
            result.append({
                "target_id": target_id,
                "label": str(target.get("label") or target_id),
                "platform": str(target.get("platform") or ""),
                "architecture": str(target.get("architecture") or ""),
                "profile": str(target.get("profile") or ""),
                "notes": str(target.get("notes") or ""),
                "package_options": options,
                "ready_any": any(bool(x.get("ready")) for x in options),
            })
        with self._lock:
            self._cap_cache = (now, [dict(x) for x in result])
        return result


    def builder_catalog(self) -> dict[str, Any]:
        """Return the P5 unified Builder matrix merged with live capabilities."""
        return build_catalog(self.targets())

    def resolve_builder_selection(
        self, *, builder_profile: str, os_family: str, os_variant: str,
        architecture: str, package_choice: str,
    ) -> dict[str, Any]:
        catalog = self.builder_catalog()
        result = resolve_choice(
            catalog, os_family=os_family, os_variant=os_variant,
            architecture=architecture, package_choice=package_choice,
        )
        result["builder_profile"] = normalize_profile_for_choice(
            builder_profile, result["os_family"], result["os_variant"]
        )
        return result

    def sites(self) -> list[dict[str, Any]]:
        """Merge detected, legacy and WebAdmin-managed sites for the Builder."""
        catalog: dict[str, dict[str, Any]] = {}

        # Agents enrolled before the catalog existed remain immediately usable.
        try:
            for raw in self.gateway.agents():
                code = str(raw.get("site_code") or "").strip().upper()
                name = str(raw.get("site_name") or "").strip()
                if code and code != "SIN_SEDE":
                    catalog[code.casefold()] = {
                        "code": code, "name": name or code, "description": "",
                        "managed": False, "source": "agent",
                    }
        except Exception:
            # A temporary Gateway outage must not hide the persistent catalog.
            pass

        # Preserve compatibility with packages that still ship config/sites.csv.
        path = self.app_root / "config" / "sites.csv"
        try:
            with path.open("r", encoding="utf-8-sig", newline="") as fh:
                for raw in csv.DictReader(fh):
                    code = str(raw.get("SiteCode") or "").strip().upper()
                    name = str(raw.get("SiteName") or "").strip()
                    if code and name:
                        catalog[code.casefold()] = {
                            "code": code, "name": name, "description": "",
                            "managed": False, "source": "config",
                        }
        except OSError:
            pass

        # The WebAdmin catalog is authoritative over detected/legacy labels.
        list_managed = getattr(self.security, "list_sites", None)
        if callable(list_managed):
            for raw in list_managed():
                code = str(raw.get("site_code") or "").strip().upper()
                name = str(raw.get("site_name") or "").strip()
                if code and name:
                    catalog[code.casefold()] = {
                        "code": code, "name": name,
                        "description": str(raw.get("description") or "").strip(),
                        "managed": True, "source": "managed",
                    }
        rows = list(catalog.values())
        rows.sort(key=lambda x: (x["code"], x["name"]))
        return rows

    def resolve_site(self, site_code: str, site_name: str = "") -> tuple[str, str]:
        code = str(site_code or "").strip().upper()
        if not code:
            return "", ""
        row = next((x for x in self.sites() if str(x["code"]).casefold() == code.casefold()), None)
        if row is None:
            raise AgentInstallerError("La sede seleccionada no existe en el catálogo de Sedes de WebAdmin.")
        return row["code"], row["name"]

    @staticmethod
    def normalize_agent_name(mode: str, value: str) -> tuple[str, str]:
        clean_mode = str(mode or "automatic").strip().lower()
        if clean_mode not in {"automatic", "custom"}:
            raise AgentInstallerError("Modo de nombre del Agent no permitido.")
        if clean_mode == "automatic":
            return clean_mode, ""
        clean = str(value or "").strip()
        if not clean:
            raise AgentInstallerError("Ingrese el nombre personalizado del Agent.")
        if len(clean) > 80 or any(ord(ch) < 32 for ch in clean):
            raise AgentInstallerError("El nombre personalizado del Agent no es válido.")
        return clean_mode, clean

    def _resolve_package_type(self, target_id: str, requested: str) -> str:
        targets = {x["target_id"]: x for x in self.targets()}
        row = targets.get(str(target_id))
        if row is None:
            raise AgentInstallerError("Plataforma de Agent desconocida.")
        requested = str(requested or "native")
        option = next((x for x in row["package_options"] if x["value"] == requested), None)
        if option is None:
            raise AgentInstallerError("Formato de instalador no permitido para esa plataforma.")
        if not bool(option.get("ready")):
            raise AgentInstallerError(str(option.get("detail") or "El backend de compilación no está disponible."))
        return str(option.get("resolved") or requested)

    def start_build(
        self,
        *, target_id: str, package_choice: str, gateway_url: str, channel: str,
        ttl_hours: int, max_uses: int, actor: str, remote_ip: str,
        site_code: str = "", site_name: str = "", agent_name: str = "",
        gateway_mode: str = "production", builder_profile: str = "custom",
        os_family: str = "", os_variant: str = "", architecture: str = "",
        offline_vlc_distribution: str = "", offline_vlc_codename: str = "",
        enrollment_mode: str = "individual", agent_name_mode: str = "automatic",
        vlc_delivery: str = "detached",
    ) -> dict[str, Any]:
        gateway_url = self.validate_gateway_url(gateway_url)
        gateway_mode = str(gateway_mode or "production").strip().lower()
        if gateway_mode not in {"production", "lan", "manual", "automatic", "personalized", "local_test"}:
            raise AgentInstallerError("Modo de conectividad del Gateway no permitido.")
        loopback = is_loopback_url(gateway_url)
        if gateway_mode == "local_test":
            if not loopback:
                raise AgentInstallerError("Prueba local debe apuntar exclusivamente a localhost/127.0.0.1.")
        elif loopback:
            raise AgentInstallerError(
                "127.0.0.1/localhost nunca se entrega a un Agent remoto. "
                "Seleccione explícitamente 'Prueba local - esta PC'."
            )
        if channel not in {"stable", "pilot"}:
            raise AgentInstallerError("Canal no permitido; use stable o pilot.")
        try:
            builder_profile = validate_profile(builder_profile)
            enrollment_mode, max_uses = enrollment_policy(enrollment_mode, max_uses)
        except ValueError as exc:
            raise AgentInstallerError(str(exc)) from exc
        agent_name_mode, agent_name = self.normalize_agent_name(agent_name_mode, agent_name)
        site_code, site_name = self.resolve_site(site_code, site_name)
        offline_vlc_distribution = str(offline_vlc_distribution or "").strip().casefold()
        offline_vlc_codename = str(offline_vlc_codename or "").strip().casefold()
        vlc_delivery = str(vlc_delivery or "detached").strip().casefold()
        # This is the authoritative boundary as callers other than the HTML
        # orchestrator can invoke start_build(). ``detached`` still carries the
        # reviewed VLC runtime; only its corresponding sources move to a signed
        # legal companion. The obsolete component-only mode remains blocked.
        if vlc_delivery == "component":
            raise AgentInstallerError(
                "AGENT_VLC_COMPONENT_DELIVERY_UNAVAILABLE: seleccione detached para conservar "
                "VLC operativo y descargar las fuentes legales como paquete separado."
            )
        if vlc_delivery not in {"detached", "bundled"}:
            raise AgentInstallerError("Entrega VLC no permitida. Seleccione instalador operativo o kit completo.")
        if bool(offline_vlc_distribution) != bool(offline_vlc_codename):
            raise AgentInstallerError("La selección VLC offline requiere distribución y versión juntas.")
        if offline_vlc_distribution and str(TARGETS.get(target_id, {}).get("platform") or "") != "linux":
            raise AgentInstallerError("La selección de distribución VLC offline sólo aplica a Linux.")
        status = self.security_assets.signing_status()
        if not bool(status.get("usable")):
            raise AgentInstallerError("Configure primero Seguridad → Claves y secretos → Firma Ed25519.")
        ca_path = self.gateway_ca_path()
        if ca_path is None:
            raise AgentInstallerError("No hay una CA de Gateway disponible para incluir en el Agent. Configure TLS/PKI antes de generar.")
        package_type = self._resolve_package_type(target_id, package_choice)
        resilient_endpoints = self.connection_endpoints(gateway_url, gateway_mode)
        ttl_hours = max(1, min(int(ttl_hours), 720))
        max_uses = max(1, min(int(max_uses), 100))
        request_fingerprint = _build_request_fingerprint(
            actor=actor,
            target_id=target_id,
            package_type=package_type,
            gateway_url=gateway_url,
            gateway_mode=gateway_mode,
            gateway_endpoints=resilient_endpoints,
            channel=channel,
            builder_profile=builder_profile,
            os_family=os_family,
            os_variant=os_variant,
            architecture=architecture,
            offline_vlc_distribution=offline_vlc_distribution,
            offline_vlc_codename=offline_vlc_codename,
            enrollment_mode=enrollment_mode,
            agent_name_mode=agent_name_mode,
            vlc_delivery=vlc_delivery,
            site_code=site_code,
            site_name=site_name,
            agent_name=agent_name,
            ttl_hours=ttl_hours,
            max_uses=max_uses,
        )
        with self._lock:
            rows = self._read_history()
            # Never share an enrollment grant between operators.  A duplicate
            # click by the same operator may safely join only the active request
            # with an identical non-secret fingerprint.
            existing = next((row for row in rows if (
                str(row.get("status") or "").upper() in {"QUEUED", "BUILDING"}
                and str(row.get("requested_by") or "").strip().casefold() == str(actor or "").strip().casefold()
                and str(row.get("request_fingerprint") or "") == request_fingerprint
            )), None)
            if existing is not None:
                try:
                    duplicate_count = max(0, int(existing.get("duplicate_requests") or 0)) + 1
                except (TypeError, ValueError):
                    duplicate_count = 1
                existing.update({
                    "duplicate_requests": duplicate_count,
                    "last_duplicate_at": _now(),
                    "detail": "Solicitud idéntica ya está en cola; se reutiliza sólo para el mismo operador.",
                })
                self._write_history(rows)
                result = next(
                    row for row in self._decorate_queue_rows(rows)
                    if str(row.get("build_id") or "") == str(existing.get("build_id") or "")
                )
                result["request_deduplicated"] = True
                try:
                    self.security.audit(
                        actor, "agent_installer.queue_deduplicated", "SUCCESS",
                        f"Build={result['build_id']}; Target={target_id}; Active request reused only for same operator",
                        remote_ip, resource=target_id,
                    )
                except Exception:
                    # The Web route writes its own audit entry too. A transient
                    # audit issue must not create a second enrollment grant.
                    pass
                return result

            build_id = uuid.uuid4().hex[:16]
            build_number = _next_build_number(rows)
            record = {
                "build_id": build_id,
                "build_number": build_number,
                "display_version": f"{AGENT_VERSION} · build {build_number:04d}",
                "status": "QUEUED",
                "target_id": target_id,
                "package_type": package_type,
                "version": AGENT_VERSION,
                "channel": channel,
                "gateway_url": gateway_url,
                "gateway_mode": gateway_mode,
                "gateway_endpoints": resilient_endpoints,
                "builder_profile": builder_profile,
                "os_family": str(os_family or "").strip(),
                "os_variant": str(os_variant or "").strip(),
                "architecture": str(architecture or "").strip(),
                "offline_vlc_distribution": offline_vlc_distribution,
                "offline_vlc_codename": offline_vlc_codename,
                "vlc_delivery": vlc_delivery,
                "package_profile": _package_profile(vlc_delivery),
                "source_companion": {
                    "schema": SOURCE_COMPANION_SCHEMA,
                    "delivery": vlc_delivery,
                    "status": "PENDING" if vlc_delivery == "detached" else "INCLUDED_IN_INSTALLER",
                },
                "enrollment_mode": enrollment_mode,
                "agent_name_mode": agent_name_mode,
                "site_code": str(site_code or "").strip(),
                "site_name": str(site_name or "").strip(),
                "agent_name": str(agent_name or "").strip(),
                "requested_by": actor,
                "requested_from": str(remote_ip or ""),
                "created_at": _now(),
                "started_at": "",
                "finished_at": "",
                # Do not create or persist a one-time enrollment secret while
                # a costly build waits in FIFO. It is issued in-memory only as
                # the worker receives its slot.
                "grant_id": "",
                "grant_expires_at": "",
                "grant_max_uses": max_uses,
                "grant_ttl_hours": ttl_hours,
                "grant_state": "PENDING",
                "grant_revoked_at": "",
                "prior_grant_ids": [],
                "request_fingerprint": request_fingerprint,
                "duplicate_requests": 0,
                "artifact_name": "",
                "artifact_rel": "",
                "sha256": "",
                "signature": "",
                "support_name": "",
                "support_rel": "",
                "support_sha256": "",
                "key_id": str(status.get("key_id") or ""),
                "fingerprint": str(status.get("fingerprint") or ""),
                "detail": "En cola para generar." + (" Modo LOCAL_TEST: solo esta PC." if gateway_mode == "local_test" else ""),
            }
            rows.insert(0, record)
            self._write_history(rows)
        self._schedule_pending_builds()
        result = self.get(build_id) or dict(record)
        result["request_deduplicated"] = False
        return result

    def _patch_record(self, build_id: str, **values: Any) -> dict[str, Any] | None:
        with self._lock:
            rows = self._read_history()
            found_id = ""
            for row in rows:
                if str(row.get("build_id")) == build_id:
                    row.update(values)
                    found_id = str(row.get("build_id") or "")
                    break
            self._write_history(rows)
            return next(
                (row for row in self._decorate_queue_rows(rows) if str(row.get("build_id") or "") == found_id),
                None,
            )

    def _create_failure_support_bundle(
        self, *, build_id: str, build_dir: Path, target_id: str, package_type: str, exc: Exception,
    ) -> Path | None:
        """Create a redacted Agent Builder support ZIP without payload/grant material."""
        try:
            support_dir = (Path(build_dir) / "support").resolve()
            support_dir.mkdir(parents=True, exist_ok=True)
            target = support_dir / f"GIDEON-AGENT-BUILD-SUPPORT-{build_id}.zip"
            backend, compiler = WindowsExePackager.preferred_backend() if package_type == "exe" else (package_type, None)
            files: list[dict[str, object]] = []
            for path in sorted(Path(build_dir).rglob("*")):
                if not path.is_file() or support_dir in path.parents:
                    continue
                rel = path.relative_to(build_dir).as_posix()
                lowered = rel.casefold()
                if any(token in lowered for token in ("payload", "enrollment", "secret", "private", "token")):
                    continue
                files.append({"path": rel, "size_bytes": path.stat().st_size})
            doc = {
                "schema": "gideon-agent-builder-support/v1",
                "build_id": build_id,
                "target_id": target_id,
                "package_type": package_type,
                "agent_version": AGENT_VERSION,
                "generated_at": _now(),
                "backend": backend,
                "compiler": str(compiler or ""),
                "platform": platform.platform(),
                "python_version": sys.version,
                "python_executable": sys.executable,
                "exception_type": type(exc).__name__,
                "exception": _safe_build_error(exc),
                "traceback": "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))[-20000:],
                "safe_build_files": files,
                "security_note": "No contiene payload.zip, bootstrap.enrollment, grants, claves privadas ni tokens.",
            }
            with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
                archive.writestr("builder-failure.json", json.dumps(doc, ensure_ascii=False, indent=2) + "\n")
                archive.writestr(
                    "LEAME.txt",
                    "GIDEON Agent Builder - Support Bundle\n"
                    "Adjunte este ZIP para diagnosticar un build fallido. No incluye credenciales de enrolamiento.\n",
                )
            _chmod(target, 0o640)
            return target
        except Exception:
            return None

    def _fail_queued_dispatch(self, *, build_id: str, actor: str, remote_ip: str,
                              target_id: str, exc: Exception) -> None:
        """Fail a record before the native builder has started, without secrets."""
        grant_revoked_at = ""
        grant_cleanup_error = ""
        try:
            row = self.get(build_id) or {}
            grant_id = str(row.get("grant_id") or "").strip()
            if grant_id and not str(row.get("grant_revoked_at") or "").strip():
                revoked = self.gateway.revoke_enrollment_grant(
                    grant_id, reason=f"installer-build-dispatch-failed:{build_id}"
                )
                grant_revoked_at = str(revoked.get("RevokedAt") or _now())
        except Exception as revoke_exc:
            grant_cleanup_error = " · No se pudo revocar automáticamente el grant: " + redact_error(
                revoke_exc, max_chars=800
            )
        detail = _safe_build_error(exc) + grant_cleanup_error
        self._patch_record(
            build_id,
            status="FAILED",
            finished_at=_now(),
            detail=detail,
            grant_revoked_at=grant_revoked_at,
            grant_state="REVOKED" if grant_revoked_at else "FAILED",
        )
        try:
            self.security.audit(
                actor, "agent_installer.build", "FAILED",
                f"Build={build_id}; Target={target_id}; Queue dispatch failed: {detail}",
                remote_ip, resource=target_id,
            )
        except Exception:
            pass

    def _run_queued_build(self, *, build_id: str) -> None:
        """Issue a fresh in-memory grant only after the FIFO slot is claimed."""
        row = self.get(build_id) or {}
        actor = str(row.get("requested_by") or "system")
        remote_ip = str(row.get("requested_from") or "")
        target_id = str(row.get("target_id") or "")
        try:
            if str(row.get("status") or "").upper() != "BUILDING":
                return
            status = self.security_assets.signing_status()
            if not bool(status.get("usable")):
                raise AgentInstallerError("Configure primero Seguridad → Claves y secretos → Firma Ed25519.")
            ca_path = self.gateway_ca_path()
            if ca_path is None:
                raise AgentInstallerError("No hay una CA de Gateway disponible para incluir en el Agent. Configure TLS/PKI antes de generar.")
            ttl_hours = max(1, min(int(row.get("grant_ttl_hours") or 24), 720))
            max_uses = max(1, min(int(row.get("grant_max_uses") or 1), 100))
            grant = self.gateway.issue_enrollment_grant(
                ttl_seconds=ttl_hours * 3600,
                max_uses=max_uses,
                label=f"web-builder:{target_id}:{actor}"[:120],
            )
            enrollment_grant = str(grant.get("EnrollmentGrant") or "")
            if not enrollment_grant:
                raise AgentInstallerError("El Gateway no devolvió la credencial temporal de enrolamiento.")
            self._patch_record(
                build_id,
                grant_id=str(grant.get("GrantId") or ""),
                grant_expires_at=str(grant.get("ExpiresAt") or ""),
                grant_state="ISSUED",
                grant_revoked_at="",
                key_id=str(status.get("key_id") or row.get("key_id") or ""),
                fingerprint=str(status.get("fingerprint") or row.get("fingerprint") or ""),
                detail="Generando instalador y verificando integridad…",
            )
            self._run_build(
                build_id=build_id,
                target_id=target_id,
                package_type=str(row.get("package_type") or ""),
                gateway_url=str(row.get("gateway_url") or ""),
                gateway_mode=str(row.get("gateway_mode") or ""),
                gateway_endpoints=[dict(item) for item in row.get("gateway_endpoints") or [] if isinstance(item, dict)],
                channel=str(row.get("channel") or "stable"),
                enrollment_grant=enrollment_grant,
                ca_path=ca_path,
                actor=actor,
                remote_ip=remote_ip,
                site_code=str(row.get("site_code") or ""),
                site_name=str(row.get("site_name") or ""),
                agent_name=str(row.get("agent_name") or ""),
                build_number=int(row.get("build_number") or 0),
                offline_vlc_distribution=str(row.get("offline_vlc_distribution") or ""),
                offline_vlc_codename=str(row.get("offline_vlc_codename") or ""),
                vlc_delivery=str(row.get("vlc_delivery") or "bundled"),
            )
        except Exception as exc:
            self._fail_queued_dispatch(
                build_id=build_id, actor=actor, remote_ip=remote_ip, target_id=target_id, exc=exc
            )
        finally:
            # The grant value is never written to history and is discarded as
            # soon as the worker exits. Free the slot even after a failed
            # gateway/signing preflight so the next FIFO item can proceed.
            with self._lock:
                self._threads.pop(build_id, None)
            self._schedule_pending_builds()

    def _validate_generated_source_companion(
        self,
        *,
        target_id: str,
        build_dir: Path,
        vlc_delivery: str,
        descriptor: dict[str, Any] | None,
        public_key_path: Path,
        fingerprint: str,
    ) -> dict[str, Any]:
        """Normalize and authenticate the separately downloadable GPL sources."""
        delivery = str(vlc_delivery or "bundled").strip().casefold()
        platform_name = str(TARGETS.get(target_id, {}).get("platform") or "").strip().casefold()
        if delivery == "bundled":
            return {
                "schema": SOURCE_COMPANION_SCHEMA,
                "delivery": delivery,
                "status": "INCLUDED_IN_INSTALLER" if platform_name in {"windows", "linux"} else "NOT_APPLICABLE",
            }
        if delivery != "detached":
            raise AgentInstallerError("SOURCE_COMPANION_DELIVERY_INVALID")
        raw = dict(descriptor or {})
        if not raw and platform_name not in {"windows", "linux"}:
            return {"schema": SOURCE_COMPANION_SCHEMA, "delivery": delivery, "status": "NOT_APPLICABLE"}
        if str(raw.get("schema") or "") != SOURCE_COMPANION_SCHEMA:
            raise AgentInstallerError("SOURCE_COMPANION_SCHEMA_INVALID")
        artifact_value = raw.get("artifact") or raw.get("path")
        if not artifact_value:
            raise AgentInstallerError("SOURCE_COMPANION_ARTIFACT_MISSING")
        source_path = Path(str(artifact_value)).expanduser()
        if not source_path.is_absolute():
            source_path = self.source_companions_dir / source_path
        source_path = source_path.resolve()
        resolved_companion_dir = self.source_companions_dir.resolve()
        if resolved_companion_dir not in source_path.parents or not source_path.is_file():
            raise AgentInstallerError("SOURCE_COMPANION_PATH_INVALID")
        artifact_name = str(raw.get("artifact_name") or source_path.name).strip()
        if artifact_name != source_path.name or source_path.suffix.casefold() != ".zip":
            raise AgentInstallerError("SOURCE_COMPANION_NAME_INVALID")
        expected_sha = str(raw.get("sha256") or "").strip().casefold()
        if len(expected_sha) != 64 or any(ch not in "0123456789abcdef" for ch in expected_sha):
            raise AgentInstallerError("SOURCE_COMPANION_SHA256_INVALID")
        actual_sha = _sha256(source_path)
        if actual_sha != expected_sha:
            raise AgentInstallerError("SOURCE_COMPANION_SHA256_MISMATCH")
        if artifact_name != f"{actual_sha}.zip":
            raise AgentInstallerError("SOURCE_COMPANION_CONTENT_ADDRESS_INVALID")
        try:
            expected_size = int(raw.get("size_bytes") or 0)
        except (TypeError, ValueError) as exc:
            raise AgentInstallerError("SOURCE_COMPANION_SIZE_INVALID") from exc
        if expected_size <= 0 or source_path.stat().st_size != expected_size:
            raise AgentInstallerError("SOURCE_COMPANION_SIZE_MISMATCH")
        signature = str(raw.get("signature") or "").strip()
        signature_scheme = str(raw.get("signature_scheme") or "").strip()
        try:
            public = serialization.load_pem_public_key(public_key_path.read_bytes())
            if signature_scheme != SOURCE_COMPANION_SIGNATURE_SCHEME or not isinstance(public, Ed25519PublicKey):
                raise TypeError("esquema o clave de firma inválidos")
            public.verify(
                base64.b64decode(signature, validate=True),
                SOURCE_COMPANION_SIGNATURE_DOMAIN + bytes.fromhex(actual_sha),
            )
        except Exception as exc:
            raise AgentInstallerError("SOURCE_COMPANION_SIGNATURE_INVALID") from exc
        key_id = str(raw.get("key_id") or "").strip()
        catalog_version = str(raw.get("catalog_version") or "").strip()
        source_ids = sorted({str(item).strip() for item in (raw.get("source_ids") or []) if str(item).strip()})
        if not key_id or not catalog_version or not source_ids:
            raise AgentInstallerError("SOURCE_COMPANION_METADATA_INCOMPLETE")
        target = dict(raw.get("target") or {}) if isinstance(raw.get("target"), dict) else {}
        return {
            "schema": SOURCE_COMPANION_SCHEMA,
            "delivery": delivery,
            "status": "READY",
            "artifact_name": artifact_name,
            "artifact_rel": str(source_path.relative_to(self.root)),
            "storage": "content-addressed-shared",
            "sha256": actual_sha,
            "size_bytes": expected_size,
            "signature": signature,
            "signature_scheme": signature_scheme,
            "key_id": key_id,
            "fingerprint": str(fingerprint or ""),
            "public_key_pem": public_key_path.read_text(encoding="utf-8-sig"),
            "catalog_version": catalog_version,
            "source_ids": source_ids,
            "target": target,
        }

    def _run_build(
        self, *, build_id: str, target_id: str, package_type: str, gateway_url: str,
        gateway_mode: str, gateway_endpoints: list[dict[str, Any]],
        channel: str, enrollment_grant: str, ca_path: Path, actor: str, remote_ip: str,
        site_code: str, site_name: str, agent_name: str, build_number: int,
        offline_vlc_distribution: str, offline_vlc_codename: str, vlc_delivery: str,
    ) -> None:
        self._patch_record(build_id, status="BUILDING", started_at=_now(), detail="Generando instalador y verificando integridad…")
        build_dir = self.artifacts_dir / build_id
        build_dir.mkdir(parents=True, exist_ok=True)
        _chmod(build_dir, 0o750)
        try:
            private_bytes = self.security_assets.signing_private_key_bytes()
            public_bytes = self.security_assets.signing_public_key_bytes()
            with tempfile.TemporaryDirectory(prefix="gideon-web-agent-key-") as td:
                key_root = Path(td)
                private_path = key_root / "execution-private.pem"
                public_path = key_root / "execution-public.pem"
                private_path.write_bytes(private_bytes)
                public_path.write_bytes(public_bytes)
                _chmod(private_path, 0o600)
                _chmod(public_path, 0o600)
                catalog = AgentDownloadCatalog(self.app_root)
                catalog.state_dir = self.root / "catalog-state"
                catalog.state_dir.mkdir(parents=True, exist_ok=True)
                catalog.registry = catalog.state_dir / "catalog.json"
                catalog.builder.private_key = private_path
                catalog.builder.public_key = public_path
                artifact = catalog.generate(
                    target_id,
                    version=AGENT_VERSION,
                    channel=channel,
                    gateway_url=gateway_url,
                    connectivity_mode=gateway_mode,
                    gateway_endpoints=gateway_endpoints,
                    output_dir=build_dir,
                    package_type=package_type,
                    gateway_ca_file_override=ca_path,
                    enrollment_grant=enrollment_grant,
                    site_code=site_code,
                    site_name=site_name,
                    agent_name=agent_name,
                    offline_vlc_distribution=offline_vlc_distribution,
                    offline_vlc_codename=offline_vlc_codename,
                    vlc_delivery=vlc_delivery,
                    source_companion_dir=self.source_companions_dir,
                    allow_toolchain_install=False,
                )
                contract = dict(catalog.last_installer_contract or {})
                artifact_validation = dict(catalog.last_artifact_validation or {})
                source_companion = self._validate_generated_source_companion(
                    target_id=target_id,
                    build_dir=build_dir,
                    vlc_delivery=vlc_delivery,
                    descriptor=getattr(catalog, "last_vlc_source_companion", None),
                    public_key_path=public_path,
                    fingerprint=str((self.get(build_id) or {}).get("fingerprint") or ""),
                )
            artifact = Path(artifact).resolve()
            if build_dir.resolve() not in artifact.parents or not artifact.is_file():
                raise AgentInstallerError("El builder devolvió un artefacto fuera del directorio GIDEON permitido.")
            # RC30.95.18: READY is a contract state, not merely "file exists".
            # Old/partial/corrupt-install repair, version coherence and native
            # service policy must all be present in the payload before publish.
            if str(contract.get("status") or "") != "PASS":
                raise AgentInstallerError("INSTALLER_CONTRACT_NOT_PASS: WebAdmin bloqueó la publicación.")
            if str(contract.get("agent_version") or "") != str(AGENT_VERSION):
                raise AgentInstallerError("INSTALLER_CONTRACT_VERSION_MISMATCH: WebAdmin bloqueó la publicación.")
            if str(contract.get("target_id") or "") != str(target_id):
                raise AgentInstallerError("INSTALLER_CONTRACT_TARGET_MISMATCH: WebAdmin bloqueó la publicación.")
            if str(artifact_validation.get("status") or "") != "PASS":
                raise AgentInstallerError("INSTALLER_ARTIFACT_VALIDATION_NOT_PASS: WebAdmin bloqueó la publicación.")
            numbered_artifact = _artifact_with_build_suffix(artifact, build_number)
            os.replace(artifact, numbered_artifact)
            artifact = numbered_artifact.resolve()
            _chmod(artifact, 0o640)
            digest = _sha256(artifact)
            if str(artifact_validation.get("artifact_sha256") or "").casefold() != digest.casefold():
                raise AgentInstallerError("INSTALLER_ARTIFACT_HASH_CHANGED_AFTER_VALIDATION")
            private = serialization.load_pem_private_key(private_bytes, password=None)
            if not isinstance(private, Ed25519PrivateKey):
                raise AgentInstallerError("La clave de firma activa ya no es Ed25519.")
            signed_message = b"GIDEON-INSTALLER-SHA256-V1\0" + bytes.fromhex(digest)
            signature = base64.b64encode(private.sign(signed_message)).decode("ascii")
            detail = (
                f"Instalador listo. Agent {AGENT_VERSION} · build {build_number:04d} · INSTALLER CONTRACT PASS · "
                "upgrade/repair + identity recovery + native service + Final Acceptance verificados; "
                "Remote Readiness administrado; no contiene la clave privada de firma. "
                + (
                    "Instalador operativo reducido: incluye VLC revisado y avisos; las fuentes legales "
                    "quedan en un Source Companion ZIP autenticado por SHA-256 y Ed25519."
                    if vlc_delivery == "detached"
                    else "Kit completo: incluye VLC offline, avisos y fuentes correspondientes GPL."
                )
            )
            row = self._patch_record(
                build_id,
                status="READY",
                finished_at=_now(),
                artifact_name=artifact.name,
                artifact_rel=str(artifact.relative_to(self.root)),
                sha256=digest,
                signature=signature,
                installer_contract_status="PASS",
                installer_contract_sha256=str(contract.get("contract_sha256") or ""),
                artifact_validation_status="PASS",
                installer_contract_checks=list(contract.get("checks") or []),
                vlc_delivery=vlc_delivery,
                package_profile=_package_profile(vlc_delivery),
                source_companion=source_companion,
                detail=detail,
            )
            self.security.audit(
                actor, "agent_installer.build", "SUCCESS",
                f"Build={build_id}; Number={build_number}; Target={target_id}; Package={package_type}; Sha256={digest}",
                remote_ip, resource=artifact.name,
            )
        except Exception as exc:
            grant_revoked_at = ""
            grant_cleanup_error = ""
            try:
                failed_record = self.get(build_id) or {}
                grant_id = str(failed_record.get("grant_id") or "").strip()
                if grant_id and not str(failed_record.get("grant_revoked_at") or "").strip():
                    revoked = self.gateway.revoke_enrollment_grant(
                        grant_id, reason=f"installer-build-failed:{build_id}"
                    )
                    grant_revoked_at = str(revoked.get("RevokedAt") or _now())
            except Exception as revoke_exc:
                grant_cleanup_error = " · No se pudo revocar automáticamente el grant: " + redact_error(
                    revoke_exc, max_chars=800
                )
            support = getattr(exc, "support_bundle", None)
            try:
                support = Path(support).resolve() if support else None
            except (TypeError, ValueError, OSError):
                support = None
            if not support or not support.is_file() or build_dir.resolve() not in support.parents:
                support = self._create_failure_support_bundle(
                    build_id=build_id, build_dir=build_dir, target_id=target_id, package_type=package_type, exc=exc
                )
            support_name = support.name if support and support.is_file() else ""
            support_rel = str(support.relative_to(self.root)) if support and support.is_file() else ""
            support_sha256 = _sha256(support) if support and support.is_file() else ""
            detail = _safe_build_error(exc)
            detail += grant_cleanup_error
            if support_name:
                detail += " · Diagnóstico del build disponible para descargar."
            self._patch_record(
                build_id, status="FAILED", finished_at=_now(), detail=detail,
                support_name=support_name, support_rel=support_rel, support_sha256=support_sha256,
                grant_revoked_at=grant_revoked_at,
            )
            self.security.audit(
                actor, "agent_installer.build", "FAILED",
                f"Build={build_id}; Target={target_id}; {_safe_build_error(exc)}; Support={support_name or '-'}",
                remote_ip, resource=target_id,
            )
        finally:
            # Do not retain the one-time grant in memory longer than this build.
            enrollment_grant = ""

    def mark_grant_revoked(self, build_id: str, revoked_at: str) -> dict[str, Any] | None:
        return self._patch_record(build_id, grant_revoked_at=str(revoked_at or _now()))

    def artifact_path(self, build_id: str) -> Path:
        row = self.get(build_id)
        if row is None or str(row.get("status")) != "READY":
            raise FileNotFoundError("El instalador no está disponible.")
        # RC30.95.18: legacy READY rows were created before the fail-closed
        # installer contract existed. Keep them in history for audit, but never
        # serve them as deployment media. Generate a current installer instead.
        if str(row.get("version") or "") != str(AGENT_VERSION):
            raise AgentInstallerError(
                f"Instalador legacy {row.get('version') or '?'} bloqueado. Genere Agent {AGENT_VERSION} desde WebAdmin."
            )
        if str(row.get("installer_contract_status") or "") != "PASS" or str(row.get("artifact_validation_status") or "") != "PASS":
            raise AgentInstallerError("Instalador sin INSTALLER CONTRACT PASS; descarga bloqueada. Genere un build nuevo.")
        rel = Path(str(row.get("artifact_rel") or ""))
        if rel.is_absolute() or ".." in rel.parts:
            raise AgentInstallerError("Ruta de artefacto inválida.")
        path = (self.root / rel).resolve()
        if self.root not in path.parents or not path.is_file():
            raise FileNotFoundError("El instalador ya no existe en disco.")
        expected = str(row.get("sha256") or "")
        if _sha256(path) != expected:
            raise AgentInstallerError("La integridad SHA-256 del instalador cambió; descarga bloqueada.")
        return path

    @staticmethod
    def _public_source_companion(build_id: str, row: dict[str, Any]) -> dict[str, Any] | None:
        companion = row.get("source_companion")
        if not isinstance(companion, dict) or str(companion.get("status") or "") != "READY":
            return None
        return {
            "schema": str(companion.get("schema") or SOURCE_COMPANION_SCHEMA),
            "delivery": "detached",
            "status": "READY",
            "artifact": str(companion.get("artifact_name") or ""),
            "sha256": str(companion.get("sha256") or ""),
            "size_bytes": int(companion.get("size_bytes") or 0),
            "signature_ed25519_base64": str(companion.get("signature") or ""),
            "signature_scheme": str(companion.get("signature_scheme") or ""),
            "key_id": str(companion.get("key_id") or ""),
            "fingerprint": str(companion.get("fingerprint") or ""),
            "public_key_pem": str(companion.get("public_key_pem") or ""),
            "catalog_version": str(companion.get("catalog_version") or ""),
            "source_ids": [str(item) for item in (companion.get("source_ids") or [])],
            "target": dict(companion.get("target") or {}) if isinstance(companion.get("target"), dict) else {},
            "storage": str(companion.get("storage") or ""),
            "download_url": f"/installers/builds/{build_id}/sources/download",
            "signature_url": f"/installers/builds/{build_id}/sources/signature.json",
        }

    def source_companions(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return safe metadata for ready legal companions without filesystem paths."""
        result: list[dict[str, Any]] = []
        by_sha: dict[str, dict[str, Any]] = {}
        for row in self.history(max(1, min(int(limit), 200))):
            build_id = str(row.get("build_id") or "")
            public = self._public_source_companion(build_id, row)
            if public is None:
                continue
            digest = str(public.get("sha256") or "")
            if digest in by_sha:
                by_sha[digest]["build_ids"].append(build_id)
                by_sha[digest]["reference_count"] = len(by_sha[digest]["build_ids"])
                continue
            public.update({
                "build_id": build_id,
                "build_number": row.get("build_number"),
                "display_version": row.get("display_version"),
                "version": row.get("version"),
                "target_id": row.get("target_id"),
                "created_at": row.get("finished_at") or row.get("created_at"),
                "requested_by": row.get("requested_by"),
                "build_ids": [build_id],
                "reference_count": 1,
            })
            result.append(public)
            by_sha[digest] = public
        return result

    def source_companion_path(self, build_id: str) -> Path:
        row = self.get(build_id)
        if row is None or str(row.get("status") or "") != "READY":
            raise FileNotFoundError("Build no disponible.")
        companion = row.get("source_companion")
        if not isinstance(companion, dict) or str(companion.get("status") or "") != "READY":
            raise FileNotFoundError("Este build no tiene un paquete legal de fuentes separado.")
        rel = Path(str(companion.get("artifact_rel") or ""))
        if not str(rel) or rel.is_absolute() or ".." in rel.parts:
            raise AgentInstallerError("Ruta del paquete legal inválida.")
        path = (self.root / rel).resolve()
        if self.root not in path.parents or not path.is_file():
            raise FileNotFoundError("El paquete legal de fuentes ya no existe en disco.")
        expected_sha = str(companion.get("sha256") or "").strip().casefold()
        if not expected_sha or _sha256(path) != expected_sha:
            raise AgentInstallerError("La integridad SHA-256 del paquete legal cambió; descarga bloqueada.")
        try:
            expected_size = int(companion.get("size_bytes") or 0)
        except (TypeError, ValueError) as exc:
            raise AgentInstallerError("Tamaño declarado del paquete legal inválido.") from exc
        if expected_size <= 0 or path.stat().st_size != expected_size:
            raise AgentInstallerError("El tamaño del paquete legal cambió; descarga bloqueada.")
        try:
            public = serialization.load_pem_public_key(
                str(companion.get("public_key_pem") or "").encode("utf-8")
            )
            if not isinstance(public, Ed25519PublicKey):
                raise TypeError("la clave pública no es Ed25519")
            public.verify(
                base64.b64decode(str(companion.get("signature") or ""), validate=True),
                SOURCE_COMPANION_SIGNATURE_DOMAIN + bytes.fromhex(expected_sha),
            )
            if str(companion.get("signature_scheme") or "") != SOURCE_COMPANION_SIGNATURE_SCHEME:
                raise TypeError("esquema de firma no permitido")
        except Exception as exc:
            raise AgentInstallerError("La firma Ed25519 del paquete legal no es válida; descarga bloqueada.") from exc
        return path

    def artifact_document(self, build_id: str) -> dict[str, Any]:
        row = self.get(build_id)
        if row is None or str(row.get("status") or "") != "READY":
            raise FileNotFoundError("Build no disponible.")
        artifact = self.artifact_path(build_id)
        companion = self._public_source_companion(build_id, row)
        if companion is not None:
            self.source_companion_path(build_id)
        return {
            "schema": "gideon-agent-installer-artifacts/v1",
            "build_id": build_id,
            "package_profile": str(row.get("package_profile") or _package_profile(str(row.get("vlc_delivery") or "bundled"))),
            "installer": {
                "artifact": artifact.name,
                "sha256": row.get("sha256"),
                "signature_ed25519_base64": row.get("signature"),
                "key_id": row.get("key_id"),
                "fingerprint": row.get("fingerprint"),
                "download_url": f"/installers/builds/{build_id}/download",
            },
            "source_companion": companion,
        }

    def support_bundle_path(self, build_id: str) -> Path:
        row = self.get(build_id)
        if row is None:
            raise FileNotFoundError("Build no encontrado.")
        rel = Path(str(row.get("support_rel") or ""))
        if not str(rel) or rel.is_absolute() or ".." in rel.parts:
            raise FileNotFoundError("Este build no tiene diagnóstico descargable.")
        path = (self.root / rel).resolve()
        if self.root not in path.parents or not path.is_file():
            raise FileNotFoundError("El diagnóstico del build ya no existe.")
        expected = str(row.get("support_sha256") or "")
        if expected and _sha256(path) != expected:
            raise AgentInstallerError("La integridad SHA-256 del diagnóstico cambió; descarga bloqueada.")
        return path

    def signature_document(self, build_id: str) -> bytes:
        row = self.get(build_id)
        if row is None or str(row.get("status")) != "READY":
            raise FileNotFoundError("Build no disponible.")
        doc = {
            "schema": "gideon-agent-installer-signature/v1",
            "build_id": build_id,
            "build_number": row.get("build_number"),
            "display_version": row.get("display_version"),
            "artifact": row.get("artifact_name"),
            "sha256": row.get("sha256"),
            "signature_ed25519_base64": row.get("signature"),
            "key_id": row.get("key_id"),
            "fingerprint": row.get("fingerprint"),
            "version": row.get("version"),
            "target_id": row.get("target_id"),
            "created_at": row.get("finished_at"),
            "package_profile": str(row.get("package_profile") or _package_profile(str(row.get("vlc_delivery") or "bundled"))),
            "source_companion": self._public_source_companion(build_id, row),
        }
        return (json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8")

    def source_companion_signature_document(self, build_id: str) -> bytes:
        row = self.get(build_id)
        if row is None or str(row.get("status") or "") != "READY":
            raise FileNotFoundError("Build no disponible.")
        # Validate the bytes immediately before exposing their attestation.
        self.source_companion_path(build_id)
        companion = self._public_source_companion(build_id, row)
        if companion is None:
            raise FileNotFoundError("Este build no tiene un paquete legal de fuentes separado.")
        doc = {
            "schema": "gideon-vlc-source-companion-signature/v1",
            "build_id": build_id,
            "package_profile": "operational-reduced",
            **companion,
        }
        return (json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
