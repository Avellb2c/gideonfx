from __future__ import annotations

import os
import base64
import hashlib
import json
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote, urlencode

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from gideon_agent_http import AgentHttpClient, AgentHttpError
from gideon_agent_update_builder import AgentUpdateBundleBuilder, MAX_SELF_UPDATE_BUNDLE_BYTES
from gideon_version import AGENT_VERSION


class GatewayFacade:
    """Resilient WebAdmin view of the Gateway.

    Read endpoints use a small stale-if-error cache plus a circuit breaker so a
    transient TLS/Gateway saturation never takes down the administrative UI.
    Mutations remain fail-closed and are never served from cache.
    """
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self._cache: dict[str, tuple[float, Any]] = {}
        self._cache_lock = threading.RLock()
        self._failures = 0
        self._circuit_open_until = 0.0
        self._last_error = ""
        self._client_instance: AgentHttpClient | None = None
        self._refreshing_keys: set[str] = set()

    def _cached_read(self, key: str, fetch: Any, *, fresh_seconds: float = 3.0, stale_seconds: float = 180.0) -> Any:
        now = time.monotonic()
        with self._cache_lock:
            cached = self._cache.get(key)
            if cached and now - cached[0] <= fresh_seconds:
                return cached[1]
            circuit_open = now < self._circuit_open_until
        if circuit_open and cached and now - cached[0] <= stale_seconds:
            return cached[1]
        try:
            value = fetch()
        except Exception as exc:
            with self._cache_lock:
                self._failures += 1
                self._last_error = f"{type(exc).__name__}: {exc}"
                if self._failures >= 3:
                    self._circuit_open_until = time.monotonic() + 5.0
                cached = self._cache.get(key)
            if cached and time.monotonic() - cached[0] <= stale_seconds:
                return cached[1]
            raise
        with self._cache_lock:
            self._cache[key] = (time.monotonic(), value)
            self._failures = 0
            self._circuit_open_until = 0.0
            self._last_error = ""
        return value

    def resilience_state(self) -> dict[str, Any]:
        with self._cache_lock:
            return {
                "CircuitOpen": time.monotonic() < self._circuit_open_until,
                "LastError": self._last_error,
                "CachedKeys": sorted(self._cache),
            }

    def client(self) -> AgentHttpClient:
        # Reuse the SSLContext/client object across WebAdmin requests. urllib still
        # owns each HTTP response lifetime, but TLS policy/CA parsing is no longer
        # rebuilt on every dashboard call.
        with self._cache_lock:
            if self._client_instance is not None:
                return self._client_instance
            base = str(self.config.get("gateway_base_url") or "").rstrip("/")
            token_env = str(self.config.get("gateway_admin_token_env") or "GIDEON_AGENT_ADMIN_TOKEN")
            token = str(self.config.get("gateway_admin_token") or os.environ.get(token_env, ""))
            if not base:
                raise RuntimeError("gateway_base_url no está configurado.")
            if not token:
                raise RuntimeError(f"No existe token administrativo del Gateway en {token_env}.")
            ca = str(self.config.get("gateway_ca_file") or "").strip() or None
            self._client_instance = AgentHttpClient(
                base,
                bearer_token=token,
                verify_tls=bool(self.config.get("gateway_verify_tls", True)),
                ca_file=ca,
                require_https=bool(self.config.get("gateway_require_https", True)),
            )
            return self._client_instance

    def health(self) -> dict[str, Any]:
        return self._cached_read(
            "health", lambda: self.client().json("GET", "/api/v1/admin/health", timeout=4),
            fresh_seconds=2.0, stale_seconds=60.0,
        )

    def agents(self) -> list[dict[str, Any]]:
        def fetch() -> list[dict[str, Any]]:
            data = self.client().json("GET", "/api/v1/admin/agents", timeout=6)
            return [dict(x) for x in (data.get("Agents") or []) if isinstance(x, dict)]
        return self._cached_read("agents", fetch, fresh_seconds=3.0, stale_seconds=180.0)

    def releases(self) -> list[dict[str, Any]]:
        def fetch() -> list[dict[str, Any]]:
            data = self.client().json("GET", "/api/v2/admin/releases", timeout=6)
            return [dict(x) for x in (data.get("Releases") or []) if isinstance(x, dict)]
        return self._cached_read("releases", fetch, fresh_seconds=5.0, stale_seconds=300.0)

    def jobs(self, *, limit: int = 300, status: str = "", agent_id: str = "", job_id: str = "") -> list[dict[str, Any]]:
        params = {"limit": max(1, min(int(limit), 2000))}
        if status:
            params["status"] = status
        if agent_id:
            params["agent_id"] = agent_id
        if job_id:
            params["job_id"] = job_id
        cache_key = "jobs:" + urlencode(sorted(params.items()))
        def fetch() -> list[dict[str, Any]]:
            data = self.client().json("GET", "/api/v1/admin/jobs?" + urlencode(params), timeout=7)
            return [dict(x) for x in (data.get("Jobs") or []) if isinstance(x, dict)]
        return self._cached_read(cache_key, fetch, fresh_seconds=2.0, stale_seconds=120.0)

    def jobs_fast(self, *, limit: int = 250, status: str = "", agent_id: str = "", job_id: str = "") -> list[dict[str, Any]]:
        """Fast Jobs overview for interactive WebAdmin pages.

        Uses the same stale cache as ``jobs()`` but caps a cold Gateway read to
        1.5 s so the Jobs page is never held by a slow Gateway for the normal
        7 s API timeout. A recent cached snapshot is preferred immediately.
        Mutations are unaffected.
        """
        params = {"limit": max(1, min(int(limit), 1000))}
        if status:
            params["status"] = status
        if agent_id:
            params["agent_id"] = agent_id
        if job_id:
            params["job_id"] = job_id
        cache_key = "jobs:" + urlencode(sorted(params.items()))
        now = time.monotonic()
        def fetch_and_store() -> list[dict[str, Any]]:
            data = self.client().json("GET", "/api/v1/admin/jobs?" + urlencode(params), timeout=1.5)
            value = [dict(x) for x in (data.get("Jobs") or []) if isinstance(x, dict)]
            with self._cache_lock:
                self._cache[cache_key] = (time.monotonic(), value)
                self._last_error = ""
            return value

        def refresh_in_background() -> None:
            try:
                fetch_and_store()
            except Exception as exc:
                with self._cache_lock:
                    self._last_error = f"{type(exc).__name__}: {exc}"
            finally:
                with self._cache_lock:
                    self._refreshing_keys.discard(cache_key)

        with self._cache_lock:
            cached = self._cache.get(cache_key)
            age = now - cached[0] if cached else float("inf")
            if cached and age <= 2.0:
                return cached[1]
            if cached and age <= 120.0:
                if cache_key not in self._refreshing_keys:
                    self._refreshing_keys.add(cache_key)
                    threading.Thread(
                        target=refresh_in_background,
                        name="gideon-gateway-jobs-refresh",
                        daemon=True,
                    ).start()
                return cached[1]
        try:
            return fetch_and_store()
        except Exception as exc:
            with self._cache_lock:
                self._last_error = f"{type(exc).__name__}: {exc}"
                cached = self._cache.get(cache_key)
            return cached[1] if cached else []

    def job(self, job_id: str) -> list[dict[str, Any]]:
        data = self.client().json("GET", f"/api/v1/admin/jobs/{job_id}", timeout=12)
        return [dict(x) for x in (data.get("Sites") or []) if isinstance(x, dict)]

    def cancel(self, job_id: str, agent_id: str) -> dict[str, Any]:
        return self.client().json("POST", f"/api/v1/admin/jobs/{job_id}/{agent_id}/cancel", {}, timeout=15)

    def purge_agent(self, agent_id: str) -> dict[str, Any]:
        return self.client().json("POST", f"/api/v1/admin/agents/{agent_id}/purge", {}, timeout=15)

    def approve_release(self, row: dict[str, Any], approved: bool, *, actor: str, note: str = "") -> dict[str, Any]:
        platform = str(row.get("platform") or "").strip()
        architecture = str(row.get("architecture") or "").strip()
        channel = str(row.get("channel") or "").strip()
        version = str(row.get("version") or "").strip()
        if not all((platform, architecture, channel, version)):
            raise ValueError("Release incompleto: plataforma/arquitectura/canal/versión.")
        payload = {
            "Platform": platform, "Architecture": architecture,
            "Channel": channel, "Version": version,
            "Approved": bool(approved), "ApprovedBy": actor, "Note": note,
        }
        client = self.client()
        try:
            return client.json("POST", "/api/v2/admin/releases/approval", payload, timeout=30)
        except AgentHttpError as exc:
            text = str(exc)
            if "HTTP 404" not in text:
                raise
            action = "approve" if approved else "revoke"
            legacy = f"/api/v2/admin/releases/{platform}/{architecture}/{channel}/{version}/{action}"
            try:
                return client.json("POST", legacy, {"ApprovedBy": actor, "Note": note}, timeout=30)
            except AgentHttpError as legacy_exc:
                raise AgentHttpError(
                    "El Gateway activo no expone la API de aprobación de releases. "
                    "Repare/actualice únicamente GIDEONRemoteControlGateway y vuelva a intentar. Detalle: " + str(legacy_exc)
                ) from legacy_exc

    def cleanup_releases(self, *, keep_per_target: int = 2, actor: str = "console", dry_run: bool = False) -> dict[str, Any]:
        try:
            return self.client().json(
                "POST", "/api/v2/admin/releases/cleanup",
                {"KeepPerTarget": max(1, min(int(keep_per_target or 2), 20)), "Actor": actor, "DryRun": bool(dry_run)},
                timeout=30,
            )
        finally:
            # A network failure can occur after the Gateway has committed the
            # mutation.  Evict any snapshot in either case; a subsequent read
            # must not claim that the old release inventory is authoritative.
            if not dry_run:
                with self._cache_lock:
                    self._cache.pop("releases", None)

    def publish_release(self, row: dict[str, Any], bundle: Path) -> dict[str, Any]:
        platform = str(row.get("platform") or "").strip().lower()
        architecture = str(row.get("architecture") or "").strip().lower()
        channel = str(row.get("channel") or "").strip().lower()
        version = str(row.get("version") or "").strip()
        signature = str(row.get("signature") or "").strip()
        key_id = str(row.get("key_id") or "gideon-agent-ed25519-1").strip()
        if channel != "stable":
            raise ValueError("La publicación corporativa automática solo admite canal stable.")
        if not all((platform, architecture, version, signature, key_id)):
            raise ValueError("Release local incompleto para publicación.")
        bundle = Path(bundle).resolve()
        if not bundle.is_file():
            raise FileNotFoundError(bundle)
        return self.client().upload_file(
            "PUT", f"/api/v2/admin/releases/{platform}/{architecture}/{channel}/{version}", bundle,
            headers={
                "X-GIDEON-Protocol-Version": "2.0",
                "X-GIDEON-Signature": signature,
                "X-GIDEON-Key-Id": key_id,
                # The Gateway validates this while ingesting the streamed body.
                # Without the expected digest, transport corruption could only
                # be discovered later when an Agent attempted the release.
                "X-GIDEON-SHA256": str(row.get("sha256") or _sha256(bundle)).lower(),
            }, timeout=120,
        )

    def issue_enrollment_grant(self, *, ttl_seconds: int, max_uses: int, label: str) -> dict[str, Any]:
        return self.client().json(
            "POST", "/api/v1/admin/enrollment-grants",
            {"TtlSeconds": int(ttl_seconds), "MaxUses": int(max_uses), "Label": label}, timeout=20,
        )

    def open_reverse_tunnel(self, agent_id: str, *, protocol: str, target_port: int = 0,
                            session_switch: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """Reserve a one-use broker port to the Agent's loopback RDP/VNC service."""
        purpose = str(protocol or "RDP").strip().upper()
        default_port = {"RDP": 3389, "VNC": 5900}.get(purpose)
        if default_port is None:
            raise ValueError("El túnel inverso solo admite RDP o VNC.")
        port = int(target_port or default_port)
        if port < 1 or port > 65535:
            raise ValueError("Puerto de destino inválido para el túnel inverso.")
        clean_agent_id = str(agent_id or "").strip()
        if not clean_agent_id:
            raise ValueError("AgentId requerido para abrir el túnel inverso.")
        return self.client().json(
            "POST", "/api/v1/admin/tunnels/open",
            {
                "AgentId": clean_agent_id,
                "Purpose": purpose,
                "TargetHost": "127.0.0.1",
                "TargetPort": port,
                "SessionSwitch": dict(session_switch or {}),
            },
            timeout=15,
        )


    def enrollment_grants(self) -> list[dict[str, Any]]:
        data = self.client().json("GET", "/api/v1/admin/enrollment-grants", timeout=12)
        return [dict(x) for x in (data.get("Grants") or []) if isinstance(x, dict)]

    def revoke_enrollment_grant(self, grant_id: str, *, reason: str = "revoked-from-web-admin") -> dict[str, Any]:
        return self.client().json(
            "POST", f"/api/v1/admin/enrollment-grants/{grant_id}/revoke",
            {"Reason": reason}, timeout=15,
        )

    def agent_configuration(self, agent_id: str) -> dict[str, Any]:
        return self.client().json("GET", f"/api/v1/admin/agents/{agent_id}/config", timeout=12)

    def agent_configuration_history(self, agent_id: str) -> list[dict[str, Any]]:
        data = self.client().json("GET", f"/api/v1/admin/agents/{agent_id}/config/history", timeout=12)
        return [dict(x) for x in (data.get("History") or []) if isinstance(x, dict)]

    def set_agent_configuration(self, agent_id: str, settings: dict[str, Any], *, actor: str, note: str = "") -> dict[str, Any]:
        return self.client().json(
            "POST", f"/api/v1/admin/agents/{agent_id}/config",
            {"Settings": settings, "Actor": actor, "Note": note}, timeout=20,
        )

    def publish_agent_media_manifest(self, agent_id: str, envelope: dict[str, Any]) -> dict[str, Any]:
        """Publish an already Ed25519-signed, immutable Player manifest.

        Gateway authenticates this administrative write; it does not receive a
        private signing key. The Player verifies the detached signature again
        using its enrolled public key before it ever starts external VLC.
        """
        clean_agent = str(agent_id or "").strip()
        if not clean_agent or not isinstance(envelope, dict):
            raise ValueError("Agent y manifiesto Player requeridos.")
        return self.client().json(
            "POST", f"/api/v1/admin/media/manifests/{quote(clean_agent, safe='')}", envelope, timeout=20,
        )

    def agent_media_player_reports(self, *, agent_id: str = "", limit: int = 200) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"limit": max(1, min(int(limit), 1000))}
        if agent_id:
            params["agent_id"] = str(agent_id)
        data = self.client().json("GET", "/api/v1/admin/media/player-reports?" + urlencode(params), timeout=12)
        return [dict(row) for row in (data.get("Reports") or []) if isinstance(row, dict)]

    def request_agent_update(self, agent_id: str, *, actor: str, target_version: str = "") -> dict[str, Any]:
        result = self.client().json(
            "POST", f"/api/v1/admin/agents/{agent_id}/update",
            {"Actor": str(actor or "admin"), "TargetVersion": str(target_version or "")}, timeout=20,
        )
        with self._cache_lock:
            self._cache.pop("agents", None)
        return result

    def agent_offline_vlc_install(self, agent_id: str) -> dict[str, Any]:
        clean_agent = str(agent_id or "").strip()
        if not clean_agent:
            raise ValueError("Agent requerido.")
        data = self.client().json(
            "GET", f"/api/v1/admin/agents/{quote(clean_agent, safe='')}/vlc-offline/install", timeout=12,
        )
        request = data.get("OfflineVlcInstallRequest") if isinstance(data.get("OfflineVlcInstallRequest"), dict) else {}
        return dict(request)

    def request_agent_offline_vlc_install(
        self, agent_id: str, *, authorization: dict[str, Any], actor: str
    ) -> dict[str, Any]:
        clean_agent = str(agent_id or "").strip()
        if not clean_agent or not isinstance(authorization, dict):
            raise ValueError("Agent y autorización VLC requeridos.")
        result = self.client().json(
            "POST", f"/api/v1/admin/agents/{quote(clean_agent, safe='')}/vlc-offline/install",
            {"Actor": str(actor or "admin"), "Authorization": authorization}, timeout=20,
        )
        with self._cache_lock:
            self._cache.pop("agents", None)
        return result

    def download_result(self, job_id: str, agent_id: str, destination: Path) -> Path:
        self.client().download_file(f"/api/v1/admin/jobs/{job_id}/{agent_id}/result", destination, timeout=120)
        return destination


class WebAgentReleaseError(RuntimeError):
    pass


class DisabledReleaseManager:
    """Fail-safe release manager when local release storage cannot initialize."""

    def __init__(self, reason: str) -> None:
        self.reason = str(reason or "Release manager unavailable")

    def local_releases(self) -> list[dict[str, Any]]:
        return []

    def build_stable(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        raise WebAgentReleaseError(self.reason)

    def publish(self, *args: Any, **kwargs: Any):
        raise WebAgentReleaseError(self.reason)

    def cleanup(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        raise WebAgentReleaseError(self.reason)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class WebAgentReleaseManager:
    """Stable Agent release lifecycle for WebAdmin: build -> publish -> approve/distribute."""

    def __init__(self, app_root: Path, data_dir: Path, gateway: Any, security_assets: Any) -> None:
        self.app_root = Path(app_root).resolve()
        self.root = (Path(data_dir).resolve() / "agent-releases").resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir(parents=True, exist_ok=True)
        self.release_file = self.root / "releases.json"
        self.gateway = gateway
        self.security_assets = security_assets

    def local_releases(self) -> list[dict[str, Any]]:
        try:
            value = json.loads(self.release_file.read_text(encoding="utf-8-sig"))
            return [dict(x) for x in value if isinstance(x, dict)] if isinstance(value, list) else []
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return []

    def _resolve_local(self, *, version: str, platform: str, architecture: str, sha256: str) -> dict[str, Any]:
        key = (str(version), str(platform).lower(), str(architecture).lower(), str(sha256).lower())
        for row in self.local_releases():
            row_key = (
                str(row.get("version") or ""), str(row.get("platform") or "").lower(),
                str(row.get("architecture") or "").lower(), str(row.get("sha256") or "").lower(),
            )
            if row_key == key:
                return row
        raise WebAgentReleaseError("El release local seleccionado ya no existe o cambió su SHA-256.")

    def build_stable(self, *, platform: str = "windows", architecture: str = "x86_64", version: str = AGENT_VERSION) -> dict[str, Any]:
        status = self.security_assets.signing_status()
        if not bool(status.get("usable")):
            raise WebAgentReleaseError("Configure primero la firma Ed25519 en Seguridad → Claves y secretos.")
        private_bytes = self.security_assets.signing_private_key_bytes()
        public_bytes = self.security_assets.signing_public_key_bytes()
        with tempfile.TemporaryDirectory(prefix="gideon-web-release-key-") as td:
            tmp = Path(td)
            private = tmp / "private.pem"; public = tmp / "public.pem"
            private.write_bytes(private_bytes); public.write_bytes(public_bytes)
            try: os.chmod(private, 0o600); os.chmod(public, 0o600)
            except OSError: pass
            profile_path = self.root.parent / "config" / "host_profiles.json"
            builder = AgentUpdateBundleBuilder(self.app_root, profiles_path=profile_path if profile_path.is_file() else None)
            builder.builder.state_dir = self.root
            builder.builder.release_file = self.release_file
            builder.builder.private_key = private
            builder.builder.public_key = public
            row = builder.build(
                version=version, platform=platform, architecture=architecture,
                channel="stable", output_dir=self.artifacts,
            )
        return dict(row)

    def validate_local(self, row: dict[str, Any]) -> Path:
        if not bool(row.get("site_neutral")):
            raise WebAgentReleaseError("Solo se puede publicar un bundle Agent site-neutral.")
        if str(row.get("channel") or "").lower() != "stable":
            raise WebAgentReleaseError("Solo se puede publicar el canal stable desde esta consola.")
        bundle = Path(str(row.get("bundle") or "")).resolve()
        if not bundle.is_file() or self.root not in bundle.parents:
            raise WebAgentReleaseError("El bundle local no existe dentro del almacén protegido de WebAdmin.")
        if bundle.stat().st_size > MAX_SELF_UPDATE_BUNDLE_BYTES:
            raise WebAgentReleaseError(
                "El bundle excede el límite seguro de actualización del Agent; "
                "entregue componentes grandes mediante su flujo firmado explícito."
            )
        expected = str(row.get("sha256") or "").strip().lower()
        actual = _sha256(bundle)
        if not expected or expected != actual:
            raise WebAgentReleaseError(f"SHA-256 local inválido: esperado={expected or '-'} actual={actual}")
        sig = str(row.get("signature") or "").strip()
        try:
            public = serialization.load_pem_public_key(self.security_assets.signing_public_key_bytes())
            if not isinstance(public, Ed25519PublicKey):
                raise TypeError("la clave activa no es Ed25519")
            public.verify(base64.b64decode(sig, validate=True), bundle.read_bytes())
        except Exception as exc:
            raise WebAgentReleaseError("La firma Ed25519 del bundle local no es válida.") from exc
        return bundle

    def publish(self, *, version: str, platform: str, architecture: str, sha256: str) -> tuple[dict[str, Any], dict[str, Any]]:
        row = self._resolve_local(version=version, platform=platform, architecture=architecture, sha256=sha256)
        bundle = self.validate_local(row)
        response = self.gateway.publish_release(row, bundle)
        return row, response

    @staticmethod
    def release_key(row: dict[str, Any]) -> tuple[str, str, str, str]:
        """Canonical release identity shared with the Gateway cleanup API."""
        values = {str(key).casefold(): value for key, value in row.items()}
        return (
            str(values.get("platform") or "").strip().lower(),
            str(values.get("architecture") or "").strip().lower(),
            str(values.get("channel") or "stable").strip().lower(),
            str(values.get("version") or "").strip(),
        )

    @staticmethod
    def _release_sort_key(row: dict[str, Any]) -> tuple[tuple[int, ...], str]:
        version = str(row.get("version") or "0")
        numeric = tuple(
            int("".join(ch for ch in token if ch.isdigit()) or 0)
            for token in version.split(".")[:4]
        )
        return numeric, str(row.get("created_at") or "")

    def cleanup(
        self,
        *,
        keep_per_target: int = 2,
        protected_releases: set[tuple[str, str, str, str]] | None = None,
        allowed_releases: set[tuple[str, str, str, str]] | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Prune local bundles only after a Gateway-authorized cleanup plan.

        A release can be locally present while remotely approved or targeted by
        an update.  ``protected_releases`` therefore wins over retention count,
        and ``allowed_releases`` limits removal to releases actually deleted by
        the Gateway.  File renames are staged before the manifest replacement,
        so a failed manifest write can be rolled back without losing a bundle.
        """
        keep = max(1, min(int(keep_per_target or 2), 20))
        rows = self.local_releases()
        externally_protected = set(protected_releases or set())
        gateway_allowed = None if allowed_releases is None else set(allowed_releases)
        groups: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
        for row in rows:
            key = self.release_key(row)
            groups.setdefault(key[:3], []).append(row)
        retained_keys: set[tuple[str, str, str, str]] = set(externally_protected)
        for group in groups.values():
            group.sort(key=self._release_sort_key, reverse=True)
            retained_keys.update(self.release_key(row) for row in group[:keep])

        retained: list[dict[str, Any]] = []
        candidates: list[tuple[dict[str, Any], Path, int]] = []
        failures: list[dict[str, Any]] = []
        seen_paths: set[Path] = set()
        for row in rows:
            key = self.release_key(row)
            if key in retained_keys or (gateway_allowed is not None and key not in gateway_allowed):
                retained.append(row)
                continue
            bundle = Path(str(row.get("bundle") or "")).resolve()
            if self.root not in bundle.parents:
                retained.append(row)
                failures.append({"release": key, "error": "BUNDLE_PATH_OUTSIDE_RELEASE_STORE"})
                continue
            if bundle in seen_paths:
                retained.append(row)
                failures.append({"release": key, "error": "DUPLICATE_LOCAL_BUNDLE_PATH"})
                continue
            seen_paths.add(bundle)
            size = bundle.stat().st_size if bundle.is_file() else 0
            candidates.append((row, bundle, size))

        deleted = [
            {
                "platform": row.get("platform"), "architecture": row.get("architecture"),
                "channel": row.get("channel") or "stable", "version": row.get("version"),
                "sha256": row.get("sha256"), "bytes": size,
            }
            for row, _bundle, size in candidates
        ]
        planned_bytes = sum(int(item.get("bytes") or 0) for item in deleted)
        result = {
            "Ok": not failures,
            "DryRun": bool(dry_run),
            "KeepPerTarget": keep,
            "Deleted": deleted,
            "DeletedCount": len(deleted),
            "DeletedBytes": planned_bytes if dry_run else 0,
            "PlannedBytes": planned_bytes,
            "RetainedCount": len(retained),
            "ProtectedCount": len(externally_protected),
            "Failures": failures,
        }
        if dry_run or not candidates:
            return result

        staged: list[tuple[Path, Path, int]] = []
        try:
            for _row, bundle, size in candidates:
                if not bundle.is_file():
                    continue
                staged_path = bundle.with_name(f".{bundle.name}.cleanup-{uuid.uuid4().hex}")
                os.replace(bundle, staged_path)
                staged.append((bundle, staged_path, size))
        except OSError as exc:
            for original, staged_path, _size in reversed(staged):
                try:
                    if staged_path.exists():
                        os.replace(staged_path, original)
                except OSError:
                    pass
            result["Ok"] = False
            result["Deleted"] = []
            result["DeletedCount"] = 0
            result["DeletedBytes"] = 0
            result["Failures"].append({"error": f"LOCAL_STAGE_FAILED: {type(exc).__name__}"})
            return result

        try:
            tmp = self.release_file.with_name(f".{self.release_file.name}.{uuid.uuid4().hex}.tmp")
            tmp.write_text(json.dumps(retained, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            try:
                os.chmod(tmp, 0o640)
            except OSError:
                pass
            os.replace(tmp, self.release_file)
        except OSError as exc:
            for original, staged_path, _size in reversed(staged):
                try:
                    if staged_path.exists():
                        os.replace(staged_path, original)
                except OSError:
                    pass
            result["Ok"] = False
            result["Deleted"] = []
            result["DeletedCount"] = 0
            result["DeletedBytes"] = 0
            result["Failures"].append({"error": f"LOCAL_MANIFEST_COMMIT_FAILED: {type(exc).__name__}"})
            return result

        orphaned: list[str] = []
        removed_bytes = 0
        for _original, staged_path, size in staged:
            try:
                staged_path.unlink(missing_ok=True)
                removed_bytes += size
            except OSError:
                orphaned.append(str(staged_path))
        result["DeletedBytes"] = removed_bytes
        if orphaned:
            result["Ok"] = False
            result["Failures"].append({"error": "LOCAL_ORPHANED_STAGED_BUNDLES", "paths": orphaned})
        return result
