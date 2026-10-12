from __future__ import annotations

import datetime as dt
import json
import logging
import os
import shutil
import uuid
import zipfile
from pathlib import Path
from typing import Any

from gideon_agent_builder import AGENT_PROTOCOL, AgentBuilder
from gideon_agent_http import AgentHttpClient, AgentHttpError
from gideon_agent_runtime import merged_agent_control_plane
from gideon_agent_security import ensure_ed25519_keypair, sha256_file, sign_file, verify_file
from gideon_agent_job_contract import build_job_envelope
from gideon_host_profiles import HostProfileStore

_LOG = logging.getLogger(__name__)


class AgentAdministrationService:
    """Lifecycle/release operations independent from Tkinter or Qt.

    Every remote operation is addressed by AgentId.  SiteCode is descriptive
    metadata only and is intentionally never used as a unique machine key.
    """

    def __init__(self, app_root: Path, config: dict[str, Any]) -> None:
        self.app_root = Path(app_root)
        self.config = config
        self.builder = AgentBuilder(self.app_root)
        self.profiles = HostProfileStore(self.app_root / "config" / "host_profiles.json")

    def connection_config(self) -> dict[str, Any]:
        return merged_agent_control_plane(self.config)

    def client(self) -> AgentHttpClient:
        cfg = self.connection_config()
        env_name = str(cfg.get("admin_api_key_env") or "GIDEON_AGENT_ADMIN_TOKEN")
        token = str(cfg.get("admin_api_key") or os.environ.get(env_name, ""))
        base = str(cfg.get("base_url") or cfg.get("public_url") or "").rstrip("/")
        if not base or not token:
            raise RuntimeError("Configure agent_control_plane.base_url y la credencial administrativa del Gateway.")
        return AgentHttpClient(
            base,
            bearer_token=token,
            verify_tls=bool(cfg.get("verify_tls", True)),
            ca_file=cfg.get("ca_file"),
            require_https=bool(cfg.get("require_https", True)),
        )

    @staticmethod
    def is_online(row: dict[str, Any], ttl_seconds: int) -> bool:
        value = row.get("last_seen")
        if not value:
            return False
        try:
            stamp = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            now = dt.datetime.now(stamp.tzinfo) if stamp.tzinfo else dt.datetime.now()
            return (now - stamp).total_seconds() <= max(1, int(ttl_seconds))
        except (TypeError, ValueError):
            return False

    def list_agents(self) -> list[dict[str, Any]]:
        payload = self.client().json("GET", "/api/v1/admin/agents", timeout=12)
        return [dict(row) for row in (payload.get("Agents") or []) if isinstance(row, dict)]

    def purge_agent(self, agent_id: str) -> dict[str, Any]:
        aid = str(agent_id or "").strip()
        if not aid:
            raise ValueError("AgentId ausente.")
        return self.client().json("POST", f"/api/v1/admin/agents/{aid}/purge", {})

    def list_releases(self) -> list[dict[str, Any]]:
        payload = self.client().json("GET", "/api/v2/admin/releases", timeout=12)
        return [dict(row) for row in (payload.get("Releases") or []) if isinstance(row, dict)]

    def set_release_approval(self, row: dict[str, Any], *, approved: bool, approved_by: str = "") -> dict[str, Any]:
        platform = str(row.get("platform") or "").strip()
        arch = str(row.get("architecture") or "").strip()
        channel = str(row.get("channel") or "").strip()
        version = str(row.get("version") or "").strip()
        if not all((platform, arch, channel, version)):
            raise ValueError("Release incompleto: plataforma/arquitectura/canal/versión.")
        actor = approved_by or os.environ.get("USERNAME") or os.environ.get("USER") or "console"
        payload = {
            "Platform": platform,
            "Architecture": arch,
            "Channel": channel,
            "Version": version,
            "Approved": bool(approved),
            "ApprovedBy": actor,
            "Note": "Aprobación desde GIDEON Remote Control Qt",
        }

        def post_canonical() -> dict[str, Any]:
            return self.client().json(
                "POST", "/api/v2/admin/releases/approval", payload, timeout=30
            )

        try:
            return post_canonical()
        except AgentHttpError as exc:
            text = str(exc)
            endpoint_missing = "HTTP 404" in text and "Endpoint not found" in text
            if not endpoint_missing:
                raise

            # A common upgrade case is a still-running local Gateway from an older
            # release. Reconcile only the Gateway managed by this controller; a
            # remote Gateway is never restarted implicitly.
            try:
                from gideon_gateway_service import GatewayCoordinator
                repaired = GatewayCoordinator(self.app_root).test_and_repair()
                if repaired.ok:
                    return post_canonical()
            except Exception as repair_exc:
                _LOG.warning("No se pudo reconciliar automáticamente el Gateway antes de aprobar el release: %s", repair_exc)

            # Compatibility fallback for Gateway builds that implemented approval
            # only as a path-form action endpoint.
            action = "approve" if approved else "revoke"
            legacy_path = f"/api/v2/admin/releases/{platform}/{arch}/{channel}/{version}/{action}"
            try:
                return self.client().json(
                    "POST", legacy_path,
                    {"ApprovedBy": actor, "Note": payload["Note"]},
                    timeout=30,
                )
            except AgentHttpError as legacy_exc:
                raise AgentHttpError(
                    "El Gateway activo no expone la API de aprobación de releases. "
                    "Use Infraestructura > Gateway > Probar/Reparar Gateway y confirme "
                    "Gateway 2.3.3 o superior. Detalle: " + str(legacy_exc)
                ) from legacy_exc

    def publish_local_release(self, row: dict[str, Any]) -> dict[str, Any]:
        bundle = Path(str(row.get("bundle") or ""))
        if not bundle.is_file():
            raise FileNotFoundError(f"No existe el bundle local: {bundle}")
        if not bool(row.get("site_neutral")):
            raise RuntimeError(
                "Solo se publican bundles de actualización site-neutral. Genere uno desde Agentes > Versiones / Releases."
            )
        archs = row.get("architectures") or [row.get("architecture") or "x86_64"]
        arch = str(archs[0])
        platform = str(row.get("platform") or "unknown")
        channel = str(row.get("channel") or "stable").lower()
        version = str(row.get("version") or "")
        if channel != "stable":
            raise RuntimeError("La distribución automática corporativa solo admite el canal stable.")
        if not version:
            raise ValueError("La versión del release está vacía.")
        expected = str(row.get("sha256") or "").strip().lower()
        actual = sha256_file(bundle)
        if not expected or actual != expected:
            raise RuntimeError(f"SHA-256 local inválido: esperado={expected or '-'} actual={actual}")
        signature = str(row.get("signature") or "").strip()
        if not signature or not verify_file(bundle, signature, self.builder.public_key):
            raise RuntimeError("La firma Ed25519 local del bundle no es válida.")
        return self.client().upload_file(
            "PUT",
            f"/api/v2/admin/releases/{platform}/{arch}/{channel}/{version}",
            bundle,
            headers={
                "X-GIDEON-Protocol-Version": AGENT_PROTOCOL,
                "X-GIDEON-Signature": str(row.get("signature") or ""),
                "X-GIDEON-Key-Id": str(row.get("key_id") or "gideon-agent-ed25519-1"),
            },
            timeout=120,
        )

    def build_remote_uninstall_package(self, row: dict[str, Any]) -> dict[str, Any]:
        if str(row.get("platform") or "").lower() not in {"windows", "win32", "win"}:
            raise RuntimeError("La limpieza remota profunda está disponible para Agents Windows.")
        agent_id = str(row.get("agent_id") or "").strip()
        if not agent_id:
            raise RuntimeError("El Agent no tiene AgentId.")
        profile_id = str(row.get("host_profile") or "windows_generic").strip() or "windows_generic"
        try:
            profile = self.profiles.get(profile_id)
        except (KeyError, OSError, ValueError):
            candidates = [
                value for _, value in self.profiles.list_profiles()
                if str(value.get("platform") or "").lower() == "windows"
            ]
            if not candidates:
                raise RuntimeError("No existe un Host Template Windows para empaquetar la desinstalación.")
            profile = candidates[0]
            profile_id = str(profile.get("id") or profile_id)

        source = self.app_root / "scripts" / "gideon_agent_remote_uninstall.ps1"
        if not source.is_file():
            raise FileNotFoundError(source)
        job_id = "agent-uninstall-" + dt.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
        stage = self.builder.state_dir / "maintenance" / job_id
        if stage.exists():
            shutil.rmtree(stage, ignore_errors=True)
        package_dir = stage / "package"
        (package_dir / "scripts").mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, package_dir / "scripts" / source.name)
        shutil.copy2(self.app_root / "gideon_agent_worker.py", package_dir / "gideon_agent_worker.py")
        shutil.copy2(self.app_root / "gideon_agent_job_contract.py", package_dir / "gideon_agent_job_contract.py")
        shutil.copy2(self.app_root / "scripts" / "gideon_script_host.ps1", package_dir / "gideon_script_host.ps1")
        (package_dir / "host_profile.json").write_text(json.dumps(profile, ensure_ascii=False, indent=2), encoding="utf-8")
        manifest = build_job_envelope(
            job_id=job_id,
            job_type="SCRIPT_EXECUTION",
            agent_id=agent_id,
            agent_name=str(row.get("agent_name") or row.get("hostname") or ""),
            hostname=str(row.get("hostname") or ""),
            site_code=str(row.get("site_code") or ""),
            site_name=str(row.get("site_name") or ""),
            host_profile=profile,
            continue_on_error=False,
            default_timeout_seconds=120,
            ttl_seconds=1800,
            scripts=[{
                "Index": 1,
                "Name": source.name,
                "Path": "scripts/" + source.name,
                "ResultName": "01_agent_uninstall.json",
                "Sha256": sha256_file(package_dir / "scripts" / source.name),
                "TimeoutSeconds": 120,
                "Arguments": [],
                "Parameters": {},
                "Environment": {},
            }],
            required_capabilities=("SIGNED_JOBS", "SCRIPT_EXECUTION", "RESULT_UPLOAD", "CANCELLATION"),
        )
        (package_dir / "agent_job.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        archive = stage / f"{agent_id}.agent.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
            for file in package_dir.rglob("*"):
                if file.is_file():
                    zf.write(file, file.relative_to(package_dir).as_posix())
        ensure_ed25519_keypair(self.builder.private_key, self.builder.public_key)
        return {
            "JobId": job_id,
            "Archive": archive,
            "Signature": sign_file(archive, self.builder.private_key),
            "KeyId": "gideon-agent-ed25519-1",
            "Profile": profile_id,
        }

    def queue_remote_uninstall(self, row: dict[str, Any]) -> dict[str, Any]:
        info = self.build_remote_uninstall_package(row)
        archive = Path(info["Archive"])
        agent_id = str(row.get("agent_id") or "").strip()
        response = self.client().upload_file(
            "PUT",
            f"/api/v1/admin/jobs/{info['JobId']}/{agent_id}",
            archive,
            headers={
                "X-GIDEON-Site-Code": str(row.get("site_code") or ""),
                "X-GIDEON-Site-Name": str(row.get("site_name") or ""),
                "X-GIDEON-SHA256": sha256_file(archive),
                "X-GIDEON-Signature": str(info["Signature"]),
                "X-GIDEON-Key-Id": str(info["KeyId"]),
                "X-GIDEON-Host-Profile": str(info["Profile"]),
            },
            timeout=120,
        )
        return {"job": info, "gateway": response}

    @staticmethod
    def _version_key(value: str) -> tuple[int, int, int, str]:
        text = str(value or "0.0.0")
        core, _, suffix = text.partition("-")
        parts = core.split(".")[:3]
        ints: list[int] = []
        for part in parts:
            try:
                ints.append(int(part))
            except ValueError:
                ints.append(0)
        while len(ints) < 3:
            ints.append(0)
        return ints[0], ints[1], ints[2], suffix

    def update_matrix(self, agents: list[dict[str, Any]], releases: list[dict[str, Any]]) -> list[dict[str, Any]]:
        approved: dict[tuple[str, str], dict[str, Any]] = {}
        for release in releases:
            if str(release.get("channel") or "").lower() != "stable":
                continue
            if str(release.get("approval_state") or "DRAFT").upper() != "APPROVED":
                continue
            key = (str(release.get("platform") or "").lower(), str(release.get("architecture") or "").lower())
            current = approved.get(key)
            if current is None or self._version_key(str(release.get("version"))) > self._version_key(str(current.get("version"))):
                approved[key] = release
        matrix: list[dict[str, Any]] = []
        for agent in agents:
            key = (str(agent.get("platform") or "").lower(), str(agent.get("architecture") or "").lower())
            release = approved.get(key)
            current = str(agent.get("agent_version") or "0.0.0")
            target = str((release or {}).get("version") or "")
            if not target:
                state = "SIN_RELEASE"
            elif self._version_key(current) < self._version_key(target):
                state = "UPDATE_AVAILABLE"
            elif self._version_key(current) > self._version_key(target):
                state = "AHEAD"
            else:
                state = "CURRENT"
            matrix.append({**agent, "update_state": state, "target_version": target, "release": release})
        return matrix
