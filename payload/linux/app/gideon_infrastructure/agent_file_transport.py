from __future__ import annotations

from gideon_common.observability import best_effort_warning

import asyncio
import datetime as dt
import json
import os
import secrets
import shutil
import tempfile
import time
import uuid
import zipfile
from pathlib import Path
from typing import Any, Mapping

from gideon_agent_builder import AgentBuilder
from gideon_agent_http import AgentHttpClient, AgentHttpError
from gideon_agent_security import ensure_ed25519_keypair, sha256_file, sign_file, sign_file_bytes
from gideon_agent_job_contract import AGENT_WORKER_VERSION, build_job_envelope
from gideon_application.ports import FileTransportCapabilities, FileTransferPort, ProgressCallback
from gideon_domain import ArtifactDescriptor, HostTarget, Outcome, TransferResult, TransportProfile
from gideon_agent_runtime import merged_agent_control_plane


_TRANSFER_SCRIPT = r'''#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, os, shutil
from pathlib import Path

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--request", default="transfer_request.json")
    args = p.parse_args()
    root = Path(__file__).resolve().parent
    req = json.loads((root / args.request).read_text(encoding="utf-8-sig"))
    source = (root / str(req["SourceRelative"])).resolve()
    if root not in source.parents:
        raise RuntimeError("Unsafe source path")
    expected = str(req["Sha256"]).lower()
    expected_size = int(req["SizeBytes"])
    if not source.is_file():
        raise RuntimeError("Transfer payload missing")
    if source.stat().st_size != expected_size or sha256_file(source).lower() != expected:
        raise RuntimeError("Transfer payload integrity mismatch")
    target = Path(str(req["DestinationPath"]))
    target.parent.mkdir(parents=True, exist_ok=True)
    job_id = str(req.get("JobId") or "job")
    safe_job = "".join(ch for ch in job_id if ch.isalnum() or ch in "-_")[-32:] or "job"
    stage = target.with_name(target.name + ".gideon-part-" + safe_job)
    shutil.copy2(source, stage)
    if stage.stat().st_size != expected_size or sha256_file(stage).lower() != expected:
        stage.unlink(missing_ok=True)
        raise RuntimeError("Destination staging integrity mismatch")
    os.replace(stage, target)
    if target.stat().st_size != expected_size or sha256_file(target).lower() != expected:
        raise RuntimeError("Destination integrity mismatch")
    print(json.dumps({"Ok": True, "Path": str(target), "Bytes": expected_size, "Sha256": expected}, ensure_ascii=False))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
'''


def _runtime_agent_cfg(cfg: Mapping[str, object]) -> dict[str, Any]:
    return merged_agent_control_plane(cfg)


class AgentHttpsPullFileTransport(FileTransferPort):
    """File delivery through the GIDEON Agent queue.

    The controller talks only to the HTTPS Gateway. The destination Agent pulls
    the signed package over Internet/LAN; a site-to-site VPN and inbound SSH are
    not required. Existing agents remain compatible because the copy worker and
    payload travel inside the signed job package.
    """

    def __init__(self, *, app_root: Path, cfg: Mapping[str, object]) -> None:
        self.app_root = Path(app_root).resolve()
        self.cfg = dict(cfg)
        self.agent_cfg = _runtime_agent_cfg(self.cfg)
        self.builder = AgentBuilder(self.app_root)
        # Headless/Web deployments keep the signing key outside the application
        # tree.  Reuse that externally mounted key instead of generating a new
        # local identity that enrolled Agents would not trust.
        raw_private_bytes = self.cfg.get("execution_signing_private_key_bytes")
        self._private_key_bytes = bytes(raw_private_bytes) if isinstance(raw_private_bytes, (bytes, bytearray)) else None
        signing_private = str(self.cfg.get("execution_signing_private_key") or self.cfg.get("signing_private_key") or os.environ.get("GIDEON_AGENT_SIGNING_PRIVATE_KEY", "")).strip()
        signing_public = str(self.cfg.get("execution_signing_public_key") or self.cfg.get("signing_public_key") or os.environ.get("GIDEON_AGENT_SIGNING_PUBLIC_KEY", "")).strip()
        if signing_private:
            self.builder.private_key = Path(os.path.expandvars(signing_private)).expanduser().resolve()
        if signing_public:
            self.builder.public_key = Path(os.path.expandvars(signing_public)).expanduser().resolve()
        self._active_jobs: dict[str, str] = {}
        self._agent_cache: tuple[float, dict[str, dict[str, Any]]] = (0.0, {})

    @property
    def profile(self) -> TransportProfile:
        return TransportProfile.AGENT_HTTPS_PULL

    @property
    def capabilities(self) -> FileTransportCapabilities:
        return FileTransportCapabilities(
            profile=self.profile,
            supports_upload=True,
            supports_download=False,
            supports_large_files=True,
            recommended_for_video=True,
        )

    def _client(self) -> AgentHttpClient:
        cfg = _runtime_agent_cfg(self.cfg)
        base = str(cfg.get("base_url") or cfg.get("public_url") or "").strip().rstrip("/")
        env_name = str(cfg.get("admin_api_key_env") or "GIDEON_AGENT_ADMIN_TOKEN")
        token = str(os.environ.get(env_name, "") or cfg.get("admin_api_key") or "")
        if not base:
            raise AgentHttpError("No hay Gateway configurado para Agent HTTPS/PULL.")
        if not token:
            raise AgentHttpError("No hay credencial administrativa para el Gateway.")
        return AgentHttpClient(
            base,
            bearer_token=token,
            timeout=float(cfg.get("timeout_seconds") or 20),
            verify_tls=bool(cfg.get("verify_tls", True)),
            ca_file=str(cfg.get("ca_file") or "") or None,
            require_https=bool(cfg.get("require_https", True)),
        )

    def _agent_rows(self, *, force: bool = False) -> dict[str, dict[str, Any]]:
        stamp, cached = self._agent_cache
        if cached and not force and time.monotonic() - stamp < 15:
            return {key: dict(row) for key, row in cached.items()}
        payload = self._client().json("GET", "/api/v1/admin/agents", timeout=10)
        result: dict[str, dict[str, Any]] = {}
        for raw in payload.get("Agents", []):
            if not isinstance(raw, dict):
                continue
            agent_id = str(raw.get("agent_id") or "").strip()
            if agent_id:
                result[agent_id] = dict(raw)
        self._agent_cache = (time.monotonic(), result)
        return {key: dict(row) for key, row in result.items()}

    def _resolve_agent_row(self, site: HostTarget, *, force: bool = False) -> dict[str, Any]:
        rows = self._agent_rows(force=force)
        agent_id = str(getattr(site, "agent_id", "") or "").strip()
        if agent_id:
            return rows.get(agent_id) or {}
        # Compatibility with cached/pre-2.1 maps that were keyed by SiteCode.
        direct = rows.get(site.code)
        if direct:
            return direct
        candidates = [row for row in rows.values() if str(row.get("site_code") or "").strip() == site.code]
        if len(candidates) == 1:
            return candidates[0]
        if len(candidates) > 1:
            raise RuntimeError(
                f"AGENT_TARGET_AMBIGUOUS: {site.code} tiene {len(candidates)} Agents. Seleccione el equipo/AgentId."
            )
        return {}

    @staticmethod
    def _target_key(site: HostTarget) -> str:
        return str(getattr(site, "agent_id", "") or site.code).strip()

    def _site_with_registered_profile(self, site: HostTarget, *, force: bool = False) -> HostTarget:
        row = self._resolve_agent_row(site, force=force)
        reported = str(row.get("host_profile") or "").strip()
        # The enrolled Agent is the source of truth for Agent transport.  Even
        # when the profile already matches, scrub the address: Agent delivery is
        # SiteCode/Gateway based and must never inherit a server IP.
        return HostTarget(
            code=site.code,
            name=site.name,
            address="",
            platform=str(row.get("platform") or site.platform or "windows").strip().lower(),
            host_profile=reported or site.host_profile,
            agent_id=str(row.get("agent_id") or getattr(site, "agent_id", "") or "").strip(),
            agent_name=str(row.get("agent_name") or getattr(site, "agent_name", "") or "").strip(),
            hostname=str(row.get("hostname") or getattr(site, "hostname", "") or "").strip(),
        )

    async def preflight(self, site: HostTarget) -> Outcome[None]:
        try:
            row = await asyncio.to_thread(self._resolve_agent_row, site)
            if not row:
                return Outcome.failure("AGENT_NOT_ENROLLED", f"{site.code} no tiene el Agent seleccionado enrolado en el Gateway.")
            return Outcome.success(None)
        except AgentHttpError as exc:
            return Outcome.failure("CONNECTIVITY_ERROR", str(exc))
        except Exception as exc:
            return Outcome.failure("AGENT_PREFLIGHT_FAILED", f"{type(exc).__name__}: {exc}")

    def _build_package(self, site: HostTarget, artifact: ArtifactDescriptor, job_id: str, root: Path) -> tuple[Path, str, str]:
        if self._private_key_bytes is None and not self.builder.private_key.is_file():
            ensure_ed25519_keypair(self.builder.private_key, self.builder.public_key)
        package_root = root / "job"
        payload_dir = package_root / "payload"
        payload_dir.mkdir(parents=True, exist_ok=True)
        payload_file = payload_dir / artifact.local_path.name
        shutil.copy2(artifact.local_path, payload_file)
        (package_root / "transfer_payload.py").write_text(_TRANSFER_SCRIPT, encoding="utf-8")
        shutil.copy2(self.app_root / "gideon_agent_job_contract.py", package_root / "gideon_agent_job_contract.py")
        request = {
            "SourceRelative": str(Path("payload") / artifact.local_path.name),
            "DestinationPath": artifact.remote_path,
            "SizeBytes": artifact.size_bytes,
            "Sha256": artifact.sha256,
            "JobId": job_id,
        }
        (package_root / "transfer_request.json").write_text(json.dumps(request, ensure_ascii=False, indent=2), encoding="utf-8")
        ttl_seconds = max(300, min(
            int((_runtime_agent_cfg(self.cfg)).get("job_package_ttl_seconds", 86400) or 86400),
            7 * 86400,
        ))
        transfer_timeout = max(1800, int(artifact.size_bytes / 100_000))
        agent_job = build_job_envelope(
            job_id=job_id,
            job_type="FILE_TRANSFER",
            agent_id=getattr(site, "agent_id", "") or "",
            agent_name=getattr(site, "agent_name", "") or "",
            hostname=getattr(site, "hostname", "") or "",
            site_code=site.code,
            site_name=site.name,
            continue_on_error=False,
            default_timeout_seconds=transfer_timeout,
            host_profile={
                "id": site.host_profile or "agent_file_transfer",
                "platform": site.platform or "",
                "allowed_extensions": [".py"],
                "preferred_executors": [],
            },
            scripts=[{
                "Path": "transfer_payload.py",
                "ResultName": "01_transfer_payload.json",
                "Arguments": ["--request", "transfer_request.json"],
                "TimeoutSeconds": transfer_timeout,
            }],
            ttl_seconds=ttl_seconds,
            artifact=request,
            required_capabilities=("SIGNED_JOBS", "FILE_TRANSFER", "RESULT_UPLOAD", "CANCELLATION"),
        )
        (package_root / "agent_job.json").write_text(json.dumps(agent_job, ensure_ascii=False, indent=2), encoding="utf-8")
        shutil.copy2(self.app_root / "gideon_agent_worker.py", package_root / "gideon_agent_worker.py")
        archive = root / f"{job_id}.zip"
        compression = zipfile.ZIP_STORED if artifact.local_path.suffix.lower() in {".zip", ".7z", ".rar", ".mp4", ".mkv", ".mov", ".avi"} else zipfile.ZIP_DEFLATED
        with zipfile.ZipFile(archive, "w", compression=compression, allowZip64=True) as zf:
            for path in package_root.rglob("*"):
                if path.is_file():
                    zf.write(path, arcname=str(path.relative_to(package_root)))
        signature = sign_file_bytes(archive, self._private_key_bytes) if self._private_key_bytes is not None else sign_file(archive, self.builder.private_key)
        key_id = str((_runtime_agent_cfg(self.cfg)).get("signing_key_id") or "gideon-agent-ed25519-1")
        return archive, signature, key_id

    def queue_upload(self, site: HostTarget, artifact: ArtifactDescriptor) -> dict[str, Any]:
        """Queue a signed HTTPS/PULL file-delivery job without waiting for it.

        This is used by the headless Web Admin so an HTTP request never remains
        open while an endpoint is offline.  Progress/result is then observed in
        the normal Gateway Jobs view.
        """
        if self._private_key_bytes is None and not self.builder.private_key.is_file():
            raise RuntimeError("No hay clave privada Ed25519 de ejecución disponible para firmar la transferencia.")
        effective_site = self._site_with_registered_profile(site, force=True)
        target_key = self._target_key(effective_site)
        if not target_key:
            raise RuntimeError("El destino Agent no tiene AgentId.")
        job_id = f"file-{dt.datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"
        with tempfile.TemporaryDirectory(prefix="gideon-agent-file-web-") as td:
            archive, signature, key_id = self._build_package(effective_site, artifact, job_id, Path(td))
            response = self._client().upload_file(
                "PUT",
                f"/api/v1/admin/jobs/{job_id}/{target_key}",
                archive,
                headers={
                    "X-GIDEON-Site-Code": effective_site.code,
                    "X-GIDEON-Site-Name": effective_site.name,
                    "X-GIDEON-SHA256": sha256_file(archive),
                    "X-GIDEON-Signature": signature,
                    "X-GIDEON-Key-Id": key_id,
                    "X-GIDEON-Host-Profile": effective_site.host_profile,
                },
                timeout=max(120.0, float(_runtime_agent_cfg(self.cfg).get("timeout_seconds") or 20), archive.stat().st_size / 250_000),
            )
        return {
            "JobId": job_id,
            "AgentId": target_key,
            "SiteCode": effective_site.code,
            "Hostname": effective_site.hostname,
            "DestinationPath": artifact.remote_path,
            "SizeBytes": artifact.size_bytes,
            "Sha256": artifact.sha256,
            "Response": response,
        }

    def _queue_and_wait(self, site: HostTarget, artifact: ArtifactDescriptor, progress: ProgressCallback | None) -> Outcome[TransferResult]:
        cfg = _runtime_agent_cfg(self.cfg)
        timeout_seconds = int((self.cfg.get("file_transfer") or {}).get("max_wait_seconds", 3600)) if isinstance(self.cfg.get("file_transfer"), Mapping) else 3600
        poll_seconds = max(2, int(cfg.get("poll_interval_seconds") or 5))
        job_id = f"file-{dt.datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"
        active_key = self._target_key(site)
        try:
            effective_site = self._site_with_registered_profile(site, force=True)
            target_key = self._target_key(effective_site)
            active_key = target_key
            self._active_jobs[active_key] = job_id
            with tempfile.TemporaryDirectory(prefix="gideon-agent-file-") as td:
                if progress:
                    progress(site.code, 8.0, "Preparando paquete firmado", 0, artifact.size_bytes)
                archive, signature, key_id = self._build_package(effective_site, artifact, job_id, Path(td))
                if progress:
                    progress(site.code, 20.0, "HTTPS → Gateway (sin VPN)", 0, artifact.size_bytes)
                client = self._client()
                client.upload_file(
                    "PUT",
                    f"/api/v1/admin/jobs/{job_id}/{target_key}",
                    archive,
                    headers={
                        "X-GIDEON-Site-Code": effective_site.code,
                        "X-GIDEON-Site-Name": effective_site.name,
                        "X-GIDEON-SHA256": sha256_file(archive),
                        "X-GIDEON-Signature": signature,
                        "X-GIDEON-Key-Id": key_id,
                        "X-GIDEON-Host-Profile": effective_site.host_profile,
                    },
                    timeout=max(120.0, float(cfg.get("timeout_seconds") or 20), archive.stat().st_size / 250_000),
                )
                if progress:
                    progress(site.code, 45.0, "En cola · Agent HTTPS/PULL", artifact.size_bytes, artifact.size_bytes)

                deadline = time.monotonic() + max(60, timeout_seconds)
                last_state = "QUEUED"
                while time.monotonic() < deadline:
                    payload = client.json("GET", f"/api/v1/admin/jobs/{job_id}", timeout=max(10, float(cfg.get("timeout_seconds") or 20)))
                    rows = [r for r in payload.get("Sites", []) if isinstance(r, dict) and str(r.get("agent_id") or "") == target_key]
                    if not rows:
                        time.sleep(poll_seconds)
                        continue
                    row = rows[0]
                    state = str(row.get("status") or "QUEUED").upper()
                    agent_status = row.get("AgentStatus") if isinstance(row.get("AgentStatus"), dict) else {}
                    remote_state = str((agent_status or {}).get("State") or state).upper()
                    if state != last_state and progress:
                        mapped = 55.0 if state == "CLAIMED" else 75.0 if state == "RUNNING" else 92.0 if state == "RESULT_READY" else 50.0
                        progress(site.code, mapped, f"Agent · {remote_state}", artifact.size_bytes, artifact.size_bytes)
                        last_state = state
                    if state == "RESULT_READY":
                        if remote_state in {"RESULT_READY_WITH_ERRORS", "FAILED", "CANCELLED"}:
                            return Outcome.failure("AGENT_FILE_FAILED", str((agent_status or {}).get("Error") or remote_state))
                        if progress:
                            progress(site.code, 100.0, "Entregado y verificado SHA-256", artifact.size_bytes, artifact.size_bytes)
                        return Outcome.success(TransferResult(artifact.size_bytes, artifact.remote_path, artifact.sha256))
                    if state in {"FAILED", "CANCELLED"}:
                        return Outcome.failure("AGENT_FILE_FAILED", str(row.get("error") or remote_state or state))
                    time.sleep(poll_seconds)

                try:
                    client.json("POST", f"/api/v1/admin/jobs/{job_id}/{target_key}/cancel", timeout=10)
                except Exception as exc:
                    best_effort_warning(f"No se pudo cancelar Job Agent {job_id}/{target_key} tras timeout", exc)
                return Outcome.failure("AGENT_WAIT_TIMEOUT", "El archivo quedó esperando al Agent más tiempo del permitido; el Job remoto fue cancelado.")
        except AgentHttpError as exc:
            return Outcome.failure("CONNECTIVITY_ERROR", str(exc))
        except Exception as exc:
            return Outcome.failure("AGENT_FILE_ERROR", f"{type(exc).__name__}: {exc}")
        finally:
            self._active_jobs.pop(active_key, None)

    async def upload(self, site: HostTarget, artifact: ArtifactDescriptor, *, progress: ProgressCallback | None = None) -> Outcome[TransferResult]:
        return await asyncio.to_thread(self._queue_and_wait, site, artifact, progress)

    async def download(self, site: HostTarget, remote_path: str, local_path: Path, *, progress: ProgressCallback | None = None) -> Outcome[TransferResult]:
        return Outcome.failure("AGENT_DOWNLOAD_UNSUPPORTED", "La descarga por Agent se incorporará como flujo separado; use SFTP/SCP para recolección.")

    async def cancel_site(self, site: HostTarget) -> Outcome[None]:
        target_key = self._target_key(site)
        job_id = self._active_jobs.get(target_key)
        if not job_id:
            return Outcome.success(None)
        try:
            await asyncio.to_thread(self._client().json, "POST", f"/api/v1/admin/jobs/{job_id}/{target_key}/cancel")
            return Outcome.success(None)
        except Exception as exc:
            return Outcome.failure("AGENT_CANCEL_FAILED", str(exc))
