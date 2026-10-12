from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import shutil
import stat
import uuid
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from gideon_product_update import (
    GIDEON_UNIT_ALLOWLIST,
    WINDOWS_SERVICE_ALLOWLIST,
    default_update_root,
    default_update_trust_dir,
    MAX_FILES,
    MAX_UNCOMPRESSED_BYTES,
    PRODUCT_NAME,
    PROTECTED_APP_PREFIXES,
    UPDATE_SCHEMA,
)
from gideon_update_security import SIGNATURE_FILE, UpdateSignatureError, list_trusted_public_keys, verify_manifest_bytes


class ProductUpdateQueue:
    """Unprivileged Web-side queue for root-applied GIDEON product updates."""

    def __init__(self, web_data_dir: Path, config: dict[str, Any]) -> None:
        self.web_data_dir = Path(web_data_dir).resolve()
        self.root = Path(str(config.get("product_update_root") or default_update_root())).resolve()
        self.quarantine = self.web_data_dir / "system_updates" / "quarantine"
        self.inbox = self.root / "inbox"
        self.status_dir = self.root / "status"
        self.trust_dir = Path(str(config.get("product_update_trust_dir") or default_update_trust_dir(self.root))).resolve()
        self.max_bytes = max(1024 * 1024, int(config.get("max_system_update_upload_bytes", 50 * 1024 * 1024)))
        self.quarantine.mkdir(parents=True, exist_ok=True)
        self.inbox.mkdir(parents=True, exist_ok=True)
        self.status_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _safe_zip_name(name: str) -> PurePosixPath:
        raw = str(name or "").replace("\\", "/").strip("/")
        p = PurePosixPath(raw)
        if not raw or p.is_absolute() or any(part in {"", ".", ".."} for part in p.parts):
            raise ValueError(f"Ruta ZIP inválida: {name!r}")
        return p

    def inspect(self, package: Path) -> dict[str, Any]:
        package = Path(package)
        if not package.is_file() or package.stat().st_size <= 0:
            raise ValueError("El paquete está vacío o no existe.")
        if package.stat().st_size > self.max_bytes:
            raise ValueError(f"El paquete excede {self.max_bytes} bytes.")
        try:
            zf = zipfile.ZipFile(package)
        except zipfile.BadZipFile as exc:
            raise ValueError("El archivo no es un ZIP válido.") from exc
        with zf:
            infos = zf.infolist()
            if not infos or len(infos) > MAX_FILES + 50:
                raise ValueError("Cantidad de archivos ZIP inválida.")
            if sum(max(0, int(info.file_size)) for info in infos) > MAX_UNCOMPRESSED_BYTES:
                raise ValueError("El tamaño descomprimido excede el límite de seguridad.")
            names: dict[str, zipfile.ZipInfo] = {}
            for info in infos:
                if info.is_dir():
                    continue
                rel = self._safe_zip_name(info.filename)
                unix_mode = (info.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(unix_mode):
                    raise ValueError(f"No se permiten symlinks: {info.filename}")
                names[rel.as_posix()] = info
            if "manifest.json" not in names:
                raise ValueError("Falta manifest.json en la raíz del paquete.")
            if SIGNATURE_FILE not in names:
                raise ValueError(f"SIGNATURE_REQUIRED: falta {SIGNATURE_FILE}.")
            if names["manifest.json"].file_size > 512 * 1024 or names[SIGNATURE_FILE].file_size > 64 * 1024:
                raise ValueError("Manifest o firma exceden el límite.")
            manifest_bytes = zf.read("manifest.json")
            try:
                signature_info = verify_manifest_bytes(manifest_bytes, zf.read(SIGNATURE_FILE), self.trust_dir)
            except UpdateSignatureError as exc:
                raise ValueError(str(exc)) from exc
            manifest = json.loads(manifest_bytes.decode("utf-8-sig"))
            if not isinstance(manifest, dict):
                raise ValueError("manifest.json debe ser un objeto.")
            if manifest.get("schema") != UPDATE_SCHEMA or manifest.get("product") != PRODUCT_NAME:
                raise ValueError("El paquete no corresponde a GIDEON Remote Control Update v1.")
            to_version = str(manifest.get("to_version") or "")
            if not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9._-]+)?", to_version):
                raise ValueError("to_version inválido.")
            baseline_raw = manifest.get("from_release_manifest_sha256")
            baseline_values: list[str] = []
            if baseline_raw not in (None, [], ""):
                candidates = [baseline_raw] if isinstance(baseline_raw, str) else baseline_raw
                if not isinstance(candidates, list) or not candidates:
                    raise ValueError("from_release_manifest_sha256 inválido.")
                for value in candidates:
                    digest = str(value or "").strip().lower()
                    if not re.fullmatch(r"[0-9a-f]{64}", digest):
                        raise ValueError("from_release_manifest_sha256 contiene un SHA-256 inválido.")
                    if digest not in baseline_values:
                        baseline_values.append(digest)
            files = manifest.get("files")
            if not isinstance(files, list) or not files or len(files) > MAX_FILES:
                raise ValueError("Lista de archivos inválida.")
            allowed_targets = {"windows_app", "windows_service_host", "linux_web", "linux_gateway", "linux_updater", "linux_systemd"}
            for item in files:
                if not isinstance(item, dict):
                    raise ValueError("Entrada files inválida.")
                source = self._safe_zip_name(str(item.get("source") or ""))
                source_name = source.as_posix()
                if source.parts[0] != "payload" or source_name not in names:
                    raise ValueError(f"Payload declarado no existe: {source_name}")
                targets = item.get("targets")
                if not isinstance(targets, list) or not targets or set(map(str, targets)) - allowed_targets:
                    raise ValueError(f"Targets inválidos en {source_name}")
                if "linux_systemd" in set(map(str, targets)):
                    if len(source.parts) != 3 or source.parts[:2] != ("payload", "systemd") or source.parts[-1] not in GIDEON_UNIT_ALLOWLIST:
                        raise ValueError(f"Unidad systemd fuera del allowlist GIDEON: {source_name}")
                if "windows_service_host" in set(map(str, targets)):
                    if len(source.parts) < 3 or source.parts[:2] != ("payload", "windows_service"):
                        raise ValueError(f"Payload Windows service host inválido: {source_name}")
                if len(source.parts) >= 3 and source.parts[:2] == ("payload", "app"):
                    app_rel = PurePosixPath(*source.parts[2:]).as_posix().lower()
                    if any(app_rel == p[:-1] or app_rel.startswith(p) for p in PROTECTED_APP_PREFIXES):
                        raise ValueError(f"El paquete intenta modificar estado/configuración protegida: {app_rel}")
                expected = str(item.get("sha256") or "").lower()
                if not re.fullmatch(r"[0-9a-f]{64}", expected):
                    raise ValueError(f"SHA-256 inválido: {source_name}")
                h = hashlib.sha256()
                with zf.open(names[source_name]) as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        h.update(chunk)
                if h.hexdigest() != expected:
                    raise ValueError(f"SHA-256 no coincide: {source_name}")
            for key in ("restart_units", "enable_units", "health_units"):
                values = manifest.get(key)
                if values is not None:
                    if not isinstance(values, list) or set(map(str, values)) - GIDEON_UNIT_ALLOWLIST:
                        raise ValueError(f"{key} contiene unidades systemd fuera del allowlist GIDEON.")
            for key in ("restart_services", "health_services"):
                values = manifest.get(key)
                if values is not None:
                    if not isinstance(values, list) or set(map(str, values)) - WINDOWS_SERVICE_ALLOWLIST:
                        raise ValueError(f"{key} contiene servicios Windows fuera del allowlist GIDEON.")
                    if key == "restart_services" and "GIDEONRemoteControlUpdater" in set(map(str, values)):
                        raise ValueError("El updater Windows no puede solicitar reinicio de sí mismo.")
            return {
                "package_id": str(manifest.get("package_id") or ""),
                "from_versions": [str(x) for x in (manifest.get("from_versions") or [])],
                "to_version": to_version,
                "files": len(files),
                "notes": [str(x) for x in (manifest.get("notes") or [])][:20],
                "from_release_manifest_sha256": baseline_values,
                "signature": signature_info,
            }

    def trusted_keys(self) -> list[dict[str, Any]]:
        try:
            return list_trusted_public_keys(self.trust_dir)
        except UpdateSignatureError:
            return []

    def new_quarantine_path(self, original_name: str) -> Path:
        safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in Path(original_name or "update.zip").name)
        if not safe.lower().endswith(".zip"):
            safe += ".zip"
        return self.quarantine / f"{dt.datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:10]}-{safe}"

    def enqueue(self, quarantined: Path, summary: dict[str, Any]) -> dict[str, Any]:
        quarantined = Path(quarantined)
        token = f"{dt.datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:10]}"
        package_name = f"{token}-GIDEON-Update-v{summary['to_version']}.zip"
        package = self.inbox / package_name
        shutil.move(str(quarantined), str(package))
        os.chmod(package, 0o640)
        marker_tmp = self.inbox / f".{token}.ready.tmp"
        marker = self.inbox / f"{token}.ready"
        marker_tmp.write_text(package_name + "\n", encoding="utf-8")
        os.chmod(marker_tmp, 0o640)
        os.replace(marker_tmp, marker)
        return {**summary, "queue_id": token, "package_name": package_name, "status": "QUEUED"}

    def statuses(self, limit: int = 50) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for path in sorted(self.status_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[: max(1, limit)]:
            try:
                value = json.loads(path.read_text(encoding="utf-8-sig"))
                if isinstance(value, dict):
                    value["queue_id"] = path.stem
                    rows.append(value)
            except Exception:
                rows.append({"queue_id": path.stem, "ok": False, "status": "STATUS_READ_ERROR"})
        # Add queue markers that have not produced a root-applier status yet.
        known = {str(r.get("queue_id") or "") for r in rows}
        for marker in sorted(self.inbox.glob("*.ready"), key=lambda p: p.stat().st_mtime, reverse=True):
            if marker.stem in known:
                continue
            rows.insert(0, {"queue_id": marker.stem, "ok": None, "status": "QUEUED", "at": ""})
        return rows[: max(1, limit)]
