from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from threading import Lock
from typing import Any


BACKUP_EXTERNAL_ROOT = Path("/var/lib/gideon/backups/external")


DEFAULT_RUNTIME_SETTINGS: dict[str, Any] = {
    "backup_enabled": True,
    "backup_destination_type": "local",
    "backup_destination": "",
    "backup_retention_days": 14,
    "smtp_enabled": False,
    "smtp_host": "",
    "smtp_port": 587,
    "smtp_username": "",
    "smtp_from": "",
}


class RuntimeSettingsStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        if not self.path.exists():
            self._write(DEFAULT_RUNTIME_SETTINGS)

    def _write(self, value: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=".runtime-settings-", suffix=".json", dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(value, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp_name, 0o640)
            os.replace(tmp_name, self.path)
        finally:
            try:
                if os.path.exists(tmp_name):
                    os.unlink(tmp_name)
            except OSError:
                pass

    def load(self) -> dict[str, Any]:
        with self._lock:
            current = dict(DEFAULT_RUNTIME_SETTINGS)
            if self.path.is_file():
                try:
                    raw = json.loads(self.path.read_text(encoding="utf-8-sig"))
                    if isinstance(raw, dict):
                        current.update(raw)
                except (OSError, json.JSONDecodeError, ValueError, TypeError):
                    raw = {}
            current["backup_destination_type"] = str(current.get("backup_destination_type") or "local").lower()
            current["backup_retention_days"] = max(1, min(int(current.get("backup_retention_days") or 14), 365))
            current["smtp_port"] = max(1, min(int(current.get("smtp_port") or 587), 65535))
            return current

    def update(self, values: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            current = dict(DEFAULT_RUNTIME_SETTINGS)
            if self.path.is_file():
                try:
                    raw = json.loads(self.path.read_text(encoding="utf-8-sig"))
                    if isinstance(raw, dict):
                        current.update(raw)
                except (OSError, json.JSONDecodeError, ValueError, TypeError):
                    raw = {}
            allowed = set(DEFAULT_RUNTIME_SETTINGS)
            for key, value in values.items():
                if key in allowed:
                    current[key] = value
            mode = str(current.get("backup_destination_type") or "local").lower()
            if mode not in {"local", "filesystem", "s3"}:
                raise ValueError("Tipo de backup inválido.")
            current["backup_destination_type"] = mode
            current["backup_destination"] = str(current.get("backup_destination") or "").strip()[:2048]
            if mode == "filesystem" and current["backup_destination"]:
                destination = Path(current["backup_destination"]).expanduser().resolve()
                allowed_root = BACKUP_EXTERNAL_ROOT.resolve()
                try:
                    destination.relative_to(allowed_root)
                except ValueError as exc:
                    raise ValueError(
                        f"El destino filesystem debe estar dentro de {allowed_root}. "
                        "Monte NAS/EBS/EFS bajo esa ruta para mantener el aislamiento GIDEON."
                    ) from exc
                current["backup_destination"] = str(destination)
            if mode == "s3" and current["backup_destination"] and not current["backup_destination"].startswith("s3://"):
                raise ValueError("El destino S3 debe comenzar con s3://")
            current["backup_retention_days"] = max(1, min(int(current.get("backup_retention_days") or 14), 365))
            current["smtp_host"] = str(current.get("smtp_host") or "").strip()[:255]
            current["smtp_username"] = str(current.get("smtp_username") or "").strip()[:255]
            current["smtp_from"] = str(current.get("smtp_from") or "").strip()[:320]
            current["smtp_port"] = max(1, min(int(current.get("smtp_port") or 587), 65535))
            self._write(current)
            return dict(current)
