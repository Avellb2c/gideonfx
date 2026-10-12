from __future__ import annotations

from gideon_common.observability import best_effort_warning

from gideon_common.clock import now_iso
import csv
import datetime as dt
import json
import re
import shutil
from pathlib import Path
from typing import Any, Iterable


SITE_FIELDS = [
    "SiteCode",
    "SiteName",
    "ServerIP",
    "Platform",
    "HostProfile",
    "AgentId",
    "AgentName",
    "Hostname",
    "AgentOnline",
    "LastSeen",
    "AgentConnection",
    "AgentRemoteIP",
    "AgentlessIP",
    "Source",
]




def safe_id(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value).strip()).strip("._-")
    return text.lower() or "group"


class SiteGroupStore:
    """Inventarios guardados por grupo.

    Cada grupo usa su propio CSV compatible con Inventory:
      SiteCode,SiteName,ServerIP

    El JSON solo mantiene metadata y el grupo activo.
    """

    def __init__(self, config_dir: Path, baseline_sites: Path) -> None:
        self.config_dir = Path(config_dir)
        self.baseline_sites = Path(baseline_sites)
        self.groups_dir = self.config_dir / "site_groups"
        self.index_path = self.config_dir / "site_groups.json"
        self.groups_dir.mkdir(parents=True, exist_ok=True)
        self.data = self._load_or_initialize()

    def _load_or_initialize(self) -> dict[str, Any]:
        if self.index_path.exists():
            value = json.loads(self.index_path.read_text(encoding="utf-8-sig"))
            value["schema_version"] = max(2, int(value.get("schema_version") or 1))
            value.setdefault("groups", {})
            value.setdefault("active_group", "")
            if value["groups"]:
                return value

        default_id = "gideons_peru_29"
        default_csv = self.groups_dir / f"{default_id}.csv"
        if not default_csv.exists():
            shutil.copy2(self.baseline_sites, default_csv)

        value = {
            "schema_version": 2,
            "active_group": default_id,
            "groups": {
                default_id: {
                    "id": default_id,
                    "name": "Gideon Rx Perú · Tiendas",
                    "description": "Inventario operativo inicial de tiendas.",
                    "sites_file": str(default_csv.relative_to(self.config_dir)),
                    "created_at": now_iso(),
                    "modified_at": now_iso(),
                    "protected": False,
                }
            },
        }
        self._save(value)
        return value

    def _save(self, value: dict[str, Any] | None = None) -> None:
        if value is not None:
            self.data = value
        tmp = self.index_path.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps(self.data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        tmp.replace(self.index_path)

    def list_groups(self) -> list[dict[str, Any]]:
        rows = list(self.data.get("groups", {}).values())
        return sorted(rows, key=lambda x: str(x.get("name") or x.get("id")))

    def get(self, group_id: str) -> dict[str, Any]:
        try:
            return dict(self.data["groups"][str(group_id)])
        except Exception as exc:
            raise KeyError(f"Grupo no encontrado: {group_id}") from exc

    @property
    def active_group_id(self) -> str:
        gid = str(self.data.get("active_group") or "")
        if gid and gid in self.data.get("groups", {}):
            return gid
        rows = self.list_groups()
        if not rows:
            raise RuntimeError("No existen grupos de hosts.")
        return str(rows[0]["id"])

    def set_active(self, group_id: str) -> None:
        self.get(group_id)
        self.data["active_group"] = str(group_id)
        self._save()

    def inventory_path(self, group_id: str | None = None) -> Path:
        row = self.get(group_id or self.active_group_id)
        raw = Path(str(row["sites_file"]))
        path = raw if raw.is_absolute() else self.config_dir / raw
        return path.resolve()

    def read_sites(self, group_id: str | None = None) -> list[dict[str, str]]:
        path = self.inventory_path(group_id)
        rows: list[dict[str, str]] = []
        with path.open("r", encoding="utf-8-sig", newline="") as f:
            for row in csv.DictReader(f):
                item = {field: str(row.get(field) or "").strip() for field in SITE_FIELDS}
                rows.append(item)
        return rows

    def write_sites(self, group_id: str, rows: Iterable[dict[str, Any]]) -> None:
        path = self.inventory_path(group_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=SITE_FIELDS)
            writer.writeheader()
            for row in rows:
                writer.writerow({field: str(row.get(field) or "").strip() for field in SITE_FIELDS})
        tmp.replace(path)
        self.data["groups"][group_id]["modified_at"] = now_iso()
        self._save()

    def gateway_cache_path(self) -> Path:
        """Inventario efímero de agentes para ejecutar sin convertirlos en grupo persistente."""
        return (self.groups_dir / "_gateway_agents_live.csv").resolve()

    def write_gateway_cache(self, rows: Iterable[dict[str, Any]]) -> Path:
        path = self.gateway_cache_path()
        tmp = path.with_suffix(path.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=SITE_FIELDS)
            writer.writeheader()
            for row in rows:
                writer.writerow({field: str(row.get(field) or "").strip() for field in SITE_FIELDS})
        tmp.replace(path)
        return path

    def create(
        self,
        name: str,
        *,
        description: str = "",
        copy_from: str | None = None,
    ) -> str:
        base = safe_id(name)
        group_id = base
        n = 2
        while group_id in self.data["groups"]:
            group_id = f"{base}_{n}"
            n += 1

        path = self.groups_dir / f"{group_id}.csv"
        if copy_from:
            shutil.copy2(self.inventory_path(copy_from), path)
        else:
            with path.open("w", encoding="utf-8-sig", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=SITE_FIELDS,
                )
                writer.writeheader()

        self.data["groups"][group_id] = {
            "id": group_id,
            "name": str(name).strip() or group_id,
            "description": str(description).strip(),
            "sites_file": str(path.relative_to(self.config_dir)),
            "created_at": now_iso(),
            "modified_at": now_iso(),
            "protected": False,
        }
        self._save()
        return group_id

    def duplicate(self, group_id: str, new_name: str) -> str:
        return self.create(new_name, copy_from=group_id)

    def rename(self, group_id: str, new_name: str) -> None:
        row = self.get(group_id)
        self.data["groups"][group_id]["name"] = str(new_name).strip() or row["name"]
        self.data["groups"][group_id]["modified_at"] = now_iso()
        self._save()

    def delete(self, group_id: str) -> None:
        if len(self.data.get("groups", {})) <= 1:
            raise RuntimeError("Debe existir al menos un grupo.")
        row = self.get(group_id)
        if row.get("protected"):
            raise RuntimeError("Este grupo está protegido.")
        try:
            self.inventory_path(group_id).unlink(missing_ok=True)
        except Exception as exc:
            best_effort_warning(f"No se pudo retirar inventario del grupo {group_id}", exc)
        self.data["groups"].pop(group_id, None)
        if self.data.get("active_group") == group_id:
            self.data["active_group"] = next(iter(self.data["groups"]))
        self._save()

    def import_csv(self, name: str, source: Path) -> str:
        source = Path(source)
        with source.open("r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            required = {"SiteCode", "SiteName", "ServerIP"}
            if not required.issubset(set(reader.fieldnames or [])):
                raise RuntimeError(
                    "El CSV debe contener SiteCode, SiteName y ServerIP."
                )
            rows = list(reader)
        gid = self.create(name)
        self.write_sites(gid, rows)
        return gid

    def export_csv(self, group_id: str, target: Path) -> Path:
        target = Path(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.inventory_path(group_id), target)
        return target
