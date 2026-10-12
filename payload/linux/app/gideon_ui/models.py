from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PySide6.QtGui import QColor

from gideon_domain import HostTarget

from .tokens import COLORS
from .state_presenter import present_job_state


@dataclass(slots=True)
class HostRow:
    target: HostTarget
    selected: bool = True
    state: str = "Sin datos"
    last_job: str = "-"
    updated_at: str = "-"
    ping_status: str = "-"
    source: str = "inventory"
    agent_id: str = ""
    agent_name: str = ""
    hostname: str = ""
    agent_online: bool | None = None
    last_seen: str = ""
    connection_display: str = ""
    agent_remote_ip: str = ""
    agentless_address: str = ""

    def target_for_agentless(self) -> HostTarget:
        """Return the SSH/SFTP address without changing the Agent route identity."""
        address = str(self.agentless_address or self.target.address).strip()
        return HostTarget(
            code=self.target.code,
            name=self.target.name,
            address=address,
            platform=self.target.platform,
            host_profile=self.target.host_profile,
            agent_id=self.target.agent_id,
            agent_name=self.target.agent_name,
            hostname=self.target.hostname,
        )


class HostTableModel(QAbstractTableModel):
    HEADERS: tuple[str, ...] = (
        "",
        "Código",
        "Sede",
        "Equipo / agente",
        "Conexión",
        "Ping",
        "Plataforma",
        "Perfil",
        "Estado",
        "Último Job",
        "Actualización",
    )
    PING_COLUMN: int = 5
    STATE_COLUMN: int = 8

    def __init__(self, rows: Sequence[HostRow] | None = None) -> None:
        super().__init__()
        self.rows: list[HostRow] = list(rows or [])
        self.ip_editable: bool = False

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self.HEADERS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> Any:  # noqa: N802
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            if 0 <= section < len(self.HEADERS):
                return self.HEADERS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid() or not (0 <= index.row() < len(self.rows)):
            return None
        row = self.rows[index.row()]
        column = index.column()

        if role == Qt.ItemDataRole.CheckStateRole and column == 0:
            return Qt.CheckState.Checked if row.selected else Qt.CheckState.Unchecked

        if role == Qt.ItemDataRole.DisplayRole:
            values: tuple[str, ...] = (
                "",
                row.target.code,
                row.target.name,
                (
                    f"{row.agent_name or row.hostname or 'Agente'} · {row.hostname}"
                    if row.hostname and (row.agent_name or "") != row.hostname
                    else (row.agent_name or row.hostname or (f"ID {row.agent_id[:12]}" if row.agent_id else "—"))
                ),
                row.connection_display or row.target.address or "—",
                row.ping_status,
                row.target.platform.upper(),
                row.target.host_profile,
                row.state,
                row.last_job,
                row.updated_at,
            )
            return values[column]

        if role == Qt.ItemDataRole.ToolTipRole and column == 3 and row.agent_id:
            return "\n".join([
                f"AgentId: {row.agent_id}",
                f"Nombre: {row.agent_name or '-'}",
                f"Hostname: {row.hostname or '-'}",
                f"Sede: {row.target.code} · {row.target.name}",
            ])

        if role == Qt.ItemDataRole.ToolTipRole and column == 4 and row.connection_display:
            parts = [row.connection_display, "El Agent inicia una conexión HTTPS saliente al Gateway; no se usa la IP del servidor como destino."]
            if row.agent_remote_ip:
                parts.append(f"IP de origen observada: {row.agent_remote_ip} (telemetría; puede ser NAT y no se usa para Dispatch).")
            if row.agentless_address:
                parts.append(f"IP Agentless separada: {row.agentless_address} (solo SSH/SFTP si se fuerza ese modo).")
            return "\n".join(parts)

        if role == Qt.ItemDataRole.ForegroundRole and column == self.STATE_COLUMN:
            state = row.state.upper()
            if any(token in state for token in ("ERROR", "FAILED", "OFFLINE", "INACTIVO")):
                return QColor(COLORS.danger)
            if any(token in state for token in ("WAIT", "DEGRADED", "WARN", "PARTIAL", "CONECTANDO")):
                return QColor(COLORS.warning)
            if any(token in state for token in ("ONLINE", "RUNNING", "COLLECTED", "COMPLETED", "ACTIVO")):
                return QColor(COLORS.success)

        if role == Qt.ItemDataRole.ForegroundRole and column == self.PING_COLUMN:
            ping = row.ping_status.upper()
            if ping.startswith("OK"):
                return QColor(COLORS.success)
            if "SIN RESPUESTA" in ping or "TIMEOUT" in ping or "NO DISPONIBLE" in ping:
                return QColor(COLORS.danger)
            if "PROBANDO" in ping:
                return QColor(COLORS.warning)
        return None

    def flags(self, index: QModelIndex) -> Qt.ItemFlag:
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags
        flags = Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
        if index.column() == 0:
            flags |= Qt.ItemFlag.ItemIsUserCheckable
        if index.column() == 4 and self.ip_editable and not self.rows[index.row()].connection_display:
            flags |= Qt.ItemFlag.ItemIsEditable
        return flags

    def setData(self, index: QModelIndex, value: Any, role: int = Qt.ItemDataRole.EditRole) -> bool:  # noqa: N802
        if not index.isValid() or not (0 <= index.row() < len(self.rows)):
            return False
        row = self.rows[index.row()]
        if index.column() == 0 and role == Qt.ItemDataRole.CheckStateRole:
            row.selected = value == Qt.CheckState.Checked.value or value == Qt.CheckState.Checked
            self.dataChanged.emit(index, index, [role])
            return True
        if index.column() == 4 and role == Qt.ItemDataRole.EditRole and self.ip_editable:
            address = str(value).strip()
            if not address:
                return False
            row.target = HostTarget(
                code=row.target.code,
                name=row.target.name,
                address=address,
                platform=row.target.platform,
                host_profile=row.target.host_profile,
                agent_id=row.target.agent_id,
                agent_name=row.target.agent_name,
                hostname=row.target.hostname,
            )
            self.dataChanged.emit(index, index, [role, Qt.ItemDataRole.DisplayRole])
            return True
        return False

    @staticmethod
    def _row_key(row: HostRow) -> tuple[str, str, str]:
        return (
            str(row.agent_id or row.target.agent_id or "").strip().lower(),
            str(row.target.code or "").strip().lower(),
            str(row.agentless_address or row.target.address or row.hostname or "").strip().lower(),
        )

    def set_rows(self, rows: Sequence[HostRow]) -> None:
        """Update cells incrementally and preserve selection/scroll when topology is stable."""
        incoming = list(rows)
        old_keys = [self._row_key(row) for row in self.rows]
        new_keys = [self._row_key(row) for row in incoming]
        old_selection = {self._row_key(row): row.selected for row in self.rows}
        for row in incoming:
            key = self._row_key(row)
            if key in old_selection:
                row.selected = old_selection[key]
        if old_keys == new_keys and len(self.rows) == len(incoming):
            for i, row in enumerate(incoming):
                if self.rows[i] != row:
                    self.rows[i] = row
                    self.dataChanged.emit(self.index(i, 0), self.index(i, len(self.HEADERS) - 1))
            return
        self.beginResetModel()
        self.rows = incoming
        self.endResetModel()

    def selected_targets(self) -> list[HostTarget]:
        return [row.target for row in self.rows if row.selected]

    def selected_rows(self) -> list[HostRow]:
        return [row for row in self.rows if row.selected]

    def set_rows_selection(self, source_rows: Sequence[int], *, selected: bool | None = None, invert: bool = False) -> None:
        changed: list[int] = []
        for source_row in source_rows:
            if not (0 <= int(source_row) < len(self.rows)):
                continue
            row = self.rows[int(source_row)]
            new_value = (not row.selected) if invert else bool(selected)
            if row.selected != new_value:
                row.selected = new_value
                changed.append(int(source_row))
        if not changed:
            return
        for source_row in changed:
            idx = self.index(source_row, 0)
            self.dataChanged.emit(idx, idx, [Qt.ItemDataRole.CheckStateRole])

    def set_all_ping(self, text: str) -> None:
        if not self.rows:
            return
        for row in self.rows:
            row.ping_status = text
        self.dataChanged.emit(
            self.index(0, self.PING_COLUMN),
            self.index(len(self.rows) - 1, self.PING_COLUMN),
        )

    def set_ping_result(self, address: str, reachable: bool, latency_ms: float | None) -> None:
        if reachable:
            text = f"OK · {latency_ms:.0f} ms" if latency_ms is not None else "OK"
        else:
            text = "Sin respuesta"
        for i, row in enumerate(self.rows):
            if row.target.address == address:
                row.ping_status = text
                idx = self.index(i, self.PING_COLUMN)
                self.dataChanged.emit(idx, idx)

    def select_all(self, selected: bool) -> None:
        if not self.rows:
            return
        for row in self.rows:
            row.selected = selected
        self.dataChanged.emit(
            self.index(0, 0),
            self.index(len(self.rows) - 1, 0),
            [Qt.ItemDataRole.CheckStateRole],
        )

    def invert_selection(self) -> None:
        if not self.rows:
            return
        for row in self.rows:
            row.selected = not row.selected
        self.dataChanged.emit(
            self.index(0, 0),
            self.index(len(self.rows) - 1, 0),
            [Qt.ItemDataRole.CheckStateRole],
        )


class JobTableModel(QAbstractTableModel):
    HEADERS: tuple[str, ...] = (
        "Job",
        "Estado",
        "Progreso",
        "Hosts",
        "Scripts",
        "Transporte",
        "Errores",
        "Actualizado",
    )

    def __init__(self) -> None:
        super().__init__()
        self.rows: list[dict[str, Any]] = []

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self.HEADERS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> Any:  # noqa: N802
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.HEADERS[section] if 0 <= section < len(self.HEADERS) else None
        return None

    @staticmethod
    def _progress(manifest: dict[str, Any]) -> str:
        total = int(manifest.get("TotalCount") or 0)
        collected = int(manifest.get("CollectedCount") or 0) + int(manifest.get("CollectedWithErrorsCount") or 0)
        dispatch = int(manifest.get("DispatchAttempted") or 0)
        if total <= 0:
            return "0 %"
        if collected:
            return f"{round((collected / total) * 100)} %"
        return f"{round((dispatch / total) * 100)} %"

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid() or not (0 <= index.row() < len(self.rows)):
            return None
        row = self.rows[index.row()]
        status = str(row.get("Status") or "UNKNOWN")
        presentation = present_job_state(status)
        if role == Qt.ItemDataRole.DisplayRole:
            values = (
                str(row.get("JobId") or "-"),
                presentation.label,
                self._progress(row),
                str(row.get("TotalCount") or 0),
                str(row.get("ScriptCount") or 0),
                str(row.get("TransportProfile") or row.get("ExecutionMethod") or "-"),
                str(row.get("FailedCount") or row.get("DispatchFailed") or 0),
                str(row.get("UpdatedAt") or row.get("CreatedAt") or "-"),
            )
            return values[index.column()]
        if role == Qt.ItemDataRole.ForegroundRole and index.column() == 1:
            palette = {
                "danger": COLORS.danger,
                "warning": COLORS.warning,
                "success": COLORS.success,
                "info": COLORS.info,
            }
            if presentation.kind in palette:
                return QColor(palette[presentation.kind])
        if role == Qt.ItemDataRole.ToolTipRole and index.column() == 1:
            return f"{presentation.label}\nCódigo técnico: {status}"
        if role == Qt.ItemDataRole.UserRole:
            return row
        return None

    def set_rows(self, rows: Sequence[dict[str, Any]]) -> None:
        self.beginResetModel()
        self.rows = [dict(row) for row in rows]
        self.endResetModel()

    def manifest_at(self, row: int) -> dict[str, Any] | None:
        if 0 <= row < len(self.rows):
            return self.rows[row]
        return None


class ScriptTableModel(QAbstractTableModel):
    HEADERS: tuple[str, ...] = ("", "Script", "Versión", "Riesgo", "Origen", "Timeout")

    def __init__(self) -> None:
        super().__init__()
        self.rows: list[dict[str, Any]] = []
        self.selected_ids: set[str] = set()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self.HEADERS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> Any:  # noqa: N802
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.HEADERS[section] if 0 <= section < len(self.HEADERS) else None
        return None

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid() or not (0 <= index.row() < len(self.rows)):
            return None
        row = self.rows[index.row()]
        script_id = str(row.get("id") or "")
        if role == Qt.ItemDataRole.CheckStateRole and index.column() == 0:
            return Qt.CheckState.Checked if script_id in self.selected_ids else Qt.CheckState.Unchecked
        if role == Qt.ItemDataRole.DisplayRole:
            values = (
                "",
                str(row.get("name") or "-"),
                str(row.get("version") or "1.0.0"),
                str(row.get("risk") or "LOW"),
                str(row.get("source") or "-"),
                f"{row.get('timeout_seconds') or 1800} s",
            )
            return values[index.column()]
        if role == Qt.ItemDataRole.ForegroundRole and index.column() == 3:
            risk = str(row.get("risk") or "LOW").upper()
            if risk in {"HIGH", "CRITICAL"}:
                return QColor(COLORS.danger)
            if risk == "MEDIUM":
                return QColor(COLORS.warning)
            return QColor(COLORS.success)
        if role == Qt.ItemDataRole.UserRole:
            return row
        return None

    def flags(self, index: QModelIndex) -> Qt.ItemFlag:
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags
        flags = Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
        if index.column() == 0:
            flags |= Qt.ItemFlag.ItemIsUserCheckable
        return flags

    def setData(self, index: QModelIndex, value: Any, role: int = Qt.ItemDataRole.EditRole) -> bool:  # noqa: N802
        if not index.isValid() or index.column() != 0 or role != Qt.ItemDataRole.CheckStateRole:
            return False
        row = self.rows[index.row()]
        script_id = str(row.get("id") or "")
        checked = value == Qt.CheckState.Checked.value or value == Qt.CheckState.Checked
        if checked:
            self.selected_ids.add(script_id)
        else:
            self.selected_ids.discard(script_id)
        self.dataChanged.emit(index, index, [Qt.ItemDataRole.CheckStateRole])
        return True

    def set_rows(self, rows: Sequence[dict[str, Any]]) -> None:
        self.beginResetModel()
        current_ids = {str(row.get("id") or "") for row in rows}
        self.selected_ids.intersection_update(current_ids)
        self.rows = [dict(row) for row in rows]
        self.endResetModel()

    def selected_rows(self) -> list[dict[str, Any]]:
        return [row for row in self.rows if str(row.get("id") or "") in self.selected_ids]
