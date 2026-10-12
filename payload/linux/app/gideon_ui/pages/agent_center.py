from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, QThread, Qt, Signal
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTableView,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from gideon_agent_builder import AgentBuilder
from gideon_version import AGENT_VERSION
from gideon_agent_catalog import AgentDownloadCatalog
from gideon_agent_update_builder import AgentUpdateBundleBuilder
from gideon_services import AgentAdministrationService

from ..tokens import COLORS, SPACE_8, SPACE_12, SPACE_16
from ..widgets import CommandBar, MetricCard, PageHeader, StatusChip, show_detailed_message
from .agents import AgentsPage
from .base import ScrollPage


class OperationWorker(QThread):
    completed: Signal = Signal(object)
    failed: Signal = Signal(str)

    def __init__(self, operation: Callable[[], Any], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.operation = operation

    def run(self) -> None:
        try:
            self.completed.emit(self.operation())
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class AgentInventoryModel(QAbstractTableModel):
    HEADERS = (
        "Estado",
        "Código",
        "Sede",
        "Equipo",
        "Conexión",
        "Versión",
        "Plataforma",
        "Perfil",
        "Última conexión",
        "Actualización",
    )

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.rows: list[dict[str, Any]] = []
        self.ttl_seconds = 90

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self.HEADERS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> Any:  # noqa: N802
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.HEADERS[section] if 0 <= section < len(self.HEADERS) else None
        return None

    @staticmethod
    def _online(row: dict[str, Any]) -> bool:
        return bool(row.get("_online"))

    def _display(self, row: dict[str, Any], column: int) -> str:
        state = str(row.get("update_state") or "")
        update_label = {
            "UPDATE_AVAILABLE": f"Disponible {row.get('target_version') or ''}".strip(),
            "CURRENT": "Al día",
            "AHEAD": "Adelantado",
            "SIN_RELEASE": "Sin release",
        }.get(state, state or "-")
        values = (
            "Activo" if self._online(row) else "Inactivo",
            str(row.get("site_code") or "-"),
            str(row.get("site_name") or "-"),
            str(row.get("agent_name") or row.get("hostname") or row.get("agent_id") or "-"),
            "HTTPS/PULL → Gateway",
            str(row.get("agent_version") or "-"),
            str(row.get("platform") or "-").upper(),
            str(row.get("host_profile") or "-"),
            str(row.get("last_seen") or "Nunca"),
            update_label,
        )
        return values[column]

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid() or not (0 <= index.row() < len(self.rows)):
            return None
        row = self.rows[index.row()]
        if role == Qt.ItemDataRole.DisplayRole:
            return self._display(row, index.column())
        if role == Qt.ItemDataRole.ToolTipRole:
            if index.column() in {3, 4}:
                return "\n".join((
                    f"AgentId: {row.get('agent_id') or '-'}",
                    f"Hostname: {row.get('hostname') or '-'}",
                    f"IP observada: {row.get('last_remote_ip') or '-'} (solo telemetría)",
                    "Ruta real: Agent inicia HTTPS/PULL hacia el Gateway.",
                ))
            return self._display(row, index.column())
        if role == Qt.ItemDataRole.ForegroundRole:
            from PySide6.QtGui import QColor
            if index.column() == 0:
                return QColor(COLORS.success if self._online(row) else COLORS.danger)
            if index.column() == 9:
                state = str(row.get("update_state") or "")
                if state == "UPDATE_AVAILABLE":
                    return QColor(COLORS.warning)
                if state == "CURRENT":
                    return QColor(COLORS.success)
        if role == Qt.ItemDataRole.UserRole:
            return row
        return None

    def set_rows(self, rows: list[dict[str, Any]]) -> None:
        """Incremental update when AgentId order is stable; reset only on topology change."""
        old_ids = [str(r.get("agent_id") or "") for r in self.rows]
        new_ids = [str(r.get("agent_id") or "") for r in rows]
        if old_ids == new_ids and len(self.rows) == len(rows):
            changed_rows: list[int] = []
            for i, new_row in enumerate(rows):
                if self.rows[i] != new_row:
                    self.rows[i] = dict(new_row)
                    changed_rows.append(i)
            for i in changed_rows:
                self.dataChanged.emit(self.index(i, 0), self.index(i, len(self.HEADERS) - 1))
            return
        self.beginResetModel()
        self.rows = [dict(row) for row in rows]
        self.endResetModel()


class AgentFilterProxy(QSortFilterProxyModel):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.search = ""
        self.status = "all"
        self.setDynamicSortFilter(True)
        self.setSortCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)

    def set_filter(self, search: str, status: str) -> None:
        self.search = str(search or "").strip().lower()
        self.status = str(status or "all")
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:  # noqa: N802
        model = self.sourceModel()
        if not isinstance(model, AgentInventoryModel) or not (0 <= source_row < len(model.rows)):
            return False
        row = model.rows[source_row]
        if self.status == "online" and not row.get("_online"):
            return False
        if self.status == "offline" and row.get("_online"):
            return False
        if self.status == "updates" and str(row.get("update_state")) != "UPDATE_AVAILABLE":
            return False
        if self.search:
            haystack = " ".join(str(row.get(k) or "") for k in (
                "site_code", "site_name", "agent_id", "agent_name", "hostname", "platform",
                "architecture", "host_profile", "last_remote_ip", "agent_version",
            )).lower()
            if self.search not in haystack:
                return False
        return True


class AgentCenterPage(ScrollPage):
    """Single Qt administration surface for the complete Agent lifecycle."""

    toastRequested: Signal = Signal(str, str, str)
    executeRequested: Signal = Signal(str)
    transferRequested: Signal = Signal(str)
    diagnoseRequested: Signal = Signal(str)

    def __init__(
        self,
        *,
        app_root: Path,
        config: dict[str, Any],
        catalog: AgentDownloadCatalog,
        gateway_url: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.app_root = Path(app_root)
        self.config = config
        self.catalog = catalog
        self.admin = AgentAdministrationService(self.app_root, config)
        self.update_builder = AgentUpdateBundleBuilder(self.app_root)
        self._worker: OperationWorker | None = None
        self._agents: list[dict[str, Any]] = []
        self._releases: list[dict[str, Any]] = []
        self._selected_agent: dict[str, Any] | None = None

        header = PageHeader(
            "Agentes",
            "Equipos, instaladores, releases estables y actualizaciones en un solo módulo.",
            self.content,
        )
        refresh = QPushButton("↻ Actualizar", header)
        refresh.setObjectName("GhostButton")
        refresh.clicked.connect(self.reload)
        header.add_action(refresh)
        self.content_layout.addWidget(header)

        self.tabs = QTabWidget(self.content)
        self.tabs.setDocumentMode(True)
        self.tabs.addTab(self._build_inventory_tab(), "Equipos")
        self.installers_page = AgentsPage(
            catalog=catalog,
            gateway_url=gateway_url,
            embedded=True,
            parent=self.tabs,
        )
        self.installers_page.toastRequested.connect(self.toastRequested)
        self.tabs.addTab(self.installers_page, "Instaladores")
        self.tabs.addTab(self._build_releases_tab(), "Versiones / Releases")
        self.tabs.addTab(self._build_updates_tab(), "Actualizaciones")
        self.tabs.currentChanged.connect(lambda _idx: self._refresh_visible_tab())
        self.content_layout.addWidget(self.tabs)
        self.content_layout.addStretch(1)
        # Carga diferida: el RefreshCoordinator consulta el Gateway solo cuando
        # esta página está visible. Esto acelera el arranque y evita polling duplicado.

    def _build_inventory_tab(self) -> QWidget:
        tab = QWidget(self.tabs)
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(SPACE_8, SPACE_12, SPACE_8, SPACE_8)
        layout.setSpacing(SPACE_12)

        metrics = QWidget(tab)
        metric_row = QHBoxLayout(metrics)
        metric_row.setContentsMargins(0, 0, 0, 0)
        self.total_card = MetricCard("Enrolados", "0", COLORS.info)
        self.online_card = MetricCard("Activos", "0", COLORS.success)
        self.offline_card = MetricCard("Inactivos", "0", COLORS.danger)
        self.update_card = MetricCard("Con actualización", "0", COLORS.warning)
        for card in (self.total_card, self.online_card, self.offline_card, self.update_card):
            metric_row.addWidget(card)
        layout.addWidget(metrics)

        filters = QHBoxLayout()
        self.agent_search = QLineEdit(tab)
        self.agent_search.setPlaceholderText("Buscar sede, equipo, AgentId, hostname o perfil…")
        self.agent_search.setClearButtonEnabled(True)
        self.agent_search.textChanged.connect(self._apply_agent_filter)
        filters.addWidget(self.agent_search, 1)
        self.agent_filter = QComboBox(tab)
        self.agent_filter.addItem("Todos", "all")
        self.agent_filter.addItem("Activos", "online")
        self.agent_filter.addItem("Inactivos", "offline")
        self.agent_filter.addItem("Con actualización", "updates")
        self.agent_filter.currentIndexChanged.connect(self._apply_agent_filter)
        filters.addWidget(self.agent_filter)
        layout.addLayout(filters)

        splitter = QSplitter(Qt.Orientation.Horizontal, tab)
        self.agent_model = AgentInventoryModel(splitter)
        self.agent_proxy = AgentFilterProxy(splitter)
        self.agent_proxy.setSourceModel(self.agent_model)
        self.agent_table = QTableView(splitter)
        self.agent_table.setModel(self.agent_proxy)
        self.agent_table.setAlternatingRowColors(True)
        self.agent_table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.agent_table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self.agent_table.setSortingEnabled(True)
        self.agent_table.verticalHeader().setVisible(False)
        self.agent_table.horizontalHeader().setStretchLastSection(True)
        self.agent_table.selectionModel().selectionChanged.connect(lambda *_: self._agent_selected())
        splitter.addWidget(self.agent_table)

        detail = QFrame(splitter)
        detail.setObjectName("Card")
        detail.setMinimumWidth(330)
        detail.setMaximumWidth(470)
        detail_layout = QVBoxLayout(detail)
        detail_layout.setContentsMargins(SPACE_16, SPACE_16, SPACE_16, SPACE_16)
        detail_layout.setSpacing(SPACE_8)
        self.detail_title = QLabel("Seleccione un Agent", detail)
        self.detail_title.setObjectName("SectionTitle")
        detail_layout.addWidget(self.detail_title)
        self.detail_status = StatusChip("Sin selección", "neutral", detail)
        detail_layout.addWidget(self.detail_status, alignment=Qt.AlignmentFlag.AlignLeft)
        self.detail_text = QLabel("El detalle muestra identidad, Gateway, telemetría y versión sin confundir la IP observada con una ruta de conexión.", detail)
        self.detail_text.setWordWrap(True)
        self.detail_text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        detail_layout.addWidget(self.detail_text)
        detail_layout.addSpacing(SPACE_8)

        self.exec_button = QPushButton("Ejecutar script", detail)
        self.exec_button.clicked.connect(lambda: self._emit_agent_action(self.executeRequested))
        detail_layout.addWidget(self.exec_button)
        self.transfer_button = QPushButton("Transferir archivo", detail)
        self.transfer_button.clicked.connect(lambda: self._emit_agent_action(self.transferRequested))
        detail_layout.addWidget(self.transfer_button)
        self.diag_button = QPushButton("Diagnosticar", detail)
        self.diag_button.clicked.connect(lambda: self._emit_agent_action(self.diagnoseRequested))
        detail_layout.addWidget(self.diag_button)

        detail_layout.addStretch(1)
        self.copy_id_button = QPushButton("Copiar Agent ID", detail)
        self.copy_id_button.setObjectName("GhostButton")
        self.copy_id_button.clicked.connect(self._copy_agent_id)
        detail_layout.addWidget(self.copy_id_button)
        self.uninstall_button = QPushButton("Desinstalar remotamente", detail)
        self.uninstall_button.setObjectName("DangerButton")
        self.uninstall_button.clicked.connect(self._remote_uninstall)
        detail_layout.addWidget(self.uninstall_button)
        self.purge_button = QPushButton("Eliminar registro del Gateway", detail)
        self.purge_button.setObjectName("GhostButton")
        self.purge_button.clicked.connect(self._purge_agent)
        detail_layout.addWidget(self.purge_button)
        splitter.addWidget(detail)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 0)
        layout.addWidget(splitter, 1)
        return tab

    def _build_releases_tab(self) -> QWidget:
        tab = QWidget(self.tabs)
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(SPACE_8, SPACE_12, SPACE_8, SPACE_8)
        layout.setSpacing(SPACE_12)

        info = QLabel(
            "Publicar no aprueba. Solo un bundle site-neutral, firmado, íntegro y APPROVED puede ser ofrecido automáticamente por el canal stable.",
            tab,
        )
        info.setWordWrap(True)
        info.setObjectName("Muted")
        layout.addWidget(info)

        actions = CommandBar(tab)
        actions.add_action("Generar bundle de actualización…", self._build_update_bundle, primary=True)
        actions.add_action("Publicar bundle local", self._publish_selected_local_release)
        actions.add_action("Aprobar", lambda: self._set_release_approval(True))
        actions.add_action("Revocar", lambda: self._set_release_approval(False))
        actions.add_stretch()
        actions.add_action("↻ Actualizar", self._refresh_releases)
        layout.addWidget(actions)

        local_title = QLabel("Bundles locales de actualización", tab)
        local_title.setObjectName("SectionTitle")
        layout.addWidget(local_title)
        self.local_release_table = QTableWidget(0, 6, tab)
        self.local_release_table.setHorizontalHeaderLabels(("Versión", "SO", "Arquitectura", "Canal", "Creado", "Bundle"))
        self.local_release_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.local_release_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.local_release_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.local_release_table.verticalHeader().setVisible(False)
        self.local_release_table.horizontalHeader().setStretchLastSection(True)
        self.local_release_table.setMinimumHeight(180)
        layout.addWidget(self.local_release_table)

        gateway_title = QLabel("Releases publicados en Gateway", tab)
        gateway_title.setObjectName("SectionTitle")
        layout.addWidget(gateway_title)
        self.gateway_release_table = QTableWidget(0, 9, tab)
        self.gateway_release_table.setHorizontalHeaderLabels((
            "SO", "Arquitectura", "Canal", "Versión", "Aprobación", "Publicado", "Aprobado", "Por", "SHA-256"
        ))
        self.gateway_release_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.gateway_release_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.gateway_release_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.gateway_release_table.verticalHeader().setVisible(False)
        self.gateway_release_table.horizontalHeader().setStretchLastSection(True)
        self.gateway_release_table.setMinimumHeight(250)
        layout.addWidget(self.gateway_release_table)
        return tab

    def _build_updates_tab(self) -> QWidget:
        tab = QWidget(self.tabs)
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(SPACE_8, SPACE_12, SPACE_8, SPACE_8)
        layout.setSpacing(SPACE_12)
        note = QLabel(
            "El Agent solo auto-instala una versión estable aprobada, con SHA-256 y firma Ed25519 válidos, cuando no tiene un Job activo. La configuración de sede, perfil y CA se preserva durante la actualización.",
            tab,
        )
        note.setWordWrap(True)
        note.setObjectName("Muted")
        layout.addWidget(note)
        self.update_table = QTableWidget(0, 8, tab)
        self.update_table.setHorizontalHeaderLabels((
            "Código", "Sede", "Equipo", "Actual", "Objetivo estable", "Estado", "Último heartbeat", "Agent ID"
        ))
        self.update_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.update_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.update_table.verticalHeader().setVisible(False)
        self.update_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.update_table)
        return tab

    def reload(self, *, force: bool = False) -> None:
        if self._worker is not None and self._worker.isRunning():
            return
        if force:
            self.installers_page.reload(force=True)
        self._run_operation(self._load_agent_release_snapshot, self._snapshot_loaded, "Consultar Agents")

    def _load_agent_release_snapshot(self) -> dict[str, Any]:
        agents = self.admin.list_agents()
        try:
            releases = self.admin.list_releases()
        except Exception:
            releases = []
        ttl = int((self.config.get("agent_control_plane") or {}).get("agent_online_ttl_seconds", 90))
        matrix = self.admin.update_matrix(agents, releases)
        for row in matrix:
            row["_online"] = self.admin.is_online(row, ttl)
        matrix.sort(key=lambda r: (not bool(r.get("_online")), str(r.get("site_code") or ""), str(r.get("hostname") or ""), str(r.get("agent_id") or "")))
        return {"agents": matrix, "releases": releases, "ttl": ttl}

    def _snapshot_loaded(self, payload: object) -> None:
        data = payload if isinstance(payload, dict) else {}
        self._agents = [dict(r) for r in (data.get("agents") or [])]
        self._releases = [dict(r) for r in (data.get("releases") or [])]
        self.agent_model.set_rows(self._agents)
        online = sum(1 for r in self._agents if r.get("_online"))
        updates = sum(1 for r in self._agents if r.get("update_state") == "UPDATE_AVAILABLE")
        self.total_card.set_value(str(len(self._agents)))
        self.online_card.set_value(str(online))
        self.offline_card.set_value(str(len(self._agents) - online))
        self.update_card.set_value(str(updates))
        self._render_releases()
        self._render_updates()
        self.agent_table.resizeColumnsToContents()
        self._reselect_current_agent()

    def _run_operation(self, operation: Callable[[], Any], callback: Callable[[object], None], title: str) -> None:
        if self._worker is not None and self._worker.isRunning():
            return
        worker = OperationWorker(operation, self)
        self._worker = worker
        worker.completed.connect(lambda payload: self._operation_completed(callback, payload))
        worker.failed.connect(lambda detail: self._operation_failed(title, detail))
        worker.start()

    def _operation_completed(self, callback: Callable[[object], None], payload: object) -> None:
        # Liberar el worker antes del callback permite encadenar una segunda
        # operación (por ejemplo publicar → refrescar releases) sin perderla.
        self._finish_worker()
        callback(payload)

    def _finish_worker(self) -> None:
        if self._worker is not None:
            self._worker.deleteLater()
        self._worker = None

    def _operation_failed(self, title: str, detail: str) -> None:
        self._finish_worker()
        self.toastRequested.emit(title, detail, "danger")
        show_detailed_message(self, title, "La operación no pudo completarse.", detail, level="warning")

    def _apply_agent_filter(self, *_args: object) -> None:
        self.agent_proxy.set_filter(self.agent_search.text(), str(self.agent_filter.currentData() or "all"))

    def _agent_selected(self) -> None:
        indexes = self.agent_table.selectionModel().selectedRows() if self.agent_table.selectionModel() else []
        if not indexes:
            self._selected_agent = None
            self._render_agent_detail()
            return
        source = self.agent_proxy.mapToSource(indexes[0])
        if not source.isValid() or not (0 <= source.row() < len(self.agent_model.rows)):
            return
        self._selected_agent = dict(self.agent_model.rows[source.row()])
        self._render_agent_detail()

    def _render_agent_detail(self) -> None:
        row = self._selected_agent
        enabled = bool(row)
        for button in (self.exec_button, self.transfer_button, self.diag_button, self.copy_id_button, self.uninstall_button, self.purge_button):
            button.setEnabled(enabled)
        if not row:
            self.detail_title.setText("Seleccione un Agent")
            self.detail_status.setText("Sin selección")
            self.detail_status.set_kind("neutral")
            return
        online = bool(row.get("_online"))
        self.detail_title.setText(str(row.get("agent_name") or row.get("hostname") or row.get("agent_id") or "Agent"))
        self.detail_status.setText("Activo" if online else "Inactivo")
        self.detail_status.set_kind("success" if online else "danger")
        self.detail_text.setText("\n".join((
            f"Sede: {row.get('site_code') or '-'} · {row.get('site_name') or '-'}",
            f"Agent ID: {row.get('agent_id') or '-'}",
            f"Hostname: {row.get('hostname') or '-'}",
            f"Ruta: HTTPS/PULL → Gateway",
            f"IP observada: {row.get('last_remote_ip') or '-'} (telemetría)",
            f"Versión: {row.get('agent_version') or '-'}",
            f"Perfil: {row.get('host_profile') or '-'}",
            f"Último heartbeat: {row.get('last_seen') or 'Nunca'}",
            f"Actualización: {row.get('update_state') or '-'} {row.get('target_version') or ''}".strip(),
        )))
        self.uninstall_button.setEnabled(online and str(row.get("platform") or "").lower() == "windows")

    def _reselect_current_agent(self) -> None:
        aid = str((self._selected_agent or {}).get("agent_id") or "")
        if not aid:
            self._render_agent_detail()
            return
        for src_row, row in enumerate(self.agent_model.rows):
            if str(row.get("agent_id") or "") == aid:
                proxy = self.agent_proxy.mapFromSource(self.agent_model.index(src_row, 0))
                if proxy.isValid():
                    self.agent_table.selectRow(proxy.row())
                return
        self._selected_agent = None
        self._render_agent_detail()

    def _emit_agent_action(self, signal: Signal) -> None:
        aid = str((self._selected_agent or {}).get("agent_id") or "")
        if aid:
            signal.emit(aid)

    def _copy_agent_id(self) -> None:
        aid = str((self._selected_agent or {}).get("agent_id") or "")
        if aid:
            QApplication.clipboard().setText(aid)
            self.toastRequested.emit("Agent ID copiado", aid, "success")

    def _remote_uninstall(self) -> None:
        row = dict(self._selected_agent or {})
        if not row:
            return
        host = str(row.get("hostname") or row.get("agent_id") or "Agent")
        accepted = QMessageBox.question(
            self,
            "Desinstalar Agent remotamente",
            f"Se retirará Gideon Rx Agent de {host}.\n\nSe limpiarán tarea/servicio, miniatura, appwiz.cpl, Program Files, ProgramData y restos de versiones anteriores. El Job espera 45 s antes de autodestruirse para devolver el resultado.\n\n¿Continuar?",
        )
        if accepted != QMessageBox.StandardButton.Yes:
            return
        self._run_operation(lambda: self.admin.queue_remote_uninstall(row), self._uninstall_queued, "Desinstalar Agent")

    def _uninstall_queued(self, payload: object) -> None:
        data = payload if isinstance(payload, dict) else {}
        job = data.get("job") if isinstance(data.get("job"), dict) else {}
        self.toastRequested.emit("Desinstalación encolada", str(job.get("JobId") or "Job enviado"), "success")
        QMessageBox.information(
            self,
            "Desinstalación encolada",
            f"Job: {job.get('JobId') or '-'}\n\nCuando el Agent quede inactivo puede usar “Eliminar registro del Gateway”.",
        )

    def _purge_agent(self) -> None:
        row = dict(self._selected_agent or {})
        aid = str(row.get("agent_id") or "")
        if not aid:
            return
        if row.get("_online"):
            QMessageBox.warning(self, "Eliminar registro", "El Agent sigue activo. Desinstálelo primero o espere a que quede inactivo.")
            return
        accepted = QMessageBox.question(
            self,
            "Eliminar registro",
            f"¿Eliminar del Gateway el enrolamiento {aid}?\n\nEsto no desinstala software del equipo.",
        )
        if accepted != QMessageBox.StandardButton.Yes:
            return
        self._run_operation(lambda: self.admin.purge_agent(aid), lambda _payload: self._purge_done(aid), "Eliminar registro")

    def _purge_done(self, aid: str) -> None:
        self.toastRequested.emit("Registro eliminado", aid, "success")
        self._selected_agent = None
        self.reload()

    def _refresh_visible_tab(self) -> None:
        index = self.tabs.currentIndex()
        if index == 1:
            self.installers_page.reload()
        elif index in {2, 3}:
            self._refresh_releases()

    def _refresh_releases(self) -> None:
        self._run_operation(self._load_agent_release_snapshot, self._snapshot_loaded, "Actualizar releases")

    def _render_releases(self) -> None:
        local_rows = [dict(r) for r in AgentBuilder(self.app_root).release_history()]
        self.local_release_table.setRowCount(0)
        for row_data in local_rows:
            row = self.local_release_table.rowCount()
            self.local_release_table.insertRow(row)
            values = (
                row_data.get("version") or "-",
                row_data.get("platform") or "-",
                (row_data.get("architecture") or (row_data.get("architectures") or ["-"])[0]),
                row_data.get("channel") or "-",
                row_data.get("created_at") or "-",
                row_data.get("bundle") or "-",
            )
            for col, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setData(Qt.ItemDataRole.UserRole, row_data)
                item.setToolTip(str(value))
                self.local_release_table.setItem(row, col, item)
        self.local_release_table.resizeColumnsToContents()

        self.gateway_release_table.setRowCount(0)
        for release in self._releases:
            row = self.gateway_release_table.rowCount()
            self.gateway_release_table.insertRow(row)
            values = (
                release.get("platform") or "-",
                release.get("architecture") or "-",
                release.get("channel") or "-",
                release.get("version") or "-",
                release.get("approval_state") or "DRAFT",
                release.get("created_at") or "-",
                release.get("approved_at") or "-",
                release.get("approved_by") or "-",
                release.get("bundle_sha256") or "-",
            )
            for col, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setData(Qt.ItemDataRole.UserRole, release)
                item.setToolTip(str(value))
                self.gateway_release_table.setItem(row, col, item)
        self.gateway_release_table.resizeColumnsToContents()

    def _selected_local_release(self) -> dict[str, Any] | None:
        row = self.local_release_table.currentRow()
        item = self.local_release_table.item(row, 0) if row >= 0 else None
        value = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        return dict(value) if isinstance(value, dict) else None

    def _selected_gateway_release(self) -> dict[str, Any] | None:
        row = self.gateway_release_table.currentRow()
        item = self.gateway_release_table.item(row, 0) if row >= 0 else None
        value = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        return dict(value) if isinstance(value, dict) else None

    def _build_update_bundle(self) -> None:
        version, ok = QInputDialog.getText(self, "Bundle estable", "Versión SemVer:", text=AGENT_VERSION)
        if not ok or not str(version).strip():
            return
        arch, ok = QInputDialog.getItem(self, "Arquitectura", "Arquitectura:", ["x86_64", "arm64"], 0, False)
        if not ok:
            return
        output = QFileDialog.getExistingDirectory(self, "Carpeta de salida")
        out_path = Path(output) if output else None
        self._run_operation(
            lambda: self.update_builder.build(version=str(version).strip(), platform="windows", architecture=str(arch), channel="stable", output_dir=out_path),
            self._update_bundle_built,
            "Generar bundle de actualización",
        )

    def _update_bundle_built(self, payload: object) -> None:
        row = payload if isinstance(payload, dict) else {}
        self.toastRequested.emit("Bundle generado", str(row.get("bundle") or ""), "success")
        self._render_releases()
        QMessageBox.information(
            self,
            "Bundle generado",
            f"{row.get('bundle') or '-'}\n\nEl bundle está firmado y es site-neutral. Debe publicarse y luego aprobarse explícitamente.",
        )

    def _publish_selected_local_release(self) -> None:
        row = self._selected_local_release()
        if not row:
            QMessageBox.information(self, "Publicar release", "Seleccione primero un bundle local.")
            return
        if not bool(row.get("site_neutral")):
            QMessageBox.warning(
                self,
                "Bundle no publicable",
                "Este paquete pertenece al flujo legado por sede y no puede publicarse como actualización estable. Genere un bundle site-neutral desde esta pestaña.",
            )
            return
        self._run_operation(lambda: self.admin.publish_local_release(row), self._release_published, "Publicar release")

    def _release_published(self, payload: object) -> None:
        self.toastRequested.emit("Release publicado", "Quedó en DRAFT; apruébelo explícitamente para stable.", "success")
        self._refresh_releases()

    def _set_release_approval(self, approved: bool) -> None:
        row = self._selected_gateway_release()
        if not row:
            QMessageBox.information(self, "Release", "Seleccione un release del Gateway.")
            return
        verb = "Aprobar" if approved else "Revocar"
        if approved:
            accepted = QMessageBox.question(
                self,
                "Aprobar release",
                f"¿Aprobar {row.get('version')} · {row.get('platform')}/{row.get('architecture')} · {row.get('channel')}?\n\nEl Gateway verificará SHA-256 y firma antes de marcarlo APPROVED.",
            )
            if accepted != QMessageBox.StandardButton.Yes:
                return
        self._run_operation(
            lambda: self.admin.set_release_approval(row, approved=approved),
            lambda _payload: self._approval_done(verb),
            f"{verb} release",
        )

    def _approval_done(self, verb: str) -> None:
        self.toastRequested.emit("Release actualizado", verb, "success")
        self._refresh_releases()

    def _render_updates(self) -> None:
        self.update_table.setRowCount(0)
        labels = {
            "UPDATE_AVAILABLE": "Actualización disponible",
            "CURRENT": "Al día",
            "AHEAD": "Versión superior",
            "SIN_RELEASE": "Sin release estable aprobado",
        }
        for data in self._agents:
            row = self.update_table.rowCount()
            self.update_table.insertRow(row)
            state = str(data.get("update_state") or "")
            values = (
                data.get("site_code") or "-",
                data.get("site_name") or "-",
                data.get("agent_name") or data.get("hostname") or "-",
                data.get("agent_version") or "-",
                data.get("target_version") or "-",
                labels.get(state, state or "-"),
                data.get("last_seen") or "Nunca",
                data.get("agent_id") or "-",
            )
            for col, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setToolTip(str(value))
                self.update_table.setItem(row, col, item)
        self.update_table.resizeColumnsToContents()
