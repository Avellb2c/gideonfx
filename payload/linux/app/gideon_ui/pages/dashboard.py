from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from gideon_site_groups import SiteGroupStore

from ..services import ManifestRepository
from ..tokens import COLORS, SPACE_12, SPACE_16, SPACE_20
from ..widgets import MetricCard, PageHeader, StatusChip
from .base import ScrollPage


class DashboardPage(ScrollPage):
    newExecutionRequested: Signal = Signal()
    jobsRequested: Signal = Signal()

    def __init__(
        self,
        *,
        manifests: ManifestRepository,
        groups: SiteGroupStore,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._manifests = manifests
        self._groups = groups

        header = PageHeader(
            "Inicio",
            "Estado operativo de la plataforma, ejecuciones recientes e incidencias.",
            self.content,
        )
        run_button = QPushButton("+ Nueva ejecución", header)
        run_button.setObjectName("PrimaryButton")
        run_button.clicked.connect(self.newExecutionRequested.emit)
        header.add_action(run_button)
        self.content_layout.addWidget(header)

        self.metrics_frame = QWidget(self.content)
        self.metrics_grid = QGridLayout(self.metrics_frame)
        self.metrics_grid.setContentsMargins(0, 0, 0, 0)
        self.metrics_grid.setHorizontalSpacing(SPACE_12)
        self.metrics_grid.setVerticalSpacing(SPACE_12)
        self.hosts_card = MetricCard("Hosts", "0", COLORS.brand_blue)
        self.active_card = MetricCard("Jobs activos", "0", COLORS.purple)
        self.completed_card = MetricCard("Finalizados", "0", COLORS.success)
        self.incidents_card = MetricCard("Incidencias", "0", COLORS.brand_red)
        self.metrics_grid.addWidget(self.hosts_card, 0, 0)
        self.metrics_grid.addWidget(self.active_card, 0, 1)
        self.metrics_grid.addWidget(self.completed_card, 0, 2)
        self.metrics_grid.addWidget(self.incidents_card, 0, 3)
        self.content_layout.addWidget(self.metrics_frame)

        self.lower_widget = QWidget(self.content)
        self.lower_grid = QGridLayout(self.lower_widget)
        self.lower_grid.setContentsMargins(0, 0, 0, 0)
        self.lower_grid.setHorizontalSpacing(SPACE_16)
        self.lower_grid.setVerticalSpacing(SPACE_16)
        self.content_layout.addWidget(self.lower_widget)

        recent_card = QFrame(self.content)
        recent_card.setObjectName("Card")
        recent_layout = QVBoxLayout(recent_card)
        recent_layout.setContentsMargins(SPACE_16, SPACE_16, SPACE_16, SPACE_16)
        recent_layout.setSpacing(SPACE_12)
        recent_head = QHBoxLayout()
        recent_title = QLabel("Actividad reciente", recent_card)
        recent_title.setObjectName("SectionTitle")
        recent_head.addWidget(recent_title)
        recent_head.addStretch(1)
        view_all = QPushButton("Ver ejecuciones", recent_card)
        view_all.setObjectName("GhostButton")
        view_all.clicked.connect(self.jobsRequested.emit)
        recent_head.addWidget(view_all)
        recent_layout.addLayout(recent_head)
        self.recent_table = QTableWidget(0, 4, recent_card)
        self.recent_table.setHorizontalHeaderLabels(("Job", "Estado", "Hosts", "Actualización"))
        self.recent_table.verticalHeader().setVisible(False)
        self.recent_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.recent_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.recent_table.horizontalHeader().setStretchLastSection(True)
        recent_layout.addWidget(self.recent_table, 1)
        self.recent_card = recent_card
        self.lower_grid.addWidget(recent_card, 0, 0)

        incident_card = QFrame(self.content)
        incident_card.setObjectName("Card")
        incident_layout = QVBoxLayout(incident_card)
        incident_layout.setContentsMargins(SPACE_16, SPACE_16, SPACE_16, SPACE_16)
        incident_layout.setSpacing(SPACE_12)
        incident_title = QLabel("Atención requerida", incident_card)
        incident_title.setObjectName("SectionTitle")
        incident_layout.addWidget(incident_title)
        self.incident_box = QVBoxLayout()
        self.incident_box.setSpacing(8)
        incident_layout.addLayout(self.incident_box)
        incident_layout.addStretch(1)
        self.incident_card = incident_card
        self.lower_grid.addWidget(incident_card, 0, 1)

        self.content_layout.addStretch(1)
        self.refresh()


    def set_compact(self, compact: bool) -> None:
        # Responsive reflow: no se comprimen tarjetas hasta volverlas ilegibles.
        for card in (self.hosts_card, self.active_card, self.completed_card, self.incidents_card):
            self.metrics_grid.removeWidget(card)
        if compact:
            self.metrics_grid.addWidget(self.hosts_card, 0, 0)
            self.metrics_grid.addWidget(self.active_card, 0, 1)
            self.metrics_grid.addWidget(self.completed_card, 1, 0)
            self.metrics_grid.addWidget(self.incidents_card, 1, 1)
        else:
            self.metrics_grid.addWidget(self.hosts_card, 0, 0)
            self.metrics_grid.addWidget(self.active_card, 0, 1)
            self.metrics_grid.addWidget(self.completed_card, 0, 2)
            self.metrics_grid.addWidget(self.incidents_card, 0, 3)

        self.lower_grid.removeWidget(self.recent_card)
        self.lower_grid.removeWidget(self.incident_card)
        if compact:
            self.lower_grid.addWidget(self.recent_card, 0, 0)
            self.lower_grid.addWidget(self.incident_card, 1, 0)
        else:
            self.lower_grid.addWidget(self.recent_card, 0, 0)
            self.lower_grid.addWidget(self.incident_card, 0, 1)

    @staticmethod
    def _is_active(status: str) -> bool:
        return status.upper() in {
            "STARTING",
            "DISPATCHING",
            "WAITING_REMOTE_REPORTS",
            "MONITORING",
            "RUNNING",
            "COLLECTING",
            "WAITING_CONNECTION",
        }

    @staticmethod
    def _is_incident(manifest: dict[str, Any]) -> bool:
        status = str(manifest.get("Status") or "").upper()
        if status in {"FAILED", "LAUNCH_FAILED", "INTERRUPTED", "PARTIAL"}:
            return True
        return int(manifest.get("FailedCount") or manifest.get("DispatchFailed") or 0) > 0

    def refresh(self) -> None:
        try:
            hosts = len(self._groups.read_sites())
        except Exception:
            hosts = 0
        manifests = self._manifests.list(limit=80)
        active = [row for row in manifests if self._is_active(str(row.get("Status") or ""))]
        completed = [
            row
            for row in manifests
            if str(row.get("Status") or "").upper()
            in {"COMPLETED", "COMPLETED_WITH_WARNINGS", "COLLECTED"}
        ]
        incidents = [row for row in manifests if self._is_incident(row)]

        self.hosts_card.set_value(hosts)
        self.active_card.set_value(len(active))
        self.completed_card.set_value(len(completed))
        self.incidents_card.set_value(len(incidents))

        self.recent_table.setRowCount(0)
        for manifest in manifests[:8]:
            row = self.recent_table.rowCount()
            self.recent_table.insertRow(row)
            values = (
                str(manifest.get("JobId") or "-"),
                str(manifest.get("Status") or "UNKNOWN"),
                str(manifest.get("TotalCount") or 0),
                str(manifest.get("UpdatedAt") or manifest.get("CreatedAt") or "-"),
            )
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                if col == 1:
                    status = value.upper()
                    if status in {"FAILED", "LAUNCH_FAILED", "INTERRUPTED"}:
                        item.setForeground(Qt.GlobalColor.red)
                    elif self._is_active(status):
                        item.setForeground(Qt.GlobalColor.darkCyan)
                self.recent_table.setItem(row, col, item)
        self.recent_table.resizeColumnsToContents()

        while self.incident_box.count():
            item = self.incident_box.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

        if not incidents:
            row_widget = QWidget(self.content)
            row_layout = QHBoxLayout(row_widget)
            row_layout.setContentsMargins(0, 4, 0, 4)
            row_layout.addWidget(StatusChip("✓ Sin incidencias", "success", row_widget))
            row_layout.addStretch(1)
            self.incident_box.addWidget(row_widget)
            return

        for manifest in incidents[:6]:
            row_widget = QWidget(self.content)
            row_layout = QVBoxLayout(row_widget)
            row_layout.setContentsMargins(0, 4, 0, 8)
            row_layout.setSpacing(2)
            top = QHBoxLayout()
            chip = StatusChip(str(manifest.get("Status") or "ERROR"), "danger", row_widget)
            top.addWidget(chip)
            top.addStretch(1)
            row_layout.addLayout(top)
            title = QLabel(str(manifest.get("JobId") or "-"), row_widget)
            title.setStyleSheet("font-weight:600;")
            row_layout.addWidget(title)
            detail = QLabel(
                f"Errores: {manifest.get('FailedCount') or manifest.get('DispatchFailed') or 0} · "
                f"Hosts: {manifest.get('TotalCount') or 0}",
                row_widget,
            )
            detail.setObjectName("Muted")
            row_layout.addWidget(detail)
            self.incident_box.addWidget(row_widget)
