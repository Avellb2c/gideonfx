from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from PySide6.QtCore import QSortFilterProxyModel, QThread, Qt, Signal
from PySide6.QtWidgets import (
    QFileDialog,
    QComboBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from gideon_core.connectivity import PingProbe
from gideon_domain import HostTarget
from gideon_host_profiles import HostProfileStore
from gideon_site_groups import SiteGroupStore

from ..models import HostRow, HostTableModel
from ..services import ManifestRepository
from ..tokens import SPACE_12
from ..widgets import CommandBar, PageHeader, show_detailed_message
from .base import ScrollPage


class PingWorker(QThread):
    """Ejecuta un PING (ICMP) hacia una lista de direcciones en segundo plano."""

    resultReady: Signal = Signal(str, bool, object)
    finishedAll: Signal = Signal(int, int)

    def __init__(self, addresses: list[str], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.addresses = addresses

    def run(self) -> None:
        probe = PingProbe(count=1, timeout_seconds=2.0, max_concurrency=20)
        try:
            results = asyncio.run(probe.probe_many(self.addresses))
        except Exception:
            results = []
        reachable = 0
        for result in results:
            if result.Reachable:
                reachable += 1
            self.resultReady.emit(result.Target, result.Reachable, result.LatencyMs)
        self.finishedAll.emit(reachable, len(results))


class HostsPage(ScrollPage):
    groupChanged: Signal = Signal(str)

    def __init__(
        self,
        *,
        groups: SiteGroupStore,
        manifests: ManifestRepository,
        host_profiles: HostProfileStore,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.groups = groups
        self.manifests = manifests
        self.host_profiles = host_profiles
        self.model = HostTableModel()
        self.proxy = QSortFilterProxyModel(self)
        self.proxy.setSourceModel(self.model)
        self.proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.proxy.setFilterKeyColumn(-1)
        self._editing: bool = False
        self._ping_worker: PingWorker | None = None

        header = PageHeader(
            "Hosts y grupos",
            "Administra inventarios, direcciones IP y perfiles sin mezclar configuración con ejecución.",
            self.content,
        )
        self.content_layout.addWidget(header)

        command = CommandBar(self.content)
        command.add_action("+ Nuevo grupo", self._new_group)
        command.add_action("Duplicar", self._duplicate_group)
        command.add_action("Importar CSV", self._import_csv)
        self.ping_button = command.add_action("Probar PING", self._test_ping)
        command.add_stretch()
        self.edit_button = command.add_action("Editar IPs", self._toggle_edit, primary=True)
        self.content_layout.addWidget(command)

        filters = QHBoxLayout()
        filters.setSpacing(SPACE_12)
        self.group_combo = QComboBox(self.content)
        self.group_combo.setMinimumWidth(280)
        self.group_combo.currentIndexChanged.connect(self._group_selected)
        filters.addWidget(QLabel("Grupo", self.content))
        filters.addWidget(self.group_combo)
        self.search = QLineEdit(self.content)
        self.search.setPlaceholderText("Buscar por código, sede, IP, perfil o estado…")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self.proxy.setFilterFixedString)
        filters.addWidget(self.search, 1)
        self.count_label = QLabel("0 hosts", self.content)
        self.count_label.setObjectName("Muted")
        filters.addWidget(self.count_label)
        self.content_layout.addLayout(filters)

        self.table = QTableView(self.content)
        self.table.setModel(self.proxy)
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(True)
        self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self.table.setMinimumHeight(520)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().setVisible(False)
        self.content_layout.addWidget(self.table, 1)

        hint = QLabel(
            "La vista es local. Cambiar una IP solo actualiza el CSV del grupo activo; no abre SSH/SFTP.",
            self.content,
        )
        hint.setObjectName("Caption")
        self.content_layout.addWidget(hint)
        self._refresh_groups()

    def _refresh_groups(self) -> None:
        active = self.groups.active_group_id
        self.group_combo.blockSignals(True)
        self.group_combo.clear()
        for row in self.groups.list_groups():
            self.group_combo.addItem(str(row.get("name") or row.get("id")), str(row.get("id")))
            if str(row.get("id")) == active:
                self.group_combo.setCurrentIndex(self.group_combo.count() - 1)
        self.group_combo.blockSignals(False)
        self.reload()

    def _group_selected(self, *_args: object) -> None:
        group_id = str(self.group_combo.currentData() or "")
        if not group_id:
            return
        try:
            self.groups.set_active(group_id)
        except Exception as exc:
            show_detailed_message(self, "Grupo", "No se pudo cargar el grupo.", f"{type(exc).__name__}: {exc}")
            return
        self.reload()
        self.groupChanged.emit(group_id)

    def reload(self) -> None:
        rows: list[HostRow] = []
        try:
            raw_rows = self.groups.read_sites()
        except Exception as exc:
            show_detailed_message(self, "Inventario", "No se pudo cargar el inventario.", f"{type(exc).__name__}: {exc}")
            raw_rows = []
        for raw in raw_rows:
            code = str(raw.get("SiteCode") or "")
            platform_meta = str(raw.get("Platform") or "").strip().lower()
            profile_meta = str(raw.get("HostProfile") or "").strip()
            try:
                profile = self.host_profiles.resolve(code)
                platform = platform_meta or str(profile.get("platform") or "windows")
                profile_id = profile_meta or str(profile.get("id") or "windows_generic")
            except Exception:
                platform = platform_meta or "windows"
                profile_id = profile_meta or "windows_generic"
            latest = self.manifests.latest_for_site(code) or {}
            state = str(
                latest.get("RemoteState")
                or latest.get("DispatchStatus")
                or latest.get("Status")
                or "Sin datos"
            )
            rows.append(
                HostRow(
                    target=HostTarget(
                        code=code,
                        name=str(raw.get("SiteName") or ""),
                        address=str(raw.get("ServerIP") or ""),
                        platform=platform,
                        host_profile=profile_id,
                    ),
                    selected=True,
                    state=state,
                    last_job=str(latest.get("JobId") or "-"),
                    updated_at=str(latest.get("LastCheckedAt") or latest.get("UpdatedAt") or raw.get("LastSeen") or "-"),
                    source=str(raw.get("Source") or "inventory"),
                    agent_name=str(raw.get("AgentName") or ""),
                    agent_online=(True if str(raw.get("AgentOnline") or "").lower() == "true" else False if str(raw.get("AgentOnline") or "").lower() == "false" else None),
                    last_seen=str(raw.get("LastSeen") or ""),
                )
            )
        self.model.set_rows(rows)
        self.count_label.setText(f"{len(rows)} hosts")
        self.table.resizeColumnsToContents()

    def selected_targets(self) -> list[HostTarget]:
        return self.model.selected_targets()

    def _toggle_edit(self) -> None:
        if not self._editing:
            self._editing = True
            self.model.ip_editable = True
            self.edit_button.setText("Guardar cambios")
            self.edit_button.setObjectName("PrimaryButton")
            self.edit_button.style().unpolish(self.edit_button)
            self.edit_button.style().polish(self.edit_button)
            return

        try:
            group_id = str(self.group_combo.currentData() or self.groups.active_group_id)
            payload = [
                {
                    "SiteCode": row.target.code,
                    "SiteName": row.target.name,
                    "ServerIP": row.target.address,
                    "Platform": row.target.platform,
                    "HostProfile": row.target.host_profile,
                    "AgentName": row.agent_name,
                    "AgentOnline": "true" if row.agent_online is True else "false" if row.agent_online is False else "",
                    "LastSeen": row.last_seen,
                    "Source": row.source,
                }
                for row in self.model.rows
            ]
            self.groups.write_sites(group_id, payload)
        except Exception as exc:
            show_detailed_message(self, "Guardar IPs", "No se pudieron guardar los cambios.", f"{type(exc).__name__}: {exc}")
            return
        self._editing = False
        self.model.ip_editable = False
        self.edit_button.setText("Editar IPs")
        QMessageBox.information(self, "Hosts", "Cambios guardados en el grupo activo.")

    def _new_group(self) -> None:
        name, ok = QInputDialog.getText(self, "Nuevo grupo", "Nombre del grupo")
        if not ok or not name.strip():
            return
        try:
            group_id = self.groups.create(name.strip())
            self.groups.set_active(group_id)
            self._refresh_groups()
        except Exception as exc:
            show_detailed_message(self, "Nuevo grupo", "No se pudo crear el grupo.", f"{type(exc).__name__}: {exc}")

    def _duplicate_group(self) -> None:
        source = str(self.group_combo.currentData() or "")
        if not source:
            return
        name, ok = QInputDialog.getText(self, "Duplicar grupo", "Nombre del nuevo grupo")
        if not ok or not name.strip():
            return
        try:
            group_id = self.groups.duplicate(source, name.strip())
            self.groups.set_active(group_id)
            self._refresh_groups()
        except Exception as exc:
            show_detailed_message(self, "Duplicar grupo", "No se pudo duplicar el grupo.", f"{type(exc).__name__}: {exc}")

    def _import_csv(self) -> None:
        source, _ = QFileDialog.getOpenFileName(self, "Importar inventario", "", "CSV (*.csv)")
        if not source:
            return
        default_name = Path(source).stem
        name, ok = QInputDialog.getText(self, "Importar grupo", "Nombre", text=default_name)
        if not ok or not name.strip():
            return
        try:
            group_id = self.groups.import_csv(name.strip(), Path(source))
            self.groups.set_active(group_id)
            self._refresh_groups()
        except Exception as exc:
            show_detailed_message(self, "Importar CSV", "No se pudo importar el inventario CSV.", f"{type(exc).__name__}: {exc}")

    def _test_ping(self) -> None:
        """Lanza un test de conexión PING (ICMP) hacia todas las IP/host visibles."""
        addresses = [row.target.address.strip() for row in self.model.rows if row.target.address.strip()]
        if not addresses:
            QMessageBox.information(self, "Test de conexión", "No hay direcciones IP/host para probar.")
            return
        if self._ping_worker is not None and self._ping_worker.isRunning():
            return
        self.ping_button.setEnabled(False)
        self.ping_button.setText("Probando…")
        self.model.set_all_ping("Probando…")
        worker = PingWorker(addresses, self)
        worker.resultReady.connect(self._on_ping_result)
        worker.finishedAll.connect(self._on_ping_finished)
        worker.finished.connect(worker.deleteLater)
        self._ping_worker = worker
        worker.start()

    def _on_ping_result(self, address: str, reachable: bool, latency_ms: float | None) -> None:
        self.model.set_ping_result(address, reachable, latency_ms)

    def _on_ping_finished(self, reachable: int, total: int) -> None:
        self.ping_button.setEnabled(True)
        self.ping_button.setText("Probar PING")
        self._ping_worker = None
        QMessageBox.information(
            self,
            "Test de conexión (PING)",
            f"{reachable} de {total} destinos respondieron al PING.",
        )
