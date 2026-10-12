from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from PySide6.QtCore import QThread, Qt, Signal
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from gideon_agent_catalog import AgentDownloadCatalog
from gideon_version import AGENT_VERSION
from gideon_gateway_bootstrap import ensure_gateway_configuration

from ..tokens import COLORS, SPACE_8, SPACE_12, SPACE_16
from ..widgets import CommandBar, EmptyState, MetricCard, PageHeader, StatusChip, show_detailed_message
from .base import ScrollPage


_SEMVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


def _bump_semver(version: str, part: str) -> str:
    """Incrementa MAJOR/MINOR/PATCH. Si el texto no es SemVer, lo deja intacto."""
    match = _SEMVER_RE.match(version.strip())
    if not match:
        return version
    major, minor, patch = (int(value) for value in match.groups())
    if part == "major":
        major, minor, patch = major + 1, 0, 0
    elif part == "minor":
        minor, patch = minor + 1, 0
    else:
        patch += 1
    return f"{major}.{minor}.{patch}"


def _short_sha(value: str) -> str:
    text = str(value or "")
    return text[:12] + "…" if len(text) > 12 else (text or "-")


class AgentBuildWorker(QThread):
    """Genera un bundle de agente en segundo plano para no bloquear la UI."""

    completed: Signal = Signal(str)
    failed: Signal = Signal(str)

    def __init__(
        self,
        *,
        catalog: AgentDownloadCatalog,
        target_id: str,
        version: str,
        channel: str,
        gateway_url: str,
        output_dir: Path,
        package_type: str = "native",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.catalog = catalog
        self.target_id = target_id
        self.version = version
        self.channel = channel
        self.gateway_url = gateway_url
        self.output_dir = output_dir
        self.package_type = package_type

    def run(self) -> None:
        try:
            capability = self.catalog.build_capability(self.target_id)
            if not bool(capability.get("ready")):
                raise RuntimeError(str(capability.get("detail") or "No hay un compilador disponible para esta plataforma."))
            # Windows usa un EXE SFX directo y valida únicamente su backend nativo:
            # solo se valida el backend nativo IExpress antes de compilar.
            target = next((row for row in self.catalog.rows() if row.get("target_id") == self.target_id), {})
            if self.package_type == "native" and target.get("platform") == "windows":
                capability = self.catalog.build_capability(self.target_id)
                if not bool(capability.get("ready")):
                    raise RuntimeError(str(capability.get("detail") or "No está disponible el generador EXE nativo de Windows."))

            effective_gateway = self.gateway_url.strip()
            if not effective_gateway:
                info = ensure_gateway_configuration()
                effective_gateway = str(info["public_url"]).rstrip("/")
                self.gateway_url = effective_gateway
            bundle = self.catalog.generate(
                self.target_id,
                version=self.version,
                channel=self.channel,
                gateway_url=effective_gateway,
                output_dir=self.output_dir,
                package_type=self.package_type,
            )
            self.completed.emit(str(bundle))
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class AgentsPage(ScrollPage):
    """Módulo Agentes: generación de paquetes multiplataforma y su actividad.

    La página delega toda persistencia/generación en ``AgentDownloadCatalog``
    (capa de datos) y toda ejecución larga en ``AgentBuildWorker`` (hilo
    aparte); esta clase se limita a construir la UI y reaccionar a eventos,
    respetando responsabilidad única entre las tres piezas.
    """

    toastRequested: Signal = Signal(str, str, str)

    def __init__(
        self,
        *,
        catalog: AgentDownloadCatalog,
        gateway_url: str,
        embedded: bool = False,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.catalog = catalog
        self.gateway_url = gateway_url
        self.embedded = bool(embedded)
        # La página puede vivir embebida dentro del Centro de Agentes o como
        # módulo independiente de compatibilidad.
        # y nunca existía en AgentsPage, por lo que el primer clic en
        # "Generar paquete" lanzaba AttributeError y el agente no se generaba.
        self._build_worker: AgentBuildWorker | None = None
        self._output_dir: Path | None = None
        self._catalog_rows: list[dict[str, Any]] = []

        if not self.embedded:
            header = PageHeader(
                "Agentes",
                "Catálogo multiplataforma opcional para Windows, Linux/AWS, Raspberry Pi y macOS.",
                self.content,
            )
            refresh_button = QPushButton("↻ Actualizar catálogo", header)
            refresh_button.setObjectName("GhostButton")
            refresh_button.clicked.connect(lambda: self.reload(force=True))
            header.add_action(refresh_button)
            self.content_layout.addWidget(header)
        else:
            embedded_actions = CommandBar(self.content)
            embedded_actions.add_action("↻ Actualizar catálogo", lambda: self.reload(force=True))
            embedded_actions.add_stretch()
            self.content_layout.addWidget(embedded_actions)

        # ---- KPIs: da visibilidad inmediata del estado del módulo -------
        metrics = QWidget(self.content)
        metrics_grid = QGridLayout(metrics)
        metrics_grid.setContentsMargins(0, 0, 0, 0)
        metrics_grid.setHorizontalSpacing(SPACE_12)
        metrics_grid.setVerticalSpacing(SPACE_12)
        self.targets_card = MetricCard("Targets disponibles", "0", COLORS.brand_blue)
        self.generated_card = MetricCard("Agentes generados", "0", COLORS.purple)
        self.coverage_card = MetricCard("Plataformas cubiertas", "0/0", COLORS.success)
        self.last_build_card = MetricCard("Último build", "Sin builds", COLORS.info)
        for column, card in enumerate(
            (self.targets_card, self.generated_card, self.coverage_card, self.last_build_card)
        ):
            metrics_grid.addWidget(card, 0, column)
        self.content_layout.addWidget(metrics)

        # ---- Card: Generar agente ---------------------------------------
        config = QFrame(self.content)
        config.setObjectName("Card")
        cfg_layout = QVBoxLayout(config)
        cfg_layout.setContentsMargins(SPACE_16, SPACE_16, SPACE_16, SPACE_16)
        cfg_layout.setSpacing(SPACE_12)

        cfg_title = QLabel("Generar agente", config)
        cfg_title.setObjectName("SectionTitle")
        cfg_layout.addWidget(cfg_title)

        form = QGridLayout()
        form.setHorizontalSpacing(SPACE_12)
        form.setVerticalSpacing(SPACE_8)
        form.setColumnStretch(1, 1)
        form.setColumnStretch(3, 1)

        form.addWidget(QLabel("Plataforma objetivo", config), 0, 0)
        self.target_combo = QComboBox(config)
        self.target_combo.currentIndexChanged.connect(self._target_combo_changed)
        form.addWidget(self.target_combo, 0, 1, 1, 3)

        form.addWidget(QLabel("Versión", config), 1, 0)
        version_row = QHBoxLayout()
        version_row.setSpacing(4)
        self.version_edit = QLineEdit(AGENT_VERSION, config)
        self.version_edit.setPlaceholderText("MAJOR.MINOR.PATCH")
        version_row.addWidget(self.version_edit, 1)
        for label, part in (("+MAJOR", "major"), ("+MINOR", "minor"), ("+PATCH", "patch")):
            bump_button = QPushButton(label, config)
            bump_button.setObjectName("GhostButton")
            bump_button.setToolTip(f"Incrementar {part.upper()} sobre la versión actual")
            bump_button.clicked.connect(lambda _checked=False, p=part: self._bump_version(p))
            version_row.addWidget(bump_button)
        form.addLayout(version_row, 1, 1)

        form.addWidget(QLabel("Canal", config), 1, 2)
        self.channel_edit = QComboBox(config)
        self.channel_edit.setEditable(True)
        self.channel_edit.addItems(["stable", "pilot", "beta"])
        form.addWidget(self.channel_edit, 1, 3)

        form.addWidget(QLabel("Http Gateway único", config), 2, 0)
        gateway_row = QHBoxLayout()
        gateway_row.setSpacing(SPACE_8)
        self.gateway_edit = QLineEdit(gateway_url, config)
        self.gateway_edit.setPlaceholderText("https://agent.example.com")
        self.gateway_edit.setToolTip("Valor único de Http Gateway que quedará incorporado en el agente generado.")
        gateway_row.addWidget(self.gateway_edit, 1)
        copy_gateway = QPushButton("Copiar", config)
        copy_gateway.setObjectName("GhostButton")
        copy_gateway.setToolTip("Copiar el Http Gateway al portapapeles")
        copy_gateway.clicked.connect(lambda: QApplication.clipboard().setText(self.gateway_edit.text().strip()))
        gateway_row.addWidget(copy_gateway)
        form.addLayout(gateway_row, 2, 1, 1, 3)

        cfg_layout.addLayout(form)

        output_row = QHBoxLayout()
        output_row.setSpacing(SPACE_8)
        output_button = QPushButton("Elegir carpeta de salida…", config)
        output_button.clicked.connect(self._choose_output_dir)
        output_row.addWidget(output_button)
        self.output_label = QLabel("Carpeta de salida: no seleccionada", config)
        self.output_label.setObjectName("Muted")
        self.output_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        output_row.addWidget(self.output_label, 1)
        cfg_layout.addLayout(output_row)

        action_row = QHBoxLayout()
        action_row.setSpacing(SPACE_8)
        self.generate_button = QPushButton("Generar paquete", config)
        self.generate_button.setObjectName("PrimaryButton")
        self.generate_button.clicked.connect(self._generate)
        action_row.addWidget(self.generate_button)
        self.build_status_chip = StatusChip("Listo", "neutral", config)
        action_row.addWidget(self.build_status_chip)
        action_row.addStretch(1)
        cfg_layout.addLayout(action_row)

        self.progress_bar = QProgressBar(config)
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setVisible(False)
        cfg_layout.addWidget(self.progress_bar)

        self.backend_note = QLabel("Compilador: validando…", config)
        self.backend_note.setObjectName("Muted")
        self.backend_note.setWordWrap(True)
        cfg_layout.addWidget(self.backend_note)

        note = QLabel(
            "Windows genera un instalador .EXE y abre un asistente crucial para confirmar Nombre del agente + Código + Sede. Linux/Raspberry y macOS incluyen gideon-agent-setup con la misma identificación de primer arranque. El Http Gateway visible arriba queda incorporado en la configuración.",
            config,
        )
        note.setObjectName("Muted")
        note.setWordWrap(True)
        cfg_layout.addWidget(note)
        self.content_layout.addWidget(config)

        # ---- Card: Catálogo de plataformas --------------------------------
        catalog_card = QFrame(self.content)
        catalog_card.setObjectName("Card")
        catalog_layout = QVBoxLayout(catalog_card)
        catalog_layout.setContentsMargins(SPACE_16, SPACE_16, SPACE_16, SPACE_16)
        catalog_layout.setSpacing(SPACE_12)
        catalog_title = QLabel("Catálogo de plataformas", catalog_card)
        catalog_title.setObjectName("SectionTitle")
        catalog_layout.addWidget(catalog_title)
        catalog_subtitle = QLabel(
            "Seleccione una fila para fijarla como plataforma objetivo arriba.", catalog_card
        )
        catalog_subtitle.setObjectName("Muted")
        catalog_layout.addWidget(catalog_subtitle)

        self.table = QTableWidget(0, 9, catalog_card)
        self.table.setHorizontalHeaderLabels(
            ("Target", "Plataforma", "Arquitectura", "Instalador", "Compilador", "Host profile", "Versión", "Canal", "Último instalador")
        )
        self._configure_table(self.table)
        self.table.setMinimumHeight(280)
        self.table.itemSelectionChanged.connect(self._table_selection_changed)
        catalog_layout.addWidget(self.table)
        self.content_layout.addWidget(catalog_card)

        # ---- Card: Actividad de generación (NUEVO) ------------------------
        activity_card = QFrame(self.content)
        activity_card.setObjectName("Card")
        activity_layout = QVBoxLayout(activity_card)
        activity_layout.setContentsMargins(SPACE_16, SPACE_16, SPACE_16, SPACE_16)
        activity_layout.setSpacing(SPACE_12)

        activity_head = QHBoxLayout()
        activity_texts = QVBoxLayout()
        activity_texts.setSpacing(2)
        activity_title = QLabel("Actividad de generación", activity_card)
        activity_title.setObjectName("SectionTitle")
        activity_subtitle = QLabel(
            "Historial local de paquetes de agente generados en este equipo, del más reciente al más antiguo.",
            activity_card,
        )
        activity_subtitle.setObjectName("Muted")
        activity_subtitle.setWordWrap(True)
        activity_texts.addWidget(activity_title)
        activity_texts.addWidget(activity_subtitle)
        activity_head.addLayout(activity_texts, 1)
        self.activity_filter = QComboBox(activity_card)
        self.activity_filter.addItem("Todas las plataformas", "")
        self.activity_filter.currentIndexChanged.connect(self._reload_activity)
        activity_head.addWidget(self.activity_filter)
        activity_layout.addLayout(activity_head)

        self.activity_stack = QStackedWidget(activity_card)
        self.activity_table = QTableWidget(0, 6, activity_card)
        self.activity_table.setHorizontalHeaderLabels(
            ("Fecha de generación", "Plataforma", "Arquitectura", "Versión", "Canal", "SHA-256 / Carpeta")
        )
        self._configure_table(self.activity_table)
        self.activity_table.setMinimumHeight(240)
        self.activity_empty = EmptyState(
            "Aún no se generó ningún agente",
            "Complete la configuración de arriba y presione \"Generar paquete\" para ver la actividad aquí.",
            activity_card,
        )
        self.activity_stack.addWidget(self.activity_table)
        self.activity_stack.addWidget(self.activity_empty)
        activity_layout.addWidget(self.activity_stack)
        self.content_layout.addWidget(activity_card)

        self.content_layout.addStretch(1)
        self.reload()

    # ------------------------------------------------------------------
    # Helpers de construcción
    # ------------------------------------------------------------------
    @staticmethod
    def _configure_table(table: QTableWidget) -> None:
        """Config común para que el contenido nunca quede oculto sin aviso."""
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setAlternatingRowColors(True)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        table.horizontalHeader().setStretchLastSection(True)
        # Texto largo (rutas, hashes) se elide con "…" en vez de recortarse
        # de forma abrupta, y cada celda expone su valor completo por tooltip.
        table.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        table.setWordWrap(False)

    # ------------------------------------------------------------------
    # Carga / refresco de datos
    # ------------------------------------------------------------------
    def reload(self, *, force: bool = False) -> None:
        if force and hasattr(self.catalog, "invalidate_capability_cache"):
            self.catalog.invalidate_capability_cache()
        self._catalog_rows = list(self.catalog.rows())
        self._reload_target_combo()
        self._reload_catalog_table()
        self._reload_activity_filter()
        self._reload_activity()
        self._reload_metrics()
        self._update_build_capability()

    def _reload_target_combo(self) -> None:
        self.target_combo.blockSignals(True)
        current = self.target_combo.currentData()
        self.target_combo.clear()
        for row in self._catalog_rows:
            label = str(row.get("label") or row.get("target_id") or "-")
            self.target_combo.addItem(label, str(row.get("target_id") or ""))
        if current:
            index = self.target_combo.findData(current)
            if index >= 0:
                self.target_combo.setCurrentIndex(index)
        self.target_combo.blockSignals(False)

    def _reload_catalog_table(self) -> None:
        self.table.setRowCount(0)
        for row_data in self._catalog_rows:
            row = self.table.rowCount()
            self.table.insertRow(row)
            target_id = str(row_data.get("target_id") or "")
            capability = self.catalog.build_capability(target_id)
            values = (
                str(row_data.get("label") or target_id or "-"),
                str(row_data.get("platform") or "-"),
                str(row_data.get("architecture") or "-"),
                str(row_data.get("package_type") or "nativo"),
                str(capability.get("backend") or "-"),
                str(row_data.get("profile") or "-"),
                str(row_data.get("available_version") or "-"),
                str(row_data.get("channel") or "-"),
                str(row_data.get("bundle") or "No generado"),
            )
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, target_id)
                item.setToolTip(value)
                self.table.setItem(row, col, item)
        self.table.resizeColumnsToContents()

    def _reload_activity_filter(self) -> None:
        self.activity_filter.blockSignals(True)
        current = self.activity_filter.currentData()
        self.activity_filter.clear()
        self.activity_filter.addItem("Todas las plataformas", "")
        for row in self._catalog_rows:
            label = str(row.get("label") or row.get("target_id") or "-")
            self.activity_filter.addItem(label, str(row.get("target_id") or ""))
        index = self.activity_filter.findData(current) if current else 0
        self.activity_filter.setCurrentIndex(index if index >= 0 else 0)
        self.activity_filter.blockSignals(False)

    def _reload_activity(self) -> None:
        target_filter = str(self.activity_filter.currentData() or "") or None
        entries = self.catalog.activity(target_id=target_filter, limit=200)
        self.activity_table.setRowCount(0)
        for entry in entries:
            row = self.activity_table.rowCount()
            self.activity_table.insertRow(row)
            sha256 = str(entry.get("sha256") or "")
            bundle = str(entry.get("bundle") or "")
            last_cell = f"{_short_sha(sha256)}  ·  {bundle or '-'}"
            values = (
                str(entry.get("built_at") or "-"),
                str(entry.get("label") or entry.get("target_id") or "-"),
                str(entry.get("architecture") or "-"),
                str(entry.get("version") or "-"),
                str(entry.get("channel") or "-"),
                last_cell,
            )
            tooltips = (
                str(entry.get("built_at") or "-"),
                str(entry.get("label") or entry.get("target_id") or "-"),
                str(entry.get("architecture") or "-"),
                str(entry.get("version") or "-"),
                str(entry.get("channel") or "-"),
                f"SHA-256: {sha256 or '-'}\nCarpeta: {bundle or '-'}",
            )
            for col, (value, tip) in enumerate(zip(values, tooltips)):
                item = QTableWidgetItem(value)
                item.setToolTip(tip)
                self.activity_table.setItem(row, col, item)
        self.activity_table.resizeColumnsToContents()
        self.activity_stack.setCurrentWidget(
            self.activity_table if entries else self.activity_empty
        )

    def _reload_metrics(self) -> None:
        all_activity = self.catalog.activity(limit=100000)
        total_targets = len(self._catalog_rows)
        covered = sum(1 for row in self._catalog_rows if row.get("bundle"))
        self.targets_card.set_value(str(total_targets))
        self.generated_card.set_value(str(len(all_activity)))
        self.coverage_card.set_value(f"{covered}/{total_targets}")
        if all_activity:
            latest = all_activity[0]
            when = str(latest.get("built_at") or "-")
            self.last_build_card.set_value(when.split("T")[0] if "T" in when else when)
        else:
            self.last_build_card.set_value("Sin builds")

    # ------------------------------------------------------------------
    # Selección de plataforma objetivo (tabla <-> combo sincronizados)
    # ------------------------------------------------------------------
    def _selected_target(self) -> str | None:
        target_id = str(self.target_combo.currentData() or "")
        return target_id or None

    def _table_selection_changed(self) -> None:
        row = self.table.currentRow()
        if row < 0:
            return
        item = self.table.item(row, 0)
        if item is None:
            return
        target_id = str(item.data(Qt.ItemDataRole.UserRole) or "")
        index = self.target_combo.findData(target_id)
        if index >= 0 and index != self.target_combo.currentIndex():
            self.target_combo.setCurrentIndex(index)

    def _target_combo_changed(self, _index: int) -> None:
        target_id = self._selected_target()
        if not target_id:
            return
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item is not None and str(item.data(Qt.ItemDataRole.UserRole) or "") == target_id:
                self.table.blockSignals(True)
                self.table.selectRow(row)
                self.table.blockSignals(False)
                break
        self._update_build_capability()

    def _update_build_capability(self) -> None:
        target_id = self._selected_target()
        if not target_id:
            self.generate_button.setEnabled(False)
            self.build_status_chip.setText("Sin target")
            self.build_status_chip.set_kind("neutral")
            self.backend_note.setText("Compilador: seleccione una plataforma objetivo.")
            return
        capability = self.catalog.build_capability(target_id)
        ready = bool(capability.get("ready"))
        backend = str(capability.get("backend") or "-")
        detail = str(capability.get("detail") or "")
        self.generate_button.setEnabled(ready)
        self.build_status_chip.setText("Listo" if ready else "No disponible")
        self.build_status_chip.set_kind("success" if ready else "warning")
        self.backend_note.setText(f"Compilador: {backend} · {detail}")
        self.backend_note.setToolTip(detail)

    # ------------------------------------------------------------------
    # Versión SemVer
    # ------------------------------------------------------------------
    def _bump_version(self, part: str) -> None:
        self.version_edit.setText(_bump_semver(self.version_edit.text().strip() or "0.0.0", part))

    # ------------------------------------------------------------------
    # Carpeta de salida
    # ------------------------------------------------------------------
    def _choose_output_dir(self) -> None:
        start_dir = str(self._output_dir) if self._output_dir else ""
        chosen = QFileDialog.getExistingDirectory(self, "Carpeta de salida", start_dir)
        if not chosen:
            return
        self._output_dir = Path(chosen)
        self.output_label.setText(f"Carpeta de salida: {chosen}")
        self.output_label.setToolTip(chosen)

    # ------------------------------------------------------------------
    # Generación
    # ------------------------------------------------------------------
    def _generate(self) -> None:
        target_id = self._selected_target()
        if not target_id:
            QMessageBox.information(self, "Agente", "Seleccione una plataforma objetivo.")
            return
        capability = self.catalog.build_capability(target_id)
        if not bool(capability.get("ready")):
            QMessageBox.information(
                self,
                "Compilador no disponible",
                str(capability.get("detail") or "No hay un compilador disponible para esta plataforma."),
            )
            self._update_build_capability()
            return

        version = self.version_edit.text().strip()
        if not _SEMVER_RE.match(version):
            QMessageBox.warning(
                self,
                "Versión inválida",
                "La versión debe seguir el formato SemVer MAJOR.MINOR.PATCH, por ejemplo 2.0.0.",
            )
            self.version_edit.setFocus()
            return

        if self._output_dir is None:
            self._choose_output_dir()
            if self._output_dir is None:
                return

        if self._build_worker is not None and self._build_worker.isRunning():
            QMessageBox.information(
                self, "Agente", "Ya hay una generación en curso. Espere a que finalice."
            )
            return

        channel = self.channel_edit.currentText().strip() or "stable"
        self._set_generating(True)
        self._build_worker = AgentBuildWorker(
            catalog=self.catalog,
            target_id=target_id,
            version=version,
            channel=channel,
            gateway_url=self.gateway_edit.text().strip(),
            output_dir=self._output_dir,
            parent=self,
        )
        self._build_worker.completed.connect(self._build_completed)
        self._build_worker.failed.connect(self._build_failed)
        self._build_worker.start()
        self.toastRequested.emit("Generando agente", target_id, "info")

    def _set_generating(self, running: bool) -> None:
        self.progress_bar.setVisible(running)
        if running:
            self.generate_button.setEnabled(False)
            self.build_status_chip.setText("Generando…")
            self.build_status_chip.set_kind("info")
        else:
            self._update_build_capability()

    def _build_completed(self, bundle: str) -> None:
        self._set_generating(False)
        self.reload()
        self.toastRequested.emit("Agente generado", bundle, "success")
        self._build_worker = None

    def _build_failed(self, detail: str) -> None:
        self._set_generating(False)
        self.build_status_chip.setText("Error")
        self.build_status_chip.set_kind("danger")
        show_detailed_message(self, "Generar agente", "No se pudo generar el paquete del agente.", detail)
        self.toastRequested.emit("Error generando agente", detail, "danger")
        self._build_worker = None
