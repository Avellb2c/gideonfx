from __future__ import annotations

from pathlib import Path
from typing import Any

from PySide6.QtCore import QSortFilterProxyModel, Qt, Signal
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from gideon_application.script_registry import ScriptRegistry
from gideon_script_library import ScriptLibrary

from ..models import ScriptTableModel
from ..tokens import SPACE_12, SPACE_16
from ..widgets import CommandBar, PageHeader, StatusChip
from .base import ScrollPage


class ScriptsPage(ScrollPage):
    libraryChanged: Signal = Signal()

    def __init__(
        self,
        *,
        library: ScriptLibrary,
        registry: ScriptRegistry,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.library = library
        self.registry = registry
        self.model = ScriptTableModel()
        self.proxy = QSortFilterProxyModel(self)
        self.proxy.setSourceModel(self.model)
        self.proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.proxy.setFilterKeyColumn(-1)

        header = PageHeader(
            "Biblioteca de scripts",
            "Scripts versionados, riesgo operativo y metadatos reutilizables para próximos Jobs.",
            self.content,
        )
        self.content_layout.addWidget(header)

        command = CommandBar(self.content)
        command.add_action("+ Agregar scripts", self._add, primary=True)
        self.remove_button = command.add_action("Quitar cargado", self._remove)
        command.add_action("Actualizar", self.reload)
        command.add_stretch()
        self.content_layout.addWidget(command)

        search_row = QHBoxLayout()
        search_row.setSpacing(SPACE_12)
        self.search = QLineEdit(self.content)
        self.search.setPlaceholderText("Buscar por nombre, riesgo, versión u origen…")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self.proxy.setFilterFixedString)
        search_row.addWidget(self.search, 1)
        self.count_label = QLabel("0 scripts", self.content)
        self.count_label.setObjectName("Muted")
        search_row.addWidget(self.count_label)
        self.content_layout.addLayout(search_row)

        splitter = QSplitter(Qt.Orientation.Horizontal, self.content)
        self.table = QTableView(splitter)
        self.table.setModel(self.proxy)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.clicked.connect(self._show_preview)
        self.table.horizontalHeader().setStretchLastSection(True)
        splitter.addWidget(self.table)

        preview = QWidget(splitter)
        preview_layout = QVBoxLayout(preview)
        preview_layout.setContentsMargins(SPACE_16, 0, 0, 0)
        preview_layout.setSpacing(SPACE_12)
        preview_title = QLabel("Detalle", preview)
        preview_title.setObjectName("SectionTitle")
        preview_layout.addWidget(preview_title)
        self.meta_label = QLabel("Seleccione un script.", preview)
        self.meta_label.setObjectName("Muted")
        self.meta_label.setWordWrap(True)
        preview_layout.addWidget(self.meta_label)
        self.risk_chip = StatusChip("LOW", "success", preview)
        preview_layout.addWidget(self.risk_chip, 0, Qt.AlignmentFlag.AlignLeft)
        self.preview_text = QPlainTextEdit(preview)
        self.preview_text.setReadOnly(True)
        self.preview_text.setPlaceholderText("Vista previa del script")
        preview_layout.addWidget(self.preview_text, 1)
        splitter.addWidget(preview)
        splitter.setSizes([760, 430])
        self.content_layout.addWidget(splitter, 1)
        self.reload()

    def _rows(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for row in self.library.all():
            enriched = dict(row)
            try:
                manifest = self.registry.load(Path(str(row.get("path"))))
                enriched.update(
                    {
                        "version": manifest.version,
                        "risk": manifest.risk.value,
                        "timeout_seconds": manifest.timeout_seconds,
                        "description": manifest.description,
                    }
                )
            except Exception:
                enriched.update(
                    {
                        "version": "1.0.0",
                        "risk": "LOW",
                        "timeout_seconds": 1800,
                        "description": "Sin manifest de ejecución.",
                    }
                )
            rows.append(enriched)
        return rows

    def reload(self) -> None:
        rows = self._rows()
        self.model.set_rows(rows)
        self.count_label.setText(f"{len(rows)} scripts")
        self.table.resizeColumnsToContents()
        self.libraryChanged.emit()

    def rows(self) -> list[dict[str, Any]]:
        return list(self.model.rows)

    def _selected_source_row(self) -> dict[str, Any] | None:
        indexes = self.table.selectionModel().selectedRows()
        if not indexes:
            return None
        source_index = self.proxy.mapToSource(indexes[0])
        if not source_index.isValid():
            return None
        row = source_index.row()
        return self.model.rows[row] if 0 <= row < len(self.model.rows) else None

    def _show_preview(self, *_args: object) -> None:
        row = self._selected_source_row()
        if row is None:
            return
        risk = str(row.get("risk") or "LOW").upper()
        kind = "danger" if risk in {"HIGH", "CRITICAL"} else "warning" if risk == "MEDIUM" else "success"
        self.risk_chip.setText(risk)
        self.risk_chip.set_kind(kind)
        self.meta_label.setText(
            f"{row.get('name')} · v{row.get('version')} · {row.get('source')}\n"
            f"Timeout: {row.get('timeout_seconds')} s · {row.get('description') or ''}"
        )
        path = Path(str(row.get("path") or ""))
        try:
            lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
            self.preview_text.setPlainText("\n".join(lines[:220]))
        except Exception as exc:
            self.preview_text.setPlainText(f"No se pudo leer {path}: {exc}")

    def _add(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(
            self,
            "Agregar scripts",
            "",
            "Scripts (*.ps1 *.py *.sh *.command *.cmd *.bat);;Todos (*.*)",
        )
        if not files:
            return
        added = self.library.add_files(files)
        self.reload()
        QMessageBox.information(self, "Biblioteca", f"{len(added)} script(s) disponibles.")

    def _remove(self) -> None:
        row = self._selected_source_row()
        if row is None:
            return
        if bool(row.get("builtin")):
            QMessageBox.information(self, "Biblioteca", "Los scripts precargados no se eliminan.")
            return
        if QMessageBox.question(
            self,
            "Quitar script",
            f"¿Quitar {row.get('name')} de la biblioteca local?",
        ) != QMessageBox.StandardButton.Yes:
            return
        self.library.remove(str(row.get("id") or ""))
        self.reload()
        self.preview_text.clear()
        self.meta_label.setText("Seleccione un script.")
