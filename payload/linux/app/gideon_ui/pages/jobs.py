from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from PySide6.QtCore import QSortFilterProxyModel, QThread, Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTableView,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from gideon_support_bundle import SupportBundleExporter
from gideon_domain.enums import JobState

from ..models import JobTableModel
from ..services import AppPaths, BackgroundCommandRunner, ManifestRepository
from ..tokens import COLORS, SPACE_8, SPACE_12, SPACE_16
from ..widgets import CommandBar, MetricCard, PageHeader, StatusChip, show_detailed_message
from .base import ScrollPage


ACTIVE_STATES: set[str] = {
    JobState.STARTING.value,
    JobState.DISPATCHING.value,
    JobState.WAITING_REMOTE_REPORTS.value,
    JobState.MONITORING.value,
    JobState.RUNNING.value,
    JobState.COLLECTING.value,
    JobState.WAITING_CONNECTIVITY.value,
    JobState.WAITING_CONNECTION.value,
    JobState.CANCEL_REQUESTED.value,
    JobState.CANCELLING.value,
}


class ActionRequiredDialog(QDialog):
    """Decision explícita para Jobs que terminaron con sedes reintentables."""

    ACTION_ACCEPT = "retry-failed"
    ACTION_SKIP = "ignore-failed"

    def __init__(self, manifest: dict[str, Any], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.manifest = manifest
        self.selected_action: str | None = None
        job_id = str(manifest.get("JobId") or "-")
        self.setWindowTitle(f"GIDEON · Acción requerida · {job_id}")
        self.setModal(True)
        self.resize(860, 560)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(SPACE_16, SPACE_16, SPACE_16, SPACE_16)
        layout.setSpacing(SPACE_12)

        head = QHBoxLayout()
        title = QLabel("Acción requerida", self)
        title.setObjectName("PageTitle")
        head.addWidget(title)
        head.addStretch(1)
        head.addWidget(StatusChip("ACTION_REQUIRED", "warning", self))
        layout.addLayout(head)

        description = QLabel(
            f"El Job {job_id} terminó su ciclo actual, pero tiene sedes que pueden reintentarse. "
            "Seleccione qué debe hacer Gideon Rx.",
            self,
        )
        description.setWordWrap(True)
        description.setObjectName("Muted")
        layout.addWidget(description)

        action_required = str(manifest.get("ActionRequired") or "RETRY_OR_IGNORE_SITES")
        reason = QLabel(f"Acción solicitada por backend: {action_required}", self)
        reason.setStyleSheet("font-weight:600;")
        layout.addWidget(reason)

        self.table = QTableWidget(0, 5, self)
        self.table.setHorizontalHeaderLabels(("Código", "Sede", "Estado", "Telemetría", "Detalle"))
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table, 1)

        sites = manifest.get("Sites") if isinstance(manifest.get("Sites"), dict) else {}
        for code, entry in sites.items():
            if not isinstance(entry, dict):
                continue
            dispatch = str(entry.get("DispatchStatus") or "").upper()
            retry_eligible = bool(entry.get("RetryEligible"))
            if dispatch not in {"FAILED", "DEFERRED"} and not retry_eligible:
                continue
            row = self.table.rowCount()
            self.table.insertRow(row)
            values = (
                str(code),
                str(entry.get("SiteName") or ""),
                dispatch or str(entry.get("RemoteState") or "-"),
                str(entry.get("TelemetryState") or "-"),
                str(
                    entry.get("ExecutionErrorDetail")
                    or entry.get("DispatchError")
                    or entry.get("LastPollError")
                    or entry.get("Error")
                    or "Reintento disponible"
                ),
            )
            for col, value in enumerate(values):
                self.table.setItem(row, col, QTableWidgetItem(value))
        self.table.resizeColumnsToContents()

        choices = QLabel(
            "Aceptar: reintenta únicamente las sedes fallidas/diferidas.   "
            "Omitir: marca esas sedes como omitidas y finaliza el Job.   "
            "Cancelar: cierra esta ventana y mantiene ACTION_REQUIRED sin cambios.",
            self,
        )
        choices.setWordWrap(True)
        choices.setObjectName("Muted")
        layout.addWidget(choices)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        cancel = QPushButton("Cancelar", self)
        cancel.setObjectName("GhostButton")
        cancel.clicked.connect(self.reject)
        buttons.addWidget(cancel)
        skip = QPushButton("Omitir", self)
        skip.clicked.connect(self._skip)
        buttons.addWidget(skip)
        accept = QPushButton("Aceptar", self)
        accept.setObjectName("PrimaryButton")
        accept.clicked.connect(self._accept)
        buttons.addWidget(accept)
        layout.addLayout(buttons)

    def _accept(self) -> None:
        self.selected_action = self.ACTION_ACCEPT
        self.accept()

    def _skip(self) -> None:
        self.selected_action = self.ACTION_SKIP
        self.accept()


class SupportBundleWorker(QThread):
    completed: Signal = Signal(str)
    failed: Signal = Signal(str)

    def __init__(
        self,
        exporter: SupportBundleExporter,
        job_id: str,
        target: Path,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.exporter = exporter
        self.job_id = job_id
        self.target = target

    def run(self) -> None:
        try:
            path = self.exporter.export(self.job_id, self.target)
            self.completed.emit(str(path))
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class JobFilterProxy(QSortFilterProxyModel):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.search_text: str = ""
        self.status_filter: str = "TODOS"
        self.incidents_only: bool = False
        self.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)

    def filterAcceptsRow(self, source_row: int, source_parent: object) -> bool:  # noqa: N802
        model = self.sourceModel()
        if not isinstance(model, JobTableModel):
            return True
        manifest = model.manifest_at(source_row)
        if manifest is None:
            return False
        status = str(manifest.get("Status") or "UNKNOWN").upper()
        if self.status_filter != "TODOS" and status != self.status_filter:
            return False
        if self.incidents_only:
            errors = int(manifest.get("FailedCount") or manifest.get("DispatchFailed") or 0)
            if status not in {"FAILED", "LAUNCH_FAILED", "PARTIAL", "INTERRUPTED", "ACTION_REQUIRED"} and errors <= 0:
                return False
        if self.search_text:
            haystack = " ".join(
                (
                    str(manifest.get("JobId") or ""),
                    status,
                    str(manifest.get("TransportProfile") or ""),
                    str(manifest.get("SiteGroupName") or ""),
                )
            ).lower()
            return self.search_text.lower() in haystack
        return True


class ActivityDialog(QDialog):
    def __init__(self, manifests: ManifestRepository, job_id: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.manifests = manifests
        self.job_id = job_id
        self.setWindowTitle(f"GIDEON · Actividad · {job_id}")
        self.resize(1050, 680)
        layout = QVBoxLayout(self)
        header = QHBoxLayout()
        title = QLabel(f"Actividad del Job · {job_id}", self)
        title.setObjectName("SectionTitle")
        header.addWidget(title)
        header.addStretch(1)
        self.state_chip = StatusChip("-", "neutral", self)
        header.addWidget(self.state_chip)
        layout.addLayout(header)
        tabs = QTabWidget(self)
        self.log_text = QPlainTextEdit(tabs)
        self.log_text.setReadOnly(True)
        self.diag_text = QPlainTextEdit(tabs)
        self.diag_text.setReadOnly(True)
        tabs.addTab(self.log_text, "Registro")
        tabs.addTab(self.diag_text, "Diagnóstico")
        layout.addWidget(tabs, 1)
        self.timer = QTimer(self)
        self.timer.setInterval(2000)
        self.timer.timeout.connect(self.refresh)
        self.timer.start()
        self.refresh()

    def refresh(self) -> None:
        manifest = self.manifests.get(self.job_id)
        if not manifest:
            self.state_chip.setText("Sin manifest")
            self.state_chip.set_kind("danger")
            return
        status = str(manifest.get("Status") or "UNKNOWN")
        self.state_chip.setText(status)
        self.state_chip.set_kind(
            "danger" if status.upper() in {"FAILED", "LAUNCH_FAILED", "INTERRUPTED"}
            else "warning" if status.upper() in {"PARTIAL", "WAITING_CONNECTION"}
            else "success" if status.upper() in {"COMPLETED", "COMPLETED_WITH_WARNINGS"}
            else "info"
        )
        backend = Path(str(manifest.get("BackendLog") or ""))
        if backend.exists():
            try:
                lines = backend.read_text(encoding="utf-8", errors="replace").splitlines()
                self.log_text.setPlainText("\n".join(lines[-500:]))
                self.log_text.verticalScrollBar().setValue(self.log_text.verticalScrollBar().maximum())
            except Exception as exc:
                self.log_text.setPlainText(str(exc))
        sites = manifest.get("Sites") if isinstance(manifest.get("Sites"), dict) else {}
        incident_lines: list[str] = [
            f"Job: {self.job_id}",
            f"Estado: {status}",
            f"Dispatch: {manifest.get('DispatchAttempted') or 0}/{manifest.get('TotalCount') or 0}",
            f"Recolectados: {manifest.get('CollectedCount') or 0}",
            f"Errores: {manifest.get('FailedCount') or manifest.get('DispatchFailed') or 0}",
            "",
            "SEDES QUE REQUIEREN ATENCIÓN",
            "=" * 64,
        ]
        for code, entry in sites.items():
            if not isinstance(entry, dict):
                continue
            error = entry.get("ExecutionErrorDetail") or entry.get("LastPollError") or entry.get("Error") or entry.get("DispatchError")
            telemetry = str(entry.get("TelemetryState") or "")
            if error or telemetry in {"DEGRADED", "WAITING_CONNECTION"}:
                incident_lines.append(
                    f"{code}_{entry.get('SiteName') or ''}: "
                    f"{entry.get('ExecutionLayer') or '-'} / {entry.get('ExecutionErrorCode') or '-'}\n"
                    f"  {error or telemetry}"
                )
        if len(incident_lines) == 8:
            incident_lines.append("Sin incidencias registradas en el manifest local.")
        self.diag_text.setPlainText("\n".join(incident_lines))


class SiteDetailsDialog(QDialog):
    def __init__(self, manifests: ManifestRepository, job_id: str, site_code: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.manifests = manifests
        self.job_id = job_id
        # `site_code` is retained as the public parameter name for compatibility,
        # but for Agent manifests it is the manifest target key (AgentId).
        self.site_code = site_code
        self.setWindowTitle(f"GIDEON · Detalle técnico · {site_code}")
        self.resize(1180, 760)
        layout = QVBoxLayout(self)
        header = QHBoxLayout()
        self.title = QLabel(f"Detalle técnico · {site_code}", self)
        self.title.setObjectName("PageTitle")
        header.addWidget(self.title)
        header.addStretch(1)
        self.state_chip = StatusChip("PENDING", "neutral", self)
        header.addWidget(self.state_chip)
        layout.addLayout(header)

        tabs = QTabWidget(self)
        timeline = QWidget(tabs)
        self.timeline_layout = QVBoxLayout(timeline)
        self.timeline_layout.setContentsMargins(SPACE_16, SPACE_16, SPACE_16, SPACE_16)
        self.timeline_layout.setSpacing(6)
        tabs.addTab(timeline, "Flujo técnico")
        self.metrics_text = QPlainTextEdit(tabs)
        self.metrics_text.setReadOnly(True)
        tabs.addTab(self.metrics_text, "Métricas / diagnóstico")
        self.results_text = QPlainTextEdit(tabs)
        self.results_text.setReadOnly(True)
        tabs.addTab(self.results_text, "Resultados")
        layout.addWidget(tabs, 1)

        self.timer = QTimer(self)
        self.timer.setInterval(1800)
        self.timer.timeout.connect(self.refresh)
        self.timer.start()
        self.refresh()

    @staticmethod
    def _stage(title: str, detail: str, state: str, parent: QWidget) -> QFrame:
        frame = QFrame(parent)
        frame.setObjectName("SoftCard")
        row = QHBoxLayout(frame)
        row.setContentsMargins(SPACE_12, SPACE_8, SPACE_12, SPACE_8)
        icon = QLabel("●", frame)
        color = (
            COLORS.success if state == "OK"
            else COLORS.info if state == "RUNNING"
            else COLORS.warning if state == "WAITING"
            else COLORS.danger if state == "ERROR"
            else COLORS.neutral_90
        )
        icon.setStyleSheet(f"color:{color}; font-size:14pt;")
        row.addWidget(icon)
        texts = QVBoxLayout()
        label = QLabel(title, frame)
        label.setStyleSheet("font-weight:600;")
        detail_label = QLabel(detail or "-", frame)
        detail_label.setObjectName("Muted")
        detail_label.setWordWrap(True)
        texts.addWidget(label)
        texts.addWidget(detail_label)
        row.addLayout(texts, 1)
        row.addWidget(StatusChip(state, "success" if state == "OK" else "danger" if state == "ERROR" else "warning" if state == "WAITING" else "info" if state == "RUNNING" else "neutral", frame))
        return frame

    def refresh(self) -> None:
        manifest = self.manifests.get(self.job_id)
        sites = manifest.get("Sites") if isinstance(manifest.get("Sites"), dict) else {}
        entry = sites.get(self.site_code) if isinstance(sites, dict) else None
        if not isinstance(entry, dict):
            return
        method = str(
            entry.get("TransportMethod")
            or manifest.get("ExecutionMethod")
            or manifest.get("TransportProfile")
            or ""
        ).upper()
        is_agent = method == "AGENT_HTTPS_PULL"
        route = (
            str(entry.get("AgentConnection") or "HTTPS/PULL → Gateway")
            if is_agent
            else str(entry.get("ServerIP") or "")
        )
        display_code = str(entry.get("SiteCode") or self.site_code)
        equipment = str(entry.get("AgentName") or entry.get("Hostname") or entry.get("AgentId") or "").strip()
        equipment_suffix = f" · {equipment}" if equipment else ""
        self.title.setText(
            f"{display_code}_{entry.get('SiteName') or ''}{equipment_suffix} · {route or '—'}"
        )
        remote = str(entry.get("RemoteState") or entry.get("DispatchStatus") or "PENDING").upper()
        self.state_chip.setText(remote)
        self.state_chip.set_kind(
            "danger" if remote in {"FAILED", "INTERRUPTED", "RESULT_READY_WITH_ERRORS"}
            else "success" if remote in {"COLLECTED", "COMPLETED"}
            else "info" if remote in {"RUNNING", "DISPATCHED", "RESULT_READY"}
            else "neutral"
        )
        while self.timeline_layout.count():
            item = self.timeline_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

        transfer = str(entry.get("TransferStatus") or "PENDING")
        start = str(entry.get("StartStatus") or "PENDING")
        telemetry = str(entry.get("TelemetryState") or "PENDING")
        task = str(entry.get("TaskState") or "-")
        task_source = str(entry.get("TaskStateSource") or "DISPATCH_SNAPSHOT")
        script_index = int(entry.get("CurrentScriptIndex") or 0)
        script_count = int(entry.get("ScriptCount") or manifest.get("ScriptCount") or 0)
        script_name = str(entry.get("CurrentScriptName") or "-")
        collect = str(entry.get("CollectionStatus") or "PENDING")
        cleanup = str(entry.get("CleanupState") or "PENDING")
        pkg_ok = bool(entry.get("PackageVerified"))
        res_ok = bool(entry.get("CollectionVerified"))

        stages = [
            ("1 · HTTPS QUEUE" if is_agent else "1 · PACKAGE", transfer, "OK" if "UPLOADED" in transfer else "ERROR" if transfer == "FAILED" else "PENDING"),
            ("2 · SHA256 PACKAGE", "Paquete remoto verificado" if pkg_ok else "Pendiente", "OK" if pkg_ok else "PENDING"),
            ("3 · AGENT PULL" if is_agent else "3 · SSH START", start, "OK" if "STARTED" in start else "ERROR" if start == "FAILED" else "PENDING"),
            ("4 · HEARTBEAT / TELEMETRÍA" if is_agent else "4 · TELEMETRÍA", f"{telemetry} · {entry.get('TelemetrySource') or 'NONE'}", "OK" if telemetry == "ONLINE" else "WAITING" if telemetry in {"DEGRADED", "WAITING_CONNECTION"} else "PENDING"),
            ("5 · WORKER / TASK", f"{task} · {task_source}", "OK" if remote not in {"PENDING", "DISPATCHED"} else "WAITING" if "STARTED" in start else "PENDING"),
            ("6 · SCRIPT REMOTO", f"{script_index}/{script_count} {script_name}", "RUNNING" if remote == "RUNNING" else "OK" if remote in {"RESULT_READY", "COLLECTED", "COMPLETED"} else "ERROR" if remote in {"FAILED", "RESULT_READY_WITH_ERRORS"} else "WAITING" if remote == "DISPATCHED" else "PENDING"),
            ("7 · RESULT READY", remote, "OK" if remote in {"RESULT_READY", "COLLECTED", "COMPLETED"} else "ERROR" if remote in {"FAILED", "RESULT_READY_WITH_ERRORS"} else "PENDING"),
            ("8 · COLLECT", collect, "OK" if "COLLECTED" in collect else "RUNNING" if collect == "COLLECTING" else "PENDING"),
            ("9 · INTEGRIDAD FINAL", "SHA256 resultados" if res_ok else "Pendiente", "OK" if res_ok else "PENDING"),
            ("10 · LIBERACIÓN DE PROCESOS", f"{cleanup} · residual {entry.get('ResidualProcessesKilled') or 0} · handles {entry.get('ProcessObjectsDisposed') or 0}", "OK" if cleanup == "COMPLETE" else "ERROR" if cleanup == "COMPLETE_WITH_ERROR" else "RUNNING" if remote in {"RUNNING", "RESULT_READY"} else "PENDING"),
        ]
        for title, detail, state in stages:
            self.timeline_layout.addWidget(self._stage(title, detail, state, self))
        self.timeline_layout.addStretch(1)

        diag = [
            f"ExecutionLayer: {entry.get('ExecutionLayer') or '-'}",
            f"ExecutionErrorCode: {entry.get('ExecutionErrorCode') or '-'}",
            f"ExecutionErrorDetail: {entry.get('ExecutionErrorDetail') or '-'}",
            f"PollFailureCount: {entry.get('PollFailureCount') or 0}",
            f"LastPollError: {entry.get('LastPollError') or '-'}",
            f"LastCheckedAt: {entry.get('LastCheckedAt') or '-'}",
            f"JobObjectAssignments: {entry.get('JobObjectAssignments') or 0}",
            f"JobObjectFallbacks: {entry.get('JobObjectFallbacks') or 0}",
            f"ResidualProcessesKilled: {entry.get('ResidualProcessesKilled') or 0}",
            f"ProcessObjectsDisposed: {entry.get('ProcessObjectsDisposed') or 0}",
        ]
        self.metrics_text.setPlainText("\n".join(diag))
        progress = entry.get("Progress") if isinstance(entry.get("Progress"), dict) else {}
        self.results_text.setPlainText(
            "\n".join(f"{key}: {value}" for key, value in progress.items())
            if progress else "Sin datos de resultado/progreso todavía."
        )


class JobDetailsDialog(QDialog):
    """Detalle completo e independiente de un Job; no reemplaza la preview lateral."""

    def __init__(self, manifests: ManifestRepository, job_id: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.manifests = manifests
        self.job_id = job_id
        self.setWindowTitle(f"GIDEON · Detalle completo del Job · {job_id}")
        self.resize(1280, 820)

        layout = QVBoxLayout(self)
        header = QHBoxLayout()
        self.title = QLabel(f"Detalle completo · {job_id}", self)
        self.title.setObjectName("PageTitle")
        header.addWidget(self.title)
        header.addStretch(1)
        self.state_chip = StatusChip("-", "neutral", self)
        header.addWidget(self.state_chip)
        layout.addLayout(header)

        tabs = QTabWidget(self)

        overview = QWidget(tabs)
        overview_layout = QVBoxLayout(overview)
        metrics = QGridLayout()
        self.m_hosts = MetricCard("Hosts", "0", COLORS.brand_blue, overview)
        self.m_dispatch = MetricCard("Dispatch", "0", COLORS.purple, overview)
        self.m_reports = MetricCard("Reportes", "0", COLORS.success, overview)
        self.m_errors = MetricCard("Errores", "0", COLORS.brand_red, overview)
        self.m_skipped = MetricCard("Omitidos", "0", COLORS.warning, overview)
        self.m_progress = MetricCard("Progreso", "0 %", COLORS.info, overview)
        for i, card in enumerate((self.m_hosts, self.m_dispatch, self.m_reports, self.m_errors, self.m_skipped, self.m_progress)):
            metrics.addWidget(card, i // 3, i % 3)
        overview_layout.addLayout(metrics)

        info = QTableWidget(0, 2, overview)
        info.setHorizontalHeaderLabels(("Propiedad", "Valor"))
        info.verticalHeader().setVisible(False)
        info.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        info.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        info.horizontalHeader().setStretchLastSection(True)
        self.info_table = info
        overview_layout.addWidget(info, 1)
        tabs.addTab(overview, "Resumen completo")

        sites_page = QWidget(tabs)
        sites_layout = QVBoxLayout(sites_page)
        self.sites_table = QTableWidget(0, 10, sites_page)
        self.sites_table.setHorizontalHeaderLabels((
            "Código", "Sede", "Equipo / Agent", "Estado", "Telemetría", "Script", "Capa", "Error", "Última actualización", "Resultado",
        ))
        self.sites_table.verticalHeader().setVisible(False)
        self.sites_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.sites_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.sites_table.horizontalHeader().setStretchLastSection(True)
        sites_layout.addWidget(self.sites_table)
        tabs.addTab(sites_page, "Todas las sedes")

        incidents_page = QWidget(tabs)
        incidents_layout = QVBoxLayout(incidents_page)
        self.incidents_text = QPlainTextEdit(incidents_page)
        self.incidents_text.setReadOnly(True)
        incidents_layout.addWidget(self.incidents_text)
        tabs.addTab(incidents_page, "Incidencias / diagnóstico")

        raw_page = QWidget(tabs)
        raw_layout = QVBoxLayout(raw_page)
        self.raw_text = QPlainTextEdit(raw_page)
        self.raw_text.setReadOnly(True)
        raw_layout.addWidget(self.raw_text)
        tabs.addTab(raw_page, "Manifest JSON")
        layout.addWidget(tabs, 1)

        close = QPushButton("Cerrar", self)
        close.clicked.connect(self.close)
        layout.addWidget(close, 0, Qt.AlignmentFlag.AlignRight)

        self.timer = QTimer(self)
        self.timer.setInterval(2000)
        self.timer.timeout.connect(self.refresh)
        self.timer.start()
        self.refresh()

    @staticmethod
    def _fmt(value: Any) -> str:
        if value is None or value == "":
            return "-"
        if isinstance(value, (dict, list)):
            return json.dumps(value, ensure_ascii=False, indent=2)
        return str(value)

    def refresh(self) -> None:
        manifest = self.manifests.get(self.job_id)
        if not isinstance(manifest, dict):
            self.state_chip.setText("Manifest no disponible")
            self.state_chip.set_kind("danger")
            return

        status = str(manifest.get("Status") or "UNKNOWN").upper()
        self.state_chip.setText(status)
        self.state_chip.set_kind(
            "danger" if status in {"FAILED", "LAUNCH_FAILED", "INTERRUPTED"}
            else "warning" if status in {"PARTIAL", "WAITING_CONNECTION", "CANCEL_REQUESTED"}
            else "success" if status in {"COMPLETED", "COMPLETED_WITH_WARNINGS", "COMPLETED_WITH_SKIPPED"}
            else "info",
        )

        total = int(manifest.get("TotalCount") or 0)
        dispatch_attempted = int(manifest.get("DispatchAttempted") or 0)
        dispatch_ok = int(manifest.get("DispatchOk") or 0)
        reports = int(manifest.get("CollectedCount") or 0) + int(manifest.get("CollectedWithErrorsCount") or 0)
        errors = int(manifest.get("FailedCount") or manifest.get("DispatchFailed") or 0)
        sites = manifest.get("Sites") if isinstance(manifest.get("Sites"), dict) else {}
        skipped = sum(1 for e in sites.values() if isinstance(e, dict) and str(e.get("RemoteState") or e.get("DispatchStatus") or "").upper() in {"SKIPPED", "OMITTED", "IGNORED"})
        progress = round((reports / total) * 100) if total and reports else round((dispatch_attempted / total) * 100) if total else 0
        self.m_hosts.set_value(total)
        self.m_dispatch.set_value(f"{dispatch_ok}/{total}")
        self.m_reports.set_value(f"{reports}/{total}")
        self.m_errors.set_value(errors)
        self.m_skipped.set_value(skipped)
        self.m_progress.set_value(f"{progress} %")

        preferred = (
            "JobId", "Status", "CreatedAt", "UpdatedAt", "FinishedAt", "StartedAt", "TotalCount",
            "DispatchAttempted", "DispatchOk", "DispatchFailed", "CollectedCount", "CollectedWithErrorsCount",
            "FailedCount", "SkippedCount", "ScriptCount", "TransportProfile", "ExecutionMethod",
            "SiteGroupName", "HostProfile", "RunMode", "Gateway", "BackendLog", "ManifestPath",
        )
        self.info_table.setRowCount(0)
        seen: set[str] = set()
        for key in preferred + tuple(str(k) for k in manifest.keys()):
            if key in seen or key not in manifest:
                continue
            seen.add(key)
            row = self.info_table.rowCount()
            self.info_table.insertRow(row)
            self.info_table.setItem(row, 0, QTableWidgetItem(key))
            self.info_table.setItem(row, 1, QTableWidgetItem(self._fmt(manifest.get(key))))
        self.info_table.resizeColumnsToContents()

        self.sites_table.setRowCount(0)
        incident_lines: list[str] = [f"JOB: {self.job_id}", f"ESTADO: {status}", ""]
        for code, entry in sites.items():
            if not isinstance(entry, dict):
                continue
            remote = str(entry.get("RemoteState") or entry.get("DispatchStatus") or "PENDING")
            telemetry = str(entry.get("TelemetryState") or "PENDING")
            script_index = int(entry.get("CurrentScriptIndex") or 0)
            script_count = int(entry.get("ScriptCount") or manifest.get("ScriptCount") or 0)
            script_name = str(entry.get("CurrentScriptName") or "-")
            error = str(entry.get("ExecutionErrorDetail") or entry.get("LastPollError") or entry.get("Error") or entry.get("DispatchError") or "-")
            layer = str(entry.get("ExecutionLayer") or "-")
            updated = str(entry.get("UpdatedAt") or entry.get("LastUpdate") or entry.get("LastHeartbeat") or "-")
            result = str(entry.get("Result") or entry.get("ResultSummary") or entry.get("RemoteResult") or "-")
            row = self.sites_table.rowCount()
            self.sites_table.insertRow(row)
            equipment = str(entry.get("AgentName") or entry.get("Hostname") or entry.get("AgentId") or "-")
            values = (str(entry.get("SiteCode") or code), str(entry.get("SiteName") or ""), equipment, remote, telemetry, f"{script_index}/{script_count} {script_name}", layer, error, updated, result)
            for col, value in enumerate(values):
                self.sites_table.setItem(row, col, QTableWidgetItem(value))
            if error != "-" or telemetry in {"DEGRADED", "WAITING_CONNECTION"}:
                incident_lines.append(f"{entry.get('SiteCode') or code} · {entry.get('SiteName') or '-'} · {entry.get('AgentName') or entry.get('Hostname') or entry.get('AgentId') or '-'}")
                incident_lines.append(f"  Estado: {remote} · Telemetría: {telemetry}")
                incident_lines.append(f"  Error: {error}")
                incident_lines.append("")
        self.sites_table.resizeColumnsToContents()
        if len(incident_lines) == 3:
            incident_lines.append("Sin incidencias registradas.")
        self.incidents_text.setPlainText("\n".join(incident_lines))
        self.raw_text.setPlainText(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True))


class JobsPage(ScrollPage):
    toastRequested: Signal = Signal(str, str, str)

    def __init__(
        self,
        *,
        manifests: ManifestRepository,
        paths: AppPaths,
        command_runner: BackgroundCommandRunner,
        support_exporter: SupportBundleExporter,
        auto_refresh: bool = True,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.manifests = manifests
        self.paths = paths
        self.command_runner = command_runner
        self.support_exporter = support_exporter
        self.model = JobTableModel()
        self.proxy = JobFilterProxy(self)
        self.proxy.setSourceModel(self.model)
        self._current_job_id: str | None = None
        self._activity_dialog: ActivityDialog | None = None
        self._job_details_dialog: JobDetailsDialog | None = None
        self._site_dialogs: list[SiteDetailsDialog] = []
        self._support_worker: SupportBundleWorker | None = None

        header = PageHeader(
            "Ejecuciones",
            "Centro de control local: seguimiento en caliente, incidencias, resultados y acciones del Job.",
            self.content,
        )
        self.content_layout.addWidget(header)

        command = CommandBar(self.content)
        command.add_action("Actualizar", self.refresh, primary=True)
        command.add_action("Reanudar", self._resume)
        command.add_action("Reintentar fallidas", self._retry_failed)
        command.add_action("Omitir faltantes", self._ignore_failed)
        command.add_action("Detalle completo", self._open_job_details)
        command.add_action("Actividad", self._open_activity)
        command.add_action("Resultados", self._open_results)
        command.add_action("Support ZIP", self._export_support)
        command.add_stretch()
        command.add_action("Cancelar", self._cancel, danger=True)
        command.add_action("Borrar historial", self._delete_history)
        self.content_layout.addWidget(command)

        filter_row = QHBoxLayout()
        filter_row.setSpacing(SPACE_12)
        self.search = QLineEdit(self.content)
        self.search.setPlaceholderText("Buscar Job, grupo, transporte o estado…")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self._filters_changed)
        filter_row.addWidget(self.search, 1)
        self.status_combo = QComboBox(self.content)
        self.status_combo.addItems(
            (
                "TODOS",
                "STARTING",
                "DISPATCHING",
                "MONITORING",
                "WAITING_REMOTE_REPORTS",
                "COLLECTING",
                "ACTION_REQUIRED",
                "COMPLETED",
                "COMPLETED_WITH_WARNINGS",
                "PARTIAL",
                "FAILED",
                "CANCELLED",
            )
        )
        self.status_combo.currentTextChanged.connect(self._filters_changed)
        filter_row.addWidget(self.status_combo)
        self.incidents_check = QCheckBox("Solo incidencias", self.content)
        self.incidents_check.toggled.connect(self._filters_changed)
        filter_row.addWidget(self.incidents_check)
        self.content_layout.addLayout(filter_row)

        splitter = QSplitter(Qt.Orientation.Horizontal, self.content)
        self.table = QTableView(splitter)
        self.table.setModel(self.proxy)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.clicked.connect(self._job_selected)
        self.table.doubleClicked.connect(self._job_double_clicked)
        splitter.addWidget(self.table)

        detail = QFrame(splitter)
        detail.setObjectName("Card")
        detail_layout = QVBoxLayout(detail)
        detail_layout.setContentsMargins(SPACE_16, SPACE_16, SPACE_16, SPACE_16)
        detail_layout.setSpacing(SPACE_12)
        self.job_title = QLabel("Seleccione un Job", detail)
        self.job_title.setObjectName("SectionTitle")
        detail_layout.addWidget(self.job_title)
        self.job_chip = StatusChip("Sin selección", "neutral", detail)
        detail_layout.addWidget(self.job_chip, 0, Qt.AlignmentFlag.AlignLeft)
        metrics = QGridLayout()
        self.metric_hosts = MetricCard("Hosts", "0", COLORS.brand_blue, detail)
        self.metric_dispatch = MetricCard("Dispatch", "0", COLORS.purple, detail)
        self.metric_reports = MetricCard("Reportes", "0", COLORS.success, detail)
        self.metric_errors = MetricCard("Errores", "0", COLORS.brand_red, detail)
        metrics.addWidget(self.metric_hosts, 0, 0)
        metrics.addWidget(self.metric_dispatch, 0, 1)
        metrics.addWidget(self.metric_reports, 1, 0)
        metrics.addWidget(self.metric_errors, 1, 1)
        detail_layout.addLayout(metrics)
        site_title = QLabel("Sedes", detail)
        site_title.setStyleSheet("font-weight:600;")
        detail_layout.addWidget(site_title)
        self.sites_table = QTableWidget(0, 7, detail)
        self.sites_table.setHorizontalHeaderLabels(("Código", "Sede", "Equipo / Agent", "Estado", "Telemetría", "Script", "Error"))
        self.sites_table.verticalHeader().setVisible(False)
        self.sites_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.sites_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.sites_table.cellDoubleClicked.connect(self._site_double_clicked)
        self.sites_table.horizontalHeader().setStretchLastSection(True)
        detail_layout.addWidget(self.sites_table, 1)
        splitter.addWidget(detail)
        splitter.setSizes([700, 650])
        self.content_layout.addWidget(splitter, 1)

        self.command_runner.commandFinished.connect(self._command_finished)
        self.command_runner.commandFailed.connect(self._command_failed)

        self.timer = QTimer(self)
        self.timer.setInterval(2000)
        self.timer.timeout.connect(self.refresh)
        if auto_refresh:
            self.timer.start()
        self.refresh()

    def _filters_changed(self, *_args: object) -> None:
        self.proxy.search_text = self.search.text().strip()
        self.proxy.status_filter = self.status_combo.currentText()
        self.proxy.incidents_only = self.incidents_check.isChecked()
        self.proxy.invalidateFilter()

    def refresh(self) -> None:
        current = self._current_job_id
        self.model.set_rows(self.manifests.list(limit=250))
        self.proxy.invalidateFilter()
        self.table.resizeColumnsToContents()
        if current:
            self.select_job(current)

    def select_job(self, job_id: str) -> None:
        self._current_job_id = job_id
        for source_row, manifest in enumerate(self.model.rows):
            if str(manifest.get("JobId") or "") != job_id:
                continue
            source_index = self.model.index(source_row, 0)
            proxy_index = self.proxy.mapFromSource(source_index)
            if proxy_index.isValid():
                self.table.selectRow(proxy_index.row())
                self.table.scrollTo(proxy_index)
            self._render_manifest(manifest)
            return
        manifest = self.manifests.get(job_id)
        if manifest:
            self._render_manifest(manifest)

    def _job_selected(self, clicked_index: object) -> None:
        indexes = self.table.selectionModel().selectedRows()
        if not indexes:
            return
        source = self.proxy.mapToSource(indexes[0])
        manifest = self.model.manifest_at(source.row())
        if manifest is None:
            return
        self._current_job_id = str(manifest.get("JobId") or "")
        self._render_manifest(manifest)

        # ACTION_REQUIRED es una decisión operativa, no un error estático.
        # Abrimos la ventana únicamente cuando el usuario hace clic en la
        # celda Estado, evitando ventanas espontáneas durante los refresh.
        try:
            clicked_column = int(clicked_index.column())  # type: ignore[attr-defined]
        except Exception:
            clicked_column = -1
        if clicked_column == 1 and str(manifest.get("Status") or "").upper() == "ACTION_REQUIRED":
            self._open_action_required(manifest)

    def _open_action_required(self, manifest: dict[str, Any]) -> None:
        job_id = str(manifest.get("JobId") or "")
        if not job_id:
            return
        dialog = ActionRequiredDialog(manifest, self)
        if dialog.exec() != QDialog.DialogCode.Accepted or not dialog.selected_action:
            self.toastRequested.emit("Acción pendiente", f"{job_id} permanece en ACTION_REQUIRED", "warning")
            return
        self._current_job_id = job_id
        if dialog.selected_action == ActionRequiredDialog.ACTION_SKIP:
            if QMessageBox.question(
                self,
                "Omitir sedes pendientes",
                f"¿Confirmar la omisión de las sedes reintentables de {job_id}?\n\n"
                "Las sedes ya completadas no se modificarán.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            ) != QMessageBox.StandardButton.Yes:
                return
        self._action(dialog.selected_action)

    def _job_double_clicked(self, _index: object) -> None:
        indexes = self.table.selectionModel().selectedRows()
        if not indexes:
            return
        source = self.proxy.mapToSource(indexes[0])
        manifest = self.model.manifest_at(source.row())
        if not manifest:
            return
        job_id = str(manifest.get("JobId") or "")
        if not job_id:
            return
        self._current_job_id = job_id
        self._render_manifest(manifest)
        self._job_details_dialog = JobDetailsDialog(self.manifests, job_id, self)
        self._job_details_dialog.show()
        self._job_details_dialog.raise_()
        self._job_details_dialog.activateWindow()

    def _render_manifest(self, manifest: dict[str, Any]) -> None:
        job_id = str(manifest.get("JobId") or "-")
        status = str(manifest.get("Status") or "UNKNOWN").upper()
        self.job_title.setText(job_id)
        self.job_chip.setText(status)
        self.job_chip.set_kind(
            "danger" if status in {"FAILED", "LAUNCH_FAILED", "INTERRUPTED"}
            else "warning" if status in {"PARTIAL", "WAITING_CONNECTION", "ACTION_REQUIRED"}
            else "success" if status in {"COMPLETED", "COMPLETED_WITH_WARNINGS"}
            else "info"
        )
        total = int(manifest.get("TotalCount") or 0)
        dispatch = int(manifest.get("DispatchOk") or 0)
        reports = int(manifest.get("CollectedCount") or 0) + int(manifest.get("CollectedWithErrorsCount") or 0)
        errors = int(manifest.get("FailedCount") or manifest.get("DispatchFailed") or 0)
        self.metric_hosts.set_value(total)
        self.metric_dispatch.set_value(f"{dispatch}/{total}")
        self.metric_reports.set_value(f"{reports}/{total}")
        self.metric_errors.set_value(errors)

        sites = manifest.get("Sites") if isinstance(manifest.get("Sites"), dict) else {}
        self.sites_table.setRowCount(0)
        for code, entry in sites.items():
            if not isinstance(entry, dict):
                continue
            row = self.sites_table.rowCount()
            self.sites_table.insertRow(row)
            remote = str(entry.get("RemoteState") or entry.get("DispatchStatus") or "PENDING")
            telemetry = str(entry.get("TelemetryState") or "PENDING")
            script_index = int(entry.get("CurrentScriptIndex") or 0)
            script_count = int(entry.get("ScriptCount") or manifest.get("ScriptCount") or 0)
            script_name = str(entry.get("CurrentScriptName") or "-")
            error = str(entry.get("ExecutionErrorCode") or entry.get("Error") or entry.get("DispatchError") or "-")
            values = (
                str(entry.get("SiteCode") or code),
                str(entry.get("SiteName") or ""),
                str(entry.get("AgentName") or entry.get("Hostname") or entry.get("AgentId") or "-"),
                remote,
                telemetry,
                f"{script_index}/{script_count} {script_name}",
                error,
            )
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, str(code))
                self.sites_table.setItem(row, col, item)
        self.sites_table.resizeColumnsToContents()

    def _site_double_clicked(self, row: int, _column: int) -> None:
        if not self._current_job_id:
            return
        item = self.sites_table.item(row, 0)
        if item is None:
            return
        target_key = str(item.data(Qt.ItemDataRole.UserRole) or item.text())
        dialog = SiteDetailsDialog(self.manifests, self._current_job_id, target_key, self)
        dialog.show()
        self._site_dialogs.append(dialog)
        dialog.finished.connect(lambda _result, d=dialog: self._site_dialogs.remove(d) if d in self._site_dialogs else None)

    def _action(self, action: str) -> None:
        if not self._current_job_id:
            return
        key = f"{action}:{self._current_job_id}"
        log = self.paths.logs / f"qt-{action}-{self._current_job_id}.log"
        self.command_runner.start(key, ["fanout", action, self._current_job_id], log)
        self.toastRequested.emit("Acción iniciada", f"{action} · {self._current_job_id}", "info")

    def _resume(self) -> None:
        self._action("resume")

    def _retry_failed(self) -> None:
        self._action("retry-failed")

    def _ignore_failed(self) -> None:
        if not self._current_job_id:
            return
        manifest = self.manifests.get(self._current_job_id) or {}
        sites = manifest.get("Sites") if isinstance(manifest.get("Sites"), dict) else {}
        retryable = 0
        for entry in sites.values():
            if not isinstance(entry, dict):
                continue
            state = str(entry.get("RemoteState") or entry.get("DispatchStatus") or "").upper()
            telemetry = str(entry.get("TelemetryState") or "").upper()
            if state in {"FAILED", "ERROR", "PENDING_RETRY", "WAITING_CONNECTION", "DEFERRED"} or telemetry in {"DEGRADED", "WAITING_CONNECTION"}:
                retryable += 1
        if retryable <= 0:
            QMessageBox.information(self, "Omitir faltantes", "No hay sedes fallidas o diferidas que puedan omitirse en este Job.")
            return
        if QMessageBox.question(
            self,
            "Omitir faltantes",
            f"¿Omitir {retryable} sede(s) fallida(s)/diferida(s) de {self._current_job_id}?\n\nLas sedes ya completadas no se modificarán. El Job podrá finalizar como COMPLETED_WITH_SKIPPED.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        self._action("ignore-failed")

    def _open_job_details(self) -> None:
        if not self._current_job_id:
            return
        self._job_details_dialog = JobDetailsDialog(self.manifests, self._current_job_id, self)
        self._job_details_dialog.show()
        self._job_details_dialog.raise_()
        self._job_details_dialog.activateWindow()

    def _cancel(self) -> None:
        if not self._current_job_id:
            return
        if QMessageBox.warning(
            self,
            "Cancelar Job",
            f"¿Cancelar {self._current_job_id}?\n\nSe detendrán únicamente tareas/procesos asociados a este Job.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        self._action("cancel")

    def _open_activity(self) -> None:
        if not self._current_job_id:
            return
        self._activity_dialog = ActivityDialog(self.manifests, self._current_job_id, self)
        self._activity_dialog.show()

    def _open_results(self) -> None:
        if not self._current_job_id:
            return
        candidates = [
            self.paths.results / self._current_job_id,
            self.paths.raw / self._current_job_id,
            self.paths.results,
        ]
        target = next((path for path in candidates if path.exists()), self.paths.results)
        if os.name == "nt":
            os.startfile(str(target))  # type: ignore[attr-defined]
        else:
            import subprocess
            subprocess.Popen(["xdg-open", str(target)])

    def _export_support(self) -> None:
        if not self._current_job_id:
            return
        default = str(Path.home() / "Desktop" / f"GIDEON-Support-{self._current_job_id}.zip")
        target, _ = QFileDialog.getSaveFileName(self, "Exportar Support Bundle", default, "ZIP (*.zip)")
        if not target:
            return
        if self._support_worker is not None and self._support_worker.isRunning():
            self.toastRequested.emit("Support Bundle", "Ya existe una exportación en curso.", "warning")
            return
        self._support_worker = SupportBundleWorker(
            self.support_exporter,
            self._current_job_id,
            Path(target),
            self,
        )
        self._support_worker.completed.connect(self._support_completed)
        self._support_worker.failed.connect(self._support_failed)
        self._support_worker.start()
        self.toastRequested.emit("Support Bundle", "Generando ZIP de diagnóstico…", "info")

    def _support_completed(self, path: str) -> None:
        self.toastRequested.emit("Support Bundle generado", path, "success")
        self._support_worker = None

    def _support_failed(self, detail: str) -> None:
        show_detailed_message(self, "Support Bundle", "No se pudo generar el paquete de soporte.", detail)
        self.toastRequested.emit("Support Bundle con error", detail, "danger")
        self._support_worker = None

    def _delete_history(self) -> None:
        if not self._current_job_id:
            return
        if QMessageBox.question(
            self,
            "Borrar historial",
            f"¿Eliminar el manifest local de {self._current_job_id}?\n\nLos resultados recolectados se conservarán.",
        ) != QMessageBox.StandardButton.Yes:
            return
        job_id = self._current_job_id
        current_manifest = self.manifests.get(job_id)
        if str(current_manifest.get("Status") or "").upper() in ACTIVE_STATES:
            QMessageBox.warning(
                self,
                "Job activo",
                "No se elimina el manifest de un Job activo. Cancélelo/finalícelo primero.",
            )
            return
        try:
            self.manifests.delete(job_id)
        except Exception as exc:
            show_detailed_message(self, "Borrar historial", "No se pudo eliminar el historial local del Job.", f"{type(exc).__name__}: {exc}")
            return
        self._current_job_id = None
        self.job_title.setText("Seleccione un Job")
        self.job_chip.setText("Sin selección")
        self.job_chip.set_kind("neutral")
        self.sites_table.setRowCount(0)
        self.refresh()
        self.toastRequested.emit("Historial eliminado", job_id, "success")

    def _command_finished(self, key: str, _rc: int) -> None:
        if ":" not in key:
            return
        self.toastRequested.emit("Acción completada", key, "success")
        self.refresh()

    def _command_failed(self, key: str, detail: str) -> None:
        self.toastRequested.emit("Acción con error", f"{key} · {detail}", "danger")
