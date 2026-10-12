from __future__ import annotations

from gideon_common.observability import best_effort_warning

from pathlib import Path
from typing import Any

from PySide6.QtCore import QModelIndex, QSortFilterProxyModel, QThread, Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QTableView,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from gideon_application.script_registry import ScriptRegistry
from gideon_core.launch import AGENT, AGENTLESS, LaunchPlan, LaunchRequest
from gideon_domain import HostTarget
from gideon_host_profiles import HostProfileStore
from gideon_script_library import ScriptLibrary
from gideon_site_groups import SiteGroupStore

from ..models import HostRow, ScriptTableModel
from ..services import LocalEnvironmentService, QtLaunchManager
from ..tokens import COLORS, SPACE_8, SPACE_12, SPACE_16, SPACE_20
from ..widgets import PageHeader, StatusChip, show_detailed_message
from .base import ScrollPage
from ..components import DestinationSelectorWidget, GATEWAY_GROUP_ID











TRANSPORT_LABELS: dict[str, tuple[str, str, str]] = {
    "SFTP_SSH_SFTP": (
        "SFTP → SSH → SFTP",
        "Producción normal",
        "Distribuye por SFTP, controla por SSH y recolecta por SFTP.",
    ),
    "SCP_SSH_SCP": (
        "SCP → SSH → SCP",
        "Alternativa Agentless",
        "Paquete ZIP por SCP, control SSH y recolección ZIP por SCP.",
    ),
    "STDIN_SSH_SCP": (
        "STDIN/SSH → SSH → SCP",
        "Fallback",
        "Sube ZIP por STDIN del canal SSH y recolecta por SCP.",
    ),
    "AGENT_HTTPS_PULL": (
        "AGENTE · HTTPS/PULL",
        "Resiliencia máxima",
        "Cola durable HTTPS con Agent. Funciona por Internet o LAN; la VPN es opcional y no requiere SSH entrante.",
    ),
}


class TransportOption(QFrame):
    clicked: Signal = Signal(str)

    def __init__(self, profile: str, title: str, subtitle: str, description: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.profile = profile
        self._selected = False
        self.setObjectName("Card")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(SPACE_16, SPACE_16, SPACE_16, SPACE_16)
        layout.setSpacing(6)
        self.title = QLabel(title, self)
        self.title.setStyleSheet("font-weight:700; font-size:12pt;")
        layout.addWidget(self.title)
        sub = QLabel(subtitle, self)
        sub.setObjectName("Muted")
        layout.addWidget(sub)
        desc = QLabel(description, self)
        desc.setWordWrap(True)
        desc.setObjectName("Caption")
        layout.addWidget(desc)
        layout.addStretch(1)

    def mousePressEvent(self, event: object) -> None:  # noqa: N802
        del event
        self.clicked.emit(self.profile)

    def set_selected(self, selected: bool) -> None:
        self._selected = selected
        self.setProperty("selected", bool(selected))
        style = self.style()
        if style is not None:
            style.unpolish(self)
            style.polish(self)
        self.update()


class ExecutionPage(ScrollPage):
    jobLaunched: Signal = Signal(str)
    toastRequested: Signal = Signal(str, str, str)

    def __init__(
        self,
        *,
        groups: SiteGroupStore,
        library: ScriptLibrary,
        registry: ScriptRegistry,
        profiles: HostProfileStore,
        environment: LocalEnvironmentService,
        launcher: QtLaunchManager,
        config: dict[str, Any],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.groups = groups
        self.library = library
        self.registry = registry
        self.profiles = profiles
        self.environment = environment
        self.launcher = launcher
        self.config = config
        self.script_model = ScriptTableModel()
        self.script_proxy = QSortFilterProxyModel(self)
        self.script_proxy.setSourceModel(self.script_model)
        self.script_proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.script_proxy.setFilterKeyColumn(-1)
        self.transport_profile = "SFTP_SSH_SFTP"
        self._plan: LaunchPlan | None = None
        self._step = 0

        header = PageHeader(
            "Nueva ejecución",
            "Flujo guiado: destinos, trabajo, transporte y revisión antes de lanzar el Job.",
            self.content,
        )
        self.content_layout.addWidget(header)

        step_bar = QFrame(self.content)
        step_bar.setObjectName("Card")
        step_layout = QHBoxLayout(step_bar)
        step_layout.setContentsMargins(SPACE_12, SPACE_8, SPACE_12, SPACE_8)
        step_layout.setSpacing(4)
        self.step_buttons: list[QPushButton] = []
        for index, label in enumerate(("1  Destinos", "2  Trabajo", "3  Transporte", "4  Revisar")):
            button = QPushButton(label, step_bar)
            button.setCheckable(True)
            button.setObjectName("GhostButton")
            button.clicked.connect(lambda _checked=False, i=index: self._goto_step(i))
            step_layout.addWidget(button, 1)
            self.step_buttons.append(button)
        self.content_layout.addWidget(step_bar)

        self.stack = QStackedWidget(self.content)
        self.stack.addWidget(self._build_hosts_step())
        self.stack.addWidget(self._build_scripts_step())
        self.stack.addWidget(self._build_transport_step())
        self.stack.addWidget(self._build_review_step())
        self.content_layout.addWidget(self.stack, 1)

        nav = QHBoxLayout()
        nav.addStretch(1)
        self.back_button = QPushButton("← Atrás", self.content)
        self.back_button.clicked.connect(self._back)
        nav.addWidget(self.back_button)
        self.next_button = QPushButton("Siguiente →", self.content)
        self.next_button.setObjectName("PrimaryButton")
        self.next_button.clicked.connect(self._next)
        nav.addWidget(self.next_button)
        self.run_button = QPushButton("▶ Ejecutar Job", self.content)
        self.run_button.setObjectName("PrimaryButton")
        self.run_button.clicked.connect(self._launch)
        self.run_button.hide()
        nav.addWidget(self.run_button)
        self.content_layout.addLayout(nav)

        self.reload()
        self._goto_step(0)

    def _build_hosts_step(self) -> QWidget:
        page = QWidget(self.stack)
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, SPACE_8, 0, 0)
        layout.setSpacing(SPACE_12)
        title = QLabel("Seleccionar destinos", page)
        title.setObjectName("SectionTitle")
        layout.addWidget(title)

        self.destination_selector = DestinationSelectorWidget(
            groups=self.groups,
            profiles=self.profiles,
            config=self.config,
            group_context="Nueva ejecución",
            min_table_height=420,
            parent=page,
        )
        self.destination_selector.toastRequested.connect(self.toastRequested)
        self.destination_selector.selectionChanged.connect(self._auto_recommend_transport)
        self.destination_selector.gatewayAgentsLoaded.connect(
            lambda _count: self._select_transport("AGENT_HTTPS_PULL")
        )
        layout.addWidget(self.destination_selector, 1)

        self.host_model = self.destination_selector.host_model
        self.host_proxy = self.destination_selector.host_proxy
        self.host_table = self.destination_selector.host_table
        return page

    def _build_scripts_step(self) -> QWidget:
        page = QWidget(self.stack)
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, SPACE_8, 0, 0)
        layout.setSpacing(SPACE_12)
        title = QLabel("Seleccionar trabajo", page)
        title.setObjectName("SectionTitle")
        layout.addWidget(title)
        row = QHBoxLayout()
        self.script_search = QLineEdit(page)
        self.script_search.setPlaceholderText("Buscar script…")
        self.script_search.setClearButtonEnabled(True)
        self.script_search.textChanged.connect(self.script_proxy.setFilterFixedString)
        row.addWidget(self.script_search, 1)
        refresh = QPushButton("Actualizar biblioteca", page)
        refresh.clicked.connect(self._load_scripts)
        row.addWidget(refresh)
        layout.addLayout(row)
        self.script_table = QTableView(page)
        self.script_table.setModel(self.script_proxy)
        self.script_table.setAlternatingRowColors(True)
        self.script_table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.script_table.verticalHeader().setVisible(False)
        self.script_table.setMinimumHeight(420)
        self.script_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.script_table, 1)
        return page

    def _build_transport_step(self) -> QWidget:
        page = QWidget(self.stack)
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, SPACE_8, 0, 0)
        layout.setSpacing(SPACE_16)
        title = QLabel("Método de transporte", page)
        title.setObjectName("SectionTitle")
        layout.addWidget(title)
        hint = QLabel(
            "El perfil queda persistido dentro del Job y se conserva en resume, retry, cancel y collect.",
            page,
        )
        hint.setObjectName("Muted")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        grid = QGridLayout()
        grid.setHorizontalSpacing(SPACE_12)
        grid.setVerticalSpacing(SPACE_12)
        self.transport_cards: dict[str, TransportOption] = {}
        for index, (profile, values) in enumerate(TRANSPORT_LABELS.items()):
            card = TransportOption(profile, *values, page)
            card.clicked.connect(self._manual_select_transport)
            grid.addWidget(card, index // 2, index % 2)
            self.transport_cards[profile] = card
        layout.addLayout(grid)

        options = QFrame(page)
        options.setObjectName("SoftCard")
        options_layout = QGridLayout(options)
        options_layout.setContentsMargins(SPACE_16, SPACE_12, SPACE_16, SPACE_12)
        self.export_combo = QComboBox(options)
        self.export_combo.addItems(("xlsx", "csv", "json", "txt", "none"))
        self.continue_check = QCheckBox("Continuar con otros scripts/sedes ante error", options)
        self.continue_check.setChecked(True)
        self.auto_transport_check = QCheckBox("Elegir automáticamente el mejor transporte según los destinos", options)
        self.auto_transport_check.setChecked(True)
        self.auto_transport_check.stateChanged.connect(self._auto_recommend_transport)
        self.profile_combo = QComboBox(options)
        self.profile_combo.addItem("AUTO")
        try:
            for profile_id, _profile in self.profiles.list_profiles():
                profile_id = str(profile_id)
                if profile_id:
                    self.profile_combo.addItem(profile_id)
        except Exception as exc:
            best_effort_warning("No se pudieron cargar Host Profiles en Nueva ejecución", exc)
        options_layout.addWidget(QLabel("Reporte final", options), 0, 0)
        options_layout.addWidget(self.export_combo, 0, 1)
        options_layout.addWidget(QLabel("Host template", options), 1, 0)
        options_layout.addWidget(self.profile_combo, 1, 1)
        options_layout.addWidget(self.continue_check, 2, 0, 1, 2)
        options_layout.addWidget(self.auto_transport_check, 3, 0, 1, 2)
        layout.addWidget(options)
        self._select_transport("SFTP_SSH_SFTP")
        layout.addStretch(1)
        return page

    def _build_review_step(self) -> QWidget:
        page = QWidget(self.stack)
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, SPACE_8, 0, 0)
        layout.setSpacing(SPACE_12)
        title = QLabel("Revisión y preflight", page)
        title.setObjectName("SectionTitle")
        layout.addWidget(title)
        self.review_status = StatusChip("Pendiente", "neutral", page)
        layout.addWidget(self.review_status, 0, Qt.AlignmentFlag.AlignLeft)
        self.review_text = QTextEdit(page)
        self.review_text.setReadOnly(True)
        self.review_text.setMinimumHeight(420)
        layout.addWidget(self.review_text, 1)
        return page

    def reload(self) -> None:
        self.destination_selector.reload()
        self._load_scripts()

















    def _load_scripts(self) -> None:
        rows: list[dict[str, Any]] = []
        for row in self.library.all():
            item = dict(row)
            try:
                manifest = self.registry.load(Path(str(row.get("path"))))
                item.update(
                    version=manifest.version,
                    risk=manifest.risk.value,
                    timeout_seconds=manifest.timeout_seconds,
                )
            except Exception:
                item.update(version="1.0.0", risk="LOW", timeout_seconds=1800)
            rows.append(item)
        self.script_model.set_rows(rows)
        if not self.script_model.selected_ids:
            for row in rows:
                if str(row.get("filename") or "").lower() == "find_backup_folders.ps1":
                    self.script_model.selected_ids.add(str(row.get("id") or ""))
                    break
            self.script_model.layoutChanged.emit()
        self.script_table.resizeColumnsToContents()

    @staticmethod
    def _row_has_agent(row: HostRow) -> bool:
        return DestinationSelectorWidget.row_has_agent(row)

    def _auto_recommend_transport(self, *_args: object) -> None:
        check = getattr(self, "auto_transport_check", None)
        if check is not None and not check.isChecked():
            return
        selected = self.host_model.selected_rows()
        profile = "AGENT_HTTPS_PULL" if selected and all(self._row_has_agent(row) for row in selected) else "SFTP_SSH_SFTP"
        self._select_transport(profile)

    def _manual_select_transport(self, profile: str) -> None:
        check = getattr(self, "auto_transport_check", None)
        if check is not None and check.isChecked():
            check.blockSignals(True)
            check.setChecked(False)
            check.blockSignals(False)
        self._select_transport(profile)

    def _select_transport(self, profile: str) -> None:
        self.transport_profile = profile
        for key, card in self.transport_cards.items():
            card.set_selected(key == profile)

    def _goto_step(self, index: int) -> None:
        if index < 0 or index > 3:
            return
        if index == 3 and not self._prepare_review():
            return
        self._step = index
        self.stack.setCurrentIndex(index)
        for i, button in enumerate(self.step_buttons):
            button.setChecked(i == index)
        self.back_button.setEnabled(index > 0)
        self.next_button.setVisible(index < 3)
        self.run_button.setVisible(index == 3)

    def _back(self) -> None:
        self._goto_step(max(0, self._step - 1))

    def _next(self) -> None:
        if self._step == 0 and not self.host_model.selected_targets():
            QMessageBox.warning(self, "Destinos", "Seleccione al menos un host.")
            return
        if self._step == 1 and not self.script_model.selected_rows():
            QMessageBox.warning(self, "Trabajo", "Seleccione al menos un script.")
            return
        self._goto_step(min(3, self._step + 1))

    def _build_request(self) -> LaunchRequest:
        selected_rows = self.host_model.selected_rows()
        method = AGENT if self.transport_profile == "AGENT_HTTPS_PULL" else AGENTLESS
        sites = tuple(
            row.target if method == AGENT else row.target_for_agentless()
            for row in selected_rows
        )
        scripts = tuple(Path(str(row.get("path"))) for row in self.script_model.selected_rows())
        group_id = str(self.destination_selector.group_combo.currentData() or self.destination_selector.current_group_id or self.groups.active_group_id)
        if group_id == GATEWAY_GROUP_ID:
            group_name = "Agentes del Gateway · en vivo"
            sites_file = self.destination_selector.current_inventory_path
        else:
            try:
                group_name = str(self.groups.get(group_id).get("name") or group_id)
                sites_file = self.groups.inventory_path(group_id)
            except Exception:
                group_name = self.destination_selector.current_group_name or group_id
                sites_file = self.destination_selector.current_inventory_path
        return LaunchRequest(
            job_id=self.launcher.new_job_id(),
            method=method,
            sites_file=sites_file,
            sites=sites,
            scripts=scripts,
            export_format=str(self.export_combo.currentText()),
            continue_on_error=self.continue_check.isChecked(),
            host_profile=(None if self.profile_combo.currentText() == "AUTO" else self.profile_combo.currentText()),
            transport_profile=("SFTP_SSH_SFTP" if method == AGENT else self.transport_profile),
            group_id=group_id,
            group_name=group_name,
        )

    def _prepare_review(self) -> bool:
        if not self.host_model.selected_targets() or not self.script_model.selected_rows():
            QMessageBox.warning(self, "Preflight", "Seleccione hosts y scripts antes de revisar.")
            return False
        request = self._build_request()
        try:
            plan = self.launcher.build_plan(request)
        except Exception as exc:
            show_detailed_message(self, "Preflight", "No se pudo construir el plan de ejecución.", f"{type(exc).__name__}: {exc}")
            return False
        self._plan = plan
        clients = self.environment.transport_clients()
        extra_errors: list[str] = []
        if request.method == AGENTLESS:
            needed = {
                "SFTP_SSH_SFTP": ("ssh", "sftp"),
                "SCP_SSH_SCP": ("ssh", "scp"),
                "STDIN_SSH_SCP": ("ssh", "scp"),
            }.get(self.transport_profile, ("ssh",))
            missing = [name for name in needed if not clients.get(name, False)]
            if missing:
                extra_errors.append("Faltan clientes OpenSSH: " + ", ".join(missing))
            if not self.environment.key_available():
                extra_errors.append("La identidad SSH GIDEON configurada no está disponible o no es válida.")
        for error in extra_errors:
            plan.preflight.errors.append(error)

        hosts = self.host_model.selected_targets()
        scripts = self.script_model.selected_rows()
        lines = [
            f"JOB\n  {request.job_id}",
            f"\nDESTINOS\n  {len(hosts)} host(s) · {request.group_name or '-'}",
            "\nSCRIPTS",
        ]
        for row in scripts:
            lines.append(
                f"  • {row.get('name')} · v{row.get('version')} · riesgo {row.get('risk')}"
            )
        lines += [
            "\nMÉTODO",
            f"  {TRANSPORT_LABELS[self.transport_profile][0]}",
            f"  Reporte: {request.export_format.upper()}",
            f"  Continue on error: {'Sí' if request.continue_on_error else 'No'}",
            "\nPRE-FLIGHT",
        ]
        for check in plan.preflight.checks:
            marker = "✓" if check.get("Ok") else "⚠" if check.get("Warning") else "✕"
            lines.append(f"  {marker} {check.get('Name')}: {check.get('Detail')}")
        for error in extra_errors:
            lines.append(f"  ✕ {error}")
        self.review_text.setPlainText("\n".join(lines))
        if plan.preflight.ok:
            self.review_status.setText("✓ Listo para ejecutar")
            self.review_status.set_kind("success")
            self.run_button.setEnabled(True)
        else:
            self.review_status.setText("✕ Requiere corrección")
            self.review_status.set_kind("danger")
            self.run_button.setEnabled(False)
        return True

    def _launch(self) -> None:
        if self._plan is None or not self._plan.preflight.ok:
            return
        critical = [
            row
            for row in self.script_model.selected_rows()
            if str(row.get("risk") or "LOW").upper() in {"HIGH", "CRITICAL"}
        ]
        if critical:
            detail = "\n".join(
                f"• {row.get('name')} · {row.get('risk')}" for row in critical
            )
            if QMessageBox.warning(
                self,
                "Confirmación de riesgo",
                "El Job contiene scripts HIGH/CRITICAL:\n\n"
                + detail
                + "\n\n¿Desea continuar?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            ) != QMessageBox.StandardButton.Yes:
                return
        self.run_button.setEnabled(False)
        try:
            job_id = self.launcher.launch(self._plan)
        except Exception as exc:
            self.run_button.setEnabled(True)
            show_detailed_message(self, "No se pudo iniciar", "El Job no pudo iniciarse.", f"{type(exc).__name__}: {exc}")
            self.toastRequested.emit("Job no iniciado", str(exc), "danger")
            return
        self.toastRequested.emit(
            "Job iniciado",
            f"{job_id} · {len(self.host_model.selected_targets())} destino(s)",
            "success",
        )
        self._plan = None
        self.jobLaunched.emit(job_id)
