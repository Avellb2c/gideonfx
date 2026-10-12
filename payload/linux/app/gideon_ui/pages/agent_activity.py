from __future__ import annotations

from gideon_common.observability import best_effort_warning

import datetime as dt
import json
import os
from pathlib import Path
from typing import Any

from PySide6.QtCore import QThread, Signal, Qt, QTimer
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from gideon_agent_http import AgentHttpClient
from gideon_agent_runtime import merged_agent_control_plane
from gideon_dependency_manager import SystemDependencyManager
from gideon_local_agent import inspect_local_agent
from gideon_gateway_service import GatewayCoordinator, GatewayResult
from gideon_gateway_bootstrap import (
    GATEWAY_CONFIG_PATH,
    NETWORK_MODE_INTERNAL,
    NETWORK_MODE_PRODUCTION,
    gateway_network_snapshot,
    gateway_status,
    make_gateway_url,
    is_public_ipv4,
)

from ..tokens import COLORS, SPACE_8, SPACE_12, SPACE_16
from ..widgets import MetricCard, PageHeader, StatusChip, show_detailed_message
from .base import ScrollPage


class AgentActivityWorker(QThread):
    finished_data: Signal = Signal(object)
    failed: Signal = Signal(str)

    def __init__(
        self,
        *,
        base_url: str,
        token: str,
        verify_tls: bool,
        ca_file: str | None,
        require_https: bool,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.base_url = base_url
        self.token = token
        self.verify_tls = verify_tls
        self.ca_file = ca_file
        self.require_https = require_https

    def run(self) -> None:
        try:
            if not self.base_url:
                raise RuntimeError("No hay Http Gateway configurado en agent_control_plane.base_url.")
            if not self.token:
                raise RuntimeError("No hay GIDEON_AGENT_ADMIN_TOKEN configurado para consultar los agentes.")
            client = AgentHttpClient(
                self.base_url,
                bearer_token=self.token,
                verify_tls=self.verify_tls,
                ca_file=self.ca_file,
                require_https=self.require_https,
            )
            payload = client.json("GET", "/api/v1/admin/agents", timeout=10)
            self.finished_data.emit(payload)
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class GatewayOperationWorker(QThread):
    """Executes one Gateway application-service operation outside the GUI thread."""

    finished_data: Signal = Signal(object)
    failed: Signal = Signal(str)

    def __init__(self, operation, *, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.operation = operation

    def run(self) -> None:
        try:
            self.finished_data.emit(self.operation())
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")



class InstalledAgentsPage(ScrollPage):
    """Inventario de agentes y configuración operativa del Gateway Central."""

    settingsRequested: Signal = Signal()

    def __init__(self, *, config: dict[str, Any], gateway_only: bool = False, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.config = config
        self.gateway_only = bool(gateway_only)
        self.gateway_tab_index = 0 if self.gateway_only else 1
        self._worker: AgentActivityWorker | None = None
        self._gateway_health_worker: GatewayOperationWorker | None = None
        self._gateway_operation_worker: GatewayOperationWorker | None = None
        self._gateway_network_worker: GatewayOperationWorker | None = None
        self._local_agent_worker: GatewayOperationWorker | None = None
        self._rows: list[dict[str, Any]] = []
        self._agents_render_pending = False
        self.root = Path(__file__).resolve().parents[2]
        self.dependency_manager = SystemDependencyManager(self.root)
        self.gateway = GatewayCoordinator(self.root)
        self._gateway_initialized = False
        self._gateway_bootstrap_attempted = False

        header = PageHeader(
            "Infraestructura" if self.gateway_only else "Agentes instalados",
            "Gateway Central HTTPS/PULL, red, TLS, dependencias y diagnóstico." if self.gateway_only
            else "Inventario en vivo y administración del Gateway Central HTTPS/PULL.",
            self.content,
        )
        refresh = QPushButton("↻ Actualizar ahora", header)
        refresh.setObjectName("GhostButton")
        refresh.clicked.connect(self.refresh)
        header.add_action(refresh)
        local_diag = QPushButton("Diagnosticar agente local", header)
        local_diag.setObjectName("GhostButton")
        local_diag.setToolTip("Comprueba instalación, identidad, token, heartbeat, CA TLS y tarea/servicio del agente en este mismo equipo.")
        local_diag.clicked.connect(self.diagnose_local_agent)
        header.add_action(local_diag)
        self.content_layout.addWidget(header)

        self.tabs = QTabWidget(self.content)
        self.tabs.setDocumentMode(True)
        if not self.gateway_only:
            self.tabs.addTab(self._build_agents_tab(), "Agentes conectados")
        self.tabs.addTab(self._build_gateway_tab(), "Gateway central")
        self.content_layout.addWidget(self.tabs)
        self.content_layout.addStretch(1)

        # Fast path: only local JSON is read during construction. TLS generation,
        # PowerShell adapter discovery and health probes are deferred to workers.
        self._populate_gateway_fields()
        self.tabs.currentChanged.connect(self._gateway_tab_changed)

    def _build_agents_tab(self) -> QWidget:
        tab = QWidget(self.tabs)
        outer = QVBoxLayout(tab)
        outer.setContentsMargins(SPACE_8, SPACE_12, SPACE_8, SPACE_8)
        outer.setSpacing(SPACE_12)

        metrics = QWidget(tab)
        grid = QGridLayout(metrics)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setHorizontalSpacing(SPACE_12)
        self.total_card = MetricCard("Agentes enrolados", "0", COLORS.info)
        self.online_card = MetricCard("Activos ahora", "0", COLORS.success)
        self.offline_card = MetricCard("Sin heartbeat", "0", COLORS.danger)
        self.ttl_card = MetricCard("TTL de actividad", "90 s", COLORS.purple)
        for col, card in enumerate((self.total_card, self.online_card, self.offline_card, self.ttl_card)):
            grid.addWidget(card, 0, col)
        outer.addWidget(metrics)

        card = QFrame(tab)
        card.setObjectName("Card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(SPACE_16, SPACE_16, SPACE_16, SPACE_16)
        layout.setSpacing(SPACE_12)

        top = QHBoxLayout()
        self.gateway_label = QLabel("Gateway: -", card)
        self.gateway_label.setObjectName("Muted")
        top.addWidget(self.gateway_label, 1)
        self.status = StatusChip("Sin validar", "neutral", card)
        top.addWidget(self.status)
        layout.addLayout(top)

        self.table = QTableWidget(0, 13, card)
        self.table.setHorizontalHeaderLabels((
            "Estado", "Código", "Sede", "Agent ID", "Nombre agente", "Hostname", "Versión", "SO", "Arquitectura",
            "Host profile", "Último heartbeat", "Enrolado", "Capacidades",
        ))
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setMinimumHeight(430)
        layout.addWidget(self.table)

        note = QLabel(
            "ACTIVO = el último heartbeat está dentro del TTL configurado. "
            "La tabla se actualiza automáticamente cada 5 segundos mientras esta vista esté abierta.",
            card,
        )
        note.setObjectName("Muted")
        note.setWordWrap(True)
        layout.addWidget(note)
        outer.addWidget(card)
        return tab

    def _build_gateway_tab(self) -> QWidget:
        tab = QWidget(self.tabs)
        outer = QVBoxLayout(tab)
        outer.setContentsMargins(SPACE_8, SPACE_12, SPACE_8, SPACE_8)
        outer.setSpacing(SPACE_12)

        card = QFrame(tab)
        card.setObjectName("Card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(SPACE_16, SPACE_16, SPACE_16, SPACE_16)
        layout.setSpacing(SPACE_12)

        head = QHBoxLayout()
        title = QLabel("Configuración del Gateway Central", card)
        title.setObjectName("SectionTitle")
        head.addWidget(title)
        head.addStretch(1)
        self.gateway_test_button = QPushButton("Probar Gateway", card)
        self.gateway_test_button.setObjectName("PrimaryButton")
        self.gateway_test_button.clicked.connect(self.test_gateway)
        self.gateway_test_button.setToolTip("Diagnostica HTTPS/TLS/TCP y, si detecta un certificado GIDEON obsoleto en memoria, sincroniza el leaf y reinicia solo el Gateway sin bloquear la interfaz.")
        head.addWidget(self.gateway_test_button)
        self.gateway_mode_status = StatusChip("Modo sin validar", "neutral", card)
        head.addWidget(self.gateway_mode_status)
        self.gateway_dependency_status = StatusChip("Requisitos sin validar", "neutral", card)
        head.addWidget(self.gateway_dependency_status)
        self.gateway_process_status = StatusChip("Gateway no iniciado", "neutral", card)
        head.addWidget(self.gateway_process_status)
        layout.addLayout(head)

        architecture = QLabel(
            "Motor: Python HTTP/HTTPS nativo (http.server + ssl) · Base local: SQLite · TLS/certificados: cryptography. "
            "No requiere PHP, Apache ni IIS. La dirección fe80:: (IPv6 link-local) nunca se selecciona automáticamente como endpoint del Gateway.",
            card,
        )
        architecture.setWordWrap(True)
        architecture.setObjectName("Muted")
        layout.addWidget(architecture)

        # Red separada en TEST interno / PRODUCCIÓN y configuración EN CALIENTE.
        self.gateway_network_tabs = QTabWidget(card)
        self.gateway_network_tabs.setDocumentMode(True)

        test_tab = QWidget(self.gateway_network_tabs)
        test_layout = QVBoxLayout(test_tab)
        test_layout.setContentsMargins(SPACE_8, SPACE_12, SPACE_8, SPACE_8)
        test_form = QFormLayout()
        self.gateway_test_ip_combo = QComboBox(test_tab)
        self.gateway_test_ip_combo.setEditable(False)
        self.gateway_test_ip_combo.currentTextChanged.connect(self._update_gateway_preview_urls)
        test_form.addRow("IPv4 local del servidor", self.gateway_test_ip_combo)
        self.gateway_test_url_edit = QLineEdit(test_tab)
        self.gateway_test_url_edit.setReadOnly(True)
        test_form.addRow("URL de prueba LAN", self.gateway_test_url_edit)
        test_layout.addLayout(test_form)
        test_actions = QHBoxLayout()
        detect = QPushButton("Detectar IPv4 locales", test_tab)
        detect.setObjectName("GhostButton")
        detect.clicked.connect(self.refresh_gateway_networks)
        detect.setToolTip("Vuelve a detectar las IPv4 físicas locales en segundo plano; excluye VPN, WSL y adaptadores virtuales.")
        test_actions.addWidget(detect)
        firewall = QPushButton("Preparar Firewall TEST", test_tab)
        firewall.setObjectName("GhostButton")
        firewall.clicked.connect(self.prepare_test_firewall)
        firewall.setToolTip("Crea/actualiza la regla de Firewall de Windows para el puerto TEST, limitada a LocalSubnet.")
        test_actions.addWidget(firewall)
        activate_test = QPushButton("Activar TEST e iniciar Gateway", test_tab)
        activate_test.setObjectName("PrimaryButton")
        activate_test.clicked.connect(self.activate_internal_test)
        activate_test.setToolTip("Prepara la regla Firewall TEST si hace falta, aplica la IPv4 LAN, asegura TLS e inicia el Gateway en una sola operación.")
        test_actions.addWidget(activate_test)
        test_actions.addStretch(1)
        test_layout.addLayout(test_actions)
        test_note = QLabel(
            "Use este modo solo para pruebas en la red interna (LAN). GIDEON prioriza una IPv4 de Ethernet/Wi-Fi física del servidor y excluye interfaces VPN, WSL, Hyper-V, Docker, loopback y fe80::.",
            test_tab,
        )
        test_note.setObjectName("Muted")
        test_note.setWordWrap(True)
        test_layout.addWidget(test_note)
        self.gateway_network_tabs.addTab(test_tab, "Test red interna")

        prod_tab = QWidget(self.gateway_network_tabs)
        prod_layout = QVBoxLayout(prod_tab)
        prod_layout.setContentsMargins(SPACE_8, SPACE_12, SPACE_8, SPACE_8)
        prod_form = QFormLayout()
        self.gateway_host_edit = QLineEdit(prod_tab)
        self.gateway_host_edit.setPlaceholderText("IPv4 pública del router/firewall NAT; ingreso manual (ej. 200.x.x.x)")
        self.gateway_host_edit.textChanged.connect(self._update_gateway_preview_urls)
        prod_form.addRow("IP pública de Internet", self.gateway_host_edit)
        self.gateway_production_url_edit = QLineEdit(prod_tab)
        self.gateway_production_url_edit.setReadOnly(True)
        prod_form.addRow("URL pública de producción", self.gateway_production_url_edit)
        prod_layout.addLayout(prod_form)
        prod_actions = QHBoxLayout()
        activate_prod = QPushButton("Activar producción e iniciar Gateway", prod_tab)
        activate_prod.setObjectName("PrimaryButton")
        activate_prod.clicked.connect(self.activate_production)
        activate_prod.setToolTip("Aplica exclusivamente la IPv4 pública configurada y deja el Gateway iniciado para producción.")
        prod_actions.addWidget(activate_prod)
        prod_actions.addStretch(1)
        prod_layout.addLayout(prod_actions)
        prod_note = QLabel(
            "Producción usa exclusivamente una IPv4 pública ingresada manualmente. Esa IP normalmente pertenece al router/firewall por NAT y no tiene que aparecer en ipconfig del servidor. El Gateway no usa la VPN para su canal de producción.",
            prod_tab,
        )
        prod_note.setObjectName("Muted")
        prod_note.setWordWrap(True)
        prod_layout.addWidget(prod_note)
        self.gateway_network_tabs.addTab(prod_tab, "Producción · IP pública")

        hot_tab = QWidget(self.gateway_network_tabs)
        hot_layout = QVBoxLayout(hot_tab)
        hot_layout.setContentsMargins(SPACE_8, SPACE_12, SPACE_8, SPACE_8)
        hot_form = QFormLayout()
        self.gateway_port_spin = QSpinBox(hot_tab)
        self.gateway_port_spin.setRange(1, 65535)
        self.gateway_port_spin.setValue(8443)
        self.gateway_port_spin.valueChanged.connect(self._update_gateway_preview_urls)
        hot_form.addRow("Puerto HTTPS", self.gateway_port_spin)
        self.gateway_url_edit = QLineEdit(hot_tab)
        self.gateway_url_edit.setReadOnly(True)
        self.gateway_url_edit.setPlaceholderText("https://gateway:8443")
        hot_form.addRow("URL activa", self.gateway_url_edit)
        self.gateway_tls_label = QLabel("-", hot_tab)
        self.gateway_tls_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        hot_form.addRow("TLS", self.gateway_tls_label)
        self.gateway_ca_label = QLabel("-", hot_tab)
        self.gateway_ca_label.setWordWrap(True)
        self.gateway_ca_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        hot_form.addRow("CA de confianza", self.gateway_ca_label)
        self.gateway_data_label = QLabel("-", hot_tab)
        self.gateway_data_label.setWordWrap(True)
        self.gateway_data_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        hot_form.addRow("Datos / SQLite", self.gateway_data_label)
        self.gateway_hot_label = QLabel("Configuración atómica · runtime recargable sin cerrar Gideon Rx", hot_tab)
        self.gateway_hot_label.setObjectName("Muted")
        self.gateway_hot_label.setWordWrap(True)
        hot_form.addRow("EN CALIENTE", self.gateway_hot_label)
        self.gateway_security_label = QLabel("Credenciales protegidas · no se muestran en pantalla", hot_tab)
        self.gateway_security_label.setObjectName("Muted")
        hot_form.addRow("Seguridad", self.gateway_security_label)
        hot_layout.addLayout(hot_form)

        row1 = QHBoxLayout()
        hot_apply = QPushButton("Aplicar EN CALIENTE", hot_tab)
        hot_apply.setObjectName("PrimaryButton")
        hot_apply.clicked.connect(self.save_gateway_configuration)
        hot_apply.setToolTip("Persiste la configuración y, si el Gateway está activo, aplica el cambio reiniciando solo el listener cuando sea imprescindible.")
        row1.addWidget(hot_apply)
        regenerate = QPushButton("Regenerar TLS", hot_tab)
        regenerate.setObjectName("GhostButton")
        regenerate.clicked.connect(self.regenerate_gateway_tls)
        regenerate.setToolTip("Renueva únicamente el certificado servidor para el host activo y conserva la CA raíz estable. Esto evita romper la confianza de agentes ya instalados.")
        row1.addWidget(regenerate)
        copy = QPushButton("Copiar URL", hot_tab)
        copy.setObjectName("GhostButton")
        copy.clicked.connect(self.copy_gateway)
        copy.setToolTip("Copia al portapapeles la URL HTTPS activa del Gateway.")
        row1.addWidget(copy)
        row1.addStretch(1)
        hot_layout.addLayout(row1)

        row2 = QHBoxLayout()
        start = QPushButton("Iniciar Gateway", hot_tab)
        start.setObjectName("PrimaryButton")
        start.clicked.connect(self.start_gateway)
        start.setToolTip("Inicia el subproceso Gateway con la configuración ya guardada.")
        row2.addWidget(start)
        stop = QPushButton("Detener Gateway", hot_tab)
        stop.setObjectName("GhostButton")
        stop.clicked.connect(self.stop_gateway)
        stop.setToolTip("Detiene únicamente el subproceso Gateway administrado por esta consola.")
        row2.addWidget(stop)
        validate = QPushButton("Validar requisitos", hot_tab)
        validate.setObjectName("GhostButton")
        validate.clicked.connect(self.validate_gateway_requirements_async)
        validate.setToolTip("Valida en segundo plano los componentes necesarios para HTTPS, TLS, SQLite y el runtime GIDEON.")
        row2.addWidget(validate)
        settings = QPushButton("Ver requisitos del sistema", hot_tab)
        settings.setObjectName("GhostButton")
        settings.clicked.connect(self.settingsRequested.emit)
        settings.setToolTip("Abre Configuración → Requisitos y dependencias del sistema.")
        row2.addWidget(settings)
        row2.addStretch(1)
        hot_layout.addLayout(row2)

        hot_note = QLabel(
            "Los cambios se escriben de forma atómica. URL, credenciales y opciones runtime se recargan en caliente. Si cambia host/puerto/certificado, solo se reinicia automáticamente el subproceso Gateway; la aplicación GIDEON permanece abierta y conserva la configuración.",
            hot_tab,
        )
        hot_note.setWordWrap(True)
        hot_note.setObjectName("Muted")
        hot_layout.addWidget(hot_note)
        self.gateway_network_tabs.addTab(hot_tab, "Configuración EN CALIENTE")

        layout.addWidget(self.gateway_network_tabs)
        outer.addWidget(card)
        outer.addStretch(1)
        return tab

    def closeEvent(self, event: object) -> None:
        # Application shutdown is exceptional; stop the owned subprocess directly
        # to avoid leaving a QThread alive while Qt destroys the page.
        try:
            self.gateway.runtime.stop()
        except Exception as exc:
            best_effort_warning("No se pudo detener runtime local del Gateway al cerrar la página", exc)
        super().closeEvent(event)  # type: ignore[arg-type]

    @staticmethod
    def _online(row: dict[str, Any], ttl: int) -> bool:
        value = row.get("last_seen")
        if not value:
            return False
        try:
            stamp = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            now = dt.datetime.now(stamp.tzinfo) if stamp.tzinfo else dt.datetime.now()
            return (now - stamp).total_seconds() <= ttl
        except Exception:
            return False

    def _reload_gateway_config(self) -> dict[str, Any]:
        try:
            cfg_path = self.root / "config" / "config.json"
            data = json.loads(cfg_path.read_text(encoding="utf-8-sig"))
            if isinstance(data, dict):
                self.config.clear()
                self.config.update(data)
        except Exception as exc:
            best_effort_warning("No se pudo recargar config/config.json desde la página Gateway", exc)
        return self.config

    def _gateway_json(self) -> dict[str, Any]:
        try:
            value = json.loads(GATEWAY_CONFIG_PATH.read_text(encoding="utf-8-sig"))
            return value if isinstance(value, dict) else {}
        except Exception:
            return {}

    def _write_gateway_json(self, value: dict[str, Any]) -> None:
        GATEWAY_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = GATEWAY_CONFIG_PATH.with_suffix(GATEWAY_CONFIG_PATH.suffix + ".tmp")
        tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, GATEWAY_CONFIG_PATH)

    def refresh_gateway_networks(self) -> None:
        if self._gateway_network_worker is not None and self._gateway_network_worker.isRunning():
            return
        self.gateway_mode_status.setText("Detectando IPv4…")
        self.gateway_mode_status.set_kind("info")
        self._gateway_network_worker = GatewayOperationWorker(
            lambda: self.gateway.network.detect_local_ipv4s(), parent=self
        )
        self._gateway_network_worker.finished_data.connect(self._gateway_networks_loaded)
        self._gateway_network_worker.failed.connect(self._gateway_networks_failed)
        self._gateway_network_worker.start()

    def _gateway_networks_loaded(self, result: object) -> None:
        rows = [str(x) for x in (result if isinstance(result, list) else []) if str(x).strip()]
        current = self.gateway_test_ip_combo.currentText().strip()
        self.gateway_test_ip_combo.blockSignals(True)
        self.gateway_test_ip_combo.clear()
        self.gateway_test_ip_combo.addItems(rows)
        if current and current in rows:
            self.gateway_test_ip_combo.setCurrentText(current)
        self.gateway_test_ip_combo.blockSignals(False)
        self._update_gateway_preview_urls()
        if rows:
            self.gateway_mode_status.setText(f"{len(rows)} IPv4 LAN detectada(s)")
            self.gateway_mode_status.set_kind("success")
        else:
            self.gateway_mode_status.setText("Sin IPv4 LAN válida")
            self.gateway_mode_status.set_kind("warning")
        if self._gateway_network_worker is not None:
            self._gateway_network_worker.deleteLater()
        self._gateway_network_worker = None

    def _gateway_networks_failed(self, detail: str) -> None:
        self.gateway_mode_status.setText("No se pudo detectar IPv4")
        self.gateway_mode_status.set_kind("danger")
        self.gateway_mode_status.setToolTip(detail)
        if self._gateway_network_worker is not None:
            self._gateway_network_worker.deleteLater()
        self._gateway_network_worker = None

    def _update_gateway_preview_urls(self) -> None:
        if not hasattr(self, "gateway_port_spin"):
            return
        port = int(self.gateway_port_spin.value())
        test_host = self.gateway_test_ip_combo.currentText().strip() if hasattr(self, "gateway_test_ip_combo") else ""
        prod_host = self.gateway_host_edit.text().strip() if hasattr(self, "gateway_host_edit") else ""
        if hasattr(self, "gateway_test_url_edit"):
            self.gateway_test_url_edit.setText(make_gateway_url(test_host, port) if test_host else "Sin IPv4 local detectada")
        if hasattr(self, "gateway_production_url_edit"):
            self.gateway_production_url_edit.setText(make_gateway_url(prod_host, port) if is_public_ipv4(prod_host) else "Indique una IPv4 pública válida")

    def _populate_gateway_fields(self) -> None:
        gw = self._gateway_json()
        status = gateway_status()
        network = gateway_network_snapshot(gw, include_local_ipv4s=False)
        mode = str(network.get("mode") or NETWORK_MODE_INTERNAL)
        active_host = str(network.get("active_host") or status.get("host") or "")
        test_host = str(network.get("test_host") or "")
        production_host = str(network.get("production_host") or "")
        port = int(gw.get("listen_port") or status.get("port") or 8443)
        url = str(gw.get("public_url") or status.get("public_url") or (make_gateway_url(active_host, port) if active_host else ""))
        data_dir = Path(str(gw.get("data_dir") or "./gateway-data"))
        if not data_dir.is_absolute():
            data_dir = (self.root / data_dir).resolve()
        db_path = data_dir / "gateway.sqlite3"

        # Never run PowerShell/network discovery here. Reuse already detected rows
        # and persisted test_host so painting/navigating remains instantaneous.
        existing = [self.gateway_test_ip_combo.itemText(i) for i in range(self.gateway_test_ip_combo.count())]
        ipv4s = [x for x in existing if x]
        if test_host and test_host not in ipv4s:
            ipv4s.insert(0, test_host)
        self.gateway_test_ip_combo.blockSignals(True)
        self.gateway_test_ip_combo.clear()
        self.gateway_test_ip_combo.addItems(ipv4s)
        if test_host:
            self.gateway_test_ip_combo.setCurrentText(test_host)
        self.gateway_test_ip_combo.blockSignals(False)

        self.gateway_host_edit.blockSignals(True)
        self.gateway_host_edit.setText(production_host)
        self.gateway_host_edit.blockSignals(False)
        self.gateway_port_spin.blockSignals(True)
        self.gateway_port_spin.setValue(port)
        self.gateway_port_spin.blockSignals(False)
        self.gateway_url_edit.setText(url)
        self._update_gateway_preview_urls()

        if mode == NETWORK_MODE_INTERNAL:
            self.gateway_mode_status.setText("TEST red interna")
            self.gateway_mode_status.set_kind("warning")
        else:
            self.gateway_mode_status.setText("Producción · IP pública")
            self.gateway_mode_status.set_kind("success")
        tls_ok = bool(status.get("tls"))
        self.gateway_tls_label.setText("TLS 1.2+ habilitado" if tls_ok else "TLS pendiente")
        ca_path = str(status.get("ca_file") or "-")
        ca_fp = str(status.get("tls_ca_fingerprint") or "").strip()
        self.gateway_ca_label.setText(ca_path + ((" · SHA256 " + ca_fp[:16] + "…") if ca_fp else ""))
        self.gateway_data_label.setText(f"{data_dir} · DB: {db_path.name}")
        hot = "activo" if bool(status.get("hot_reload_enabled", True)) else "deshabilitado"
        self.gateway_hot_label.setText(f"Hot reload runtime: {hot} · modo activo: {mode} · host efectivo: {active_host}")
        # ``gateway_label`` belongs to the optional Agents inventory tab.
        # In the consolidated Qt console this page is instantiated with
        # gateway_only=True, so that tab (and therefore the widget) does not
        # exist.  Guarding it is required for startup of the main window.
        if hasattr(self, "gateway_label"):
            self.gateway_label.setText(f"Gateway: {url or '(no configurado)'}")

    def _gateway_tab_changed(self, index: int) -> None:
        if index == self.gateway_tab_index:
            if not self._gateway_initialized and not self._gateway_bootstrap_attempted:
                self.configure_gateway(silent=True)
            if self.gateway_test_ip_combo.count() == 0:
                QTimer.singleShot(0, self.refresh_gateway_networks)
            return
        if not self.gateway_only and self._agents_render_pending:
            ttl = int((self.config.get("agent_control_plane") or {}).get("agent_online_ttl_seconds", 90))
            self._render(ttl)
            self._agents_render_pending = False

    def _run_gateway_operation(self, operation, callback, *, failure_title: str = "Gateway central") -> None:
        if self._gateway_operation_worker is not None and self._gateway_operation_worker.isRunning():
            return
        worker = GatewayOperationWorker(operation, parent=self)
        self._gateway_operation_worker = worker
        worker.finished_data.connect(callback)
        worker.failed.connect(lambda detail: self._gateway_operation_failed(failure_title, detail))
        worker.start()

    def _gateway_operation_failed(self, title: str, detail: str) -> None:
        self.gateway_process_status.setText("Operación fallida")
        self.gateway_process_status.set_kind("danger")
        self.gateway_process_status.setToolTip(detail)
        show_detailed_message(self, title, "La operación del Gateway terminó con una incidencia.", detail, level="warning")
        if self._gateway_operation_worker is not None:
            self._gateway_operation_worker.deleteLater()
        self._gateway_operation_worker = None

    def _finish_gateway_operation(self) -> None:
        if self._gateway_operation_worker is not None:
            self._gateway_operation_worker.deleteLater()
        self._gateway_operation_worker = None

    def configure_gateway(self, *, silent: bool = False) -> None:
        if self._gateway_operation_worker is not None and self._gateway_operation_worker.isRunning():
            return
        self._gateway_bootstrap_attempted = True
        self.gateway_process_status.setText("Preparando en segundo plano…")
        self.gateway_process_status.set_kind("info")
        worker = GatewayOperationWorker(self.gateway.bootstrap, parent=self)
        self._gateway_operation_worker = worker

        def done(result: object) -> None:
            data = result if isinstance(result, GatewayResult) else GatewayResult(False, "Respuesta inválida")
            self._gateway_initialized = bool(data.ok)
            self._reload_gateway_config()
            self._populate_gateway_fields()
            deps = list(data.data.get("dependencies") or [])
            missing = [d for d in deps if not getattr(d, "installed", False)]
            if data.ok:
                self.gateway_process_status.setText("Gateway configurado")
                self.gateway_process_status.set_kind("success")
                self.gateway_dependency_status.setText("Requisitos listos")
                self.gateway_dependency_status.set_kind("success")
            else:
                self.gateway_process_status.setText("Configuración incompleta")
                self.gateway_process_status.set_kind("warning")
                if missing:
                    self.gateway_dependency_status.setText(f"Faltan {len(missing)} requisito(s)")
                    self.gateway_dependency_status.set_kind("danger")
                if not silent and data.message:
                    show_detailed_message(self, data.title, "La configuración del Gateway requiere atención.", data.message, level="warning")
            self._finish_gateway_operation()

        worker.finished_data.connect(done)
        worker.failed.connect(lambda detail: self._gateway_operation_failed("Gateway central", detail) if not silent else self._silent_gateway_failure(detail))
        worker.start()

    def _silent_gateway_failure(self, detail: str) -> None:
        self.gateway_process_status.setText("Gateway requiere atención")
        self.gateway_process_status.set_kind("warning")
        self.gateway_process_status.setToolTip(detail)
        self._finish_gateway_operation()

    def _apply_gateway_configuration(
        self, *, mode: str, host: str, force_tls: bool = False, ensure_started: bool = True
    ) -> None:
        host = host.strip().strip("[]")
        port = int(self.gateway_port_spin.value())
        if not host:
            label = "una IPv4 local" if mode == NETWORK_MODE_INTERNAL else "una IPv4 pública de Internet"
            QMessageBox.warning(self, "Gateway central", f"Indique {label} para el Gateway.")
            return
        if mode == NETWORK_MODE_PRODUCTION and not is_public_ipv4(host):
            QMessageBox.warning(
                self,
                "Gateway central",
                "Producción requiere una IPv4 pública real. No se aceptan IP privadas, VPN, WSL, loopback, DNS ni fe80::.\n\n"
                "Para pruebas use la pestaña 'Test red interna'.",
            )
            return
        self.gateway_process_status.setText("Aplicando configuración…")
        self.gateway_process_status.set_kind("info")
        self._run_gateway_operation(
            lambda: self.gateway.activate(
                mode=mode, host=host, port=port, force_tls=force_tls, ensure_started=ensure_started
            ),
            self._gateway_configuration_applied,
        )

    def _gateway_configuration_applied(self, result: object) -> None:
        data = result if isinstance(result, GatewayResult) else GatewayResult(False, "Respuesta inválida")
        self._reload_gateway_config()
        self._populate_gateway_fields()
        if data.ok:
            self.gateway_process_status.setText("Gateway ejecutándose" if self.gateway.runtime.is_running() else "Configuración aplicada")
            self.gateway_process_status.set_kind("success")
            self.gateway_hot_label.setText(
                "Aplicado EN CALIENTE · configuración persistida atómicamente; solo el subproceso Gateway se reinicia cuando cambia listener/TLS."
            )
        else:
            self.gateway_process_status.setText("Gateway requiere atención")
            self.gateway_process_status.set_kind("warning")
            show_detailed_message(self, data.title, "No se pudo aplicar la configuración del Gateway.", data.message or "No se pudo aplicar la configuración.", level="warning")
        self._finish_gateway_operation()

    def prepare_test_firewall(self) -> None:
        host = self.gateway_test_ip_combo.currentText().strip()
        port = int(self.gateway_port_spin.value())
        self.gateway_process_status.setText("Preparando firewall…")
        self.gateway_process_status.set_kind("info")
        self._run_gateway_operation(
            lambda: self.gateway.firewall.prepare_internal_test(host=host, port=port),
            self._firewall_prepared,
            failure_title="Firewall TEST",
        )

    def _firewall_prepared(self, result: object) -> None:
        data = result if isinstance(result, GatewayResult) else GatewayResult(False, "Respuesta inválida")
        self.gateway_process_status.setText("Firewall TEST listo" if data.ok else "Firewall TEST pendiente")
        self.gateway_process_status.set_kind("success" if data.ok else "warning")
        if data.ok:
            QMessageBox.information(self, data.title, data.message)
        else:
            show_detailed_message(self, data.title, "La operación del Gateway requiere atención.", data.message, level="warning")
        self._finish_gateway_operation()

    def activate_internal_test(self) -> None:
        host = self.gateway_test_ip_combo.currentText().strip()
        port = int(self.gateway_port_spin.value())
        if not host:
            QMessageBox.warning(self, "Gateway central", "Seleccione primero una IPv4 local del servidor.")
            return
        self.gateway_process_status.setText("Preparando TEST interno…")
        self.gateway_process_status.set_kind("info")
        self._run_gateway_operation(
            lambda: self.gateway.activate_internal_test(host=host, port=port),
            self._gateway_configuration_applied,
            failure_title="TEST red interna",
        )

    def activate_production(self) -> None:
        host = self.gateway_host_edit.text().strip()
        self._apply_gateway_configuration(mode=NETWORK_MODE_PRODUCTION, host=host, ensure_started=True)

    def save_gateway_configuration(self) -> None:
        gw = self._gateway_json()
        mode = str(gw.get("network_mode") or NETWORK_MODE_INTERNAL)
        host = self.gateway_host_edit.text().strip() if mode == NETWORK_MODE_PRODUCTION else self.gateway_test_ip_combo.currentText().strip()
        self._apply_gateway_configuration(mode=mode, host=host, ensure_started=self.gateway.runtime.is_running())

    def regenerate_gateway_tls(self) -> None:
        gw = self._gateway_json()
        mode = str(gw.get("network_mode") or NETWORK_MODE_INTERNAL)
        host = self.gateway_host_edit.text().strip() if mode == NETWORK_MODE_PRODUCTION else self.gateway_test_ip_combo.currentText().strip()
        self._apply_gateway_configuration(mode=mode, host=host, force_tls=True, ensure_started=self.gateway.runtime.is_running())

    def copy_gateway(self) -> None:
        QApplication.clipboard().setText(self.gateway_url_edit.text().strip())

    def validate_gateway_requirements_async(self) -> None:
        self.gateway_dependency_status.setText("Validando…")
        self.gateway_dependency_status.set_kind("info")
        self._run_gateway_operation(
            lambda: self.dependency_manager.gateway_ready(),
            self._gateway_requirements_validated,
            failure_title="Requisitos del Gateway",
        )

    def _gateway_requirements_validated(self, result: object) -> None:
        try:
            ready, deps = result  # type: ignore[misc]
        except Exception:
            ready, deps = False, []
        missing = [dep for dep in deps if not getattr(dep, "installed", False)]
        if ready:
            self.gateway_dependency_status.setText("Requisitos listos")
            self.gateway_dependency_status.set_kind("success")
            QMessageBox.information(self, "Gateway central", "Requisitos validados: Python HTTP/HTTPS, TLS/OpenSSL, SQLite, cryptography y archivos GIDEON.")
        else:
            self.gateway_dependency_status.setText(f"Faltan {len(missing)} requisito(s)")
            self.gateway_dependency_status.set_kind("danger")
            detail = "\n".join(f"• {dep.name}: {dep.detail or dep.install_hint}" for dep in missing) or "No se pudo completar la validación."
            show_detailed_message(self, "Requisitos del Gateway", "Faltan requisitos para iniciar el Gateway.", detail, level="warning")
        self._finish_gateway_operation()

    def validate_gateway_requirements(self, *, show_dialog: bool = True) -> bool:
        ready, deps = self.dependency_manager.gateway_ready()
        missing = [dep for dep in deps if not dep.installed]
        if ready:
            self.gateway_dependency_status.setText("Requisitos listos")
            self.gateway_dependency_status.set_kind("success")
            self.gateway_dependency_status.setToolTip(
                "HTTP/HTTPS Python, TLS/OpenSSL, SQLite, cryptography y archivos del Gateway validados."
            )
            if show_dialog:
                QMessageBox.information(
                    self,
                    "Gateway central",
                    "Requisitos del Gateway validados. No se requiere PHP, Apache ni IIS.",
                )
            return True

        self.gateway_dependency_status.setText(f"Faltan {len(missing)} requisito(s)")
        self.gateway_dependency_status.set_kind("danger")
        detail = "\n".join(f"• {dep.name}: {dep.detail or dep.install_hint}" for dep in missing)
        self.gateway_dependency_status.setToolTip(detail)
        if show_dialog:
            show_detailed_message(
                self,
                "Requisitos del Gateway",
                "No se puede iniciar el Gateway hasta corregir los requisitos pendientes.",
                detail + "\n\nRevise Configuración → Requisitos y dependencias del sistema.",
                level="warning",
            )
        return False

    def start_gateway(self) -> None:
        self.gateway_process_status.setText("Iniciando…")
        self.gateway_process_status.set_kind("info")
        self._run_gateway_operation(self.gateway.runtime.start, self._gateway_started)

    def _gateway_started(self, result: object) -> None:
        data = result if isinstance(result, GatewayResult) else GatewayResult(False, "Respuesta inválida")
        self._reload_gateway_config()
        self._populate_gateway_fields()
        self.gateway_process_status.setText("Gateway ejecutándose" if data.ok else "No se pudo iniciar")
        self.gateway_process_status.set_kind("success" if data.ok else "danger")
        if not data.ok:
            show_detailed_message(self, data.title, "La operación del Gateway requiere atención.", data.message, level="warning")
        self._finish_gateway_operation()

    def stop_gateway(self, *, refresh_after: bool = True) -> None:
        if self._gateway_operation_worker is not None and self._gateway_operation_worker.isRunning():
            return
        self.gateway_process_status.setText("Deteniendo…")
        self.gateway_process_status.set_kind("info")
        worker = GatewayOperationWorker(self.gateway.runtime.stop, parent=self)
        self._gateway_operation_worker = worker

        def done(result: object) -> None:
            data = result if isinstance(result, GatewayResult) else GatewayResult(False, "Respuesta inválida")
            self.gateway_process_status.setText("Gateway detenido" if data.ok else "No se pudo detener")
            self.gateway_process_status.set_kind("neutral" if data.ok else "danger")
            self._finish_gateway_operation()
            if refresh_after:
                self.refresh()

        worker.finished_data.connect(done)
        worker.failed.connect(lambda detail: self._gateway_operation_failed("Detener Gateway", detail))
        worker.start()

    def _connection(self) -> tuple[str, str, bool, str | None, bool]:
        cfg = merged_agent_control_plane(self.config)
        base = str(cfg.get("base_url") or cfg.get("public_url") or "").rstrip("/")
        env_name = str(cfg.get("admin_api_key_env") or "GIDEON_AGENT_ADMIN_TOKEN")
        token = str(cfg.get("admin_api_key") or os.environ.get(env_name, ""))
        return (
            base,
            token,
            bool(cfg.get("verify_tls", True)),
            cfg.get("ca_file"),
            bool(cfg.get("require_https", True)),
        )

    def test_gateway(self) -> None:
        if self._gateway_health_worker is not None and self._gateway_health_worker.isRunning():
            return
        self.gateway_test_button.setEnabled(False)
        self.gateway_test_button.setText("Probando / reparando…")
        self._gateway_health_worker = GatewayOperationWorker(self.gateway.test_and_repair, parent=self)
        self._gateway_health_worker.finished_data.connect(self._gateway_test_finished)
        self._gateway_health_worker.failed.connect(self._gateway_test_failed)
        self._gateway_health_worker.start()

    def _gateway_test_failed(self, detail: str) -> None:
        self.gateway_test_button.setEnabled(True)
        self.gateway_test_button.setText("Probar Gateway")
        self.gateway_process_status.setText("Prueba fallida")
        self.gateway_process_status.set_kind("danger")
        show_detailed_message(self, "Gateway requiere atención", "La prueba del Gateway terminó con una incidencia.", detail, level="warning")
        if self._gateway_health_worker is not None:
            self._gateway_health_worker.deleteLater()
        self._gateway_health_worker = None

    def _gateway_test_finished(self, result: object) -> None:
        data = result if isinstance(result, GatewayResult) else GatewayResult(False, "Gateway requiere atención", "Respuesta de diagnóstico inválida.")
        def check_tag(check) -> str:
            if check.ok:
                return "OK"
            return "FALTA" if getattr(check, "blocking", True) else "INFO"

        lines = [f"[{check_tag(check)}] {check.name}: {check.detail}" for check in data.checks]
        message = (data.message or "") + ("\n\n" if lines else "") + "\n".join(lines)
        if data.ok:
            show_detailed_message(self, data.title, "Gateway verificado correctamente.", message, level="info")
            self.gateway_process_status.setText("Gateway verificado")
            self.gateway_process_status.set_kind("success")
        else:
            show_detailed_message(self, data.title, "El Gateway requiere atención.", message, level="warning")
            self.gateway_process_status.setText("Gateway requiere atención")
            self.gateway_process_status.set_kind("warning")
        self.gateway_test_button.setEnabled(True)
        self.gateway_test_button.setText("Probar Gateway")
        if self._gateway_health_worker is not None:
            self._gateway_health_worker.deleteLater()
        self._gateway_health_worker = None

    def diagnose_local_agent(self) -> None:
        if self._local_agent_worker is not None and self._local_agent_worker.isRunning():
            return
        self._local_agent_worker = GatewayOperationWorker(lambda: inspect_local_agent(self.root), parent=self)
        self._local_agent_worker.finished_data.connect(self._local_agent_diagnostic_finished)
        self._local_agent_worker.failed.connect(self._local_agent_diagnostic_failed)
        self._local_agent_worker.start()

    def _local_agent_diagnostic_finished(self, result: object) -> None:
        data = result if isinstance(result, dict) else {}
        lines = []
        for check in data.get("checks") or []:
            if not isinstance(check, dict):
                continue
            lines.append(f"[{'OK' if check.get('ok') else 'FALTA'}] {check.get('name')}: {check.get('detail')}")
        message = str(data.get("summary") or "")
        if lines:
            message += "\n\n" + "\n".join(lines)
        if data.get("installed") and not any(bool(c.get("ok")) for c in (data.get("checks") or []) if isinstance(c, dict) and c.get("name") == "Enrolamiento"):
            message += "\n\nAcción recomendada: vuelva a generar/ejecutar el agente con v6.0.20. El instalador ahora incorpora la credencial bootstrap cuando se genera desde este Gateway y NO muestra éxito hasta confirmar enrolamiento + heartbeat."
        if data.get("ok"):
            show_detailed_message(self, str(data.get("title") or "Agente local"), "Diagnóstico del agente completado.", message, level="info")
        else:
            show_detailed_message(self, str(data.get("title") or "Agente local"), "El diagnóstico del agente requiere atención.", message, level="warning")
        if self._local_agent_worker is not None:
            self._local_agent_worker.deleteLater()
        self._local_agent_worker = None

    def _local_agent_diagnostic_failed(self, detail: str) -> None:
        show_detailed_message(self, "Diagnóstico de agente local", "No se pudo completar el diagnóstico del agente local.", detail, level="warning")
        if self._local_agent_worker is not None:
            self._local_agent_worker.deleteLater()
        self._local_agent_worker = None

    def refresh(self) -> None:
        # Keep Gateway navigation deterministic and fast. The 5-second page timer
        # must not start an agents HTTP query while the Gateway tab is visible.
        self._reload_gateway_config()
        self._populate_gateway_fields()
        if self.tabs.currentIndex() == self.gateway_tab_index:
            if (
                not self._gateway_initialized
                and not self._gateway_bootstrap_attempted
                and not (self._gateway_operation_worker and self._gateway_operation_worker.isRunning())
            ):
                self.configure_gateway(silent=True)
            return
        if self._worker is not None and self._worker.isRunning():
            return
        base, token, verify_tls, ca_file, require_https = self._connection()
        if self.gateway.runtime.is_running():
            self.gateway_process_status.setText("Gateway ejecutándose")
            self.gateway_process_status.set_kind("success")
        ttl = int((self.config.get("agent_control_plane") or {}).get("agent_online_ttl_seconds", 90))
        self.ttl_card.set_value(f"{ttl} s")
        self.status.setText("Consultando…")
        self.status.set_kind("info")
        self._worker = AgentActivityWorker(
            base_url=base,
            token=token,
            verify_tls=verify_tls,
            ca_file=ca_file,
            require_https=require_https,
            parent=self,
        )
        self._worker.finished_data.connect(self._loaded)
        self._worker.failed.connect(self._failed)
        self._worker.start()

    def _loaded(self, payload: object) -> None:
        data = payload if isinstance(payload, dict) else {}
        rows = data.get("Agents") or []
        self._rows = [dict(r) for r in rows if isinstance(r, dict)]
        ttl = int((self.config.get("agent_control_plane") or {}).get("agent_online_ttl_seconds", 90))
        online = sum(1 for r in self._rows if self._online(r, ttl))
        self.total_card.set_value(str(len(self._rows)))
        self.online_card.set_value(str(online))
        self.offline_card.set_value(str(len(self._rows) - online))
        # Do not resize/repaint a hidden table while the Gateway tab is open.
        # That completion callback was a common source of perceived "tirones".
        if not self.gateway_only and self.tabs.currentIndex() != self.gateway_tab_index:
            self._render(ttl)
            self._agents_render_pending = False
        else:
            self._agents_render_pending = True
        self.status.setText(f"Actualizado · {dt.datetime.now().strftime('%H:%M:%S')}")
        self.status.set_kind("success")
        if self.gateway.runtime.is_running():
            self.gateway_process_status.setText("Gateway ejecutándose")
            self.gateway_process_status.set_kind("success")
        else:
            self.gateway_process_status.setText("Gateway disponible")
            self.gateway_process_status.set_kind("success")
        self._worker = None

    def _failed(self, detail: str) -> None:
        self.status.setText("Gateway no disponible")
        self.status.set_kind("danger")
        self._worker = None
        self.total_card.set_value("-")
        self.online_card.set_value("-")
        self.offline_card.set_value("-")
        self.gateway_label.setToolTip(detail)
        if not self.gateway.runtime.is_running():
            self.gateway_process_status.setText("Gateway detenido / error")
            self.gateway_process_status.set_kind("danger")
            self.gateway_process_status.setToolTip(detail)

    def _render(self, ttl: int) -> None:
        rows = sorted(self._rows, key=lambda r: (not self._online(r, ttl), str(r.get("site_code") or "")))
        self.table.setRowCount(0)
        for data in rows:
            online = self._online(data, ttl)
            row = self.table.rowCount()
            self.table.insertRow(row)
            caps = data.get("Capabilities") or data.get("capabilities_json") or data.get("capabilities") or {}
            if isinstance(caps, dict):
                cap_text = ", ".join(sorted(str(k) for k, v in caps.items() if v)) or "-"
            else:
                cap_text = str(caps) or "-"
            values = (
                "ACTIVO" if online else "INACTIVO",
                data.get("site_code") or "-",
                data.get("site_name") or "-",
                data.get("agent_id") or "-",
                data.get("agent_name") or data.get("hostname") or "-",
                data.get("hostname") or "-",
                data.get("agent_version") or "-",
                data.get("platform") or "-",
                data.get("architecture") or "-",
                data.get("host_profile") or "-",
                data.get("last_seen") or "Nunca",
                data.get("enrolled_at") or "-",
                cap_text,
            )
            for col, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setToolTip(str(value))
                if col == 0:
                    item.setData(Qt.ItemDataRole.UserRole, online)
                self.table.setItem(row, col, item)
        self.table.resizeColumnsToContents()
