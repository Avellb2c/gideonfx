from __future__ import annotations

from dataclasses import asdict
import ipaddress
from pathlib import Path

from PySide6.QtCore import QThread, Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from gideon_remote_access import (
    RemoteAccessManager,
    RemoteHostSettings,
    SecurityPolicy,
    SshTunnelConfig,
)
from gideon_site_groups import SiteGroupStore
from gideon_platform import detect_platform

from ..tokens import SPACE_8, SPACE_12, SPACE_16
from ..widgets import CommandBar, PageHeader, StatusChip, show_detailed_message
from .base import ScrollPage


class RemoteAccessWorker(QThread):
    done: Signal = Signal(str, str, bool, str)

    def __init__(self, manager: RemoteAccessManager, action: str, site_code: str, host: str, parent: QWidget | None = None):
        super().__init__(parent)
        self.manager = manager
        self.action = action
        self.site_code = site_code
        self.host = host

    def run(self) -> None:
        if self.action == "connect":
            ok, detail = self.manager.connect(self.site_code, self.host)
        else:
            ok, detail = self.manager.test(self.site_code, self.host)
        self.done.emit(self.action, self.site_code, ok, detail)


class RemoteEnvironmentWorker(QThread):
    done: Signal = Signal(object)

    def __init__(self, manager: RemoteAccessManager, *, force: bool = False, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.manager = manager
        self.force = force

    def run(self) -> None:
        try:
            client = self.manager.client_status()
            interfaces = self.manager.network_interfaces(force=self.force)
            vpn = self.manager.vpn_status(force=False)
            keys = self.manager.ssh_private_key_candidates()
            known_hosts = self.manager.known_hosts_candidates()
            self.done.emit({"client": client, "interfaces": interfaces, "vpn": vpn, "keys": keys, "known_hosts": known_hosts})
        except Exception as exc:
            self.done.emit({"error": f"{type(exc).__name__}: {exc}"})


class RemoteAccessPage(ScrollPage):
    toastRequested: Signal = Signal(str, str, str)
    manageListsRequested: Signal = Signal()
    settingsRequested: Signal = Signal()

    COL_CODE = 0
    COL_NAME = 1
    COL_HOST = 2
    COL_PORT = 3
    COL_MODE = 4
    COL_STATUS = 5

    def __init__(
        self,
        *,
        app_root: Path,
        groups: SiteGroupStore,
        known_hosts: Path,
        default_key: Path,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.groups = groups
        self.platform_profile = detect_platform()
        self.manager = RemoteAccessManager(app_root, known_hosts=known_hosts, default_key=default_key)
        self._worker: RemoteAccessWorker | None = None
        self._environment_worker: RemoteEnvironmentWorker | None = None
        self._selected_site: str = ""

        active_client = "RDC / MSTSC" if self.platform_profile.family == "windows" else "Remmina + RDP"
        header = PageHeader(
            "Acceso remoto seguro",
            f"{self.platform_profile.label} · cliente activo: {active_client}. Solo permite destinos privados cuya ruta pase por la VPN; opcionalmente añade un túnel OpenSSH con claves.",
            self.content,
        )
        self.content_layout.addWidget(header)

        status_card = QFrame(self.content)
        status_card.setObjectName("Card")
        status_layout = QHBoxLayout(status_card)
        status_layout.setContentsMargins(SPACE_16, SPACE_12, SPACE_16, SPACE_12)
        status_layout.setSpacing(SPACE_12)
        self.platform_chip = StatusChip(self.platform_profile.label, "info", status_card)
        self.client_chip = StatusChip("Cliente · verificando", "neutral", status_card)
        self.vpn_chip = StatusChip("VPN · verificando", "neutral", status_card)
        self.security_chip = StatusChip("Política · VPN obligatoria", "success", status_card)
        status_layout.addWidget(self.platform_chip)
        status_layout.addWidget(self.client_chip)
        status_layout.addWidget(self.vpn_chip)
        status_layout.addWidget(self.security_chip)
        status_layout.addStretch(1)
        requirements = QPushButton("Requisitos del sistema", status_card)
        requirements.setObjectName("GhostButton")
        requirements.clicked.connect(self.settingsRequested.emit)
        status_layout.addWidget(requirements)
        refresh = QPushButton("↻ Actualizar", status_card)
        refresh.setObjectName("GhostButton")
        refresh.clicked.connect(self.refresh)
        status_layout.addWidget(refresh)
        self.content_layout.addWidget(status_card)

        inventory = QFrame(self.content)
        inventory.setObjectName("Card")
        inventory_layout = QVBoxLayout(inventory)
        inventory_layout.setContentsMargins(SPACE_16, SPACE_16, SPACE_16, SPACE_16)
        inventory_layout.setSpacing(SPACE_12)

        title = QLabel("Hosts por listas configurables", inventory)
        title.setObjectName("SectionTitle")
        inventory_layout.addWidget(title)

        command = CommandBar(inventory)
        command.add_action("Probar acceso", self._test_selected)
        command.add_action("Conectar", self._connect_selected, primary=True)
        command.add_stretch()
        command.add_action("Administrar listas", self.manageListsRequested.emit)
        inventory_layout.addWidget(command)

        filters = QHBoxLayout()
        filters.setSpacing(SPACE_12)
        filters.addWidget(QLabel("Lista", inventory))
        self.group_combo = QComboBox(inventory)
        self.group_combo.setMinimumWidth(300)
        self.group_combo.currentIndexChanged.connect(self._reload_hosts)
        filters.addWidget(self.group_combo)
        self.search_edit = QLineEdit(inventory)
        self.search_edit.setPlaceholderText("Buscar sede, código o IP…")
        self.search_edit.setClearButtonEnabled(True)
        self.search_edit.textChanged.connect(self._filter_rows)
        filters.addWidget(self.search_edit, 1)
        inventory_layout.addLayout(filters)

        self.table = QTableWidget(0, 6, inventory)
        self.table.setHorizontalHeaderLabels(("Código", "Sede", "Host / IP", "RDP", "Modo", "Estado"))
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setMinimumHeight(340)
        self.table.itemSelectionChanged.connect(self._selection_changed)
        self.table.itemDoubleClicked.connect(lambda *_: self._connect_selected())
        inventory_layout.addWidget(self.table)
        inventory_layout.addWidget(QLabel(
            "Las listas son los grupos de Hosts y grupos. Las contraseñas nunca se guardan: MSTSC/Remmina solicitan la credencial al abrir la sesión.",
            inventory,
        ))
        self.content_layout.addWidget(inventory)

        host_card = QFrame(self.content)
        host_card.setObjectName("Card")
        host_layout = QVBoxLayout(host_card)
        host_layout.setContentsMargins(SPACE_16, SPACE_16, SPACE_16, SPACE_16)
        host_layout.setSpacing(SPACE_12)
        host_title = QLabel("Perfil del host seleccionado", host_card)
        host_title.setObjectName("SectionTitle")
        host_layout.addWidget(host_title)
        self.host_label = QLabel("Seleccione un host", host_card)
        self.host_label.setObjectName("Muted")
        host_layout.addWidget(self.host_label)

        host_form = QGridLayout()
        self.rdp_port_spin = QSpinBox(host_card)
        self.rdp_port_spin.setRange(1, 65535)
        self.rdp_user_edit = QLineEdit(host_card)
        self.rdp_user_edit.setPlaceholderText("Vacío = solicitar al conectar")
        self.rdp_domain_edit = QLineEdit(host_card)
        self.rdp_domain_edit.setPlaceholderText("Dominio opcional")
        self.mode_combo = QComboBox(host_card)
        self.mode_combo.addItem("VPN + RDP NLA/TLS", "vpn_rdp")
        self.mode_combo.addItem("VPN + túnel SSH + RDP", "vpn_ssh_rdp")
        host_form.addWidget(QLabel("Puerto RDP", host_card), 0, 0)
        host_form.addWidget(self.rdp_port_spin, 0, 1)
        host_form.addWidget(QLabel("Usuario", host_card), 0, 2)
        host_form.addWidget(self.rdp_user_edit, 0, 3)
        host_form.addWidget(QLabel("Dominio", host_card), 1, 0)
        host_form.addWidget(self.rdp_domain_edit, 1, 1)
        host_form.addWidget(QLabel("Transporte", host_card), 1, 2)
        host_form.addWidget(self.mode_combo, 1, 3)
        host_layout.addLayout(host_form)

        redir = QHBoxLayout()
        self.fullscreen_check = QCheckBox("Pantalla completa", host_card)
        self.clipboard_check = QCheckBox("Portapapeles", host_card)
        self.printers_check = QCheckBox("Impresoras", host_card)
        self.drives_check = QCheckBox("Unidades", host_card)
        self.smartcards_check = QCheckBox("Smart cards", host_card)
        for widget in (self.fullscreen_check, self.clipboard_check, self.printers_check, self.drives_check, self.smartcards_check):
            redir.addWidget(widget)
        redir.addStretch(1)
        host_layout.addLayout(redir)
        warning = QLabel(
            "Por seguridad las redirecciones de portapapeles, impresoras, unidades y smart cards vienen desactivadas. Active solo lo necesario.",
            host_card,
        )
        warning.setObjectName("Muted")
        warning.setWordWrap(True)
        host_layout.addWidget(warning)
        host_actions = QHBoxLayout()
        save_host = QPushButton("Guardar perfil del host", host_card)
        save_host.setObjectName("PrimaryButton")
        save_host.clicked.connect(self._save_host)
        reset_host = QPushButton("Usar valores predeterminados", host_card)
        reset_host.setObjectName("GhostButton")
        reset_host.clicked.connect(self._reset_host)
        host_actions.addWidget(save_host)
        host_actions.addWidget(reset_host)
        host_actions.addStretch(1)
        host_layout.addLayout(host_actions)
        self.content_layout.addWidget(host_card)

        security_card = QFrame(self.content)
        security_card.setObjectName("Card")
        security_layout = QVBoxLayout(security_card)
        security_layout.setContentsMargins(SPACE_16, SPACE_16, SPACE_16, SPACE_16)
        security_layout.setSpacing(SPACE_12)
        sec_title = QLabel("Seguridad, VPN y OpenSSH", security_card)
        sec_title.setObjectName("SectionTitle")
        security_layout.addWidget(sec_title)
        sec_text = QLabel(
            "Política fija: VPN obligatoria, ruta al destino obligatoriamente por interfaz VPN y bloqueo de IP públicas. "
            "RDP usa NLA/TLS. El modo SSH añade un port-forward local con autenticación solo por clave, StrictHostKeyChecking y known_hosts verificado.",
            security_card,
        )
        sec_text.setObjectName("Muted")
        sec_text.setWordWrap(True)
        security_layout.addWidget(sec_text)

        policy_form = QFormLayout()
        self.cidrs_edit = QLineEdit(security_card)
        self.vpn_patterns_edit = QLineEdit(security_card)
        self.trusted_vpn_edit = QLineEdit(security_card)
        self.default_port_spin = QSpinBox(security_card)
        self.default_port_spin.setRange(1, 65535)
        policy_form.addRow("Redes privadas permitidas", self.cidrs_edit)
        policy_form.addRow("Patrones de interfaz VPN", self.vpn_patterns_edit)
        policy_form.addRow("Interfaces VPN confiables (manual / contingencia)", self.trusted_vpn_edit)
        policy_form.addRow("Puerto RDP predeterminado", self.default_port_spin)
        security_layout.addLayout(policy_form)

        detected_title = QLabel("Interfaces detectadas en este equipo", security_card)
        detected_title.setObjectName("SectionTitle")
        security_layout.addWidget(detected_title)
        detected_help = QLabel(
            "GIDEON enumera los adaptadores reales durante la validación. Seleccione la interfaz que corresponde a su VPN y agréguela como confiable; escribir el alias manualmente queda solo como contingencia.",
            security_card,
        )
        detected_help.setObjectName("Muted")
        detected_help.setWordWrap(True)
        security_layout.addWidget(detected_help)
        detected_row = QHBoxLayout()
        detected_row.setSpacing(SPACE_8)
        self.detected_vpn_combo = QComboBox(security_card)
        self.detected_vpn_combo.setMinimumWidth(420)
        detected_row.addWidget(self.detected_vpn_combo, 1)
        trust_button = QPushButton("Agregar como VPN confiable", security_card)
        trust_button.setObjectName("PrimaryButton")
        trust_button.clicked.connect(self._trust_detected_interface)
        detected_row.addWidget(trust_button)
        detect_refresh = QPushButton("↻ Detectar de nuevo", security_card)
        detect_refresh.setObjectName("GhostButton")
        detect_refresh.clicked.connect(lambda: self.refresh(force=True))
        detected_row.addWidget(detect_refresh)
        security_layout.addLayout(detected_row)
        self.detected_vpn_note = QLabel("Aún no se han enumerado interfaces.", security_card)
        self.detected_vpn_note.setObjectName("Muted")
        self.detected_vpn_note.setWordWrap(True)
        security_layout.addWidget(self.detected_vpn_note)

        ssh_title = QLabel("Túnel SSH opcional", security_card)
        ssh_title.setObjectName("SectionTitle")
        security_layout.addWidget(ssh_title)
        ssh_form = QGridLayout()
        self.jump_host_edit = QLineEdit(security_card)
        self.jump_host_edit.setPlaceholderText("IP privada del bastión/jump host")
        self.jump_port_spin = QSpinBox(security_card)
        self.jump_port_spin.setRange(1, 65535)
        self.jump_user_edit = QLineEdit(security_card)
        self.key_edit = QLineEdit(security_card)
        self.known_hosts_edit = QLineEdit(security_card)
        ssh_form.addWidget(QLabel("Jump Host", security_card), 0, 0)
        ssh_form.addWidget(self.jump_host_edit, 0, 1)
        ssh_form.addWidget(QLabel("Puerto SSH", security_card), 0, 2)
        ssh_form.addWidget(self.jump_port_spin, 0, 3)
        ssh_form.addWidget(QLabel("Usuario SSH", security_card), 1, 0)
        ssh_form.addWidget(self.jump_user_edit, 1, 1)
        ssh_form.addWidget(QLabel("Clave privada", security_card), 2, 0)
        ssh_form.addWidget(self.key_edit, 2, 1, 1, 2)
        key_button = QPushButton("Seleccionar…", security_card)
        key_button.clicked.connect(self._choose_key)
        ssh_form.addWidget(key_button, 2, 3)
        self.detected_key_combo = QComboBox(security_card)
        self.detected_key_combo.setToolTip("Claves privadas detectadas automáticamente en ~/.ssh")
        use_key = QPushButton("Usar detectada", security_card)
        use_key.setObjectName("GhostButton")
        use_key.clicked.connect(self._use_detected_key)
        ssh_form.addWidget(QLabel("Claves detectadas", security_card), 3, 0)
        ssh_form.addWidget(self.detected_key_combo, 3, 1, 1, 2)
        ssh_form.addWidget(use_key, 3, 3)
        ssh_form.addWidget(QLabel("known_hosts", security_card), 4, 0)
        ssh_form.addWidget(self.known_hosts_edit, 4, 1, 1, 2)
        kh_button = QPushButton("Seleccionar…", security_card)
        kh_button.clicked.connect(self._choose_known_hosts)
        ssh_form.addWidget(kh_button, 4, 3)
        self.detected_known_hosts_combo = QComboBox(security_card)
        self.detected_known_hosts_combo.setToolTip("Archivos known_hosts detectados automáticamente en ~/.ssh")
        use_kh = QPushButton("Usar detectado", security_card)
        use_kh.setObjectName("GhostButton")
        use_kh.clicked.connect(self._use_detected_known_hosts)
        ssh_form.addWidget(QLabel("known_hosts detectados", security_card), 5, 0)
        ssh_form.addWidget(self.detected_known_hosts_combo, 5, 1, 1, 2)
        ssh_form.addWidget(use_kh, 5, 3)
        security_layout.addLayout(ssh_form)

        save_security = QPushButton("Guardar política segura", security_card)
        save_security.setObjectName("PrimaryButton")
        save_security.clicked.connect(self._save_security)
        security_layout.addWidget(save_security, 0, Qt.AlignmentFlag.AlignLeft)
        self.content_layout.addWidget(security_card)
        self.content_layout.addStretch(1)

        self._load_security()
        self.refresh()

    @staticmethod
    def _split_csv(value: str) -> tuple[str, ...]:
        return tuple(part.strip() for part in value.split(",") if part.strip())

    def _load_groups(self) -> None:
        current = str(self.group_combo.currentData() or self.groups.active_group_id)
        self.group_combo.blockSignals(True)
        self.group_combo.clear()
        for group in self.groups.list_groups():
            gid = str(group.get("id") or "")
            self.group_combo.addItem(str(group.get("name") or gid), gid)
            if gid == current:
                self.group_combo.setCurrentIndex(self.group_combo.count() - 1)
        self.group_combo.blockSignals(False)
        self._reload_hosts()

    def _reload_hosts(self, *_args: object) -> None:
        gid = str(self.group_combo.currentData() or self.groups.active_group_id)
        try:
            rows = self.groups.read_sites(gid)
        except Exception as exc:
            show_detailed_message(self, "Acceso remoto", "No se pudo completar la operación de acceso remoto.", f"{type(exc).__name__}: {exc}")
            rows = []
        self.table.setRowCount(0)
        for raw in rows:
            code = str(raw.get("SiteCode") or "")
            settings = self.manager.host_settings(code)
            row = self.table.rowCount()
            self.table.insertRow(row)
            values = (
                code,
                str(raw.get("SiteName") or ""),
                str(raw.get("ServerIP") or ""),
                str(settings.rdp_port),
                "VPN + SSH" if settings.mode == "vpn_ssh_rdp" else "VPN + RDP",
                "Sin probar",
            )
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                if col == self.COL_CODE:
                    item.setData(Qt.ItemDataRole.UserRole, code)
                self.table.setItem(row, col, item)
        self.table.resizeColumnsToContents()
        self._filter_rows(self.search_edit.text())
        self._selected_site = ""
        self.host_label.setText("Seleccione un host")

    def _filter_rows(self, text: str) -> None:
        needle = str(text or "").strip().lower()
        for row in range(self.table.rowCount()):
            haystack = " ".join(str(self.table.item(row, col).text() if self.table.item(row, col) else "") for col in range(3)).lower()
            self.table.setRowHidden(row, bool(needle and needle not in haystack))

    def _selected(self) -> tuple[str, str, str] | None:
        row = self.table.currentRow()
        if row < 0:
            return None
        code = self.table.item(row, self.COL_CODE).text()
        name = self.table.item(row, self.COL_NAME).text()
        host = self.table.item(row, self.COL_HOST).text()
        return code, name, host

    def _selection_changed(self) -> None:
        selected = self._selected()
        if not selected:
            return
        code, name, host = selected
        self._selected_site = code
        self.host_label.setText(f"{code} · {name} · {host}")
        settings = self.manager.host_settings(code)
        self.rdp_port_spin.setValue(settings.rdp_port)
        self.rdp_user_edit.setText(settings.username)
        self.rdp_domain_edit.setText(settings.domain)
        idx = self.mode_combo.findData(settings.mode)
        self.mode_combo.setCurrentIndex(max(0, idx))
        self.fullscreen_check.setChecked(settings.fullscreen)
        self.clipboard_check.setChecked(settings.clipboard)
        self.printers_check.setChecked(settings.printers)
        self.drives_check.setChecked(settings.drives)
        self.smartcards_check.setChecked(settings.smartcards)

    def _current_host_settings(self) -> RemoteHostSettings:
        return RemoteHostSettings(
            rdp_port=self.rdp_port_spin.value(),
            username=self.rdp_user_edit.text().strip(),
            domain=self.rdp_domain_edit.text().strip(),
            mode=str(self.mode_combo.currentData() or "vpn_rdp"),
            fullscreen=self.fullscreen_check.isChecked(),
            clipboard=self.clipboard_check.isChecked(),
            printers=self.printers_check.isChecked(),
            drives=self.drives_check.isChecked(),
            smartcards=self.smartcards_check.isChecked(),
        )

    def _save_host(self) -> None:
        selected = self._selected()
        if not selected:
            QMessageBox.information(self, "Perfil RDP", "Seleccione un host.")
            return
        code, _, _ = selected
        self.manager.save_host_settings(code, self._current_host_settings())
        self.toastRequested.emit("Acceso remoto", f"Perfil {code} guardado", "success")
        self._reload_hosts()

    def _reset_host(self) -> None:
        selected = self._selected()
        if not selected:
            return
        self.manager.clear_host_settings(selected[0])
        self._reload_hosts()
        self.toastRequested.emit("Acceso remoto", f"{selected[0]} usa valores predeterminados", "info")

    def _load_security(self) -> None:
        cfg = self.manager.config()
        self.cidrs_edit.setText(", ".join(cfg.policy.allowed_cidrs))
        self.vpn_patterns_edit.setText(", ".join(cfg.policy.vpn_interface_patterns))
        self.trusted_vpn_edit.setText(", ".join(cfg.policy.trusted_vpn_interfaces))
        self.default_port_spin.setValue(cfg.policy.default_rdp_port)
        self.jump_host_edit.setText(cfg.ssh_tunnel.jump_host)
        self.jump_port_spin.setValue(cfg.ssh_tunnel.jump_port)
        self.jump_user_edit.setText(cfg.ssh_tunnel.username)
        self.key_edit.setText(cfg.ssh_tunnel.private_key)
        self.known_hosts_edit.setText(cfg.ssh_tunnel.known_hosts)

    def _render_detected_security(self, interfaces: object, keys: object, known_hosts: object) -> None:
        interfaces = tuple(interfaces or ())
        self.detected_vpn_combo.blockSignals(True)
        self.detected_vpn_combo.clear()
        active_count = 0
        for item in interfaces:
            active = item.status.casefold() not in {"down", "disabled", "notpresent"}
            if active:
                active_count += 1
            addresses = ", ".join(item.addresses[:3]) or "sin IP"
            candidate = " · VPN detectada" if item.vpn_candidate else ""
            label = f"{item.alias} · {item.description or 'sin descripción'} · {item.status or '-'} · {addresses}{candidate}"
            self.detected_vpn_combo.addItem(label, item.alias)
        self.detected_vpn_combo.blockSignals(False)
        if interfaces:
            vpn_candidates = [x.alias for x in interfaces if x.vpn_candidate]
            self.detected_vpn_note.setText(
                f"{len(interfaces)} interfaces detectadas · {active_count} activas · candidatos VPN: "
                + (", ".join(vpn_candidates) if vpn_candidates else "ninguno por patrón; puede seleccionar una interfaz real y confiarla manualmente")
            )
        else:
            self.detected_vpn_combo.addItem("No se pudieron enumerar interfaces", "")
            self.detected_vpn_note.setText("No se pudieron enumerar interfaces automáticamente. Use el campo manual solo como contingencia.")

        self.detected_key_combo.clear()
        for value in tuple(keys or ()):
            self.detected_key_combo.addItem(value, value)
        if self.detected_key_combo.count() == 0:
            self.detected_key_combo.addItem("No se detectaron claves privadas en ~/.ssh", "")

        self.detected_known_hosts_combo.clear()
        for value in tuple(known_hosts or ()):
            self.detected_known_hosts_combo.addItem(value, value)
        if self.detected_known_hosts_combo.count() == 0:
            self.detected_known_hosts_combo.addItem("No se detectó known_hosts en ~/.ssh", "")

    def _environment_loaded(self, payload: object) -> None:
        data = payload if isinstance(payload, dict) else {}
        error = str(data.get("error") or "")
        if error:
            self.client_chip.setText("Cliente · error de validación")
            self.client_chip.set_kind("warning")
            self.vpn_chip.setText("VPN · validación pendiente")
            self.vpn_chip.set_kind("warning")
            self.vpn_chip.setToolTip(error)
        else:
            status = data.get("client")
            if status is not None:
                self.client_chip.setText(f"{status.client} · {'listo' if status.installed else 'falta'}")
                self.client_chip.set_kind("success" if status.installed else "danger")
                self.client_chip.setToolTip(status.detail)
            vpn = data.get("vpn")
            if vpn is not None and vpn.active:
                self.vpn_chip.setText("VPN · " + ", ".join(vpn.interfaces[:2]))
                self.vpn_chip.set_kind("success")
            else:
                self.vpn_chip.setText("VPN · no detectada")
                self.vpn_chip.set_kind("warning")
            if vpn is not None:
                self.vpn_chip.setToolTip(vpn.detail)
            self._render_detected_security(data.get("interfaces"), data.get("keys"), data.get("known_hosts"))
        if self._environment_worker is not None:
            self._environment_worker.deleteLater()
        self._environment_worker = None

    def _trust_detected_interface(self) -> None:
        alias = str(self.detected_vpn_combo.currentData() or "").strip()
        if not alias:
            QMessageBox.information(self, "VPN", "Seleccione una interfaz detectada válida.")
            return
        values = list(self._split_csv(self.trusted_vpn_edit.text()))
        existing = {x.casefold() for x in values}
        if alias.casefold() not in existing:
            values.append(alias)
        self.trusted_vpn_edit.setText(", ".join(values))
        self.toastRequested.emit("Acceso remoto", f"{alias} agregado como interfaz VPN confiable. Guarde la política para aplicar.", "info")

    def _use_detected_key(self) -> None:
        value = str(self.detected_key_combo.currentData() or "").strip()
        if value:
            self.key_edit.setText(value)

    def _use_detected_known_hosts(self) -> None:
        value = str(self.detected_known_hosts_combo.currentData() or "").strip()
        if value:
            self.known_hosts_edit.setText(value)

    def _save_security(self) -> None:
        cfg = self.manager.config()
        cidrs = self._split_csv(self.cidrs_edit.text())
        patterns = tuple(x.lower() for x in self._split_csv(self.vpn_patterns_edit.text()))
        trusted = tuple(x.lower() for x in self._split_csv(self.trusted_vpn_edit.text()))
        if not cidrs or not patterns:
            QMessageBox.warning(self, "Política VPN", "Debe existir al menos una red privada y un patrón de interfaz VPN.")
            return
        try:
            for cidr in cidrs:
                network = ipaddress.ip_network(cidr, strict=False)
                if not network.is_private:
                    raise ValueError(f"{cidr} no es una red privada")
        except ValueError as exc:
            QMessageBox.warning(self, "Política VPN", f"Red permitida inválida: {exc}")
            return
        policy = SecurityPolicy(
            require_vpn=True,
            require_route_over_vpn=True,
            block_public_targets=True,
            allowed_cidrs=cidrs,
            vpn_interface_patterns=patterns,
            trusted_vpn_interfaces=trusted,
            default_rdp_port=self.default_port_spin.value(),
            connect_timeout_seconds=cfg.policy.connect_timeout_seconds,
        )
        ssh = SshTunnelConfig(
            enabled=True,
            jump_host=self.jump_host_edit.text().strip(),
            jump_port=self.jump_port_spin.value(),
            username=self.jump_user_edit.text().strip(),
            private_key=self.key_edit.text().strip(),
            known_hosts=self.known_hosts_edit.text().strip(),
            strict_host_key_checking=True,
            identities_only=True,
            server_alive_interval=cfg.ssh_tunnel.server_alive_interval,
            server_alive_count_max=cfg.ssh_tunnel.server_alive_count_max,
        )
        defaults = RemoteHostSettings(**{**asdict(cfg.defaults), "rdp_port": self.default_port_spin.value()})
        self.manager.save_policy_and_ssh(policy=policy, ssh_tunnel=ssh, defaults=defaults)
        self.toastRequested.emit("Acceso remoto", "Política VPN/SSH guardada", "success")
        self.refresh()

    def _choose_key(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Seleccionar clave privada OpenSSH", self.key_edit.text() or "", "Todos (*.*)")
        if path:
            self.key_edit.setText(path)

    def _choose_known_hosts(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Seleccionar known_hosts", self.known_hosts_edit.text() or "", "Todos (*.*)")
        if path:
            self.known_hosts_edit.setText(path)

    def _run(self, action: str) -> None:
        selected = self._selected()
        if not selected:
            QMessageBox.information(self, "Acceso remoto", "Seleccione un host de la lista.")
            return
        if self._worker is not None and self._worker.isRunning():
            return
        code, _, host = selected
        row = self.table.currentRow()
        self.table.item(row, self.COL_STATUS).setText("Conectando…" if action == "connect" else "Probando…")
        self._worker = RemoteAccessWorker(self.manager, action, code, host, self)
        self._worker.done.connect(self._operation_done)
        self._worker.finished.connect(self._worker_finished)
        self._worker.start()

    def _test_selected(self) -> None:
        self._run("test")

    def _connect_selected(self) -> None:
        self._run("connect")

    def _operation_done(self, action: str, site_code: str, ok: bool, detail: str) -> None:
        for row in range(self.table.rowCount()):
            if self.table.item(row, self.COL_CODE).text() == site_code:
                self.table.item(row, self.COL_STATUS).setText("OK" if ok else "BLOQUEADO")
                self.table.item(row, self.COL_STATUS).setToolTip(detail)
                break
        if ok:
            self.toastRequested.emit("Acceso remoto", detail, "success" if action == "connect" else "info")
        else:
            show_detailed_message(self, "Acceso remoto seguro", "La validación de acceso remoto requiere atención.", detail, level="warning")

    def _worker_finished(self) -> None:
        if self._worker is not None:
            self._worker.deleteLater()
        self._worker = None

    def refresh(self, *, force: bool = False) -> None:
        # Render cheap local data immediately; external OS probes run in QThread.
        self._load_groups()
        if self._environment_worker is not None and self._environment_worker.isRunning():
            return
        self.client_chip.setText("Cliente · actualizando…")
        self.client_chip.set_kind("neutral")
        self.vpn_chip.setText("VPN · actualizando…")
        self.vpn_chip.set_kind("neutral")
        self._environment_worker = RemoteEnvironmentWorker(self.manager, force=force, parent=self)
        self._environment_worker.done.connect(self._environment_loaded)
        self._environment_worker.start()
