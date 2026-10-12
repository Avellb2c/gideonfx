from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QThread, Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QFileDialog,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from gideon_dependency_manager import DependencyStatus, SystemDependencyManager
from gideon_platform import detect_platform
from gideon_branding import BrandingRepository
from gideon_packaging.signing import WindowsCodeSigningService

from ..services import AppPaths
from ..theme import ThemeMode
from ..tokens import COLORS, SPACE_8, SPACE_12, SPACE_16
from ..widgets import PageHeader, StatusChip, show_detailed_message
from .base import ScrollPage


class DependencyScanWorker(QThread):
    finished_scan: Signal = Signal(object)
    failed: Signal = Signal(str)

    def __init__(self, manager: SystemDependencyManager, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.manager = manager

    def run(self) -> None:
        try:
            self.finished_scan.emit(self.manager.scan())
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class DependencyInstallWorker(QThread):
    finished_install: Signal = Signal(str, bool, str)

    def __init__(self, manager: SystemDependencyManager, key: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.manager = manager
        self.key = key

    def run(self) -> None:
        ok, output = self.manager.install_dependency(self.key)
        self.finished_install.emit(self.key, ok, output)


class SettingsPage(ScrollPage):
    themeChanged: Signal = Signal(str)
    refreshChanged: Signal = Signal(int)

    def __init__(self, *, paths: AppPaths, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.paths = paths
        self.dependency_manager = SystemDependencyManager(paths.root)
        self.branding_repository = BrandingRepository(paths.root)
        self.platform_profile = detect_platform()
        self._scan_worker: DependencyScanWorker | None = None
        self._install_worker: DependencyInstallWorker | None = None
        self._dependency_rows: list[DependencyStatus] = []

        header = PageHeader(
            "Configuración",
            f"Perfil adaptativo: {self.platform_profile.label}. Los requisitos cambian automáticamente según sistema operativo, distribución y módulo.",
            self.content,
        )
        self.content_layout.addWidget(header)

        # ---- Validador completo del sistema --------------------------------
        dependency_card = QFrame(self.content)
        dependency_card.setObjectName("Card")
        dependency_layout = QVBoxLayout(dependency_card)
        dependency_layout.setContentsMargins(SPACE_16, SPACE_16, SPACE_16, SPACE_16)
        dependency_layout.setSpacing(SPACE_12)

        dependency_head = QHBoxLayout()
        dependency_title = QLabel("Requisitos y dependencias del sistema", dependency_card)
        dependency_title.setObjectName("SectionTitle")
        dependency_head.addWidget(dependency_title)
        dependency_head.addStretch(1)
        self.platform_chip = StatusChip(self.platform_profile.label, "info", dependency_card)
        dependency_head.addWidget(self.platform_chip)
        self.dependency_status = StatusChip("Sin validar", "neutral", dependency_card)
        dependency_head.addWidget(self.dependency_status)
        self.scan_button = QPushButton("↻ Validar todo", dependency_card)
        self.scan_button.setObjectName("GhostButton")
        self.scan_button.clicked.connect(self.scan_dependencies)
        dependency_head.addWidget(self.scan_button)
        self.install_all_button = QPushButton("Instalar faltantes", dependency_card)
        self.install_all_button.setObjectName("PrimaryButton")
        self.install_all_button.clicked.connect(self.install_missing)
        dependency_head.addWidget(self.install_all_button)
        dependency_layout.addLayout(dependency_head)

        remote_client = "MSTSC" if self.platform_profile.family == "windows" else "Remmina + RDP"
        description = QLabel(
            f"Perfil activo: {self.platform_profile.label}. Valida únicamente componentes aplicables a este host: Runtime Qt/Python, Gateway HTTP/HTTPS, TLS/OpenSSL, SQLite, "
            f"acceso remoto seguro ({remote_client}), ruta VPN, OpenSSH y toolchains de empaquetado compatibles. "
            "PowerShell, WSL y comprobaciones auxiliares se ejecutan en segundo plano sin ventanas de consola. El Gateway no requiere PHP, Apache ni IIS.",
            dependency_card,
        )
        description.setWordWrap(True)
        description.setObjectName("Muted")
        dependency_layout.addWidget(description)

        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Módulo / categoría", dependency_card))
        self.dependency_filter = QComboBox(dependency_card)
        self.dependency_filter.addItem("Todos los módulos", "*")
        self.dependency_filter.currentIndexChanged.connect(self._render_dependencies)
        filter_row.addWidget(self.dependency_filter)
        filter_row.addStretch(1)
        dependency_layout.addLayout(filter_row)

        self.dependency_table = QTableWidget(0, 6, dependency_card)
        self.dependency_table.setHorizontalHeaderLabels(
            ("Dependencia", "Categoría", "Necesaria para", "Estado", "Versión / detalle", "Acción")
        )
        self.dependency_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.dependency_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.dependency_table.setAlternatingRowColors(True)
        self.dependency_table.verticalHeader().setVisible(False)
        self.dependency_table.horizontalHeader().setStretchLastSection(True)
        self.dependency_table.setMinimumHeight(360)
        dependency_layout.addWidget(self.dependency_table)
        self.content_layout.addWidget(dependency_card)

        # ---- Marca blanca + firma ----------------------------------------
        branding_card = QFrame(self.content)
        branding_card.setObjectName("Card")
        branding_layout = QVBoxLayout(branding_card)
        branding_layout.setContentsMargins(SPACE_16, SPACE_16, SPACE_16, SPACE_16)
        branding_layout.setSpacing(SPACE_12)
        branding_head = QHBoxLayout()
        branding_title = QLabel("Marca blanca y firma de distribución", branding_card)
        branding_title.setObjectName("SectionTitle")
        branding_head.addWidget(branding_title)
        branding_head.addStretch(1)
        self.branding_status = StatusChip("Gideon Rx Project", "info", branding_card)
        branding_head.addWidget(self.branding_status)
        branding_layout.addLayout(branding_head)

        brand_note = QLabel(
            "Los metadatos identifican el producto, pero Windows no confía en un EXE solo por el nombre de empresa. "
            "Para un Publisher confiable configure una firma Authenticode con certificado de firma de código emitido a la empresa. "
            "La clave privada/PFX nunca se incrusta en el proyecto y la contraseña solo se lee desde una variable de entorno.",
            branding_card,
        )
        brand_note.setWordWrap(True)
        brand_note.setObjectName("Muted")
        branding_layout.addWidget(brand_note)

        brand_form = QFormLayout()
        self.brand_company = QLineEdit(branding_card)
        self.brand_publisher = QLineEdit(branding_card)
        self.brand_product = QLineEdit(branding_card)
        self.brand_agent_product = QLineEdit(branding_card)
        self.brand_description = QLineEdit(branding_card)
        self.brand_website = QLineEdit(branding_card)
        self.brand_support = QLineEdit(branding_card)
        self.brand_bundle_id = QLineEdit(branding_card)
        self.brand_basename = QLineEdit(branding_card)
        self.brand_icon = QLineEdit(branding_card)
        brand_form.addRow("Empresa", self.brand_company)
        brand_form.addRow("Editor / Publisher esperado", self.brand_publisher)
        brand_form.addRow("Producto", self.brand_product)
        brand_form.addRow("Nombre del agente", self.brand_agent_product)
        brand_form.addRow("Descripción", self.brand_description)
        brand_form.addRow("Sitio web (opcional)", self.brand_website)
        brand_form.addRow("Soporte (opcional)", self.brand_support)
        brand_form.addRow("Bundle ID macOS", self.brand_bundle_id)
        brand_form.addRow("Nombre base del paquete", self.brand_basename)
        icon_row = QHBoxLayout()
        icon_row.addWidget(self.brand_icon, 1)
        browse_icon = QPushButton("Seleccionar…", branding_card)
        browse_icon.setObjectName("GhostButton")
        browse_icon.clicked.connect(self._browse_brand_icon)
        icon_row.addWidget(browse_icon)
        brand_form.addRow("Icono", icon_row)
        branding_layout.addLayout(brand_form)

        sign_title = QLabel("Firma Authenticode (Windows)", branding_card)
        sign_title.setObjectName("SectionTitle")
        branding_layout.addWidget(sign_title)
        sign_form = QFormLayout()
        self.sign_mode = QComboBox(branding_card)
        self.sign_mode.addItem("Opcional · compilar aunque falte certificado", "optional")
        self.sign_mode.addItem("Obligatoria · bloquear release sin firma", "required")
        self.sign_mode.addItem("Deshabilitada", "disabled")
        self.sign_provider = QComboBox(branding_card)
        self.sign_provider.addItem("Automático (almacén o PFX)", "auto")
        self.sign_provider.addItem("Certificado del almacén Windows", "store")
        self.sign_provider.addItem("Archivo PFX", "pfx")
        self.sign_thumbprint = QLineEdit(branding_card)
        self.sign_pfx = QLineEdit(branding_card)
        self.sign_timestamp = QLineEdit(branding_card)
        self.sign_expected = QLineEdit(branding_card)
        sign_form.addRow("Política", self.sign_mode)
        sign_form.addRow("Proveedor", self.sign_provider)
        sign_form.addRow("Thumbprint certificado", self.sign_thumbprint)
        pfx_row = QHBoxLayout()
        pfx_row.addWidget(self.sign_pfx, 1)
        browse_pfx = QPushButton("Seleccionar PFX…", branding_card)
        browse_pfx.setObjectName("GhostButton")
        browse_pfx.clicked.connect(self._browse_signing_pfx)
        pfx_row.addWidget(browse_pfx)
        sign_form.addRow("PFX (ruta, sin contraseña)", pfx_row)
        sign_form.addRow("Servidor timestamp RFC3161", self.sign_timestamp)
        sign_form.addRow("Publisher esperado", self.sign_expected)
        branding_layout.addLayout(sign_form)
        password_hint = QLabel(
            "Contraseña PFX: defina GIDEON_SIGNING_PFX_PASSWORD en el entorno del proceso de compilación. "
            "No se guarda en branding.json. Para mayor seguridad se recomienda certificado no exportable en el almacén Windows/EV.",
            branding_card,
        )
        password_hint.setWordWrap(True)
        password_hint.setObjectName("Muted")
        branding_layout.addWidget(password_hint)
        brand_actions = QHBoxLayout()
        save_brand = QPushButton("Guardar marca y firma", branding_card)
        save_brand.setObjectName("PrimaryButton")
        save_brand.clicked.connect(self._save_branding)
        brand_actions.addWidget(save_brand)
        validate_sign = QPushButton("Validar firma Windows", branding_card)
        validate_sign.setObjectName("GhostButton")
        validate_sign.clicked.connect(self._validate_signing)
        brand_actions.addWidget(validate_sign)
        brand_actions.addStretch(1)
        branding_layout.addLayout(brand_actions)
        self.content_layout.addWidget(branding_card)
        self._load_branding()

        appearance = QFrame(self.content)
        appearance.setObjectName("Card")
        layout = QVBoxLayout(appearance)
        layout.setContentsMargins(SPACE_16, SPACE_16, SPACE_16, SPACE_16)
        title = QLabel("Apariencia y actualización", appearance)
        title.setObjectName("SectionTitle")
        layout.addWidget(title)
        form = QFormLayout()
        self.theme_combo = QComboBox(appearance)
        self.theme_combo.addItem("Claro", ThemeMode.LIGHT.value)
        self.theme_combo.addItem("Oscuro", ThemeMode.DARK.value)
        self.theme_combo.currentIndexChanged.connect(
            lambda: self.themeChanged.emit(str(self.theme_combo.currentData()))
        )
        form.addRow("Tema", self.theme_combo)
        self.refresh_spin = QComboBox(appearance)
        self.refresh_spin.addItems(["1 s", "2 s", "5 s", "10 s", "30 s"])
        self.refresh_spin.setCurrentIndex(1)
        self.refresh_spin.currentIndexChanged.connect(lambda i: self.refreshChanged.emit([1, 2, 5, 10, 30][i]))
        form.addRow("Refresh local", self.refresh_spin)
        layout.addLayout(form)
        self.content_layout.addWidget(appearance)

        architecture = QFrame(self.content)
        architecture.setObjectName("Card")
        arch_layout = QVBoxLayout(architecture)
        arch_layout.setContentsMargins(SPACE_16, SPACE_16, SPACE_16, SPACE_16)
        arch_title = QLabel("Arquitectura", architecture)
        arch_title.setObjectName("SectionTitle")
        arch_layout.addWidget(arch_title)
        arch_layout.addWidget(StatusChip("SOLID · DI · PySide6 / Qt6 · Multi-Transport", "info", architecture))
        details = QLabel(
            "La capa Qt consume los mismos Application Services y adapters. "
            "El validador de dependencias es independiente del motor de ejecución y no modifica credenciales ni secretos.",
            architecture,
        )
        details.setWordWrap(True)
        details.setObjectName("Muted")
        arch_layout.addWidget(details)
        self.content_layout.addWidget(architecture)

        paths_card = QFrame(self.content)
        paths_card.setObjectName("Card")
        paths_layout = QVBoxLayout(paths_card)
        paths_layout.setContentsMargins(SPACE_16, SPACE_16, SPACE_16, SPACE_16)
        paths_title = QLabel("Rutas locales", paths_card)
        paths_title.setObjectName("SectionTitle")
        paths_layout.addWidget(paths_title)
        for name, path in (
            ("Jobs", paths.jobs),
            ("Logs", paths.logs),
            ("Resultados", paths.results),
            ("Raw", paths.raw),
            ("Transfer Jobs", paths.transfer_jobs),
            ("Known Hosts", paths.known_hosts),
        ):
            label = QLabel(f"{name}\n{Path(path)}", paths_card)
            label.setObjectName("Muted")
            label.setWordWrap(True)
            paths_layout.addWidget(label)
        self.content_layout.addWidget(paths_card)
        self.content_layout.addStretch(1)
        self.scan_dependencies()

    def _load_branding(self) -> None:
        brand = self.branding_repository.load()
        self.brand_company.setText(brand.company_name)
        self.brand_publisher.setText(brand.publisher_name)
        self.brand_product.setText(brand.product_name)
        self.brand_agent_product.setText(brand.agent_product_name)
        self.brand_description.setText(brand.product_description)
        self.brand_website.setText(brand.website_url)
        self.brand_support.setText(brand.support_url)
        self.brand_bundle_id.setText(brand.bundle_id)
        self.brand_basename.setText(brand.agent_package_basename)
        self.brand_icon.setText(brand.icon_path)
        idx = self.sign_mode.findData(brand.signing.mode)
        if idx >= 0: self.sign_mode.setCurrentIndex(idx)
        idx = self.sign_provider.findData(brand.signing.provider)
        if idx >= 0: self.sign_provider.setCurrentIndex(idx)
        self.sign_thumbprint.setText(brand.signing.certificate_thumbprint)
        self.sign_pfx.setText(brand.signing.pfx_path)
        self.sign_timestamp.setText(brand.signing.timestamp_url)
        self.sign_expected.setText(brand.signing.expected_publisher)
        self.branding_status.setText(brand.company_name)

    def _browse_brand_icon(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Seleccionar icono", str(self.paths.root), "Iconos (*.ico *.png);;Todos (*.*)")
        if path: self.brand_icon.setText(path)

    def _browse_signing_pfx(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Seleccionar certificado PFX", str(self.paths.root), "Certificado PFX/P12 (*.pfx *.p12);;Todos (*.*)")
        if path: self.sign_pfx.setText(path)

    def _save_branding(self) -> None:
        try:
            brand = self.branding_repository.save({
                "company_name": self.brand_company.text().strip(),
                "publisher_name": self.brand_publisher.text().strip(),
                "product_name": self.brand_product.text().strip(),
                "agent_product_name": self.brand_agent_product.text().strip(),
                "product_description": self.brand_description.text().strip(),
                "agent_description": self.brand_description.text().strip(),
                "website_url": self.brand_website.text().strip(),
                "support_url": self.brand_support.text().strip(),
                "bundle_id": self.brand_bundle_id.text().strip(),
                "agent_package_basename": self.brand_basename.text().strip(),
                "icon_path": self.brand_icon.text().strip(),
                "signing": {
                    "mode": str(self.sign_mode.currentData() or "optional"),
                    "provider": str(self.sign_provider.currentData() or "auto"),
                    "certificate_thumbprint": self.sign_thumbprint.text().strip(),
                    "pfx_path": self.sign_pfx.text().strip(),
                    "timestamp_url": self.sign_timestamp.text().strip(),
                    "expected_publisher": self.sign_expected.text().strip() or self.brand_publisher.text().strip(),
                    "digest_algorithm": "sha256",
                    "verify_after_sign": True,
                },
            })
            self.branding_status.setText(brand.company_name)
            self.branding_status.set_kind("success")
            QMessageBox.information(self, "Marca blanca", "Configuración guardada. Se aplicará a las próximas compilaciones nativas.")
            self.scan_dependencies()
        except Exception as exc:
            show_detailed_message(self, "Marca blanca", "No se pudo guardar la configuración.", f"{type(exc).__name__}: {exc}")

    def _validate_signing(self) -> None:
        brand = self.branding_repository.load()
        result = WindowsCodeSigningService().readiness(brand, self.paths.root)
        ok = result.status in {"ready", "disabled"}
        title = "Firma Windows lista" if ok else "Firma Windows requiere atención"
        text = result.detail
        if result.tool: text += f"\n\nSignTool: {result.tool}"
        if brand.signing.mode == "optional" and not ok:
            text += "\n\nEl build puede continuar sin firma porque la política es Opcional, pero Windows puede mostrar Publisher desconocido/SmartScreen."
        (QMessageBox.information if ok else QMessageBox.warning)(self, title, text)

    def set_theme(self, mode: ThemeMode) -> None:
        index = self.theme_combo.findData(mode.value)
        if index >= 0:
            self.theme_combo.blockSignals(True)
            self.theme_combo.setCurrentIndex(index)
            self.theme_combo.blockSignals(False)

    def scan_dependencies(self) -> None:
        if self._scan_worker is not None and self._scan_worker.isRunning():
            return
        self.scan_button.setEnabled(False)
        self.dependency_status.setText("Validando…")
        self.dependency_status.set_kind("info")
        self._scan_worker = DependencyScanWorker(self.dependency_manager, self)
        self._scan_worker.finished_scan.connect(self._scan_finished)
        self._scan_worker.failed.connect(self._scan_failed)
        self._scan_worker.start()

    def _scan_finished(self, rows: object) -> None:
        self._dependency_rows = list(rows) if isinstance(rows, list) else []
        current = str(self.dependency_filter.currentData() or "*")
        categories = sorted({dep.category for dep in self._dependency_rows})
        self.dependency_filter.blockSignals(True)
        self.dependency_filter.clear()
        self.dependency_filter.addItem("Todos los módulos", "*")
        for category in categories:
            self.dependency_filter.addItem(category, category)
        index = self.dependency_filter.findData(current)
        self.dependency_filter.setCurrentIndex(index if index >= 0 else 0)
        self.dependency_filter.blockSignals(False)
        self._render_dependencies()
        self.scan_button.setEnabled(True)
        self._scan_worker = None

    def _scan_failed(self, detail: str) -> None:
        self.scan_button.setEnabled(True)
        self.dependency_status.setText("Error")
        self.dependency_status.set_kind("danger")
        show_detailed_message(self, "Validador de dependencias", "La validación de dependencias terminó con error.", detail)
        self._scan_worker = None

    def _render_dependencies(self) -> None:
        self.dependency_table.setRowCount(0)
        missing = 0
        selected = str(self.dependency_filter.currentData() or "*")
        visible = [dep for dep in self._dependency_rows if selected == "*" or dep.category == selected]
        for dep in visible:
            row = self.dependency_table.rowCount()
            self.dependency_table.insertRow(row)
            values = (
                dep.name,
                dep.category,
                dep.required_for,
                "INSTALADO" if dep.installed else "FALTA",
                dep.version or dep.detail or "-",
            )
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                if col == 3:
                    item.setData(Qt.ItemDataRole.UserRole, dep.installed)
                item.setToolTip(dep.detail or dep.version or value)
                self.dependency_table.setItem(row, col, item)
            action = QPushButton("Reparar" if not dep.installed else "Validar", self.dependency_table)
            action.setObjectName("GhostButton")
            action.setEnabled(not dep.installed and dep.installable)
            if not dep.installed:
                missing += 1
                action.clicked.connect(lambda _checked=False, key=dep.key: self.install_one(key))
            else:
                action.clicked.connect(self.scan_dependencies)
            self.dependency_table.setCellWidget(row, 5, action)

        self.dependency_table.resizeColumnsToContents()
        if missing:
            self.dependency_status.setText(f"Faltan {missing} dependencia(s)")
            self.dependency_status.set_kind("danger")
        else:
            self.dependency_status.setText("Sistema listo")
            self.dependency_status.set_kind("success")

    def install_one(self, key: str) -> None:
        if self._install_worker is not None and self._install_worker.isRunning():
            return
        self.install_all_button.setEnabled(False)
        self.scan_button.setEnabled(False)
        self.dependency_status.setText("Instalando…")
        self.dependency_status.set_kind("info")
        self._install_worker = DependencyInstallWorker(self.dependency_manager, key, self)
        self._install_worker.finished_install.connect(self._install_finished)
        self._install_worker.start()

    def install_missing(self) -> None:
        missing = [dep for dep in self._dependency_rows if not dep.installed and dep.installable]
        if not missing:
            QMessageBox.information(self, "Dependencias", "No hay dependencias instalables pendientes.")
            return
        # Instala secuencialmente para respetar dependencias del sistema y del módulo seleccionado.
        self._install_queue = [dep.key for dep in missing]
        self._install_next()

    def _install_next(self) -> None:
        queue = getattr(self, "_install_queue", [])
        if not queue:
            self.install_all_button.setEnabled(True)
            self.scan_button.setEnabled(True)
            self.scan_dependencies()
            return
        self.install_one(queue.pop(0))

    def _install_finished(self, key: str, ok: bool, output: str) -> None:
        self._install_worker = None
        queue = getattr(self, "_install_queue", [])
        if not ok:
            self.install_all_button.setEnabled(True)
            self.scan_button.setEnabled(True)
            show_detailed_message(
                self,
                f"No se pudo instalar {key}",
                "El instalador terminó con error. El detalle completo puede copiarse con “Copiar todo”.",
                output or "El instalador terminó con error sin salida adicional.",
            )
            self.scan_dependencies()
            return
        if queue:
            self._install_queue = queue
            self._install_next()
        else:
            self.install_all_button.setEnabled(True)
            self.scan_button.setEnabled(True)
            self.scan_dependencies()
