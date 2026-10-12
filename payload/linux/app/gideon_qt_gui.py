from __future__ import annotations

from gideon_common.observability import best_effort_warning

import json
import logging
import os
import sys
import time
import traceback
from pathlib import Path
from typing import Any

try:
    from PySide6.QtCore import Qt, QTimer, QThread, Signal
    from PySide6.QtGui import QCloseEvent, QFont
    from PySide6.QtWidgets import (
        QApplication,
        QFrame,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QInputDialog,
        QMainWindow,
        QMessageBox,
        QPushButton,
        QVBoxLayout,
        QWidget,
    )
except ModuleNotFoundError as exc:  # pragma: no cover - only first-run dependency path
    raise SystemExit(
        "PySide6 no está instalado. Ejecute GIDEON-Remote-Control-v6.bat o: "
        "py -m pip install -r requirements-ui.txt"
    ) from exc

from gideon_agent_catalog import AgentDownloadCatalog
from gideon_bootstrap import ApplicationContainer, build_application
from gideon_host_profiles import HostProfileStore
from gideon_script_library import ScriptLibrary
from gideon_site_groups import SiteGroupStore
from gideon_support_bundle import SupportBundleExporter

from gideon_ui import APP_UI_VERSION, PRODUCT_ACRONYM, PRODUCT_NAME
from gideon_ui.pages.agent_center import AgentCenterPage
from gideon_ui.pages.agent_activity import InstalledAgentsPage
from gideon_ui.refresh import RefreshCoordinator
from gideon_ui.pages.dashboard import DashboardPage
from gideon_ui.pages.execution import ExecutionPage
from gideon_ui.pages.hosts import HostsPage
from gideon_ui.pages.jobs import JobsPage
from gideon_ui.pages.scripts import ScriptsPage
from gideon_ui.pages.settings import SettingsPage
from gideon_ui.pages.remote_access import RemoteAccessPage
from gideon_ui.pages.transfers import TransfersPage
from gideon_ui.services import (
    AppPaths,
    BackgroundCommandRunner,
    LocalEnvironmentService,
    ManifestRepository,
    QtLaunchManager,
)
from gideon_ui.theme import ThemeMode, build_stylesheet
from gideon_ui.tokens import (
    COLORS,
    NAV_COLLAPSED,
    NAV_EXPANDED,
    SPACE_8,
    SPACE_12,
    SPACE_16,
    SPACE_20,
    TOP_BAR_HEIGHT,
)
from gideon_ui.widgets import (
    AnimatedStackedWidget,
    CollapsibleSidebar,
    GideonRxMarkWidget,
    SidebarButton,
    StatusChip,
    ToastManager,
    show_detailed_message,
)


from gideon_version import PRODUCT_VERSION

APP_VERSION: str = PRODUCT_VERSION
APP_ROOT: Path = Path(__file__).resolve().parent
GUI_STARTUP_LOG: Path = APP_ROOT / "logs" / "gui-startup.log"
LOGGER = logging.getLogger(__name__)


def _append_startup_log(message: str) -> None:
    try:
        GUI_STARTUP_LOG.parent.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with GUI_STARTUP_LOG.open("a", encoding="utf-8") as handle:
            handle.write(f"[{stamp}] {message.rstrip()}\n")
    except Exception:
        # This is the last-resort crash logger. Never mask the original error.
        return


def _native_startup_error(detail: str) -> None:
    _append_startup_log("GUI_STARTUP_FAILED\n" + detail)
    message = (
        "Gideon Rx no pudo abrir la interfaz gráfica.\n\n"
        + detail[-2600:]
        + f"\n\nLog completo: {GUI_STARTUP_LOG}"
    )
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, message, "Gideon Rx · Error de inicio", 0x10)
            return
        except Exception as exc:
            best_effort_warning("No se pudo mostrar el MessageBox nativo de error de inicio", exc)
    try:
        print(message, file=sys.stderr)
    except Exception as exc:
        best_effort_warning("No se pudo escribir el error de inicio en stderr", exc)


def _python_exe() -> str:
    executable = Path(sys.executable)
    if executable.name.lower() == "pythonw.exe":
        candidate = executable.with_name("python.exe")
        if candidate.exists():
            return str(candidate)
    return str(executable)


def _load_config() -> dict[str, Any]:
    path = APP_ROOT / "config" / "config.json"
    return json.loads(path.read_text(encoding="utf-8-sig"))


class EnvironmentStatusWorker(QThread):
    """Probes SSH/runtime state without ever blocking Qt's event loop."""

    finished_data: Signal = Signal(object)

    def __init__(self, environment: LocalEnvironmentService, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.environment = environment

    def run(self) -> None:
        self.finished_data.emit({
            "clients": self.environment.transport_clients(),
            "key_loaded": self.environment.key_loaded(),
            "key_available": self.environment.key_available(),
        })


class SshKeyLoadWorker(QThread):
    """Validates the configured SSH key without mutating host ssh-agent state."""

    finished_data: Signal = Signal(object)

    def __init__(
        self,
        environment: LocalEnvironmentService,
        passphrase: str | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.environment = environment
        self.passphrase = passphrase

    def run(self) -> None:
        try:
            payload = self.environment.load_key(self.passphrase)
        except Exception as exc:
            payload = {
                "ok": False,
                "needs_passphrase": False,
                "detail": f"{type(exc).__name__}: {exc}",
                "key_path": str(self.environment.key_path),
                "fingerprint": "",
            }
        finally:
            # Do not keep the passphrase alive in the worker object.
            self.passphrase = None
        self.finished_data.emit(payload)


class GideonMainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        # Startup must be paint-first. Gateway TLS/network/bootstrap runs lazily
        # inside the Gateway page worker instead of blocking construction here.
        self.cfg: dict[str, Any] = _load_config()
        self.paths = AppPaths.from_config(APP_ROOT, self.cfg)
        self.paths.ensure()
        self._ui_state_path = self.paths.logs.parent / "ui-v6-state.json"
        self._theme = self._load_theme()

        self.groups = SiteGroupStore(APP_ROOT / "config", APP_ROOT / "config" / "sites.csv")
        self.host_profiles = HostProfileStore(APP_ROOT / "config" / "host_profiles.json")
        self.script_library = ScriptLibrary(APP_ROOT / "scripts")
        self.manifests = ManifestRepository(self.paths.jobs)
        self.environment = LocalEnvironmentService(self.paths.key_path)
        self._environment_worker: EnvironmentStatusWorker | None = None
        self._ssh_key_worker: SshKeyLoadWorker | None = None

        self.application: ApplicationContainer = build_application(
            app_root=APP_ROOT,
            cfg=self.cfg,
            jobs_dir=self.paths.jobs,
            logs_dir=self.paths.logs,
            transfer_jobs_dir=self.paths.transfer_jobs,
            python_exe=_python_exe(),
            version=APP_VERSION,
            key_path=self.paths.key_path,
            known_hosts=self.paths.known_hosts,
        )
        self.launcher = QtLaunchManager(
            app_root=APP_ROOT,
            launch_port=self.application.script_launch,
            parent=self,
        )
        self.command_runner = BackgroundCommandRunner(APP_ROOT, self)
        self.support_exporter = SupportBundleExporter(
            app_root=APP_ROOT,
            jobs_dir=self.paths.jobs,
            gui_logs_dir=self.paths.logs,
            results_dir=self.paths.results,
            raw_dir=self.paths.raw,
            packages_dir=self.paths.packages,
            config_path=self.paths.config,
        )
        self.agent_catalog = AgentDownloadCatalog(APP_ROOT)

        self.setWindowTitle(f"{PRODUCT_ACRONYM} · {PRODUCT_NAME} · v{APP_VERSION}")
        self.setMinimumSize(1100, 720)
        self.resize(1560, 930)
        self._page_refresh_at: dict[str, float] = {}
        self._page_refresh_ttl: dict[str, float] = {
            "dashboard": 3.0, "jobs": 2.0, "hosts": 5.0, "scripts": 15.0,
            "execution": 10.0, "agents": 5.0, "infrastructure": 5.0,
            "remote_access": 15.0, "settings": 30.0, "transfers": 10.0,
        }
        self._current_page_key = "dashboard"
        self._ssh_runtime_text = "OpenSSH · verificando"
        self._ssh_runtime_kind = "neutral"
        self._build_ui()
        self._wire_events()
        self.refresh_coordinator = RefreshCoordinator(self)
        self._configure_refresh_coordinator()
        self.apply_theme(self._theme)
        self.navigate("dashboard")

        self.environment_timer = QTimer(self)
        self.environment_timer.setInterval(15000)
        self.environment_timer.timeout.connect(self._refresh_environment)
        self.environment_timer.start()
        self._refresh_environment()

    def _load_theme(self) -> ThemeMode:
        try:
            raw = json.loads(self._ui_state_path.read_text(encoding="utf-8"))
            return ThemeMode(str(raw.get("theme") or ThemeMode.LIGHT.value))
        except Exception as exc:
            LOGGER.debug("No se pudo cargar el estado visual: %s", exc)
            return ThemeMode.LIGHT

    def _save_state(self) -> None:
        try:
            self._ui_state_path.parent.mkdir(parents=True, exist_ok=True)
            self._ui_state_path.write_text(
                json.dumps({"theme": self._theme.value}, indent=2),
                encoding="utf-8",
            )
        except Exception as exc:
            LOGGER.warning("No se pudo guardar el estado visual: %s", exc)

    def _build_ui(self) -> None:
        root = QWidget(self)
        root.setObjectName("AppRoot")
        self.setCentralWidget(root)
        layout = QHBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.sidebar = CollapsibleSidebar(root)
        side_layout = QVBoxLayout(self.sidebar)
        side_layout.setContentsMargins(SPACE_8, SPACE_12, SPACE_8, SPACE_12)
        side_layout.setSpacing(6)
        brand = QHBoxLayout()
        brand.setSpacing(SPACE_8)
        brand.addWidget(GideonRxMarkWidget(self.sidebar, 42))
        brand_text = QVBoxLayout()
        brand_text.setSpacing(1)
        self.brand_title = QLabel(PRODUCT_ACRONYM, self.sidebar)
        self.brand_title.setObjectName("BrandTitle")
        self.brand_subtitle = QLabel(PRODUCT_NAME, self.sidebar)
        self.brand_subtitle.setObjectName("BrandSubTitle")
        brand_text.addWidget(self.brand_title)
        brand_text.addWidget(self.brand_subtitle)
        brand.addLayout(brand_text, 1)
        side_layout.addLayout(brand)
        side_layout.addSpacing(14)
        self.sidebar.bind_brand(self.brand_title, self.brand_subtitle)

        self.nav_buttons: dict[str, SidebarButton] = {}
        icon_dir = APP_ROOT / "assets" / "icons"
        nav_items = (
            ("dashboard", "Inicio", str(icon_dir / "home.svg")),
            ("execution", "Nueva ejecución", str(icon_dir / "play.svg")),
            ("jobs", "Ejecuciones", str(icon_dir / "jobs.svg")),
            ("hosts", "Hosts y grupos", str(icon_dir / "hosts.svg")),
            ("scripts", "Biblioteca", str(icon_dir / "scripts.svg")),
            ("transfers", "Archivos y video", str(icon_dir / "files.svg")),
            ("agents", "Agentes", str(icon_dir / "agents.svg")),
            ("infrastructure", "Infraestructura", str(icon_dir / "infrastructure.svg")),
            ("remote_access", "Acceso remoto", str(icon_dir / "remote.svg")),
            ("settings", "Configuración", str(icon_dir / "settings.svg")),
        )
        for key, label, glyph in nav_items:
            button = SidebarButton(label, glyph, self.sidebar)
            button.clicked.connect(lambda _checked=False, name=key: self.navigate(name))
            self.sidebar.register_button(button)
            self.nav_buttons[key] = button
            side_layout.addWidget(button)
        side_layout.addStretch(1)
        footer = QLabel(f"Sistemas · v{APP_UI_VERSION} · Qt6", self.sidebar)
        footer.setObjectName("SidebarFooter")
        side_layout.addWidget(footer)
        layout.addWidget(self.sidebar)

        right = QWidget(root)
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)
        layout.addWidget(right, 1)

        top = QWidget(right)
        top.setObjectName("TopBar")
        top.setFixedHeight(TOP_BAR_HEIGHT)
        top_layout = QHBoxLayout(top)
        top_layout.setContentsMargins(SPACE_16, SPACE_8, SPACE_20, SPACE_8)
        top_layout.setSpacing(SPACE_12)
        burger = QPushButton("☰", top)
        burger.setObjectName("GhostButton")
        burger.setFixedWidth(40)
        burger.clicked.connect(self.sidebar.toggle)
        top_layout.addWidget(burger)
        self.breadcrumb = QLabel("Inicio", top)
        self.breadcrumb.setStyleSheet("font-size:12pt; font-weight:600;")
        top_layout.addWidget(self.breadcrumb)
        top_layout.addStretch(1)
        self.runtime_chip = StatusChip("LOCAL", "info", top)
        top_layout.addWidget(self.runtime_chip)
        self.key_chip = StatusChip("SSH · verificando", "neutral", top)
        top_layout.addWidget(self.key_chip)
        self.key_button = QPushButton("Validar clave SSH", top)
        self.key_button.clicked.connect(self._begin_ssh_key_load)
        top_layout.addWidget(self.key_button)
        right_layout.addWidget(top)

        self.pages = AnimatedStackedWidget(right)
        right_layout.addWidget(self.pages, 1)

        self.dashboard_page = DashboardPage(
            manifests=self.manifests,
            groups=self.groups,
            parent=self.pages,
        )
        self.execution_page = ExecutionPage(
            groups=self.groups,
            library=self.script_library,
            registry=self.application.controller.script_registry,
            profiles=self.host_profiles,
            environment=self.environment,
            launcher=self.launcher,
            config=self.cfg,
            parent=self.pages,
        )
        self.jobs_page = JobsPage(
            manifests=self.manifests,
            paths=self.paths,
            command_runner=self.command_runner,
            support_exporter=self.support_exporter,
            auto_refresh=False,
            parent=self.pages,
        )
        self.hosts_page = HostsPage(
            groups=self.groups,
            manifests=self.manifests,
            host_profiles=self.host_profiles,
            parent=self.pages,
        )
        self.scripts_page = ScriptsPage(
            library=self.script_library,
            registry=self.application.controller.script_registry,
            parent=self.pages,
        )
        self.transfers_page = TransfersPage(
            controller=self.application.controller,
            groups=self.groups,
            profiles=self.host_profiles,
            default_remote_dir=str((self.cfg.get("file_transfer") or {}).get("default_remote_dir") or r"C:\ProgramData\GIDEONFiles"),
            config=self.cfg,
            parent=self.pages,
        )
        self.agents_page = AgentCenterPage(
            app_root=APP_ROOT,
            config=self.cfg,
            catalog=self.agent_catalog,
            gateway_url=str((self.cfg.get("agent_control_plane") or {}).get("base_url") or ""),
            parent=self.pages,
        )
        self.infrastructure_page = InstalledAgentsPage(
            config=self.cfg,
            gateway_only=True,
            parent=self.pages,
        )
        self.remote_access_page = RemoteAccessPage(
            app_root=APP_ROOT,
            groups=self.groups,
            known_hosts=self.paths.known_hosts,
            default_key=self.paths.key_path,
            parent=self.pages,
        )
        self.settings_page = SettingsPage(paths=self.paths, parent=self.pages)
        self.settings_page.set_theme(self._theme)

        self.page_map: dict[str, tuple[int, str]] = {}
        page_defs = (
            ("dashboard", self.dashboard_page, "Inicio"),
            ("execution", self.execution_page, "Nueva ejecución"),
            ("jobs", self.jobs_page, "Ejecuciones"),
            ("hosts", self.hosts_page, "Hosts y grupos"),
            ("scripts", self.scripts_page, "Biblioteca de scripts"),
            ("transfers", self.transfers_page, "Archivos y video"),
            ("agents", self.agents_page, "Agentes"),
            ("infrastructure", self.infrastructure_page, "Infraestructura · Gateway"),
            ("remote_access", self.remote_access_page, "Acceso remoto seguro"),
            ("settings", self.settings_page, "Configuración"),
        )
        for key, page, title in page_defs:
            index = self.pages.addWidget(page)
            self.page_map[key] = (index, title)

        # Constructors load their initial local state. Mark it fresh so the first
        # sidebar click does not immediately repeat expensive probes/build scans.
        stamp = time.monotonic()
        self._page_refresh_at = {key: stamp for key in self.page_map}

        self.toasts = ToastManager(root)
        self.toasts.reposition()

    def _wire_events(self) -> None:
        self.dashboard_page.newExecutionRequested.connect(lambda: self.navigate("execution"))
        self.dashboard_page.jobsRequested.connect(lambda: self.navigate("jobs"))
        self.execution_page.jobLaunched.connect(self._job_launched)
        self.execution_page.toastRequested.connect(self.toasts.show_toast)
        self.jobs_page.toastRequested.connect(self.toasts.show_toast)
        self.transfers_page.toastRequested.connect(self.toasts.show_toast)
        self.agents_page.toastRequested.connect(self.toasts.show_toast)
        self.remote_access_page.toastRequested.connect(self.toasts.show_toast)
        self.remote_access_page.manageListsRequested.connect(lambda: self.navigate("hosts"))
        self.remote_access_page.settingsRequested.connect(lambda: self.navigate("settings"))
        self.hosts_page.groupChanged.connect(self._group_changed)
        self.scripts_page.libraryChanged.connect(self.execution_page._load_scripts)
        self.settings_page.themeChanged.connect(self._theme_changed)
        self.settings_page.refreshChanged.connect(self._refresh_interval_changed)
        self.infrastructure_page.settingsRequested.connect(lambda: self.navigate("settings"))
        self.agents_page.executeRequested.connect(self._open_agent_execution)
        self.agents_page.transferRequested.connect(self._open_agent_transfer)
        self.agents_page.diagnoseRequested.connect(self._open_agent_diagnostics)

        self.launcher.jobStarted.connect(
            lambda job_id, pid: self.toasts.show_toast(
                "Backend iniciado", f"{job_id} · PID {pid}", "info", 3200
            )
        )
        self.launcher.jobTransitioned.connect(self._job_transitioned)
        self.launcher.jobFailed.connect(self._job_failed)
        self.launcher.logMessage.connect(
            lambda message: self.statusBar().showMessage(message, 5000)
        )

    def _configure_refresh_coordinator(self) -> None:
        refreshers: dict[str, tuple[object, float]] = {
            "dashboard": (self.dashboard_page.refresh, 3.0),
            "execution": (self.execution_page.reload, 10.0),
            "jobs": (self.jobs_page.refresh, 2.0),
            "hosts": (self.hosts_page.reload, 5.0),
            "scripts": (self.scripts_page.reload, 15.0),
            "transfers": (self.transfers_page.destination_selector.reload, 10.0),
            "agents": (self.agents_page.reload, 5.0),
            "infrastructure": (self.infrastructure_page.refresh, 5.0),
            "remote_access": (self.remote_access_page.refresh, 15.0),
        }
        for key, (callback, interval) in refreshers.items():
            self.refresh_coordinator.register(key, callback, interval)  # type: ignore[arg-type]
            self.refresh_coordinator.mark_fresh(key)

    def navigate(self, key: str) -> None:
        if key not in self.page_map:
            return
        index, title = self.page_map[key]
        self._current_page_key = key
        self.pages.setCurrentIndexAnimated(index)
        self.breadcrumb.setText(title)
        for name, button in self.nav_buttons.items():
            button.setChecked(name == key)
        self._update_topbar_context(key)
        self.refresh_coordinator.set_active(key)
        # Cambiar de página nunca debe bloquear el pintado. El coordinador
        # ejecuta solo la vista visible y respeta su TTL.
        QTimer.singleShot(25, lambda expected=key: self._refresh_page_if_stale(expected))

    def _refresh_page_if_stale(self, key: str, *, force: bool = False) -> None:
        if key not in self.page_map or self._current_page_key != key:
            return
        now = time.monotonic()
        ttl = float(self._page_refresh_ttl.get(key, 5.0))
        if not force and now - float(self._page_refresh_at.get(key, 0.0)) < ttl:
            return
        self._page_refresh_at[key] = now
        self.refresh_coordinator.run_now(key)

    def _update_topbar_context(self, key: str) -> None:
        ssh_context = key in {"execution", "transfers", "hosts", "remote_access"}
        self.key_chip.setVisible(ssh_context)
        self.key_button.setVisible(ssh_context)
        if key == "agents":
            self.runtime_chip.setText("AGENT · HTTPS/PULL")
            self.runtime_chip.set_kind("success")
        elif key == "infrastructure":
            self.runtime_chip.setText("GATEWAY · HTTPS")
            self.runtime_chip.set_kind("info")
        elif ssh_context:
            self.runtime_chip.setText(self._ssh_runtime_text)
            self.runtime_chip.set_kind(self._ssh_runtime_kind)
        else:
            self.runtime_chip.setText("LOCAL")
            self.runtime_chip.set_kind("info")

    def _select_agent_destination(self, page: object, agent_id: str) -> None:
        selector = getattr(page, "destination_selector", None)
        if selector is None:
            return
        search = getattr(selector, "search_edit", None) or getattr(selector, "search", None)
        if search is not None:
            search.setText(agent_id)
        selector.pull_gateway_agents()

    def _open_agent_execution(self, agent_id: str) -> None:
        self.navigate("execution")
        self._select_agent_destination(self.execution_page, agent_id)
        self.execution_page._goto_step(1)

    def _open_agent_transfer(self, agent_id: str) -> None:
        self.navigate("transfers")
        self._select_agent_destination(self.transfers_page, agent_id)

    def _open_agent_diagnostics(self, agent_id: str) -> None:
        self.navigate("execution")
        self._select_agent_destination(self.execution_page, agent_id)
        self.execution_page._load_scripts()
        preferred = None
        for row in self.execution_page.script_model.rows:
            haystack = " ".join(str(row.get(k) or "") for k in ("id", "name", "path")).lower()
            if "service_inventory" in haystack or "diagnostic" in haystack or "diagnost" in haystack:
                preferred = str(row.get("id") or "")
                break
        if preferred:
            self.execution_page.script_model.selected_ids = {preferred}
            self.execution_page.script_model.layoutChanged.emit()
            self.execution_page.script_search.setText("")
            self.toasts.show_toast("Diagnóstico preparado", "Revise el script y confirme la ejecución sobre el Agent seleccionado.", "info", 4500)
        else:
            self.execution_page.script_search.setText("diagn")
            self.toasts.show_toast("Diagnóstico", "No encontré un script de diagnóstico predeterminado; seleccione uno de la biblioteca.", "warning", 5000)
        self.execution_page._goto_step(1)

    def _job_launched(self, job_id: str) -> None:
        self.navigate("jobs")
        self.jobs_page.refresh()
        self.jobs_page.select_job(job_id)

    def _job_transitioned(self, job_id: str, status: str) -> None:
        self.toasts.show_toast("Job en ejecución", f"{job_id} · {status}", "success")
        self.jobs_page.refresh()
        self.jobs_page.select_job(job_id)
        self.dashboard_page.refresh()

    def _job_failed(self, job_id: str, detail: str) -> None:
        self.toasts.show_toast("Job no iniciado", f"{job_id} · {detail[:220]}", "danger", 7000)
        self.jobs_page.refresh()
        self.jobs_page.select_job(job_id)
        show_detailed_message(
            self,
            "Job no iniciado",
            "El backend finalizó antes de iniciar el Dispatch. Puede copiar el diagnóstico completo con “Copiar todo”.",
            detail,
            level="error",
        )

    def _group_changed(self, _group_id: str) -> None:
        self.execution_page.destination_selector.refresh_groups()
        self.transfers_page.destination_selector.refresh_groups()
        self.dashboard_page.refresh()

    def _theme_changed(self, mode: str) -> None:
        try:
            self.apply_theme(ThemeMode(mode))
        except ValueError:
            return

    def apply_theme(self, mode: ThemeMode) -> None:
        self._theme = mode
        app = QApplication.instance()
        if app is not None:
            app.setStyleSheet(build_stylesheet(mode))
        self.settings_page.set_theme(mode)
        self._save_state()

    def _refresh_interval_changed(self, seconds: int) -> None:
        interval = max(1, int(seconds))
        # Un solo coordinador controla los refrescos; Jobs ya no mantiene un
        # timer paralelo que reconstruya la misma vista dos veces.
        for key in ("dashboard", "jobs", "hosts"):
            self.refresh_coordinator.set_interval(key, float(interval))

    def _begin_ssh_key_load(self, passphrase: str | None = None) -> None:
        if self._ssh_key_worker is not None and self._ssh_key_worker.isRunning():
            return
        self.key_button.setEnabled(False)
        self.key_button.setText("Validando clave…")
        worker = SshKeyLoadWorker(self.environment, passphrase, self)
        self._ssh_key_worker = worker
        worker.finished_data.connect(self._ssh_key_load_finished)
        worker.start()

    def _ssh_key_load_finished(self, payload: object) -> None:
        data = payload if isinstance(payload, dict) else {}
        worker = self._ssh_key_worker
        if worker is not None:
            worker.deleteLater()
        self._ssh_key_worker = None

        if bool(data.get("needs_passphrase")):
            passphrase, accepted = QInputDialog.getText(
                self,
                "Validar clave SSH",
                "La clave configurada requiere passphrase para validación.\n"
                "Se usa solo para este intento y no se guarda:",
                QLineEdit.EchoMode.Password,
            )
            if accepted:
                self._begin_ssh_key_load(str(passphrase))
                # Drop the local Python reference as soon as the worker copied it.
                passphrase = ""
                return
            self.key_button.setEnabled(True)
            self.key_button.setText("Validar clave SSH")
            self.toasts.show_toast(
                "Validación SSH cancelada",
                "La passphrase no se guardó ni se modificó la configuración.",
                "info",
                4200,
            )
            self._refresh_environment()
            return

        self.key_button.setEnabled(True)
        self.key_button.setText("Validar clave SSH")
        detail = str(data.get("detail") or "Sin detalle")
        key_path = str(data.get("key_path") or self.environment.key_path)
        fingerprint = str(data.get("fingerprint") or "")
        diagnostic = f"Clave: {key_path}\n"
        if fingerprint:
            diagnostic += f"Fingerprint: {fingerprint}\n"
        diagnostic += f"Resultado: {detail}"

        if bool(data.get("ok")):
            self.toasts.show_toast(
                "Clave SSH validada",
                fingerprint or "La identidad configurada fue validada sin modificar ssh-agent.",
                "success",
                5000,
            )
        else:
            show_detailed_message(
                self,
                "No se pudo validar la clave SSH",
                "La validación no se completó. Puede copiar el diagnóstico completo.",
                diagnostic,
                level="error",
            )
        self._refresh_environment()

    def _refresh_environment(self) -> None:
        if self._environment_worker is not None and self._environment_worker.isRunning():
            return
        worker = EnvironmentStatusWorker(self.environment, self)
        self._environment_worker = worker
        worker.finished_data.connect(self._environment_refreshed)
        worker.start()

    def _environment_refreshed(self, payload: object) -> None:
        data = payload if isinstance(payload, dict) else {}
        clients = data.get("clients") if isinstance(data.get("clients"), dict) else {}
        key_loaded = bool(data.get("key_loaded"))
        key_available = bool(data.get("key_available"))
        if key_loaded:
            self.key_chip.setText("SSH · CLAVE EXTERNA")
            self.key_chip.set_kind("success")
        elif key_available:
            self.key_chip.setText("SSH · IDENTIDAD GIDEON")
            self.key_chip.set_kind("success")
        else:
            self.key_chip.setText("SSH · CLAVE PENDIENTE")
            self.key_chip.set_kind("warning")
        available = sum(1 for value in clients.values() if value)
        self._ssh_runtime_text = f"OpenSSH {available}/3"
        self._ssh_runtime_kind = "success" if available == 3 else "warning"
        self._update_topbar_context(self._current_page_key)
        if self._environment_worker is not None:
            self._environment_worker.deleteLater()
        self._environment_worker = None

    def resizeEvent(self, event: object) -> None:  # noqa: N802
        super().resizeEvent(event)  # type: ignore[arg-type]
        compact = self.width() < 1180
        if compact and not self.sidebar.collapsed:
            self.sidebar.set_collapsed(True)
        elif self.width() > 1380 and self.sidebar.collapsed:
            self.sidebar.set_collapsed(False)
        self.dashboard_page.set_compact(compact)
        self.toasts.reposition()

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802
        local_busy = (
            (self.transfers_page.worker is not None and self.transfers_page.worker.isRunning())
            or (self.agents_page.installers_page._build_worker is not None and self.agents_page.installers_page._build_worker.isRunning())
            or (self.jobs_page._support_worker is not None and self.jobs_page._support_worker.isRunning())
        )
        if local_busy:
            QMessageBox.information(
                self,
                "Operación local en curso",
                "Hay una transferencia/exportación/generación local en curso. "
                "Espere a que termine antes de cerrar la interfaz.",
            )
            event.ignore()
            return
        # Avoid destroying a QThread object while an read-only SSH identity probe is finishing.
        if self._environment_worker is not None and self._environment_worker.isRunning():
            self._environment_worker.wait(3500)
        self._save_state()
        # Los controladores Python lanzados son procesos desacoplados; cerrar la
        # UI no cancela Jobs remotos ni corta la recuperación LAN/VPN.
        event.accept()




def _ensure_elevated() -> bool:
    """Solicita UAC una sola vez en Windows; otros SO continúan normalmente."""
    if os.name != "nt":
        return True
    try:
        import ctypes

        if bool(ctypes.windll.shell32.IsUserAnAdmin()):
            return True

        script = str(Path(__file__).resolve())
        executable = Path(sys.executable)
        pythonw = executable.with_name("pythonw.exe")
        runner = str(pythonw if pythonw.exists() else executable)
        params = f'"{script}" --uac-launched'
        result = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", runner, params, str(APP_ROOT), 1
        )
        if int(result) <= 32:
            try:
                ctypes.windll.user32.MessageBoxW(
                    None,
                    "Gideon Rx requiere permisos de Administrador local.",
                    "Gideon Rx",
                    0x10,
                )
            except Exception as exc:
                best_effort_warning("No se pudo mostrar el MessageBox de elevación UAC", exc)
        # El proceso actual siempre sale tras solicitar UAC; solo la nueva
        # instancia elevada continúa.
        return False
    except Exception:
        return True


def main() -> int:
    if not _ensure_elevated():
        return 0
    try:
        _append_startup_log(f"GUI_STARTING v{APP_VERSION} · python={sys.version.split()[0]} · exe={sys.executable}")
        QApplication.setHighDpiScaleFactorRoundingPolicy(
            Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
        )
        app = QApplication(sys.argv)
        app.setApplicationName("Gideon Rx")
        app.setOrganizationName("Gideon Rx Project")
        app.setFont(QFont("Segoe UI", 10))
        app.setStyle("Fusion")
        window = GideonMainWindow()
        window.show()
        _append_startup_log("GUI_READY")
        return app.exec()
    except Exception:
        detail = traceback.format_exc()
        _native_startup_error(detail)
        return 10


if __name__ == "__main__":
    raise SystemExit(main())
