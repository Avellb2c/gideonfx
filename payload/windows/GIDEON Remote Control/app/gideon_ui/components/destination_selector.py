from __future__ import annotations

import datetime as dt
import os
from pathlib import Path
from typing import Any

from PySide6.QtCore import QModelIndex, QSortFilterProxyModel, QThread, Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableView,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from gideon_agent_http import AgentHttpClient
from gideon_agent_runtime import agent_gateway_connection_label, merged_agent_control_plane
from gideon_domain import HostTarget
from gideon_host_profiles import HostProfileStore
from gideon_site_groups import SiteGroupStore

from ..models import HostRow, HostTableModel
from ..tokens import SPACE_8, SPACE_12
from ..widgets import show_detailed_message


GATEWAY_GROUP_ID = "__gateway_agents_live__"


def bool_or_none(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    if text in {"1", "true", "yes", "si", "sí", "online", "activo"}:
        return True
    if text in {"0", "false", "no", "offline", "inactivo"}:
        return False
    return None


def agent_online(row: dict[str, Any], ttl_seconds: int) -> bool:
    value = row.get("last_seen") or row.get("LastSeen")
    if not value:
        return False
    try:
        stamp = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        now = dt.datetime.now(stamp.tzinfo) if stamp.tzinfo else dt.datetime.now()
        return (now - stamp).total_seconds() <= max(1, int(ttl_seconds))
    except (TypeError, ValueError):
        return False


class HostFilterProxyModel(QSortFilterProxyModel):
    """One filter implementation shared by execution and file transfer pages."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.search_text = ""
        self.status_filter = "all"
        self.platform_filter = "all"
        self.profile_filter = "all"
        self.setDynamicSortFilter(True)
        self.setSortCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)

    def set_filters(self, *, search: str, status: str, platform: str, profile: str) -> None:
        self.search_text = str(search or "").strip().lower()
        self.status_filter = str(status or "all")
        self.platform_filter = str(platform or "all").lower()
        self.profile_filter = str(profile or "all")
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:  # noqa: N802
        model = self.sourceModel()
        if not isinstance(model, HostTableModel) or not (0 <= source_row < len(model.rows)):
            return False
        row = model.rows[source_row]
        if self.search_text:
            haystack = " ".join((
                row.target.code,
                row.target.name,
                row.target.address,
                row.target.platform,
                row.target.host_profile,
                row.agent_id,
                row.agent_name,
                row.hostname,
                row.state,
                row.source,
                row.last_seen,
                row.connection_display,
                row.agent_remote_ip,
                row.agentless_address,
            )).lower()
            if self.search_text not in haystack:
                return False
        if self.status_filter == "online" and row.agent_online is not True:
            return False
        if self.status_filter == "offline" and row.agent_online is not False:
            return False
        if self.status_filter == "unknown" and row.agent_online is not None:
            return False
        if self.platform_filter != "all" and row.target.platform.lower() != self.platform_filter:
            return False
        if self.profile_filter != "all" and row.target.host_profile != self.profile_filter:
            return False
        return True


class GatewayAgentsWorker(QThread):
    loaded: Signal = Signal(object)
    failed: Signal = Signal(str)

    def __init__(self, *, config: dict[str, Any], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.config = config

    def run(self) -> None:
        try:
            cfg = merged_agent_control_plane(self.config)
            base = str(cfg.get("base_url") or cfg.get("public_url") or "").strip().rstrip("/")
            env_name = str(cfg.get("admin_api_key_env") or "GIDEON_AGENT_ADMIN_TOKEN")
            token = str(os.environ.get(env_name, "") or cfg.get("admin_api_key") or "")
            if not base:
                raise RuntimeError("No hay Gateway configurado en agent_control_plane.base_url.")
            if not token:
                raise RuntimeError("No hay credencial administrativa para consultar el Gateway.")
            client = AgentHttpClient(
                base,
                bearer_token=token,
                verify_tls=bool(cfg.get("verify_tls", True)),
                ca_file=cfg.get("ca_file"),
                require_https=bool(cfg.get("require_https", True)),
            )
            self.loaded.emit(client.json("GET", "/api/v1/admin/agents", timeout=10))
        except Exception as exc:  # network boundary: preserve complete type + message
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class DestinationSelectorWidget(QFrame):
    """Canonical destination picker used by all remote operations.

    It owns group selection, live Gateway inventory, search/filter/sort, selection
    actions and persisted deployment groups.  Pages consume selected HostRow
    objects and no longer duplicate Agent identity/routing rules.
    """

    toastRequested: Signal = Signal(str, str, str)
    selectionChanged: Signal = Signal()
    gatewayAgentsLoaded: Signal = Signal(int)
    groupChanged: Signal = Signal(str)

    def __init__(
        self,
        *,
        groups: SiteGroupStore,
        profiles: HostProfileStore,
        config: dict[str, Any],
        group_context: str,
        min_table_height: int = 340,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("Card")
        self.groups = groups
        self.profiles = profiles
        self.config = dict(config or {})
        self.group_context = str(group_context or "despliegue")
        self.host_model = HostTableModel()
        self.host_proxy = HostFilterProxyModel(self)
        self.host_proxy.setSourceModel(self.host_model)
        self._gateway_worker: GatewayAgentsWorker | None = None
        self._gateway_rows: list[dict[str, Any]] = []
        self.current_inventory_path: Path = self.groups.inventory_path()
        self.current_group_id = self.groups.active_group_id
        self.current_group_name = str(self.groups.get(self.current_group_id).get("name") or self.current_group_id)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(SPACE_12, SPACE_12, SPACE_12, SPACE_12)
        layout.setSpacing(SPACE_8)

        source_row = QHBoxLayout()
        self.group_combo = QComboBox(self)
        self.group_combo.setMinimumWidth(280)
        self.group_combo.currentIndexChanged.connect(self._group_changed)
        source_row.addWidget(self.group_combo, 1)
        self.pull_agents_button = QPushButton("↻ Actualizar agentes", self)
        self.pull_agents_button.setToolTip("Consulta el Gateway HTTPS y carga Agents por AgentId. La IP observada es solo telemetría.")
        self.pull_agents_button.clicked.connect(self.pull_gateway_agents)
        source_row.addWidget(self.pull_agents_button)
        self.save_group_button = QPushButton("Guardar grupo…", self)
        self.save_group_button.clicked.connect(self.save_selection_as_group)
        source_row.addWidget(self.save_group_button)
        layout.addLayout(source_row)

        search_row = QHBoxLayout()
        self.search = QLineEdit(self)
        # Stable public alias used by navigation helpers and older page code.
        self.search_edit = self.search
        self.search.setPlaceholderText("Buscar sede, código, equipo, AgentId, IP alternativa o perfil…")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self._filters_changed)
        search_row.addWidget(self.search, 1)

        self.agent_status_filter = QComboBox(self)
        self.agent_status_filter.addItem("Todos los estados", "all")
        self.agent_status_filter.addItem("Agentes activos", "online")
        self.agent_status_filter.addItem("Agentes inactivos", "offline")
        self.agent_status_filter.addItem("Sin telemetría", "unknown")
        self.agent_status_filter.currentIndexChanged.connect(self._filters_changed)
        search_row.addWidget(self.agent_status_filter)

        self.more_filters_button = QToolButton(self)
        self.more_filters_button.setText("Más filtros ▾")
        self.more_filters_button.setCheckable(True)
        self.more_filters_button.setToolTip("Mostrar/ocultar plataforma, perfil y orden.")
        self.more_filters_button.toggled.connect(self._toggle_more_filters)
        search_row.addWidget(self.more_filters_button)
        layout.addLayout(search_row)

        self.more_filters = QWidget(self)
        more_row = QHBoxLayout(self.more_filters)
        more_row.setContentsMargins(0, 0, 0, 0)
        more_row.addStretch(1)
        self.platform_filter = QComboBox(self.more_filters)
        self.platform_filter.addItem("Todas las plataformas", "all")
        self.platform_filter.currentIndexChanged.connect(self._filters_changed)
        more_row.addWidget(self.platform_filter)
        self.profile_filter = QComboBox(self.more_filters)
        self.profile_filter.addItem("Todos los perfiles", "all")
        self.profile_filter.currentIndexChanged.connect(self._filters_changed)
        more_row.addWidget(self.profile_filter)
        self.sort_combo = QComboBox(self.more_filters)
        self.sort_combo.addItem("Orden: del grupo", (-1, Qt.SortOrder.AscendingOrder))
        self.sort_combo.addItem("Código ↑", (1, Qt.SortOrder.AscendingOrder))
        self.sort_combo.addItem("Sede ↑", (2, Qt.SortOrder.AscendingOrder))
        self.sort_combo.addItem("Equipo ↑", (3, Qt.SortOrder.AscendingOrder))
        self.sort_combo.addItem("Plataforma ↑", (6, Qt.SortOrder.AscendingOrder))
        self.sort_combo.addItem("Estado ↑", (8, Qt.SortOrder.AscendingOrder))
        self.sort_combo.addItem("Última conexión ↓", (10, Qt.SortOrder.DescendingOrder))
        self.sort_combo.currentIndexChanged.connect(self._apply_sort)
        more_row.addWidget(self.sort_combo)
        self.more_filters.hide()
        layout.addWidget(self.more_filters)

        selection_row = QHBoxLayout()
        self.host_summary = QLabel("-", self)
        self.host_summary.setObjectName("Muted")
        selection_row.addWidget(self.host_summary, 1)
        self.selection_button = QToolButton(self)
        self.selection_button.setText("Seleccionar ▾")
        self.selection_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        # QToolButton has no addMenu; attach a small menu explicitly.
        from PySide6.QtWidgets import QMenu
        selection_menu = QMenu(self.selection_button)
        selection_menu.addAction("Solo visibles", lambda: self.select_visible(selected=True))
        selection_menu.addAction("Ninguno", lambda: self.host_model.select_all(False))
        selection_menu.addAction("Invertir visibles", lambda: self.select_visible(invert=True))
        self.selection_button.setMenu(selection_menu)
        selection_row.addWidget(self.selection_button)
        layout.addLayout(selection_row)

        self.host_table = QTableView(self)
        self.host_table.setModel(self.host_proxy)
        self.host_table.setAlternatingRowColors(True)
        self.host_table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.host_table.setSortingEnabled(True)
        self.host_table.verticalHeader().setVisible(False)
        self.host_table.setMinimumHeight(min_table_height)
        self.host_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.host_table, 1)

        self.host_model.dataChanged.connect(lambda *_args: self._selection_changed())
        self.host_model.modelReset.connect(self._selection_changed)
        self.refresh_groups()

    @staticmethod
    def row_has_agent(row: HostRow) -> bool:
        return bool(
            row.agent_id.strip()
            or row.agent_name.strip()
            or row.hostname.strip()
            or row.connection_display.strip()
            or row.source.startswith("gateway")
        )

    def _toggle_more_filters(self, visible: bool) -> None:
        self.more_filters.setVisible(bool(visible))
        self.more_filters_button.setText("Menos filtros ▴" if visible else "Más filtros ▾")

    def reload(self) -> None:
        self.refresh_groups()
        group_id = str(self.group_combo.currentData() or self.groups.active_group_id)
        if group_id == GATEWAY_GROUP_ID:
            if self._gateway_rows:
                self.load_hosts(group_id=GATEWAY_GROUP_ID, sites=self._gateway_rows)
            else:
                self.pull_gateway_agents()
        else:
            self.load_hosts(group_id=group_id)

    def refresh_groups(self, preferred_group_id: str | None = None) -> None:
        current = preferred_group_id or str(self.group_combo.currentData() or self.current_group_id or self.groups.active_group_id)
        self.group_combo.blockSignals(True)
        self.group_combo.clear()
        self.group_combo.addItem("⚡ Agentes del Gateway · en vivo", GATEWAY_GROUP_ID)
        selected_index = -1
        for row in self.groups.list_groups():
            group_id = str(row.get("id") or "")
            self.group_combo.addItem(str(row.get("name") or group_id), group_id)
            if group_id == current:
                selected_index = self.group_combo.count() - 1
        if current == GATEWAY_GROUP_ID:
            selected_index = 0
        if selected_index < 0:
            selected_index = max(0, self.group_combo.findData(self.groups.active_group_id))
        self.group_combo.setCurrentIndex(selected_index)
        self.group_combo.blockSignals(False)

    def _group_changed(self, *_args: object) -> None:
        group_id = str(self.group_combo.currentData() or "")
        if group_id == GATEWAY_GROUP_ID:
            self.pull_gateway_agents()
            return
        if not group_id:
            return
        try:
            self.groups.set_active(group_id)
        except Exception as exc:
            self.toastRequested.emit("Grupo no disponible", str(exc), "danger")
            return
        self.load_hosts(group_id=group_id)
        self.groupChanged.emit(group_id)

    def load_hosts(self, *, group_id: str | None = None, sites: list[dict[str, Any]] | None = None) -> None:
        rows: list[HostRow] = []
        requested_group = str(group_id or self.groups.active_group_id)
        if sites is None:
            try:
                sites = self.groups.read_sites(requested_group)
                group = self.groups.get(requested_group)
                self.current_inventory_path = self.groups.inventory_path(requested_group)
                self.current_group_id = requested_group
                self.current_group_name = str(group.get("name") or requested_group)
            except (KeyError, OSError, ValueError):
                sites = []
        else:
            sites = [dict(site) for site in sites]

        for site in sites:
            code = str(site.get("SiteCode") or "").strip()
            if not code:
                continue
            profile_meta = str(site.get("HostProfile") or "").strip()
            platform_meta = str(site.get("Platform") or "").strip().lower()
            try:
                profile = self.profiles.resolve(code)
                platform = platform_meta or str(profile.get("platform") or "windows")
                profile_id = profile_meta or str(profile.get("id") or "windows_generic")
            except (KeyError, OSError, ValueError):
                platform = platform_meta or "windows"
                profile_id = profile_meta or "windows_generic"
            online = bool_or_none(site.get("AgentOnline"))
            last_seen = str(site.get("LastSeen") or "").strip()
            source = str(site.get("Source") or "inventory").strip() or "inventory"
            agent_id = str(site.get("AgentId") or site.get("AgentID") or "").strip()
            agent_name = str(site.get("AgentName") or "").strip()
            hostname = str(site.get("Hostname") or "").strip()
            connection_display = str(site.get("AgentConnection") or "").strip()
            agent_remote_ip = str(site.get("AgentRemoteIP") or "").strip()
            server_ip = str(site.get("ServerIP") or "").strip()
            agentless_address = str(site.get("AgentlessIP") or "").strip()
            has_agent_identity = bool(agent_id or agent_name or hostname or connection_display or source.startswith("gateway"))
            if has_agent_identity:
                # Legacy inventories can keep the old server address only as an
                # Agentless fallback.  It is never the Agent HTTPS/PULL target.
                agentless_address = agentless_address or server_ip
                server_ip = ""
                connection_display = connection_display or agent_gateway_connection_label(
                    self.config, observed_ip=agent_remote_ip
                )
            if online is True:
                state = "Agente activo"
            elif online is False:
                state = "Agente inactivo"
            else:
                state = "Sin telemetría" if has_agent_identity else "Sin datos"
            rows.append(HostRow(
                target=HostTarget(
                    code=code,
                    name=str(site.get("SiteName") or ""),
                    address=server_ip,
                    platform=platform,
                    host_profile=profile_id,
                    agent_id=agent_id,
                    agent_name=agent_name,
                    hostname=hostname,
                ),
                selected=True,
                state=state,
                updated_at=last_seen or "-",
                source=source,
                agent_id=agent_id,
                agent_name=agent_name,
                hostname=hostname,
                agent_online=online,
                last_seen=last_seen,
                connection_display=connection_display,
                agent_remote_ip=agent_remote_ip,
                agentless_address=agentless_address,
            ))
        self.host_model.set_rows(rows)
        self._refresh_host_filter_options()
        self._filters_changed()
        self._apply_sort()
        self.host_table.resizeColumnsToContents()
        self._update_host_summary()

    def _refresh_host_filter_options(self) -> None:
        platform_value = str(self.platform_filter.currentData() or "all")
        profile_value = str(self.profile_filter.currentData() or "all")
        platforms = sorted({row.target.platform.lower() for row in self.host_model.rows if row.target.platform})
        profiles = sorted({row.target.host_profile for row in self.host_model.rows if row.target.host_profile})

        self.platform_filter.blockSignals(True)
        self.platform_filter.clear()
        self.platform_filter.addItem("Todas las plataformas", "all")
        for platform in platforms:
            self.platform_filter.addItem(platform.upper(), platform)
        idx = self.platform_filter.findData(platform_value)
        self.platform_filter.setCurrentIndex(idx if idx >= 0 else 0)
        self.platform_filter.blockSignals(False)

        self.profile_filter.blockSignals(True)
        self.profile_filter.clear()
        self.profile_filter.addItem("Todos los perfiles", "all")
        for profile in profiles:
            self.profile_filter.addItem(profile, profile)
        idx = self.profile_filter.findData(profile_value)
        self.profile_filter.setCurrentIndex(idx if idx >= 0 else 0)
        self.profile_filter.blockSignals(False)

    def _filters_changed(self, *_args: object) -> None:
        self.host_proxy.set_filters(
            search=self.search.text(),
            status=str(self.agent_status_filter.currentData() or "all"),
            platform=str(self.platform_filter.currentData() or "all"),
            profile=str(self.profile_filter.currentData() or "all"),
        )
        self._update_host_summary()

    def _apply_sort(self, *_args: object) -> None:
        data = self.sort_combo.currentData()
        if isinstance(data, (tuple, list)) and len(data) == 2:
            try:
                self.host_proxy.sort(int(data[0]), data[1])
            except (TypeError, ValueError):
                self.host_proxy.sort(-1, Qt.SortOrder.AscendingOrder)
        else:
            self.host_proxy.sort(-1, Qt.SortOrder.AscendingOrder)
        self._update_host_summary()

    def visible_source_rows(self) -> list[int]:
        rows: list[int] = []
        for proxy_row in range(self.host_proxy.rowCount()):
            source_index = self.host_proxy.mapToSource(self.host_proxy.index(proxy_row, 0))
            if source_index.isValid():
                rows.append(source_index.row())
        return rows

    def select_visible(self, *, selected: bool | None = None, invert: bool = False) -> None:
        visible = self.visible_source_rows()
        if selected is True and not invert:
            self.host_model.select_all(False)
            self.host_model.set_rows_selection(visible, selected=True)
        else:
            self.host_model.set_rows_selection(visible, selected=selected, invert=invert)
        self._selection_changed()

    def _selection_changed(self) -> None:
        self._update_host_summary()
        self.selectionChanged.emit()

    def _update_host_summary(self) -> None:
        total = len(self.host_model.rows)
        visible = self.host_proxy.rowCount()
        selected = len(self.host_model.selected_targets())
        online = sum(1 for row in self.host_model.rows if row.agent_online is True)
        offline = sum(1 for row in self.host_model.rows if row.agent_online is False)
        telemetry = f" · {online} activos · {offline} inactivos" if online or offline else ""
        self.host_summary.setText(
            f"{visible} visibles de {total} · {selected} seleccionados{telemetry} · {self.current_group_name}"
        )

    def pull_gateway_agents(self, *_args: object) -> None:
        if self._gateway_worker is not None and self._gateway_worker.isRunning():
            return
        special_index = self.group_combo.findData(GATEWAY_GROUP_ID)
        if special_index >= 0 and self.group_combo.currentIndex() != special_index:
            self.group_combo.blockSignals(True)
            self.group_combo.setCurrentIndex(special_index)
            self.group_combo.blockSignals(False)
        self.current_group_id = GATEWAY_GROUP_ID
        self.current_group_name = "Agentes del Gateway · en vivo"
        self.pull_agents_button.setEnabled(False)
        self.pull_agents_button.setText("Consultando…")
        self.host_summary.setText("Consultando agentes enrolados en el Gateway…")
        worker = GatewayAgentsWorker(config=self.config, parent=self)
        self._gateway_worker = worker
        worker.loaded.connect(self._gateway_agents_loaded)
        worker.failed.connect(self._gateway_agents_failed)
        worker.finished.connect(self._gateway_worker_finished)
        worker.start()

    def _gateway_worker_finished(self) -> None:
        self._gateway_worker = None

    def _known_addresses(self) -> dict[str, str]:
        """Resolve Agentless IP without assuming SiteCode uniquely identifies a PC.

        AgentId/hostname win. A site-level fallback is emitted only when every
        known row for that site points to the same address; otherwise it stays
        blank so a multi-PC site can never be sent to the wrong server by SSH.
        """
        result: dict[str, str] = {}
        site_candidates: dict[str, set[str]] = {}
        for group in self.groups.list_groups():
            group_id = str(group.get("id") or "")
            try:
                for site in self.groups.read_sites(group_id):
                    code = str(site.get("SiteCode") or "").strip()
                    agent_id = str(site.get("AgentId") or site.get("AgentID") or "").strip().lower()
                    hostname = str(site.get("Hostname") or "").strip().lower()
                    address = str(site.get("AgentlessIP") or site.get("ServerIP") or "").strip()
                    if not address:
                        continue
                    if agent_id:
                        result[f"agent:{agent_id}"] = address
                    if hostname:
                        result[f"host:{hostname}"] = address
                    if code:
                        site_candidates.setdefault(code, set()).add(address)
            except (KeyError, OSError, ValueError):
                continue
        for code, addresses in site_candidates.items():
            if len(addresses) == 1:
                result[f"site:{code}"] = next(iter(addresses))
        return result

    def _gateway_agents_loaded(self, payload: object) -> None:
        data = payload if isinstance(payload, dict) else {}
        raw_rows = [dict(row) for row in (data.get("Agents") or []) if isinstance(row, dict)]
        ttl = int((self.config.get("agent_control_plane") or {}).get("agent_online_ttl_seconds", 90))
        known = self._known_addresses()
        dedup: dict[str, dict[str, Any]] = {}
        for row in raw_rows:
            code = str(row.get("site_code") or "").strip()
            if not code:
                continue
            agent_id = str(row.get("agent_id") or row.get("AgentId") or "").strip()
            name = str(row.get("site_name") or code).strip()
            agent_name = str(row.get("agent_name") or row.get("hostname") or "").strip()
            hostname = str(row.get("hostname") or "").strip()
            identity = agent_id or f"legacy:{code}:{hostname or agent_name}"
            remote_ip = str(row.get("last_remote_ip") or "").strip()
            platform = str(row.get("platform") or "").strip().lower()
            profile_id = str(row.get("host_profile") or "").strip()
            if not platform or not profile_id:
                try:
                    profile = self.profiles.resolve(code)
                    platform = platform or str(profile.get("platform") or "windows")
                    profile_id = profile_id or str(profile.get("id") or "windows_generic")
                except (KeyError, OSError, ValueError):
                    platform = platform or "windows"
                    profile_id = profile_id or "windows_generic"
            dedup[identity] = {
                "SiteCode": code,
                "SiteName": name,
                "AgentId": agent_id,
                "AgentName": agent_name or hostname,
                "Hostname": hostname,
                "ServerIP": "",
                "Platform": platform,
                "HostProfile": profile_id,
                "AgentOnline": "true" if agent_online(row, ttl) else "false",
                "LastSeen": str(row.get("last_seen") or ""),
                "AgentConnection": agent_gateway_connection_label(self.config, observed_ip=remote_ip),
                "AgentRemoteIP": remote_ip,
                "AgentlessIP": (
                    known.get(f"agent:{agent_id.lower()}", "")
                    or known.get(f"host:{hostname.lower()}", "")
                    or known.get(f"site:{code}", "")
                ),
                "Source": "gateway_live",
            }
        self._gateway_rows = list(dedup.values())
        self.current_inventory_path = self.groups.write_gateway_cache(self._gateway_rows)
        self.current_group_id = GATEWAY_GROUP_ID
        self.current_group_name = "Agentes del Gateway · en vivo"
        self.load_hosts(group_id=GATEWAY_GROUP_ID, sites=self._gateway_rows)
        self.pull_agents_button.setEnabled(True)
        self.pull_agents_button.setText("↻ Actualizar agentes")
        self.toastRequested.emit(
            "Agentes actualizados",
            f"{len(self._gateway_rows)} agente(s) cargados por AgentId. HTTPS/PULL no usa la IP del servidor.",
            "success",
        )
        self.gatewayAgentsLoaded.emit(len(self._gateway_rows))

    def _gateway_agents_failed(self, detail: str) -> None:
        self.pull_agents_button.setEnabled(True)
        self.pull_agents_button.setText("↻ Actualizar agentes")
        self.host_summary.setText("No se pudieron consultar los agentes del Gateway.")
        self.toastRequested.emit("Gateway no disponible", detail, "danger")
        show_detailed_message(
            self,
            "Actualizar agentes",
            "No se pudieron consultar los agentes del Gateway.",
            detail,
            level="warning",
        )

    def selected_rows_in_current_order(self) -> list[HostRow]:
        ordered: list[HostRow] = []
        seen: set[int] = set()
        for source_row in self.visible_source_rows():
            if 0 <= source_row < len(self.host_model.rows) and self.host_model.rows[source_row].selected:
                ordered.append(self.host_model.rows[source_row])
                seen.add(source_row)
        for source_row, row in enumerate(self.host_model.rows):
            if source_row not in seen and row.selected:
                ordered.append(row)
        return ordered

    def save_selection_as_group(self) -> None:
        selected = self.selected_rows_in_current_order()
        if not selected:
            QMessageBox.information(self, "Grupo de despliegue", "Seleccione al menos un destino.")
            return
        suggested = f"{self.group_context.capitalize()} {dt.datetime.now().strftime('%Y-%m-%d %H%M')}"
        name, accepted = QInputDialog.getText(
            self,
            "Guardar grupo",
            "Nombre del grupo:",
            text=suggested,
        )
        if not accepted or not str(name).strip():
            return
        try:
            gid = self.groups.create(
                str(name).strip(),
                description=f"Grupo creado desde {self.group_context}.",
            )
            persisted: list[dict[str, Any]] = []
            for row in selected:
                has_agent = self.row_has_agent(row)
                persisted.append({
                    "SiteCode": row.target.code,
                    "SiteName": row.target.name,
                    "ServerIP": row.target.address if not has_agent else "",
                    "Platform": row.target.platform,
                    "HostProfile": row.target.host_profile,
                    "AgentId": row.agent_id or row.target.agent_id,
                    "AgentName": row.agent_name,
                    "Hostname": row.hostname,
                    "AgentOnline": "",
                    "LastSeen": row.last_seen,
                    "AgentConnection": row.connection_display if has_agent else "",
                    "AgentRemoteIP": row.agent_remote_ip if has_agent else "",
                    "AgentlessIP": row.agentless_address if has_agent else "",
                    "Source": "deployment_group",
                })
            self.groups.write_sites(gid, persisted)
            self.groups.set_active(gid)
            self.refresh_groups(preferred_group_id=gid)
            self.load_hosts(group_id=gid)
            self.toastRequested.emit(
                "Grupo guardado",
                f"{str(name).strip()} · {len(persisted)} destino(s) · orden preservado.",
                "success",
            )
            self.groupChanged.emit(gid)
        except Exception as exc:
            show_detailed_message(
                self,
                "Grupo de despliegue",
                "No se pudo guardar el grupo.",
                f"{type(exc).__name__}: {exc}",
            )
