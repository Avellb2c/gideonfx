from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Mapping

from PySide6.QtCore import QThread, Qt, Signal
from PySide6.QtWidgets import (
    QFileDialog,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from gideon_application.controller import RemoteControlController
from gideon_domain import ArtifactDescriptor, HostTarget, JobRecord, TransportProfile
from gideon_host_profiles import HostProfileStore
from gideon_site_groups import SiteGroupStore

from ..models import HostRow
from ..tokens import SPACE_12, SPACE_16
from ..widgets import CommandBar, PageHeader, show_detailed_message
from .base import ScrollPage
from ..components import DestinationSelectorWidget


class TransferWorker(QThread):
    """Runs one or more transport-specific batches as one UI operation.

    AUTO can split a mixed selection: Agent-capable endpoints use outbound
    HTTPS/PULL while Agentless endpoints keep SFTP/SSH. This prevents a VPN
    requirement from being accidentally imposed on machines that already have
    an Agent.
    """

    progressChanged: Signal = Signal(str, float, str, int, int)
    completed: Signal = Signal(object)
    failed: Signal = Signal(str)

    def __init__(
        self,
        *,
        controller: RemoteControlController,
        batches: list[tuple[JobRecord, ArtifactDescriptor, Mapping[str, HostTarget]]],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.controller = controller
        self.batches = list(batches)

    def _progress(self, site: str, percent: float, operation: str, sent: int, total: int) -> None:
        self.progressChanged.emit(site, percent, operation, sent, total)

    async def _run_all(self) -> list[JobRecord]:
        tasks = [
            self.controller.execute_file_upload(
                job=job,
                artifact=artifact,
                sites=sites,
                progress=self._progress,
            )
            for job, artifact, sites in self.batches
        ]
        return list(await asyncio.gather(*tasks))

    def run(self) -> None:
        try:
            self.completed.emit(asyncio.run(self._run_all()))
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class TransfersPage(ScrollPage):
    toastRequested: Signal = Signal(str, str, str)

    def __init__(
        self,
        *,
        controller: RemoteControlController,
        groups: SiteGroupStore,
        profiles: HostProfileStore,
        default_remote_dir: str,
        config: dict[str, Any] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.controller = controller
        self.groups = groups
        self.profiles = profiles
        self.default_remote_dir = default_remote_dir
        self.config = dict(config or {})
        self.worker: TransferWorker | None = None
        self._progress_rows: dict[str, int] = {}

        header = PageHeader(
            "Archivos y video",
            "Transferencia con SHA-256. Agent usa HTTPS/PULL por Internet o LAN; la VPN es opcional.",
            self.content,
        )
        self.content_layout.addWidget(header)

        command = CommandBar(self.content)
        command.add_action("Seleccionar archivo", self._browse, primary=True)
        command.add_stretch()
        self.start_button = command.add_action("Iniciar transferencia", self._start, primary=True)
        self.content_layout.addWidget(command)

        config_card = QFrame(self.content)
        config_card.setObjectName("Card")
        config_layout = QVBoxLayout(config_card)
        config_layout.setContentsMargins(SPACE_16, SPACE_16, SPACE_16, SPACE_16)
        config_layout.setSpacing(SPACE_12)

        row1 = QHBoxLayout()
        self.file_edit = QLineEdit(config_card)
        self.file_edit.setPlaceholderText("Archivo local (.mp4, .zip, .log, etc.)")
        self.file_edit.textChanged.connect(self._update_transport_recommendation)
        row1.addWidget(QLabel("Origen", config_card))
        row1.addWidget(self.file_edit, 1)
        browse = QPushButton("Examinar…", config_card)
        browse.clicked.connect(self._browse)
        row1.addWidget(browse)
        config_layout.addLayout(row1)

        row2 = QHBoxLayout()
        self.destination_edit = QLineEdit(default_remote_dir, config_card)
        self.transport_combo = QComboBox(config_card)
        self.transport_combo.addItem("Automático · recomendado", "AUTO")
        self.transport_combo.addItem("AGENTE · HTTPS/PULL · sin VPN", TransportProfile.AGENT_HTTPS_PULL.value)
        self.transport_combo.addItem("SFTP → SSH → SFTP", TransportProfile.SFTP_SSH_SFTP.value)
        self.transport_combo.addItem("SCP → SSH → SCP", TransportProfile.SCP_SSH_SCP.value)
        self.transport_combo.addItem("STDIN/SSH → SSH → SCP", TransportProfile.STDIN_SSH_SCP.value)
        self.transport_combo.currentIndexChanged.connect(self._update_transport_recommendation)
        row2.addWidget(QLabel("Destino remoto", config_card))
        row2.addWidget(self.destination_edit, 1)
        row2.addWidget(QLabel("Transporte", config_card))
        row2.addWidget(self.transport_combo)
        config_layout.addLayout(row2)

        self.transport_hint = QLabel("", config_card)
        self.transport_hint.setObjectName("Muted")
        self.transport_hint.setWordWrap(True)
        config_layout.addWidget(self.transport_hint)
        self.content_layout.addWidget(config_card)

        self.destination_selector = DestinationSelectorWidget(
            groups=self.groups,
            profiles=self.profiles,
            config=self.config,
            group_context="Archivos y video",
            min_table_height=340,
            parent=self.content,
        )
        self.destination_selector.toastRequested.connect(self.toastRequested)
        self.destination_selector.selectionChanged.connect(self._update_transport_recommendation)
        self.destination_selector.gatewayAgentsLoaded.connect(
            lambda _count: self.transport_combo.setCurrentIndex(0)
        )
        self.content_layout.addWidget(self.destination_selector)
        self.host_model = self.destination_selector.host_model
        self.host_proxy = self.destination_selector.host_proxy
        self.host_table = self.destination_selector.host_table

        progress_card = QFrame(self.content)
        progress_card.setObjectName("Card")
        progress_layout = QVBoxLayout(progress_card)
        progress_layout.setContentsMargins(SPACE_16, SPACE_16, SPACE_16, SPACE_16)
        self.progress_title = QLabel("Progreso", progress_card)
        self.progress_title.setObjectName("SectionTitle")
        progress_layout.addWidget(self.progress_title)
        self.progress_bar = QProgressBar(progress_card)
        self.progress_bar.setRange(0, 100)
        progress_layout.addWidget(self.progress_bar)
        self.progress_table = QTableWidget(0, 4, progress_card)
        self.progress_table.setHorizontalHeaderLabels(("Sede", "Progreso", "Operación", "Bytes"))
        self.progress_table.verticalHeader().setVisible(False)
        self.progress_table.horizontalHeader().setStretchLastSection(True)
        progress_layout.addWidget(self.progress_table)
        self.content_layout.addWidget(progress_card)

        self.destination_selector.reload()
        self._update_transport_recommendation()


















    def _browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Seleccionar archivo", "", "Todos (*.*)")
        if path:
            self.file_edit.setText(path)
            self._update_transport_recommendation()

    @staticmethod
    def _row_has_agent(row: HostRow) -> bool:
        return DestinationSelectorWidget.row_has_agent(row)

    def _recommended_transport(self) -> tuple[TransportProfile | None, str]:
        selected = self.host_model.selected_rows()
        if selected and all(self._row_has_agent(row) for row in selected):
            active = sum(1 for row in selected if row.agent_online is True)
            offline = sum(1 for row in selected if row.agent_online is False)
            detail = (
                f"AGENTE · HTTPS/PULL: {len(selected)} destino(s) con Agent ({active} activos, {offline} inactivos). "
                "Funciona por Internet o LAN y no necesita VPN ni SSH entrante; los inactivos reciben la cola cuando vuelvan a conectarse."
            )
            return TransportProfile.AGENT_HTTPS_PULL, detail
        if selected and any(self._row_has_agent(row) for row in selected):
            agent_count = sum(1 for row in selected if self._row_has_agent(row))
            agentless_count = len(selected) - agent_count
            return (
                None,
                f"AUTO HÍBRIDO: {agent_count} destino(s) con Agent irán por HTTPS/PULL (Internet/LAN, sin VPN) y "
                f"{agentless_count} Agentless por SFTP/SSH (LAN/VPN). Cada destino usa su mejor ruta sin degradar a los Agents.",
            )
        source = Path(self.file_edit.text().strip())
        size = source.stat().st_size if source.is_file() else 0
        if size >= 500 * 1024 * 1024 or source.suffix.lower() in {".mp4", ".mkv", ".mov", ".avi"}:
            return TransportProfile.SFTP_SSH_SFTP, "SFTP recomendado para archivos grandes/video en destinos Agentless; requiere conectividad SSH (LAN/VPN)."
        return TransportProfile.SFTP_SSH_SFTP, "SFTP es el transporte Agentless predeterminado; requiere conectividad SSH (LAN/VPN)."

    def _resolved_transport_profile(self) -> TransportProfile | None:
        raw = str(self.transport_combo.currentData() or "AUTO")
        return self._recommended_transport()[0] if raw == "AUTO" else TransportProfile(raw)

    def _update_transport_recommendation(self, *_args: object) -> None:
        if not hasattr(self, "transport_hint"):
            return
        recommended, reason = self._recommended_transport()
        raw = str(self.transport_combo.currentData() or "AUTO")
        if raw == "AUTO":
            label = recommended.value if recommended is not None else "HÍBRIDO · AGENT + SFTP"
            self.transport_hint.setText(f"AUTO → {label} · {reason}")
        elif raw == TransportProfile.AGENT_HTTPS_PULL.value:
            self.transport_hint.setText("Forzado: AGENTE · HTTPS/PULL. Usa salida HTTPS del Agent al Gateway; VPN no requerida.")
        else:
            self.transport_hint.setText(f"Forzado: {raw}. Este modo Agentless requiere acceso SSH al destino (LAN/VPN).")

    def _start(self) -> None:
        if self.worker is not None and self.worker.isRunning():
            QMessageBox.information(self, "Transferencia", "Ya existe una transferencia iniciada desde esta vista.")
            return
        source = Path(self.file_edit.text().strip())
        if not source.is_file():
            QMessageBox.warning(self, "Archivo", "Seleccione un archivo local válido.")
            return
        selected_rows = self.host_model.selected_rows()
        sites = [row.target for row in selected_rows]
        if not sites:
            QMessageBox.warning(self, "Destinos", "Seleccione al menos un host.")
            return
        destination = self.destination_edit.text().strip()
        if not destination:
            QMessageBox.warning(self, "Destino", "Indique el directorio remoto.")
            return

        raw = str(self.transport_combo.currentData() or "AUTO")
        batches_spec: list[tuple[TransportProfile, list[HostTarget]]] = []
        if raw == "AUTO":
            agent_sites = [row.target for row in selected_rows if self._row_has_agent(row)]
            agentless_sites = [row.target_for_agentless() for row in selected_rows if not self._row_has_agent(row)]
            if agent_sites:
                batches_spec.append((TransportProfile.AGENT_HTTPS_PULL, agent_sites))
            if agentless_sites:
                batches_spec.append((TransportProfile.SFTP_SSH_SFTP, agentless_sites))
        else:
            profile = TransportProfile(raw)
            if profile == TransportProfile.AGENT_HTTPS_PULL and not all(self._row_has_agent(row) for row in selected_rows):
                QMessageBox.warning(
                    self,
                    "Agent HTTPS/PULL",
                    "Hay destinos sin Agent identificado. Use AUTO para que DRC divida la selección entre Agent HTTPS/PULL y SFTP/SSH, o filtre solo agentes.",
                )
                return
            if profile == TransportProfile.AGENT_HTTPS_PULL:
                batch_sites = [row.target for row in selected_rows]
            else:
                batch_sites = [row.target_for_agentless() for row in selected_rows]
                missing = [site.code for site in batch_sites if not site.address]
                if missing:
                    QMessageBox.warning(
                        self,
                        "Transporte Agentless",
                        "Los siguientes destinos Agent no tienen una IP Agentless separada para SSH/SFTP: "
                        + ", ".join(missing[:8])
                        + ". Use AGENTE · HTTPS/PULL o configure AgentlessIP explícitamente.",
                    )
                    return
            batches_spec.append((profile, batch_sites))

        try:
            batches: list[tuple[JobRecord, ArtifactDescriptor, Mapping[str, HostTarget]]] = []
            labels: list[str] = []
            for profile, batch_sites in batches_spec:
                job, artifact = self.controller.create_file_upload_job(
                    source=source,
                    destination_dir=destination,
                    sites=batch_sites,
                    transport_profile=profile,
                )
                batches.append((job, artifact, {(site.agent_id or site.code) if profile == TransportProfile.AGENT_HTTPS_PULL else site.code: site for site in batch_sites}))
                labels.append(f"{profile.value}: {len(batch_sites)}")
        except Exception as exc:
            show_detailed_message(self, "Transferencia", "No se pudo preparar la transferencia.", f"{type(exc).__name__}: {exc}")
            return

        self._progress_rows.clear()
        self.progress_table.setRowCount(0)
        self.progress_bar.setValue(0)
        batch_ids = ", ".join(job.job_id for job, _artifact, _mapping in batches)
        mode = "AUTO HÍBRIDO" if len(batches) > 1 else batches[0][0].transport_profile.value
        self.progress_title.setText(f"Progreso · {mode} · {batch_ids}")
        self.worker = TransferWorker(controller=self.controller, batches=batches, parent=self)
        self.worker.progressChanged.connect(self._progress)
        self.worker.completed.connect(self._completed)
        self.worker.failed.connect(self._failed)
        self.start_button.setEnabled(False)
        self.worker.start()
        self.toastRequested.emit(
            "Transferencia iniciada",
            f"{source.name} · {mode} · " + " · ".join(labels),
            "info",
        )

    def _progress(self, site: str, percent: float, operation: str, sent: int, total: int) -> None:
        row = self._progress_rows.get(site)
        if row is None:
            row = self.progress_table.rowCount()
            self.progress_table.insertRow(row)
            self._progress_rows[site] = row
        values = (site, f"{percent:.1f} %", operation, f"{sent:,} / {total:,}")
        for col, value in enumerate(values):
            self.progress_table.setItem(row, col, QTableWidgetItem(value))
        percentages: list[float] = []
        for index in range(self.progress_table.rowCount()):
            item = self.progress_table.item(index, 1)
            if item is not None:
                try:
                    percentages.append(float(item.text().split()[0]))
                except ValueError:
                    pass
        if percentages:
            self.progress_bar.setValue(round(sum(percentages) / len(percentages)))

    def _completed(self, result: object) -> None:
        self.start_button.setEnabled(True)
        jobs = list(result) if isinstance(result, (list, tuple)) else [result]
        successful = [job for job in jobs if str(getattr(job, "state", "")).upper().endswith("COMPLETED")]
        if len(successful) == len(jobs):
            self.progress_bar.setValue(100)
        detail = " · ".join(f"{getattr(job, 'job_id', '-')} {getattr(job, 'state', '-')}" for job in jobs)
        tone = "success" if len(successful) == len(jobs) else "warning"
        self.toastRequested.emit("Transferencia finalizada", detail, tone)
        self.worker = None

    def _failed(self, detail: str) -> None:
        self.start_button.setEnabled(True)
        self.toastRequested.emit("Transferencia con error", detail, "danger")
        show_detailed_message(self, "Transferencia", "La transferencia terminó con error.", detail)
        self.worker = None
