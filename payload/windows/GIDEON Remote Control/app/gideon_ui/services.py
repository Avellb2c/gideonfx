from __future__ import annotations

from gideon_common.observability import best_effort_warning

from gideon_version import PRODUCT_VERSION
import datetime as dt
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from PySide6.QtCore import QObject, QTimer, Signal

from gideon_application.ports import ScriptLaunchPort
from gideon_core.launch import LaunchPlan, LaunchRequest
from gideon_io import read_json_retry
from gideon_infrastructure.subprocess_utils import popen_hidden, run_hidden


_PERCENT_VAR = re.compile(r"%([^%]+)%")


def expand_windows_env(value: str) -> str:
    text = str(value)

    def repl(match: re.Match[str]) -> str:
        key = match.group(1)
        return os.environ.get(key, match.group(0))

    text = _PERCENT_VAR.sub(repl, text)
    return os.path.expanduser(os.path.expandvars(text))


@dataclass(frozen=True, slots=True)
class AppPaths:
    root: Path
    config: Path
    jobs: Path
    logs: Path
    results: Path
    raw: Path
    packages: Path
    transfer_jobs: Path
    known_hosts: Path
    key_path: Path

    @classmethod
    def from_config(cls, root: Path, cfg: Mapping[str, object]) -> "AppPaths":
        path_cfg = cfg.get("paths") if isinstance(cfg.get("paths"), dict) else {}
        ssh_cfg = cfg.get("ssh") if isinstance(cfg.get("ssh"), dict) else {}
        assert isinstance(path_cfg, dict)
        assert isinstance(ssh_cfg, dict)

        def path_value(name: str, default: str) -> Path:
            return Path(expand_windows_env(str(path_cfg.get(name) or default)))

        return cls(
            root=Path(root).resolve(),
            config=Path(root).resolve() / "config" / "config.json",
            jobs=path_value("fanout_jobs_dir", r"%LOCALAPPDATA%\GIDEONSSH\fanout_jobs"),
            logs=Path(expand_windows_env(str((cfg.get("gui") or {}).get("logs_dir") if isinstance(cfg.get("gui"), dict) else r"%LOCALAPPDATA%\GIDEONSSH\gui_logs"))),
            results=path_value("results_dir", r"%USERPROFILE%\Documents\GIDEON-SSH-Results"),
            raw=path_value("raw_dir", r"%USERPROFILE%\Documents\GIDEON-SSH-Results\raw"),
            packages=path_value("packages_dir", r"%LOCALAPPDATA%\GIDEONSSH\packages"),
            transfer_jobs=path_value("transfer_jobs_dir", r"%LOCALAPPDATA%\GIDEONSSH\transfer_jobs"),
            known_hosts=path_value("known_hosts", r"%LOCALAPPDATA%\GIDEONSSH\known_hosts"),
            key_path=Path(expand_windows_env(str(ssh_cfg.get("key_path") or r"%USERPROFILE%\.ssh\gideons_damautapp"))),
        )

    def ensure(self) -> None:
        for path in (
            self.jobs,
            self.logs,
            self.results,
            self.raw,
            self.packages,
            self.transfer_jobs,
            self.known_hosts.parent,
        ):
            path.mkdir(parents=True, exist_ok=True)


class ManifestRepository:
    def __init__(self, jobs_dir: Path) -> None:
        self.jobs_dir: Path = Path(jobs_dir)
        self.jobs_dir.mkdir(parents=True, exist_ok=True)

    def list(self, limit: int = 250) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        def modified(path: Path) -> float:
            try:
                return path.stat().st_mtime
            except OSError:
                return 0.0

        files = sorted(
            self.jobs_dir.glob("*.json"),
            key=modified,
            reverse=True,
        )
        for path in files[: max(1, int(limit))]:
            try:
                value = read_json_retry(path, retries=2, delay=0.01)
                if isinstance(value, dict):
                    value.setdefault("_ManifestPath", str(path))
                    rows.append(value)
            except Exception:
                continue
        return rows

    def get(self, job_id: str) -> dict[str, Any]:
        path = self.jobs_dir / f"{job_id}.json"
        if not path.exists():
            return {}
        try:
            value = read_json_retry(path, retries=3, delay=0.02)
            return dict(value) if isinstance(value, dict) else {}
        except Exception:
            return {}

    def delete(self, job_id: str) -> None:
        (self.jobs_dir / f"{job_id}.json").unlink(missing_ok=True)

    def latest_for_site(self, site_code: str) -> dict[str, Any] | None:
        for manifest in self.list(limit=80):
            sites = manifest.get("Sites")
            if not isinstance(sites, dict):
                continue
            entry = sites.get(site_code)
            if not isinstance(entry, dict):
                # Agent manifests are keyed by AgentId from v6.0.34 onward.
                # Hosts view is site-level, so resolve by the entry's SiteCode.
                entry = next((
                    value for value in sites.values()
                    if isinstance(value, dict) and str(value.get("SiteCode") or "") == str(site_code)
                ), None)
            if isinstance(entry, dict):
                return {
                    "JobId": manifest.get("JobId"),
                    "Status": manifest.get("Status"),
                    "UpdatedAt": manifest.get("UpdatedAt"),
                    **entry,
                }
        return None


class LocalEnvironmentService:
    """Local OpenSSH integration used by the Qt console.

    The service never stores a private-key passphrase. P8C validates the
    configured identity with read-only OpenSSH operations; an externally managed
    ssh-agent may be queried but is never started, configured or mutated by GIDEON.
    """

    def __init__(self, key_path: Path) -> None:
        self.key_path: Path = Path(key_path)

    @staticmethod
    def _command(name: str) -> str | None:
        from shutil import which

        return which(name)

    @staticmethod
    def _creationflags() -> int:
        return getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0

    def transport_clients(self) -> dict[str, bool]:
        return {
            "ssh": bool(self._command("ssh.exe") or self._command("ssh")),
            "sftp": bool(self._command("sftp.exe") or self._command("sftp")),
            "scp": bool(self._command("scp.exe") or self._command("scp")),
        }

    def _fingerprint(self) -> str:
        ssh_keygen = self._command("ssh-keygen.exe") or self._command("ssh-keygen")
        if not ssh_keygen or not self.key_path.is_file():
            return ""
        for candidate in (Path(str(self.key_path) + ".pub"), self.key_path):
            if not candidate.is_file():
                continue
            try:
                cp = run_hidden(
                    [ssh_keygen, "-lf", str(candidate)],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    encoding="utf-8",
                    errors="replace",
                    creationflags=self._creationflags(),
                )
            except Exception:
                continue
            if cp.returncode == 0:
                for token in (cp.stdout or "").split():
                    if token.startswith("SHA256:"):
                        return token
        return ""

    def _agent_listing(self) -> tuple[int, str]:
        """Read externally managed ssh-agent state without changing it."""
        ssh_add = self._command("ssh-add.exe") or self._command("ssh-add")
        if not ssh_add:
            return 127, "ssh-add no está instalado."
        try:
            cp = run_hidden(
                [ssh_add, "-l"],
                capture_output=True,
                text=True,
                timeout=5,
                encoding="utf-8",
                errors="replace",
                creationflags=self._creationflags(),
            )
            return cp.returncode, ((cp.stdout or "") + "\n" + (cp.stderr or "")).strip()
        except Exception as exc:
            return 1, f"{type(exc).__name__}: {exc}"

    def key_loaded(self) -> bool:
        """Return whether an external ssh-agent already exposes this key.

        This is a read-only compatibility probe. GIDEON never starts/configures the
        Windows ssh-agent service and never calls ``ssh-add`` to mutate it.
        """
        rc, listing = self._agent_listing()
        if rc != 0 or not listing.strip():
            return False
        fingerprint = self._fingerprint()
        return bool(fingerprint and fingerprint in listing)

    def key_available(self) -> bool:
        """Return whether the configured GIDEON private key can be identified."""
        return self.key_path.is_file() and bool(self._fingerprint())

    @staticmethod
    def _looks_like_passphrase_prompt(detail: str) -> bool:
        lowered = str(detail or "").lower()
        needles = (
            "passphrase", "incorrect passphrase", "bad passphrase",
            "load failed", "invalid format",
        )
        return any(token in lowered for token in needles)

    def _validate_private_key(self, passphrase: str | None) -> tuple[int, str]:
        ssh_keygen = self._command("ssh-keygen.exe") or self._command("ssh-keygen")
        if not ssh_keygen:
            return 127, "No se encontró ssh-keygen. Instale OpenSSH Client."
        args = [ssh_keygen, "-y", "-P", passphrase or "", "-f", str(self.key_path)]
        try:
            cp = run_hidden(
                args,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=10,
                encoding="utf-8",
                errors="replace",
                creationflags=self._creationflags(),
            )
            detail = ((cp.stderr or "") + "\n" + (cp.stdout or "")).strip()
            return cp.returncode, detail
        except subprocess.TimeoutExpired:
            return 124, "ssh-keygen agotó el tiempo de validación."
        except Exception as exc:
            return 1, f"{type(exc).__name__}: {exc}"

    def load_key(self, passphrase: str | None = None) -> dict[str, object]:
        """Validate the GIDEON SSH identity without modifying host ssh-agent state.

        The method keeps its historical name for UI compatibility. P8C changes
        its semantics deliberately: host service configuration and ``ssh-add`` mutation
        are forbidden by the product isolation contract.
        """
        result: dict[str, object] = {
            "ok": False,
            "needs_passphrase": False,
            "key_path": str(self.key_path),
            "fingerprint": self._fingerprint(),
            "detail": "",
            "agent_modified": False,
        }
        if not self.key_path.is_file():
            result["detail"] = f"No existe la clave privada configurada: {self.key_path}"
            return result
        if self.key_loaded():
            result["ok"] = True
            result["detail"] = "Identidad GIDEON validada; ssh-agent externo ya contiene la clave. GIDEON no lo modificó."
            return result

        rc, detail = self._validate_private_key(passphrase)
        if rc == 0:
            result["ok"] = True
            result["fingerprint"] = self._fingerprint()
            result["detail"] = "Identidad SSH GIDEON validada desde archivo. GIDEON no inicia, configura ni modifica ssh-agent."
            return result
        if passphrase is None and self._looks_like_passphrase_prompt(detail):
            result["needs_passphrase"] = True
            result["detail"] = detail or "La clave requiere passphrase para validación."
            return result
        result["detail"] = detail or f"ssh-keygen terminó con código {rc}."
        return result

    def open_key_loader(self) -> None:
        """Compatibility shim: validates identity only; never mutates ssh-agent."""
        self.load_key(None)


@dataclass(slots=True)
class _ActiveLaunch:
    plan: LaunchPlan
    process: subprocess.Popen[bytes]
    started_monotonic: float


class QtLaunchManager(QObject):
    jobCreated: Signal = Signal(str)
    jobStarted: Signal = Signal(str, int)
    jobTransitioned: Signal = Signal(str, str)
    jobFailed: Signal = Signal(str, str)
    logMessage: Signal = Signal(str)

    def __init__(
        self,
        *,
        app_root: Path,
        launch_port: ScriptLaunchPort,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._root: Path = Path(app_root)
        self._launch_port: ScriptLaunchPort = launch_port
        self._active: dict[str, _ActiveLaunch] = {}
        self._timer = QTimer(self)
        self._timer.setInterval(500)
        self._timer.timeout.connect(self._poll)
        self._timer.start()

    @staticmethod
    def new_job_id() -> str:
        return dt.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + os.urandom(3).hex()

    @staticmethod
    def _hidden_process_kwargs() -> dict[str, object]:
        if os.name != "nt":
            return {}
        startup = subprocess.STARTUPINFO()
        startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startup.wShowWindow = getattr(subprocess, "SW_HIDE", 0)
        return {
            "creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0),
            "startupinfo": startup,
        }

    def build_plan(self, request: LaunchRequest) -> LaunchPlan:
        return self._launch_port.build_plan(request)

    @staticmethod
    def _read_full_launch_log(plan: LaunchPlan) -> str:
        """Return the complete launch log for copy-friendly diagnostics.

        Pre-dispatch failures are exactly where operators need the full Python
        traceback and launch plan. Do not truncate the payload sent to the UI;
        the manifest can still store a short tail for compact history.
        """
        try:
            return plan.log_path.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            return f"[No se pudo leer el log completo: {type(exc).__name__}: {exc}]"

    def launch(self, plan: LaunchPlan) -> str:
        if not plan.preflight.ok:
            raise RuntimeError("Preflight falló: " + " | ".join(plan.preflight.errors[:5]))

        plan.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._launch_port.bootstrap_manifest(plan)
        self.jobCreated.emit(plan.request.job_id)

        with plan.log_path.open("a", encoding="utf-8", buffering=1) as log_file:
            log_file.write(f"DRC · GIDEON REMOTE CONTROL v{PRODUCT_VERSION} · LAUNCH PLAN\n")
            log_file.write("=" * 78 + "\n")
            log_file.write(f"Job: {plan.request.job_id}\n")
            log_file.write(f"Method: {plan.request.method}\n")
            log_file.write(f"Command: {plan.command_text()}\n")
            log_file.write(
                "Preflight: "
                + json.dumps(plan.preflight.as_dict(), ensure_ascii=False)
                + "\n\n"
            )
            log_file.flush()

            env = os.environ.copy()
            env["PYTHONUTF8"] = "1"
            env["PYTHONIOENCODING"] = "utf-8"
            env["GIDEON_FORCE_UTF8_STDIO"] = "1"
            env["GIDEON_BACKEND_LOG"] = str(plan.log_path)
            env["GIDEON_GUI_PARENT_PID"] = str(os.getpid())
            env["GIDEON_UI"] = "PYSIDE6_FLUENT_V6"
            if plan.request.group_id:
                env["GIDEON_SITE_GROUP_ID"] = str(plan.request.group_id)
            if plan.request.group_name:
                env["GIDEON_SITE_GROUP_NAME"] = str(plan.request.group_name)

            process = subprocess.Popen(
                list(plan.command),
                cwd=str(self._root),
                stdout=log_file,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                close_fds=(os.name != "nt"),
                env=env,
                **self._hidden_process_kwargs(),
            )

        self._launch_port.mark_started(plan, int(process.pid))
        self._active[plan.request.job_id] = _ActiveLaunch(
            plan=plan,
            process=process,
            started_monotonic=time.monotonic(),
        )
        self.jobStarted.emit(plan.request.job_id, int(process.pid))
        self.logMessage.emit(f"Backend iniciado PID={process.pid} · {plan.request.job_id}")
        return plan.request.job_id

    def _poll(self) -> None:
        finished: list[str] = []
        for job_id, active in tuple(self._active.items()):
            manifest: dict[str, Any]
            try:
                value = read_json_retry(active.plan.manifest_path, retries=1, delay=0.01)
                manifest = dict(value) if isinstance(value, dict) else {}
            except Exception:
                manifest = {}

            status = str(manifest.get("Status") or "").upper()
            stage = str(manifest.get("LaunchStage") or "").upper()
            rc = active.process.poll()

            if status and status not in {"STARTING", "CREATED", "LAUNCH_FAILED"}:
                self.jobTransitioned.emit(job_id, status)
                finished.append(job_id)
                continue

            if status == "LAUNCH_FAILED":
                error = str(manifest.get("LaunchError") or "Error de lanzamiento")
                full_log = self._read_full_launch_log(active.plan)
                detail = error + ("\n\nLOG COMPLETO\n" + "=" * 78 + "\n" + full_log if full_log else "")
                self.jobFailed.emit(job_id, detail)
                finished.append(job_id)
                continue

            if rc is not None:
                error = f"Backend finalizó antes de iniciar Dispatch (exit code {rc})."
                try:
                    tail = active.plan.log_path.read_text(
                        encoding="utf-8",
                        errors="replace",
                    ).splitlines()[-24:]
                    tail_text = "\n".join(tail)
                except Exception:
                    tail_text = ""
                try:
                    self._launch_port.mark_failed(
                        active.plan,
                        error=error,
                        return_code=int(rc),
                        log_tail=tail_text,
                    )
                except Exception as exc:
                    best_effort_warning(f"No se pudo persistir runtime FAILED para {job_id}", exc)
                full_log = self._read_full_launch_log(active.plan)
                detail = error + ("\n\nLOG COMPLETO\n" + "=" * 78 + "\n" + full_log if full_log else "")
                self.jobFailed.emit(job_id, detail)
                finished.append(job_id)
                continue

            if stage == "BACKEND_STARTED":
                elapsed = time.monotonic() - active.started_monotonic
                if elapsed > 20:
                    self.logMessage.emit(
                        f"{job_id}: backend iniciado, STARTING hace {int(elapsed)} s"
                    )

        for job_id in finished:
            self._active.pop(job_id, None)


class BackgroundCommandRunner(QObject):
    commandStarted: Signal = Signal(str, int)
    commandFinished: Signal = Signal(str, int)
    commandFailed: Signal = Signal(str, str)

    def __init__(self, app_root: Path, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._root: Path = Path(app_root)
        self._processes: dict[str, subprocess.Popen[bytes]] = {}
        self._timer = QTimer(self)
        self._timer.setInterval(650)
        self._timer.timeout.connect(self._poll)
        self._timer.start()

    def start(self, key: str, args: list[str], log_path: Path) -> None:
        if key in self._processes and self._processes[key].poll() is None:
            raise RuntimeError(f"Ya existe una acción en curso: {key}")
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as log_file:
            env = os.environ.copy()
            env["PYTHONUTF8"] = "1"
            env["PYTHONIOENCODING"] = "utf-8"
            env["GIDEON_FORCE_UTF8_STDIO"] = "1"
            process = subprocess.Popen(
                [sys.executable, str(self._root / "gideon_admin.py"), *args],
                cwd=str(self._root),
                stdout=log_file,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                close_fds=(os.name != "nt"),
                env=env,
                **QtLaunchManager._hidden_process_kwargs(),
            )
        self._processes[key] = process
        self.commandStarted.emit(key, int(process.pid))

    def _poll(self) -> None:
        finished: list[str] = []
        for key, process in tuple(self._processes.items()):
            rc = process.poll()
            if rc is None:
                continue
            if rc == 0:
                self.commandFinished.emit(key, 0)
            else:
                self.commandFailed.emit(key, f"Exit code {rc}")
            finished.append(key)
        for key in finished:
            self._processes.pop(key, None)
