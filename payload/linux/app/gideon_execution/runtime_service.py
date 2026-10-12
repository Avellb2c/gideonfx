from __future__ import annotations

import logging
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Optional

from gideon_admin import Site, command_exists, ensure_dir, now_iso
from gideon_common.process import windows_hidden_kwargs
from gideon_core.events import JobEventJournal
from gideon_core.states import JOB_CANCEL_STATES, JOB_TERMINAL_STATES, SITE_TERMINAL_STATES
from gideon_execution.connectivity_service import _run_local_powershell_json
from gideon_io import atomic_write_json as _atomic_write_json, atomic_write_json_nolock, read_json_retry, update_json_atomic

_LOG = logging.getLogger(__name__)


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    _atomic_write_json(path, payload, lock_timeout=2.0, retries=8)

class FanoutStore:
    def __init__(self, root: Path) -> None:
        self.root = ensure_dir(root)
        self.events = JobEventJournal(self.root / "events")

    def path(self, job_id: str) -> Path:
        return self.root / f"{job_id}.json"

    def _merge_protected_state(
        self,
        current: Optional[dict[str, Any]],
        incoming: dict[str, Any],
    ) -> dict[str, Any]:
        """Evita regresiones por writers concurrentes/stale."""
        result = dict(incoming)
        if not isinstance(current, dict):
            result["ManifestRevision"] = int(result.get("ManifestRevision", 0) or 0) + 1
            result["UpdatedAt"] = now_iso()
            return result

        cancel_sidecar = self.cancel_requested(str(result.get("JobId") or current.get("JobId") or ""))
        current_status = str(current.get("Status") or "").upper()
        incoming_status = str(result.get("Status") or "").upper()
        terminal_statuses = JOB_TERMINAL_STATES
        cancel_statuses = JOB_CANCEL_STATES

        # CancelRequested es sticky y tiene prioridad mientras exista sidecar.
        if current.get("CancelRequested") or cancel_sidecar:
            result["CancelRequested"] = True
            for key in ("CancelRequestedAt", "CancelRequestSource"):
                if current.get(key) and not result.get(key):
                    result[key] = current.get(key)
            if incoming_status not in cancel_statuses:
                result["Status"] = current_status if current_status in cancel_statuses else "CANCEL_REQUESTED"

        # Un estado terminal confirmado no puede volver a MONITORING/DISPATCHED.
        if current_status in terminal_statuses and incoming_status not in terminal_statuses:
            result["Status"] = current_status
            for key in ("FinishedAt", "CancelCompletedAt", "CancelFailureCount"):
                if current.get(key) is not None:
                    result[key] = current.get(key)

        current_sites = current.get("Sites") or {}
        incoming_sites = result.get("Sites") or {}
        merged_sites: dict[str, Any] = {}
        for code in set(current_sites) | set(incoming_sites):
            old_entry = current_sites.get(code) or {}
            new_entry = incoming_sites.get(code) or {}
            merged = dict(old_entry)
            merged.update(new_entry)
            old_state = str(old_entry.get("RemoteState") or "").upper()
            new_state = str(new_entry.get("RemoteState") or "").upper()
            terminal_remote = SITE_TERMINAL_STATES
            old_retry_gen=int(old_entry.get("RetryGeneration",0) or 0)
            new_retry_gen=int(new_entry.get("RetryGeneration",0) or 0)
            retry_advancing=new_retry_gen>old_retry_gen
            if old_state in terminal_remote and new_state not in terminal_remote and not retry_advancing:
                merged["RemoteState"] = old_state
                for key in ("CollectedAt", "CancelCompletedAt", "CollectionVerified", "RawFile"):
                    if old_entry.get(key) is not None:
                        merged[key] = old_entry.get(key)
            merged_sites[code] = merged
        if merged_sites:
            result["Sites"] = merged_sites

        result["ManifestRevision"] = max(
            int(current.get("ManifestRevision", 0) or 0),
            int(result.get("ManifestRevision", 0) or 0),
        ) + 1
        result["UpdatedAt"] = now_iso()
        return result

    def write(self, payload: dict[str, Any]) -> None:
        job_id = str(payload["JobId"])
        path = self.path(job_id)
        incoming = dict(payload)
        before_holder: dict[str, Any] = {}

        def updater(current):
            if isinstance(current, dict):
                before_holder.update(current)
            return self._merge_protected_state(
                current if isinstance(current, dict) else None,
                incoming,
            )

        merged = update_json_atomic(
            path,
            updater,
            default=None,
            lock_timeout=2.0,
            retries=8,
        )
        # Mantener el objeto en memoria alineado con lo realmente persistido.
        payload.clear(); payload.update(merged)
        self.events.record_manifest_changes(job_id, before_holder or None, merged)

    def read(self, job_id: str) -> dict[str, Any]:
        path = self.path(job_id)
        if not path.exists():
            raise FileNotFoundError(f"Fan-out job no encontrado: {job_id}")
        value = read_json_retry(path, retries=5)
        if not isinstance(value, dict):
            raise ValueError(f"Manifest inválido: {path}")
        return value

    def list(self, limit: int | None = None) -> list[dict[str, Any]]:
        rows = []
        paths = list(self.root.glob("*.json"))
        # Newest files first lets overview pages avoid parsing an unbounded
        # historical manifest set. Full callers keep the previous behavior by
        # omitting ``limit``.
        try:
            paths.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        except OSError:
            paths.sort(key=lambda p: p.name, reverse=True)
        if limit is not None:
            paths = paths[:max(1, int(limit))]
        for path in paths:
            try:
                value = read_json_retry(path, retries=2)
                if isinstance(value, dict):
                    rows.append(value)
            except Exception:
                continue
        rows.sort(key=lambda x: str(x.get("CreatedAt", "")), reverse=True)
        return rows

    def cancel_path(self, job_id: str) -> Path:
        # Sidecar sin extensión .json para que NO aparezca como otro Job.
        return self.root / f"{job_id}.cancel"

    def request_cancel(
        self,
        job_id: str,
        *,
        requested_by: str = "administrator",
        source: str = "unknown",
    ) -> dict[str, Any]:
        payload = {
            "JobId": job_id,
            "RequestedAt": now_iso(),
            "RequestedBy": requested_by,
            "Source": source,
        }
        atomic_write_json(self.cancel_path(job_id), payload)
        return payload

    def cancel_request(self, job_id: str) -> Optional[dict[str, Any]]:
        path = self.cancel_path(job_id)
        if not path.exists():
            return None
        try:
            value = read_json_retry(path, retries=3)
            return value if isinstance(value, dict) else None
        except Exception:
            return {"JobId": job_id, "RequestedAt": None, "Source": "sidecar"}

    def cancel_requested(self, job_id: str) -> bool:
        return self.cancel_path(job_id).exists()

    def clear_cancel_request(self, job_id: str) -> None:
        path = self.cancel_path(job_id)
        try:
            path.unlink(missing_ok=True)
        except TypeError:
            if path.exists():
                path.unlink()


    def site_skip_path(self, job_id: str, site_code: str) -> Path:
        return self.root / f"{job_id}.{safe_component(str(site_code), fallback='site')}.skip"

    def request_site_skip(self, job_id: str, site_code: str, *, requested_by: str="administrator", source: str="unknown") -> dict[str, Any]:
        payload={"JobId":str(job_id),"SiteCode":str(site_code),"RequestedAt":now_iso(),"RequestedBy":requested_by,"Source":source}
        atomic_write_json(self.site_skip_path(job_id,site_code),payload)
        return payload

    def site_skip_requested(self, job_id: str, site_code: str) -> bool:
        return self.site_skip_path(job_id,site_code).exists()

    def clear_site_skip(self, job_id: str, site_code: str) -> None:
        path=self.site_skip_path(job_id,site_code)
        try: path.unlink(missing_ok=True)
        except TypeError:
            if path.exists(): path.unlink()
        except Exception as exc:
            _LOG.warning("No se pudo limpiar sidecar skip %s: %s", path, exc)

class LocalProcessRegistry:
    """Registro por Job de procesos locales SSH/SFTP activos.

    Cada proceso usa un sidecar `<JOB>.<PID>.proc`, por lo que otro proceso de
    cancelación puede identificar exactamente qué conexiones pertenecen a ese
    Job sin tocar sesiones SSH/SFTP ajenas.
    """

    def __init__(self, root: Path, job_id: str) -> None:
        self.root = ensure_dir(root)
        self.job_id = str(job_id)

    def path(self, pid: int) -> Path:
        return self.root / f"{self.job_id}.{int(pid)}.proc"

    def register(
        self,
        *,
        pid: int,
        kind: str,
        site: Site,
        operation: str,
    ) -> None:
        payload = {
            "JobId": self.job_id,
            "Pid": int(pid),
            "Kind": str(kind).upper(),
            "SiteCode": site.code,
            "SiteName": site.name,
            "ServerIP": site.ip,
            "Operation": operation,
            "ParentPid": os.getpid(),
            "StartedAt": now_iso(),
        }
        atomic_write_json_nolock(self.path(pid), payload, retries=6)

    def unregister(self, pid: int) -> None:
        try:
            self.path(pid).unlink(missing_ok=True)
        except TypeError:
            path = self.path(pid)
            if path.exists():
                path.unlink()
        except Exception as exc:
            _LOG.warning("No se pudo retirar sidecar de proceso PID %s: %s", pid, exc)

    def entries(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for path in self.root.glob(f"{self.job_id}.*.proc"):
            try:
                value = read_json_retry(path, retries=2)
                if isinstance(value, dict):
                    value["_RegistryPath"] = str(path)
                    rows.append(value)
            except Exception:
                continue
        return rows

    def clear_stale_files(self) -> None:
        for path in self.root.glob(f"{self.job_id}.*.proc"):
            try:
                path.unlink()
            except Exception as exc:
                _LOG.warning("No se pudo limpiar sidecar de proceso obsoleto %s: %s", path, exc)


    def terminate_site_transports(self, site_code: str) -> dict[str, Any]:
        report={"SiteCode":str(site_code),"Terminated":[],"Protected":[],"Errors":[]}
        for entry in self.entries():
            if str(entry.get("SiteCode") or "") != str(site_code): continue
            pid=int(entry.get("Pid") or 0); op=str(entry.get("Operation") or "").upper()
            if pid<=0: continue
            # SSH_START puede haber creado el Scheduled Task antes de perder la respuesta.
            if op=="SSH_START":
                report["Protected"].append({"Pid":pid,"Operation":op}); continue
            if os.name=="nt":
                info=_windows_process_info(pid)
                if info and not _is_tracked_transport_process(info):
                    report["Errors"].append({"Pid":pid,"Error":"PID no corresponde a transporte GIDEON"}); continue
                ok_kill,detail=_terminate_windows_tree(pid)
            else:
                try: os.kill(pid,15); ok_kill,detail=True,"SIGTERM"
                except Exception as exc: ok_kill,detail=False,str(exc)
            if ok_kill:
                report["Terminated"].append({"Pid":pid,"Operation":op,"Detail":detail}); self.unregister(pid)
            else: report["Errors"].append({"Pid":pid,"Operation":op,"Error":detail})
        return report

def _windows_process_exists(pid: int) -> bool:
    """Chequeo rápido sin lanzar PowerShell; usado en loops de espera."""
    if pid <= 0:
        return False
    if os.name != "nt":
        try:
            os.kill(int(pid), 0)
            return True
        except OSError:
            return False
    try:
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
        if handle:
            code = wintypes.DWORD()
            ok_code = kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
            kernel32.CloseHandle(handle)
            return bool(ok_code) and int(code.value) == 259  # STILL_ACTIVE
        # ACCESS_DENIED normalmente significa que el proceso existe pero no es consultable.
        return ctypes.get_last_error() == 5
    except Exception:
        return False

def _windows_process_info(pid: int) -> Optional[dict[str, Any]]:
    """Devuelve nombre, PPID y command line para validación segura."""
    if os.name != "nt":
        return None
    script = rf"""
$proc = Get-CimInstance Win32_Process -Filter "ProcessId = {int(pid)}" -ErrorAction SilentlyContinue |
    Select-Object ProcessId,ParentProcessId,Name,CommandLine
if ($null -ne $proc) {{ $proc | ConvertTo-Json -Compress }}
"""
    try:
        value = _run_local_powershell_json(script)
        return value if isinstance(value, dict) else None
    except Exception:
        return None

def _terminate_windows_tree(pid: int) -> tuple[bool, str]:
    if os.name != "nt":
        return False, "Limpieza de procesos locales solo aplica en Windows."
    taskkill = command_exists("taskkill.exe") or command_exists("taskkill")
    if not taskkill:
        return False, "No se encontró taskkill.exe."
    cp = subprocess.run(
        [taskkill, "/PID", str(int(pid)), "/T", "/F"],
        text=True,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        **windows_hidden_kwargs(),
    )
    time.sleep(0.10)
    if not _windows_process_exists(pid):
        return True, cp.stdout.strip() or f"PID {pid} finalizado."
    return False, cp.stderr.strip() or cp.stdout.strip() or f"PID {pid} sigue activo."

def _is_gideon_controller_process(
    info: dict[str, Any],
    *,
    job_id: Optional[str] = None,
) -> bool:
    name = str(info.get("Name") or "").lower()
    cmd = str(info.get("CommandLine") or "").lower()
    if name not in {"python.exe", "pythonw.exe", "py.exe"}:
        return False
    basic = (
        "gideon_admin.py" in cmd
        and "fanout" in cmd
        and any(token in cmd for token in (" run", " resume", " dispatch", " status"))
    )
    if not basic:
        return False

    # v2.11 incluye JobId en la línea de comando de ejecuciones iniciadas por
    # GUI. Resume/status también lo incluyen de forma natural. Cuando existe,
    # se usa como señal adicional contra PID reuse.
    if job_id and str(job_id).lower() in cmd:
        return True

    # Compatibilidad con jobs heredados: el PID sigue validado al menos por
    # nombre de ejecutable + gideon_admin.py + fanout.
    return True

def _is_tracked_transport_process(info: dict[str, Any]) -> bool:
    return str(info.get("Name") or "").lower() in {
        "ssh.exe", "sftp.exe", "scp.exe"
    }

def safe_component(value: str, *, fallback: str = "item") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value)).strip("._-")
    return cleaned or fallback
