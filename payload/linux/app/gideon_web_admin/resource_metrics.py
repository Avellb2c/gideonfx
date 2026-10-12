from __future__ import annotations

"""Low-overhead, read-only resource telemetry for the WebAdmin dashboard.

The collector intentionally uses operating-system counters instead of an extra
monitoring dependency.  Linux service values come from the systemd cgroups that
own GIDEON processes, so child processes are included without inspecting secrets or
other users' command lines.  A short cache keeps dashboard polling inexpensive.
"""

import copy
import ctypes
import datetime as dt
import os
import platform
from pathlib import Path
import shutil
import socket
import subprocess
import threading
import time
from typing import Any, Callable, Sequence


Runner = Callable[[Sequence[str], int], subprocess.CompletedProcess[str]]

LINUX_GIDEON_RESOURCE_UNITS: tuple[tuple[str, str], ...] = (
    ("web_admin", "gideon-web-admin.service"),
    ("gateway", "gideon-agent-gateway.service"),
    ("coordinator", "gideon-coordinator.service"),
    ("diagnostics", "gideon-diagnostics.service"),
    ("antimalware", "gideon-clamd.service"),
)

SERVICE_LABELS = {
    "web_admin": "WebAdmin",
    "gateway": "Gateway",
    "coordinator": "Coordinator",
    "diagnostics": "Diagnóstico",
    "antimalware": "Antimalware",
}


def _default_runner(args: Sequence[str], timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args), capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=timeout, check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return max(0, int(str(value).strip()))
    except (TypeError, ValueError):
        return default


def _percent(value: float | int, total: float | int) -> float:
    if float(total or 0) <= 0:
        return 0.0
    return round(max(0.0, min(100.0, float(value) * 100.0 / float(total))), 1)


def human_bytes(value: int | float) -> str:
    size = max(0.0, float(value or 0))
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    unit = units[0]
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            break
        size /= 1024.0
    precision = 0 if unit == "B" else 1
    return f"{size:.{precision}f} {unit}"


def human_duration(seconds: int | float) -> str:
    remaining = max(0, int(seconds or 0))
    days, remaining = divmod(remaining, 86400)
    hours, remaining = divmod(remaining, 3600)
    minutes, _ = divmod(remaining, 60)
    if days:
        return f"{days} d {hours} h"
    if hours:
        return f"{hours} h {minutes} min"
    return f"{minutes} min"


def parse_systemd_show(text: str) -> list[dict[str, str]]:
    """Parse blank-line-delimited ``systemctl show`` property blocks."""
    rows: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for raw in (text or "").splitlines() + [""]:
        line = raw.strip()
        if not line:
            if current.get("Id"):
                rows.append(current)
            current = {}
            continue
        key, separator, value = line.partition("=")
        if separator:
            current[key] = value
    return rows


def _read_text(path: Path, limit: int = 8192) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return ""


def _linux_os_name() -> str:
    values: dict[str, str] = {}
    for line in _read_text(Path("/etc/os-release")).splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key.strip()] = value.strip().strip('"')
    return values.get("PRETTY_NAME") or platform.platform(terse=True)


def _linux_cpu_model() -> str:
    for line in _read_text(Path("/proc/cpuinfo"), 256 * 1024).splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip().lower() in {"model name", "hardware"} and value.strip():
            return " ".join(value.split())
    return platform.processor() or "CPU no identificada"


def _linux_memory() -> tuple[int, int]:
    values: dict[str, int] = {}
    for line in _read_text(Path("/proc/meminfo")).splitlines():
        key, separator, value = line.partition(":")
        if separator:
            values[key] = _safe_int(value.split()[0] if value.split() else 0) * 1024
    total = values.get("MemTotal", 0)
    available = values.get("MemAvailable", values.get("MemFree", 0))
    return total, min(total, available)


def _linux_cpu_counter() -> tuple[int, int] | None:
    first = _read_text(Path("/proc/stat"), 4096).splitlines()
    if not first or not first[0].startswith("cpu "):
        return None
    values = [_safe_int(item) for item in first[0].split()[1:]]
    if len(values) < 4:
        return None
    total = sum(values)
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    return total, idle


def _windows_memory() -> tuple[int, int]:
    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]
    state = MEMORYSTATUSEX()
    state.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(state)):
        return 0, 0
    return int(state.ullTotalPhys), int(state.ullAvailPhys)


def _filetime_value(value: Any) -> int:
    return (int(value.dwHighDateTime) << 32) | int(value.dwLowDateTime)


def _windows_cpu_counter() -> tuple[int, int] | None:
    class FILETIME(ctypes.Structure):
        _fields_ = [("dwLowDateTime", ctypes.c_ulong), ("dwHighDateTime", ctypes.c_ulong)]
    idle = FILETIME(); kernel = FILETIME(); user = FILETIME()
    if not ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user)):
        return None
    idle_value = _filetime_value(idle)
    return _filetime_value(kernel) + _filetime_value(user), idle_value


def _windows_process_memory() -> int:
    class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("cb", ctypes.c_ulong), ("PageFaultCount", ctypes.c_ulong),
            ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t),
        ]
    counters = PROCESS_MEMORY_COUNTERS()
    counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
    handle = ctypes.windll.kernel32.GetCurrentProcess()
    if not ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
        return 0
    return int(counters.WorkingSetSize)


def _linux_process_memory() -> tuple[int, int]:
    values: dict[str, int] = {}
    for line in _read_text(Path("/proc/self/status")).splitlines():
        key, separator, value = line.partition(":")
        if separator and key in {"VmRSS", "Threads"}:
            multiplier = 1024 if key == "VmRSS" else 1
            values[key] = _safe_int(value.split()[0] if value.split() else 0) * multiplier
    return values.get("VmRSS", 0), values.get("Threads", 0)


class ServerResourceMetrics:
    """Collect host capacity and GIDEON-only consumption with a bounded cache."""

    def __init__(
        self, app_root: Path, *, cache_ttl_seconds: float = 5.0,
        runner: Runner = _default_runner, platform_name: str | None = None,
    ) -> None:
        self.app_root = Path(app_root).resolve()
        self.cache_ttl_seconds = max(1.0, float(cache_ttl_seconds))
        self.runner = runner
        self.platform_name = (platform_name or platform.system()).strip().lower()
        self._lock = threading.RLock()
        self._cache: dict[str, Any] | None = None
        self._cache_at = 0.0
        self._previous_at = time.monotonic()
        self._previous_host_cpu = self._host_cpu_counter()
        self._previous_process_cpu_ns = time.process_time_ns()
        self._previous_gideon_cpu: dict[str, int] = {}
        if self.platform_name == "linux":
            try:
                self._previous_gideon_cpu = {
                    row["unit"]: int(row["cpu_total_ns"])
                    for row in self._linux_service_rows()
                }
            except Exception:
                self._previous_gideon_cpu = {}

    def _host_cpu_counter(self) -> tuple[int, int] | None:
        try:
            return _windows_cpu_counter() if self.platform_name == "windows" else _linux_cpu_counter()
        except (AttributeError, OSError):
            return None

    def _host_snapshot(self) -> dict[str, Any]:
        if self.platform_name == "windows":
            total_memory, available_memory = _windows_memory()
            os_name = f"{platform.system()} {platform.release()}".strip()
            uptime = int(ctypes.windll.kernel32.GetTickCount64() / 1000)
            cpu_model = os.environ.get("PROCESSOR_IDENTIFIER") or platform.processor() or "CPU no identificada"
            vendor = "Microsoft Windows"
            machine = platform.machine()
        else:
            total_memory, available_memory = _linux_memory()
            os_name = _linux_os_name()
            try:
                uptime = int(float(_read_text(Path("/proc/uptime")).split()[0]))
            except (IndexError, ValueError):
                uptime = 0
            cpu_model = _linux_cpu_model()
            vendor = _read_text(Path("/sys/class/dmi/id/sys_vendor"), 256).strip()
            product = _read_text(Path("/sys/class/dmi/id/product_name"), 256).strip()
            vendor = " · ".join(value for value in (vendor, product) if value) or "Host Linux"
            machine = platform.machine()
        try:
            disk = shutil.disk_usage(self.app_root)
            disk_total, disk_used, disk_free = int(disk.total), int(disk.used), int(disk.free)
        except OSError:
            disk_total = disk_used = disk_free = 0
        memory_used = max(0, total_memory - available_memory)
        return {
            "hostname": socket.gethostname(), "os": os_name,
            "kernel": platform.release(), "architecture": machine,
            "cpu_model": cpu_model, "cpu_logical": int(os.cpu_count() or 1),
            "vendor": vendor, "uptime_seconds": uptime, "uptime_display": human_duration(uptime),
            "memory_total_bytes": total_memory, "memory_used_bytes": memory_used,
            "memory_available_bytes": available_memory, "memory_percent": _percent(memory_used, total_memory),
            "memory_total_display": human_bytes(total_memory), "memory_used_display": human_bytes(memory_used),
            "memory_available_display": human_bytes(available_memory),
            "disk_total_bytes": disk_total, "disk_used_bytes": disk_used, "disk_free_bytes": disk_free,
            "disk_percent": _percent(disk_used, disk_total), "disk_total_display": human_bytes(disk_total),
            "disk_used_display": human_bytes(disk_used), "disk_free_display": human_bytes(disk_free),
        }

    def _linux_service_rows(self) -> list[dict[str, Any]]:
        units = [unit for _, unit in LINUX_GIDEON_RESOURCE_UNITS]
        cp = self.runner([
            "systemctl", "show", "--no-pager",
            "--property=Id,LoadState,ActiveState,SubState,MemoryCurrent,CPUUsageNSec,TasksCurrent",
            *units,
        ], 5)
        by_unit = {str(row.get("Id") or ""): row for row in parse_systemd_show(cp.stdout or "")}
        rows: list[dict[str, Any]] = []
        for component, unit in LINUX_GIDEON_RESOURCE_UNITS:
            raw = by_unit.get(unit)
            if not raw or raw.get("LoadState") == "not-found":
                continue
            memory = _safe_int(raw.get("MemoryCurrent"))
            rows.append({
                "component": component, "label": SERVICE_LABELS[component], "unit": unit,
                "active": raw.get("ActiveState") == "active", "state": raw.get("ActiveState") or "unknown",
                "substate": raw.get("SubState") or "unknown", "memory_bytes": memory,
                "memory_display": human_bytes(memory), "cpu_total_ns": _safe_int(raw.get("CPUUsageNSec")),
                "tasks": _safe_int(raw.get("TasksCurrent")),
            })
        return rows

    def _fallback_process_row(self) -> list[dict[str, Any]]:
        if self.platform_name == "windows":
            memory, tasks = _windows_process_memory(), 1
        else:
            memory, tasks = _linux_process_memory()
        return [{
            "component": "web_admin", "label": "WebAdmin", "unit": "current-process",
            "active": True, "state": "active", "substate": "running",
            "memory_bytes": memory, "memory_display": human_bytes(memory),
            "cpu_total_ns": time.process_time_ns(), "tasks": tasks,
        }]

    def snapshot(self, *, force: bool = False) -> dict[str, Any]:
        with self._lock:
            now = time.monotonic()
            if not force and self._cache is not None and now - self._cache_at < self.cache_ttl_seconds:
                return copy.deepcopy(self._cache)
            warnings: list[str] = []
            try:
                host = self._host_snapshot()
            except Exception as exc:
                warnings.append(f"host:{type(exc).__name__}")
                host = {
                    "hostname": socket.gethostname(), "os": platform.platform(), "kernel": platform.release(),
                    "architecture": platform.machine(), "cpu_model": platform.processor() or "No disponible",
                    "cpu_logical": int(os.cpu_count() or 1), "vendor": "No disponible",
                    "uptime_seconds": 0, "uptime_display": "No disponible",
                    "memory_total_bytes": 0, "memory_used_bytes": 0, "memory_available_bytes": 0,
                    "memory_percent": 0.0, "memory_total_display": "No disponible",
                    "memory_used_display": "No disponible", "memory_available_display": "No disponible",
                    "disk_total_bytes": 0, "disk_used_bytes": 0, "disk_free_bytes": 0,
                    "disk_percent": 0.0, "disk_total_display": "No disponible",
                    "disk_used_display": "No disponible", "disk_free_display": "No disponible",
                }
            try:
                services = self._linux_service_rows() if self.platform_name == "linux" else self._fallback_process_row()
                if not services:
                    services = self._fallback_process_row()
                    warnings.append("services:fallback")
            except Exception as exc:
                warnings.append(f"services:{type(exc).__name__}")
                services = self._fallback_process_row()

            elapsed = max(0.001, now - self._previous_at)
            current_host_cpu = self._host_cpu_counter()
            host_cpu_percent: float | None = None
            if current_host_cpu and self._previous_host_cpu:
                total_delta = current_host_cpu[0] - self._previous_host_cpu[0]
                idle_delta = current_host_cpu[1] - self._previous_host_cpu[1]
                if total_delta > 0:
                    host_cpu_percent = round(max(0.0, min(100.0, (total_delta - idle_delta) * 100.0 / total_delta)), 1)

            logical_cpus = max(1, int(host.get("cpu_logical") or 1))
            service_cpu_percent = 0.0
            current_gideon_cpu: dict[str, int] = {}
            for row in services:
                unit = str(row.get("unit") or "")
                current_total = _safe_int(row.get("cpu_total_ns"))
                previous_total = self._previous_gideon_cpu.get(unit, current_total)
                delta = max(0, current_total - previous_total)
                row["cpu_percent"] = round(min(100.0, delta / 1_000_000_000.0 / elapsed / logical_cpus * 100.0), 1)
                service_cpu_percent += float(row["cpu_percent"])
                current_gideon_cpu[unit] = current_total
            if self.platform_name != "linux" and services:
                process_now = time.process_time_ns()
                process_delta = max(0, process_now - self._previous_process_cpu_ns)
                service_cpu_percent = round(min(100.0, process_delta / 1_000_000_000.0 / elapsed / logical_cpus * 100.0), 1)
                services[0]["cpu_percent"] = service_cpu_percent
                self._previous_process_cpu_ns = process_now

            gideon_memory = sum(_safe_int(row.get("memory_bytes")) for row in services)
            gideon_tasks = sum(_safe_int(row.get("tasks")) for row in services)
            gideon = {
                "cpu_percent": round(min(100.0, service_cpu_percent), 1),
                "memory_bytes": gideon_memory, "memory_display": human_bytes(gideon_memory),
                "memory_percent": _percent(gideon_memory, host.get("memory_total_bytes", 0)),
                "tasks": gideon_tasks, "active_services": sum(1 for row in services if row.get("active")),
                "total_services": len(services), "services": services,
            }
            host["cpu_percent"] = host_cpu_percent
            try:
                host["load_1m"] = round(float(os.getloadavg()[0]), 2)
            except (AttributeError, OSError):
                host["load_1m"] = None

            self._previous_at = now
            self._previous_host_cpu = current_host_cpu
            self._previous_gideon_cpu = current_gideon_cpu
            payload = {
                "available": bool(host.get("memory_total_bytes") or host.get("disk_total_bytes")),
                "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                "refresh_seconds": max(5, int(round(self.cache_ttl_seconds * 2))),
                "host": host, "gideon": gideon, "warnings": warnings,
            }
            self._cache = payload
            self._cache_at = now
            return copy.deepcopy(payload)
