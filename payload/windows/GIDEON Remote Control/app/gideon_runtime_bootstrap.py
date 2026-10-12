from __future__ import annotations

from gideon_common.observability import best_effort_warning

from gideon_version import PRODUCT_VERSION
"""Silent adaptive launcher for GIDEON Remote Control Desktop.

The bootstrap only self-heals Python runtime dependencies. System-wide components
(OpenSSH, Remmina, platform packagers, etc.) are audited and exposed in Settings because changing
system packages may require administrative authorization.
"""

import json
import os
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path

from gideon_infrastructure.subprocess_utils import popen_hidden, run_hidden
from gideon_platform import detect_platform

ROOT = Path(__file__).resolve().parent
LOG_DIR = ROOT / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "runtime-bootstrap.log"
SNAPSHOT_FILE = LOG_DIR / "runtime-preflight.json"
GUI_STARTUP_LOG = LOG_DIR / "gui-startup.log"


def _log(message: str) -> None:
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with LOG_FILE.open("a", encoding="utf-8") as handle:
        handle.write(f"[{stamp}] {message}\n")


def _native_error(title: str, message: str) -> None:
    _log(f"ERROR {title}: {message}")
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, message, title, 0x10)
            return
        except Exception as exc:
            best_effort_warning("No se pudo mostrar MessageBox de error de arranque", exc)
    # No terminal is spawned; stderr is useful only when launched from one.
    try:
        print(f"{title}: {message}", file=sys.stderr)
    except Exception as exc:
        best_effort_warning("No se pudo escribir el error de arranque en stderr", exc)


def _runtime_ready() -> tuple[bool, str]:
    if sys.version_info < (3, 11):
        return False, f"Python {sys.version.split()[0]} detectado; se requiere Python 3.11+."
    missing: list[str] = []
    for module in ("PySide6", "cryptography", "openpyxl"):
        try:
            __import__(module)
        except Exception:
            missing.append(module)
    return not missing, ("" if not missing else "Faltan módulos Python: " + ", ".join(missing))


def _repair_python_runtime() -> tuple[bool, str]:
    requirements = ROOT / "requirements-runtime.txt"
    command = [
        sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "--no-input",
        "--upgrade-strategy", "only-if-needed", "-r", str(requirements),
    ]
    _log("Reparando runtime Python en segundo plano: " + " ".join(command))
    try:
        proc = run_hidden(
            command,
            cwd=str(ROOT),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=1800,
        )
        output = (proc.stdout or "").strip()
        if output:
            _log(output[-12000:])
        return proc.returncode == 0, output
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def _write_system_snapshot() -> None:
    try:
        from gideon_dependency_manager import SystemDependencyManager
        manager = SystemDependencyManager(ROOT)
        rows = manager.scan()
        profile = detect_platform()
        payload = {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "platform": asdict(profile),
            "dependencies": [asdict(item) for item in rows],
            "missing": [item.key for item in rows if not item.installed],
        }
        temp = SNAPSHOT_FILE.with_suffix(".json.tmp")
        temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        temp.replace(SNAPSHOT_FILE)
        _log(f"Preflight: {len(payload['missing'])} requisito(s) no disponible(s).")
    except Exception as exc:
        _log(f"Preflight de sistema no bloqueante falló: {type(exc).__name__}: {exc}")


def main() -> int:
    profile = detect_platform()
    _log("=" * 72)
    _log(f"Inicio v{PRODUCT_VERSION} · {profile.label}")
    if profile.family not in {"windows", "linux"}:
        _native_error("GIDEON Remote Control", f"Sistema no soportado por la edición Desktop: {profile.label}")
        return 2
    if profile.family == "windows" and profile.windows_server_core:
        _native_error(
            "GIDEON Remote Control",
            "Windows Server Core no dispone de escritorio para Qt/MSTSC. Use Desktop Experience para la consola gráfica.",
        )
        return 3

    ready, detail = _runtime_ready()
    if not ready:
        _log(detail)
        ok, output = _repair_python_runtime()
        if not ok:
            _native_error(
                "GIDEON Remote Control · dependencias",
                "No se pudo preparar el runtime Python. Revise logs\\runtime-bootstrap.log.\n\n" + (output[-2500:] if output else detail),
            )
            return 4
        ready, detail = _runtime_ready()
        if not ready:
            _native_error("GIDEON Remote Control · dependencias", detail)
            return 5

    _write_system_snapshot()

    gui = ROOT / "gideon_qt_gui.py"
    env = {**os.environ, "GIDEON_PLATFORM_PROFILE": profile.family, "GIDEON_SILENT_SUBPROCESSES": "1"}
    try:
        GUI_STARTUP_LOG.parent.mkdir(parents=True, exist_ok=True)
        with GUI_STARTUP_LOG.open("a", encoding="utf-8") as startup_log:
            startup_log.write(
                f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] BOOTSTRAP_LAUNCH v{PRODUCT_VERSION} "
                f"python={sys.version.split()[0]} exe={sys.executable}\n"
            )
            startup_log.flush()
            proc = popen_hidden(
                [sys.executable, str(gui)],
                cwd=str(ROOT),
                stdin=subprocess.DEVNULL,
                stdout=startup_log,
                stderr=subprocess.STDOUT,
                env=env,
            )
        # Catch import/constructor failures that terminate immediately. A return
        # code of 0 is also valid when the first process only relays to UAC.
        try:
            rc = proc.wait(timeout=1.8)
        except subprocess.TimeoutExpired:
            return 0
        if rc not in (0, None):
            try:
                tail = GUI_STARTUP_LOG.read_text(encoding="utf-8", errors="replace")[-3500:]
            except Exception:
                tail = ""
            _native_error(
                "GIDEON Remote Control · inicio",
                "La interfaz terminó durante el arranque.\n\n"
                + (tail or f"Código de salida: {rc}")
                + f"\n\nLog: {GUI_STARTUP_LOG}",
            )
            return 10
        return 0
    except Exception as exc:
        _native_error(
            "GIDEON Remote Control · inicio",
            f"No se pudo lanzar la interfaz: {type(exc).__name__}: {exc}\n\nLog: {GUI_STARTUP_LOG}",
        )
        return 11


if __name__ == "__main__":
    raise SystemExit(main())
