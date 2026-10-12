from __future__ import annotations

"""Bounded Windows workstation-session handoff helper.

The RDP confirmation shown to the user who is currently at the console belongs
to that user's interactive desktop; it cannot reliably be accepted through the
new Guacamole/RDP stream.  The Agent service therefore starts a short-lived
helper in the active console session when WebAdmin explicitly authorizes a
single-interactive-session handoff.  The helper only clicks a positively
identified Windows/RDP confirmation dialog and exits after one action or a
short timeout.
"""

import ctypes
import os
import subprocess
import sys
import threading
import time
from ctypes import wintypes
from pathlib import Path
from typing import Any, Callable


_MAX_TEXT = 512
_MAX_USER = 128
_DEFAULT_TIMEOUT = 35.0
_CREATE_UNICODE_ENVIRONMENT = 0x00000400
_CREATE_NO_WINDOW = 0x08000000
_STARTF_USESHOWWINDOW = 0x00000001
_SW_HIDE = 0
_WM_COMMAND = 0x0111
_BM_CLICK = 0x00F5
_IDOK = 1
_VK_RETURN = 0x0D
_KEYEVENTF_KEYUP = 0x0002

_CONTEXT_WORDS = (
    "remote desktop", "escritorio remoto", "another user", "otro usuario",
    "connected", "conectado", "session", "sesión", "sesion", "disconnect",
    "desconectar", "log off", "cerrar sesión", "cerrar sesion", "sign in",
    "iniciar sesión", "iniciar sesion", "log on", "signed in", "logged on",
    "conexión existente", "conexion existente", "existing connection",
    "continue", "continuar", "will be disconnected", "será desconectado",
    "sera desconectado", "se desconectará", "se desconectara",
)
_AFFIRMATIVE_WORDS = (
    "yes", "sí", "si", "allow", "permitir", "continue", "continuar",
    "accept", "aceptar", "ok",
)
_NEGATIVE_WORDS = ("no", "cancel", "cancelar", "deny", "rechazar")


def _text(value: Any, limit: int = _MAX_TEXT) -> str:
    return " ".join(str(value or "").split())[:limit]


def _user(value: Any) -> str:
    value = _text(value, _MAX_USER).casefold()
    if "\\" in value:
        value = value.rsplit("\\", 1)[-1]
    if "@" in value:
        value = value.split("@", 1)[0]
    return value.strip()


def _window_text(user32: Any, hwnd: int) -> str:
    chunks: list[str] = []
    for getter in (user32.GetWindowTextW, user32.GetClassNameW):
        buffer = ctypes.create_unicode_buffer(_MAX_TEXT)
        try:
            getter(hwnd, buffer, _MAX_TEXT)
            chunks.append(buffer.value)
        except Exception:
            pass

    enum_child = getattr(user32, "EnumChildWindows", None)
    if enum_child is not None:
        callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

        def child_callback(child: int, _lparam: int) -> bool:
            buffer = ctypes.create_unicode_buffer(_MAX_TEXT)
            try:
                user32.GetWindowTextW(child, buffer, _MAX_TEXT)
                if buffer.value:
                    chunks.append(buffer.value)
            except Exception:
                pass
            return True

        try:
            enum_child(hwnd, callback_type(child_callback), 0)
        except Exception:
            pass
    return " ".join(chunks)


def _is_switch_prompt(text: str, *, active_user: str, requested_user: str) -> bool:
    normalized = _text(text).casefold()
    if not normalized:
        return False
    has_context = any(word in normalized for word in _CONTEXT_WORDS)
    if not has_context:
        return False
    # Prefer a prompt that names the user being displaced.  If Windows omits
    # the name in the localized dialog, the explicit RDP/session context is
    # still required before any button can be considered.
    if active_user and active_user in normalized:
        return True
    if requested_user and requested_user in normalized:
        return True
    return any(phrase in normalized for phrase in (
        "allow this user", "permitir que este usuario", "disconnect this user",
        "desconectar a este usuario", "another user is connected",
        "hay otro usuario conectado", "do you want to continue",
        "¿desea continuar", "desea continuar", "the user is currently signed in",
        "el usuario está conectado", "el usuario esta conectado",
    ))


def _find_affirmative_button(user32: Any, hwnd: int) -> int | None:
    enum_child = getattr(user32, "EnumChildWindows", None)
    if enum_child is None:
        return None
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    found: list[int] = []

    def callback(child: int, _lparam: int) -> bool:
        buffer = ctypes.create_unicode_buffer(_MAX_TEXT)
        try:
            user32.GetWindowTextW(child, buffer, _MAX_TEXT)
            label = _text(buffer.value).casefold()
            if label and any(word == label or word in label for word in _AFFIRMATIVE_WORDS):
                if not any(word in label for word in _NEGATIVE_WORDS):
                    found.append(int(child))
                    return False
        except Exception:
            pass
        return True

    try:
        enum_child(hwnd, callback_type(callback), 0)
    except Exception:
        return None
    return found[0] if found else None


def _send_enter(user32: Any) -> bool:
    class KEYBDINPUT(ctypes.Structure):
        _fields_ = [("wVk", wintypes.WORD), ("wScan", wintypes.WORD),
                    ("dwFlags", wintypes.DWORD), ("time", wintypes.DWORD),
                    ("dwExtraInfo", ctypes.c_size_t)]

    class INPUT(ctypes.Structure):
        _fields_ = [("type", wintypes.DWORD), ("ki", KEYBDINPUT)]

    inputs = (INPUT * 2)()
    inputs[0].type = 1
    inputs[0].ki = KEYBDINPUT(_VK_RETURN, 0, 0, 0, 0)
    inputs[1].type = 1
    inputs[1].ki = KEYBDINPUT(_VK_RETURN, 0, _KEYEVENTF_KEYUP, 0, 0)
    try:
        return int(user32.SendInput(2, ctypes.byref(inputs), ctypes.sizeof(INPUT))) == 2
    except Exception:
        return False


def _helper_main(*, active_user: str, requested_user: str, timeout_seconds: float) -> dict[str, Any]:
    if os.name != "nt":
        return {"accepted": False, "reason": "not-windows"}
    user32 = ctypes.windll.user32
    deadline = time.monotonic() + max(5.0, min(float(timeout_seconds), 45.0))
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    while time.monotonic() < deadline:
        candidates: list[tuple[int, str]] = []

        def callback(hwnd: int, _lparam: int) -> bool:
            try:
                if user32.IsWindowVisible(hwnd):
                    text = _window_text(user32, hwnd)
                    if _is_switch_prompt(text, active_user=active_user, requested_user=requested_user):
                        candidates.append((int(hwnd), text))
            except Exception:
                pass
            return True

        try:
            user32.EnumWindows(callback_type(callback), 0)
        except Exception:
            candidates = []
        for hwnd, _window in candidates:
            button = _find_affirmative_button(user32, hwnd)
            if button:
                try:
                    user32.SendMessageW(button, _BM_CLICK, 0, 0)
                    return {"accepted": True, "method": "BM_CLICK"}
                except Exception:
                    pass
            try:
                user32.SetForegroundWindow(hwnd)
            except Exception:
                pass
            if _send_enter(user32):
                return {"accepted": True, "method": "SEND_INPUT_ENTER"}
        time.sleep(0.20)
    return {"accepted": False, "reason": "timeout"}


def _helper_entry(argv: list[str]) -> int:
    values = {str(argv[index]): str(argv[index + 1]) for index in range(len(argv) - 1) if argv[index].startswith("--")}
    result = _helper_main(
        active_user=_user(values.get("--active-user")),
        requested_user=_user(values.get("--requested-user")),
        timeout_seconds=float(values.get("--timeout", _DEFAULT_TIMEOUT)),
    )
    return 0 if result.get("accepted") else 1


def _spawn_in_active_session(*, request_id: str, active_user: str, requested_user: str, timeout_seconds: float) -> bool:
    if os.name != "nt":
        return False
    kernel32 = ctypes.windll.kernel32
    wtsapi32 = ctypes.windll.wtsapi32
    advapi32 = ctypes.windll.advapi32
    session_id = int(kernel32.WTSGetActiveConsoleSessionId())
    if session_id == 0xFFFFFFFF:
        return False
    token = wintypes.HANDLE()
    wtsapi32.WTSQueryUserToken.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    wtsapi32.WTSQueryUserToken.restype = wintypes.BOOL
    if not wtsapi32.WTSQueryUserToken(session_id, ctypes.byref(token)):
        return False

    class STARTUPINFO(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR),
                    ("lpTitle", wintypes.LPWSTR), ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                    ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD), ("dwXCountChars", wintypes.DWORD),
                    ("dwYCountChars", wintypes.DWORD), ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                    ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD), ("lpReserved2", ctypes.POINTER(ctypes.c_ubyte)),
                    ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE)]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                    ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]

    executable = str(Path(sys.executable).resolve())
    if getattr(sys, "frozen", False):
        command = [executable, "--session-switch-helper", "--request-id", request_id,
                   "--active-user", active_user, "--requested-user", requested_user,
                   "--timeout", str(int(timeout_seconds))]
    else:
        command = [executable, str(Path(__file__).resolve()), "--session-switch-helper", "--request-id", request_id,
                   "--active-user", active_user, "--requested-user", requested_user,
                   "--timeout", str(int(timeout_seconds))]
    cmdline = subprocess.list2cmdline(command)
    command_buffer = ctypes.create_unicode_buffer(cmdline)
    startup = STARTUPINFO()
    startup.cb = ctypes.sizeof(STARTUPINFO)
    startup.lpDesktop = r"winsta0\default"
    startup.dwFlags = _STARTF_USESHOWWINDOW
    startup.wShowWindow = _SW_HIDE
    process = PROCESS_INFORMATION()
    try:
        advapi32.CreateProcessAsUserW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPWSTR,
            ctypes.c_void_p, ctypes.c_void_p, wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p,
            wintypes.LPCWSTR, ctypes.POINTER(STARTUPINFO), ctypes.POINTER(PROCESS_INFORMATION)]
        advapi32.CreateProcessAsUserW.restype = wintypes.BOOL
        ok = advapi32.CreateProcessAsUserW(
            token, executable, command_buffer, None, None, False,
            _CREATE_UNICODE_ENVIRONMENT | _CREATE_NO_WINDOW, None,
            str(Path(__file__).resolve().parent), ctypes.byref(startup), ctypes.byref(process),
        )
        return bool(ok)
    finally:
        if process.hThread:
            kernel32.CloseHandle(process.hThread)
        if process.hProcess:
            kernel32.CloseHandle(process.hProcess)
        if token:
            kernel32.CloseHandle(token)


def spawn_session_switch_watcher(*, request_id: str, active_user: str, requested_user: str,
                                 timeout_seconds: float = _DEFAULT_TIMEOUT,
                                 status_callback: Callable[[dict[str, Any]], None] | None = None) -> bool:
    """Start one helper in the active user's desktop; never blocks the tunnel."""
    if os.name != "nt":
        return False
    active = _user(active_user)
    requested = _user(requested_user)
    request = _text(request_id, 80)
    if not active or not requested or active == requested or not request:
        return False

    def run() -> None:
        try:
            ok = _spawn_in_active_session(
                request_id=request, active_user=active, requested_user=requested,
                timeout_seconds=timeout_seconds,
            )
            result = {"scheduled": bool(ok), "request_id": request, "active_user": active}
        except Exception as exc:
            result = {"scheduled": False, "request_id": request, "error": f"{type(exc).__name__}: {exc}"[:240]}
        if status_callback:
            try:
                status_callback(result)
            except Exception:
                pass

    threading.Thread(target=run, name="GIDEONAgent-SessionHandoff", daemon=True).start()
    return True


def run_session_switch_helper(argv: list[str]) -> int:
    """Entry point used by the short-lived process created in the console session."""
    return _helper_entry(list(argv or []))


__all__ = ["spawn_session_switch_watcher", "run_session_switch_helper"]
