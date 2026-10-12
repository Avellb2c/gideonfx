from __future__ import annotations

import os
import subprocess
from typing import Any


def windows_hidden_kwargs(*, new_process_group: bool = False) -> dict[str, Any]:
    if os.name != "nt":
        return {}
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = getattr(subprocess, "SW_HIDE", 0)
    flags = int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if new_process_group:
        flags |= int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
    return {"startupinfo": startup, "creationflags": flags}
