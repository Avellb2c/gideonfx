from __future__ import annotations

"""Cross-platform subprocess helpers.

Administrative/background helpers must never create console windows or steal focus on
Windows. Interactive GUI programs (MSTSC/Remmina) are intentionally not launched
through these helpers because their windows are the requested user experience.
"""

import os
import subprocess
from typing import Any, Sequence

from gideon_common.process import windows_hidden_kwargs


def run_hidden(command: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[Any]:
    options = dict(kwargs)
    options.update(windows_hidden_kwargs())
    return subprocess.run(list(command), **options)


def popen_hidden(command: Sequence[str], *, new_process_group: bool = False, **kwargs: Any) -> subprocess.Popen[Any]:
    options = dict(kwargs)
    options.update(windows_hidden_kwargs(new_process_group=new_process_group))
    if os.name != "nt" and "start_new_session" not in options:
        options["start_new_session"] = True
    return subprocess.Popen(list(command), **options)


def check_output_hidden(command: Sequence[str], **kwargs: Any) -> bytes | str:
    options = dict(kwargs)
    options.update(windows_hidden_kwargs())
    return subprocess.check_output(list(command), **options)


__all__ = ["windows_hidden_kwargs", "run_hidden", "popen_hidden", "check_output_hidden"]
