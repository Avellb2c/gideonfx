from __future__ import annotations

"""Small best-effort observability helpers shared by runtime modules.

The application deliberately tolerates failures in cleanup/UI fallback paths, but
those failures must not disappear silently.  This helper records them without
changing control flow or introducing a dependency on the Qt/Tk layers.
"""

import logging
from typing import Any

from .redaction import redact_error

_LOG = logging.getLogger("gideon.best_effort")


def best_effort_warning(context: str, exc: BaseException | str, *args: Any) -> None:
    detail = redact_error(exc)
    if args:
        context = context.format(*args)
    _LOG.warning("%s: %s", context, detail)


def best_effort_debug(context: str, exc: BaseException | str, *args: Any) -> None:
    detail = redact_error(exc)
    if args:
        context = context.format(*args)
    _LOG.debug("%s: %s", context, detail)


__all__ = ["best_effort_warning", "best_effort_debug"]
