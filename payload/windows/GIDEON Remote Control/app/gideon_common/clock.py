from __future__ import annotations

import datetime as dt


def now_iso(*, timespec: str = "seconds") -> str:
    return dt.datetime.now().astimezone().isoformat(timespec=timespec)
