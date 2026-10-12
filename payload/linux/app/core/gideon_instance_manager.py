"""
GIDEON Remote Control RC20.4 Process Identity Manager
"""

import json
import os
import socket
import time
from pathlib import Path

ROOT = Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) / "GIDEON Remote Control"
IDENTITY = ROOT / "runtime" / "identity"

def write_identity(service, pid):
    IDENTITY.mkdir(parents=True, exist_ok=True)
    data = {
        "service": service,
        "pid": pid,
        "host": socket.gethostname(),
        "started": time.strftime("%Y-%m-%dT%H:%M:%S")
    }
    (IDENTITY / f"{service}.identity.json").write_text(
        json.dumps(data, indent=2),
        encoding="utf-8"
    )
