#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "$EUID" -ne 0 ]]; then
  exec sudo -- bash "$0" "$@"
fi
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PY=/opt/gideon/web/venv/bin/python
[[ -x "$PY" ]] || { echo '[FAIL] Instale primero GIDEON Master Linux.' >&2; exit 1; }
if [[ $# -eq 0 ]]; then set -- --wizard; fi
exec flock -n /run/lock/gideon-external-access.lock "$PY" "$ROOT/gideon_external_access.py" "$@"
