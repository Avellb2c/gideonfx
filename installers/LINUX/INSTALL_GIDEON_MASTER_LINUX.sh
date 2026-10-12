#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if [[ "$EUID" -ne 0 ]]; then
  command -v sudo >/dev/null 2>&1 || {
    echo "[ERROR] sudo no esta disponible; ejecute como root." >&2
    exit 10
  }
  exec sudo --preserve-env=GIDEON_ALLOW_ONLINE_INSTALL -- bash "$0" "$@"
fi

export GIDEON_ALLOW_ONLINE_INSTALL="${GIDEON_ALLOW_ONLINE_INSTALL:-1}"
exec bash "$SCRIPT_DIR/install-gideon-master-linux.sh" "$@"
