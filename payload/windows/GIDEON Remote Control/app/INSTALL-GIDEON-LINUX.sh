#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
exec "$ROOT/deploy/linux/INSTALL-GIDEON-LINUX.sh" "$@"
