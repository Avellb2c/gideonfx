#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
exec "$ROOT/deploy/ubuntu/INSTALL-GIDEON-UBUNTU.sh" "$@"
