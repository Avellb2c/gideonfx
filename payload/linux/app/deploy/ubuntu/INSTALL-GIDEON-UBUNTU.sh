#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CORE="$ROOT/deploy/aws/install_gideon_aws.sh"
if [ "$(id -u)" -eq 0 ]; then exec "$CORE" --platform-mode ubuntu "$@"; fi
command -v sudo >/dev/null 2>&1 || { echo "ERROR: ejecute como root o instale/use sudo para elevar únicamente el instalador GIDEON." >&2; exit 1; }
exec sudo "$CORE" --platform-mode ubuntu "$@"
