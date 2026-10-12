#!/usr/bin/env bash
set -Eeuo pipefail

OUT="${1:-$PWD/gideon-linux-offline-cache}"
mkdir -p "$OUT/packages" "$OUT/metadata"

if [[ "$EUID" -ne 0 ]]; then
  echo "[ERROR] Run with sudo/root." >&2
  exit 10
fi

. /etc/os-release
DISTRO="${ID:-unknown}"
LIKE="${ID_LIKE:-}"
echo "Preparing offline package cache for ${PRETTY_NAME:-$DISTRO}"

if [[ "$DISTRO" =~ ^(ubuntu|debian)$ ]] || [[ "$LIKE" == *debian* ]]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  # ffprobe is supplied by the distro's signed ffmpeg package. GIDEON never
  # fetches standalone FFmpeg binaries or enables an external media repo.
  apt-get install -y --download-only --no-install-recommends \
    python3 python3-venv python3-pip rsync jq ca-certificates curl \
    yara clamav clamav-freshclam clamav-daemon clamdscan docker.io docker-compose-v2 certbot ffmpeg || true
  cp -av /var/cache/apt/archives/*.deb "$OUT/packages/" 2>/dev/null || true

elif [[ "$DISTRO" =~ ^(rhel|rocky|almalinux|fedora|centos)$ ]] \
  || [[ "$LIKE" == *rhel* ]] || [[ "$LIKE" == *fedora* ]]; then

  PM=dnf
  command -v dnf >/dev/null 2>&1 || PM=yum
  "$PM" install -y --downloadonly --downloaddir="$OUT/packages" \
    python3 python3-pip rsync jq ca-certificates curl yara clamav clamav-update podman ffmpeg || true
else
  echo "[ERROR] Unsupported distro family: $DISTRO" >&2
  exit 11
fi

python3 - "$OUT" <<'PY'
from pathlib import Path
import hashlib
import json
import sys

root = Path(sys.argv[1])
rows = []
for path in sorted((root / "packages").glob("*")):
    if path.is_file():
        rows.append(
            {
                "file": path.name,
                "size": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )

(root / "metadata" / "packages.json").write_text(
    json.dumps(rows, indent=2),
    encoding="utf-8",
)
PY

echo "OFFLINE_CACHE=PASS path=$OUT"
