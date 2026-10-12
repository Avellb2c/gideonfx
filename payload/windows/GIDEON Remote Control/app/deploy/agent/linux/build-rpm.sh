#!/usr/bin/env bash
# Construye gideon-agent-<version>-1.noarch.rpm con perfil de arquitectura destino.
# El payload es Python puro; no se genera debuginfo/ELF. Requiere rpmbuild + file + tar + gzip.
#
# Uso:
#   ./build-rpm.sh [version] [arch] [output_dir]
set -euo pipefail

VERSION="${1:-2.4.0}"
ARCH="${2:-x86_64}"
OUT_DIR="${3:-$(pwd)/dist}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
PKG_SRC="$SCRIPT_DIR/packaging"

for cmd in rpmbuild file tar gzip; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "Falta $cmd para construir RPM."; exit 1; }
done

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

APP="$STAGE/usr/lib/gideon-agent"
BIN="$STAGE/usr/bin"
SYSTEMD="$STAGE/lib/systemd/system"
mkdir -p "$APP/vendor" "$BIN" "$SYSTEMD"

# Keep native RPM packages on the exact same validated runtime closure as the
# signed download/update builders.  A duplicated hard-coded list previously
# allowed new Agent modules to be omitted from only native Linux packages.
python3 - "$REPO_ROOT" "$APP" <<'PYEOF'
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
target = Path(sys.argv[2]).resolve()
sys.path.insert(0, str(root))
from gideon_agent_payload import copy_agent_runtime_payload

copy_agent_runtime_payload(root, target)
PYEOF
install -m 755 "$SCRIPT_DIR/gideon-agent-player-launch" "$APP/gideon-agent-player-launch"
cp "$SCRIPT_DIR/packaging/configure-agent.py" "$APP/configure-agent.py"
printf '%s\n' 'cryptography>=45,<48' 'pystray>=0.19,<1' 'Pillow>=10,<12' > "$APP/requirements-agent.txt"
[ -f "$REPO_ROOT/gideon_agent_signing_public.pem" ] && cp "$REPO_ROOT/gideon_agent_signing_public.pem" "$APP/gideon_agent_signing_public.pem" || true

python3 - "$APP/agent.template.json" "$VERSION" <<'PYEOF'
import json, sys
out, version = sys.argv[1], sys.argv[2]
cfg = {
    "schema_version": 2, "agent_version": version, "agent_protocol": 2,
    "site_code": "", "site_name": "", "host_profile": "linux_aws_x64",
    "data_dir": "/var/lib/gideon-agent", "poll_seconds": 5, "status_seconds": 5,
    "security": {"package_signature_required": True, "trusted_signing_public_key": "gideon_agent_signing_public.pem", "job_freshness_required": True, "mtls_required": False},
    "control_plane": {"base_url": "", "connectivity_mode": "production", "endpoints": [], "network_check_seconds": 3, "require_https": True, "verify_tls": True, "minimum_tls": "TLSv1.2", "prefer_tls13": True, "timeout_seconds": 20},
    "enrollment_secret_env": "GIDEON_AGENT_ENROLL_SECRET",
}
open(out, "w", encoding="utf-8").write(json.dumps(cfg, ensure_ascii=False, indent=2))
PYEOF

if command -v pip3 >/dev/null 2>&1; then
    pip3 download -r "$APP/requirements-agent.txt" -d "$APP/vendor" \
        || echo "AVISO: sin red, vendor/ queda vacío; el %post del rpm necesitará red."
fi

cp "$PKG_SRC/gideon-agent.service" "$SYSTEMD/gideon-agent.service"
cp "$PKG_SRC/gideon-agent-player-launch.service" "$SYSTEMD/gideon-agent-player-launch.service"
cp "$PKG_SRC/gideon-agent-player-launch.timer" "$SYSTEMD/gideon-agent-player-launch.timer"
install -m 755 "$PKG_SRC/gideon-agent-configure" "$BIN/gideon-agent-configure"
cat > "$BIN/gideon-agent-player-launch" <<'EOF'
#!/bin/sh
set -eu
exec /usr/lib/gideon-agent/gideon-agent-player-launch "$@"
EOF
chmod 0755 "$BIN/gideon-agent-player-launch"

mkdir -p "$OUT_DIR"
sed \
    -e "s/%{_gideon_version}/${VERSION}/g" \
    -e "s/%{_gideon_arch}/${ARCH}/g" \
    -e "s/%{_gideon_stage}/$(printf '%s' "$STAGE" | sed 's/[&/\]/\\&/g')/g" \
    -e "s/%{_gideon_changelog_date}/$(date '+%a %b %d %Y')/g" \
    "$PKG_SRC/gideon-agent.spec.template" > "$STAGE/gideon-agent.spec"

rpmbuild -bb --define "_topdir $STAGE/rpmbuild" --define "_rpmdir $OUT_DIR" \
    --define "debug_package %{nil}" "$STAGE/gideon-agent.spec"
echo "Generado en: $OUT_DIR"
