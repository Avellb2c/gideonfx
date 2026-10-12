#!/usr/bin/env bash
# Construye gideon-agent_<version>_<arch>.deb totalmente autocontenido:
# el .deb lleva el runtime del agente, la config template, el unit de
# systemd y las ruedas (.whl) de sus dependencias Python, así que instalar
# en el servidor NO requiere acceso a internet ni a PyPI.
#
# Este script se corre en una máquina de build con internet (para bajar las
# ruedas una sola vez); el .deb resultante ya es offline-instalable.
#
# Uso:
#   ./build-deb.sh [version] [arch] [output_dir]
# Ejemplo:
#   ./build-deb.sh 6.0.3 amd64 dist/
set -euo pipefail

VERSION="${1:-2.4.0}"
ARCH="${2:-amd64}"
OUT_DIR="${3:-$(pwd)/dist}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
PKG_SRC="$SCRIPT_DIR/packaging"

command -v dpkg-deb >/dev/null 2>&1 || { echo "Falta dpkg-deb (apt install dpkg-dev)"; exit 1; }

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

APP="$STAGE/usr/lib/gideon-agent"
DOC="$STAGE/usr/share/doc/gideon-agent"
BIN="$STAGE/usr/bin"
SYSTEMD="$STAGE/lib/systemd/system"
DEBIAN="$STAGE/DEBIAN"
mkdir -p "$APP/vendor" "$DOC" "$BIN" "$SYSTEMD" "$DEBIAN"

# --- 1. Runtime del Agent: una única clausura validada para todos los paquetes ---
# Do not maintain a second, stale list here.  gideon_agent_payload validates every
# local import and copies the same runtime closure used by Downloads/Updates.
# This includes the optional isolated Player and its VLC provenance notice; VLC
# itself is deliberately never bundled, installed or downloaded by GIDEON.
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

# --- 2. Plantilla de configuración e identidad (sin secretos) ---
python3 - "$APP/agent.template.json" "$VERSION" <<'PYEOF'
import json, sys
out, version = sys.argv[1], sys.argv[2]
cfg = {
    "schema_version": 2,
    "agent_version": version,
    "agent_protocol": 2,
    "site_code": "",
    "site_name": "",
    "host_profile": "linux_aws_x64",
    "data_dir": "/var/lib/gideon-agent",
    "poll_seconds": 5,
    "status_seconds": 5,
    "security": {
        "package_signature_required": True,
        "trusted_signing_public_key": "gideon_agent_signing_public.pem",
        "job_freshness_required": True,
        "mtls_required": False,
    },
    "control_plane": {
        "base_url": "",
        "connectivity_mode": "production",
        "endpoints": [],
        "network_check_seconds": 3,
        "require_https": True,
        "verify_tls": True,
        "minimum_tls": "TLSv1.2",
        "prefer_tls13": True,
        "timeout_seconds": 20,
    },
    "enrollment_secret_env": "GIDEON_AGENT_ENROLL_SECRET",
}
open(out, "w", encoding="utf-8").write(json.dumps(cfg, ensure_ascii=False, indent=2))
PYEOF

cp "$SCRIPT_DIR/packaging/configure-agent.py" "$APP/configure-agent.py"
printf '%s\n' 'cryptography>=45,<48' 'pystray>=0.19,<1' 'Pillow>=10,<12' > "$APP/requirements-agent.txt"

# Clave pública de firma Ed25519 (si ya existe una emitida por el Control Center)
if [ -f "$REPO_ROOT/gideon_agent_signing_public.pem" ]; then
    cp "$REPO_ROOT/gideon_agent_signing_public.pem" "$APP/gideon_agent_signing_public.pem"
fi

# --- 3. Vendorizar dependencias como ruedas (.whl) para instalación offline ---
if command -v pip3 >/dev/null 2>&1; then
    pip3 download --only-binary=:all: --platform manylinux2014_x86_64 \
        --python-version 3.11 -r "$APP/requirements-agent.txt" -d "$APP/vendor" \
        || pip3 download -r "$APP/requirements-agent.txt" -d "$APP/vendor" \
        || echo "AVISO: no se pudieron descargar ruedas (sin red). El .deb quedará sin vendor/ y el postinst necesitará red."
else
    echo "AVISO: pip3 no disponible en esta máquina de build; vendor/ quedará vacío."
fi

# --- 4. systemd unit + scripts de mantenimiento ---
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
install -m 755 "$PKG_SRC/preinst" "$DEBIAN/preinst"
install -m 755 "$PKG_SRC/postinst" "$DEBIAN/postinst"
install -m 755 "$PKG_SRC/prerm" "$DEBIAN/prerm"
install -m 755 "$PKG_SRC/postrm" "$DEBIAN/postrm"

DEPENDS="python3 (>= 3.9), python3-venv"
INSTALLED_SIZE="$(du -sk "$STAGE" | cut -f1)"
cat > "$DEBIAN/control" <<EOF
Package: gideon-agent
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: ${ARCH}
Depends: ${DEPENDS}
Recommends: acl
Installed-Size: ${INSTALLED_SIZE}
Maintainer: GIDEON Infraestructura <infraestructura@gideon.example.invalid>
Description: Gideon Rx Agent
 Agente multiplataforma que se conecta de salida (outbound HTTPS) hacia el
 Gateway del Gideon Rx para recibir Jobs, ejecutar scripts firmados
 y reportar resultados. Instala como servicio systemd (gideon-agent).
EOF

cp "$REPO_ROOT/README-AGENT-DOWNLOADS.md" "$DOC/README.md" 2>/dev/null || true
cp "$REPO_ROOT/THIRD_PARTY_VLC_NOTICE.txt" "$DOC/THIRD_PARTY_VLC_NOTICE.txt" 2>/dev/null || true

mkdir -p "$OUT_DIR"
FINAL="$OUT_DIR/gideon-agent_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "$STAGE" "$FINAL"
echo "Generado: $FINAL"

