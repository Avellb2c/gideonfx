#!/usr/bin/env bash
set -euo pipefail
umask 027
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: ejecute con sudo/root: sudo ./deploy/aws/install_gideon_aws.sh" >&2
  exit 1
fi
if [ -f /var/lib/gideon/tls-manager/active.json ]; then
  echo 'ERROR: hay un cambio TLS pendiente desde WebAdmin. Confírmelo o espere la restauración antes de reinstalar.' >&2
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LOG_DIR=/var/log/gideon/installer
mkdir -p "$LOG_DIR"
INSTALL_LOG="$LOG_DIR/install-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$INSTALL_LOG") 2>&1

CREATE_HOST_ADMIN=0
PLATFORM_MODE="auto"
INITIAL_UBUNTU_USER="damautapp"
INITIAL_UBUNTU_PASSWORD=""
UBUNTU_USER_CREATED=0

usage(){
  cat <<'EOF'
Uso: sudo ./deploy/aws/install_gideon_aws.sh [opciones]

Opciones P8H OneClick:
  --platform-mode MODE      auto | ubuntu | linux. Los OneClick fijan este valor automáticamente.
  --create-host-admin       Crea explícitamente un usuario administrativo local GIDEON si no existe.
  --host-admin-user USER    Nombre del usuario a crear (requiere --create-host-admin).
  -h, --help                Muestra esta ayuda.

Por defecto NO se crea, modifica ni agrega a sudo ningún usuario humano del host.
Las cuentas de servicio gideongateway/gideonweb/gideonbackup/gideonmonitor sí pertenecen a GIDEON.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --platform-mode)
      [ "$#" -ge 2 ] || { echo "ERROR: --platform-mode requiere auto|ubuntu|linux" >&2; exit 2; }
      PLATFORM_MODE="$2"; shift 2 ;;
    --create-host-admin) CREATE_HOST_ADMIN=1; shift ;;
    --host-admin-user)
      [ "$#" -ge 2 ] || { echo "ERROR: --host-admin-user requiere un valor" >&2; exit 2; }
      INITIAL_UBUNTU_USER="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERROR: opción desconocida: $1" >&2; usage >&2; exit 2 ;;
  esac
done
case "$PLATFORM_MODE" in auto|ubuntu|linux) ;; *) echo "ERROR: --platform-mode debe ser auto|ubuntu|linux" >&2; exit 2 ;; esac
if [ "$CREATE_HOST_ADMIN" -ne 1 ] && [ "$INITIAL_UBUNTU_USER" != "damautapp" ]; then
  echo "ERROR: --host-admin-user requiere --create-host-admin" >&2
  exit 2
fi
if ! [[ "$INITIAL_UBUNTU_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
  echo "ERROR: nombre de usuario administrativo inválido" >&2
  exit 2
fi

INITIAL_WEB_USER="dchaskypp"
INITIAL_WEB_PASSWORD="$(openssl rand -hex 18)"
WEB_ADMIN_CREATED=0
DEFAULT_WEB_PORT="${GIDEON_WEB_INTERNAL_PORT:-28443}"
DEFAULT_GATEWAY_PORT="${GIDEON_GATEWAY_INTERNAL_PORT:-29443}"

say(){ printf '\n[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
fail(){ echo "ERROR: $*" >&2; exit 1; }
ask_required(){
  local prompt="$1" value=""
  while [ -z "$value" ]; do read -r -p "$prompt" value; value="$(printf '%s' "$value" | xargs)"; done
  printf '%s' "$value"
}
ask_default(){ local prompt="$1" def="$2" value=""; read -r -p "$prompt [$def]: " value; printf '%s' "${value:-$def}"; }
yesno(){ local prompt="$1" def="${2:-N}" value=""; read -r -p "$prompt [$def]: " value; value="${value:-$def}"; [[ "$value" =~ ^[YySs]$ ]]; }

validate_port(){
  local p="$1"
  [[ "$p" =~ ^[0-9]+$ ]] || return 1
  (( p >= 1024 && p <= 65535 )) || return 1
  (( p != 443 && p != 22 )) || return 1
}
port_in_use(){ ss -ltnH 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)$1$"; }

say "GIDEON Remote Control 6.3.4-rc30 RELEASE-P8H-RC22-SELF-CONTAINED-AGENT · instalación segura aislada Linux/Ubuntu"
echo "Este instalador NO modifica SSH/sshd, NO usa ni modifica el puerto 443 y NO altera UFW/Security Groups."
echo "No reutiliza el virtualenv de su usuario ni modifica servicios/BBDD existentes."

if [ -r /etc/os-release ]; then . /etc/os-release; else fail "No se pudo identificar el sistema operativo."; fi
OS_ID="${ID:-unknown}"
OS_LIKE="${ID_LIKE:-}"
case "$OS_ID:$OS_LIKE" in
  ubuntu:*|*:ubuntu*) GIDEON_LINUX_FAMILY="ubuntu" ;;
  debian:*|*:debian*) GIDEON_LINUX_FAMILY="debian" ;;
  rhel:*|rocky:*|almalinux:*|centos:*|fedora:*|*:rhel*|*:fedora*) GIDEON_LINUX_FAMILY="rpm" ;;
  *) fail "Distribución Linux no soportada por este OneClick: ${PRETTY_NAME:-$OS_ID}. Use Ubuntu 24.04+ o Linux systemd Debian/RHEL compatible." ;;
esac
if [ "$PLATFORM_MODE" = "ubuntu" ] && [ "$GIDEON_LINUX_FAMILY" != "ubuntu" ]; then
  fail "Este paquete es exclusivo para Ubuntu. Use GIDEON-Remote-Control-LINUX-ONECLICK para ${PRETTY_NAME:-$OS_ID}."
fi
if [ "$PLATFORM_MODE" = "linux" ] && [ "$GIDEON_LINUX_FAMILY" = "ubuntu" ]; then
  fail "Este paquete Linux genérico no instala sobre Ubuntu. Use GIDEON-Remote-Control-UBUNTU-ONECLICK."
fi
command -v systemctl >/dev/null 2>&1 || fail "GIDEON Control Plane requiere systemd/systemctl en Linux."

WEB_PUBLIC_HOST="${GIDEON_WEB_HOST:-$(ask_required 'Hostname/FQDN o IP para la Web Admin: ')}"
AGENT_PUBLIC_HOST="${GIDEON_AGENT_HOST:-$(ask_required 'Hostname/FQDN o IP para el Gateway de Agents: ')}"
CANONICAL_HOSTS="$(python3 "$ROOT/deploy/ubuntu/gideon_bootstrap_hosts.py" "$WEB_PUBLIC_HOST" "$AGENT_PUBLIC_HOST")" || fail 'Hostname de instalación inválido.'
WEB_PUBLIC_HOST="${CANONICAL_HOSTS%%$'\n'*}"
AGENT_PUBLIC_HOST="${CANONICAL_HOSTS#*$'\n'}"
if [ "${GIDEON_MANAGED_ONECLICK:-0}" = 1 ]; then
  WEB_PORT="$DEFAULT_WEB_PORT"
  GATEWAY_PORT="$DEFAULT_GATEWAY_PORT"
else
  WEB_PORT="$(ask_default 'Puerto HTTPS Web Admin (no 443)' "$DEFAULT_WEB_PORT")"
  GATEWAY_PORT="$(ask_default 'Puerto HTTPS Gateway Agents (no 443)' "$DEFAULT_GATEWAY_PORT")"
fi
validate_port "$WEB_PORT" || fail "Puerto Web inválido. Use 1024-65535 excepto 443/22."
validate_port "$GATEWAY_PORT" || fail "Puerto Gateway inválido. Use 1024-65535 excepto 443/22."
[ "$WEB_PORT" != "$GATEWAY_PORT" ] || fail "Web y Gateway deben usar puertos diferentes."
port_in_use "$WEB_PORT" && fail "El puerto $WEB_PORT ya está en uso. Elija otro para no afectar servicios existentes."
port_in_use "$GATEWAY_PORT" && fail "El puerto $GATEWAY_PORT ya está en uso. Elija otro para no afectar servicios existentes."

if [ "${GIDEON_MANAGED_ONECLICK:-0}" = 1 ]; then
  # Bootstrap is loopback-only. The external wizard validates and imports the
  # final certificate, URL and administrative allowlist after all services pass.
  TLS_MODE=private-ca
else
  TLS_MODE="$(ask_default 'TLS: escriba private-ca (CA privada GIDEON) o existing (certificados existentes)' 'private-ca')"
fi
TLS_MODE="${TLS_MODE,,}"
[[ "$TLS_MODE" == "private-ca" || "$TLS_MODE" == "existing" ]] || fail "TLS_MODE inválido."

MTLS_REQUIRED=false
if [ -f /etc/gideon/gateway/gateway.json ]; then
  MTLS_REQUIRED="$(python3 -c 'import json; print(str(bool(json.load(open("/etc/gideon/gateway/gateway.json")).get("require_agent_mtls",False))).lower())')"
fi
if [ "$MTLS_REQUIRED" != true ] && yesno "¿Exigir mTLS a Agents AHORA? Solo active si todos los Agents disponen de certificado cliente" "N"; then
  echo "Para evitar bloquear Agents por accidente, escriba exactamente ENFORCE para confirmar mTLS obligatorio:"
  read -r MTLS_CONFIRM
  [[ "$MTLS_CONFIRM" == "ENFORCE" ]] && MTLS_REQUIRED=true || echo "mTLS queda preparado pero NO obligatorio."
fi

say "Instalando únicamente dependencias GIDEON (sin upgrade global del sistema)"
PYTHON_BIN=""
if [ -n "${GIDEON_CLAMD_WAS_PRESENT:-}" ]; then
  CLAMD_WAS_PRESENT="$GIDEON_CLAMD_WAS_PRESENT"
elif systemctl cat clamav-daemon.service >/dev/null 2>&1 || command -v clamd >/dev/null 2>&1; then
  CLAMD_WAS_PRESENT=1
else
  CLAMD_WAS_PRESENT=0
fi
python_is_compatible(){
  local candidate="$1"
  [ -x "$(command -v "$candidate" 2>/dev/null || true)" ] || return 1
  "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)' >/dev/null 2>&1
}
select_python(){
  for candidate in python3.13 python3.12 python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1 && python_is_compatible "$candidate"; then PYTHON_BIN="$(command -v "$candidate")"; return 0; fi
  done
  return 1
}
install_optional_yara_deb(){ apt-get install -y --no-install-recommends yara >/dev/null 2>&1 || echo "ADVERTENCIA: YARA no disponible en repositorios configurados; la comprobación YARA quedará WARNING/fail-closed donde sea obligatoria."; }
install_optional_yara_rpm(){ "$GIDEON_PKG" install -y yara >/dev/null 2>&1 || echo "ADVERTENCIA: YARA no disponible en repositorios configurados; GIDEON no habilita repositorios externos automáticamente."; }
case "$GIDEON_LINUX_FAMILY" in
  ubuntu|debian)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    # ffprobe comes only from the signed distro ffmpeg package. This
    # installer never adds a PPA, third-party media repository or standalone
    # binary download for campaign validation.
    apt-get install -y --no-install-recommends python3 python3-venv python3-pip rsync ca-certificates openssl curl sqlite3 clamav clamav-freshclam clamav-daemon clamdscan ffmpeg
    if ! select_python; then
      apt-cache show python3.11 >/dev/null 2>&1 || fail "Python 3.11+ no está disponible en los repositorios configurados. GIDEON no añade PPAs/repositorios externos automáticamente."
      apt-get install -y --no-install-recommends python3.11 python3.11-venv
    fi
    install_optional_yara_deb
    ;;
  rpm)
    if command -v dnf >/dev/null 2>&1; then GIDEON_PKG=dnf; elif command -v yum >/dev/null 2>&1; then GIDEON_PKG=yum; else fail "Se requiere dnf/yum en Linux RHEL-compatible."; fi
    "$GIDEON_PKG" install -y python3 python3-pip rsync ca-certificates openssl curl sqlite ffmpeg || fail "No se pudieron instalar dependencias base GIDEON (incluido ffprobe para campañas). GIDEON no habilita repositorios externos automáticamente."
    if ! select_python; then
      "$GIDEON_PKG" install -y python3.11 python3.11-pip || fail "Python 3.11+ no está disponible. GIDEON no habilita repositorios externos automáticamente."
    fi
    install_optional_yara_rpm
    ;;
esac
select_python || fail "GIDEON Remote Control requiere Python 3.11+."
echo "Python GIDEON seleccionado: $PYTHON_BIN ($($PYTHON_BIN --version 2>&1))"
command -v ffprobe >/dev/null 2>&1 || fail "FFprobe no está disponible. Instale ffmpeg desde el repositorio firmado configurado o desde la cache offline GIDEON; no se aceptan binarios multimedia externos."
ffprobe -version >/dev/null 2>&1 || fail "FFprobe instalado no es ejecutable."
echo "MEDIA_VALIDATION=PASS ffprobe=$(command -v ffprobe)"

# Debian/Ubuntu receives a dedicated GIDEON clamd. It uses only the private GIDEON
# signature database and a local Unix socket; it never exposes the unauthenticated
# ClamAV TCP protocol. Pre-existing host ClamAV units are preserved.
if command -v clamscan >/dev/null 2>&1; then
  echo "ClamAV detectado: GIDEON preferirá clamd privado y conservará clamscan como fallback aislado."
else
  echo "ADVERTENCIA: ClamAV no está disponible; uploads con escaneo obligatorio fallarán cerrado."
fi

# Only GIDEON services are stopped during an in-place upgrade. No unrelated service is touched.
systemctl stop gideon-coordinator.service gideon-diagnostics.service gideon-web-admin.service gideon-agent-gateway.service gideon-clamd.service 2>/dev/null || true

say "Aislamiento de cuentas humanas del host"
if [ "$CREATE_HOST_ADMIN" -eq 1 ]; then
  if id "$INITIAL_UBUNTU_USER" >/dev/null 2>&1; then
    echo "El usuario $INITIAL_UBUNTU_USER ya existe: NO se modifica contraseña, shell, home ni grupos."
  else
    INITIAL_UBUNTU_PASSWORD="$(openssl rand -hex 16)"
    useradd -m -s /bin/bash "$INITIAL_UBUNTU_USER"
    printf '%s:%s\n' "$INITIAL_UBUNTU_USER" "$INITIAL_UBUNTU_PASSWORD" | chpasswd
    usermod -aG sudo "$INITIAL_UBUNTU_USER"
    chage -d 0 "$INITIAL_UBUNTU_USER"
    UBUNTU_USER_CREATED=1
    echo "Usuario $INITIAL_UBUNTU_USER creado por solicitud explícita con contraseña temporal aleatoria; deberá cambiarla en el primer login."
  fi
else
  echo "P8H: no se crea ni modifica ningún usuario humano/sudo del host por defecto."
fi

say "Creando cuentas de servicio aisladas"
id gideongateway >/dev/null 2>&1 || useradd --system --home /var/lib/gideon/gateway --shell /usr/sbin/nologin gideongateway
id gideonweb >/dev/null 2>&1 || useradd --system --home /var/lib/gideon/web --shell /usr/sbin/nologin gideonweb
id gideonbackup >/dev/null 2>&1 || useradd --system --home /var/lib/gideon/backups --shell /usr/sbin/nologin gideonbackup
id gideonmonitor >/dev/null 2>&1 || useradd --system --home /var/lib/gideon/diagnostics --shell /usr/sbin/nologin gideonmonitor
# Service unit SupplementaryGroups grants only the exact reads each process
# needs. Remove broad legacy memberships so the TLS socket ACL rejects them.
for account in gideonbackup gideonmonitor; do
  for service_group in gideongateway gideonweb; do
    gpasswd -d "$account" "$service_group" >/dev/null 2>&1 || true
  done
done

say "Construyendo filesystem GIDEON aislado"
install -d -m 0755 -o root -g root /opt/gideon /opt/gideon/gateway /opt/gideon/web /etc/gideon /var/lib/gideon /var/log/gideon
install -d -m 0755 -o root -g root /opt/gideon/gateway/app /opt/gideon/web/app /opt/gideon/updater
install -d -m 0750 -o root -g gideongateway /etc/gideon/gateway
install -d -m 0750 -o root -g gideonweb /etc/gideon/web
install -d -m 0755 -o root -g root /etc/gideon/pki /etc/gideon/pki/root /etc/gideon/pki/agent-ca
# Public CA files must be traversable by service users; CA private keys remain 0600.
install -d -m 0750 -o root -g gideonweb /etc/gideon/pki/web
install -d -m 0750 -o root -g gideongateway /etc/gideon/pki/gateway
install -d -m 0755 -o root -g root /etc/gideon/security /etc/gideon/security/yara
install -d -m 0750 -o gideonweb -g gideonweb /var/lib/gideon/security /var/lib/gideon/security/clamav
install -d -m 0750 -o gideongateway -g gideongateway /var/lib/gideon/gateway
install -d -m 0750 -o gideonweb -g gideonweb /var/lib/gideon/web /var/lib/gideon/web/tmp /var/lib/gideon/web/scripts /var/lib/gideon/web/jobs /var/lib/gideon/web/transfers
install -d -m 2750 -o gideonweb -g gideonbackup /var/lib/gideon/shared
install -d -m 0750 -o gideonbackup -g gideonbackup /var/lib/gideon/backups /var/lib/gideon/backups/local /var/lib/gideon/backups/external
# Coordinator state remains private to gideonmonitor. Diagnostics is the sanitized
# read-only projection consumed by WebAdmin; setgid preserves gideonweb ownership
# on every atomic snapshot replacement without granting WebAdmin write access.
install -d -m 2750 -o gideonmonitor -g gideonweb /var/lib/gideon/diagnostics
install -d -m 0750 -o gideonmonitor -g gideonmonitor /var/lib/gideon/coordinator
[ ! -f /var/lib/gideon/diagnostics/health.json ] || { chown gideonmonitor:gideonweb /var/lib/gideon/diagnostics/health.json; chmod 0640 /var/lib/gideon/diagnostics/health.json; }
for d in quarantine approved releases uploads reports; do install -d -m 0750 -o gideonweb -g gideonweb "/var/lib/gideon/$d"; done
install -d -m 0750 -o gideongateway -g gideongateway /var/log/gideon/gateway
install -d -m 0750 -o gideonweb -g gideonweb /var/log/gideon/web
install -d -m 0750 -o root -g root /var/log/gideon/audit
install -d -m 0750 -o root -g gideonweb /var/lib/gideon/updates /var/lib/gideon/updates/staging /var/lib/gideon/updates/status /var/lib/gideon/updates/archive /var/lib/gideon/updates/archive/success /var/lib/gideon/updates/archive/failed /var/lib/gideon/updates/rollback /var/lib/gideon/updates/transactions /var/lib/gideon/updates/trust /var/lib/gideon/updates/trust/update-signing
install -d -m 0750 -o gideonweb -g gideonweb /var/lib/gideon/updates/inbox
install -d -m 0750 -o root -g root /var/log/gideon/updater

say "Preparando firmas ClamAV privadas de GIDEON"
CLAMAV_PREPARER="$ROOT/deploy/aws/prepare_gideon_clamav_db.sh"
chmod 0755 "$CLAMAV_PREPARER"
if ! "$CLAMAV_PREPARER" --ensure; then
  echo "ADVERTENCIA: la base ClamAV privada aún no está lista. El gate OneClick reintentará y fallará cerrado si continúa ausente."
fi

# Migrate only GIDEON-owned state from the previous v6.2.0 layout when the new
# isolated paths are still empty. Other application/BBDD paths are never scanned.
if [ ! -f /var/lib/gideon/gateway/gateway.sqlite3 ] && [ -f /var/lib/gideon-agent-gateway/gateway.sqlite3 ]; then
  sqlite3 /var/lib/gideon-agent-gateway/gateway.sqlite3 ".backup '/var/lib/gideon/gateway/gateway.sqlite3'"
  chown gideongateway:gideongateway /var/lib/gideon/gateway/gateway.sqlite3; chmod 0640 /var/lib/gideon/gateway/gateway.sqlite3
  echo "Migrado estado Gateway GIDEON previo."
fi
if [ ! -f /var/lib/gideon/web/security.sqlite3 ] && [ -f /var/lib/gideon-web-admin/security.sqlite3 ]; then
  sqlite3 /var/lib/gideon-web-admin/security.sqlite3 ".backup '/var/lib/gideon/web/security.sqlite3'"
  chown gideonweb:gideonweb /var/lib/gideon/web/security.sqlite3; chmod 0640 /var/lib/gideon/web/security.sqlite3
  for d in scripts jobs transfers; do
    [ -d "/var/lib/gideon-web-admin/$d" ] && rsync -a "/var/lib/gideon-web-admin/$d/" "/var/lib/gideon/web/$d/" || true
    chown -R gideonweb:gideonweb "/var/lib/gideon/web/$d"
  done
  echo "Migrado estado Web GIDEON previo."
fi

say "Instalando Gateway en /opt/gideon/gateway (sin usar virtualenv del usuario)"
install -m 0644 "$ROOT/gideon_agent_gateway.py" /opt/gideon/gateway/app/gideon_agent_gateway.py
install -m 0644 "$ROOT/gideon_version.py" /opt/gideon/gateway/app/gideon_version.py
install -m 0644 "$ROOT/gideon_gateway_bootstrap.py" /opt/gideon/gateway/app/gideon_gateway_bootstrap.py
"$PYTHON_BIN" -m venv /opt/gideon/gateway/venv
/opt/gideon/gateway/venv/bin/python -m pip install --no-cache-dir --disable-pip-version-check --upgrade pip >/dev/null
chown -R root:root /opt/gideon/gateway
chmod -R a+rX,go-w /opt/gideon/gateway

say "Instalando Web Admin en /opt/gideon/web/app"
rsync -a --delete \
  --exclude '.git' --exclude '__pycache__' --exclude '*.pyc' --exclude 'tests' --exclude 'legacy_tkinter' \
  --exclude 'docs/history' --exclude '*.zip' --exclude 'gateway-data' --exclude 'web-data' --exclude 'config' \
  "$ROOT/" /opt/gideon/web/app/
"$PYTHON_BIN" -m venv /opt/gideon/web/venv
/opt/gideon/web/venv/bin/python -m pip install --no-cache-dir --disable-pip-version-check --upgrade pip wheel >/dev/null
/opt/gideon/web/venv/bin/pip install --no-cache-dir -r /opt/gideon/web/app/requirements-web.txt >/dev/null
chown -R root:root /opt/gideon/web
chmod -R a+rX,go-w /opt/gideon/web
# The reviewed VLC source closure is consumed by the WebAdmin build worker but
# is not runtime payload. Keep it root-owned and grant only gideonweb read/traverse
# access; never leave the legal/source tree world-readable.
if [ -d /opt/gideon/web/app/third_party/vlc-offline ] && [ ! -L /opt/gideon/web/app/third_party/vlc-offline ]; then
  chgrp -R gideonweb /opt/gideon/web/app/third_party/vlc-offline
  find /opt/gideon/web/app/third_party/vlc-offline -type d -exec chmod 0750 {} +
  find /opt/gideon/web/app/third_party/vlc-offline -type f -exec chmod 0640 {} +
fi
install -m 0644 -o root -g root "$ROOT/deploy/web/security/gideon-policy.yar" /etc/gideon/security/yara/gideon-policy.yar

# Mutable host profiles/inventory belong to the service data directory, not
# the root-owned executable tree protected by ProtectSystem=strict.
install -d -m 0750 -o gideonweb -g gideonweb /var/lib/gideon/web/config
if [ -d /opt/gideon/web/app/config ] && [ ! -L /opt/gideon/web/app/config ]; then
  cp -an /opt/gideon/web/app/config/. /var/lib/gideon/web/config/
  mv /opt/gideon/web/app/config "/opt/gideon/web/app/config.before-data-migration-$(date +%Y%m%d%H%M%S)"
fi
ln -sfn /var/lib/gideon/web/config /opt/gideon/web/app/config
if [ ! -f /var/lib/gideon/web/config/host_profiles.json ]; then
  install -m 0640 -o gideonweb -g gideonweb "$ROOT/deploy/web/default-host-profiles.json" /var/lib/gideon/web/config/host_profiles.json
fi
"$PYTHON_BIN" - <<'PY'
import csv, json
from pathlib import Path
root=Path('/var/lib/gideon/web/config')
if not (root/'config.json').exists(): (root/'config.json').write_text('{}\n')
if not (root/'sites.csv').exists(): (root/'sites.csv').write_text('SiteCode,SiteName,ServerIP\n')
if not (root/'site_groups.json').exists():
    (root/'site_groups').mkdir(exist_ok=True)
    (root/'site_groups/default.csv').write_text('SiteCode,SiteName,ServerIP\n')
    (root/'site_groups.json').write_text(json.dumps({'schema_version':2,'active_group':'default','groups':{'default':{
        'id':'default','name':'Inventario GIDEON','description':'Instalación nueva, sin hosts de producción.',
        'sites_file':'site_groups/default.csv','protected':False}}})+'\n')
PY
chown -R gideonweb:gideonweb /var/lib/gideon/web/config
chmod -R u+rwX,g+rX,o-rwx /var/lib/gideon/web/config

say "Preparando PKI/TLS sin tocar 443"
make_server_cert(){
  local host="$1" cn="$2" crt="$3" key="$4"
  local san="DNS:$host,DNS:localhost,IP:127.0.0.1"
  if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || "$host" == *:* ]]; then san="IP:$host,DNS:localhost,IP:127.0.0.1"; fi
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$key" >/dev/null 2>&1
  openssl req -new -key "$key" -subj "/CN=$cn" -out /tmp/gideon-server.csr >/dev/null 2>&1
  cat >/tmp/gideon-server.ext <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=$san
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
  openssl x509 -req -in /tmp/gideon-server.csr -CA /etc/gideon/pki/root/gideon-root-ca.pem -CAkey /etc/gideon/pki/root/gideon-root-ca.key -CAcreateserial -out "$crt" -days 825 -sha256 -extfile /tmp/gideon-server.ext >/dev/null 2>&1
  rm -f /tmp/gideon-server.csr /tmp/gideon-server.ext
}

if [ "$TLS_MODE" = "private-ca" ]; then
  if [ ! -f /etc/gideon/pki/root/gideon-root-ca.pem ]; then
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out /etc/gideon/pki/root/gideon-root-ca.key >/dev/null 2>&1
    openssl req -x509 -new -key /etc/gideon/pki/root/gideon-root-ca.key -sha256 -days 3650 -subj "/CN=GIDEON Remote Control Private Root CA" -out /etc/gideon/pki/root/gideon-root-ca.pem >/dev/null 2>&1
  fi
  /opt/gideon/web/venv/bin/python "$ROOT/deploy/ubuntu/gideon_private_ca.py" /etc/gideon/pki/root/gideon-root-ca.pem /etc/gideon/pki/root/gideon-root-ca.key
  make_server_cert "$WEB_PUBLIC_HOST" "GIDEON Web Admin" /etc/gideon/pki/web/web.crt /etc/gideon/pki/web/web.key
  make_server_cert "$AGENT_PUBLIC_HOST" "GIDEON Agent Gateway" /etc/gideon/pki/gateway/gateway.crt /etc/gideon/pki/gateway/gateway.key
else
  WEB_CERT="$(ask_required 'Ruta certificado Web PEM: ')"; WEB_KEY="$(ask_required 'Ruta clave Web PEM: ')"
  GW_CERT="$(ask_required 'Ruta certificado Gateway PEM: ')"; GW_KEY="$(ask_required 'Ruta clave Gateway PEM: ')"
  TRUST_CA="$(ask_required 'Ruta CA/cadena que deben confiar Web/Agents: ')"
  for f in "$WEB_CERT" "$WEB_KEY" "$GW_CERT" "$GW_KEY" "$TRUST_CA"; do [ -f "$f" ] || fail "No existe $f"; done
  install -m 0644 "$TRUST_CA" /etc/gideon/pki/root/gideon-root-ca.pem
  install -m 0640 -o root -g gideonweb "$WEB_CERT" /etc/gideon/pki/web/web.crt
  install -m 0640 -o root -g gideonweb "$WEB_KEY" /etc/gideon/pki/web/web.key
  install -m 0640 -o root -g gideongateway "$GW_CERT" /etc/gideon/pki/gateway/gateway.crt
  install -m 0640 -o root -g gideongateway "$GW_KEY" /etc/gideon/pki/gateway/gateway.key
fi
chmod 0600 /etc/gideon/pki/root/gideon-root-ca.key 2>/dev/null || true
chown root:gideonweb /etc/gideon/pki/web/web.key /etc/gideon/pki/web/web.crt
chmod 0640 /etc/gideon/pki/web/web.key /etc/gideon/pki/web/web.crt
chown root:gideongateway /etc/gideon/pki/gateway/gateway.key /etc/gideon/pki/gateway/gateway.crt
chmod 0640 /etc/gideon/pki/gateway/gateway.key /etc/gideon/pki/gateway/gateway.crt
chmod 0644 /etc/gideon/pki/root/gideon-root-ca.pem

# Separate client CA: prepared now, enforcement is optional to avoid breaking older Agents.
if [ ! -f /etc/gideon/pki/agent-ca/agent-client-ca.pem ]; then
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out /etc/gideon/pki/agent-ca/agent-client-ca.key >/dev/null 2>&1
  openssl req -x509 -new -key /etc/gideon/pki/agent-ca/agent-client-ca.key -sha256 -days 3650 -subj "/CN=GIDEON Agent Client CA" -out /etc/gideon/pki/agent-ca/agent-client-ca.pem >/dev/null 2>&1
  chmod 0600 /etc/gideon/pki/agent-ca/agent-client-ca.key
  chmod 0644 /etc/gideon/pki/agent-ca/agent-client-ca.pem
fi
/opt/gideon/web/venv/bin/python "$ROOT/deploy/ubuntu/gideon_private_ca.py" /etc/gideon/pki/agent-ca/agent-client-ca.pem /etc/gideon/pki/agent-ca/agent-client-ca.key

say "Generando/preservando secretos internos GIDEON"
env_value(){
  local file="$1" key="$2"
  [ -f "$file" ] || return 0
  sed -n "s/^${key}=//p" "$file" | head -n1
}
LEGACY_GW_ENV=/etc/gideon-agent-gateway/gateway.env
LEGACY_WEB_ENV=/etc/gideon-web-admin/web.env
GW_ENV=/etc/gideon/gateway/gateway.env
WEB_ENV=/etc/gideon/web/web.env

ADMIN_TOKEN="$(env_value "$GW_ENV" GIDEON_AGENT_ADMIN_TOKEN)"
[ -n "$ADMIN_TOKEN" ] || ADMIN_TOKEN="$(env_value "$LEGACY_GW_ENV" GIDEON_AGENT_ADMIN_TOKEN)"
[ -n "$ADMIN_TOKEN" ] || ADMIN_TOKEN="$("$PYTHON_BIN" - <<'PY'
import secrets; print(secrets.token_urlsafe(48))
PY
)"
ENROLL_SECRET="$(env_value "$GW_ENV" GIDEON_AGENT_ENROLL_SECRET)"
[ -n "$ENROLL_SECRET" ] || ENROLL_SECRET="$(env_value "$LEGACY_GW_ENV" GIDEON_AGENT_ENROLL_SECRET)"
[ -n "$ENROLL_SECRET" ] || ENROLL_SECRET="$("$PYTHON_BIN" - <<'PY'
import secrets; print(secrets.token_urlsafe(48))
PY
)"
BOOTSTRAP_TOKEN="$(env_value "$WEB_ENV" GIDEON_WEB_BOOTSTRAP_TOKEN)"
[ -n "$BOOTSTRAP_TOKEN" ] || BOOTSTRAP_TOKEN="$(env_value "$LEGACY_WEB_ENV" GIDEON_WEB_BOOTSTRAP_TOKEN)"
[ -n "$BOOTSTRAP_TOKEN" ] || BOOTSTRAP_TOKEN="$("$PYTHON_BIN" - <<'PY'
import secrets; print(secrets.token_urlsafe(32))
PY
)"
TOTP_KEY="$(env_value "$WEB_ENV" GIDEON_WEB_TOTP_ENCRYPTION_KEY)"
[ -n "$TOTP_KEY" ] || TOTP_KEY="$(env_value "$LEGACY_WEB_ENV" GIDEON_WEB_TOTP_ENCRYPTION_KEY)"
[ -n "$TOTP_KEY" ] || TOTP_KEY="$("$PYTHON_BIN" - <<'PY'
import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())
PY
)"
SMTP_PASSWORD="$(env_value "$WEB_ENV" GIDEON_SMTP_PASSWORD)"
[ -n "$SMTP_PASSWORD" ] || SMTP_PASSWORD="$(env_value "$LEGACY_WEB_ENV" GIDEON_SMTP_PASSWORD)"

cat >"$GW_ENV" <<EOF
GIDEON_AGENT_ADMIN_TOKEN=$ADMIN_TOKEN
GIDEON_AGENT_ENROLL_SECRET=$ENROLL_SECRET
EOF
chown root:gideongateway "$GW_ENV"; chmod 0640 "$GW_ENV"
cat >"$WEB_ENV" <<EOF
GIDEON_AGENT_ADMIN_TOKEN=$ADMIN_TOKEN
GIDEON_WEB_BOOTSTRAP_TOKEN=$BOOTSTRAP_TOKEN
GIDEON_WEB_TOTP_ENCRYPTION_KEY=$TOTP_KEY
# SMTP remains optional. Configure GIDEON_SMTP_PASSWORD only when SMTP is enabled.
EOF
if [ -n "$SMTP_PASSWORD" ]; then printf 'GIDEON_SMTP_PASSWORD=%s\n' "$SMTP_PASSWORD" >>"$WEB_ENV"; fi
chown root:gideonweb "$WEB_ENV"; chmod 0640 "$WEB_ENV"

say "Escribiendo configuración aislada"
if [ "${GIDEON_MANAGED_ONECLICK:-0}" = 1 ] && [ -f /etc/gideon/external-access.json ]; then
  /opt/gideon/web/venv/bin/python - <<'PY'
import json
from pathlib import Path
path=Path('/etc/gideon/external-access.json')
state=json.loads(path.read_text())
state['status']='PENDING_RECONFIGURATION'
path.write_text(json.dumps(state,indent=2)+'\n')
path.chmod(0o600)
PY
fi
"$PYTHON_BIN" - "$GATEWAY_PORT" "$AGENT_PUBLIC_HOST" "$MTLS_REQUIRED" <<'PY'
import json,sys,os
port=int(sys.argv[1]); host=sys.argv[2]; mtls=sys.argv[3].lower()=="true"
cfg={
 "data_dir":"/var/lib/gideon/gateway","listen_host":"0.0.0.0","listen_address":"0.0.0.0","listen_port":port,
 "admin_api_key_env":"GIDEON_AGENT_ADMIN_TOKEN","enrollment_secret_env":"GIDEON_AGENT_ENROLL_SECRET",
 "tls_certfile":"/etc/gideon/pki/gateway/gateway.crt","tls_keyfile":"/etc/gideon/pki/gateway/gateway.key",
 "ca_file":"/etc/gideon/pki/root/gideon-root-ca.pem","client_ca_file":"/etc/gideon/pki/agent-ca/agent-client-ca.pem","client_ca_key_file":"/etc/gideon/pki/agent-ca/agent-client-ca.key",
 "require_agent_mtls":mtls,"public_host":host,"public_url":f"https://{host}:{port}",
 "advertised_endpoint":f"https://{host}:{port}","internal_endpoint":f"https://127.0.0.1:{port}",
 "hot_reload_enabled":True,"installer_enrollment_ttl_seconds":86400,"installer_enrollment_max_uses":8,
 "max_job_package_bytes":1073741824,"max_job_result_bytes":1073741824,
 "max_release_bundle_bytes":1073741824,
 "security":{"minimum_tls":"TLSv1.2","prefer_tls13":True,"package_signing":"Ed25519","digest":"SHA-256"}
}
if os.environ.get('GIDEON_MANAGED_ONECLICK') == '1':
 cfg['listen_host']=cfg['listen_address']='127.0.0.1'
open('/etc/gideon/gateway/gateway.json','w',encoding='utf-8').write(json.dumps(cfg,indent=2,ensure_ascii=False)+'\n')
PY
chown root:gideongateway /etc/gideon/gateway/gateway.json; chmod 0640 /etc/gideon/gateway/gateway.json

"$PYTHON_BIN" - "$WEB_PORT" "$GATEWAY_PORT" "$WEB_PUBLIC_HOST" <<'PY'
import json,sys,os
from pathlib import Path
source=Path('/etc/gideon/web/web_admin.json')
if not source.is_file(): source=Path('/opt/gideon/web/app/config/web_admin.json')
base=json.loads(source.read_text(encoding='utf-8-sig')) if source.is_file() else {}
base.update({
 'data_dir':'/var/lib/gideon/web','listen_host':'0.0.0.0','listen_port':int(sys.argv[1]),
 'tls_certfile':'/etc/gideon/pki/web/web.crt','tls_keyfile':'/etc/gideon/pki/web/web.key',
 'gateway_base_url':f'https://127.0.0.1:{int(sys.argv[2])}','gateway_public_url':json.load(open('/etc/gideon/gateway/gateway.json',encoding='utf-8')).get('advertised_endpoint',''),
 'gateway_config_file':'/etc/gideon/gateway/gateway.json','gateway_ca_file':'/etc/gideon/pki/root/gideon-root-ca.pem',
 'trust_proxy_headers':False,'forwarded_allow_ips':'127.0.0.1','secure_cookies':True,
 'runtime_settings_file':'/var/lib/gideon/shared/runtime_settings.json','security_event_log':'/var/log/gideon/web/security.log',
 'yara_rules_file':'/etc/gideon/security/yara/gideon-policy.yar','prefer_low_memory_clamav':True,
 'clamav_database_dir':'/var/lib/gideon/security/clamav','malware_scan_timeout_seconds':300,
 'use_private_clamd':True,'clamd_config_file':'/etc/gideon/security/clamd.conf',
 'clamd_socket':'/run/gideon-clamd/clamd.sock','clamd_scan_timeout_seconds':180,'clamd_parallel_scans':2,
 'clamd_fallback_to_clamscan':True,
 'ffprobe_path':'/usr/bin/ffprobe','media_validation_timeout_seconds':20,
 'product_update_root':'/var/lib/gideon/updates','malware_scan_allowed_root':'/var/lib/gideon',
 'require_mfa':True,'session_idle_timeout_seconds':43200,'session_ttl_seconds':43200,'max_sessions_per_user':5,
 'min_free_disk_bytes':1073741824,
 'public_fqdn':sys.argv[3],
})
if os.environ.get('GIDEON_MANAGED_ONECLICK') == '1':
 base['listen_host']='127.0.0.1'
open('/etc/gideon/web/web_admin.json','w',encoding='utf-8').write(json.dumps(base,indent=2,ensure_ascii=False)+'\n')
PY
chown root:gideonweb /etc/gideon/web/web_admin.json; chmod 0640 /etc/gideon/web/web_admin.json

say "Creando SuperAdmin Web temporal y obligatorio cambio + MFA"
if [ ! -f /var/lib/gideon/web/security.sqlite3 ]; then
  runuser -u gideonweb -- env \
    PYTHONPATH=/opt/gideon/web/app \
    GIDEON_WEB_TOTP_ENCRYPTION_KEY="$TOTP_KEY" \
    /opt/gideon/web/venv/bin/python - <<PY
from pathlib import Path
from gideon_web_admin.auth import SecurityStore
s=SecurityStore(Path('/var/lib/gideon/web/security.sqlite3'),idle_timeout_seconds=43200,max_sessions_per_user=5)
s.bootstrap_admin('$INITIAL_WEB_USER','$INITIAL_WEB_PASSWORD','Administrador GIDEON',must_change_password=True,allow_temporary_password=True)
print('SuperAdmin temporal creado')
PY
  WEB_ADMIN_CREATED=1
else
  echo "security.sqlite3 ya existe: NO se reemplazan usuarios ni contraseñas Web."
fi

say "Configurando backup local y destino externo editable desde la Web"
install -m 0644 "$ROOT/gideon_backup.py" /opt/gideon/web/app/gideon_backup.py
install -d -m 0755 -o root -g root /var/lib/gideon/backup-snapshots
for role in gateway web; do
  install -d -m 2750 -o "gideon$role" -g gideonbackup "/var/lib/gideon/backup-snapshots/$role"
  database=gateway.sqlite3
  [[ "$role" == web ]] && database=security.sqlite3
  cat >"/etc/systemd/system/gideon-backup-$role-snapshot.service" <<UNIT
[Unit]
Description=GIDEON $role SQLite snapshot as database owner

[Service]
Type=oneshot
User=gideon$role
Group=gideon$role
ExecStart=/opt/gideon/web/venv/bin/python /opt/gideon/web/app/gideon_backup.py --snapshot-source /var/lib/gideon/$role/$database --snapshot-target /var/lib/gideon/backup-snapshots/$role/$database
UMask=0027
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
CapabilityBoundingSet=
RestrictAddressFamilies=AF_UNIX
ReadWritePaths=/var/lib/gideon/$role /var/lib/gideon/backup-snapshots/$role
NoExecPaths=/var/lib/gideon /tmp /var/tmp /dev/shm
MemoryMax=192M
TasksMax=16
UNIT
done
if [ ! -f /var/lib/gideon/shared/runtime_settings.json ]; then
  cat >/var/lib/gideon/shared/runtime_settings.json <<'JSON'
{
  "backup_enabled": true,
  "backup_destination_type": "local",
  "backup_destination": "",
  "backup_retention_days": 14,
  "smtp_enabled": false,
  "smtp_host": "",
  "smtp_port": 587,
  "smtp_username": "",
  "smtp_from": ""
}
JSON
  chown gideonweb:gideonbackup /var/lib/gideon/shared/runtime_settings.json; chmod 0640 /var/lib/gideon/shared/runtime_settings.json
fi

say "Instalando aplicador incremental GIDEON aislado"
for f in gideon_product_update.py gideon_update_lock.py gideon_update_security.py gideon_update_transaction.py; do install -m 0644 -o root -g root "$ROOT/$f" "/opt/gideon/updater/$f"; done
install -m 0755 -o root -g root "$ROOT/deploy/aws/prepare_gideon_clamav_db.sh" /opt/gideon/updater/prepare_gideon_clamav_db.sh
install -m 0644 -o root -g root "$ROOT/deploy/aws/systemd/gideon-remote-control.target" /etc/systemd/system/gideon-remote-control.target
install -m 0644 -o root -g root "$ROOT/deploy/aws/systemd/gideon-update.service" /etc/systemd/system/gideon-update.service
install -m 0644 -o root -g root "$ROOT/deploy/aws/systemd/gideon-update.path" /etc/systemd/system/gideon-update.path
install -m 0644 -o root -g root "$ROOT/deploy/aws/systemd/gideon-diagnostics.service" /etc/systemd/system/gideon-diagnostics.service
install -m 0644 -o root -g root "$ROOT/deploy/aws/systemd/gideon-coordinator.service" /etc/systemd/system/gideon-coordinator.service
install -m 0644 -o root -g root "$ROOT/deploy/aws/systemd/gideon-clamav-update.service" /etc/systemd/system/gideon-clamav-update.service
install -m 0644 -o root -g root "$ROOT/deploy/aws/systemd/gideon-clamav-update.timer" /etc/systemd/system/gideon-clamav-update.timer
CLAMD_SERVICE_AVAILABLE=0
if command -v clamd >/dev/null 2>&1 && command -v clamdscan >/dev/null 2>&1 && id clamav >/dev/null 2>&1; then
  install -m 0640 -o root -g gideonweb "$ROOT/deploy/ubuntu/gideon-clamd.conf" /etc/gideon/security/clamd.conf
  install -m 0644 -o root -g root "$ROOT/deploy/ubuntu/gideon-clamd.service" /etc/systemd/system/gideon-clamd.service
  if command -v apparmor_parser >/dev/null 2>&1 && [ -f /etc/apparmor.d/usr.sbin.clamd ]; then
    install -m 0644 -o root -g root "$ROOT/deploy/ubuntu/gideon-clamd.apparmor" /etc/apparmor.d/gideon-clamd.paths
    install -d -m 0755 -o root -g root /etc/apparmor.d/local
    touch /etc/apparmor.d/local/usr.sbin.clamd
    grep -Fqx '#include <gideon-clamd.paths>' /etc/apparmor.d/local/usr.sbin.clamd \
      || printf '\n#include <gideon-clamd.paths>\n' >> /etc/apparmor.d/local/usr.sbin.clamd
    apparmor_parser -r /etc/apparmor.d/usr.sbin.clamd
  fi
  if command -v apparmor_parser >/dev/null 2>&1 && [ -f /etc/apparmor.d/usr.bin.freshclam ]; then
    install -m 0644 -o root -g root "$ROOT/deploy/ubuntu/gideon-freshclam.apparmor" /etc/apparmor.d/gideon-freshclam.paths
    install -d -m 0755 -o root -g root /etc/apparmor.d/local
    touch /etc/apparmor.d/local/usr.bin.freshclam
    grep -Fqx '#include <gideon-freshclam.paths>' /etc/apparmor.d/local/usr.bin.freshclam \
      || printf '\n#include <gideon-freshclam.paths>\n' >> /etc/apparmor.d/local/usr.bin.freshclam
    apparmor_parser -r /etc/apparmor.d/usr.bin.freshclam
  fi
  CLAMD_SERVICE_AVAILABLE=1
  if [ "$CLAMD_WAS_PRESENT" -eq 0 ]; then
    systemctl disable --now clamav-daemon.socket clamav-daemon.service >/dev/null 2>&1 || true
  else
    echo "ClamAV previo detectado: no se deshabilitan ni modifican sus unidades existentes."
  fi
else
  echo "ADVERTENCIA: clamd/clamdscan no están disponibles; WebAdmin conservará el fallback clamscan fail-closed."
fi

say "Instalando servicios systemd con hardening y límites de recursos"
cat >/etc/systemd/system/gideon-agent-gateway.service <<'UNIT'
[Unit]
Description=GIDEON Agent Gateway (isolated)
PartOf=gideon-remote-control.target
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=gideongateway
Group=gideongateway
EnvironmentFile=/etc/gideon/gateway/gateway.env
Environment=PYTHONDONTWRITEBYTECODE=1
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONPATH=/opt/gideon/web/app
ExecStart=/opt/gideon/gateway/venv/bin/python /opt/gideon/gateway/app/gideon_agent_gateway.py --config /etc/gideon/gateway/gateway.json
WorkingDirectory=/opt/gideon/gateway/app
Restart=on-failure
RestartSec=5
UMask=0027
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectHostname=true
ProtectClock=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectKernelLogs=true
ProtectProc=invisible
ProcSubset=pid
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictNamespaces=true
LockPersonality=true
SystemCallArchitectures=native
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths=/var/lib/gideon/gateway /var/log/gideon/gateway
NoExecPaths=/var/lib/gideon /tmp /var/tmp /dev/shm
MemoryHigh=192M
MemoryMax=384M
TasksMax=128
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
UNIT

cat >/etc/systemd/system/gideon-web-admin.service <<'UNIT'
[Unit]
Description=GIDEON Remote Control Web Admin (isolated)
PartOf=gideon-remote-control.target
After=network-online.target gideon-agent-gateway.service
Wants=network-online.target

[Service]
Type=simple
User=gideonweb
Group=gideonweb
EnvironmentFile=/etc/gideon/web/web.env
Environment=PYTHONDONTWRITEBYTECODE=1
Environment=PYTHONUNBUFFERED=1
Environment=GIDEON_WEB_ADMIN_CONFIG=/etc/gideon/web/web_admin.json
Environment=TMPDIR=/var/lib/gideon/web/tmp
ExecStart=/opt/gideon/web/venv/bin/python /opt/gideon/web/app/gideon_web_admin.py --config /etc/gideon/web/web_admin.json
WorkingDirectory=/opt/gideon/web/app
Restart=on-failure
RestartSec=5
UMask=0027
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectHostname=true
ProtectClock=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectKernelLogs=true
ProtectProc=invisible
ProcSubset=pid
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictNamespaces=true
LockPersonality=true
SystemCallArchitectures=native
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths=/var/lib/gideon/web /var/lib/gideon/shared /var/lib/gideon/updates/inbox /var/log/gideon/web
NoExecPaths=/var/lib/gideon /tmp /var/tmp /dev/shm
MemoryHigh=768M
MemoryMax=1536M
TasksMax=128
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
UNIT

cat >/etc/systemd/system/gideon-backup.service <<'UNIT'
[Unit]
Description=GIDEON isolated SQLite backup
Requires=gideon-backup-gateway-snapshot.service gideon-backup-web-snapshot.service
After=gideon-agent-gateway.service gideon-web-admin.service gideon-backup-gateway-snapshot.service gideon-backup-web-snapshot.service

[Service]
Type=oneshot
User=gideonbackup
Group=gideonbackup
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=/opt/gideon/web/venv/bin/python /opt/gideon/web/app/gideon_backup.py --settings /var/lib/gideon/shared/runtime_settings.json --root /var/lib/gideon/backups/local --gateway-db /var/lib/gideon/backup-snapshots/gateway/gateway.sqlite3 --web-db /var/lib/gideon/backup-snapshots/web/security.sqlite3
UMask=0027
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
CapabilityBoundingSet=
AmbientCapabilities=
ReadOnlyPaths=/var/lib/gideon/gateway /var/lib/gideon/web /var/lib/gideon/shared
ReadWritePaths=/var/lib/gideon/backups
NoExecPaths=/var/lib/gideon /tmp /var/tmp /dev/shm
MemoryMax=256M
TasksMax=32
UNIT

cat >/etc/systemd/system/gideon-backup.timer <<'UNIT'
[Unit]
Description=Daily GIDEON backup timer
PartOf=gideon-remote-control.target

[Timer]
OnCalendar=*-*-* 03:17:00
RandomizedDelaySec=30m
Persistent=true
AccuracySec=5m

[Install]
WantedBy=timers.target
UNIT

say "Configurando rotación de logs solo GIDEON"
cat >/etc/logrotate.d/gideon-remote-control <<'ROTATE'
/var/log/gideon/gateway/*.log /var/log/gideon/web/*.log /var/log/gideon/audit/*.log /var/log/gideon/installer/*.log {
    daily
    rotate 14
    maxsize 50M
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
    create 0640 root root
}
ROTATE

# GIDEON-only audit rules when auditd already exists. Do not install/reconfigure global auditd.
if command -v auditctl >/dev/null 2>&1 && [ -d /etc/audit/rules.d ]; then
  cat >/etc/audit/rules.d/gideon-remote-control.rules <<'AUDIT'
-w /opt/gideon/ -p wa -k gideon_code
-w /etc/gideon/ -p wa -k gideon_config
-w /etc/systemd/system/gideon-agent-gateway.service -p wa -k gideon_service
-w /etc/systemd/system/gideon-web-admin.service -p wa -k gideon_service
-w /etc/systemd/system/gideon-remote-control.target -p wa -k gideon_service
-w /etc/systemd/system/gideon-update.service -p wa -k gideon_service
-w /etc/systemd/system/gideon-update.path -p wa -k gideon_service
-w /etc/systemd/system/gideon-diagnostics.service -p wa -k gideon_service
-w /etc/systemd/system/gideon-coordinator.service -p wa -k gideon_service
-w /etc/systemd/system/gideon-clamav-update.service -p wa -k gideon_service
-w /etc/systemd/system/gideon-clamav-update.timer -p wa -k gideon_service
-w /etc/systemd/system/gideon-clamd.service -p wa -k gideon_service
AUDIT
  echo "Reglas auditd GIDEON creadas; no se modificaron otras reglas."
fi

say "AWS Systems Manager"
if systemctl list-unit-files 2>/dev/null | grep -q '^amazon-ssm-agent.service'; then
  echo "amazon-ssm-agent detectado. GIDEON NO cambia su estado, inicio ni configuración."
else
  echo "amazon-ssm-agent no está instalado. GIDEON no instala ni modifica este servicio."
fi

say "Activando únicamente servicios GIDEON"
bash /opt/gideon/web/app/deploy/ubuntu/INSTALL-GIDEON-TLS-MANAGER.sh
systemctl daemon-reload
systemctl enable gideon-remote-control.target gideon-agent-gateway.service gideon-web-admin.service gideon-backup.timer gideon-update.path gideon-diagnostics.service gideon-coordinator.service gideon-clamav-update.timer
[ "$CLAMD_SERVICE_AVAILABLE" -eq 0 ] || systemctl enable gideon-clamd.service
systemctl start gideon-remote-control.target
systemctl restart gideon-agent-gateway.service
sleep 1
[ "$CLAMD_SERVICE_AVAILABLE" -eq 0 ] || systemctl restart gideon-clamd.service
systemctl restart gideon-web-admin.service
systemctl start gideon-tls-recovery.service
systemctl start gideon-backup.timer gideon-update.path gideon-clamav-update.timer
systemctl restart gideon-diagnostics.service
sleep 1
systemctl restart gideon-coordinator.service

say "Pruebas locales"
GW_OK=0; WEB_OK=0
for attempt in $(seq 1 30); do
  curl --silent --fail --max-time 2 --cacert /etc/gideon/pki/root/gideon-root-ca.pem "https://127.0.0.1:$GATEWAY_PORT/health" >/dev/null && GW_OK=1 || GW_OK=0
  curl --silent --fail --max-time 2 --cacert /etc/gideon/pki/root/gideon-root-ca.pem "https://127.0.0.1:$WEB_PORT/healthz" >/dev/null && WEB_OK=1 || WEB_OK=0
  [[ "$GW_OK" -eq 1 && "$WEB_OK" -eq 1 ]] && break
  sleep 2
done
[ "$GW_OK" -eq 1 ] || { systemctl --no-pager --full status gideon-agent-gateway.service || true; fail "Gateway no superó health check local."; }
[ "$WEB_OK" -eq 1 ] || { systemctl --no-pager --full status gideon-web-admin.service || true; fail "Web Admin no superó health check local."; }

cat >/etc/gideon/INSTALLATION-SUMMARY.txt <<EOF
GIDEON Remote Control 6.3.4-rc30 RELEASE-P8H-RC22-SELF-CONTAINED-AGENT
Web Admin URL: https://$WEB_PUBLIC_HOST:$WEB_PORT
Agent Gateway URL: https://$AGENT_PUBLIC_HOST:$GATEWAY_PORT
Ubuntu host admin: ${INITIAL_UBUNTU_USER:-N/A} (creación opt-in; por defecto no se crea)
Web initial user: $INITIAL_WEB_USER (cambio obligatorio + MFA)
TLS mode: $TLS_MODE
mTLS required now: $MTLS_REQUIRED
CA to trust on administrative devices/Agents: /etc/gideon/pki/root/gideon-root-ca.pem
External backup destination: configurable later in Web > Configuración
SMTP: not configured
SSH: untouched
Port 443: untouched
Firewall/UFW: untouched; configure AWS Security Group manually for the two GIDEON ports.
EOF
chmod 0644 /etc/gideon/INSTALLATION-SUMMARY.txt

say "INSTALACIÓN COMPLETADA"
echo "Web Admin : https://$WEB_PUBLIC_HOST:$WEB_PORT"
echo "Gateway   : https://$AGENT_PUBLIC_HOST:$GATEWAY_PORT"
echo "Web user  : $INITIAL_WEB_USER"
if [ "$WEB_ADMIN_CREATED" -eq 1 ]; then
  install -d -m 0700 -o root -g root /etc/gideon/bootstrap
  printf 'User: %s\nTemporary password: %s\n' "$INITIAL_WEB_USER" "$INITIAL_WEB_PASSWORD" >/etc/gideon/bootstrap/web-credentials.txt
  chmod 0600 /etc/gideon/bootstrap/web-credentials.txt
  echo "Credenciales temporales: /etc/gideon/bootstrap/web-credentials.txt (root; cambio obligatorio + MFA)"
else
  echo "Web       : base existente preservada; no se cambió ninguna contraseña."
fi
if [ "$UBUNTU_USER_CREATED" -eq 1 ]; then
  echo "Ubuntu    : $INITIAL_UBUNTU_USER / $INITIAL_UBUNTU_PASSWORD (temporal; cambio obligatorio)"
elif [ "$CREATE_HOST_ADMIN" -eq 1 ]; then
  echo "Ubuntu    : usuario $INITIAL_UBUNTU_USER preexistente preservado; no se cambió su contraseña/grupos."
else
  echo "Ubuntu    : no se creó ni modificó usuario humano/sudo del host (modo aislado por defecto)."
fi
echo ""
echo "NO se modificó /etc/ssh, sshd, puerto 22, puerto 443, UFW, Nginx, Apache, bases de datos ni virtualenvs existentes."
echo "Configure su AWS Security Group para permitir TCP $WEB_PORT solo desde IPs administrativas y TCP $GATEWAY_PORT desde los Agents necesarios."
echo "Si usó CA privada GIDEON, importe /etc/gideon/pki/root/gideon-root-ca.pem en los equipos administrativos y use esa CA en los Agents."
echo "Log de instalación: $INSTALL_LOG"
