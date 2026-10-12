#!/usr/bin/env bash
set -Eeuo pipefail
umask 027
# Do not accidentally use Windows Docker/Python from WSL's inherited PATH.
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

[[ "$(uname -s)" == "Linux" ]] || {
  echo "[ERROR] Este instalador requiere Linux; macOS no está soportado como servidor Master." >&2
  exit 10
}

if [[ "$EUID" -ne 0 ]]; then
  command -v sudo >/dev/null 2>&1 || {
    echo "[ERROR] sudo no esta disponible; ejecute como root." >&2
    exit 10
  }
  exec sudo --preserve-env=GIDEON_ALLOW_ONLINE_INSTALL,GIDEON_RESOURCE_PROFILE,GIDEON_WEB_HOST,GIDEON_AGENT_HOST,GIDEON_EXTERNAL_ACCESS,GIDEON_INSTALL_MODE -- bash "$0" "$@"
fi

export GIDEON_ALLOW_ONLINE_INSTALL="${GIDEON_ALLOW_ONLINE_INSTALL:-1}"
INSTALL_MODE="${GIDEON_INSTALL_MODE:-fresh}"
case "$INSTALL_MODE" in
  fresh|clone) ;;
  *) echo '[ERROR] GIDEON_INSTALL_MODE debe ser fresh o clone.' >&2; exit 13 ;;
esac

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
MANIFEST="$BUNDLE_DIR/deployment.manifest.json"
CFG="$BUNDLE_DIR/master.config.json"

APPROOT="/opt/gideon-remote-control"
DATAROOT="/var/lib/gideon-remote-control"
CONFROOT="/etc/gideon-remote-control"
LOGROOT="/var/log/gideon-remote-control"

STAGE="INIT"
BACKUP=""
GUACD_PORT=""
PRE_GUACD_UNIT=0
PRE_CLAMD_UNIT=0

log() {
  printf '[%s] %s\n' "$(date '+%F %T')" "$*"
}

step() {
  STAGE="$1"
  echo
  echo "==== $1 ===="
}

fail() {
  echo "[FAIL] $STAGE :: $*" >&2
  return 1
}

on_exit() {
  rc=$?
  if [[ "$rc" -ne 0 ]]; then
    bash "$SCRIPT_DIR/collect-gideon-install-diagnostics.sh" \
      "$DATAROOT/diagnostics" "$STAGE" "exit=$rc" || true

    if [[ -n "$BACKUP" && -d "$BACKUP" ]]; then
      echo "[WARN] Instalación fallida. Backup disponible: $BACKUP"
    fi
  fi
}

trap on_exit EXIT

[[ -f "$MANIFEST" ]] || { echo "[ERROR] Missing $MANIFEST" >&2; exit 11; }
[[ -f "$CFG" ]] || { echo "[ERROR] Missing $CFG" >&2; exit 12; }
[[ -r /etc/os-release ]] || { echo "[ERROR] /etc/os-release no está disponible." >&2; exit 13; }

. /etc/os-release
DISTRO="${ID:-unknown}"
LIKE="${ID_LIKE:-}"
ARCH="$(uname -m)"

case "$ARCH" in
  x86_64|amd64) ;;
  *) echo "[ERROR] Arquitectura no soportada por las imágenes offline amd64: $ARCH" >&2; exit 13 ;;
esac

if [[ ! "$DISTRO" =~ ^(ubuntu|debian|rhel|rocky|almalinux|fedora|centos)$ ]] \
  && [[ "$LIKE" != *debian* ]] && [[ "$LIKE" != *rhel* ]] && [[ "$LIKE" != *fedora* ]]; then
  echo "[ERROR] Distribución no soportada: ${PRETTY_NAME:-$DISTRO}" >&2
  exit 13
fi

command -v systemctl >/dev/null 2>&1 \
  || { echo "[ERROR] GIDEON requiere Linux con systemd/systemctl." >&2; exit 13; }
[[ -d /run/systemd/system ]] \
  || { echo "[ERROR] systemd no está ejecutándose como init; no se admite contenedor/WSL sin systemd." >&2; exit 13; }

ROOT_FREE_KIB="$(df -Pk / | awk 'NR==2 {print $4}')"
MIN_ROOT_FREE_KIB=8388608
[[ "$ROOT_FREE_KIB" =~ ^[0-9]+$ ]] \
  || { echo "[ERROR] No se pudo medir el espacio libre del filesystem raíz." >&2; exit 13; }
[[ "$ROOT_FREE_KIB" -ge "$MIN_ROOT_FREE_KIB" ]] \
  || { echo "[ERROR] Espacio insuficiente: libre=${ROOT_FREE_KIB}KiB requerido=${MIN_ROOT_FREE_KIB}KiB." >&2; exit 13; }

mkdir -p "$DATAROOT/diagnostics" "$LOGROOT" "$CONFROOT"
exec > >(tee -a "$LOGROOT/master-install-$(date +%Y%m%d-%H%M%S).log") 2>&1

step PREFLIGHT

echo "DISTRO=${PRETTY_NAME:-$DISTRO}"
echo "ARCH=$ARCH"
if command -v python3 >/dev/null 2>&1; then
  for supplied_host in "${GIDEON_WEB_HOST:-}" "${GIDEON_AGENT_HOST:-}"; do
    [[ -z "$supplied_host" ]] || python3 "$BUNDLE_DIR/payload/linux/app/deploy/ubuntu/gideon_bootstrap_hosts.py" "$supplied_host" >/dev/null \
      || fail 'Hostname de instalación inválido (antes de instalar paquetes).'
  done
fi

MEM_KIB="$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null || true)"
[[ "$MEM_KIB" =~ ^[0-9]+$ ]] \
  || { echo "[ERROR] No se pudo medir la memoria física disponible." >&2; exit 13; }
# MemTotal excluye una pequeña porción reservada por kernel/firmware. Este
# margen reconoce correctamente una VM configurada con 8 GiB.
[[ "$MEM_KIB" -ge 7864320 ]] \
  || { echo "[ERROR] Memoria insuficiente: detectado=${MEM_KIB}KiB; configure al menos 8 GiB de RAM." >&2; exit 13; }
LOGICAL_PROCESSORS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || true)"
[[ "$LOGICAL_PROCESSORS" =~ ^[0-9]+$ ]] \
  || { echo "[ERROR] No se pudo medir la cantidad de procesadores lógicos." >&2; exit 13; }
[[ "$LOGICAL_PROCESSORS" -ge 4 ]] \
  || { echo "[ERROR] CPU insuficiente: procesadores_logicos=$LOGICAL_PROCESSORS requerido=4." >&2; exit 13; }
echo "HOST_CAPACITY=PASS memory_kib=$MEM_KIB logical_processors=$LOGICAL_PROCESSORS"

RESOURCE_PROFILE="${GIDEON_RESOURCE_PROFILE:-auto}"
case "${RESOURCE_PROFILE,,}" in
  auto|'')
    if [[ "$MEM_KIB" -ge 32505856 && "$LOGICAL_PROCESSORS" -ge 8 ]]; then
      RESOURCE_PROFILE="performance"
    elif [[ "$MEM_KIB" -ge 15728640 ]]; then
      RESOURCE_PROFILE="standard"
    else
      RESOURCE_PROFILE="compact"
    fi
    ;;
  compact|standard|performance) RESOURCE_PROFILE="${RESOURCE_PROFILE,,}" ;;
  *) echo "[ERROR] GIDEON_RESOURCE_PROFILE inválido: $RESOURCE_PROFILE" >&2; exit 13 ;;
esac
case "$RESOURCE_PROFILE" in
  compact) GUACD_MEMORY_LIMIT="768m"; GUACD_CPU_LIMIT="1.0" ;;
  standard) GUACD_MEMORY_LIMIT="1024m"; GUACD_CPU_LIMIT="1.0" ;;
  performance) GUACD_MEMORY_LIMIT="1536m"; GUACD_CPU_LIMIT="2.0" ;;
esac
echo "RESOURCE_PROFILE=PASS selected=$RESOURCE_PROFILE guacd_memory=$GUACD_MEMORY_LIMIT guacd_cpus=$GUACD_CPU_LIMIT maintenance=systemd-timer-path"

if command -v getenforce >/dev/null 2>&1; then
  SELINUX_MODE="$(getenforce 2>/dev/null || true)"
  echo "SELINUX=$SELINUX_MODE"
  [[ "$SELINUX_MODE" != "Disabled" ]] || echo "[WARN] SELinux está deshabilitado previamente; GIDEON no lo modifica."
fi

if command -v aa-status >/dev/null 2>&1; then
  aa-status >/dev/null 2>&1 && echo "APPARMOR=ACTIVE" || echo "APPARMOR=DETECTED"
fi

if systemctl cat guacd.service >/dev/null 2>&1; then
  PRE_GUACD_UNIT=1
  echo "PREEXISTING_NATIVE_GUACD=YES"
fi
if systemctl cat clamav-daemon.service >/dev/null 2>&1 || command -v clamd >/dev/null 2>&1; then
  PRE_CLAMD_UNIT=1
  echo "PREEXISTING_CLAMD=YES"
fi

step PACKAGES

[[ ! -f /var/lib/gideon/tls-manager/active.json ]] || fail "Hay un cambio TLS pendiente desde WebAdmin; confirme o espere su restauración antes de reinstalar."

install_offline_deb() {
  local package_dir="$BUNDLE_DIR/offline-cache/linux/deb/packages"
  local metadata_file="$BUNDLE_DIR/offline-cache/linux/deb/metadata/packages.json"
  verify_offline_package_cache "$package_dir" "$metadata_file" deb || return 1

  echo "[INFO] Instalando paquetes desde cache offline Debian/Ubuntu."
  dpkg -i "$package_dir"/*.deb || apt-get -f install -y --no-download
}

install_offline_rpm() {
  local package_dir="$BUNDLE_DIR/offline-cache/linux/rpm/packages"
  local metadata_file="$BUNDLE_DIR/offline-cache/linux/rpm/metadata/packages.json"
  verify_offline_package_cache "$package_dir" "$metadata_file" rpm || return 1

  echo "[INFO] Instalando paquetes desde cache offline RPM."
  local pm="dnf"
  command -v dnf >/dev/null 2>&1 || pm="yum"
  "$pm" install -y "$package_dir"/*.rpm
}

verify_offline_package_cache() {
  # A cache is optional, but when one is used every package must be covered by
  # the SHA-256 manifest created by prepare-offline-cache-linux.sh. This
  # prevents a side-loaded .deb/.rpm from being installed through GIDEON.
  local package_dir="$1"
  local metadata_file="$2"
  local extension="$3"
  [[ -d "$package_dir" && -f "$metadata_file" ]] || return 1
  python3 - "$package_dir" "$metadata_file" "$extension" <<'PY'
import hashlib
import json
import re
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
manifest_path = Path(sys.argv[2]).resolve()
extension = "." + str(sys.argv[3]).lower().lstrip(".")
try:
    rows = json.loads(manifest_path.read_text(encoding="utf-8"))
except Exception as exc:
    raise SystemExit(f"Cache offline inválida: no se pudo leer packages.json ({type(exc).__name__}).")
if not isinstance(rows, list):
    raise SystemExit("Cache offline inválida: packages.json debe ser una lista.")
expected: dict[str, tuple[int, str]] = {}
for row in rows:
    if not isinstance(row, dict):
        raise SystemExit("Cache offline inválida: fila de packages.json no válida.")
    name = str(row.get("file") or "")
    digest = str(row.get("sha256") or "").lower()
    size = row.get("size")
    if Path(name).name != name or not name.endswith(extension) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise SystemExit("Cache offline inválida: nombre o SHA-256 no válido.")
    try:
        size_value = int(size)
    except (TypeError, ValueError):
        raise SystemExit("Cache offline inválida: tamaño no válido.")
    if size_value < 1 or name in expected:
        raise SystemExit("Cache offline inválida: paquete duplicado o vacío.")
    expected[name] = (size_value, digest)
actual = {
    path.name: path for path in root.iterdir()
    if path.is_file() and not path.is_symlink() and path.name.endswith(extension)
}
if not actual or set(actual) != set(expected):
    raise SystemExit("Cache offline inválida: paquetes no coinciden exactamente con packages.json.")
for name, path in actual.items():
    size, digest = expected[name]
    if path.stat().st_size != size:
        raise SystemExit(f"Cache offline inválida: tamaño inesperado para {name}.")
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    if hasher.hexdigest() != digest:
        raise SystemExit(f"Cache offline inválida: SHA-256 inesperado para {name}.")
print(f"OFFLINE_PACKAGE_CACHE=PASS format={extension[1:]} packages={len(actual)}")
PY
}

need_packages=0
for command_name in python3 ip ss yara clamscan freshclam docker rsync jq ffprobe; do
  command -v "$command_name" >/dev/null 2>&1 || need_packages=1
done
if [[ "$DISTRO" =~ ^(ubuntu|debian)$ ]] || [[ "$LIKE" == *debian* ]]; then
  command -v certbot >/dev/null 2>&1 || need_packages=1
  command -v clamdscan >/dev/null 2>&1 || need_packages=1
fi

if [[ "$need_packages" -eq 1 ]]; then
  if [[ "$DISTRO" =~ ^(ubuntu|debian)$ ]] || [[ "$LIKE" == *debian* ]]; then
    install_offline_deb || {
      [[ "${GIDEON_ALLOW_ONLINE_INSTALL:-0}" == "1" ]] \
        || fail "Faltan paquetes y no hay cache offline. Use prepare-offline-cache-linux.sh o GIDEON_ALLOW_ONLINE_INSTALL=1."

      export DEBIAN_FRONTEND=noninteractive
      apt-get update
      apt-get install -y \
        python3 python3-venv python3-pip rsync jq yara clamav clamav-freshclam clamav-daemon clamdscan \
        ca-certificates curl iproute2 docker.io docker-compose-v2 certbot ffmpeg
    }
  elif [[ "$DISTRO" =~ ^(rhel|rocky|almalinux|fedora|centos)$ ]] \
    || [[ "$LIKE" == *rhel* ]] || [[ "$LIKE" == *fedora* ]]; then

    install_offline_rpm || {
      [[ "${GIDEON_ALLOW_ONLINE_INSTALL:-0}" == "1" ]] \
        || fail "Faltan paquetes y no hay cache offline."

      PM="dnf"
      command -v dnf >/dev/null 2>&1 || PM="yum"
      "$PM" install -y \
        python3 python3-pip rsync jq yara clamav ca-certificates curl iproute \
        podman podman-docker ffmpeg
      "$PM" install -y clamav-update || echo '[WARN] clamav-update no está disponible; se intentarán firmas ClamAV del sistema.'
    }
  else
    fail "Distribución no soportada: $DISTRO"
  fi
fi

step RUNTIME_PREFLIGHT

for command_name in python3 ip ss rsync jq ffprobe; do
  command -v "$command_name" >/dev/null 2>&1 || fail "Dependencia requerida ausente después de instalar paquetes: $command_name"
done
ffprobe -version >/dev/null 2>&1 || fail "FFprobe no es ejecutable; instale el paquete ffmpeg desde la cache GIDEON o repositorio firmado configurado."
echo "MEDIA_VALIDATION=PASS ffprobe=$(command -v ffprobe)"

python3 - <<'PY'
import sys
if sys.version_info < (3, 11):
    raise SystemExit(f"Python 3.11+ requerido; detectado={sys.version.split()[0]}")
print(f"PYTHON_RUNTIME=PASS version={sys.version.split()[0]}")
PY

python3 -c 'import venv; print("PYTHON_VENV=PASS")' \
  || fail "El módulo Python venv no está disponible."

if command -v timedatectl >/dev/null 2>&1; then
  SYNC="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)"
  [[ "$SYNC" == "yes" ]] || fail "Hora/NTP no sincronizada; MFA/TLS requieren tiempo confiable."
fi

ip route > "$DATAROOT/diagnostics/preflight-routes.txt"
ss -lntup > "$DATAROOT/diagnostics/preflight-ports.txt"

step BACKUP

STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="$APPROOT/backups/pre-master-$STAMP"
mkdir -p "$BACKUP"

GIDEON_UNITS="$(
  systemctl list-unit-files --type=service --no-legend 2>/dev/null \
    | awk '/^gideon.*\.service/{print $1}' || true
)"

for unit in $GIDEON_UNITS; do
  [[ "$unit" == *@.service ]] && continue
  systemctl stop "$unit" || true
done

for trigger in gideon-backup.timer gideon-update.path gideon-tls-manager.socket; do
  systemctl stop "$trigger" 2>/dev/null || true
done
# Back up the effective native Linux layout as well as the legacy Master layout.
for native_path in /etc/gideon /var/lib/gideon; do
  if [[ -d "$native_path" ]]; then
    mkdir -p "$BACKUP/native$native_path"
    rsync -a --exclude backups --exclude backup-snapshots --exclude security/clamav "$native_path/" "$BACKUP/native$native_path/"
  fi
done

if [[ -d "$APPROOT/app" ]]; then
  rsync -a "$APPROOT/app/" "$BACKUP/app/"
fi

if [[ -d "$DATAROOT" ]]; then
  rsync -a \
    --exclude backups \
    --exclude diagnostics \
    "$DATAROOT/" "$BACKUP/data/"
fi

step FILESYSTEM

mkdir -p \
  "$APPROOT/source" \
  "$APPROOT/app" \
  "$DATAROOT" \
  "$DATAROOT/data" \
  "$DATAROOT/security/yara" \
  "$DATAROOT/secrets" \
  "$DATAROOT/uploads" \
  "$DATAROOT/quarantine" \
  "$DATAROOT/backups" \
  "$LOGROOT" \
  "$CONFROOT"

getent group gideonremote >/dev/null 2>&1 || groupadd --system gideonremote

for user_name in gideon-webadmin gideon-gateway gideon-worker gideon-updater gideon-scanner; do
  id "$user_name" >/dev/null 2>&1 \
    || useradd --system --gid gideonremote --home /nonexistent --shell /usr/sbin/nologin "$user_name"
done

chmod 0755 "$APPROOT"
chmod 0750 "$DATAROOT" "$CONFROOT" "$LOGROOT"
chmod 0700 "$DATAROOT/secrets" "$DATAROOT/quarantine"

step DEPLOY

[[ -d "$BUNDLE_DIR/payload/linux" ]] || fail "Payload Linux ausente."

rsync -a --delete "$BUNDLE_DIR/payload/linux/" "$APPROOT/source/"
chown -R root:root "$APPROOT/source"

SOURCE_DATA="$BUNDLE_DIR/payload/data/GIDEON Remote Control"
if [[ "$INSTALL_MODE" == clone && -d "$SOURCE_DATA" ]]; then
  rsync -a "$SOURCE_DATA/" "$DATAROOT/"
else
  echo 'INSTALL_MODE=FRESH (no se importan bases de datos ni secretos del clon)'
fi

INCLUDE_STATE="$(
  python3 - "$MANIFEST" <<'PY'
import json
import sys
m=json.load(open(sys.argv[1], encoding="utf-8-sig"))
print("1" if m.get("source",{}).get("include_state_databases") else "0")
PY
)"

if [[ "$INSTALL_MODE" == clone && "$INCLUDE_STATE" == "1" ]]; then
  MACHINE_ID="$(cat /etc/machine-id 2>/dev/null || hostname)"
  BOOTSTRAP_MARKER="$CONFROOT/bootstrap-machine.json"
  NEW_MACHINE=1
  if [[ -f "$BOOTSTRAP_MARKER" ]]; then
    PREVIOUS_MACHINE="$(
      python3 - "$BOOTSTRAP_MARKER" <<'PY'
import json
import sys
try:
    print(json.load(open(sys.argv[1],encoding="utf-8-sig")).get("machine_id",""))
except Exception:
    print("")
PY
    )"
    [[ "$PREVIOUS_MACHINE" == "$MACHINE_ID" ]] && NEW_MACHINE=0
  fi

  RESET_AGENT_POLICY="$(
    python3 - "$CFG" <<'PY'
import json
import sys
cfg=json.load(open(sys.argv[1], encoding="utf-8-sig"))
print("1" if cfg.get("security",{}).get("reset_agent_state_on_new_machine",True) else "0")
PY
  )"
  SANITIZE_ARGS=(
    "$BUNDLE_DIR/installers/tools/sanitize_cloned_runtime_state.py"
    --data-root "$DATAROOT"
    --report "$DATAROOT/diagnostics/clone-state-sanitization.json"
  )
  if [[ "$NEW_MACHINE" == "1" && "$RESET_AGENT_POLICY" == "1" ]]; then
    echo "[INFO] Nueva máquina: eliminando identidades, grants y trabajos de Agents clonados; el catálogo de instaladores se conserva."
    SANITIZE_ARGS+=(--reset-agent-state)
  else
    echo "[INFO] Sanitizando únicamente sesiones efímeras; se conserva el estado de Agents de esta máquina."
  fi
  python3 "${SANITIZE_ARGS[@]}"
fi

step CONFIG_TRANSLATION

read_cfg() {
  python3 - "$CFG" "$1" <<'PY'
import json
import sys

cfg = json.load(open(sys.argv[1], encoding="utf-8-sig"))
value = cfg
for part in sys.argv[2].split("."):
    value = value[part]
print(value)
PY
}

WEB_PORT="$(read_cfg windows.webadmin_internal_port)"
GW_PORT="$(read_cfg windows.gateway_internal_port)"

port_free() {
  ! ss -lntH | awk '{print $4}' | grep -Eq "[:.]${1}$"
}

if ! port_free "$WEB_PORT"; then
  for candidate in $(seq $((WEB_PORT + 1)) $((WEB_PORT + 100))); do
    if port_free "$candidate"; then
      echo "[WARN] WebAdmin port $WEB_PORT ocupado; GIDEON usará $candidate."
      WEB_PORT="$candidate"
      break
    fi
  done
fi

if ! port_free "$GW_PORT"; then
  for candidate in $(seq $((GW_PORT + 1)) $((GW_PORT + 100))); do
    if port_free "$candidate"; then
      echo "[WARN] Gateway port $GW_PORT ocupado; GIDEON usará $candidate."
      GW_PORT="$candidate"
      break
    fi
  done
fi

FQDN="${GIDEON_FQDN:-$(hostname -f 2>/dev/null || hostname)}"
SRC_CONFIG="$DATAROOT/config"

if [[ -d "$SRC_CONFIG" ]]; then
  python3 "$BUNDLE_DIR/installers/tools/translate_config_to_linux.py" \
    --source "$SRC_CONFIG" \
    --dest "$CONFROOT" \
    --web-port "$WEB_PORT" \
    --gateway-port "$GW_PORT" \
    --fqdn "$FQDN"
fi

step NATIVE_INSTALL

NATIVE=""
for candidate in \
  "$APPROOT/source/INSTALL-GIDEON-UBUNTU-LINUX.sh" \
  "$APPROOT/source/app/deploy/aws/install_gideon_aws.sh" \
  "$APPROOT/source/deploy/aws/install_gideon_aws.sh"
do
  if [[ -f "$candidate" ]]; then
    NATIVE="$candidate"
    break
  fi
done

[[ -n "$NATIVE" ]] || fail "No se encontró instalador Linux nativo del producto en el payload."
bash -n "$NATIVE" || fail "Instalador Linux nativo tiene error de sintaxis."

export GIDEON_INSTALL_ROOT="$APPROOT/app"
export GIDEON_DATA_ROOT="$DATAROOT"
export GIDEON_CONFIG_ROOT="$CONFROOT"
export GIDEON_LOG_ROOT="$LOGROOT"
export GIDEON_GUACAMOLE_MODE="docker-external"
export GIDEON_MANAGED_ONECLICK=1
export GIDEON_CLAMD_WAS_PRESENT="$PRE_CLAMD_UNIT"
export GIDEON_WEB_INTERNAL_PORT="$WEB_PORT"
export GIDEON_GATEWAY_INTERNAL_PORT="$GW_PORT"

(
  cd "$(dirname "$NATIVE")"
  bash "$NATIVE"
)

step DOCKER_GUACD

if command -v docker >/dev/null 2>&1; then
  systemctl enable docker >/dev/null 2>&1 || true
  systemctl start docker >/dev/null 2>&1 || true
  docker info >/dev/null 2>&1 || fail "Docker Engine no operativo."
else
  fail "Docker Engine requerido para guacd."
fi

# Validate and load only the GIDEON offline images.
# Never prune/reconfigure the host Docker engine.
IMG_MAP="$BUNDLE_DIR/offline-cache/containers/images.json"

[[ -f "$IMG_MAP" ]] || fail "Falta images.json de Guacamole."

python3 - "$IMG_MAP" "$BUNDLE_DIR/offline-cache/containers" <<'PY'
import hashlib
import json
import os
import re
import sys

map_path=sys.argv[1]
cache=sys.argv[2]
rows=json.load(open(map_path, encoding="utf-8-sig"))

if not rows:
    raise SystemExit("images.json vacío")

for row in rows:
    image_id=str(row.get("image_id") or "")
    archive=str(row.get("archive") or "")
    expected=str(row.get("archive_sha256") or "").lower()

    if not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", image_id):
        raise SystemExit(f"Image ID no inmutable: {image_id}")

    if not archive or not expected:
        raise SystemExit(f"Metadata de imagen incompleta: {row}")

    path=os.path.join(cache, archive)
    if not os.path.isfile(path):
        raise SystemExit(f"Archivo Docker faltante: {path}")

    h=hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024*1024), b""):
            h.update(block)
    actual=h.hexdigest()

    if actual != expected:
        raise SystemExit(
            f"SHA256 Docker inválido {archive}: expected={expected} actual={actual}"
        )

print(f"DOCKER_OFFLINE_ARCHIVES=PASS rows={len(rows)}")
PY

for archive in "$BUNDLE_DIR/offline-cache/containers"/*.tar; do
  [[ -f "$archive" ]] || continue
  echo "[INFO] docker load $(basename "$archive")"
  docker load -i "$archive" >/dev/null
done

USED_ROUTES="$(
  {
    ip route | awk '{print $1}' | grep / || true
    docker network inspect $(docker network ls -q) 2>/dev/null \
      | python3 -c '
import json, sys
try:
    data=json.load(sys.stdin)
except Exception:
    data=[]
for network in data:
    for item in (network.get("IPAM",{}).get("Config") or []):
        subnet=item.get("Subnet")
        if subnet:
            print(subnet)
' || true
  } | sort -u
)"

SUBNET="$(
  python3 - "$CFG" "$USED_ROUTES" <<'PY'
import ipaddress
import json
import sys

cfg=json.load(open(sys.argv[1], encoding="utf-8-sig"))
used=[]
for value in sys.argv[2].splitlines():
    try:
        used.append(ipaddress.ip_network(value, strict=False))
    except Exception:
        pass

for value in cfg["linux"]["docker_network_candidates"]:
    candidate=ipaddress.ip_network(value, strict=False)
    if not any(candidate.overlaps(other) for other in used):
        print(candidate)
        break
PY
)"

[[ -n "$SUBNET" ]] || fail "No hay subred Docker GIDEON libre sin solapamiento."

NET="$(read_cfg linux.docker_network_name)"
docker network inspect "$NET" >/dev/null 2>&1 \
  || docker network create \
       --driver bridge \
       --subnet "$SUBNET" \
       --label com.gideon.remote-control=true \
       "$NET" >/dev/null

GUACD_PORT="$(read_cfg linux.guacd_host_port)"
OWN_GUACD=0
if docker container inspect gideon-guacd >/dev/null 2>&1; then
  [[ "$(docker inspect gideon-guacd --format '{{index .Config.Labels "com.gideon.remote-control"}}')" == true ]] \
    || fail 'Existe un contenedor gideon-guacd ajeno al instalador; no se reemplazará.'
  EXISTING_BIND="$(docker inspect gideon-guacd --format '{{(index (index .HostConfig.PortBindings "4822/tcp") 0).HostIp}}')"
  [[ "$EXISTING_BIND" == 127.0.0.1 ]] || fail 'El guacd existente no está limitado a loopback.'
  GUACD_PORT="$(docker inspect gideon-guacd --format '{{(index (index .HostConfig.PortBindings "4822/tcp") 0).HostPort}}')"
  OWN_GUACD=1
fi
if [[ "$OWN_GUACD" -eq 0 ]] && ! port_free "$GUACD_PORT"; then
  for candidate in $(seq $((GUACD_PORT + 1)) $((GUACD_PORT + 100))); do
    if port_free "$candidate"; then
      echo "[WARN] guacd port $GUACD_PORT ocupado; GIDEON usará $candidate."
      GUACD_PORT="$candidate"
      break
    fi
  done
fi

IMG_MAP="$BUNDLE_DIR/offline-cache/containers/images.json"
GUACD_IMAGE=""

if [[ -f "$IMG_MAP" ]]; then
  GUACD_IMAGE="$(
    python3 - "$IMG_MAP" <<'PY'
import json
import sys

rows=json.load(open(sys.argv[1], encoding="utf-8-sig"))
for row in rows:
    if row.get("container") == "gideon-guacd":
        print(row.get("image_id") or row.get("image") or "")
        break
PY
  )"
fi

if [[ -z "$GUACD_IMAGE" ]]; then
  GUACD_IMAGE="$(
    docker images --no-trunc --format '{{.Repository}} {{.ID}}' \
      | awk 'tolower($1) ~ /guacd/{print $2; exit}'
  )"
fi

[[ -n "$GUACD_IMAGE" ]] || fail "No se encontró imagen offline gideon-guacd."
[[ "$GUACD_IMAGE" =~ ^sha256:[0-9a-fA-F]{64}$ ]]   || fail "GUACD_IMAGE no es un Image ID inmutable: $GUACD_IMAGE"

docker image inspect "$GUACD_IMAGE" >/dev/null 2>&1   || fail "Image ID guacd no quedó cargado: $GUACD_IMAGE"

echo "[PASS] GUACD_IMAGE_ID=PASS $GUACD_IMAGE"

docker rm -f gideon-guacd >/dev/null 2>&1 || true

docker run -d \
  --name gideon-guacd \
  --network "$NET" \
  --label com.gideon.remote-control=true \
  --restart unless-stopped \
  --init \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  --tmpfs /home/guacd:rw,nosuid,nodev,size=16m,uid=1000,gid=1000,mode=0700 \
  --pids-limit 256 \
  --memory "$GUACD_MEMORY_LIMIT" \
  --cpus "$GUACD_CPU_LIMIT" \
  --log-opt max-size=10m \
  --log-opt max-file=3 \
  --health-interval 30s \
  --health-timeout 5s \
  --health-retries 3 \
  --health-start-period 5s \
  -p "127.0.0.1:${GUACD_PORT}:4822" \
  "$GUACD_IMAGE" >/dev/null

# Only suppress a duplicate native guacd if it did NOT pre-exist before GIDEON install.
if [[ "$PRE_GUACD_UNIT" -eq 0 ]] && systemctl cat guacd.service >/dev/null 2>&1; then
  echo "[INFO] Deshabilitando guacd nativo introducido durante instalación; Docker es el runtime oficial GIDEON."
  systemctl disable --now guacd.service >/dev/null 2>&1 || true
fi

step GUACD_CONFIG

WEB_CFG="/etc/gideon/web/web_admin.json"
[[ -f "$WEB_CFG" ]] || fail "No existe la configuración efectiva del servicio WebAdmin: $WEB_CFG"
if [[ -f "$WEB_CFG" ]]; then
  python3 - "$WEB_CFG" "$GUACD_PORT" <<'PY'
import json
import sys

path=sys.argv[1]
port=int(sys.argv[2])
obj=json.load(open(path, encoding="utf-8-sig"))
remote=obj.setdefault("remote_sessions",{})
remote.setdefault("clipboard_enabled", True)
remote.setdefault("file_transfer_enabled", True)
remote.setdefault("max_clipboard_bytes", 1024 * 1024)
remote.setdefault("max_file_transfer_bytes", 100 * 1024 * 1024)
guacd=remote.setdefault("guacd",{})
guacd["host"]="127.0.0.1"
guacd["port"]=port
guacd["vnc_enabled"]=True
open(path,"w",encoding="utf-8").write(
    json.dumps(obj, indent=2, ensure_ascii=False)
)
PY
fi

# Guacd runs in a Docker bridge; reverse-tunnel listeners must be reachable
# from that container, not advertised as a nonexistent 'gideon-gateway' hostname.
BRIDGE_IP="$(docker network inspect "$NET" --format '{{(index .IPAM.Config 0).Gateway}}')"
python3 - /etc/gideon/gateway/gateway.json "$BRIDGE_IP" <<'PY'
import ipaddress, json, sys
address=str(ipaddress.ip_address(sys.argv[2]))
path=sys.argv[1]
cfg=json.load(open(path,encoding='utf-8-sig'))
cfg['reverse_tunnel_listen_host']=address
cfg['reverse_tunnel_advertised_host']=address
open(path,'w',encoding='utf-8').write(json.dumps(cfg,indent=2)+'\n')
PY

step SECRETS

ENV_SRC="$BUNDLE_DIR/metadata/machine-environment.json"
ENV_FILE="$CONFROOT/secrets.env"
: > "$ENV_FILE"
chmod 0600 "$ENV_FILE"

if [[ "$INSTALL_MODE" == clone && -f "$ENV_SRC" ]]; then
  python3 - "$ENV_SRC" <<'PY' >> "$ENV_FILE"
import json
import sys

rows=json.load(open(sys.argv[1], encoding="utf-8-sig"))
for row in rows:
    name=str(row.get("name") or "")
    value=str(row.get("value") or "")
    if name and value and value != "__REDACTED__":
        print(f"{name}={value}")
PY
fi

if ! grep -q '^GIDEON_WEB_TOTP_ENCRYPTION_KEY=' "$ENV_FILE"; then
  if find "$DATAROOT" -type f -name '*.fernet' -print -quit | grep -q .; then
    fail "Hay secretos .fernet pero falta GIDEON_WEB_TOTP_ENCRYPTION_KEY."
  fi

  KEY="$(
    python3 - <<'PY'
import base64
import os
print(base64.urlsafe_b64encode(os.urandom(32)).decode())
PY
  )"
  printf 'GIDEON_WEB_TOTP_ENCRYPTION_KEY=%s\n' "$KEY" >> "$ENV_FILE"
fi

step MALWARE_GATES

command -v yara >/dev/null 2>&1 || fail "YARA requerido y no instalado."
command -v clamscan >/dev/null 2>&1 || fail "ClamAV requerido y no instalado."

CLAMAV_PREPARER="$APPROOT/source/app/deploy/aws/prepare_gideon_clamav_db.sh"
CLAMAV_PREPARE_REPORT="$DATAROOT/diagnostics/clamav-prepare.txt"
[[ -x "$CLAMAV_PREPARER" ]] || fail "Preparador de firmas ClamAV GIDEON ausente o no ejecutable: $CLAMAV_PREPARER"
if ! "$CLAMAV_PREPARER" --ensure > >(tee "$CLAMAV_PREPARE_REPORT") 2>&1; then
  fail "No se pudo preparar la base privada ClamAV. Revise $CLAMAV_PREPARE_REPORT y /var/log/gideon/updater/clamav-update.log"
fi

mapfile -t YARA_RULES < <(
  find "$DATAROOT" "$BUNDLE_DIR/security" \
    -type f \( -name '*.yar' -o -name '*.yara' \) \
    2>/dev/null | sort -u
)

if [[ "${#YARA_RULES[@]}" -gt 0 ]]; then
  YARA_REPORT="$DATAROOT/diagnostics/yara-install.txt"
  : > "$YARA_REPORT"
  # Only the exact, reviewed rules file contains its own detection strings.
  # No extension-wide exclusion: modified or additional rules are not exempt.
  SELF_RULE="$APPROOT/source/app/deploy/web/security/gideon-policy.yar"
  cmp -s "$SELF_RULE" "$BUNDLE_DIR/security/security_yara/gideon-policy.yar" \
    || fail 'El ruleset empaquetado no coincide con la política YARA revisada.'
  SCAN_LIST="$(mktemp)"
  find "$APPROOT/source" -type f ! -path "$SELF_RULE" > "$SCAN_LIST"

  for rule in "${YARA_RULES[@]}"; do
    TMP_YARA="$(mktemp)"

    set +e
    yara --scan-list "$rule" "$SCAN_LIST" > "$TMP_YARA" 2>&1
    YARA_RC=$?
    set -e

    {
      printf '=== RULESET %s ===\n' "$rule"
      cat "$TMP_YARA"
    } >> "$YARA_REPORT"

    if [[ "$YARA_RC" -ne 0 ]]; then
      rm -f "$TMP_YARA"
      fail "YARA falló rc=$YARA_RC con $rule. Revise diagnostics/yara-install.txt"
    fi

    if [[ -s "$TMP_YARA" ]]; then
      rm -f "$TMP_YARA"
      fail "YARA detectó coincidencias con $rule. Revise diagnostics/yara-install.txt"
    fi

    rm -f "$TMP_YARA"
  done
  rm -f "$SCAN_LIST"

  echo "YARA_SCAN=PASS rulesets=${#YARA_RULES[@]}"
else
  fail "No se encontró ruleset YARA GIDEON."
fi

set +e
clamscan -r --infected --no-summary --database=/var/lib/gideon/security/clamav "$APPROOT/source" \
  > "$DATAROOT/diagnostics/clamav-install.txt" 2>&1
CLAM_RC=$?
set -e

if [[ "$CLAM_RC" -eq 1 ]]; then
  fail "ClamAV detectó malware en payload."
elif [[ "$CLAM_RC" -gt 1 ]]; then
  echo '[ERROR] Últimas líneas de ClamAV:' >&2
  tail -n 20 "$DATAROOT/diagnostics/clamav-install.txt" >&2 || true
  fail "ClamAV falló rc=$CLAM_RC. Revise $DATAROOT/diagnostics/clamav-install.txt"
fi

step WEBADMIN_USERS

PY=""
for candidate in \
  /opt/gideon/web/venv/bin/python \
  "$APPROOT/venv/bin/python" \
  "$APPROOT/app/venv/bin/python" \
  /usr/bin/python3
do
  if [[ -x "$candidate" ]]; then
    PY="$candidate"
    break
  fi
done

[[ -n "$PY" ]] || fail "Python no disponible para bootstrap de usuarios."

USERS_TMP="$(mktemp)"
CREDS_TMP="$(mktemp)"
CREDENTIALS_WRITTEN=0
chmod 0600 "$USERS_TMP" "$CREDS_TMP"

python3 - "$CFG" > "$USERS_TMP" <<'PY'
import json
import sys

cfg=json.load(open(sys.argv[1], encoding="utf-8-sig"))
rows=[]
for index,user in enumerate(cfg["webadmin_bootstrap_users"],1):
    rows.append(
        {
            "username": user["username"],
            "display_name": user.get("display_name",user["username"]),
            "role": user.get("role","ADMIN"),
            "password_env": f"GIDEON_BOOTSTRAP_PWD_{index}",
        }
    )
print(json.dumps(rows))
PY

COUNT="$(python3 -c "import json; print(len(json.load(open('$USERS_TMP'))))")"

GENERATED_PASSWORDS=()
for index in $(seq 1 "$COUNT"); do
  while true; do
    PASSWORD="$(
      python3 - <<'PY'
import secrets
import string
alphabet=string.ascii_letters+string.digits+"!@#%_-+="
print("A9!"+''.join(secrets.choice(alphabet) for _ in range(21)))
PY
    )"
    DUPLICATE=0
    for previous in "${GENERATED_PASSWORDS[@]}"; do
      [[ "$PASSWORD" == "$previous" ]] && DUPLICATE=1
    done
    [[ "$DUPLICATE" == "0" ]] && break
  done
  GENERATED_PASSWORDS+=("$PASSWORD")
  export "GIDEON_BOOTSTRAP_PWD_${index}=$PASSWORD"
done

MACHINE_ID="${MACHINE_ID:-$(cat /etc/machine-id 2>/dev/null || hostname)}"
BOOTSTRAP_MARKER="${BOOTSTRAP_MARKER:-$CONFROOT/bootstrap-machine.json}"
ROTATE_EXISTING=0

ROTATE_POLICY="$(
  python3 - "$CFG" <<'PY'
import json
import sys
cfg=json.load(open(sys.argv[1], encoding="utf-8-sig"))
print("1" if cfg.get("security",{}).get("rotate_bootstrap_passwords_on_new_machine",True) else "0")
PY
)"

if [[ "$ROTATE_POLICY" == "1" ]]; then
  if [[ ! -f "$BOOTSTRAP_MARKER" ]]; then
    ROTATE_EXISTING=1
  else
    PREVIOUS_MACHINE="$(
      python3 - "$BOOTSTRAP_MARKER" <<'PY'
import json
import sys
try:
    print(json.load(open(sys.argv[1],encoding="utf-8-sig")).get("machine_id",""))
except Exception:
    print("")
PY
    )"
    [[ "$PREVIOUS_MACHINE" == "$MACHINE_ID" ]] || ROTATE_EXISTING=1
  fi
fi

BOOTSTRAP_ARGS=(
  "$BUNDLE_DIR/installers/tools/bootstrap_webadmin_users.py"
  --app-root "$APPROOT/source/app"
  --config "$WEB_CFG"
  --users-json "$USERS_TMP"
)

if [[ "$ROTATE_EXISTING" == "1" ]]; then
  echo "[WARN] Nueva identidad de servidor: se rotarán una sola vez las contraseñas bootstrap."
  BOOTSTRAP_ARGS+=(--rotate-existing)
fi

set +x
RESULT="$(
  "$PY" "${BOOTSTRAP_ARGS[@]}"
)" || fail "Bootstrap users falló."

python3 - "$RESULT" "$USERS_TMP" > "$CREDS_TMP" <<'PY'
import json
import os
import sys

result=json.loads(sys.argv[1])
users=json.load(open(sys.argv[2]))
created={
    x.get("username")
    for x in result.get("users",[])
    if x.get("status") in {"CREATED","ROTATED"}
}

for index,user in enumerate(users,1):
    if user["username"] in created:
        print(f"User: {user['username']}")
        print(f"Role: {user['role']}")
        print(f"Temporary password: {os.environ.get('GIDEON_BOOTSTRAP_PWD_'+str(index),'')}")
        print()
PY

while IFS='=' read -r name _; do
  [[ "$name" =~ ^GIDEON_BOOTSTRAP_PWD_[0-9]+$ ]] && unset "$name"
done < <(env)

rm -f "$USERS_TMP"

if [[ -s "$CREDS_TMP" ]]; then
  cp "$CREDS_TMP" "$DATAROOT/secrets/bootstrap-credentials.txt"
  chmod 0600 "$DATAROOT/secrets/bootstrap-credentials.txt"
  CREDENTIALS_WRITTEN=1
fi
rm -f "$CREDS_TMP"

python3 - "$BOOTSTRAP_MARKER" "$MACHINE_ID" "$ROTATE_EXISTING" <<'PY'
import datetime
import json
import sys

path=sys.argv[1]
payload={
    "machine_id":sys.argv[2],
    "rotated_on_install":sys.argv[3]=="1",
    "updated_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
}
open(path,"w",encoding="utf-8").write(
    json.dumps(payload,indent=2,ensure_ascii=False)
)
PY
chmod 0600 "$BOOTSTRAP_MARKER"

step SYSTEMD_HARDENING

GIDEON_UNITS="$(
  systemctl list-unit-files --type=service --no-legend 2>/dev/null \
    | awk '/^gideon.*\.service/{print $1}' || true
)"

for unit in $GIDEON_UNITS; do
  mkdir -p "/etc/systemd/system/$unit.d"

  UNIT_TEXT="$(systemctl cat "$unit" 2>/dev/null || true)"
  ENV_LINE=""
  NO_NEW_PRIVILEGES=true
  if [[ "$unit" == "gideon-clamav-update.service" ]]; then
    # Its root-owned wrapper drops to gideonweb for freshclam. Setting NNP would
    # block that setuid transition and silently leave signatures stale.
    NO_NEW_PRIVILEGES=false
  fi
  if [[ ! -f /etc/gideon/web/web.env ]] && { [[ "$unit" =~ [Ww]eb.*[Aa]dmin ]] || [[ "$UNIT_TEXT" == *"gideon_web_admin"* ]]; }; then
    ENV_LINE="EnvironmentFile=-$CONFROOT/secrets.env"
  fi

  cat > "/etc/systemd/system/$unit.d/10-gideon-security.conf" <<EOF
[Service]
NoNewPrivileges=$NO_NEW_PRIVILEGES
PrivateTmp=true
ProtectHome=true
UMask=0027
$ENV_LINE
EOF
done

systemctl daemon-reload

for unit in gideon-agent-gateway.service gideon-web-admin.service gideon-diagnostics.service gideon-coordinator.service; do
  systemctl restart "$unit" || fail "No se pudo reiniciar $unit"
done

step EXTERNAL_ACCESS

EXTERNAL_HELPER=/opt/gideon/web/app/deploy/ubuntu/CONFIGURE-GIDEON-EXTERNAL.sh
[[ -f "$EXTERNAL_HELPER" ]] || fail "Herramienta de publicación HTTPS ausente."
chmod 0755 "$EXTERNAL_HELPER"
if [[ "${GIDEON_EXTERNAL_ACCESS:-wizard}" != 'later' ]]; then
  bash "$EXTERNAL_HELPER" --wizard || fail "Publicación/certificados incompletos; los servicios privados permanecen disponibles."
else
  echo 'EXTERNAL_ACCESS=PENDING (GIDEON_EXTERNAL_ACCESS=later)'
fi

step EXTERNAL_ACCESS_PLAN

python3 - "$CONFROOT/external-access-plan.json" "$GUACD_PORT" "$EXTERNAL_HELPER" <<'PY'
import json, sys
from pathlib import Path
state_path=Path('/etc/gideon/external-access.json')
state=json.loads(state_path.read_text()) if state_path.is_file() else {}
configured=state.get('status','').startswith('LOCAL_HTTPS_PASS')
plan={
  "admin": {
    "mode": "DIRECT_TLS_CIDR_RESTRICTED" if configured else "PENDING",
    "port": state.get('web_port') if configured else None,
    "url": state.get('web_url') if configured else None,
    "admin_cidrs": state.get('admin_cidr',[]) if configured else [],
    "listener_configured": configured
  },
  "agents": {
    "port": state.get('agent_port') if configured else None,
    "url": state.get('agent_url') if configured else None,
    "transport": "HTTPS_WSS_WITH_EXISTING_MTLS_POLICY",
    "direct_rdp_ssh_public": False
  },
  "guacd": {
    "host": "127.0.0.1",
    "port": int(sys.argv[2]),
    "public": False
  },
  "effective_state": str(state_path),
  "certificate_tool": sys.argv[3],
  "internet_reachability": "NOT_TESTED",
  "note": "GIDEON direct TLS supports 443/9443 without a proxy. Configure DNS, static IP and GCP/host firewall separately; local verification is not an Internet reachability test."
}
Path(sys.argv[1]).write_text(json.dumps(plan,indent=2)+'\n')
PY

step VERIFY

GIDEON_GUACD_HOST_PORT="$GUACD_PORT" \
  bash "$SCRIPT_DIR/verify-gideon-master-linux.sh"

trap - EXIT

echo
echo "============================================================"
echo "FINAL_INSTALL=PASS"
echo "WEBADMIN_STAGING_PORT=$WEB_PORT (may have been replaced by external configuration)"
echo "GATEWAY_STAGING_PORT=$GW_PORT (may have been replaced by external configuration)"
echo "GUACD=127.0.0.1:$GUACD_PORT"
echo "EXTERNAL_ACCESS_PLAN=$CONFROOT/external-access-plan.json"

if [[ "$CREDENTIALS_WRITTEN" == "1" ]]; then
  # The managed bootstrap rotates the native temporary account once; discard
  # the now-stale standalone-installer credential copy.
  rm -f /etc/gideon/bootstrap/web-credentials.txt
  echo "GIDEON_WEBADMIN_CREDENTIALS_FILE=$DATAROOT/secrets/bootstrap-credentials.txt (root, modo 0600)"
  echo "ACTION=Configurar MFA y cambiar inmediatamente las contraseñas."
elif [[ -s "$DATAROOT/secrets/bootstrap-credentials.txt" ]]; then
  echo "GIDEON_WEBADMIN_CREDENTIALS_PRESERVED=$DATAROOT/secrets/bootstrap-credentials.txt"
  echo "INFO=No se generaron ni rotaron contraseñas en esta ejecución; el archivo existente no fue reemplazado."
fi

echo "============================================================"
