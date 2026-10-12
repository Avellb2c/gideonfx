#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE="${GIDEON_PORTABLE_PROFILE:-@@PROFILE@@}"

[[ "$(uname -s)" == "Linux" ]] || {
  echo "[FAIL] Este launcher instala el servidor GIDEON únicamente en Linux; macOS no está soportado como servidor Master." >&2
  exit 94
}

if [[ "$(id -u)" -ne 0 ]]; then
  command -v sudo >/dev/null 2>&1 || {
    echo "[FAIL] Se requiere root o sudo." >&2
    exit 90
  }
  exec sudo --preserve-env=GIDEON_PACKAGE_BASE_URL,GIDEON_ALLOW_ONLINE_INSTALL,GIDEON_PORTABLE_PROFILE,GIDEON_RESOURCE_PROFILE,GIDEON_WEB_HOST,GIDEON_AGENT_HOST,GIDEON_EXTERNAL_ACCESS,GIDEON_INSTALL_MODE \
    bash "$0" "$@"
fi

fail() { echo "[FAIL] $1" >&2; exit "${2:-90}"; }
info() { echo "[PORTABLE] $1"; }
pass() { echo "[PASS] $1"; }
safe_cache_target() {
  case "$1" in
    /var/cache/gideon-oneclick/?*) ;;
    *) fail "Destino de caché inseguro rechazado: $1" 98 ;;
  esac
  [[ "$1" != "/var/cache/gideon-oneclick" ]] || fail "No se puede borrar la raíz de caché." 98
}

[[ "$PROFILE" == "linux" ]] || fail "Perfil Linux inválido: $PROFILE" 91
command -v tar >/dev/null 2>&1 || fail "tar no está disponible." 91
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum no está disponible." 91
command -v flock >/dev/null 2>&1 || fail "flock (util-linux) no está disponible." 91
command -v python3 >/dev/null 2>&1 || fail "python3 es requerido para extraer módulos de forma segura." 91
case "$(uname -m)" in
  x86_64|amd64) ;;
  *) fail "Arquitectura no soportada por los módulos offline amd64: $(uname -m)" 94 ;;
esac

mem_kib="$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null || true)"
[[ "$mem_kib" =~ ^[0-9]+$ ]] || fail "No se pudo medir la memoria física disponible." 94
# Linux no expone como MemTotal toda la RAM asignada a la VM. El margen de
# 512 MiB permite reconocer correctamente un host configurado con 8 GiB sin
# rebajar el requisito de hardware publicado.
[[ "$mem_kib" -ge 7864320 ]] \
  || fail "Memoria insuficiente para Gideon Rx: detectado=${mem_kib}KiB; configure al menos 8 GiB de RAM." 94
logical_processors="$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || true)"
[[ "$logical_processors" =~ ^[0-9]+$ ]] || fail "No se pudo medir la cantidad de procesadores lógicos." 94
[[ "$logical_processors" -ge 4 ]] \
  || fail "CPU insuficiente para Gideon Rx: procesadores_logicos=$logical_processors requerido=4." 94
pass "HOST_CAPACITY=PASS memory_kib=$mem_kib logical_processors=$logical_processors"
resource_profile="${GIDEON_RESOURCE_PROFILE:-auto}"
case "${resource_profile,,}" in
  auto|'')
    if [[ "$mem_kib" -ge 32505856 && "$logical_processors" -ge 8 ]]; then
      resource_profile="performance"
    elif [[ "$mem_kib" -ge 15728640 ]]; then
      resource_profile="standard"
    else
      resource_profile="compact"
    fi
    ;;
  compact|standard|performance) resource_profile="${resource_profile,,}" ;;
  *) fail "GIDEON_RESOURCE_PROFILE inválido: $resource_profile" 94 ;;
esac
export GIDEON_RESOURCE_PROFILE="$resource_profile"
pass "RESOURCE_PROFILE=$resource_profile"

SHIPPED_PROFILE_MANIFEST="$SCRIPT_DIR/profiles/linux.sha256"
PACKAGE_MODULES_MANIFEST="$SCRIPT_DIR/package.modules.sha256"
PROFILE_MANIFEST="$SHIPPED_PROFILE_MANIFEST"

if [[ -f "$PACKAGE_MODULES_MANIFEST" ]]; then
  package_hash="$(sha256sum "$PACKAGE_MODULES_MANIFEST" | awk '{print $1}')"
  recovery_root="/var/cache/gideon-oneclick/recovered-profiles/${package_hash:0:24}"
  mkdir -p "$recovery_root"
  recovered_profile="$recovery_root/linux.sha256"
  recovered_tmp="$recovered_profile.tmp-$$"
  : > "$recovered_tmp"

  for required_name in 10-GIDEON-COMMON.tar.gz 20-GIDEON-LINUX.tar.gz; do
    match_count=0
    matched_sha=""
    while read -r expected raw_name; do
      [[ -n "${expected:-}" ]] || continue
      [[ "$expected" == \#* ]] && continue
      name="${raw_name#\*}"
      if [[ "$name" == "$required_name" ]]; then
        [[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]] \
          || fail "SHA inválido para $required_name en package.modules.sha256" 91
        match_count=$((match_count + 1))
        matched_sha="${expected,,}"
      fi
    done < "$PACKAGE_MODULES_MANIFEST"
    [[ "$match_count" -eq 1 ]] \
      || fail "package.modules.sha256 debe contener exactamente un $required_name" 91
    printf '%s *%s\n' "$matched_sha" "$required_name" >> "$recovered_tmp"
  done

  mv -f -- "$recovered_tmp" "$recovered_profile"
  if [[ ! -f "$SHIPPED_PROFILE_MANIFEST" ]]; then
    echo "[WARN] PROFILE_MANIFEST_MISSING=$SHIPPED_PROFILE_MANIFEST"
    echo "[WARN] PROFILE_MANIFEST_REBUILT_FROM_PACKAGE=$recovered_profile"
    PROFILE_MANIFEST="$recovered_profile"
  elif [[ "$(sha256sum "$SHIPPED_PROFILE_MANIFEST" | awk '{print $1}')" != "$(sha256sum "$recovered_profile" | awk '{print $1}')" ]]; then
    echo "[WARN] PROFILE_MANIFEST_STALE=$SHIPPED_PROFILE_MANIFEST"
    echo "[WARN] PROFILE_MANIFEST_REBUILT_FROM_PACKAGE=$recovered_profile"
    PROFILE_MANIFEST="$recovered_profile"
  fi
elif [[ ! -f "$SHIPPED_PROFILE_MANIFEST" ]]; then
  fail "Faltan $SHIPPED_PROFILE_MANIFEST y package.modules.sha256; el kit está incompleto." 91
fi

MANIFEST_HASH="$(sha256sum "$PROFILE_MANIFEST" | awk '{print $1}')"
CACHE_ROOT="/var/cache/gideon-oneclick/${MANIFEST_HASH:0:24}"
BUNDLE_ROOT="$CACHE_ROOT/bundle"
MARKER="$CACHE_ROOT/READY"
DOWNLOAD_ROOT="/var/cache/gideon-oneclick/downloads"

mkdir -p "$(dirname "$CACHE_ROOT")" "$DOWNLOAD_ROOT"
exec 9>"/var/cache/gideon-oneclick/bootstrap.lock"
flock -n 9 || fail "Otro bootstrap Gideon Rx está preparando paquetes." 95

if [[ -f "$MARKER" \
   && -f "$BUNDLE_ROOT/deployment.manifest.json" \
   && -f "$BUNDLE_ROOT/installers/LINUX/install-gideon-master-linux.sh" \
   && -f "$BUNDLE_ROOT/offline-cache/containers/images.json" \
   && -d "$BUNDLE_ROOT/payload/linux/app" ]] \
   && grep -Fxq "$MANIFEST_HASH" "$MARKER"; then
  pass "PACKAGE_CACHE_REUSED=$CACHE_ROOT"
else
  STAGE="${CACHE_ROOT}.stage-$$"
  safe_cache_target "$STAGE"
  safe_cache_target "$CACHE_ROOT"
  available_kib="$(df -Pk /var/cache | awk 'NR==2 {print $4}')"
  required_kib=6291456
  [[ "$available_kib" =~ ^[0-9]+$ ]] || fail "No se pudo medir espacio libre en /var/cache." 98
  [[ "$available_kib" -ge "$required_kib" ]] \
    || fail "Espacio insuficiente en /var/cache: libre=${available_kib}KiB requerido=${required_kib}KiB." 98
  rm -rf -- "$STAGE"
  mkdir -p "$STAGE/bundle"

  while read -r expected raw_name; do
    [[ -n "${expected:-}" ]] || continue
    [[ "$expected" == \#* ]] && continue
    name="${raw_name#\*}"
    [[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]] || fail "SHA inválido en manifiesto." 91
    [[ "$name" != */* && "$name" != *\\* && "$name" != "." && "$name" != ".." ]] \
      || fail "Nombre de módulo inseguro: $name" 91

    module="$SCRIPT_DIR/$name"
    if [[ ! -f "$module" ]]; then
      base="${GIDEON_PACKAGE_BASE_URL:-}"
      [[ -n "$base" ]] || fail "Falta $name. Copie el kit completo o defina GIDEON_PACKAGE_BASE_URL." 92
      command -v curl >/dev/null 2>&1 || fail "curl es requerido para descargar módulos." 92
      module="$DOWNLOAD_ROOT/${expected:0:16}-$name"
      info "Descargando de forma reanudable: ${base%/}/$name"
      curl --fail --location --retry 5 --continue-at - --output "$module" "${base%/}/$name"
    fi

    info "Verificando SHA-256: $name"
    actual="$(sha256sum "$module" | awk '{print $1}')"
    [[ "${actual,,}" == "${expected,,}" ]] \
      || fail "KIT_MIXED_VERSION: SHA-256 inválido para $name. Copie el kit completo en una carpeta nueva; no mezcle versiones." 93
    info "Preparando $name directamente en la caché local"
    python3 - "$module" "$STAGE/bundle" <<'PY'
import pathlib, sys, tarfile
archive, destination = sys.argv[1:]
with tarfile.open(archive, 'r:gz') as source:
    members = source.getmembers()
    if not members or len(members) > 20000:
        raise SystemExit('Módulo vacío o con demasiadas entradas.')
    total = 0; names = set()
    for member in members:
        path = pathlib.PurePosixPath(member.name.replace('\\', '/'))
        if path.is_absolute() or not path.parts or '..' in path.parts or member.name in names:
            raise SystemExit('Ruta de archivo insegura o duplicada: ' + member.name)
        if not (member.isfile() or member.isdir()):
            raise SystemExit('Enlaces y archivos especiales no están permitidos: ' + member.name)
        names.add(member.name); total += max(0, member.size)
    if total > 8 * 1024 * 1024 * 1024:
        raise SystemExit('Módulo excede el límite descomprimido de 8 GiB.')
    source.extractall(destination, members=members, filter='data')
PY
    [[ "$?" -eq 0 ]] || fail "Extracción segura falló para $name" 97
  done < "$PROFILE_MANIFEST"

  [[ -f "$STAGE/bundle/deployment.manifest.json" ]] || fail "Paquete incompleto: deployment.manifest.json" 97
  [[ -f "$STAGE/bundle/installers/LINUX/install-gideon-master-linux.sh" ]] \
    || fail "Paquete incompleto: instalador Linux" 97
  printf '%s\n' "$MANIFEST_HASH" > "$STAGE/READY"
  rm -rf -- "$CACHE_ROOT"
  mv -- "$STAGE" "$CACHE_ROOT"
  pass "PACKAGE_CACHE_READY=$CACHE_ROOT"
fi

info "Iniciando el instalador Linux desde la caché verificada"
exec bash "$BUNDLE_ROOT/installers/LINUX/install-gideon-master-linux.sh" "$@"
