#!/usr/bin/env bash
set -Eeuo pipefail
umask 027
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

MODE="${1:---ensure}"
case "$MODE" in
  --ensure|--refresh) ;;
  *) echo "ERROR: uso: $0 [--ensure|--refresh]" >&2; exit 2 ;;
esac

DB_DIR="${GIDEON_CLAMAV_DATABASE_DIR:-/var/lib/gideon/security/clamav}"
CONFIG_FILE="${GIDEON_CLAMAV_CONFIG_FILE:-/etc/gideon/security/freshclam.conf}"
LOG_FILE="${GIDEON_CLAMAV_LOG_FILE:-/var/log/gideon/updater/clamav-update.log}"
LOCK_FILE="${GIDEON_CLAMAV_LOCK_FILE:-/run/gideon-clamav-update.lock}"
DB_OWNER="${GIDEON_CLAMAV_OWNER:-gideonweb}"
SYSTEM_DIRS="${GIDEON_CLAMAV_SYSTEM_DIRS:-/var/lib/clamav:/usr/share/clamav}"

[[ "$DB_DIR" == /* && "$DB_DIR" != / ]] || {
  echo "ERROR: directorio ClamAV GIDEON inseguro o no absoluto: $DB_DIR" >&2
  exit 2
}
[[ "$CONFIG_FILE" == /* && "$CONFIG_FILE" != / ]] || {
  echo "ERROR: ruta de configuración freshclam insegura: $CONFIG_FILE" >&2
  exit 2
}
id "$DB_OWNER" >/dev/null 2>&1 || {
  echo "ERROR: la cuenta propietaria ClamAV GIDEON no existe: $DB_OWNER" >&2
  exit 2
}

install -d -m 0750 -o "$DB_OWNER" -g "$DB_OWNER" "$DB_DIR"
install -d -m 0755 -o root -g root "$(dirname "$CONFIG_FILE")" "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"
chown root:root "$LOG_FILE"
chmod 0640 "$LOG_FILE"

exec 9>"$LOCK_FILE"
if command -v flock >/dev/null 2>&1; then
  flock -w 45 9 || {
    echo "ERROR: otra actualización ClamAV GIDEON sigue activa." >&2
    exit 3
  }
fi

log() {
  printf '[%s] %s\n' "$(date -Is)" "$*" | tee -a "$LOG_FILE"
}

component_file() {
  local component="$1"
  find "$DB_DIR" -maxdepth 1 -type f \
    \( -name "$component.cvd" -o -name "$component.cld" \) \
    -size +1024c -print -quit 2>/dev/null
}

has_component() {
  local component="$1" candidate=""
  candidate="$(component_file "$component")"
  [[ -n "$candidate" ]] || return 1
  if command -v sigtool >/dev/null 2>&1; then
    sigtool --info "$candidate" >/dev/null 2>&1
  fi
}

database_ready() {
  has_component main && has_component daily
}

normalize_permissions() {
  find "$DB_DIR" -maxdepth 1 -type f -exec chown "$DB_OWNER:$DB_OWNER" {} +
  find "$DB_DIR" -maxdepth 1 -type f -exec chmod 0640 {} +
  chown "$DB_OWNER:$DB_OWNER" "$DB_DIR"
  chmod 0750 "$DB_DIR"
}

import_system_database() {
  local imported=0 source source_dir base temporary
  local -a source_dirs=()
  IFS=: read -r -a source_dirs <<< "$SYSTEM_DIRS"

  for source_dir in "${source_dirs[@]}"; do
    [[ "$source_dir" == /* && -d "$source_dir" && "$source_dir" != "$DB_DIR" ]] || continue
    while IFS= read -r -d '' source; do
      base="$(basename "$source")"
      [[ "$base" =~ ^[A-Za-z0-9_.-]+\.(cvd|cld|cvd\.sign|cld\.sign)$ ]] || continue
      temporary="$DB_DIR/.${base}.gideon-import-$$"
      if cp -- "$source" "$temporary" 2>>"$LOG_FILE"; then
        chown "$DB_OWNER:$DB_OWNER" "$temporary"
        chmod 0640 "$temporary"
        mv -f -- "$temporary" "$DB_DIR/$base"
        imported=$((imported + 1))
      else
        rm -f -- "$temporary"
      fi
    done < <(find "$source_dir" -maxdepth 1 -type f \
      \( -name '*.cvd' -o -name '*.cld' -o -name '*.cvd.sign' -o -name '*.cld.sign' \) \
      -size +0c -print0 2>/dev/null)
  done

  if [[ "$imported" -gt 0 ]]; then
    log "CLAMAV_SYSTEM_DB_IMPORT=PASS files=$imported"
  else
    log "CLAMAV_SYSTEM_DB_IMPORT=NONE"
  fi
}

write_private_config() {
  cat >"$CONFIG_FILE" <<EOF
DatabaseDirectory $DB_DIR
DatabaseOwner $DB_OWNER
DatabaseMirror database.clamav.net
Checks 1
ConnectTimeout 30
ReceiveTimeout 120
TestDatabases yes
EOF
  chown "root:$DB_OWNER" "$CONFIG_FILE"
  chmod 0640 "$CONFIG_FILE"
}

refresh_private_database() {
  command -v freshclam >/dev/null 2>&1 || {
    log "CLAMAV_FRESHCLAM=UNAVAILABLE"
    return 1
  }
  write_private_config
  log "CLAMAV_FRESHCLAM=START"
  local rc=0
  if runuser -u "$DB_OWNER" -- freshclam --config-file="$CONFIG_FILE" --stdout >>"$LOG_FILE" 2>&1; then
    normalize_permissions
    log "CLAMAV_FRESHCLAM=PASS"
    return 0
  else
    rc=$?
  fi
  normalize_permissions
  log "CLAMAV_FRESHCLAM=WARN rc=$rc"
  return "$rc"
}

if [[ "$MODE" == --refresh ]]; then
  import_system_database
  refresh_private_database || true
  if database_ready; then
    normalize_permissions
    log "CLAMAV_PRIVATE_DB=PASS mode=refresh"
    exit 0
  fi
  log "CLAMAV_PRIVATE_DB=FAIL mode=refresh reason=main-or-daily-missing"
  exit 4
fi

if database_ready; then
  normalize_permissions
  log "CLAMAV_PRIVATE_DB=PASS source=existing"
  exit 0
fi

for attempt in 1 2 3; do
  log "CLAMAV_PRIVATE_DB_PREPARE attempt=$attempt"
  import_system_database
  if database_ready; then
    normalize_permissions
    log "CLAMAV_PRIVATE_DB=PASS source=system attempt=$attempt"
    exit 0
  fi

  refresh_private_database || true
  if database_ready; then
    normalize_permissions
    log "CLAMAV_PRIVATE_DB=PASS source=freshclam attempt=$attempt"
    exit 0
  fi

  [[ "$attempt" -eq 3 ]] || sleep $((attempt * 5))
done

log "CLAMAV_PRIVATE_DB=FAIL reason=main-or-daily-missing"
echo "ERROR: ClamAV no tiene firmas privadas GIDEON utilizables. Revise $LOG_FILE y la salida HTTPS/DNS hacia database.clamav.net." >&2
exit 4
