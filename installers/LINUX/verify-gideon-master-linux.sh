#!/usr/bin/env bash
set -u

FAIL=0

ok() {
  echo "$1=PASS ${2:-}"
}

bad() {
  echo "$1=FAIL ${2:-}"
  FAIL=$((FAIL + 1))
}

[[ -d /opt/gideon-remote-control ]] && ok APP_ROOT || bad APP_ROOT
[[ -d /var/lib/gideon-remote-control ]] && ok DATA_ROOT || bad DATA_ROOT

PY=""
for candidate in \
  /opt/gideon/web/venv/bin/python \
  /opt/gideon-remote-control/venv/bin/python \
  /opt/gideon-remote-control/app/venv/bin/python \
  /usr/bin/python3
do
  if [[ -x "$candidate" ]]; then
    PY="$candidate"
    break
  fi
done
[[ -n "$PY" ]] && ok PYTHON "$PY" || bad PYTHON

if [[ -x /opt/gideon/web/venv/bin/python && -f /etc/gideon/web/web_admin.json ]]; then
  if /opt/gideon/web/venv/bin/python \
      /opt/gideon/web/app/deploy/ubuntu/gideon_external_access.py --verify-current; then
    ok GIDEON_TLS_LOCAL
  else
    bad GIDEON_TLS_LOCAL
  fi
fi
if [[ ! -f /etc/gideon/external-access.json ]]; then
  echo 'EXTERNAL_ACCESS=PENDING; complete el asistente de certificados y DNS/firewall.'
else
  python3 - <<'PY'
import json
state=json.load(open('/etc/gideon/external-access.json'))
print('EXTERNAL_ACCESS='+state.get('status','PENDING')+'; requiere prueba desde otra red.')
PY
fi

if command -v docker >/dev/null 2>&1; then
  if docker ps --format '{{.Names}}' | grep -qx gideon-guacd; then
    ok GUACD_CONTAINER
  else
    bad GUACD_CONTAINER
  fi
else
  bad DOCKER
fi

PORT="${GIDEON_GUACD_HOST_PORT:-4822}"
if command -v ss >/dev/null 2>&1 \
  && ss -lnt | awk '{print $4}' | grep -Eq "127\.0\.0\.1:${PORT}$|\[::1\]:${PORT}$"; then
  ok GUACD_LOOPBACK "port=$PORT"
else
  bad GUACD_LOOPBACK "port=$PORT"
fi

ROOT_UNITS="$(
  systemctl list-unit-files --type=service --no-legend 2>/dev/null \
    | awk '/^gideon.*\.service/{print $1}' || true
)"
for unit in $ROOT_UNITS; do
  # Socket templates and timer-triggered oneshots are intentionally not daemons.
  [[ "$unit" == *@.service ]] && continue
  ENABLED="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
  if [[ "$ENABLED" == enabled || "$ENABLED" == enabled-runtime ]]; then
    if systemctl is-active --quiet "$unit"; then
      ok "SERVICE_${unit}"
    else
      bad "SERVICE_${unit}"
    fi
  fi
done

if [[ -f /etc/systemd/system/gideon-tls-manager.socket ]]; then
  if systemctl is-active --quiet gideon-tls-manager.socket; then
    ok TLS_MANAGEMENT_SOCKET
  else
    bad TLS_MANAGEMENT_SOCKET
  fi
fi

if command -v timedatectl >/dev/null 2>&1; then
  SYNC="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)"
  [[ "$SYNC" == "yes" ]] && ok TIME_SYNC || bad TIME_SYNC "$SYNC"
fi

if [[ "$FAIL" -eq 0 ]]; then
  echo "FINAL_VERIFY=PASS"
  exit 0
fi

echo "FINAL_VERIFY=FAIL failures=$FAIL"
exit 2
