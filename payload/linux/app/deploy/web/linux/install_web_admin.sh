#!/usr/bin/env bash
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then echo "Use sudo/root"; exit 1; fi
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
APP=/opt/gideon-remote-control
CFG=/etc/gideon-web-admin
DATA=/var/lib/gideon-web-admin

id gideonweb >/dev/null 2>&1 || useradd --system --home "$DATA" --shell /usr/sbin/nologin gideonweb
install -d -m 0755 -o root -g root "$APP"
install -d -m 0750 -o root -g gideonweb "$CFG" "$CFG/yara"
install -d -m 0750 -o gideonweb -g gideonweb "$DATA"
install -m 0640 -o root -g gideonweb "$ROOT/deploy/web/security/gideon-policy.yar" "$CFG/yara/gideon-policy.yar"

# Application code is root-owned/read-only to the Web service.
rsync -a --delete \
  --exclude '.git' --exclude '__pycache__' --exclude '*.pyc' --exclude 'gateway-data' --exclude 'web-data' \
  "$ROOT/" "$APP/"
chown -R root:root "$APP"
chmod -R go-w "$APP"

python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install --upgrade pip wheel
"$APP/venv/bin/pip" install -r "$APP/requirements-web.txt"
chown -R root:root "$APP/venv"
chmod -R go-w "$APP/venv"

if [ ! -f "$CFG/web_admin.json" ]; then
  cp "$ROOT/config/web_admin.json" "$CFG/web_admin.json"
fi
chown root:gideonweb "$CFG/web_admin.json"
chmod 0640 "$CFG/web_admin.json"

if [ ! -f "$CFG/web.env" ]; then
  umask 077
  ADMIN_TOKEN="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
)"
  BOOTSTRAP_TOKEN="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)"
  cat >"$CFG/web.env" <<ENV
# Debe coincidir con GIDEON_AGENT_ADMIN_TOKEN del Gateway.
GIDEON_AGENT_ADMIN_TOKEN=$ADMIN_TOKEN
GIDEON_WEB_BOOTSTRAP_TOKEN=$BOOTSTRAP_TOKEN
ENV
  chown root:gideonweb "$CFG/web.env"
  chmod 0640 "$CFG/web.env"
  echo "IMPORTANTE: sincronice GIDEON_AGENT_ADMIN_TOKEN con /etc/gideon-agent-gateway/gateway.env"
  echo "Bootstrap token inicial: $BOOTSTRAP_TOKEN"
else
  echo "Conservando $CFG/web.env existente."
fi

install -m 0644 "$ROOT/deploy/web/linux/gideon-web-admin.service" /etc/systemd/system/gideon-web-admin.service
systemctl daemon-reload
systemctl enable gideon-web-admin.service

echo "GIDEON Web Admin instalado."
echo "1) Revise $CFG/web_admin.json"
echo "2) Sincronice el GIDEON_AGENT_ADMIN_TOKEN con el Gateway"
echo "3) systemctl restart gideon-web-admin"
echo "4) Publique SOLO HTTPS/443 mediante Nginx/ALB hacia 127.0.0.1:8080"
echo "5) Cree el primer SuperAdmin en /bootstrap o con:"
echo "   sudo -u gideonweb /opt/gideon-remote-control/venv/bin/python /opt/gideon-remote-control/gideon_web_admin.py --config $CFG/web_admin.json --init-admin"
