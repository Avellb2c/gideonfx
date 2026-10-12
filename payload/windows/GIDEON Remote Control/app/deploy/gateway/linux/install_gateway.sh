#!/usr/bin/env bash
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then echo "Use sudo/root"; exit 1; fi
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
APP=/opt/gideon-agent-gateway
CFG=/etc/gideon-agent-gateway
DATA=/var/lib/gideon-agent-gateway

id gideongateway >/dev/null 2>&1 || useradd --system --home "$DATA" --shell /usr/sbin/nologin gideongateway
install -d -m 0755 -o root -g root "$APP"
install -d -m 0750 -o root -g gideongateway "$CFG" "$CFG/pki"
install -d -m 0750 -o gideongateway -g gideongateway "$DATA"

# Runtime Gateway root-owned. The service account may read but cannot modify code.
install -m 0644 "$ROOT/gideon_agent_gateway.py" "$APP/gideon_agent_gateway.py"
install -m 0644 "$ROOT/gideon_version.py" "$APP/gideon_version.py"
install -m 0644 "$ROOT/gideon_gateway_bootstrap.py" "$APP/gideon_gateway_bootstrap.py"

if [ ! -f "$CFG/gateway.json" ]; then
  install -m 0640 -o root -g gideongateway "$ROOT/deploy/gateway/gateway-config.template.json" "$CFG/gateway.json"
fi

python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install --upgrade pip >/dev/null
chown -R root:root "$APP"
chmod -R go-w "$APP"

install -m 0644 "$ROOT/deploy/gateway/linux/gideon-agent-gateway.service" /etc/systemd/system/gideon-agent-gateway.service
if [ ! -f "$CFG/gateway.env" ]; then
  ADMIN_TOKEN="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
)"
  ENROLL_SECRET="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
)"
  umask 077
  cat >"$CFG/gateway.env" <<ENV
GIDEON_AGENT_ADMIN_TOKEN=$ADMIN_TOKEN
GIDEON_AGENT_ENROLL_SECRET=$ENROLL_SECRET
ENV
  chown root:gideongateway "$CFG/gateway.env"
  chmod 0640 "$CFG/gateway.env"
fi
systemctl daemon-reload
systemctl enable gideon-agent-gateway.service

echo "GIDEON Agent Gateway instalado."
echo "Edite $CFG/gateway.json y coloque certificados en $CFG/pki/."
echo "Luego: systemctl restart gideon-agent-gateway"
echo "AWS: no publique 8443 directamente salvo mediante NLB/TLS pass-through o una política equivalente."
