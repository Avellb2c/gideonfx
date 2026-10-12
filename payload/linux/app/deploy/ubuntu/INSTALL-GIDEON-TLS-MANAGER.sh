#!/usr/bin/env bash
set -Eeuo pipefail
[[ "$EUID" -eq 0 ]] || exec sudo -- bash "$0" "$@"
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
APP=/opt/gideon/web/app
PY=/opt/gideon/web/venv/bin/python
[[ ! -f /var/lib/gideon/tls-manager/active.json ]] || { echo '[FAIL] Hay un cambio TLS pendiente. Confírmelo o espere su restauración.' >&2; exit 1; }
[[ -x "$PY" && -f "$APP/gideon_web_admin/tls_management.py" && -f "$APP/deploy/ubuntu/gideon_tls_manager_entry.py" ]] || {
  echo '[FAIL] Actualice primero el código instalado con el OneClick original; este script solo registra sus servicios TLS.' >&2; exit 1;
}
id gideonweb >/dev/null
install -d -m 0700 -o root -g root /var/lib/gideon/tls-manager /var/lib/gideon/backups/external-access
install -d -m 0755 -o root -g root /etc/letsencrypt /var/lib/letsencrypt /var/log/letsencrypt
for unit in gideon-tls-manager.socket gideon-tls-manager@.service gideon-tls-apply@.service gideon-tls-rollback.service gideon-tls-rollback.timer gideon-tls-recovery.service gideon-tls-cleanup.timer; do
  install -m 0644 -o root -g root "$ROOT/systemd/$unit" "/etc/systemd/system/$unit"
done
for unit in gideon-tls-manager@.service gideon-tls-apply@.service gideon-tls-rollback.service gideon-tls-recovery.service; do
  install -d -m 0755 -o root -g root "/etc/systemd/system/$unit.d"
  install -m 0644 -o root -g root "$ROOT/systemd/tls-hardening.conf" "/etc/systemd/system/$unit.d/20-tls-hardening.conf"
done
"$PY" - "$APP" <<'PY'
import grp, sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1])/'deploy/ubuntu'))
import gideon_external_access as tls
config=tls.read_json(tls.WEB)
config['tls_manager_enabled']=True
tls.atomic_write(tls.WEB, tls.json_bytes(config), 0o640, grp.getgrnam('gideonweb').gr_gid)
PY
systemctl daemon-reload
systemctl enable --now gideon-tls-manager.socket
systemctl enable gideon-tls-recovery.service
echo 'TLS_WEB_MANAGER=INSTALLED; reinicie WebAdmin para cargar la nueva pantalla si ya estaba activo.'
