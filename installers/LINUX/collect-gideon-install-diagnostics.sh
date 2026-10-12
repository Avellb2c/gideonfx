#!/usr/bin/env bash
set +e

OUTROOT="${1:-/var/lib/gideon-remote-control/diagnostics}"
STAGE="${2:-UNKNOWN}"
ERR="${3:-}"
STAMP="$(date +%Y%m%d-%H%M%S)"
DIR="$OUTROOT/install-$STAMP"

mkdir -p "$DIR"
chmod 0700 "$DIR"
if [[ -f /etc/gideon/external-access.json ]]; then
  cp /etc/gideon/external-access.json "$DIR/external-access.json"
fi

printf 'stage=%s\nerror=%s\ntime=%s\n' \
  "$STAGE" "$ERR" "$(date -Is)" > "$DIR/failure.txt"

cat /etc/os-release > "$DIR/os-release.txt" 2>&1
uname -a > "$DIR/uname.txt" 2>&1
ip addr > "$DIR/ip-addr.txt" 2>&1
ip route > "$DIR/ip-route.txt" 2>&1
ss -lntup > "$DIR/ports.txt" 2>&1
systemctl list-units --all 'gideon*' > "$DIR/gideon-units.txt" 2>&1
journalctl --since '-6 hours' -u 'gideon*' --no-pager > "$DIR/gideon-journal.txt" 2>&1
docker info > "$DIR/docker-info.txt" 2>&1
docker ps -a > "$DIR/docker-ps.txt" 2>&1

for report in clamav-prepare.txt clamav-install.txt yara-install.txt; do
  if [[ -f "$OUTROOT/$report" ]]; then
    cp "$OUTROOT/$report" "$DIR/$report"
  fi
done
if [[ -f /var/log/gideon/updater/clamav-update.log ]]; then
  tail -n 250 /var/log/gideon/updater/clamav-update.log > "$DIR/clamav-update-tail.txt" 2>&1
fi
if [[ -d /var/lib/gideon/security/clamav ]]; then
  find /var/lib/gideon/security/clamav -maxdepth 1 -type f \
    -printf '%f\t%s bytes\t%M\t%u:%g\n' > "$DIR/clamav-database-inventory.txt" 2>&1
fi
if command -v clamdscan >/dev/null 2>&1 && [[ -f /etc/gideon/security/clamd.conf ]]; then
  clamdscan --config-file=/etc/gideon/security/clamd.conf --ping 3:1 > "$DIR/clamd-ping.txt" 2>&1
  stat -c '%A %U:%G %s %n' /run/gideon-clamd/clamd.sock /etc/gideon/security/clamd.conf \
    > "$DIR/clamd-private-socket.txt" 2>&1
  systemctl show gideon-clamd.service -p ActiveState -p SubState -p MemoryCurrent -p MemoryMax \
    -p RestrictAddressFamilies > "$DIR/clamd-runtime.txt" 2>&1
fi

if command -v nft >/dev/null 2>&1; then
  nft list ruleset > "$DIR/nft.txt" 2>&1
fi

if command -v firewall-cmd >/dev/null 2>&1; then
  firewall-cmd --list-all > "$DIR/firewalld.txt" 2>&1
fi

if command -v ufw >/dev/null 2>&1; then
  ufw status verbose > "$DIR/ufw.txt" 2>&1
fi

if command -v aa-status >/dev/null 2>&1; then
  aa-status > "$DIR/apparmor.txt" 2>&1
fi

if command -v getenforce >/dev/null 2>&1; then
  getenforce > "$DIR/selinux.txt" 2>&1
fi

tar -C "$OUTROOT" -czf \
  "$OUTROOT/GIDEON-INSTALL-DIAGNOSTICS-$STAMP.tar.gz" \
  "install-$STAMP"

echo "DIAGNOSTICS=$OUTROOT/GIDEON-INSTALL-DIAGNOSTICS-$STAMP.tar.gz"
