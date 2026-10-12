#!/bin/sh
set -eu

ARCHIVE="/mnt/gideondata/@@GUACD_ARCHIVE@@"
ARCHIVE_SHA="@@GUACD_ARCHIVE_SHA256@@"
IMAGE_ID="@@GUACD_IMAGE_ID@@"
DOCKER_TGZ="/mnt/gideondata/@@DOCKER_STATIC_ARCHIVE@@"
DOCKER_TGZ_SHA="@@DOCKER_STATIC_SHA256@@"
DOCKER_VERSION="@@DOCKER_STATIC_VERSION@@"
DOCKER_ROOT="/opt/gideon/docker/@@DOCKER_STATIC_VERSION@@"
DOCKER_SOCKET="unix:///run/gideon-docker.sock"

test -f "$ARCHIVE"
echo "$ARCHIVE_SHA  $ARCHIVE" | sha256sum -c -
test -f "$DOCKER_TGZ"
echo "$DOCKER_TGZ_SHA  $DOCKER_TGZ" | sha256sum -c -

DOCKER_INSTALL_OK=1
for binary in dockerd docker containerd runc containerd-shim-runc-v2 docker-init; do
  [ -x "$DOCKER_ROOT/$binary" ] || DOCKER_INSTALL_OK=0
done
if [ "$DOCKER_INSTALL_OK" -eq 1 ]; then
  "$DOCKER_ROOT/docker" --version | grep -F "version $DOCKER_VERSION," >/dev/null || DOCKER_INSTALL_OK=0
fi

if [ "$DOCKER_INSTALL_OK" -ne 1 ]; then
  systemctl stop gideon-docker.service >/dev/null 2>&1 || true
  DOCKER_STAGE="$DOCKER_ROOT.stage"
  DOCKER_PREVIOUS="$DOCKER_ROOT.previous"
  rm -rf "$DOCKER_STAGE" "$DOCKER_PREVIOUS"
  mkdir -p "$DOCKER_STAGE"
  tar -xzf "$DOCKER_TGZ" -C "$DOCKER_STAGE" --strip-components=1
  for binary in dockerd docker containerd runc containerd-shim-runc-v2 docker-init; do
    test -x "$DOCKER_STAGE/$binary"
  done
  if [ -d "$DOCKER_ROOT" ]; then mv "$DOCKER_ROOT" "$DOCKER_PREVIOUS"; fi
  mv "$DOCKER_STAGE" "$DOCKER_ROOT"
  rm -rf "$DOCKER_PREVIOUS"
fi

"$DOCKER_ROOT/docker" --version | grep -F "version $DOCKER_VERSION," >/dev/null

cat > /etc/systemd/system/gideon-docker.service <<EOF
[Unit]
Description=GIDEON private Docker Engine
After=network-online.target local-fs.target
Wants=network-online.target

[Service]
Type=notify
Environment=PATH=$DOCKER_ROOT:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=$DOCKER_ROOT/dockerd --host=$DOCKER_SOCKET --data-root=/var/lib/gideon-docker --exec-root=/run/gideon-docker --pidfile=/run/gideon-docker.pid --bridge=none --iptables=false --ip6tables=false --ip-masq=false --ip-forward=false --userland-proxy=false
ExecReload=/bin/kill -s HUP \$MAINPID
Delegate=yes
KillMode=process
Restart=always
RestartSec=2
TimeoutStartSec=0
LimitNOFILE=infinity
LimitNPROC=infinity
TasksMax=infinity

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable gideon-docker.service
systemctl restart gideon-docker.service

i=0
until "$DOCKER_ROOT/docker" -H "$DOCKER_SOCKET" info >/dev/null 2>&1; do
  i=$((i + 1))
  [ "$i" -lt 60 ] || { systemctl status gideon-docker.service --no-pager; exit 1; }
  sleep 1
done

"$DOCKER_ROOT/docker" -H "$DOCKER_SOCKET" load -i "$ARCHIVE"
"$DOCKER_ROOT/docker" -H "$DOCKER_SOCKET" image inspect "$IMAGE_ID" >/dev/null

"$DOCKER_ROOT/docker" -H "$DOCKER_SOCKET" rm -f gideon-guacd >/dev/null 2>&1 || true

"$DOCKER_ROOT/docker" -H "$DOCKER_SOCKET" run -d \
  --name gideon-guacd \
  --network host \
  --label com.gideon.remote-control=true \
  --restart unless-stopped \
  --init \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  --tmpfs /home/guacd:rw,nosuid,nodev,size=16m,uid=1000,gid=1000,mode=0700 \
  --pids-limit 256 \
  --memory @@GUACD_MEMORY@@ \
  --cpus @@GUACD_CPUS@@ \
  --log-opt max-size=10m \
  --log-opt max-file=3 \
  --health-interval 30s \
  --health-timeout 5s \
  --health-retries 3 \
  --health-start-period 5s \
  "$IMAGE_ID"

echo "GIDEON_GUACD_START=PASS"
