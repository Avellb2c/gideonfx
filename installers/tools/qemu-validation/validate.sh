#!/bin/bash
set -Eeuo pipefail
umask 077

BUNDLE_ROOT=/bundle
REPORT_ROOT=/report
BUILD_REPORT="$BUNDLE_ROOT/metadata/hyperv-appliance-build.json"
LOCK_FILE="$BUNDLE_ROOT/installers/config/dependency-lock.json"
IMAGE_MAP="$BUNDLE_ROOT/offline-cache/containers/images.json"
LAUNCHER_TEMPLATE="$BUNDLE_ROOT/installers/WINDOWS/templates/start-guacd.sh.tpl"
REPORT_FILE="$REPORT_ROOT/hyperv-qemu-prevalidation.json"
WORK_ROOT=$(mktemp -d /var/tmp/gideon-qemu-validation.XXXXXX)
SERIAL_LOG="$WORK_ROOT/serial.log"
QEMU_PID=''
START_EPOCH=$(date +%s)

cleanup() {
  if [ -n "$QEMU_PID" ] && kill -0 "$QEMU_PID" 2>/dev/null; then
    kill "$QEMU_PID" 2>/dev/null || true
    wait "$QEMU_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

for required in "$BUILD_REPORT" "$LOCK_FILE" "$IMAGE_MAP" "$LAUNCHER_TEMPLATE"; do
  test -f "$required"
done
mkdir -p "$REPORT_ROOT"

CANDIDATE_REL=$(jq -er '.candidate.path' "$BUILD_REPORT")
CANDIDATE_SHA=$(jq -er '.candidate.sha256' "$BUILD_REPORT")
CANDIDATE="$BUNDLE_ROOT/$CANDIDATE_REL"

DOCKER_REL=$(jq -er '.artifacts[] | select(.id == "linux-docker-static-amd64") | .destination' "$LOCK_FILE")
DOCKER_SHA=$(jq -er '.artifacts[] | select(.id == "linux-docker-static-amd64") | .sha256' "$LOCK_FILE")
DOCKER_VERSION=$(jq -er '.artifacts[] | select(.id == "linux-docker-static-amd64") | .version' "$LOCK_FILE")
DOCKER_ARCHIVE="$BUNDLE_ROOT/$DOCKER_REL"
DOCKER_NAME=$(basename "$DOCKER_ARCHIVE")

GUACD_ARCHIVE_NAME=$(jq -er '.[] | select(.container == "gideon-guacd") | .archive' "$IMAGE_MAP")
GUACD_ARCHIVE_SHA=$(jq -er '.[] | select(.container == "gideon-guacd") | .archive_sha256' "$IMAGE_MAP")
GUACD_IMAGE_ID=$(jq -er '.[] | select(.container == "gideon-guacd") | .image_id' "$IMAGE_MAP")
GUACD_ARCHIVE="$BUNDLE_ROOT/offline-cache/containers/$GUACD_ARCHIVE_NAME"

echo "$CANDIDATE_SHA  $CANDIDATE" | sha256sum -c -
echo "$DOCKER_SHA  $DOCKER_ARCHIVE" | sha256sum -c -
echo "$GUACD_ARCHIVE_SHA  $GUACD_ARCHIVE" | sha256sum -c -

python3 - "$LAUNCHER_TEMPLATE" "$WORK_ROOT/start-guacd.sh" \
  "$GUACD_ARCHIVE_NAME" "$GUACD_ARCHIVE_SHA" "$GUACD_IMAGE_ID" \
  "$DOCKER_NAME" "$DOCKER_SHA" "$DOCKER_VERSION" <<'PY'
from pathlib import Path
import sys

source, destination, guacd_name, guacd_sha, image_id, docker_name, docker_sha, docker_version = sys.argv[1:]
text = Path(source).read_text(encoding="utf-8-sig")
replacements = {
    "@@GUACD_ARCHIVE@@": guacd_name,
    "@@GUACD_ARCHIVE_SHA256@@": guacd_sha,
    "@@GUACD_IMAGE_ID@@": image_id,
    "@@DOCKER_STATIC_ARCHIVE@@": docker_name,
    "@@DOCKER_STATIC_SHA256@@": docker_sha,
    "@@DOCKER_STATIC_VERSION@@": docker_version,
}
for old, new in replacements.items():
    text = text.replace(old, new)
if "@@" in text:
    raise SystemExit("unresolved launcher template placeholder")
Path(destination).write_text(text, encoding="utf-8", newline="\n")
PY
chmod 0700 "$WORK_ROOT/start-guacd.sh"
bash -n "$WORK_ROOT/start-guacd.sh"

DATA_DISK="$WORK_ROOT/gideondata.raw"
truncate -s 768M "$DATA_DISK"
mkntfs -F -Q -L GIDEONDATA "$DATA_DISK" >/dev/null
ntfscp -f "$DATA_DISK" "$GUACD_ARCHIVE" "/$GUACD_ARCHIVE_NAME"
ntfscp -f "$DATA_DISK" "$DOCKER_ARCHIVE" "/$DOCKER_NAME"
ntfscp -f "$DATA_DISK" "$IMAGE_MAP" /images.json
ntfscp -f "$DATA_DISK" "$WORK_ROOT/start-guacd.sh" /start-guacd.sh

cat > "$WORK_ROOT/user-data" <<'EOF'
#cloud-config
hostname: gideon-guacd-qemu-validation
manage_etc_hosts: true
users: []
disable_root: true
ssh_pwauth: false
package_update: false
package_upgrade: false

runcmd:
  - [ sh, -c, 'mkdir -p /mnt/gideondata /etc/gideon-guacd' ]
  - [ sh, -c, 'systemctl disable --now ssh.service ssh.socket 2>/dev/null || true' ]
  - [ sh, -c, 'systemctl disable --now apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true' ]
  - [ sh, -c, 'mount -t ntfs3 /dev/disk/by-label/GIDEONDATA /mnt/gideondata || mount /dev/disk/by-label/GIDEONDATA /mnt/gideondata' ]
  - [ sh, -c, 'chmod 0700 /mnt/gideondata/start-guacd.sh' ]
  - [ sh, -c, '/mnt/gideondata/start-guacd.sh' ]
EOF

cat > "$WORK_ROOT/meta-data" <<EOF
instance-id: gideon-qemu-$(date +%s)
local-hostname: gideon-guacd-qemu-validation
EOF

SEED_DISK="$WORK_ROOT/cidata.raw"
truncate -s 64M "$SEED_DISK"
mkfs.vfat -n CIDATA "$SEED_DISK" >/dev/null
MTOOLS_SKIP_CHECK=1 mcopy -o -i "$SEED_DISK" "$WORK_ROOT/user-data" ::user-data
MTOOLS_SKIP_CHECK=1 mcopy -o -i "$SEED_DISK" "$WORK_ROOT/meta-data" ::meta-data

OS_OVERLAY="$WORK_ROOT/os.qcow2"
qemu-img create -q -f qcow2 -F vhdx -b "$CANDIDATE" "$OS_OVERLAY"

if [ -f /usr/share/OVMF/OVMF_CODE_4M.fd ]; then
  OVMF_CODE=/usr/share/OVMF/OVMF_CODE_4M.fd
  OVMF_VARS_SOURCE=/usr/share/OVMF/OVMF_VARS_4M.fd
else
  OVMF_CODE=/usr/share/OVMF/OVMF_CODE.fd
  OVMF_VARS_SOURCE=/usr/share/OVMF/OVMF_VARS.fd
fi
OVMF_VARS="$WORK_ROOT/OVMF_VARS.fd"
cp "$OVMF_VARS_SOURCE" "$OVMF_VARS"

echo "QEMU_UEFI_BOOT=START"
qemu-system-x86_64 \
  -machine q35,accel=tcg \
  -cpu max \
  -smp 2 \
  -m 2048 \
  -display none \
  -monitor none \
  -serial "file:$SERIAL_LOG" \
  -drive "if=pflash,format=raw,readonly=on,file=$OVMF_CODE" \
  -drive "if=pflash,format=raw,file=$OVMF_VARS" \
  -drive "id=os,if=none,format=qcow2,file=$OS_OVERLAY" \
  -device virtio-blk-pci,drive=os,bootindex=1 \
  -drive "id=seed,if=none,format=raw,readonly=on,file=$SEED_DISK" \
  -device virtio-blk-pci,drive=seed \
  -drive "id=data,if=none,format=raw,file=$DATA_DISK" \
  -device virtio-blk-pci,drive=data \
  -netdev user,id=net0,hostfwd=tcp:127.0.0.1:14822-:4822 \
  -device virtio-net-pci,netdev=net0 \
  -no-reboot &
QEMU_PID=$!

READY=0
for _ in $(seq 1 180); do
  if nc -z -w 1 127.0.0.1 14822; then
    READY=1
    break
  fi
  if ! kill -0 "$QEMU_PID" 2>/dev/null; then
    break
  fi
  sleep 5
done

END_EPOCH=$(date +%s)
DURATION=$((END_EPOCH - START_EPOCH))
QEMU_VERSION=$(qemu-system-x86_64 --version | head -n 1)

if [ "$READY" -ne 1 ]; then
  jq -n \
    --arg generated_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg appliance_sha256 "$CANDIDATE_SHA" \
    --arg qemu_version "$QEMU_VERSION" \
    --argjson duration_seconds "$DURATION" \
    '{schema_version:1,generated_utc:$generated_utc,result:"FAIL",validation_status:"QEMU_UEFI_PREVALIDATION_FAILED",appliance_sha256:$appliance_sha256,qemu_version:$qemu_version,duration_seconds:$duration_seconds,tests:{uefi_boot:false,cloud_init:false,docker_offline:false,guacd_tcp_4822:false}}' \
    > "$REPORT_FILE"
  tail -n 200 "$SERIAL_LOG" || true
  exit 1
fi

jq -n \
  --arg generated_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg appliance_sha256 "$CANDIDATE_SHA" \
  --arg docker_static_sha256 "$DOCKER_SHA" \
  --arg guacd_archive_sha256 "$GUACD_ARCHIVE_SHA" \
  --arg qemu_version "$QEMU_VERSION" \
  --argjson duration_seconds "$DURATION" \
  '{schema_version:1,generated_utc:$generated_utc,result:"PASS",validation_status:"QEMU_UEFI_PREVALIDATION_PASS_NOT_HYPERV",tested_on_qemu_tcg:true,tested_on_hyperv:false,appliance_sha256:$appliance_sha256,duration_seconds:$duration_seconds,qemu_version:$qemu_version,tests:{uefi_boot:true,cloud_init:true,docker_offline:true,guacd_tcp_4822:true},evidence:{docker_static_sha256:$docker_static_sha256,guacd_archive_sha256:$guacd_archive_sha256,tcp_endpoint:"127.0.0.1:14822"}}' \
  > "$REPORT_FILE"

echo "QEMU_UEFI_PREVALIDATION=PASS duration_seconds=$DURATION"
