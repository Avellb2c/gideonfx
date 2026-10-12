#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
exec sudo "$ROOT/deploy/aws/install_gideon_aws.sh" "$@"
