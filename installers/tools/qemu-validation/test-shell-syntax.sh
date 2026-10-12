#!/bin/bash
set -Eeuo pipefail

ROOT=${1:-/bundle}
COUNT=0

while IFS= read -r -d '' FILE; do
  bash -n "$FILE"
  COUNT=$((COUNT + 1))
done < <(find "$ROOT" -type f -name '*.sh' -print0)

bash -n "$ROOT/installers/WINDOWS/templates/start-guacd.sh.tpl"

printf 'SHELL_SYNTAX_FILES=%s\n' "$COUNT"
printf 'SHELL_SYNTAX_ERRORS=0\n'
printf 'HYPERV_LAUNCHER_TEMPLATE=PASS\n'
