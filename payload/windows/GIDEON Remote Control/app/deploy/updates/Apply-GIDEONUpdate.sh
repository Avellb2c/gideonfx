#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-$(cd "$(dirname "$0")" && pwd)}"
if [ "$(id -u)" -ne 0 ]; then
  echo "Use sudo: sudo ./Apply-GIDEONUpdate.sh" >&2
  exit 1
fi
[ -f /opt/gideon/updater/gideon_product_update.py ] || { echo "GIDEON Remote Control 6.3.0+ no está instalado." >&2; exit 2; }
[ -f "$ROOT/manifest.json" ] || { echo "Falta manifest.json en $ROOT" >&2; exit 3; }
/opt/gideon/web/venv/bin/python - "$ROOT/manifest.json" /opt/gideon/web/app <<'PY'
import hashlib, json, pathlib, sys
package = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8-sig"))
app = pathlib.Path(sys.argv[2]).resolve()
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
required = package.get("from_release_manifest_sha256") or []
if isinstance(required, str): required = [required]
if required:
    installed = app / "RELEASE-MANIFEST.json"
    if not installed.is_file(): raise SystemExit("BASELINE_ATTESTATION_MISSING: no existe RELEASE-MANIFEST.json instalado.")
    actual = sha(installed); allowed = [str(x).strip().lower() for x in required]
    if actual not in allowed: raise SystemExit(f"BASELINE_MISMATCH: manifest instalado {actual} no coincide con {allowed}")
    print(f"Baseline release GIDEON verificado: {actual}")
required_i = package.get("from_install_integrity_manifest_sha256") or []
if isinstance(required_i, str): required_i = [required_i]
if required_i:
    installed_i = app / "INSTALL-INTEGRITY-MANIFEST.json"
    if not installed_i.is_file(): raise SystemExit("INTEGRITY_BASELINE_MISSING: no existe INSTALL-INTEGRITY-MANIFEST.json instalado.")
    actual_i = sha(installed_i); allowed_i = [str(x).strip().lower() for x in required_i]
    if actual_i not in allowed_i: raise SystemExit(f"INTEGRITY_BASELINE_MISMATCH: manifest instalado {actual_i} no coincide con {allowed_i}")
    payload = json.loads(installed_i.read_text(encoding="utf-8-sig")); verified = 0
    for row in payload.get("files") or []:
        rel = pathlib.PurePosixPath(str(row.get("path") or ""))
        if rel.is_absolute() or not rel.parts or any(x in {"", ".", ".."} for x in rel.parts): raise SystemExit(f"INTEGRITY_BASELINE_INVALID: ruta insegura {rel}")
        target = app.joinpath(*rel.parts)
        if not target.is_file(): raise SystemExit(f"INTEGRITY_BASELINE_MISMATCH: falta {rel}")
        if target.stat().st_size != int(row.get("size_bytes") or -1): raise SystemExit(f"INTEGRITY_BASELINE_MISMATCH: tamaño distinto {rel}")
        if sha(target) != str(row.get("sha256") or "").lower(): raise SystemExit(f"INTEGRITY_BASELINE_MISMATCH: SHA-256 distinto {rel}")
        verified += 1
    print(f"Baseline inmutable GIDEON verificado: {actual_i} ({verified} archivos)")
PY
exec /opt/gideon/web/venv/bin/python /opt/gideon/updater/gideon_product_update.py \
  --package-dir "$ROOT" --platform linux --state-root /var/lib/gideon/updates
