#!/bin/bash
set -euo pipefail
INSTALL_DOCKER=0
INSTALL_XCODE=0
for arg in "$@"; do
  case "$arg" in
    --install-docker) INSTALL_DOCKER=1 ;;
    --install-xcode-tools) INSTALL_XCODE=1 ;;
    --all) INSTALL_DOCKER=1; INSTALL_XCODE=1 ;;
    -h|--help) echo "Uso: $0 [--install-xcode-tools] [--install-docker] [--all]"; exit 0 ;;
  esac
done
[ "$(uname -s)" = Darwin ] || { echo 'Este remediador requiere macOS.' >&2; exit 2; }
step(){ printf '\n[GIDEON] %s\n' "$*"; }
have(){ command -v "$1" >/dev/null 2>&1; }
step 'Inventario macOS'
sw_vers || true
for c in ssh curl openssl pkgbuild xcode-select; do command -v "$c" || true; done
if [ "$INSTALL_XCODE" -eq 1 ] && ! xcode-select -p >/dev/null 2>&1; then
  step 'Solicitando Xcode Command Line Tools'
  xcode-select --install || true
  echo 'Complete la ventana de instalación de Apple y vuelva a ejecutar la validación.'
fi
if [ "$INSTALL_DOCKER" -eq 1 ]; then
  step 'Instalando Docker Desktop para macOS'
  if [ -d '/Applications/Docker.app' ]; then echo 'Docker Desktop ya está instalado.'
  elif have brew; then brew install --cask docker
  else echo 'Homebrew no está disponible. Instale Docker Desktop desde el paquete corporativo/aprobado y revalide.' >&2; exit 3
  fi
fi
step 'Validación final'
have pkgbuild && pkgbuild --version || echo 'pkgbuild MISSING (Xcode Command Line Tools)'
have docker && { docker --version; docker compose version || true; } || echo 'Docker CLI no detectado.'
echo 'FINAL STATUS: GIDEON_MACOS_DEPENDENCY_REMEDIATION_COMPLETED'
