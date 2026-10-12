#!/usr/bin/env bash
set -Eeuo pipefail
ROLE="control-plane"
INSTALL_DOCKER=0
INSTALL_AGENT_REMOTE=0
UPGRADE=0
for arg in "$@"; do
  case "$arg" in
    --install-docker) INSTALL_DOCKER=1 ;;
    --agent) ROLE="agent" ;;
    --install-agent-remote) INSTALL_AGENT_REMOTE=1 ;;
    --upgrade) UPGRADE=1 ;;
    --all) INSTALL_DOCKER=1; INSTALL_AGENT_REMOTE=1 ;;
    -h|--help) echo "Uso: $0 [--install-docker] [--agent] [--install-agent-remote] [--upgrade] [--all]"; exit 0 ;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo 'Ejecute como root/sudo.' >&2; exit 2; }
LOGDIR=/var/log/gideon-remote-control
mkdir -p "$LOGDIR"
LOG="$LOGDIR/dependencies-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG") 2>&1
step(){ printf '\n[GIDEON] %s\n' "$*"; }
have(){ command -v "$1" >/dev/null 2>&1; }
OS_ID="unknown"; OS_LIKE=""
if [ -r /etc/os-release ]; then . /etc/os-release; OS_ID="${ID:-unknown}"; OS_LIKE="${ID_LIKE:-}"; fi
PM=""
have apt-get && PM=apt
[ -z "$PM" ] && have dnf && PM=dnf
[ -z "$PM" ] && have yum && PM=yum
[ -z "$PM" ] && have zypper && PM=zypper
[ -z "$PM" ] && have pacman && PM=pacman
[ -n "$PM" ] || { echo "No se reconoce gestor apt/dnf/yum/zypper/pacman para $OS_ID ($OS_LIKE)." >&2; exit 3; }
step "Distro=$OS_ID ID_LIKE=$OS_LIKE gestor=$PM rol=$ROLE"

install_pkgs(){
  case "$PM" in
    apt) export DEBIAN_FRONTEND=noninteractive; apt-get update; apt-get install -y "$@" ;;
    dnf) dnf install -y "$@" ;;
    yum) yum install -y "$@" ;;
    zypper) zypper --non-interactive install -y "$@" ;;
    pacman) pacman -Sy --noconfirm --needed "$@" ;;
  esac
}
upgrade_pkgs(){
  case "$PM" in
    apt) apt-get update; DEBIAN_FRONTEND=noninteractive apt-get upgrade -y ;;
    dnf) dnf upgrade -y ;;
    yum) yum update -y ;;
    zypper) zypper --non-interactive update ;;
    pacman) pacman -Syu --noconfirm ;;
  esac
}
[ "$UPGRADE" -eq 1 ] && { step 'Actualizando paquetes del sistema por solicitud explícita'; upgrade_pkgs; }

step 'Instalando utilidades base GIDEON'
case "$PM" in
  apt) install_pkgs ca-certificates curl openssl openssh-client iproute2 procps tar gzip unzip file binutils ;;
  dnf|yum) install_pkgs ca-certificates curl openssl openssh-clients iproute procps-ng tar gzip unzip file binutils ;;
  zypper) install_pkgs ca-certificates curl openssl openssh iproute2 procps tar gzip unzip file binutils ;;
  pacman) install_pkgs ca-certificates curl openssl openssh iproute2 procps-ng tar gzip unzip file binutils ;;
esac

if [ "$ROLE" = control-plane ]; then
  step 'Validando toolchains DEB/RPM'
  case "$PM" in
    apt) install_pkgs dpkg-dev rpm || true ;;
    dnf|yum) install_pkgs rpm-build || true ;;
    zypper) install_pkgs rpm-build || true ;;
    pacman) install_pkgs rpm-tools || true ;;
  esac

  # Campaign media validation runs only in the WebAdmin/control-plane worker.
  # ``ffprobe`` is provided by the distribution's signed ffmpeg package; do
  # not add PPAs, third-party media repositories, standalone binaries or VLC.
  if ! have ffprobe; then
    step 'Instalando validador de medios de campañas (ffprobe)'
    case "$PM" in
      apt) install_pkgs ffmpeg ;;
      dnf|yum) install_pkgs ffmpeg ;;
      zypper) install_pkgs ffmpeg ;;
      pacman) install_pkgs ffmpeg ;;
    esac
  fi
  have ffprobe || { echo 'ffprobe no quedó disponible. Instale el paquete ffmpeg desde el repositorio firmado/corporativo configurado; GIDEON no descarga binarios multimedia externos.' >&2; exit 14; }
  ffprobe -version >/dev/null 2>&1 || { echo 'ffprobe existe pero no es ejecutable.' >&2; exit 14; }
  printf 'MEDIA_VALIDATION=PASS ffprobe=%s\n' "$(command -v ffprobe)"
fi

if [ "$INSTALL_DOCKER" -eq 1 ]; then
  step 'Instalando Docker Engine/CLI + Compose v2 desde repositorios configurados'
  case "$PM" in
    apt)
      if apt-cache show docker.io >/dev/null 2>&1; then install_pkgs docker.io; else echo 'No existe docker.io en repositorios configurados.' >&2; exit 10; fi
      if apt-cache show docker-compose-v2 >/dev/null 2>&1; then install_pkgs docker-compose-v2
      elif apt-cache show docker-compose-plugin >/dev/null 2>&1; then install_pkgs docker-compose-plugin
      elif apt-cache show docker-compose >/dev/null 2>&1; then install_pkgs docker-compose
      fi
      ;;
    dnf|yum)
      if $PM list --available moby-engine >/dev/null 2>&1; then install_pkgs moby-engine
      elif $PM list --available docker-ce >/dev/null 2>&1; then install_pkgs docker-ce docker-ce-cli
      elif $PM list --available docker >/dev/null 2>&1; then install_pkgs docker
      else echo 'No hay paquete Docker Engine en los repositorios configurados. Configure un repositorio corporativo/aprobado de Docker y reintente.' >&2; exit 11; fi
      $PM list --available docker-compose-plugin >/dev/null 2>&1 && install_pkgs docker-compose-plugin || true
      ;;
    zypper)
      install_pkgs docker
      zypper --non-interactive install docker-compose-switch docker-compose-plugin 2>/dev/null || true
      ;;
    pacman)
      install_pkgs docker docker-compose
      ;;
  esac
  have systemctl && { systemctl enable --now docker || true; }
  have docker || { echo 'docker CLI no quedó instalado.' >&2; exit 12; }
  docker --version
  if ! docker compose version; then
    echo 'Docker Engine existe pero Compose v2 no está disponible. Instale el plugin v2 desde el repositorio corporativo/aprobado.' >&2
    exit 13
  fi
fi

if [ "$INSTALL_AGENT_REMOTE" -eq 1 ]; then
  step 'Instalando capacidad de escritorio remoto Linux/Raspberry'
  case "$PM" in
    apt) install_pkgs xrdp xorgxrdp || install_pkgs xrdp ;;
    dnf|yum) install_pkgs xrdp || true ;;
    zypper) install_pkgs xrdp || true ;;
    pacman) echo 'xrdp puede requerir repositorio AUR/corporativo en Arch; no se ejecutan scripts AUR automáticamente.' ;;
  esac
  have systemctl && have xrdp && systemctl enable --now xrdp || true
fi

step 'Validación final'
for c in curl openssl ssh ip ss tar gzip; do if have "$c"; then printf 'OK %-16s %s\n' "$c" "$(command -v "$c")"; else printf 'MISSING %s\n' "$c"; fi; done
if have docker; then docker --version; docker compose version || true; fi
printf '\nFINAL STATUS: GIDEON_LINUX_DEPENDENCY_REMEDIATION_COMPLETED\nLog: %s\n' "$LOG"
