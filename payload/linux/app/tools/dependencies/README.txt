GIDEON Remote Control - Entorno y dependencias

Los scripts son deliberadamente explícitos: WebAdmin no ejecuta gestores de paquetes como LocalService/root.

Windows (PowerShell como Administrador):
  Install-GIDEONDependencies-Windows.ps1 -RepairPython
  Install-GIDEONDependencies-Windows.ps1 -InstallOpenSSHClient
  Install-GIDEONDependencies-Windows.ps1 -InstallWSL2
  Install-GIDEONDependencies-Windows.ps1 -InstallDockerDesktop
  Install-GIDEONDependencies-Windows.ps1 -All

Linux (sudo/root):
  ./install-gideon-dependencies-linux.sh
  ./install-gideon-dependencies-linux.sh --install-docker
  ./install-gideon-dependencies-linux.sh --agent --install-agent-remote
  ./install-gideon-dependencies-linux.sh --all

El rol predeterminado (control-plane/WebAdmin) instala `ffprobe` mediante el
paquete `ffmpeg` del repositorio firmado ya configurado. Se usa sólo para
validar medios de campañas; no instala VLC, reproductores ni binarios externos.
El modo `--agent` no instala esta capacidad.

Windows Server: Docker Desktop no se instala por política GIDEON. Use Docker Engine en Linux/WSL2/VM o un host Linux controlado para guacd.

macOS:
  sudo ./install-gideon-dependencies-macos.sh --install-xcode-tools
  sudo ./install-gideon-dependencies-macos.sh --install-docker
