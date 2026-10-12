#requires -RunAsAdministrator
[CmdletBinding()]
param(
  [switch]$RepairPython,
  [switch]$InstallDockerDesktop,
  [switch]$InstallWSL2,
  [switch]$InstallOpenSSHClient,
  [switch]$All,
  [switch]$UpgradePythonPackages
)
$ErrorActionPreference='Stop'
$Python='C:\Program Files\GIDEON Remote Control\venv\Scripts\python.exe'
$LogRoot='C:\ProgramData\GIDEON Remote Control\logs\dependencies'
New-Item -ItemType Directory -Path $LogRoot -Force|Out-Null
$Log=Join-Path $LogRoot ("windows-dependencies-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
Start-Transcript -Path $Log -Force|Out-Null
function Step($m){Write-Host "`n[GIDEON] $m" -ForegroundColor Cyan}
function Have($c){[bool](Get-Command $c -ErrorAction SilentlyContinue)}
function IsServer(){try{return ((Get-CimInstance Win32_OperatingSystem).ProductType -ne 1)}catch{return $false}}
try{
  Step 'Inventario previo'
  Write-Host "Windows: $((Get-CimInstance Win32_OperatingSystem).Caption)"
  if(Test-Path $Python){& $Python --version}else{Write-Warning "No existe runtime GIDEON: $Python"}
  if(Have docker){docker --version; try{docker compose version}catch{}}else{Write-Warning 'Docker CLI no está instalado.'}
  if(Have ssh){ssh -V}else{Write-Warning 'OpenSSH Client no está instalado.'}

  if($All){$RepairPython=$true;$InstallOpenSSHClient=$true;$InstallWSL2=$true;if(-not (IsServer)){$InstallDockerDesktop=$true}}

  if($RepairPython){
    Step 'Reparando dependencias Python WebAdmin'
    if(!(Test-Path $Python)){throw "Python GIDEON no existe: $Python"}
    $requirements='C:\Program Files\GIDEON Remote Control\app\requirements-web.txt'
    if(Test-Path $requirements){
      if($UpgradePythonPackages){& $Python -m pip install --upgrade -r $requirements}
      else{& $Python -m pip install -r $requirements}
      if($LASTEXITCODE-ne 0){throw 'pip requirements-web.txt falló'}
    }
    & $Python -m pip install 'bcrypt>=4.2,<6'
    if($LASTEXITCODE-ne 0){throw 'No se pudo instalar bcrypt'}
    & $Python -c "import fastapi,uvicorn,starlette,jinja2,multipart,cryptography,bcrypt,pydantic,anyio,websockets;print('PYTHON_DEPENDENCIES_OK');print('bcrypt',bcrypt.__version__)"
    if($LASTEXITCODE-ne 0){throw 'Smoke test Python falló'}
  }

  if($InstallOpenSSHClient){
    Step 'Validando/instalando OpenSSH Client'
    if(-not (Have ssh)){
      Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0 | Out-Host
    }
    if(-not (Have ssh)){throw 'OpenSSH Client sigue sin estar disponible.'}
    ssh -V
  }

  if($InstallWSL2){
    Step 'Validando/instalando WSL2'
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -All -NoRestart | Out-Host
    Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -All -NoRestart | Out-Host
    if(Have wsl){
      wsl --set-default-version 2
      $distros=@(wsl -l -q 2>$null | ForEach-Object { $_.Replace([char]0,'').Trim() } | Where-Object {$_})
      if($distros.Count -eq 0){wsl --install -d Ubuntu --no-launch; Write-Warning 'WSL/Ubuntu solicitado. Reinicie Windows y abra Ubuntu una vez si se requiere.'}
    }else{
      wsl --install -d Ubuntu --no-launch
      Write-Warning 'WSL solicitado. Reinicio de Windows puede ser necesario.'
    }
  }

  if($InstallDockerDesktop){
    Step 'Validando/instalando Docker Desktop'
    if(IsServer){throw 'Docker Desktop no se instala en Windows Server por política GIDEON. Use Docker Engine en Linux/WSL2/VM o un host Linux.'}
    $desktop="$env:ProgramFiles\Docker\Docker\Docker Desktop.exe"
    if(!(Test-Path $desktop)){
      if(Have winget){
        winget install --id Docker.DockerDesktop -e --accept-source-agreements --accept-package-agreements
        if($LASTEXITCODE-ne 0){throw "winget Docker Desktop falló con $LASTEXITCODE"}
      }else{
        throw 'winget no está disponible. Instale Docker Desktop desde el instalador corporativo/aprobado y vuelva a validar.'
      }
    }
    Write-Host 'Docker Desktop instalado/detectado. Inícielo y acepte/revise la configuración corporativa antes de validar docker info.'
  }

  Step 'Validación final'
  if(Have docker){docker --version; docker compose version}else{Write-Warning 'Docker CLI sigue ausente (puede requerir abrir Docker Desktop/reiniciar sesión).'}
  if(Test-Path $Python){& $Python -c "import cryptography;print('cryptography',cryptography.__version__);import bcrypt;print('bcrypt',bcrypt.__version__)"}
  Write-Host "`nFINAL STATUS: GIDEON_WINDOWS_DEPENDENCY_REMEDIATION_COMPLETED" -ForegroundColor Green
  Write-Host "Log: $Log"
}finally{Stop-Transcript|Out-Null}
