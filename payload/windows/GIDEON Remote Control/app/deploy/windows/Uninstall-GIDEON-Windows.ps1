#requires -Version 5.1
[CmdletBinding()]
param([switch]$PurgeData)
$ErrorActionPreference='Stop'
$id=[Security.Principal.WindowsIdentity]::GetCurrent()
$p=New-Object Security.Principal.WindowsPrincipal($id)
if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Ejecute como Administrador.'}
$key='HKLM:\SOFTWARE\GIDEON\RemoteControl'
$install='C:\Program Files\GIDEON Remote Control'; $data='C:\ProgramData\GIDEON Remote Control'; $app=Join-Path $install 'app'
try{$install=(Get-ItemProperty $key).InstallRoot;$data=(Get-ItemProperty $key).DataRoot;$app=(Get-ItemProperty $key).AppRoot}catch{}
$python=Join-Path $install 'venv\Scripts\python.exe'
$host=Join-Path $app 'deploy\windows\gideon_windows_service.py'
if((Test-Path $python) -and (Test-Path $host)){& $python $host remove-all | Out-Null}
foreach($name in @('GIDEONRemoteControlDiagnostics','GIDEONRemoteControlUpdater','GIDEONRemoteControlBackup','GIDEONRemoteControlWebAdmin','GIDEONRemoteControlGateway','GIDEONRemoteControl')){
  sc.exe stop $name | Out-Null
  sc.exe delete $name | Out-Null
}
foreach($rule in @('GIDEON Remote Control - Web Admin','GIDEON Remote Control - Agent Gateway')){Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue|Remove-NetFirewallRule -ErrorAction SilentlyContinue}
Remove-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\GIDEONRemoteControl' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $key -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\GIDEON Remote Control') -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $install -Recurse -Force -ErrorAction SilentlyContinue
if($PurgeData){Remove-Item $data -Recurse -Force -ErrorAction SilentlyContinue; Write-Host 'Código y datos GIDEON eliminados.' -ForegroundColor Yellow}else{Write-Host "Código eliminado. Datos/configuración/PKI/backups preservados en: $data" -ForegroundColor Green}
