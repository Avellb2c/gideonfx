param(
  [string]$InstallRoot = "$env:ProgramData\GIDEONAgentGateway",
  [string]$PythonExe = "py.exe"
)
$ErrorActionPreference='Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Ejecute como Administrador.' }
New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
Copy-Item "$PSScriptRoot\..\..\..\gideon_agent_gateway.py" "$InstallRoot\gideon_agent_gateway.py" -Force
Copy-Item "$PSScriptRoot\..\gateway-config.template.json" "$InstallRoot\gateway.json" -Force
$bootstrap=(Get-Command $PythonExe -ErrorAction Stop).Source
$venv=Join-Path $InstallRoot 'venv'
& $bootstrap -m venv $venv
$python=Join-Path $venv 'Scripts\python.exe'
$cfgPath=Join-Path $InstallRoot 'gateway.json'
$cfg=Get-Content -LiteralPath $cfgPath -Raw | ConvertFrom-Json
$cfg.data_dir=(Join-Path $InstallRoot 'data')
$cfg.listen_host='127.0.0.1'
$jsonText = $cfg | ConvertTo-Json -Depth 20
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($cfgPath, $jsonText, $utf8NoBom)
New-Item -ItemType Directory -Path $cfg.data_dir -Force | Out-Null
$task='GIDEONAgentGateway'
$action=New-ScheduledTaskAction -Execute $python -Argument ('"{0}" --config "{1}"' -f "$InstallRoot\gideon_agent_gateway.py",$cfgPath) -WorkingDirectory $InstallRoot
$trigger=New-ScheduledTaskTrigger -AtStartup
$system=(New-Object Security.Principal.SecurityIdentifier('S-1-5-18')).Translate([Security.Principal.NTAccount]).Value
$principal=New-ScheduledTaskPrincipal -UserId $system -LogonType ServiceAccount -RunLevel Highest
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 10 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $task
Write-Host "Configure GIDEON_AGENT_ADMIN_TOKEN y GIDEON_AGENT_ENROLL_SECRET como variables de entorno del sistema antes de iniciar."
Write-Host "En AWS publique HTTPS/443 mediante ALB/IIS reverse proxy o TLS directo."
