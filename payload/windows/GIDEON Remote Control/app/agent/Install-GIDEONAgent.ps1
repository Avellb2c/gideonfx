#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$SiteCode,
    [Parameter(Mandatory=$true)][string]$SiteName,
    [Parameter(Mandatory=$true)][string]$ControlPlaneUrl,
    [Parameter(Mandatory=$true)][string]$EnrollmentSecret,
    [string]$PythonExe = "",
    [string]$SourceRoot = (Split-Path -Parent $PSScriptRoot),
    [switch]$AllowInsecureHttp
)

$ErrorActionPreference='Stop'
$sourceBundledPython=Join-Path $SourceRoot 'runtime\python\python.exe'
if([string]::IsNullOrWhiteSpace($PythonExe) -and (Test-Path -LiteralPath $sourceBundledPython)){
    $PythonExe=$sourceBundledPython
}
if([string]::IsNullOrWhiteSpace($PythonExe)){
    $bundled=Join-Path $SourceRoot 'runtime\python\python.exe'
    if(Test-Path -LiteralPath $bundled -PathType Leaf){ $PythonExe=$bundled }
    else { throw 'AGENT_INSTALLER_INCOMPLETE: falta runtime\\python\\python.exe. Regenere el instalador desde RC24; no se usará Python global del equipo.' }
}
$root='C:\ProgramData\GIDEONAgent'
New-Item -ItemType Directory -Path $root -Force | Out-Null
$sourceRuntime=Join-Path $SourceRoot 'runtime'
if(-not (Test-Path -LiteralPath $sourceRuntime -PathType Container)){ throw 'AGENT_INSTALLER_INCOMPLETE: falta carpeta runtime.' }
if(Test-Path -LiteralPath $sourceRuntime -PathType Container){
    $runtimeDst=Join-Path $root 'runtime'
    Remove-Item -LiteralPath $runtimeDst -Recurse -Force -ErrorAction SilentlyContinue
    Copy-Item -LiteralPath $sourceRuntime -Destination $runtimeDst -Recurse -Force
    $copiedPython=Join-Path $runtimeDst 'python\python.exe'
    if(Test-Path -LiteralPath $copiedPython){ $PythonExe=$copiedPython }
}
$configPath=Join-Path $root 'agent.json'
$existingConfig=$null
if(Test-Path -LiteralPath $configPath){
    try { $existingConfig=Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 } catch {}
}
Stop-ScheduledTask -TaskName 'GIDEONAgent' -ErrorAction SilentlyContinue

foreach($name in @('gideon_agent.py','gideon_agent_http.py','gideon_agent_security.py','gideon_agent_bootstrap.py','gideon_agent_worker.py','gideon_agent_job_contract.py','gideon_host_profiles.py','gideon_agent_tray.py','gideon_agent_update.py','gideon_agent_connectivity.py','gideon_agent_config.py')) {
    $src=Join-Path $SourceRoot $name
    if(-not (Test-Path -LiteralPath $src)){ throw "Missing $src" }
    Copy-Item -LiteralPath $src -Destination (Join-Path $root $name) -Force
}
$scriptHostSrc=Join-Path $SourceRoot 'gideon_script_host.ps1'
if(-not (Test-Path -LiteralPath $scriptHostSrc)){ throw "Missing $scriptHostSrc" }
Copy-Item -LiteralPath $scriptHostSrc -Destination (Join-Path $root 'gideon_script_host.ps1') -Force
$commonSrc=Join-Path $SourceRoot 'gideon_common'
if(-not (Test-Path -LiteralPath (Join-Path $commonSrc '__init__.py'))){ throw "Missing standalone runtime package $commonSrc" }
$commonDst=Join-Path $root 'gideon_common'
Remove-Item -LiteralPath $commonDst -Recurse -Force -ErrorAction SilentlyContinue
Copy-Item -LiteralPath $commonSrc -Destination $commonDst -Recurse -Force
Remove-Item -LiteralPath (Join-Path $root '__pycache__') -Recurse -Force -ErrorAction SilentlyContinue

$config=[ordered]@{
    site_code=$SiteCode
    site_name=$SiteName
    data_dir=$root
    poll_seconds=5
    status_seconds=5
    cancel_grace_seconds=8
    enrollment_secret=$EnrollmentSecret
    control_plane=[ordered]@{
        base_url=$ControlPlaneUrl.TrimEnd('/')
        require_https=(-not $AllowInsecureHttp)
        verify_tls=$true
        ca_file=$null
        timeout_seconds=20
    }
}
if($existingConfig){
    # Software-only repair/upgrade: never reset identity/token-related config.
    [IO.File]::WriteAllText($configPath,$existingConfig,(New-Object Text.UTF8Encoding($false)))
} else {
    [IO.File]::WriteAllText($configPath,($config|ConvertTo-Json -Depth 8),(New-Object Text.UTF8Encoding($false)))
}
Push-Location $root
try { & $PythonExe -c "import gideon_agent,gideon_agent_http,gideon_agent_security,gideon_agent_worker,gideon_agent_job_contract,gideon_agent_connectivity,gideon_agent_config,gideon_common;print(gideon_agent.VERSION)" } finally { Pop-Location }
if($LASTEXITCODE -ne 0){ throw 'El runtime copiado está incompleto; import smoke-test falló.' }

# ACL independiente del idioma: SYSTEM (S-1-5-18) + Builtin Administrators (S-1-5-32-544).
$systemAccount=(New-Object Security.Principal.SecurityIdentifier('S-1-5-18')).Translate([Security.Principal.NTAccount]).Value
$adminsAccount=(New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([Security.Principal.NTAccount]).Value
& icacls.exe $root /inheritance:r /grant:r ("$systemAccount`:(OI)(CI)F") ("$adminsAccount`:(OI)(CI)F") | Out-Null

$task='GIDEONAgent'
Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
$action=New-ScheduledTaskAction -Execute $PythonExe -Argument ('"{0}" --config "{1}"' -f (Join-Path $root 'gideon_agent.py'),$configPath) -WorkingDirectory $root
$trigger=New-ScheduledTaskTrigger -AtStartup
$principal=New-ScheduledTaskPrincipal -UserId $systemAccount -LogonType ServiceAccount -RunLevel Highest
$settings=New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'GIDEON Agent HTTPS/PULL optional execution method' | Out-Null
Start-ScheduledTask -TaskName $task
Write-Host "GIDEONAgent installed for $SiteCode $SiteName" -ForegroundColor Green
Write-Host "Task: $task | Root: $root"
# Registrar también las instalaciones realizadas por PowerShell en appwiz.cpl.
try {
    $srcUninstall=Join-Path $SourceRoot 'deploy\agent\windows\gideon-agent-uninstall.ps1'
    $dstUninstall=Join-Path $root 'gideon-agent-uninstall.ps1'
    if(Test-Path $srcUninstall){ Copy-Item $srcUninstall $dstUninstall -Force }
    if(Test-Path $dstUninstall){
        $key='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\GIDEONRemoteControlAgent'
        New-Item $key -Force | Out-Null
        $u=('powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -InstallRoot "{1}" -RemoveData -RemoveLegacy' -f $dstUninstall,$root)
        New-ItemProperty $key DisplayName 'Gideon Rx Agent' -PropertyType String -Force | Out-Null
        New-ItemProperty $key DisplayVersion '2.4.0' -PropertyType String -Force | Out-Null
        New-ItemProperty $key Publisher 'Gideon Rx Project' -PropertyType String -Force | Out-Null
        New-ItemProperty $key InstallLocation $root -PropertyType String -Force | Out-Null
        New-ItemProperty $key UninstallString $u -PropertyType String -Force | Out-Null
        New-ItemProperty $key QuietUninstallString ($u+' -Quiet') -PropertyType String -Force | Out-Null
    }
} catch {}
