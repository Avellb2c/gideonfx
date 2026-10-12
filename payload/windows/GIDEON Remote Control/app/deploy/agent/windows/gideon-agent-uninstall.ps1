#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$InstallRoot = 'C:\Program Files\GIDEONAgent',
    [switch]$RemoveData,
    [switch]$RemoveLegacy = $true,
    [switch]$Quiet
)
$ErrorActionPreference='Continue'

function Write-Gideon([string]$Text){ if(-not $Quiet){ Write-Host $Text } }

# 1) Stop native Windows service and tray registration.
try { & "$env:WINDIR\System32\sc.exe" stop GIDEONAgent 2>$null | Out-Null } catch {}
Start-Sleep -Milliseconds 500
try { & "$env:WINDIR\System32\sc.exe" delete GIDEONAgent 2>$null | Out-Null } catch {}

# Defensive cleanup of obsolete pre-RC30.95.5 task-based installations.
Stop-ScheduledTask -TaskName 'GIDEONAgent' -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'GIDEONAgent' -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'GIDEONAgentTray' -Confirm:$false -ErrorAction SilentlyContinue
foreach($runKey in @(
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
)){
  Remove-ItemProperty -Path $runKey -Name 'GIDEONAgentTray' -ErrorAction SilentlyContinue
}

# Kill only Python processes whose command line belongs to GIDEON Agent.
try {
  Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -and ($_.CommandLine -match 'gideon_agent\.py|gideon_agent_tray\.py|\\GIDEONAgent\\') } |
    ForEach-Object { Stop-Process -Id ([int]$_.ProcessId) -Force -ErrorAction SilentlyContinue }
} catch {}
Start-Sleep -Milliseconds 500

# 2) Remove Add/Remove Programs entries left by old/native/manual installers.
$uninstallRoots=@(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
)
foreach($root in $uninstallRoots){
  if(-not (Test-Path $root)){ continue }
  Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
    try {
      $p=Get-ItemProperty $_.PSPath -ErrorAction Stop
      $display=[string]$p.DisplayName
      $loc=[string]$p.InstallLocation
      if($display -match '^GIDEON (Remote Control )?Agent' -or $loc -match '\\GIDEONAgent\\?$'){
        Remove-Item $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
      }
    } catch {}
  }
}

# 3) Remove local agent data and legacy roots. Do not remove the current Inno
# application directory here; Inno owns that folder and deletes it after this hook.
$roots=@()
if($RemoveData){ $roots += 'C:\ProgramData\GIDEONAgent' }
if($RemoveLegacy){
  $roots += @('C:\ProgramData\GIDEONAgent','C:\Program Files (x86)\GIDEONAgent')
  if($InstallRoot -ne 'C:\Program Files\GIDEONAgent'){ $roots += 'C:\Program Files\GIDEONAgent' }
}
foreach($root in ($roots | Select-Object -Unique)){
  if(-not $root -or -not (Test-Path -LiteralPath $root)){ continue }
  for($i=0;$i -lt 5;$i++){
    try { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop; break }
    catch { Start-Sleep -Milliseconds (400 * ($i+1)) }
  }
}
Write-Gideon 'GIDEON Agent desinstalado. Servicio Windows, runtime, miniatura y datos heredados fueron retirados.'
exit 0
