#requires -Version 5.1
[CmdletBinding()]
param([switch]$RemoveData)
$script=Join-Path (Split-Path -Parent $PSScriptRoot) 'deploy\agent\windows\gideon-agent-uninstall.ps1'
if(Test-Path $script){ & $script -InstallRoot 'C:\ProgramData\GIDEONAgent' -RemoveData:$RemoveData -RemoveLegacy -Quiet; exit $LASTEXITCODE }
Stop-ScheduledTask -TaskName 'GIDEONAgent' -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'GIDEONAgent' -Confirm:$false -ErrorAction SilentlyContinue
Remove-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'GIDEONAgentTray' -ErrorAction SilentlyContinue
if($RemoveData){ Remove-Item 'C:\ProgramData\GIDEONAgent' -Recurse -Force -ErrorAction SilentlyContinue }
Write-Host 'GIDEONAgent uninstalled.'
