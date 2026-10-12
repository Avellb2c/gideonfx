#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$InstallRoot = "$env:ProgramFiles\GIDEON Remote Control",
    [string]$DataRoot = "$env:ProgramData\GIDEON Remote Control"
)
$ErrorActionPreference='Stop'
$module=Join-Path $PSScriptRoot 'New-GideonWindowsSupportBundle.ps1'
. $module
$sourceRoot=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$zip=New-GideonWindowsSupportBundle -InstallRoot $InstallRoot -DataRoot $DataRoot -SourceRoot $sourceRoot -FailureMessage 'Manual support bundle requested' -FailureType 'MANUAL' -FailurePosition ''
Write-Host "`n[GIDEON] SUPPORT BUNDLE GENERADO" -ForegroundColor Green
Write-Host ("ZIP     : " + $zip) -ForegroundColor Yellow
Write-Host ("CARPETA : " + (Split-Path -Parent $zip)) -ForegroundColor Yellow
Write-Host 'Pásame ese ZIP completo para diagnóstico.' -ForegroundColor Yellow
