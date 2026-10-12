#requires -Version 5.1
[CmdletBinding()]
param([string]$PackageRoot = $PSScriptRoot)
$ErrorActionPreference='Stop'
$id=[Security.Principal.WindowsIdentity]::GetCurrent()
$p=New-Object Security.Principal.WindowsPrincipal($id)
if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
  throw 'Ejecute Apply-GIDEONUpdate.ps1 como Administrador.'
}
$key='HKLM:\SOFTWARE\GIDEON\RemoteControl'
if(-not (Test-Path $key)){throw 'GIDEON Remote Control 6.3.0+ no está instalado en este Windows.'}
$reg=Get-ItemProperty $key
$app=[string]$reg.AppRoot; $data=[string]$reg.DataRoot; $install=[string]$reg.InstallRoot
$python=Join-Path $install 'venv\Scripts\python.exe'
$updater=Join-Path $app 'gideon_product_update.py'
if(-not (Test-Path $python)){throw "Runtime GIDEON no encontrado: $python"}
if(-not (Test-Path $updater)){throw "Updater GIDEON no encontrado: $updater"}
$root=(Resolve-Path -LiteralPath $PackageRoot).Path
$manifestPath=Join-Path $root 'manifest.json'
if(-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)){throw "Falta manifest.json en $root"}
$pkg=Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
$required=@($pkg.from_release_manifest_sha256 | Where-Object { $_ })
if($required.Count -gt 0){
  $installedManifest=Join-Path $app 'RELEASE-MANIFEST.json'
  if(-not (Test-Path -LiteralPath $installedManifest -PathType Leaf)){throw 'BASELINE_ATTESTATION_MISSING: no existe RELEASE-MANIFEST.json instalado.'}
  $actual=(Get-FileHash -LiteralPath $installedManifest -Algorithm SHA256).Hash.ToLowerInvariant()
  $allowed=@($required | ForEach-Object { ([string]$_).ToLowerInvariant() })
  if($actual -notin $allowed){throw "BASELINE_MISMATCH: manifest instalado $actual no coincide con $($allowed -join ', ')"}
  Write-Host "Baseline release GIDEON verificado: $actual" -ForegroundColor Green
}
$requiredIntegrity=@($pkg.from_install_integrity_manifest_sha256 | Where-Object { $_ })
if($requiredIntegrity.Count -gt 0){
  $installedIntegrity=Join-Path $app 'INSTALL-INTEGRITY-MANIFEST.json'
  if(-not (Test-Path -LiteralPath $installedIntegrity -PathType Leaf)){throw 'INTEGRITY_BASELINE_MISSING: no existe INSTALL-INTEGRITY-MANIFEST.json instalado.'}
  $actualIntegrity=(Get-FileHash -LiteralPath $installedIntegrity -Algorithm SHA256).Hash.ToLowerInvariant()
  $allowedIntegrity=@($requiredIntegrity | ForEach-Object { ([string]$_).ToLowerInvariant() })
  if($actualIntegrity -notin $allowedIntegrity){throw "INTEGRITY_BASELINE_MISMATCH: manifest instalado $actualIntegrity no coincide con $($allowedIntegrity -join ', ')"}
  $integrity=Get-Content -LiteralPath $installedIntegrity -Raw -Encoding UTF8 | ConvertFrom-Json
  $verified=0
  foreach($row in @($integrity.files)){
    $rel=[string]$row.path
    if([string]::IsNullOrWhiteSpace($rel) -or $rel -match '(^|[\\/])\.\.([\\/]|$)' -or [IO.Path]::IsPathRooted($rel)){throw "INTEGRITY_BASELINE_INVALID: ruta insegura $rel"}
    $target=Join-Path $app ($rel -replace '/', [IO.Path]::DirectorySeparatorChar)
    if(-not (Test-Path -LiteralPath $target -PathType Leaf)){throw "INTEGRITY_BASELINE_MISMATCH: falta $rel"}
    $item=Get-Item -LiteralPath $target
    if([int64]$item.Length -ne [int64]$row.size_bytes){throw "INTEGRITY_BASELINE_MISMATCH: tamaño distinto $rel"}
    $digest=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
    if($digest -ne ([string]$row.sha256).ToLowerInvariant()){throw "INTEGRITY_BASELINE_MISMATCH: SHA-256 distinto $rel"}
    $verified++
  }
  Write-Host "Baseline inmutable GIDEON verificado: $actualIntegrity ($verified archivos)" -ForegroundColor Green
}
& $python $updater --package-dir $root --platform windows --app-root $app --state-root (Join-Path $data 'updates')
if($LASTEXITCODE -ne 0){throw "Actualización GIDEON falló con código $LASTEXITCODE. Revise $(Join-Path $data 'updates\rollback')"}
