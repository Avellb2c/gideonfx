[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$VhdxPath,

    [Parameter(Mandatory=$true)]
    [string]$ExpectedSha256,

    [Parameter(Mandatory=$true)]
    [string]$ValidationReportPath,

    [string]$Version = 'GIDEON-GUACD-APPLIANCE-VALIDATED'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$InstallerRoot = Split-Path -Parent $PSScriptRoot
$BundleRoot = Split-Path -Parent $InstallerRoot
Import-Module (Join-Path $InstallerRoot 'common\GIDEON.Common.psm1') -Force

$source = [IO.Path]::GetFullPath($VhdxPath)
if (-not (Test-Path -LiteralPath $source)) {
    throw "VHDX no encontrado: $source"
}

if ([IO.Path]::GetExtension($source) -ne '.vhdx') {
    throw 'El appliance debe ser un archivo .vhdx.'
}

$expected = $ExpectedSha256.Trim().ToLowerInvariant()
if ($expected -notmatch '^[a-f0-9]{64}$') {
    throw 'ExpectedSha256 debe contener exactamente 64 caracteres hexadecimales.'
}

$actual = Get-GideonSha256 $source
if ($actual -ne $expected) {
    throw "SHA256_MISMATCH esperado=$expected actual=$actual"
}

$validationSource = [IO.Path]::GetFullPath($ValidationReportPath)
if (-not (Test-Path -LiteralPath $validationSource -PathType Leaf)) {
    throw "Reporte de validacion Hyper-V no encontrado: $validationSource"
}

$validation = Read-GideonJson $validationSource
if ([int]$validation.schema_version -ne 1 -or [string]$validation.result -ne 'PASS') {
    throw 'El reporte no declara schema_version=1 y result=PASS.'
}

if (-not [bool]$validation.tested_on_hyperv) {
    throw 'El reporte no confirma una prueba real en Hyper-V.'
}

if (([string]$validation.appliance_sha256).ToLowerInvariant() -ne $expected) {
    throw 'El SHA-256 del reporte no coincide con el VHDX importado.'
}

foreach ($requiredTest in @('generation2_boot','secure_boot','cloud_init','docker_offline','guacd_tcp_4822')) {
    $property = $validation.tests.PSObject.Properties[$requiredTest]
    if (-not $property -or -not [bool]$property.Value) {
        throw "El reporte no confirma la prueba obligatoria: $requiredTest"
    }
}

$destDir = Join-Path $BundleRoot 'offline-cache\hyperv'
New-GideonDirectory $destDir
$dest = Join-Path $destDir 'GIDEON-GUACD-UBUNTU.vhdx'

Write-GideonInfo "Copiando appliance validado -> $dest"
$copyTemp = "$dest.import-$([guid]::NewGuid().ToString('N'))"
$validationDest = Join-Path $BundleRoot 'metadata\hyperv-appliance-validation.json'
New-GideonDirectory (Split-Path -Parent $validationDest)
$validationTemp = "$validationDest.import-$([guid]::NewGuid().ToString('N'))"

$lockPath = Join-Path $InstallerRoot 'config\dependency-lock.json'
$lockTemp = "$lockPath.import-$([guid]::NewGuid().ToString('N'))"
if (Test-Path -LiteralPath $lockPath) {
    $lock = Read-GideonJson $lockPath
}
else {
    $lock = [pscustomobject]@{schema_version=1;artifacts=@()}
}

$retained = @(
    @($lock.artifacts) |
        Where-Object { [string]$_.id -ne 'ubuntu-guacd-appliance-vhdx' }
)
$retained += [pscustomobject][ordered]@{
    id = 'ubuntu-guacd-appliance-vhdx'
    platform = 'windows-hyperv'
    architecture = 'amd64'
    version = $Version
    source = 'Locally imported after Hyper-V Generation 2 validation'
    url = 'LOCAL_VALIDATED_IMPORT'
    sha256 = $expected
    destination = 'offline-cache/hyperv/GIDEON-GUACD-UBUNTU.vhdx'
    required = $true
    validation_status = 'VALIDATED_HYPERV_BOOT'
    validation_report = 'metadata/hyperv-appliance-validation.json'
}

$lock.artifacts = @($retained)
if ($lock.PSObject.Properties['generated_utc']) {
    $lock.generated_utc = [DateTime]::UtcNow.ToString('o')
}
else {
    $lock | Add-Member -NotePropertyName generated_utc -NotePropertyValue ([DateTime]::UtcNow.ToString('o'))
}

$validationSourceSha = Get-GideonSha256 $validationSource
try {
    Copy-Item -LiteralPath $source -Destination $copyTemp -Force
    Copy-Item -LiteralPath $validationSource -Destination $validationTemp -Force
    Write-GideonJson $lock $lockTemp 12

    if ((Get-GideonSha256 $copyTemp) -ne $expected) {
        throw 'La copia VHDX no conserva el SHA-256 esperado.'
    }

    if ((Get-GideonSha256 $validationTemp) -ne $validationSourceSha) {
        throw 'La copia del reporte de validacion no conserva el SHA-256 esperado.'
    }
}
catch {
    Remove-Item -LiteralPath $copyTemp -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $validationTemp -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $lockTemp -Force -ErrorAction SilentlyContinue
    throw
}

# Commit the three related files with the lock last. If any replacement fails,
# restore every destination already changed so the bundle cannot remain in a
# mixed VHDX/report/lock state.
$transactionId = [guid]::NewGuid().ToString('N')
$items = @(
    [pscustomobject]@{Stage=$copyTemp;Dest=$dest;Backup="$dest.backup-$transactionId";HadOriginal=$false},
    [pscustomobject]@{Stage=$validationTemp;Dest=$validationDest;Backup="$validationDest.backup-$transactionId";HadOriginal=$false},
    [pscustomobject]@{Stage=$lockTemp;Dest=$lockPath;Backup="$lockPath.backup-$transactionId";HadOriginal=$false}
)
$committed = New-Object Collections.ArrayList
$commitSucceeded = $false
try {
    foreach ($item in $items) {
        $item.HadOriginal = Test-Path -LiteralPath $item.Dest
        if ($item.HadOriginal) {
            Remove-Item -LiteralPath $item.Backup -Force -ErrorAction SilentlyContinue
            [IO.File]::Replace($item.Stage,$item.Dest,$item.Backup,$true)
        }
        else {
            Move-Item -LiteralPath $item.Stage -Destination $item.Dest
        }
        [void]$committed.Add($item)
    }
    $commitSucceeded = $true
}
catch {
    for ($index = $committed.Count - 1; $index -ge 0; $index--) {
        $item = $committed[$index]
        Remove-Item -LiteralPath $item.Dest -Force -ErrorAction SilentlyContinue
        if ($item.HadOriginal -and (Test-Path -LiteralPath $item.Backup)) {
            Move-Item -LiteralPath $item.Backup -Destination $item.Dest -Force
        }
    }
    throw
}
finally {
    foreach ($item in $items) {
        Remove-Item -LiteralPath $item.Stage -Force -ErrorAction SilentlyContinue
        if ($commitSucceeded) {
            Remove-Item -LiteralPath $item.Backup -Force -ErrorAction SilentlyContinue
        }
    }
}

Write-Host ''
Write-GideonPass 'GUACD_APPLIANCE_IMPORT=PASS'
Write-Host "VHDX=$dest"
Write-Host "SHA256=$expected"
Write-Host "VALIDATION=$validationDest"
Write-Host "LOCK=$lockPath"
$global:LASTEXITCODE = 0
return
