[CmdletBinding()]
param(
    [string]$ImageTag = 'gideon/hyperv-qemu-validation:ubuntu-24.04-qemu8'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$InstallerRoot = Split-Path -Parent $PSScriptRoot
$BundleRoot = Split-Path -Parent $InstallerRoot
$Context = Join-Path $PSScriptRoot 'qemu-validation'
$ReportPath = Join-Path $BundleRoot 'metadata\hyperv-qemu-prevalidation.json'

if (-not (Get-Command docker.exe -ErrorAction SilentlyContinue)) {
    throw 'Docker Desktop no esta disponible para la prevalidacion QEMU.'
}

Write-Host "[INFO] Construyendo entorno QEMU fijado: $ImageTag"
& docker.exe build --tag $ImageTag $Context
if ($LASTEXITCODE -ne 0) {
    throw "QEMU_VALIDATION_IMAGE_BUILD_FAILED rc=$LASTEXITCODE"
}

$bundleFull = [IO.Path]::GetFullPath($BundleRoot)
$metadataFull = [IO.Path]::GetFullPath((Join-Path $BundleRoot 'metadata'))

Write-Host '[INFO] Arrancando la VHDX candidata con UEFI + QEMU TCG; puede tardar varios minutos.'
& docker.exe run --rm `
    --name gideon-hyperv-qemu-prevalidation `
    --mount "type=bind,source=$bundleFull,destination=/bundle,readonly" `
    --mount "type=bind,source=$metadataFull,destination=/report" `
    $ImageTag

if ($LASTEXITCODE -ne 0) {
    throw "QEMU_UEFI_PREVALIDATION_FAILED rc=$LASTEXITCODE report=$ReportPath"
}

if (-not (Test-Path -LiteralPath $ReportPath -PathType Leaf)) {
    throw "QEMU validation report missing: $ReportPath"
}

$report = Get-Content -LiteralPath $ReportPath -Raw | ConvertFrom-Json
if ([string]$report.result -ne 'PASS' -or [string]$report.validation_status -ne 'QEMU_UEFI_PREVALIDATION_PASS_NOT_HYPERV') {
    throw 'QEMU validation report does not declare the expected PASS state.'
}

$buildReport = Get-Content -LiteralPath (Join-Path $BundleRoot 'metadata\hyperv-appliance-build.json') -Raw | ConvertFrom-Json
if (([string]$report.appliance_sha256).ToLowerInvariant() -ne ([string]$buildReport.candidate.sha256).ToLowerInvariant()) {
    throw 'QEMU validation report hash does not match the candidate build report.'
}

Write-Host "QEMU_UEFI_PREVALIDATION=PASS report=$ReportPath"
Write-Warning 'Esta prueba no sustituye el gate final en Microsoft Hyper-V Generation 2.'
