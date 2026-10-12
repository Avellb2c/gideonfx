[CmdletBinding()]
param(
    [string]$SourceImage = '',
    [string]$ExpectedSourceSha256 = '6e40c07ae715f744f84af0bec76415cc1987dd115b4b8de437818561f01a3733',
    [string]$ConverterImage = 'ubuntu:24.04@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517',
    [string]$OutputVhdx = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$InstallerRoot = Split-Path -Parent $PSScriptRoot
$BundleRoot = Split-Path -Parent $InstallerRoot
Import-Module (Join-Path $InstallerRoot 'common\GIDEON.Common.psm1') -Force

if ([string]::IsNullOrWhiteSpace($SourceImage)) {
    $SourceImage = Join-Path $BundleRoot 'offline-cache\hyperv\sources\ubuntu-24.04-server-cloudimg-amd64-20260814.img'
}

if ([string]::IsNullOrWhiteSpace($OutputVhdx)) {
    $OutputVhdx = Join-Path $BundleRoot 'offline-cache\hyperv\candidates\GIDEON-GUACD-UBUNTU-CANDIDATE.vhdx'
}

$source = [IO.Path]::GetFullPath($SourceImage)
$output = [IO.Path]::GetFullPath($OutputVhdx)
$candidateRoot = [IO.Path]::GetFullPath((Join-Path $BundleRoot 'offline-cache\hyperv\candidates'))

if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
    throw "Imagen fuente no encontrada: $source"
}

if (-not $output.StartsWith($candidateRoot + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) {
    throw "La salida debe permanecer dentro de $candidateRoot"
}

$expected = $ExpectedSourceSha256.Trim().ToLowerInvariant()
if ($expected -notmatch '^[a-f0-9]{64}$') {
    throw 'ExpectedSourceSha256 debe contener exactamente 64 caracteres hexadecimales.'
}

$actualSourceSha = Get-GideonSha256 $source
if ($actualSourceSha -ne $expected) {
    throw "SOURCE_SHA256_MISMATCH expected=$expected actual=$actualSourceSha"
}

if (Test-Path -LiteralPath $output) {
    throw "La VHDX candidata ya existe; no se sobrescribira automaticamente: $output"
}

if (-not (Get-Command docker.exe -ErrorAction SilentlyContinue)) {
    throw 'Docker Desktop no esta disponible para ejecutar qemu-img de forma aislada.'
}

$inspectRaw = (& docker.exe image inspect $ConverterImage 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0) {
    throw "La imagen de conversion no esta disponible localmente: $ConverterImage. Ejecute: docker pull $ConverterImage"
}

$imageInfo = @($inspectRaw | ConvertFrom-Json)[0]
$repoDigests = @($imageInfo.RepoDigests | Where-Object { $_ })
if ($repoDigests.Count -lt 1) {
    throw "La imagen de conversion no tiene RepoDigest inmutable: $ConverterImage"
}

$resolvedImage = [string]$repoDigests[0]
$sourceDir = Split-Path -Parent $source
$sourceName = Split-Path -Leaf $source
$outputDir = Split-Path -Parent $output
$outputName = Split-Path -Leaf $output
$sourceReportPath = if ($source.StartsWith($BundleRoot + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) {
    $source.Substring($BundleRoot.Length + 1).Replace('\','/')
}
else {
    $source
}
$candidateReportPath = $output.Substring($BundleRoot.Length + 1).Replace('\','/')
New-GideonDirectory $outputDir

$containerScript = @"
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends qemu-utils ca-certificates >/dev/null
qemu-img convert -f qcow2 -O vhdx -o subformat=dynamic "/input/$sourceName" "/output/$outputName"
qemu-img compare -f qcow2 -F vhdx "/input/$sourceName" "/output/$outputName"
printf 'GIDEON_QEMU_BLOCK_COMPARE=PASS\n'
printf 'GIDEON_QEMU_INFO='
qemu-img info --output=json "/output/$outputName" | tr -d '\n'
printf '\n'
printf 'GIDEON_QEMU_VERSION='
qemu-img --version | head -n 1
dpkg-query -W -f='GIDEON_QEMU_UTILS_PACKAGE=`${Version}\n' qemu-utils
"@

Write-GideonInfo "Convirtiendo QCOW2 oficial a VHDX dinamica con $resolvedImage"
$previousErrorActionPreference = $ErrorActionPreference
try {
    # Windows PowerShell 5.1 wraps any native stderr line as NativeCommandError.
    # qemu-img progress and apt informational messages legitimately use stderr.
    $ErrorActionPreference = 'Continue'
    $conversionOutput = (& docker.exe run --rm `
        --mount "type=bind,source=$sourceDir,destination=/input,readonly" `
        --mount "type=bind,source=$outputDir,destination=/output" `
        $resolvedImage `
        sh -lc $containerScript 2>&1 | Out-String)
    $conversionExitCode = $LASTEXITCODE
}
finally {
    $ErrorActionPreference = $previousErrorActionPreference
}

if ($conversionExitCode -ne 0) {
    throw "QEMU_IMG_CONVERSION_FAILED`n$conversionOutput"
}

if (-not (Test-Path -LiteralPath $output -PathType Leaf)) {
    throw "qemu-img no genero la salida esperada: $output"
}

$toolSummary = @(
    $conversionOutput -split "`r?`n" |
        Where-Object { $_ -match '^GIDEON_QEMU_' }
) -join "`n"

$candidateSha = Get-GideonSha256 $output
$reportPath = Join-Path $BundleRoot 'metadata\hyperv-appliance-build.json'
$report = [ordered]@{
    schema_version = 1
    generated_utc = [DateTime]::UtcNow.ToString('o')
    result = 'CANDIDATE_CREATED'
    validation_status = 'REQUIRES_HYPERV_GENERATION2_BOOT_TEST'
    conversion_integrity = 'QEMU_BLOCK_COMPARE_PASS'
    source = [ordered]@{
        product = 'Ubuntu Server 24.04 LTS release cloud image'
        release = '20260814'
        format = 'qcow2'
        path = $sourceReportPath
        sha256 = $actualSourceSha
        url = 'https://cloud-images.ubuntu.com/releases/releases/noble/release-20260814/ubuntu-24.04-server-cloudimg-amd64.img'
    }
    converter = [ordered]@{
        requested_image = $ConverterImage
        resolved_image = $resolvedImage
        image_id = [string]$imageInfo.Id
        tool_summary = $toolSummary
    }
    candidate = [ordered]@{
        path = $candidateReportPath
        sha256 = $candidateSha
        size_bytes = [int64](Get-Item -LiteralPath $output).Length
    }
}

Write-GideonJson $report $reportPath 12

Write-Host ''
Write-GideonPass 'HYPERV_APPLIANCE_CANDIDATE=CREATED'
Write-Host "VHDX=$output"
Write-Host "SHA256=$candidateSha"
Write-Host "BUILD_REPORT=$reportPath"
Write-GideonWarn 'CANDIDATE_ONLY: falta prueba de arranque Generation 2, cloud-init, Docker offline y TCP 4822 en Hyper-V.'
