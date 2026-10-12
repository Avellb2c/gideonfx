[CmdletBinding()]
param(
    [string]$CandidateVhdx = '',
    [string]$ValidationReportPath = '',
    [switch]$CleanupOnSuccess
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$InstallerRoot = Split-Path -Parent $PSScriptRoot
$BundleRoot = Split-Path -Parent $InstallerRoot
$common = Join-Path $InstallerRoot 'common\GIDEON.Common.psm1'
Import-Module $common -Force

if (-not (Test-GideonAdministrator)) {
    throw 'Ejecute esta validacion como Administrador en Windows Pro/Enterprise/Server con Hyper-V.'
}

if ([string]::IsNullOrWhiteSpace($CandidateVhdx)) {
    $CandidateVhdx = Join-Path $BundleRoot 'offline-cache\hyperv\candidates\GIDEON-GUACD-UBUNTU-CANDIDATE.vhdx'
}

if ([string]::IsNullOrWhiteSpace($ValidationReportPath)) {
    $ValidationReportPath = Join-Path $BundleRoot 'metadata\hyperv-appliance-validation.json'
}

$python = Join-Path $BundleRoot 'payload\windows\GIDEON Remote Control\venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) {
    $python = Join-Path $BundleRoot 'payload\windows\GIDEON Remote Control\runtime\python-base\python.exe'
}

if (-not (Test-Path -LiteralPath $python)) {
    throw 'Runtime Python privado del bundle no encontrado.'
}

$config = Join-Path $BundleRoot 'master.config.json'
$provisioner = Join-Path $InstallerRoot 'WINDOWS\Provision-GuacdHyperV.ps1'

if ($CleanupOnSuccess) {
    Write-GideonInfo 'La prueba retirara sus recursos GIDEON-GUACD-VALIDATION despues de guardar evidencia PASS.'
}
else {
    Write-GideonWarn 'La prueba crea recursos aislados GIDEON-GUACD-VALIDATION y los deja encendidos para inspeccion.'
}
Write-GideonInfo "Candidate=$([IO.Path]::GetFullPath($CandidateVhdx))"

& $provisioner `
    -BundleRoot $BundleRoot `
    -PythonExe $python `
    -ConfigPath $config `
    -CandidateVhdPath $CandidateVhdx `
    -ValidationReportPath $ValidationReportPath

if ($LASTEXITCODE -ne 0) {
    throw "HYPERV_APPLIANCE_VALIDATION_FAILED rc=$LASTEXITCODE"
}

if ($CleanupOnSuccess) {
    $cfg = Read-GideonJson $config
    $vmName = ([string]$cfg.windows.hyperv.vm_name) + '-VALIDATION'
    $switchName = ([string]$cfg.windows.hyperv.switch_name) + '-Validation'
    $natName = ([string]$cfg.windows.hyperv.nat_name) + '-Validation'

    Import-Module Hyper-V -ErrorAction Stop
    $vm = Get-VM -Name $vmName -ErrorAction SilentlyContinue
    if ($vm) {
        Stop-VM -Name $vmName -TurnOff -Force -ErrorAction SilentlyContinue
        Remove-VM -Name $vmName -Force
    }

    Get-NetNat -Name $natName -ErrorAction SilentlyContinue |
        Remove-NetNat -Confirm:$false -ErrorAction SilentlyContinue

    Get-VMSwitch -Name $switchName -ErrorAction SilentlyContinue |
        Remove-VMSwitch -Force -ErrorAction SilentlyContinue

    Get-NetFirewallRule `
        -DisplayName 'GIDEON-RC-Guacd-HyperV-Validation' `
        -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue

    $hypervRoot = Join-Path $env:ProgramData 'GIDEON Remote Control\hyperv'
    $validationRoot = Join-Path $hypervRoot $vmName
    if (Test-Path -LiteralPath $validationRoot -PathType Container) {
        $resolvedHypervRoot = [IO.Path]::GetFullPath($hypervRoot).TrimEnd('\')
        $resolvedValidationRoot = [IO.Path]::GetFullPath($validationRoot).TrimEnd('\')
        $expectedPrefix = $resolvedHypervRoot + '\'
        if (-not $resolvedValidationRoot.StartsWith($expectedPrefix,[StringComparison]::OrdinalIgnoreCase) -or
            (Split-Path -Leaf $resolvedValidationRoot) -ne $vmName -or
            $vmName -notlike '*-VALIDATION') {
            throw "UNSAFE_HYPERV_VALIDATION_CLEANUP_TARGET: $resolvedValidationRoot"
        }
        Remove-Item -LiteralPath $resolvedValidationRoot -Recurse -Force
    }

    Write-GideonInfo 'Los recursos temporales de validacion Hyper-V fueron retirados.'
}
