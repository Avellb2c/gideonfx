[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$BundleRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
$SourceTool = Join-Path $BundleRoot 'installers\tools\Import-ValidatedGuacdAppliance.ps1'
$SourceCommon = Join-Path $BundleRoot 'installers\common\GIDEON.Common.psm1'
$TestRoot = Join-Path ([IO.Path]::GetTempPath()) ('gideon-import-test-' + [guid]::NewGuid().ToString('N'))
$Utf8NoBom = New-Object Text.UTF8Encoding($false)

try {
    foreach ($relative in @('installers\tools','installers\common','installers\config')) {
        New-Item -ItemType Directory -Force -Path (Join-Path $TestRoot $relative) | Out-Null
    }

    Copy-Item -LiteralPath $SourceTool -Destination (Join-Path $TestRoot 'installers\tools\Import-ValidatedGuacdAppliance.ps1')
    Copy-Item -LiteralPath $SourceCommon -Destination (Join-Path $TestRoot 'installers\common\GIDEON.Common.psm1')

    $initialLock = [ordered]@{
        schema_version = 1
        artifacts = @([ordered]@{id='preserved-artifact';sha256=('1' * 64);destination='keep.bin'})
    }
    [IO.File]::WriteAllText(
        (Join-Path $TestRoot 'installers\config\dependency-lock.json'),
        ($initialLock | ConvertTo-Json -Depth 10),
        $Utf8NoBom
    )

    foreach ($round in 1..2) {
        $candidate = Join-Path $TestRoot "candidate-$round.vhdx"
        [IO.File]::WriteAllText($candidate,"candidate-content-$round",$Utf8NoBom)
        $sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $candidate).Hash.ToLowerInvariant()
        $report = [ordered]@{
            schema_version = 1
            result = 'PASS'
            tested_on_hyperv = $true
            appliance_sha256 = $sha
            tests = [ordered]@{
                generation2_boot = $true
                secure_boot = $true
                cloud_init = $true
                docker_offline = $true
                guacd_tcp_4822 = $true
            }
        }
        $reportPath = Join-Path $TestRoot "validation-$round.json"
        [IO.File]::WriteAllText($reportPath,($report | ConvertTo-Json -Depth 10),$Utf8NoBom)

        & (Join-Path $TestRoot 'installers\tools\Import-ValidatedGuacdAppliance.ps1') `
            -VhdxPath $candidate `
            -ExpectedSha256 $sha `
            -ValidationReportPath $reportPath `
            -Version "test-$round" | Out-Null

        $destination = Join-Path $TestRoot 'offline-cache\hyperv\GIDEON-GUACD-UBUNTU.vhdx'
        $destinationSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $destination).Hash.ToLowerInvariant()
        if ($destinationSha -ne $sha) {
            throw "Destination mismatch in round $round"
        }
    }

    $finalLock = Get-Content -LiteralPath (Join-Path $TestRoot 'installers\config\dependency-lock.json') -Raw | ConvertFrom-Json
    if (@($finalLock.artifacts | Where-Object { [string]$_.id -eq 'preserved-artifact' }).Count -ne 1) {
        throw 'The pre-existing lock artifact was not preserved.'
    }
    if (@($finalLock.artifacts | Where-Object { [string]$_.id -eq 'ubuntu-guacd-appliance-vhdx' }).Count -ne 1) {
        throw 'The validated VHDX lock artifact was not written exactly once.'
    }

    $debris = @(
        Get-ChildItem -LiteralPath $TestRoot -Recurse -File |
            Where-Object { $_.Name -match '\.(stage|backup|import)-' }
    )
    if ($debris.Count -ne 0) {
        throw "Transaction debris found: $($debris.Count)"
    }

    Write-Host "IMPORT_TRANSACTION_TEST=PASS artifacts=$($finalLock.artifacts.Count) rounds=2"
}
finally {
    if (Test-Path -LiteralPath $TestRoot) {
        Remove-Item -LiteralPath $TestRoot -Recurse -Force
    }
}

