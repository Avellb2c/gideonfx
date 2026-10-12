#requires -Version 5.1
Set-StrictMode -Version 2.0

# Host compatibility policy for the Windows control plane. Keep this module
# deliberately PowerShell-5.1-safe: plain arrays/PSCustomObject only, no generic
# collection wrapping, no PowerShell 7 syntax, and no registry provider reliance.

function Get-GideonWindowsCompatibilityReport {
    [CmdletBinding()]
    param()

    $checks = @()

    function Add-CompatCheck {
        param([string]$Name,[bool]$Ok,[string]$Detail)
        $script:__gideonCompatChecks += [pscustomobject]@{
            Name = $Name
            Ok = $Ok
            Detail = $Detail
        }
    }

    $script:__gideonCompatChecks = @()
    try {
        Add-CompatCheck '64-bit Windows' ([Environment]::Is64BitOperatingSystem) ("Is64BitOperatingSystem=" + [Environment]::Is64BitOperatingSystem)
        Add-CompatCheck '64-bit PowerShell process' ([Environment]::Is64BitProcess) ("Is64BitProcess=" + [Environment]::Is64BitProcess)

        $psv = $PSVersionTable.PSVersion
        $psOk = ($psv.Major -gt 5) -or (($psv.Major -eq 5) -and ($psv.Minor -ge 1))
        Add-CompatCheck 'Windows PowerShell 5.1+' $psOk ("PSVersion=" + $psv.ToString() + "; PSEdition=" + [string]$PSVersionTable.PSEdition)

        $edition = [string]$PSVersionTable.PSEdition
        Add-CompatCheck 'Windows PowerShell Desktop edition' ($edition -eq 'Desktop') ("PSEdition=" + $edition)

        $clr = [Environment]::Version
        Add-CompatCheck '.NET CLR 4.x' ($clr.Major -eq 4) ("CLR=" + $clr.ToString())

        foreach ($tool in @('sc.exe','icacls.exe','takeown.exe','powershell.exe')) {
            $cmd = Get-Command $tool -ErrorAction SilentlyContinue
            Add-CompatCheck ("Windows tool " + $tool) ($null -ne $cmd) ($(if($null -ne $cmd){[string]$cmd.Source}else{'NOT_FOUND'}))
        }
        $addType = Get-Command Add-Type -ErrorAction SilentlyContinue
        Add-CompatCheck 'Add-Type available' ($null -ne $addType) ($(if($null -ne $addType){[string]$addType.Source}else{'NOT_FOUND'}))

        $regOk = $false
        $regDetail = ''
        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                [Microsoft.Win32.RegistryHive]::LocalMachine,
                [Microsoft.Win32.RegistryView]::Registry64
            )
            try {
                $regOk = ($null -ne $base)
                $regDetail = 'HKLM Registry64 accessible'
            } finally {
                if($null -ne $base){ $base.Dispose() }
            }
        } catch {
            $regDetail = $_.Exception.Message
        }
        Add-CompatCheck 'Registry64 available' $regOk $regDetail

        $programDataRoot = [IO.Path]::GetPathRoot([Environment]::GetFolderPath('CommonApplicationData'))
        $driveId = $programDataRoot.TrimEnd('\')
        $fs = ''
        try {
            $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter ("DeviceID='" + $driveId.Replace("'","''") + "'") -ErrorAction Stop
            $fs = [string]$disk.FileSystem
        } catch {
            $fs = ''
        }
        Add-CompatCheck 'GIDEON persistent volume is NTFS' ($fs -eq 'NTFS') ("drive=" + $driveId + "; filesystem=" + $fs)

        # Windows PowerShell 5.1 on the certified host has a known Generic.List
        # binder bug. GIDEON production scripts avoid that collection pattern entirely.

        return [pscustomobject]@{
            schema = 'gideon-windows-compatibility/v1'
            compatible = ((@($script:__gideonCompatChecks | Where-Object { -not $_.Ok })).Count -eq 0)
            checks = $script:__gideonCompatChecks
            powershell_generic_list_avoided = $true
        }
    } finally {
        Remove-Variable -Name __gideonCompatChecks -Scope Script -ErrorAction SilentlyContinue
    }
}

function Assert-GideonWindowsCompatibility {
    [CmdletBinding()]
    param()
    $report = Get-GideonWindowsCompatibilityReport
    foreach($row in $report.checks){
        $prefix = if($row.Ok){'[OK]'}else{'[FAIL]'}
        $color = if($row.Ok){'DarkGreen'}else{'Red'}
        Write-Host ("$prefix " + $row.Name + ' · ' + $row.Detail) -ForegroundColor $color
    }
    Write-Host '[INFO] GIDEON Windows scripts use PS5.1-safe plain arrays; Generic.List binder patterns are not used.' -ForegroundColor DarkGray
    if(-not $report.compatible){
        throw 'WINDOWS_HOST_COMPATIBILITY_FAILED: el host no cumple los requisitos del control plane GIDEON.'
    }
    return $report
}
