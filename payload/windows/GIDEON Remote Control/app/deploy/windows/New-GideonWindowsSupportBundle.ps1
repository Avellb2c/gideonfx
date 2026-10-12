#requires -Version 5.1
Set-StrictMode -Version 2.0

function Write-GideonSupportText {
    param([string]$Path, [object]$Value)
    $parent = Split-Path -Parent $Path
    if ($parent) { New-Item -ItemType Directory -Path $parent -Force -ErrorAction SilentlyContinue | Out-Null }
    $enc = New-Object System.Text.UTF8Encoding($true)
    [IO.File]::WriteAllText($Path, ([string]$Value), $enc)
}

function Copy-GideonSupportFile {
    param([string]$Source, [string]$Destination)
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) { return }
    $parent = Split-Path -Parent $Destination
    if ($parent) { New-Item -ItemType Directory -Path $parent -Force -ErrorAction SilentlyContinue | Out-Null }
    Copy-Item -LiteralPath $Source -Destination $Destination -Force -ErrorAction SilentlyContinue
}

function Redact-GideonSupportText {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    $value=[string]$Text
    $patterns=@(
        '(?im)^\s*(GIDEON_[A-Z0-9_]*(?:TOKEN|SECRET|KEY|PASSWORD)[A-Z0-9_]*)\s*=.*$',
        '(?im)^\s*(Temporary password|Contraseña temporal|Password|Contraseña|Token|Secret)\s*[:=].*$',
        '(?im)(Authorization\s*:\s*(?:Bearer|Basic)\s+)\S+'
    )
    $value=[regex]::Replace($value,$patterns[0],'$1=[REDACTED]')
    $value=[regex]::Replace($value,$patterns[1],'$1: [REDACTED]')
    $value=[regex]::Replace($value,$patterns[2],'$1[REDACTED]')
    return $value
}

function Copy-GideonSupportTextFileSanitized {
    param([string]$Source,[string]$Destination)
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) { return }
    try {
        $text=Get-Content -LiteralPath $Source -Raw -ErrorAction Stop
        Write-GideonSupportText $Destination (Redact-GideonSupportText $text)
    } catch {
        Write-GideonSupportText $Destination ("Unable to read source text: " + $_.Exception.Message)
    }
}

function New-GideonWindowsSupportBundle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$InstallRoot,
        [Parameter(Mandatory=$true)][string]$DataRoot,
        [string]$SourceRoot = '',
        [string]$FailureMessage = '',
        [string]$FailureType = '',
        [string]$FailurePosition = ''
    )

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $hostName = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { 'WINDOWS' }
    $preferredRoot = Join-Path $DataRoot 'support-bundles'
    $fallbackRoot = Join-Path $env:TEMP 'GIDEON-Support'
    $bundleRoot = $preferredRoot
    try {
        New-Item -ItemType Directory -Path $bundleRoot -Force -ErrorAction Stop | Out-Null
    } catch {
        $bundleRoot = $fallbackRoot
        New-Item -ItemType Directory -Path $bundleRoot -Force -ErrorAction Stop | Out-Null
    }

    $work = Join-Path $bundleRoot ("staging-$stamp")
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    $zip = Join-Path $bundleRoot ("GIDEON-WINDOWS-SUPPORT-$hostName-$stamp.zip")

    try {
        $failure = @(
            "timestamp=$(Get-Date -Format o)",
            "computer=$hostName",
            "failure_type=$FailureType",
            "failure_message=$FailureMessage",
            "failure_position=$FailurePosition",
            "install_root=$InstallRoot",
            "data_root=$DataRoot"
        ) -join "`r`n"
        Write-GideonSupportText (Join-Path $work 'FAILURE.txt') ($failure + "`r`n")

        $systemLines = New-Object System.Collections.ArrayList
        [void]$systemLines.Add("timestamp=$(Get-Date -Format o)")
        [void]$systemLines.Add("computer=$hostName")
        [void]$systemLines.Add("user=$env:USERNAME")
        [void]$systemLines.Add("process_arch=$env:PROCESSOR_ARCHITECTURE")
        [void]$systemLines.Add("powershell=$($PSVersionTable.PSVersion)")
        [void]$systemLines.Add("psedition=$($PSVersionTable.PSEdition)")
        [void]$systemLines.Add("clr=$($PSVersionTable.CLRVersion)")
        try {
            $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
            [void]$systemLines.Add("os=$($os.Caption)")
            [void]$systemLines.Add("version=$($os.Version)")
            [void]$systemLines.Add("build=$($os.BuildNumber)")
            [void]$systemLines.Add("product_type=$($os.ProductType)")
        } catch { [void]$systemLines.Add("os_probe_error=$($_.Exception.Message)") }
        Write-GideonSupportText (Join-Path $work 'SYSTEM.txt') (($systemLines -join "`r`n") + "`r`n")

        $services = @(
            'GIDEONRemoteControl','GIDEONRemoteControlGateway','GIDEONRemoteControlWebAdmin',
            'GIDEONRemoteControlBackup','GIDEONRemoteControlUpdater','GIDEONRemoteControlDiagnostics'
        )
        $svcOut = New-Object System.Collections.ArrayList
        foreach ($name in $services) {
            [void]$svcOut.Add("===== $name =====")
            foreach ($args in @(@('queryex',$name), @('qc',$name), @('qsidtype',$name))) {
                try { [void]$svcOut.Add(((& sc.exe @args 2>&1) -join "`r`n")) } catch { [void]$svcOut.Add("sc error: $($_.Exception.Message)") }
            }
            try {
                $svc = Get-CimInstance Win32_Service -Filter ("Name='" + $name.Replace("'","''") + "'") -ErrorAction Stop
                [void]$svcOut.Add("StartName=$($svc.StartName); State=$($svc.State); StartMode=$($svc.StartMode); PathName=$($svc.PathName)")
            } catch { [void]$svcOut.Add("CIM: $($_.Exception.Message)") }
        }
        Write-GideonSupportText (Join-Path $work 'SERVICES.txt') (($svcOut -join "`r`n") + "`r`n")

        $registryOut = New-Object System.Collections.ArrayList
        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
            try {
                $key = $base.OpenSubKey('SOFTWARE\GIDEON\RemoteControl',$false)
                if ($null -eq $key) { [void]$registryOut.Add('Registry64 SOFTWARE\\GIDEON\\RemoteControl: MISSING') }
                else {
                    try {
                        foreach ($name in @('InstallRoot','AppRoot','DataRoot','Version')) {
                            [void]$registryOut.Add("$name=$($key.GetValue($name,$null))")
                        }
                    } finally { $key.Dispose() }
                }
            } finally { $base.Dispose() }
        } catch { [void]$registryOut.Add("Registry64 probe failed: $($_.Exception.Message)") }
        Write-GideonSupportText (Join-Path $work 'REGISTRY64.txt') (($registryOut -join "`r`n") + "`r`n")

        $runtimeOut = New-Object System.Collections.ArrayList
        $venvPython = Join-Path $InstallRoot 'venv\Scripts\python.exe'
        $venvCfg = Join-Path $InstallRoot 'venv\pyvenv.cfg'
        $basePython = Join-Path $InstallRoot 'runtime\python-base\python.exe'
        foreach ($p in @($venvPython,$venvCfg,$basePython)) {
            [void]$runtimeOut.Add("$p : exists=$(Test-Path -LiteralPath $p)")
        }
        if (Test-Path -LiteralPath $venvCfg -PathType Leaf) {
            [void]$runtimeOut.Add('--- pyvenv.cfg ---')
            try { [void]$runtimeOut.Add(((Get-Content -LiteralPath $venvCfg -ErrorAction Stop) -join "`r`n")) } catch { [void]$runtimeOut.Add($_.Exception.Message) }
        }
        foreach ($python in @($venvPython,$basePython)) {
            if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { continue }
            try {
                $probe = & $python -c "import os,sys,platform; print('exe='+sys.executable); print('prefix='+sys.prefix); print('base_prefix='+sys.base_prefix); print('version='+sys.version.replace(chr(10),' ')); print('platform='+platform.platform())" 2>&1
                [void]$runtimeOut.Add("--- $python ---")
                [void]$runtimeOut.Add(($probe -join "`r`n"))
                [void]$runtimeOut.Add("exit=$LASTEXITCODE")
            } catch { [void]$runtimeOut.Add("probe_error=$($_.Exception.Message)") }
        }
        Write-GideonSupportText (Join-Path $work 'PYTHON-RUNTIME.txt') (($runtimeOut -join "`r`n") + "`r`n")
        Copy-GideonSupportFile $venvCfg (Join-Path $work 'runtime\pyvenv.cfg')

        $aclPaths = @(
            $InstallRoot,
            (Join-Path $InstallRoot 'runtime'),
            (Join-Path $InstallRoot 'runtime\python-base'),
            (Join-Path $InstallRoot 'venv'),
            $DataRoot,
            (Join-Path $DataRoot 'config'),
            (Join-Path $DataRoot 'gateway'),
            (Join-Path $DataRoot 'web'),
            (Join-Path $DataRoot 'diagnostics'),
            (Join-Path $DataRoot 'coordinator'),
            (Join-Path $DataRoot 'pki'),
            (Join-Path $DataRoot 'secrets')
        )
        $aclOut = New-Object System.Collections.ArrayList
        foreach ($p in $aclPaths) {
            [void]$aclOut.Add("===== $p =====")
            if (-not (Test-Path -LiteralPath $p)) { [void]$aclOut.Add('MISSING'); continue }
            try { [void]$aclOut.Add(((& icacls.exe $p 2>&1) -join "`r`n")) } catch { [void]$aclOut.Add($_.Exception.Message) }
        }
        Write-GideonSupportText (Join-Path $work 'ACL.txt') (($aclOut -join "`r`n") + "`r`n")

        $logsRoot = Join-Path $DataRoot 'logs\services'
        if (Test-Path -LiteralPath $logsRoot -PathType Container) {
            foreach ($serviceDir in Get-ChildItem -LiteralPath $logsRoot -Directory -ErrorAction SilentlyContinue) {
                foreach ($logName in @('service-host.log','scm-manager.log','background.log','diagnostics.log','coordinator.log')) {
                    $src = Join-Path $serviceDir.FullName $logName
                    $dst = Join-Path $work ("logs\" + $serviceDir.Name + "\" + $logName)
                    Copy-GideonSupportTextFileSanitized $src $dst
                }
            }
        }
        foreach ($p in @(
            (Join-Path $DataRoot 'diagnostics\health.json'),
            (Join-Path $DataRoot 'coordinator\status.json')
        )) {
            Copy-GideonSupportTextFileSanitized $p (Join-Path $work ('state\' + (Split-Path -Leaf $p)))
        }

        $transcriptCandidates=@()
        if ($env:GIDEON_INSTALL_TRANSCRIPT) { $transcriptCandidates += $env:GIDEON_INSTALL_TRANSCRIPT }
        foreach ($root in @((Join-Path $DataRoot 'logs\install'),(Join-Path $env:TEMP 'GIDEON-Install'))) {
            if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
            $latest=Get-ChildItem -LiteralPath $root -Filter 'install-*.log' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 3
            foreach ($f in $latest) { $transcriptCandidates += $f.FullName }
        }
        $seenTranscript=@{}
        foreach ($t in $transcriptCandidates) {
            if (-not $t -or $seenTranscript.ContainsKey($t)) { continue }
            $seenTranscript[$t]=$true
            Copy-GideonSupportTextFileSanitized $t (Join-Path $work ('install-transcript\' + (Split-Path -Leaf $t)))
        }

        $fallbackPattern = 'GIDEONServiceHost-startup-*.log'
        $fallbackDirs = @(
            (Join-Path $env:WINDIR 'ServiceProfiles\LocalService\AppData\Local\Temp'),
            $env:TEMP
        ) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container) }
        foreach ($dir in $fallbackDirs) {
            foreach ($f in Get-ChildItem -LiteralPath $dir -Filter $fallbackPattern -File -ErrorAction SilentlyContinue) {
                Copy-GideonSupportTextFileSanitized $f.FullName (Join-Path $work ('fallback\' + $f.Name))
            }
        }

        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddHours(-4)} -ErrorAction Stop |
                Where-Object { $_.ProviderName -eq 'Service Control Manager' -and $_.Message -match 'GIDEONRemoteControl' } |
                Select-Object -First 120 TimeCreated,Id,LevelDisplayName,Message |
                Format-List | Out-String -Width 220
            Write-GideonSupportText (Join-Path $work 'EVENTS-SCM.txt') $events
        } catch { Write-GideonSupportText (Join-Path $work 'EVENTS-SCM.txt') ("Event probe failed: " + $_.Exception.Message) }

        $scriptRoots = @()
        if ($SourceRoot -and (Test-Path -LiteralPath $SourceRoot -PathType Container)) { $scriptRoots += (Join-Path $SourceRoot 'deploy\windows') }
        $installedWindows = Join-Path $InstallRoot 'app\deploy\windows'
        if (Test-Path -LiteralPath $installedWindows -PathType Container) { $scriptRoots += $installedWindows }
        $seen = @{}
        foreach ($root in $scriptRoots) {
            if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
            foreach ($f in Get-ChildItem -LiteralPath $root -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in @('.ps1','.cmd','.py','.cs') }) {
                $key = $f.Name.ToLowerInvariant()
                if ($seen.ContainsKey($key)) { continue }
                $seen[$key] = $true
                Copy-GideonSupportFile $f.FullName (Join-Path $work ('windows-scripts\' + $f.Name))
            }
        }

        if (Test-Path -LiteralPath $zip -PathType Leaf) { Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue }
        Compress-Archive -Path (Join-Path $work '*') -DestinationPath $zip -CompressionLevel Optimal -Force
        return $zip
    } finally {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}
