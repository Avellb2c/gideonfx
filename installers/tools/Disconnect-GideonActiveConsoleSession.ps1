#requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$targetUser = 'gideonsis'
$rows = New-Object System.Collections.Generic.List[object]

function Add-GideonResult {
    param([string]$Kind,[string]$Name,[string]$Status,[string]$Detail='')
    $rows.Add([pscustomobject]@{Kind=$Kind;Name=$Name;Status=$Status;Detail=$Detail})
}

try {
    $explorers = @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'")
    $candidates = foreach ($process in $explorers) {
        $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwner -ErrorAction SilentlyContinue
        if (-not $owner -or -not $owner.User) { continue }
        [pscustomobject]@{
            SessionId = [int]$process.SessionId
            User = [string]$owner.User
            Domain = [string]$owner.Domain
            Pid = [int]$process.ProcessId
        }
    }
    $candidate = $candidates |
        Where-Object { $_.SessionId -gt 0 -and $_.User -ine $targetUser } |
        Sort-Object SessionId |
        Select-Object -First 1
    if (-not $candidate) {
        Add-GideonResult 'SESSION_SWITCH' 'ActiveConsole' 'NO_ACTION' 'No existe una sesión interactiva distinta de gideonsis.'
        $rows
        return
    }

    Add-GideonResult 'SESSION_SWITCH' 'ActiveConsole' 'FOUND' (
        'SessionId={0}; User={1}\{2}; ExplorerPid={3}' -f $candidate.SessionId,$candidate.Domain,$candidate.User,$candidate.Pid
    )
    $tsdiscon = Join-Path $env:SystemRoot 'System32\tsdiscon.exe'
    $output = @(& $tsdiscon $candidate.SessionId /V 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "tsdiscon terminó con código ${LASTEXITCODE}: $($output -join ' ')"
    }
    Add-GideonResult 'SESSION_SWITCH' 'Disconnect' 'SUCCESS' (
        'SessionId={0}; User={1}\{2}; Mode=DISCONNECT_ONLY; ProgramsPreserved=true; Output={3}' -f $candidate.SessionId,$candidate.Domain,$candidate.User,($output -join ' ')
    )
}
catch {
    Add-GideonResult 'SESSION_SWITCH' 'Disconnect' 'ERROR' $_.Exception.Message
}

try {
    foreach ($line in @(& (Join-Path $env:SystemRoot 'System32\quser.exe') 2>&1)) {
        Add-GideonResult 'SESSION' 'QUSER' 'OBSERVED' ([string]$line).Trim()
    }
}
catch {
    Add-GideonResult 'SESSION' 'QUSER' 'ERROR' $_.Exception.Message
}

$rows
