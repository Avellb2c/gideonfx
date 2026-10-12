#requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$rows = New-Object System.Collections.Generic.List[object]
function Add-GideonResult {
    param([string]$Kind,[string]$Name,[string]$Status,[string]$Detail='')
    $rows.Add([pscustomobject]@{Kind=$Kind;Name=$Name;Status=$Status;Detail=$Detail})
}

try {
    $sessionLines = @(& (Join-Path $env:SystemRoot 'System32\qwinsta.exe') 2>&1)
    foreach ($line in $sessionLines) {
        Add-GideonResult 'SESSION_BEFORE' 'QWINSTA' 'OBSERVED' ([string]$line).Trim()
    }
    # Resolve the session by the explicitly authorized Windows account. Session
    # IDs are transient and must never be guessed or hard-coded.
    $targetLine = $sessionLines | Where-Object { [string]$_ -match '(?i)\bgideonsis\b' } | Select-Object -First 1
    if (-not $targetLine -or [string]$targetLine -notmatch '\s+(\d+)\s+(?:Activo|Active|Desc|Disc|Conn|Conectado)\b') {
        throw 'No se encontró una sesión Windows de gideonsis que pueda promoverse.'
    }
    $targetSessionId = [int]$Matches[1]
    $tscon = Join-Path $env:SystemRoot 'System32\tscon.exe'
    $output = @(& $tscon $targetSessionId /dest:console /v 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "tscon terminó con código ${LASTEXITCODE}: $($output -join ' ')"
    }
    Add-GideonResult 'SESSION_SWITCH' 'PromotePendingRdp' 'SUCCESS' (
        'SessionId={0}; Destination=console; Logoff=false; Output={1}' -f $targetSessionId,($output -join ' ')
    )
}
catch {
    Add-GideonResult 'SESSION_SWITCH' 'PromotePendingRdp' 'ERROR' $_.Exception.Message
}

Start-Sleep -Milliseconds 500
try {
    foreach ($line in @(& (Join-Path $env:SystemRoot 'System32\qwinsta.exe') 2>&1)) {
        Add-GideonResult 'SESSION_AFTER' 'QWINSTA' 'OBSERVED' ([string]$line).Trim()
    }
}
catch {
    Add-GideonResult 'SESSION_AFTER' 'QWINSTA' 'ERROR' $_.Exception.Message
}
$rows
