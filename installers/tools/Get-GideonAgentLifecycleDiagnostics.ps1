#requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$rows = New-Object System.Collections.Generic.List[object]

function Add-GideonRow {
    param(
        [string]$Kind,
        [string]$Name,
        [string]$Status,
        [AllowEmptyString()][string]$Detail = '',
        [AllowEmptyString()][string]$Time = ''
    )
    $rows.Add([pscustomobject]@{
        Kind = $Kind
        Name = $Name
        Status = $Status
        Detail = $Detail
        Time = $Time
    })
}

try {
    $service = Get-CimInstance Win32_Service -Filter "Name='GIDEONAgent'" -ErrorAction Stop
    Add-GideonRow 'SERVICE' 'GIDEONAgent' ([string]$service.State) (
        'StartMode={0}; StartName={1}; ProcessId={2}; ExitCode={3}' -f 
        $service.StartMode,$service.StartName,$service.ProcessId,$service.ExitCode
    )
    if ([int]$service.ProcessId -gt 0) {
        $process = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $service.ProcessId) -ErrorAction Stop
        Add-GideonRow 'PROCESS' ([string]$process.Name) 'RUNNING' (
            'Pid={0}; ParentPid={1}; SessionId={2}; Created={3}' -f
            $process.ProcessId,$process.ParentProcessId,$process.SessionId,$process.CreationDate
        )
        foreach ($child in Get-CimInstance Win32_Process -Filter ("ParentProcessId={0}" -f $service.ProcessId) -ErrorAction SilentlyContinue) {
            Add-GideonRow 'CHILD_PROCESS' ([string]$child.Name) 'RUNNING' (
                'Pid={0}; ParentPid={1}; SessionId={2}; Created={3}' -f
                $child.ProcessId,$child.ParentProcessId,$child.SessionId,$child.CreationDate
            )
        }
    }
}
catch {
    Add-GideonRow 'SERVICE' 'GIDEONAgent' 'ERROR' $_.Exception.Message
}

try {
    $sessionLines = @(& "$env:SystemRoot\System32\quser.exe" 2>&1)
    foreach ($line in $sessionLines) {
        Add-GideonRow 'SESSION' 'QUSER' 'OBSERVED' ([string]$line).Trim()
    }
}
catch {
    Add-GideonRow 'SESSION' 'QUSER' 'ERROR' $_.Exception.Message
}

try {
    $since = (Get-Date).AddHours(-24)
    foreach ($event in Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Service Control Manager'; StartTime=$since} -MaxEvents 400 -ErrorAction Stop) {
        $message = ([string]$event.Message -replace '[\r\n]+',' ' -replace '\s+',' ').Trim()
        if ($message -notmatch '(?i)GIDEONAgent|GIDEON Agent') { continue }
        if ($message.Length -gt 1000) { $message = $message.Substring(0,1000) }
        Add-GideonRow 'SERVICE_EVENT' ("ServiceControlManager#{0}" -f $event.Id) ([string]$event.LevelDisplayName) $message ($event.TimeCreated.ToString('o'))
    }
}
catch {
    Add-GideonRow 'SERVICE_EVENT' 'Service Control Manager' 'ERROR' $_.Exception.Message
}

$rows
