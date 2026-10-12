#requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$since = (Get-Date).AddMinutes(-20)
$rows = New-Object System.Collections.Generic.List[object]

function Add-GideonTrace {
    param(
        [string]$Kind,
        [string]$Name,
        [string]$Status,
        [AllowEmptyString()][string]$Detail = '',
        [AllowEmptyString()][string]$Time = ''
    )
    $rows.Add([pscustomobject]@{
        Kind = $Kind; Name = $Name; Status = $Status; Detail = $Detail; Time = $Time
    })
}

foreach ($command in @('quser.exe','qwinsta.exe')) {
    try {
        $path = Join-Path $env:SystemRoot ("System32\{0}" -f $command)
        foreach ($line in @(& $path 2>&1)) {
            Add-GideonTrace 'SESSION' $command 'OBSERVED' ([string]$line).Trim()
        }
    }
    catch {
        Add-GideonTrace 'SESSION' $command 'ERROR' $_.Exception.Message
    }
}

try {
    Get-CimInstance Win32_UserProfile | Where-Object {
        $_.LocalPath -match '\\Users\\(gideonsis|USER)$'
    } | ForEach-Object {
        Add-GideonTrace 'PROFILE' ([string]$_.LocalPath) ($(if ($_.Loaded) {'LOADED'} else {'UNLOADED'})) (
            "SID={0}; Status={1}; LastUse={2}" -f $_.SID,$_.Status,$_.LastUseTime
        )
    }
}
catch {
    Add-GideonTrace 'PROFILE' 'Win32_UserProfile' 'ERROR' $_.Exception.Message
}

foreach ($name in @('GIDEONAgentServiceHost.exe','python.exe','winlogon.exe','LogonUI.exe','explorer.exe','sihost.exe','dwm.exe')) {
    try {
        Get-CimInstance Win32_Process -Filter ("Name='{0}'" -f $name) | ForEach-Object {
            $owner = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction SilentlyContinue
            $ownerName = if ($owner -and $owner.User) { "{0}\{1}" -f $owner.Domain,$owner.User } else { '-' }
            Add-GideonTrace 'PROCESS' $name 'RUNNING' (
                "Pid={0}; ParentPid={1}; SessionId={2}; Owner={3}; Created={4}" -f $_.ProcessId,$_.ParentProcessId,$_.SessionId,$ownerName,$_.CreationDate
            )
        }
    }
    catch {
        Add-GideonTrace 'PROCESS' $name 'ERROR' $_.Exception.Message
    }
}

$logs = @(
    'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
    'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
    'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational',
    'Microsoft-Windows-User Profiles Service/Operational'
)
foreach ($log in $logs) {
    try {
        Get-WinEvent -FilterHashtable @{LogName=$log; StartTime=$since} -ErrorAction Stop |
            Sort-Object TimeCreated -Descending |
            Select-Object -First 80 |
            ForEach-Object {
                $message = ([string]$_.Message -replace '[\r\n]+',' ' -replace '\s{2,}',' ').Trim()
                Add-GideonTrace 'EVENT' ("{0}#{1}" -f $log,$_.Id) ([string]$_.LevelDisplayName) $message ($_.TimeCreated.ToString('o'))
            }
    }
    catch {
        Add-GideonTrace 'EVENT' $log 'UNAVAILABLE' $_.Exception.Message
    }
}

try {
    Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$since; Id=@(4624,4625,4634,4647,4778,4779)} -ErrorAction Stop |
        Where-Object { [string]$_.Message -match '(?i)gideonsis|127\.0\.0\.1|RemoteInteractive|TerminalServices' } |
        Sort-Object TimeCreated -Descending |
        Select-Object -First 80 |
        ForEach-Object {
            $message = ([string]$_.Message -replace '[\r\n]+',' ' -replace '\s{2,}',' ').Trim()
            # Event data contains account names and addresses but never the password.
            Add-GideonTrace 'SECURITY_EVENT' ("Security#{0}" -f $_.Id) ([string]$_.LevelDisplayName) $message ($_.TimeCreated.ToString('o'))
        }
}
catch {
    Add-GideonTrace 'SECURITY_EVENT' 'Security' 'UNAVAILABLE' $_.Exception.Message
}

$rows
