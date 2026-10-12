#requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
# Keep enough history to diagnose sessions reported after the store has returned
# to operation. Event collection remains read-only and bounded by MaxEvents.
$since = (Get-Date).AddHours(-48)
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
        Kind   = $Kind
        Name   = $Name
        Status = $Status
        Detail = $Detail
        Time   = $Time
    })
}

function Get-GideonRegistryValue {
    param([string]$Path, [string]$Name)
    try {
        return (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name
    }
    catch {
        return $null
    }
}

try {
    $os = Get-CimInstance Win32_OperatingSystem
    Add-GideonRow 'HOST' 'OperatingSystem' 'OK' ("{0}; Version={1}; Build={2}; LastBoot={3:o}; FreeMemoryMB={4}" -f $os.Caption,$os.Version,$os.BuildNumber,$os.LastBootUpTime,[math]::Round($os.FreePhysicalMemory/1024,0))
    $computer = Get-CimInstance Win32_ComputerSystem
    Add-GideonRow 'HOST' 'Capacity' 'OK' ("Processors={0}; LogicalProcessors={1}; MemoryMB={2}" -f $computer.NumberOfProcessors,$computer.NumberOfLogicalProcessors,[math]::Round($computer.TotalPhysicalMemory/1MB,0))
}
catch {
    Add-GideonRow 'HOST' 'OperatingSystem' 'ERROR' $_.Exception.Message
}

foreach ($name in @('GIDEONAgent','TermService','ProfSvc','UserManager','AppReadiness','Schedule','RpcSs')) {
    try {
        $service = Get-Service -Name $name -ErrorAction Stop
        Add-GideonRow 'SERVICE' $name ([string]$service.Status) ("StartType={0}" -f $service.StartType)
    }
    catch {
        Add-GideonRow 'SERVICE' $name 'NOT_FOUND' $_.Exception.Message
    }
}

$tsPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$rdpPath = Join-Path $tsPath 'WinStations\RDP-Tcp'
foreach ($entry in @(
    @($tsPath,'fDenyTSConnections'),
    @($tsPath,'fSingleSessionPerUser'),
    @($rdpPath,'UserAuthentication'),
    @($rdpPath,'SecurityLayer'),
    @($rdpPath,'MinEncryptionLevel'),
    @($rdpPath,'PortNumber')
)) {
    $value = Get-GideonRegistryValue -Path $entry[0] -Name $entry[1]
    Add-GideonRow 'RDP_CONFIG' $entry[1] ($(if ($null -eq $value) {'MISSING'} else {'OK'})) ([string]$value)
}

try {
    $sessionLines = @(& "$env:SystemRoot\System32\quser.exe" 2>&1)
    if (-not $sessionLines) { $sessionLines = @(& "$env:SystemRoot\System32\query.exe" session 2>&1) }
    foreach ($line in $sessionLines) {
        Add-GideonRow 'SESSION' 'QUSER' 'OBSERVED' ([string]$line).Trim()
    }
}
catch {
    Add-GideonRow 'SESSION' 'QUSER' 'ERROR' $_.Exception.Message
}

try {
    foreach ($profile in Get-CimInstance Win32_UserProfile | Sort-Object LastUseTime -Descending | Select-Object -First 12) {
        Add-GideonRow 'PROFILE' ([string]$profile.LocalPath) ($(if ($profile.Loaded) {'LOADED'} else {'UNLOADED'})) ("SID={0}; Status={1}; LastUse={2}" -f $profile.SID,$profile.Status,$profile.LastUseTime)
    }
}
catch {
    Add-GideonRow 'PROFILE' 'Win32_UserProfile' 'ERROR' $_.Exception.Message
}

try {
    $interesting = @('LogonUI','userinit','explorer','dwm','rdpclip','winlogon','sihost','fontdrvhost')
    foreach ($process in Get-CimInstance Win32_Process | Where-Object { $interesting -contains $_.Name.Replace('.exe','') }) {
        $owner = ''
        try {
            $ownerData = Invoke-CimMethod -InputObject $process -MethodName GetOwner -ErrorAction Stop
            $owner = ("{0}\{1}" -f $ownerData.Domain,$ownerData.User).Trim('\')
        }
        catch { }
        Add-GideonRow 'PROCESS' ([string]$process.Name) 'RUNNING' ("Pid={0}; SessionId={1}; Owner={2}; Created={3}" -f $process.ProcessId,$process.SessionId,$owner,$process.CreationDate)
    }
}
catch {
    Add-GideonRow 'PROCESS' 'SessionProcesses' 'ERROR' $_.Exception.Message
}

$logs = @(
    'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
    'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
    'Microsoft-Windows-User Profile Service/Operational'
)
foreach ($logName in $logs) {
    try {
        foreach ($event in Get-WinEvent -FilterHashtable @{LogName=$logName; StartTime=$since} -MaxEvents 80 -ErrorAction Stop) {
            $message = ([string]$event.Message -replace '[\r\n]+',' ' -replace '\s+',' ').Trim()
            if ($message.Length -gt 1200) { $message = $message.Substring(0,1200) }
            Add-GideonRow 'EVENT' ("{0}#{1}" -f $event.ProviderName,$event.Id) ([string]$event.LevelDisplayName) $message ($event.TimeCreated.ToString('o'))
        }
    }
    catch {
        Add-GideonRow 'EVENT_LOG' $logName 'UNAVAILABLE' $_.Exception.Message
    }
}

foreach ($logName in @('Application','System')) {
    try {
        $providers = @('Microsoft-Windows-User Profiles Service','Microsoft-Windows-Winlogon','Microsoft-Windows-TerminalServices-LocalSessionManager','Microsoft-Windows-TerminalServices-RemoteConnectionManager','Microsoft-Windows-GroupPolicy','Application Readiness')
        foreach ($event in Get-WinEvent -FilterHashtable @{LogName=$logName; StartTime=$since; Level=@(1,2,3)} -MaxEvents 200 -ErrorAction Stop | Where-Object { $providers -contains $_.ProviderName }) {
            $message = ([string]$event.Message -replace '[\r\n]+',' ' -replace '\s+',' ').Trim()
            if ($message.Length -gt 1200) { $message = $message.Substring(0,1200) }
            Add-GideonRow 'EVENT' ("{0}#{1}" -f $event.ProviderName,$event.Id) ([string]$event.LevelDisplayName) $message ($event.TimeCreated.ToString('o'))
        }
    }
    catch {
        Add-GideonRow 'EVENT_LOG' $logName 'UNAVAILABLE' $_.Exception.Message
    }
}

$rows
