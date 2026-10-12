#requires -Version 5.1
<#
GIDEON Script Execution Host v3.2

Ejecuta UN payload PowerShell en un proceso aislado. El worker remoto crea este
proceso, controla timeout/cancelación y lee el JSON resultante.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ScriptPath,

    [Parameter(Mandatory=$true)]
    [string]$ParametersPath,

    [Parameter(Mandatory=$true)]
    [string]$ResultPath,

    [Parameter(ValueFromRemainingArguments=$true)]
    [object[]]$ScriptArguments = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Write-Utf8Atomic {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$Text
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'Write-Utf8Atomic received an empty path.'
    }

    # Normalize once. All temp/backup files remain in the same directory/volume,
    # which is required for an atomic File.Replace operation.
    try {
        $fullPath = [IO.Path]::GetFullPath($Path)
    }
    catch {
        throw "Write-Utf8Atomic invalid path '$Path': $($_.Exception.Message)"
    }

    $parent = [IO.Path]::GetDirectoryName($fullPath)
    if ([string]::IsNullOrWhiteSpace($parent)) {
        throw "Write-Utf8Atomic path has no parent directory: $fullPath"
    }

    [IO.Directory]::CreateDirectory($parent) | Out-Null

    $token = '{0}.{1}' -f $PID,([guid]::NewGuid().ToString('N'))
    $tmp = $fullPath + '.tmp.' + $token
    $backup = $null
    $encoding = New-Object System.Text.UTF8Encoding($true)
    $maxAttempts = 8
    $lastError = $null

    [IO.File]::WriteAllText($tmp, $Text, $encoding)

    try {
        for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
            $backup = $null
            try {
                if ([IO.File]::Exists($fullPath)) {
                    # Windows PowerShell 5.1 / .NET Framework can throw
                    # "The path is not of a legal form" when the 4-argument
                    # File.Replace overload receives $null as backup path.
                    #
                    # Use a real, unique backup path on the SAME volume.
                    $backup = $fullPath + '.bak.' + $token + '.' + $attempt
                    [IO.File]::Replace(
                        $tmp,
                        $fullPath,
                        $backup,
                        $true
                    )

                    if ([IO.File]::Exists($backup)) {
                        [IO.File]::Delete($backup)
                    }
                }
                else {
                    [IO.File]::Move($tmp, $fullPath)
                }

                return
            }
            catch {
                $lastError = $_.Exception

                # A failed Replace may have created a backup. Never leave it
                # behind and never reuse a stale backup name.
                if (
                    -not [string]::IsNullOrWhiteSpace($backup) -and
                    [IO.File]::Exists($backup)
                ) {
                    try { [IO.File]::Delete($backup) } catch { }
                }

                # Some filesystem/AV failures may consume the temp file before
                # reporting an exception. Recreate it before retrying.
                if (-not [IO.File]::Exists($tmp)) {
                    [IO.File]::WriteAllText($tmp, $Text, $encoding)
                }

                if ($attempt -lt $maxAttempts) {
                    $delay = [Math]::Min(
                        750,
                        25 * [Math]::Pow(2, ($attempt - 1))
                    )
                    Start-Sleep -Milliseconds ([int]$delay)
                }
            }
        }

        throw $lastError
    }
    finally {
        if ([IO.File]::Exists($tmp)) {
            try { [IO.File]::Delete($tmp) } catch { }
        }

        if (
            -not [string]::IsNullOrWhiteSpace($backup) -and
            [IO.File]::Exists($backup)
        ) {
            try { [IO.File]::Delete($backup) } catch { }
        }
    }
}

function Write-JsonAtomic {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][object]$Value,
        [int]$Depth = 24
    )
    Write-Utf8Atomic -Path $Path -Text ($Value | ConvertTo-Json -Depth $Depth)
}

function ConvertTo-HashtableDeep {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return $null }

    if ($Value -is [System.Collections.IDictionary]) {
        $table = @{}
        foreach ($key in $Value.Keys) {
            $table[[string]$key] = ConvertTo-HashtableDeep -Value $Value[$key]
        }
        return $table
    }

    if ($Value -is [pscustomobject]) {
        $table = @{}
        foreach ($prop in $Value.PSObject.Properties) {
            $table[$prop.Name] = ConvertTo-HashtableDeep -Value $prop.Value
        }
        return $table
    }

    if (($Value -is [System.Collections.IEnumerable]) -and -not ($Value -is [string])) {
        $items = @()
        foreach ($item in $Value) {
            $items += ,(ConvertTo-HashtableDeep -Value $item)
        }
        return $items
    }

    return $Value
}

if (-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) {
    throw "Payload script not found: $ScriptPath"
}

$parameters = @{}
if (Test-Path -LiteralPath $ParametersPath -PathType Leaf) {
    $rawParameters = Get-Content -LiteralPath $ParametersPath -Raw | ConvertFrom-Json
    $converted = ConvertTo-HashtableDeep -Value $rawParameters
    if ($converted -is [hashtable]) { $parameters = $converted }
}

function Clear-GideonPayloadResources {
    # This process exists only for one payload, so every PowerShell job/session
    # found here belongs to that payload and is safe to dispose.
    try {
        Get-Job -ErrorAction SilentlyContinue |
            Stop-Job -ErrorAction SilentlyContinue
    }
    catch {
    }

    try {
        Get-Job -ErrorAction SilentlyContinue |
            Remove-Job -Force -ErrorAction SilentlyContinue
    }
    catch {
    }

    try {
        Get-PSSession -ErrorAction SilentlyContinue |
            Remove-PSSession -ErrorAction SilentlyContinue
    }
    catch {
    }

    try {
        Get-CimSession -ErrorAction SilentlyContinue |
            Remove-CimSession -ErrorAction SilentlyContinue
    }
    catch {
    }

    try {
        Get-EventSubscriber -ErrorAction SilentlyContinue |
            Unregister-Event -Force -ErrorAction SilentlyContinue
    }
    catch {
    }
}

$startedAt = Get-Date
$success = $true
$errorText = $null
$data = @()

try {
    $data = @(& $ScriptPath @parameters @ScriptArguments)
}
catch {
    $success = $false
    $errorText = $_.Exception.Message
}

$finishedAt = Get-Date

$result = [ordered]@{
    Success      = $success
    Error        = $errorText
    HostPid      = $PID
    ScriptPath   = $ScriptPath
    Parameters   = $parameters
    Arguments    = $ScriptArguments
    StartedAt    = $startedAt.ToString('o')
    FinishedAt   = $finishedAt.ToString('o')
    ElapsedSec   = [math]::Round(($finishedAt - $startedAt).TotalSeconds, 3)
    Data         = $data
}

try {
    Write-JsonAtomic -Path $ResultPath -Value $result -Depth 28
}
finally {
    Clear-GideonPayloadResources

    # Release managed wrappers before the dedicated process terminates.
    try {
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
        [GC]::Collect()
    }
    catch {
    }
}

if ($success) { exit 0 }
exit 2
