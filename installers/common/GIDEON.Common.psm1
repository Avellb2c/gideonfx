Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-GideonUtf8NoBom {
    param(
      [Parameter(Mandatory=$true)][string]$Path,
      [Parameter(Mandatory=$true)][AllowNull()][AllowEmptyString()][string]$Text
    )

    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    if ($null -eq $Text) {
        $Text = ''
    }

    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Text, $enc)
}

function Write-GideonJson {
    param(
      [Parameter(Mandatory=$true)][AllowNull()]$Object,
      [Parameter(Mandatory=$true)][string]$Path,
      [int]$Depth=20
    )

    # IMPORTANT (PowerShell 5.1):
    # Do not pipe an empty array into ConvertTo-Json. The pipeline emits
    # nothing and produces $null/empty output instead of [].
    if ($null -eq $Object) {
        $json = 'null'
    }
    elseif (($Object -is [System.Array]) -and $Object.Count -eq 0) {
        $json = '[]'
    }
    else {
        $json = ConvertTo-Json -InputObject $Object -Depth $Depth
    }

    if ($null -eq $json) {
        throw "JSON_SERIALIZATION_RETURNED_NULL: $Path"
    }

    Write-GideonUtf8NoBom -Path $Path -Text ([string]$json)
}

function ConvertTo-GideonJson {
    param(
      [Parameter(Mandatory=$true)][AllowNull()]$Object,
      [int]$Depth=20,
      [switch]$Compress
    )

    if ($null -eq $Object) {
        return 'null'
    }

    if (($Object -is [System.Array]) -and $Object.Count -eq 0) {
        return '[]'
    }

    if ($Compress) {
        return (ConvertTo-Json -InputObject $Object -Depth $Depth -Compress)
    }

    return (ConvertTo-Json -InputObject $Object -Depth $Depth)
}

function Read-GideonJson {
    param([Parameter(Mandatory=$true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "JSON no encontrado: $Path" }
    return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json)
}

function New-GideonDirectory {
    param([Parameter(Mandatory=$true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
}

function Write-GideonStep {
    param([int]$Index,[int]$Total,[string]$Text)
    $prefix = ('[STEP {0:D2}/{1:D2}]' -f $Index,$Total)
    Write-Host ""; Write-Host "$prefix $Text" -ForegroundColor Cyan
}

function Write-GideonInfo { param([string]$Text) Write-Host "[INFO] $Text" }
function Write-GideonWarn { param([string]$Text) Write-Host "[WARN] $Text" -ForegroundColor Yellow }
function Write-GideonPass { param([string]$Text) Write-Host "[PASS] $Text" -ForegroundColor Green }
function Write-GideonFail { param([string]$Text) Write-Host "[FAIL] $Text" -ForegroundColor Red }

function Test-GideonAdministrator {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $p=New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-GideonSha256 {
    param([Parameter(Mandatory=$true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Invoke-GideonRetry {
    param(
      [Parameter(Mandatory=$true)][scriptblock]$Script,
      [int]$Attempts=6,
      [int]$DelayMilliseconds=500,
      [string]$Label='operation'
    )
    $last=$null
    for($i=1;$i -le $Attempts;$i++){
        try { return & $Script }
        catch {
            $last=$_
            if($i -lt $Attempts){ Start-Sleep -Milliseconds ($DelayMilliseconds*$i) }
        }
    }
    throw "Fallo tras $Attempts intentos en $Label. $($last.Exception.Message)"
}

function New-GideonRandomPassword {
    param([int]$Length=24)
    if($Length -lt 20){$Length=20}
    $alphabet='ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#%_-+=' 
    $rng=[Security.Cryptography.RandomNumberGenerator]::Create()
    try{
        $bytes=New-Object byte[] $Length
        $rng.GetBytes($bytes)
        $chars=New-Object System.Collections.Generic.List[char]
        foreach($b in $bytes){ $chars.Add($alphabet[$b % $alphabet.Length]) }
        $pwd=-join $chars.ToArray()
        return ('A9!'+$pwd.Substring(3))
    } finally { $rng.Dispose() }
}

function Test-GideonTcpPortFree {
    param([int]$Port,[string]$Address='0.0.0.0')
    try{
        $hits=@(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -eq $Port })
        return ($hits.Count -eq 0)
    } catch { return $true }
}

function Get-GideonListeningPorts {
    try{
        return @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Select-Object LocalAddress,LocalPort,OwningProcess)
    }catch{
        $rows=@()
        & netstat.exe -ano -p tcp 2>$null | ForEach-Object {
            if($_ -match '^\s*TCP\s+(\S+):(\d+)\s+\S+\s+LISTENING\s+(\d+)'){
                $rows += [pscustomobject]@{LocalAddress=$matches[1];LocalPort=[int]$matches[2];OwningProcess=[int]$matches[3]}
            }
        }
        return $rows
    }
}

function Stop-GideonTranscriptSafe {
    try { Stop-Transcript | Out-Null } catch {}
}

Export-ModuleMember -Function *
