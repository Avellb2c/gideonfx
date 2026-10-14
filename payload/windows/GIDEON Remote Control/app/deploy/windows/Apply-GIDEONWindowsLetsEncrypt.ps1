[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$DataRoot,
  [Parameter(Mandatory=$true)][string]$InstallRoot
)

$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$pythonCandidates=@(
  (Join-Path $InstallRoot 'venv\Scripts\python.exe'),
  (Join-Path $InstallRoot 'runtime\python-base\python.exe'),
  (Join-Path $InstallRoot 'runtime\python\python.exe')
)
$python=$null
foreach($candidate in $pythonCandidates){if(Test-Path -LiteralPath $candidate -PathType Leaf){$python=$candidate;break}}
if(-not $python){$found=Get-Command python.exe -ErrorAction SilentlyContinue;if($found){$python=$found.Source}}
if(-not $python){throw 'No se encontró el runtime Python de GIDEON para el hook ACME.'}
$helper=Join-Path $InstallRoot 'app\deploy\windows\gideon_windows_acme.py'
if(-not(Test-Path -LiteralPath $helper -PathType Leaf)){throw "Helper ACME ausente: $helper"}
& $python $helper renew-hook --data-root $DataRoot --install-root $InstallRoot
if($LASTEXITCODE -ne 0){throw "El hook ACME GIDEON terminó con rc=$LASTEXITCODE."}
