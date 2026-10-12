[CmdletBinding()]
param([string]$InstallRoot='C:\Program Files\GIDEON Remote Control',[string]$DataRoot='C:\ProgramData\GIDEON Remote Control')
$ErrorActionPreference='Continue';Set-StrictMode -Version Latest
$failed=0
function R($n,$ok,$detail=''){if($ok){Write-Host "$n=PASS $detail" -ForegroundColor Green}else{Write-Host "$n=FAIL $detail" -ForegroundColor Red;$script:failed++}}
R 'INSTALL_ROOT' (Test-Path $InstallRoot)
R 'DATA_ROOT' (Test-Path $DataRoot)
$py=Join-Path $InstallRoot 'runtime\python-base\python.exe';if(-not(Test-Path $py)){$py=Join-Path $InstallRoot 'venv\Scripts\python.exe'}
R 'PRIVATE_PYTHON' (Test-Path $py) $py
$resourceProfilePath=Join-Path $DataRoot 'diagnostics\resource-profile.json'
$resourceProfileOk=$false;$resourceProfile=''
if(Test-Path -LiteralPath $resourceProfilePath -PathType Leaf){
  try{$resourceProfile=[string](Get-Content -LiteralPath $resourceProfilePath -Raw|ConvertFrom-Json).selected;$resourceProfileOk=$resourceProfile -in @('compact','standard','performance')}catch{}
}
R 'RESOURCE_PROFILE' $resourceProfileOk $resourceProfile
$serviceHost=Join-Path $InstallRoot 'service-host\GIDEONServiceHost.exe'
$serviceHostVersion=''
if(Test-Path -LiteralPath $serviceHost -PathType Leaf){try{$serviceHostVersion=[string](Get-Item -LiteralPath $serviceHost).VersionInfo.FileVersion}catch{}}
$serviceHostOk=$false
try{$serviceHostOk=([version]$serviceHostVersion -ge [version]'6.3.4.15')}catch{}
R 'RESOURCE_AWARE_SERVICE_HOST' $serviceHostOk $serviceHostVersion
$svcs=@(Get-CimInstance Win32_Service|Where-Object{($_.Name -match '(?i)^GIDEON|GIDEONRemote|RemoteControl') -or (([string]$_.PathName).IndexOf($InstallRoot,[StringComparison]::OrdinalIgnoreCase)-ge 0)})
foreach($s in $svcs){$expect=([string]$s.StartMode -eq 'Auto');if($expect){R ("SERVICE_"+$s.Name) ([string]$s.State -eq 'Running') ([string]$s.State)}}
$orphans=@(Get-CimInstance Win32_Process|Where-Object{([string]$_.ExecutablePath).IndexOf($InstallRoot,[StringComparison]::OrdinalIgnoreCase)-ge 0 -and $_.Name -match '(?i)python' -and $_.ParentProcessId -eq 0})
R 'NO_GIDEON_ORPHANS' ($orphans.Count -eq 0) ("count="+$orphans.Count)
$legacyMaintenance=@(Get-CimInstance Win32_Process|Where-Object{[string]$_.CommandLine -match '(?i)gideon_windows_background\.py\s+(backup|updater)'})
R 'NO_LEGACY_MAINTENANCE_POLLERS' ($legacyMaintenance.Count -eq 0) ("count="+$legacyMaintenance.Count)
$fernet=[Environment]::GetEnvironmentVariable('GIDEON_WEB_TOTP_ENCRYPTION_KEY','Machine');R 'FERNET_KEY_PRESENT' (-not [string]::IsNullOrWhiteSpace($fernet))
$guacdOk=$false
$runtime="$DataRoot\guacd\runtime.json"
if(-not(Test-Path -LiteralPath $runtime)){$runtime="$DataRoot\hyperv\GIDEON-GUACD\runtime.json"}
if(Test-Path -LiteralPath $runtime){try{$g=Get-Content -LiteralPath $runtime -Raw|ConvertFrom-Json;$hostName=if($g.PSObject.Properties['host']){[string]$g.host}else{[string]$g.guest_ip};$tcp=New-Object Net.Sockets.TcpClient;$ar=$tcp.BeginConnect($hostName,[int]$g.port,$null,$null);$guacdOk=$ar.AsyncWaitHandle.WaitOne(1500);if($guacdOk){$tcp.EndConnect($ar)};$tcp.Close()}catch{}}
if((Test-Path -LiteralPath $runtime) -and (Get-Module -ListAvailable Hyper-V)){
  try{
    $runtimeConfig=Get-Content -LiteralPath $runtime -Raw|ConvertFrom-Json
    if([string]$runtimeConfig.backend -eq 'hyperv' -or $runtime -match '(?i)hyperv'){
      $vmMemory=Get-VMMemory -VMName 'GIDEON-GUACD' -ErrorAction Stop
      R 'HYPERV_DYNAMIC_MEMORY' ([bool]$vmMemory.DynamicMemoryEnabled) ("min={0} startup={1} max={2}" -f $vmMemory.Minimum,$vmMemory.Startup,$vmMemory.Maximum)
    }
  }catch{R 'HYPERV_DYNAMIC_MEMORY' $false $_.Exception.Message}
}
if(Get-Command docker.exe -ErrorAction SilentlyContinue){try{$x=& docker.exe ps --filter name=gideon-guacd --format '{{.Names}}' 2>$null;if($x -match 'gideon-guacd'){$guacdOk=$true}}catch{}}
R 'GUACD_PRIVATE' $guacdOk
try{$w32=Get-Service W32Time -ErrorAction Stop;R 'TIME_SERVICE' ($w32.Status -eq 'Running') ([string]$w32.Status)}catch{R 'TIME_SERVICE' $false}
if($failed -eq 0){Write-Host 'FINAL_VERIFY=PASS';$global:LASTEXITCODE=0;return}else{Write-Host "FINAL_VERIFY=FAIL failures=$failed";throw "GIDEON_FINAL_VERIFY_FAILED failures=$failed"}
