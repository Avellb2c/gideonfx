[CmdletBinding()]
param(
  [string]$InstallRoot='C:\Program Files\GIDEON Remote Control',
  [string]$DataRoot='C:\ProgramData\GIDEON Remote Control',
  [ValidateSet('fresh','clone')][string]$InstallMode='fresh',
  [bool]$EnableHyperVIfMissing=$true,
  [switch]$SkipGuacd
)

$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$BundleRoot=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$Common=Join-Path $BundleRoot 'installers\common\GIDEON.Common.psm1'
Import-Module $Common -Force
$ManifestPath=Join-Path $BundleRoot 'deployment.manifest.json'
$ConfigPath=Join-Path $BundleRoot 'master.config.json'
$manifest=Read-GideonJson $ManifestPath
$cfg=Read-GideonJson $ConfigPath
$InstallerRevision='20261014-service-assets-20261014'
$stage='INIT';$backup=$null;$mutex=$null;$transcriptStarted=$false;$credFile=$null
$machineIdentity='';$bootstrapMarker='';$newMachine=$false
$guacdBackend='none';$resumeTaskName='GIDEON Remote Control Master Installer Resume'
$resourceProfile='standard';$EffectiveConfigPath=$ConfigPath;$GideonServiceHostExe=''
$GideonAgentInstallRoot=''

function Fail([string]$m,[int]$c=1){throw (New-Object System.Exception("GIDEON_INSTALL_FAIL[$c]: $m"))}
function Ensure-GideonWindowsTime {
  if(-not [bool]$cfg.security.require_time_sync){
    Write-GideonInfo 'WINDOWS_TIME=SKIP require_time_sync=false'
    return
  }

  try{
    $w32=Get-Service -Name 'W32Time' -ErrorAction Stop
  }catch{
    Fail "WINDOWS_TIME_SERVICE_MISSING: Windows Time (W32Time) no esta disponible. Repare el componente antes de instalar. detail=$($_.Exception.Message)" 16
  }

  if($w32.Status -ne 'Running'){
    Write-GideonWarn "Windows Time esta $($w32.Status). OneClick lo configurara e iniciara."
    try{
      Set-Service -Name 'W32Time' -StartupType Automatic -ErrorAction Stop
      Start-Service -Name 'W32Time' -ErrorAction Stop
      $w32=Get-Service -Name 'W32Time' -ErrorAction Stop
      $w32.WaitForStatus(
        [System.ServiceProcess.ServiceControllerStatus]::Running,
        [TimeSpan]::FromSeconds(15)
      )
      $w32.Refresh()
    }catch{
      $current=Get-Service -Name 'W32Time' -ErrorAction SilentlyContinue
      $status=if($current){[string]$current.Status}else{'Missing'}
      Fail "WINDOWS_TIME_REMEDIATION_FAILED: OneClick no pudo habilitar/iniciar W32Time. status=$status detail=$($_.Exception.Message)" 16
    }
  }

  $w32=Get-Service -Name 'W32Time' -ErrorAction SilentlyContinue
  if(-not $w32 -or $w32.Status -ne 'Running'){
    $status=if($w32){[string]$w32.Status}else{'Missing'}
    Fail "WINDOWS_TIME_NOT_RUNNING: MFA/TLS requieren hora confiable. status=$status" 16
  }

  $resyncOutput=''
  try{
    $resyncOutput=((& w32tm.exe /resync /nowait 2>&1 | Out-String).Trim())
    if($LASTEXITCODE -ne 0){
      Write-GideonWarn "WINDOWS_TIME_RESYNC=DEFERRED rc=$LASTEXITCODE detail=$resyncOutput"
    }
  }catch{
    Write-GideonWarn "WINDOWS_TIME_RESYNC=DEFERRED detail=$($_.Exception.Message)"
  }

  $source='unknown'
  try{
    $queried=((& w32tm.exe /query /source 2>&1 | Out-String).Trim())
    if($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($queried)){$source=$queried}
  }catch{}
  Write-GideonPass "WINDOWS_TIME=PASS status=Running source=$source"
}
function Replace-IgnoreCase([string]$Text,[string]$Old,[string]$New){return [regex]::Replace($Text,[regex]::Escape($Old),[System.Text.RegularExpressions.MatchEvaluator]{param($m)$New},[Text.RegularExpressions.RegexOptions]::IgnoreCase)}
function Robocopy-OrFail([string]$Source,[string]$Dest,[string[]]$Extra){
  New-GideonDirectory $Dest
  $args=@($Source,$Dest,'/E','/R:5','/W:2','/XJ','/NFL','/NDL','/NP')+$Extra
  & robocopy.exe @args | Out-Null
  $rc=$LASTEXITCODE
  if($rc -ge 8){Fail "robocopy rc=$rc source=$Source dest=$Dest" 50}
}
function Set-GideonRelocatedVenvBinding([string]$Root){
  $venvRoot=Join-Path $Root 'venv'
  $cfgPath=Join-Path $venvRoot 'pyvenv.cfg'
  $venvPython=Join-Path $venvRoot 'Scripts\python.exe'
  $privateBase=Join-Path $Root 'runtime\python-base'
  $privatePython=Join-Path $privateBase 'python.exe'
  if(-not(Test-Path -LiteralPath $cfgPath -PathType Leaf)){return}
  if(-not(Test-Path -LiteralPath $privatePython -PathType Leaf)){Fail "Runtime Python base ausente: $privatePython" 21}
  # El archivo existente puede conservar una ACL individual o estar protegido
  # por una política que bloquea File.WriteAllText aunque el árbol ya haya
  # sido normalizado. Se toma como plantilla el archivo del bundle y se
  # reemplaza mediante Robocopy /ZB, que es el mismo canal protegido usado en
  # el despliegue y el backup.
  $templateCfg=Join-Path $BundleRoot 'payload\windows\GIDEON Remote Control\venv\pyvenv.cfg'
  if(-not(Test-Path -LiteralPath $templateCfg -PathType Leaf)){Fail "Plantilla pyvenv.cfg ausente: $templateCfg" 21}
  $lines=@(Get-Content -LiteralPath $templateCfg)
  $seenHome=$false;$seenExecutable=$false;$seenCommand=$false
  $updated=@(
    foreach($line in $lines){
      if($line -match '(?i)^\s*home\s*='){$seenHome=$true;"home = $privateBase";continue}
      if($line -match '(?i)^\s*executable\s*='){$seenExecutable=$true;"executable = $privatePython";continue}
      if($line -match '(?i)^\s*command\s*='){$seenCommand=$true;"command = $privatePython -m venv $venvRoot";continue}
      $line
    }
  )
  if(-not $seenHome){$updated += "home = $privateBase"}
  if(-not $seenExecutable){$updated += "executable = $privatePython"}
  if(-not $seenCommand){$updated += "command = $privatePython -m venv $venvRoot"}
  Repair-GideonWritableFile $cfgPath
  $cfgText=($updated -join [Environment]::NewLine)
  $cfgStage=Join-Path ([IO.Path]::GetTempPath()) ('gideon-pyvenv-'+[guid]::NewGuid().ToString('N'))
  try{
    New-GideonDirectory $cfgStage
    Write-GideonUtf8NoBom -Path (Join-Path $cfgStage 'pyvenv.cfg') -Text $cfgText
    try{
      # Direct replacement is deterministic once the individual ACL has been
      # repaired; keep protected Robocopy as a fallback for locked legacy files.
      Write-GideonUtf8NoBom -Path $cfgPath -Text $cfgText
    }catch{
      Robocopy-OrFail $cfgStage $venvRoot @('/ZB','/IS','/IT')
    }
  }finally{
    Remove-Item -LiteralPath $cfgStage -Recurse -Force -ErrorAction SilentlyContinue
  }
  $cfgVerify=(Get-Content -LiteralPath $cfgPath -Raw -ErrorAction Stop)
  if($cfgVerify -notmatch [regex]::Escape($privateBase)){Fail "No se pudo persistir el binding privado de pyvenv.cfg en $cfgPath" 21}
  # El ejecutable del venv también puede conservar una ACL individual del
  # despliegue anterior. Normalizarlo antes de invocarlo evita que PowerShell
  # devuelva "Program failed to run: Access is denied" aunque el cfg ya esté
  # corregido.
  Repair-GideonWritableFile $venvPython
  Repair-GideonWritableFile $privatePython
  $probeOutput=(& $venvPython -c "import os,sys; print(os.path.abspath(sys.base_prefix))" 2>&1|Out-String).Trim()
  $probeRc=$LASTEXITCODE
  $basePrefix=$probeOutput
  if($probeRc -ne 0 -or -not $basePrefix.Equals([IO.Path]::GetFullPath($privateBase),[StringComparison]::OrdinalIgnoreCase)){
    Fail "El venv no quedó ligado al runtime privado. rc=$probeRc Esperado=$privateBase Actual=$basePrefix" 21
  }
  Write-GideonPass "VENV_RELOCATION=PASS base=$basePrefix"
}
function Stop-GideonServices {
  $names=@($manifest.services|ForEach-Object{[string]$_.name})
  foreach($n in $names){$s=Get-Service -Name $n -ErrorAction SilentlyContinue;if($s -and $s.Status -ne 'Stopped'){Write-GideonInfo "Stop $n";Stop-Service $n -Force -ErrorAction SilentlyContinue}}
  $deadline=(Get-Date).AddSeconds(45)
  while((Get-Date)-lt $deadline){$running=@($names|ForEach-Object{Get-Service -Name $_ -ErrorAction SilentlyContinue}|Where-Object{$_.Status -ne 'Stopped'});if($running.Count -eq 0){break};Start-Sleep -Seconds 1}
}
function Cleanup-GideonOrphans {
  if(-not [bool]$cfg.windows.cleanup_gideon_orphan_processes){return}
  $ps=@(Get-CimInstance Win32_Process|Where-Object{(([string]$_.ExecutablePath).IndexOf($InstallRoot,[StringComparison]::OrdinalIgnoreCase)-ge 0) -or (([string]$_.CommandLine).IndexOf($InstallRoot,[StringComparison]::OrdinalIgnoreCase)-ge 0)})
  foreach($p in $ps){
    try{Write-GideonWarn "Terminando proceso GIDEON huérfano PID=$($p.ProcessId) $($p.Name)";Stop-Process -Id ([int]$p.ProcessId) -Force -ErrorAction Stop}catch{}
  }
  Start-Sleep -Seconds 2
}
function Set-JsonPropertyIfPresent($Object,[string]$Name,$Value){if($Object.PSObject.Properties.Name -contains $Name){$Object.$Name=$Value;return $true};return $false}
function Get-JsonPropertyOrDefault($Object,[string]$Name,$DefaultValue){$p=$Object.PSObject.Properties[$Name];if($p -and $null -ne $p.Value){return $p.Value};return $DefaultValue}
function Save-Json($obj,[string]$path){Write-GideonJson $obj $path 30}
function Write-GideonDiagnosticJson {
  param(
    [Parameter(Mandatory=$true)]$Object,
    [Parameter(Mandatory=$true)][string]$Path,
    [int]$Depth=20
  )
  try{
    Write-GideonJson $Object $Path $Depth
    return $Path
  }catch{
    # Los diagnósticos no deben bloquear una instalación tras un rollback que
    # dejó un archivo protegido. Se conserva una copia temporal local; no se
    # relajan permisos de DPP ni se ignora un error de configuración funcional.
    $fallback=Join-Path ([IO.Path]::GetTempPath()) ('GIDEON-diagnostics-'+[guid]::NewGuid().ToString('N')+'-'+[IO.Path]::GetFileName($Path))
    Write-GideonJson $Object $fallback $Depth
    Write-GideonWarn "Diagnóstico no escribible en $Path; se guardó temporalmente en $fallback."
    return $fallback
  }
}
function Resolve-GideonDiagnosticDirectory {
  $preferred=Join-Path $DataRoot 'diagnostics'
  $probe=Join-Path $preferred ('.write-probe-'+[guid]::NewGuid().ToString('N'))
  try{
    New-GideonDirectory $preferred
    [IO.File]::WriteAllText($probe,'ok',(New-Object System.Text.UTF8Encoding($false)))
    Remove-Item -LiteralPath $probe -Force -ErrorAction Stop
    return $preferred
  }catch{
    $fallback=Join-Path ([IO.Path]::GetTempPath()) ('GIDEON-diagnostics-runtime-'+[guid]::NewGuid().ToString('N'))
    New-GideonDirectory $fallback
    Write-GideonWarn "Diagnostics no escribible en $preferred; se usarán archivos temporales en $fallback."
    return $fallback
  }
}
function Repair-GideonWritableTree {
  param([Parameter(Mandatory=$true)][string]$Root)
  New-GideonDirectory $Root
  # /inheritance:r se aplica sólo a la raíz. Aplicarlo con /T a cada archivo
  # elimina la herencia de las DLL y puede dejar una DACL vacía (STATUS_ACCESS_DENIED
  # al cargar Python). Los hijos se corrigen por herencia desde esta raíz.
  $grant=@($Root,'/inheritance:r','/grant:r','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F','/C','/Q')
  try{
    # Tomar posesión antes del reset permite reparar archivos que quedaron
    # bajo un propietario o ACL de un servicio eliminado.
    & takeown.exe '/F' $Root '/R' '/D' 'Y' | Out-Null
    $takeRc=$LASTEXITCODE
    if($takeRc -ne 0){Write-GideonWarn "TAKEOWN GIDEON tree rc=$takeRc; se continúa con la ACL explícita."}
    # Robocopy preserva las ACL existentes en archivos que ya están en el
    # destino. Un rollback puede haber dejado DENY explícitos que /grant:r no
    # elimina; resetear primero el árbol Gideon evita que el runtime quede
    # bloqueado antes de que Apply-Acls vuelva a aplicar las identidades de
    # servicio en el paso 10.
    & icacls.exe $Root '/reset' '/T' '/C' '/Q' | Out-Null
    $resetRc=$LASTEXITCODE
    if($resetRc -ne 0){Write-GideonWarn "RESET ACL GIDEON tree rc=$resetRc; se continuará con la ACL explícita."}
    # Se ejecuta siempre: icacls puede devolver 0 aun cuando no pudo procesar
    # entradas protegidas. El alcance queda limitado al árbol solicitado.
    & icacls.exe @grant | Out-Null
    $aclRc=$LASTEXITCODE
    if($aclRc -ne 0){Write-GideonWarn "ACL de GIDEON tree rc=$aclRc; se intentará escribir igualmente."}
  }catch{Write-GideonWarn "No se pudo ajustar ACL del árbol GIDEON: $($_.Exception.Message)"}
}
function Repair-GideonWritableFile {
  param([Parameter(Mandatory=$true)][string]$Path)
  if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){return}
  try{
    & takeown.exe '/F' $Path '/A' | Out-Null
    $takeRc=$LASTEXITCODE
    if($takeRc -ne 0){Write-GideonWarn "TAKEOWN GIDEON file rc=$takeRc path=$Path"}
    & icacls.exe $Path '/reset' '/C' '/Q' | Out-Null
    $resetRc=$LASTEXITCODE
    if($resetRc -ne 0){Write-GideonWarn "RESET ACL GIDEON file rc=$resetRc path=$Path"}
    & icacls.exe $Path '/inheritance:r' '/grant:r' '*S-1-5-18:F' '*S-1-5-32-544:F' '/C' '/Q' | Out-Null
    $aclRc=$LASTEXITCODE
    if($aclRc -ne 0){Write-GideonWarn "ACL GIDEON file rc=$aclRc path=$Path"}
  }catch{Write-GideonWarn "No se pudo ajustar ACL del archivo GIDEON $Path`: $($_.Exception.Message)"}
}
function Repair-GideonDiagnosticsAccess {
  # Un rollback anterior puede dejar diagnostics con una ACL exclusiva del
  # Service SID. Reparamos sólo ese árbol GIDEON, sin tocar DPP.
  Repair-GideonWritableTree (Join-Path $DataRoot 'diagnostics')
}
function Set-GideonAdaptiveResourceProfile {
  $computer=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
  $memory=[uint64]$computer.TotalPhysicalMemory
  $logicalProcessors=[int]$computer.NumberOfLogicalProcessors
  $requested=[string]$env:GIDEON_RESOURCE_PROFILE
  $selectionSource='environment'
  if([string]::IsNullOrWhiteSpace($requested)){
    $requested=[string](Get-JsonPropertyOrDefault $cfg.windows 'resource_profile' 'auto')
    $selectionSource='configuration'
  }
  $requested=$requested.Trim().ToLowerInvariant()
  if([string]::IsNullOrWhiteSpace($requested)){$requested='auto'}
  if($requested -notin @('auto','compact','standard','performance')){
    Fail "RESOURCE_PROFILE_INVALID: $requested" 15
  }
  if($requested -eq 'auto'){
    $selectionSource='automatic'
    if($memory -ge [uint64]32GB -and $logicalProcessors -ge 8){$selected='performance'}
    elseif($memory -ge [uint64]16GB){$selected='standard'}
    else{$selected='compact'}
  }else{$selected=$requested}

  if($selected -eq 'performance' -and ($memory -lt [uint64]16GB -or $logicalProcessors -lt 4)){
    Fail "RESOURCE_PROFILE_CAPACITY_MISMATCH: performance requiere al menos 16GB/4 CPU logicos. memory_gb=$([math]::Round($memory/1GB,2)) cpu=$logicalProcessors" 15
  }
  if($selected -eq 'standard' -and $memory -lt [uint64]12GB){
    Fail "RESOURCE_PROFILE_CAPACITY_MISMATCH: standard requiere al menos 12GB. memory_gb=$([math]::Round($memory/1GB,2))" 15
  }

  $settings=switch($selected){
    'compact' {[ordered]@{vm_start_mb=1536;vm_min_mb=768;vm_max_mb=1536;vm_cpu=1;container_memory='768m';container_cpus='1.0'}}
    'standard' {[ordered]@{vm_start_mb=1536;vm_min_mb=1024;vm_max_mb=2048;vm_cpu=1;container_memory='1024m';container_cpus='1.0'}}
    'performance' {[ordered]@{vm_start_mb=2048;vm_min_mb=1536;vm_max_mb=4096;vm_cpu=2;container_memory='1536m';container_cpus='2.0'}}
  }
  $cfg.windows.resource_profile=$selected
  $h=$cfg.windows.hyperv
  $h.dynamic_memory_enabled=$true
  $h.vm_memory_mb=[int]$settings.vm_start_mb
  $h.vm_memory_min_mb=[int]$settings.vm_min_mb
  $h.vm_memory_max_mb=[int]$settings.vm_max_mb
  $h.vm_memory_buffer_percent=20
  $h.vm_cpu_count=[int]$settings.vm_cpu
  $h.guacd_container_memory=[string]$settings.container_memory
  $h.guacd_container_cpus=[string]$settings.container_cpus
  $docker=$cfg.windows.docker_desktop
  $docker.guacd_memory=[string]$settings.container_memory
  $docker.guacd_cpus=[string]$settings.container_cpus

  $script:resourceProfile=$selected
  $script:EffectiveConfigPath=Join-Path $DataRoot 'diagnostics\effective-master.config.json'
  $script:EffectiveConfigPath=Write-GideonDiagnosticJson $cfg $script:EffectiveConfigPath 30
  [void](Write-GideonDiagnosticJson `
    ([ordered]@{
      schema_version=1
      selected=$selected
      selection_source=$selectionSource
      host_memory_bytes=$memory
      host_logical_processors=$logicalProcessors
      hyperv_dynamic_memory=$true
      hyperv_startup_mb=[int]$settings.vm_start_mb
      hyperv_minimum_mb=[int]$settings.vm_min_mb
      hyperv_maximum_mb=[int]$settings.vm_max_mb
      hyperv_processors=[int]$settings.vm_cpu
      guacd_container_memory=[string]$settings.container_memory
      guacd_container_cpus=[string]$settings.container_cpus
      maintenance_mode='event-driven'
      generated_utc=[DateTime]::UtcNow.ToString('o')
    }) `
    (Join-Path $DataRoot 'diagnostics\resource-profile.json') `
    10)
  Write-GideonPass "RESOURCE_PROFILE=PASS selected=$selected source=$selectionSource hyperv=$([int]$settings.vm_min_mb)/$([int]$settings.vm_start_mb)/$([int]$settings.vm_max_mb)MB guacd=$([string]$settings.container_memory)/$([string]$settings.container_cpus)CPU"
}
function Build-GideonOptimizedServiceHost {
  $source=Join-Path $InstallRoot 'app\deploy\windows\GIDEONServiceHost.cs'
  if(-not(Test-Path -LiteralPath $source -PathType Leaf)){Fail "Código fuente GIDEONServiceHost ausente: $source" 72}
  $hostDir=Join-Path $InstallRoot 'service-host'
  New-GideonDirectory $hostDir
  $hostExe=Join-Path $hostDir 'GIDEONServiceHost.exe'
  $candidates=@(
    (Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'),
    (Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe')
  )
  $csc=$candidates|Where-Object{Test-Path -LiteralPath $_ -PathType Leaf}|Select-Object -First 1
  if(-not $csc){Fail 'Compilador .NET Framework csc.exe ausente; no se puede construir el host optimizado.' 72}
  $temporary=$hostExe+'.new-'+[guid]::NewGuid().ToString('N')
  try{
    & $csc '/nologo' '/target:exe' '/optimize+' '/debug-' (('/out:{0}' -f $temporary)) '/reference:System.ServiceProcess.dll' $source
    if($LASTEXITCODE -ne 0 -or -not(Test-Path -LiteralPath $temporary -PathType Leaf)){Fail "Compilación GIDEONServiceHost falló rc=$LASTEXITCODE" 72}
    Move-Item -LiteralPath $temporary -Destination $hostExe -Force
  }finally{Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue}
  $script:GideonServiceHostExe=$hostExe
  Write-GideonPass "SERVICE_HOST_BUILD=PASS path=$hostExe bytes=$((Get-Item -LiteralPath $hostExe).Length)"
}
function Find-FreePort([int]$Preferred,[int]$MaxOffset=50){for($p=$Preferred;$p -le ($Preferred+$MaxOffset);$p++){if(Test-GideonTcpPortFree $p){return $p}};Fail "No hay puerto libre desde $Preferred" 60}
function Get-PortOwnerPath([int]$Port){
  try{$c=Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction Stop|Select-Object -First 1;if($c){$p=Get-CimInstance Win32_Process -Filter "ProcessId=$($c.OwningProcess)" -ErrorAction SilentlyContinue;return [string]$p.ExecutablePath}}catch{};return ''
}
function Resolve-InternalPort([int]$Preferred){
  if(Test-GideonTcpPortFree $Preferred){return $Preferred}
  $owner=Get-PortOwnerPath $Preferred
  if($owner -and $owner.IndexOf($InstallRoot,[StringComparison]::OrdinalIgnoreCase)-ge 0){return $Preferred}
  $new=Find-FreePort ($Preferred+1) 100
  Write-GideonWarn "Puerto $Preferred ocupado por tercero ($owner). GIDEON usará $new sin detenerlo."
  return $new
}
function Test-Web([string]$Url){
  $old=[Net.ServicePointManager]::ServerCertificateValidationCallback
  try{
    [Net.ServicePointManager]::ServerCertificateValidationCallback={param($sender,$cert,$chain,$errors) $true}
    $r=Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 8 -ErrorAction Stop
    return ($r.StatusCode -ge 200 -and $r.StatusCode -lt 500)
  }catch{return $false}finally{[Net.ServicePointManager]::ServerCertificateValidationCallback=$old}
}
function Ensure-GideonLocalAgentPayload([int]$GatewayPort) {
  $agentRoot=Join-Path ${env:ProgramFiles} 'GIDEONAgent'
  $sourceApp=Join-Path $InstallRoot 'app'
  $sourceHost=Join-Path $sourceApp 'deploy\agent\windows\prebuilt\GIDEONAgentServiceHost.exe'
  $runtimeSource=Join-Path $InstallRoot 'runtime\python-base'
  if(-not(Test-Path -LiteralPath $sourceHost -PathType Leaf)){Fail "Host GIDEONAgent ausente: $sourceHost" 73}
  if(-not(Test-Path -LiteralPath $runtimeSource -PathType Container)){Fail "Runtime Python base ausente para GIDEONAgent: $runtimeSource" 73}
  New-GideonDirectory $agentRoot
  # The master payload already contains the complete Agent Python tree. Copy
  # it into the Agent's canonical service root; its data/identity stays under
  # ProgramData\GIDEONAgent and is never mixed with WebAdmin state.
  Robocopy-OrFail $sourceApp $agentRoot @('/ZB')
  Copy-Item -LiteralPath $sourceHost -Destination (Join-Path $agentRoot 'GIDEONAgentServiceHost.exe') -Force
  $runtimeRoot=Join-Path $agentRoot 'runtime'
  $runtimePython=Join-Path $runtimeRoot 'python'
  New-GideonDirectory $runtimeRoot
  if(-not(Test-Path -LiteralPath (Join-Path $runtimePython 'python.exe') -PathType Leaf)){
    try{
      if(Test-Path -LiteralPath $runtimePython){Remove-Item -LiteralPath $runtimePython -Recurse -Force -ErrorAction Stop}
      New-Item -ItemType Junction -Path $runtimePython -Target $runtimeSource -Force -ErrorAction Stop | Out-Null
    }catch{
      Robocopy-OrFail $runtimeSource $runtimePython @('/ZB')
    }
  }
  if(-not(Test-Path -LiteralPath (Join-Path $runtimePython 'python.exe') -PathType Leaf)){Fail "Runtime Python del Agent no disponible: $runtimePython" 73}

  $agentData=Join-Path ${env:ProgramData} 'GIDEONAgent';New-GideonDirectory $agentData
  $enroll=''
  $envFile=Join-Path $DataRoot 'secrets\gateway.env'
  if(Test-Path -LiteralPath $envFile){
    foreach($line in @(Get-Content -LiteralPath $envFile -ErrorAction SilentlyContinue)){
      if($line -match '^GIDEON_AGENT_ENROLL_SECRET=(.+)$'){$enroll=$Matches[1].Trim();break}
    }
  }
  if([string]::IsNullOrWhiteSpace($enroll)){Fail 'No se pudo resolver GIDEON_AGENT_ENROLL_SECRET para el Agent local.' 73}
  $agentConfig=[ordered]@{
    schema_version=2
    site_code='GIDEON-SERVER'
    site_name=[string]$env:COMPUTERNAME
    agent_name=(([string]$env:COMPUTERNAME)+'-server')
    data_dir=$agentData
    poll_seconds=5
    status_seconds=5
    cancel_grace_seconds=8
    enrollment_secret=$enroll
    control_plane=[ordered]@{
      base_url=("https://127.0.0.1:{0}" -f $GatewayPort)
      require_https=$true
      verify_tls=$true
      ca_file=(Join-Path $DataRoot 'pki\root\gideon-root-ca.pem')
      timeout_seconds=20
    }
  }
  Save-Json $agentConfig (Join-Path $agentRoot 'agent.json')
  & icacls.exe $agentRoot '/grant:r' '*S-1-5-18:(OI)(CI)RX' '*S-1-5-32-544:(OI)(CI)F' '/C' '/Q' | Out-Null
  & icacls.exe $agentData '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '/C' '/Q' | Out-Null
  $script:GideonAgentInstallRoot=$agentRoot
  Write-GideonPass "AGENT_LOCAL_PAYLOAD=PASS root=$agentRoot runtime=$runtimePython"
}
function Configure-GideonService($svc){
  $name=[string]$svc.name;$srcRoot=[string]$manifest.source.install_root
  if($name -eq 'GIDEONAgent'){
    if([string]::IsNullOrWhiteSpace($GideonAgentInstallRoot)){Fail 'Payload local de GIDEONAgent no preparado.' 73}
    $agentHost=Join-Path $GideonAgentInstallRoot 'GIDEONAgentServiceHost.exe'
    if(-not(Test-Path -LiteralPath $agentHost -PathType Leaf)){Fail "Host GIDEONAgent no disponible: $agentHost" 73}
    $bin=('"{0}"' -f $agentHost)
  }
  elseif($name -match '^GIDEONRemoteControl(?:Gateway|WebAdmin|Backup|Updater|Diagnostics)?$'){
    if([string]::IsNullOrWhiteSpace($GideonServiceHostExe) -or -not(Test-Path -LiteralPath $GideonServiceHostExe -PathType Leaf)){Fail "Host optimizado no disponible para $name" 72}
    $bin=('"{0}" {1}' -f $GideonServiceHostExe,$name)
  }else{
    $bin=Replace-IgnoreCase ([string]$svc.path_name) $srcRoot $InstallRoot
  }
  $startName=[string]$svc.start_name
  $allowedBuiltIn=@('LocalSystem','NT AUTHORITY\LocalService','NT AUTHORITY\NetworkService','LocalService','NetworkService')
  $existing=Get-Service -Name $name -ErrorAction SilentlyContinue
  if(-not $existing -and $allowedBuiltIn -notcontains $startName){Fail "Servicio $name usa cuenta personalizada $startName; se requiere reprovisionar credencial de servicio." 70}
  if(-not $existing){
    Write-GideonInfo "Creando servicio $name"
    $obj=$startName
    if($obj -eq 'LocalService'){$obj='NT AUTHORITY\LocalService'}
    if($obj -eq 'NetworkService'){$obj='NT AUTHORITY\NetworkService'}

    # New-Service recibe BinaryPathName como una cadena única y evita que
    # PowerShell 5/7 reinterprete las comillas de rutas con espacios al
    # invocar sc.exe (que producía ERROR_INVALID_COMMAND_LINE=1639).
    $newService=@{
      Name=$name
      BinaryPathName=$bin
      DisplayName=([string]$svc.display_name)
      StartupType='Manual'
      ErrorAction='Stop'
    }
    if($obj -eq 'LocalSystem'){
      New-Service @newService | Out-Null
    }else{
      # Las cuentas integradas no requieren una contraseña interactiva. Se
      # mantiene la validación de cuentas permitidas y se crea con la misma
      # identidad que declaraba el manifiesto.
      $emptyPassword=New-Object System.Security.SecureString
      $newService.Credential=New-Object System.Management.Automation.PSCredential($obj,$emptyPassword)
      New-Service @newService | Out-Null
    }
  }
  else {
    # Actualización idempotente sin volver a serializar binPath mediante
    # sc.exe. El Service Control Manager lee estos valores del registro al
    # iniciar el servicio y se conservan los locks/servicios existentes.
    $svcKey="HKLM:\SYSTEM\CurrentControlSet\Services\$name"
    if(-not (Test-Path -LiteralPath $svcKey)){Fail "Registro del servicio $name no encontrado" 72}
    Set-ItemProperty -LiteralPath $svcKey -Name ImagePath -Value $bin -ErrorAction Stop
    Set-ItemProperty -LiteralPath $svcKey -Name DisplayName -Value ([string]$svc.display_name) -ErrorAction Stop
  }

  $mode=[string]$svc.start_mode
  if($mode -eq 'Disabled'){
    & sc.exe config $name 'start=' 'disabled' | Out-Null
  }
  elseif($mode -eq 'Manual'){
    & sc.exe config $name 'start=' 'demand' | Out-Null
  }
  else {
    & sc.exe config $name 'start=' 'auto' | Out-Null
  }

  $deps=@($svc.dependencies | ForEach-Object {[string]$_} | Where-Object {$_})
  if($deps.Count -gt 0){
    $depValue=($deps -join '/')
    & sc.exe config $name 'depend=' $depValue | Out-Null
  }

  if([string]$svc.description){
    & sc.exe description $name ([string]$svc.description) | Out-Null
  }

  if([int]$svc.delayed_auto_start -eq 1 -and $mode -eq 'Auto'){
    New-ItemProperty `
      -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$name" `
      -Name DelayedAutoStart `
      -Value 1 `
      -PropertyType DWord `
      -Force | Out-Null
  }

  & sc.exe sidtype $name unrestricted | Out-Null
  & sc.exe failure $name `
    'reset=' '86400' `
    'actions=' 'restart/10000/restart/30000/restart/60000' | Out-Null
  & sc.exe failureflag $name 1 | Out-Null
}
function Apply-Acls {
  foreach($p in @($InstallRoot,$DataRoot)){New-GideonDirectory $p}
  # Restablecer primero reactiva la herencia de los archivos que provienen de
  # una instalación anterior. Las ACL restrictivas se fijan sólo en la raíz;
  # /T junto con /inheritance:r en archivos deja DLLs sin DACL.
  & icacls.exe $InstallRoot '/reset' '/T' '/C' '/Q'|Out-Null
  & icacls.exe $InstallRoot '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' '/C' '/Q'|Out-Null
  & icacls.exe $DataRoot '/reset' '/T' '/C' '/Q'|Out-Null
  & icacls.exe $DataRoot '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '/C' '/Q'|Out-Null
  $dirs=@('config','data','logs','security','security\yara','secrets','web','updates','uploads','quarantine','remote_sessions','backups','diagnostics','hyperv')
  foreach($d in $dirs){New-GideonDirectory (Join-Path $DataRoot $d)}
  foreach($svc in @($manifest.services)){
    $n=[string]$svc.name
    try{& icacls.exe $InstallRoot '/grant' "NT SERVICE\${n}:(OI)(CI)RX" '/C' '/Q'|Out-Null}catch{}
    try{& icacls.exe $DataRoot '/grant' "NT SERVICE\${n}:(OI)(CI)M" '/C' '/Q'|Out-Null}catch{}
    if($n -match '(?i)Updater') { try{& icacls.exe $InstallRoot '/grant' "NT SERVICE\${n}:(OI)(CI)M" '/C' '/Q'|Out-Null}catch{} }
  }
  $secret=Join-Path $DataRoot 'secrets'
  & icacls.exe $secret '/reset' '/T' '/C' '/Q'|Out-Null
  & icacls.exe $secret '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '/C' '/Q'|Out-Null
  foreach($svc in @($manifest.services|Where-Object{([string]$_.name -match '(?i)WebAdmin|Gateway')})){try{& icacls.exe $secret '/grant' ("NT SERVICE\{0}:(OI)(CI)M" -f ([string]$svc.name)) '/C' '/Q'|Out-Null}catch{}}
}

function Get-GideonLockedArtifact {
  param([Parameter(Mandatory=$true)][string]$Id)
  $lockPath=Join-Path $BundleRoot 'installers\config\dependency-lock.json'
  if(-not(Test-Path -LiteralPath $lockPath)){Fail "Dependency lock ausente: $lockPath" 74}
  $lock=Read-GideonJson $lockPath
  $matches=@($lock.artifacts|Where-Object{[string]$_.id -eq $Id})
  if($matches.Count -ne 1){Fail "Dependency lock debe contener exactamente un artefacto $Id; encontrados=$($matches.Count)" 74}
  return $matches[0]
}

function Install-GideonYara {
  $dependencyId=[string]$cfg.security.yara_dependency_id
  if([string]::IsNullOrWhiteSpace($dependencyId)){Fail 'security.yara_dependency_id no está configurado.' 74}
  $artifact=Get-GideonLockedArtifact -Id $dependencyId
  if([string]$artifact.architecture -ne 'x64'){Fail "YARA bloqueado no es x64: $($artifact.architecture)" 74}

  $archivePath=Join-Path $BundleRoot ([string]$artifact.destination)
  if(-not(Test-Path -LiteralPath $archivePath)){
    if(-not [bool]$cfg.security.yara_network_fetch_if_cache_missing){Fail "Cache YARA ausente y descarga deshabilitada: $archivePath" 74}
    Write-GideonWarn 'Cache YARA ausente. Se aplicará la excepción temporal de descarga HTTPS fijada por URL/SHA-256.'
    & (Join-Path $BundleRoot 'installers\tools\Fetch-LockedDependencies.ps1') `
      -LockFile (Join-Path $BundleRoot 'installers\config\dependency-lock.json') `
      -Root $BundleRoot `
      -ArtifactId $dependencyId
  }

  if(-not(Test-Path -LiteralPath $archivePath)){Fail "No se obtuvo el archivo YARA: $archivePath" 74}
  $archiveSha=Get-GideonSha256 $archivePath
  $expectedArchiveSha=([string]$artifact.sha256).ToLowerInvariant()
  if($archiveSha -ne $expectedArchiveSha){Fail "SHA-256 inválido para el ZIP YARA. Esperado=$expectedArchiveSha Actual=$archiveSha" 74}

  $version=[string]$artifact.version
  $installDir=Join-Path $DataRoot ("security\tools\yara\{0}" -f $version)
  Repair-GideonWritableTree $installDir
  $installedExe=Join-Path $installDir ([string]$artifact.executable)
  $installedCompiler=Join-Path $installDir ([string]$artifact.compiler)
  $expectedExeSha=([string]$artifact.executable_sha256).ToLowerInvariant()
  $expectedCompilerSha=([string]$artifact.compiler_sha256).ToLowerInvariant()
  $installedValid=$false
  try{
    $installedValid=(
      (Test-Path -LiteralPath $installedExe) -and
      (Test-Path -LiteralPath $installedCompiler) -and
      ((Get-GideonSha256 $installedExe) -eq $expectedExeSha) -and
      ((Get-GideonSha256 $installedCompiler) -eq $expectedCompilerSha)
    )
  }catch{
    Write-GideonWarn "YARA existente no es legible; se volverá a validar desde la caché offline."
    $installedValid=$false
  }

  if(-not $installedValid){
    $tempRoot=Join-Path ([IO.Path]::GetTempPath()) ('gideon-yara-install-'+[guid]::NewGuid().ToString('N'))
    New-GideonDirectory $tempRoot
    try{
      Expand-Archive -LiteralPath $archivePath -DestinationPath $tempRoot -Force
      $stagedExe=Join-Path $tempRoot ([string]$artifact.executable)
      $stagedCompiler=Join-Path $tempRoot ([string]$artifact.compiler)
      if(-not(Test-Path -LiteralPath $stagedExe)){Fail "El ZIP YARA no contiene $($artifact.executable)" 74}
      if(-not(Test-Path -LiteralPath $stagedCompiler)){Fail "El ZIP YARA no contiene $($artifact.compiler)" 74}
      if((Get-GideonSha256 $stagedExe) -ne $expectedExeSha){Fail 'yara64.exe no coincide con el hash fijado.' 74}
      if((Get-GideonSha256 $stagedCompiler) -ne $expectedCompilerSha){Fail 'yarac64.exe no coincide con el hash fijado.' 74}
      try{
        New-GideonDirectory $installDir
        Copy-Item -LiteralPath $stagedExe -Destination $installedExe -Force
        Copy-Item -LiteralPath $stagedCompiler -Destination $installedCompiler -Force
      }catch{
        if($_.Exception.Message -notmatch '(?i)access.*denied|denied.*access|unauthorized') {throw}
        # Un rollback puede conservar un archivo protegido aun después de
        # reparar la ACL. YARA se usa aquí para validar el payload; una ruta
        # temporal íntegra permite continuar sin relajar permisos ajenos.
        $installDir=Join-Path ([IO.Path]::GetTempPath()) ('gideon-yara-runtime-'+$version+'-'+[guid]::NewGuid().ToString('N'))
        New-GideonDirectory $installDir
        $installedExe=Join-Path $installDir ([string]$artifact.executable)
        $installedCompiler=Join-Path $installDir ([string]$artifact.compiler)
        Copy-Item -LiteralPath $stagedExe -Destination $installedExe -Force
        Copy-Item -LiteralPath $stagedCompiler -Destination $installedCompiler -Force
        Write-GideonWarn "YARA persistente no escribible; se usará temporalmente $installDir."
      }
    }finally{
      if(Test-Path -LiteralPath $tempRoot){Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue}
    }
  }

  if((Get-GideonSha256 $installedExe) -ne $expectedExeSha){Fail 'Hash post-instalación de yara64.exe inválido.' 74}
  if((Get-GideonSha256 $installedCompiler) -ne $expectedCompilerSha){Fail 'Hash post-instalación de yarac64.exe inválido.' 74}
  $versionOutput=@(& $installedExe --version 2>&1)
  $versionRc=$LASTEXITCODE
  $reportedVersion=(@($versionOutput)-join ' ').Trim()
  if($versionRc -ne 0 -or $reportedVersion -ne $version){Fail "Versión YARA inválida. Esperada=$version Reportada=$reportedVersion rc=$versionRc" 74}

  Write-GideonJson `
    ([ordered]@{
      dependency_id=$dependencyId
      version=$version
      architecture=[string]$artifact.architecture
      archive=[string]$artifact.destination
      archive_sha256=$archiveSha
      executable_sha256=$expectedExeSha
      installed_utc=[DateTime]::UtcNow.ToString('o')
    }) `
    (Join-Path $installDir 'gideon-yara-install.json') `
    6
  Write-GideonPass "YARA_INSTALL=PASS version=$version path=$installedExe"
  return $installedExe
}

function Test-GideonPayloadSecurity {
  param([Parameter(Mandatory=$true)][string]$PayloadRoot)

  $diag=Resolve-GideonDiagnosticDirectory

  $rules=@(
    Get-ChildItem `
      -LiteralPath (Join-Path $BundleRoot 'security') `
      -Recurse `
      -File `
      -ErrorAction SilentlyContinue |
    Where-Object {$_.Extension -in @('.yar','.yara')}
  )

  if([bool]$cfg.security.require_yara){
    if($rules.Count -eq 0){Fail 'No existen reglas YARA en el bundle.' 73}

    if(-not [bool]$cfg.security.yara_auto_install){Fail 'YARA es obligatorio pero yara_auto_install está deshabilitado.' 74}
    $yara=Install-GideonYara

    $runId=[guid]::NewGuid().ToString('N')
    $report=Join-Path $diag ("yara-install-$runId.txt")
    $scanList=Join-Path $diag ("yara-scan-list-$runId.txt")
    $scanFiles=@(
      Get-ChildItem -LiteralPath $PayloadRoot -Recurse -File -ErrorAction Stop |
      Where-Object {$_.Extension -notin @('.yar','.yara')}
    )
    if($scanFiles.Count -eq 0){Fail 'El payload no contiene archivos escaneables por YARA.' 75}
    $scanPaths=@(
      $scanFiles|ForEach-Object{
        $full=[IO.Path]::GetFullPath($_.FullName)
        if($full.StartsWith('\\')){'\\?\UNC\'+$full.Substring(2)}else{'\\?\'+$full}
      }
    )
    # yara.exe on Windows expects --scan-list as UTF-16LE without BOM.
    # The Win32 long-path prefix is required for the bundled Python/Qt trees.
    $scanListEncoding=New-Object Text.UnicodeEncoding($false,$false)
    [IO.File]::WriteAllText($scanList,($scanPaths -join [Environment]::NewLine),$scanListEncoding)

    $args=@('-w','--no-follow-symlinks','--scan-list')
    foreach($rule in $rules){$args += $rule.FullName}
    $args += $scanList

    $oldErrorAction=$ErrorActionPreference
    try{
      $ErrorActionPreference='Continue'
      $output=@(& $yara @args 2>&1)
      $yaraRc=$LASTEXITCODE
    }finally{
      $ErrorActionPreference=$oldErrorAction
    }
    $outputText=@($output)-join [Environment]::NewLine
    Write-GideonUtf8NoBom -Path $report -Text $outputText

    if($yaraRc -ne 0){Fail "YARA falló rc=$yaraRc. Revise $report" 75}
    if($outputText -match '(?im)error scanning'){Fail "YARA no pudo abrir uno o más archivos. Revise $report" 75}
    if(@($output).Count -gt 0){Fail "YARA detectó coincidencias. Revise $report" 76}

    Write-GideonPass "YARA_SCAN=PASS files=$($scanFiles.Count) rulesets=$($rules.Count)"
  }

  if([bool]$cfg.security.windows_defender_scan){
    $mp=Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue
    if($mp){
      try{
        $status=Get-MpComputerStatus
        if($status.AntivirusEnabled -or $status.AMServiceEnabled){
          $started=Get-Date
          Start-MpScan -ScanType CustomScan -ScanPath $PayloadRoot
          $detections=@(
            Get-MpThreatDetection -ErrorAction SilentlyContinue |
            Where-Object {
              $_.InitialDetectionTime -ge $started.AddMinutes(-1) -and
              (($_.Resources -join ' ') -like "*$PayloadRoot*")
            }
          )
          if($detections.Count -gt 0){
            $detections |
              Select-Object ThreatID,InitialDetectionTime,Resources |
              Format-List |
              Out-File -LiteralPath (Join-Path $diag 'defender-install.txt') -Encoding utf8
            Fail 'Microsoft Defender detectó una amenaza en el payload GIDEON.' 77
          }
          Write-GideonPass 'DEFENDER_SCAN=PASS'
        }
        else {
          Write-GideonWarn 'Microsoft Defender está presente pero no activo. No se modifica porque puede existir un AV corporativo.'
        }
      }
      catch {
        Write-GideonWarn "Defender scan no pudo completarse: $($_.Exception.Message). YARA continúa siendo obligatorio."
      }
    }
    else {
      Write-GideonWarn 'Microsoft Defender cmdlets no disponibles. GIDEON no deshabilita ni reemplaza el AV corporativo.'
    }
  }
}

function Restore-GideonFirewallRules {
  param([int]$WebPort,[int]$GatewayPort)

  foreach($rule in @($manifest.firewall_rules)){
    $name=[string]$rule.display_name
    if(-not $name){continue}

    if(Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue){
      Write-GideonInfo "Firewall GIDEON ya existe: $name"
      continue
    }

    $protocol=[string]$rule.protocol
    $localPort=[string]$rule.local_port
    $remotePort=[string]$rule.remote_port
    $localAddress=[string]$rule.local_address
    $remoteAddress=[string]$rule.remote_address

    if($localPort -eq [string]$cfg.windows.webadmin_internal_port){$localPort=[string]$WebPort}
    if($localPort -eq [string]$cfg.windows.gateway_internal_port){$localPort=[string]$GatewayPort}

    $params=@{
      DisplayName=$name
      Direction=[string]$rule.direction
      Action=[string]$rule.action
      Profile=[string]$rule.profile
    }

    # DisplayGroup no está expuesto por algunas versiones de NetSecurity
    # (por ejemplo, Windows Home con el módulo reducido). Es metadato; la
    # regla debe seguir creándose aunque el parámetro no exista.
    $fwCommand=Get-Command New-NetFirewallRule -ErrorAction Stop
    if($fwCommand.Parameters.ContainsKey('DisplayGroup')){
      $params['DisplayGroup']='GIDEON Remote Control'
    }elseif($fwCommand.Parameters.ContainsKey('Group')){
      $params['Group']='GIDEON Remote Control'
    }

    if([string]$rule.enabled -eq 'False'){$params['Enabled']='False'}
    if($protocol -and $protocol -ne 'Any'){$params['Protocol']=$protocol}
    if($localPort -and $localPort -ne 'Any'){$params['LocalPort']=$localPort}
    if($remotePort -and $remotePort -ne 'Any'){$params['RemotePort']=$remotePort}
    if($localAddress -and $localAddress -ne 'Any'){$params['LocalAddress']=$localAddress}
    if($remoteAddress -and $remoteAddress -ne 'Any'){$params['RemoteAddress']=$remoteAddress}

    try{
      New-NetFirewallRule @params | Out-Null
      Write-GideonPass "Firewall GIDEON creado: $name"
    }
    catch{
      Fail "No se pudo recrear regla firewall GIDEON '$name': $($_.Exception.Message)" 78
    }
  }
}

function Remove-GideonOneClickResume {
  if(-not(Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)){return}
  $task=Get-ScheduledTask -TaskName $resumeTaskName -ErrorAction SilentlyContinue
  if($task){
    Unregister-ScheduledTask -TaskName $resumeTaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-GideonInfo 'Reanudacion OneClick anterior retirada.'
  }
}

function Register-GideonOneClickResume {
  if(-not(Get-Command Register-ScheduledTask -ErrorAction SilentlyContinue)){
    Write-GideonWarn 'No se pudo registrar reanudacion automatica: ScheduledTasks no esta disponible.'
    return
  }

  $escape={param([string]$v) $v.Replace("'","''")}
  $scriptPath=& $escape $PSCommandPath
  $installPath=& $escape $InstallRoot
  $dataPath=& $escape $DataRoot
  $modeLiteral=if($InstallMode -eq 'clone'){'clone'}else{'fresh'}
  $enableLiteral=if($EnableHyperVIfMissing){'$true'}else{'$false'}
  $command="& '$scriptPath' -InstallRoot '$installPath' -DataRoot '$dataPath' -InstallMode '$modeLiteral' -EnableHyperVIfMissing $enableLiteral"
  if($SkipGuacd){$command+=' -SkipGuacd'}
  $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
  $powerShellExe=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  $action=New-ScheduledTaskAction `
    -Execute $powerShellExe `
    -Argument "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded"
  if($guacdBackend -eq 'docker-desktop'){
    $resumeUser=[Security.Principal.WindowsIdentity]::GetCurrent().Name
    if([string]::IsNullOrWhiteSpace($resumeUser) -or $resumeUser -match '(?i)\\SYSTEM$'){
      Fail 'No se pudo resolver el usuario interactivo para reanudar Docker Desktop.' 88
    }
    $trigger=New-ScheduledTaskTrigger -AtLogOn -User $resumeUser
    $principal=New-ScheduledTaskPrincipal `
      -UserId $resumeUser `
      -LogonType Interactive `
      -RunLevel Highest
    $resumeMode="logon:$resumeUser"
  }else{
    $trigger=New-ScheduledTaskTrigger -AtStartup
    $principal=New-ScheduledTaskPrincipal `
      -UserId 'SYSTEM' `
      -LogonType ServiceAccount `
      -RunLevel Highest
    $resumeMode='startup:SYSTEM'
  }
  $settings=New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::FromHours(4))
  Register-ScheduledTask `
    -TaskName $resumeTaskName `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings `
    -Force | Out-Null
  Write-GideonPass "ONECLICK_RESUME_REGISTERED=PASS task=$resumeTaskName mode=$resumeMode"
}

function Resolve-GideonGuacdBackend($Os) {
  if($SkipGuacd){return 'none'}

  $configured=[string](Get-JsonPropertyOrDefault $cfg.windows 'guacd_backend' 'auto')
  $configured=$configured.Trim().ToLowerInvariant()
  if($configured -notin @('auto','hyperv','docker-desktop')){
    Fail "windows.guacd_backend invalido: $configured" 14
  }

  $editionId=''
  try{$editionId=[string](Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name EditionID -ErrorAction Stop).EditionID}catch{}
  $isHome=([string]$Os.Caption -match '(?i)Home|CoreSingleLanguage') -or ($editionId -match '(?i)^Core')

  if($configured -eq 'auto'){
    if($isHome){return 'docker-desktop'}
    return 'hyperv'
  }

  if($configured -eq 'hyperv' -and $isHome){
    Fail 'Hyper-V no esta disponible en Windows Home. Use windows.guacd_backend=auto o docker-desktop.' 14
  }
  return $configured
}

function Write-GideonPlatformSelection($Os,[string]$Backend) {
  $editionId=''
  try{$editionId=[string](Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name EditionID -ErrorAction Stop).EditionID}catch{}
  $path=Join-Path $DataRoot 'diagnostics\platform-selection.json'
  [void](Write-GideonDiagnosticJson `
    ([ordered]@{
      schema_version=1
      os=[string]$Os.Caption
      version=[string]$Os.Version
      build=[string]$Os.BuildNumber
      edition_id=$editionId
       architecture=[string]$Os.OSArchitecture
       guacd_backend=$Backend
       resource_profile=$resourceProfile
       install_mode=$InstallMode
       selection='automatic'
      generated_utc=[DateTime]::UtcNow.ToString('o')
    }) `
    $path `
    8)
  Write-GideonPass "OS_BACKEND_SELECTION=PASS os=$([string]$Os.Caption) guacd=$Backend"
}

function Request-GideonOneClickReboot([string]$Reason) {
  Register-GideonOneClickResume
  if($transcriptStarted){
    Stop-GideonTranscriptSafe
    $script:transcriptStarted=$false
  }
  Write-Host 'REBOOT_REQUIRED=YES' -ForegroundColor Yellow
  Write-Host 'ONECLICK_AUTO_RESUME=REGISTERED' -ForegroundColor Yellow
  Write-Host "REBOOT_REASON=$Reason"
  if($guacdBackend -eq 'docker-desktop'){
    Write-Host 'Reinicie Windows. GIDEON continuara automaticamente al iniciar sesion el mismo administrador.'
  }else{
    Write-Host 'Reinicie Windows. GIDEON continuara automaticamente como SYSTEM durante el siguiente arranque.'
  }
  exit 194
}

function Assert-GideonVirtualizationCpu([string]$Backend) {
  $processors=@(Get-CimInstance Win32_Processor -ErrorAction Stop)
  if($processors.Count -eq 0){Fail 'No se pudo consultar Win32_Processor.' 83}
  $vmMonitorOk=@($processors|Where-Object{-not [bool]$_.VMMonitorModeExtensions}).Count -eq 0
  $firmwareOk=@($processors|Where-Object{-not [bool]$_.VirtualizationFirmwareEnabled}).Count -eq 0
  $slatOk=@($processors|Where-Object{-not [bool]$_.SecondLevelAddressTranslationExtensions}).Count -eq 0
  if(-not($vmMonitorOk -and $firmwareOk -and $slatOk)){
    $computer=Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $manufacturer=[string]$computer.Manufacturer
    $model=[string]$computer.Model
    $virtualHint=if("$manufacturer $model" -match '(?i)virtual|vmware|virtualbox|kvm|qemu|hyper-v'){
      ' La VM necesita virtualizacion anidada habilitada desde el hipervisor anfitrion.'
    }else{
      ' Habilite VT-x/AMD-V y SLAT/NPT/EPT en BIOS/UEFI.'
    }
    Fail "VIRTUALIZATION_PREREQUISITES_MISSING backend=$Backend VMMonitor=$vmMonitorOk Firmware=$firmwareOk SLAT=$slatOk manufacturer=$manufacturer model=$model.$virtualHint" 83
  }
  Write-GideonPass "VIRTUALIZATION_PREREQUISITES=PASS backend=$Backend"
}

function Assert-GideonDockerDesktopInstalled {
  $desktopCandidates=@(
    (Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'),
    (Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin\docker.exe')
  )
  if(@($desktopCandidates|Where-Object{Test-Path -LiteralPath $_ -PathType Leaf}).Count -eq 0){
    Fail 'DOCKER_DESKTOP_REQUIRED: instale Docker Desktop con backend WSL 2, acepte su licencia y vuelva a ejecutar el mismo OneClick.' 88
  }
  Write-GideonPass 'DOCKER_DESKTOP_INSTALLATION=PASS'
}

function Assert-GideonBackendHostPrerequisites([string]$Backend,$Os) {
  if(-not [Environment]::Is64BitOperatingSystem){Fail 'GIDEON Master requiere Windows x64.' 14}
  $build=[int]$Os.BuildNumber
  $isClient=([int]$Os.ProductType -eq 1)
  if(($isClient -and $build -lt 19045) -or (-not $isClient -and $build -lt 17763)){
    Fail "WINDOWS_VERSION_UNSUPPORTED: $([string]$Os.Caption) build=$build. Requerido: Windows 10 22H2/11 o Windows Server 2019+." 14
  }
  $computer=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
  $memory=[uint64]$computer.TotalPhysicalMemory
  $logicalProcessors=[int]$computer.NumberOfLogicalProcessors
  if($memory -lt [uint64]8GB){
    Fail "HOST_MEMORY_INSUFFICIENT: detectado=$([math]::Round($memory/1GB,2))GB requerido=8GB." 15
  }
  if($logicalProcessors -lt 4){
    Fail "HOST_CPU_INSUFFICIENT: procesadores_logicos=$logicalProcessors requerido=4." 15
  }
  Write-GideonPass "HOST_CAPACITY=PASS memory_gb=$([math]::Round($memory/1GB,2)) logical_processors=$logicalProcessors"
  if($Backend -eq 'hyperv'){
    $feature=Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue
    if(-not $feature){Fail 'Esta edicion de Windows no expone Microsoft-Hyper-V-All.' 14}
    if([string]$feature.State -ne 'Enabled'){Assert-GideonVirtualizationCpu -Backend $Backend}
    return
  }
  if($Backend -eq 'docker-desktop'){
    Assert-GideonDockerDesktopInstalled
    $needsVirtualization=$false
    foreach($featureName in @('VirtualMachinePlatform','Microsoft-Windows-Subsystem-Linux')){
      $feature=Get-WindowsOptionalFeature -Online -FeatureName $featureName -ErrorAction SilentlyContinue
      if(-not $feature){Fail "Caracteristica Windows requerida no disponible: $featureName" 88}
      if([string]$feature.State -ne 'Enabled'){$needsVirtualization=$true}
    }
    if($needsVirtualization){Assert-GideonVirtualizationCpu -Backend $Backend}
  }
}

function Ensure-GideonHyperVFeature {
  $feature=Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue
  if(-not $feature){
    Fail 'Esta edicion de Windows no expone Microsoft-Hyper-V-All. Use backend Docker Desktop.' 14
  }
  if([string]$feature.State -eq 'Enabled'){
    Import-Module Hyper-V -ErrorAction Stop
    return
  }
  if(-not $EnableHyperVIfMissing){Fail 'Hyper-V no esta habilitado.' 82}

  Write-GideonWarn 'Hyper-V se habilitara ahora. Windows requiere un reinicio antes de continuar.'
  Enable-WindowsOptionalFeature `
    -Online `
    -FeatureName Microsoft-Hyper-V-All `
    -All `
    -NoRestart | Out-Null
  Request-GideonOneClickReboot 'Microsoft-Hyper-V-All enabled'
}

function Ensure-GideonDockerDesktopFeatures {
  $changed=@()
  foreach($featureName in @('VirtualMachinePlatform','Microsoft-Windows-Subsystem-Linux')){
    $feature=Get-WindowsOptionalFeature -Online -FeatureName $featureName -ErrorAction SilentlyContinue
    if(-not $feature){Fail "Caracteristica Windows requerida no disponible: $featureName" 88}
    if([string]$feature.State -ne 'Enabled'){
      Write-GideonInfo "Habilitando caracteristica para Docker Desktop WSL2: $featureName"
      Enable-WindowsOptionalFeature `
        -Online `
        -FeatureName $featureName `
        -All `
        -NoRestart | Out-Null
      $changed += $featureName
    }
  }
  if($changed.Count -gt 0){
    Request-GideonOneClickReboot ("WSL2 features enabled: {0}" -f ($changed -join ','))
  }
}

function Update-GideonBundleManifest {
  $python=Join-Path $BundleRoot 'payload\windows\GIDEON Remote Control\venv\Scripts\python.exe'
  if(-not(Test-Path -LiteralPath $python -PathType Leaf)){
    $python=Join-Path $BundleRoot 'payload\windows\GIDEON Remote Control\runtime\python-base\python.exe'
  }
  if(-not(Test-Path -LiteralPath $python -PathType Leaf)){
    Fail 'Runtime Python ausente para regenerar el manifiesto posterior a la promocion Hyper-V.' 79
  }
  & $python `
    (Join-Path $BundleRoot 'installers\tools\build_file_manifest.py') `
    --root $BundleRoot `
    --sha-output (Join-Path $BundleRoot 'FILE_MANIFEST.sha256') `
    --json-report (Join-Path $BundleRoot 'metadata\file-manifest-report.json')
  if($LASTEXITCODE -ne 0){Fail "No se pudo regenerar FILE_MANIFEST.sha256 rc=$LASTEXITCODE" 79}
  Write-GideonPass 'BUNDLE_MANIFEST_AFTER_HYPERV_PROMOTION=PASS'
}

function Promote-GideonHyperVCandidateAutomatically {
  $buildReportPath=Join-Path $BundleRoot 'metadata\hyperv-appliance-build.json'
  if(-not(Test-Path -LiteralPath $buildReportPath -PathType Leaf)){
    Fail "Falta reporte de build de la candidata Hyper-V: $buildReportPath" 79
  }
  $build=Read-GideonJson $buildReportPath
  if([int]$build.schema_version -ne 1 -or [string]$build.result -ne 'CANDIDATE_CREATED'){
    Fail 'El reporte de build Hyper-V no declara una candidata valida.' 79
  }
  if([string]$build.conversion_integrity -ne 'QEMU_BLOCK_COMPARE_PASS'){
    Fail 'La candidata Hyper-V no tiene qemu-img block compare PASS.' 79
  }
  $candidate=[IO.Path]::GetFullPath((Join-Path $BundleRoot ([string]$build.candidate.path)))
  if(-not(Test-Path -LiteralPath $candidate -PathType Leaf)){
    Fail "Falta VHDX candidata: $candidate" 79
  }
  $expected=([string]$build.candidate.sha256).ToLowerInvariant()
  $actual=Get-GideonSha256 $candidate
  if($actual -ne $expected){Fail "SHA-256 de candidata invalido esperado=$expected actual=$actual" 79}

  $validationReport=Join-Path $BundleRoot 'metadata\hyperv-appliance-validation.json'
  Write-GideonInfo 'OneClick ejecutara el gate real Hyper-V Generation 2 antes de promover la candidata.'
  $validationArgs=@{
    CandidateVhdx=$candidate
    ValidationReportPath=$validationReport
  }
  if([bool](Get-JsonPropertyOrDefault $cfg.windows.hyperv 'cleanup_validation_resources' $true)){
    $validationArgs['CleanupOnSuccess']=$true
  }
  & (Join-Path $BundleRoot 'installers\tools\Test-GideonGuacdApplianceOnHyperV.ps1') @validationArgs
  if($LASTEXITCODE -ne 0){Fail "Validacion automatica Hyper-V fallo rc=$LASTEXITCODE" 79}

  $version="ubuntu-24.04-lts-$([string]$build.source.release)-gideon1"
  & (Join-Path $BundleRoot 'installers\tools\Import-ValidatedGuacdAppliance.ps1') `
    -VhdxPath $candidate `
    -ExpectedSha256 $expected `
    -ValidationReportPath $validationReport `
    -Version $version
  if($LASTEXITCODE -ne 0){Fail "Promocion automatica Hyper-V fallo rc=$LASTEXITCODE" 79}
  Update-GideonBundleManifest
}

function Preflight-GuacdHyperV {
  if($SkipGuacd){return}

  $baseVhd=Join-Path $BundleRoot ([string]$cfg.windows.hyperv.vm_vhdx_relative_path)
  if(-not(Test-Path -LiteralPath $baseVhd)){
    Fail "Falta appliance Hyper-V validado: $baseVhd" 79
  }

  $applianceId=[string]$cfg.windows.hyperv.appliance_dependency_id
  if([string]::IsNullOrWhiteSpace($applianceId)){
    Fail 'windows.hyperv.appliance_dependency_id no esta configurado.' 79
  }

  $appliance=Get-GideonLockedArtifact -Id $applianceId
  if([string]$appliance.validation_status -ne 'VALIDATED_HYPERV_BOOT'){
    Fail 'La appliance existe, pero no tiene validacion real de arranque Hyper-V Generation 2.' 79
  }

  $lockedVhd=[IO.Path]::GetFullPath((Join-Path $BundleRoot ([string]$appliance.destination)))
  if($lockedVhd -ne [IO.Path]::GetFullPath($baseVhd)){
    Fail "La ruta de la appliance no coincide con dependency-lock: $lockedVhd" 79
  }

  $expectedVhdSha=([string]$appliance.sha256).ToLowerInvariant()
  $actualVhdSha=Get-GideonSha256 $baseVhd
  if($actualVhdSha -ne $expectedVhdSha){
    Fail "SHA-256 invalido para appliance Hyper-V. Esperado=$expectedVhdSha Actual=$actualVhdSha" 79
  }

  $validationReport=Join-Path $BundleRoot ([string]$appliance.validation_report)
  if(-not(Test-Path -LiteralPath $validationReport -PathType Leaf)){
    Fail "Falta evidencia de validacion Hyper-V: $validationReport" 79
  }

  $validationProblem=''
  try{
    $validation=Read-GideonJson $validationReport
    if([int]$validation.schema_version -ne 1){$validationProblem='schema_version no es 1'}
    elseif([string]$validation.result -ne 'PASS'){$validationProblem='result no es PASS'}
    elseif(-not [bool]$validation.tested_on_hyperv){$validationProblem='tested_on_hyperv no es true'}
    elseif(([string]$validation.appliance_sha256).ToLowerInvariant() -ne $actualVhdSha){$validationProblem='appliance_sha256 no coincide'}
    else{
      foreach($requiredTest in @('generation2_boot','secure_boot','cloud_init','docker_offline','guacd_tcp_4822')){
        $testProperty=$validation.tests.PSObject.Properties[$requiredTest]
        if(-not $testProperty -or -not [bool]$testProperty.Value){
          $validationProblem="prueba ausente o fallida: $requiredTest"
          break
        }
      }
    }
  }catch{
    $validationProblem=$_.Exception.Message
  }

  if(-not [string]::IsNullOrWhiteSpace($validationProblem)){
    Fail "Evidencia Hyper-V invalida: $validationProblem" 79
  }

  $dockerStaticId=[string]$cfg.windows.hyperv.docker_static_dependency_id
  if([string]::IsNullOrWhiteSpace($dockerStaticId)){
    Fail 'windows.hyperv.docker_static_dependency_id no esta configurado.' 87
  }

  $dockerStatic=Get-GideonLockedArtifact -Id $dockerStaticId
  $dockerStaticPath=Join-Path $BundleRoot ([string]$dockerStatic.destination)
  if(-not(Test-Path -LiteralPath $dockerStaticPath -PathType Leaf)){
    Fail "Falta Docker Engine estatico para bootstrap offline: $dockerStaticPath" 87
  }

  $actualDockerStaticSha=Get-GideonSha256 $dockerStaticPath
  $expectedDockerStaticSha=([string]$dockerStatic.sha256).ToLowerInvariant()
  if($actualDockerStaticSha -ne $expectedDockerStaticSha){
    Fail "SHA-256 invalido para Docker estatico. Esperado=$expectedDockerStaticSha Actual=$actualDockerStaticSha" 87
  }

  Write-GideonPass "HYPERV_APPLIANCE_LOCK=PASS $actualVhdSha"
  Write-GideonPass "DOCKER_STATIC_LOCK=PASS $actualDockerStaticSha"

  $map=Join-Path $BundleRoot 'offline-cache\containers\images.json'
  if(-not(Test-Path -LiteralPath $map)){
    Fail "Falta mapa de imágenes Docker: $map" 80
  }

  $rows=@(Read-GideonJson $map)
  $guacd=@($rows|Where-Object{[string]$_.container -eq 'gideon-guacd'})|Select-Object -First 1
  if(-not $guacd){Fail 'El bundle no contiene la imagen exacta de gideon-guacd.' 81}

  foreach($row in $rows){
    $imageId=[string]$row.image_id
    $archiveName=[string]$row.archive
    $expectedSha=[string]$row.archive_sha256

    if($imageId -notmatch '^sha256:[0-9a-fA-F]{64}$'){
      Fail "Image ID Docker no inmutable: $imageId" 83
    }

    if(-not $archiveName -or -not $expectedSha){
      Fail "Metadata Docker incompleta para $([string]$row.container)" 84
    }

    $archivePath=Join-Path `
      $BundleRoot `
      ('offline-cache\containers\' + $archiveName)

    if(-not(Test-Path -LiteralPath $archivePath)){
      Fail "Archivo Docker faltante: $archivePath" 85
    }

    $actualSha=Get-GideonSha256 $archivePath
    if($actualSha -ne $expectedSha.ToLowerInvariant()){
      Fail (
        "SHA256 Docker inválido archive={0} expected={1} actual={2}" -f
        $archiveName,$expectedSha,$actualSha
      ) 86
    }
  }

  Write-GideonPass "DOCKER_OFFLINE_ARCHIVES=PASS rows=$($rows.Count)"

  $feature=Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue
  if(-not $feature -or [string]$feature.State -ne 'Enabled'){
    Fail 'Hyper-V no esta listo despues de la preparacion OneClick.' 82
  }
}

function Prepare-GideonGuacdBackend {
  if($SkipGuacd){return}

  if($guacdBackend -eq 'hyperv'){
    Ensure-GideonHyperVFeature
    $productionReady=$true
    try{
      Preflight-GuacdHyperV
    }catch{
      $productionReady=$false
      Write-GideonWarn "La appliance de produccion aun no esta lista: $($_.Exception.Message)"
    }
    if(-not $productionReady){
      if(-not [bool](Get-JsonPropertyOrDefault $cfg.windows.hyperv 'auto_validate_candidate' $false)){
        Fail 'La appliance Hyper-V requiere validacion/promocion y auto_validate_candidate esta deshabilitado.' 79
      }
      Promote-GideonHyperVCandidateAutomatically
      Preflight-GuacdHyperV
    }
    return
  }

  if($guacdBackend -eq 'docker-desktop'){
    Ensure-GideonDockerDesktopFeatures
    & (Join-Path $PSScriptRoot 'Provision-GuacdDockerWindows.ps1') `
      -BundleRoot $BundleRoot `
      -DataRoot $DataRoot `
      -ConfigPath $EffectiveConfigPath `
      -PreflightOnly
    if($LASTEXITCODE -ne 0){Fail "Preflight Docker Desktop guacd fallo rc=$LASTEXITCODE" 88}
    return
  }

  Fail "Backend guacd no implementado: $guacdBackend" 14
}

function Restore-MachineEnvironment([bool]$AllowStateImport=$false) {
  if(-not $AllowStateImport){
    Write-GideonInfo 'INSTALL_MODE=FRESH: no se importan variables de entorno del bundle.'
    return
  }
  $p=Join-Path $BundleRoot 'metadata\machine-environment.json';if(-not(Test-Path $p)){return}
  foreach($e in @(Read-GideonJson $p)){
    $name=[string]$e.name;$value=[string]$e.value
    if(-not $name -or $value -eq '__REDACTED__'){continue}
    [Environment]::SetEnvironmentVariable($name,$value,[EnvironmentVariableTarget]::Machine)
  }
}
function New-GideonMachineSecret([string]$PythonExe,[int]$Bytes=32){
  $value=(& $PythonExe -c "import secrets; print(secrets.token_urlsafe($Bytes))"|Out-String).Trim()
  if($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($value)){Fail 'No se pudo generar un secreto local para la instalación fresca.' 83}
  return $value
}
function New-GideonMachineFernetKey([string]$PythonExe){
  $value=(& $PythonExe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"|Out-String).Trim()
  if($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($value)){Fail 'No se pudo generar la clave Fernet local para la instalación fresca.' 84}
  return $value
}
function Initialize-GideonFreshState([string]$PythonExe,[int]$WebPort,[int]$GatewayPort){
  # Do not use payload/data as a template here.  A fresh install receives its
  # own PKI, tokens, Fernet key and empty databases on the target machine.
  $serverName=[string]$env:COMPUTERNAME
  if([string]::IsNullOrWhiteSpace($serverName)){$serverName='localhost'}
  foreach($sub in @(
    'config','scripts','logs','logs\services','tmp','gateway','web','shared',
    'backups','backups\local','backups\external','diagnostics','coordinator',
    'updates','updates\inbox','updates\staging','updates\status','updates\archive',
    'updates\archive\success','updates\archive\failed','updates\rollback','updates\transactions',
    'updates\trust','updates\trust\update-signing','pki','pki\root','pki\web','pki\gateway',
    'pki\agent-ca','security','security\yara','releases','uploads','quarantine','secrets',
    'remote_sessions','hyperv'
  )){New-GideonDirectory (Join-Path $DataRoot $sub)}

  $pkiScript=Join-Path $InstallRoot 'app\deploy\windows\gideon_install_pki.py'
  if(-not(Test-Path -LiteralPath $pkiScript -PathType Leaf)){Fail "Bootstrap PKI ausente: $pkiScript" 85}
  & $PythonExe $pkiScript --root (Join-Path $DataRoot 'pki') --web-host $serverName --gateway-host $serverName | Out-Null
  if($LASTEXITCODE -ne 0){Fail 'No se pudo crear la PKI local de la instalación fresca.' 86}

  $adminToken=New-GideonMachineSecret $PythonExe 48
  $enrollmentSecret=New-GideonMachineSecret $PythonExe 48
  $bootstrapToken=New-GideonMachineSecret $PythonExe 32
  $totpKey=New-GideonMachineFernetKey $PythonExe
  Write-GideonUtf8NoBom (Join-Path $DataRoot 'secrets\gateway.env') "GIDEON_AGENT_ADMIN_TOKEN=$adminToken`r`nGIDEON_AGENT_ENROLL_SECRET=$enrollmentSecret`r`n"
  Write-GideonUtf8NoBom (Join-Path $DataRoot 'secrets\web.env') "GIDEON_AGENT_ADMIN_TOKEN=$adminToken`r`nGIDEON_WEB_BOOTSTRAP_TOKEN=$bootstrapToken`r`nGIDEON_WEB_TOTP_ENCRYPTION_KEY=$totpKey`r`n"
  [Environment]::SetEnvironmentVariable('GIDEON_WEB_TOTP_ENCRYPTION_KEY',$totpKey,[EnvironmentVariableTarget]::Machine)

  $gateway=[ordered]@{
    data_dir=(Join-Path $DataRoot 'gateway');listen_host='0.0.0.0';listen_address='0.0.0.0';listen_port=$GatewayPort
    admin_api_key_env='GIDEON_AGENT_ADMIN_TOKEN';enrollment_secret_env='GIDEON_AGENT_ENROLL_SECRET'
    tls_certfile=(Join-Path $DataRoot 'pki\gateway\gateway.crt');tls_keyfile=(Join-Path $DataRoot 'pki\gateway\gateway.key')
    ca_file=(Join-Path $DataRoot 'pki\root\gideon-root-ca.pem');client_ca_file=(Join-Path $DataRoot 'pki\agent-ca\agent-client-ca.pem')
    client_ca_key_file=(Join-Path $DataRoot 'pki\agent-ca\agent-client-ca.key');require_agent_mtls=$false
    public_host=$serverName;public_url="https://${serverName}:$GatewayPort";advertised_endpoint="https://${serverName}:$GatewayPort"
    internal_endpoint="https://127.0.0.1:$GatewayPort";hot_reload_enabled=$true;installer_enrollment_ttl_seconds=86400
    installer_enrollment_max_uses=8;max_job_package_bytes=1073741824;max_job_result_bytes=1073741824;max_release_bundle_bytes=1073741824
    security=[ordered]@{minimum_tls='TLSv1.2';prefer_tls13=$true;package_signing='Ed25519';digest='SHA-256'}
    reverse_tunnel_enabled=$true;reverse_tunnel_listen_host='127.0.0.1';reverse_tunnel_advertised_host=$serverName
    reverse_tunnel_open_ttl_seconds=45;reverse_tunnel_max_reservations=64;reverse_tunnel_max_streams_per_agent=4
  }
  $web=[ordered]@{
    data_dir=(Join-Path $DataRoot 'web');listen_host='0.0.0.0';listen_port=$WebPort
    gateway_base_url="https://127.0.0.1:$GatewayPort";gateway_public_url="https://${serverName}:$GatewayPort"
    gateway_admin_token_env='GIDEON_AGENT_ADMIN_TOKEN';gateway_verify_tls=$true;gateway_require_https=$true
    gateway_ca_file=(Join-Path $DataRoot 'pki\root\gideon-root-ca.pem');gateway_config_file=(Join-Path $DataRoot 'config\gateway.json')
    tls_certfile=(Join-Path $DataRoot 'pki\web\web.crt');tls_keyfile=(Join-Path $DataRoot 'pki\web\web.key')
    secure_cookies=$true;session_ttl_seconds=43200;session_idle_timeout_seconds=43200;max_sessions_per_user=5;require_mfa=$true
    trust_proxy_headers=$false;forwarded_allow_ips='127.0.0.1';access_log=$true;agent_online_ttl_seconds=90
    max_script_upload_bytes=5242880;default_script_timeout_seconds=1800;bootstrap_token_env='GIDEON_WEB_BOOTSTRAP_TOKEN'
    execution_signing_private_key='';execution_signing_public_key='';signing_key_id='';allow_server_side_signing=$false
    require_malware_scan_for_scripts=$true;require_dual_script_approval=$true;yara_rules_file='';max_transfer_upload_bytes=536870912
    require_malware_scan_for_transfers=$true;transfer_max_wait_seconds=3600;require_bootstrap_token=$true
    login_ip_window_seconds=600;login_ip_max_failures=10;login_ip_ban_seconds=900;mfa_ip_max_failures=10
    runtime_settings_file=(Join-Path $DataRoot 'shared\runtime_settings.json')
    security_event_log=(Join-Path $DataRoot 'logs\services\GIDEONRemoteControlWebAdmin\web-security.log')
    prefer_low_memory_clamav=$true;min_free_disk_bytes=1073741824;product_update_root=(Join-Path $DataRoot 'updates')
    malware_scan_allowed_root=$DataRoot;windows_defender_custom_scan=$true;clamav_database_dir='';session_policy='workday';session_rotation_on_mfa=$true
  }
  Save-Json $gateway (Join-Path $DataRoot 'config\gateway.json')
  Save-Json $web (Join-Path $DataRoot 'config\web_admin.json')
  Save-Json ([ordered]@{backup_enabled=$true;backup_destination_type='local';backup_destination='';backup_retention_days=14}) (Join-Path $DataRoot 'shared\runtime_settings.json')
  Save-Json ([ordered]@{schema_version=1;install_mode='fresh';state_imported=$false;generated_utc=[DateTime]::UtcNow.ToString('o')}) (Join-Path $DataRoot 'diagnostics\fresh-state.json')
  Write-GideonPass 'FRESH_STATE=PASS: PKI, configuración y secretos nuevos fueron generados localmente.'
}
function Assert-GideonStateConfiguration {
  $required=@((Join-Path $DataRoot 'config\web_admin.json'),(Join-Path $DataRoot 'config\gateway.json'),(Join-Path $DataRoot 'secrets\web.env'),(Join-Path $DataRoot 'secrets\gateway.env'))
  $missing=@($required|Where-Object{-not(Test-Path -LiteralPath $_ -PathType Leaf)})
  if($missing.Count -gt 0){Fail "Estado GIDEON incompleto; faltan: $($missing -join ', '). Una instalación fresh no importa payload/data. Corrija el estado local o use -InstallMode clone con un kit de clonación autorizado." 87}
}
function Ensure-Fernet([string]$PythonExe){
  $key=[Environment]::GetEnvironmentVariable('GIDEON_WEB_TOTP_ENCRYPTION_KEY',[EnvironmentVariableTarget]::Machine)
  $encrypted=@(Get-ChildItem $DataRoot -Recurse -File -Filter '*.fernet' -ErrorAction SilentlyContinue)
  if([string]::IsNullOrWhiteSpace($key)){
    if($encrypted.Count -gt 0){Fail 'Existen secretos .fernet clonados pero falta GIDEON_WEB_TOTP_ENCRYPTION_KEY. Reconstruya el bundle con -IncludeSecrets o reprovisione la clave.' 80}
    $key=(& $PythonExe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"|Out-String).Trim()
    if(-not $key){Fail 'No se pudo generar Fernet key.' 81}
    [Environment]::SetEnvironmentVariable('GIDEON_WEB_TOTP_ENCRYPTION_KEY',$key,[EnvironmentVariableTarget]::Machine)
  }
  $env:GIDEON_FERNET_VALIDATE=$key
  & $PythonExe -c "import os; from cryptography.fernet import Fernet; Fernet(os.environ['GIDEON_FERNET_VALIDATE'].encode()); print('FERNET=PASS')"|Out-Null
  if($LASTEXITCODE -ne 0){Fail 'GIDEON_WEB_TOTP_ENCRYPTION_KEY inválida.' 82}
  Remove-Item Env:\GIDEON_FERNET_VALIDATE -ErrorAction SilentlyContinue
}
function Get-GideonMachineIdentity {
  try{
    return [string](Get-ItemProperty `
      -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' `
      -Name MachineGuid `
      -ErrorAction Stop).MachineGuid
  }catch{
    return [string]$env:COMPUTERNAME
  }
}

function Bootstrap-Users([string]$PythonExe,[string]$ConfigFile,[bool]$RotateExisting){
  $defs=@($cfg.webadmin_bootstrap_users)
  if($defs.Count -eq 0){return @()}

  $rows=@()
  $passwords=@{}

  for($i=0;$i -lt $defs.Count;$i++){
    $envName="GIDEON_BOOTSTRAP_PWD_$($i+1)"
    do{$pwd=New-GideonRandomPassword 24}while(@($passwords.Values) -contains $pwd)
    $passwords[[string]$defs[$i].username]=$pwd

    [Environment]::SetEnvironmentVariable(
      $envName,
      $pwd,
      [EnvironmentVariableTarget]::Process
    )

    $rows += [pscustomobject]@{
      username=[string]$defs[$i].username
      display_name=[string]$defs[$i].display_name
      role=[string]$defs[$i].role
      password_env=$envName
    }
  }

  $tmp=Join-Path $env:TEMP (
    "gideon-bootstrap-users-"+[guid]::NewGuid().ToString('N')+'.json'
  )

  Write-GideonJson $rows $tmp 8

  try{
    $args=@(
      (Join-Path $BundleRoot 'installers\tools\bootstrap_webadmin_users.py'),
      '--app-root',(Join-Path $InstallRoot 'app'),
      '--config',$ConfigFile,
      '--users-json',$tmp
    )

    if($RotateExisting){
      $args += '--rotate-existing'
    }

    $resultRaw=& $PythonExe @args
    if($LASTEXITCODE -ne 0){
      Fail 'Bootstrap/rotación WebAdmin users falló.' 90
    }

    $result=($resultRaw|Out-String).Trim()|ConvertFrom-Json
    $changed=@()

    foreach($u in @($result.users)){
      $status=[string]$u.status
      if($status -in @('CREATED','ROTATED')){
        $changed += [pscustomobject]@{
          username=[string]$u.username
          role=[string]$u.role
          temporary_password=$passwords[[string]$u.username]
          action=$status
        }
      }
    }

    return $changed
  }
  finally{
    foreach($i in 1..$defs.Count){
      [Environment]::SetEnvironmentVariable(
        "GIDEON_BOOTSTRAP_PWD_$i",
        $null,
        [EnvironmentVariableTarget]::Process
      )
    }

    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
  }
}
function Write-CredentialFile($Created){
  if(@($Created).Count -eq 0){return $null}
  $path=Join-Path $DataRoot 'secrets\bootstrap-credentials.txt'
  $txt="GIDEON WEBADMIN TEMPORARY CREDENTIALS`r`nGenerated=$(Get-Date -Format o)`r`nCHANGE_IMMEDIATELY=YES`r`n`r`n"
  foreach($u in @($Created)){$txt += "User: $($u.username)`r`nRole: $($u.role)`r`nTemporary password: $($u.temporary_password)`r`n`r`n"}
  Write-GideonUtf8NoBom $path $txt
  & icacls.exe $path '/inheritance:r' '/grant:r' '*S-1-5-18:F' '*S-1-5-32-544:F' '/Q'|Out-Null
  return $path
}
function Patch-ConfigPorts([int]$WebPort,[int]$GatewayPort){
  $web=Join-Path $DataRoot 'config\web_admin.json';$gw=Join-Path $DataRoot 'config\gateway.json'
  if(Test-Path $web){$o=Read-GideonJson $web;Set-JsonPropertyIfPresent $o 'listen_port' $WebPort|Out-Null;if($o.PSObject.Properties.Name -contains 'gateway_base_url'){$o.gateway_base_url="https://127.0.0.1:$GatewayPort"};Save-Json $o $web}
  if(Test-Path $gw){$g=Read-GideonJson $gw;$changed=$false;foreach($k in @('listen_port','port','bind_port')){if(Set-JsonPropertyIfPresent $g $k $GatewayPort){$changed=$true;break}};if($changed){Save-Json $g $gw}}
}
function Patch-Guacd([string]$GuacdHost,[int]$Port){
  $web=Join-Path $DataRoot 'config\web_admin.json';if(-not(Test-Path $web)){return}
  $o=Read-GideonJson $web
  # Fresh payloads may contain remote_sessions/guacd as JSON null.  Checking
  # Properties.Name on a null value raises under PowerShell 5.1, so normalize
  # each object through the property indexer before reading its members.
  $remoteProp=$o.PSObject.Properties['remote_sessions']
  if(-not $remoteProp -or $null -eq $remoteProp.Value){
    $o|Add-Member -Force -NotePropertyName remote_sessions -NotePropertyValue ([pscustomobject]@{})
  }
  $remote=$o.remote_sessions
  $remoteDefaults=@{clipboard_enabled=$true;file_transfer_enabled=$true;max_clipboard_bytes=1048576;max_file_transfer_bytes=104857600}
  foreach($key in $remoteDefaults.Keys){
    $prop=$remote.PSObject.Properties[$key]
    if(-not $prop){$remote|Add-Member -Force -NotePropertyName $key -NotePropertyValue $remoteDefaults[$key]}
  }
  $guacdProp=$remote.PSObject.Properties['guacd']
  if(-not $guacdProp -or $null -eq $guacdProp.Value){
    $remote|Add-Member -Force -NotePropertyName guacd -NotePropertyValue ([pscustomobject]@{})
  }
  $g=$remote.guacd
  foreach($entry in @(
    @{Name='host';Value=$GuacdHost},
    @{Name='port';Value=$Port},
    @{Name='vnc_enabled';Value=$true}
  )){
    $prop=$g.PSObject.Properties[$entry.Name]
    if($prop){$prop.Value=$entry.Value}else{$g|Add-Member -Force -NotePropertyName $entry.Name -NotePropertyValue $entry.Value}
  }
  Save-Json $o $web
}
function Start-GideonServices {
  foreach($svc in @($manifest.services)){
    if([string]$svc.start_mode -eq 'Disabled'){continue}
    $n=[string]$svc.name
    Write-GideonInfo "Start $n"
    Start-Service -Name $n -ErrorAction SilentlyContinue
  }
}
function Wait-GideonServices {
  $deadline=(Get-Date).AddSeconds(90)
  while((Get-Date)-lt $deadline){
    $bad=@()
    foreach($svc in @($manifest.services|Where-Object{[string]$_.start_mode -eq 'Auto'})){$s=Get-Service -Name ([string]$svc.name) -ErrorAction SilentlyContinue;if(-not $s -or $s.Status -ne 'Running'){$bad += [string]$svc.name}}
    if($bad.Count -eq 0){return}
    Write-Host ("[WAIT] Servicios pendientes: "+($bad -join ', '));Start-Sleep -Seconds 3
  }
  # Preserve the actionable child-service error before the outer transaction
  # performs rollback and restores the previous payload. This is intentionally
  # emitted only on timeout so normal installs remain quiet.
  foreach($n in @($bad)){
    $lp=Join-Path $DataRoot ("logs\services\{0}\service-host.log" -f $n)
    if(Test-Path -LiteralPath $lp){
      Write-GideonWarn "SERVICE_DIAGNOSTIC $n (before rollback)"
      try{Get-Content -LiteralPath $lp -Tail 40 -ErrorAction Stop | ForEach-Object {Write-Host ("[SERVICE $n] "+$_)}}catch{Write-GideonWarn "No se pudo leer diagnóstico de $n`: $($_.Exception.Message)"}
    }
  }
  Fail 'Uno o más servicios automáticos no llegaron a RUNNING.' 100
}
function Rollback {
  if(-not $backup -or -not(Test-Path $backup)){return}
  Write-GideonWarn "ROLLBACK desde $backup"
  try{Stop-GideonServices;Cleanup-GideonOrphans}catch{}
  $ba=Join-Path $backup 'app';$bd=Join-Path $backup 'data'
  if(Test-Path $ba){& robocopy.exe $ba $InstallRoot /MIR /R:3 /W:2 /XJ /NFL /NDL /NP|Out-Null}
  if(Test-Path $bd){& robocopy.exe $bd $DataRoot /MIR /R:3 /W:2 /XJ /NFL /NDL /NP|Out-Null}
  try{Start-GideonServices}catch{}
}

try{
  Write-GideonInfo "INSTALLER_REVISION=$InstallerRevision"
  $mutex=New-Object Threading.Mutex($false,'Global\GIDEONRemoteControlMasterInstall')
  if(-not $mutex.WaitOne(0)){Fail 'Otra instalación GIDEON está en curso.' 12}
  New-GideonDirectory (Join-Path $DataRoot 'logs\installer')
  $log=Join-Path $DataRoot ('logs\installer\master-install-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'.log')
  Start-Transcript -LiteralPath $log -Force|Out-Null;$transcriptStarted=$true

  $stage='PREFLIGHT';Write-GideonStep 1 15 'Preflight Windows/edición/recursos/tiempo'
  if(-not(Test-GideonAdministrator)){Fail 'Administrator requerido.' 13}
  Repair-GideonDiagnosticsAccess
  Remove-GideonOneClickResume
  $os=Get-CimInstance Win32_OperatingSystem
  $guacdBackend=Resolve-GideonGuacdBackend $os
  Assert-GideonBackendHostPrerequisites -Backend $guacdBackend -Os $os
  Set-GideonAdaptiveResourceProfile
  Write-GideonPlatformSelection -Os $os -Backend $guacdBackend
  $requiredFree=if($guacdBackend -eq 'hyperv'){12GB}else{8GB}
  $drive=Get-PSDrive -Name ([IO.Path]::GetPathRoot($InstallRoot).Substring(0,1));if($drive.Free -lt $requiredFree){Fail "Espacio libre insuficiente. Requerido=$([math]::Round($requiredFree/1GB))GB libre=$([math]::Round($drive.Free/1GB,2))GB." 15}
  Ensure-GideonWindowsTime

  $stage='PORTS';Write-GideonStep 2 15 'Detectar conflictos de puertos sin detener aplicaciones ajenas'
  $webPort=Resolve-InternalPort ([int]$cfg.windows.webadmin_internal_port)
  $gatewayPort=Resolve-InternalPort ([int]$cfg.windows.gateway_internal_port)
  $external=[ordered]@{admin_port=[int]$cfg.windows.admin_external_port;admin_port_free=(Test-GideonTcpPortFree ([int]$cfg.windows.admin_external_port));agent_port=[int]$cfg.windows.agent_external_port;agent_port_free=(Test-GideonTcpPortFree ([int]$cfg.windows.agent_external_port));policy=[string]$cfg.windows.external_access_profile;note='Admin debe quedar VPN/ZTNA o restringido; Agents pueden exponerse por 443 mediante WAF/LB/reverse proxy mTLS. El instalador no secuestra puertos de terceros.'}
  [void](Write-GideonDiagnosticJson $external (Join-Path $DataRoot 'config\external-access-plan.json') 8)

  $stage='SECURITY_GATE';Write-GideonStep 3 15 'Instalar YARA, validar antimalware y preparar el backend guacd seleccionado para este Windows'
  $sourcePayload=Join-Path $BundleRoot 'payload\windows\GIDEON Remote Control'
  if(-not(Test-Path -LiteralPath $sourcePayload)){Fail 'Payload Windows ausente.' 20}
  Test-GideonPayloadSecurity -PayloadRoot $sourcePayload
  Prepare-GideonGuacdBackend

  $stage='STOP';Write-GideonStep 4 15 'Detener exclusivamente servicios/procesos GIDEON'
  Stop-GideonServices;Cleanup-GideonOrphans

  $stage='BACKUP';Write-GideonStep 5 15 'Backup transaccional fuera de DataRoot (evita locks SQLite y restore recursivo)'
  $programDataParent=Split-Path -Parent $DataRoot
  $backupRoot=Join-Path $programDataParent 'GIDEON Remote Control Backups'
  New-GideonDirectory $backupRoot
  $backup=Join-Path $backupRoot ('pre-master-'+(Get-Date -Format 'yyyyMMdd-HHmmss'))
  New-GideonDirectory $backup
  if(Test-Path $InstallRoot){Invoke-GideonRetry -Label 'backup app' -Script {Robocopy-OrFail $InstallRoot (Join-Path $backup 'app') @('/MIR','/ZB')}}
  if(Test-Path $DataRoot){Invoke-GideonRetry -Label 'backup data' -Script {Robocopy-OrFail $DataRoot (Join-Path $backup 'data') @('/ZB','/XD',(Join-Path $DataRoot 'backups'))}}

  $stage='DEPLOY';Write-GideonStep 6 15 "Desplegar payload exacto de producción (modo $InstallMode)"
  $srcApp=Join-Path $BundleRoot 'payload\windows\GIDEON Remote Control';if(-not(Test-Path $srcApp)){Fail 'Payload Windows ausente.' 20}
  # Un intento anterior puede haber dejado ACL restrictivas en Program Files
  # (por ejemplo, tras un rollback de servicios). Reparamos sólo el árbol de
  # instalación de GIDEON antes de copiar; nunca se modifican carpetas DPP ni
  # otros programas instalados.
  Write-GideonInfo "Normalizando ACL del árbol de instalación GIDEON: $InstallRoot"
  Repair-GideonWritableTree $InstallRoot
  Write-GideonInfo 'Copiando payload GIDEON con Robocopy en modo protegido; puede tardar si hay muchos archivos.'
  Robocopy-OrFail $srcApp $InstallRoot @('/MIR','/ZB')
  $srcData=Join-Path $BundleRoot 'payload\data\GIDEON Remote Control'

  $stage='RUNTIME';Write-GideonStep 7 15 'Validar runtime Python privado y evitar mezcla de intérpretes'
  Set-GideonRelocatedVenvBinding -Root $InstallRoot
  $python=Join-Path $InstallRoot 'venv\Scripts\python.exe';if(-not(Test-Path $python)){$python=Join-Path $InstallRoot 'runtime\python-base\python.exe'}
  if(-not(Test-Path $python)){Fail 'Python privado GIDEON no encontrado.' 21}
  Build-GideonOptimizedServiceHost
  & $python (Join-Path $BundleRoot 'installers\tools\validate_runtime.py') --app-root (Join-Path $InstallRoot 'app')|Out-File -LiteralPath (Join-Path $DataRoot 'diagnostics\runtime-smoke.json') -Encoding utf8
  if($LASTEXITCODE -ne 0){Fail 'Smoke test de imports Python falló.' 22}

  if($InstallMode -eq 'clone'){
    if(-not(Test-Path -LiteralPath $srcData -PathType Container)){
      Fail 'INSTALL_MODE=CLONE requiere payload/data. Reconstruya el kit con --include-clone-state o ejecute el modo fresh.' 23
    }
    $stateDeclared=[bool](Get-JsonPropertyOrDefault $manifest.source 'include_state_databases' $true)
    $secretsDeclared=[bool](Get-JsonPropertyOrDefault $manifest.source 'include_secrets' $true)
    if(-not $stateDeclared -or -not $secretsDeclared){
      Fail 'INSTALL_MODE=CLONE requiere un manifiesto que declare estado y secretos de clonación. Use un kit de clonación autorizado.' 23
    }
    Write-GideonWarn 'INSTALL_MODE=CLONE: se importará estado exclusivamente porque fue solicitado de forma explícita.'
    Robocopy-OrFail $srcData $DataRoot @()
    $machineIdentity=Get-GideonMachineIdentity
    $bootstrapMarker=Join-Path $DataRoot 'config\bootstrap-machine.json'
    $newMachine=$true
    if(Test-Path -LiteralPath $bootstrapMarker){
      try{
        $previousMarker=Read-GideonJson $bootstrapMarker
        $newMachine=([string]$previousMarker.machine_id -ne $machineIdentity)
      }catch{$newMachine=$true}
    }

    $sanitizeArgs=@(
      (Join-Path $BundleRoot 'installers\tools\sanitize_cloned_runtime_state.py'),
      '--data-root',$DataRoot,
      '--report',(Join-Path $DataRoot 'diagnostics\clone-state-sanitization.json')
    )
    if($newMachine -and [bool]$cfg.security.reset_agent_state_on_new_machine){
      Write-GideonInfo 'Nueva máquina: eliminando identidades, grants y trabajos de Agents clonados; el catálogo de instaladores se conserva.'
      $sanitizeArgs += '--reset-agent-state'
    }else{
      Write-GideonInfo 'Sanitizando únicamente sesiones efímeras; el estado de Agents de esta máquina se conserva.'
    }
    & $python @sanitizeArgs | Out-Null
    if($LASTEXITCODE -ne 0){Fail 'No se pudo sanear el estado efímero del clon.' 23}
  }
  else {
    $localWeb=Join-Path $DataRoot 'config\web_admin.json'
    $localGateway=Join-Path $DataRoot 'config\gateway.json'
    if(-not(Test-Path -LiteralPath $localWeb) -and -not(Test-Path -LiteralPath $localGateway)){
      Initialize-GideonFreshState $python $webPort $gatewayPort
    }
    elseif((Test-Path -LiteralPath $localWeb) -and (Test-Path -LiteralPath $localGateway)){
      Write-GideonInfo 'INSTALL_MODE=FRESH: se conserva solamente el estado que ya existe en este servidor; no se importó payload/data del bundle.'
    }
    else{
      Fail 'El estado local de GIDEON está incompleto (solo una configuración está presente). Fresh no importará estado del bundle; repare el estado local o use -InstallMode clone con un kit autorizado.' 87
    }
  }
  Assert-GideonStateConfiguration

  $stage='ENV';Write-GideonStep 8 15 'Validar secretos locales y Fernet/TOTP'
  Restore-MachineEnvironment ($InstallMode -eq 'clone');Ensure-Fernet $python
  Patch-ConfigPorts $webPort $gatewayPort

  $stage='SERVICES';Write-GideonStep 9 15 'Recrear servicios ausentes, Service SID, recovery y start mode'
  $authoritative=@($manifest.services|ForEach-Object{[string]$_.name})
  $extras=@(Get-CimInstance Win32_Service|Where-Object{(($_.Name -match '(?i)^GIDEON|GIDEONRemote|RemoteControl') -or ($_.DisplayName -match '(?i)GIDEON.*Remote')) -and ($authoritative -notcontains [string]$_.Name)})
  foreach($x in $extras){Write-GideonWarn "Servicio GIDEON no autoritativo detectado: $($x.Name). Se detiene/deshabilita para evitar procesos duplicados; no se elimina.";Stop-Service $x.Name -Force -ErrorAction SilentlyContinue;& sc.exe config $x.Name 'start= disabled'|Out-Null}
  Ensure-GideonLocalAgentPayload -GatewayPort $gatewayPort
  foreach($svc in @($manifest.services)){Configure-GideonService $svc}

  $stage='ACL';Write-GideonStep 10 15 'Aplicar aislamiento ACL por Program Files/ProgramData/Service SID'
  Apply-Acls
  Restore-GideonFirewallRules -WebPort $webPort -GatewayPort $gatewayPort

  $stage='USERS';Write-GideonStep 11 15 'Crear/rotar cuentas WebAdmin bootstrap con contraseñas temporales aleatorias'

  if([string]::IsNullOrWhiteSpace($machineIdentity)){$machineIdentity=Get-GideonMachineIdentity}
  if([string]::IsNullOrWhiteSpace($bootstrapMarker)){$bootstrapMarker=Join-Path $DataRoot 'config\bootstrap-machine.json'}
  $rotateExisting=$false

  if([bool]$cfg.security.rotate_bootstrap_passwords_on_new_machine){
    if(-not(Test-Path -LiteralPath $bootstrapMarker)){
      $rotateExisting=$true
    }else{
      try{
        $oldMarker=Read-GideonJson $bootstrapMarker
        if([string]$oldMarker.machine_id -ne $machineIdentity){
          $rotateExisting=$true
        }
      }catch{
        $rotateExisting=$true
      }
    }
  }

  if($rotateExisting){
    Write-GideonWarn 'Nueva identidad de servidor detectada: se rotarán una sola vez las contraseñas bootstrap de dchaskypp/damautapp.'
  }

  $created=Bootstrap-Users `
    $python `
    (Join-Path $DataRoot 'config\web_admin.json') `
    $rotateExisting

  $credFile=Write-CredentialFile $created

  Write-GideonJson `
    ([ordered]@{
      machine_id=$machineIdentity
      rotated_on_install=$rotateExisting
      updated_utc=[DateTime]::UtcNow.ToString('o')
    }) `
    $bootstrapMarker `
    6

  $stage='GUACD';Write-GideonStep 12 15 "Provisionar Guacamole con backend adaptativo: $guacdBackend"
  if(-not $SkipGuacd){
    if($guacdBackend -eq 'hyperv'){
      & (Join-Path $PSScriptRoot 'Provision-GuacdHyperV.ps1') `
        -BundleRoot $BundleRoot `
        -PythonExe $python `
        -ConfigPath $EffectiveConfigPath
      $grc=$LASTEXITCODE
      if($grc -ne 0){Fail "Provision Hyper-V guacd rc=$grc" 30}
      $gr=Read-GideonJson (Join-Path $DataRoot 'hyperv\GIDEON-GUACD\runtime.json')
      $generalRuntime=Join-Path $DataRoot 'guacd\runtime.json'
      New-GideonDirectory (Split-Path -Parent $generalRuntime)
      Write-GideonJson `
        ([ordered]@{
          backend='hyperv'
          host=[string]$gr.guest_ip
          guest_ip=[string]$gr.guest_ip
          port=[int]$gr.port
          vm=[string]$gr.vm
          subnet=[string]$gr.subnet
          generated_utc=[DateTime]::UtcNow.ToString('o')
        }) `
        $generalRuntime `
        8
    }elseif($guacdBackend -eq 'docker-desktop'){
      & (Join-Path $PSScriptRoot 'Provision-GuacdDockerWindows.ps1') `
        -BundleRoot $BundleRoot `
        -DataRoot $DataRoot `
        -ConfigPath $EffectiveConfigPath
      $grc=$LASTEXITCODE
      if($grc -ne 0){Fail "Provision Docker Desktop guacd rc=$grc" 30}
    }else{
      Fail "Backend guacd inesperado durante provision: $guacdBackend" 30
    }
    $gr=Read-GideonJson (Join-Path $DataRoot 'guacd\runtime.json')
    $guacdHost=if($gr.PSObject.Properties['host']){[string]$gr.host}else{[string]$gr.guest_ip}
    Patch-Guacd $guacdHost ([int]$gr.port)
  }

  $stage='START';Write-GideonStep 13 15 'Arrancar servicios y esperar estado estable'
  Start-GideonServices;Wait-GideonServices

  $stage='HEALTH';Write-GideonStep 14 15 'Health checks WebAdmin/Gateway/guacd compatibles con Windows PowerShell 5.1'
  $webOk=(Test-Web "https://127.0.0.1:$webPort/healthz") -or (Test-Web "https://127.0.0.1:$webPort/")
  if(-not $webOk){Fail "WebAdmin no responde en $webPort" 40}
  $gwOk=(Test-Web "https://127.0.0.1:$gatewayPort/health") -or (Test-Web "https://127.0.0.1:$gatewayPort/healthz")
  if(-not $gwOk){Write-GideonWarn "Gateway health no confirmado por HTTP en $gatewayPort; Verify final revisará servicios."}

  $stage='VERIFY';Write-GideonStep 15 15 'Verificación final y reporte'
  & (Join-Path $PSScriptRoot 'Verify-GIDEONMasterWindows.ps1') -InstallRoot $InstallRoot -DataRoot $DataRoot
  if($LASTEXITCODE -ne 0){Fail 'Verify final falló.' 41}

  Remove-GideonOneClickResume
  if($transcriptStarted){Stop-GideonTranscriptSafe;$transcriptStarted=$false}
  Write-Host ''
  Write-Host '============================================================' -ForegroundColor Green
  Write-Host 'FINAL_INSTALL=PASS' -ForegroundColor Green
  Write-Host "WEBADMIN=https://$env:COMPUTERNAME`:$webPort"
  Write-Host "GATEWAY_INTERNAL=https://127.0.0.1`:$gatewayPort"
  Write-Host "GUACD_BACKEND=$guacdBackend"
  Write-Host "EXTERNAL_ACCESS_PLAN=$DataRoot\config\external-access-plan.json"
  if($credFile){
    Write-Host ''
    Write-Host 'GIDEON WEBADMIN TEMPORARY CREDENTIALS' -ForegroundColor Yellow
    foreach($u in @($created)){Write-Host ("User: {0}  Role: {1}" -f $u.username,$u.role)}
    Write-Host "CREDENTIAL_FILE=$credFile"
    Write-Host 'Abra ese archivo como Administrador para ver las contraseñas. No se escriben en el log de instalación.'
    Write-Host 'ACTION=Iniciar sesión, configurar MFA y cambiar inmediatamente cada contraseña temporal.'
  }
  Write-Host '============================================================' -ForegroundColor Green
  exit 0
}catch{
  $msg=$_.Exception.Message
  Write-GideonFail "$stage :: $msg"
  try{if($transcriptStarted){Stop-GideonTranscriptSafe;$transcriptStarted=$false}}catch{}
  try{Rollback}catch{}
  try{
    & (Join-Path $PSScriptRoot 'Collect-GIDEONInstallDiagnostics.ps1') `
      -OutputRoot (Join-Path $DataRoot 'diagnostics') `
      -DataRoot $DataRoot `
      -Stage $stage `
      -ErrorMessage $msg | Out-Null
  }catch{}
  exit 99
}finally{
  if($mutex){try{$mutex.ReleaseMutex()}catch{};try{$mutex.Dispose()}catch{}}
}
