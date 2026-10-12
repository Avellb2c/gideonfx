[CmdletBinding()]
param()

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

$toolRoot=Split-Path -Parent $PSScriptRoot
$common=Join-Path $toolRoot 'common\GIDEON.Common.psm1'
Import-Module $common -Force

function Get-TestPropertyValue {
  param(
    [AllowNull()]$Object,
    [Parameter(Mandatory=$true)][string]$Name,
    [AllowNull()]$Default=$null
  )

  if($null -eq $Object){
    return $Default
  }

  $property=$Object.PSObject.Properties[$Name]
  if($null -eq $property){
    return $Default
  }

  return $property.Value
}

$failures=@()

# Test 1: empty array JSON in Windows PowerShell 5.1.
try{
  $json=ConvertTo-GideonJson -Object @() -Depth 4 -Compress
  if([string]$json -ne '[]'){
    $failures += "EMPTY_ARRAY_JSON expected=[] actual=$json"
  }
}catch{
  $failures += "EMPTY_ARRAY_JSON exception=$($_.Exception.Message)"
}

# Test 2: PowerShell 5.1-safe environment parsing. Preserve '=' in value.
try{
  $line='TOKEN=abc=def=='
  $separatorIndex=$line.IndexOf('=')

  if($separatorIndex -lt 0){
    $failures += 'ENV_SPLIT separator not found'
  }else{
    $name=$line.Substring(0,$separatorIndex)
    $value=$line.Substring($separatorIndex+1)

    if($name -ne 'TOKEN'){
      $failures += "ENV_SPLIT name=$name"
    }

    if($value -ne 'abc=def=='){
      $failures += "ENV_SPLIT value=$value"
    }
  }
}catch{
  $failures += "ENV_SPLIT exception=$($_.Exception.Message)"
}

# Test 3: StrictMode-safe missing Docker Health property.
try{
  $sample='{"State":{"Running":true,"Status":"running"},"Config":{"Image":"guacd:test"}}' |
    ConvertFrom-Json

  $state=Get-TestPropertyValue $sample 'State' $null
  $health=Get-TestPropertyValue $state 'Health' $null
  $running=[bool](Get-TestPropertyValue $state 'Running' $false)

  if($null -ne $health){
    $failures += 'OPTIONAL_HEALTH expected null'
  }

  if(-not $running){
    $failures += 'OPTIONAL_RUNNING expected true'
  }
}catch{
  $failures += "OPTIONAL_DOCKER_PROPERTY exception=$($_.Exception.Message)"
}

# Test 4: String formatting avoids the recurrent "$variable:" parser pattern.
try{
  $cname='gideon-guacd'
  $message=("docker inspect {0}: {1}" -f $cname,'test')
  if($message -ne 'docker inspect gideon-guacd: test'){
    $failures += "FORMAT_STRING actual=$message"
  }
}catch{
  $failures += "FORMAT_STRING exception=$($_.Exception.Message)"
}


# Test 5: root-only ACL hardening with SID-based .NET APIs.
try{
  $tempAclRoot=Join-Path $env:TEMP (
    'gideon-acl-precheck-' + [guid]::NewGuid().ToString('N')
  )
  New-Item -ItemType Directory -Path $tempAclRoot -Force | Out-Null

  $probeFile=Join-Path $tempAclRoot 'probe.txt'
  [IO.File]::WriteAllText($probeFile,'GIDEON-ACL-PROBE')

  $currentSid=[Security.Principal.WindowsIdentity]::GetCurrent().User
  $systemSid=New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
  $adminsSid=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')

  $directoryAcl=New-Object Security.AccessControl.DirectorySecurity
  $directoryAcl.SetAccessRuleProtection($true,$false)
  $directoryAcl.SetOwner($currentSid)

  $rights=[Security.AccessControl.FileSystemRights]::FullControl
  $inherit=(
    [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
    [Security.AccessControl.InheritanceFlags]::ObjectInherit
  )
  $propagation=[Security.AccessControl.PropagationFlags]::None
  $allow=[Security.AccessControl.AccessControlType]::Allow

  foreach($sid in @($currentSid,$systemSid,$adminsSid)){
    $rule=New-Object Security.AccessControl.FileSystemAccessRule(
      $sid,$rights,$inherit,$propagation,$allow
    )
    [void]$directoryAcl.AddAccessRule($rule)
  }

  [IO.Directory]::SetAccessControl($tempAclRoot,$directoryAcl)

  $probe=[IO.File]::ReadAllText($probeFile)
  if($probe -ne 'GIDEON-ACL-PROBE'){
    $failures += "ACL_ROOT_PROBE content=$probe"
  }
}catch{
  $failures += "ACL_ROOT_PROBE exception=$($_.Exception.Message)"
}finally{
  if($tempAclRoot -and (Test-Path -LiteralPath $tempAclRoot)){
    Remove-Item -LiteralPath $tempAclRoot -Recurse -Force -ErrorAction SilentlyContinue
  }
}


# Test 6: real Docker inspect single-object JSON, when available.
$dockerInspectTest='SKIP'
try{
  $dockerCommand=Get-Command docker.exe -ErrorAction SilentlyContinue
  $dockerReady=$false

  if($dockerCommand){
    try{
      $serverVersion=(& docker.exe version --format '{{.Server.Version}}' 2>$null|Out-String).Trim()
      $dockerReady=($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($serverVersion))
    }catch{
      # A CLI without a running engine is normal before installation and
      # must not fail a static PowerShell compatibility precheck.
      $dockerReady=$false
    }
  }

  if($dockerReady){
    $names=@(
      & docker.exe ps -a --format '{{.Names}}' 2>$null |
        Where-Object {$_ -in @('gideon-guacd','gideon-guacamole-bridge')}
    )

    if($names.Count -gt 0){
      $dockerInspectTest='PASS'

      foreach($name in $names){
        $raw=(
          & docker.exe inspect `
            --format '{{json .}}' `
            $name 2>$null |
          Out-String
        ).Trim()

        if($LASTEXITCODE -ne 0 -or -not $raw){
          $failures += "DOCKER_INSPECT_SINGLE_OBJECT no output name=$name"
          $dockerInspectTest='FAIL'
          continue
        }

        $obj=$raw|ConvertFrom-Json
        $config=Get-TestPropertyValue $obj 'Config' $null
        $state=Get-TestPropertyValue $obj 'State' $null
        $image=[string](Get-TestPropertyValue $config 'Image' '')
        $status=[string](Get-TestPropertyValue $state 'Status' '')

        if(-not $image){
          $failures += "DOCKER_INSPECT_SINGLE_OBJECT image empty name=$name"
          $dockerInspectTest='FAIL'
        }

        if(-not $status){
          $failures += "DOCKER_INSPECT_SINGLE_OBJECT status empty name=$name"
          $dockerInspectTest='FAIL'
        }
      }
    }
  }
}catch{
  $failures += "DOCKER_INSPECT_SINGLE_OBJECT exception=$($_.Exception.Message)"
  $dockerInspectTest='FAIL'
}


# Test 7: effective WebAdmin -> guacd resolver on the known production layout.
$effectiveGuacdTest='SKIP'
$resourceOptimizationTest='SKIP'
$tempEffectiveGuacd=$null
$tempEffectiveDiag=$null

try{
  # The compatibility precheck must be deterministic and runnable before
  # installation. Reading a hardened existing Program Files/ProgramData tree
  # can correctly return Access Denied for a non-elevated caller.
  $bundleRoot=Split-Path -Parent $toolRoot
  $payloadRoot=Join-Path $bundleRoot 'payload\windows\GIDEON Remote Control'
  $venvPython=Join-Path $payloadRoot 'venv\Scripts\python.exe'
  $runtimePython=Join-Path $payloadRoot 'runtime\python-base\python.exe'
  $precheckPython=if(Test-Path -LiteralPath $runtimePython -PathType Leaf){
    $runtimePython
  }else{
    $venvPython
  }
  $webConfig=Join-Path $bundleRoot 'payload\data\GIDEON Remote Control\config\web_admin.json'
  $appRoot=Join-Path $payloadRoot 'app'
  $resolver=Join-Path $toolRoot 'tools\export_effective_guacd_config.py'

  if(
    (Test-Path -LiteralPath $precheckPython -PathType Leaf) -and
    (Test-Path -LiteralPath $webConfig) -and
    (Test-Path -LiteralPath $resolver)
  ){
    $effectiveGuacdTest='PASS'
    $token=[guid]::NewGuid().ToString('N')
    $tempEffectiveGuacd=Join-Path $env:TEMP ("gideon-guacd-effective-$token.json")
    $tempEffectiveDiag=Join-Path $env:TEMP ("gideon-guacd-effective-$token-diag.json")

    $resolverOutput=& $precheckPython `
      $resolver `
      --app-root $appRoot `
      --config $webConfig `
      --output $tempEffectiveGuacd `
      --diagnostics $tempEffectiveDiag 2>&1

    $resolverRc=$LASTEXITCODE

    if(
      $resolverRc -ne 0 -or
      -not(Test-Path -LiteralPath $tempEffectiveGuacd)
    ){
      $failures += (
        "EFFECTIVE_GUACD_CONFIG rc={0} output={1}" -f
        $resolverRc,(@($resolverOutput) -join ' | ')
      )
      $effectiveGuacdTest='FAIL'
    }else{
      $resolved=Get-Content `
        -LiteralPath $tempEffectiveGuacd `
        -Raw `
        -ErrorAction Stop |
        ConvertFrom-Json

      if(
        -not [string]$resolved.host -or
        [int]$resolved.port -le 0
      ){
        $failures += 'EFFECTIVE_GUACD_CONFIG host/port unresolved'
        $effectiveGuacdTest='FAIL'
      }
    }
  }
}catch{
  $failures += "EFFECTIVE_GUACD_CONFIG exception=$($_.Exception.Message)"
  $effectiveGuacdTest='FAIL'
}finally{
  foreach($tempFile in @($tempEffectiveGuacd,$tempEffectiveDiag)){
    if($tempFile -and (Test-Path -LiteralPath $tempFile)){
      Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
    }
  }
}

# Test 8: adaptive resource contract and compilable event-driven service host.
$resourceHostTemp=$null
try{
  $bundleRoot=Split-Path -Parent $toolRoot
  $masterConfig=Get-Content -LiteralPath (Join-Path $bundleRoot 'master.config.json') -Raw|ConvertFrom-Json
  $hyperv=$masterConfig.windows.hyperv
  $dockerDesktop=$masterConfig.windows.docker_desktop
  if([string]$masterConfig.windows.resource_profile -ne 'auto'){
    throw 'windows.resource_profile debe iniciar en auto'
  }
  if(-not [bool]$hyperv.dynamic_memory_enabled){throw 'Hyper-V dynamic memory no está habilitado'}
  if([int]$hyperv.vm_memory_min_mb -gt [int]$hyperv.vm_memory_mb){throw 'Hyper-V min supera startup'}
  if([int]$hyperv.vm_memory_mb -gt [int]$hyperv.vm_memory_max_mb){throw 'Hyper-V startup supera max'}
  foreach($limit in @([string]$hyperv.guacd_container_memory,[string]$dockerDesktop.guacd_memory)){
    if($limit -notmatch '^[0-9]+[mMgG]$'){throw "Límite guacd inválido: $limit"}
  }

  $source=Join-Path $bundleRoot 'payload\windows\GIDEON Remote Control\app\deploy\windows\GIDEONServiceHost.cs'
  $sourceText=Get-Content -LiteralPath $source -Raw -Encoding UTF8
  foreach($marker in @('FileSystemWatcher','ScheduleNextBackup','No resident Python worker','No 3-second Python polling')){
    if($sourceText.IndexOf($marker,[StringComparison]::Ordinal) -lt 0){throw "GIDEONServiceHost marker ausente: $marker"}
  }
  $csc=@(
    (Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'),
    (Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe')
  )|Where-Object{Test-Path -LiteralPath $_ -PathType Leaf}|Select-Object -First 1
  if(-not $csc){throw 'csc.exe ausente'}
  $resourceHostTemp=Join-Path $env:TEMP ('gideon-service-host-precheck-'+[guid]::NewGuid().ToString('N')+'.exe')
  & $csc '/nologo' '/target:exe' '/optimize+' '/debug-' (('/out:{0}' -f $resourceHostTemp)) '/reference:System.ServiceProcess.dll' $source
  if($LASTEXITCODE -ne 0 -or -not(Test-Path -LiteralPath $resourceHostTemp -PathType Leaf)){
    throw "Compilación de GIDEONServiceHost falló rc=$LASTEXITCODE"
  }
  if((Get-Item -LiteralPath $resourceHostTemp).Length -gt 262144){throw 'GIDEONServiceHost compilado supera 256 KiB'}

  $installerSource=Join-Path $bundleRoot 'installers\WINDOWS\Install-GIDEONMasterWindows.ps1'
  $tokens=$null;$parseErrors=$null
  $installerAst=[Management.Automation.Language.Parser]::ParseFile($installerSource,[ref]$tokens,[ref]$parseErrors)
  if($parseErrors.Count -ne 0){throw 'No se pudo analizar Install-GIDEONMasterWindows.ps1'}
  $profileFunction=@($installerAst.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Set-GideonAdaptiveResourceProfile'},$true))
  if($profileFunction.Count -ne 1){throw "Set-GideonAdaptiveResourceProfile count=$($profileFunction.Count)"}
  Invoke-Expression $profileFunction[0].Extent.Text
  function Fail([string]$Message,[int]$Code=1){throw "TEST_FAIL[$Code]: $Message"}
  function Get-JsonPropertyOrDefault($Object,[string]$Name,$DefaultValue){$p=$Object.PSObject.Properties[$Name];if($p -and $null -ne $p.Value){return $p.Value};return $DefaultValue}
  function Get-CimInstance {[CmdletBinding()]param([Parameter(Position=0)][string]$ClassName);return $script:resourceTestComputer}
  function New-GideonDirectory {param([string]$Path)}
  function Write-GideonPass {param([string]$Text)}
  function Write-GideonJson {param($Object,[string]$Path,[int]$Depth);if($Path -like '*resource-profile.json'){$script:resourceTestReport=$Object}}
  $savedResourceOverride=[string]$env:GIDEON_RESOURCE_PROFILE
  try{
    $scenarios=@(
      [pscustomobject]@{memory=[uint64]8GB;cpu=4;expected='compact';min=768;startup=1536;max=1536},
      [pscustomobject]@{memory=[uint64]16GB;cpu=4;expected='standard';min=1024;startup=1536;max=2048},
      [pscustomobject]@{memory=[uint64]32GB;cpu=8;expected='performance';min=1536;startup=2048;max=4096}
    )
    foreach($scenario in $scenarios){
      $script:resourceTestComputer=[pscustomobject]@{TotalPhysicalMemory=$scenario.memory;NumberOfLogicalProcessors=$scenario.cpu}
      $script:resourceTestReport=$null
      $cfg=Get-Content -LiteralPath (Join-Path $bundleRoot 'master.config.json') -Raw|ConvertFrom-Json
      $DataRoot=Join-Path $env:TEMP 'gideon-resource-profile-precheck'
      $env:GIDEON_RESOURCE_PROFILE='auto'
      Set-GideonAdaptiveResourceProfile
      if([string]$script:resourceProfile -ne [string]$scenario.expected){throw "Perfil esperado=$($scenario.expected) actual=$script:resourceProfile"}
      if([int]$cfg.windows.hyperv.vm_memory_min_mb -ne [int]$scenario.min -or [int]$cfg.windows.hyperv.vm_memory_mb -ne [int]$scenario.startup -or [int]$cfg.windows.hyperv.vm_memory_max_mb -ne [int]$scenario.max){
        throw "Memoria de perfil incorrecta para $($scenario.expected)"
      }
      if($null -eq $script:resourceTestReport -or [string]$script:resourceTestReport.selected -ne [string]$scenario.expected){throw "Reporte de perfil ausente para $($scenario.expected)"}
    }
  }finally{
    $env:GIDEON_RESOURCE_PROFILE=$savedResourceOverride
  }
  $resourceOptimizationTest='PASS'
}catch{
  $failures += "RESOURCE_OPTIMIZATION exception=$($_.Exception.Message)"
  $resourceOptimizationTest='FAIL'
}finally{
  if($resourceHostTemp -and (Test-Path -LiteralPath $resourceHostTemp)){
    Remove-Item -LiteralPath $resourceHostTemp -Force -ErrorAction SilentlyContinue
  }
}

if($failures.Count -gt 0){
  Write-Host ''
  Write-Host 'POWERSHELL_COMPAT_PRECHECK=FAIL' -ForegroundColor Red
  Write-Host ("COMPAT_ERRORS={0}" -f $failures.Count)

  foreach($failure in $failures){
    Write-Host ("COMPAT_ERROR={0}" -f $failure)
  }

  exit 2
}

Write-Host 'POWERSHELL_COMPAT_PRECHECK=PASS' -ForegroundColor Green
Write-Host 'TEST_EMPTY_ARRAY_JSON=PASS'
Write-Host 'TEST_ENV_SPLIT=PASS'
Write-Host 'TEST_OPTIONAL_DOCKER_PROPERTY=PASS'
Write-Host 'TEST_FORMAT_STRING=PASS'
Write-Host 'TEST_ROOT_ACL=PASS'
Write-Host ("TEST_DOCKER_INSPECT_SINGLE_OBJECT={0}" -f $dockerInspectTest)
Write-Host ("TEST_EFFECTIVE_GUACD_CONFIG={0}" -f $effectiveGuacdTest)
Write-Host ("TEST_RESOURCE_OPTIMIZATION={0}" -f $resourceOptimizationTest)
exit 0
