[CmdletBinding()]
param(
 [string]$OutputRoot="$env:ProgramData\GIDEON Remote Control\diagnostics",
 [string]$DataRoot="$env:ProgramData\GIDEON Remote Control",
 [string]$Stage='UNKNOWN',
 [string]$ErrorMessage=''
)
$ErrorActionPreference='SilentlyContinue';Set-StrictMode -Version Latest
$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
$dir=Join-Path $OutputRoot "install-$stamp"
New-Item -ItemType Directory -Path $dir -Force|Out-Null
function Write-GideonDiagnosticFile {
  param(
    [Parameter(Mandatory=$true)][string]$Name,
    [Parameter(Mandatory=$true)][scriptblock]$Collector
  )
  $path=Join-Path $dir $Name
  try{
    $text=(& $Collector 2>&1 | Out-String -Width 4096).TrimEnd()
    if([string]::IsNullOrWhiteSpace($text)){$text='NO_MATCHING_DATA'}
  }catch{
    $text="COLLECTION_ERROR=$($_.Exception.Message)"
  }
  $text | Out-File -LiteralPath $path -Encoding utf8 -Width 4096
}

"Stage=$Stage`r`nError=$ErrorMessage`r`nTime=$(Get-Date -Format o)"|Out-File -LiteralPath (Join-Path $dir 'failure.txt') -Encoding utf8
Write-GideonDiagnosticFile 'os.txt' {Get-CimInstance Win32_OperatingSystem -ErrorAction Stop|Format-List *}
Write-GideonDiagnosticFile 'computer.txt' {
  Get-CimInstance Win32_ComputerSystem -ErrorAction Stop|Select-Object Manufacturer,Model,SystemType,TotalPhysicalMemory,Domain,PartOfDomain,HypervisorPresent|Format-List
}
Write-GideonDiagnosticFile 'services.txt' {
  Get-CimInstance Win32_Service -ErrorAction Stop|Where-Object{($_.Name -eq 'W32Time') -or ($_.Name -match '(?i)^GIDEON|RemoteControl') -or ($_.DisplayName -match '(?i)GIDEON.*Remote')}|Format-List Name,DisplayName,State,StartMode,Status,ExitCode,ServiceSpecificExitCode,PathName,StartName
}
Write-GideonDiagnosticFile 'time-service.txt' {
  '===== SERVICE ====='
  Get-CimInstance Win32_Service -Filter "Name='W32Time'" -ErrorAction Stop|Format-List Name,DisplayName,State,StartMode,Status,ExitCode,ServiceSpecificExitCode,PathName,StartName
  '===== SC.EXE QC ====='
  & sc.exe qc W32Time
  '===== W32TM SOURCE ====='
  & w32tm.exe /query /source
  '===== W32TM STATUS ====='
  & w32tm.exe /query /status /verbose
  '===== W32TM CONFIGURATION ====='
  & w32tm.exe /query /configuration
}
Write-GideonDiagnosticFile 'virtualization.txt' {
  '===== PROCESSOR ====='
  Get-CimInstance Win32_Processor -ErrorAction Stop|Select-Object Name,Architecture,AddressWidth,DataWidth,VMMonitorModeExtensions,VirtualizationFirmwareEnabled,SecondLevelAddressTranslationExtensions|Format-List
  '===== WINDOWS FEATURES ====='
  foreach($featureName in @('Microsoft-Hyper-V-All','VirtualMachinePlatform','Microsoft-Windows-Subsystem-Linux')){
    Get-WindowsOptionalFeature -Online -FeatureName $featureName -ErrorAction SilentlyContinue|Select-Object FeatureName,State,RestartRequired|Format-List
  }
  if(Get-Module -ListAvailable Hyper-V){
    '===== GIDEON VM MEMORY ====='
    Get-VMMemory -VMName 'GIDEON-GUACD' -ErrorAction SilentlyContinue|Format-List DynamicMemoryEnabled,Minimum,Startup,Maximum,Buffer,Priority,AssignedMemory,Demand
    '===== GIDEON VM PROCESSOR ====='
    Get-VMProcessor -VMName 'GIDEON-GUACD' -ErrorAction SilentlyContinue|Format-List Count,CompatibilityForMigrationEnabled,ExposeVirtualizationExtensions
  }
}
Write-GideonDiagnosticFile 'processes.txt' {
  Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object{([string]$_.ExecutablePath -match '(?i)GIDEON Remote Control') -or ([string]$_.CommandLine -match '(?i)GIDEON Remote Control')}|Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine|Format-List
}
Write-GideonDiagnosticFile 'ports.txt' {Get-NetTCPConnection -ErrorAction Stop|Sort-Object LocalPort|Format-Table -AutoSize}
Write-GideonDiagnosticFile 'routes.txt' {Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop|Format-Table -AutoSize}
Write-GideonDiagnosticFile 'adapters.txt' {Get-NetAdapter -ErrorAction Stop|Format-Table -AutoSize}
Write-GideonDiagnosticFile 'scm-events.txt' {
  Get-WinEvent -FilterHashtable @{LogName='System';StartTime=(Get-Date).AddHours(-6)} -ErrorAction Stop|Where-Object{($_.ProviderName -in @('Service Control Manager','Microsoft-Windows-Time-Service')) -and ($_.Message -match '(?i)GIDEON|Remote Control|W32Time|Windows Time|servicio de hora')}|Select-Object TimeCreated,ProviderName,Id,LevelDisplayName,Message|Format-List
}
if(Get-Command docker.exe -ErrorAction SilentlyContinue){
  Write-GideonDiagnosticFile 'docker-info.txt' {& docker.exe info}
  Write-GideonDiagnosticFile 'docker-ps.txt' {& docker.exe ps -a}
}
if(Get-Module -ListAvailable Hyper-V){
  Write-GideonDiagnosticFile 'hyperv-vms.txt' {Get-VM -ErrorAction Stop|Format-List *}
  Write-GideonDiagnosticFile 'hyperv-switches.txt' {Get-VMSwitch -ErrorAction Stop|Format-List *}
}
$platformSelection=Join-Path $DataRoot 'diagnostics\platform-selection.json'
if(Test-Path -LiteralPath $platformSelection -PathType Leaf){Copy-Item -LiteralPath $platformSelection -Destination (Join-Path $dir 'platform-selection.json') -Force -ErrorAction SilentlyContinue}
$resourceSelection=Join-Path $DataRoot 'diagnostics\resource-profile.json'
if(Test-Path -LiteralPath $resourceSelection -PathType Leaf){Copy-Item -LiteralPath $resourceSelection -Destination (Join-Path $dir 'resource-profile.json') -Force -ErrorAction SilentlyContinue}
$installerLogRoot=Join-Path $DataRoot 'logs\installer'
if(Test-Path -LiteralPath $installerLogRoot -PathType Container){
  $latestInstallerLog=Get-ChildItem -LiteralPath $installerLogRoot -Filter 'master-install-*.log' -File -ErrorAction SilentlyContinue|Sort-Object LastWriteTime -Descending|Select-Object -First 1
  if($latestInstallerLog){Copy-Item -LiteralPath $latestInstallerLog.FullName -Destination (Join-Path $dir 'installer-transcript.log') -Force -ErrorAction SilentlyContinue}
}
$logRoot=Join-Path $DataRoot 'logs\services'
if(Test-Path -LiteralPath $logRoot -PathType Container){Get-ChildItem -LiteralPath $logRoot -Recurse -File -ErrorAction SilentlyContinue|Where-Object{$_.LastWriteTime -gt (Get-Date).AddHours(-12)}|ForEach-Object{Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $dir ('log-'+($_.FullName -replace '[:\\/]','_'))) -Force -ErrorAction SilentlyContinue}}
$zip="$OutputRoot\GIDEON-INSTALL-DIAGNOSTICS-$stamp.zip"
Compress-Archive -Path "$dir\*" -DestinationPath $zip -Force
Write-Host "DIAGNOSTICS=$zip"
$zip
