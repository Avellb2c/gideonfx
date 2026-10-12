[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$BundleRoot,
    [Parameter(Mandatory=$true)][string]$PythonExe,
    [Parameter(Mandatory=$true)][string]$ConfigPath,
    [switch]$EnableHyperVIfMissing,
    [string]$CandidateVhdPath = '',
    [string]$ValidationReportPath = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$common = Join-Path $BundleRoot 'installers\common\GIDEON.Common.psm1'
Import-Module $common -Force

$cfg = Read-GideonJson $ConfigPath
$h = $cfg.windows.hyperv
$validationMode = -not [string]::IsNullOrWhiteSpace($CandidateVhdPath)
$memoryStartupMb = [int]$h.vm_memory_mb
$dynamicMemory = [bool]$h.dynamic_memory_enabled
$memoryMinimumMb = [int]$h.vm_memory_min_mb
$memoryMaximumMb = [int]$h.vm_memory_max_mb
$memoryBufferPercent = [int]$h.vm_memory_buffer_percent
$guacdContainerMemory = [string]$h.guacd_container_memory
$guacdContainerCpus = [string]$h.guacd_container_cpus
if($memoryStartupMb -lt 768 -or $memoryMinimumMb -lt 512 -or $memoryMaximumMb -lt $memoryStartupMb -or $memoryMinimumMb -gt $memoryStartupMb){
    throw "HYPERV_MEMORY_PROFILE_INVALID min=$memoryMinimumMb startup=$memoryStartupMb max=$memoryMaximumMb"
}
if($memoryBufferPercent -lt 5 -or $memoryBufferPercent -gt 50){throw "HYPERV_MEMORY_BUFFER_INVALID: $memoryBufferPercent"}
if($guacdContainerMemory -notmatch '^[0-9]+[mMgG]$'){throw "GUACD_MEMORY_LIMIT_INVALID: $guacdContainerMemory"}
if($guacdContainerCpus -notmatch '^[0-9]+(?:\.[0-9]+)?$'){throw "GUACD_CPU_LIMIT_INVALID: $guacdContainerCpus"}

if ($validationMode -and [string]::IsNullOrWhiteSpace($ValidationReportPath)) {
    throw 'ValidationReportPath es obligatorio al validar una VHDX candidata.'
}

$feature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue
if (-not $feature -or [string]$feature.State -ne 'Enabled') {
    if (-not $EnableHyperVIfMissing) {
        throw 'HYPERV_DISABLED'
    }

    Write-GideonInfo 'Habilitando Hyper-V sin reinicio automático...'
    Enable-WindowsOptionalFeature `
        -Online `
        -FeatureName Microsoft-Hyper-V `
        -All `
        -NoRestart | Out-Null

    Write-Host 'REBOOT_REQUIRED=YES'
    exit 194
}

Import-Module Hyper-V -ErrorAction Stop

$vhdRel = [string]$h.vm_vhdx_relative_path
if ($validationMode) {
    $baseVhd = [IO.Path]::GetFullPath($CandidateVhdPath)
}
else {
    $baseVhd = Join-Path $BundleRoot $vhdRel
}

if (-not (Test-Path -LiteralPath $baseVhd)) {
    throw "HYPERV_APPLIANCE_MISSING: $baseVhd"
}

$lockPath = Join-Path $BundleRoot 'installers\config\dependency-lock.json'
if (-not (Test-Path -LiteralPath $lockPath)) {
    throw "DEPENDENCY_LOCK_MISSING: $lockPath"
}

$lock = Read-GideonJson $lockPath
function Get-LockedArtifact([string]$Id) {
    $matches = @($lock.artifacts | Where-Object { [string]$_.id -eq $Id })
    if ($matches.Count -ne 1) {
        throw "LOCKED_ARTIFACT_COUNT_INVALID id=$Id count=$($matches.Count)"
    }
    return $matches[0]
}

$actualBaseVhdSha = Get-GideonSha256 $baseVhd
if (-not $validationMode) {
    $applianceArtifact = Get-LockedArtifact ([string]$h.appliance_dependency_id)
    if ([string]$applianceArtifact.validation_status -ne 'VALIDATED_HYPERV_BOOT') {
        throw 'HYPERV_APPLIANCE_NOT_VALIDATED'
    }

    $expectedBaseVhdSha = ([string]$applianceArtifact.sha256).ToLowerInvariant()
    if ($actualBaseVhdSha -ne $expectedBaseVhdSha) {
        throw "HYPERV_APPLIANCE_SHA256_MISMATCH expected=$expectedBaseVhdSha actual=$actualBaseVhdSha"
    }
}

$dockerStaticArtifact = Get-LockedArtifact ([string]$h.docker_static_dependency_id)
$dockerStaticPath = Join-Path $BundleRoot ([string]$dockerStaticArtifact.destination)
if (-not (Test-Path -LiteralPath $dockerStaticPath)) {
    throw "DOCKER_STATIC_ARCHIVE_MISSING: $dockerStaticPath"
}

$dockerStaticSha = ([string]$dockerStaticArtifact.sha256).ToLowerInvariant()
$actualDockerStaticSha = Get-GideonSha256 $dockerStaticPath
if ($actualDockerStaticSha -ne $dockerStaticSha) {
    throw "DOCKER_STATIC_SHA256_MISMATCH expected=$dockerStaticSha actual=$actualDockerStaticSha"
}

$dockerStaticName = Split-Path -Leaf $dockerStaticPath
$dockerStaticVersion = [string]$dockerStaticArtifact.version
Write-GideonPass "HYPERV_APPLIANCE_SHA256=PASS $actualBaseVhdSha"
Write-GideonPass "DOCKER_STATIC_SHA256=PASS $actualDockerStaticSha"

$imageMapPath = Join-Path $BundleRoot 'offline-cache\containers\images.json'
if (-not (Test-Path -LiteralPath $imageMapPath)) {
    throw "GUACD_IMAGE_MAP_MISSING: $imageMapPath"
}

$imageRows = @(Read-GideonJson $imageMapPath)
$guacdRow = @($imageRows | Where-Object { [string]$_.container -eq 'gideon-guacd' }) | Select-Object -First 1
if (-not $guacdRow -or -not [string]$guacdRow.image_id) {
    throw 'GUACD_IMAGE_NOT_CAPTURED'
}

$guacdImageId = [string]$guacdRow.image_id
$guacdArchive = [string]$guacdRow.archive
$guacdArchiveSha = [string]$guacdRow.archive_sha256
$guacdArchivePath = Join-Path $BundleRoot ('offline-cache\containers\' + $guacdArchive)

if (-not (Test-Path -LiteralPath $guacdArchivePath)) {
    throw "GUACD_ARCHIVE_MISSING: $guacdArchivePath"
}

if (-not $guacdArchiveSha) {
    throw 'GUACD_ARCHIVE_SHA256_MISSING'
}

$actualArchiveSha = Get-GideonSha256 $guacdArchivePath
if ($actualArchiveSha -ne $guacdArchiveSha.ToLowerInvariant()) {
    throw (
        "GUACD_ARCHIVE_SHA256_MISMATCH expected={0} actual={1}" -f
        $guacdArchiveSha,$actualArchiveSha
    )
}

Write-GideonPass "GUACD_ARCHIVE_SHA256=PASS $actualArchiveSha"

# Discover currently used routes. The private /28 is only Host <-> GIDEON-GUACD VM.
$used = @()
try {
    $used += @(Get-NetRoute -AddressFamily IPv4 | Select-Object -ExpandProperty DestinationPrefix)
} catch {}

try {
    if (Get-Command docker.exe -ErrorAction SilentlyContinue) {
        $networkIds = @(& docker.exe network ls -q 2>$null)
        if ($networkIds.Count -gt 0) {
            $raw = (& docker.exe network inspect $networkIds 2>$null | Out-String)
            if ($raw) {
                $objects = $raw | ConvertFrom-Json
                foreach ($network in @($objects)) {
                    foreach ($item in @($network.IPAM.Config)) {
                        if ($item.Subnet) {
                            $used += [string]$item.Subnet
                        }
                    }
                }
            }
        }
    }
} catch {}

$candidates = @($h.candidate_subnets) | ForEach-Object { [string]$_ }

$candidateJson = ConvertTo-GideonJson -Object @($candidates) -Depth 8 -Compress
$usedJson = ConvertTo-GideonJson -Object @($used) -Depth 8 -Compress

$selectedRaw = & $PythonExe `
    (Join-Path $BundleRoot 'installers\tools\find_free_subnet.py') `
    --candidates $candidateJson `
    --used $usedJson

if ($LASTEXITCODE -ne 0) {
    throw 'NO_FREE_HYPERV_SUBNET'
}

$selected = $selectedRaw | ConvertFrom-Json
$subnet = [string]$selected.subnet
$hostIp = [string]$selected.host_ip
$guestIp = [string]$selected.guest_ip
$prefix = [int]($subnet.Split('/')[1])

Write-GideonInfo "Hyper-V subnet=$subnet host=$hostIp guest=$guestIp"

$switchName = [string]$h.switch_name
$natName = [string]$h.nat_name
$vmName = [string]$h.vm_name

if ($validationMode) {
    $switchName = "$switchName-Validation"
    $natName = "$natName-Validation"
    $vmName = "$vmName-VALIDATION"
    Write-GideonWarn "VALIDATION_MODE vm=$vmName switch=$switchName nat=$natName"
}

if (-not (Get-VMSwitch -Name $switchName -ErrorAction SilentlyContinue)) {
    New-VMSwitch -Name $switchName -SwitchType Internal | Out-Null
}

$ifAlias = "vEthernet ($switchName)"
$currentHostIp = @(
    Get-NetIPAddress `
        -InterfaceAlias $ifAlias `
        -AddressFamily IPv4 `
        -ErrorAction SilentlyContinue
)

if (-not ($currentHostIp | Where-Object { [string]$_.IPAddress -eq $hostIp })) {
    # This touches only the GIDEON-owned Internal vSwitch, never the physical DHCP NIC.
    $currentHostIp |
        Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue

    New-NetIPAddress `
        -InterfaceAlias $ifAlias `
        -IPAddress $hostIp `
        -PrefixLength $prefix | Out-Null
}

$existingNat = Get-NetNat -Name $natName -ErrorAction SilentlyContinue
if ($existingNat) {
    if ([string]$existingNat.InternalIPInterfaceAddressPrefix -ne $subnet) {
        throw "NAT_CONFLICT: $natName ya existe con otra subred"
    }
}
else {
    New-NetNat `
        -Name $natName `
        -InternalIPInterfaceAddressPrefix $subnet | Out-Null
}

$vmRoot = "$env:ProgramData\GIDEON Remote Control\hyperv\$vmName"
New-GideonDirectory $vmRoot

# Stop and detach only the GIDEON-owned VM before replacing any attached disk.
# This also guarantees that validation always boots the candidate currently
# being hashed, rather than a stale OS disk left by an earlier run.
$existingVm = Get-VM -Name $vmName -ErrorAction SilentlyContinue
if ($existingVm) {
    Stop-VM -Name $vmName -TurnOff -Force -ErrorAction SilentlyContinue
    Remove-VM -Name $vmName -Force
}

$vmVhd = Join-Path $vmRoot 'GIDEON-GUACD-OS.vhdx'
$vmVhdStage = "$vmVhd.stage-$([guid]::NewGuid().ToString('N'))"
$vmVhdBackup = "$vmVhd.previous"
try {
    Copy-Item -LiteralPath $baseVhd -Destination $vmVhdStage -Force
    $stagedVhdSha = Get-GideonSha256 $vmVhdStage
    if ($stagedVhdSha -ne $actualBaseVhdSha) {
        throw "HYPERV_APPLIANCE_STAGE_SHA256_MISMATCH expected=$actualBaseVhdSha actual=$stagedVhdSha"
    }

    if (Test-Path -LiteralPath $vmVhd) {
        Remove-Item -LiteralPath $vmVhdBackup -Force -ErrorAction SilentlyContinue
        [IO.File]::Replace($vmVhdStage,$vmVhd,$vmVhdBackup,$true)
        Remove-Item -LiteralPath $vmVhdBackup -Force -ErrorAction SilentlyContinue
    }
    else {
        Move-Item -LiteralPath $vmVhdStage -Destination $vmVhd
    }
}
finally {
    Remove-Item -LiteralPath $vmVhdStage -Force -ErrorAction SilentlyContinue
}

# Prepare a data VHDX containing the exact captured image and a deterministic launcher.
$dataVhd = Join-Path $vmRoot 'GIDEON-GUACD-DATA.vhdx'
if (Test-Path -LiteralPath $dataVhd) {
    Remove-Item -LiteralPath $dataVhd -Force
}

New-VHD -Path $dataVhd -SizeBytes 8GB -Dynamic | Out-Null

try {
    $disk = @(Mount-VHD $dataVhd -PassThru | Get-Disk) | Select-Object -First 1

    if (-not $disk -or [string]$disk.PartitionStyle -ne 'RAW') {
        throw 'GIDEONDATA_RAW_DISK_NOT_FOUND'
    }

    Initialize-Disk -Number $disk.Number -PartitionStyle MBR | Out-Null
    $partition = New-Partition `
        -DiskNumber $disk.Number `
        -UseMaximumSize `
        -AssignDriveLetter

    $volume = Format-Volume `
        -Partition $partition `
        -FileSystem NTFS `
        -NewFileSystemLabel GIDEONDATA `
        -Confirm:$false

    $drive = ([string]$volume.DriveLetter + ':')

    Copy-Item `
        -LiteralPath $guacdArchivePath `
        -Destination (Join-Path $drive $guacdArchive) `
        -Force

    Copy-Item `
        -LiteralPath $imageMapPath `
        -Destination (Join-Path $drive 'images.json') `
        -Force

    Copy-Item `
        -LiteralPath $dockerStaticPath `
        -Destination (Join-Path $drive $dockerStaticName) `
        -Force

    $launcherTemplatePath = Join-Path $PSScriptRoot 'templates\start-guacd.sh.tpl'
    if (-not (Test-Path -LiteralPath $launcherTemplatePath -PathType Leaf)) {
        throw "GUACD_LAUNCHER_TEMPLATE_MISSING: $launcherTemplatePath"
    }

    $launcher = Get-Content -LiteralPath $launcherTemplatePath -Raw -Encoding UTF8
    $launcherReplacements = [ordered]@{
        '@@GUACD_ARCHIVE@@' = $guacdArchive
        '@@GUACD_ARCHIVE_SHA256@@' = $guacdArchiveSha
        '@@GUACD_IMAGE_ID@@' = $guacdImageId
        '@@DOCKER_STATIC_ARCHIVE@@' = $dockerStaticName
        '@@DOCKER_STATIC_SHA256@@' = $dockerStaticSha
        '@@DOCKER_STATIC_VERSION@@' = $dockerStaticVersion
        '@@GUACD_MEMORY@@' = $guacdContainerMemory
        '@@GUACD_CPUS@@' = $guacdContainerCpus
    }
    foreach ($placeholder in $launcherReplacements.Keys) {
        $launcher = $launcher.Replace($placeholder,[string]$launcherReplacements[$placeholder])
    }
    if ($launcher -match '@@[A-Z0-9_]+@@') {
        throw "GUACD_LAUNCHER_TEMPLATE_UNRESOLVED: $($Matches[0])"
    }

    Write-GideonUtf8NoBom `
        -Path (Join-Path $drive 'start-guacd.sh') `
        -Text $launcher
}
finally {
    Dismount-VHD $dataVhd -ErrorAction SilentlyContinue
}

# Seed VHDX for NoCloud. The appliance contract guarantees cloud-init and eth0.
$seed = Join-Path $vmRoot 'GIDEON-GUACD-CIDATA.vhdx'
if (Test-Path -LiteralPath $seed) {
    Remove-Item -LiteralPath $seed -Force
}

New-VHD -Path $seed -SizeBytes 128MB -Dynamic | Out-Null

try {
    $disk = @(Mount-VHD $seed -PassThru | Get-Disk) | Select-Object -First 1

    if (-not $disk -or [string]$disk.PartitionStyle -ne 'RAW') {
        throw 'CIDATA_RAW_DISK_NOT_FOUND'
    }

    Initialize-Disk -Number $disk.Number -PartitionStyle MBR | Out-Null
    $partition = New-Partition `
        -DiskNumber $disk.Number `
        -UseMaximumSize `
        -AssignDriveLetter

    $volume = Format-Volume `
        -Partition $partition `
        -FileSystem FAT32 `
        -NewFileSystemLabel CIDATA `
        -Confirm:$false

    $drive = ([string]$volume.DriveLetter + ':')

    $userData = @"
#cloud-config
hostname: gideon-guacd
manage_etc_hosts: true
users: []
disable_root: true
ssh_pwauth: false
package_update: false
package_upgrade: false

write_files:
  - path: /etc/gideon-guacd/host.json
    permissions: '0600'
    content: |
      {"host_ip":"$hostIp","guest_ip":"$guestIp","subnet":"$subnet","guacd_port":4822}

runcmd:
  - [ sh, -c, 'mkdir -p /mnt/gideondata /etc/gideon-guacd' ]
  - [ sh, -c, 'systemctl disable --now ssh.service ssh.socket 2>/dev/null || true' ]
  - [ sh, -c, 'systemctl disable --now apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true' ]
  - [ sh, -c, 'mount -t ntfs3 /dev/disk/by-label/GIDEONDATA /mnt/gideondata || mount /dev/disk/by-label/GIDEONDATA /mnt/gideondata' ]
  - [ sh, -c, 'chmod 0700 /mnt/gideondata/start-guacd.sh' ]
  - [ sh, -c, '/mnt/gideondata/start-guacd.sh' ]
"@

    $metaData = @"
instance-id: gideon-guacd-$([guid]::NewGuid().ToString('N'))
local-hostname: gideon-guacd
"@

    # No public DNS is hard-coded. The VM uses IP targets for GIDEON RDP/SSH paths.
    $networkConfig = @"
version: 2
ethernets:
  gideon_hyperv:
    match:
      driver: hv_netvsc
    set-name: eth0
    dhcp4: false
    addresses:
      - $guestIp/$prefix
    routes:
      - to: 0.0.0.0/0
        via: $hostIp
"@

    Write-GideonUtf8NoBom -Path (Join-Path $drive 'user-data') -Text $userData
    Write-GideonUtf8NoBom -Path (Join-Path $drive 'meta-data') -Text $metaData
    Write-GideonUtf8NoBom -Path (Join-Path $drive 'network-config') -Text $networkConfig
}
finally {
    Dismount-VHD $seed -ErrorAction SilentlyContinue
}

New-VM `
    -Name $vmName `
    -Generation 2 `
    -MemoryStartupBytes ([int64]$memoryStartupMb * 1MB) `
    -VHDPath $vmVhd `
    -SwitchName $switchName | Out-Null

Set-VMProcessor -VMName $vmName -Count ([int]$h.vm_cpu_count)
if($dynamicMemory){
    Set-VMMemory `
        -VMName $vmName `
        -DynamicMemoryEnabled $true `
        -MinimumBytes ([int64]$memoryMinimumMb * 1MB) `
        -StartupBytes ([int64]$memoryStartupMb * 1MB) `
        -MaximumBytes ([int64]$memoryMaximumMb * 1MB) `
        -Buffer $memoryBufferPercent `
        -Priority 50
}else{
    Set-VMMemory -VMName $vmName -DynamicMemoryEnabled $false -StartupBytes ([int64]$memoryStartupMb * 1MB)
}

Set-VMFirmware `
    -VMName $vmName `
    -EnableSecureBoot On `
    -SecureBootTemplate MicrosoftUEFICertificateAuthority

Set-VM `
    -Name $vmName `
    -AutomaticStartAction StartIfRunning `
    -AutomaticStopAction ShutDown `
    -CheckpointType ProductionOnly

Add-VMHardDiskDrive -VMName $vmName -Path $seed | Out-Null
Add-VMHardDiskDrive -VMName $vmName -Path $dataVhd | Out-Null

Start-VM -Name $vmName | Out-Null

$deadline = (Get-Date).AddMinutes(7)
$ok = $false

while ((Get-Date) -lt $deadline) {
    Write-Host '[WAIT] Esperando guacd privado en la micro-VM...'

    try {
        $tcp = New-Object Net.Sockets.TcpClient
        $async = $tcp.BeginConnect($guestIp, 4822, $null, $null)

        if ($async.AsyncWaitHandle.WaitOne(1500)) {
            $tcp.EndConnect($async)
            $ok = $true
            $tcp.Close()
            break
        }

        $tcp.Close()
    }
    catch {}

    Start-Sleep -Seconds 5
}

if (-not $ok) {
    throw "GUACD_VM_HEALTH_TIMEOUT: ${guestIp}:4822"
}

if ($validationMode) {
    $validatedVm = Get-VM -Name $vmName -ErrorAction Stop
    if ([int]$validatedVm.Generation -ne 2 -or [string]$validatedVm.State -ne 'Running') {
        throw 'HYPERV_GENERATION2_BOOT_VALIDATION_FAILED'
    }

    $validatedFirmware = Get-VMFirmware -VMName $vmName -ErrorAction Stop
    if ([string]$validatedFirmware.SecureBoot -ne 'On') {
        throw 'HYPERV_SECURE_BOOT_VALIDATION_FAILED'
    }

    $validationReport = [ordered]@{
        schema_version = 1
        generated_utc = [DateTime]::UtcNow.ToString('o')
        result = 'PASS'
        tested_on_hyperv = $true
        appliance_sha256 = $actualBaseVhdSha
        appliance_path = $baseVhd
        vm = $vmName
        guest_ip = $guestIp
        tests = [ordered]@{
            generation2_boot = $true
            secure_boot = $true
            cloud_init = $true
            docker_offline = $true
            guacd_tcp_4822 = $true
        }
        evidence = [ordered]@{
            vm_state = [string]$validatedVm.State
            vm_generation = [int]$validatedVm.Generation
            secure_boot = [string]$validatedFirmware.SecureBoot
            secure_boot_template = 'MicrosoftUEFICertificateAuthority'
            docker_static_sha256 = $actualDockerStaticSha
            guacd_archive_sha256 = $actualArchiveSha
            tcp_endpoint = "${guestIp}:4822"
        }
    }

    $validationReportFull = [IO.Path]::GetFullPath($ValidationReportPath)
    New-GideonDirectory (Split-Path -Parent $validationReportFull)
    Write-GideonJson $validationReport $validationReportFull 12
    Write-GideonPass "HYPERV_APPLIANCE_VALIDATION=PASS report=$validationReportFull"
}

# GIDEON owns only this outbound firewall rule. No global firewall reset.
$ruleName = if ($validationMode) {
    'GIDEON-RC-Guacd-HyperV-Validation'
}
else {
    'GIDEON-RC-Guacd-HyperV-Private'
}

Get-NetFirewallRule `
    -DisplayName $ruleName `
    -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue

New-NetFirewallRule `
    -DisplayName $ruleName `
    -DisplayGroup 'GIDEON Remote Control' `
    -Direction Outbound `
    -Action Allow `
    -RemoteAddress $guestIp `
    -Protocol TCP `
    -RemotePort 4822 | Out-Null

Write-Host "GUACD_HYPERV=PASS guest=$guestIp port=4822 subnet=$subnet"

Write-GideonJson `
    ([ordered]@{
        host_ip = $hostIp
        guest_ip = $guestIp
        subnet = $subnet
        port = 4822
        vm = $vmName
        docker_network_mode = 'host-inside-dedicated-microvm'
        physical_lan_ip_dependency = $false
        resource_profile = [string]$cfg.windows.resource_profile
        dynamic_memory = $dynamicMemory
        memory_minimum_mb = $memoryMinimumMb
        memory_startup_mb = $memoryStartupMb
        memory_maximum_mb = $memoryMaximumMb
        processors = [int]$h.vm_cpu_count
        guacd_container_memory = $guacdContainerMemory
        guacd_container_cpus = $guacdContainerCpus
    }) `
    (Join-Path $vmRoot 'runtime.json') `
    8

$global:LASTEXITCODE = 0
return
