[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$BundleRoot,
    [Parameter(Mandatory=$true)][string]$DataRoot,
    [Parameter(Mandatory=$true)][string]$ConfigPath,
    [string]$ContainerName = 'gideon-guacd',
    [switch]$PreflightOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Import-Module (Join-Path $BundleRoot 'installers\common\GIDEON.Common.psm1') -Force

function Get-OptionalProperty($Object,[string]$Name,$DefaultValue) {
    $property = $Object.PSObject.Properties[$Name]
    if ($property -and $null -ne $property.Value) {
        return $property.Value
    }
    return $DefaultValue
}

function Resolve-DockerExecutable {
    $command = Get-Command docker.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    $candidates = @(
        (Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin\docker.exe'),
        (Join-Path $env:ProgramFiles 'Docker\Docker\resources\docker.exe')
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }
    throw 'DOCKER_DESKTOP_REQUIRED: install Docker Desktop with the WSL 2 backend, then run the same OneClick again.'
}

function Test-DockerEngine([string]$DockerExe) {
    $output = @(& $DockerExe info --format '{{.OSType}}' 2>$null)
    return ($LASTEXITCODE -eq 0 -and (($output -join '').Trim()) -eq 'linux')
}

function Start-DockerEngine([string]$DockerExe,[int]$TimeoutSeconds) {
    if (Test-DockerEngine $DockerExe) {
        return
    }

    $service = Get-Service -Name 'com.docker.service' -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne 'Running') {
        Start-Service -Name $service.Name -ErrorAction SilentlyContinue
    }

    $desktop = Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'
    if (Test-Path -LiteralPath $desktop -PathType Leaf) {
        $running = Get-Process -Name 'Docker Desktop' -ErrorAction SilentlyContinue
        if (-not $running) {
            Start-Process -FilePath $desktop -WindowStyle Hidden
        }
    }

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Seconds 3
        if (Test-DockerEngine $DockerExe) {
            return
        }
    } while ([DateTime]::UtcNow -lt $deadline)

    throw "DOCKER_LINUX_ENGINE_NOT_READY timeout_seconds=$TimeoutSeconds"
}

function Test-TcpPort([string]$HostName,[int]$Port,[int]$TimeoutMs=1500) {
    $client = New-Object Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($HostName,$Port,$null,$null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs)) {
            return $false
        }
        $client.EndConnect($async)
        return $true
    }
    catch {
        return $false
    }
    finally {
        $client.Close()
    }
}

$cfg = Read-GideonJson $ConfigPath
$dockerCfgProperty = $cfg.windows.PSObject.Properties['docker_desktop']
if (-not $dockerCfgProperty) {
    throw 'windows.docker_desktop is not configured.'
}
$dockerCfg = $dockerCfgProperty.Value
$timeout = [int](Get-OptionalProperty $dockerCfg 'startup_timeout_seconds' 180)
$bindHost = [string](Get-OptionalProperty $dockerCfg 'guacd_bind_host' '127.0.0.1')
$preferredPort = [int](Get-OptionalProperty $dockerCfg 'guacd_host_port' 4822)
$guacdMemory = [string](Get-OptionalProperty $dockerCfg 'guacd_memory' '768m')
$guacdCpus = [string](Get-OptionalProperty $dockerCfg 'guacd_cpus' '1.0')
if($guacdMemory -notmatch '^[0-9]+[mMgG]$'){throw "DOCKER_GUACD_MEMORY_INVALID: $guacdMemory"}
if($guacdCpus -notmatch '^[0-9]+(?:\.[0-9]+)?$'){throw "DOCKER_GUACD_CPUS_INVALID: $guacdCpus"}

if ($ContainerName -notmatch '^gideon-[a-z0-9][a-z0-9_.-]{0,62}$') {
    throw "DOCKER_CONTAINER_NAME_INVALID: $ContainerName"
}

if ($bindHost -ne '127.0.0.1') {
    throw "DOCKER_GUACD_BIND_NOT_PRIVATE: $bindHost"
}

$docker = Resolve-DockerExecutable
Start-DockerEngine -DockerExe $docker -TimeoutSeconds $timeout

$mapPath = Join-Path $BundleRoot 'offline-cache\containers\images.json'
if (-not (Test-Path -LiteralPath $mapPath -PathType Leaf)) {
    throw "DOCKER_IMAGE_MAP_MISSING: $mapPath"
}

$rows = @(Read-GideonJson $mapPath)
if ($rows.Count -eq 0) {
    throw 'DOCKER_IMAGE_MAP_EMPTY'
}

foreach ($row in $rows) {
    $imageId = [string]$row.image_id
    $archiveName = [string]$row.archive
    $expectedSha = ([string]$row.archive_sha256).ToLowerInvariant()
    if ($imageId -notmatch '^sha256:[a-fA-F0-9]{64}$') {
        throw "DOCKER_IMAGE_ID_NOT_IMMUTABLE: $imageId"
    }
    if ([string]::IsNullOrWhiteSpace($archiveName) -or $expectedSha -notmatch '^[a-f0-9]{64}$') {
        throw "DOCKER_IMAGE_METADATA_INVALID: $([string]$row.container)"
    }
    $archivePath = Join-Path $BundleRoot ('offline-cache\containers\' + $archiveName)
    if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
        throw "DOCKER_IMAGE_ARCHIVE_MISSING: $archivePath"
    }
    $actualSha = Get-GideonSha256 $archivePath
    if ($actualSha -ne $expectedSha) {
        throw "DOCKER_IMAGE_ARCHIVE_SHA256_MISMATCH archive=$archiveName expected=$expectedSha actual=$actualSha"
    }
}

$guacd = @($rows | Where-Object { [string]$_.container -eq 'gideon-guacd' }) | Select-Object -First 1
if (-not $guacd) {
    throw 'DOCKER_GUACD_IMAGE_NOT_DECLARED'
}

Write-GideonPass "DOCKER_DESKTOP_PREFLIGHT=PASS images=$($rows.Count)"
if ($PreflightOnly) {
    $global:LASTEXITCODE = 0
    return
}

$guacdImage = [string]$guacd.image_id
$guacdArchive = Join-Path $BundleRoot ('offline-cache\containers\' + [string]$guacd.archive)

& $docker image inspect $guacdImage *> $null
if ($LASTEXITCODE -ne 0) {
    Write-GideonInfo "Loading pinned guacd image from $guacdArchive"
    & $docker load --input $guacdArchive | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "DOCKER_GUACD_LOAD_FAILED rc=$LASTEXITCODE"
    }
}

& $docker image inspect $guacdImage *> $null
if ($LASTEXITCODE -ne 0) {
    throw "DOCKER_GUACD_IMAGE_NOT_LOADED: $guacdImage"
}

$existingName = @(& $docker ps -a --filter "name=^/$ContainerName`$" --format '{{.Names}}' 2>$null)
if ($existingName -contains $ContainerName) {
    $existingRaw = (& $docker inspect $ContainerName 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($existingRaw)) {
        throw "DOCKER_CONTAINER_INSPECT_FAILED: $ContainerName"
    }
    $existingObject = @($existingRaw | ConvertFrom-Json)[0]
    $owner = [string]$existingObject.Config.Labels.'com.gideon.remote-control'
    if ($owner -ne 'true') {
        throw "DOCKER_CONTAINER_NAME_CONFLICT: $ContainerName is not owned by GIDEON."
    }
    & $docker rm --force $ContainerName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "DOCKER_GUACD_REMOVE_FAILED rc=$LASTEXITCODE"
    }
}

$port = $preferredPort
while (-not (Test-GideonTcpPortFree $port)) {
    $port++
    if ($port -gt ($preferredPort + 100)) {
        throw "DOCKER_GUACD_NO_FREE_PORT start=$preferredPort"
    }
}

$runArgs = @(
    'run','--detach',
    '--name',$ContainerName,
    '--label','com.gideon.remote-control=true',
    '--restart','unless-stopped',
    '--init',
    '--read-only',
    '--cap-drop','ALL',
    '--security-opt','no-new-privileges:true',
    '--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=64m',
    '--tmpfs','/home/guacd:rw,nosuid,nodev,size=16m,uid=1000,gid=1000,mode=0700',
    '--pids-limit','256',
    '--memory',$guacdMemory,
    '--cpus',$guacdCpus,
    '--log-opt','max-size=10m',
    '--log-opt','max-file=3',
    '--health-interval','30s',
    '--health-timeout','5s',
    '--health-retries','3',
    '--health-start-period','5s',
    '--publish',"${bindHost}:${port}:4822",
    $guacdImage
)

$containerId = (@(& $docker @runArgs 2>&1) -join '').Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($containerId)) {
    throw "DOCKER_GUACD_RUN_FAILED rc=$LASTEXITCODE output=$containerId"
}

$ready = $false
for ($attempt = 1; $attempt -le 60; $attempt++) {
    if (Test-TcpPort -HostName $bindHost -Port $port) {
        $ready = $true
        break
    }
    Start-Sleep -Seconds 2
}

if (-not $ready) {
    $logs = (@(& $docker logs --tail 100 $ContainerName 2>&1) -join [Environment]::NewLine)
    throw "DOCKER_GUACD_TCP_TIMEOUT endpoint=${bindHost}:$port logs=$logs"
}

$runtimePath = Join-Path $DataRoot 'guacd\runtime.json'
New-GideonDirectory (Split-Path -Parent $runtimePath)
Write-GideonJson `
    ([ordered]@{
        backend = 'docker-desktop'
        host = $bindHost
        guest_ip = $bindHost
        port = $port
        container = $ContainerName
        image_id = $guacdImage
        archive_sha256 = ([string]$guacd.archive_sha256).ToLowerInvariant()
        physical_lan_ip_dependency = $false
        generated_utc = [DateTime]::UtcNow.ToString('o')
    }) `
    $runtimePath `
    8

Write-GideonPass "GUACD_DOCKER_DESKTOP=PASS endpoint=${bindHost}:$port image=$guacdImage"
$global:LASTEXITCODE = 0
return
