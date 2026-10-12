param(
    [Parameter(Mandatory=$true)][string]$PackageRoot,
    [ValidateSet('auto','windows-home','windows-hyperv')][string]$Profile='auto'
)

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function Write-GideonPortableInfo([string]$Text){Write-Host "[PORTABLE] $Text" -ForegroundColor Cyan}
function Write-GideonPortablePass([string]$Text){Write-Host "[PASS] $Text" -ForegroundColor Green}
function Write-GideonPortableWarn([string]$Text){Write-Host "[WARN] $Text" -ForegroundColor Yellow}
function Stop-GideonPortable([string]$Text,[int]$Code=90){Write-Host "[FAIL] $Text" -ForegroundColor Red;exit $Code}

function Assert-GideonSafeCacheTarget([string]$Path,[string]$AllowedRoot){
    $full=[IO.Path]::GetFullPath($Path).TrimEnd([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar)
    $root=[IO.Path]::GetFullPath($AllowedRoot).TrimEnd([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar)
    $prefix=$root+[IO.Path]::DirectorySeparatorChar
    if($full.Equals($root,[StringComparison]::OrdinalIgnoreCase) -or -not $full.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){
        Stop-GideonPortable "Destino de caché inseguro rechazado: $full" 98
    }
}

function Assert-GideonPortableFreeSpace([string]$Path,[string]$SelectedProfile){
    $root=[IO.Path]::GetPathRoot([IO.Path]::GetFullPath($Path))
    if([string]::IsNullOrWhiteSpace($root)){Stop-GideonPortable "No se pudo resolver la unidad de caché: $Path" 98}
    $drive=Get-PSDrive -Name $root.Substring(0,1) -ErrorAction Stop
    $required=if($SelectedProfile -eq 'windows-hyperv'){12GB}else{8GB}
    if([long]$drive.Free -lt [long]$required){
        Stop-GideonPortable "Espacio insuficiente para preparar $SelectedProfile. Unidad=$root libre=$([math]::Round($drive.Free/1GB,2))GB requerido=$([math]::Round($required/1GB))GB" 98
    }
    Write-GideonPortablePass "PACKAGE_CACHE_SPACE=PASS free_gb=$([math]::Round($drive.Free/1GB,2)) required_gb=$([math]::Round($required/1GB))"
}

function Test-GideonAdministrator {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-GideonWindowsProfile {
    $os=Get-CimInstance Win32_OperatingSystem
    $computer=Get-CimInstance Win32_ComputerSystem
    $edition=''
    try{
        $edition=[string](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name EditionID -ErrorAction Stop).EditionID
    }catch{}
    $isClient=([int]$os.ProductType -eq 1)
    $isHome=$isClient -and ($edition -match '(?i)Core|Home')
    return [pscustomobject]@{
        Selected=if($isHome){'windows-home'}else{'windows-hyperv'}
        Caption=[string]$os.Caption
        Edition=$edition
        IsHome=$isHome
        IsClient=$isClient
        BuildNumber=[int]$os.BuildNumber
        TotalPhysicalMemory=[uint64]$computer.TotalPhysicalMemory
        LogicalProcessors=[int]$computer.NumberOfLogicalProcessors
    }
}

function Read-GideonModuleManifest([string]$Path){
    if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){Stop-GideonPortable "Manifiesto de módulos ausente: $Path" 91}
    $rows=@()
    foreach($line in Get-Content -LiteralPath $Path){
        $text=[string]$line
        if([string]::IsNullOrWhiteSpace($text) -or $text.TrimStart().StartsWith('#')){continue}
        if($text -notmatch '^([0-9a-fA-F]{64})\s+\*?([^\\/]+)$'){
            Stop-GideonPortable "Línea inválida en manifiesto: $text" 91
        }
        $name=[string]$matches[2]
        if($name -match '[\x00-\x1f:]' -or $name -in @('.','..')){Stop-GideonPortable "Nombre de módulo inseguro: $name" 91}
        $rows += [pscustomobject]@{Sha256=$matches[1].ToLowerInvariant();Name=$name}
    }
    if($rows.Count -eq 0){Stop-GideonPortable "El manifiesto no contiene módulos: $Path" 91}
    return $rows
}

function New-GideonRecoveredProfileManifest([string]$SelectedProfile){
    $packageManifestPath=Join-Path $PackageRoot 'package.manifest.json'
    if(-not(Test-Path -LiteralPath $packageManifestPath -PathType Leaf)){
        Stop-GideonPortable "Faltan profiles\$SelectedProfile.sha256 y package.manifest.json. La copia del kit está incompleta." 91
    }
    try{
        $packageManifest=Get-Content -LiteralPath $packageManifestPath -Raw | ConvertFrom-Json
    }catch{
        Stop-GideonPortable "package.manifest.json no es válido: $($_.Exception.Message)" 91
    }
    if([int]$packageManifest.schema_version -ne 1){
        Stop-GideonPortable 'package.manifest.json tiene una versión no compatible.' 91
    }

    $requiredNames=switch($SelectedProfile){
        'windows-home' {@('10-GIDEON-COMMON.tar.gz','20-GIDEON-WINDOWS.tar.gz')}
        'windows-hyperv' {@('10-GIDEON-COMMON.tar.gz','20-GIDEON-WINDOWS.tar.gz','30-GIDEON-HYPERV.tar.gz')}
        default {Stop-GideonPortable "No se puede recuperar el perfil: $SelectedProfile" 91}
    }
    $lines=@()
    foreach($name in $requiredNames){
        $matches=@($packageManifest.modules|Where-Object{[string]$_.filename -eq $name})
        if($matches.Count -ne 1){
            Stop-GideonPortable "package.manifest.json no contiene exactamente un módulo $name" 91
        }
        $sha=([string]$matches[0].sha256).ToLowerInvariant()
        if($sha -notmatch '^[0-9a-f]{64}$'){
            Stop-GideonPortable "SHA-256 inválido para $name en package.manifest.json" 91
        }
        $lines += "$sha *$name"
    }

    $packageHash=(Get-FileHash -LiteralPath $packageManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $recoveryRoot=Join-Path $env:ProgramData ("GIDEON\RecoveredProfiles\{0}" -f $packageHash.Substring(0,24))
    New-Item -ItemType Directory -Path $recoveryRoot -Force | Out-Null
    $recoveredPath=Join-Path $recoveryRoot ($SelectedProfile+'.sha256')
    Set-Content -LiteralPath $recoveredPath -Value $lines -Encoding Ascii
    return $recoveredPath
}

function Get-GideonEffectiveProfileManifest([string]$SelectedProfile,[string]$ShippedPath){
    $packageManifestPath=Join-Path $PackageRoot 'package.manifest.json'
    if(Test-Path -LiteralPath $packageManifestPath -PathType Leaf){
        $generatedPath=New-GideonRecoveredProfileManifest $SelectedProfile
        if(Test-Path -LiteralPath $ShippedPath -PathType Leaf){
            $shippedHash=(Get-FileHash -LiteralPath $ShippedPath -Algorithm SHA256).Hash.ToLowerInvariant()
            $generatedHash=(Get-FileHash -LiteralPath $generatedPath -Algorithm SHA256).Hash.ToLowerInvariant()
            if($shippedHash -eq $generatedHash){return $ShippedPath}
            Write-GideonPortableWarn "PROFILE_MANIFEST_STALE=$ShippedPath"
        }else{
            Write-GideonPortableWarn "PROFILE_MANIFEST_MISSING=$ShippedPath"
        }
        Write-GideonPortableWarn "PROFILE_MANIFEST_REBUILT_FROM_PACKAGE=$generatedPath"
        return $generatedPath
    }
    if(Test-Path -LiteralPath $ShippedPath -PathType Leaf){return $ShippedPath}
    Stop-GideonPortable "Faltan $ShippedPath y package.manifest.json. La copia del kit esta incompleta." 91
}

function Get-GideonPackageModule($Row,[string]$DownloadRoot){
    $local=Join-Path $PackageRoot ([string]$Row.Name)
    if(Test-Path -LiteralPath $local -PathType Leaf){return $local}

    $cached=Join-Path $DownloadRoot (('{0}-{1}' -f [string]$Row.Sha256,[string]$Row.Name))
    if(Test-Path -LiteralPath $cached -PathType Leaf){return $cached}

    $base=[string]$env:GIDEON_PACKAGE_BASE_URL
    if([string]::IsNullOrWhiteSpace($base)){
        Stop-GideonPortable "Falta el módulo $($Row.Name). Copie el kit completo o defina GIDEON_PACKAGE_BASE_URL." 92
    }

    if(-not(Get-Command Start-BitsTransfer -ErrorAction SilentlyContinue)){
        Import-Module BitsTransfer -ErrorAction Stop
    }
    New-Item -ItemType Directory -Path $DownloadRoot -Force | Out-Null
    $url=$base.TrimEnd('/')+'/'+[Uri]::EscapeDataString([string]$Row.Name)
    $partial=$cached+'.partial'
    Remove-Item -LiteralPath $partial -Force -ErrorAction SilentlyContinue
    Write-GideonPortableInfo "Descargando con BITS: $url"
    Start-BitsTransfer -Source $url -Destination $partial -DisplayName ('Gideon Rx '+[string]$Row.Name) -Description 'Gideon Rx Portable OneClick module'
    Move-Item -LiteralPath $partial -Destination $cached -Force
    return $cached
}

function Test-GideonModuleHash([string]$Path,[string]$Expected){
    Write-GideonPortableInfo "Verificando SHA-256: $(Split-Path -Leaf $Path)"
    $actual=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if($actual -ne $Expected){
        Stop-GideonPortable "KIT_MIXED_VERSION: SHA-256 invalido para $Path. Esperado=$Expected Actual=$actual. Renombre la carpeta anterior y copie el kit completo en una carpeta nueva; no mezcle versiones." 93
    }
}

if(-not(Test-GideonAdministrator)){Stop-GideonPortable 'Ejecute el OneClick como Administrador.' 90}
try{
    $PackageRoot=[IO.Path]::GetFullPath($PackageRoot.Trim().Trim('"'))
}catch{
    Stop-GideonPortable "La ruta del kit es inválida: [$PackageRoot]. Detalle: $($_.Exception.Message)" 91
}
if(-not(Test-Path -LiteralPath $PackageRoot -PathType Container)){
    Stop-GideonPortable "La carpeta del kit no existe: $PackageRoot" 91
}
if(-not [Environment]::Is64BitOperatingSystem){
    Stop-GideonPortable 'Gideon Rx requiere Windows x64.' 94
}
$detected=Get-GideonWindowsProfile
if(([bool]$detected.IsClient -and [int]$detected.BuildNumber -lt 19045) -or (-not [bool]$detected.IsClient -and [int]$detected.BuildNumber -lt 17763)){
    Stop-GideonPortable "Windows no soportado: $($detected.Caption) build=$($detected.BuildNumber). Requerido: Windows 10 22H2/11 o Windows Server 2019+." 94
}
if([uint64]$detected.TotalPhysicalMemory -lt [uint64]8GB){
    Stop-GideonPortable "Memoria insuficiente para Gideon Rx. Detectado=$([math]::Round($detected.TotalPhysicalMemory/1GB,2))GB requerido=8GB." 94
}
if([int]$detected.LogicalProcessors -lt 4){
    Stop-GideonPortable "CPU insuficiente para Gideon Rx. Procesadores logicos=$($detected.LogicalProcessors) requerido=4." 94
}
Write-GideonPortablePass "HOST_CAPACITY=PASS memory_gb=$([math]::Round($detected.TotalPhysicalMemory/1GB,2)) logical_processors=$($detected.LogicalProcessors)"
$resourceOverride=[string]$env:GIDEON_RESOURCE_PROFILE
if([string]::IsNullOrWhiteSpace($resourceOverride) -or $resourceOverride.Trim().ToLowerInvariant() -eq 'auto'){
    if([uint64]$detected.TotalPhysicalMemory -ge [uint64]32GB -and [int]$detected.LogicalProcessors -ge 8){
        $resourceProfile='performance'
    }elseif([uint64]$detected.TotalPhysicalMemory -ge [uint64]16GB){
        $resourceProfile='standard'
    }else{
        $resourceProfile='compact'
    }
}else{
    $resourceProfile=$resourceOverride.Trim().ToLowerInvariant()
    if($resourceProfile -notin @('compact','standard','performance')){
        Stop-GideonPortable "GIDEON_RESOURCE_PROFILE invalido: $resourceOverride. Use auto, compact, standard o performance." 94
    }
}
$env:GIDEON_RESOURCE_PROFILE=$resourceProfile
Write-GideonPortablePass "RESOURCE_PROFILE=$resourceProfile"
$selected=if($Profile -eq 'auto'){[string]$detected.Selected}else{$Profile}

if($selected -eq 'windows-home' -and -not [bool]$detected.IsHome){
    Stop-GideonPortable "Este kit es exclusivo para Windows Home/Core. Detectado: $($detected.Caption) / $($detected.Edition)" 94
}
if($selected -eq 'windows-hyperv' -and [bool]$detected.IsHome){
    Stop-GideonPortable "Windows Home/Core no ofrece el rol Microsoft Hyper-V. Use el kit Windows Home/Docker." 94
}

$shippedProfileManifest=Join-Path $PackageRoot ("profiles\{0}.sha256" -f $selected)
$profileManifest=Get-GideonEffectiveProfileManifest $selected $shippedProfileManifest
$manifestHash=(Get-FileHash -LiteralPath $profileManifest -Algorithm SHA256).Hash.ToLowerInvariant()
$cacheBase=Join-Path $env:ProgramData 'GIDEON\PackageCache'
$cacheRoot=Join-Path $cacheBase $manifestHash.Substring(0,24)
$bundleRoot=Join-Path $cacheRoot 'bundle'
$marker=Join-Path $cacheRoot 'READY.json'
$downloadRoot=Join-Path $env:ProgramData 'GIDEON\PackageDownloads'

$mutex=New-Object Threading.Mutex($false,'Global\GIDEONPortableOneClickBootstrap')
$ownsMutex=$false
try{
    $ownsMutex=$mutex.WaitOne(0)
    if(-not $ownsMutex){Stop-GideonPortable 'Otro bootstrap Gideon Rx está preparando paquetes.' 95}

    $ready=$false
    if((Test-Path -LiteralPath $marker -PathType Leaf) -and (Test-Path -LiteralPath (Join-Path $bundleRoot 'deployment.manifest.json') -PathType Leaf)){
        try{
            $state=Get-Content -LiteralPath $marker -Raw | ConvertFrom-Json
            $ready=([string]$state.profile -eq $selected -and [string]$state.profile_manifest_sha256 -eq $manifestHash)
        }catch{$ready=$false}
    }
    if($ready -and -not(Test-Path -LiteralPath (Join-Path $bundleRoot 'installers\WINDOWS\INSTALL_GIDEON_MASTER_WINDOWS.cmd') -PathType Leaf)){
        $ready=$false
    }
    if($ready -and $selected -eq 'windows-home' -and -not(Test-Path -LiteralPath (Join-Path $bundleRoot 'offline-cache\containers\images.json') -PathType Leaf)){
        $ready=$false
    }
    if($ready -and $selected -eq 'windows-hyperv' -and -not(Test-Path -LiteralPath (Join-Path $bundleRoot 'offline-cache\hyperv\candidates\GIDEON-GUACD-UBUNTU-CANDIDATE.vhdx') -PathType Leaf)){
        $ready=$false
    }

    if(-not $ready){
        Assert-GideonPortableFreeSpace $cacheRoot $selected
        $modules=Read-GideonModuleManifest $profileManifest
        $stage=$cacheRoot+'.stage-'+[Diagnostics.Process]::GetCurrentProcess().Id
        Assert-GideonSafeCacheTarget $stage $cacheBase
        Assert-GideonSafeCacheTarget $cacheRoot $cacheBase
        if(Test-Path -LiteralPath $stage){Remove-Item -LiteralPath $stage -Recurse -Force}
        New-Item -ItemType Directory -Path (Join-Path $stage 'bundle') -Force | Out-Null
        $stageBundle=Join-Path $stage 'bundle'

        foreach($row in $modules){
            $module=Get-GideonPackageModule $row $downloadRoot
            Test-GideonModuleHash $module ([string]$row.Sha256)
            Write-GideonPortableInfo "Preparando $($row.Name) directamente en la caché local"
            & tar.exe -xzf $module -C $stageBundle
            if($LASTEXITCODE -ne 0){Stop-GideonPortable "No se pudo extraer $($row.Name), tar rc=$LASTEXITCODE" 96}
        }

        foreach($required in @('deployment.manifest.json','master.config.json','installers\WINDOWS\INSTALL_GIDEON_MASTER_WINDOWS.cmd')){
            if(-not(Test-Path -LiteralPath (Join-Path $stageBundle $required) -PathType Leaf)){
                Stop-GideonPortable "El paquete materializado está incompleto; falta $required" 97
            }
        }
        if($selected -eq 'windows-home' -and -not(Test-Path -LiteralPath (Join-Path $stageBundle 'offline-cache\containers\images.json') -PathType Leaf)){
            Stop-GideonPortable 'El kit Windows Home no contiene el cache de contenedores.' 97
        }
        if($selected -eq 'windows-hyperv' -and -not(Test-Path -LiteralPath (Join-Path $stageBundle 'offline-cache\hyperv\candidates\GIDEON-GUACD-UBUNTU-CANDIDATE.vhdx') -PathType Leaf)){
            Stop-GideonPortable 'El kit Hyper-V no contiene la VHDX candidata.' 97
        }

        $state=[ordered]@{
            schema_version=1
            profile=$selected
            profile_manifest_sha256=$manifestHash
            prepared_utc=[DateTime]::UtcNow.ToString('o')
            package_root=$PackageRoot
        }
        New-Item -ItemType Directory -Path $stage -Force | Out-Null
        $state|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $stage 'READY.json') -Encoding UTF8

        if(Test-Path -LiteralPath $cacheRoot){Remove-Item -LiteralPath $cacheRoot -Recurse -Force}
        Move-Item -LiteralPath $stage -Destination $cacheRoot
        Write-GideonPortablePass "PACKAGE_CACHE_READY=$cacheRoot"
    }else{
        Write-GideonPortablePass "PACKAGE_CACHE_REUSED=$cacheRoot"
    }
}finally{
    if($ownsMutex){try{$mutex.ReleaseMutex()}catch{}}
    $mutex.Dispose()
}

$installer=Join-Path $bundleRoot 'installers\WINDOWS\INSTALL_GIDEON_MASTER_WINDOWS.cmd'
$argumentLine=[string]$env:GIDEON_PORTABLE_INSTALLER_ARGS
Write-GideonPortableInfo "Plataforma: $($detected.Caption) / $($detected.Edition)"
Write-GideonPortableInfo "Perfil seleccionado: $selected"
Write-GideonPortableInfo "Iniciando el instalador GIDEON desde la caché verificada"

$start=@{FilePath=$installer;Wait=$true;PassThru=$true;WorkingDirectory=(Split-Path -Parent $installer)}
if(-not [string]::IsNullOrWhiteSpace($argumentLine)){$start['ArgumentList']=$argumentLine}
$process=Start-Process @start
exit [int]$process.ExitCode
