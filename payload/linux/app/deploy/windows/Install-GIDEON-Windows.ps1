#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$InstallRoot = "$env:ProgramFiles\GIDEON Remote Control",
    [string]$DataRoot = "$env:ProgramData\GIDEON Remote Control",
    [string]$WebHost = $env:COMPUTERNAME,
    [ValidateRange(1024,65535)][int]$WebPort = 28443,
    [string]$GatewayHost = $env:COMPUTERNAME,
    [ValidateRange(1024,65535)][int]$GatewayPort = 29443,
    [string]$PythonExe = "",
    [string]$OfflineWheelDir = "",
    [string]$MigrateFrom = "",
    [ValidateSet('Any','Desktop','Server')][string]$ExpectedHostType = 'Any',
    [switch]$AddFirewallRules,
    [switch]$InstallPythonIfMissing,
    [switch]$NonInteractive,
    [switch]$StartServices = $true
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

function Test-IsAdministrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Quote-ProcessArgument([string]$Value) {
    return '"' + ($Value -replace '"', '\"') + '"'
}

if (-not (Test-IsAdministrator)) {
    $relaunch = @('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',(Quote-ProcessArgument $PSCommandPath))
    foreach ($key in $PSBoundParameters.Keys) {
        $value = $PSBoundParameters[$key]
        if ($value -is [System.Management.Automation.SwitchParameter]) {
            if ([bool]$value) { $relaunch += ('-' + $key) }
            continue
        }
        $relaunch += ('-' + $key)
        $relaunch += (Quote-ProcessArgument ([string]$value))
    }
    Write-Host 'Solicitando permisos de Administrador para instalar GIDEON Remote Control...' -ForegroundColor Yellow
    $proc = Start-Process powershell.exe -Verb RunAs -Wait -PassThru -ArgumentList $relaunch
    exit $proc.ExitCode
}
$SourceRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$ServiceNames = @(
    'GIDEONRemoteControl',
    'GIDEONRemoteControlGateway',
    'GIDEONRemoteControlWebAdmin',
    'GIDEONRemoteControlBackup',
    'GIDEONRemoteControlUpdater',
    'GIDEONRemoteControlDiagnostics'
)

$RegistryModule = Join-Path $PSScriptRoot 'Gideon-WindowsRegistry.ps1'
if (-not (Test-Path -LiteralPath $RegistryModule -PathType Leaf)) { throw "Falta módulo de registro Windows GIDEON: $RegistryModule" }
. $RegistryModule

$IsolationModule = Join-Path $PSScriptRoot 'Gideon-WindowsServiceIsolation.ps1'
if (-not (Test-Path -LiteralPath $IsolationModule -PathType Leaf)) { throw "Falta módulo de aislamiento Windows GIDEON: $IsolationModule" }
. $IsolationModule

$CompatibilityModule = Join-Path $PSScriptRoot 'Gideon-WindowsCompatibility.ps1'
if (-not (Test-Path -LiteralPath $CompatibilityModule -PathType Leaf)) { throw "Falta módulo de compatibilidad Windows GIDEON: $CompatibilityModule" }
. $CompatibilityModule

$SupportModule = Join-Path $PSScriptRoot 'New-GideonWindowsSupportBundle.ps1'
if (-not (Test-Path -LiteralPath $SupportModule -PathType Leaf)) { throw "Falta módulo de soporte Windows GIDEON: $SupportModule" }
. $SupportModule

$script:GideonFailureBundleInProgress = $false
trap {
    $failure = $_
    try { Stop-GideonInstallTranscriptSafe } catch {}
    if (-not $script:GideonFailureBundleInProgress) {
        $script:GideonFailureBundleInProgress = $true
        try {
            $failureType = $failure.Exception.GetType().FullName
            $failurePosition = $failure.InvocationInfo.PositionMessage
            $bundle = New-GideonWindowsSupportBundle -InstallRoot $InstallRoot -DataRoot $DataRoot -SourceRoot $SourceRoot -FailureMessage ([string]$failure.Exception.Message) -FailureType ([string]$failureType) -FailurePosition ([string]$failurePosition)
            Write-Host "`n[GIDEON] SUPPORT BUNDLE GENERADO AUTOMÁTICAMENTE" -ForegroundColor Yellow
            Write-Host ("ZIP     : " + $bundle) -ForegroundColor Yellow
            Write-Host ("CARPETA : " + (Split-Path -Parent $bundle)) -ForegroundColor Yellow
            Write-Host 'Pásame ese ZIP completo para revisar el fallo.' -ForegroundColor Yellow
        } catch {
            Write-Warning ("No fue posible generar el Support Bundle GIDEON: " + $_.Exception.Message)
        }
    }
    exit 1
}

function Write-Step([string]$Text) {
    Write-Host "`n[GIDEON] $Text" -ForegroundColor Cyan
}

function Assert-Administrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Ejecute INSTALL-GIDEON-WINDOWS.cmd o este PowerShell como Administrador.'
    }
}

function Get-GideonWindowsHostType {
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        if ([int]$os.ProductType -eq 1) { return 'Desktop' }
        return 'Server'
    } catch {
        throw "No se pudo identificar si Windows es Desktop o Server: $($_.Exception.Message)"
    }
}

function Assert-GideonWindowsHostType {
    if ($ExpectedHostType -eq 'Any') { return }
    $actual = Get-GideonWindowsHostType
    if ($actual -ne $ExpectedHostType) {
        if ($ExpectedHostType -eq 'Desktop') {
            throw 'Este OneClick es exclusivo para Windows 10/11. Use el paquete WINDOWS-SERVER-ONECLICK en Windows Server.'
        }
        throw 'Este OneClick es exclusivo para Windows Server. Use el paquete WINDOWS-ONECLICK en Windows 10/11.'
    }
    Write-Host "Host validado: Windows $actual" -ForegroundColor Green
}

function Invoke-NativeProbe {
    param(
        [Parameter(Mandatory=$true)][string]$FilePath,
        [Parameter(Mandatory=$true)][string[]]$Arguments
    )
    # Windows PowerShell 5.1 can convert native STDERR into ErrorRecord objects.
    # Probes must never abort the installer merely because a launcher reports
    # "runtime not installed" on STDERR.
    $previousErrorAction = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'SilentlyContinue'
        $output = @(& $FilePath @Arguments 2>$null)
        $code = $LASTEXITCODE
        if ($null -eq $code) { $code = 0 }
        return [pscustomobject]@{ ExitCode = [int]$code; Output = $output }
    } catch {
        return [pscustomobject]@{ ExitCode = 9001; Output = @() }
    } finally {
        $ErrorActionPreference = $previousErrorAction
    }
}

function Resolve-CompatiblePythonCandidate {
    param(
        [Parameter(Mandatory=$true)][string]$FilePath,
        [string[]]$PrefixArguments = @()
    )
    $probeCode = "import sys; print(sys.executable); raise SystemExit(0 if sys.version_info >= (3,11) else 4)"
    $args = @($PrefixArguments) + @('-c', $probeCode)
    $probe = Invoke-NativeProbe -FilePath $FilePath -Arguments $args
    if ($probe.ExitCode -ne 0 -or -not $probe.Output) { return '' }
    $resolved = (($probe.Output | Select-Object -Last 1) -as [string])
    if (-not $resolved) { return '' }
    $resolved = $resolved.Trim()
    if (-not $resolved -or -not (Test-Path -LiteralPath $resolved -PathType Leaf)) { return '' }
    return $resolved
}

function Install-Python311WithManager {
    param([Parameter(Mandatory=$true)][string]$PyLauncher)
    Write-Step 'Python 3.11+ no está instalado'
    Write-Host 'Se detectó Python Install Manager/Launcher, pero no un runtime compatible.' -ForegroundColor Yellow
    Write-Host "GIDEON puede ejecutar: py install 3.11" -ForegroundColor Yellow
    Write-Host 'Esto instala únicamente la dependencia Python requerida; no crea ni modifica servicios de Windows.'

    $approved = [bool]$InstallPythonIfMissing
    if (-not $approved -and -not $NonInteractive) {
        $answer = Read-Host '¿Desea instalar Python 3.11 ahora? [S/N]'
        $approved = $answer -match '^[sSyY]'
    }
    if (-not $approved) {
        throw @'
No hay un runtime Python 3.11+ disponible.
La instalación GIDEON se detuvo antes de crear servicios.
Opciones:
  1) Vuelva a ejecutar y responda S cuando se solicite instalar Python 3.11.
  2) Instale Python 3.11+ por su mecanismo corporativo y vuelva a ejecutar.
  3) Use -PythonExe "C:\ruta\python.exe" para un runtime aprobado/offline.
Para despliegue no interactivo puede usar -InstallPythonIfMissing.
'@
    }

    $previousErrorAction = $ErrorActionPreference
    try {
        # Do not let native STDERR become a terminating PowerShell error.
        $ErrorActionPreference = 'Continue'
        & $PyLauncher install 3.11
        $installCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorAction
    }
    if ($installCode -ne 0) {
        throw "Python Install Manager no pudo instalar Python 3.11 (código $installCode). No se crearon servicios GIDEON."
    }

    $resolved = Resolve-CompatiblePythonCandidate -FilePath $PyLauncher -PrefixArguments @('-3.11')
    if (-not $resolved) {
        throw 'Python 3.11 fue solicitado al Install Manager, pero el runtime no quedó disponible. No se crearon servicios GIDEON.'
    }
    return $resolved
}

function Resolve-PythonBootstrap {
    if ($PythonExe) {
        $command = Get-Command $PythonExe -ErrorAction Stop
        $candidate = Resolve-CompatiblePythonCandidate -FilePath $command.Source
        if (-not $candidate) { throw "-PythonExe no apunta a Python 3.11+ utilizable: $PythonExe" }
        return $candidate
    }

    $existing = Join-Path $InstallRoot 'venv\Scripts\python.exe'
    if (Test-Path -LiteralPath $existing -PathType Leaf) {
        $candidate = Resolve-CompatiblePythonCandidate -FilePath $existing
        if ($candidate) { return $candidate }
    }

    $py = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($py) {
        # Prefer the certified baseline first, then newer supported runtimes.
        foreach ($tag in @('-3.11','-3.12','-3.13','-3.14','-3')) {
            $candidate = Resolve-CompatiblePythonCandidate -FilePath $py.Source -PrefixArguments @($tag)
            if ($candidate) { return $candidate }
        }
    }

    foreach ($name in @('python.exe','python3.exe')) {
        $python = Get-Command $name -ErrorAction SilentlyContinue
        if ($python) {
            $candidate = Resolve-CompatiblePythonCandidate -FilePath $python.Source
            if ($candidate) { return $candidate }
        }
    }

    if ($py) {
        return Install-Python311WithManager -PyLauncher $py.Source
    }

    throw @'
No se encontró Python 3.11+ ni Python Install Manager en Windows.
La instalación GIDEON se detuvo antes de crear servicios.
Instale un runtime Python 3.11+ aprobado o vuelva a ejecutar indicando:
  -PythonExe "C:\ruta\python.exe"
El instalador no descarga software de terceros por rutas alternativas ni cambia proveedores del sistema.
'@
}

function Assert-Python311([string]$Exe) {
    $candidate = Resolve-CompatiblePythonCandidate -FilePath $Exe
    if (-not $candidate) { throw 'GIDEON Remote Control requiere Python 3.11 o superior.' }
}

function Get-GideonPythonBasePrefix {
    param([Parameter(Mandatory=$true)][string]$Python)
    $probe = Invoke-NativeProbe -FilePath $Python -Arguments @('-c','import os,sys; print(os.path.abspath(sys.base_prefix))')
    if ($probe.ExitCode -ne 0 -or -not $probe.Output) { return '' }
    $value = ([string]($probe.Output | Select-Object -Last 1)).Trim()
    if (-not $value -or -not (Test-Path -LiteralPath $value -PathType Container)) { return '' }
    return [IO.Path]::GetFullPath($value).TrimEnd('\')
}

function Test-GideonPathUnderRoot {
    param([Parameter(Mandatory=$true)][string]$Path,[Parameter(Mandatory=$true)][string]$Root)
    try {
        $p=[IO.Path]::GetFullPath($Path).TrimEnd('\')
        $r=[IO.Path]::GetFullPath($Root).TrimEnd('\')
        return ($p.Equals($r,[StringComparison]::OrdinalIgnoreCase) -or $p.StartsWith($r+'\',[StringComparison]::OrdinalIgnoreCase))
    } catch { return $false }
}

function Test-GideonPrivatePythonBase {
    param([Parameter(Mandatory=$true)][string]$BaseRoot)
    $exe=Join-Path $BaseRoot 'python.exe'
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { return $false }
    $candidate=Resolve-CompatiblePythonCandidate -FilePath $exe
    if (-not $candidate) { return $false }
    $reported=Get-GideonPythonBasePrefix -Python $exe
    return ($reported -and (Test-GideonPathUnderRoot -Path $reported -Root $BaseRoot))
}

function Install-GideonPrivatePythonBase {
    param([Parameter(Mandatory=$true)][string]$BootstrapPython)
    $runtimeRoot=Join-Path $InstallRoot 'runtime'
    $privateBase=Join-Path $runtimeRoot 'python-base'
    if (Test-GideonPrivatePythonBase -BaseRoot $privateBase) {
        Write-Host "Runtime Python base GIDEON preservado: $privateBase" -ForegroundColor Green
        return (Join-Path $privateBase 'python.exe')
    }

    $sourceBase=Get-GideonPythonBasePrefix -Python $BootstrapPython
    if (-not $sourceBase) { throw "No se pudo determinar sys.base_prefix del Python bootstrap: $BootstrapPython" }
    if (Test-GideonPathUnderRoot -Path $sourceBase -Root $env:USERPROFILE) {
        Write-Host "Python bootstrap está bajo perfil de usuario y NO será usado por servicios: $sourceBase" -ForegroundColor Yellow
    }

    New-Item -ItemType Directory -Path $runtimeRoot -Force | Out-Null
    $stage=Join-Path $runtimeRoot ('python-base.stage-' + [Guid]::NewGuid().ToString('N').Substring(0,8))
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    Write-Host "Copiando runtime Python base a Program Files: $sourceBase -> $privateBase" -ForegroundColor Cyan
    $args=@($sourceBase,$stage,'/E','/COPY:DAT','/DCOPY:DAT','/R:2','/W:1','/XJ','/NFL','/NDL','/NJH','/NJS','/NP','/XD','__pycache__')
    & robocopy.exe @args | Out-Null
    $rc=$LASTEXITCODE
    if ($rc -gt 7) {
        Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
        throw "No se pudo copiar el runtime Python base GIDEON. robocopy=$rc"
    }
    $stagePython=Join-Path $stage 'python.exe'
    if (-not (Test-Path -LiteralPath $stagePython -PathType Leaf)) {
        Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
        throw "El runtime Python copiado no contiene python.exe: $stage"
    }
    # IMPORTANTE (Windows PowerShell 5.1): no dejar que la salida del smoke test
    # viaje por el success stream de esta función. Si se mezcla con el path de
    # retorno, el caller recibe Object[] y un parámetro [string] falla con
    # ArgumentTransformationMetadataException.
    $stageSmoke = Invoke-NativeProbe -FilePath $stagePython -Arguments @(
        '-c',
        'import ssl,sqlite3,venv,sys; assert sys.version_info >= (3,11); print(sys.executable); print(sys.base_prefix)'
    )
    if ($stageSmoke.ExitCode -ne 0) {
        Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
        throw 'La copia machine-local de Python no pasó el smoke test antes de activarse.'
    }
    if ($stageSmoke.Output) {
        Write-Host ('Runtime Python base smoke: ' + (($stageSmoke.Output | ForEach-Object { [string]$_ }) -join ' | ')) -ForegroundColor DarkGray
    }

    $old=$null
    if (Test-Path -LiteralPath $privateBase -PathType Container) {
        $old=Join-Path $runtimeRoot ('python-base.old-' + (Get-Date -Format 'yyyyMMddHHmmss'))
        Move-Item -LiteralPath $privateBase -Destination $old -Force
    }
    Move-Item -LiteralPath $stage -Destination $privateBase -Force
    try {
        Set-GideonCodeAcl $privateBase -Recursive
        if (-not (Test-GideonPrivatePythonBase -BaseRoot $privateBase)) { throw 'El runtime Python base GIDEON activado no es autosuficiente.' }
    } catch {
        Remove-Item -LiteralPath $privateBase -Recurse -Force -ErrorAction SilentlyContinue
        if ($old -and (Test-Path -LiteralPath $old -PathType Container)) { Move-Item -LiteralPath $old -Destination $privateBase -Force }
        throw
    }
    if ($old) { Remove-Item -LiteralPath $old -Recurse -Force -ErrorAction SilentlyContinue }
    return (Join-Path $privateBase 'python.exe')
}

function Test-GideonVenvBoundToPrivateBase {
    param([Parameter(Mandatory=$true)][string]$VenvRoot,[Parameter(Mandatory=$true)][string]$PrivateBase)
    $exe=Join-Path $VenvRoot 'Scripts\python.exe'
    $cfg=Join-Path $VenvRoot 'pyvenv.cfg'
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf) -or -not (Test-Path -LiteralPath $cfg -PathType Leaf)) { return $false }
    $probe=Invoke-NativeProbe -FilePath $exe -Arguments @('-c','import os,sys; print(os.path.abspath(sys.base_prefix))')
    if ($probe.ExitCode -ne 0 -or -not $probe.Output) { return $false }
    $base=([string]($probe.Output | Select-Object -Last 1)).Trim()
    if (-not (Test-GideonPathUnderRoot -Path $base -Root $PrivateBase)) { return $false }
    $cfgText=(Get-Content -LiteralPath $cfg -Raw -ErrorAction SilentlyContinue)
    if ($cfgText -match '(?im)^\s*(home|executable|command)\s*=.*\\Users\\') { return $false }
    return $true
}

function Reset-GideonVenvToPrivateBase {
    param([Parameter(Mandatory=$true)][string]$PrivatePython,[Parameter(Mandatory=$true)][string]$PrivateBase,[Parameter(Mandatory=$true)][string]$VenvRoot)
    if (Test-GideonVenvBoundToPrivateBase -VenvRoot $VenvRoot -PrivateBase $PrivateBase) {
        Write-Host 'Venv GIDEON ya está ligado al runtime machine-local.' -ForegroundColor Green
        return
    }
    if (Test-Path -LiteralPath $VenvRoot) {
        Write-Warning 'Se detectó venv heredado ligado a un runtime externo/perfil de usuario. Se recreará sin tocar DataRoot/PKI/configuración.'
        & cmd.exe /d /c "rmdir /s /q `"$VenvRoot`"" | Out-Null
        if (Test-Path -LiteralPath $VenvRoot) { throw "No se pudo retirar el venv heredado: $VenvRoot" }
    }
    & $PrivatePython -m venv --copies $VenvRoot
    if ($LASTEXITCODE -ne 0) { throw 'No se pudo crear el virtualenv GIDEON desde el runtime machine-local.' }
    if (-not (Test-GideonVenvBoundToPrivateBase -VenvRoot $VenvRoot -PrivateBase $PrivateBase)) {
        throw 'El venv creado no quedó ligado exclusivamente al runtime machine-local GIDEON.'
    }
}

function Stop-GideonServices {
    for ($i = $ServiceNames.Count - 1; $i -ge 0; $i--) {
        $name = $ServiceNames[$i]
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne 'Stopped') {
            Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
            try { $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(20)) } catch {}
        }
    }
}

function Test-PortAvailable([int]$Port) {
    if ($Port -in @(22,443)) { return $false }
    try {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
        $listener.Start(); $listener.Stop(); return $true
    } catch { return $false }
}

function New-RandomSecret([string]$Python, [int]$Bytes = 36) {
    $value = & $Python -c "import secrets; print(secrets.token_urlsafe($Bytes))"
    if ($LASTEXITCODE -ne 0 -or -not $value) { throw 'No se pudo generar secreto criptográfico.' }
    return (($value | Select-Object -Last 1).Trim())
}

function Test-FernetKey([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $clean = $Value.Trim()
    # Fernet requires exactly 32 raw bytes encoded as URL-safe Base64.
    # 32 bytes -> 44 Base64 characters with one trailing '=' padding byte.
    if ($clean -notmatch '^[A-Za-z0-9_-]{43}=$') { return $false }
    try {
        $standard = $clean.Replace('-', '+').Replace('_', '/')
        $raw = [Convert]::FromBase64String($standard)
        return ($raw.Length -eq 32)
    } catch {
        return $false
    }
}

function New-FernetKey {
    $bytes = New-Object 'System.Byte[]' 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        if ($null -ne $rng) { $rng.Dispose() }
    }
    return ([Convert]::ToBase64String($bytes).Replace('+', '-').Replace('/', '_'))
}

function Read-EnvValue([string]$Path, [string]$Name) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return '' }
    foreach ($line in Get-Content -LiteralPath $Path -Encoding UTF8) {
        if ($line -match ('^' + [regex]::Escape($Name) + '=(.*)$')) { return $Matches[1] }
    }
    return ''
}

function Write-Utf8NoBom([string]$Path, [string]$Text) {
    $parent = Split-Path -Parent $Path
    if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    $enc = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($Path, $Text, $enc)
}

function Reset-GideonChildAclToInherited([string]$Path) {
    # /reset en los descendientes transforma las ACE heredables del contenedor
    # en permisos efectivos correctos para archivos. Evita aplicar (OI)(CI)
    # directamente a cada python.exe/DLL, que puede dejar un ejecutable sin RX efectivo.
    $firstChild = Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $firstChild) { return }
    & icacls.exe (Join-Path $Path '*') /reset /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "No se pudieron normalizar ACL heredadas GIDEON en $Path" }
}

function Set-GideonPrivateDataAcl([string]$Path) {
    # Datos sensibles GIDEON: solo SYSTEM y Administradores en el CONTENEDOR raiz.
    # RC6 usa la API ACL de .NET en vez de icacls /grant:r para la raiz. En hosts
    # con ACL legacy dañada, icacls puede devolver código 1 aun después de cambiar
    # propietario. Esta operación NO enumera ni modifica descendientes.
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }
    try {
        $acl = Get-Acl -LiteralPath $Path
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRuleSpecific($rule) }

        $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        $prop = [System.Security.AccessControl.PropagationFlags]::None
        $allow = [System.Security.AccessControl.AccessControlType]::Allow
        $full = [System.Security.AccessControl.FileSystemRights]::FullControl
        foreach ($sidText in @('S-1-5-18','S-1-5-32-544')) {
            $sid = New-Object System.Security.Principal.SecurityIdentifier($sidText)
            $ace = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, $full, $inherit, $prop, $allow)
            [void]$acl.AddAccessRule($ace)
        }
        Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
    } catch {
        throw "No se pudo aplicar ACL privada GIDEON a $Path. $($_.Exception.Message)"
    }
}

function Protect-GideonLegacyBackupRoot([string]$DataRoot) {
    # Versiones legacy usaban backup (singular). Algunos recovery/oneclick
    # copiaron DataRoot dentro del mismo backup y generaron recursion. RC6 no
    # lo borra ni lo atraviesa: intenta proteger SOLO el directorio superior.
    # Si el legacy tiene una ACL irrecuperable, no se bloquea la instalación:
    # ningún servicio GIDEON recibe permisos desde ese árbol y jamás se enumera.
    $legacy = Join-Path $DataRoot 'backup'
    if (-not (Test-Path -LiteralPath $legacy -PathType Container)) { return }
    Write-Warning "Se detecto backup GIDEON legacy. No se recorrera: $legacy"
    try {
        Set-GideonPrivateDataAcl $legacy
    } catch {
        Write-Warning "No fue posible endurecer la ACL del contenedor backup legacy sin recorrerlo. Se deja intacto y excluido del runtime GIDEON. Detalle: $($_.Exception.Message)"
    }
}

function Repair-GideonPrivateDataAcl([string]$Path) {
    # Reparación idempotente EXCLUSIVA del DataRoot GIDEON.
    # RC6 nunca usa /T ni /R sobre DataRoot. Recupera temporalmente el
    # propietario del contenedor raíz, reescribe la DACL por API .NET y devuelve
    # el propietario a SYSTEM. No enumera backup legacy ni otros descendientes.
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }

    $expected = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'GIDEON Remote Control')).TrimEnd('\')
    $actual = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    if (-not $actual.Equals($expected, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing ACL repair outside GIDEON DataRoot: $actual"
    }

    # Camino rápido para instalaciones ya sanas.
    try {
        Set-GideonPrivateDataAcl $Path
        Protect-GideonLegacyBackupRoot $Path
        return
    } catch {
        Write-Warning "ACL GIDEON raíz requiere recuperación no recursiva de propietario. Detalle: $($_.Exception.Message)"
    }

    # takeown sin /R: únicamente la carpeta C:\ProgramData\GIDEON Remote Control.
    # Se usa el usuario administrativo actual de forma temporal porque ese SID
    # sí obtiene WRITE_DAC como propietario incluso si la DACL heredada está rota.
    $takeOutput = & takeown.exe /F $Path 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "No se pudo tomar propiedad temporal del DataRoot GIDEON. takeown=$LASTEXITCODE Detalle: $($takeOutput -join ' ')"
    }

    try {
        Set-GideonPrivateDataAcl $Path
    } catch {
        throw "No se pudo reconstruir la DACL del DataRoot GIDEON después de takeown. $($_.Exception.Message)"
    }

    # Con Administradores/SYSTEM ya en FullControl, devolver owner a SYSTEM.
    $ownerOutput = & icacls.exe $Path /setowner '*S-1-5-18' /Q 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "La DACL fue reparada, pero no se pudo devolver propietario SYSTEM al DataRoot GIDEON. icacls=$LASTEXITCODE Detalle: $($ownerOutput -join ' ')"
    }

    Protect-GideonLegacyBackupRoot $Path
}

function Set-GideonCodeAcl([string]$Path, [switch]$Recursive) {
    # Codigo/runtime GIDEON: SYSTEM y Administradores pueden modificar; Usuarios solo leer/ejecutar.
    # El permiso RX es necesario para python.exe, DLLs y launchers, sin conceder escritura.
    $icaclsArgs = @(
        $Path,
        '/inheritance:r',
        '/grant:r',
        '*S-1-5-18:(OI)(CI)F',
        '*S-1-5-32-544:(OI)(CI)F',
        '*S-1-5-32-545:(OI)(CI)RX',
        '/Q'
    )
    & icacls.exe @icaclsArgs | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "No se pudo aplicar ACL de codigo GIDEON a $Path" }
    if ($Recursive) { Reset-GideonChildAclToInherited $Path }
}

function Remove-GideonKnownAppJunctions([string]$Path) {
    # Desvincular SOLO los enlaces conocidos hacia ProgramData antes de una reparacion
    # recursiva del codigo. Nunca recorrer sus destinos persistentes.
    foreach ($name in @('config','scripts','logs')) {
        $candidate = Join-Path $Path $name
        if (-not (Test-Path -LiteralPath $candidate)) { continue }
        $item = Get-Item -LiteralPath $candidate -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            & cmd.exe /d /c "rmdir `"$candidate`"" | Out-Null
            if ($LASTEXITCODE -ne 0 -and (Test-Path -LiteralPath $candidate)) {
                throw "No se pudo retirar junction GIDEON antes de reparar codigo: $candidate"
            }
        }
    }
}

function Repair-GideonAppCodeAclForReplacement([string]$Path) {
    # Reparacion EXCLUSIVA del arbol de codigo reemplazable. R2 podia dejar ACE
    # inherit-only sobre archivos existentes y bloquear su eliminacion en R4.
    $expected = [IO.Path]::GetFullPath((Join-Path $InstallRoot 'app')).TrimEnd('\\')
    $actual = [IO.Path]::GetFullPath($Path).TrimEnd('\\')
    if (-not $actual.Equals($expected, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing code ACL repair outside GIDEON AppRoot: $actual"
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }

    Remove-GideonKnownAppJunctions $Path

    try {
        Set-GideonCodeAcl $Path -Recursive
        return
    } catch {
        Write-Warning 'ACL de codigo GIDEON heredada requiere recuperar propietario antes del reemplazo.'
    }

    # Fallback solo dentro de AppRoot: recuperar propietario/Full Control temporalmente
    # para SYSTEM y Administradores, normalizar y luego eliminar el codigo viejo.
    & icacls.exe $Path /setowner '*S-1-5-32-544' /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "No se pudo recuperar propietario del AppRoot GIDEON: $Path" }
    & icacls.exe $Path /grant '*S-1-5-18:F' '*S-1-5-32-544:F' /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "No se pudo conceder control temporal del AppRoot GIDEON: $Path" }
    Set-GideonCodeAcl $Path -Recursive
}

function Clear-GideonAppRoot([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }
    Get-ChildItem -LiteralPath $Path -Force | ForEach-Object {
        if ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            # Quitar solo la junction/link; nunca recorrer ni borrar su destino persistente.
            if ($_.PSIsContainer) {
                & cmd.exe /d /c "rmdir `"$($_.FullName)`"" | Out-Null
                if ($LASTEXITCODE -ne 0 -and (Test-Path -LiteralPath $_.FullName)) {
                    throw "No se pudo retirar junction GIDEON: $($_.FullName)"
                }
            } else {
                Remove-Item -LiteralPath $_.FullName -Force
            }
        } else {
            Remove-Item -LiteralPath $_.FullName -Recurse -Force
        }
    }
}

function New-GideonJunction([string]$Link, [string]$Target) {
    New-Item -ItemType Directory -Path $Target -Force | Out-Null
    if (Test-Path -LiteralPath $Link) {
        $item = Get-Item -LiteralPath $Link -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            Remove-Item -LiteralPath $Link -Force
        } else {
            Remove-Item -LiteralPath $Link -Recurse -Force
        }
    }
    $null = & cmd.exe /d /c "mklink /J `"$Link`" `"$Target`""
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $Link)) { throw "No se pudo crear junction $Link -> $Target" }
}

function Copy-SeedDirectory([string]$Source, [string]$Destination) {
    if (-not (Test-Path -LiteralPath $Source -PathType Container)) { return }
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    Get-ChildItem -LiteralPath $Source -Force | ForEach-Object {
        $dest = Join-Path $Destination $_.Name
        if (-not (Test-Path -LiteralPath $dest)) {
            Copy-Item -LiteralPath $_.FullName -Destination $dest -Recurse -Force
        }
    }
}

function Write-RegistryState([string]$AppRoot) {
    Set-GideonRegistryState64 -InstallRoot $InstallRoot -AppRoot $AppRoot -DataRoot $DataRoot -Version '6.3.4-rc30'
}

function Build-GideonWindowsServiceHost([string]$AppRoot) {
    $source = Join-Path $AppRoot 'deploy\windows\GIDEONServiceHost.cs'
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "No existe el código fuente del host de servicios GIDEON: $source" }
    $hostDir = Join-Path $InstallRoot 'service-host'
    New-Item -ItemType Directory -Path $hostDir -Force | Out-Null
    $hostExe = Join-Path $hostDir 'GIDEONServiceHost.exe'
    if (Test-Path -LiteralPath $hostExe) { Remove-Item -LiteralPath $hostExe -Force }

    $candidates = @(
        (Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'),
        (Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe')
    )
    $csc = $candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    if ($csc) {
        $args = @('/nologo','/target:exe','/optimize+',(('/out:"{0}"' -f $hostExe)),'/reference:System.ServiceProcess.dll',$source)
        & $csc @args
        if ($LASTEXITCODE -ne 0) { throw "No se pudo compilar el host de servicios GIDEON con csc.exe. Código $LASTEXITCODE" }
    } else {
        # Fallback PowerShell/.NET Framework. Solo compila el ejecutable GIDEON local.
        $sourceText = Get-Content -LiteralPath $source -Raw -Encoding UTF8
        Add-Type -TypeDefinition $sourceText -Language CSharp -ReferencedAssemblies @('System.ServiceProcess.dll') -OutputAssembly $hostExe -OutputType ConsoleApplication
    }
    if (-not (Test-Path -LiteralPath $hostExe -PathType Leaf)) { throw 'El host GIDEONServiceHost.exe no fue generado.' }
    Set-GideonCodeAcl $hostDir -Recursive
    return $hostExe
}

$script:GideonTranscriptStarted = $false
$script:GideonTranscriptPath = ''

function Start-GideonInstallTranscript {
    $preferred=Join-Path $DataRoot 'logs\install'
    $fallback=Join-Path $env:TEMP 'GIDEON-Install'
    $root=$preferred
    try { New-Item -ItemType Directory -Path $root -Force -ErrorAction Stop | Out-Null }
    catch { $root=$fallback; New-Item -ItemType Directory -Path $root -Force -ErrorAction SilentlyContinue | Out-Null }
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { return }
    $script:GideonTranscriptPath=Join-Path $root ('install-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.log')
    try {
        Start-Transcript -LiteralPath $script:GideonTranscriptPath -Force -ErrorAction Stop | Out-Null
        $script:GideonTranscriptStarted=$true
        $env:GIDEON_INSTALL_TRANSCRIPT=$script:GideonTranscriptPath
    } catch {
        $script:GideonTranscriptStarted=$false
        $script:GideonTranscriptPath=''
    }
}

function Stop-GideonInstallTranscriptSafe {
    if ($script:GideonTranscriptStarted) {
        try { Stop-Transcript | Out-Null } catch {}
        $script:GideonTranscriptStarted=$false
    }
}

Start-GideonInstallTranscript

Assert-Administrator
Assert-GideonWindowsHostType
Write-Step 'Validando compatibilidad nativa Windows/PowerShell/.NET'
$null = Assert-GideonWindowsCompatibility
if ($WebPort -eq $GatewayPort) { throw 'WebPort y GatewayPort deben ser diferentes.' }
if ($WebPort -in @(22,443) -or $GatewayPort -in @(22,443)) { throw 'GIDEON no utiliza ni modifica los puertos 22/443 por defecto.' }

Write-Step 'GIDEON Remote Control 6.3.4-rc30 RELEASE-P8H-RC22-SELF-CONTAINED-AGENT · Windows'
Write-Host 'Este instalador solo crea/modifica componentes GIDEON Remote Control.'
Write-Host 'No modifica Defender, políticas antivirus, OpenSSH Server, firewall ni servicios ajenos.'

# Antes de reconstruir ACL, detener los servicios GIDEON existentes. Una reinstalación
# RC3 puede tener servicios LocalSystem activos; nunca retirarles permisos en caliente.
Write-Step 'Deteniendo únicamente servicios GIDEON existentes antes de reparar ACL'
Stop-GideonServices

# Recuperacion idempotente para una R2 que haya quedado detenida despues de endurecer ACL.
# Se repara solo el contenedor de codigo y el venv; DataRoot conserva su ACL privada.
$RecoveryVenv = Join-Path $InstallRoot 'venv'
if (Test-Path -LiteralPath $InstallRoot -PathType Container) {
    Write-Step 'Verificando/reparando permisos de ejecución del runtime GIDEON'
    Set-GideonCodeAcl $InstallRoot
    if (Test-Path -LiteralPath $RecoveryVenv -PathType Container) {
        Set-GideonCodeAcl $RecoveryVenv -Recursive
    }
}
if (Test-Path -LiteralPath $DataRoot -PathType Container) {
    Write-Step 'Verificando/reparando ACL del estado persistente GIDEON'
    Repair-GideonPrivateDataAcl $DataRoot
}

$BootstrapPython = Resolve-PythonBootstrap
Assert-Python311 $BootstrapPython

if (-not (Test-PortAvailable $WebPort)) { throw "Puerto Web $WebPort ocupado por otro proceso. Elija otro puerto." }
if (-not (Test-PortAvailable $GatewayPort)) { throw "Puerto Gateway $GatewayPort ocupado por otro proceso. Elija otro puerto." }

$AppRoot = Join-Path $InstallRoot 'app'
$VenvRoot = Join-Path $InstallRoot 'venv'
New-Item -ItemType Directory -Path $InstallRoot,$DataRoot,$AppRoot -Force | Out-Null
Set-GideonCodeAcl $InstallRoot
Set-GideonCodeAcl $AppRoot
if (Test-Path -LiteralPath $VenvRoot -PathType Container) { Set-GideonCodeAcl $VenvRoot -Recursive }
foreach ($sub in @(
    'config','scripts','logs','logs\services','tmp',
    'logs\services\GIDEONRemoteControl','logs\services\GIDEONRemoteControlGateway','logs\services\GIDEONRemoteControlWebAdmin','logs\services\GIDEONRemoteControlBackup','logs\services\GIDEONRemoteControlUpdater','logs\services\GIDEONRemoteControlDiagnostics',
    'tmp\GIDEONRemoteControl','tmp\GIDEONRemoteControlGateway','tmp\GIDEONRemoteControlWebAdmin','tmp\GIDEONRemoteControlBackup','tmp\GIDEONRemoteControlUpdater','tmp\GIDEONRemoteControlDiagnostics',
    'gateway','web','shared','backups','backups\local','backups\external','diagnostics','coordinator',
    'updates','updates\inbox','updates\staging','updates\status','updates\archive','updates\archive\success','updates\archive\failed','updates\rollback','updates\transactions','updates\trust','updates\trust\update-signing',
    'pki','pki\root','pki\web','pki\gateway','pki\agent-ca','security','security\yara','releases','uploads','quarantine','secrets'
)) { New-Item -ItemType Directory -Path (Join-Path $DataRoot $sub) -Force | Out-Null }

Write-Step 'Preservando/sembrando configuración y scripts fuera del código actualizable'
Copy-SeedDirectory (Join-Path $SourceRoot 'config') (Join-Path $DataRoot 'config')
Copy-SeedDirectory (Join-Path $SourceRoot 'scripts') (Join-Path $DataRoot 'scripts')
if ($MigrateFrom) {
    $migrationRoot = (Resolve-Path -LiteralPath $MigrateFrom).Path
    if (Test-Path (Join-Path $migrationRoot 'config')) {
        Copy-Item -Path (Join-Path $migrationRoot 'config\*') -Destination (Join-Path $DataRoot 'config') -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path (Join-Path $migrationRoot 'scripts')) {
        Copy-Item -Path (Join-Path $migrationRoot 'scripts\*') -Destination (Join-Path $DataRoot 'scripts') -Recurse -Force -ErrorAction SilentlyContinue
    }
}
$legacyGateway = Join-Path $env:ProgramData 'GIDEONRemoteControl\Gateway'
if (Test-Path -LiteralPath $legacyGateway -PathType Container) {
    # Migracion conservadora: copiar solo elementos que aun NO existan en el nuevo DataRoot.
    # Nunca sobreescribir agent_gateway.json, DB, identidad u otro estado ya preservado.
    Copy-SeedDirectory $legacyGateway (Join-Path $DataRoot 'gateway')
}

Write-Step 'Instalando código base GIDEON en Program Files'
Repair-GideonAppCodeAclForReplacement $AppRoot
Clear-GideonAppRoot $AppRoot
$roboArgs = @(
    $SourceRoot, $AppRoot, '/E','/R:2','/W:1','/NFL','/NDL','/NJH','/NJS','/NP',
    '/XD','config','scripts','logs','__pycache__','.pytest_cache','.git','venv','gateway-data','web-data',
    '/XF','*.pyc','*.zip'
)
& robocopy.exe @roboArgs | Out-Null
if ($LASTEXITCODE -gt 7) { throw "robocopy falló con código $LASTEXITCODE" }
# Aplicar RX al codigo antes de crear junctions hacia DataRoot para no propagar permisos al estado privado.
Set-GideonCodeAcl $AppRoot -Recursive

New-GideonJunction (Join-Path $AppRoot 'config') (Join-Path $DataRoot 'config')
New-GideonJunction (Join-Path $AppRoot 'scripts') (Join-Path $DataRoot 'scripts')
New-GideonJunction (Join-Path $AppRoot 'logs') (Join-Path $DataRoot 'logs')

Write-Step 'Creando runtime Python privado machine-local de GIDEON'
$PrivatePythonResult = Install-GideonPrivatePythonBase -BootstrapPython $BootstrapPython
if ($PrivatePythonResult -is [System.Array]) {
    throw 'Install-GideonPrivatePythonBase produjo múltiples valores en el success stream. Se aborta antes de modificar el venv.'
}
$PrivatePython = [string]$PrivatePythonResult
if ([string]::IsNullOrWhiteSpace($PrivatePython) -or -not (Test-Path -LiteralPath $PrivatePython -PathType Leaf)) {
    throw "Install-GideonPrivatePythonBase no devolvió un python.exe válido: $PrivatePython"
}
$PrivatePythonBase = [string](Split-Path -Parent $PrivatePython)
Reset-GideonVenvToPrivateBase -PrivatePython $PrivatePython -PrivateBase $PrivatePythonBase -VenvRoot $VenvRoot
Set-GideonCodeAcl $PrivatePythonBase -Recursive
Set-GideonCodeAcl $VenvRoot -Recursive
$Python = Join-Path $VenvRoot 'Scripts\python.exe'
$RuntimeBindingCode = "import os,sys; p=os.path.abspath(sys.base_prefix).lower(); expected=os.path.abspath(r'$PrivatePythonBase').lower(); print('GIDEON venv base:',sys.base_prefix); raise SystemExit(0 if (p==expected or p.startswith(expected+os.sep)) and '\\users\\' not in p else 9)"
& $Python -c $RuntimeBindingCode
if ($LASTEXITCODE -ne 0) { throw 'El venv GIDEON aún depende de un runtime externo/perfil de usuario. Se aborta antes de crear servicios.' }
$PipArgs = @('-m','pip','install','--disable-pip-version-check')
if ($OfflineWheelDir) {
    $WheelDir = (Resolve-Path -LiteralPath $OfflineWheelDir).Path
    $PipArgs += @('--no-index','--find-links',$WheelDir)
}
$PipArgs += @('-r',(Join-Path $AppRoot 'requirements-windows.txt'))
& $Python @PipArgs
if ($LASTEXITCODE -ne 0) { throw 'No se pudieron instalar las dependencias privadas de GIDEON.' }
& $Python -c "import fastapi,uvicorn,jinja2,argon2,openpyxl,cryptography,PySide6; print('GIDEON Windows runtime OK')"
if ($LASTEXITCODE -ne 0) { throw 'El runtime Windows GIDEON no pasó el smoke test.' }

Write-Step 'Generando/preservando PKI privada GIDEON'
& $Python (Join-Path $AppRoot 'deploy\windows\gideon_install_pki.py') --root (Join-Path $DataRoot 'pki') --web-host $WebHost --gateway-host $GatewayHost
if ($LASTEXITCODE -ne 0) { throw 'No se pudo preparar la PKI privada GIDEON.' }

$GatewayEnv = Join-Path $DataRoot 'secrets\gateway.env'
$WebEnv = Join-Path $DataRoot 'secrets\web.env'
$AdminToken = Read-EnvValue $GatewayEnv 'GIDEON_AGENT_ADMIN_TOKEN'
if (-not $AdminToken) { $AdminToken = New-RandomSecret $Python 48 }
$EnrollSecret = Read-EnvValue $GatewayEnv 'GIDEON_AGENT_ENROLL_SECRET'
if (-not $EnrollSecret) { $EnrollSecret = New-RandomSecret $Python 48 }
$BootstrapToken = Read-EnvValue $WebEnv 'GIDEON_WEB_BOOTSTRAP_TOKEN'
if (-not $BootstrapToken) { $BootstrapToken = New-RandomSecret $Python 32 }
$SecurityDb = Join-Path $DataRoot 'web\security.sqlite3'
$TotpKey = Read-EnvValue $WebEnv 'GIDEON_WEB_TOTP_ENCRYPTION_KEY'
if (-not $TotpKey) {
    $TotpKey = New-FernetKey
} elseif (-not (Test-FernetKey $TotpKey)) {
    # R5 and earlier could persist secrets.token_urlsafe(32), which is not a
    # canonical Fernet key because it omits the required Base64 padding.
    # Auto-repair is safe only before a real security DB exists. If a DB already
    # exists, do not rotate the encryption key silently: an existing encrypted
    # MFA secret could otherwise become unrecoverable.
    $dbExistsWithContent = $false
    if (Test-Path -LiteralPath $SecurityDb -PathType Leaf) {
        try { $dbExistsWithContent = ((Get-Item -LiteralPath $SecurityDb).Length -gt 0) } catch { $dbExistsWithContent = $true }
    }
    if ($dbExistsWithContent) {
        throw 'GIDEON_WEB_TOTP_ENCRYPTION_KEY existente no es una clave Fernet válida y security.sqlite3 ya contiene datos. Por seguridad no se rotará automáticamente; restaure la clave válida anterior antes de continuar.'
    }
    Write-Warning 'Se detectó una clave TOTP/Fernet inválida de una instalación parcial anterior. Se regenerará porque security.sqlite3 aún no contiene datos.'
    $TotpKey = New-FernetKey
}
if (-not (Test-FernetKey $TotpKey)) { throw 'No se pudo generar una clave Fernet válida para GIDEON_WEB_TOTP_ENCRYPTION_KEY.' }
Write-Utf8NoBom $GatewayEnv "GIDEON_AGENT_ADMIN_TOKEN=$AdminToken`r`nGIDEON_AGENT_ENROLL_SECRET=$EnrollSecret`r`n"
Write-Utf8NoBom $WebEnv "GIDEON_AGENT_ADMIN_TOKEN=$AdminToken`r`nGIDEON_WEB_BOOTSTRAP_TOKEN=$BootstrapToken`r`nGIDEON_WEB_TOTP_ENCRYPTION_KEY=$TotpKey`r`n"

Write-Step 'Escribiendo configuración Windows GIDEON'
$GatewayConfig = [ordered]@{
    data_dir = (Join-Path $DataRoot 'gateway')
    listen_host = '0.0.0.0'
    listen_address = '0.0.0.0'
    listen_port = $GatewayPort
    admin_api_key_env = 'GIDEON_AGENT_ADMIN_TOKEN'
    enrollment_secret_env = 'GIDEON_AGENT_ENROLL_SECRET'
    tls_certfile = (Join-Path $DataRoot 'pki\gateway\gateway.crt')
    tls_keyfile = (Join-Path $DataRoot 'pki\gateway\gateway.key')
    ca_file = (Join-Path $DataRoot 'pki\root\gideon-root-ca.pem')
    client_ca_file = (Join-Path $DataRoot 'pki\agent-ca\agent-client-ca.pem')
    client_ca_key_file = (Join-Path $DataRoot 'pki\agent-ca\agent-client-ca.key')
    require_agent_mtls = $false
    public_host = $GatewayHost
    public_url = "https://${GatewayHost}:$GatewayPort"
    advertised_endpoint = "https://${GatewayHost}:$GatewayPort"
    internal_endpoint = "https://127.0.0.1:$GatewayPort"
    hot_reload_enabled = $true
    installer_enrollment_ttl_seconds = 86400
    installer_enrollment_max_uses = 8
    security = [ordered]@{ minimum_tls='TLSv1.2'; prefer_tls13=$true; package_signing='Ed25519'; digest='SHA-256' }
}
Write-Utf8NoBom (Join-Path $DataRoot 'config\gateway.json') (($GatewayConfig | ConvertTo-Json -Depth 12) + "`r`n")

$DefaultWeb = Get-Content -LiteralPath (Join-Path $DataRoot 'config\web_admin.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$DefaultWeb.data_dir = (Join-Path $DataRoot 'web')
$DefaultWeb.listen_host = '0.0.0.0'
$DefaultWeb.listen_port = $WebPort
$DefaultWeb.tls_certfile = (Join-Path $DataRoot 'pki\web\web.crt')
$DefaultWeb.tls_keyfile = (Join-Path $DataRoot 'pki\web\web.key')
$DefaultWeb.gateway_base_url = "https://127.0.0.1:$GatewayPort"
$DefaultWeb.gateway_public_url = "https://${GatewayHost}:$GatewayPort"
$DefaultWeb.gateway_config_file = (Join-Path $DataRoot 'config\gateway.json')
$DefaultWeb.gateway_ca_file = (Join-Path $DataRoot 'pki\root\gideon-root-ca.pem')
$DefaultWeb.runtime_settings_file = (Join-Path $DataRoot 'shared\runtime_settings.json')
$DefaultWeb.security_event_log = (Join-Path $DataRoot 'logs\services\GIDEONRemoteControlWebAdmin\web-security.log')
$DefaultWeb.product_update_root = (Join-Path $DataRoot 'updates')
$DefaultWeb.malware_scan_allowed_root = $DataRoot
$DefaultWeb.windows_defender_custom_scan = $true
$DefaultWeb.clamav_database_dir = ''
$DefaultWeb.malware_scan_timeout_seconds = 300
$DefaultWeb.yara_rules_file = ''
$DefaultWeb.require_malware_scan_for_scripts = $true
$DefaultWeb.require_malware_scan_for_transfers = $true
$DefaultWeb.trust_proxy_headers = $false
$DefaultWeb.forwarded_allow_ips = '127.0.0.1'
$DefaultWeb.secure_cookies = $true
$DefaultWeb.require_mfa = $true
Write-Utf8NoBom (Join-Path $DataRoot 'config\web_admin.json') (($DefaultWeb | ConvertTo-Json -Depth 20) + "`r`n")

$RuntimeSettingsPath = Join-Path $DataRoot 'shared\runtime_settings.json'
if (-not (Test-Path -LiteralPath $RuntimeSettingsPath)) {
    $RuntimeSettings = [ordered]@{
        backup_enabled=$true; backup_destination_type='local'; backup_destination=''; backup_retention_days=14
        smtp_enabled=$false; smtp_host=''; smtp_port=587; smtp_username=''; smtp_from=''
    }
    Write-Utf8NoBom $RuntimeSettingsPath (($RuntimeSettings | ConvertTo-Json -Depth 6) + "`r`n")
}

Write-Step 'Aplicando ACL diferenciadas solo al árbol GIDEON'
Set-GideonPrivateDataAcl $DataRoot
Set-GideonCodeAcl $InstallRoot
Set-GideonCodeAcl $VenvRoot -Recursive

Write-Step 'Creando/preservando SuperAdmin Web'
$InitialWebUser = 'dchaskypp'
$InitialWebPassword = ''
if (-not (Test-Path -LiteralPath $SecurityDb)) {
    $InitialWebPassword = New-RandomSecret $Python 18
    $env:GIDEON_WEB_TOTP_ENCRYPTION_KEY = $TotpKey
    $env:GIDEON_INSTALL_ADMIN_PASSWORD = $InitialWebPassword
    $env:GIDEON_INSTALL_ADMIN_USER = $InitialWebUser
    $env:GIDEON_INSTALL_WEB_DB = $SecurityDb
    $env:PYTHONPATH = $AppRoot
    & $Python -c "import os; from pathlib import Path; from gideon_web_admin.auth import SecurityStore; p=Path(os.environ['GIDEON_INSTALL_WEB_DB']); p.parent.mkdir(parents=True,exist_ok=True); s=SecurityStore(p,idle_timeout_seconds=43200,max_sessions_per_user=5); s.bootstrap_admin(os.environ['GIDEON_INSTALL_ADMIN_USER'],os.environ['GIDEON_INSTALL_ADMIN_PASSWORD'],'Administrador GIDEON',must_change_password=True,allow_temporary_password=True); print('SuperAdmin creado')"
    if ($LASTEXITCODE -ne 0) { throw 'No se pudo crear el SuperAdmin inicial.' }
    Remove-Item Env:GIDEON_INSTALL_ADMIN_PASSWORD,Env:GIDEON_INSTALL_ADMIN_USER,Env:GIDEON_INSTALL_WEB_DB -ErrorAction SilentlyContinue
}

Write-Step 'Registrando servicios Windows GIDEON independientes'
Write-RegistryState $AppRoot
$ServiceHostExe = Build-GideonWindowsServiceHost $AppRoot
Write-Host "Host SCM GIDEON: $ServiceHostExe"
& $Python (Join-Path $AppRoot 'deploy\windows\gideon_windows_service.py') install-all
if ($LASTEXITCODE -ne 0) { throw 'No se pudieron registrar los servicios Windows GIDEON.' }
# RC13: confirmar de nuevo el estado en Registry64 justo antes de endurecer ACL.
# Esto evita divergencias de vista WOW64/proveedor observadas en Windows real.
Write-RegistryState $AppRoot

Write-Step 'Aplicando identidades virtuales y ACL por microservicio GIDEON'
Set-GideonWindowsServiceIsolation -InstallRoot $InstallRoot -AppRoot $AppRoot -VenvRoot $VenvRoot -DataRoot $DataRoot
Write-Host 'Windows service isolation: Gateway/Web/Backup/Diagnostics/Coordinator usan LocalService + Service SID NT SERVICE\<servicio>; Updater permanece LocalSystem.' -ForegroundColor Green
$IsolationTest = Join-Path $AppRoot 'deploy\windows\Test-GideonWindowsIsolation.ps1'
& powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $IsolationTest -InstallRoot $InstallRoot -DataRoot $DataRoot
if ($LASTEXITCODE -ne 0) { throw 'La matriz de aislamiento Windows GIDEON no pasó la validación previa al arranque.' }

Write-Step 'Creando launcher elevado y acceso directo'
$Launcher = Join-Path $InstallRoot 'Launch-GIDEONRemoteControl.ps1'
$LauncherText = @"
#requires -Version 5.1
`$ErrorActionPreference='Stop'
`$id=[Security.Principal.WindowsIdentity]::GetCurrent()
`$p=New-Object Security.Principal.WindowsPrincipal(`$id)
if(-not `$p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
  Start-Process powershell.exe -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',`$PSCommandPath)
  exit
}
Start-Process -FilePath '$($VenvRoot.Replace("'","''"))\Scripts\pythonw.exe' -ArgumentList @('$($AppRoot.Replace("'","''"))\gideon_qt_gui.py') -WorkingDirectory '$($AppRoot.Replace("'","''"))'
"@
Write-Utf8NoBom $Launcher $LauncherText
$Programs = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\GIDEON Remote Control'
New-Item -ItemType Directory -Path $Programs -Force | Out-Null
$ShortcutPath = Join-Path $Programs 'GIDEON Remote Control.lnk'
$ws = New-Object -ComObject WScript.Shell
$shortcut = $ws.CreateShortcut($ShortcutPath)
$shortcut.TargetPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$Launcher`""
$shortcut.WorkingDirectory = $AppRoot
$shortcut.Description = 'GIDEON Remote Control 6.3.4-rc30'
$shortcut.Save()

$Uninstall = Join-Path $AppRoot 'deploy\windows\Uninstall-GIDEON-Windows.ps1'
$Arp = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\GIDEONRemoteControl'
New-Item -Path $Arp -Force | Out-Null
New-ItemProperty -Path $Arp -Name DisplayName -Value 'GIDEON Remote Control' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $Arp -Name DisplayVersion -Value '6.3.4-rc30' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $Arp -Name Publisher -Value 'GIDEON CORP S.A.' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $Arp -Name InstallLocation -Value $InstallRoot -PropertyType String -Force | Out-Null
New-ItemProperty -Path $Arp -Name UninstallString -Value "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$Uninstall`"" -PropertyType String -Force | Out-Null

if ($AddFirewallRules) {
    Write-Step 'Creando únicamente reglas Windows Firewall GIDEON solicitadas'
    foreach ($rule in @('GIDEON Remote Control - Web Admin','GIDEON Remote Control - Agent Gateway')) {
        Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    }
    New-NetFirewallRule -DisplayName 'GIDEON Remote Control - Web Admin' -Direction Inbound -Action Allow -Protocol TCP -LocalPort $WebPort -Profile Domain,Private -Description 'GIDEON Remote Control Web Admin only' | Out-Null
    New-NetFirewallRule -DisplayName 'GIDEON Remote Control - Agent Gateway' -Direction Inbound -Action Allow -Protocol TCP -LocalPort $GatewayPort -Profile Domain,Private -Description 'GIDEON Remote Control Agent Gateway only' | Out-Null
} else {
    Write-Host 'Firewall: sin cambios. Use -AddFirewallRules solo si desea las dos reglas GIDEON.' -ForegroundColor Yellow
}

if ($StartServices) {
    Write-Step 'Armando AUTO_START únicamente después de validar aislamiento GIDEON'
    & $Python (Join-Path $AppRoot 'deploy\windows\gideon_windows_service.py') arm-auto
    if ($LASTEXITCODE -ne 0) {
        & $Python (Join-Path $AppRoot 'deploy\windows\gideon_windows_service.py') quiesce | Out-Null
        throw 'No se pudo armar AUTO_START de los servicios GIDEON. Permanecen en DEMAND_START.'
    }

    Write-Step 'Iniciando únicamente servicios GIDEON'
    & $Python (Join-Path $AppRoot 'deploy\windows\gideon_windows_service.py') start-all
    if ($LASTEXITCODE -ne 0) {
        & $Python (Join-Path $AppRoot 'deploy\windows\gideon_windows_service.py') diagnostics
        & $Python (Join-Path $AppRoot 'deploy\windows\gideon_windows_service.py') quiesce | Out-Null
        throw 'Uno o más servicios GIDEON no pudieron iniciar. Se detuvieron y quedaron en DEMAND_START para evitar un restart storm.'
    }
    & $Python (Join-Path $AppRoot 'deploy\windows\gideon_windows_service.py') status
    if ($LASTEXITCODE -ne 0) {
        & $Python (Join-Path $AppRoot 'deploy\windows\gideon_windows_service.py') diagnostics
        & $Python (Join-Path $AppRoot 'deploy\windows\gideon_windows_service.py') quiesce | Out-Null
        throw 'Uno o más servicios GIDEON no permanecieron en RUNNING. Se dejaron en DEMAND_START.'
    }

    Write-Step 'Validando publicación funcional de Diagnostics/Coordinator'
    & $Python (Join-Path $AppRoot 'deploy\windows\gideon_windows_service.py') runtime-health
    if ($LASTEXITCODE -ne 0) {
        & $Python (Join-Path $AppRoot 'deploy\windows\gideon_windows_service.py') diagnostics
        & $Python (Join-Path $AppRoot 'deploy\windows\gideon_windows_service.py') quiesce | Out-Null
        throw 'Los servicios GIDEON arrancaron pero Diagnostics/Coordinator no publicaron estado fresco. Se dejaron en DEMAND_START.'
    }
} else {
    Write-Host 'Servicios GIDEON instalados en DEMAND_START porque -StartServices está deshabilitado.' -ForegroundColor Yellow
}

Write-Step 'Validando endpoints locales'
$HealthCa = Join-Path $DataRoot 'pki\root\gideon-root-ca.pem'
$HealthCode = @"
import ssl, urllib.request, sys, time
urls=['https://127.0.0.1:$GatewayPort/health','https://127.0.0.1:$WebPort/healthz']
cafile=r'''$HealthCa'''
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname=True
ctx.verify_mode=ssl.CERT_REQUIRED
ctx.load_verify_locations(cafile=cafile)
strict=getattr(ssl,'VERIFY_X509_STRICT',0)
if strict:
    ctx.verify_flags = ctx.verify_flags & ~strict
if hasattr(ssl,'TLSVersion'):
    ctx.minimum_version=ssl.TLSVersion.TLSv1_2
failed=[]
for u in urls:
    deadline=time.monotonic()+30
    last=None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(u,context=ctx,timeout=5) as r:
                print(u, r.status)
                if r.status < 400:
                    last=None
                    break
                last=RuntimeError('HTTP %s' % r.status)
        except Exception as exc:
            last=exc
        time.sleep(1)
    if last is not None:
        print('HEALTH FAIL',u,type(last).__name__,str(last),file=sys.stderr)
        failed.append(u)
raise SystemExit(1 if failed else 0)
"@
if ($StartServices) {
    & $Python -c $HealthCode
    if ($LASTEXITCODE -ne 0) {
        & $Python (Join-Path $AppRoot 'deploy\windows\gideon_windows_service.py') diagnostics
        & $Python (Join-Path $AppRoot 'deploy\windows\gideon_windows_service.py') quiesce | Out-Null
        throw 'Un endpoint GIDEON no respondió después de 30 segundos. Los servicios fueron detenidos y quedaron en DEMAND_START.'
    }
}

$Summary = Join-Path $DataRoot 'INSTALLATION-SUMMARY.txt'
$lines = @(
    'GIDEON Remote Control 6.3.4-rc30 RELEASE-P8H-RC22-SELF-CONTAINED-AGENT - Windows',
    "Web Admin URL: https://${WebHost}:$WebPort",
    "Agent Gateway URL: https://${GatewayHost}:$GatewayPort",
    "InstallRoot: $InstallRoot",
    "DataRoot: $DataRoot",
    "CA: $(Join-Path $DataRoot 'pki\root\gideon-root-ca.pem')",
    'Windows Defender: no policy/default/exclusion/service changes; only per-file custom scan when Web Admin scans GIDEON-owned uploads.',
    'OpenSSH/ssh-agent: untouched. GIDEON validates its identity only and never starts/configures ssh-agent or globally closes SSH processes.',
    'Firewall: ' + ($(if($AddFirewallRules){'two GIDEON-only rules created'}else{'untouched'})),
    'Future updates: Web Admin > Actualización del sistema or console updater package.',
    'Windows service logon: Coordinator/Gateway/WebAdmin/Backup/Diagnostics = NT AUTHORITY\LocalService; ACL identity = NT SERVICE\<service>; Updater = LocalSystem.',
    'Install safety: services are staged as DEMAND_START; AUTO_START is enabled only after isolation validation succeeds.',
    'Service ACL isolation: per-component DataRoot, PKI/secrets split, per-service writable logs.',
    "Web initial user: $InitialWebUser"
)
if ($InitialWebPassword) { $lines += "Temporary password (change required + MFA): $InitialWebPassword" }
Write-Utf8NoBom $Summary (($lines -join "`r`n") + "`r`n")
# No volver a ejecutar Set-GideonPrivateDataAcl aquí: borraría las ACE específicas
# NT SERVICE aplicadas arriba. El resumen hereda SYSTEM/Administrators del DataRoot.

Write-Host "`nINSTALACIÓN GIDEON REMOTE CONTROL 6.3.4-rc30 COMPLETADA" -ForegroundColor Green
Write-Host "Web Admin : https://${WebHost}:$WebPort"
Write-Host "Gateway   : https://${GatewayHost}:$GatewayPort"
Write-Host "Servicios : $($ServiceNames -join ', ')"
if ($InitialWebPassword) {
    Write-Host "Usuario Web temporal: $InitialWebUser" -ForegroundColor Yellow
    Write-Host "Contraseña temporal : $InitialWebPassword" -ForegroundColor Yellow
    Write-Host 'Cambio de contraseña y MFA son obligatorios.' -ForegroundColor Yellow
}
Write-Host "Resumen protegido: $Summary"
Write-Host 'No se modificaron Defender, OpenSSH Server, sshd, servicios de terceros ni valores globales de antivirus.'
Stop-GideonInstallTranscriptSafe
