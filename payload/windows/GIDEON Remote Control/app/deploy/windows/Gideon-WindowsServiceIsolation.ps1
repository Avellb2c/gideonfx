#requires -Version 5.1
Set-StrictMode -Version 2.0

$RegistryModule = Join-Path $PSScriptRoot 'Gideon-WindowsRegistry.ps1'
if (-not (Test-Path -LiteralPath $RegistryModule -PathType Leaf)) { throw "Falta módulo de registro Windows GIDEON: $RegistryModule" }
. $RegistryModule

# RC13 least-privilege Windows model.
# These principals are Service SIDs used exclusively in ACLs. The SCM logon
# account is LocalService for non-updater services; no password is stored.
$script:GideonWindowsServicePrincipals = [ordered]@{
    'GIDEONRemoteControl'            = 'NT SERVICE\GIDEONRemoteControl'
    'GIDEONRemoteControlGateway'     = 'NT SERVICE\GIDEONRemoteControlGateway'
    'GIDEONRemoteControlWebAdmin'    = 'NT SERVICE\GIDEONRemoteControlWebAdmin'
    'GIDEONRemoteControlBackup'      = 'NT SERVICE\GIDEONRemoteControlBackup'
    'GIDEONRemoteControlDiagnostics' = 'NT SERVICE\GIDEONRemoteControlDiagnostics'
    'GIDEONRemoteControlUpdater'     = 'NT SERVICE\GIDEONRemoteControlUpdater'
}

function Get-GideonWindowsServicePrincipals {
    return $script:GideonWindowsServicePrincipals.Clone()
}

function Invoke-GideonIcacls {
    param([Parameter(Mandatory=$true)][string[]]$Arguments)
    & icacls.exe @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "icacls falló (código $LASTEXITCODE): $($Arguments -join ' ')"
    }
}

function Reset-GideonAclChildren {
    param([Parameter(Mandatory=$true)][string]$Path)
    $first = Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $first) { return }
    Invoke-GideonIcacls -Arguments @((Join-Path $Path '*'), '/reset', '/T', '/C', '/Q')
}

function Set-GideonExactDirectoryAcl {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [hashtable]$Rules = @{},
        [switch]$ResetChildren
    )
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    # Start from the parent default so stale explicit ACEs from an older RC are
    # removed. /inheritance:r below then removes inherited entries and the
    # matrix is rebuilt from an empty DACL surface.
    Invoke-GideonIcacls -Arguments @($Path, '/reset', '/Q')
    $args = @(
        $Path, '/inheritance:r', '/grant:r',
        '*S-1-5-18:(OI)(CI)F',       # SYSTEM
        '*S-1-5-32-544:(OI)(CI)F'    # BUILTIN\Administrators
    )
    foreach ($principal in ($Rules.Keys | Sort-Object)) {
        $rights = [string]$Rules[$principal]
        $args += ($principal + ':(OI)(CI)' + $rights)
    }
    $args += '/Q'
    Invoke-GideonIcacls -Arguments $args
    if ($ResetChildren) { Reset-GideonAclChildren -Path $Path }
}

function Set-GideonExactFileAcl {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [hashtable]$Rules = @{}
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    Invoke-GideonIcacls -Arguments @($Path, '/reset', '/Q')
    $args = @(
        $Path, '/inheritance:r', '/grant:r',
        '*S-1-5-18:F',
        '*S-1-5-32-544:F'
    )
    foreach ($principal in ($Rules.Keys | Sort-Object)) {
        $args += ($principal + ':' + [string]$Rules[$principal])
    }
    $args += '/Q'
    Invoke-GideonIcacls -Arguments $args
}

function Grant-GideonDirectDirectoryAccess {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][hashtable]$Rules
    )
    foreach ($principal in ($Rules.Keys | Sort-Object)) {
        Invoke-GideonIcacls -Arguments @($Path, '/grant:r', ($principal + ':(' + [string]$Rules[$principal] + ')'), '/Q')
    }
}

function Grant-GideonCodeReadExecute {
    param([Parameter(Mandatory=$true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }
    foreach ($service in @(
        'GIDEONRemoteControl',
        'GIDEONRemoteControlGateway',
        'GIDEONRemoteControlWebAdmin',
        'GIDEONRemoteControlBackup',
        'GIDEONRemoteControlDiagnostics'
    )) {
        $principal = [string]$script:GideonWindowsServicePrincipals[$service]
        Invoke-GideonIcacls -Arguments @($Path, '/grant', ($principal + ':(OI)(CI)RX'), '/Q')
    }
}

function Set-GideonRegistryReadAcl {
    # RC13: no usar cmdlets ACL del provider HKLM. Operar siempre sobre
    # Registry64 mediante Microsoft.Win32.RegistryKey para evitar WOW64/provider races.
    $readers = @(
        'GIDEONRemoteControl',
        'GIDEONRemoteControlGateway',
        'GIDEONRemoteControlWebAdmin',
        'GIDEONRemoteControlBackup',
        'GIDEONRemoteControlDiagnostics'
    ) | ForEach-Object { [string]$script:GideonWindowsServicePrincipals[$_] }
    Set-GideonRegistryReadAcl64 -ReadPrincipals $readers
}

function Assert-GideonServiceSidPrincipalsResolvable {
    foreach ($service in @(
        'GIDEONRemoteControl',
        'GIDEONRemoteControlGateway',
        'GIDEONRemoteControlWebAdmin',
        'GIDEONRemoteControlBackup',
        'GIDEONRemoteControlDiagnostics'
    )) {
        $account = [string]$script:GideonWindowsServicePrincipals[$service]
        try {
            $nt = New-Object System.Security.Principal.NTAccount($account)
            [void]$nt.Translate([System.Security.Principal.SecurityIdentifier])
        } catch {
            throw "Windows no pudo resolver el Service SID $account. Verifique que $service exista y tenga sidtype unrestricted."
        }
    }
}

function Set-GideonWindowsServiceIsolation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$InstallRoot,
        [Parameter(Mandatory=$true)][string]$AppRoot,
        [Parameter(Mandatory=$true)][string]$VenvRoot,
        [Parameter(Mandatory=$true)][string]$DataRoot
    )

    $install = [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\')
    $data = [IO.Path]::GetFullPath($DataRoot).TrimEnd('\')
    $expectedInstall = [IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'GIDEON Remote Control')).TrimEnd('\')
    $expectedData = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'GIDEON Remote Control')).TrimEnd('\')
    if (-not $install.Equals($expectedInstall, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing service ACL isolation outside GIDEON InstallRoot: $install"
    }
    if (-not $data.Equals($expectedData, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing service ACL isolation outside GIDEON DataRoot: $data"
    }

    Assert-GideonServiceSidPrincipalsResolvable

    $coord = [string]$script:GideonWindowsServicePrincipals['GIDEONRemoteControl']
    $gateway = [string]$script:GideonWindowsServicePrincipals['GIDEONRemoteControlGateway']
    $web = [string]$script:GideonWindowsServicePrincipals['GIDEONRemoteControlWebAdmin']
    $backup = [string]$script:GideonWindowsServicePrincipals['GIDEONRemoteControlBackup']
    $diag = [string]$script:GideonWindowsServicePrincipals['GIDEONRemoteControlDiagnostics']

    # Code/runtime is immutable to services.  The virtual identities receive RX
    # explicitly rather than relying on membership in BUILTIN\Users.
    Grant-GideonCodeReadExecute -Path $InstallRoot
    Grant-GideonCodeReadExecute -Path $AppRoot
    Grant-GideonCodeReadExecute -Path (Join-Path $InstallRoot 'runtime')
    Grant-GideonCodeReadExecute -Path (Join-Path $InstallRoot 'runtime\python-base')
    Grant-GideonCodeReadExecute -Path $VenvRoot
    Grant-GideonCodeReadExecute -Path (Join-Path $InstallRoot 'service-host')

    # DataRoot itself only grants traverse/read at the root; no service ACE is
    # inherited from here.  Each sub-tree below gets an explicit matrix.
    Set-GideonExactDirectoryAcl -Path $DataRoot
    Grant-GideonDirectDirectoryAccess -Path $DataRoot -Rules @{
        $coord='RX'; $gateway='RX'; $web='RX'; $backup='RX'; $diag='RX'
    }

    # Configuration has no private keys. Gateway/Web/Diagnostics are read-only.
    Set-GideonExactDirectoryAcl -Path (Join-Path $DataRoot 'config') -Rules @{
        $gateway='RX'; $web='RX'; $diag='RX'
    } -ResetChildren

    # Operational stores. Backup gets read-only access to source DB trees.
    Set-GideonExactDirectoryAcl -Path (Join-Path $DataRoot 'gateway') -Rules @{
        $gateway='M'; $backup='RX'
    } -ResetChildren
    Set-GideonExactDirectoryAcl -Path (Join-Path $DataRoot 'web') -Rules @{
        $web='M'; $backup='RX'
    } -ResetChildren
    Set-GideonExactDirectoryAcl -Path (Join-Path $DataRoot 'shared') -Rules @{
        $web='M'; $backup='RX'
    } -ResetChildren
    # RC6: no recorrer todo el árbol de backups durante una reparación. Versiones
    # legacy pudieron dejar backups recursivos/ultralargos; el contenedor actual
    # y sus destinos conocidos reciben ACL nuevas sin /T. Los backups nuevos
    # heredarán correctamente estas ACE.
    Set-GideonExactDirectoryAcl -Path (Join-Path $DataRoot 'backups') -Rules @{
        $backup='M'
    }
    Set-GideonExactDirectoryAcl -Path (Join-Path $DataRoot 'backups\local') -Rules @{
        $backup='M'
    }
    Set-GideonExactDirectoryAcl -Path (Join-Path $DataRoot 'backups\external') -Rules @{
        $backup='M'
    }

    # Diagnostics is write-only to its own snapshot area; Coordinator reads that
    # and writes only its own aggregate status. WebAdmin consumes both read-only.
    Set-GideonExactDirectoryAcl -Path (Join-Path $DataRoot 'diagnostics') -Rules @{
        $diag='M'; $coord='RX'; $web='RX'
    } -ResetChildren
    Set-GideonExactDirectoryAcl -Path (Join-Path $DataRoot 'coordinator') -Rules @{
        $coord='M'; $web='RX'
    } -ResetChildren

    # Per-service log directories avoid one shared writable location.
    Set-GideonExactDirectoryAcl -Path (Join-Path $DataRoot 'logs')
    Grant-GideonDirectDirectoryAccess -Path (Join-Path $DataRoot 'logs') -Rules @{
        $coord='RX'; $gateway='RX'; $web='RX'; $backup='RX'; $diag='RX'
    }
    Set-GideonExactDirectoryAcl -Path (Join-Path $DataRoot 'logs\services')
    Grant-GideonDirectDirectoryAccess -Path (Join-Path $DataRoot 'logs\services') -Rules @{
        $coord='RX'; $gateway='RX'; $web='RX'; $backup='RX'; $diag='RX'
    }
    foreach ($pair in @(
        @('GIDEONRemoteControl',$coord),
        @('GIDEONRemoteControlGateway',$gateway),
        @('GIDEONRemoteControlWebAdmin',$web),
        @('GIDEONRemoteControlBackup',$backup),
        @('GIDEONRemoteControlDiagnostics',$diag)
    )) {
        $logRules = @{}
        $logRules[[string]$pair[1]] = 'M'
        Set-GideonExactDirectoryAcl -Path (Join-Path $DataRoot ('logs\services\' + $pair[0])) -Rules $logRules -ResetChildren
    }
    # Updater is LocalSystem; its log directory remains SYSTEM/Administrators only.
    Set-GideonExactDirectoryAcl -Path (Join-Path $DataRoot 'logs\services\GIDEONRemoteControlUpdater') -ResetChildren

    # Private TEMP/TMP per service avoids granting write access to Windows\Temp.
    Set-GideonExactDirectoryAcl -Path (Join-Path $DataRoot 'tmp')
    Grant-GideonDirectDirectoryAccess -Path (Join-Path $DataRoot 'tmp') -Rules @{
        $coord='RX'; $gateway='RX'; $web='RX'; $backup='RX'; $diag='RX'
    }
    foreach ($pair in @(
        @('GIDEONRemoteControl',$coord),
        @('GIDEONRemoteControlGateway',$gateway),
        @('GIDEONRemoteControlWebAdmin',$web),
        @('GIDEONRemoteControlBackup',$backup),
        @('GIDEONRemoteControlDiagnostics',$diag)
    )) {
        $tempRules = @{}
        $tempRules[[string]$pair[1]] = 'M'
        Set-GideonExactDirectoryAcl -Path (Join-Path $DataRoot ('tmp\' + $pair[0])) -Rules $tempRules -ResetChildren
    }
    Set-GideonExactDirectoryAcl -Path (Join-Path $DataRoot 'tmp\GIDEONRemoteControlUpdater') -ResetChildren

    # WebAdmin may enqueue packages but cannot modify privileged staging,
    # rollback, transaction or trust state. Read access is enough for status UI.
    Set-GideonExactDirectoryAcl -Path (Join-Path $DataRoot 'updates') -Rules @{ $web='RX' } -ResetChildren
    Set-GideonExactDirectoryAcl -Path (Join-Path $DataRoot 'updates\inbox') -Rules @{ $web='M' } -ResetChildren

    # PKI: never inherit service read rights into root/agent CA private keys.
    Set-GideonExactDirectoryAcl -Path (Join-Path $DataRoot 'pki')
    Grant-GideonDirectDirectoryAccess -Path (Join-Path $DataRoot 'pki') -Rules @{
        $gateway='RX'; $web='RX'; $diag='RX'
    }
    Set-GideonExactDirectoryAcl -Path (Join-Path $DataRoot 'pki\gateway') -Rules @{ $gateway='RX' } -ResetChildren
    Set-GideonExactDirectoryAcl -Path (Join-Path $DataRoot 'pki\web') -Rules @{ $web='RX' } -ResetChildren
    Set-GideonExactDirectoryAcl -Path (Join-Path $DataRoot 'pki\root')
    Grant-GideonDirectDirectoryAccess -Path (Join-Path $DataRoot 'pki\root') -Rules @{
        $gateway='RX'; $web='RX'; $diag='RX'
    }
    Set-GideonExactFileAcl -Path (Join-Path $DataRoot 'pki\root\gideon-root-ca.pem') -Rules @{
        $gateway='R'; $web='R'; $diag='R'
    }
    Set-GideonExactFileAcl -Path (Join-Path $DataRoot 'pki\root\gideon-root-ca.key')

    Set-GideonExactDirectoryAcl -Path (Join-Path $DataRoot 'pki\agent-ca')
    Grant-GideonDirectDirectoryAccess -Path (Join-Path $DataRoot 'pki\agent-ca') -Rules @{ $gateway='RX' }
    Set-GideonExactFileAcl -Path (Join-Path $DataRoot 'pki\agent-ca\agent-client-ca.pem') -Rules @{ $gateway='R' }
    Set-GideonExactFileAcl -Path (Join-Path $DataRoot 'pki\agent-ca\agent-client-ca.key')

    # Environment secrets are split by service. No cross-read between Web/Gateway.
    Set-GideonExactDirectoryAcl -Path (Join-Path $DataRoot 'secrets')
    Grant-GideonDirectDirectoryAccess -Path (Join-Path $DataRoot 'secrets') -Rules @{ $gateway='RX'; $web='RX' }
    Set-GideonExactFileAcl -Path (Join-Path $DataRoot 'secrets\gateway.env') -Rules @{ $gateway='R' }
    Set-GideonExactFileAcl -Path (Join-Path $DataRoot 'secrets\web.env') -Rules @{ $web='R' }

    # Scanner/rule tree is readable but not writable by WebAdmin. Managed Web
    # security assets live under DataRoot\web and inherit WebAdmin Modify there.
    if (Test-Path -LiteralPath (Join-Path $DataRoot 'security') -PathType Container) {
        Set-GideonExactDirectoryAcl -Path (Join-Path $DataRoot 'security') -Rules @{ $web='RX' } -ResetChildren
    }

    Set-GideonRegistryReadAcl
}
