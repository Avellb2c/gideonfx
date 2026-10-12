#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$InstallRoot = '',
    [string]$DataRoot = '',
    [switch]$Json
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0

$RegistryModule = Join-Path $PSScriptRoot 'Gideon-WindowsRegistry.ps1'
if (-not (Test-Path -LiteralPath $RegistryModule -PathType Leaf)) { throw "Falta módulo de registro Windows GIDEON: $RegistryModule" }
. $RegistryModule

$expectedLogon = [ordered]@{
    'GIDEONRemoteControl'            = 'NT AUTHORITY\LocalService'
    'GIDEONRemoteControlGateway'     = 'NT AUTHORITY\LocalService'
    'GIDEONRemoteControlWebAdmin'    = 'NT AUTHORITY\LocalService'
    'GIDEONRemoteControlBackup'      = 'NT AUTHORITY\LocalService'
    'GIDEONRemoteControlDiagnostics' = 'NT AUTHORITY\LocalService'
    'GIDEONRemoteControlUpdater'     = 'LocalSystem'
}
$serviceSid = [ordered]@{
    'GIDEONRemoteControl'            = 'NT SERVICE\GIDEONRemoteControl'
    'GIDEONRemoteControlGateway'     = 'NT SERVICE\GIDEONRemoteControlGateway'
    'GIDEONRemoteControlWebAdmin'    = 'NT SERVICE\GIDEONRemoteControlWebAdmin'
    'GIDEONRemoteControlBackup'      = 'NT SERVICE\GIDEONRemoteControlBackup'
    'GIDEONRemoteControlDiagnostics' = 'NT SERVICE\GIDEONRemoteControlDiagnostics'
    'GIDEONRemoteControlUpdater'     = 'NT SERVICE\GIDEONRemoteControlUpdater'
}

if(-not $InstallRoot -or -not $DataRoot){
    $state=Get-GideonRegistryState64
    if(-not $InstallRoot){ $InstallRoot=[string]$state.InstallRoot }
    if(-not $DataRoot){ $DataRoot=[string]$state.DataRoot }
}
$AppRoot=Join-Path $InstallRoot 'app'
$VenvRoot=Join-Path $InstallRoot 'venv'
$PrivatePythonRoot=Join-Path $InstallRoot 'runtime\python-base'
$script:rows=@()

function Add-Check([string]$Name,[bool]$Ok,[string]$Detail){
    $script:rows += [pscustomobject]@{Name=$Name;Ok=$Ok;Detail=$Detail}
}

function Get-AllowRights([string]$Path,[string]$Principal){
    if(-not (Test-Path -LiteralPath $Path)){ return [System.Security.AccessControl.FileSystemRights]0 }
    $rights=[System.Security.AccessControl.FileSystemRights]0
    $acl=Get-Acl -LiteralPath $Path
    foreach($ace in $acl.Access){
        if($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow){ continue }
        if(-not ([string]$ace.IdentityReference.Value).Equals($Principal,[StringComparison]::OrdinalIgnoreCase)){ continue }
        $rights = $rights -bor $ace.FileSystemRights
    }
    return $rights
}

function Has-Right([string]$Path,[string]$Principal,[System.Security.AccessControl.FileSystemRights]$Required){
    $actual=Get-AllowRights $Path $Principal
    return (($actual -band $Required) -eq $Required)
}

function Get-GideonMutableRightsMask {
    # Do not use composite enums such as Modify or FullControl here. Those
    # contain ReadAndExecute bits, so an RX-only ACE would be misclassified as
    # writable. Evaluate only atomic capabilities that can mutate data, delete
    # objects, or change security metadata.
    $mask=[System.Security.AccessControl.FileSystemRights]::WriteData
    $mask=$mask -bor [System.Security.AccessControl.FileSystemRights]::AppendData
    $mask=$mask -bor [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes
    $mask=$mask -bor [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles
    $mask=$mask -bor [System.Security.AccessControl.FileSystemRights]::WriteAttributes
    $mask=$mask -bor [System.Security.AccessControl.FileSystemRights]::Delete
    $mask=$mask -bor [System.Security.AccessControl.FileSystemRights]::ChangePermissions
    $mask=$mask -bor [System.Security.AccessControl.FileSystemRights]::TakeOwnership
    return $mask
}

function Has-AnyWrite([string]$Path,[string]$Principal){
    $actual=Get-AllowRights $Path $Principal
    $mask=Get-GideonMutableRightsMask
    return (($actual -band $mask) -ne 0)
}

function Has-AnyAllow([string]$Path,[string]$Principal){
    return ((Get-AllowRights $Path $Principal) -ne [System.Security.AccessControl.FileSystemRights]0)
}

# SCM identity contract.
foreach($name in $expectedLogon.Keys){
    $svc=Get-CimInstance -ClassName Win32_Service -Filter ("Name='" + $name.Replace("'","''") + "'") -ErrorAction SilentlyContinue
    if($null -eq $svc){ Add-Check "SCM identity $name" $false 'Servicio no instalado'; continue }
    $actual=[string]$svc.StartName
    $wanted=[string]$expectedLogon[$name]
    Add-Check "SCM identity $name" ($actual.Equals($wanted,[StringComparison]::OrdinalIgnoreCase)) "StartName=$actual; expected=$wanted"
    $serviceReg='HKLM:\SYSTEM\CurrentControlSet\Services\' + $name
    $sidType=0
    try { $sidType=[int](Get-ItemPropertyValue -LiteralPath $serviceReg -Name ServiceSidType -ErrorAction Stop) } catch { $sidType=0 }
    Add-Check "Service SID $name" ($sidType -eq 1) "ServiceSidType=$sidType; expected=1 (UNRESTRICTED)"
}

$coord=[string]$serviceSid['GIDEONRemoteControl']
$gateway=[string]$serviceSid['GIDEONRemoteControlGateway']
$web=[string]$serviceSid['GIDEONRemoteControlWebAdmin']
$backup=[string]$serviceSid['GIDEONRemoteControlBackup']
$diag=[string]$serviceSid['GIDEONRemoteControlDiagnostics']
$rx=[System.Security.AccessControl.FileSystemRights]::ReadAndExecute
$modify=[System.Security.AccessControl.FileSystemRights]::Modify
$read=[System.Security.AccessControl.FileSystemRights]::Read
# PS 5.1 argument mode can stringify an inline [Type]::Member token; pass typed variables to functions.

# All non-updater services must be able to execute immutable code explicitly.
foreach($account in @($coord,$gateway,$web,$backup,$diag)){
    Add-Check "Code RX $account" (Has-Right $AppRoot $account $rx) $AppRoot
    Add-Check "Runtime RX $account" (Has-Right $PrivatePythonRoot $account $rx) $PrivatePythonRoot
    Add-Check "Venv RX $account" (Has-Right $VenvRoot $account $rx) $VenvRoot
}

# Positive least-privilege paths.
$positive=@(
    @((Join-Path $DataRoot 'gateway'),$gateway,$modify,'Gateway Modify gateway'),
    @((Join-Path $DataRoot 'web'),$web,$modify,'WebAdmin Modify web'),
    @((Join-Path $DataRoot 'backups'),$backup,$modify,'Backup Modify backups'),
    @((Join-Path $DataRoot 'diagnostics'),$diag,$modify,'Diagnostics Modify diagnostics'),
    @((Join-Path $DataRoot 'coordinator'),$coord,$modify,'Coordinator Modify coordinator'),
    @((Join-Path $DataRoot 'diagnostics'),$coord,$rx,'Coordinator Read diagnostics'),
    @((Join-Path $DataRoot 'diagnostics'),$web,$rx,'WebAdmin Read diagnostics'),
    @((Join-Path $DataRoot 'tmp\GIDEONRemoteControl'),$coord,$modify,'Coordinator Modify own TEMP'),
    @((Join-Path $DataRoot 'tmp\GIDEONRemoteControlGateway'),$gateway,$modify,'Gateway Modify own TEMP'),
    @((Join-Path $DataRoot 'tmp\GIDEONRemoteControlWebAdmin'),$web,$modify,'WebAdmin Modify own TEMP'),
    @((Join-Path $DataRoot 'tmp\GIDEONRemoteControlBackup'),$backup,$modify,'Backup Modify own TEMP'),
    @((Join-Path $DataRoot 'tmp\GIDEONRemoteControlDiagnostics'),$diag,$modify,'Diagnostics Modify own TEMP')
)
foreach($item in $positive){ Add-Check ([string]$item[3]) (Has-Right ([string]$item[0]) ([string]$item[1]) $item[2]) ([string]$item[0]) }

# Negative/cross-service boundaries.
$negativeWrite=@(
    @((Join-Path $DataRoot 'gateway'),$backup,'Backup cannot modify Gateway source'),
    @((Join-Path $DataRoot 'web'),$backup,'Backup cannot modify Web source'),
    @((Join-Path $DataRoot 'config'),$diag,'Diagnostics cannot modify config'),
    @((Join-Path $DataRoot 'gateway'),$web,'WebAdmin cannot modify Gateway data'),
    @((Join-Path $DataRoot 'web'),$gateway,'Gateway cannot modify Web data')
)
foreach($item in $negativeWrite){ Add-Check ([string]$item[2]) (-not (Has-AnyWrite ([string]$item[0]) ([string]$item[1]))) ([string]$item[0]) }

# Private key and env cross-read boundaries. These files are created by the installer.
$denyRead=@(
    @((Join-Path $DataRoot 'pki\gateway\gateway.key'),$web,'WebAdmin cannot read gateway.key'),
    @((Join-Path $DataRoot 'pki\web\web.key'),$gateway,'Gateway cannot read web.key'),
    @((Join-Path $DataRoot 'pki\root\gideon-root-ca.key'),$web,'WebAdmin cannot read root CA key'),
    @((Join-Path $DataRoot 'pki\root\gideon-root-ca.key'),$gateway,'Gateway cannot read root CA key'),
    @((Join-Path $DataRoot 'pki\agent-ca\agent-client-ca.key'),$gateway,'Gateway cannot read agent CA private key'),
    @((Join-Path $DataRoot 'secrets\gateway.env'),$web,'WebAdmin cannot read gateway.env'),
    @((Join-Path $DataRoot 'secrets\web.env'),$gateway,'Gateway cannot read web.env')
)
foreach($item in $denyRead){
    $path=[string]$item[0]; $principal=[string]$item[1]
    $ok=(Test-Path -LiteralPath $path -PathType Leaf) -and (-not (Has-AnyAllow $path $principal))
    Add-Check ([string]$item[2]) $ok $path
}

# Own secret/key access must still exist.
$positiveRead=@(
    @((Join-Path $DataRoot 'pki\gateway\gateway.key'),$gateway,'Gateway reads own TLS key'),
    @((Join-Path $DataRoot 'pki\web\web.key'),$web,'WebAdmin reads own TLS key'),
    @((Join-Path $DataRoot 'secrets\gateway.env'),$gateway,'Gateway reads own env'),
    @((Join-Path $DataRoot 'secrets\web.env'),$web,'WebAdmin reads own env')
)
foreach($item in $positiveRead){
    $path=[string]$item[0]; $principal=[string]$item[1]
    Add-Check ([string]$item[2]) (Has-Right $path $principal $read) $path
}

$failed=@($script:rows | Where-Object { -not $_.Ok })
$payload=[ordered]@{
    schema='gideon-windows-service-isolation/v1'
    version='6.3.4-rc30'
    install_root=$InstallRoot
    data_root=$DataRoot
    passed=($failed.Count -eq 0)
    checks=$script:rows
}
if($Json){ $payload | ConvertTo-Json -Depth 8 }
else{
    foreach($row in $script:rows){
        $prefix=if($row.Ok){'[OK]'}else{'[FAIL]'}
        Write-Host "$prefix $($row.Name) · $($row.Detail)" -ForegroundColor $(if($row.Ok){'Green'}else{'Red'})
    }
    Write-Host ("Windows isolation: " + $(if($failed.Count -eq 0){'PASS'}else{'FAIL'}))
}
exit $(if($failed.Count -eq 0){0}else{1})
