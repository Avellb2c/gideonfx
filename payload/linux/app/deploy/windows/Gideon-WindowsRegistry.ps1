#requires -Version 5.1
Set-StrictMode -Version 2.0

# GIDEON Windows registry state is always stored in the native 64-bit registry view.
# This avoids WOW64 view mismatches between PowerShell, Python and the SCM host.
$script:GideonRegistrySubPath = 'SOFTWARE\GIDEON\RemoteControl'

function Open-GideonRegistry64Base {
    return [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64
    )
}

function Set-GideonRegistryState64 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$InstallRoot,
        [Parameter(Mandatory=$true)][string]$AppRoot,
        [Parameter(Mandatory=$true)][string]$DataRoot,
        [Parameter(Mandatory=$true)][string]$Version
    )
    $base = Open-GideonRegistry64Base
    try {
        $key = $base.CreateSubKey($script:GideonRegistrySubPath, $true)
        if ($null -eq $key) { throw 'CreateSubKey devolvió null.' }
        try {
            $key.SetValue('InstallRoot', $InstallRoot, [Microsoft.Win32.RegistryValueKind]::String)
            $key.SetValue('AppRoot', $AppRoot, [Microsoft.Win32.RegistryValueKind]::String)
            $key.SetValue('DataRoot', $DataRoot, [Microsoft.Win32.RegistryValueKind]::String)
            $key.SetValue('Version', $Version, [Microsoft.Win32.RegistryValueKind]::String)
            $key.Flush()
        } finally { $key.Dispose() }
    } finally { $base.Dispose() }

    # Read-after-write verification in the exact same native view.
    $state = Get-GideonRegistryState64
    foreach ($pair in @{
        InstallRoot=$InstallRoot; AppRoot=$AppRoot; DataRoot=$DataRoot; Version=$Version
    }.GetEnumerator()) {
        if (-not ([string]$state[$pair.Key]).Equals([string]$pair.Value, [StringComparison]::OrdinalIgnoreCase)) {
            throw "REGISTRY_STATE_VERIFY_FAILED: $($pair.Key)"
        }
    }
}

function Get-GideonRegistryState64 {
    [CmdletBinding()]
    param()
    $base = Open-GideonRegistry64Base
    try {
        $key = $base.OpenSubKey($script:GideonRegistrySubPath, $false)
        if ($null -eq $key) { throw "REGISTRY_STATE_MISSING: HKLM\$script:GideonRegistrySubPath (Registry64)" }
        try {
            return [ordered]@{
                InstallRoot = [string]$key.GetValue('InstallRoot', '')
                AppRoot = [string]$key.GetValue('AppRoot', '')
                DataRoot = [string]$key.GetValue('DataRoot', '')
                Version = [string]$key.GetValue('Version', '')
            }
        } finally { $key.Dispose() }
    } finally { $base.Dispose() }
}

function Set-GideonRegistryReadAcl64 {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string[]]$ReadPrincipals)

    $base = Open-GideonRegistry64Base
    try {
        # Create-or-open the known GIDEON key. This is intentionally idempotent and
        # limited to HKLM\SOFTWARE\GIDEON\RemoteControl.
        $key = $base.CreateSubKey(
            $script:GideonRegistrySubPath,
            [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree
        )
        if ($null -eq $key) { throw 'REGISTRY_ACL_OPEN_FAILED' }
        try {
            $security = $key.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)
            $security.SetAccessRuleProtection($true, $false)
            foreach ($rule in @($security.GetAccessRules($true, $true, [System.Security.Principal.NTAccount]))) {
                [void]$security.RemoveAccessRuleSpecific($rule)
            }

            $inherit = [System.Security.AccessControl.InheritanceFlags]::None
            $prop = [System.Security.AccessControl.PropagationFlags]::None
            $allow = [System.Security.AccessControl.AccessControlType]::Allow
            foreach ($principal in @('NT AUTHORITY\SYSTEM','BUILTIN\Administrators')) {
                $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
                    $principal,
                    [System.Security.AccessControl.RegistryRights]::FullControl,
                    $inherit,
                    $prop,
                    $allow
                )
                [void]$security.AddAccessRule($rule)
            }
            foreach ($principal in ($ReadPrincipals | Sort-Object -Unique)) {
                $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
                    $principal,
                    [System.Security.AccessControl.RegistryRights]::ReadKey,
                    $inherit,
                    $prop,
                    $allow
                )
                [void]$security.AddAccessRule($rule)
            }
            $key.SetAccessControl($security)
        } finally { $key.Dispose() }
    } finally { $base.Dispose() }
}
