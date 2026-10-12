rule GIDEON_Review_Credential_Dumping_Terms {
    meta:
        description = "Requires manual review: credential dumping terminology"
    strings:
        $a = "Invoke-Mimikatz" nocase ascii wide
        $b = "sekurlsa::" nocase ascii wide
        $c = "lsadump::" nocase ascii wide
    condition:
        any of them
}

rule GIDEON_Review_Defender_Disable {
    meta:
        description = "Requires manual review: attempts to disable endpoint protection"
    strings:
        $a = "DisableRealtimeMonitoring" nocase ascii wide
        $b = "Set-MpPreference" nocase ascii wide
        $c = "Add-MpPreference" nocase ascii wide
    condition:
        any of them
}
