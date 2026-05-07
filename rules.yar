rule Suspicious_String
{
    strings:
        $a = "cmd.exe" nocase
        $b = "powershell" nocase
        $c = "Invoke-Mimikatz" nocase
        $d = "Meterpreter" nocase
        $e = "Cobalt Strike" nocase
    condition:
        any of them
}

rule Suspicious_Credential_Access
{
    strings:
        $lsa = "lsass.exe" nocase
        $sekurlsa = "sekurlsa::logonpasswords" nocase
        $dump = "procdump -ma lsass.exe" nocase
    condition:
        2 of them
}