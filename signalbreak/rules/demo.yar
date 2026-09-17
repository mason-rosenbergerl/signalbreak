rule demo_powershell_family {
    meta:
        description = "Safe demo rule for the snapshot fixture corpus"
    strings:
        $ps1 = "powershell.exe" ascii wide nocase
        $b64 = "FromBase64String" ascii wide nocase
    condition:
        1 of them
}
