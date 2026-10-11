rule lnk_incognito_evasion_flag
{
    meta:
        description = "Detects LNK files combining browser execution with incognito flag."
        author = "Maya Thorne"
        date = "2026-10-11"
        reference = "https://github.com/maya-thorne/chromium-app-spoofing-forensics"
        threat_level = "high"
    strings:
        $a = "-incognito" ascii wide nocase
        $b = "--incognito" ascii wide nocase
    condition:
        uint32(0) == 0x0000004C and ($a or $b)
}
