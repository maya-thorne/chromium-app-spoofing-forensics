rule lnk_teams_icon_masquerade
{
    meta:
        description = "Detects LNK files pointing to Teams icon while executing browser binary."
        author = "Maya Thorne"
        date = "2026-10-11"
        reference = "https://github.com/maya-thorne/chromium-app-spoofing-forensics"
        threat_level = "high"
    strings:
        $a = "teams.ico" ascii wide nocase
    condition:
        uint32(0) == 0x0000004C and $a
}
