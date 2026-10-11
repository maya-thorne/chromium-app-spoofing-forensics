rule lnk_stealth_minimized_show
{
    meta:
        description = "Detects LNK files set to SW_SHOWMINNOACTIVE (ShowCommand=7)."
        author = "Maya Thorne"
        date = "2026-10-11"
        reference = "https://github.com/maya-thorne/chromium-app-spoofing-forensics"
        threat_level = "high"
    condition:
        uint32(0) == 0x0000004C and uint32(0x3C) == 7
}
