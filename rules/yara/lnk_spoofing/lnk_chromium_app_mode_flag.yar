rule lnk_chromium_app_mode_flag
{
    meta:
        description = "Detects Windows LNK files embedding the --app= command line argument."
        author = "Maya Thorne"
        date = "2026-10-11"
        reference = "https://github.com/maya-thorne/chromium-app-spoofing-forensics"
        threat_level = "high"
    strings:
        $a = "--app=" ascii wide nocase
    condition:
        uint32(0) == 0x0000004C and $a
}
