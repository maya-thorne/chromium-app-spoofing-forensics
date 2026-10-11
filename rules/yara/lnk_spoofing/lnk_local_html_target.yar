rule lnk_local_html_target
{
    meta:
        description = "Detects LNK files targeting local HTML files via --app parameter."
        author = "Maya Thorne"
        date = "2026-10-11"
        reference = "https://github.com/maya-thorne/chromium-app-spoofing-forensics"
        threat_level = "high"
    strings:
        $a = "--app=" ascii wide nocase
        $b = ".html" ascii wide nocase
    condition:
        uint32(0) == 0x0000004C and $a and $b
}
