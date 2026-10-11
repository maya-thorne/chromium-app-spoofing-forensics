rule lnk_office_icon_masquerade
{
    meta:
        description = "Detects LNK files using Microsoft Office icons with browser target."
        author = "Maya Thorne"
        date = "2026-10-11"
        reference = "https://github.com/maya-thorne/chromium-app-spoofing-forensics"
        threat_level = "high"
    strings:
        $a = "office.ico" ascii wide nocase
    condition:
        uint32(0) == 0x0000004C and $a
}
