rule lnk_kiosk_fullscreen_mode
{
    meta:
        description = "Detects LNK files configuring browser kiosk mode."
        author = "Maya Thorne"
        date = "2026-10-11"
        reference = "https://github.com/maya-thorne/chromium-app-spoofing-forensics"
        threat_level = "high"
    strings:
        $a = "--kiosk" ascii wide nocase
    condition:
        uint32(0) == 0x0000004C and $a
}
