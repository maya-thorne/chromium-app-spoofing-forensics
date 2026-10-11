rule lnk_chrome_browser_target
{
    meta:
        description = "Detects LNK files targeting Chrome in standalone app mode."
        author = "Maya Thorne"
        date = "2026-10-11"
        reference = "https://github.com/maya-thorne/chromium-app-spoofing-forensics"
        threat_level = "high"
    strings:
        $a = "chrome.exe" ascii wide nocase
        $b = "--app=" ascii wide nocase
    condition:
        uint32(0) == 0x0000004C and $a and $b
}
