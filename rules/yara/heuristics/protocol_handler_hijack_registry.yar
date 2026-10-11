rule protocol_handler_hijack_registry
{
    meta:
        description = "Detects registry modification scripts tampering with msteams or slack URI schemes."
        author = "Maya Thorne"
        date = "2026-10-11"
        reference = "https://github.com/maya-thorne/chromium-app-spoofing-forensics"
        threat_level = "high"
    strings:
        $a = "HKCU\\Software\\Classes\\msteams" ascii wide nocase
    condition:
        $a
}
