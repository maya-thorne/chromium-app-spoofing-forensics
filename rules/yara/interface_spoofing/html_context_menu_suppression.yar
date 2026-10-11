rule html_context_menu_suppression
{
    meta:
        description = "Detects JS suppressing right-click context menu to prevent browser inspection."
        author = "Maya Thorne"
        date = "2026-10-11"
        reference = "https://github.com/maya-thorne/chromium-app-spoofing-forensics"
        threat_level = "high"
    strings:
        $a = "oncontextmenu=\"return false\"" ascii wide nocase
    condition:
        $a
}
