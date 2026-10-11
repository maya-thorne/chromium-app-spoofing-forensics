rule win32_window_class_checker
{
    meta:
        description = "Detects code verifying or spoofing Chrome_WidgetWin_1 window classes."
        author = "Maya Thorne"
        date = "2026-10-11"
        reference = "https://github.com/maya-thorne/chromium-app-spoofing-forensics"
        threat_level = "high"
    strings:
        $a = "Chrome_WidgetWin_1" ascii wide
    condition:
        $a
}
