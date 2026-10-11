rule cefsharp_embedded_browser
{
    meta:
        description = "Detects CefSharp Chromium embedded controls used in custom wrappers."
        author = "Maya Thorne"
        date = "2026-10-11"
        reference = "https://github.com/maya-thorne/chromium-app-spoofing-forensics"
        threat_level = "high"
    strings:
        $a = "CefSharp.WinForms" ascii wide
        $b = "CefSharp.Wpf" ascii wide
    condition:
        uint16(0) == 0x5A4D and ($a or $b)
}
