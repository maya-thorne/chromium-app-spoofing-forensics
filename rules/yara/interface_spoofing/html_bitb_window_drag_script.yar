rule html_bitb_window_drag_script
{
    meta:
        description = "Detects JavaScript implementing draggable synthetic desktop windows inside web view."
        author = "Maya Thorne"
        date = "2026-10-11"
        reference = "https://github.com/maya-thorne/chromium-app-spoofing-forensics"
        threat_level = "high"
    strings:
        $a = "dragElement" ascii wide
        $b = "window-drag-region" ascii wide
    condition:
        $a and $b
}
