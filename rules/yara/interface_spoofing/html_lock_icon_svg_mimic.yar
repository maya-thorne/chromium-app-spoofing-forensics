rule html_lock_icon_svg_mimic
{
    meta:
        description = "Detects synthetic SSL padlock SVG icons embedded in web views."
        author = "Maya Thorne"
        date = "2026-10-11"
        reference = "https://github.com/maya-thorne/chromium-app-spoofing-forensics"
        threat_level = "high"
    strings:
        $a = "lock-icon" ascii wide
        $b = "M18 8h-1V6c0-2.76" ascii
    condition:
        $a and $b
}
