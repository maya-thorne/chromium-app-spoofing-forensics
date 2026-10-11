rule html_browser_chrome_css_strip
{
    meta:
        description = "Detects CSS disabling standard UI controls and scrollbars for seamless app mimicry."
        author = "Maya Thorne"
        date = "2026-10-11"
        reference = "https://github.com/maya-thorne/chromium-app-spoofing-forensics"
        threat_level = "high"
    strings:
        $a = "overflow: hidden" ascii
        $b = "user-select: none" ascii
    condition:
        $a and $b
}
