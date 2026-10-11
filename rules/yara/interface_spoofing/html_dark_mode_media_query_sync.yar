rule html_dark_mode_media_query_sync
{
    meta:
        description = "Detects JS matching prefers-color-scheme to dynamically skin fake titlebar."
        author = "Maya Thorne"
        date = "2026-10-11"
        reference = "https://github.com/maya-thorne/chromium-app-spoofing-forensics"
        threat_level = "high"
    strings:
        $a = "matchMedia('(prefers-color-scheme: dark)')" ascii
    condition:
        $a
}
