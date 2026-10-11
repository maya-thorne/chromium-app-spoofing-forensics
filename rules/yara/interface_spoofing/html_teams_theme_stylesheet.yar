rule html_teams_theme_stylesheet
{
    meta:
        description = "Detects stylesheet rules replicating Teams dark/light theme palettes."
        author = "Maya Thorne"
        date = "2026-10-11"
        reference = "https://github.com/maya-thorne/chromium-app-spoofing-forensics"
        threat_level = "high"
    strings:
        $a = "#464775" ascii wide
        $b = "#6264a7" ascii wide
    condition:
        $a or $b
}
