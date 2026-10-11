rule powershell_shortcut_generator
{
    meta:
        description = "Detects PowerShell scripts creating WScript.Shell shortcuts with app arguments."
        author = "Maya Thorne"
        date = "2026-10-11"
        reference = "https://github.com/maya-thorne/chromium-app-spoofing-forensics"
        threat_level = "high"
    strings:
        $a = "CreateShortcut" ascii wide nocase
        $b = "--app=" ascii wide nocase
    condition:
        $a and $b
}
