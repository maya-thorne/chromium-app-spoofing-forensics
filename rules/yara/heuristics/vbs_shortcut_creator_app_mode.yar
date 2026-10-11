rule vbs_shortcut_creator_app_mode
{
    meta:
        description = "Detects VBScript files dropping Chromium app mode shortcuts."
        author = "Maya Thorne"
        date = "2026-10-11"
        reference = "https://github.com/maya-thorne/chromium-app-spoofing-forensics"
        threat_level = "high"
    strings:
        $a = ".TargetPath" ascii wide nocase
        $b = ".Arguments" ascii wide nocase
        $c = "--app=" ascii wide nocase
    condition:
        $a and $b and $c
}
