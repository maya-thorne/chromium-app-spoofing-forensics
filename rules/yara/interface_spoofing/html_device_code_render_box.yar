rule html_device_code_render_box
{
    meta:
        description = "Detects HTML layouts dedicated to rendering 8-character device login codes."
        author = "Maya Thorne"
        date = "2026-10-11"
        reference = "https://github.com/maya-thorne/chromium-app-spoofing-forensics"
        threat_level = "high"
    strings:
        $a = "devicelogin" ascii wide nocase
        $b = "Enter the code" ascii wide nocase
    condition:
        $a and $b
}
