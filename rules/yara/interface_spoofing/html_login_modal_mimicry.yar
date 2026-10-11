rule html_login_modal_mimicry
{
    meta:
        description = "Detects HTML files styling login forms to mimic Microsoft/Google authentication."
        author = "Maya Thorne"
        date = "2026-10-11"
        reference = "https://github.com/maya-thorne/chromium-app-spoofing-forensics"
        threat_level = "high"
    strings:
        $a = "login.microsoftonline.com" ascii wide nocase
        $b = "Sign in to your account" ascii wide
    condition:
        $a and $b
}
