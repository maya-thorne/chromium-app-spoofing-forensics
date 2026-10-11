rule aitm_session_cookie_interceptor
{
    meta:
        description = "Detects scripts intercepting Azure AD session cookies (ESTSAUTH)."
        author = "Maya Thorne"
        date = "2026-10-11"
        reference = "https://github.com/maya-thorne/chromium-app-spoofing-forensics"
        threat_level = "high"
    strings:
        $a = "ESTSAUTH" ascii wide
        $b = "ESTSAUTHPERSISTENT" ascii wide
    condition:
        $a or $b
}
