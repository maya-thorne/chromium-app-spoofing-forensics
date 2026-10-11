rule fido2_origin_downgrade_trap
{
    meta:
        description = "Detects code attempting to bypass WebAuthn by falling back to credential prompt."
        author = "Maya Thorne"
        date = "2026-10-11"
        reference = "https://github.com/maya-thorne/chromium-app-spoofing-forensics"
        threat_level = "high"
    strings:
        $a = "navigator.credentials.get" ascii wide
        $b = "fallback" ascii wide
    condition:
        $a and $b
}
