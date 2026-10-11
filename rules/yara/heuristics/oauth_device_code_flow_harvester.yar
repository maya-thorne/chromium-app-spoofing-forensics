rule oauth_device_code_flow_harvester
{
    meta:
        description = "Detects scripts initiating RFC 8628 Device Authorization Grant."
        author = "Maya Thorne"
        date = "2026-10-11"
        reference = "https://github.com/maya-thorne/chromium-app-spoofing-forensics"
        threat_level = "high"
    strings:
        $a = "grant_type=urn:ietf:params:oauth:grant-type:device_code" ascii wide
    condition:
        $a
}
