rule cdp_cookie_extractor_snippet
{
    meta:
        description = "Detects CDP scripts invoking Network.getCookies to dump session state."
        author = "Maya Thorne"
        date = "2026-10-11"
        reference = "https://github.com/maya-thorne/chromium-app-spoofing-forensics"
        threat_level = "high"
    strings:
        $a = "Network.getCookies" ascii wide
        $b = "Page.navigate" ascii wide
    condition:
        $a and $b
}
