rule html_fake_address_bar_dom
{
    meta:
        description = "Detects HTML files containing fake address bar CSS/DOM classes."
        author = "Maya Thorne"
        date = "2026-10-11"
        reference = "https://github.com/maya-thorne/chromium-app-spoofing-forensics"
        threat_level = "high"
    strings:
        $a = "fake-address-bar" ascii wide nocase
        $b = "address-bar-mock" ascii wide nocase
    condition:
        $a or $b
}
