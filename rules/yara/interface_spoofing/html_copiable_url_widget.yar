rule html_copiable_url_widget
{
    meta:
        description = "Detects HTML widgets mimicking browser omnibox copy-url button."
        author = "Maya Thorne"
        date = "2026-10-11"
        reference = "https://github.com/maya-thorne/chromium-app-spoofing-forensics"
        threat_level = "high"
    strings:
        $a = "copy-address" ascii wide
        $b = "clipboard.writeText" ascii wide
    condition:
        $a and $b
}
