rule cs_webview2_native_wrapper
{
    meta:
        description = "Detects .NET binaries embedding Microsoft Edge WebView2 control for headless UI framing."
        author = "Maya Thorne"
        date = "2026-10-11"
        reference = "https://github.com/maya-thorne/chromium-app-spoofing-forensics"
        threat_level = "high"
    strings:
        $a = "Microsoft.Web.WebView2" ascii wide
        $b = "EnsureCoreWebView2Async" ascii wide
    condition:
        uint16(0) == 0x5A4D and ($a or $b)
}
