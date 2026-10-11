rule lnk_inprivate_edge_flag
{
    meta:
        description = "Detects LNK files invoking Edge with inprivate mode."
        author = "Maya Thorne"
        date = "2026-10-11"
        reference = "https://github.com/maya-thorne/chromium-app-spoofing-forensics"
        threat_level = "high"
    strings:
        $a = "-inprivate" ascii wide nocase
    condition:
        uint32(0) == 0x0000004C and $a
}
