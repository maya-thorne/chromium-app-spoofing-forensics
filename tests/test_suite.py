#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_suite.py - Unit Test Suite for Chromium App Spoofing Forensics Suite
Part of chromium-app-spoofing-forensics
Zero-dependency unit tests verifying 100% engine integrity.
"""

import os
import sys
import unittest

# Ensure src/ is importable
SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from lnk_forensics_parser import LNKForensicsParser, filetime_to_iso
from chromium_app_detector import ChromiumAppDetector
from window_hierarchy_auditor import WindowHierarchyAuditor
from device_code_flow_guard import DeviceCodeFlowGuard


class TestLNKForensicsParser(unittest.TestCase):
    """Verifies binary LNK parsing and indicator scoring."""

    def test_filetime_converter(self):
        # 133500000000000000 approx 2024
        res = filetime_to_iso(133500000000000000)
        self.assertIsNotNone(res)
        self.assertTrue(res.startswith("2024"))

        # Zero or invalid filetime
        self.assertIsNone(filetime_to_iso(0))
        self.assertIsNone(filetime_to_iso(-100))

    def test_synthetic_lnk_header(self):
        # Construct valid 76-byte ShellLinkHeader
        hdr_size = 76
        clsid = b"\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46"
        flags = (1 << 5) | (1 << 7)  # HasArguments + IsUnicode
        file_attrs = 32  # FILE_ATTRIBUTE_ARCHIVE
        ctime = 133500000000000000
        atime = 133500000000000000
        wtime = 133500000000000000
        file_len = 1024
        icon_idx = 0
        show_cmd = 1  # SW_SHOWNORMAL
        hotkey = 0
        res1 = 0
        res2 = 0
        res3 = 0

        import struct
        header_bytes = struct.pack(
            "<I16sIIQQQIIIHHII",
            hdr_size, clsid, flags, file_attrs, ctime, atime, wtime, file_len, icon_idx, show_cmd, hotkey, res1, res2, res3
        )
        self.assertEqual(len(header_bytes), 76)

        # Append string data: arguments in UTF-16LE
        args_text = "--app=https://youtube.com -incognito"
        char_count = len(args_text)
        args_bytes = struct.pack("<H", char_count) + args_text.encode("utf-16le")

        full_raw = header_bytes + args_bytes
        parser = LNKForensicsParser(full_raw, "synthetic_test.lnk")
        report = parser.parse()

        self.assertTrue(report["is_valid_header"])
        self.assertEqual(report["header"]["show_command"], "SW_SHOWNORMAL (Normal Window)")
        self.assertIn("HasArguments", report["header"]["link_flags_active"])
        self.assertEqual(report["string_data"].get("command_line_arguments"), args_text)

        # Threat assessment check
        risk = report["risk_assessment"]
        self.assertGreaterEqual(risk["risk_score"], 60)
        self.assertIn("CHROMIUM_APP_MODE_DETECTED", risk["indicators"][0])


class TestChromiumAppDetector(unittest.TestCase):
    """Verifies process creation telemetry and argument heuristics."""

    def setUp(self):
        self.detector = ChromiumAppDetector()

    def test_clean_browser_invocation(self):
        cli = '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" https://example.com'
        report = self.detector.analyze_command_line(cli, image_path="chrome.exe")
        self.assertTrue(report["is_browser_execution"])
        self.assertEqual(report["threat_level"], "LOW")
        self.assertEqual(report["risk_score"], 0)

    def test_app_mode_local_file_evasion(self):
        cli = 'brave.exe --app="C:\\Users\\Victim\\Desktop\\invoice.html" -incognito --window-size=440,520'
        report = self.detector.analyze_command_line(cli, parent_image="powershell.exe")
        self.assertTrue(report["is_browser_execution"])
        self.assertEqual(report["threat_level"], "CRITICAL")
        self.assertGreaterEqual(report["risk_score"], 80)
        tags = [f["tag"] for f in report["findings"]]
        self.assertIn("CHROMIUM_APP_MODE_INVOCATION", tags)
        self.assertIn("LOCAL_FILE_APP_HOSTING", tags)
        self.assertIn("INCOGNITO_CREDENTIAL_ISOLATION", tags)
        self.assertIn("LOGIN_MODAL_DIMENSION_MIMICRY", tags)
        self.assertIn("SUSPICIOUS_SCRIPT_PARENT_HIERARCHY", tags)


class TestWindowHierarchyAuditor(unittest.TestCase):
    """Verifies Win32 window title and process mismatch auditing."""

    def setUp(self):
        self.auditor = WindowHierarchyAuditor()

    def test_legitimate_teams_window(self):
        report = self.auditor.audit_window_record(
            window_title="Microsoft Teams - General Channel",
            window_class="TeamsWebView",
            process_name="ms-teams.exe",
            process_path="C:\\Program Files\\WindowsApps\\MSTeams\\ms-teams.exe"
        )
        self.assertEqual(report["threat_level"], "CLEAN")
        self.assertEqual(report["risk_score"], 0)

    def test_masquerading_browser_window(self):
        report = self.auditor.audit_window_record(
            window_title="Sign in to Microsoft Teams",
            window_class="Chrome_WidgetWin_1",
            process_name="brave.exe",
            process_path="C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe"
        )
        self.assertEqual(report["threat_level"], "CRITICAL")
        self.assertGreaterEqual(report["risk_score"], 70)
        tags = [v["tag"] for v in report["violations"]]
        self.assertIn("WINDOW_TITLE_BROWSER_MISMATCH", tags)
        self.assertIn("CHROME_WIDGET_MODAL_TRAP", tags)


class TestDeviceCodeFlowGuard(unittest.TestCase):
    """Verifies RFC 8628 abuse, fake address bar CSS, and AiTM cookies."""

    def setUp(self):
        self.guard = DeviceCodeFlowGuard()

    def test_benign_html(self):
        html = "<html><head><title>Welcome</title></head><body>Hello World</body></html>"
        report = self.guard.inspect_html_or_script(html)
        self.assertEqual(report["threat_level"], "CLEAN")
        self.assertEqual(report["risk_score"], 0)

    def test_phishing_payload_with_device_code_and_css(self):
        html = """
        <div class="fake-address-bar">
            <span class="lock-icon">🔒</span> https://login.microsoftonline.com
        </div>
        <p>To sign in, open https://microsoft.com/devicelogin and enter code: B4X9-K2L8</p>
        <script>
            document.cookie = 'ESTSAUTH=xyz; path=/';
        </script>
        """
        report = self.guard.inspect_html_or_script(html)
        self.assertEqual(report["threat_level"], "CRITICAL")
        self.assertEqual(report["risk_score"], 100)
        tags = [f["tag"] for f in report["findings"]]
        self.assertIn("OAUTH_DEVICE_CODE_FLOW_URL", tags)
        self.assertIn("DEVICE_USER_CODE_STRING", tags)
        self.assertIn("SYNTHETIC_ADDRESS_BAR_DOM", tags)
        self.assertIn("AITM_SESSION_COOKIE_EXFILTRATION", tags)


if __name__ == "__main__":
    unittest.main()
