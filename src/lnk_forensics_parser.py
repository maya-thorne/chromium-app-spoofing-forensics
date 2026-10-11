#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
lnk_forensics_parser.py - Production [MS-SHLLINK] Binary Parser & Forensic Carving Engine
Part of chromium-app-spoofing-forensics suite
Zero-dependency static analysis tool for Windows Shortcut (.LNK) artifacts.
"""

from __future__ import annotations

import os
import struct
import datetime
from typing import Dict, Any, List, Optional, Tuple

# MS-SHLLINK Flag Definitions
FLAG_HAS_TARGET_ID_LIST = 1 << 0
FLAG_HAS_LINK_INFO = 1 << 1
FLAG_HAS_NAME = 1 << 2
FLAG_HAS_RELATIVE_PATH = 1 << 3
FLAG_HAS_WORKING_DIR = 1 << 4
FLAG_HAS_ARGUMENTS = 1 << 5
FLAG_HAS_ICON_LOCATION = 1 << 6
FLAG_IS_UNICODE = 1 << 7
FLAG_FORCE_NO_LINK_INFO = 1 << 8
FLAG_HAS_EXP_STRING = 1 << 9
FLAG_RUN_IN_SEPARATE = 1 << 10
FLAG_RUN_AS_USER = 1 << 13
FLAG_HAS_EXP_ICON = 1 << 14

SHOW_COMMAND_MAP = {
    1: "SW_SHOWNORMAL (Normal Window)",
    3: "SW_SHOWMAXIMIZED (Maximized Window)",
    7: "SW_SHOWMINNOACTIVE (Minimized / Hidden Window)"
}

EXPECTED_CLSID = b"\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46"


def filetime_to_iso(ft_int: int) -> Optional[str]:
    """Converts 64-bit Windows FILETIME (100ns intervals since 1601-01-01) to ISO-8601 string."""
    if ft_int <= 0:
        return None
    try:
        # Microseconds since 1601
        us = ft_int / 10
        dt = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=us)
        return dt.isoformat()
    except (OverflowError, OSError, ValueError):
        return None


class LNKForensicsParser:
    """Enterprise-grade zero-dependency [MS-SHLLINK] binary parser."""

    def __init__(self, raw_bytes: bytes, filename: str = "unknown.lnk") -> None:
        self.raw_bytes = raw_bytes
        self.filename = filename
        self.file_size = len(raw_bytes)
        self.offset = 0
        self.metadata: Dict[str, Any] = {
            "filename": filename,
            "file_size": self.file_size,
            "is_valid_header": False,
            "header": {},
            "target_id_list": None,
            "link_info": None,
            "string_data": {},
            "extra_data_blocks": [],
            "risk_assessment": {}
        }

    def parse(self) -> Dict[str, Any]:
        """Parses the entire LNK binary stream."""
        if len(self.raw_bytes) < 76:
            self.metadata["error"] = "File too small to contain ShellLinkHeader (less than 76 bytes)"
            return self.metadata

        # 1. ShellLinkHeader (76 bytes fixed size)
        self._parse_header()
        if not self.metadata["is_valid_header"]:
            return self.metadata

        # 2. LinkTargetIDList (optional)
        link_flags = self.metadata["header"]["link_flags_int"]
        if link_flags & FLAG_HAS_TARGET_ID_LIST:
            self._parse_target_id_list()

        # 3. LinkInfo (optional)
        if (link_flags & FLAG_HAS_LINK_INFO) and not (link_flags & FLAG_FORCE_NO_LINK_INFO):
            self._parse_link_info()

        # 4. StringData Structures (optional: Name, RelativePath, WorkingDir, Arguments, IconLocation)
        is_unicode = bool(link_flags & FLAG_IS_UNICODE)
        if link_flags & FLAG_HAS_NAME:
            self.metadata["string_data"]["name"] = self._read_string_data(is_unicode)
        if link_flags & FLAG_HAS_RELATIVE_PATH:
            self.metadata["string_data"]["relative_path"] = self._read_string_data(is_unicode)
        if link_flags & FLAG_HAS_WORKING_DIR:
            self.metadata["string_data"]["working_dir"] = self._read_string_data(is_unicode)
        if link_flags & FLAG_HAS_ARGUMENTS:
            self.metadata["string_data"]["command_line_arguments"] = self._read_string_data(is_unicode)
        if link_flags & FLAG_HAS_ICON_LOCATION:
            self.metadata["string_data"]["icon_location"] = self._read_string_data(is_unicode)

        # 5. ExtraData Blocks (0 or more blocks terminated by block_size < 4)
        self._parse_extra_data()

        # 6. Perform Forensic Security & Spoofing Risk Assessment
        self._evaluate_risk()

        return self.metadata

    def _parse_header(self) -> None:
        """Parses the 76-byte ShellLinkHeader."""
        hdr_size, clsid = struct.unpack_from("<I16s", self.raw_bytes, 0)
        if hdr_size != 76 or clsid != EXPECTED_CLSID:
            self.metadata["error"] = f"Invalid LNK HeaderSize ({hdr_size} != 76) or CLSID mismatch"
            return

        flags, file_attrs, ctime, atime, wtime, file_len, icon_idx, show_cmd, hotkey, res1, res2, res3 = struct.unpack_from(
            "<IIQQQIIIHHII", self.raw_bytes, 20
        )

        self.metadata["is_valid_header"] = True
        self.metadata["header"] = {
            "header_size": hdr_size,
            "link_flags_int": flags,
            "link_flags_active": self._decode_flags(flags),
            "file_attributes_int": file_attrs,
            "creation_time": filetime_to_iso(ctime),
            "access_time": filetime_to_iso(atime),
            "write_time": filetime_to_iso(wtime),
            "target_file_size": file_len,
            "icon_index": icon_idx,
            "show_command": SHOW_COMMAND_MAP.get(show_cmd, f"SW_UNKNOWN ({show_cmd})"),
            "hotkey": hotkey
        }
        self.offset = 76

    def _decode_flags(self, flags: int) -> List[str]:
        """Translates active bit flags into human-readable labels."""
        active = []
        mapping = {
            FLAG_HAS_TARGET_ID_LIST: "HasLinkTargetIDList",
            FLAG_HAS_LINK_INFO: "HasLinkInfo",
            FLAG_HAS_NAME: "HasName",
            FLAG_HAS_RELATIVE_PATH: "HasRelativePath",
            FLAG_HAS_WORKING_DIR: "HasWorkingDir",
            FLAG_HAS_ARGUMENTS: "HasArguments",
            FLAG_HAS_ICON_LOCATION: "HasIconLocation",
            FLAG_IS_UNICODE: "IsUnicode",
            FLAG_FORCE_NO_LINK_INFO: "ForceNoLinkInfo",
            FLAG_HAS_EXP_STRING: "HasExpString",
            FLAG_RUN_IN_SEPARATE: "RunInSeparateProcess",
            FLAG_RUN_AS_USER: "RunAsUser",
            FLAG_HAS_EXP_ICON: "HasExpIcon"
        }
        for bit, name in mapping.items():
            if flags & bit:
                active.append(name)
        return active

    def _parse_target_id_list(self) -> None:
        """Parses the LinkTargetIDList structure."""
        if self.offset + 2 > self.file_size:
            return
        id_list_size = struct.unpack_from("<H", self.raw_bytes, self.offset)[0]
        self.metadata["target_id_list"] = {
            "id_list_size": id_list_size,
            "raw_offset": self.offset + 2
        }
        self.offset += 2 + id_list_size

    def _parse_link_info(self) -> None:
        """Parses the LinkInfo structure containing local/network base paths."""
        if self.offset + 4 > self.file_size:
            return
        link_info_size = struct.unpack_from("<I", self.raw_bytes, self.offset)[0]
        if link_info_size < 28 or self.offset + link_info_size > self.file_size:
            self.offset += max(4, link_info_size)
            return

        header_size, flags, local_base_path_offset, cnr_offset, common_path_suffix_offset = struct.unpack_from(
            "<IIIII", self.raw_bytes, self.offset + 4
        )

        local_path = None
        if local_base_path_offset and (self.offset + local_base_path_offset < self.file_size):
            str_start = self.offset + local_base_path_offset
            null_pos = self.raw_bytes.find(b"\x00", str_start)
            if null_pos != -1:
                local_path = self.raw_bytes[str_start:null_pos].decode("cp1252", errors="ignore")

        self.metadata["link_info"] = {
            "link_info_size": link_info_size,
            "local_base_path": local_path
        }
        self.offset += link_info_size

    def _read_string_data(self, is_unicode: bool) -> Optional[str]:
        """Reads a StringData block prefixed with a 16-bit character count."""
        if self.offset + 2 > self.file_size:
            return None
        char_count = struct.unpack_from("<H", self.raw_bytes, self.offset)[0]
        self.offset += 2

        if is_unicode:
            byte_len = char_count * 2
            if self.offset + byte_len > self.file_size:
                return None
            res = self.raw_bytes[self.offset:self.offset + byte_len].decode("utf-16le", errors="ignore")
            self.offset += byte_len
            return res
        else:
            if self.offset + char_count > self.file_size:
                return None
            res = self.raw_bytes[self.offset:self.offset + char_count].decode("cp1252", errors="ignore")
            self.offset += char_count
            return res

    def _parse_extra_data(self) -> None:
        """Parses optional ExtraData blocks (Tracker, PropertyStore, EnvironmentVariable, etc.)."""
        while self.offset + 4 <= self.file_size:
            block_size = struct.unpack_from("<I", self.raw_bytes, self.offset)[0]
            if block_size < 4:
                break
            if self.offset + block_size > self.file_size:
                break

            sig = struct.unpack_from("<I", self.raw_bytes, self.offset + 4)[0]
            block_info = {"block_size": block_size, "signature": f"0x{sig:08X}"}

            # EnvironmentVariableDataBlock (0xA0000001)
            if sig == 0xA0000001:
                block_info["type"] = "EnvironmentVariableDataBlock"
                target_ansi = self.raw_bytes[self.offset + 8:self.offset + 8 + 260].split(b"\x00")[0].decode("cp1252", errors="ignore")
                block_info["target_ansi"] = target_ansi
            # TrackerDataBlock (0xA0000003)
            elif sig == 0xA0000003:
                block_info["type"] = "TrackerDataBlock"
                machine_id = self.raw_bytes[self.offset + 16:self.offset + 16 + 16].split(b"\x00")[0].decode("ascii", errors="ignore")
                block_info["machine_id"] = machine_id
            # VistaAndAboveIDListDataBlock (0xA000000C)
            elif sig == 0xA000000C:
                block_info["type"] = "VistaAndAboveIDListDataBlock"
            else:
                block_info["type"] = "UnknownExtraDataBlock"

            self.metadata["extra_data_blocks"].append(block_info)
            self.offset += block_size

    def _evaluate_risk(self) -> None:
        """Evaluates interface masquerading, Chromium --app abuse, and defense evasion indicators."""
        args = self.metadata["string_data"].get("command_line_arguments") or ""
        icon = self.metadata["string_data"].get("icon_location") or ""
        local_path = (self.metadata.get("link_info") or {}).get("local_base_path") or ""

        # Search inside entire raw bytes for args if StringData was obscured
        combined_text = (args + " " + local_path).lower()
        if not args:
            # Fallback raw search in binary for arguments
            import re
            m = re.search(r'--app=[^\s"]+', self.raw_bytes.decode("latin-1", errors="ignore"))
            if m:
                args = m.group(0)
                combined_text += " " + args.lower()

        indicators = []
        score = 0

        # Check for Chromium --app spoofing
        if "--app=" in combined_text:
            score += 45
            indicators.append("CHROMIUM_APP_MODE_DETECTED: Invokes browser with --app flag to eliminate address bar & tabs")

        # Check for incognito isolation evasion
        if "-incognito" in combined_text or "--incognito" in combined_text or "--inprivate" in combined_text:
            score += 20
            indicators.append("INCOGNITO_PROFILE_EVASION: Forces clean browser profile to defeat existing auth & cookie caches")

        # Check for local file execution in app mode
        if "--app=c:" in combined_text or "--app=file:" in combined_text or ".html" in combined_text or ".htm" in combined_text:
            score += 25
            indicators.append("LOCAL_HTML_APP_LOAD: Launches local HTML file disguised as native desktop application")

        # Check for remote URL in app mode
        if "--app=http" in combined_text:
            score += 20
            indicators.append("REMOTE_URL_APP_LOAD: Directly frames remote authentication page without browser chrome")

        # Check for Icon Masquerading
        icon_lower = icon.lower()
        spoofed_apps = ["teams", "office", "onedrive", "outlook", "excel", "word", "zoom", "slack", "chrome"]
        for sa in spoofed_apps:
            if sa in icon_lower and ("brave" in combined_text or "chrome" in combined_text or "msedge" in combined_text):
                score += 30
                indicators.append(f"ICON_MASQUERADING: Target browser executable masquerades under '{sa}' application icon")
                break

        # Check for hidden/minimized execution
        show_cmd = self.metadata["header"].get("show_command", "")
        if "SW_SHOWMINNOACTIVE" in show_cmd:
            score += 15
            indicators.append("STEALTH_SHOW_WINDOW: Shortcut configured to launch minimized or hidden")

        self.metadata["risk_assessment"] = {
            "risk_score": min(100, score),
            "threat_level": "CRITICAL" if score >= 60 else "HIGH" if score >= 40 else "MEDIUM" if score >= 20 else "LOW",
            "indicators": indicators,
            "extracted_app_parameter": self._extract_app_param(args)
        }

    def _extract_app_param(self, args: str) -> Optional[str]:
        """Extracts the exact target URL or file path passed to --app=."""
        import re
        match = re.search(r'--app=([^\s"]+)', args)
        if match:
            return match.group(1)
        return None
