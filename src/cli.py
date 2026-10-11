#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cli.py - Unified Forensic Triage & Masquerading Detection CLI
Part of chromium-app-spoofing-forensics suite
Zero-dependency static triage and analysis interface.
"""

from __future__ import annotations

import os
import sys
import json
import argparse
from typing import Dict, Any

from lnk_forensics_parser import LNKForensicsParser
from chromium_app_detector import ChromiumAppDetector
from window_hierarchy_auditor import WindowHierarchyAuditor
from device_code_flow_guard import DeviceCodeFlowGuard


# Enforce UTF-8 output encoding across Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


BANNER = """
╔══════════════════════════════════════════════════════════════════════════╗
║   CHROMIUM APP SPOOFING & INTERFACE MASQUERADING FORENSIC SUITE (CASF)  ║
║   Blue Team EDR/SIEM Analysis · LNK Carving · Window Hierarchy Auditor   ║
║   Engineered & Audited by Maya Thorne · Systems & Security Research      ║
╚══════════════════════════════════════════════════════════════════════════╝
"""


def format_risk_badge(level: str, score: int) -> str:
    color_map = {
        "CRITICAL": "\033[91m",  # Red
        "HIGH": "\033[93m",      # Yellow
        "MEDIUM": "\033[96m",    # Cyan
        "LOW": "\033[92m",       # Green
        "CLEAN": "\033[92m"      # Green
    }
    reset = "\033[0m"
    color = color_map.get(level, "")
    return f"{color}[{level} - Score: {score}/100]{reset}"


def analyze_lnk_file(filepath: str, json_output: bool = False) -> Dict[str, Any]:
    with open(filepath, "rb") as f:
        raw_bytes = f.read()

    parser = LNKForensicsParser(raw_bytes, filename=os.path.basename(filepath))
    report = parser.parse()

    if json_output:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return report

    print(f"\n📂 LNK Forensic Analysis: {os.path.basename(filepath)} ({len(raw_bytes):,} bytes)")
    print("─" * 70)
    hdr = report.get("header", {})
    print(f"  • Link Flags: {', '.join(hdr.get('link_flags_active', []))}")
    print(f"  • Timestamps: Created={hdr.get('creation_time')} | Written={hdr.get('write_time')}")
    print(f"  • Window Mode: {hdr.get('show_command')}")

    str_data = report.get("string_data", {})
    if str_data.get("command_line_arguments"):
        print(f"  • Target Arguments: {str_data.get('command_line_arguments')}")
    if str_data.get("icon_location"):
        print(f"  • Icon Location: {str_data.get('icon_location')}")

    risk = report.get("risk_assessment", {})
    print(f"\n  🎯 Threat Assessment: {format_risk_badge(risk.get('threat_level', 'LOW'), risk.get('risk_score', 0))}")
    for ind in risk.get("indicators", []):
        print(f"     [!] {ind}")

    return report


def analyze_cli_string(cmd_line: str, parent: str = "", json_output: bool = False) -> Dict[str, Any]:
    detector = ChromiumAppDetector()
    report = detector.analyze_command_line(cmd_line, parent_image=parent if parent else None)

    if json_output:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return report

    print(f"\n⚡ Telemetry CommandLine Analysis")
    print("─" * 70)
    print(f"  • Command Line: {cmd_line}")
    if parent:
        print(f"  • Parent Image: {parent}")
    print(f"  • Target Browser: {report.get('target_browser')}")
    if report.get("app_target"):
        print(f"  • Target App Endpoint: {report.get('app_target')}")

    print(f"\n  🎯 Threat Assessment: {format_risk_badge(report.get('threat_level', 'LOW'), report.get('risk_score', 0))}")
    for f in report.get("findings", []):
        print(f"     [!] [{f['rule_id']}] {f['tag']}: {f['description']}")

    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Chromium App Spoofing Forensics & EDR Telemetry Detection Engine"
    )
    parser.add_argument("--lnk", "-l", help="Path to Windows Shortcut (.lnk) file to analyze")
    parser.add_argument("--cli", "-c", help="Process command line string to inspect for --app evasion")
    parser.add_argument("--parent", "-p", help="Parent process image name (e.g. explorer.exe, powershell.exe)")
    parser.add_argument("--html", "-w", help="Path to HTML/JS file to inspect for fake-address-bar / Device Flow")
    parser.add_argument("--json", "-j", action="store_true", help="Output results in JSON format")

    args = parser.parse_args()

    if not args.json:
        print(BANNER)

    if args.lnk:
        analyze_lnk_file(args.lnk, json_output=args.json)
    elif args.cli:
        analyze_cli_string(args.cli, parent=args.parent or "", json_output=args.json)
    elif args.html:
        with open(args.html, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        guard = DeviceCodeFlowGuard()
        report = guard.inspect_html_or_script(content, source_name=os.path.basename(args.html))
        if args.json:
            print(json.dumps(report, indent=2, ensure_ascii=False))
        else:
            print(f"\n🌐 DOM & Protocol Guard Analysis: {os.path.basename(args.html)}")
            print("─" * 70)
            print(f"  🎯 Threat Assessment: {format_risk_badge(report.get('threat_level', 'LOW'), report.get('risk_score', 0))}")
            for f in report.get("findings", []):
                print(f"     [!] [{f['rule_id']}] {f['tag']}: {f['description']}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
