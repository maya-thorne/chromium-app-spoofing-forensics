#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
window_hierarchy_auditor.py - Win32 Window Hierarchy & Class-Process Mismatch Auditor
Part of chromium-app-spoofing-forensics suite
Zero-dependency static detection engine for GUI window masquerading & class spoofing.
"""

from __future__ import annotations

import re
from typing import Dict, Any, List, Optional


LEGITIMATE_TITLE_APP_MAP = {
    "teams": ["teams.exe", "ms-teams.exe", "update.exe"],
    "microsoft teams": ["teams.exe", "ms-teams.exe"],
    "outlook": ["outlook.exe"],
    "onedrive": ["onedrive.exe"],
    "word": ["winword.exe"],
    "excel": ["excel.exe"],
    "zoom": ["zoom.exe"],
    "slack": ["slack.exe"]
}


class WindowHierarchyAuditor:
    """Audits desktop top-level windows for window title and owning process mismatches."""

    def __init__(self) -> None:
        pass

    def audit_window_record(
        self,
        window_title: str,
        window_class: str,
        process_name: str,
        process_path: Optional[str] = None,
        is_visible: bool = True
    ) -> Dict[str, Any]:
        """Audits an individual window descriptor for interface masquerading indicators."""
        title_norm = window_title.strip()
        title_lower = title_norm.lower()
        proc_lower = process_name.strip().lower()
        class_lower = window_class.strip().lower()

        violations: List[Dict[str, Any]] = []
        risk_score = 0

        # 1. Detect Masquerading Title vs Browser Host Mismatch
        matched_category = None
        for category, allowed_procs in LEGITIMATE_TITLE_APP_MAP.items():
            if category in title_lower:
                matched_category = category
                # If window title claims to be Teams/Outlook, but process is a generic browser
                if proc_lower in {"chrome.exe", "brave.exe", "msedge.exe", "opera.exe"}:
                    risk_score += 50
                    violations.append({
                        "rule_id": "WH-AUDIT-001",
                        "severity": "CRITICAL",
                        "tag": "WINDOW_TITLE_BROWSER_MISMATCH",
                        "description": f"Window claims '{title_norm}' identity but is hosted by browser process '{process_name}'.",
                        "detail": f"Legitimate process expected: {allowed_procs}, Actual: {process_name}"
                    })
                break

        # 2. Detect WinForms/WPF Native Wrapper Spoofing
        if "windowsforms10" in class_lower or "hwndwrapper" in class_lower:
            if matched_category:
                # C# wrapper hosting legitimate-looking title from suspicious paths
                path_lower = (process_path or "").lower()
                if any(sp in path_lower for sp in ["\\temp\\", "\\appdata\\local\\temp", "\\downloads\\"]):
                    risk_score += 45
                    violations.append({
                        "rule_id": "WH-AUDIT-002",
                        "severity": "HIGH",
                        "tag": "UNVERIFIED_WRAPPER_LOCATION",
                        "description": f"Native .NET/WPF wrapper window hosted from temporary directory: {process_path}",
                        "detail": "High correlation with lightweight WebView2 phishing containers."
                    })

        # 3. Detect Chrome Widget Win masquerading with no browser chrome
        if class_lower == "chrome_widgetwin_1":
            if matched_category and proc_lower in {"chrome.exe", "brave.exe", "msedge.exe"}:
                risk_score += 20
                violations.append({
                    "rule_id": "WH-AUDIT-003",
                    "severity": "HIGH",
                    "tag": "CHROME_WIDGET_MODAL_TRAP",
                    "description": "Chrome_WidgetWin_1 class window masquerading as enterprise desktop app.",
                    "detail": "Standard Chromium widget frame rendered without native navigation UI."
                })

        final_score = min(100, risk_score)
        threat_level = "CRITICAL" if final_score >= 60 else "HIGH" if final_score >= 40 else "MEDIUM" if final_score >= 20 else "CLEAN"

        return {
            "window_title": window_title,
            "window_class": window_class,
            "process_name": process_name,
            "process_path": process_path,
            "is_visible": is_visible,
            "claimed_identity": matched_category,
            "risk_score": final_score,
            "threat_level": threat_level,
            "violations_count": len(violations),
            "violations": violations
        }
