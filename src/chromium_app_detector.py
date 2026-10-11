#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
chromium_app_detector.py - Chromium Application Mode & Interface Masquerading Detection Engine
Part of chromium-app-spoofing-forensics suite
Zero-dependency static detection engine for process command lines & telemetry feeds.
"""

from __future__ import annotations

import re
from typing import Dict, Any, List, Optional


CHROMIUM_EXECUTABLES = {
    "chrome.exe", "msedge.exe", "brave.exe", "opera.exe", "vivaldi.exe",
    "chromium.exe", "centbrowser.exe", "whale.exe", "thorium.exe"
}

LOGIN_MODAL_DIMENSIONS = [
    (440, 520),  # Microsoft Account Login Modal
    (480, 640),  # Teams / Azure AD Prompt
    (500, 600),  # Google OAuth Dialog
    (450, 550)   # Okta / Duo SSO Dialog
]


class ChromiumAppDetector:
    """Analyzes process execution telemetry for browser-based interface masquerading."""

    def __init__(self) -> None:
        pass

    def analyze_command_line(self, command_line: str, image_path: Optional[str] = None, parent_image: Optional[str] = None) -> Dict[str, Any]:
        """Performs multi-vector telemetry inspection on a process creation event."""
        norm_cli = command_line.strip()
        cli_lower = norm_cli.lower()

        is_browser = False
        target_browser = "unknown"
        if image_path:
            img_base = image_path.lower().replace("/", "\\").split("\\")[-1]
            if img_base in CHROMIUM_EXECUTABLES:
                is_browser = True
                target_browser = img_base
        else:
            for b in CHROMIUM_EXECUTABLES:
                if b in cli_lower:
                    is_browser = True
                    target_browser = b
                    break

        findings: List[Dict[str, Any]] = []
        risk_score = 0

        # 1. Inspect --app Flag
        app_match = re.search(r'--app=(["\']?)([^"\'\s]+)\1', norm_cli, re.IGNORECASE)
        app_target = None
        if app_match:
            app_target = app_match.group(2)
            risk_score += 40
            findings.append({
                "rule_id": "CASF-EVASION-001",
                "severity": "HIGH",
                "tag": "CHROMIUM_APP_MODE_INVOCATION",
                "description": f"Browser started in standalone app mode: --app={app_target}",
                "detail": "Eliminates omnibox, tab strip, bookmark bar, and security indicators."
            })

            # Check if target is a local file
            if re.match(r'^(?:[a-zA-Z]:|file:|\\\\|\.)', app_target, re.IGNORECASE) or app_target.lower().endswith(('.html', '.htm')):
                risk_score += 30
                findings.append({
                    "rule_id": "CASF-EVASION-002",
                    "severity": "CRITICAL",
                    "tag": "LOCAL_FILE_APP_HOSTING",
                    "description": f"Target of --app is a local or network file: {app_target}",
                    "detail": "High correlation with phishing HTML dropped locally or accessed via UNC share."
                })
            elif app_target.lower().startswith(('http://', 'https://')):
                risk_score += 15
                findings.append({
                    "rule_id": "CASF-EVASION-003",
                    "severity": "MEDIUM",
                    "tag": "REMOTE_ENDPOINT_APP_HOSTING",
                    "description": f"Target of --app is a remote URL: {app_target}",
                    "detail": "Directly renders remote portal without browser security controls."
                })

        # 2. Inspect Incognito / InPrivate Flag
        incognito_match = re.search(r'-(?:-)?(?:incognito|inprivate)', cli_lower)
        if incognito_match:
            risk_score += 20
            findings.append({
                "rule_id": "CASF-EVASION-004",
                "severity": "HIGH",
                "tag": "INCOGNITO_CREDENTIAL_ISOLATION",
                "description": "Browser launched with incognito/inprivate session isolation.",
                "detail": "Prevents existing authentication state from loading, forcing victim to input credentials."
            })

        # 3. Inspect Window Dimensions (Login Modal Spoofing)
        size_match = re.search(r'--window-size=(\d+),(\d+)', cli_lower)
        if size_match:
            w, h = int(size_match.group(1)), int(size_match.group(2))
            is_modal_ratio = False
            for mw, mh in LOGIN_MODAL_DIMENSIONS:
                if abs(w - mw) <= 30 and abs(h - mh) <= 30:
                    is_modal_ratio = True
                    break
            if is_modal_ratio:
                risk_score += 25
                findings.append({
                    "rule_id": "CASF-MASQUERADE-001",
                    "severity": "HIGH",
                    "tag": "LOGIN_MODAL_DIMENSION_MIMICRY",
                    "description": f"Window size ({w}x{h}) specifically mimics cloud identity login dialogs.",
                    "detail": "Engineered to match Microsoft/Google authentication popup dimensions precisely."
                })

        # 4. Inspect Kiosk Mode or Fullscreen Manipulation
        if "--kiosk" in cli_lower or "--start-fullscreen" in cli_lower:
            risk_score += 35
            findings.append({
                "rule_id": "CASF-EVASION-005",
                "severity": "CRITICAL",
                "tag": "KIOSK_DESKTOP_HIJACK",
                "description": "Browser initiated in kiosk mode (full screen borderless takeover).",
                "detail": "Restricts victim desktop navigation and forces full-screen interface trap."
            })

        # 5. Inspect User Data Directory Redirection
        if "--user-data-dir=" in cli_lower:
            risk_score += 15
            findings.append({
                "rule_id": "CASF-EVASION-006",
                "severity": "MEDIUM",
                "tag": "EPHEMERAL_PROFILE_ISOLATION",
                "description": "Custom user-data-dir specified, bypassing default browser defenses and extensions.",
                "detail": "Ensures defensive password managers and web-filtering extensions are absent."
            })

        # 6. Inspect Parent Process Hierarchy Anomalies
        if parent_image:
            p_base = parent_image.lower().replace("/", "\\").split("\\")[-1]
            suspicious_parents = ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"]
            if p_base in suspicious_parents:
                risk_score += 25
                findings.append({
                    "rule_id": "CASF-EXEC-001",
                    "severity": "HIGH",
                    "tag": "SUSPICIOUS_SCRIPT_PARENT_HIERARCHY",
                    "description": f"Chromium process spawned by scripting interpreter: {p_base}",
                    "detail": "Standard desktop app launches originate from explorer.exe or taskbar."
                })

        # Calculate Overall Classification
        final_score = min(100, risk_score)
        threat_level = "CRITICAL" if final_score >= 65 else "HIGH" if final_score >= 45 else "MEDIUM" if final_score >= 25 else "LOW"

        return {
            "target_browser": target_browser,
            "is_browser_execution": is_browser,
            "app_target": app_target,
            "risk_score": final_score,
            "threat_level": threat_level,
            "findings_count": len(findings),
            "findings": findings
        }
