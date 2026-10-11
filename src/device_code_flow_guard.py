#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
device_code_flow_guard.py - OAuth Device Code Flow & AiTM Artifact Forensic Guard
Part of chromium-app-spoofing-forensics suite
Zero-dependency static detection engine for RFC 8628 abuse & AiTM session interception.
"""

from __future__ import annotations

import re
from typing import Dict, Any, List


DEVICE_LOGIN_PATTERNS = [
    r'microsoft\.com/devicelogin',
    r'microsoft\.com/link',
    r'google\.com/device',
    r'device\.login',
    r'devicelogin'
]

DEVICE_CODE_REGEX = r'\b[A-Z0-9]{4}-[A-Z0-9]{4,5}\b'

AITM_COOKIE_PATTERNS = [
    r'ESTSAUTH',
    r'ESTSAUTHPERSISTENT',
    r'SignInStateCookie',
    r'x-ms-gateway-slice',
    r'buid'
]

FAKE_ADDRESS_BAR_SELECTORS = [
    r'fake-address-bar',
    r'address-bar-mock',
    r'omnibox-mimic',
    r'custom-titlebar',
    r'window-drag-region'
]


class DeviceCodeFlowGuard:
    """Analyzes HTML, scripts, and network artifacts for Device Code Flow & AiTM phishing indicators."""

    def __init__(self) -> None:
        pass

    def inspect_html_or_script(self, content: str, source_name: str = "in_memory_content") -> Dict[str, Any]:
        """Performs static signature and heuristic analysis on an HTML/JS payload."""
        findings: List[Dict[str, Any]] = []
        risk_score = 0

        # 1. Inspect for Device Code Flow Indicators
        for pattern in DEVICE_LOGIN_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                risk_score += 40
                findings.append({
                    "rule_id": "DCF-GUARD-001",
                    "severity": "CRITICAL",
                    "tag": "OAUTH_DEVICE_CODE_FLOW_URL",
                    "description": f"Detected OAuth 2.0 Device Authorization endpoint: {pattern}",
                    "detail": "Adversary abuses RFC 8628 to bypass MFA/FIDO2 keys by redirecting victim to legitimate devicelogin."
                })
                break

        # Check for extracted device code string
        code_match = re.search(DEVICE_CODE_REGEX, content)
        if code_match:
            risk_score += 25
            findings.append({
                "rule_id": "DCF-GUARD-002",
                "severity": "HIGH",
                "tag": "DEVICE_USER_CODE_STRING",
                "description": f"Detected pre-rendered OAuth user code: {code_match.group(0)}",
                "detail": "Prompts victim to approve an attacker-initiated OAuth device flow session."
            })

        # 2. Inspect for Fake Address Bar CSS/DOM Elements
        for selector in FAKE_ADDRESS_BAR_SELECTORS:
            if re.search(selector, content, re.IGNORECASE):
                risk_score += 35
                findings.append({
                    "rule_id": "DCF-GUARD-003",
                    "severity": "CRITICAL",
                    "tag": "SYNTHETIC_ADDRESS_BAR_DOM",
                    "description": f"Identified synthetic address bar element: '{selector}'",
                    "detail": "Renders CSS fake lock icon and URL bar inside app viewport to deceive victim."
                })
                break

        # 3. Inspect for AiTM Session Cookie Harvesters
        harvested_cookies = []
        for cookie_pat in AITM_COOKIE_PATTERNS:
            if re.search(cookie_pat, content, re.IGNORECASE):
                harvested_cookies.append(cookie_pat)

        if harvested_cookies:
            risk_score += 45
            findings.append({
                "rule_id": "DCF-GUARD-004",
                "severity": "CRITICAL",
                "tag": "AITM_SESSION_COOKIE_EXFILTRATION",
                "description": f"Detected Azure AD/Office 365 session cookie references: {harvested_cookies}",
                "detail": "High correlation with Evilginx3/Modlishka reverse-proxy token interception scripts."
            })

        final_score = min(100, risk_score)
        threat_level = "CRITICAL" if final_score >= 60 else "HIGH" if final_score >= 40 else "MEDIUM" if final_score >= 20 else "CLEAN"

        return {
            "source_name": source_name,
            "risk_score": final_score,
            "threat_level": threat_level,
            "findings_count": len(findings),
            "findings": findings
        }
