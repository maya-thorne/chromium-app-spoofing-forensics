<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 中文</a> · <a href="./es.md">🇪🇸 Español</a> · <a href="./hi.md">🇮🇳 हिन्दी</a><br />
  <a href="./ar.md">🇸🇦 العربية</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./fr.md">🇫🇷 Français</a> · <a href="./id.md">🇮🇩 Bahasa Indonesia</a>
</p>

<p align="center">
  <a href="https://github.com/maya-thorne/chromium-app-spoofing-forensics"><img src="../assets/locales/ko/banner.svg" alt="chromium-app-spoofing-forensics banner" width="100%" /></a>
</p>

# 🛡️ chromium-app-spoofing-forensics

**블루팀 EDR/SIEM 탐지 엔지니어링, 52개 Sigma 룰, 32개 YARA 시그니처, [MS-SHLLINK] 바이너리 카빙 및 윈도우 클래스 위장 감사 프레임워크**

[![Release](https://img.shields.io/github/v/release/maya-thorne/chromium-app-spoofing-forensics?color=10b981)](https://github.com/maya-thorne/chromium-app-spoofing-forensics/releases/latest)
[![Sigma Rules](https://img.shields.io/badge/Sigma_Rules-52_Modular-f59e0b.svg)](../../rules/sigma)
[![YARA Rules](https://img.shields.io/badge/YARA_Rules-32_Signatures-10b981.svg)](../../rules/yara)
[![SIEM Feeds](https://img.shields.io/badge/SIEM-Splunk_%26_Elastic-38bdf8.svg)](../../rules/siem_queries)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-Enterprise_Matrix-818cf8.svg)](../MITRE_ATTACK_DEFENSE_MATRIX.md)
[![Tests](https://img.shields.io/badge/Tests-100%25_Passing-10b981.svg)](../../tests)
[![License: MT-SRL](https://img.shields.io/badge/License-MT--SRL-blue.svg)](../../LICENSE)

<sub>Engineered &amp; Audited by **[Maya Thorne](https://github.com/maya-thorne)** · Systems &amp; Detection Engineering Research</sub>

</div>

---

## 📌 개요 및 기술 배경

크로미움(Chromium) 기반 브라우저(Chrome, Brave, Edge 등)의 애플리케이션 모드(`--app`)는 본래 프로그레시브 웹 앱(PWA) 지원을 위해 개발된 공식 기능입니다. 그러나 이 모드가 활성화되면 Omnibox(주소창), 탭 표시줄, 확장 프로그램 아이콘 및 SSL 인증서 자물쇠 등 브라우저 보안 경계선이 100% 제거됩니다.

공격자는 바로가기 파일(`.lnk`)의 아이콘을 Microsoft Teams, OneDrive, Outlook 등으로 위장하고 대상 인자에 `--app=`와 `-incognito`를 주입하여, 사용자가 네이티브 데스크톱 프로그램을 실행한 것으로 오인하게 만듭니다. 본 저장소는 엔터프라이즈 SOC/EDR 블루팀을 위한 포렌식 분석 및 탐지 엔지니어링 룰셋을 제공합니다.

---

## 🏛️ 시스템 아키텍처 및 분석 토폴로지

<p align="center">
  <a href="https://github.com/maya-thorne/chromium-app-spoofing-forensics"><img src="../assets/locales/ko/architecture.svg" alt="architecture diagram" width="100%" /></a>
</p>

---

## 🏗️ 블루팀 EDR/SIEM 탐지 파이프라인

<p align="center">
  <a href="https://github.com/maya-thorne/chromium-app-spoofing-forensics"><img src="../assets/locales/ko/detection_pipeline.svg" alt="detection pipeline" width="100%" /></a>
</p>

---

## 💻 대화형 포렌식 터미널 시연

<p align="center">
  <img src="../assets/demo_casf_terminal.svg" alt="Terminal Demo" width="100%" />
</p>

---

## 📚 핵심 역공학 백서 및 연구 보고서 색인

<details open>
<summary><b>📚 View 4 Core Architecture &amp; Forensic Whitepapers</b></summary>
<br>

<table width="100%">
  <thead>
    <tr>
      <th width="32%">Whitepaper / Artifact</th>
      <th width="68%">Technical Scope &amp; Target Systems</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>
        🔬 <strong><a href="../whitepapers/01_CHROMIUM_APP_MODE_INTERFACE_SPOOFING.md">01_CHROMIUM_APP_MODE_INTERFACE_SPOOFING.md</a></strong>
      </td>
      <td>
        Chromium <code>--app</code> architecture, Omnibox stripping mechanics, <code>-incognito</code> session cache evasion, and modal window geometry mimicry.
      </td>
    </tr>
    <tr>
      <td>
        🔬 <strong><a href="../whitepapers/02_LNK_BINARY_EXTRACTION_AND_FORENSICS.md">02_LNK_BINARY_EXTRACTION_AND_FORENSICS.md</a></strong>
      </td>
      <td>
        <code>[MS-SHLLINK]</code> binary format specifications, LinkFlags dissection, ExtraData block carving, and IconLocation masquerading.
      </td>
    </tr>
    <tr>
      <td>
        🔬 <strong><a href="../whitepapers/03_NATIVE_WRAPPER_AND_AITM_CONVERGENCE.md">03_NATIVE_WRAPPER_AND_AITM_CONVERGENCE.md</a></strong>
      </td>
      <td>
        Microsoft Edge WebView2 C# wrappers, RFC 8628 OAuth Device Code Flow abuse, and Evilginx3/Modlishka AiTM reverse-proxy session cookie interception.
      </td>
    </tr>
    <tr>
      <td>
        🔬 <strong><a href="../whitepapers/04_EDR_TELEMETRY_AND_DEFENSE_ARCHITECTURE.md">04_EDR_TELEMETRY_AND_DEFENSE_ARCHITECTURE.md</a></strong>
      </td>
      <td>
        Sysmon Event ID 1 &amp; 4688 correlation, Win32 window hierarchy auditing (Chrome_WidgetWin_1 vs TeamsWebView), and FIDO2 cryptographic origin binding.
      </td>
    </tr>
  </tbody>
</table>
</details>

---

## ⚡ 초고속 CLI 포렌식 도구체인 실행

<details open>
<summary><b>⚡ View CLI Execution Commands &amp; Inspection Options</b></summary>
<br>

```bash
# Analyze Windows Shortcut (.lnk) artifact
python -m src.cli --lnk "references/poc_shortcuts/01_brave_app_youtube_incognito.lnk"

# Inspect process creation command line for --app evasion
python -m src.cli --cli "brave.exe --app=C:\Users\user\Desktop\1.html -incognito"

# Output structured JSON for SIEM / SOAR pipeline ingestion
python -m src.cli --lnk "references/poc_shortcuts/03_brave_app_local_html_incognito.lnk" --json
```
</details>

---

<div align="center">
  <sub>All materials licensed under the <strong><a href="../../LICENSE">Maya Thorne Systems &amp; Security Research License (MT-SRL)</a></strong>.</sub>
</div>
