<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 中文</a> · <a href="./es.md">🇪🇸 Español</a> · <a href="./hi.md">🇮🇳 हिन्दी</a><br />
  <a href="./ar.md">🇸🇦 العربية</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./fr.md">🇫🇷 Français</a> · <a href="./id.md">🇮🇩 Bahasa Indonesia</a>
</p>

<p align="center">
  <a href="https://github.com/maya-thorne/chromium-app-spoofing-forensics"><img src="../assets/locales/ar/banner.svg" alt="chromium-app-spoofing-forensics banner" width="100%" /></a>
</p>

# 🛡️ chromium-app-spoofing-forensics

**هندسة كشف EDR/SIEM للفرق الزرقاء، 52 قاعدة Sigma، 32 توقيع YARA، تحليل [MS-SHLLINK] وتدقيق النوافذ**

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

## 📌 نظرة عامة والسياق التقني

يقوم وضع التطبيقات (`--app`) في متصفحات Chromium بإزالة شريط العناوين (Omnibox) وعلامات التبويب ومؤشرات أمان المتصفح تماماً.

يستغل المهاجمون اختصارات Windows (`.lnk`) المتخفية بأيقونات برامج مشروعة لتشغيل صفحات تصيد. يقدم هذا المستودع قواعد كشف متكاملة للفرق الزرقاء.

---

## 🏛️ المعمارية التقنية وطوبولوجيا التحليل

<p align="center">
  <a href="https://github.com/maya-thorne/chromium-app-spoofing-forensics"><img src="../assets/locales/ar/architecture.svg" alt="architecture diagram" width="100%" /></a>
</p>

---

## 🏗️ مسار كشف EDR و SIEM للفرق الزرقاء

<p align="center">
  <a href="https://github.com/maya-thorne/chromium-app-spoofing-forensics"><img src="../assets/locales/ar/detection_pipeline.svg" alt="detection pipeline" width="100%" /></a>
</p>

---

## 💻 عرض توضيحي لطرفية التحليل الجنائي

<p align="center">
  <img src="../assets/demo_casf_terminal.svg" alt="Terminal Demo" width="100%" />
</p>

---

## 📚 فهرس الأوراق البحثية والتقارير التقنية

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

## ⚡ تشغيل أداة الفحص الجنائي عبر سطر الأوامر

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
