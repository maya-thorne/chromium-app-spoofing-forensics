# 🔬 Chromium `--app` Mode Interface Spoofing & Evasion Mechanics
**Whitepaper CASF-WP-01 · Systems & Security Research**
*Authored by Maya Thorne · Published October 2026*

---

## 1. Executive Summary

Chromium-based web browsers (Google Chrome, Microsoft Edge, Brave, Opera, Vivaldi) incorporate a dedicated command-line parameter: `--app=<URL|Path>`. While designed to facilitate Progressive Web Applications (PWAs) by providing a chromeless desktop viewport, this feature inherently strips away critical browser security boundary indicators—including the Omnibox (address bar), SSL padlock certificate badges, extension icons, and tab strips. 

This paper presents an exhaustive architectural analysis of how adversary infrastructure and interface spoofing vectors weaponize the `--app` runtime flag to deceive users into perceiving web-hosted authentication dialogs as native operating system software.

---

## 2. Browser Chrome Stripping Architecture

When launched normally, a Chromium browser instance initializes a complex top-level window hierarchy composed of the TabStrip, ToolbarView, LocationBarView (Omnibox), and BookmarksBarView.

```
Standard Navigation Window
┌─────────────────────────────────────────────────────────────────┐
│ [Tab 1: Inbox] [Tab 2: Portal] [+]                      [-] [x] │  TabStrip
├─────────────────────────────────────────────────────────────────┤
│ [←] [→] [↻]  🔒 https://login.microsoftonline.com      [★] [🧩] │  LocationBarView (Omnibox)
├─────────────────────────────────────────────────────────────────┤
│ [Bookmark A] [Bookmark B] [Bookmark C]                          │  BookmarksBarView
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│                      WebContents Viewport                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

                            ▼  Launched with --app=<URL>

Chromium --app Window (App Window)
┌─────────────────────────────────────────────────────────────────┐
│ 🪟 Sign in to Microsoft Teams                          [-] [x] │  Native Win32 Titlebar
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│                                                                 │
│                      WebContents Viewport                       │
│            (Omnibox, URL Bar, Security Indicators: 0%)          │
│                                                                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 2.1 Critical Security Invariants Compromised
1. **Zero Origin Feedback**: In `--app` mode, the current domain origin (whether `https://malicious.domain`, `http://insecure`, or `file:///C:/Users/...`) is entirely invisible to the user.
2. **Context Extension Invalidation**: Password manager browser extensions (e.g., 1Password, Bitwarden) that rely on user-visible toolbar icons and autofill prompts are frequently silenced or hidden.
3. **OS Titlebar Spoofing**: The native Windows titlebar displays the `<title>` tag of the loaded HTML document. By setting `<title>Sign in to your account</title>` or `<title>Microsoft Teams</title>`, the window visually impersonates legitimate desktop applications.

---

## 3. Parameter Synergy: Session Isolation & Modal Geometry

In advanced campaigns, `--app` is rarely deployed in isolation. Adversaries chain multiple Chromium command-line switches to craft high-fidelity desktop dialog replicas:

```powershell
# Chained execution syntax
brave.exe --app="C:\Users\Victim\Desktop\invoice.html" -incognito --window-size=440,520 --window-position=500,200
```

### 3.1 `-incognito` / `--inprivate` Evasion
Standard browser sessions retain authentication cookies, session tokens, and autofill credentials. Launching with `-incognito` forces an isolated in-memory profile:
- Clears all existing single sign-on (SSO) sessions.
- Forces the display of unauthenticated username/password input forms.
- Leaves zero browser history or disk cache artifacts upon window termination.

### 3.2 Modal Geometry Mimicry (`--window-size`)
Cloud identity authentication popups feature strictly standardized pixel dimensions:
- **Microsoft Entra ID / Microsoft Account**: `440px × 520px`
- **Teams Desktop Auth Modal**: `480px × 640px`
- **Google OAuth Consent**: `500px × 600px`

By enforcing `--window-size=440,520`, the spawned browser window perfectly overlays the geometry expected by the operating system user, eliminating suspicious wide aspect ratios.

---

## 4. Blue Team Detection Strategies

1. **Process Creation Auditing (Sysmon Event ID 1 & 4688)**:
   - Alert on any browser process where `CommandLine` contains `--app=`.
   - Escalate to CRITICAL if `--app=` targets a local file (`file:///`, `.html`, `.htm`) or paths within `%TEMP%` / `%APPDATA%`.
2. **Parent-Child Process Discrepancies**:
   - Flag instances where browser executables are spawned by scripting hosts (`powershell.exe`, `cmd.exe`, `wscript.exe`) rather than `explorer.exe`.
