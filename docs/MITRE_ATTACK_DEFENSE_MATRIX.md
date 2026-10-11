# 🛡️ MITRE ATT&CK Enterprise Defense Mapping Matrix

This matrix formalizes the defensive coverage provided by the **52 Sigma rules, 32 YARA signatures, and static forensic engines** within this repository against MITRE ATT&CK enterprise adversary techniques.

---

<table width="100%">
  <thead>
    <tr>
      <th width="32%">MITRE ATT&amp;CK Technique</th>
      <th width="68%">Detection Engineering &amp; Defense Rule Mappings</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>
        🏷️ <strong>T1036.005</strong><br>
        <code>Masquerading:<wbr>Match Legitimate Name or Location</code>
      </td>
      <td>
        <strong>Sigma Rules (20 Rules)</strong>: <code>proc_creation_win_chromium_app_mode_flag.yml</code>, <code>proc_creation_win_chromium_app_local_file.yml</code>, <code>proc_creation_win_chromium_app_window_size.yml</code>.<br>
        <strong>YARA Signatures (12 Rules)</strong>: <code>lnk_teams_icon_masquerade.yar</code>, <code>lnk_office_icon_masquerade.yar</code>, <code>lnk_chromium_app_mode_flag.yar</code>.<br>
        <strong>Forensic Engine</strong>: <code>LNKForensicsParser</code> extracts IconLocation and checks for browser binary target mismatches.
      </td>
    </tr>
    <tr>
      <td>
        🏷️ <strong>T1204.002</strong><br>
        <code>User Execution:<wbr>Malicious File (LNK Shortcuts)</code>
      </td>
      <td>
        <strong>Sigma Rules (10 Rules)</strong>: <code>proc_creation_win_lnk_file_creation_suspicious_args.yml</code>, <code>proc_creation_win_lnk_app_mode_shortcut_drop.yml</code>.<br>
        <strong>YARA Signatures (8 Rules)</strong>: <code>lnk_incognito_evasion_flag.yar</code>, <code>lnk_local_html_target.yar</code>.<br>
        <strong>Forensic Engine</strong>: <code>LNKForensicsParser</code> performs binary carving of [MS-SHLLINK] structures and detects stealth execution flags.
      </td>
    </tr>
    <tr>
      <td>
        🏷️ <strong>T1566.002</strong><br>
        <code>Phishing:<wbr>Spearphishing Link (Synthetic UI)</code>
      </td>
      <td>
        <strong>Sigma Rules (12 Rules)</strong>: <code>proc_creation_win_fake_login_portal_spawn.yml</code>, <code>proc_creation_win_fake_address_bar_injection.yml</code>.<br>
        <strong>YARA Signatures (10 Rules)</strong>: <code>html_fake_address_bar_dom.yar</code>, <code>html_login_modal_mimicry.yar</code>, <code>html_lock_icon_svg_mimic.yar</code>.<br>
        <strong>Forensic Engine</strong>: <code>DeviceCodeFlowGuard</code> identifies synthetic address bar CSS classes and spoofed lock icons.
      </td>
    </tr>
    <tr>
      <td>
        🏷️ <strong>T1528</strong><br>
        <code>Steal Application Access Token:<wbr>OAuth Device Code Flow</code>
      </td>
      <td>
        <strong>Sigma Rules (8 Rules)</strong>: <code>proc_creation_win_oauth_device_code_url.yml</code>, <code>proc_creation_win_devicelogin_portal_access.yml</code>.<br>
        <strong>YARA Signatures (6 Rules)</strong>: <code>oauth_device_code_flow_harvester.yar</code>, <code>html_device_code_render_box.yar</code>.<br>
        <strong>Forensic Engine</strong>: <code>DeviceCodeFlowGuard</code> identifies <code>microsoft.com/devicelogin</code> targets and 8-character user authorization codes.
      </td>
    </tr>
    <tr>
      <td>
        🏷️ <strong>T1547.001</strong><br>
        <code>Boot or Logon Autostart:<wbr>Registry Run Keys / Startup Folder</code>
      </td>
      <td>
        <strong>Sigma Rules (8 Rules)</strong>: <code>file_event_win_startup_lnk_spoofing.yml</code>, <code>registry_set_win_run_key_app_mode.yml</code>.<br>
        <strong>YARA Signatures (6 Rules)</strong>: <code>powershell_shortcut_generator.yar</code>, <code>vbs_shortcut_creator_app_mode.yar</code>.<br>
        <strong>SIEM Queries</strong>: <code>splunk_queries.spl</code> Query 5 monitors Sysmon Event ID 11 shortcut drops into Startup paths.
      </td>
    </tr>
    <tr>
      <td>
        🏷️ <strong>T1564.004</strong><br>
        <code>Defense Evasion:<wbr>Hide Artifacts (Incognito Mode)</code>
      </td>
      <td>
        <strong>Sigma Rules (10 Rules)</strong>: <code>proc_creation_win_chromium_app_incognito.yml</code>, <code>proc_creation_win_chromium_app_custom_userdata.yml</code>.<br>
        <strong>YARA Signatures (6 Rules)</strong>: <code>lnk_incognito_evasion_flag.yar</code>, <code>lnk_inprivate_edge_flag.yar</code>.<br>
        <strong>Forensic Engine</strong>: <code>ChromiumAppDetector</code> scores incognito parameter combinations as high-severity evasion indicators.
      </td>
    </tr>
  </tbody>
</table>
