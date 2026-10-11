# 🔬 [MS-SHLLINK] Binary Extraction & Shortcut Spoofing Forensics
**Whitepaper CASF-WP-02 · Systems & Security Research**
*Authored by Maya Thorne · Published October 2026*

---

## 1. Executive Summary

Windows Shortcut files (`.lnk`) adhere to the Microsoft `[MS-SHLLINK]: Shell Link (.LNK) Binary File Format` specification. While primarily intended for desktop convenience, shortcuts are a favored initial delivery vector (MITRE ATT&CK T1204.002). Because Windows File Explorer conceals command-line arguments and target paths behind friendly icons and labels, users routinely execute arbitrary browser commands under the assumption of launching local desktop applications.

This whitepaper dissects the binary anatomy of `.lnk` artifacts, demonstrating how forensic examiners and automated static parsers can extract embedded arguments, target timestamps, network metadata, and masquerading icons.

---

## 2. Binary Structure of [MS-SHLLINK]

A `.lnk` file is structured into sequential binary segments:

```
[MS-SHLLINK Binary Stream]
┌────────────────────────────────────────────────────────┐
│ ShellLinkHeader (76 bytes fixed)                       │
│  - HeaderSize: 0x0000004C (76)                         │
│  - LinkCLSID: {00021401-0000-0000-C000-000000000046}  │
│  - LinkFlags: Bitmask controlling optional structures   │
│  - Timestamps: Creation, Access, Write (FILETIME)      │
│  - FileSize & ShowCommand (SW_SHOWNORMAL / MINIMIZED)  │
├────────────────────────────────────────────────────────┤
│ LinkTargetIDList (Optional - ITEMIDLIST)               │
├────────────────────────────────────────────────────────┤
│ LinkInfo (Optional - Volume, Local/Network Paths)      │
├────────────────────────────────────────────────────────┤
│ StringData Structures (Optional):                      │
│  - NAME_STRING (Shortcut Description)                  │
│  - RELATIVE_PATH                                       │
│  - WORKING_DIR                                         │
│  - COMMAND_LINE_ARGUMENTS (--app=... -incognito)       │
│  - ICON_LOCATION (Targeting legitimate .ico files)     │
├────────────────────────────────────────────────────────┤
│ ExtraData Blocks (0 or more metadata blocks):          │
│  - TrackerDataBlock (NetBIOS Name, Droid Volume IDs)   │
│  - EnvironmentVariableDataBlock                        │
│  - Terminal Block (Size < 4)                           │
└────────────────────────────────────────────────────────┘
```

---

## 3. Shortcut Argument Concealment Vectors

### 3.1 Exploiting `COMMAND_LINE_ARGUMENTS`
When the `HasArguments` flag (Bit 5, `0x00000020`) in `LinkFlags` is set, a 16-bit character count followed by a UTF-16LE string specifies arbitrary parameters passed to the target binary.
- Explorer UI renders only the shortcut name (e.g., `Microsoft Teams.lnk`).
- When double-clicked, Explorer invokes:
  `ShellExecuteEx(lpFile="brave.exe", lpParameters="--app=https://spoofed.site -incognito")`.

### 3.2 Icon Location Masquerading (`HasIconLocation`)
When `HasIconLocation` (Bit 6, `0x00000040`) is active, Explorer extracts the visual icon from the specified file rather than the target executable.
- Example: Setting `IconLocation = "C:\Program Files\Microsoft Office\root\Office16\teams.ico"`.
- The user sees a 100% authentic Teams icon on their desktop, even though the underlying target is `brave.exe` or `chrome.exe`.

---

## 4. Automated Forensic Extraction Algorithm

Our pure-Python engine (`src/lnk_forensics_parser.py`) parses LNK streams without external dependencies:

```python
# Extracting arguments and icon location from raw bytes
flags = struct.unpack_from("<I", raw_bytes, 20)[0]
offset = 76

# Skip LinkTargetIDList if present
if flags & 0x01:
    id_list_len = struct.unpack_from("<H", raw_bytes, offset)[0]
    offset += 2 + id_list_len

# Skip LinkInfo if present
if flags & 0x02:
    link_info_len = struct.unpack_from("<I", raw_bytes, offset)[0]
    offset += link_info_len

# Read StringData blocks
def read_string(offset, is_unicode):
    cnt = struct.unpack_from("<H", raw_bytes, offset)[0]
    offset += 2
    if is_unicode:
        val = raw_bytes[offset:offset + cnt * 2].decode("utf-16le", errors="ignore")
        return val, offset + cnt * 2
    else:
        val = raw_bytes[offset:offset + cnt].decode("cp1252", errors="ignore")
        return val, offset + cnt
```

This extraction guarantees instant visibility into embedded flags and enables SOC analysts to triage thousands of shortcut artifacts per second.
