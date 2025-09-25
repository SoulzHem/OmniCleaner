# Antivirus Whitelist Instructions

## OmniCleaner - Security Tool

This is a **legitimate security tool** designed to help users remove shortcut viruses and malware from USB drives and local storage devices.

### Why Antivirus Programs May Flag This Tool

Antivirus programs may flag this tool as suspicious because it:
- Modifies file attributes (makes hidden files visible)
- Deletes files and shortcuts
- Modifies registry entries
- Accesses removable drives

**This is normal behavior for a security tool** and does not indicate malicious activity.

### How to Whitelist This Tool

#### Windows Defender
1. Open Windows Security
2. Go to "Virus & threat protection"
3. Click "Manage settings" under "Virus & threat protection settings"
4. Scroll down to "Exclusions"
5. Click "Add or remove exclusions"
6. Click "Add an exclusion" → "Folder"
7. Select the entire `shortcutremove` folder

#### Other Antivirus Programs
**Avast/AVG:**
- Settings → General → Exceptions → Add Exception → Folder
- Add the `shortcutremove` folder

**Norton:**
- Settings → Antivirus → Scans and Risks → Exclusions/Low Risks
- Add the `shortcutremove` folder

**McAfee:**
- Real-Time Scanning → Excluded Files
- Add the `shortcutremove` folder

**Kaspersky:**
- Settings → Threats and Exclusions → Exclusions
- Add the `shortcutremove` folder

### File Signatures

The following files are part of this legitimate security tool:
- `RunCleanerGUI.bat` - GUI launcher
- `scripts/OmniCleaner.ps1` - Main cleaning script
- `scripts/OmniCleaner.GUI.ps1` - GUI interface

### What This Tool Does

✅ **Legitimate Security Functions:**
- Removes shortcut viruses from USB drives
- Makes hidden files visible again
- Cleans malicious autorun.inf files
- Removes suspicious payload files
- Quarantines threats instead of deleting them

❌ **What This Tool Does NOT Do:**
- Install malware or viruses
- Steal personal information
- Connect to malicious servers
- Modify system files unnecessarily
- Run without user permission

### Verification

This tool is open-source and its code can be reviewed. All functions are clearly documented and perform legitimate security operations.

### Support

If you continue to have issues with antivirus detection, please:
1. Add the entire folder to your antivirus exclusions
2. Ensure you downloaded from a trusted source
3. Check that all files are present and not corrupted

---
**Version:** 1.0  
**Last Updated:** 2025-09-15  
**License:** MIT
