# OmniCleaner

**A legitimate security tool** for cleaning shortcut viruses and providing advanced system scanning on Windows.

## ⚠️ Antivirus Notice

This is a **legitimate security tool**. Some antivirus programs may flag it as suspicious due to its security-related functions. Please see [ANTIVIRUS_WHITELIST.md](ANTIVIRUS_WHITELIST.md) for whitelist instructions.

## 🔧 Features

- **Recovers hidden files** - Makes hidden files visible again (attrib -h -s -r)
- **Removes malicious shortcuts** - Cleans .lnk and autorun.inf
- **Stops suspicious services** - Disables randomly named services
- **Cleans payload files** - Heuristics for .dat/.vbs/.js (with whitelists)
- **Registry cleaning** - Optional cleaning of Run/Services entries
- **Quarantine system** - Safely quarantines threats instead of deleting
- **Exclusions** - Supports `exclusions.txt` and built-in dev-path whitelists
- **GUI interface** - Modern, consistent teal theme (light/dark)
- **Real-time logs** - Clean tab and Advanced tab inline logs (word wrap)
- **Export reports** - CSV and HTML reports under `scripts/reports/`
- **Quarantine Manager** - Separate UI to browse/restore/delete items
- **Log rotation** - Old `omnicleaner.log` auto-archived to `scripts/logs/`
- **Advanced scans (log-only)**
  - Startup folders
  - Hosts file inspection
  - Browser extensions listing
  - PowerShell profiles inspection
  - Open ports scan (with risk/warn coloring)
  - Suspicious processes scan
  - Keylogger heuristics
  - Optional actions: close risky ports, kill suspicious processes (opt-in)

## 🚀 Quick Start

### GUI Mode (Recommended)
```batch
RunCleanerGUI.bat
```

### First-time Setup (optional but recommended)
```powershell
./Setup.ps1
# If ExecutionPolicy is restrictive, start PowerShell with:
# powershell -ExecutionPolicy Bypass -NoProfile
```

### Command Line Mode
```powershell
.\scripts\OmniCleaner.ps1 -AllRemovable -Aggressive
```

### Run from GitHub (Clone)
```powershell
# 1) Clone the repository
git clone https://github.com/SoulzHem/OmniCleaner.git
cd OmniCleaner

# 2) Unblock scripts (first time only)
Get-ChildItem -Recurse -Filter *.ps1 | Unblock-File

# 3) Start GUI
./RunCleanerGUI.bat
```

### Run from GitHub (Download ZIP)
```powershell
# Download ZIP from the GitHub Releases or Code → Download ZIP
# Extract it, then inside the folder:
./Setup.ps1
./RunCleanerGUI.bat
```

### One-liner (PowerShell) to clone and run GUI
```powershell
$repo = 'https://github.com/SoulzHem/OmniCleaner.git'
$temp = Join-Path $env:TEMP ('svc_' + [Guid]::NewGuid())
git clone $repo $temp; Set-Location $temp; Get-ChildItem -Recurse -Filter *.ps1 | Unblock-File; ./RunCleanerGUI.bat
```

## 📋 Parameters

- `-AllRemovable`: Scan all removable drives
- `-IncludeFixed`: Include fixed disks
- `-IncludeSystem`: Include system drive (C:)
- `-Aggressive`: Clean registry startup entries
- `-WhatIf`: Show what would be done (dry run)
- `-Quarantine`: Quarantine files instead of deleting
- `-Targets`: Target specific drives (e.g., D:, E:)
- Advanced (log-only): `-DoKeyloggerHeuristics`, `-DoStartup`, `-DoHosts`, `-DoBrowserExt`, `-DoPSProfiles`, `-DoOpenPorts`, `-DoProcessAnomalies`
- Actions (opt-in): `-KillProcesses -KillProcessPatterns <strings>`, `-CloseOpenPorts -PortTargets <ints>`

## 💡 Examples

```powershell
# Clean all removable drives
.\scripts\OmniCleaner.ps1 -AllRemovable

# Clean specific drives
.\scripts\OmniCleaner.ps1 -Targets "D:\", "E:\"

# Aggressive mode with all drives
.\scripts\OmniCleaner.ps1 -AllRemovable -IncludeFixed -Aggressive

# Dry run (show what would be done)
.\scripts\OmniCleaner.ps1 -AllRemovable -WhatIf

# Advanced scans (log-only)
./scripts/OmniCleaner.ps1 -DoOpenPorts -LogPath "./scripts/omnicleaner.log"
./scripts/OmniCleaner.ps1 -DoProcessAnomalies -LogPath "./scripts/omnicleaner.log"
./scripts/OmniCleaner.ps1 -DoHosts -DoStartup -LogPath "./scripts/omnicleaner.log"

# Advanced actions (dangerous; use with care)
./scripts/OmniCleaner.ps1 -CloseOpenPorts -PortTargets 135,139,445,3389 -LogPath "./scripts/omnicleaner.log"
```

## 🛡️ Security

This tool is designed specifically for cleaning shortcut viruses. It:
- ✅ Removes malware and viruses
- ✅ Recovers hidden files
- ✅ Quarantines threats safely
- ❌ Does NOT install malware
- ❌ Does NOT steal information
- ❌ Does NOT connect to malicious servers

## 📋 Requirements

- Windows 10/11
- PowerShell 5.1 or higher
- Administrator privileges (for full functionality)

## 🔍 Verification

Run the verification script to confirm tool legitimacy:
```powershell
.\VerifyTool.ps1 -Detailed
```

## 📁 File Structure

```
shortcutremove/
├── Setup.ps1                       # First-time setup (unblock files, create folders)
├── RunCleanerGUI.bat              # GUI launcher
├── VerifyTool.ps1                 # Tool verification script
├── ANTIVIRUS_WHITELIST.md         # Antivirus whitelist instructions
├── README.md                      # This file
├── .github/
│   └── workflows/
│       └── release.yml            # Tag-based release zip automation
└── scripts/
    ├── OmniCleaner.ps1               # Main cleaning script
    ├── OmniCleaner.GUI.ps1           # GUI interface (dot-sources gui/*.ps1)
    ├── gui_settings.json             # GUI settings
    ├── reports/                      # CSV/HTML exports
    ├── quarantine/                   # Quarantined items
    ├── logs/                         # Archived logs (auto-created)
    └── gui/                          # Modular GUI parts (dot-sourced)
        ├── Logging.ps1               # Write-Log, Advanced log coloring
        ├── Theme.ps1                 # Set-UiStyle, Set-Theme
        ├── Settings.ps1              # Get-Settings, Set-Settings
        ├── CleanTab.ps1              # Clean tab UI/logic
        ├── AdvancedTab.ps1           # Initialize-AdvancedTab
        └── Quarantine.ps1            # Open-QuarantineManager
```

## 🎯 GUI Features

- **Scan (dry run)** - Preview changes without making them
- **Clean** - Perform actual cleaning
- **Inline logs** - Live logs in Clean and Advanced tabs
- **Word wrap** - Long log lines wrap within the view
- **Settings persistence** - Saves your preferences
- **Export reports** - CSV and HTML generation
- **Quarantine Manager** - List, filter, restore, delete
- **Dark theme** - Toggleable light/dark with consistent teal palette

## 📦 Releases

- Pushing a tag starting with `v` (e.g., `v1.1.0`) triggers GitHub Actions to build `OmniCleaner.zip` and upload it to the Release page automatically.
- The ZIP includes `scripts/`, `RunCleanerGUI.bat`, `Setup.ps1`, and `README.md`.

## 📞 Support

If you encounter issues:
1. Check [ANTIVIRUS_WHITELIST.md](ANTIVIRUS_WHITELIST.md) for antivirus instructions
2. Run `./VerifyTool.ps1 -Detailed` to verify tool integrity
3. Ensure all files are present and not corrupted
4. Run as Administrator for full functionality

---
**Version:** 1.0  
**Last Updated:** 2025-09-24  
**License:** MIT  
**Author:** SoulzHem

---
### Notes on Repository Structure and Modularity
- The GUI script is kept as a single file for portability. If needed, it can be modularized using PowerShell dot-sourcing (split into `scripts/gui/*.ps1` and loaded from the main GUI script). This does not change runtime behavior and is safe for GitHub.
- Running from GitHub is supported via cloning or ZIP download; no installer is required.