# NetLedger — Windows Network Traffic Monitoring & Log Collection

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell)](https://github.com/PowerShell/PowerShell)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11%20%7C%20Server%202016%2B-lightgrey)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

> A pure PowerShell toolkit for full-scale Windows network traffic monitoring, log aggregation, and anomaly detection.

## Features

- **One-click initialization** — Auto-configure audit policies, enable DNS logging, download & install Sysmon, register scheduled tasks
- **Multi-source collection** — Collect network activity from 6 data sources (Security 5156/4688, DNS 3008, Sysmon 1/3/11)
- **Intelligent anomaly detection** — Auto-detect: unusual port connections, night-time anomalies, DNS resolution failures (possible DGA), first-seen domains, large file downloads, suspicious processes
- **Structured daily reports** — Bilingual (CN/EN), statistics summary + detailed records, openable in Notepad/VS Code, AI-analysis ready
- **Zero external dependencies** — Pure PowerShell, Sysmon auto-downloaded, no third-party tools required
- **Automatic maintenance** — Scheduled daily collection (00:30 + on startup), auto-cleanup of expired logs

## Quick Start

```powershell
# 1. Navigate to scripts directory
cd scripts/

# 2. Initialize (run as Administrator, once)
.\NetworkMonitor.ps1 -Mode Init

# 3. Check status
.\NetworkMonitor.ps1 -Mode Status

# 4. Manual collection
.\NetworkMonitor.ps1 -Mode Export

# 5. View reports (in D:\NetworkMonitor\logs\)
ls D:\NetworkMonitor\logs\
```

## Project Structure

```
NetLedger/
├── scripts/
│   ├── NetworkMonitor.ps1              # Core main script
│   └── Uninstall-NetworkMonitor.ps1    # Uninstall script
├── config/
│   └── sysmon-config.xml              # Sysmon configuration
├── docs/
│   ├── 原始需求.md                     # Original requirements (CN)
│   ├── ARCHITECTURE.md                # Architecture doc (AI-readable)
│   ├── DEVELOPMENT.md                 # Development guide (AI-readable)
│   ├── DESIGN-DECISIONS.md            # Design decisions (AI-readable)
│   ├── user-guide.zh-CN.md            # User guide (Chinese)
│   ├── user-guide.en.md               # User guide (English)
│   ├── faq.zh-CN.md                   # FAQ (Chinese)
│   └── faq.en.md                      # FAQ (English)
├── README.md                          # Project README (Chinese)
├── README.en.md                       # Project README (English)
└── README.txt                         # Deployment README
```

## Documentation Index

| Document | Audience | Language |
|----------|----------|----------|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | AI / Developers | English |
| [DEVELOPMENT.md](docs/DEVELOPMENT.md) | AI / Developers | English |
| [DESIGN-DECISIONS.md](docs/DESIGN-DECISIONS.md) | AI / Architects | English |
| [user-guide.zh-CN.md](docs/user-guide.zh-CN.md) | Users | Chinese |
| [user-guide.en.md](docs/user-guide.en.md) | Users | English |
| [faq.zh-CN.md](docs/faq.zh-CN.md) | Users | Chinese |
| [faq.en.md](docs/faq.en.md) | Users | English |

## Uninstall

```powershell
cd scripts/
# Basic uninstall
.\Uninstall-NetworkMonitor.ps1

# Full uninstall (including logs & scripts)
.\Uninstall-NetworkMonitor.ps1 -RemoveLogs -RemoveScripts
```

## Compatibility

- Windows 10 / Windows 11
- Windows Server 2016+
- PowerShell 5.1+ (7.6+ recommended)

## License

MIT License
