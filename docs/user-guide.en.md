# NetLedger User Guide

> **Target Audience**: End users
> **Purpose**: Installation, configuration, and daily usage instructions

## Quick Start

### 1. Download

Copy the `scripts/` directory from the project to any location (e.g., `D:\NetworkMonitor\scripts\`).

### 2. One-Click Initialization (Run as Administrator)

Open **PowerShell (Admin)**:

```powershell
cd D:\NetworkMonitor\scripts
.\NetworkMonitor.ps1 -Mode Init
```

The initialization will:
- Enable Windows Audit Policies (network connection + process creation)
- Enable DNS Client Operational log
- Download and install Sysmon (if not already installed)
- Create log directory structure
- Register daily scheduled task (daily at 00:30 + at system startup)

### 3. Check Status

```powershell
.\NetworkMonitor.ps1 -Mode Status
```

### 4. Manual Collection

```powershell
# Collect past 24 hours
.\NetworkMonitor.ps1 -Mode Export

# Collect past 48 hours
.\NetworkMonitor.ps1 -Mode Export -Hours 48
```

### 5. View Logs

Log files are in `D:\NetworkMonitor\logs\`, named by date (e.g., `2026-07-27.txt`). Open directly with Notepad or VS Code.

---

## Configuration

Edit the configuration block at the top of `NetworkMonitor.ps1`:

```powershell
$LogRootDir    = "D:\NetworkMonitor"        # Log root directory
$SysmonDir     = "C:\Sysmon"                # Sysmon install directory
$DailyRunTime  = "00:30"                    # Daily collection time (24h)
$RetentionDays = 90                         # Log retention days
$ExportFormat  = "txt"                      # Export format: txt or csv
```

Changes take effect on the next Export run; no re-initialization needed.

---

## Daily Report Structure

Each daily report contains six sections:

| Section | Content |
|---------|---------|
| Statistics Summary | Total connections, inbound/outbound, unique IPs/domains, TOP10 processes/domains/file creation |
| Anomaly Alerts | Unusual ports, night activity, DNS failures, suspicious processes, large downloads |
| Connection Details | All network connections: process, destination IP, port, direction |
| DNS Query Records | All domain queries and resolution results |
| File Creation Records | Files created in Downloads/Temp/Desktop |
| Process Launch Records | All new processes and command-line arguments |

---

## Uninstall

Run as Administrator:

```powershell
.\Uninstall-NetworkMonitor.ps1
```

Full cleanup (including logs and scripts):

```powershell
.\Uninstall-NetworkMonitor.ps1 -RemoveLogs -RemoveScripts
```

---

## FAQ

### Why is Administrator privilege required?
- Initialization modifies system audit policies and installs Sysmon
- Export needs to read Windows Security event logs
- Always run as Administrator

### What if Sysmon download fails?
Download `Sysmon64.exe` manually from [Microsoft Sysinternals](https://learn.microsoft.com/sysinternals/downloads/sysmon), place it in `C:\Sysmon\`, then re-run Init.

### The report file is too large?
- Reduce `$RetentionDays` (e.g., 30 days)
- Large reports are expected on busy systems; all events are logged without truncation

### How to change the scheduled collection time?
Edit `$DailyRunTime` in the script config (e.g., `"06:00"` for 6 AM), then re-run Init to update the scheduled task.

### Which Windows versions are supported?
- Windows 10 / Windows 11
- Windows Server 2016+

### How to analyze logs with AI?
Open the `.txt` log file in VS Code, select all, copy, and paste into ChatGPT/Claude or any AI tool. Reports include bilingual (Chinese/English) labels for easy AI comprehension.
