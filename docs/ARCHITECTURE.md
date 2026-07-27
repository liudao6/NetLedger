# NetLedger Architecture

> **Target Audience**: AI agents, developers, maintainers
> **Purpose**: Understand system architecture, component relationships, and data flow

## Overview

NetLedger is a Windows network traffic monitoring and log collection system implemented entirely in PowerShell. It collects events from 6 data sources across Windows Event Logs and Sysmon, aggregates them into a human-readable daily report, and supports anomaly detection.

## Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                        ENTRY LAYER                               │
│  param($Mode, $Hours) → Mode Dispatch (Init/Export/Status)       │
│  Admin check → Self-elevation on demand                          │
└──────────────────────────┬───────────────────────────────────────┘
                           │
           ┌───────────────┼───────────────┐
           ▼               ▼               ▼
    ┌──────────┐    ┌──────────┐    ┌──────────┐
    │   INIT   │    │  EXPORT  │    │  STATUS  │
    │   Mode   │    │   Mode   │    │   Mode   │
    └────┬─────┘    └────┬─────┘    └────┬─────┘
         │               │               │
    ┌────▼────┐    ┌─────▼──────┐   ┌────▼────┐
    │AuditPol │    │ 6 Collectors│   │Component │
    │DNS Log  │    │ (parallel)  │   │ Status   │
    │Sysmon   │    └─────┬──────┘   │ Checks   │
    │Dirs     │          │          └──────────┘
    │TaskSched│    ┌─────▼──────┐
    └─────────┘    │Statistics  │
                   │Anomaly Det.│
                   │Formatter   │
                   └─────┬──────┘
                         │
                    ┌────▼────┐
                    │  Daily  │
                    │ Report  │
                    │  .txt   │
                    └─────────┘
```

## Component Map

### 1. Configuration Layer (Lines ~89-118)
- **All user-modifiable variables** in a single block at the top
- `$LogRootDir`, `$SysmonDir`, `$DailyRunTime`, `$RetentionDays`, `$ExportFormat`
- Sysmon XML config embedded as a PowerShell here-string for self-contained deployment
- Separate `config/sysmon-config.xml` serves as the canonical config reference

### 2. Utility Layer (Lines ~120-170)
| Function | Purpose |
|----------|---------|
| `Write-RunLog` | Write timestamped log entries to `run.log` |
| `Test-IsAdmin` | Check if running as Administrator |
| `Test-IsInitialized` / `Set-Initialized` | State tracking via `.initialized` marker file |
| `Format-FixedWidth` | Column-based text alignment for report tables |
| `Get-DateRange` | Compute start/end time window |
| `Test-SysmonAvailable` | Check if Sysmon service is running |

### 3. Initialization Subsystem (Lines ~172-310)
Functions invoked only during `-Mode Init`:

| Function | Side Effects |
|----------|-------------|
| `Initialize-AuditPolicy` | Calls `auditpol.exe` to enable Filtering Platform Connection + Process Creation (Success) |
| `Initialize-DNSLog` | Calls `wevtutil` to enable `Microsoft-Windows-DNS-Client/Operational` |
| `Initialize-Sysmon` | Downloads Sysmon64.exe from Microsoft Sysinternals, writes config, executes `-accepteula -i` |
| `Initialize-DirectoryStructure` | Creates `$LogRootDir/logs/`, `scripts/`, `sysmon/` directories; self-copies script to deployment dir |
| `Initialize-TaskScheduler` | Registers `NetworkMonitor_DailyExport` task with 2 triggers (daily + startup) |
| `Initialize-Readme` | Writes `README.txt` to `$LogRootDir` |

### 4. Data Collection Subsystem (Lines ~312-470)
Six independent collectors, each with its own try-catch. Failure in one does not affect others.

| Function | Event Source | Event ID | Query Method |
|----------|-------------|----------|-------------|
| `Get-Security5156` | Security | 5156 | `Get-WinEvent -FilterHashtable` |
| `Get-Security4688` | Security | 4688 | `Get-WinEvent -FilterHashtable` |
| `Get-DNS3008` | DNS Client | 3008 | `Get-WinEvent -FilterHashtable` |
| `Get-Sysmon1` | Sysmon | 1 | `Get-WinEvent -FilterHashtable` |
| `Get-Sysmon3` | Sysmon | 3 | `Get-WinEvent -FilterHashtable` |
| `Get-Sysmon11` | Sysmon | 11 | `Get-WinEvent -FilterHashtable` |

**Key Design Decision**: Use `-FilterHashtable` (not `-FilterXml`) because:
- Provider-side filtering reduces data transfer from ETW
- Simpler syntax for time-range + ID combinations
- `-MaxEvents` parameter caps memory usage at 50,000 events per source

**Sysmon Fallback**: If `Test-SysmonAvailable` returns false, Sysmon collectors return empty arrays without errors.

**XML Parsing Pattern**: All collectors use a consistent pattern:
```powershell
$xml = [xml]$evt.ToXml()
$data = @{}
$xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }
```

### 5. Statistics Subsystem (Lines ~472-560)
Memory-only computation, no persistent storage.
- `Get-ConnectionStats`: Total/outbound/inbound/unique IPs
- `Get-Top10ProcessByConnection`: Aggregates Security 5156 + Sysmon 3
- `Get-Top10Domain`: Aggregates DNS 3008
- `Get-Top10FileCreate`: Aggregates Sysmon 11
- `Get-NewDomains`: Diff today's domains against yesterday's report file (regex extraction)

### 6. Anomaly Detection Subsystem (Lines ~562-670)
Six detectors, each returning filtered result sets:

| Detector | Rule | Data Sources |
|----------|------|-------------|
| `Test-UnusualPort` | Port NOT in whitelist (80/443/53/22/21/25/110/143/993/995/8080/8443/3389) | 5156 + Sysmon3 |
| `Test-NightActivity` | Hour 0-5 AND outbound >50 per process | 5156 + Sysmon3 |
| `Test-DNSFailure` | Empty/null DNS result string | DNS 3008 |
| `Test-SuspiciousProcess` | Process name/cmdline matches regex: `miner\|crypto\|hack\|inject\|trojan\|backdoor\|payload\|keylog\|ransom\|exploit\|stealer\|rat\|botnet` | 4688 + Sysmon1 + 5156 + Sysmon3 |
| `Test-LargeDownload` | File path contains Downloads/Temp AND size >100MB | Sysmon11 |

All detectors return arrays (empty if no anomalies). Report generation handles empty arrays gracefully.

### 7. Formatting Subsystem (Lines ~672-840)
`Write-Report` function generates the complete daily report using `StringBuilder` for performance:
1. Header block (timestamp, computer name)
2. Part 1: Statistics Summary (connection stats, TOP10 tables, new domains)
3. Anomaly Alerts section (conditionally generated)
4. Part 2: Connection Details (all 5156 + Sysmon3 events)
5. Part 3: DNS Query Details (all 3008 events)
6. Part 4: File Creation Details (all Sysmon11 events)
7. Part 5: Process Creation Details (all 4688 + Sysmon1 events)
8. Footer (file size, total records)

## Data Flow

```
Windows Event Logs (ETW)
    │
    ▼
Get-WinEvent -FilterHashtable (6 parallel queries)
    │
    ├── Security 5156 ──► [PSCustomObject[]] with Time/AppName/Direction/DestIP/DestPort/Protocol
    ├── Security 4688 ──► [PSCustomObject[]] with Time/NewProcessName/CommandLine/ParentProcessName
    ├── DNS 3008      ──► [PSCustomObject[]] with Time/Domain/QueryType/Result
    ├── Sysmon 1      ──► [PSCustomObject[]] with Time/Image/CommandLine/ParentImage/User
    ├── Sysmon 3      ──► [PSCustomObject[]] with Time/Image/Direction/DestIP/DestPort/Protocol
    └── Sysmon 11     ──► [PSCustomObject[]] with Time/Image/TargetFile
    │
    ▼
Statistics Functions (in-memory group-by/count/distinct)
    │
    ▼
Anomaly Detectors (filter + aggregate)
    │
    ▼
StringBuilder → Format-FixedWidth tables
    │
    ▼
UTF-8 with BOM → {yyyy-MM-dd}.txt
```

## Key Design Patterns

### Error Isolation
Every data collector has its own try-catch. A failure in `Get-Security5156` does not prevent `Get-DNS3008` from running. The report will simply show empty data for the failed source.

### State Management
No SQLite, no registry keys. The initialization state is tracked via a `.initialized` marker file in `$LogRootDir`. Task Scheduler handles execution timing.

### Self-Contained Deployment
The script copies itself to `$LogRootDir/scripts/` during Init. The Sysmon XML config is embedded as a string. The only external dependency is Sysmon64.exe (auto-downloaded).

### Separation of Concerns
- **Collection** functions ONLY query events and return arrays
- **Statistics** functions ONLY compute aggregations
- **Anomaly** functions ONLY detect and return alerts
- **Write-Report** ONLY formats and writes output
- No function mixes collection with formatting or detection with output
