# NetLedger Development Guide

> **Target Audience**: AI agents, developers contributing to or modifying NetLedger
> **Purpose**: Function reference, coding standards, extension points, testing methodology

## Function Index

### Utility Functions

| Function | File | Line | Signature |
|----------|------|------|-----------|
| `Write-RunLog` | NetworkMonitor.ps1 | ~120 | `param([string]$Message, [string]$Level)` |
| `Test-IsAdmin` | NetworkMonitor.ps1 | ~135 | `returns [bool]` |
| `Test-IsInitialized` | NetworkMonitor.ps1 | ~140 | `returns [bool]` |
| `Set-Initialized` | NetworkMonitor.ps1 | ~145 | `void` |
| `Format-FixedWidth` | NetworkMonitor.ps1 | ~152 | `param([string[]]$Columns, [int[]]$Widths, [string]$Separator)` |
| `Get-DateRange` | NetworkMonitor.ps1 | ~170 | `param([int]$HoursBack) returns @{Start, End}` |
| `Test-SysmonAvailable` | NetworkMonitor.ps1 | ~178 | `returns [bool]` |

### Init Functions

| Function | Side Effects |
|----------|-------------|
| `Initialize-AuditPolicy` | Modifies system audit policy via `auditpol.exe` |
| `Initialize-DNSLog` | Enables ETW log channel via `wevtutil` |
| `Initialize-Sysmon` | Network: downloads from live.sysinternals.com; File: writes config XML; Process: runs Sysmon64.exe |
| `Initialize-DirectoryStructure` | Creates directories, copies self |
| `Initialize-TaskScheduler` | Registers scheduled task with SYSTEM principal |
| `Initialize-Readme` | Writes README.txt |

### Data Collectors (each returns `[PSCustomObject[]]`)

| Function | Event Source | MaxEvents | Fallback Behavior |
|----------|-------------|-----------|-------------------|
| `Get-Security5156` | Security/5156 | 50,000 | Returns @() on error |
| `Get-Security4688` | Security/4688 | 10,000 | Returns @() on error |
| `Get-DNS3008` | DNS Client/3008 | 50,000 | Returns @() on error |
| `Get-Sysmon1` | Sysmon/1 | 10,000 | Returns @() if Sysmon unavailable |
| `Get-Sysmon3` | Sysmon/3 | 50,000 | Returns @() if Sysmon unavailable |
| `Get-Sysmon11` | Sysmon/11 | 10,000 | Returns @() if Sysmon unavailable |

### Statistics Functions

| Function | Input | Output |
|----------|-------|--------|
| `Get-ConnectionStats` | Security5156[], Sysmon3[] | `@{TotalConn, Outbound, Inbound, UniqueIPs}` |
| `Get-Top10ProcessByConnection` | Security5156[], Sysmon3[] | `[PSCustomObject[]]` with Rank/ProcessName/TotalConn/Outbound/Inbound/UniqueIPs |
| `Get-Top10Domain` | DNS3008[] | `[PSCustomObject[]]` with Rank/Domain/QueryCount |
| `Get-Top10FileCreate` | Sysmon11[] | `[PSCustomObject[]]` with Rank/ProcessName/FileCount |
| `Get-NewDomains` | DNS3008[], YesterdayLogFile path | `[PSCustomObject[]]` with Domain/FirstSeen |

### Anomaly Detectors

| Function | Detection Rule | Whitelist/Config |
|----------|---------------|-----------------|
| `Test-UnusualPort` | DestPort not in common list | `@{80,443,53,22,21,25,110,143,993,995,8080,8443,3389}` |
| `Test-NightActivity` | Time.Hour 0-5 AND Direction=出站 AND count>50 | Threshold: 50 |
| `Test-DNSFailure` | Result is null/empty/"-" | N/A |
| `Test-SuspiciousProcess` | Name/cmd matches keyword regex | `miner\|crypto\|hack\|inject\|trojan\|backdoor\|payload\|keylog\|ransom\|exploit\|stealer\|rat\|botnet` |
| `Test-LargeDownload` | Path matches Downloads/Temp AND size>100MB | Threshold: 100MB |

### Output Function

| Function | Input | Output |
|----------|-------|--------|
| `Write-Report` | All collected data arrays + time range + output path | Writes UTF-8 BOM file |

### Maintenance Functions

| Function | Purpose |
|----------|---------|
| `Remove-OldLogs` | Deletes log files older than `$RetentionDays` |
| `Show-Status` | Displays system component status |

## Coding Standards

1. **PowerShell Version**: Target PowerShell 5.1 minimum, compatible with 7.6+
2. **Error Handling**: Every data collector MUST have its own try-catch; init functions use try-catch with meaningful messages
3. **Output Encoding**: All files use `Out-File -Encoding UTF8` (which includes BOM) for Chinese character compatibility
4. **Naming Convention**: PowerShell standard Verb-Noun for exported functions; internal helpers use `Test-` prefix for boolean returns
5. **Path Handling**: Use `Join-Path` instead of string concatenation; avoid hardcoded paths (except in config block)
6. **No External Dependencies**: The script must work with built-in PowerShell cmdlets only; Sysmon64.exe is the sole external binary (auto-downloaded)

## Extension Points

### Adding a New Data Source
1. Add a new `Get-*` collector function following the template:
   ```powershell
   function Get-NewSource {
       param([DateTime]$StartTime, [DateTime]$EndTime)
       try {
           Write-RunLog "Collecting NewSource..."
           $events = Get-WinEvent -FilterHashtable @{
               LogName   = "LogName"
               ID        = 9999
               StartTime = $StartTime
               EndTime   = $EndTime
           } -ErrorAction Stop -MaxEvents 10000
           $results = @()
           foreach ($evt in $events) {
               $xml = [xml]$evt.ToXml()
               $data = @{}
               $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }
               $results += [PSCustomObject]@{ Time = $evt.TimeCreated; ... }
           }
           return $results
       } catch {
           Write-RunLog "Failed: $_" -Level "WARN"
           return @()
       }
   }
   ```
2. Call it in the Export mode dispatch
3. Add a new section in `Write-Report` if needed
4. Update statistics/anomaly functions if relevant

### Adding a New Anomaly Rule
1. Add a new `Test-*` function returning `[PSCustomObject[]]`
2. Call it in `Write-Report`
3. Add formatted output under the anomaly alerts section
4. Update the `$hasAnomaly` flag logic if needed

### Adding a New Export Format (CSV)
1. Implement a `Write-ReportCsv` function
2. Add a format switch in the Export dispatch based on `$ExportFormat`

## Testing Methodology

### Unit Testing Approach
PowerShell scripts can be tested using Pester:
```powershell
# Example: Test Format-FixedWidth
Describe "Format-FixedWidth" {
    It "Should align columns to fixed widths" {
        $result = Format-FixedWidth -Columns @("a", "bb", "ccc") -Widths @(4, 4, 4)
        $result | Should -Be "a   bb  ccc "
    }
}
```

### Manual Test Checklist
- [ ] Init mode with no existing setup (fresh system)
- [ ] Init mode with partial existing setup (e.g., Sysmon already installed)
- [ ] Export mode with 1-hour range (quick validation)
- [ ] Export mode with 24-hour range (normal operation)
- [ ] Export mode with Sysmon stopped (graceful degradation)
- [ ] Status mode with all components healthy
- [ ] Status mode with missing components
- [ ] New domain detection with/without previous log file
- [ ] Log cleanup after setting `$RetentionDays` to 1
- [ ] Uninstall with -RemoveLogs -RemoveScripts flags

## Known Limitations

1. **Event Log Size**: Security event logs have a maximum size; events older than the log capacity will not be available
2. **Sysmon Dependency**: Sysmon events (1, 3, 11) may not be available if Sysmon is not installed or configured differently
3. **Large File Detection**: `Test-LargeDownload` checks file size at report time, not at creation time (the file may have been deleted)
4. **New Domain Detection**: Relies on regex parsing of yesterday's report file; custom report format changes could break this
5. **MaxEvents Cap**: Each collector caps at 10,000-50,000 events; high-traffic systems may hit this limit
