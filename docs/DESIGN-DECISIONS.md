# NetLedger Design Decisions

> **Target Audience**: AI agents, architects, technical reviewers
> **Purpose**: Record key technical decisions and their trade-off rationale

## DD-001: Single-File Script Architecture

**Decision**: All functionality in one `NetworkMonitor.ps1` file (no modules, no dot-sourcing).

**Rationale**:
- **Portability**: A single file can be deployed to `$LogRootDir/scripts/` without managing dependencies
- **Task Scheduler Compatibility**: Scheduled tasks reference one file path; multi-file setups risk version mismatches
- **Auditability**: Users can review and verify the entire script in one place

**Trade-off**: ~1000 lines in one file; harder to unit-test individual functions. Mitigated by clear section headers and consistent function naming.

**Rejected Alternative**: Multi-module PowerShell project (.psm1 files). Rejected because Task Scheduler deployment and manual user execution become fragile with module path dependencies.

---

## DD-002: Get-WinEvent -FilterHashtable vs -FilterXml

**Decision**: Use `-FilterHashtable` for all event log queries.

**Rationale**:
- ETW performs Provider-side filtering, reducing data transfer from kernel to user mode
- Hash table syntax is simpler and less error-prone than XPath XML
- `-MaxEvents` parameter directly bounds memory usage without needing XPath position predicates

**Trade-off**: FilterHashtable cannot express complex boolean logic (AND/OR across fields). Acceptable because all queries filter only on LogName + ID + TimeRange.

**Rejected Alternative**: `-FilterXml` with XPath queries. More powerful filtering but requires XML expertise and is harder to audit. Performance difference is negligible for daily batch processing.

---

## DD-003: StringBuilder vs Stream Output

**Decision**: Build the entire report in a `System.Text.StringBuilder` then write once with `Out-File`.

**Rationale**:
- Memory for a typical daily report (2-5 MB) is well within acceptable limits
- Single I/O operation prevents partial writes on script interruption
- Simplifies the formatting code (no need to manage open file handles)

**Trade-off**: Full report in memory before writing. For extreme data volumes (>100 MB), this could cause memory pressure. Mitigated by `-MaxEvents` caps on collectors.

**Rejected Alternative**: `StreamWriter` with incremental writes. More memory-efficient but risks partial/corrupted output files if the script is interrupted mid-write.

---

## DD-004: .initialized Marker File for State

**Decision**: Track initialization state with a marker file (`$LogRootDir\.initialized`) instead of registry keys or WMI.

**Rationale**:
- File-based state is transparent and user-inspectable
- No registry pollution
- Trivially portable (backup the directory = backup all state)
- Cross-version compatible (no registry path changes between Windows versions)

**Trade-off**: Can be accidentally deleted, causing re-initialization attempts. However, all init functions are idempotent (check before enabling/installing).

---

## DD-005: New Domain Detection via Previous Report Parsing

**Decision**: Parse yesterday's `.txt` report file to extract historical domain list, rather than maintaining a separate domain database.

**Rationale**:
- Zero additional storage overhead
- No database schema to maintain or migrate
- Report files are human-readable, so domain extraction logic is verifiable

**Trade-off**: Regex-based parsing is fragile; changes to the report format may break domain extraction. Mitigated by maintaining a stable report format and documenting the parsing logic.

**Rejected Alternative**: SQLite database for persistent domain tracking. Rejected because it adds dependency complexity (SQLite may not be available by default on all Windows versions in PowerShell).

---

## DD-006: SYSTEM Account for Scheduled Task

**Decision**: Run the scheduled task as `SYSTEM` (via `New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount`).

**Rationale**:
- Security event logs often require elevated privileges to read
- Running as SYSTEM ensures the task executes regardless of which user is logged in
- Avoids credential management issues (no stored passwords)

**Trade-off**: SYSTEM account has broad system access. The script must not be modified to perform unintended actions. Mitigated by recommending users review the script before deployment.

---

## DD-007: UTF-8 with BOM Encoding

**Decision**: All output files use UTF-8 encoding with BOM (`Out-File -Encoding UTF8`).

**Rationale**:
- Required by the specification for Chinese character compatibility
- BOM helps applications (Notepad, VS Code) auto-detect encoding correctly
- The report contains both Chinese and English text; mixed encoding could cause display issues

**Trade-off**: BOM adds 3 bytes per file. Negligible for log files. Some Unix tools handle BOM poorly, but this is a Windows-only system.

---

## DD-008: Separate Uninstall Script

**Decision**: Provide a separate `Uninstall-NetworkMonitor.ps1` rather than an `-Uninstall` mode in the main script.

**Rationale**:
- Uninstall is a one-time destructive operation; separating it reduces accidental invocation risk
- The uninstall script can delete the main script directory (self-deletion), which would be impossible if they were the same file
- Clear separation of concerns: main script = monitoring, uninstall script = cleanup

**Trade-off**: Two scripts to manage. Configuration variables are duplicated across files (must be kept in sync). Mitigated by documenting the sync requirement prominently.

---

## DD-009: Auto-Download Sysmon from Microsoft

**Decision**: Download Sysmon64.exe from `https://live.sysinternals.com/Sysmon64.exe` during Init if not present.

**Rationale**:
- Sysmon requires accepting EULA; auto-download streamlines the setup process
- Official Microsoft Sysinternals source uses HTTPS with valid certificate
- Avoids packaging a binary in the repository (licensing and size concerns)

**Trade-off**: Network connectivity required during Init. Offline deployment requires manual Sysmon download. Mitigated by checking if Sysmon is already installed before attempting download.

---

## DD-010: Mixed Chinese/English Report Output

**Decision**: Daily report contains both Chinese and English labels (e.g., "出站连接 Outbound").

**Rationale**:
- Chinese users can read metrics in their native language
- English labels enable AI/LLM analysis without translation
- Bilingual format serves the project's dual audience

**Trade-off**: Report files are slightly larger due to dual labels. Accepted as necessary for the use case.

---

## DD-011: ETW Kernel-Network Session for Per-Process Byte Attribution

**Decision**: Add a persistent real-time ETW trace session (`logman create trace NetLedgerTraffic`) that enables both `Microsoft-Windows-Kernel-Network` (Send/Recv events with `size` field) and `Microsoft-Windows-Kernel-Process` (ImageLoad/ProcessStart for PID→ProcessName resolution), so the daily report can answer "which process is consuming bandwidth" by actual byte counts rather than connection counts.

**Rationale**:
- The original 6 data sources (Security 5156/4688, DNS 3008, Sysmon 1/3/11) only record **connection establishment**, not bytes transferred. The "流量 TOP 10 进程" table in v1.0 was actually a "连接次数 TOP 10" — a `chrome.exe` with 3000 connections might transfer only 5 MB while `steam.exe` with 50 connections could move 30 GB. Connection count and bandwidth are uncorrelated.
- `Microsoft-Windows-Kernel-Network` is the kernel provider that fires on **every** TCP/UDP Send/Recv with the byte `size` plus the owning PID in the event header — the only native Windows mechanism that gives true per-process byte attribution without third-party drivers.
- A companion `Microsoft-Windows-Kernel-Process` provider is enabled so ProcessStart/ImageLoad events carry `ProcessID + ImageFileName`, letting the parser resolve PID→name for processes that **started before the trace session began** (the failure mode of `Get-Process -Id` after the process has exited).

**Architecture choices**:
- **Persistent registry session (no `-ets`)**: `logman create trace` without `-ets` stores the session in `HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger`. This survives reboots, but the session still needs an explicit `logman start` after each boot — handled by a standalone scheduled task `NetLedger_TrafficSessionAtBoot` triggered at startup with a 30-second delay, plus an idempotent `Ensure-TrafficSession` guard at the head of every `Export` run (defense in depth).
- **Circular ETL (`-ctw`, max 256 MB)**: bounds disk usage so the trace can run 24/7. Old events are overwritten by new ones once the cap is hit — accepted because Export archives the ETL daily.
- **Stop-archive-restart workflow**: at each Export, the live session is stopped, `traffic.etl` is moved to a timestamped archive, then the session is restarted. ~1 second of network events are lost during the restart; accepted as a trade-off vs. the alternative of running a second shadow session (more complex, double resource usage).

**Trade-offs**:
- **Constant overhead**: a kernel ETW session at this verbosity generates roughly 100-1000 events/sec under typical usage. CPU impact is <1% on modern hardware; disk I/O is bounded by the 256 MB circular file.
- **PID reuse edge case**: a PID can be reused by a different process between the trace start and the Send/Recv event. Mitigated by always taking the **latest** ImageLoad event for a given PID — imperfect but rarely wrong in practice.
- **Session requires Admin to create** (matches existing Init requirement; no new privilege escalation).
- **`Get-WinEvent -Path` ETL parsing**: capped to 1,000,000 events per parse to bound memory. On very-high-traffic hosts (>1 GB/day) some Send/Recv events will be silently dropped from the daily report. Mitigated by warning in `run.log` when the cap is hit (future work).

**Rejected alternatives**:
- **Performance counters `\Process(*)\IO Data Bytes/sec`**: includes disk I/O, overestimates network traffic 2-5×. Wrong data is worse than no data here.
- **`pktmon` continuous capture**: precise per-packet bytes but per-PID aggregation requires manual PID filter setup and is awkward for 24/7 collection. Better suited for ad-hoc diagnosis.
- **Sysmon-only**: Sysmon Event 3 (NetworkConnect) fires only on connection establishment; the schema has no `sentBytes`/`receivedBytes` field. Configuration changes cannot fix this — it is a provider-level limitation.
- **Third-party driver (NetLimiter/GlassWire)**: violates the "zero external dependencies" project principle (DD-009).

---

## DD-012: Rename "流量 TOP 10" → "连接 TOP 10"

**Decision**: The pre-existing report section formerly titled "流量 TOP 10 进程" (whose actual fields were `连接数/出站/入站/涉及IP数`) is renamed to "连接 TOP 10 进程 Top 10 Processes by Connection Count", and a new "流量 TOP 10 进程 Top 10 Processes by Traffic (Bytes)" section using ETW Send/Recv byte aggregation is inserted above it.

**Rationale**:
- The v1.0 section title was misleading: it counted connections, not bytes. Keeping the old title with byte data underneath would be equally misleading.
- Both tables are kept (rather than removing the connection-count table) because the two views answer different questions — connection count tells you which process is "chatty" (lots of short connections, e.g. telemetry), while byte count tells you which process is "heavy" (large transfers, e.g. downloads). The report now answers both.
