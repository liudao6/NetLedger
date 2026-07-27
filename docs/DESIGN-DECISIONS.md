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
