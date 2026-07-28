<#
.SYNOPSIS
    NetLedger - Windows Network Traffic Monitoring & Log Collection System
.DESCRIPTION
    A comprehensive PowerShell script for monitoring Windows network traffic,
    collecting security/DNS/Sysmon logs, and generating daily formatted reports.

    Supported Modes:
      - Init   : First-time initialization (audit policies, Sysmon, task scheduler)
      - Export : Daily log collection and report generation
      - Status : View system status and log overview

.PARAMETER Mode
    Operating mode: Init, Export, or Status

.PARAMETER Hours
    For Export mode: rolling time window in hours (only used when -Date is not specified).
    Default Export behavior (without -Hours or -Date) collects the PREVIOUS full calendar day.

.PARAMETER Date
    For Export mode: specify which date's complete daily log to collect (format: yyyy-MM-dd).
    When specified, collects the entire calendar day from 00:00:00 to 23:59:59.

.EXAMPLE
    .\NetworkMonitor.ps1 -Mode Init
    # Initialize the system (run once as Administrator)

.EXAMPLE
    .\NetworkMonitor.ps1 -Mode Export
    # Collect previous full calendar day (00:00 ~ 23:59:59) as a true daily summary

.EXAMPLE
    .\NetworkMonitor.ps1 -Mode Export -Date 2026-07-26
    # Collect full calendar day of 2026-07-26

.EXAMPLE
    .\NetworkMonitor.ps1 -Mode Export -Hours 48
    # Collect past 48 hours as a rolling window (manual custom range)

.EXAMPLE
    .\NetworkMonitor.ps1 -Mode Status
    # Check system status

.NOTES
    Version: 1.0.0
    Requires: PowerShell 5.1+ (recommended 7.6+), Administrator privileges
    Compatibility: Windows 10 / Windows 11 / Windows Server 2016+
#>

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Init", "Export", "Status")]
    [string]$Mode = "Status",

    [Parameter(Mandatory=$false)]
    [ValidateRange(1, 720)]
    [int]$Hours = 24,

    [Parameter(Mandatory=$false)]
    [ValidatePattern("^\d{4}-\d{2}-\d{2}$")]
    [string]$Date = ""
)

# ==================================================================
#  CONFIGURATION (User-modifiable)
# ==================================================================
$LogRootDir    = "D:\NetworkMonitor"        # Log root directory
$SysmonDir     = "C:\Sysmon"                # Sysmon installation directory
$DailyRunTime  = "00:30"                    # Daily collection time (24h format)
$RetentionDays = 90                         # Log retention days (auto-delete older)
$ExportFormat  = "txt"                      # Export format: txt or csv

# --- Per-Process Traffic Capture (ETW Kernel-Network session) ---
# A persistent ETW real-time session logs every TCP/UDP Send/Recv with byte
# counts + PID, so the daily report can answer "which process is eating bandwidth".
$TrafficSessionName = "NetLedgerTraffic"                 # logman trace session name (must be unique on the host)
$TrafficEtlMaxMB    = 256                                # ETL file max size (circular overwrite)
$TrafficNetworkKW   = [uint64]"0xFFFFFFFF"               # Kernel-Network keywords: all events
$TrafficNetworkLV   = 4                                 # Kernel-Network level: informational (>=4)
$TrafficProcessKW   = [uint64]"0x40"                     # Kernel-Process keywords: ProcessStart/Stop (ImageID)
$TrafficProcessLV   = 4                                 # Kernel-Process level: informational
# ==================================================================

# Script paths
$ScriptName     = "NetworkMonitor.ps1"
$ScriptDir      = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $PSCommandPath }
$LogsDir        = Join-Path $LogRootDir "logs"
$ScriptsDir     = Join-Path $LogRootDir "scripts"
$SysmonLogDir   = Join-Path $LogRootDir "sysmon"
$TrafficEtlDir  = Join-Path $LogRootDir "traffic"        # ETW live + archived ETL files
$RunLogFile     = Join-Path $ScriptsDir "run.log"
$TaskName       = "NetworkMonitor_DailyExport"
$TrafficTaskName = "NetLedger_TrafficSessionAtBoot"      # standalone boot task: logman start
$SysmonExe      = Join-Path $SysmonDir "Sysmon64.exe"
$SysmonConfig   = Join-Path $SysmonDir "sysmon-config.xml"
$ReadmeFile     = Join-Path $LogRootDir "README.txt"

# Embedded Sysmon XML Configuration
$SysmonXmlContent = @'
<?xml version="1.0" encoding="UTF-8"?>
<Sysmon schemaversion="4.90">
  <!-- NetLedger Sysmon Configuration -->
  <!--
    Rule logic:
    - onmatch="exclude" with empty rules = include EVERYTHING (nothing excluded)
    - onmatch="include" with rules     = only include matched events
    DO NOT use onmatch="include" with empty rules — it matches NOTHING.
  -->
  <EventFiltering>
    <ProcessCreate onmatch="exclude">
    </ProcessCreate>
    <NetworkConnect onmatch="exclude">
    </NetworkConnect>
    <FileCreateTime onmatch="include">
      <TargetFilename condition="contains">Downloads</TargetFilename>
      <TargetFilename condition="contains">Temp</TargetFilename>
      <TargetFilename condition="contains">AppData\Local\Temp</TargetFilename>
      <TargetFilename condition="contains">Desktop</TargetFilename>
    </FileCreateTime>
  </EventFiltering>
  <HashAlgorithms>SHA256</HashAlgorithms>
</Sysmon>
'@

# ==================================================================
#  HELPER FUNCTIONS
# ==================================================================

function Write-RunLog {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR")]
        [string]$Level = "INFO"
    )
    $timestamp = [DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss')
    $logLine = "$timestamp [$Level] $Message"
    try {
        if (-not (Test-Path $ScriptsDir)) {
            New-Item -ItemType Directory -Path $ScriptsDir -Force | Out-Null
        }
        Add-Content -Path $RunLogFile -Value $logLine -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch { }
    $color = switch ($Level) {
        "WARN"  { "Yellow" }
        "ERROR" { "Red" }
        default { "Gray" }
    }
    Write-Host $logLine -ForegroundColor $color
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-IsInitialized {
    return (Test-Path (Join-Path $LogRootDir ".initialized"))
}

function Set-Initialized {
    try {
        if (-not (Test-Path $LogRootDir)) {
            New-Item -ItemType Directory -Path $LogRootDir -Force | Out-Null
        }
        New-Item -ItemType File -Path (Join-Path $LogRootDir ".initialized") -Force | Out-Null
    } catch { }
}

function Format-FixedWidth {
    param(
        [string[]]$Columns,
        [int[]]$Widths,
        [string]$Separator = "    "
    )
    $result = ""
    for ($i = 0; $i -lt $Columns.Count; $i++) {
        $text = if ($Columns[$i] -ne $null) { $Columns[$i] } else { "" }
        if ($text.Length -gt $Widths[$i]) {
            $text = $text.Substring(0, [Math]::Max(0, $Widths[$i] - 2)) + ".."
        }
        $result += $text.PadRight($Widths[$i])
        if ($i -lt $Columns.Count - 1) { $result += $Separator }
    }
    return $result
}

function Format-BytesForReport {
    # Human-readable byte count: 1023 B / 1.45 KB / 2.30 MB / 5.10 GB
    param([long]$Bytes)
    if ($Bytes -ge 1GB) { return "$([math]::Round($Bytes / 1GB, 2)) GB" }
    if ($Bytes -ge 1MB) { return "$([math]::Round($Bytes / 1MB, 2)) MB" }
    if ($Bytes -ge 1KB) { return "$([math]::Round($Bytes / 1KB, 2)) KB" }
    return "$Bytes B"
}

function Get-DateRange {
    param([int]$HoursBack = 24)
    $endTime   = [DateTime]::Now
    $startTime = $endTime.AddHours(-$HoursBack)
    return @{ Start = $startTime; End = $endTime }
}

function Get-FullDayRange {
    param(
        [Parameter(Mandatory=$true)]
        [DateTime]$Date
    )
    $dayStart = $Date.Date  # 00:00:00.000
    $dayEnd   = $dayStart.AddDays(1).AddMilliseconds(-1)  # 23:59:59.999
    return @{ Start = $dayStart; End = $dayEnd }
}

function Test-SysmonAvailable {
    $svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
    return ($svc -ne $null -and $svc.Status -eq "Running")
}

# ETW-based process name cache for DNS query attribution
# Maps PID -> ProcessName, with lazy population on first access
$script:ProcessNameCache = @{}
$script:ProcessNameCachePIDs = @{}

function Get-ProcessNameByPID {
    param([int]$ProcId)   # NOTE: $Pid is a PowerShell automatic variable (read-only), avoid name conflict
    if ($ProcId -le 0) { return "PID:0" }

    if ($script:ProcessNameCache.ContainsKey($ProcId)) {
        return $script:ProcessNameCache[$ProcId]
    }

    try {
        $proc = Get-Process -Id $ProcId -ErrorAction Stop
        $name = $proc.ProcessName
        $script:ProcessNameCache[$ProcId] = $name
        return $name
    } catch {
        $name = "PID:$ProcId"
        $script:ProcessNameCache[$ProcId] = $name
        return $name
    }
}

function Initialize-ProcessNameCache {
    param([int[]]$Pids)
    if ($Pids.Count -eq 0) { return }

    $uniquePids = $Pids | Where-Object { $_ -gt 0 } | Select-Object -Unique

    foreach ($pid_ in $uniquePids) {
        if (-not $script:ProcessNameCache.ContainsKey($pid_)) {
            try {
                $proc = Get-Process -Id $pid_ -ErrorAction Stop
                $script:ProcessNameCache[$pid_] = $proc.ProcessName
            } catch {
                $script:ProcessNameCache[$pid_] = "PID:$pid_"
            }
        }
    }
}

# ==================================================================
#  INITIALIZATION FUNCTIONS
# ==================================================================

function Initialize-AuditPolicy {
    Write-Host "--- Configuring Windows Audit Policies ---" -ForegroundColor Cyan
    Write-RunLog "Starting audit policy configuration..."

    # List of subcategories to enable (Success only)
    # Each has a Name (English) and a GUID — auditpol may require GUID on some localized Windows
    $policies = @(
        @{
            Name = "Filtering Platform Connection"
            Guid = "{0CCE9225-69AE-11D9-BED3-505054503030}"
            Desc = "Network connection auditing"
        },
        @{
            Name = "Process Creation"
            Guid = "{0CCE922B-69AE-11D9-BED3-505054503030}"
            Desc = "Process creation auditing"
        }
    )

    foreach ($pol in $policies) {
        $setOk = $false
        Write-Host "  Enabling: $($pol.Name) ($($pol.Desc))..." -ForegroundColor Gray

        # Try name-based first, then GUID-based fallback
        $identifiers = @($pol.Name, $pol.Guid)
        foreach ($id in $identifiers) {
            if ($setOk) { break }
            try {
                Write-RunLog "  Trying: auditpol /set /subcategory:`"$id`" /success:enable"
                $result = auditpol /set /subcategory:"$id" /success:enable 2>&1
                $exitCode = $LASTEXITCODE

                # Verify the policy was actually set
                $verifyResult = auditpol /get /subcategory:"$id" 2>&1 | Out-String

                if ($exitCode -eq 0 -and ($verifyResult -match 'Success|成功|启用')) {
                    Write-RunLog "Audit policy enabled and verified: $($pol.Name) (via $id)"
                    Write-Host "    [OK] Enabled" -ForegroundColor Green
                    $setOk = $true
                    break
                } else {
                    Write-RunLog "  Verify failed (exit=$exitCode), trying next identifier..." -Level "WARN"
                    # Retry with same identifier once
                    Start-Sleep -Seconds 1
                    $result2 = auditpol /set /subcategory:"$id" /success:enable 2>&1
                    $exitCode2 = $LASTEXITCODE
                    $verifyResult2 = auditpol /get /subcategory:"$id" 2>&1 | Out-String

                    if ($exitCode2 -eq 0 -and ($verifyResult2 -match 'Success|成功|启用')) {
                        Write-RunLog "Audit policy enabled on retry: $($pol.Name) (via $id)"
                        Write-Host "    [OK] Enabled (retry)" -ForegroundColor Green
                        $setOk = $true
                        break
                    }
                }
            } catch {
                Write-RunLog "  Exception with identifier [$id]: $_" -Level "WARN"
            }
        }

        if (-not $setOk) {
            Write-RunLog "Failed to enable audit policy [$($pol.Name)]" -Level "ERROR"
            Write-Host "    [ERROR] Failed to enable. Try manually:" -ForegroundColor Red
            Write-Host "    auditpol /set /subcategory:`"$($pol.Name)`" /success:enable" -ForegroundColor Yellow
        }
    }
    Write-RunLog "Audit policy configuration completed."
}

function Initialize-DNSLog {
    Write-Host "--- Enabling DNS Client Operational Log ---" -ForegroundColor Cyan
    Write-RunLog "Enabling DNS Client Operational log..."

    try {
        $dnsLogName = "Microsoft-Windows-DNS-Client/Operational"
        $dnsLog = Get-WinEvent -ListLog $dnsLogName -ErrorAction Stop

        # Increase log size to 256 MB (default ~1 MB is too small for both 3006/3008 events)
        $newSizeMB = 256
        $newSizeBytes = $newSizeMB * 1024 * 1024
        if ($dnsLog.MaximumSizeInBytes -lt $newSizeBytes) {
            wevtutil sl $dnsLogName /ms:$newSizeBytes 2>&1 | Out-Null
            Write-RunLog "DNS Client log size increased to $newSizeMB MB (was $([math]::Round($dnsLog.MaximumSizeInBytes/1MB, 1)) MB)."
        }

        if (-not $dnsLog.IsEnabled) {
            wevtutil sl $dnsLogName /e:true /ms:$newSizeBytes 2>&1 | Out-Null
            Write-RunLog "DNS Client Operational log enabled."
            Write-Host "  [OK] DNS Client Operational log enabled (${newSizeMB}MB)" -ForegroundColor Green
        } else {
            Write-RunLog "DNS Client Operational log already enabled."
            Write-Host "  [OK] Already enabled (${newSizeMB}MB)" -ForegroundColor Green
        }
    } catch {
        Write-RunLog "Failed to enable DNS Client Operational log: $_" -Level "ERROR"
        Write-Host "  [ERROR] Failed: $_" -ForegroundColor Red
    }
}

function Initialize-Sysmon {
    Write-Host "--- Setting Up Sysmon ---" -ForegroundColor Cyan
    Write-RunLog "Checking Sysmon status..."

    $sysmonSvc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
    $isRunning = ($sysmonSvc -and $sysmonSvc.Status -eq "Running")

    if ($isRunning) {
        Write-RunLog "Sysmon is already installed and running. Will update config if changed."
        Write-Host "  [INFO] Sysmon already running — updating configuration..." -ForegroundColor Yellow

        # Write updated config file
        try {
            $SysmonXmlContent | Out-File -FilePath $SysmonConfig -Encoding UTF8 -Force
            Write-RunLog "Sysmon config updated: $SysmonConfig"
        } catch {
            Write-RunLog "Failed to write Sysmon config: $_" -Level "ERROR"
            Write-Host "  [ERROR] Failed to write config" -ForegroundColor Red
            return
        }

        # Reload config: Sysmon64.exe -c <config>
        if (-not (Test-Path $SysmonExe)) {
            Write-RunLog "Sysmon64.exe not found at $SysmonExe, cannot reload config." -Level "WARN"
            Write-Host "  [WARN] Sysmon binary not found, config not reloaded." -ForegroundColor Yellow
            return
        }

        Write-Host "  Reloading Sysmon configuration..." -ForegroundColor Gray
        try {
            $proc = Start-Process -FilePath $SysmonExe `
                -ArgumentList "-c `"$SysmonConfig`"" `
                -NoNewWindow -Wait -PassThru
            if ($proc.ExitCode -eq 0) {
                Write-RunLog "Sysmon config reloaded successfully."
                Write-Host "  [OK] Config reloaded" -ForegroundColor Green
            } else {
                Write-RunLog "Sysmon config reload returned exit code: $($proc.ExitCode)" -Level "WARN"
                Write-Host "  [WARN] Config reload exit code: $($proc.ExitCode)" -ForegroundColor Yellow
            }
        } catch {
            Write-RunLog "Failed to reload Sysmon config: $_" -Level "ERROR"
            Write-Host "  [ERROR] Config reload failed: $_" -ForegroundColor Red
        }
        return
    }

    # Ensure Sysmon directory exists
    if (-not (Test-Path $SysmonDir)) {
        New-Item -ItemType Directory -Path $SysmonDir -Force | Out-Null
        Write-RunLog "Created Sysmon directory: $SysmonDir"
    }

    # Detect scoop availability
    $hasScoop = $null -ne (Get-Command scoop -ErrorAction SilentlyContinue)

    # Helper: acquire Sysmon64.exe via scoop (install sysinternals if needed, then copy)
    function Use-ScoopToAcquire {
        try {
            # Install sysinternals if not already installed
            $scoopList = scoop list 2>&1 | Out-String
            if ($scoopList -notmatch 'sysinternals') {
                Write-Host "  Installing sysinternals via scoop..." -ForegroundColor Gray
                Write-RunLog "Running: scoop install sysinternals"
                scoop install sysinternals 2>&1 | ForEach-Object {
                    Write-Host "    $_" -ForegroundColor Gray
                }
                Write-RunLog "scoop install sysinternals completed."
            } else {
                Write-RunLog "sysinternals already installed via scoop."
            }

            # Locate Sysmon64.exe — try scoop prefix first, then fallback paths
            $prefix = $null
            $raw = scoop prefix sysinternals 2>&1 | Select-Object -Last 1
            if ($raw) { $prefix = $raw.ToString().Trim() }

            $src = $null
            $searchDirs = @()
            if ($prefix -and (Test-Path $prefix)) {
                $searchDirs += $prefix
            }
            $searchDirs += @(
                "$env:USERPROFILE\scoop\apps\sysinternals\current",
                "$env:USERPROFILE\scoop\apps\sysinternals"
            )
            foreach ($dir in $searchDirs) {
                $candidate = Join-Path $dir "Sysmon64.exe"
                if (Test-Path $candidate) { $src = $candidate; break }
            }

            if ($src) {
                Copy-Item $src $SysmonExe -Force
                Write-RunLog "Sysmon64.exe acquired via scoop: $src"
                Write-Host "  [OK] Sysmon64.exe from scoop" -ForegroundColor Green
                return $true
            }
            Write-RunLog "Scoop: sysinternals installed but Sysmon64.exe not located." -Level "WARN"
            return $false
        } catch {
            Write-RunLog "Scoop acquire failed: $_" -Level "WARN"
            return $false
        }
    }

    # Helper: acquire Sysmon64.exe via direct download
    function Use-DirectDownload {
        Write-Host "  Downloading Sysmon from Microsoft Sysinternals..." -ForegroundColor Gray
        Write-RunLog "Downloading Sysmon64.exe..."
        try {
            $sysmonUrl = "https://live.sysinternals.com/Sysmon64.exe"
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $sysmonUrl -OutFile $SysmonExe -ErrorAction Stop
            Write-RunLog "Sysmon64.exe downloaded successfully."
            Write-Host "  [OK] Downloaded" -ForegroundColor Green
            return $true
        } catch {
            Write-RunLog "Direct download failed: $_" -Level "ERROR"
            Write-Host "  [ERROR] Download failed: $_" -ForegroundColor Red
            return $false
        }
    }

    # Check existing binary validity — valid Sysmon64.exe is ~2.5+ MB
    $needAcquire = $true
    if (Test-Path $SysmonExe) {
        $fileInfo = Get-Item $SysmonExe -ErrorAction SilentlyContinue
        if ($fileInfo -and $fileInfo.Length -gt 2097152) {  # > 2 MB
            Write-RunLog "Existing Sysmon64.exe found ($([math]::Round($fileInfo.Length/1MB, 1)) MB), skipping acquire."
            $needAcquire = $false
        } else {
            $sizeStr = if ($fileInfo) { "$($fileInfo.Length) bytes" } else { "unknown" }
            Write-RunLog "Existing Sysmon64.exe is corrupted/incomplete ($sizeStr), will re-acquire."
            Write-Host "  [WARN] Corrupted Sysmon binary ($sizeStr), re-acquiring..." -ForegroundColor Yellow
            Remove-Item $SysmonExe -Force -ErrorAction SilentlyContinue
        }
    }

    # Acquire Sysmon binary
    if ($needAcquire) {
        $acquired = $false
        if ($hasScoop) {
            Write-Host "  [INFO] Scoop detected - using scoop to acquire Sysmon" -ForegroundColor Gray
            Write-RunLog "Scoop detected, acquiring Sysmon via scoop..."
            $acquired = Use-ScoopToAcquire
        }
        if (-not $acquired) {
            if ($hasScoop) {
                Write-Host "  [WARN] Scoop acquire failed, falling back to direct download..." -ForegroundColor Yellow
            }
            $acquired = Use-DirectDownload
        }
        if (-not $acquired) {
            Write-Host "  Please download and install Sysmon manually from:" -ForegroundColor Yellow
            Write-Host "  https://learn.microsoft.com/sysinternals/downloads/sysmon" -ForegroundColor Yellow
            return
        }
    }

    # Write Sysmon config
    try {
        $SysmonXmlContent | Out-File -FilePath $SysmonConfig -Encoding UTF8 -Force
        Write-RunLog "Sysmon config written to: $SysmonConfig"
    } catch {
        Write-RunLog "Failed to write Sysmon config: $_" -Level "ERROR"
        Write-Host "  [ERROR] Failed to write Sysmon config" -ForegroundColor Red
        return
    }

    # Install Sysmon (with retry on failure)
    $maxRetries = 2
    for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
        if ($attempt -gt 1) {
            $retryMsg = "Attempt ${attempt}/${maxRetries} - re-acquiring Sysmon..."
            Write-Host "  [RETRY] $retryMsg" -ForegroundColor Yellow
            Write-RunLog "Retry attempt ${attempt}: re-acquiring Sysmon64.exe..."
            Remove-Item $SysmonExe -Force -ErrorAction SilentlyContinue

            $reacquired = $false
            if ($hasScoop) { $reacquired = Use-ScoopToAcquire }
            if (-not $reacquired) { $reacquired = Use-DirectDownload }
            if (-not $reacquired) { break }
        }

        Write-Host "  Installing Sysmon..." -ForegroundColor Gray
        Write-RunLog "Installing Sysmon (attempt $attempt)..."
        try {
            $proc = Start-Process -FilePath $SysmonExe `
                -ArgumentList "-accepteula -i `"$SysmonConfig`"" `
                -NoNewWindow -Wait -PassThru
            if ($proc.ExitCode -eq 0) {
                Write-RunLog "Sysmon installed successfully."
                Write-Host "  [OK] Sysmon installed and running" -ForegroundColor Green
                return
            } else {
                Write-RunLog "Sysmon installation returned exit code: $($proc.ExitCode)" -Level "WARN"
                Write-Host "  [WARN] Exit code: $($proc.ExitCode)" -ForegroundColor Yellow
            }
        } catch {
            Write-RunLog "Failed to install Sysmon (attempt $attempt): $_" -Level "ERROR"
            Write-Host "  [ERROR] Installation failed: $_" -ForegroundColor Red
            if ($attempt -ge $maxRetries) {
                Write-Host "  Please download and install Sysmon manually from:" -ForegroundColor Yellow
                Write-Host "  https://learn.microsoft.com/sysinternals/downloads/sysmon" -ForegroundColor Yellow
            }
        }
    }
}

function Initialize-DirectoryStructure {
    Write-Host "--- Creating Directory Structure ---" -ForegroundColor Cyan
    Write-RunLog "Creating directory structure..."

    $dirs = @($LogRootDir, $LogsDir, $ScriptsDir, $SysmonLogDir, $TrafficEtlDir)
    foreach ($dir in $dirs) {
        if (-not (Test-Path $dir)) {
            try {
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
                Write-RunLog "Created directory: $dir"
                Write-Host "  [OK] Created: $dir" -ForegroundColor Green
            } catch {
                Write-RunLog "Failed to create directory [$dir]: $_" -Level "ERROR"
                Write-Host "  [ERROR] Failed: $dir" -ForegroundColor Red
            }
        } else {
            Write-Host "  [INFO] Exists: $dir" -ForegroundColor Gray
        }
    }

    # Copy script to deployment directory (self-copy)
    $selfPath = if ($PSScriptRoot) {
        Join-Path $PSScriptRoot $ScriptName
    } else {
        $PSCommandPath
    }
    $destScript = Join-Path $ScriptsDir $ScriptName

    try {
        Copy-Item -Path $selfPath -Destination $destScript -Force -ErrorAction Stop
        Write-RunLog "Script copied to deployment directory: $destScript"
        Write-Host "  [OK] Script deployed to: $ScriptsDir" -ForegroundColor Green
    } catch {
        Write-RunLog "Failed to copy script: $_" -Level "WARN"
    }
}

function Initialize-TaskScheduler {
    Write-Host "--- Registering Windows Task Scheduler ---" -ForegroundColor Cyan
    Write-RunLog "Registering scheduled task: $TaskName..."

    $scriptPath = Join-Path $ScriptsDir $ScriptName
    $action = New-ScheduledTaskAction `
        -Execute "powershell.exe" `
        -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`" -Mode Export"

    # Trigger 1: Daily at configured time
    $timeParts = $DailyRunTime -split ":"
    $hour = [int]$timeParts[0]
    $minute = [int]$timeParts[1]
    $trigger1 = New-ScheduledTaskTrigger -Daily -At "$($hour.ToString('00')):$($minute.ToString('00'))"

    # Trigger 2: At system startup (delay 1 minute)
    $trigger2 = New-ScheduledTaskTrigger -AtStartup -RandomDelay (New-TimeSpan -Minutes 1)

    # Settings
    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -RunOnlyIfNetworkAvailable:$false `
        -RestartCount:3 `
        -RestartInterval:(New-TimeSpan -Minutes 10) `
        -ExecutionTimeLimit:(New-TimeSpan -Minutes 10) `
        -MultipleInstances "IgnoreNew"

    # Principal: SYSTEM account, run whether user is logged on or not
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    try {
        # Remove existing task if present
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

        Register-ScheduledTask `
            -TaskName $TaskName `
            -Action $action `
            -Trigger @($trigger1, $trigger2) `
            -Settings $settings `
            -Principal $principal `
            -Description "NetLedger Network Monitor - Daily log collection and report generation" `
            -ErrorAction Stop

        Write-RunLog "Scheduled task registered: $TaskName"
        Write-Host "  [OK] Scheduled task registered" -ForegroundColor Green
    } catch {
        Write-RunLog "Failed to register scheduled task: $_" -Level "ERROR"
        Write-Host "  [ERROR] Failed to register task: $_" -ForegroundColor Red
    }

    # --- Standalone boot task: ensure the ETW traffic session is running ASAP
    # after every reboot. This task only runs `logman start` and is independent
    # of the daily Export task so traffic capture resumes within ~30s of boot
    # rather than waiting until the next 00:30 run.
    try {
        $trafficAction = New-ScheduledTaskAction `
            -Execute "logman.exe" `
            -Argument "start $TrafficSessionName"

        # Boot trigger with a short delay (kernel networking + logman service must be up first)
        $trafficTrigger = New-ScheduledTaskTrigger -AtStartup -RandomDelay (New-TimeSpan -Seconds 30)

        $trafficSettings = New-ScheduledTaskSettingsSet `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -StartWhenAvailable `
            -RestartCount:3 `
            -RestartInterval:(New-TimeSpan -Minutes 5) `
            -ExecutionTimeLimit:(New-TimeSpan -Minutes 2) `
            -MultipleInstances "IgnoreNew"

        $trafficPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

        # Remove existing task if present
        Unregister-ScheduledTask -TaskName $TrafficTaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask `
            -TaskName $TrafficTaskName `
            -Action $trafficAction `
            -Trigger $trafficTrigger `
            -Settings $trafficSettings `
            -Principal $trafficPrincipal `
            -Description "NetLedger - restart the ETW traffic trace session at every boot" `
            -ErrorAction Stop | Out-Null

        Write-RunLog "Boot task for traffic session registered: $TrafficTaskName"
        Write-Host "  [OK] Boot task registered for ETW session: $TrafficTaskName" -ForegroundColor Green
    } catch {
        Write-RunLog "Failed to register traffic boot task: $_" -Level "WARN"
        Write-Host "  [WARN] Failed to register traffic boot task: $_" -ForegroundColor Yellow
    }
}

function Initialize-Readme {
    Write-Host "--- Creating README.txt ---" -ForegroundColor Cyan
    Write-RunLog "Creating README.txt..."

    $readmeContent = @"
================================================================
  NetLedger - Windows Network Traffic Monitor
  网络流量监控日志归集系统
================================================================

Installation Directory: $LogRootDir

Directory Structure:
  logs\        - Daily collected log files
  scripts\     - Monitor scripts
  sysmon\      - Sysmon binaries and config

Daily Report Files:
  Format: yyyy-MM-dd.txt
  Encoding: UTF-8 (with BOM)
  Location: $LogsDir\

How to Use:
  1. First-time setup (run as Administrator):
     powershell -ExecutionPolicy Bypass -File "$ScriptsDir\$ScriptName" -Mode Init

  2. Manual collection:
     powershell -ExecutionPolicy Bypass -File "$ScriptsDir\$ScriptName" -Mode Export

  3. Check status:
     powershell -ExecutionPolicy Bypass -File "$ScriptsDir\$ScriptName" -Mode Status

  4. Uninstall (run as Administrator):
     powershell -ExecutionPolicy Bypass -File "$ScriptsDir\Uninstall-NetworkMonitor.ps1"

Scheduled Task:
  Task Name: $TaskName
  Triggers:  Daily at $DailyRunTime + At system startup
  Account:   SYSTEM

Log Retention: $RetentionDays days (auto-cleanup)

For detailed documentation, see the project docs/ directory.

================================================================
"@
    try {
        $readmeContent | Out-File -FilePath $ReadmeFile -Encoding UTF8 -Force
        Write-Host "  [OK] README.txt created" -ForegroundColor Green
    } catch {
        Write-RunLog "Failed to create README.txt: $_" -Level "WARN"
    }
}

# ==================================================================
#  ETW TRAFFIC SESSION MANAGEMENT
#  Persistent real-time trace session logging every TCP/UDP Send/Recv
#  with byte counts + owning PID, so the daily report can attribute
#  traffic to the process that actually consumed it.
# ==================================================================

function Test-TrafficSessionExists {
    # Returns $true if the logman trace session is registered (Running or Stopped)
    try {
        $null = logman query -name $TrafficSessionName 2>&1
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    }
}

function Test-TrafficSessionRunning {
    try {
        $query = logman query -name $TrafficSessionName 2>&1 | Out-String
        return ($query -match 'Running|运行')
    } catch {
        return $false
    }
}

function Initialize-TrafficSession {
    Write-Host "--- Setting Up ETW Traffic Capture Session ---" -ForegroundColor Cyan
    Write-RunLog "Initializing ETW traffic session [$TrafficSessionName]..."

    # Ensure traffic directory exists
    if (-not (Test-Path $TrafficEtlDir)) {
        try {
            New-Item -ItemType Directory -Path $TrafficEtlDir -Force | Out-Null
            Write-RunLog "Created traffic ETL directory: $TrafficEtlDir"
        } catch {
            Write-RunLog "Failed to create traffic directory: $_" -Level "ERROR"
            Write-Host "  [ERROR] Failed: $_" -ForegroundColor Red
            return
        }
    }

    # NOTE: no fixed ETL path here — logman appends a version suffix
    # (traffic_000001.etl), so all consumers glob traffic*.etl instead.

    # If a previous session exists, restart with current config
    if (Test-TrafficSessionExists) {
        Write-Host "  [INFO] Session already registered — recreating with current config..." -ForegroundColor Yellow
        try { logman stop $TrafficSessionName 2>&1 | Out-Null } catch { }
        try { logman delete $TrafficSessionName 2>&1 | Out-Null } catch { }
        Start-Sleep -Milliseconds 800  # let the old ETL file handle release
    }

    # Leftover live ETLs from a previous session make `logman start` fail with
    # ERROR_ALREADY_EXISTS ("当文件已存在时，无法创建该文件") — logman appends a
    # version suffix (traffic_000001.etl) and refuses to reuse the file. Move
    # them into timestamped archives; the next Export will parse and delete them.
    $leftovers = @(Get-ChildItem -Path (Join-Path $TrafficEtlDir "traffic*.etl") -ErrorAction SilentlyContinue |
                   Where-Object { $_.Name -notmatch '^traffic-' })
    if ($leftovers.Count -gt 0) {
        $stamp = [DateTime]::Now.ToString('yyyyMMddHHmmss')
        $n = 0
        foreach ($lf in $leftovers) {
            $n++
            try {
                Move-Item -Path $lf.FullName -Destination (Join-Path $TrafficEtlDir "traffic-$stamp-$n.etl") -Force -ErrorAction Stop
            } catch {
                Write-RunLog "Could not archive leftover ETL $($lf.Name): $_" -Level "WARN"
            }
        }
        Write-RunLog "Archived $n leftover live ETL file(s) to unblock logman start."
    }

    # Create persistent trace session:
    #   -pf <file>     : enable MULTIPLE providers via a text file (logman does NOT
    #                    accept two -p flags on the same command — "参数'p'定义的次数过多").
    #                    File format: one provider per line as "<Name> <Keywords> <Level>"
    #   -f bincirc     : binary circular log format — universally supported across
    #                    all logman versions (the shorter -ctw flag is rejected on
    #                    some localized Windows builds with "参数'ctw'未知").
    #   -max <MB>      : max file size before wrap-around
    #   -o <path>      : ETL output (without extension; logman appends .etl)
    #   -ets is NOT used — we want the session persisted in the registry so it
    #   survives reboots and can be re-started by the boot task.
    $providersFile = Join-Path $TrafficEtlDir "providers.txt"
    $netKW  = '0x{0:X}' -f $TrafficNetworkKW
    $procKW = '0x{0:X}' -f $TrafficProcessKW
    $providerLines = @(
        "Microsoft-Windows-Kernel-Network $netKW $($TrafficNetworkLV)",
        "Microsoft-Windows-Kernel-Process $procKW $($TrafficProcessLV)"
    )
    try {
        $providerLines | Out-File -FilePath $providersFile -Encoding ASCII -Force
        Write-RunLog "Wrote providers.txt with $($providerLines.Count) providers."
    } catch {
        Write-RunLog "Failed to write providers.txt: $_" -Level "ERROR"
        Write-Host "  [ERROR] $_" -ForegroundColor Red
        return
    }

    $etlBasePath = Join-Path $TrafficEtlDir "traffic"
    # NOTE: avoid $args — it's a PowerShell automatic variable (collides with the
    # function's implicit args array). Use $lmArgs instead.
    $lmArgs = @(
        "create", "trace", $TrafficSessionName,
        "-pf", $providersFile,
        "-o", $etlBasePath,
        "-f", "bincirc",
        "-max", $TrafficEtlMaxMB
    )
    Write-RunLog "Running: logman $($lmArgs -join ' ')"
    $createOut = & logman @lmArgs 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        Write-RunLog "logman create failed (exit=$LASTEXITCODE): $createOut" -Level "ERROR"
        Write-Host "  [ERROR] logman create failed: $createOut" -ForegroundColor Red
        Write-Host "         Try manually: logman create trace $TrafficSessionName -pf `"$providersFile`" -o `"$etlBasePath`" -f bincirc -max $TrafficEtlMaxMB" -ForegroundColor Yellow
        return
    }
    Write-RunLog "logman trace session created."

    # Start the session
    $startOut = & logman start $TrafficSessionName 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        Write-RunLog "logman start failed (exit=$LASTEXITCODE): $startOut" -Level "ERROR"
        Write-Host "  [ERROR] logman start failed: $startOut" -ForegroundColor Red
        return
    }
    # logman appends a version suffix, so the live file is traffic_000001.etl
    Write-RunLog "ETW traffic session started. ETL: $etlBasePath`_NNNNNN.etl (max $TrafficEtlMaxMB MB, circular)"
    Write-Host "  [OK] ETW traffic session started" -ForegroundColor Green
    Write-Host "       ETL: $etlBasePath`_NNNNNN.etl (max ${TrafficEtlMaxMB}MB circular)" -ForegroundColor Gray
}

function Ensure-TrafficSession {
    # Idempotent guard: if the session isn't running (e.g. after a reboot the boot
    # task hasn't fired yet, or someone stopped it), start it. Called at the head
    # of Export to guarantee there's always data to archive.
    if (-not (Test-TrafficSessionExists)) {
        Write-RunLog "Traffic session [$TrafficSessionName] not registered — skipping Ensure (run Init first)." -Level "WARN"
        return $false
    }
    if (Test-TrafficSessionRunning) {
        return $true
    }
    Write-RunLog "Traffic session not running — starting..."
    try {
        & logman start $TrafficSessionName 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-RunLog "Traffic session started by Ensure-TrafficSession."
            return $true
        }

        # Most common failure: leftover live ETLs block the start with
        # ERROR_ALREADY_EXISTS. Archive them (Export will parse the archives)
        # and retry once.
        Write-RunLog "logman start returned exit code $LASTEXITCODE — archiving leftover ETLs and retrying..." -Level "WARN"
        $leftovers = @(Get-ChildItem -Path (Join-Path $TrafficEtlDir "traffic*.etl") -ErrorAction SilentlyContinue |
                       Where-Object { $_.Name -notmatch '^traffic-' })
        $stamp = [DateTime]::Now.ToString('yyyyMMddHHmmss')
        $n = 0
        foreach ($lf in $leftovers) {
            $n++
            try {
                Move-Item -Path $lf.FullName -Destination (Join-Path $TrafficEtlDir "traffic-$stamp-$n.etl") -Force -ErrorAction Stop
            } catch { }
        }
        & logman start $TrafficSessionName 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-RunLog "Traffic session started after archiving $n leftover ETL(s)."
            return $true
        }
        Write-RunLog "logman start still failing (exit code $LASTEXITCODE)." -Level "WARN"
        return $false
    } catch {
        Write-RunLog "Ensure-TrafficSession exception: $_" -Level "WARN"
        return $false
    }
}

# ==================================================================
#  DATA COLLECTION FUNCTIONS
# ==================================================================

function Get-Security5156 {
    param([DateTime]$StartTime, [DateTime]$EndTime)
    try {
        Write-RunLog "Collecting Security Event 5156 (Network Connection)..."
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = "Security"
            ID        = 5156
            StartTime = $StartTime
            EndTime   = $EndTime
        } -ErrorAction Stop -MaxEvents 50000

        $results = @()
        foreach ($evt in $events) {
            $xml = [xml]$evt.ToXml()
            $data = @{}
            $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }

            $direction = if ([int]$data.Direction -eq 1) { "入站" } else { "出站" }

            $results += [PSCustomObject]@{
                Time      = $evt.TimeCreated
                ProcessId = $data.ProcessId
                AppName   = if ($data.Application) { Split-Path $data.Application -Leaf } else { "PID:$($data.ProcessId)" }
                AppPath   = $data.Application
                Direction = $direction
                DestIP    = $data.DestAddress
                DestPort  = $data.DestPort
                Protocol  = $data.Protocol
                LayerName = $data.LayerName
            }
        }
        Write-RunLog "  Collected $($results.Count) network connection events."
        return $results
    } catch {
        Write-RunLog "Failed to collect Security 5156 events: $_" -Level "WARN"
        return @()
    }
}

function Get-Security4688 {
    param([DateTime]$StartTime, [DateTime]$EndTime)
    try {
        Write-RunLog "Collecting Security Event 4688 (Process Creation)..."
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = "Security"
            ID        = 4688
            StartTime = $StartTime
            EndTime   = $EndTime
        } -ErrorAction Stop -MaxEvents 10000

        $results = @()
        foreach ($evt in $events) {
            $xml = [xml]$evt.ToXml()
            $data = @{}
            $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }

            $results += [PSCustomObject]@{
                Time             = $evt.TimeCreated
                NewProcessName   = $data.NewProcessName
                CommandLine      = $data.CommandLine
                ParentProcessName = $data.ParentProcessName
                ProcessId        = $data.NewProcessId
            }
        }
        Write-RunLog "  Collected $($results.Count) process creation events."
        return $results
    } catch {
        Write-RunLog "Failed to collect Security 4688 events: $_" -Level "WARN"
        return @()
    }
}

function Get-DNS3008 {
    param([DateTime]$StartTime, [DateTime]$EndTime)
    try {
        # ---- Step 1: Collect Event 3006 (query initiation, has ProcessId) ----
        Write-RunLog "Collecting DNS Client Event 3006 (DNS Query with ProcessId)..."
        $events3006 = Get-WinEvent -FilterHashtable @{
            LogName   = "Microsoft-Windows-DNS-Client/Operational"
            ID        = 3006
            StartTime = $StartTime
            EndTime   = $EndTime
        } -ErrorAction Stop -MaxEvents 50000

        # Build lookup: key = "Domain|QueryType" (earliest match) -> ProcessId
        $dnsProcessMap = @{}
        $allPids = @()
        foreach ($evt in $events3006) {
            $xml = [xml]$evt.ToXml()
            $data = @{}
            $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }

            $domain    = $data.QueryName
            $queryType = $data.QueryType
            $processId = try { [int]$data.ProcessId } catch { 0 }
            $time      = $evt.TimeCreated

            if (-not $domain) { continue }

            $key = "$domain|$queryType"
            # Keep the first occurrence (earliest) for this query key
            if (-not $dnsProcessMap.ContainsKey($key)) {
                $dnsProcessMap[$key] = @{
                    ProcessId  = $processId
                    FirstSeen  = $time
                }
                if ($processId -gt 0) { $allPids += $processId }
            }
        }
        Write-RunLog "  Collected $($events3006.Count) DNS 3006 events, mapped $($dnsProcessMap.Count) unique query keys."

        # ---- Step 2: Bulk-resolve PIDs to process names ----
        if ($allPids.Count -gt 0) {
            Initialize-ProcessNameCache -Pids $allPids
        }

        # ---- Step 3: Collect Event 3008 (query result) ----
        Write-RunLog "Collecting DNS Client Event 3008 (DNS Query Result)..."
        $events3008 = Get-WinEvent -FilterHashtable @{
            LogName   = "Microsoft-Windows-DNS-Client/Operational"
            ID        = 3008
            StartTime = $StartTime
            EndTime   = $EndTime
        } -ErrorAction Stop -MaxEvents 50000

        $results = @()
        foreach ($evt in $events3008) {
            $xml = [xml]$evt.ToXml()
            $data = @{}
            $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }

            $domain    = $data.QueryName
            $rawType   = $data.QueryType
            $result    = $data.QueryResults

            $queryType = switch ($rawType) {
                "1"  { "A" }
                "28" { "AAAA" }
                "5"  { "CNAME" }
                "15" { "MX" }
                "16" { "TXT" }
                "2"  { "NS" }
                "12" { "PTR" }
                "33" { "SRV" }
                default { "TYPE:$rawType" }
            }

            # ---- Merge with process info from Event 3006 ----
            $key = "$domain|$rawType"
            $processId   = 0
            $processName = "Unknown"

            if ($dnsProcessMap.ContainsKey($key)) {
                $procInfo = $dnsProcessMap[$key]
                $processId = $procInfo.ProcessId
                $processName = Get-ProcessNameByPID -ProcId $processId
            }

            $results += [PSCustomObject]@{
                Time        = $evt.TimeCreated
                Domain      = $domain
                QueryType   = $queryType
                Result      = $result
                ProcessId   = $processId
                ProcessName = $processName
            }
        }
        Write-RunLog "  Collected $($results.Count) DNS query events (merged with process info)."
        return $results
    } catch {
        Write-RunLog "Failed to collect DNS events: $_" -Level "WARN"
        return @()
    }
}

function Get-Sysmon1 {
    param([DateTime]$StartTime, [DateTime]$EndTime)
    if (-not (Test-SysmonAvailable)) {
        Write-RunLog "Sysmon not running, skipping Sysmon Event 1." -Level "WARN"
        return @()
    }
    try {
        Write-RunLog "Collecting Sysmon Event 1 (Process Creation)..."
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = "Microsoft-Windows-Sysmon/Operational"
            ID        = 1
            StartTime = $StartTime
            EndTime   = $EndTime
        } -ErrorAction Stop -MaxEvents 10000

        $results = @()
        foreach ($evt in $events) {
            $xml = [xml]$evt.ToXml()
            $data = @{}
            $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }

            $results += [PSCustomObject]@{
                Time       = $evt.TimeCreated
                Image      = $data.Image
                CommandLine = $data.CommandLine
                ParentImage = $data.ParentImage
                User       = $data.User
            }
        }
        Write-RunLog "  Collected $($results.Count) Sysmon process creation events."
        return $results
    } catch {
        Write-RunLog "Failed to collect Sysmon 1 events: $_" -Level "WARN"
        return @()
    }
}

function Get-Sysmon3 {
    param([DateTime]$StartTime, [DateTime]$EndTime)
    if (-not (Test-SysmonAvailable)) {
        Write-RunLog "Sysmon not running, skipping Sysmon Event 3." -Level "WARN"
        return @()
    }
    try {
        Write-RunLog "Collecting Sysmon Event 3 (Network Connection)..."
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = "Microsoft-Windows-Sysmon/Operational"
            ID        = 3
            StartTime = $StartTime
            EndTime   = $EndTime
        } -ErrorAction Stop -MaxEvents 50000

        $results = @()
        foreach ($evt in $events) {
            $xml = [xml]$evt.ToXml()
            $data = @{}
            $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }

            $direction = if ($data.Initiated -eq "true") { "出站" } else { "入站" }

            $results += [PSCustomObject]@{
                Time        = $evt.TimeCreated
                Image       = $data.Image
                ProcessName = if ($data.Image) { Split-Path $data.Image -Leaf } else { "Unknown" }
                Direction   = $direction
                DestIP      = $data.DestinationIp
                DestPort    = $data.DestinationPort
                Protocol    = $data.Protocol
            }
        }
        Write-RunLog "  Collected $($results.Count) Sysmon network connection events."
        return $results
    } catch {
        Write-RunLog "Failed to collect Sysmon 3 events: $_" -Level "WARN"
        return @()
    }
}

function Get-Sysmon11 {
    param([DateTime]$StartTime, [DateTime]$EndTime)
    if (-not (Test-SysmonAvailable)) {
        Write-RunLog "Sysmon not running, skipping Sysmon Event 11." -Level "WARN"
        return @()
    }
    try {
        Write-RunLog "Collecting Sysmon Event 11 (File Creation)..."
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = "Microsoft-Windows-Sysmon/Operational"
            ID        = 11
            StartTime = $StartTime
            EndTime   = $EndTime
        } -ErrorAction Stop -MaxEvents 10000

        $results = @()
        foreach ($evt in $events) {
            $xml = [xml]$evt.ToXml()
            $data = @{}
            $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }

            $results += [PSCustomObject]@{
                Time         = $evt.TimeCreated
                Image        = $data.Image
                ProcessName  = if ($data.Image) { Split-Path $data.Image -Leaf } else { "Unknown" }
                TargetFile   = $data.TargetFilename
            }
        }
        Write-RunLog "  Collected $($results.Count) Sysmon file creation events."
        return $results
    } catch {
        Write-RunLog "Failed to collect Sysmon 11 events: $_" -Level "WARN"
        return @()
    }
}

function Get-TrafficBytes {
    param([DateTime]$StartTime, [DateTime]$EndTime)
    <#
        .SYNOPSIS
        Archives the live ETW traffic ETL, restarts the session, then parses the
        archived ETL to extract per-event Send/Recv bytes with owning PID.
        .DESCRIPTION
        Workflow:
          1. If the trace session is running: stop it, move ALL live traffic*.etl
             files to timestamped archives (logman appends version suffixes like
             traffic_000001.etl — never assume a fixed name), restart the session.
             Also picks up orphaned traffic-*.etl archives from previous runs.
          2. Parse the archived ETL(s) with Get-WinEvent to extract:
             - Microsoft-Windows-Kernel-Network TCP/UDP Send (10/26/42/58) and
               Recv (11/27/43/59) events → bytes + PID (from event PAYLOAD;
               the event header PID is the kernel's, always 4/System)
             - Microsoft-Windows-Kernel-Process Event 5/1 (ImageLoad/ProcessStart) → PID -> ImagePath
          3. Returns one PSCustomObject per Send/Recv event, filtered to [StartTime, EndTime].
        .OUTPUTS
        [PSCustomObject[]] with Time/PID/ProcessName/Direction/Bytes
    #>
    try {
        Write-RunLog "Collecting ETW traffic data (Kernel-Network Send/Recv)..."

        # Live ETL discovery: logman appends a version suffix by default, so the
        # live file is traffic_000001.etl (NOT traffic.etl). Glob traffic*.etl and
        # exclude our own timestamped archives (traffic-<stamp>-<n>.etl).
        $getLiveEtls = {
            @(Get-ChildItem -Path (Join-Path $TrafficEtlDir "traffic*.etl") -ErrorAction SilentlyContinue |
              Where-Object { $_.Name -notmatch '^traffic-' })
        }

        # ---- Step 1: archive the live ETL(s) and restart the session ----
        $archiveEtls = @()
        $sessionExists = Test-TrafficSessionExists

        if ($sessionExists -and (Test-TrafficSessionRunning)) {
            Write-RunLog "  Stopping traffic session to archive ETL..."
            & logman stop $TrafficSessionName 2>&1 | Out-Null
            Start-Sleep -Milliseconds 800  # let the ETL file handle release
        }

        $liveEtls = & $getLiveEtls
        if ($liveEtls.Count -eq 0) {
            Write-RunLog "  No live traffic*.etl under $TrafficEtlDir (first run after Init?)" -Level "WARN"
        }
        $stamp = [DateTime]::Now.ToString('yyyyMMddHHmmss')
        $idx = 0
        foreach ($live in $liveEtls) {
            $idx++
            $dest = Join-Path $TrafficEtlDir "traffic-$stamp-$idx.etl"
            try {
                Move-Item -Path $live.FullName -Destination $dest -Force -ErrorAction Stop
                $archiveEtls += $dest
                Write-RunLog "  Archived ETL: $dest"
            } catch {
                Write-RunLog "  Move failed, trying copy: $_" -Level "WARN"
                try {
                    Copy-Item -Path $live.FullName -Destination $dest -Force -ErrorAction Stop
                    Remove-Item -Path $live.FullName -Force -ErrorAction SilentlyContinue
                    $archiveEtls += $dest
                } catch {
                    Write-RunLog "  Copy also failed, reading in place: $_" -Level "WARN"
                    $archiveEtls += $live.FullName
                }
            }
        }

        if ($sessionExists) {
            # Restart the session to resume capture for the next interval
            # (live files were moved away first — otherwise logman start fails
            # with ERROR_ALREADY_EXISTS)
            & logman start $TrafficSessionName 2>&1 | Out-Null
            Write-RunLog "  Traffic session restarted."
        }

        # Pick up orphaned archives (e.g. files archived by Init to unblock
        # logman start, or left behind if a previous Export crashed mid-parse)
        $orphans = @(Get-ChildItem -Path (Join-Path $TrafficEtlDir "traffic-*.etl") -ErrorAction SilentlyContinue |
                     Where-Object { $archiveEtls -notcontains $_.FullName })
        foreach ($o in $orphans) {
            Write-RunLog "  Picking up orphaned archive: $($o.Name)"
            $archiveEtls += $o.FullName
        }

        if ($archiveEtls.Count -eq 0) {
            Write-RunLog "  No ETL data to parse. Run -Mode Init first if the session is missing." -Level "WARN"
            return @()
        }

        # ---- Step 2: parse the archived ETL(s) ----
        # Kernel-Network manifest event IDs (verified against a live capture —
        # this provider does NOT use 3/4 for send/recv):
        #   TCPv4 send/recv = 10/11    TCPv6 send/recv = 26/27
        #   UDPv4 send/recv = 42/43    UDPv6 send/recv = 58/59
        # 18 (TCP copy) is deliberately excluded — it would double-count bytes.
        $sendIds = @(10, 26, 42, 58)
        $recvIds = @(11, 27, 43, 59)

        $pidNameMap = @{}        # PID -> process name (from Kernel-Process ImageLoad)
        $trafficEvents = [System.Collections.Generic.List[object]]::new()

        foreach ($archiveEtl in $archiveEtls) {
            Write-RunLog "  Parsing ETL: $archiveEtl"
            $events = $null
            try {
                # Cap to 1M events per file to bound memory
                $events = Get-WinEvent -Path $archiveEtl -Oldest -MaxEvents 1000000 -ErrorAction Stop
            } catch {
                if ($_.Exception.Message -match 'No events were found|没有事件') {
                    Write-RunLog "  ETL was empty: $archiveEtl"
                } else {
                    Write-RunLog "  Failed to parse ETL ${archiveEtl}: $_" -Level "WARN"
                }
                continue
            }

            foreach ($evt in $events) {
                $provName = $evt.ProviderName
                $evtId    = $evt.Id

                # ---- Kernel-Process ImageLoad / ProcessStart: build PID -> ProcessName ----
                # Event ID 5 is Image Load (DLL/exe mapped into a process) — it carries
                # ProcessID + ImageFileName, the most reliable source of "PID -> name"
                # for processes that started BEFORE the trace session began.
                if ($provName -match 'Kernel-Process|KernelProcess') {
                    if ($evtId -eq 5 -or $evtId -eq 1) {
                        try {
                            $xml = [xml]$evt.ToXml()
                            $data = @{}
                            $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }

                            $procId = 0
                            foreach ($k in @('ProcessID','ProcessId','PID')) {
                                if ($data[$k]) { try { $procId = [int]$data[$k]; break } catch { } }
                            }
                            if ($procId -eq 0 -and $evt.ProcessId) { $procId = [int]$evt.ProcessId }

                            $imgPath = $null
                            foreach ($k in @('ImageFileName','ImageName','FileName','ImagePath','Image','ImageBase')) {
                                if ($data[$k]) { $imgPath = $data[$k]; break }
                            }

                            # Event 5 (ImageLoad) fires for every DLL mapped into the
                            # process — only the .exe image identifies the process itself
                            # (verified: without this filter PIDs get labelled with DLL names)
                            if ($procId -gt 0 -and $imgPath -and $imgPath -match '\.exe$' -and -not $pidNameMap.ContainsKey($procId)) {
                                $pidNameMap[$procId] = (Split-Path -Leaf $imgPath)
                            }
                        } catch { }
                    }
                    continue
                }

                # ---- Kernel-Network Send / Recv: the bytes we want ----
                if ($provName -match 'Kernel-Network|KernelNetwork') {
                    $isSend = $sendIds -contains $evtId
                    if ($isSend -or ($recvIds -contains $evtId)) {
                        # Filter to the requested time range first (cheap)
                        if ($evt.TimeCreated -lt $StartTime -or $evt.TimeCreated -gt $EndTime) {
                            continue
                        }
                        try {
                            $xml = [xml]$evt.ToXml()
                            $data = @{}
                            $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }

                            $size = [long]0
                            foreach ($k in @('size','Size','bytes','Bytes','sizebytes','ByteCount')) {
                                if ($data[$k]) { try { $size = [long]$data[$k]; break } catch { } }
                            }

                            # Owning PID lives in the PAYLOAD. The event header PID is
                            # the kernel's (always 4 = System) — never fall back to it.
                            $procId = 0
                            foreach ($k in @('PID','ProcessID','ProcessId')) {
                                if ($data[$k]) { try { $procId = [int]$data[$k]; break } catch { } }
                            }

                            $trafficEvents.Add([PSCustomObject]@{
                                Time        = $evt.TimeCreated
                                PID         = $procId
                                ProcessName = ""
                                Direction   = if ($isSend) { "Sent" } else { "Recv" }
                                Bytes       = $size
                            })
                        } catch { }
                    }
                }
            }
        }
        Write-RunLog "  Parsed $($trafficEvents.Count) Send/Recv events (PID map size: $($pidNameMap.Count))."

        # ---- Step 3: attach process names ----
        foreach ($evt in $trafficEvents) {
            if ($pidNameMap.ContainsKey($evt.PID)) {
                $evt.ProcessName = $pidNameMap[$evt.PID]
            } else {
                $evt.ProcessName = Get-ProcessNameByPID -ProcId $evt.PID
            }
        }

        # Cleanup: delete the archived ETLs after successful parse to bound disk usage
        # (the live ETL is the source of truth for the next interval)
        foreach ($archiveEtl in $archiveEtls) {
            try {
                Remove-Item -Path $archiveEtl -Force -ErrorAction SilentlyContinue
            } catch { }
        }

        return $trafficEvents
    } catch [System.Exception] {
        Write-RunLog "Failed to collect traffic data: $_" -Level "WARN"
        return @()
    }
}

# ==================================================================
#  STATISTICS FUNCTIONS
# ==================================================================

function Get-ConnectionStats {
    param(
        [object[]]$Security5156,
        [object[]]$Sysmon3
    )
    $allConn = @($Security5156) + @($Sysmon3)
    $outbound = ($allConn | Where-Object { $_.Direction -eq "出站" }).Count
    $inbound  = ($allConn | Where-Object { $_.Direction -eq "入站" }).Count
    $uniqueIPs = ($allConn | Where-Object { $_.DestIP } | Select-Object -ExpandProperty DestIP -Unique).Count

    return @{
        TotalConn   = $allConn.Count
        Outbound    = $outbound
        Inbound     = $inbound
        UniqueIPs   = $uniqueIPs
    }
}

function Get-Top10ProcessByConnection {
    param([object[]]$Security5156, [object[]]$Sysmon3)
    $allConn = @($Security5156) + @($Sysmon3)
    $grouped = $allConn | Where-Object { $_.ProcessName -or $_.AppName } | Group-Object {
        if ($_.ProcessName) { $_.ProcessName } else { $_.AppName }
    } | Sort-Object Count -Descending | Select-Object -First 10

    $results = @()
    foreach ($grp in $grouped) {
        $conns = $grp.Group
        $outCount = ($conns | Where-Object { $_.Direction -eq "出站" }).Count
        $inCount  = ($conns | Where-Object { $_.Direction -eq "入站" }).Count
        $ipCount  = ($conns | Where-Object { $_.DestIP } | Select-Object -ExpandProperty DestIP -Unique).Count

        $results += [PSCustomObject]@{
            Rank        = 0
            ProcessName = $grp.Name
            TotalConn   = $grp.Count
            Outbound    = $outCount
            Inbound     = $inCount
            UniqueIPs   = $ipCount
        }
    }
    for ($i = 0; $i -lt $results.Count; $i++) { $results[$i].Rank = $i + 1 }
    return $results
}

function Get-Top10ProcessByTraffic {
    param([object[]]$TrafficEvents)
    <#
        .SYNOPSIS
        Aggregate Send/Recv events per process, rank by total bytes.
        .OUTPUTS
        [PSCustomObject[]] with Rank/ProcessName/SentBytes/RecvBytes/TotalBytes/EventCount/Percent
    #>
    if (-not $TrafficEvents -or $TrafficEvents.Count -eq 0) { return @() }

    # Aggregate per process name (PID may repeat with different names if a PID was reused,
    # but ProcessName is the stable user-facing label)
    $agg = @{}
    $grandTotal = [long]0
    foreach ($e in $TrafficEvents) {
        $name = if ($e.ProcessName) { $e.ProcessName } else { "PID:$($e.PID)" }
        if (-not $agg.ContainsKey($name)) {
            $agg[$name] = @{ Sent = [long]0; Recv = [long]0; Count = 0 }
        }
        if ($e.Direction -eq "Sent") {
            $agg[$name].Sent += [long]$e.Bytes
        } else {
            $agg[$name].Recv += [long]$e.Bytes
        }
        $agg[$name].Count++
        $grandTotal += [long]$e.Bytes
    }

    $results = @()
    foreach ($k in $agg.Keys) {
        $total = $agg[$k].Sent + $agg[$k].Recv
        $pct = if ($grandTotal -gt 0) { [math]::Round(($total / $grandTotal) * 100, 2) } else { 0 }
        $results += [PSCustomObject]@{
            Rank         = 0
            ProcessName  = $k
            SentBytes    = $agg[$k].Sent
            RecvBytes    = $agg[$k].Recv
            TotalBytes   = $total
            EventCount   = $agg[$k].Count
            Percent      = $pct
        }
    }

    $results = $results | Sort-Object TotalBytes -Descending | Select-Object -First 10
    for ($i = 0; $i -lt $results.Count; $i++) { $results[$i].Rank = $i + 1 }
    return $results
}

function Get-Top10Domain {
    param([object[]]$DNS3008)
    $grouped = $DNS3008 | Where-Object { $_.Domain } | Group-Object Domain | Sort-Object Count -Descending | Select-Object -First 10

    $results = @()
    foreach ($grp in $grouped) {
        $procs = ($grp.Group | Where-Object { $_.ProcessName -and $_.ProcessName -ne "Unknown" } | Select-Object -ExpandProperty ProcessName -Unique | Select-Object -First 3) -join ', '
        if (-not $procs) { $procs = "-" }

        $results += [PSCustomObject]@{
            Rank        = 0
            Domain      = $grp.Name
            QueryCount  = $grp.Count
            ProcessName = $procs
        }
    }
    for ($i = 0; $i -lt $results.Count; $i++) { $results[$i].Rank = $i + 1 }
    return $results
}

function Get-Top10FileCreate {
    param([object[]]$Sysmon11)
    $grouped = $Sysmon11 | Where-Object { $_.ProcessName } | Group-Object ProcessName | Sort-Object Count -Descending | Select-Object -First 10

    $results = @()
    foreach ($grp in $grouped) {
        $results += [PSCustomObject]@{
            Rank        = 0
            ProcessName = $grp.Name
            FileCount   = $grp.Count
        }
    }
    for ($i = 0; $i -lt $results.Count; $i++) { $results[$i].Rank = $i + 1 }
    return $results
}

function Get-NewDomains {
    param(
        [object[]]$DNS3008,
        [string]$YesterdayLogFile
    )

    $todayDomains = $DNS3008 | Where-Object { $_.Domain } | Select-Object -ExpandProperty Domain -Unique

    if (-not (Test-Path $YesterdayLogFile)) {
        Write-RunLog "No previous log file found, skipping new domain detection."
        return @()
    }

    try {
        $content = Get-Content -Path $YesterdayLogFile -Encoding UTF8 -ErrorAction Stop -Raw
        $yesterdayDomains = @{}
        $inDNSSection = $false
        foreach ($line in ($content -split "`r`n|`n")) {
            if ($line -match "DNS查询明细|DNS Query Detail") { $inDNSSection = $true; continue }
            if ($line -match "━━━|文件创建|File Create|进程创建|Process Create|日志结束|End") { $inDNSSection = $false }
            if ($inDNSSection -and $line -match '\S+\s+(\S+)\s+\S+\s+') {
                $domain = $Matches[1]
                if ($domain -notmatch '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$') {
                    $yesterdayDomains[$domain] = $true
                }
            }
        }

        $newDomains = @()
        foreach ($d in $todayDomains) {
            if (-not $yesterdayDomains.ContainsKey($d)) {
                # Find first occurrence time and process
                $firstRec = $DNS3008 | Where-Object { $_.Domain -eq $d } | Sort-Object Time | Select-Object -First 1
                $newDomains += [PSCustomObject]@{
                    Domain      = $d
                    FirstSeen   = $firstRec.Time
                    ProcessName = if ($firstRec.ProcessName) { $firstRec.ProcessName } else { "-" }
                }
            }
        }
        return $newDomains
    } catch {
        Write-RunLog "Failed to compare with previous log: $_" -Level "WARN"
        return @()
    }
}

# ==================================================================
#  ANOMALY DETECTION FUNCTIONS
# ==================================================================

function Test-UnusualPort {
    param([object[]]$Security5156, [object[]]$Sysmon3)
    $commonPorts = @(80, 443, 53, 22, 21, 25, 110, 143, 993, 995, 8080, 8443, 3389)

    $allConn = @($Security5156) + @($Sysmon3)
    $unusual = $allConn | Where-Object {
        $port = [int]$_.DestPort
        $port -and ($commonPorts -notcontains $port)
    }

    $results = @()
    $seen = @{}
    foreach ($conn in $unusual) {
        $key = "$($conn.ProcessName)$($conn.DestIP)$($conn.DestPort)"
        if (-not $seen[$key]) {
            $seen[$key] = $true
            $results += [PSCustomObject]@{
                ProcessName = if ($conn.ProcessName) { $conn.ProcessName } else { $conn.AppName }
                DestIP      = $conn.DestIP
                DestPort    = $conn.DestPort
                Protocol    = $conn.Protocol
            }
        }
    }
    return $results | Select-Object -First 50
}

function Test-NightActivity {
    param([object[]]$Security5156, [object[]]$Sysmon3)
    $allConn = @($Security5156) + @($Sysmon3)

    $nightConn = $allConn | Where-Object {
        $_.Time.Hour -ge 0 -and $_.Time.Hour -lt 6 -and $_.Direction -eq "出站"
    }

    $grouped = $nightConn | Group-Object { if ($_.ProcessName) { $_.ProcessName } else { $_.AppName } }

    $results = @()
    foreach ($grp in $grouped) {
        if ($grp.Count -gt 50) {
            $results += [PSCustomObject]@{
                ProcessName = $grp.Name
                OutConnCount = $grp.Count
            }
        }
    }
    return $results
}

function Test-DNSFailure {
    param([object[]]$DNS3008)
    $failed = $DNS3008 | Where-Object { -not $_.Result -or $_.Result -eq "" -or $_.Result -eq "-" }

    # Group by domain, collect all processes and first seen time
    $grouped = $failed | Where-Object { $_.Domain } | Group-Object Domain

    $results = @()
    foreach ($grp in $grouped) {
        $first = $grp.Group | Sort-Object Time | Select-Object -First 1
        $procs = ($grp.Group | Where-Object { $_.ProcessName -and $_.ProcessName -ne "Unknown" } | Select-Object -ExpandProperty ProcessName -Unique) -join ', '
        if (-not $procs) { $procs = "Unknown" }

        $results += [PSCustomObject]@{
            Domain      = $grp.Name
            FailCount   = $grp.Count
            ProcessName = $procs
            FirstSeen   = $first.Time
        }
    }

    return $results | Sort-Object FailCount -Descending | Select-Object -First 50
}

function Test-SuspiciousProcess {
    param(
        [object[]]$Security4688,
        [object[]]$Sysmon1,
        [object[]]$Security5156,
        [object[]]$Sysmon3
    )
    $suspiciousKeywords = @("miner", "crypto", "hack", "inject", "trojan", "backdoor", "payload", "keylog", "ransom", "exploit", "stealer", "rat", "botnet")

    # Whitelist: known legitimate processes that may trigger substring false positives
    # (e.g., "crashpad_handler" was flagged by "rat" in path/command fragments)
    $processWhitelist = @(
        "crashpad_handler",    # Google Crashpad - crash reporting, NOT "rat"
        "crashpad_handler.exe"
    )
    # Short keywords (<= 3 chars) prone to substring false positives - require word boundary
    $shortKeywords = @("rat")

    # Check process creation events
    $allProcesses = @($Security4688) + @($Sysmon1)
    $suspiciousProc = @()
    foreach ($proc in $allProcesses) {
        $procName = if ($proc.NewProcessName) {
            Split-Path $proc.NewProcessName -Leaf
        } elseif ($proc.Image) {
            Split-Path $proc.Image -Leaf
        } else { continue }

        # Skip whitelisted processes
        if ($processWhitelist -contains $procName) { continue }

        $cmd = if ($proc.CommandLine) { $proc.CommandLine } else { "" }

        foreach ($kw in $suspiciousKeywords) {
            $matched = $false
            if ($shortKeywords -contains $kw) {
                # Use word boundary to avoid substring false positives (e.g. "Separator" matching "rat")
                if ($procName -match "\b$([regex]::Escape($kw))\b" -or $cmd -match "\b$([regex]::Escape($kw))\b") {
                    $matched = $true
                }
            } else {
                if ($procName -match $kw -or $cmd -match $kw) {
                    $matched = $true
                }
            }

            if ($matched) {
                $suspiciousProc += [PSCustomObject]@{
                    ProcessName = $procName
                    Reason      = "Name/command contains keyword: '$kw'"
                    Detail      = if ($proc.NewProcessName) { $proc.NewProcessName } else { $proc.Image }
                    CmdLine     = $cmd
                    Time        = $proc.Time
                }
                break
            }
        }
    }

    # Check network connections
    $allConn = @($Security5156) + @($Sysmon3)
    foreach ($conn in $allConn) {
        $procName = if ($conn.ProcessName) { $conn.ProcessName } else { $conn.AppName }
        if (-not $procName) { continue }
        # Skip whitelisted processes
        if ($processWhitelist -contains $procName) { continue }
        foreach ($kw in $suspiciousKeywords) {
            $matched = $false
            if ($shortKeywords -contains $kw) {
                if ($procName -match "\b$([regex]::Escape($kw))\b") { $matched = $true }
            } else {
                if ($procName -match $kw) { $matched = $true }
            }

            if ($matched) {
                # Check if already reported
                if (-not ($suspiciousProc | Where-Object { $_.ProcessName -eq $procName })) {
                    $suspiciousProc += [PSCustomObject]@{
                        ProcessName = $procName
                        Reason      = "Network-active process matches keyword: '$kw'"
                        Detail      = $procName
                        CmdLine     = ""
                        Time        = $conn.Time
                    }
                }
                break
            }
        }
    }

    return $suspiciousProc | Select-Object -Unique ProcessName, Reason | Select-Object -First 50
}

function Test-LargeDownload {
    param([object[]]$Sysmon11)
    $results = @()
    foreach ($evt in $Sysmon11) {
        $path = $evt.TargetFile
        if (-not $path) { continue }
        if ($path -match "Downloads|Temp" -and (Test-Path $path)) {
            try {
                $size = (Get-Item $path -ErrorAction Stop).Length
                if ($size -gt 100MB) {
                    $results += [PSCustomObject]@{
                        ProcessName = $evt.ProcessName
                        FilePath    = $path
                        FileSizeMB  = [math]::Round($size / 1MB, 2)
                        Time        = $evt.Time
                    }
                }
            } catch { }
        }
    }
    return $results
}

# ==================================================================
#  FORMATTED REPORT GENERATION
# ==================================================================

function Write-Report {
    param(
        [DateTime]$StartTime,
        [DateTime]$EndTime,
        [object[]]$Security5156,
        [object[]]$Security4688,
        [object[]]$DNS3008,
        [object[]]$Sysmon1,
        [object[]]$Sysmon3,
        [object[]]$Sysmon11,
        [object[]]$TrafficEvents,
        [string]$OutputFile
    )

    $sb = [System.Text.StringBuilder]::new()
    $computerName = $env:COMPUTERNAME

    # Calculate stats
    $connStats = Get-ConnectionStats -Security5156 $Security5156 -Sysmon3 $Sysmon3
    $top10Proc = Get-Top10ProcessByConnection -Security5156 $Security5156 -Sysmon3 $Sysmon3
    $top10Traffic = Get-Top10ProcessByTraffic -TrafficEvents $TrafficEvents
    $top10Domain = Get-Top10Domain -DNS3008 $DNS3008
    $top10File = Get-Top10FileCreate -Sysmon11 $Sysmon11

    # New domain comparison: compare against previous day's report
    $prevDayFile = Join-Path $LogsDir "$($StartTime.Date.AddDays(-1).ToString('yyyy-MM-dd')).txt"
    $newDomains = Get-NewDomains -DNS3008 $DNS3008 -YesterdayLogFile $prevDayFile

    # Anomalies
    $unusualPorts = Test-UnusualPort -Security5156 $Security5156 -Sysmon3 $Sysmon3
    $nightActivity = Test-NightActivity -Security5156 $Security5156 -Sysmon3 $Sysmon3
    $dnsFailures = Test-DNSFailure -DNS3008 $DNS3008
    $suspiciousProc = Test-SuspiciousProcess -Security4688 $Security4688 -Sysmon1 $Sysmon1 -Security5156 $Security5156 -Sysmon3 $Sysmon3
    $largeDownloads = Test-LargeDownload -Sysmon11 $Sysmon11

    $uniqueDomains = ($DNS3008 | Where-Object { $_.Domain } | Select-Object -ExpandProperty Domain -Unique).Count
    $totalRecords = $Security5156.Count + $Security4688.Count + $DNS3008.Count + $Sysmon1.Count + $Sysmon3.Count + $Sysmon11.Count

    # ---- HEADER ----
    $isFullDay = ($StartTime.Hour -eq 0 -and $StartTime.Minute -eq 0 -and $EndTime.Hour -eq 23 -and $EndTime.Minute -eq 59)
    $headerTitleCN = if ($isFullDay) { "网络流量监控日报（完整自然日）" } else { "网络流量监控报告（滚动窗口）" }
    $headerTitleEN = if ($isFullDay) { "Network Traffic Monitor - Daily Report (Full Calendar Day)" } else { "Network Traffic Monitor - Report (Rolling Window)" }

    [void]$sb.AppendLine("================================================================")
    [void]$sb.AppendLine("  $headerTitleCN")
    [void]$sb.AppendLine("  $headerTitleEN")
    [void]$sb.AppendLine("  报告日期 Report Date: $($StartTime.ToString('yyyy-MM-dd'))")
    [void]$sb.AppendLine("  采集范围 Collection Range: $($StartTime.ToString('yyyy-MM-dd HH:mm:ss')) ~ $($EndTime.ToString('yyyy-MM-dd HH:mm:ss'))")
    [void]$sb.AppendLine("  生成时间 Generated: $([DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss'))")
    [void]$sb.AppendLine("  计算机名 Computer: $computerName")
    [void]$sb.AppendLine("================================================================")
    [void]$sb.AppendLine("")

    # ---- PART 1: Statistics ----
    [void]$sb.AppendLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    [void]$sb.AppendLine("  第一部分 Part 1：统计汇总 Statistics Summary")
    [void]$sb.AppendLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("【连接统计 Connection Statistics】")
    [void]$sb.AppendLine("  总连接数 Total Connections    : $($connStats.TotalConn)")
    [void]$sb.AppendLine("  出站连接 Outbound              : $($connStats.Outbound)")
    [void]$sb.AppendLine("  入站连接 Inbound               : $($connStats.Inbound)")
    [void]$sb.AppendLine("  涉及独立目标IP Unique Dest IPs : $($connStats.UniqueIPs)")
    [void]$sb.AppendLine("  涉及独立域名 Unique Domains    : $uniqueDomains")
    [void]$sb.AppendLine("")

    # TOP 10 Processes by Traffic (bytes) — the real "who is eating bandwidth" table
    if ($top10Traffic.Count -gt 0) {
        [void]$sb.AppendLine("【流量 TOP 10 进程 Top 10 Processes by Traffic (Bytes)】")
        [void]$sb.AppendLine((Format-FixedWidth -Columns @("排名", "进程名", "上传 Sent", "下载 Recv", "总流量 Total", "占比%") -Widths @(6, 28, 14, 14, 14, 8)))
        [void]$sb.AppendLine((Format-FixedWidth -Columns @("----", "--------", "----------", "----------", "------------", "------") -Widths @(6, 28, 14, 14, 14, 8)))
        foreach ($proc in $top10Traffic) {
            $sentStr = Format-BytesForReport -Bytes $proc.SentBytes
            $recvStr = Format-BytesForReport -Bytes $proc.RecvBytes
            $totalStr = Format-BytesForReport -Bytes $proc.TotalBytes
            [void]$sb.AppendLine((Format-FixedWidth -Columns @(
                $proc.Rank.ToString(),
                $proc.ProcessName,
                $sentStr,
                $recvStr,
                $totalStr,
                "$($proc.Percent)%"
            ) -Widths @(6, 28, 14, 14, 14, 8)))
        }
        [void]$sb.AppendLine("")
    } else {
        # Make the absence of traffic data visible instead of silently omitting
        # the section — an empty table here almost always means the ETW session
        # was not running during the collection window.
        [void]$sb.AppendLine("【流量 TOP 10 进程 Top 10 Processes by Traffic (Bytes)】")
        [void]$sb.AppendLine("  本时段无 ETW 流量数据 No ETW traffic data in this window.")
        [void]$sb.AppendLine("  请确认 Check: 1) ETW 会话是否运行 Traffic session running (-Mode Status);")
        [void]$sb.AppendLine("              2) 采集时段是否晚于会话启动时间 window starts after session start.")
        [void]$sb.AppendLine("")
    }

    # TOP 10 Processes by connection count (renamed from "流量 TOP 10" — it was misleading:
    # "连接次数" tells you who connects often, not who transfers bytes)
    if ($top10Proc.Count -gt 0) {
        [void]$sb.AppendLine("【连接 TOP 10 进程 Top 10 Processes by Connection Count】")
        [void]$sb.AppendLine((Format-FixedWidth -Columns @("排名", "进程名", "连接数", "出站", "入站", "涉及IP数") -Widths @(6, 28, 10, 8, 8, 10)))
        [void]$sb.AppendLine((Format-FixedWidth -Columns @("----", "--------", "------", "----", "----", "--------") -Widths @(6, 28, 10, 8, 8, 10)))
        foreach ($proc in $top10Proc) {
            [void]$sb.AppendLine((Format-FixedWidth -Columns @(
                $proc.Rank.ToString(),
                $proc.ProcessName,
                $proc.TotalConn.ToString(),
                $proc.Outbound.ToString(),
                $proc.Inbound.ToString(),
                $proc.UniqueIPs.ToString()
            ) -Widths @(6, 28, 10, 8, 8, 10)))
        }
        [void]$sb.AppendLine("")
    }

    # TOP 10 Domains
    if ($top10Domain.Count -gt 0) {
        [void]$sb.AppendLine("【域名 TOP 10 Top 10 Domains by Query】")
        [void]$sb.AppendLine((Format-FixedWidth -Columns @("排名", "域名", "查询次数", "来源进程") -Widths @(6, 50, 12, 28)))
        [void]$sb.AppendLine((Format-FixedWidth -Columns @("----", "----", "--------", "--------") -Widths @(6, 50, 12, 28)))
        foreach ($d in $top10Domain) {
            [void]$sb.AppendLine((Format-FixedWidth -Columns @($d.Rank.ToString(), $d.Domain, $d.QueryCount.ToString(), $d.ProcessName) -Widths @(6, 50, 12, 28)))
        }
        [void]$sb.AppendLine("")
    }

    # TOP 10 File Creation
    if ($top10File.Count -gt 0) {
        [void]$sb.AppendLine("【文件创建 TOP 10 Top 10 File Creation by Process】")
        [void]$sb.AppendLine((Format-FixedWidth -Columns @("排名", "进程名", "创建文件数") -Widths @(6, 30, 14)))
        [void]$sb.AppendLine((Format-FixedWidth -Columns @("----", "--------", "----------") -Widths @(6, 30, 14)))
        foreach ($f in $top10File) {
            [void]$sb.AppendLine((Format-FixedWidth -Columns @($f.Rank.ToString(), $f.ProcessName, $f.FileCount.ToString()) -Widths @(6, 30, 14)))
        }
        [void]$sb.AppendLine("")
    }

    # New Domains
    if ($newDomains.Count -gt 0) {
        [void]$sb.AppendLine("【新出现的域名 New Domains (first seen today)】")
        foreach ($nd in $newDomains) {
            [void]$sb.AppendLine("  - $($nd.Domain)（首次出现 First seen at $($nd.FirstSeen.ToString('HH:mm:ss')) | 来源进程: $($nd.ProcessName)）")
        }
        [void]$sb.AppendLine("")
    }

    # ---- Anomaly Alerts ----
    $hasAnomaly = $false
    if ($unusualPorts.Count -gt 0 -or $nightActivity.Count -gt 0 -or $dnsFailures.Count -gt 0 -or $suspiciousProc.Count -gt 0 -or $largeDownloads.Count -gt 0) {
        $hasAnomaly = $true
    }

    if ($hasAnomaly) {
        [void]$sb.AppendLine("【异常告警 Anomaly Alerts】")
        [void]$sb.AppendLine("")

        if ($unusualPorts.Count -gt 0) {
            [void]$sb.AppendLine("  !! $($unusualPorts.Count) 条连接使用了非常用端口 Unusual ports detected (non 80/443/53/22/21/25/110/143/993/995/8080/8443/3389)：")
            foreach ($up in $unusualPorts) {
                [void]$sb.AppendLine("     - $($up.ProcessName) -> $($up.DestIP):$($up.DestPort) ($($up.Protocol))")
            }
            [void]$sb.AppendLine("")
        }

        if ($nightActivity.Count -gt 0) {
            [void]$sb.AppendLine("  !! $($nightActivity.Count) 个进程在凌晨 00:00-06:00 有大量出站连接 >50 outbound connections during night hours：")
            foreach ($na in $nightActivity) {
                [void]$sb.AppendLine("     - $($na.ProcessName) -> 共 $($na.OutConnCount) 次出站连接")
            }
            [void]$sb.AppendLine("")
        }

        if ($dnsFailures.Count -gt 0) {
            [void]$sb.AppendLine("  !! $($dnsFailures.Count) 个域名解析失败 DNS resolution failures (possible DGA domains)：")
            [void]$sb.AppendLine((Format-FixedWidth -Columns @("  域名 Domain", "失败次数 Fails", "来源进程 Process", "首次出现 First Seen") -Widths @(45, 14, 28, 22)))
            [void]$sb.AppendLine((Format-FixedWidth -Columns @("  ------------", "------------", "----------------", "----------------") -Widths @(45, 14, 28, 22)))
            foreach ($df in $dnsFailures) {
                [void]$sb.AppendLine((Format-FixedWidth -Columns @(
                    "  $($df.Domain)",
                    $df.FailCount.ToString(),
                    $df.ProcessName,
                    $df.FirstSeen.ToString('MM-dd HH:mm:ss')
                ) -Widths @(45, 14, 28, 22)))
            }
            [void]$sb.AppendLine("")
        }

        if ($suspiciousProc.Count -gt 0) {
            [void]$sb.AppendLine("  !! 发现 $($suspiciousProc.Count) 个可疑进程 Suspicious processes detected (miner/crypto/hack/inject/trojan/backdoor/payload/keylog/ransom/exploit/stealer/rat/botnet)：")
            foreach ($sp in $suspiciousProc) {
                [void]$sb.AppendLine("     - $($sp.ProcessName) | Reason: $($sp.Reason) | Path: $($sp.Detail)")
            }
            [void]$sb.AppendLine("")
        }

        if ($largeDownloads.Count -gt 0) {
            [void]$sb.AppendLine("  !! 发现 $($largeDownloads.Count) 个大文件下载 Large file downloads >100MB in Downloads/Temp：")
            foreach ($ld in $largeDownloads) {
                [void]$sb.AppendLine("     - $($ld.ProcessName) -> $($ld.FilePath) ($($ld.FileSizeMB) MB)")
            }
            [void]$sb.AppendLine("")
        }
    } else {
        [void]$sb.AppendLine("【异常告警 Anomaly Alerts】")
        [void]$sb.AppendLine("  无异常 No anomalies detected.")
        [void]$sb.AppendLine("")
    }

    # ---- PART 2: Connection Details ----
    [void]$sb.AppendLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    [void]$sb.AppendLine("  第二部分 Part 2：详细连接记录 Connection Details")
    [void]$sb.AppendLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("【网络连接明细 Network Connection Details】（按时间排序 by time）")
    [void]$sb.AppendLine((Format-FixedWidth -Columns @("时间 Time", "进程 Process", "方向 Dir", "目标IP Dest IP", "端口 Port", "协议 Proto") -Widths @(22, 30, 6, 18, 8, 6)))
    [void]$sb.AppendLine((Format-FixedWidth -Columns @("----------", "-------------", "------", "--------------", "--------", "---------") -Widths @(22, 30, 6, 18, 8, 6)))

    $allConn = @($Security5156) + @($Sysmon3) | Sort-Object Time
    foreach ($conn in $allConn) {
        $procName = if ($conn.ProcessName) { $conn.ProcessName } else { $conn.AppName }
        [void]$sb.AppendLine((Format-FixedWidth -Columns @(
            $conn.Time.ToString('yyyy-MM-dd HH:mm:ss'),
            $procName,
            $conn.Direction,
            $conn.DestIP,
            $conn.DestPort,
            $conn.Protocol
        ) -Widths @(22, 30, 6, 18, 8, 6)))
    }
    [void]$sb.AppendLine("...（共 $($allConn.Count) 条 Total records）")
    [void]$sb.AppendLine("")

    # ---- PART 3: DNS Records ----
    [void]$sb.AppendLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    [void]$sb.AppendLine("  第三部分 Part 3：DNS 查询记录 DNS Query Records")
    [void]$sb.AppendLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("【DNS查询明细 DNS Query Details】（按时间排序 by time）")
    [void]$sb.AppendLine((Format-FixedWidth -Columns @("时间 Time", "域名 Domain", "类型 Type", "解析结果 Result", "来源进程 Process") -Widths @(22, 45, 8, 25, 22)))
    [void]$sb.AppendLine((Format-FixedWidth -Columns @("----------", "-----------", "--------", "-------------", "---------------") -Widths @(22, 45, 8, 25, 22)))

    $sortedDNS = $DNS3008 | Sort-Object Time
    foreach ($dns in $sortedDNS) {
        [void]$sb.AppendLine((Format-FixedWidth -Columns @(
            $dns.Time.ToString('yyyy-MM-dd HH:mm:ss'),
            $dns.Domain,
            $dns.QueryType,
            $dns.Result,
            $dns.ProcessName
        ) -Widths @(22, 45, 8, 25, 22)))
    }
    [void]$sb.AppendLine("...（共 $($sortedDNS.Count) 条 Total records）")
    [void]$sb.AppendLine("")

    # ---- PART 4: File Creation ----
    [void]$sb.AppendLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    [void]$sb.AppendLine("  第四部分 Part 4：文件创建记录 File Creation Records")
    [void]$sb.AppendLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("【文件创建明细 File Creation Details】（按时间排序 by time）")
    [void]$sb.AppendLine((Format-FixedWidth -Columns @("时间 Time", "进程 Process", "文件路径 File Path") -Widths @(22, 30, 60)))
    [void]$sb.AppendLine((Format-FixedWidth -Columns @("----------", "-------------", "------------------") -Widths @(22, 30, 60)))

    $sortedFiles = $Sysmon11 | Sort-Object Time
    foreach ($f in $sortedFiles) {
        [void]$sb.AppendLine((Format-FixedWidth -Columns @(
            $f.Time.ToString('yyyy-MM-dd HH:mm:ss'),
            $f.ProcessName,
            $f.TargetFile
        ) -Widths @(22, 30, 60)))
    }
    [void]$sb.AppendLine("...（共 $($sortedFiles.Count) 条 Total records）")
    [void]$sb.AppendLine("")

    # ---- PART 5: Process Creation ----
    $allProcCreate = @($Security4688) + @($Sysmon1) | Sort-Object Time
    [void]$sb.AppendLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    [void]$sb.AppendLine("  第五部分 Part 5：进程创建记录 Process Creation Records")
    [void]$sb.AppendLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("【进程启动明细 Process Launch Details】（按时间排序 by time）")
    [void]$sb.AppendLine((Format-FixedWidth -Columns @("时间 Time", "进程路径 Process Path", "命令行 Command Line") -Widths @(22, 55, 60)))
    [void]$sb.AppendLine((Format-FixedWidth -Columns @("----------", "--------------------", "-------------------") -Widths @(22, 55, 60)))

    foreach ($proc in $allProcCreate) {
        $pathStr = if ($proc.NewProcessName) { $proc.NewProcessName } else { $proc.Image }
        $cmdStr = if ($proc.CommandLine) { $proc.CommandLine } else { "" }
        [void]$sb.AppendLine((Format-FixedWidth -Columns @(
            $proc.Time.ToString('yyyy-MM-dd HH:mm:ss'),
            $pathStr,
            $cmdStr
        ) -Widths @(22, 55, 60)))
    }
    [void]$sb.AppendLine("...（共 $($allProcCreate.Count) 条 Total records）")
    [void]$sb.AppendLine("")

    # ---- FOOTER ----
    [void]$sb.AppendLine("================================================================")
    [void]$sb.AppendLine("  日志结束 End of Report")
    if (Test-Path $OutputFile) {
        try {
            $fileSize = (Get-Item $OutputFile).Length
            $sizeStr = if ($fileSize -gt 1MB) { "$([math]::Round($fileSize / 1MB, 2)) MB" } else { "$([math]::Round($fileSize / 1KB, 2)) KB" }
            [void]$sb.AppendLine("  文件大小 File Size: $sizeStr")
        } catch { }
    }
    [void]$sb.AppendLine("  总记录数 Total Records: $totalRecords 条")
    [void]$sb.AppendLine("================================================================")

    # Write to file (UTF-8 with BOM)
    $sb.ToString() | Out-File -FilePath $OutputFile -Encoding UTF8 -Force
}

# ==================================================================
#  CLEANUP FUNCTION
# ==================================================================

function Remove-OldLogs {
    Write-RunLog "Starting automatic log cleanup (retention: $RetentionDays days)..."

    if (-not (Test-Path $LogsDir)) {
        Write-RunLog "Logs directory not found, skipping cleanup."
        return
    }

    $cutoffDate = (Get-Date).AddDays(-$RetentionDays)
    $oldFiles = Get-ChildItem -Path $LogsDir -Filter "*.txt" -ErrorAction SilentlyContinue | Where-Object {
        $_.LastWriteTime -lt $cutoffDate
    }

    $deletedCount = 0
    foreach ($file in $oldFiles) {
        try {
            Remove-Item -Path $file.FullName -Force -ErrorAction Stop
            $deletedCount++
        } catch {
            Write-RunLog "Failed to delete old log: $($file.Name) - $_" -Level "WARN"
        }
    }

    if ($deletedCount -gt 0) {
        Write-RunLog "Cleaned up $deletedCount old log files."
    } else {
        Write-RunLog "No old logs to clean up."
    }
}

# ==================================================================
#  STATUS FUNCTION
# ==================================================================

function Show-Status {
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "  NetLedger Network Monitor - Status Report" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""

    # Sysmon status
    $sysmonSvc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
    if ($sysmonSvc) {
        Write-Host "  Sysmon 服务状态 Service Status : $($sysmonSvc.Status)" -ForegroundColor $(if ($sysmonSvc.Status -eq "Running") { "Green" } else { "Red" })
    } else {
        Write-Host "  Sysmon 服务状态 Service Status : 未安装 Not installed" -ForegroundColor Red
    }

    # Audit policy status
    try {
        <#
          auditpol /get output varies by OS language:
            English:  "Filtering Platform Connection           Success"
            Chinese:  "筛选平台连接                            成功"
          We check for "Success", "成功", and also try the GUID-based approach as fallback.

          GUIDs for the two subcategories:
            {0CCE9225-69AE-11D9-BED3-505054503030} = Filtering Platform Connection
            {0CCE922B-69AE-11D9-BED3-505054503030} = Process Creation
        #>
        $auditFCResult = auditpol /get /subcategory:"Filtering Platform Connection" 2>&1 | Out-String
        $auditPCResult = auditpol /get /subcategory:"Process Creation" 2>&1 | Out-String

        # Fallback: if subcategory name not found, try GUID
        if ($auditFCResult -match '错误|Error|参数不正确|parameter is incorrect|未找到') {
            Write-RunLog "Subcategory name 'Filtering Platform Connection' not recognized, trying GUID..." -Level "WARN"
            $auditFCResult = auditpol /get /subcategory:"{0CCE9225-69AE-11D9-BED3-505054503030}" 2>&1 | Out-String
        }
        if ($auditPCResult -match '错误|Error|参数不正确|parameter is incorrect|未找到') {
            Write-RunLog "Subcategory name 'Process Creation' not recognized, trying GUID..." -Level "WARN"
            $auditPCResult = auditpol /get /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" 2>&1 | Out-String
        }

        if ($auditFCResult -match 'Success|成功|启用') {
            Write-Host "  审计策略-网络连接 Audit: Filtering Platform Connection : 已开启 Enabled" -ForegroundColor Green
        } else {
            Write-Host "  审计策略-网络连接 Audit: Filtering Platform Connection : 未开启 Disabled" -ForegroundColor Red
        }

        if ($auditPCResult -match 'Success|成功|启用') {
            Write-Host "  审计策略-进程创建 Audit: Process Creation : 已开启 Enabled" -ForegroundColor Green
        } else {
            Write-Host "  审计策略-进程创建 Audit: Process Creation : 未开启 Disabled" -ForegroundColor Red
        }
    } catch {
        Write-Host "  审计策略状态 Audit Status : 无法检测 Cannot detect" -ForegroundColor Red
    }

    # DNS log status
    try {
        $dnsLog = Get-WinEvent -ListLog "Microsoft-Windows-DNS-Client/Operational" -ErrorAction Stop
        if ($dnsLog.IsEnabled) {
            $sizeMB = [math]::Round($dnsLog.MaximumSizeInBytes / 1MB, 0)
            Write-Host "  DNS日志状态 DNS Client Log : 已开启 Enabled (最大 ${sizeMB}MB)" -ForegroundColor Green
        } else {
            Write-Host "  DNS日志状态 DNS Client Log : 未开启 Disabled" -ForegroundColor Red
        }
    } catch {
        Write-Host "  DNS日志状态 DNS Client Log : 无法检测 Cannot detect" -ForegroundColor Red
    }

    # ETW traffic session status
    try {
        if (Test-TrafficSessionExists) {
            if (Test-TrafficSessionRunning) {
                # Live ETLs carry a logman version suffix (traffic_000001.etl) — sum them all
                $liveEtls = @(Get-ChildItem -Path (Join-Path $TrafficEtlDir "traffic*.etl") -ErrorAction SilentlyContinue |
                              Where-Object { $_.Name -notmatch '^traffic-' })
                $sizeStr = "N/A"
                if ($liveEtls.Count -gt 0) {
                    $sz = ($liveEtls | Measure-Object -Property Length -Sum).Sum
                    if ($sz) { $sizeStr = Format-BytesForReport -Bytes $sz }
                }
                Write-Host "  ETW会话状态 Traffic Session : 运行中 Running (ETL: $sizeStr / max ${TrafficEtlMaxMB}MB circular)" -ForegroundColor Green
            } else {
                Write-Host "  ETW会话状态 Traffic Session : 已注册但未运行 Registered but stopped" -ForegroundColor Yellow
            }
        } else {
            Write-Host "  ETW会话状态 Traffic Session : 未注册 Not registered (run Init to enable per-process traffic capture)" -ForegroundColor Red
        }
    } catch {
        Write-Host "  ETW会话状态 Traffic Session : 无法检测 Cannot detect" -ForegroundColor Red
    }

    # Traffic boot task status
    $trafficTask = Get-ScheduledTask -TaskName $TrafficTaskName -ErrorAction SilentlyContinue
    if ($trafficTask) {
        Write-Host "  开机任务状态 Boot Traffic Task : 已注册 Registered (State: $($trafficTask.State))" -ForegroundColor Green
    } else {
        Write-Host "  开机任务状态 Boot Traffic Task : 未注册 Not registered" -ForegroundColor Red
    }

    # Task scheduler status
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) {
        Write-Host "  任务计划状态 Task Scheduler : 已注册 Registered (State: $($task.State))" -ForegroundColor Green
    } else {
        Write-Host "  任务计划状态 Task Scheduler : 未注册 Not registered" -ForegroundColor Red
    }

    # Log directory overview
    Write-Host ""
    Write-Host "  日志目录 Log Directory : $LogsDir" -ForegroundColor Gray
    if (Test-Path $LogsDir) {
        $logFiles = Get-ChildItem -Path $LogsDir -Filter "*.txt" -ErrorAction SilentlyContinue | Sort-Object Name
        $fileCount = $logFiles.Count
        $totalSize = 0
        foreach ($f in $logFiles) { $totalSize += $f.Length }

        $sizeStr = if ($totalSize -gt 1GB) {
            "$([math]::Round($totalSize / 1GB, 2)) GB"
        } elseif ($totalSize -gt 1MB) {
            "$([math]::Round($totalSize / 1MB, 2)) MB"
        } else {
            "$([math]::Round($totalSize / 1KB, 2)) KB"
        }

        Write-Host "  已有日志 Existing Logs : $fileCount 个文件 files，共 $sizeStr" -ForegroundColor Gray

        if ($logFiles.Count -gt 0) {
            $first = $logFiles | Select-Object -First 1
            $last  = $logFiles | Select-Object -Last 1
            $firstDate = ([System.IO.Path]::GetFileNameWithoutExtension($first.Name))
            $lastDate  = ([System.IO.Path]::GetFileNameWithoutExtension($last.Name))
            Write-Host "  最早日志 Earliest : $firstDate" -ForegroundColor Gray
            Write-Host "  最新日志 Latest   : $lastDate" -ForegroundColor Gray
        }
    } else {
        Write-Host "  日志目录不存在 Log directory does not exist." -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""
}

# ==================================================================
#  MAIN ENTRY POINT
# ==================================================================

# Clear host for clean output
Clear-Host

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  NetLedger - Windows Network Traffic Monitor" -ForegroundColor Cyan
Write-Host "  Version 1.0.0" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

Write-RunLog "Script started. Mode: $Mode, Hours: $Hours"

# Check admin for Init mode
if ($Mode -eq "Init") {
    if (-not (Test-IsAdmin)) {
        Write-Host "[ERROR] Init mode requires Administrator privileges." -ForegroundColor Red
        Write-Host "        Please re-run as Administrator." -ForegroundColor Red
        Write-RunLog "Init failed: Not running as Administrator." -Level "ERROR"
        exit 1
    }
    Write-Host "[INFO] Running in Init mode (Administrator)" -ForegroundColor Yellow
    Write-Host ""
}

if ($Mode -eq "Export") {
    # Check admin (needed for reading Security logs)
    if (-not (Test-IsAdmin)) {
        Write-Host "[WARN] Export may fail without Administrator privileges for Security event logs." -ForegroundColor Yellow
        Write-Host "       Continuing anyway..." -ForegroundColor Yellow
    }
}

switch ($Mode) {
    "Init" {
        Write-Host ">>> Starting Initialization..." -ForegroundColor Yellow
        Write-Host ""

        Initialize-AuditPolicy
        Write-Host ""
        Initialize-DNSLog
        Write-Host ""
        Initialize-Sysmon
        Write-Host ""
        Initialize-DirectoryStructure
        Write-Host ""
        Initialize-TrafficSession
        Write-Host ""
        Initialize-TaskScheduler
        Write-Host ""
        Initialize-Readme

        Set-Initialized
        Write-RunLog "Initialization completed successfully."

        Write-Host ""
        Write-Host "================================================================" -ForegroundColor Green
        Write-Host "  Initialization Complete!" -ForegroundColor Green
        Write-Host "================================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "  Log Root     : $LogRootDir" -ForegroundColor Gray
        Write-Host "  Next Steps   : System will auto-collect daily at $DailyRunTime" -ForegroundColor Gray
        Write-Host "               : Or run manually: .\NetworkMonitor.ps1 -Mode Export" -ForegroundColor Gray
        Write-Host ""
    }

    "Export" {
        Write-Host ">>> Starting Log Collection..." -ForegroundColor Yellow

        # Determine time range and report date
        # Priority: -Date (specific full day) > -Hours (rolling window) > default (yesterday full day)
        $useFullDay = $true
        $reportDate = ""

        if ($Date -ne "") {
            # User specified a specific date: collect that full calendar day
            $targetDate = [DateTime]::ParseExact($Date, "yyyy-MM-dd", $null)
            $dateRange = Get-FullDayRange -Date $targetDate
            $reportDate = $targetDate.ToString('yyyy-MM-dd')
            Write-Host "  Mode: Full Calendar Day (Specified)" -ForegroundColor Gray
        } elseif ($PSBoundParameters.ContainsKey('Hours')) {
            # User explicitly specified -Hours: use rolling window (backward compatible)
            $dateRange = Get-DateRange -HoursBack $Hours
            $reportDate = $dateRange.End.ToString('yyyy-MM-dd')
            $useFullDay = $false
            Write-Host "  Mode: Rolling Window ($Hours hours)" -ForegroundColor Gray
        } else {
            # Default: collect yesterday's full calendar day
            $yesterday = [DateTime]::Now.Date.AddDays(-1)
            $dateRange = Get-FullDayRange -Date $yesterday
            $reportDate = $yesterday.ToString('yyyy-MM-dd')
            Write-Host "  Mode: Full Calendar Day (Default: Yesterday)" -ForegroundColor Gray
        }

        $outputFile = Join-Path $LogsDir "$reportDate.txt"

        Write-Host "  Time Range: $($dateRange.Start.ToString('yyyy-MM-dd HH:mm')) ~ $($dateRange.End.ToString('yyyy-MM-dd HH:mm'))" -ForegroundColor Gray

        # Ensure directories exist
        if (-not (Test-Path $LogsDir)) {
            New-Item -ItemType Directory -Path $LogsDir -Force | Out-Null
        }

        # Ensure the ETW traffic session is running before collecting —
        # if Init ran but a reboot happened in between and the boot task hasn't
        # fired yet, this is the fallback that guarantees capture.
        Write-Host "  Ensuring ETW traffic session is running..." -ForegroundColor Gray
        Ensure-TrafficSession | Out-Null

        # Collect data from all 7 sources
        Write-Host ""
        Write-Host "  [1/7] Collecting Security 5156 (Network Connection)..." -ForegroundColor Gray
        $sec5156 = Get-Security5156 -StartTime $dateRange.Start -EndTime $dateRange.End

        Write-Host "  [2/7] Collecting Security 4688 (Process Creation)..." -ForegroundColor Gray
        $sec4688 = Get-Security4688 -StartTime $dateRange.Start -EndTime $dateRange.End

        Write-Host "  [3/7] Collecting DNS 3008 (DNS Query)..." -ForegroundColor Gray
        $dns3008 = Get-DNS3008 -StartTime $dateRange.Start -EndTime $dateRange.End

        Write-Host "  [4/7] Collecting Sysmon 1 (Process Creation)..." -ForegroundColor Gray
        $sys1 = Get-Sysmon1 -StartTime $dateRange.Start -EndTime $dateRange.End

        Write-Host "  [5/7] Collecting Sysmon 3 (Network Connection)..." -ForegroundColor Gray
        $sys3 = Get-Sysmon3 -StartTime $dateRange.Start -EndTime $dateRange.End

        Write-Host "  [6/7] Collecting Sysmon 11 (File Creation)..." -ForegroundColor Gray
        $sys11 = Get-Sysmon11 -StartTime $dateRange.Start -EndTime $dateRange.End

        Write-Host "  [7/7] Collecting ETW traffic (Kernel-Network Send/Recv)..." -ForegroundColor Gray
        $traffic = Get-TrafficBytes -StartTime $dateRange.Start -EndTime $dateRange.End

        # Generate report(s)
        Write-Host ""
        Write-Host "  Generating report..." -ForegroundColor Yellow

        # Helper: filter events by day boundaries
        function Filter-ByDay {
            param([object[]]$Events, [DateTime]$DayStart, [DateTime]$DayEnd)
            if ($Events -and $Events.Count -gt 0) {
                return @($Events | Where-Object { $_.Time -ge $DayStart -and $_.Time -le $DayEnd })
            }
            return @()
        }

        if ($useFullDay) {
            # Full calendar day: single report
            Write-Report `
                -StartTime $dateRange.Start `
                -EndTime $dateRange.End `
                -Security5156 $sec5156 `
                -Security4688 $sec4688 `
                -DNS3008 $dns3008 `
                -Sysmon1 $sys1 `
                -Sysmon3 $sys3 `
                -Sysmon11 $sys11 `
                -TrafficEvents $traffic `
                -OutputFile $outputFile

            $totalRecords = $sec5156.Count + $sec4688.Count + $dns3008.Count + $sys1.Count + $sys3.Count + $sys11.Count + $traffic.Count
            $totalFiles = 1
            $outputFiles = @($outputFile)
        } else {
            # Rolling window: split by calendar day, one report per day
            $currentDay = $dateRange.Start.Date
            $endDay = $dateRange.End.Date
            $totalRecords = 0
            $totalFiles = 0
            $outputFiles = @()

            # Diagnostic: show actual event time span from collected data
            $allTimes = @()
            foreach ($arr in @($sec5156, $sec4688, $dns3008, $sys1, $sys3, $sys11, $traffic)) {
                foreach ($e in $arr) { if ($e.Time) { $allTimes += $e.Time } }
            }
            if ($allTimes.Count -gt 0) {
                $minTime = ($allTimes | Measure-Object -Minimum).Minimum
                $maxTime = ($allTimes | Measure-Object -Maximum).Maximum
                Write-Host "  Collected event time span: $($minTime.ToString('yyyy-MM-dd HH:mm:ss')) ~ $($maxTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor DarkGray
            }

            while ($currentDay -le $endDay) {
                # Day start: actual range start (for first day), or midnight (for subsequent days)
                $dayStart = if ($currentDay -lt $dateRange.Start) { $dateRange.Start } else { $currentDay }
                # Day end: either 23:59:59 of this day, or capped by the actual EndTime
                $dayEndFull = $currentDay.AddDays(1).AddMilliseconds(-1)
                $dayEnd = if ($dayEndFull -lt $dateRange.End) { $dayEndFull } else { $dateRange.End }

                # Filter data for this day
                $day5156 = Filter-ByDay -Events $sec5156 -DayStart $dayStart -DayEnd $dayEnd
                $day4688 = Filter-ByDay -Events $sec4688 -DayStart $dayStart -DayEnd $dayEnd
                $day3008 = Filter-ByDay -Events $dns3008 -DayStart $dayStart -DayEnd $dayEnd
                $day1    = Filter-ByDay -Events $sys1    -DayStart $dayStart -DayEnd $dayEnd
                $day3    = Filter-ByDay -Events $sys3    -DayStart $dayStart -DayEnd $dayEnd
                $day11   = Filter-ByDay -Events $sys11   -DayStart $dayStart -DayEnd $dayEnd
                $dayTraffic = Filter-ByDay -Events $traffic -DayStart $dayStart -DayEnd $dayEnd

                $dayTotal = $day5156.Count + $day4688.Count + $day3008.Count + $day1.Count + $day3.Count + $day11.Count + $dayTraffic.Count
                $isPartial = ($dayStart -ne $currentDay) -or ($dayEnd -ne $dayEndFull)
                $dayLabel = if ($isPartial) { "（部分 Partial）" } else { "" }

                if ($dayTotal -gt 0) {
                    $dayFile = Join-Path $LogsDir "$($currentDay.ToString('yyyy-MM-dd')).txt"
                    Write-Host "    -> $($currentDay.ToString('yyyy-MM-dd'))$dayLabel : $dayTotal events  [生成文件]" -ForegroundColor Green
                    Write-Report `
                        -StartTime $dayStart `
                        -EndTime $dayEnd `
                        -Security5156 $day5156 `
                        -Security4688 $day4688 `
                        -DNS3008 $day3008 `
                        -Sysmon1 $day1 `
                        -Sysmon3 $day3 `
                        -Sysmon11 $day11 `
                        -TrafficEvents $dayTraffic `
                        -OutputFile $dayFile

                    $totalRecords += $dayTotal
                    $totalFiles++
                    $outputFiles += $dayFile
                } else {
                    Write-Host "    -> $($currentDay.ToString('yyyy-MM-dd'))$dayLabel : 0 events  [跳过 Skip]" -ForegroundColor DarkGray
                }

                $currentDay = $currentDay.AddDays(1)
            }

            if ($totalFiles -eq 0) {
                Write-Host "    No events in the specified time range." -ForegroundColor Yellow
            }
        }

        # Cleanup old logs
        Remove-OldLogs

        $reportType = if ($useFullDay) { "完整自然日 Full Calendar Day" } else { "滚动窗口 Rolling Window ($Hours hours) — 按日拆分 Split by Day" }
        Write-Host ""
        Write-Host "================================================================" -ForegroundColor Green
        Write-Host "  Export Complete!" -ForegroundColor Green
        Write-Host "================================================================" -ForegroundColor Green
        Write-Host "  Report Type  : $reportType" -ForegroundColor Gray
        Write-Host "  Total Events : $totalRecords" -ForegroundColor Gray
        Write-Host "  Total Files  : $totalFiles" -ForegroundColor Gray
        foreach ($f in $outputFiles) {
            Write-Host "    - $f" -ForegroundColor Gray
        }
        Write-Host ""

        Write-RunLog "Export completed. Files: $totalFiles, Events: $totalRecords"
    }

    "Status" {
        Show-Status
        Write-RunLog "Status check completed."
    }
}

Write-RunLog "Script finished."
