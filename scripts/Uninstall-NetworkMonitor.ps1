<#
.SYNOPSIS
    NetLedger Network Monitor - Uninstall Script
.DESCRIPTION
    One-click uninstall script that:
      1. Removes Windows Task Scheduler job
      2. Disables Windows audit policies (Filtering Platform Connection, Process Creation)
      3. Disables DNS Client Operational log
      4. Uninstalls Sysmon service
      5. Optionally removes log directory and script files
.PARAMETER RemoveLogs
    If specified, also deletes the log directory ($LogRootDir).
.PARAMETER RemoveScripts
    If specified, also deletes the scripts directory and this script.
.EXAMPLE
    .\Uninstall-NetworkMonitor.ps1
    # Uninstall without removing logs or scripts

.EXAMPLE
    .\Uninstall-NetworkMonitor.ps1 -RemoveLogs -RemoveScripts
    # Full uninstall - removes everything
.NOTES
    Requires Administrator privileges.
    Version: 1.0.0
#>

param(
    [switch]$RemoveLogs,
    [switch]$RemoveScripts
)

# ============ Configuration (must match NetworkMonitor.ps1) ============
$LogRootDir    = "D:\NetworkMonitor"
$TaskName      = "NetworkMonitor_DailyExport"
$SysmonService = "Sysmon64"
$SysmonExe     = "C:\Windows\Sysmon64.exe"
# ======================================================================

$script:UninstallLog = Join-Path $LogRootDir "scripts\uninstall.log"

# ---- Helper Functions ----
function Write-UninstallLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = [DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss')
    $logLine = "$timestamp [$Level] $Message"
    Write-Host $logLine
    if (Test-Path (Split-Path $script:UninstallLog -Parent)) {
        Add-Content -Path $script:UninstallLog -Value $logLine -Encoding UTF8
    }
}

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ==================== MAIN ====================
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  NetLedger Network Monitor - Uninstall Script" -ForegroundColor Cyan
Write-Host "  Version 1.0.0" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# Check admin
if (-not (Test-Admin)) {
    Write-Host "[ERROR] Administrator privileges required. Please run as Administrator." -ForegroundColor Red
    exit 1
}

$allSuccess = $true

# 1. Remove Scheduled Task
Write-Host "[1/5] Removing Scheduled Task '$TaskName'..." -ForegroundColor Yellow
try {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
        Write-Host "       Scheduled task removed successfully." -ForegroundColor Green
    } else {
        Write-Host "       Scheduled task not found (already removed)." -ForegroundColor Gray
    }
} catch {
    Write-Host "       WARNING: Failed to remove scheduled task: $_" -ForegroundColor DarkYellow
    $allSuccess = $false
}

# 2. Disable Audit Policies
Write-Host "[2/5] Disabling Windows Audit Policies..." -ForegroundColor Yellow
try {
    $auditPolicies = @(
        @{Subcategory = "Filtering Platform Connection"; Guid = "{0CCE922B-69AE-11D9-BED3-505054503030}"},
        @{Subcategory = "Process Creation"; Guid = "{0CCE922B-69AE-11D9-BED3-505054503030}"}
    )

    foreach ($policy in $auditPolicies) {
        try {
            $result = auditpol /get /subcategory:"$($policy.Subcategory)" 2>&1 | Out-String
            if ($result -match "Success") {
                auditpol /set /subcategory:"$($policy.Subcategory)" /success:disable /failure:disable 2>&1 | Out-Null
                Write-Host "       Disabled: $($policy.Subcategory)" -ForegroundColor Green
            } else {
                Write-Host "       Already disabled: $($policy.Subcategory)" -ForegroundColor Gray
            }
        } catch {
            Write-Host "       WARNING: Failed to disable $($policy.Subcategory): $_" -ForegroundColor DarkYellow
        }
    }
} catch {
    Write-Host "       WARNING: Error processing audit policies: $_" -ForegroundColor DarkYellow
    $allSuccess = $false
}

# 3. Disable DNS Client Operational Log
Write-Host "[3/5] Disabling DNS Client Operational Log..." -ForegroundColor Yellow
try {
    $dnsLog = Get-WinEvent -ListLog "Microsoft-Windows-DNS-Client/Operational" -ErrorAction SilentlyContinue
    if ($dnsLog -and $dnsLog.IsEnabled) {
        wevtutil sl "Microsoft-Windows-DNS-Client/Operational" /e:false 2>&1 | Out-Null
        Write-Host "       DNS Client Operational log disabled." -ForegroundColor Green
    } else {
        Write-Host "       DNS Client Operational log already disabled or not found." -ForegroundColor Gray
    }
} catch {
    Write-Host "       WARNING: Failed to disable DNS log: $_" -ForegroundColor DarkYellow
    $allSuccess = $false
}

# 4. Uninstall Sysmon
Write-Host "[4/5] Uninstalling Sysmon..." -ForegroundColor Yellow
try {
    $sysmonService = Get-Service -Name $SysmonService -ErrorAction SilentlyContinue
    if ($sysmonService) {
        $sysmonExe = $SysmonExe
        if (-not (Test-Path $sysmonExe)) {
            $sysmonExe = Join-Path $LogRootDir "sysmon\Sysmon64.exe"
        }
        if (Test-Path $sysmonExe) {
            & $sysmonExe -u -quiet 2>&1 | Out-Null
            Write-Host "       Sysmon uninstalled successfully." -ForegroundColor Green
        } else {
            # Try to find it
            $sysmonExe = Get-Command Sysmon64.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
            if ($sysmonExe -and (Test-Path $sysmonExe)) {
                & $sysmonExe -u -quiet 2>&1 | Out-Null
                Write-Host "       Sysmon uninstalled successfully." -ForegroundColor Green
            } else {
                Stop-Service -Name $SysmonService -Force -ErrorAction SilentlyContinue
                sc.exe delete $SysmonService 2>&1 | Out-Null
                Write-Host "       Sysmon service removed (executable not found, service deleted)." -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "       Sysmon service not found (already removed)." -ForegroundColor Gray
    }
} catch {
    Write-Host "       WARNING: Failed to uninstall Sysmon: $_" -ForegroundColor DarkYellow
    $allSuccess = $false
}

# 5. Optionally remove directories
if ($RemoveLogs) {
    Write-Host "[5/5] Removing log directory '$LogRootDir'..." -ForegroundColor Yellow
    try {
        if (Test-Path $LogRootDir) {
            Remove-Item -Path $LogRootDir -Recurse -Force -ErrorAction Stop
            Write-Host "       Log directory removed." -ForegroundColor Green
        } else {
            Write-Host "       Log directory not found." -ForegroundColor Gray
        }
    } catch {
        Write-Host "       WARNING: Failed to remove log directory: $_" -ForegroundColor DarkYellow
        $allSuccess = $false
    }
}

if ($RemoveScripts) {
    Write-Host "[Extra] Removing script directory..." -ForegroundColor Yellow
    $scriptDir = Split-Path -Parent $PSCommandPath
    try {
        Remove-Item -Path $scriptDir -Recurse -Force -ErrorAction Stop
        Write-Host "       Script directory removed." -ForegroundColor Green
        Write-Host ""
        Write-Host "================================================================" -ForegroundColor Cyan
        Write-Host "  All components have been removed. Goodbye!" -ForegroundColor Cyan
        Write-Host "================================================================" -ForegroundColor Cyan
        exit 0
    } catch {
        Write-Host "       WARNING: Failed to remove script directory: $_" -ForegroundColor DarkYellow
    }
}

Write-Host ""
if ($allSuccess) {
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "  Uninstall completed successfully!" -ForegroundColor Green
    Write-Host "================================================================" -ForegroundColor Cyan
} else {
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "  Uninstall completed with warnings (see above)." -ForegroundColor Yellow
    Write-Host "================================================================" -ForegroundColor Cyan
}
Write-Host ""
