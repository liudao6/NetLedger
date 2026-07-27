================================================================
  NetLedger - Windows Network Traffic Monitor
  网络流量监控日志归集系统
================================================================

Installation Directory: D:\NetworkMonitor

Directory Structure:
  logs\        - Daily collected log files
  scripts\     - Monitor scripts
  sysmon\      - Sysmon binaries and config

Daily Report Files:
  Format: yyyy-MM-dd.txt
  Encoding: UTF-8 (with BOM)
  Location: D:\NetworkMonitor\logs\

How to Use:
  1. First-time setup (run as Administrator):
     powershell -ExecutionPolicy Bypass -File "D:\NetworkMonitor\scripts\NetworkMonitor.ps1" -Mode Init

  2. Manual collection:
     powershell -ExecutionPolicy Bypass -File "D:\NetworkMonitor\scripts\NetworkMonitor.ps1" -Mode Export

  3. Check status:
     powershell -ExecutionPolicy Bypass -File "D:\NetworkMonitor\scripts\NetworkMonitor.ps1" -Mode Status

  4. Manual collection with custom time range:
     powershell -ExecutionPolicy Bypass -File "D:\NetworkMonitor\scripts\NetworkMonitor.ps1" -Mode Export -Hours 48

  5. Uninstall (run as Administrator):
     powershell -ExecutionPolicy Bypass -File "D:\NetworkMonitor\scripts\Uninstall-NetworkMonitor.ps1"

Scheduled Task:
  Task Name: NetworkMonitor_DailyExport
  Triggers:  Daily at 00:30 + At system startup (1 min delay)
  Account:   SYSTEM

Log Retention: 90 days (auto-cleanup)

Open Source Project: https://github.com/yourusername/NetLedger

For detailed documentation, see the project docs/ directory.

================================================================
