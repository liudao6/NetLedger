# NetLedger 用户使用指南

> **适用对象**：终端用户
> **用途**：安装、配置、日常使用 NetLedger 网络流量监控系统

## 快速开始（Quick Start）

### 1. 下载脚本

将项目中的 `scripts/` 目录复制到任意位置（例如 `D:\NetworkMonitor\scripts\`）。

### 2. 一键初始化（以管理员身份运行）

打开 **PowerShell（管理员）**，执行：

```powershell
cd D:\NetworkMonitor\scripts
.\NetworkMonitor.ps1 -Mode Init
```

初始化会自动完成以下操作：
- 开启 Windows 审计策略（网络连接 + 进程创建）
- 启用 DNS Client 操作日志
- 下载并安装 Sysmon（如果未安装）
- 创建日志目录结构
- 注册每日定时任务（每天 00:30 + 开机自启）

### 3. 查看状态

```powershell
.\NetworkMonitor.ps1 -Mode Status
```

### 4. 手动采集

```powershell
# 采集过去 24 小时
.\NetworkMonitor.ps1 -Mode Export

# 采集过去 48 小时
.\NetworkMonitor.ps1 -Mode Export -Hours 48
```

### 5. 查看日志

日志文件位于 `D:\NetworkMonitor\logs\`，按日期命名（如 `2026-07-27.txt`），用记事本或 VS Code 直接打开即可。

---

## 配置修改

编辑 `NetworkMonitor.ps1` 文件顶部的配置块：

```powershell
$LogRootDir    = "D:\NetworkMonitor"        # 日志根目录（可修改）
$SysmonDir     = "C:\Sysmon"                # Sysmon 安装目录
$DailyRunTime  = "00:30"                    # 每天归集时间（24小时制）
$RetentionDays = 90                         # 日志保留天数（超过自动删除）
$ExportFormat  = "txt"                      # 导出格式：txt 或 csv
```

修改后无需重新初始化，下次 Export 执行时生效。

---

## 日报内容说明

每天的日报包含六个部分：

| 部分 | 内容 |
|------|------|
| 统计汇总 | 连接总数、进出站数量、独立IP/域名数、TOP10进程/域名/文件创建 |
| 异常告警 | 非常用端口、凌晨异常活动、DNS失败、可疑进程、大文件下载 |
| 连接明细 | 所有网络连接的进程、目标IP、端口、方向 |
| DNS查询记录 | 所有域名查询及解析结果 |
| 文件创建记录 | 在 Downloads/Temp/Desktop 创建的文件 |
| 进程启动记录 | 所有新启动的进程及命令行参数 |

---

## 卸载

以管理员身份运行：

```powershell
.\Uninstall-NetworkMonitor.ps1
```

完全清理（包括日志和脚本）：

```powershell
.\Uninstall-NetworkMonitor.ps1 -RemoveLogs -RemoveScripts
```

---

## 常见问题

### 为什么需要管理员权限？
- 初始化需要修改系统审计策略和安装 Sysmon
- 导出时需要读取 Windows 安全事件日志
- 建议始终以管理员身份运行

### 如果 Sysmon 下载失败怎么办？
手动从 [Microsoft Sysinternals](https://learn.microsoft.com/sysinternals/downloads/sysmon) 下载 `Sysmon64.exe`，放到 `C:\Sysmon\` 目录下，然后重新运行 Init。

### 日报文件太大怎么办？
- 缩短 `$RetentionDays` 保留天数（如设为 30 天）
- 日报会记录所有事件（不截断），数据量大属于正常现象

### 如何修改定时采集时间？
修改脚本配置区的 `$DailyRunTime` 变量（如 `"06:00"` 表示每天早上 6 点），然后重新运行 Init，任务计划会自动更新。

### 支持哪些 Windows 版本？
- Windows 10 / Windows 11
- Windows Server 2016 及以上

### 如何把日志发给 AI 分析？
直接用 VS Code 打开 `.txt` 日志文件，全选复制，粘贴到 ChatGPT/Claude 等 AI 工具即可。日报已包含中英文双语标签，AI 可直接理解。
