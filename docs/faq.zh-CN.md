# NetLedger 常见问题

## 安装与初始化

### Q: 运行 Init 时报错 "Access Denied"
**A**: 必须以管理员身份运行 PowerShell。右键点击 PowerShell 图标 → "以管理员身份运行"。

### Q: Sysmon 下载失败，提示网络错误
**A**: 可能原因：
1. 网络防火墙阻止了 `live.sysinternals.com` 的访问
2. 代理设置问题
3. 手动解决方案：从 [微软官网](https://learn.microsoft.com/sysinternals/downloads/sysmon) 下载 `Sysmon64.exe`，放到 `C:\Sysmon\` 目录，然后重新运行 Init

### Q: 初始化完成后日志目录里没有文件
**A**: 正常现象。初始化只创建目录结构和定时任务，日志文件在第一次定时执行后（默认每天 00:30）或手动 Export 后才会生成。

### Q: 已有其他 Sysmon 配置，会被覆盖吗？
**A**: 会。本脚本的 Init 会写入自己的 Sysmon 配置文件。如果已有自定义 Sysmon 规则，请先备份，Init 后再手动合并。

---

## 日常使用

### Q: 日报没有数据，显示为 0
**A**: 检查以下几点：
1. 运行 `.\NetworkMonitor.ps1 -Mode Status` 查看各组件状态
2. 确认 Sysmon 服务正在运行（`Get-Service Sysmon64`）
3. 确认审计策略已开启（`auditpol /get /category:*`）
4. 确认时间范围内确实有网络活动

### Q: 日报中文乱码
**A**: 日志文件使用 UTF-8 with BOM 编码。如果用记事本打开乱码，尝试：
- 用 VS Code 打开（自动检测编码）
- 记事本打开后选择"文件" → "另存为" → 编码选 UTF-8

### Q: Export 执行超过 5 分钟
**A**: 正常情况应在 1-3 分钟内完成。如果超时：
1. 安全日志量大（`-MaxEvents 50000` 限制）
2. 磁盘 I/O 繁忙
3. 建议检查 `run.log` 查看具体哪个采集步骤耗时最长

### Q: 可以导出 CSV 格式吗？
**A**: 当前版本仅支持 TXT 格式。`$ExportFormat` 配置项预留了 CSV 选项，后续版本会支持。

### Q: 日志里有两个 "TOP 10 进程" 表，有什么区别？
**A**: 从 v1.1 起，日报有两张表：
- **流量 TOP 10 进程 Top 10 Processes by Traffic (Bytes)** — 真正的"哪个应用在吃流量"。字段是「上传 Sent / 下载 Recv / 总流量 Total / 占比%」，数据来自 ETW Kernel-Network 会话记录的每个 TCP/UDP Send/Recv 的字节数。
- **连接 TOP 10 进程 Top 10 Processes by Connection Count** — 哪个进程"连接次数多"。字段是「连接数 / 出站 / 入站 / 涉及IP数」，数据来自 Security 5156 + Sysmon 3。

两者经常不一致：`chrome.exe` 可能连接数最多但流量不大（小请求多），`steam.exe` 可能连接数少但流量最大（在下游戏）。回答"哪个应用在吃流量"请看第一张表。

---

## 流量采集（ETW）

### Q: Status 显示 "ETW会话状态：未注册 Not registered"，怎么办？
**A**: 这通常意味着 Init 还没运行过、或被人手动 `logman delete` 删除了。重新以管理员运行 `.\NetworkMonitor.ps1 -Mode Init`，会重新创建并启动 ETW 会话。Init 是幂等的，重复运行只会重置配置不会破坏其他东西。

### Q: Status 显示 "ETW会话状态：已注册但未运行 Registered but stopped"，怎么办？
**A**: 通常出现在系统刚启动后 30 秒内（开机自启任务还没执行）或者有人手动 `logman stop` 了。可以：
- 等几秒让开机任务自动执行
- 手动执行：`logman start NetLedgerTraffic`（管理员）
- 直接运行 Export：`.\NetworkMonitor.ps1 -Mode Export` — 脚本开头会自动 `Ensure-TrafficSession` 把会话重新拉起来

### Q: 日志里"流量 TOP 10"表是空的，但连接 TOP 10 有数据，为什么？
**A**: 三种可能：
1. **会话刚启动还没积累数据**：第一次 Export 后，下次 Export 才能看到完整一天的字节数。请等下一个采集周期再看。
2. **Init 后没有重启过 Export**：会话在 Init 时启动，但 Export 还没运行过，ETL 文件还是空。运行 `.\NetworkMonitor.ps1 -Mode Export` 即可。
3. **会话被某个安全软件拦截**：部分 EDR（如 CrowdStrike、Defender for Endpoint）会接管 kernel trace，导致 `logman start` 看似成功但实际不写事件。检查 `run.log` 里 Export 步骤是否报告"ETL was empty"。

### Q: 报表里"上传 Sent"和"下载 Recv"具体指什么？
**A**: 来自 `Microsoft-Windows-Kernel-Network` provider：
- **上传 Sent** (Event ID 3)：本机进程主动发起的 TCP/UDP `send` 调用，包含发送的字节数。
- **下载 Recv** (Event ID 4)：本机进程收到的 TCP/UDP `recv` 数据。
注意：方向是按"本机进程视角"标记的，与防火墙的"入站/出站"含义一致但来源不同。NAT 后的流量、UDP 无连接流量也都会被记录。

### Q: ETW 会话会占用很多资源吗？
**A**: 普通办公电脑约 100-1000 事件/秒，CPU 占用 <1%，磁盘固定上限 256 MB（循环覆盖）。如果担心，可以编辑脚本顶部的 `$TrafficEtlMaxMB` 改小到 64 或 128，再重新 Init。

### Q: 卸载会停掉 ETW 会话吗？
**A**: 会的。`Uninstall-NetworkMonitor.ps1` 第 [5/6] 步会 `logman stop` 并 `logman delete` 移除 ETW 会话，第 [6/6] 步会删除开机自启任务，不会残留。

---

## 告警相关

### Q: 告警中出现了很多 "非常用端口" 连接，是不是中病毒了？
**A**: 不一定。很多合法软件也会使用非常用端口（如 Steam 使用 27015-27030，数据库使用 1433/3306 等）。告警规则是保守的启发式检测，建议结合进程名和目标 IP 综合判断。

### Q: 出现了可疑进程告警，怎么确认是否安全？
**A**: 
1. 查看告警中进程的完整路径
2. 用 VirusTotal 等工具检查该文件
3. 查看该进程的历史连接目标 IP
4. 如果确认安全，可以在脚本的 `Test-SuspiciousProcess` 函数中将该进程名加入白名单

### Q: 为什么有些域名解析失败却被标记为 "DGA域名"？
**A**: DGA（Domain Generation Algorithm）域名是恶意软件随机生成的域名。解析失败不一定是 DGA，也可能是正常的临时故障。只有持续反复出现失败且域名看起来随机（如 `xk3j9f8a2b.com`）时才需警惕。

---

## 性能与存储

### Q: 日志占用多少磁盘空间？
**A**: 每日日志文件大小取决于网络活动量：
- 普通办公电脑：0.5-2 MB/天
- 开发/下载较多的电脑：2-10 MB/天
- 90 天保留期约占用：45 MB - 900 MB

### Q: 脚本运行时会占用 CPU 吗？
**A**: Export 执行时会有短暂的 CPU 占用（主要是 `Get-WinEvent` 查询）。定时任务在凌晨 00:30 执行，对日常使用无影响。

### Q: 如何修改日志保留天数？
**A**: 编辑 `NetworkMonitor.ps1`，修改 `$RetentionDays` 变量（如改为 30），保存即可。下次 Export 时自动清理。

---

## 卸载

### Q: 卸载后审计策略没有完全关闭？
**A**: 卸载脚本会尝试关闭，但某些组策略可能覆盖本地设置。检查方法：
```powershell
auditpol /get /subcategory:"Filtering Platform Connection"
```
如仍为启用状态，可手动关闭：
```powershell
auditpol /set /subcategory:"Filtering Platform Connection" /success:disable
```

### Q: 卸载后 Sysmon 驱动残留？
**A**: 卸载脚本执行 `Sysmon64.exe -u` 会卸载驱动。如果失败，重启后驱动会自动被清理。也可手动删除 `C:\Windows\Sysmon64.exe` 和 `C:\Windows\SysmonDrv.sys`（如有）。
