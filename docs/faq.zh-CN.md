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
