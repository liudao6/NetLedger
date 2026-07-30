<#
.SYNOPSIS
    排查指定时间段内本机下载/新增的文件与浏览器下载记录
.DESCRIPTION
    扫描 下载文件夹 以及 Chrome/Edge 的下载历史，列出落在时间窗口内的条目。
    适用于：怀疑电脑在无人时段被使用、想确认"凌晨下了什么"。
.PARAMETER StartHour
    窗口起始小时(24小时制, 默认 0 = 午夜)
.PARAMETER EndHour
    窗口结束小时(默认 7 = 早上7点)
.PARAMETER Date
    要排查的日期, 默认昨天 (格式 yyyy-MM-dd)
.EXAMPLE
    .\ForensicDownloads.ps1                 # 查昨天 0:00-7:00
    .\ForensicDownloads.ps1 -Date 2026-07-28 -StartHour 0 -EndHour 7
#>
param(
    [int]$StartHour = 0,
    [int]$EndHour   = 7,
    [string]$Date   = (Get-Date).AddDays(-1).ToString('yyyy-MM-dd')
)

$day = [datetime]::ParseExact($Date, 'yyyy-MM-dd', $null)
$winStart = $day.AddHours($StartHour)
$winEnd   = $day.AddHours($EndHour)

Write-Host "`n===== 排查窗口: $winStart  ~  $winEnd =====`n" -ForegroundColor Cyan

# ---------- 1. 文件系统: 下载/桌面/临时 目录下该时段新增或修改的文件 ----------
$scanRoots = @(
    [Environment]::GetFolderPath('UserProfile') + '\Downloads',
    [Environment]::GetFolderPath('Desktop'),
    $env:TEMP
)

Write-Host "【1】文件系统扫描 (Downloads / Desktop / Temp)" -ForegroundColor Yellow
$found = @()
foreach ($root in $scanRoots) {
    if (-not (Test-Path $root)) { continue }
    Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.CreationTime -ge $winStart -and $_.CreationTime -le $winEnd } |
        ForEach-Object {
            $found += [PSCustomObject]@{
                位置   = $root
                文件名 = $_.Name
                大小MB = '{0:N2}' -f ($_.Length/1MB)
                创建时间 = $_.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
                路径   = $_.FullName
            }
        }
}
if ($found.Count -eq 0) {
    Write-Host "  - 未发现该时段新增文件 (注意: 仅扫了前两层常见目录, 不代表全盘无文件)`n" -ForegroundColor DarkGray
} else {
    $found | Sort-Object 创建时间 | Format-Table -AutoSize
}

# ---------- 2. 浏览器下载历史 (Chrome / Edge 的 History SQLite) ----------
Write-Host "【2】浏览器下载历史 (Chrome / Edge)" -ForegroundColor Yellow
$userPath = [Environment]::GetFolderPath('UserProfile')
$browsers = @(
    @{ Name='Chrome'; Path="$userPath\AppData\Local\Google\Chrome\User Data\Default\History" },
    @{ Name='Edge';   Path="$userPath\AppData\Local\Microsoft\Edge\User Data\Default\History" }
)

# 需要一个能读 SQLite 的方式; 优先用系统自带的方式
$sqliteDll = "$env:TEMP\SQLite.Interop.dll"
$haveSQLite = $false
try {
    Add-Type -Path "$env:TEMP\System.Data.SQLite.dll" -ErrorAction Stop
    $haveSQLite = $true
} catch { $haveSQLite = $false }

foreach ($b in $browsers) {
    if (-not (Test-Path $b.Path)) { continue }
    Write-Host "  - $($b.Name): $($b.Path)" -ForegroundColor DarkGray
    # 复制一份避免锁文件
    $tmp = "$env:TEMP\hist_copy_$($b.Name).db"
    Copy-Item $b.Path $tmp -Force -ErrorAction SilentlyContinue
    try {
        $conn = New-Object System.Data.SQLite.SQLiteConnection("Data Source=$tmp")
        $conn.Open()
        $cmd = $conn.CreateCommand()
        # downloads 表: start_time 是自1601-01-01起的微秒数(Webkit时间)
        $cmd.CommandText = @"
SELECT target_path, url,
       datetime(start_time/1000000 - 11644473600, 'unixepoch','localtime') AS dl_time
FROM downloads
WHERE dl_time >= '$($winStart.ToString('yyyy-MM-dd HH:mm:ss'))'
  AND dl_time <= '$($winEnd.ToString('yyyy-MM-dd HH:mm:ss'))'
ORDER BY dl_time
"@
        $rdr = $cmd.ExecuteReader()
        $any = $false
        while ($rdr.Read()) {
            $any = $true
            Write-Host ("    [{0}] {1}`n        URL: {2}" -f $rdr['dl_time'], $rdr['target_path'], $rdr['url'])
        }
        if (-not $any) { Write-Host "    (该时段无下载记录)" -ForegroundColor DarkGray }
        $conn.Close()
    } catch {
        Write-Host "    读取失败(缺少SQLite驱动或格式差异): $_" -ForegroundColor Red
        Write-Host "    提示: 可用免费工具 'DB Browser for SQLite' 直接打开上面的 History 文件查看 downloads 表。" -ForegroundColor DarkGray
    }
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
}

# ---------- 3. Windows 事件日志: 该时段的登录与会话 ----------
Write-Host "`n【3】Windows 事件日志 (登录/注销, 需管理员权限才完整)" -ForegroundColor Yellow
try {
    $logons = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4624; StartTime=$winStart; EndTime=$winEnd } -ErrorAction Stop
    if ($logons.Count -eq 0) { Write-Host "  - 该时段无登录事件记录" -ForegroundColor DarkGray }
    else {
        $logons | ForEach-Object {
            $x = [xml]$_.ToXml()
            $acct = $x.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' } | Select-Object -ExpandProperty '#text'
            $typ  = $x.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonType' } | Select-Object -ExpandProperty '#text'
            Write-Host ("  {0}  用户={1}  LogonType={2}" -f $_.TimeCreated, $acct, $typ)
        }
    }
} catch {
    Write-Host "  - 无权限或未开启审计策略: $_" -ForegroundColor Red
    Write-Host "    开启方法: secpol.msc -> 高级审计策略 -> 登录/注销 -> 审核登录(成功)" -ForegroundColor DarkGray
}

Write-Host "`n===== 排查完成 =====`n" -ForegroundColor Cyan
