# NetLedger — Windows 网络流量监控日志归集系统

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell)](https://github.com/PowerShell/PowerShell)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11%20%7C%20Server%202016%2B-lightgrey)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

> 一套纯 PowerShell 工具，实现 Windows 系统网络流量全量监控、日志归集与异常检测。

## 功能特性（Features）

- **一键初始化** — 自动配置审计策略、开启 DNS 日志、下载安装 Sysmon、注册定时任务
- **多源数据采集** — 从 6 个数据源（Security 5156/4688、DNS 3008、Sysmon 1/3/11）采集网络活动
- **智能异常检测** — 自动识别：非常用端口连接、凌晨异常活动、DNS 解析失败（疑似 DGA）、首次出现域名、大文件下载、可疑进程
- **结构化日报** — 中英双语，统计汇总 + 明细记录，记事本/VS Code 可直接打开，方便 AI 分析
- **零外部依赖** — 纯 PowerShell，Sysmon 自动下载，无需安装任何第三方工具
- **自动维护** — 定时采集（每日 00:30 + 开机自启）、过期日志自动清理

## 快速开始（Quick Start）

```powershell
# 1. 进入脚本目录
cd scripts/

# 2. 初始化（以管理员身份运行，只需一次）
.\NetworkMonitor.ps1 -Mode Init

# 3. 查看状态
.\NetworkMonitor.ps1 -Mode Status

# 4. 手动采集
.\NetworkMonitor.ps1 -Mode Export

# 5. 查看报告（在 D:\NetworkMonitor\logs\ 目录）
ls D:\NetworkMonitor\logs\
```

## 项目结构（Project Structure）

```
NetLedger/
├── scripts/
│   ├── NetworkMonitor.ps1              # 核心主脚本
│   └── Uninstall-NetworkMonitor.ps1    # 卸载脚本
├── config/
│   └── sysmon-config.xml              # Sysmon 配置文件
├── docs/
│   ├── 原始需求.md                     # 原始需求文档
│   ├── ARCHITECTURE.md                # 架构文档（AI 可读）
│   ├── DEVELOPMENT.md                 # 开发指南（AI 可读）
│   ├── DESIGN-DECISIONS.md            # 设计决策（AI 可读）
│   ├── user-guide.zh-CN.md            # 用户使用指南（中文）
│   ├── user-guide.en.md               # 用户使用指南（英文）
│   ├── faq.zh-CN.md                   # 常见问题（中文）
│   └── faq.en.md                      # 常见问题（英文）
├── README.md                          # 项目主文档（中文）
├── README.en.md                       # 项目主文档（英文）
└── README.txt                         # 部署版使用说明
```

## 文档索引（Documentation Index）

| 文档 | 对象 | 语言 |
|------|------|------|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | AI / 开发者 | 英文 |
| [DEVELOPMENT.md](docs/DEVELOPMENT.md) | AI / 开发者 | 英文 |
| [DESIGN-DECISIONS.md](docs/DESIGN-DECISIONS.md) | AI / 架构师 | 英文 |
| [user-guide.zh-CN.md](docs/user-guide.zh-CN.md) | 用户 | 中文 |
| [user-guide.en.md](docs/user-guide.en.md) | 用户 | 英文 |
| [faq.zh-CN.md](docs/faq.zh-CN.md) | 用户 | 中文 |
| [faq.en.md](docs/faq.en.md) | 用户 | 英文 |

## 卸载（Uninstall）

```powershell
cd scripts/
# 基础卸载
.\Uninstall-NetworkMonitor.ps1

# 完全卸载（含日志和脚本）
.\Uninstall-NetworkMonitor.ps1 -RemoveLogs -RemoveScripts
```

## 兼容性（Compatibility）

- Windows 10 / Windows 11
- Windows Server 2016 及以上
- PowerShell 5.1+（推荐 7.6+）

## 许可协议（License）

MIT License
