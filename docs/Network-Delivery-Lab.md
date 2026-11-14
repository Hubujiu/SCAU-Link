# 本机网络交付实验

入口：`scripts/Test-NetworkDelivery.ps1`。只使用本机已有 Python、Windows PowerShell、Windows WLAN API 和已构建的客户端，不下载依赖。无需聊天、浏览器、远程服务器或持续在线的终端驱动实验。

```powershell
# 离线故障注入，不接触真实网络、账号或应用数据
.\scripts\Test-NetworkDelivery.ps1 -Action SelfTest

# 使用全新的日志目录，开始真实实验
.\scripts\Test-NetworkDelivery.ps1 -Action Run `
  -RunDirectory 'D:\Workspace\AiProjects\Ruijie\captures\my-delivery-test' `
  -ObservationSeconds 120

# 查看已落盘的结果
.\scripts\Test-NetworkDelivery.ps1 -Action Status `
  -RunDirectory 'D:\Workspace\AiProjects\Ruijie\captures\my-delivery-test'

# 停止实验并自动恢复原客户端
.\scripts\Test-NetworkDelivery.ps1 -Action Stop `
  -RunDirectory 'D:\Workspace\AiProjects\Ruijie\captures\my-delivery-test'

# 需要单独重新执行本地回退时使用
.\scripts\Test-NetworkDelivery.ps1 -Action Restore `
  -RunDirectory 'D:\Workspace\AiProjects\Ruijie\captures\my-delivery-test'
```

当前入口针对本机安装目录 `D:\Apps\Network\SCAU Link` 和 0.11.1 预览版构建。四个应用/认证核心的 SHA-256 均固定校验；换构建后先更新校验值。可以通过 `-PythonPath` 指定已有的本地 Python 3，不使用在线安装或自动下载。

本机无线网卡的 IPv4 自动获取原本关闭，且无有效 IPv4 / DNS。如果需要临时启用 DHCP 来做完整无线联网实验，使用 `-Mode Wireless8021x -TemporaryWlanDhcp`。该选项会弹出 Windows UAC，要求用户确认；脚本不能替用户确认。仅测试看门狗/配置恢复进程提升权限，测试客户端与恢复后的原客户端均通过 Explorer 以普通用户权限启动。切换前保存在 `private/wlan-ip.before.json` 的仅为原 IP 配置，用于恢复原 DHCP 开关、静态地址和手动 DNS；它不包含账号密码，不进入公开报告或发布包。看门狗和控制器崩溃的离线测试同时检查了此配置的恢复。

默认不使用抓包驱动。`-CaptureEapMetadata` 仅供可选诊断，本机旧 WinPcap 在无线媒体切换时会中断，不能把该探针视为有效的无线抓包证据。常规实验只使用 Windows WLAN ACM/ONEX 的只读事件通知。

## 实验流程

1. 通过已有 Explorer 桌面启动隐藏的独立看门狗，避免 Codex 包环境的应用数据重定向。验证用户 SID、真实 LocalAppData、原客户端和核心的进程身份、已保存账号目录以及有线基线。
2. 复制运行脚本到本次 `runtime` 目录；同步落盘原设置备份、文件摘要、进程创建时间和接口信息。确认看门狗与控制器都已运行后，才开始切换认证。
3. 使用新版真实桌面应用的静默自动登录，测试有线认证、绑定有线接口的 DNS/HTTP、强制核心崩溃后的重新认证及短时在线观察。
4. 通过同一应用切换无线 802.1X，测试 SCAUNET_1x 认证、绑定无线接口的 DNS/HTTP、核心崩溃恢复、短时观察与停止。保留网卡启用状态，完全依靠接口绑定辨别无线与有线流量。
5. 无论通过还是失败，都停止测试客户端、恢复原设置，并启动原客户端。必须取得新的认证事件以及绑定有线接口的互联网检测通过，才记为回退成功。

观察时长是每种模式的时长。默认每种 120 秒；认证、核心恢复、DHCP等待和回退另有独立超时。默认整个测试硬上限为 900 秒，回退另留最多 110 秒。手动停止由本地文件触发，不需要网络。正常停止优先发送认证核心自己的停止事件，再退出测试桌面进程。

## 独立恢复与证据

看门狗监控控制器的进程身份、心跳和总时限。控制器也监控看门狗；任何一方异常，存活的一方都会执行本地回退。回退有文件锁，进程终止同时检查可执行文件路径、PID 和创建时间，避免 PID 被复用后误杀其他进程。设置以原始字节备份、核验和恢复；原本不存在设置文件时，回退后仍不存在。

每次实验目录包含：

| 文件 | 内容 |
|---|---|
| `preflight.json` / `baseline.json` | 切换前检查和有线接口绑定检测 |
| `controller.jsonl` / `watchdog.jsonl` | 实时落盘的事件与恢复过程 |
| `wired.json` / `wireless_8021x.json` | 各步骤通过、失败、时间与固定失败码 |
| `wlan-diagnostics.json` | Windows 无线事件的数字原因码，不包含原始事件正文 |
| `restored.json` | 设置、原客户端新认证与有线联网的恢复证据 |
| `result.json` | 实测结果，以及没有进行真实操作的项目 |
| `runtime` | 本次独立运行的脚本副本 |

不导出密码、Windows 凭据、账号文本、Cookie、Token、网页响应或数据包。账号仍由应用通过 Windows 凭据管理器读取。只清理实验新增且同时满足随机名称、允许的网络配置存储和当前用户自定义归属标记的 WLAN 配置，不删除其他无线网络配置。0.11.1 的网络配置使用所有用户存储；EAP 凭据仍仅设置给当前调用者。

## 验证边界

离线故障测试实际启动并强制结束子进程，检查控制器崩溃、看门狗崩溃、卡死、心跳超时、总时限、手动停止和慢回退等情况，并检查原设置逐字节恢复、PID 复用保护及日志脱敏。它不声称模拟了学校的 AP、RADIUS、真实账务接口或真实上网。

真实实验需要已保存的有效账号、当前工作的有线连接和初始断开的无线网卡。通过两分钟观察只能证明本次短时结果。无线漫游、休眠恢复和长时间稳定性需要另外的实际观察；无线 Web、改密码和校园网暂停/恢复没有在此实验中自动提交。机器关机、系统崩溃、磁盘损坏或两个恢复进程同时被外部终止不在进程看门狗的保证范围内。

只有真实证据通过的项目可以标为已验收；预览版不会因某个模拟测试通过而自动安装或替换正式版。
