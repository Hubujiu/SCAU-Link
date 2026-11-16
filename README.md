# SCAU Link

华南农业大学校园网 Windows 原生客户端，使用 C++20、Win32、Direct2D 和 DirectWrite，无网页运行时。

[下载安装包](https://github.com/Hubujiu/SCAU-Link/releases/tag/v0.14.4-preview) · [首次使用](docs/SCAU-First-Run-0.14.4.md) · [验证报告](docs/Network-Delivery-Results-0.14.4.md)

0.14.4 将自启改为零延迟登录任务，网卡变化即时唤醒连接检查，并明确区分有线抓包驱动故障与账号认证拒绝，见 [自启和有线说明](docs/Startup-Wired-0.14.4.md)。每次版本变更提交并推送 GitHub，通过对应 CI 后发布签名 Release，客户端才能检查到更新。

## 使用

安装到所需目录，在“账号”页保存校园网账号和密码，然后选择有线 802.1X、SCAUNET Web 或 SCAUNET_1x。三种连接方式共用账号；网卡和学校参数在本机生成，无须原锐捷、抓包或导入配置。有线需要已安装的 WinPcap/Npcap，无线使用 Windows WLAN/EAP；电脑须有可用的 IP/DNS 配置。

支持多账号拖动排序，按顺序登录，明确的账号拒绝重试一次后尝试下一账号；环境错误和未知认证结果不会盲目换号。当前成功认证的账号显示“活跃中”。主页和账号页查询余额、套餐周期费用及已知期限；主页根据余额可支付的完整周期显示“预计到期”，有当前账期时先保留本期剩余时间，固定天数套餐按实际天数、月费套餐按自然月计算；仅有余额与月费时从当天估算。学校明确返回的到期日优先，缺少必要数据时显示未知或本期剩余天数，预计扣费日期明确标注。Web 已放行但无法核实账号时显示“账号未确认”。

开机自启默认关闭；开启后在当前 Windows 用户登录时立即触发，等待网卡及驱动就绪，使用保存的凭据，默认复用上次选择的连接方式，也可设置有序备用方式。静默启动不显示窗口和通知，失败记录在本机。小窗只保留连接操作；关闭窗口收起到托盘，核心异常后自动恢复。

安装向导支持其他盘符、中文及空格路径，默认按当前用户安装，携带应用本地 VC++ 运行库。安装过程不启动认证、不安装驱动、不结束现有客户端；卸载保留用户凭据和设置。

## 更新

设置页“检查更新”支持手动更新；默认空闲两分钟后后台检查和下载，每六小时检查一次。0.14.0 会核对签名兼容说明、认证核心和运行库的摘要：兼容时显示“无需断网”，在线替换磁盘文件，保留原认证进程，新界面下次启动生效。需要完整安装时显示“更新时可能断网”，手动确认后才断开，自动更新则等待连接已断开。小窗设置仍只显示“退出小窗模式”。

更新来自本仓库 Releases，使用标准 Windows TLS、Ed25519 签名和 SHA-256 校验。完整安装由独立助手等待主进程退出后执行。0.13.0 及更早版本首次升级仍按旧流程退出并安装本版。见 [更新机制与发布步骤](docs/Updates-0.14.0.md)。

## 数据与验证范围

账号和密码保存在当前 Windows 用户的凭据管理器；`%LOCALAPPDATA%\ScauLink` 保存设置、账号随机标识及脱敏记录。密码不进入命令行、普通配置或日志。学校旧证书兼容限定于学校端点，GitHub 更新使用正常证书验证。仓库、安装包和源码包均不包含私人抓包、配置、Cookie 或发布私钥。

本版 Release CTest **37/37** 通过，含真实隔离登录任务的注册、设置、禁用及清理验证，以及驱动错误从工作进程到界面的回归。本机旧 NPF 驱动停止且启动服务被拒绝访问，仍需管理员修复；未实测重启耗时或恢复后的有线认证。详见 [验证报告](docs/Network-Delivery-Results-0.14.4.md)。

客户端按认证核心与运行库的实际摘要决定更新方式。此前本机普通权限下完成的 Web 新登录、SCAUNET_1x 登录及核心崩溃后重登属于 [0.12.0 历史证据](docs/Network-Delivery-Results-0.12.0.md)。本版未重新实测无线新登录、其他电脑、Windows 实际重启、漫游、休眠或长时在线，也未提交真实改密及校园网暂停／恢复。

## 构建

需要 Windows 10/11 x64、Visual Studio 2022 Build Tools、Windows SDK、CMake 和 Python 3.12+：

```powershell
.\scripts\build.ps1 -Configuration Release
```

脚本校验随源码提供的 OpenSSL 源码，首次下载并校验便携 Perl，在工作区静态编译依赖。版本、来源及许可见 `third_party/openssl/`。GitHub Actions 在 Windows 2022 上编译并执行离线检查，不使用校园账号或发布私钥。

运行 `build/Release/SCAU-Link.exe`，保持 `scau-auth.exe`、`scau-update.exe` 和运行库 DLL 在同一目录。仅查看演示可使用 `--demo-package` 或 `--demo-update`，不会发起校园认证。

```powershell
python scripts/package_desktop.py --preview
python scripts/build_installer.py --preview
```

打包脚本要求先准备当前版本的程序、运行库和验证记录；详见脚本中的校验。对应源码随安装包放在 `docs/source.zip`，便携包放在 `source/`。

图标使用 Lucide，应用标识源文件为 `assets/app-icon.svg`。已生成的矢量路径和 ICO 随源码提供，正常构建无需图像工具。许可为 GPL-3.0，第三方许可见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
