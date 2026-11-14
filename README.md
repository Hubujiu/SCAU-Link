# SCAU Link · Windows 原生客户端

0.12.0 预览安装向导为 `out/SCAU-Link-0.12.0-Setup-x64-preview.exe`，支持自定义目录。账号密码保存一次后共用于有线、SCAUNET Web 和 SCAUNET_1x；开机连接默认跟随上次选择，也可指定有序备用。最终构建通过普通用户权限下两次 Web 新登录、1x 登录/核心崩溃重登、Web 已放行状态/核心恢复、接口绑定上网及套餐字段查询。34 项 CTest 全部通过，其中包括 17 项离线实验故障与恢复测试。当前有线客户端未被替换，网络设置已恢复。见 [本轮实测报告](docs/Network-Delivery-Results-0.12.0.md)、[首次使用](docs/SCAU-First-Run-0.12.0.md) 和 [实验脚本](docs/Network-Delivery-Lab.md)。本轮没有实际重启 Windows、其他电脑和长时稳定性测试，保留预览标记。

安装向导可输入路径或浏览选择目录，支持其他盘符、中文和空格。默认安装到当前用户目录，可选快捷方式，完成后默认不启动应用。卸载保留账号和设置。Visual C++ 运行库随应用安装，有线模式所需 WinPcap/Npcap 驱动由用户自行安装。构建预览安装版运行 `python scripts/build_installer.py --preview`；首次会校验并下载便携编译工具到工作区。源代码副本随安装版放在 `docs/source.zip`。

0.10.0 在连接页增加“有线 802.1X / 无线 Web”切换；切换前先断开，小窗沿用选定模式。无线 Web 使用物理无线网卡，先由 Windows 连接 `SCAUNET`，程序自动发现认证页面；首次发现时在原生界面确认来源，不需要填写服务器地址。随后复用保存的账号密码和列表顺序，明确拒绝时重试一次再轮换。无线模式不依赖 Npcap，不会切换 SSID、调整路由或结束其他客户端。未知登录结果停止自动重发。协议、链路恢复与来源绑定通过离线及回环测试；**当前学校无线 authAPI、首次页面来源及长期在线仍未实网验证**。见 [无线实现](docs/SCAU-Wireless-Web-20261114.md)。

账号右键新增“修改密码”：输入旧密码、新密码及确认密码，再次点击确认后按原客户端接口单次提交。只有服务器明确成功才更新 Windows 凭据管理器；失败或结果未知保留本地旧密码，不自动重发、不主动断开当前连接。表单保留“信息门户改密”和必要时的“官方自助”入口，兼容接口不等同于统一身份认证密码同步。**未提交真实学校改密，当前学校端是否接受此历史客户端接口尚未验证**。见 [改密请求证据与边界](docs/SCAU-Password-Change-20261114.md)。

REA 确认原产品通过 Windows WLAN/EAP 实现无线 802.1X，0.11.0 已接入这条系统认证路径。小锐 WiFi 为热点共享，未实现，也没有足以确认 PPPoE / VPN 登录的证据。见 [原版上网模式调查](docs/SCAU-Connection-Modes-20261114.md)。

0.9.0 首次使用只需填写账号、密码并点击登录。程序自动选择物理有线网卡、使用学校服务名并读取本机设备标识，在用户目录生成 `connection.scau`；无须原锐捷、抓包或配置导入。未接网线时等待接入，不以尚未取得 IPv4 为由阻止二层认证。已有本机旧配置可自动迁移，原文件保留。Npcap 仍是系统驱动依赖。见 [自动连接参数与验证边界](docs/SCAU-Automatic-Setup-20261114.md)。

0.8.1 接入学校“我的套餐”完整页，按实际固定天数显示周期费用；周期、正常状态和余额满足条件时显示“预计下次扣费”，与学校明确返回的实际扣费时间分开。见 [费用来源与估算边界](docs/SCAU-Billing-Query-20261114.md)。

0.8.0 新增在线设备数，以及“账号 → 右键 → 校园网”的暂停／恢复面板。真实自有账号在两处响应中均返回在线数 2，已验证正常状态、暂停权限及自身目标；设备明细页仍报学校端查询失败。暂停／恢复需在原生界面再次确认，单次提交后只读核对，不自动重试写操作。真实暂停、恢复没有执行，两个方向通过离线测试。见 [接口与验证范围](docs/SCAU-Campus-Service-20261113.md) 和 [0.8.0 验证记录](docs/validation-0.8.0.json)。

沿用静态链接 OpenSSL 3.5.9 兼容学校 MD5 签名证书与旧接口 GET 格式。真实自有账号已取得余额及本期截止日期；学校未明确提供的月费和下次扣费时间显示“未知”，不从套餐名称或余额推算。证书例外只作用于固定学校主机，不修改系统信任或认证核心。

账号采用独立圆角横条，右键提供“管理 / 修改密码 / 校园网 / 删除 / 置顶”，支持浮起拖动排序，认证成功的账号标记“活跃中”。使用 C++20 / Win32 / Direct2D / DirectWrite，保留现有认证工作进程与崩溃守护。

构建后运行 `build/Release/SCAU-Link.exe`。首次在“账号”页输入校园网账号与密码，登录后凭据存入当前 Windows 用户的凭据管理器；以后启动均自动登录。原客户端 `8021x.exe` 仍在运行时，新应用会提示冲突，不会结束原进程或启动并发认证。请在准备好切换时自行退出原客户端。

账号页最多保存 32 个账号，每个账号占一行。右键“管理”展开所选账号的表单，“删除”会确认后移除，“置顶”把这一行移到最上面，其他行保持相对顺序。也可拖动或选中后按 Alt+↑/↓ 排序。没有独立默认账号；最上方就是下一轮首先使用的账号。“活跃中”只标记当前已认证成功的账号。在线时修改和排序应用于下一轮登录。密码留空保留已有密码，更改账号名时需要重新输入密码。

每轮登录从第一行开始，按列表自上而下尝试；当前账号明确认证失败后再重试一次，仍失败则切换到下一行。每轮每个账号最多尝试两次，全部失败后停止。网线等待、环境错误、协议不兼容、服务器下线和核心崩溃不会被当成换号条件；手动断开会取消整轮。连接成功后继续使用成功账号进行断线恢复，不自动改动列表顺序。

桌面版设置只有“小窗模式”“开机自启”“静默启动”。小窗模式保留连接、登录和断开；小窗的设置页只保留“退出小窗模式”。核心异常恢复、连接状态通知和关闭到通知区域固定开启。静默启动时不显示窗口或状态通知，失败保留在记录中；从托盘打开后恢复交互反馈。自动登录不需要额外开关。

通知区域左键打开/收起窗口，右键菜单为连接/断开、打开窗口、设置、退出。关闭或最小化窗口只隐藏视图；退出才结束认证。启动项只写入当前用户的 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SCAULink`，不安装服务或计划任务。默认不开启开机自启或静默启动，开启前请把程序放在固定目录。

页面首次进入才创建控件并缓存，记录进入页面或点击刷新时才在后台读取。记录最多显示 200 条；每次只读取最近三个会话和桌面记录各至多 128 KiB 的尾部。可打断的解析弹簧负责页面、导航标记、开关、悬停与窗口过渡；系统关闭动画时直接到达终态，静止后停止动画计时器。文字格式、矢量路径与渐变画刷缓存复用。网络和文件操作在后台执行。

配置和脱敏事件记录位于 `%LOCALAPPDATA%\ScauLink`；账号名和密码保存在 Windows 凭据管理器中，`accounts.dat` 只记录随机标识与列表顺序，密码不进入 INI、命令行或普通日志。修改凭据采用版本化写入与原子目录提交。兼容导入旧版单账号及 0.5 的多账号目录，保留列表顺序并忽略旧的默认设置；新提交采用 SCAUAC02 格式。认证参数自动在本机生成，服务端地址由本次 Identity 交换发现；不会搜索工程父目录或私人抓包。交付压缩包不含私人抓包或本机配置。

环境：Windows 10/11 x64、已安装的 WinPcap/Npcap 及 Visual C++ 2022 x64 运行时。驱动权限不足时认证会失败；应用不会自动提权、改动路由或修改驱动设置。

以下命令只运行界面演示，不读取正式凭据、写启动项或发起网络认证：

```powershell
.\build\Release\SCAU-Link.exe --demo-online
.\build\Release\SCAU-Link.exe --demo-first-run
.\build\Release\SCAU-Link.exe --demo-web
.\build\Release\SCAU-Link.exe --demo-web-portal
.\build\Release\SCAU-Link.exe --demo-1x
.\build\Release\SCAU-Link.exe --demo-package
.\build\Release\SCAU-Link.exe --demo-online --mini
.\build\Release\SCAU-Link.exe --demo-failover
.\build\Release\SCAU-Link.exe --demo-failure --silent
```

桌面版验证见 [0.12.0 验证记录](docs/validation-0.12.0.json)。[本轮界面证据](docs/ui-native-0.12.0-preview/) 包含最终构建的五项启动选择和小窗检查，真实联网证据单独记录。历史界面及 0.11.1 有线测试保留原构建摘要和范围，不归为本轮重测。重启 Windows、其他电脑、漫游、休眠与长时在线仍需实测。

构建使用已生成的 `src/desktop/icons.hpp`。需要从原型重新生成图标时，可在安装 Python `fontTools` 后运行 `scripts/generate_native_icons.py`；这不是运行或构建原生应用的必需依赖。

应用图标源文件为 `assets/app-icon.svg`；窗口、程序资源和托盘共用该标识。已生成多尺寸 ICO，正常构建不依赖图像工具；需要重新生成时使用 `scripts/generate_app_icon.py`，可选依赖 `resvg-py` 和 Pillow。

## 认证核心

Windows 原生 C++20 认证核心，使用 MSVC、Windows CNG、WinSock 和已安装的 WinPcap/Npcap。0.3.0 在标准 EAPOL、EAP MD5、锐捷 v3/v4 兼容扩展和链路恢复之上，完成 SAM 加密维护通道，以及认证工作进程崩溃后的自动重启与重新登录。

程序不启动原锐捷进行认证。0.9.0 桌面版自动准备硬件与学校服务参数；独立命令行核心的 `--profile` 仍是内部协议参数输入，可接受原生配置或研究用抓包。密码通过 Windows 凭据框或桌面版私有管道输入，不接受密码命令行参数，不写入协议配置文件。

当前兼容模式使用公开 MiniEAP 算法及其兼容版本头，和原 SCAU 6.86 的 EAP 扩展不逐字节相同。0.1.0 曾完成独立认证和 30 分钟在线观测，但自动切回流程导致过断网；0.1.1 起观察结束后保持连接。历史实测只属于 0.1.0。本轮 0.3.0 完成离线、原生进程夹具、本机 UDP 回环测试和只读预检，未切换当前原客户端，尚未实测新版校园网互操作或长时在线。详见 [0.3.0 实现与验证](docs/SAM-and-Crash-Recovery-0.3.0.md)、[历史实机记录](docs/SCAU-Native-Core-Validation-20261112.md) 和 [0.2.0 逆向记录](docs/SCAU-Longterm-Reverse-20261112.md)。

0.3.0 核心仍通过独立工作进程运行，0.4.0 桌面版负责窗口、托盘、持久凭据与启动项；未安装正式 Windows 服务。命令行工具仍需要本机的 x64 Visual C++ 运行时及 WinPcap/Npcap 驱动。

构建需要 Visual Studio 2022 Build Tools、Windows SDK、CMake 和 Python 3.12+。终端中运行：

```powershell
.\scripts\build.ps1 -Configuration Release
```

构建脚本校验随源码提供的 OpenSSL 源码归档，首次构建会下载并校验便携 Perl 编译工具，再生成原生静态库；不会安装到系统，也不需要另外分发 OpenSSL DLL。依赖版本与校验值位于 `third_party/openssl/provenance.json`，之后构建复用本地缓存。

检查配置与网卡访问，不发送认证报文：

```powershell
.\build\Release\scau-auth.exe --profile .\captures\20261112-164221\eapol-only.pcapng --probe
```

在已处理原守护进程和认证进程冲突的环境中，可以直接连接；本机验证优先使用下方受控切换脚本：

```powershell
.\build\Release\scau-auth.exe --profile .\captures\20261112-164221\eapol-only.pcapng --connect --duration 1800 --log .\captures\manual-events.jsonl --capture .\captures\manual-authentication.pcapng
```

程序弹出本机凭据框。`--duration` 指定观察窗口；到时记录结果，继续保持认证、接收请求和检查网络，不自动退出或发送 Logoff。Ctrl+C 或下方停止脚本才会请求断开。仅显式添加 `--disconnect-after-test` 时才在观察窗口结束后主动下线。

连接时启动一个会话守护进程和一个认证工作进程。账号密码只需输入一次，父进程使用 `CryptProtectMemory` 加密保存本次会话凭据，通过私有管道交给工作进程。工作进程异常退出后，以 1/2/4/8/16 秒等退避重新启动，重新发起 EAP 认证；五分钟内最多自动重启五次。连续已认证 60 秒后重置崩溃预算。正常退出、取消、明确拒绝及服务端下线均不会触发崩溃重试。关闭父进程会清除会话并结束其子进程；未实现关机后保存密码、开机自动登录或守护进程自身崩溃后的恢复。

每轮 Start 最多三次，间隔 3 秒；无响应则等待 10–29 秒后开始新一轮。Identity 与首次 MD5 各有一个 9 秒窗口，重复请求不延长该阶段。带明确原因或无法识别原因的服务端拒绝会停止自动重试；空原因失败与认证超时最多按 1/2/4 秒退避三次。事件日志不输出账号、密码、MAC、IP、Challenge、响应摘要或保活 key。诊断抓包包含原始认证信息，只保存在本机。

受控切换测试由管理员 PowerShell 脚本执行：

```powershell
.\scripts\Test-NativeAuth.ps1 -RunDirectory D:\Workspace\AiProjects\Ruijie\captures\native-test-manual -DurationSeconds 1800
```

该脚本先检查原守护进程能否暂停并恢复，再启动原生核心等待本机凭据。输入完成后，停止或临时暂停原守护进程、结束原认证进程，放行新核心。原服务拒绝停止控制时，脚本仅暂停其现有线程，不改变服务启动类型。

观察期结束后，核心和控制器继续运行，`status.json` 的 `online_test_passed_connection_held` 表示观察窗口通过；当前状态另见 `native_state` 与 `native_connected`。拔线会等待原物理网卡恢复，恢复后去抖并重开抓包句柄；睡眠恢复至少等待 5 秒。恢复过程中重新计算连续在线观察窗口，控制器只记录延迟，不因观察超时停止核心。需要断开、恢复原客户端时，在管理员 PowerShell 中明确执行：

```powershell
.\scripts\Stop-NativeAuth.ps1 -RunDirectory D:\Workspace\AiProjects\Ruijie\captures\native-test-manual
```

控制器恢复守护线程并打开原客户端，只在观察到新的 `AUTH_SUCCESS` 后确认认证恢复。如果原客户端未自动登录，状态为 `original_authentication_required`，需在原客户端中点击连接。进程启动本身不再计为联网恢复。

每次测试使用新的空目录，避免把先前的凭据就绪事件和本次日志混在一起。脚本会拒绝复用非空目录。

交付包不含私人抓包。使用解压包中的脚本时，以 `-ProfilePath` 指定本机的 `eapol-only.pcapng`；脚本优先使用构建目录中的程序，否则使用包根目录的程序。

一次测试的 `status.json` 记录切换与恢复结果；`events.jsonl` 记录认证阶段、SAM 安全事件、每 10 秒的在线样本及约每 30 秒一次的 HTTP 可达性检查；`events.jsonl.supervisor.jsonl` 单独记录工作进程崩溃、重启与终止。控制器会合并两份状态，避免崩溃期间沿用旧的“已连接”。HTTP 检查使用 Microsoft Connect Test 的公开固定响应，关闭 WinHTTP 代理和重定向。可达性与 EAP 认证状态分别记录。

如果系统使用 VPN/TUN，HTTP 检查仍可能经过虚拟网卡。可用 Python 辅助脚本补充绑定物理以太网的 DNS/HTTP 检查；该脚本不会更改网络设置：

```powershell
python -X utf8 .\scripts\probe_ethernet.py --log .\captures\native-test-manual\ethernet-probes.jsonl --status .\captures\native-test-manual\status.json --count 60 --interval 30
python -X utf8 .\scripts\summarize_native_test.py .\captures\native-test-manual --output .\captures\native-test-manual\summary.json
```

服务器 Success 每次重新解析维护参数：0x56 的重认证间隔单位是分钟，0 表示关闭；旧式 EAPOL 0xbf 保活仅在 enable 非零且周期有效时发送。SAM 解包本次 Key/IV 与服务器时间，按协商版本、端点和 HELLO 周期建立 DES-CBC 通道，逐片校验 MD5，处理可靠消息确认、重传、分片与服务器下线。0x80 仅在等于 1 时添加 SAM 完整性字段，不是全部心跳的总开关。

当前两份 SCAU 抓包的旧式 echo enable=0、重认证间隔=0、SAM HELLO 周期=0，因此不主动发送这些维护报文，但 0.3.0 仍绑定 SAM 接收端口并校验服务器消息。HELLO 非零时立即发送首包并按周期继续；普通 HELLO 不等待 ACK，不能把“已经发送”当成双向握手成功。SAM UDP 固定物理网卡与源 IPv4，不修改路由、网卡或防火墙配置。诊断 PCAPNG 仍只包含 EAPOL；SAM 日志只含事件类别与命令号，不保存服务器消息正文或会话材料。

0.3.0 已通过 14 组 CTest（含 Python 汇总器回归），覆盖合成 SAM 报文、密码学独立对照、真实 Windows 子进程崩溃、私有管道、父进程退出清理、本机回环 UDP 和抓包尾部恢复。此前的虚拟八小时及 47 次链路恢复回归仍通过；它们不代表实网八小时。0.9.0 新增独立生成学校协议配置、空目录首次登录与迁移检查；原客户端全部 ring 状态仍未逐项复刻，新机器实网兼容仍需验证。

项目复用的锐捷哈希代码保留上游 GPL-3.0 许可，见 `THIRD_PARTY_NOTICES.md`。驱动不随程序分发。`captures/` 和 `build/` 均被 Git 忽略。
