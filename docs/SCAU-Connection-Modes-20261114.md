# 原锐捷客户端的上网模式调查

2026-11-14。对象为 `D:/Apps/Network/Ruijie Networks/Ruijie Supplicant`。本轮使用 REA 6.9.0 / Ghidra 12.2 做静态分析，并检查安装包公共界面资源。没有运行原二进制、附加进程、读取保存账号，或发送认证、退出、改密请求；没有变更网卡或系统配置。

## 结论

**原产品除有线 802.1X 和无线 Web 外，还有无线 802.1X 配置及 Windows WLAN/EAP 委托能力。小锐 WiFi 的 NAT / ICS 是网络共享方式。没有找到足以确认 PPPoE、主动拨号或 VPN 登录模式的证据。** 产品能力、学校部署与新版 SCAU Link 已实现功能需要分别判断。

| 功能 / 名称 | 原程序证据 | 可下的结论与边界 |
| --- | --- | --- |
| 有线连接 / 有线登录 | 公共布局 `authorModelWiredOpt`；选择处理器保存 `Wire`；认证分派进入原状态机。[E1, E2] | 原程序可选连接类型。有线 802.1X 已有本项目成功抓包，见 [抓包分析](SCAU-Capture-Analysis-20261112.md)。 |
| 无线连接 / 无线登录 | 同一 `authorModel` 单选组的 `authorModelWirelessOpt`；处理器保存 `Wlan`、切换无线网卡信息。[E1] | 原程序可选连接类型。公共标签本身没有把 Web 与 802.1X 列为两个同级单选项。 |
| 无线 Web / Portal | 主程序在另一认证分支建立工作线程，调用 `StartPortalAuth`，传入回调 `0x46a300`；DLL 的 HTTP 协议由独立无线 Web 调查保存。[E2, E3] | 已确认产品有 Portal 调用链；不能由此认定任意学校 Portal 的当前 API 都兼容。 |
| 无线 802.1X（WPA / WPA2） | 无线管理布局提供 SSID、WPA/WPA2、CCMP/TKIP；主程序加载 `WirelessCore.dll!ExportWireless`；DLL 实际调用 `WlanSetProfile`、`WlanSetProfileEapXmlUserData`、`WlanConnect`。[E4–E7] | 有 UI 与代码共同支持的产品能力。现代 Windows 路径由系统 WLAN/EAP 执行认证；本轮未连接无线网验证。 |
| 小锐 WiFi 热点 | `BodyHL_Wifi` 包含热点名、热点密码、设备管理、关闭按钮；`NATsharemode` / `ICSsharemode` 有独立配置处理；启动处理器检查 `rjwifi.exe` 与驱动状态。[E1, E8] | 网络共享功能；NAT / ICS 不是校园网登录协议。本轮没有启动或安装热点组件。 |
| PPPoE / 主动拨号 | 已检查的公共 XML 没有对应登录控件；主程序定义字符串中未匹配 `PPPoE` 或 `RasDial*`；实际 `RasEnumConnectionsA` 路径只枚举已有连接并排除类型 `vpn`。[E9] | 只能报告“未确认支持”。拨号检测线程不足以证明能创建、登录拨号连接。 |
| VPN | `MsVPNServer` 的引用位于 `CheckHomeShare`：枚举正在运行的 `RemoteAccess` 等服务并生成共享规避消息。[E10] | 该字符串是检测逻辑证据，不能据此声称存在 VPN 登录模式。 |
| MD5 / PEAP / 有线 TLS / 无线 TLS | 配置解析器读取 `custom_info/auth_method` 下四个 `support_*` 开关。[E11] | 属于 802.1X 认证方法能力配置；此处静态开关不证明当前部署启用或本项目已实现全部方法。 |

## 学校与产品能力的对应

学校公开说明把 `SCAUNET` 定义为网页认证，把 `SCAUNET_1x` 定义为 802.1X，并给出 WPA2 企业 / AES 与 Windows 原生连接步骤。它支持“学校存在两类无线接入”的结论；这是 2019 年发布的说明，本轮没有实测当前 AP 或账号策略。[学校接入说明](https://metc.scau.edu.cn/2019/1225/c126a216614/page.htm)

图书馆的 2017 年说明记录了连接 `SCAUNET` 后由浏览器跳转 ePortal 的流程。它没有公开本轮所需的全部客户端 API 契约。[图书馆无线网络说明](https://lib.scau.edu.cn/2017/1128/c11489a247971/page.htm)

新版界面可以继续提供已实现的“有线 802.1X / 无线 Web”。原产品的无线 802.1X、热点或认证方法开关应作为后续能力依据，不能直接显示为已可用功能。

## 证据索引

完整证据位于 [`captures/connection-modes-20261114/`](../captures/connection-modes-20261114/)，其中 `rea-combined-evidence-bundle.json` 保留本轮两个原生目标的 REA 记录与限制。`public-resource-manifest.json` 记录原始文件和 ZIP 成员的 SHA-256；`public-resource-text/` 是公共布局的解码副本，不是用户配置。

| 编号 | 文件 / 地址 | REA Evidence ID |
| --- | --- | --- |
| E1 | `layout_softwareconfig.xml:78–79`；`FUN_0052a880` 处理 `Wire/Wlan` 与独立 `WifiShareMode` | `ev_5f97f2324631cda58f900ee1a47bd86cbd726fb6ac67b3f33565f2af41d61793`；ZIP 完整盘点 `ev_07c10a26b43a3d62030c757bd95a1383d9dd43d332bb0de4ab0c477facad9c7b` |
| E2 | `FUN_0046d9a0`：状态机 / Portal 工作线程分派 | `ev_5a953c4f4dc9493d1b9a915afd25366d4190ac06cff582c04efff00549f46b18` |
| E3 | `FUN_0046d120`，`0x46d8d3–0x46d8e7`：传回调并调用 `StartPortalAuth` | `ev_4adbf1be12bb4413371359315cdb4e7c1a9d7c5d889c8aa46065c31d19b46665`；汇编 `ev_17864268ff99aa66400629a4a7add07cbe4cc7f8fa5a1e5a3c5bdda4e0e20e57` |
| E4 | `layout_advancedconfig.xml:56–68`；主程序 `FUN_0055bed0` 动态加载 WirelessCore | `ev_1422d34d81ea75ab901ba9c6eb3d393828958349d3764babed5c9a6257621ad8` |
| E5 | WirelessCore `FUN_10009f00`：`WlanSetProfile` | `ev_243a3d7b7c259f3347f8f9bdb9d1fab05775768abffb123a4d8f8b37e3f0f7d6` |
| E6 | WirelessCore `FUN_1000bff0`：组装 EAP 用户凭据 XML 并交给系统 | `ev_61316354d7da6f54eda00a2b638c9d07a80fd58d2b43f0aafb7fc947346c1a40` |
| E7 | WirelessCore `FUN_1000ace0`：按配置调用 `WlanConnect` | `ev_5c80be3c943faa186fc34468fa6c9a6cd6cd98eb9c0f82f9549c4ab12a7309f9` |
| E8 | `layout_authdialog.xml:93–134`；`FUN_00432560` 热点启动处理 | `ev_3a6b7a9619d2ef9781bc704fdaa8ee94a6487b31054b5f06532273d869b1209c` |
| E9 | `FUN_00457380` 枚举已有 RAS 连接；有界名称搜索无匹配 | `ev_23a3c1180ae1b171f557622318a2dbdfc6002c86c510e711f5a1d5d09f156008`；`ev_e4b7fd9ff159a6bfe1ef10dff204707fdbb19a11afbb10558e585de1e1d24948` |
| E10 | `FUN_00467450` / `CContextControlThread::CheckHomeShare` | `ev_726ebe8bc655b80b9491fa7b6873ae645d18658202e1d57100f605a16316e329` |
| E11 | `FUN_00485690`；证据由并行密码调查提供，位于 `captures/password-change-20261114/pseudo-0x486935.json` | `ev_132c73a0444bdb472df8f405c19eed7ddf604f4225b98df117a07753ef9b109c` |

主程序 SHA-256：`1a782d368b253f2035927d6439f9ad184e7fd6dddc196d6a6688a414129da7ee`。WirelessCore：`3cc5798201473668559a3154477bbfbd01efe50ac4816830c2429ecb316919c3`。根目录 newskin.zip：`dd9124032f983aa0f4fc6a797494e8cb846cfb09333201551d777c5ac73ab170`。

另外对 `RJIX.dll`、`RuijieSupplicant.exe` 做了 REA 导出表盘点：前者仅列出 `CreateContextObject` / `FreeContextObject`，后者没有导出目录。这两个结果本身不能判断其登录能力，未用作“不支持其它模式”的依据。证据为 `ev_4fc07528b1863c75f3f4d0ed3157a5ec5e953dfab096ae72825ccf73afeab604` 与 `ev_74a6ebdbb61f8d2c8d17379509d7aa2fdd65a1a08fb09df0ea9c814f54ca0152`。

## 未验证事项

这是静态调查，反编译输出不是原源码。Windows 分支的存在不证明原版本在本机当前系统或校园 AP 上正常运行。字符串搜索仅覆盖 Ghidra 已定义字符串；没有匹配不证明所有字节或动态加载逻辑都不存在。`uiCHS.ini`、`uiENG.ini` 的常规文本解码失败，未将乱码用作证据；未读取 `users`、保存凭据或 `Conf/Wireless/baseXml/userCredential.xml`。

主程序 Portal 回调与 `keepaliveInterval` 的完整后续消费关系仍未确定，没有据此杜撰心跳接口。学校网页、原厂 Portal 客户端和当前校园部署的完整兼容性需在用户选择无线网络后另行验证。
