# 历史研究记录

本文保留早期研究和对应版本证据。0.12.0 产品改用固定 `SCAUNET_1x` 配置名，并已在普通用户权限下完成认证与核心重登；当前行为见 [0.12.0 报告](Network-Delivery-Results-0.12.0.md)。

# SCAUNET_1x 无线 802.1X：实现与验证

日期：2026-11-14；版本：0.11.1 预览版。

本轮实现了原生 Windows WLAN/EAP 认证路径，连接页可选择有线 802.1X、无线 Web、无线 802.1X。后者自动连接固定 SSID `SCAUNET_1x`，复用保存的账号与列表顺序。无线模式不依赖原锐捷或 Npcap，不需要提前连接该 SSID，也不等待 IPv4/DHCP 后才发起二层认证。

## 协议依据

学校公开说明将 SCAUNET 定义为网页认证，将 SCAUNET_1x 定义为无线 802.1X，给出 WPA2 企业 / AES 与手动密码认证配置。该说明发表于 2019 年，不能证明当前 AP、RADIUS、证书或账号策略没有变化。

- [学校接入说明](https://metc.scau.edu.cn/2019/1225/c126a216614/page.htm)
- [Microsoft WPA2 / PEAP-MSCHAPv2 配置示例](https://learn.microsoft.com/en-us/windows/win32/nativewifi/wpa2-enterprise-with-peap-mschapv2-profile-sample)
- [Microsoft PEAP 用户凭据结构](https://learn.microsoft.com/en-us/windows/win32/eaphost/peap-ms-chapv2-user-properties)

前轮 REA 对原 `WirelessCore.dll` 的静态证据已保存，无需再次执行目标：`FUN_10009f00` 调用 `WlanSetProfile`；`FUN_1000bff0` 构造 EAP 用户凭据并调用 `WlanSetProfileEapXmlUserData`；`FUN_1000ace0` 调用 `WlanConnect`。见 [原版模式调查](SCAU-Connection-Modes-20261114.md) 的 E5–E7。实现没有加载或调用厂商 DLL，没有读取原客户端的 userCredential.xml 或保存密码。

## 实现

`src/desktop/wlan_8021x.hpp/.cpp` 使用 WPA2-Enterprise / AES、PEAP 类型 25、内部 EAP-MSCHAPv2 类型 26。认证身份仅为所选校园网账号，不使用 Windows 登录凭据、机器身份或域登录密码。

连接页的“无线 802.1X”只增加一种模式，不增加认证参数表单；小窗沿用模式。选择模式需先断开当前客户端连接。该设置持久化为 Desktop/ConnectionMode=2，已有 0/1 分别保持有线与无线 Web。

每轮认证为每个账号生成随机的 32 位十六进制配置标识；守护进程重启该轮工作进程时沿用标识。配置名称不包含账号、密码或密码哈希。0.11.1 使用 Windows 所有用户网络配置存储，manual、autoSwitch=false；EAP 用户凭据仍仅属于当前调用者。不会覆盖用户自己配置的 SCAUNET_1x。重用同名配置必须同时匹配应用命名规则、选定的网络配置存储和当前用户的自定义所有权标记；否则停止。

该变化来自本机真实对照实验：同一账号、接口和 PEAP 参数，当前用户网络配置持续等待 EAP；使用所有用户网络配置后约一秒完成认证。直接 C++ 诊断也得到相同结果，排除了桌面凭据传递作为主要原因。Windows 的取消原因码出现在测试超时后的清理阶段，不能解释为密码错误。该主机普通用户可以创建此类网络配置；受策略限制的机器仍应报告环境错误，不自动提权。

密码只通过既有加密会话与私有双管道交给工作进程。EAP XML 的用户名与密码经过 XML 转义和 Unicode 检查，临时缓冲区清理；配置 XML 不包含密码。`WlanSetProfileEapXmlUserData` 的 flags=0，仅给当前调用者设置凭据，Windows 会为该专属配置保存一份 EAP 用户数据。正常结束时尝试删除该配置及对应 EAP 数据；进程被强制终止时可能留下手动配置。后续认证只在无线网卡断开时，有限清理符合所有权标记的残留配置，不删除其他用户或已有校园网配置。

按学校公开的旧版手动设置，本兼容配置的 PEAP `PerformServerValidation=false`、`AcceptServerName=false`，仅适用于应用生成的 SCAUNET_1x 配置。它不验证 RADIUS 服务器证书身份；没有修改系统证书信任、其他无线配置或 HTTP TLS 策略。本轮没有获取当前校园 RADIUS 证书，不能声称已完成其身份绑定。学校部署若改用其他 EAP 方法或需要新的证书策略，需根据实网结果调整。

## 状态与恢复

`WlanConnect` 返回成功仅表示 Windows 接受请求；不会直接显示已连接。只接受目标物理接口 GUID、此次专属配置名、精确 SSID、基础设施模式、安全启用且原因码成功的 ACM connection_complete。EAP 成功事件或已有 IPv4 单独出现均不足以标记 Online。

注册 ACM 与 ONEX，不注册 MSM，不扫描 AP，不调用 BSSID / current_connection 查询，不请求定位权限。Microsoft 对新版 Windows 中可能要求定位的接口有明确说明：[Wi-Fi API 与位置权限变化](https://learn.microsoft.com/en-us/windows/win32/nativewifi/wi-fi-access-location-changes)。

ONEX 错误仅在本次 ACM 连接上下文中解析，且对变长结构做长度、偏移与溢出校验。只有 Windows 明确给出登录失败、无效密码、账号禁用/到期等错误，并且本次连接最终失败，才返回账号拒绝，进入现有的“一次重试后下一账号”。泛化 EAP 失败可能是证书或组件问题，不推断为密码错误；保留 Windows 数字原因码及错误码，不编造欠费、并发数或禁网时段。

信号不可见、适配器暂时断开或系统暂忙时，以 1/2/4…30 秒退避继续当前账号；失去连接后重新等待安全连接完成。没有信号不会遍历账号。连接请求 60 秒仍无最终结果则显示结果未确认并停止主动重发。用户或其他程序切换无线连接后停止自动重连。手动断开通过停止事件取消工作进程，尝试结束本次连接并删除自己的专属配置；不结束当前有线认证或改路由。

系统 WLAN 服务停止、权限限制、EAP 组件不可用等显示环境错误。程序不自动启动系统服务、提权、关闭 Credential Guard 或修改 Windows 隐私设置。重启、休眠、USB 重插与漫游的现网行为仍需单独验证。

## 验证范围

- Release 编译通过；34 项 CTest，包括新增的本地实验恢复测试。
- `wlan-8021x-tests`：622 项检查，包括默认使用所有用户网络配置、EAP 配置与合成凭据解析、通知截断/偏移/接口/配置/SSID过滤、连接完成、明确拒绝、未知结果、信号恢复、取消、外部切网和环境错误。
- 后台集成测试覆盖首次保存账号直接进入所选无线模式、在线禁止切换模式、手动断开及三种模式持久化，均使用演示夹具。
- 原生界面的历史演示检查和对应二进制摘要保留在 `ui-native-0.11.0-preview/`；演示“已连接”不代表校园认证结果。
- 在用户授权下，0.11.1 普通权限真实桌面客户端已完成 SCAUNET_1x 认证、接口绑定的 DNS/HTTP 互联网检测，以及强制终止核心后的新核心认证。实验脚本、最终观察时长和回退结果见 [本机实验说明](Network-Delivery-Lab.md) 与 [本轮实测报告](Network-Delivery-Results-20261114.md)。

本机 WLAN 原配置关闭 IPv4 DHCP，且没有有效静态地址和 DNS。EAP 成功本身不代表互联网可用。测试通过单独授权的临时 DHCP 选项完成地址获取，结束后恢复原配置。客户端没有自动修改主机 IP 配置。真实凭据只由本地应用读取，不进入命令行、聊天、公共日志或发布包。

长时间在线、漫游、休眠恢复、重启和其他机器仍需分别实测，因此保留预览标记。无线 Web、改密码与校园网暂停/恢复没有在本轮自动提交真实操作。
