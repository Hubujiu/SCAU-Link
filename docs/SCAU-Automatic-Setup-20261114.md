# 历史研究记录

本文保留 0.9.0 有线自动准备参数的说明。0.12.0 的三种连接模式、启动顺序和首次使用说明见 [当前文档](SCAU-First-Run-0.12.0.md)。

# SCAU Link 0.9.0 自动准备认证参数

首次使用的交互是“登录 → 账号、密码 → 登录”。桌面版移除认证配置导入入口；用户不需要原锐捷、抓包或开发目录。

## 本机准备

- `GetAdaptersAddresses` 配合 `GetIfEntry2` 只选择物理 Ethernet 网卡。排除 Wi-Fi、VPN/TUN、虚拟网卡和无效 MAC。优先已接入网卡，再考虑已有 IPv4、仍可用的缓存网卡、网关和接口 metric；结果保持稳定。
- 没有物理网卡时等待“有线网卡”，未接网线时等待“网线接入”。每秒可取消地重新检查，支持接入 USB 有线网卡。IPv4 尚未就绪不会阻止 EAPOL 开始；认证核心仍从该物理网卡刷新地址并处理后续网络变化。
- 学校服务名“有线1x上网”采用已观察到的 32 字节 GBK 字段。它是学校公共服务参数，不随包分发某个用户的硬件信息。
- 系统盘设备标识通过原生 `IOCTL_STORAGE_QUERY_PROPERTY` 只读查询，使用 `STORAGE_DEVICE_DESCRIPTOR.SerialNumberOffset` 的 ASCII 串，校验边界并去掉首尾空格后填充为 64 字节。无权读取或设备不支持时使用有界零字段，不复制其他电脑的标识。这种情况下学校是否接受仍需实网验证。
- 网络头从当前 DHCP 模式和协议常量生成，缓存中的 IPv4/掩码/网关/DNS 均为零，附有效 CRC；运行时从所选网卡刷新。不会修改网卡、路由、DHCP 设置或防火墙。
- 标准 PAE 多播发送 Start，由本次受校验的 Identity 请求发现认证器，后续响应发给该服务器。全新配置不提前向未知或多播地址发送 Logoff；崩溃恢复也不发送初始 Logoff。

自动生成的 `connection.scau` 位于当前 Windows 用户的 `%LOCALAPPDATA%\ScauLink`。文件固定 141 字节，原子替换，不含账号、密码、挑战或认证交换。相同参数复用缓存，避免重复磁盘设备查询与写入。账号及密码继续由 Windows 凭据管理器保存。

## 兼容迁移

仅检查用户数据目录内的 `connection.scau` 与旧版 `profile.scau`，不搜索父目录、安装目录或抓包。同一物理网卡的旧配置可迁移到新文件，并清除缓存认证器及地址；原文件保留。旧 MAC 与当前所选网卡不同时重新生成本机字段。损坏、截断或过大的缓存会忽略并重建。

Npcap/WinPcap 仍是收发二层帧的系统驱动依赖。安装向导检测缺少驱动时提供 Npcap 官网入口，运行时显示明确提示；程序不捆绑不具备分发许可的驱动，也不自动提权安装。账号密码以外的认证参数无需用户手填。

## 验证范围

新增隔离空目录测试，覆盖无旧文件、本机字段、网卡筛选与排序、无 IPv4、网线等待、同机迁移、异机隔离、损坏缓存、重复读写控制、Identity/MD5 帧构造和首次保存账号后直接登录的异步流程。原有认证、SAM、恢复、账号、套餐、TLS 和滚动测试继续运行。

`connection-setup-probe --local-only-empty-directory <绝对空目录>` 只查询本地网卡/存储属性并在指定 QA 目录生成配置，不读取账号、不加载抓包驱动、不发网络请求。输出仅包含布尔可用性，不记录 MAC、磁盘序列号、地址或私人报文。实际探针和原生界面检查结果见本版本 verification.json。

本轮不停止原锐捷、不发起真实 EAP/SAM、不执行暂停、重启或断网。空目录生成成功和离线握手构造不能证明另一台电脑的学校端实际认证或长时在线；这些仍需单独验证。

## 字段依据

- 学校服务字段来自项目此前本机抓包/原程序研究，源数据不随安装包分发。
- [MiniEAP 上游的锐捷扩展参数处理](https://github.com/updateing/minieap/blob/master/packet_plugin/rjv3/packet_plugin_rjv3_priv.c) 区分服务参数和设备序列字段；本实现使用 Windows 原生属性读取，没有移植 Linux 磁盘 ioctl。
- [Microsoft STORAGE_DEVICE_DESCRIPTOR](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-storage_device_descriptor) 说明序列字段偏移、设备数据长度及空字段。
- [Microsoft IOCTL_STORAGE_QUERY_PROPERTY](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-ioctl_storage_query_property) 说明设备属性查询。
