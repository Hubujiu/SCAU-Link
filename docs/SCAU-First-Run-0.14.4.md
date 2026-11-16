# SCAU Link 0.14.4 预览版

下载见 [GitHub Release](https://github.com/Hubujiu/SCAU-Link/releases/tag/v0.14.4-preview)。保存校园网账号密码后，选择有线 802.1X、SCAUNET Web 或 SCAUNET_1x。

设置中开启“开机自启”，Windows 登录后会立即触发应用，待网卡和认证所需驱动就绪后连接。已开启自启的旧版会在安装或首次运行新版时迁移。静默启动与备用连接顺序继续有效。这里的自启发生在用户登录后，不是登录前。

有线连接需要可访问的 Npcap/WinPcap 驱动。提示驱动权限不足时，请由管理员启动/修复驱动；有网线和网卡名称不代表抓包驱动已经可用。不要把驱动故障当成密码错误反复改账号。

本次修改了认证核心，旧版更新到本版需要完整安装，应在你方便断开当前连接时更新。发布过程不会覆盖正在运行的客户端。详见 [改动说明](Startup-Wired-0.14.4.md) 和 [验证范围](Network-Delivery-Results-0.14.4.md)。
