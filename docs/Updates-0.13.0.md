# GitHub 分发与客户端更新

仓库：<https://github.com/Hubujiu/SCAU-Link>。安装包和便携包通过 Releases 分发，当前通道为预览版。

## 用户操作

设置页右上角“检查更新”，有新版时变为“下载更新”，下载完成后变为“安装并重启”。联网时保留已下载的更新，断开后才可安装；小窗设置仍只有退出小窗模式。

默认自动更新：系统连续两分钟没有键鼠输入后，后台检查并下载。正常检查间隔为六小时，失败退避半小时；安装还要求认证核心未运行，且没有账号编辑、改密、校园网确认、拖动或菜单交互。更新不会主动断开校园网，不弹自动更新窗口；静默启动保持静默。

独立助手继承父进程句柄和就绪事件，校验目标目录、用户身份和安装包后才确认就绪。主程序正常退出，助手等待该进程真正结束，再静默安装到原目录并重启。父进程不退出则不安装，不按 PID 强杀进程。安装失败也尝试启动原目录程序；结果只记录数值退出码。

更新检查和下载使用后台线程。状态通知不携带堆指针，进度按整数百分比合并；安装包分块写入，避免整包驻留内存。下载完成前不提升为可安装状态，退出会取消请求。

## 发布校验

客户端从固定仓库的 [GitHub Releases API](https://docs.github.com/en/rest/releases/releases) 查询发布，排除草稿、旧版本和不匹配的通道。API 不携带 GitHub Token、校园账号或密码。

发布附带 `SCAU-Link-update.json` 与独立的 64 字节 Ed25519 签名。程序内置公钥，签名绑定版本、通道、架构、文件名、大小、SHA-256 和下载地址；下载后及安装前均核对安装包。私钥位于本机忽略的 `build/signing/`，不会进入仓库、源码包、安装包或 Actions 缓存。

更新联网与学校旧证书兼容完全分离，使用标准 Windows TLS 校验。手动检查 HTTPS 重定向，只接受固定 GitHub 仓库及 GitHub 下载域，不接受 HTTP、其他主机或携带用户信息的 URL。[WinHTTP 重定向说明](https://learn.microsoft.com/en-us/windows/win32/winhttp/winhttp-security-considerations)。

## 维护者

1. 修改 CMake 项目版本和应用资源版本，运行 `scripts/build.ps1`。
2. 执行相应 UI、离线与必要的真机验证，记录真实构建摘要；未执行的验证注明来源和限制。
3. 运行 `scripts/package_desktop.py --preview`、`scripts/build_installer.py --preview`。
4. 使用 `scripts/sign_release.py sign --installer out/SCAU-Link-VERSION-Setup-x64-preview.exe --version VERSION` 签名更新说明。签名工具需要 `cryptography`，本机使用 50.0.1。
5. 提交源码并建立对应 `vVERSION-preview` 标签，通过 `scripts/publish_release.py --version VERSION --notes-file RELEASE_NOTES` 上传安装包、便携包、签名说明及校验文件。先创建草稿，上传完成后才公开。

首次初始化签名身份使用 `scripts/sign_release.py init`，只允许在没有既有身份时运行。应单独备份私钥；重新生成公钥会使旧客户端无法验证后续更新。常规发布继续使用同一身份。

GitHub Actions 负责 Windows 原生编译与离线检查，不持有发布私钥，也不将 CI 夹具当作校园网真机测试。公开源码沿用 GPL-3.0。
