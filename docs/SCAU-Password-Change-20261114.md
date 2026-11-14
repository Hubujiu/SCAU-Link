# 校园网修改密码：原客户端流程与兼容实现

2026-11-14。使用 REA 6.9.0 / Ghidra 12.2 静态分析原 `8021x.exe` 的只读副本，并读取学校无需登录即可获取的 JavaScript。没有读取真实账号、密码、CredMan 或浏览器 Cookie，没有启动、附加或停止原客户端，没有提交真实登录或修改密码请求，没有改变当前 802.1X 会话。

## 结论与边界

原客户端确有原生修改密码对话框和实际提交函数，不是只有打开自助网页的菜单。兼容实现使用已还原的原生 `login_judge.jsf` 协议，固定请求学校自助主机。只有解析到唯一、完整的 `&success=0` 才确认成功；发送后超时、断线、重定向、响应不完整或语义未知均保留“结果未确认”，不自动重试，也不更新本地凭据。

本轮验证了静态调用链和合成夹具，没有执行真实改密。因此尚未验证学校当前部署是否仍接受该原版兼容入口、真实写入结果、密码变更后的在线会话行为，或与统一身份认证之间的同步规则。

学校目前明确区分账号类型：师生学号／工号可用信息门户密码登录校园网，忘记密码应在信息门户找回或重置；非学工号账号通过校园网或 VPN 访问锐捷自助系统修改。此模块只表示“校园网密码”，不把校园网接口当作统一身份认证的密码修改接口。[学校网络故障报修与账号说明](https://inc.scau.edu.cn/wlfw_17605/list.psp)

## 原生调用链：静态事实

分析对象原路径 `D:/Apps/Network/Ruijie Networks/Ruijie Supplicant/8021x.exe`，SHA-256：

```text
1a782d368b253f2035927d6439f9ad184e7fd6dddc196d6a6688a414129da7ee
```

| 阶段 | 代码与行为 | REA Evidence |
| --- | --- | --- |
| 菜单 | `FUN_005da2b0` 匹配 `menu_Change_Password`，向主窗口投递 `0x51a` | `ev_c685583550db9e1e6d9e01bff01ab224b81d2fa7ed6e8447f28584b29f284c15` |
| 打开窗口 | `FUN_00429620` 的 `0x51a` 分支实例化 `CModifiPassword`，加载 `layout_modifipassword.xml` | `ev_cc17d0515ce181034fbe6b5b35c9bf29707a6bf67f1a4ee25415cce4279202d8` |
| 密码控件 | `FUN_004de660` 取得旧／新／确认密码控件，各自 `SetMaxChar(16)`、`SetPasswordMode(true)` | `ev_015318d002f7339a0664f3523748b6cf2a957f27e4912d86d40ab88be126f6c2` |
| 确认事件 | `FUN_004dd3d0` 匹配 `confirmbtn`，调用 `FUN_004dd480` | `ev_a08532ac268c2a917beaaf5189a473452cb8894234a4f0019603a0bbec18d6aa` |
| 验证／请求／结果 | `FUN_004dd480` 完成输入校验、编码、HTTP 调用、返回标记判断；仅成功分支保存新密码 | `ev_4136e06639b4060ae389b2c85fbeb56a04755b5bd49f5480fa263662ff9428bb` |
| 指令核对 | `0x4dd7af` 比较 institution 与 `hust`；`0x4de0eb` 加 `s=`；结果分支引用实际失败文案 | `ev_14d2f8067df8c6a0bc53eb8c77e764325d938f656c55894ca73b1a90a27796d3` |
| 字节核对 | `0x6b7338` 为 `hust`；`0x6c4478` 起包含 `&success=`、`&callBack=modifyPwd:`、长度与错误文案 | `ev_70ac1303f4ec6b9bc42cf789e16395042cc4719fc27aaa09042588a15fac0356`、`ev_56c984d809da94144afc166edd73494690f0112f432d7d539b2a8eec2d109099` |

原生请求结构：

```text
GET <配置的自助基础地址>/module/scgroup/web/login_judge.jsf?s=<兼容编码>
body: 空

编码前参数，严格按原函数顺序：
userid=<当前账号>&password=<客户端保存密码>&callBack=modifyPwd:<输入原密码>:<新密码>&channel=su
```

注意此处是 `login_judge.jsf`，不是只读信息查询使用的 `login_judge2.jsf`。`s` 使用同一 `FUN_0054aa60` 编码：UTF-8、补零至 16 字节边界、与 `MD5("hust" || 前一密文块)` 异或、初始链为 16 个 ASCII `1`、小写十六进制。编码只是原协议兼容变换，不应视作独立安全加密；输出和完整 URL 都等同敏感凭据。

HTTP 方法沿用已核对的 `FUN_004c5d70` helper 证据：第五参数为空，`s=` 在第四参数中进入 URL，空 body 对应 GET。已有 helper 指令证据及编码验证复用自 [账号查询调查](SCAU-Account-Query-Reverse-20261113.md)，未重复分析或执行原程序。

原函数输入校验：

- 三个输入不能为空，旧／新密码不可全部为空格；旧密码必须与客户端当前保存密码一致，新密码必须与确认密码一致。
- institution 等于 `hust` 时新密码长度为 6–12；其他分支为 3–16。提交函数比较 ANSI 字符串长度，三框还存在 16 的编辑器上限。
- 提交函数没有对 `modifyPwd:<old>:<new>` 的冒号做转义，也没有看到对内层查询的 `&`／`=` 做转义。外层 `s` 变换不会解除内层字段歧义；不能自行发明 URL 编码后声称服务器会正确解码。
- 未从本轮静态证据确认学校运行配置一定选择 `hust` 分支。新模块显式提供两种 policy，默认一般 3–16 字节范围；学校服务端仍可进一步拒绝。

原函数响应处理：

| 标记 | 原版语义 | 新实现 |
| --- | --- | --- |
| `&success=0` | 成功，显示成功区并保存新密码 | `Success`，由上层核对账号版本后决定是否写凭据 |
| `&success=1` | 密码修改失败 | `Rejected / ServerRejected` |
| `&success=2` | 原密码输入错误 | `Rejected / OldPasswordRejected` |
| `errorMsg=0` | 用户不存在或密码错误 | `Rejected / AuthenticationRejected` |
| `errorMsg=1` | 用户无修改密码权限 | `Rejected / PermissionDenied` |
| `errorMsg=2` | 服务器已禁止访问 | `Rejected / AccessDenied` |
| 缺少已知标记 | 原版提示访问自助服务修改 | `Unknown / UnsupportedResponse` |

新实现额外拒绝重复、冲突、缺位数字和 `0junk`／`00` 等不完整结果，不沿用原版 `atol` 将异常文本解释成 0 的宽松行为。不会把服务端 HTML、异常文本或密码拼入用户消息。

## 学校现代网页：公开资源事实

2026-11-14 只读 GET 获取的公开文件位于本机忽略目录 `captures/password-change-20261114/public/`，每个文件旁有 URL、状态、字节数及 SHA-256 元数据。未提交账号或 Cookie。

- [公开首页脚本](https://mavis.scau.edu.cn:8443/selfservice/module/webcontent/js/index_self.js) 的 `changePwd` 分支打开 `module/userself/web/regpassuserpassword_update.jsf`。
- [公开改密脚本](https://mavis.scau.edu.cn:8443/selfservice/module/userself/js/regpassuserpassword_update.js) 的 `submitchange()` 先 Base64 编码旧／新密码，再以页面 `publicKeyNew` 做 RSA 处理，向 `userself_ajax.jsf?methodName=regUserinfoListBean.updateAjaxByBase64` POST `key=<old>:<new>`。文本 `0`／`1`／`2` 分别进入成功／一般失败／旧密码错误分支；`false#...` 为密码策略失败。
- 同一脚本的密码策略检查为 `regUserinfoBean.checkUserPassword`，页面 RSA 公钥是动态输入；脚本里旧的 3–16 长度检查已被注释，不能当作该现代网页的现行学校规则。
- 未登录 GET 该改密页面返回“未登录或会话过期”，没有取得已认证表单或动态公钥，也没有执行 JavaScript。未进行真实登录来补齐它们。

这些是另一套现代网页流程。原生兼容模块只复刻实际原客户端调用链，不混用 RSA 网页字段和旧客户端返回值。

## 模块与离线验证

新增 `src/desktop/password_change.hpp/.cpp`：

- `validate_password_change()` 进行本地验证；长度以无损 GBK 字节数核对，拒绝无法表示的字符、控制字符及内层分隔符 `&=:`，提示使用固定学校官方页面。整体 UTF-8 参数继续受既有 240 字节编码边界约束。
- `PasswordChangeSession::submit()` 使用固定学校 HTTPS origin、空 body GET，不读取浏览器会话、不访问凭据存储、不做 EAP 操作。
- `may_commit` 在构造请求之后、发送之前核对上层账号和凭据版本；取消在发送前生效。
- 原子的一次提交标记保证同一 Session 最多进入传输一次。只要进入传输，异常和取消都不能证明请求未到达服务器，结果不会被自动重试。
- 模块不修改传入 `Credential` 或持久凭据；上层仅在 `Success` 时更新保存的密码。未知结果不得更新，也不得自动尝试新密码登录来“确认”。
- 明文参数、编码值、完整请求路径、响应正文、临时 Cookie、Location 及解码响应使用作用域清零。返回值只有 enum 和 `request_sent`，固定文案不含服务端原文。

`tests/password_change_tests.cpp` 的合成夹具覆盖原请求字段顺序和独立 Python hashlib 冻结向量、两种长度 policy、GBK 字节边界、旧／新／确认匹配、内层分隔符、总长度、成功和五种拒绝、13 种未知／歧义响应、非 200、无效／不完整帧、超大响应、TLS／网络／协议错误、传输异常、取消、版本 guard，以及连续／并发重复提交。所有 Sender 都是内存夹具，不请求学校、不读取正式凭据。

独立 MSVC Release 编译和夹具通过；复现入口为本机 `captures/password-change-20261114/build-offline-tests.cmd`。完整 REA bundle 已导出 55 条（含复用的 26 条旧记录），原生会话已 `close_binary`，调查已 `reset_investigation` 保存 checkpoint。证据未进入安装包。

仍未知：学校端真实成功样本、原版兼容改密入口的当前权限与可用性、所有账号类型的服务端密码策略、统一身份认证同步语义。原有网络和用户密码均未修改。
