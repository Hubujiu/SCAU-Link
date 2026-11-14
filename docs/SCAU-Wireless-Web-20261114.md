# 历史研究记录

本文保留 0.10.0 阶段的发现与当时验证范围。0.12.0 已自动连接 SCAUNET 并完成现网新登录、保活和注销；当前行为和证据以 [0.12.0 报告](Network-Delivery-Results-0.12.0.md) 为准。

# 无线 Web 认证：原程序证据与实现边界

日期：2026-11-14。分析目标为原安装目录中的 `PortalAuth.dll`，SHA-256：`caf8555ced7c227078275e2dc0cdb7f362538cd01040b621fce92761a5242254`，x86，映像基址 `0x10000000`。使用本机既有 REA 6.9.0 / Ghidra 12.2；没有升级工具、加载 DLL、执行原程序、读取真实凭据或向学校提交登录/退出请求。

学校官方资料区分 `SCAUNET` 网页认证和 `SCAUNET_1x` WPA2 企业无线认证。[学校无线连接说明](https://metc.scau.edu.cn/2019/1225/c126a216614/page.htm)。本文的实现只处理前者的已恢复 Portal 协议；无线 802.1X 不是该 HTTP 模块的另一个路径。

## 原程序中已经确认的协议

复用 2026-11-13 同一哈希的 REA 证据，没有重复反编译已知入口：

| 操作 | 方法与路径 | 请求 JSON | 客户端读取的响应 |
| --- | --- | --- | --- |
| 页面配置 | `POST /eportal/inferface/authAPI/pageInfo` | `queryString`, `userAgent="PC"`, `userip` | `portalUrl`, `selfUrl`, `announcement`, `service[]` 中的 `serviceName` / `serviceDefault` |
| 登录 | `POST /eportal/inferface/authAPI/login` | `password`, `queryString`, `service`, `userAgent="PC"`, `userId`, `userip` | `result`, `message`, `userIndex`, `keepaliveInterval` |
| 本机状态 | `POST /eportal/inferface/authAPI/getOnlineUserInfo` | `userip`, `userIndex`（初始探测为空字符串） | 仅 `result` |
| 退出 | `POST /eportal/inferface/authAPI/logout` | `userip`, `userIndex` | `result`, `message` |

`inferface` 是 DLL 中的实际拼写。主机与端口来自发现/调用参数，不能用学校自助服务 `mavis.scau.edu.cn:8443/selfservice/` 替换。HTTP helper 在请求体非空时选择 POST，发送 JSON；原实现具备明文 HTTP 能力。

`StartPortalAuth` 为 `0x10003560`，`SendLogout` 为 `0x10004d80`。原发现 helper `0x100032b0` 对 `123.123.123.123:80` 做无请求体 GET，从 HTTP 200 HTML 的 `location.href=` 提取 Portal URL。这个地址是拦截探测占位，**不是学校 Portal 的固定地址**。原登录路径随后提取问号后的 `queryString`。

本次补充反编译 `0x10002260`，确认它只是 CString 写时复制和取缓冲区指针，没有对 `queryString` 或 `service` 做 URL 解码/编码。因此新模块保留发现 URL 中问号后的原始文本，并只做 JSON 字符串转义。

原登录成功回调为 stage 3 / code 5，`keepaliveInterval` 位于结果结构偏移 `0x420`。它由 DLL 传给主程序。DLL 的已定义字符串和全部已知 HTTP helper 调用中只有上述四个 API，未确认独立 keepalive 路径。主程序回调复制该结构并分发线程消息，也没有建立该值的单位、定时方式或保活包契约。**不能把 HTTP 的 `Connection: keepAlive` 头当作认证保活。**

原 `getOnlineUserInfo` 仅按 IP / 会话索引做状态检查。客户端没有读取账号身份、设备列表或在线设备数。新模块不会据初始探测成功宣称“当前保存账号已认证”，也不会取得退出其他会话的所有权。

## 本轮实现采用的约束

`src/desktop/portal_auth.hpp/.cpp` 提供可注入传输、纯发现/JSON 解析、请求构造和原生异步 WinHTTP。`src/desktop/wireless_session.hpp/.cpp` 管理工作进程内的会话状态。主进程与工作进程仍复用原有加密会话秘密及私有双管道 IPC；`--wireless-web` 必须是私有 worker，不走 Npcap 或有线 EAP。

- 只把 `/eportal/index.jsp?非空查询串` 识别为可处理的页面形状；其他路径、执行脚本才能求出的地址、含用户信息的 URL、畸形地址和有歧义的跳转均不构成可提交目标。这是实现主动收窄的边界，不是声称原 DLL 只接受该路径。
- 发现不携带凭据、不执行脚本、不自动跟随 HTTP 跳转。未获信任的候选只返回规范化的 `scheme://host[:port]`，供首次页面确认；不返回可直接登录的 Target。实际登录需要应用按该无线网卡保存的精确来源认可。主机名、端口或协议改变后必须重新识别。
- 所有认证字段只进 POST JSON；账号和密码不进入 URL、命令行、诊断事件或持久缓存。请求体和临时凭据缓冲区按生命周期清理；登录失败文本屏蔽本次账号与密码，只经私有终端结果展示。
- WinHTTP 禁止代理、自动跳转、Cookie 和 HTTP 自动认证，保持正常系统 TLS 证书策略。原生请求先发不含凭据的固定路径请求头，检查实际 socket 的本地地址属于指定接口且匹配本次 IP，再写入 JSON 请求体。接口不可用、路由不符或 DHCP 已改变 IP 时停止发送请求体。没有扩大学校自助查询模块的既有证书例外。
- 只有明确 `result="success"` 且获得非空 `userIndex` 的登录才产生 Online。只有明确登录拒绝进入账号重试/轮换；未知结果、超时和无法解析的结果停止自动重发。未知状态不能推断为成功。
- 服务只有唯一默认项、唯一项或空列表时自动选择；多个无法唯一选择的服务停止认证，不猜测学校套餐。
- 链路、MAC、接口索引或 IPv4 改变后清理本地会话上下文，等待原无线网卡恢复并重新发现，再使用同一账号认证。稳定链路上服务器明确返回离线则单独报告会话终止，不猜测欠费、时段或并发原因。
- 成功登录后的 30 秒 `getOnlineUserInfo` 是本实现的保守状态轮询，**不是已恢复的 Portal keepalive**；没有使用单位未知的 `keepaliveInterval` 发明新协议。
- 用户取消仅在本 worker 已成功取得索引、当前 MAC / 接口 / IP / 信任来源仍匹配时，尝试一次 2 秒退出。未知退出结果只记录固定的“未确认”事件，不声称服务器已经下线。工作进程的 stop-event watcher 由 RAII 收尾并 join，可打断正在等待的 WinHTTP。

## 验证与未验证部分

验证只使用合成账号、注入网络状态/传输，以及 `127.0.0.1` 临时 HTTP 监听器。Portal 94 项检查、无线会话 246 项检查通过，原有 `protocol-tests` / `exchange-tests` / `supervisor-tests` 三项 CTest 通过。覆盖请求字段与路径、严格 JSON / Unicode / 重复字段边界、服务选择、凭据转义和脱敏、来源确认、禁止跳转、接口和源 IP 校验、总超时与取消、会话所有权、链路/地址恢复、明确拒绝与未知登录结果、服务端会话终止。原生 worker 分支做了编译链接，没有执行真实 `--connect`。

当前学校无线 Portal 的实际来源、无线拦截页面以及上述 authAPI 家族在现网中的可用性仍未得到实网验证。公共 `SuConfig.txt` 仅发现 `http://1.1.1.1.` 占位；`SuConfig.dat` 的原始字节未发现明文 Portal URL，这只是有界搜索结果。学校网页若使用 `eportal/InterFace.do` 或其他服务端协议，当前模块会保持不支持，不会把凭据提交到推测路径。尚未证明状态轮询足以满足学校长期保活要求。

因此，模块的离线协议实现与现网兼容是两件事。本轮未切换无线网络、未修改系统路由、未停止或替换正在运行的认证会话；不能用离线/回环测试声称校园无线登录或长期保活已通过。

## REA 证据索引

旧证据位于本机忽略目录 `captures/reverse-device-api-20261113/portal-auth/`，新证据位于 `captures/wireless-web-20261114/`。新会话已经导出 Evidence bundle、关闭二进制并 reset。桥鉴权状态不进入本报告或发布包。

| 事实 | Evidence ID |
| --- | --- |
| StartPortalAuth、四种字段/结果与回调结构 | `ev_ccac269f78b4025a4d33b10e59aad4aa4183e6acdaadf5c5c53be17728a54804` |
| SendLogout 状态预检及退出 | `ev_5eb02df5e026058773140a40c4b57b87a060c0b3be56c83b94d6e574f6a95e33` |
| HTTP helper 的请求体、JSON 头与请求方法 | `ev_d0c4ef6c3d2deee662cf8f35cdf99df1af2fb5ce901cd2cd7e86541bdf76581e` |
| 方法字符串及指针表原始字节 | `ev_f8c6e45c5b247aea18947f2520e72e94d94c303cea68a41915993bd4fdcfe393` |
| HTTP helper 全部已观察调用点 | `ev_a49abbfdec43477aa3d671c986e37bf61209d9f6818f0ca162694c0091521035` |
| `location.href` 发现 helper | `ev_508a9d7eb08bf5760fc7ca0c550194ee2d7cc607412746026b8e80d703ab6a95` |
| 字符串比较的等于/不等于语义 | `ev_03ff1c25fe5b92fa7b36df2c5039867408f22f3c634425743b59326af367dd83` / `ev_76453efbcdaec6fd39ab03701ad0db1c9043dcfc3fdc71bc69be8712fcac3b0e` |
| CString 指针 helper `0x10002260` 无编解码 | `ev_11e97d05b0d0e3ca37449392c532818258225a4d10c5070aaebe5f49f256b05b` |
| 本次 `keep / authAPI / http://` 定义字符串有界搜索 | `ev_df95860ed84aea7c85cba3b634765827709fb6f3f465237ae80beb5c0c59078a` |
| 原发现失败后的独立 ICMP 连通检查，不是认证保活 | `ev_4e5e4a809a794985da09c5cfa0219e3047807441ee51e5e11cf03ca8d7926fea` |
| 主程序 Portal 回调复制与消息分发（独立并行调查） | `ev_ba9d64b57c4ddc848e993e63ed73ece3b9dd4f1e3180f113f3fd6c0cfd07d37f` / `ev_1e2d44ca7872a2e4c69d23f0d05d06c35c752f24cc5e7c557d1c3d493f4ed54b` |

以上反编译为静态观察，不是源代码或运行记录。定义字符串、已观察引用和回调的数据复制不能证明所有厂商协议、所有学校部署或隐藏服务端功能都已穷尽。
