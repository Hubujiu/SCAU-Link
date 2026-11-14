# 在线设备与校园网暂停／恢复

2026-11-13，SCAU Link 0.8.0。用户授权查询自己已保存的账号，并接入学校自助服务。真实环境只查询，没有提交暂停、恢复、踢设备、EAP 登录或退出，也没有停止真实客户端。

## 已验证的数据

同一个自有账号在两种真实响应中均返回在线数量 **2**：

- 原客户端账号信息接口 `getNewLoginInfo.ballInfo`：`id=onlinedevice`、`type=deviceNum`、`displayName=在线设备`、`value="2"`。
- 学校自助首页刷新：`indexBean.refreshSelfIndexData` 返回 `onlineNum="2"`。

按学校字段显示“在线设备”，没有声称已经辨识两台具体硬件、去重 MAC 或证明每个账号都能认证。零台和未知分别显示；负数、超限或非数字保持未知。账号横条和展开后的连接详情显示在线数，与套餐查询共用 5 分钟缓存，只在普通窗口相关页面可见时查询，不轮流执行 EAP 登录。

设备明细仍不可用。正常网页验证码登录和原客户端业务详情会话分别尝试过以下只读页面，均返回学校通用错误页：

```text
GET /selfservice/module/webcontent/web/portal_onlinedevice_list.jsf
GET /selfservice/module/webcontent/web/onlinedevice_list.jsf
```

公开 `onlinedevice_list.js` 未发现可替代页面的独立设备列表读取接口。它包含重命名、下线、解绑等操作，本轮没有调用这些操作，界面也没有伪造设备明细。

## 暂停／恢复契约

原客户端信息查询返回的已验证业务详情链接可建立独立自助服务会话。它与信息查询的 JSESSIONID 分开；不读取浏览器 Cookie，不执行网页脚本，不跟随任意跳转。此前使用用户输入的验证码完成普通网页登录仅用于交叉核对；原生应用不保存验证码，也不依赖这次浏览器会话。

固定主机仍为 `https://mavis.scau.edu.cn:8443`。TLS 兼容策略沿用用户已要求的学校专用 OpenSSL 设置，不修改系统证书或其他主机的校验。

只读准备流程：

1. 使用所选账号自己的 Windows 凭据，调用原客户端信息查询并取得已允许的业务详情登录路径。
2. 清除信息查询 Cookie，以业务详情链接建立新的自助会话。
3. `GET /selfservice/module/webcontent/web/index_self.jsf`，读取 `canSuspend`、`canResume`。
4. `POST /selfservice/module/userself/web/userself_ajax.jsf?methodName=indexBean.refreshSelfIndexData`，空请求体；这是学校原页面使用的只读状态刷新。
5. 校验返回 `userId` 与所选凭据账号一致。服务端 `userState=2` 为正常（与真实暂停表单核对），`userState=1` 为暂停（学校公开 JS 的判断）；其他值保持未知。
6. 按当前状态读取 `self_suspend.jsf` 或 `self_resume.jsf`，校验唯一的隐藏 `targetUserId` 再次匹配自身账号，且存在可用的确认按钮。

真实只读准备结果：正常、允许暂停、在线数 2、目标一致；最终原生探测 `stage=9`，`mutationRequests=0`。

学校公开 `self_suspend.js`、`self_resume.js` 中的实际提交契约：

| 操作 | 方法和路径 | 表单 | 成功标记 |
| --- | --- | --- | --- |
| 暂停 | `POST /selfservice/module/userself/web/userself_ajax.jsf?methodName=userSelfOperationBean.newConfirmSuspend` | `targetUserId=<已核对的自身账号>` | `data=toSelfPause` |
| 恢复 | `POST /selfservice/module/userself/web/userself_ajax.jsf?methodName=userSelfOperationBean.newConfirmResume` | 同上 | `data=toSelfResume` |

**真实提交没有执行，服务端写入成功与实际断网／恢复时延尚未验证。** 恢复表单在真实已暂停账号下的控件也未实测。原生代码已按公开脚本接线，并通过离线夹具验证两个方向。

## 原生操作与约束

“账号 → 右键一行 → 校园网”按需创建面板，显示该行账号、服务状态和在线数。点击暂停／恢复后展开简短影响说明和第二次确认；首次进入确认时焦点移到“取消”，Enter 长按不重复触发。刷新只查询，不提交操作。

界面只持有不含凭据的一次性随机票据。后端将票据绑定账号随机 ID、凭据版本和变更代数；会话所有者只在创建／准备会话时赋值，错误账号的请求不能改写既有会话归属。确认最长有效 2 分钟，提交前重新读取身份、权限、状态、表单，并在读取完成后再次检查有效期和凭据版本。提交只发送一次，不自动重试。

提交后只读刷新核对状态。超时但已观察到目标状态可确认成功；明确拒绝显示未接受操作；无法确认则显示“结果未确认，请刷新”，不再提供可重复使用的提交票据。公共记录仅写固定事件名，不写账号、密码、私有 URL、Cookie 或服务端原文。

暂停的是当前认证账号时，收到成功或已发送但结果未知后会停止本地自动恢复，避免与用户的暂停意图竞争；明确拒绝不会主动断开。暂停其他保存账号不操作当前认证。恢复校园网服务后，由用户按连接按钮重新认证。

后台显式查询与确认按顺序执行，优先于排队中的套餐查询。隐藏窗口、小窗和静默启动不主动查询；加载时才运行进度动画，静止后停止帧计时器。

## 验证范围

- Release CTest 26/26：新增离线会话测试覆盖两种状态、缺失／零／异常在线数、账号和隐藏目标不匹配、重复字段、权限不足、确认失效、慢刷新期间失效、凭据中途变化、取消、明确拒绝、超时后已提交／未确认、禁止自动重试。
- 后端演示测试覆盖一次性票据重放、账号隔离、凭据更新失效，不读取正式凭据或请求学校。
- 最终原生窗口仅用 `--demo-package` 合成数据进行点击检查，截图在 `ui-native-0.8.0`。实网只读探测与界面演示分开记录。
- 新 EAP 登录、真实暂停／恢复、设备明细、完整 SAM 往返、长时稳定性和重启自启仍不属于本轮验证结果。

学校说明：[自助服务常见问题](https://inc.scau.edu.cn/wlkhjf/list.psp)、[校园网管理规定](https://metc.scau.edu.cn/2018/0626/c124a284768/page.htm)。运行时契约以本机读取的学校页面和脚本为依据。
