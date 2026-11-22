# SCAU Link 0.15.0 验证与性能对比

0.15.0 将有线认证的 EAPOL 帧解析和重连状态机迁入 Rust。普通窗口与小窗的连接主页面通过 NSH 0.6.1 渲染。原 Win32 主机负责账号、设置、日志、托盘和更新。现有 Windows 认证传输、无线认证以及 MiniEAP 兼容算法仍由 C/C++ 实现。NSH 构建使用 Rust API，未启用 QuickJS 和 WebView2。 [NSH Windows 文档](https://nsh.dev/docs/windows/)

## Release 构建实测

同一台 Windows 11 x64 机器（22621，Core i9-12900HX），对比公开的 0.14.5 安装内容与本次 0.15.0 Release 构建。每版、每个场景预热一次，再交替各跑 10 次。表中取中位数，原始样本记录两版主程序的 SHA-256。演示进程使用合成数据。 [样本](network-delivery-0.15.0/migration-benchmark.json)

| 指标 | 0.14.5 C++ / Win32 | 0.15.0 Rust / NSH | 变化 |
| --- | ---: | ---: | ---: |
| 离线主页私有工作集 | 12.20 MiB | 19.56 MiB | +60.4% |
| 在线演示私有工作集 | 12.37 MiB | 19.83 MiB | +60.3% |
| 离线主页总工作集 | 45.03 MiB | 58.10 MiB | +29.0% |
| 离线主页私有提交量 | 54.60 MiB | 73.66 MiB | +34.9% |
| 离线窗口可见时间 | 52.82 ms | 182.22 ms | +129 ms |
| 在线演示窗口可见时间 | 58.96 ms | 198.54 ms | +140 ms |
| 两种场景的空闲 CPU 中位数 | 0 ms/s | 0 ms/s | 计时分辨率内 |
| EAPOL 解析（单个合法 VLAN 帧） | 10.83 ns | 11.57 ns | +6.8% |
| 重连状态机（五步模拟循环） | 86.19 ns | 49.51 ns | -42.6% |
| 桌面主程序文件大小 | 3.93 MiB | 12.35 MiB | +8.42 MiB |

桌面内存是窗口出现约 3.1 秒后的单进程快照。启动计时从创建进程到 Windows 报告可见的主窗口，未测首帧渲染完成。核心测试各跑一百万次迭代，校验和一致。重连控制器最多返回一个动作，本版用可选值替代向量，去掉了每个有输出的转换中的堆分配。两个帧解析样本的范围有重叠。以上数据未覆盖真实在线认证时延、吞吐、后台长时占用或工作进程的在线内存。

## 验证范围

- Release CTest 37/37。包括 EAPOL 双层 VLAN 和长度边界、模拟时钟下的断线重连和重新认证、更新验签、账号和无线连接夹具。
- Windows UI Automation 验证两种窗口的登录入口、合成门户密码测试、余额、未确认账号提示，以及 NSH 切换连接方式、连接、断开和退出。 [交互记录](ui-native-0.15.0-preview/interaction-checks.json)
- 安装和升级验证使用隔离的测试安装器与目录。真实校园网登录、学校自助查询与长时间在线未复测。 [验证清单](validation-0.15.0.json)

## 复跑方法

从 0.14.5 的发布包获取 `SCAU-Link.exe`，并从该标签构建 `scau_protocol.lib`。在 x64 Visual Studio 开发者终端，用 `/MD /O2 /EHsc /std:c++20` 编译 `scripts/core_benchmark.cpp`，引用 0.14.5 的 `src` 头文件并链接其 `scau_protocol.lib` 和 `bcrypt.lib`。在当前源码构建 CMake 的 `scau-core-benchmark` Release 目标。各演示进程使用对应版本的运行库。

```powershell
./scripts/benchmark_migration.ps1 `
  -Baseline <0.14.5 的 SCAU-Link.exe> -Candidate build/Release/SCAU-Link.exe `
  -BaselineCore <0.14.5 的基准程序> -CandidateCore build/Release/scau-core-benchmark.exe
```
