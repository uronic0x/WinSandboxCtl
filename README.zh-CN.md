# WinSandboxCtl：Windows Sandbox 用户态控制器

这是你选定的**方案 A——Windows Sandbox 虚拟化路线**的可修改源码实现。没有自制驱动，不需要 WDK，也不需要签名 `.sys`。宿主机控制器使用原生 C++，盒内启动代理使用系统内置 Windows PowerShell。项目自身代码采用 MIT 许可证；Windows 和 Windows Sandbox 是微软提供的运行平台，不包含在本项目开源代码中。

**当前交付已在 Windows 11 完成功能验证**：编译与 5461 条核心参数用例通过；断网／直连／代理三种网络模式、只读输入保护、PersistData 持久化均验证通过；与白名单防火墙配合时，代理模式只需放行用户态的 `SandboxHost.exe` 即可让盒内联网（盒内流量经 CONNECT 隧道访问白名单域名），NAT 直连流量保持拦截——具体行为见下文"与宿主防火墙配合"。仍**没有声称完成防逃逸安全审计**。详细记录见 `docs/TEST-RESULTS.md`。新手从 `TUTORIAL.zh-CN.md` 开始。

## 交付内容

| 文件 | 用途 |
| --- | --- |
| `src/main.cpp` | 宿主机 CLI：建盒、生成 `.wsb`、启动、查看状态 |
| `src/core.hpp` | 参数校验、Windows 参数转义、JSON／XML 生成 |
| `src/proxy.hpp` | 显式 HTTPS CONNECT 代理：域名／端口白名单、客户端网段、DNS 地址校验、流量字节统计 |
| `guest/guest.ps1` | 盒内管理员／SYSTEM 启动、临时工作副本、AppData 持久化、代理配置、网络就绪等待与静态地址兜底、日志 |
| `tests/DemoProbe.cpp` | 无害的盒内测试程序：检查 Windows／HKLM 写入、只读映射、持久化和真实 Token SID |
| `tests/core_tests.cpp` | 核心边界测试；Windows 下额外使用原生参数解析 API 核对 |
| `scripts/Test-Windows.ps1` | 在你的 Windows 上执行端到端功能验证 |
| `build.cmd` | MSVC 一键编译并运行核心测试 |
| `CMakeLists.txt` | 可选 CMake 构建入口，无外部包下载 |

## 先在 Windows 跑通

### 环境

- 使用受支持的 Windows 11 Pro／Enterprise／Education 系统，打开硬件虚拟化，并启用 Windows Sandbox。Windows Home 不在本项目支持范围，不使用包侧载破解，也不自动退回 Hook 沙盒。
- 安装 Visual Studio 或 C++ Build Tools，选择“使用 C++ 的桌面开发”和 Windows SDK。默认构建面向 Windows x64；其他架构需要自行选择相应 MSVC 工具链并实测。
- 运行不依赖 Python、Go、Qt、第三方 Hook 库或 .NET SDK。可选的跨平台集成测试才使用 Python。
- 首次启用系统功能需要宿主机管理员权限；日常控制器不主动申请宿主机提权。实际启动权限也受本机 Windows／组织策略影响。

若 Windows Sandbox 尚未启用，在管理员 PowerShell 中执行：

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All
```

根据系统提示重启。项目也附带显式执行的 `scripts/Enable-WindowsSandbox.ps1`，该脚本不自动重启。检查环境可运行 `scripts/Doctor.ps1` 或编译后的 `SandboxHost.exe doctor`。

### 编译与第一次实测

解压后，在项目根目录打开 CMD：

```bat
build.cmd
```

构建脚本会寻找已安装的 MSVC，也可直接从“x64 Native Tools Command Prompt”运行。它生成 `bin\SandboxHost.exe`、`bin\core-tests.exe`、`bin\DemoProbe.exe`，随后执行核心测试。不要只复制 EXE；保留同级项目中的 `guest\guest.ps1`。

在项目根目录的 PowerShell 中运行管理员模式的盒内功能测试：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-Windows.ps1 -Identity admin
```

出现盒内 UAC 提示时，在 **Windows Sandbox 窗口内**确认。自测程序会尝试在**盒内**写一个专用 Windows 文件和一个专用 HKLM 项，确认输入映射不可写，并检查宿主机没有出现对应标记。测试不改宿主机防火墙，也不在宿主机启动被测程序。

关闭当前 Sandbox 窗口，再测试真实盒内 SYSTEM：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-Windows.ps1 -Identity system
```

SYSTEM 模式通过**盒内**管理员创建的按需计划任务执行，使用真实的 `S-1-5-18` Token。它运行在非交互任务会话，适合控制台任务／服务测试；普通 GUI 请选 `admin`。不注入宿主机，不在宿主机创建 SYSTEM 任务。

如果 Protected Client 导致本机环境启动失败，先保留错误信息；可以显式追加 `-ProtectedClient off` 做兼容性对比，程序不会静默降级。

## 运行自己的程序

### 建立一个盒

```powershell
.\bin\SandboxHost.exe init --box MyApp
```

默认位置为 `%LOCALAPPDATA%\WinSandboxCtl\Boxes\MyApp`。把待测程序及所需 DLL／资源文件放进该盒的 `ReadOnlyBin` 子目录。例如主程序是 `App.exe`：

```powershell
.\bin\SandboxHost.exe run --box MyApp --app App.exe --network off --data write
```

也可以直接指定一个专用输入文件夹和自定义盒目录：

```powershell
.\bin\SandboxHost.exe run --root D:\SandboxBoxes --box MyApp --input D:\AppToTest --app App.exe --network off --data write
```

不要把用户主目录、桌面全集、项目源码全集或整个磁盘当作输入。该目录下所有普通文件都会进入只读快照，盒内程序能读到它们。程序拒绝链接／重解析路径及部分不安全路径形式；复制前后仍假定宿主机和其他宿主机进程可信。

### 参数、MSI 和 SYSTEM

`--` 后面的每一个参数原样进入 JSON，并由 Windows argv 转义传入目标进程。CMD 示例：

```bat
bin\SandboxHost.exe run --box MyApp --app App.exe --network off -- --config "C:\Sandbox\Data\settings.json" "two words"
bin\SandboxHost.exe run --box MyApp --app Setup.msi --network off -- /qn /norestart
bin\SandboxHost.exe run --box MyApp --app ConsoleTool.exe --identity system --network off
```

宿主侧仅接受 `.exe` 和 `.msi` 入口，拒绝把任意命令串当启动脚本。目标程序若自行使用特殊命令行解析规则，应按它自己的规则配置参数。Windows PowerShell 自身对原生命令的空串／嵌套引号传参有限制；需要精确传入这些边界参数时，先用 CMD 或按当前 PowerShell 的原生参数规则传递，控制器无法恢复被上游 Shell 丢弃的字符。

## 存储语义

| 盒内位置 | 实际含义 | 持久化 |
| --- | --- | --- |
| `C:\Sandbox\Control` | 本次启动脚本和 JSON；宿主机只读映射 | 宿主保留生成文件，盒内不可写 |
| `C:\Sandbox\Input` | 本次输入快照；宿主机只读映射 | 宿主保留快照，盒内不可写 |
| `C:\Sandbox\Work\<runId>` | 从输入复制得到的盒内工作副本，目标从这里启动 | 关闭整个 Sandbox 后丢弃 |
| `C:\Sandbox\Data` | 该盒专用 `PersistData` 的显式映射 | 取决于数据模式 |
| 盒内 Windows／HKLM | Windows Sandbox 自己的系统状态 | 关闭整个 Sandbox 后丢弃 |

`--data none` 完全不映射宿主数据目录；`--data read` 只读；`--data write` 允许盒内任意程序读写该盒的整个 `PersistData`，默认是 `write`。**该目录就是有意开放的宿主写入通道**，里面不要放敏感文件、宿主启动脚本或会被宿主自动执行的内容。项目没有为共享目录配置磁盘配额。

为程序保存特定的用户配置目录：

```powershell
.\bin\SandboxHost.exe run --box MyApp --app App.exe --data write --appdata Vendor\App --localappdata Vendor\App
```

只链接所指定的子目录，不重定向整个用户目录。目标是 `PersistData\AppData\Roaming\Vendor\App`／`Local\Vendor\App`。如果盒内目标位置已有非空目录，代理会报错并保留原目录，不删除它来强行完成链接。SYSTEM 模式按 SYSTEM 的用户配置位置处理，和管理员账户的位置不同。

目标进程可读取环境变量：`SANDBOX_INPUT_DIR`、`SANDBOX_WORK_DIR`、`SANDBOX_DATA_DIR`、`SANDBOX_RUN_ID`。工作目录是主程序所在子目录。不要假定所有软件都会把数据写入指定 Data；安装到盒内系统目录的软件不会随关盒持久保存。

## 联网与显式代理

### 断网与直连

```powershell
.\bin\SandboxHost.exe run --box MyApp --app App.exe --network off
.\bin\SandboxHost.exe run --box MyApp --app App.exe --network direct
```

`off` 在 `.wsb` 中禁用网络；`direct` 使用系统提供的 Sandbox 网络，会开放访问宿主可达网络的能力。不要把直连模式称作“仅互联网”，它没有实现 LAN 隔离。

### HTTPS CONNECT 白名单代理

附带的代理是一个独立前台进程，支持 HTTPS CONNECT、白名单域名／端口、客户端 IPv4 网段、隧道字节统计。它不解密 TLS，不识别完整 HTTPS URL，也不校验隧道内载荷是否确实为 TLS；不支持 SOCKS、UDP 和明文 HTTP 转发。

在宿主机查看虚拟网卡地址与前缀：

```powershell
Get-NetIPAddress -AddressFamily IPv4 | Where-Object InterfaceAlias -like '*vEthernet*'
```

下面的地址是**格式示例，必须换成本机真实地址和准许的客户端网段**。先在一个宿主终端启动代理：

```powershell
.\bin\SandboxHost.exe proxy --listen 172.20.0.1 --clients 172.20.0.0/20 --port 18080 --allow example.com --allow '*.example.org'
```

再从另一个终端启动盒：

```powershell
.\bin\SandboxHost.exe run --box MyApp --app App.exe --network proxy --proxy 172.20.0.1:18080
```

盒内启动器设置当前身份的 WinINET 代理（进程内 Win32 注册表 API）和常见代理环境变量（`HTTP_PROXY`／`HTTPS_PROXY`／`ALL_PROXY`）；不写 WinHTTP——沙盒内 `reg.exe`／`netsh.exe` 子进程存在挂起兼容问题，且 WinHTTP 只影响少数服务类程序。代理只允许匹配白名单的 CONNECT 目的地，默认端口是 HTTPS 端口，默认拒绝解析到私有／回环／链路本地等非公网地址。`*.example.org` 不包含裸域 `example.org`，如需两者应分别添加。

**网络就绪与 DHCP 兜底**：盒内启动器是 LogonCommand，起跑时盒网卡通常还没完成 DHCP。启动目标程序前，启动器会先等待代理端口 TCP 可达（约 90 秒上限）。如果宿主防火墙拦截了 ICS（SharedAccess 服务的 svchost）——白名单防火墙默认拦截系统进程的出网连接，这是常见行为——盒内 DHCP 永远无应答并退化为 169.254.x.x。代理模式下 DHCP 等待约 20 秒无果后，启动器会自动为盒配置静态地址（网关＝代理宿主地址，盒地址＝宿主 /20 网段末尾的 .2），因为代理路径根本不需要 NAT，与宿主机二层可达即可。

代理默认绑定宿主回环地址，无法直接给盒内使用；绑定其他明确的本机地址时必须提供 `--clients`。它没有认证机制，允许网段内其他客户端也可使用同一白名单服务。不要将它暴露到公网。`--allow-private-upstream` 仅供你有意访问私网服务的测试，默认不开启。

本项目**不会自动修改宿主防火墙**。若防火墙阻止盒到代理的连接，需要你在管理员策略中只对实际虚拟接口／来访网段开放相应端口，或先退回断网测试。不要为省事关闭整个宿主防火墙。

**与白名单防火墙配合时，代理模式可以做到只放行一个用户态程序**：盒直连外网的流量经 NAT 转发，在宿主 WFP 层归属 `System`（PID 4），保持拦截即可；而盒到代理的连接终止在宿主 `SandboxHost.exe`，代理的出网连接也由它发起——两条都归这个用户态进程，防火墙弹窗放行 `SandboxHost.exe` 后盒即可联网。此时盒内 DNS 和不走代理的程序天然断网（DNS 走 NAT 被拦），代理白名单成为事实上的强制出口。此场景下 ICS DHCP 也会被拦，由上文所述的盒内静态地址兜底自动解决，无需放行 SharedAccess。

**代理模式不是强制流量网关。盒内管理员／SYSTEM 可以关闭代理或使用不遵循代理设置的网络 API 直连。** 标准 `.wsb` 配置没有提供本项目所需的、可由普通用户控制器可靠设置的逐盒强制代理策略。本版没有实现经过验证的宿主 Hyper-V／WFP 强制出站策略。需要抗恶意程序绕过的联网控制时，必须增加宿主侧隔离网络／策略管理员组件并重新验证；不能把本代理的白名单结果当作全部盒内流量审计。

## 日志、状态和生命周期

```powershell
.\bin\SandboxHost.exe status --box MyApp
```

写数据模式下，`PersistData\Runs\<runId>` 包含 `status.json`、各启动阶段日志、`stdout.txt`、`stderr.txt`。其他模式日志在盒内 `C:\Sandbox\Logs\<runId>`，关闭后丢弃。没有持久化状态时，`status` 会明确说明。

所有盒内状态和输出均为**不可信遥测**：目标有足够权限篡改它们。宿主只显示有大小限制的状态文本，不执行输出、不根据状态自动提权或执行后续主机命令。`exited` 仅表示根进程结束；安装器派生的服务或其他进程可能仍在盒内运行。

关闭 Windows Sandbox 桌面窗口才结束该虚拟环境；关闭控制器终端不会自动销毁虚拟机。系统当前不支持同时打开多个 Windows Sandbox 实例；请关闭一个再启动下一个盒。盒内重启和关闭整个 Sandbox 的语义不同。

宿主保留 `Runtime` 下的输入快照、控制文件及 `.wsb` 供排查，本版不自动清理，也没有“无痕清理”承诺。关闭 Sandbox 后，你可手动删除确定不再使用的会话目录。

## 和原方案文档的差异

- 使用公开的 `.wsb` 路径，没有直接依赖 HCS／HNS 内部 JSON 或开源容器框架。
- 默认来宾是管理员账户；SYSTEM 需要盒内单独启动，不是 `.wsb` 的默认账户。
- 支持 EXE／MSI，不承诺所有安装器、驱动、反虚拟机检测或硬件依赖软件都兼容。
- 没有实现宿主端强制代理、TUN、SOCKS5、无缝 RemoteApp、后台无窗口沙盒或 Windows Home 支持。
- 文件隔离依靠微软虚拟机和映射机制；项目不声称自制了 Windows 内核，也不承诺零逃逸漏洞。

## 可选构建与测试

```powershell
cmake -S . -B build-cmake
cmake --build build-cmake --config Release
ctest --test-dir build-cmake -C Release --output-on-failure
```

Linux 的可移植测试入口是 `sh tests/test-portable.sh`，需要 C++ 编译器和 Python。它运行真实配置／代理代码，但不能验证 Windows SDK 分支、PowerShell 执行、计划任务、共享映射或 Hyper-V。

Windows 实测遇到问题时，保留编译输出、`doctor` 结果、生成的 `.wsb`、盒内日志和 Windows 错误代码。不要附带敏感输入文件；本项目没有自动上传诊断数据。

## 依据

原生功能与限制参照微软的 [Windows Sandbox 概述](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/)、[安装指南](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-install)、[配置指南](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file)。SYSTEM 任务使用 [Task Scheduler 安全上下文](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)。更复杂的网络控制可进一步评估 [Hyper-V 防火墙](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/hyper-v-firewall)，它不是本版已经验证的功能。
