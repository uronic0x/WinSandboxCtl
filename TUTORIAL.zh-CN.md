# WinSandboxCtl 新手操作教程

目标：从零开始，把一个有网络访问需求的程序放进 Windows Sandbox 里跑，并用自带的代理白名单控制它能访问哪些域名。全程不需要管理员终端（首次启用系统功能除外），不需要改宿主防火墙规则——防火墙弹窗时点"允许"即可。

## 第 0 步：准备环境（只做一次）

1. 确认系统是 **Windows 11 Pro / Enterprise / Education**，BIOS 已开虚拟化。
2. 用**管理员** PowerShell 启用 Windows Sandbox，然后重启：

   ```powershell
   Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All
   ```

3. 安装 Visual Studio 或 C++ Build Tools（勾选"使用 C++ 的桌面开发"）。
4. 在项目根目录打开 CMD，编译：

   ```bat
   build.cmd
   ```

   看到 `PASS core tests; argument cases=5461` 即成功。产物在 `bin\` 下。

## 第 1 步：建盒并放入程序

```powershell
.\bin\SandboxHost.exe init --box Demo
```

这会在 `%LOCALAPPDATA%\WinSandboxCtl\Boxes\Demo\` 下建好目录。把要测试的程序（含 DLL、资源文件）复制进 `ReadOnlyBin` 子目录。

> ⚠️ 不要放敏感文件。盒内程序能读到 `ReadOnlyBin` 的全部内容。

## 第 2 步：先跑一个断网测试（可选，熟悉流程）

```powershell
.\bin\SandboxHost.exe run --box Demo --app DemoProbe.exe --network off --data write
```

会弹出 Windows Sandbox 桌面窗口，程序自动运行。关掉沙盒窗口后，查看状态：

```powershell
.\bin\SandboxHost.exe status --box Demo
```

## 第 3 步：启动代理（盒要联网的关键）

盒的直连流量会被宿主防火墙当成 `System` 拦死（这是设计目标），联网必须走代理。

**3.1** 查看宿主虚拟网卡地址（沙盒运行过一次后才有）：

```powershell
Get-NetIPAddress -InterfaceAlias "vEthernet (Default Switch)" -AddressFamily IPv4
```

假设得到 `172.18.64.1`，前缀 `/20`（你的机器上可能不同，以实际为准）。

**3.2** 开一个**专门的终端窗口**启动代理（它会一直在前台运行，关掉即断网）：

```powershell
.\bin\SandboxHost.exe proxy --listen 172.18.64.1 --clients 172.18.64.0/20 --port 18080 --allow example.com --allow *.example.com
```

- `--allow`：盒内允许访问的域名白名单，每个域名加一条
- `--clients`：允许哪些客户端用这个代理，填宿主虚拟网卡所在网段
- 看到 `READY explicit CONNECT proxy` 就就绪了

**3.3** 防火墙弹窗：代理第一次收到盒的连接时，宿主白名单防火墙会弹"SandboxHost.exe 需要网络连接"——**点允许**（入站、出站都要）。只需要放行这一个程序，不要放行 System。

## 第 4 步：用代理模式启动盒

另开一个终端：

```powershell
.\bin\SandboxHost.exe run --box Demo --app curl.exe --network proxy --proxy 172.18.64.1:18080 --data write --protected-client off -- -v https://example.com/
```

（`curl.exe` 可从 `C:\Windows\System32\curl.exe` 复制进 `ReadOnlyBin`；`--protected-client off` 用于规避部分宿主机代理残留导致的 0x80072EFD 启动报错。）

盒内启动器会自动完成：设置 WinINET 代理和环境变量 → 等网络就绪（DHCP 被防火墙拦死时自动配静态 IP，约 20 秒）→ 启动你的程序。

**验证**：`status` 显示 `exitCode: 0`，`PersistData\Runs\<runId>\stderr.txt` 里能看到 `CONNECT tunnel established` 和 `HTTP/1.1 200 OK`。代理终端会打印 `ALLOW example.com:443 ...`。

## 第 5 步：跑你自己的程序

```powershell
.\bin\SandboxHost.exe run --box Demo --app YourApp.exe --network proxy --proxy 172.18.64.1:18080 --data write
```

盒内程序联网方式：

| 程序类型 | 能否联网 |
| --- | --- |
| 读 `HTTP_PROXY`/`HTTPS_PROXY` 环境变量的（curl、多数 CLI 工具） | ✅ 直接通 |
| 用 WinINET 的（IE 内核组件、部分安装器） | ✅ 注册表已配好 |
| 用 WinHTTP 的服务类程序 | ❌ 故意不配（沙盒内 netsh 有兼容问题） |
| 不支持代理、直连的 | ❌ 被 NAT/System 拦截，天然断网 |

DNS 由**代理端**解析，盒内程序不需要也无法自己解析域名。

## 常见问题排查

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| 启动报 0x80072EFD | 宿主机 WinINET 残留代理（如 127.0.0.1:10809）干扰 Protected Client | 加 `--protected-client off` |
| 状态一直 `starting`/`configuring` | 看 `PersistData\Runs\<runId>\status.json` 的 message 停在哪句 | 卡在 "Setting guest proxy" 之后属正常等待；超 90 秒会报错 |
| curl 报 exit 7 / "Network unreachable" | 盒内 DHCP 未就绪且静态兜底失败 | 升级后的 guest.ps1 已自动处理；检查代理地址是否写对 |
| 代理日志出现 `DENY xxx:443` | 域名不在白名单 | 代理终端加 `--allow` 重启代理 |
| 防火墙没弹窗、盒内连不上代理 | 防火墙静默拦截了 SandboxHost.exe | 手动在防火墙里为 `bin\SandboxHost.exe` 添加允许规则（入站+出站） |
| 想同时开两个盒 | 系统限制 | 关掉一个沙盒窗口再开下一个 |

## 收尾

- 关闭沙盒桌面窗口即销毁盒内全部状态；`PersistData` 里的内容保留在宿主机
- 代理终端 Ctrl+C 或关窗即停止代理
- `Runtime` 目录下的快照和 `.wsb` 不自动清理，确认不用后可手动删
