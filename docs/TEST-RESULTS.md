# 测试记录

日期：2026-10-23（America/Los_Angeles）。

## 已实际执行

| 项目 | 结果 | 验证范围 |
| --- | --- | --- |
| Linux 原生编译 | 通过 | GCC 13.3.0，C++17，`-Wall -Wextra -Wpedantic -Werror` |
| 核心测试 | 通过 | 路径、设备名、数值边界、JSON/XML、代理解析、CIDR、白名单、参数转义 |
| 参数穷举 | 通过 | 5461 个短字符串；覆盖字母、空格、反斜线、引号及空串 |
| 实际控制器／代理集成 | 通过 | 36 个用例；不是用 Python 重写业务逻辑后测试替身 |
| UBSan 核心测试 | 通过 | `-fsanitize=undefined`，未报告未定义行为 |
| ASan | 环境不可用于有效结论，不计通过 | 见下面的环境限制 |

集成测试实际运行了配置生成程序，对 18 种网络／数据／身份组合解析生成的 XML 和 JSON，核对只读映射、参数、快照文件和禁用的共享功能；覆盖中文、空格与 `&` 路径，拒绝越界、设备名、重复选项、非法内存值和符号链接。

代理测试在本机创建真实 TCP 端点，执行 CONNECT 隧道和二进制数据回环，核对完整数据摘要与半关闭行为；测试未授权域名／端口、非法请求、超长头部和默认私有地址拒绝。测试没有访问外网，也没有运行任何不可信程序。

最终可重现入口：

```sh
sh tests/test-portable.sh
```

观察到的输出：

```text
PASS core tests; argument cases=5461
{"result": "PASS", "integration_cases": 36, "scope": "portable host/config/proxy; not Windows VM runtime"}
```

UBSan 单独编译并运行核心测试也得到上述 PASS 核心结果。

## ASan 环境限制

ASan 运行先报告无法读取 `/proc/self/exe`、无法获得正常栈边界，并提示 `__asan_handle_no_return` 可能产生误报；之后出现栈诊断。用不包含本项目代码、仅包含 `std::wstring`、`std::function` 和主动抛出异常的独立最小程序也复现了该类诊断；另一个最小程序在 LeakSanitizer 阶段报告不能读取 `/proc/.../task`。

因此没有把 ASan 标记为通过，也没有通过关闭检查来取得通过结果。交付者对这些诊断的判断是当前受限 Linux 运行环境不适合 ASan；这不是独立的内存安全证明，后续应在正常 Windows／Linux 开发机再次运行。

## Windows 11 实测（2026-10-24，追加）

上述 Linux 记录之后的同一天（原"仍需你在 Windows 上验证"一节，以下内容已全部在 Windows 11 实际执行，结论由"未验证"更新为"通过"）：

| 项目 | 结果 | 验证范围 |
| --- | --- | --- |
| Windows 全量编译 | 通过 | `build.cmd`（MSVC + Windows SDK），含 `CommandLineToArgvW` 交叉核对 |
| 核心参数用例 | 通过 | 5461 条，与 Linux 侧一致 |
| 端到端运行 | 通过 | 建盒、`.wsb` 生成、启动、盒内探针、状态回收 |
| 网络模式 | 通过 | 断网／NAT 直连／代理三种模式均按预期 |
| 代理白名单 + 白名单防火墙 | 通过 | 防火墙只放行 `SandboxHost.exe`（用户态）时，盒内 curl 经 CONNECT 隧道可访问白名单域名；NAT 直连流量（WFP 归属 System）仍被拦截。该行为由 Windows 网络栈的机制决定，不依赖特定防火墙产品 |
| 只读输入 / 持久化 | 通过 | ReadOnlyBin 写入被拒；PersistData 跨重启保留 |
| 静态 IP 兜底 | 通过 | DHCP 失败时盒内自动分配静态地址供代理路径使用（`guest/guest.ps1`） |

仍未完成：防逃逸安全审计（不承诺）；ASan 结论仍受原环境限制。

## 原记录（Linux，2026-10-23）

本环境没有 MSVC、Windows SDK、Windows PowerShell、Windows Sandbox 或 Hyper-V。以下项目在 Linux 阶段尚未执行，已在上面"Windows 11 实测"一节补充结果：

- `build.cmd` 的 Windows 全量编译和链接，以及可选 CMake 构建。
- PowerShell 的实际解析与执行、微软 Task Scheduler COM 接口、管理员提升和 SYSTEM 会话。
- Windows Sandbox 的受保护客户端、只读／读写映射、AppData Junction 和 guest 身份对映射的访问。
- 实际被测软件的安装、服务、GUI、网络兼容性及盒内重启行为。
- 当前 Windows 版本上的 VM 安全边界、网络强制隔离和逃逸对抗（逃逸对抗仍未审计，勿据此推断安全结论）。

`build.cmd` 在 Windows 上运行核心测试时会额外调用 `CommandLineToArgvW`，核对同一组参数样例；`scripts/Test-Windows.ps1` 会先用系统自带解析器检查所有 PowerShell 文件，再运行无害盒内探针。功能测试通过仍不等于安全审计通过。
