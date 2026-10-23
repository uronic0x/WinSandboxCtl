# WinSandboxCtl

User-mode controller for Windows Sandbox: native C++ host CLI, in-guest
PowerShell bootstrap, read-only input snapshots, explicit persistent data,
administrator or non-interactive SYSTEM execution, and an optional
domain-whitelisted CONNECT proxy.

- Build on Windows: `build.cmd` (MSVC C++ tools + Windows SDK).
- Test on Windows: `scripts/Test-Windows.ps1` after building.
- Portable tests: `sh tests/test-portable.sh` (C++ compiler + Python).
- 中文文档：[README.zh-CN.md](README.zh-CN.md)；新手教程见 `TUTORIAL.zh-CN.md`。
- Architecture (NAT vs. proxy enforcement diagram): `docs/ARCHITECTURE.md`.
- License: MIT for project source; Windows is a separate proprietary platform.

## Verified on Windows 11

- MSVC build and 5,461 core argument test cases pass.
- All three network modes work: offline, NAT direct, and explicit proxy.
- With a whitelist-based host firewall allowing only the user-mode
  `SandboxHost.exe`, in-guest traffic reaches whitelisted domains through the
  CONNECT tunnel while NAT direct traffic stays blocked — no driver, no WDK.
- In-guest networking uses WinINET-style proxy configuration, with a static
  address fallback if guest DHCP fails, so the proxy path works without NAT.
- Read-only input snapshots reject writes; `PersistData` survives sandbox
  restarts.

## Honest security scope

- The proxy is advisory and can be bypassed by guest code. Default networking
  is disabled.
- SYSTEM mode does not support ordinary interactive GUI windows.
- **No escape-resistance security audit has been performed or claimed.**
  Passing functional tests is not a security audit. Full records: see
  `docs/TEST-RESULTS.md`.
