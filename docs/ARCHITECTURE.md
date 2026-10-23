# Architecture

WinSandboxCtl runs entirely in user mode: no driver, no WDK, no signed `.sys`.
The security boundary comes from Windows Sandbox itself; the network policy
comes from where each component runs.

## Network policy: NAT vs. proxy

```
NAT direct mode (blocked at host firewall):

  Guest app ──► Sandbox NAT ──► host firewall sees "WindowsSandbox.exe"
                                (a Microsoft system component) ──► ❌ blocked

Proxy mode (allowed):

  Guest app ──► CONNECT tunnel ──► host-side SandboxHost.exe
                                   (user-mode, whitelisted) ──► ✅ allowed
```

- **NAT → treated as a system component.** Traffic leaving the sandbox via
  NAT is attributed to the Windows Sandbox host process, which a whitelist
  firewall blocks by default.
- **Proxy → treated as a user-mode program.** The CONNECT proxy lives inside
  `SandboxHost.exe` on the host. With a whitelist-based firewall
  allowing only that binary, in-guest programs reach whitelisted domains
  through the tunnel while direct traffic stays blocked.

The proxy enforces its own domain/port whitelist and rejects private
addresses by default. It is advisory: guest code that ignores the proxy
setting gets no network, because NAT is disabled in proxy mode. If guest
DHCP fails, `guest/guest.ps1` assigns a static address so the proxy path
still works without NAT.

## Runtime layout

```
Host                                   Guest (Windows Sandbox)
─────                                  ──────────────────────
SandboxHost.exe (CLI)                  guest.ps1 (bootstrap)
  ├─ builds runtime.wsb  ──launch──►     ├─ admin phase: AppData junctions,
  ├─ stages ReadOnlyBin   (read-only)    │  proxy config, static-IP fallback
  ├─ mounts PersistData   (persistent)   ├─ SYSTEM phase (optional, via
  └─ runs CONNECT proxy ◄──CONNECT────   │  Task Scheduler): run target
     (domain/port whitelist)             └─ writes status.json + logs
```

- Input snapshot is mapped read-only; writes are rejected by the VM.
- `PersistData` is the only writable shared location and survives restarts.
- Guest-reported `status.json` is untrusted telemetry; the host only
  displays it.
