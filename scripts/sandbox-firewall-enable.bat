@echo off
rem ============================================================
rem  WinSandboxCtl - Enable Hyper-V firewall enforcement
rem  Forces ALL Windows Sandbox outbound traffic through the
rem  user-mode CONNECT proxy (SandboxHost.exe). Everything else
rem  is dropped at the virtual switch layer.
rem
rem  Usage (run as Administrator):
rem    sandbox-firewall-enable.bat [proxy_ip] [proxy_port]
rem
rem  Defaults: proxy_ip=172.18.64.1  proxy_port=18080
rem  Rollback: sandbox-firewall-disable.bat
rem ============================================================
setlocal

set PROXY_IP=%1
if "%PROXY_IP%"=="" set PROXY_IP=172.18.64.1
set PROXY_PORT=%2
if "%PROXY_PORT%"=="" set PROXY_PORT=18080

rem Fixed platform identity of Windows Sandbox (not user-configurable)
set VMCREATOR={40E0AC32-46A5-438A-A0B2-2B479E8F2E90}

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%PROXY_IP% %PROXY_PORT%' -Verb RunAs"
    exit /b 0
)

echo [1/3] Enabling Hyper-V firewall for Windows Sandbox (default outbound = Block)...
powershell -NoProfile -Command "Set-NetFirewallHyperVVMSetting -Name '%VMCREATOR%' -Enabled True -DefaultOutboundAction Block"
if %errorlevel% neq 0 (
    echo [ERROR] Failed to set VM setting. Is Hyper-V firewall supported on this OS?
    exit /b 1
)

echo [2/3] Removing stale rules with the same display name...
powershell -NoProfile -Command "Get-NetFirewallHyperVRule -VMCreatorId '%VMCREATOR%' -ErrorAction SilentlyContinue | Where-Object DisplayName -eq 'WinSandboxCtl proxy egress' | Remove-NetFirewallHyperVRule"
if %errorlevel% neq 0 (
    echo [WARN] Stale rule cleanup failed or none existed. Continuing.
)

echo [3/3] Allowing the single egress path: VM --TCP--^> %PROXY_IP%:%PROXY_PORT%
powershell -NoProfile -Command "New-NetFirewallHyperVRule -DisplayName 'WinSandboxCtl proxy egress' -VMCreatorId '%VMCREATOR%' -Direction Outbound -Action Allow -Protocol TCP -RemoteAddresses %PROXY_IP% -RemotePorts %PROXY_PORT%"
if %errorlevel% neq 0 (
    echo [ERROR] Failed to create the egress rule.
    exit /b 1
)

echo.
echo ============================================================
echo  ENFORCED. Windows Sandbox outbound is now:
echo    allowed : TCP to %PROXY_IP%:%PROXY_PORT% (the proxy)
echo    blocked : everything else (direct IPs, DNS UDP 53, ...)
echo  NOTE: only affects Windows Sandbox VMs, not the host.
echo        A VM started BEFORE this change may need a restart
echo        (close and reopen the Sandbox window) to pick it up.
echo  Rollback: sandbox-firewall-disable.bat
echo ============================================================
pause
endlocal
exit /b 0
