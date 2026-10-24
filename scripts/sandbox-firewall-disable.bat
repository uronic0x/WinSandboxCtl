@echo off
rem ============================================================
rem  WinSandboxCtl - Disable Hyper-V firewall enforcement
rem  Removes the forced-proxy policy created by
rem  sandbox-firewall-enable.bat. Windows Sandbox returns to
rem  platform default (no per-VM outbound restriction).
rem
rem  Usage (run as Administrator):
rem    sandbox-firewall-disable.bat
rem ============================================================
setlocal

rem Fixed platform identity of Windows Sandbox (not user-configurable)
set VMCREATOR={40E0AC32-46A5-438A-A0B2-2B479E8F2E90}

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b 0
)

echo [1/2] Removing WinSandboxCtl Hyper-V firewall rules...
powershell -NoProfile -Command "Get-NetFirewallHyperVRule -VMCreatorId '%VMCREATOR%' -ErrorAction SilentlyContinue | Remove-NetFirewallHyperVRule"
if %errorlevel% neq 0 (
    echo [ERROR] Failed to remove Hyper-V firewall rules.
    exit /b 1
)

echo [2/2] Disabling Hyper-V firewall policy for Windows Sandbox...
powershell -NoProfile -Command "Set-NetFirewallHyperVVMSetting -Name '%VMCREATOR%' -Enabled False"
if %errorlevel% neq 0 (
    echo [ERROR] Failed to disable the VM setting.
    exit /b 1
)

echo.
echo ============================================================
echo  DISABLED. Windows Sandbox outbound is back to platform
echo  default. Direct connections will reach the host NAT again
echo  (subject to your host/corporate firewall, as before).
echo  A running VM may need a restart to pick this up.
echo  Re-enable: sandbox-firewall-enable.bat
echo ============================================================
pause
endlocal
exit /b 0
