@echo off
setlocal
cd /d "%~dp0"
where cl.exe >nul 2>nul
if errorlevel 1 (
  if not exist "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" (
    echo Install Visual Studio C++ Build Tools with a Windows SDK, then retry.
    exit /b 1
  )
  for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "SA_VS=%%i"
  if not defined SA_VS (
    echo Visual Studio Desktop development with C++ was not found.
    exit /b 1
  )
)
if defined SA_VS call "%SA_VS%\VC\Auxiliary\Build\vcvarsall.bat" x64
where cl.exe >nul 2>nul
if errorlevel 1 exit /b 1
if not exist bin mkdir bin
if not exist build mkdir build
cl /nologo /std:c++17 /EHsc /O2 /MT /W4 /utf-8 /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0A00 /DNOMINMAX src\main.cpp /Fo"build\host.obj" /Fe"bin\SandboxHost.exe" /link shell32.lib advapi32.lib ole32.lib ws2_32.lib
if errorlevel 1 exit /b 1
cl /nologo /std:c++17 /EHsc /O2 /MT /W4 /utf-8 /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0A00 /DNOMINMAX tests\core_tests.cpp /Fo"build\core-tests.obj" /Fe"bin\core-tests.exe" /link ws2_32.lib shell32.lib
if errorlevel 1 exit /b 1
cl /nologo /std:c++17 /EHsc /O2 /MT /W4 /utf-8 /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0A00 tests\DemoProbe.cpp /Fo"build\probe.obj" /Fe"bin\DemoProbe.exe" /link advapi32.lib
if errorlevel 1 exit /b 1
bin\core-tests.exe
if errorlevel 1 exit /b 1
echo Build and core tests passed. Read README.zh-CN.md for the Windows VM test.
exit /b 0
