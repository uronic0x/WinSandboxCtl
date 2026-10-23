# This script runs ONLY inside Windows Sandbox. The host never invokes it.
# Read-only Control/Input -> private guest Work; only explicit Data is persistent.
[CmdletBinding()]
param([ValidateSet('Entry', 'Elevated', 'System')][string]$Phase = 'Entry')

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:StatusDirectory = $null
$script:TranscriptActive = $false
$script:Config = $null

function Write-RunStatus {
    param([string]$State, [string]$Message, [Nullable[int]]$ProcessExitCode = $null)
    if (-not $script:StatusDirectory) { return }
    $status = [ordered]@{
        schema = 1; runId = $script:Config.runId; state = $State
        message = $Message; timeUtc = [DateTime]::UtcNow.ToString('o')
        phase = $Phase; identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        exitCode = $ProcessExitCode; telemetryTrust = 'guest-controlled'
    }
    $file = Join-Path $script:StatusDirectory 'status.json'
    $temporary = Join-Path $script:StatusDirectory ('status-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    [IO.File]::WriteAllText($temporary, ($status | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $temporary -Destination $file -Force
}

function Test-Administrator {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-RelativePath {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value) -or [IO.Path]::IsPathRooted($Value)) { throw 'Invalid relative path.' }
    foreach ($part in ($Value -split '[\\/]')) {
        if ($part -eq '' -or $part -eq '.' -or $part -eq '..' -or $part -match '[:<>"|?*\x00-\x1f]' -or $part -match '[. ]$') {
            throw 'Unsafe relative path in launch manifest.'
        }
    }
}

function Set-PersistentDirectory {
    param([string]$Base, [string]$SubPath, [string]$Category)
    if (-not $SubPath) { return }
    Assert-RelativePath $SubPath
    if ($script:Config.data -ne 'write') { throw 'AppData links require writable data.' }
    if (-not $Base) { throw 'Current identity has no AppData directory.' }
    $source = Join-Path $Base $SubPath
    $target = Join-Path ('C:\Sandbox\Data\AppData\' + $Category) $SubPath
    [IO.Directory]::CreateDirectory($target) | Out-Null
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($source)) | Out-Null
    if (Test-Path -LiteralPath $source) {
        $existing = Get-Item -LiteralPath $source -Force
        if (($existing.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Refusing to replace an existing AppData link.' }
        if (-not $existing.PSIsContainer -or @(Get-ChildItem -LiteralPath $source -Force).Count -ne 0) {
            throw ('AppData destination already contains files; no data was deleted: ' + $source)
        }
        [IO.Directory]::Delete($source, $false)
    }
    New-Item -ItemType Junction -Path $source -Target $target -ErrorAction Stop | Out-Null
    Write-Host ('Persistent directory: ' + $source + ' -> ' + $target)
}

function Set-GuestProxy {
    if ($script:Config.network -ne 'proxy') { return }
    $proxy = [string]$script:Config.proxy
    if ($proxy -notmatch '^([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}$') { throw 'Invalid proxy endpoint.' }
    Write-RunStatus 'configuring' ('Setting guest proxy to ' + $proxy)
    # In-process Win32 registry API: no child process (reg.exe hangs in Sandbox)
    # and no PowerShell registry provider (access denied for WDAGUtilityAccount).
    $subKey = 'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($subKey, $true)
    if ($null -eq $key) { throw 'Unable to open the WinINET settings hive.' }
    try {
        $key.SetValue('ProxyEnable', 1, [Microsoft.Win32.RegistryValueKind]::DWord)
        $key.SetValue('ProxyServer', $proxy, [Microsoft.Win32.RegistryValueKind]::String)
        $key.SetValue('ProxyOverride', '', [Microsoft.Win32.RegistryValueKind]::String)
        $key.Flush()
    } finally {
        $key.Close()
    }
    # Notify WinINET so already-loaded in-process copies pick up the change.
    Add-Type -Namespace 'SA' -Name 'WinINet' -MemberDefinition '[System.Runtime.InteropServices.DllImport("wininet.dll", SetLastError=true)] public static extern bool InternetSetOption(System.IntPtr h, int option, System.IntPtr buffer, int length);'
    [SA.WinINet]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null # SETTINGS_CHANGED
    [SA.WinINet]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null # REFRESH
    $env:HTTP_PROXY = 'http://' + $proxy
    $env:HTTPS_PROXY = 'http://' + $proxy
    $env:ALL_PROXY = 'http://' + $proxy
    $env:NO_PROXY = ''
    # No netsh winhttp: child processes can hang in Sandbox, and WinHTTP is only
    # used by services; WinINET apps and env-var clients are already covered.
    Write-RunStatus 'configuring' 'Guest proxy configuration finished.'
    # The guest NIC gets its DHCP address AFTER logon; without this wait the
    # target starts while every route is still "network unreachable".
    $proxyHost = $proxy.Split(':')[0]
    $proxyPort = [int]$proxy.Split(':')[1]
    # Host firewalls that block ICS (SharedAccess svchost) silently break guest
    # DHCP (guest falls back to 169.254.x.x). The proxy path needs no NAT, so
    # after a short DHCP grace period fall back to a static address derived
    # from the proxy endpoint: gateway = proxy host, guest = last .x.2 of the
    # host's /20 (Default Switch convention).
    $dhcpDeadline = [DateTime]::UtcNow.AddSeconds(20)
    $hasAddress = $false
    while ([DateTime]::UtcNow -lt $dhcpDeadline) {
        $hasAddress = [bool](Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1' -and $_.PrefixOrigin -ne 'WellKnown' })
        if ($hasAddress) { break }
        Start-Sleep -Seconds 2
    }
    if (-not $hasAddress) {
        Write-RunStatus 'configuring' 'Guest DHCP failed; assigning a static address for the proxy path.'
        $parts = $proxyHost.Split('.')
        $guestIp = $parts[0] + '.' + $parts[1] + '.' + ([int]$parts[2] + 15) + '.2'
        $adapter = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up' | Select-Object -First 1
        if ($null -eq $adapter) { throw 'No guest adapter is up for static addressing.' }
        New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $guestIp -PrefixLength 20 -DefaultGateway $proxyHost -ErrorAction Stop | Out-Null
        Write-RunStatus 'configuring' ('Static guest address ' + $guestIp + '/20 via ' + $proxyHost)
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(90)
    $ready = $false
    while ([DateTime]::UtcNow -lt $deadline) {
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $task = $client.ConnectAsync($proxyHost, $proxyPort)
            if ($task.Wait(3000) -and $client.Connected) { $ready = $true; break }
        } catch { } finally { $client.Close() }
        Start-Sleep -Seconds 2
    }
    if (-not $ready) { throw ('Proxy endpoint unreachable from guest: ' + $proxy) }
    Write-RunStatus 'configuring' ('Guest reached proxy at ' + $proxy)
    Write-Host 'Explicit proxy configured. This does not prevent direct networking.' -ForegroundColor Yellow
    Write-Host 'The included proxy supports HTTPS CONNECT; plain HTTP, UDP and SOCKS are unsupported.'
}

function Invoke-AsGuestSystem {
    # Administrator-only Task Scheduler API, invoked after guest-only guards.
    # SYSTEM tasks use a non-interactive session. GUI applications are not supported here.
    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    $folder = $service.GetFolder('\')
    $definition = $service.NewTask(0)
    $definition.RegistrationInfo.Description = 'WinSandboxCtl guest-only on-demand SYSTEM worker'
    $definition.Principal.UserId = 'S-1-5-18'
    $definition.Principal.LogonType = 5
    $definition.Principal.RunLevel = 1
    $definition.Settings.Enabled = $true
    $definition.Settings.AllowDemandStart = $true
    $definition.Settings.DisallowStartIfOnBatteries = $false
    $definition.Settings.StopIfGoingOnBatteries = $false
    $definition.Settings.ExecutionTimeLimit = 'PT0S'
    $action = $definition.Actions.Create(0)
    $action.Path = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $action.Arguments = '-NoLogo -NoProfile -ExecutionPolicy Bypass -File C:\Sandbox\Control\guest.ps1 -Phase System'
    $action.WorkingDirectory = 'C:\Sandbox\Control'
    $name = 'WinSandboxCtl-' + $script:Config.runId
    $registered = $folder.RegisterTaskDefinition($name, $definition, 6, 'SYSTEM', $null, 5)
    try {
        Write-Host 'Launching SYSTEM worker in a non-interactive guest task session.'
        $running = $registered.Run($null)
        do {
            Start-Sleep -Milliseconds 500
            $running.Refresh()
            $taskState = [int]$running.State
        } while ($taskState -eq 2 -or $taskState -eq 4)
        $finished = $folder.GetTask($name)
        $result = [long]$finished.LastTaskResult
        Write-Host ('SYSTEM task result: ' + $result)
        if ($result -ne 0) { throw ('SYSTEM task failed with code ' + $result + '; inspect the run logs.') }
    } finally {
        $folder.DeleteTask($name, 0)
    }
}

try {
    # Accident-prevention guards, NOT a replacement for the VM security boundary.
    if ([IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\') -ine 'C:\Sandbox\Control') {
        throw 'Guest script must run from C:\Sandbox\Control inside Windows Sandbox.'
    }
    $script:Config = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'launch.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($script:Config.schema -ne 1 -or $script:Config.runId -notmatch '^[a-fA-F0-9-]{16,64}$') { throw 'Invalid launch manifest.' }
    if (-not $script:Config.hostMachine -or [Environment]::MachineName -ieq $script:Config.hostMachine) {
        throw 'Host/guest machine guard failed; refusing to run.'
    }
    if ($script:Config.identity -notin @('admin', 'system') -or $script:Config.network -notin @('off', 'direct', 'proxy') -or
        $script:Config.data -notin @('none', 'read', 'write')) { throw 'Unsupported manifest policy.' }
    if ($Phase -eq 'Entry' -and $env:USERNAME -ine 'WDAGUtilityAccount') {
        throw 'Expected the Windows Sandbox WDAGUtilityAccount at initial logon.'
    }
    if ($Phase -eq 'System' -and -not [Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) {
        throw 'SYSTEM phase did not receive a SYSTEM token.'
    }
    Assert-RelativePath $script:Config.entry
    $logBase = if ($script:Config.data -eq 'write') { 'C:\Sandbox\Data\Runs' } else { 'C:\Sandbox\Logs' }
    $script:StatusDirectory = Join-Path $logBase $script:Config.runId
    [IO.Directory]::CreateDirectory($script:StatusDirectory) | Out-Null
    Start-Transcript -LiteralPath (Join-Path $script:StatusDirectory ('agent-' + $Phase + '.log')) -Force | Out-Null
    $script:TranscriptActive = $true
    Write-RunStatus 'starting' 'Guest bootstrap entered.'
    Write-Host ('Run logs: ' + $script:StatusDirectory)

    if (-not (Test-Administrator)) {
        if ($Phase -ne 'Entry') { throw 'Guest administrator elevation was not obtained.' }
        Write-Host 'Accept the elevation prompt INSIDE the Sandbox desktop.'
        $parameters = '-NoLogo -NoProfile -ExecutionPolicy Bypass -File C:\Sandbox\Control\guest.ps1 -Phase Elevated'
        $elevated = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Verb RunAs -ArgumentList $parameters -Wait -PassThru
        if ($elevated.ExitCode -ne 0) { throw 'Elevated guest bootstrap failed; inspect its log.' }
        exit 0
    }
    if ($script:Config.identity -eq 'system' -and $Phase -ne 'System') {
        Invoke-AsGuestSystem
        exit 0
    }

    $work = Join-Path 'C:\Sandbox\Work' $script:Config.runId
    if (Test-Path -LiteralPath $work) { throw 'This guest run already has a work directory; close Sandbox and start a fresh run.' }
    [IO.Directory]::CreateDirectory($work) | Out-Null
    Get-ChildItem -LiteralPath 'C:\Sandbox\Input' -Force | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination $work -Recurse -Force
    }
    $env:SANDBOX_RUN_ID = [string]$script:Config.runId
    $env:SANDBOX_INPUT_DIR = 'C:\Sandbox\Input'
    $env:SANDBOX_WORK_DIR = $work
    $env:SANDBOX_DATA_DIR = if ($script:Config.data -eq 'none') { '' } else { 'C:\Sandbox\Data' }
    Set-PersistentDirectory ([Environment]::GetFolderPath('ApplicationData')) ([string]$script:Config.roaming) 'Roaming'
    Set-PersistentDirectory ([Environment]::GetFolderPath('LocalApplicationData')) ([string]$script:Config.local) 'Local'
    Set-GuestProxy

    $target = Join-Path $work ([string]$script:Config.entry)
    if (-not (Test-Path -LiteralPath $target -PathType Leaf)) { throw 'Staged entry is missing.' }
    $program = $target
    $argumentLine = [string]$script:Config.argumentsCommandLine
    if ([IO.Path]::GetExtension($target) -ieq '.msi') {
        $program = "$env:SystemRoot\System32\msiexec.exe"
        $argumentLine = '/i "' + $target + '" ' + $argumentLine
    }
    $start = @{
        FilePath = $program; WorkingDirectory = [IO.Path]::GetDirectoryName($target)
        PassThru = $true
        RedirectStandardOutput = (Join-Path $script:StatusDirectory 'stdout.txt')
        RedirectStandardError = (Join-Path $script:StatusDirectory 'stderr.txt')
    }
    if ($argumentLine.Length -gt 0) { $start.ArgumentList = $argumentLine }
    Write-RunStatus 'launching' ('Starting ' + $script:Config.entry)
    $process = Start-Process @start
    $null = $process.Handle
    Write-RunStatus 'running' ('Root process PID ' + $process.Id)
    $process.WaitForExit()
    # Refresh before reading ExitCode, including programs that exit immediately.
    $process.Refresh()
    if ($null -eq $process.ExitCode) { throw 'The target exit code could not be retrieved.' }
    $targetExit = [int]$process.ExitCode
    Write-RunStatus 'exited' 'Root process exited; guest services/children may still be running.' $targetExit
    Write-Host ('Target root exit code: ' + $targetExit)
    Write-Host 'Close the Windows Sandbox desktop to discard guest state. Writable mapped data persists.'
    exit 0
} catch {
    $message = $_.Exception.Message
    try { Write-RunStatus 'error' $message } catch { }
    Write-Host ('WinSandboxCtl guest error: ' + $message) -ForegroundColor Red
    if ($script:StatusDirectory) { Write-Host ('Logs: ' + $script:StatusDirectory) }
    exit 1
} finally {
    if ($script:TranscriptActive) { try { Stop-Transcript | Out-Null } catch { } }
}
