# Local Windows integration test. Launches only the supplied harmless DemoProbe.
[CmdletBinding()]
param(
    [ValidateSet('admin', 'system')][string]$Identity = 'admin',
    [ValidateSet('on', 'off')][string]$ProtectedClient = 'on',
    [int]$TimeoutSeconds = 240,
    [string]$Root = (Join-Path $env:LOCALAPPDATA 'WinSandboxCtl\TestBoxes')
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$package = Split-Path -Parent $PSScriptRoot
$hostProgram = Join-Path $package 'bin\SandboxHost.exe'
$probe = Join-Path $package 'bin\DemoProbe.exe'
if (-not (Test-Path -LiteralPath $hostProgram) -or -not (Test-Path -LiteralPath $probe)) { throw 'Run build.cmd first.' }
if ($TimeoutSeconds -lt 10) { throw 'Timeout must be at least 10 seconds.' }

# Parse all PowerShell source on the actual Windows parser, before launching.
$parseErrors = @()
Get-ChildItem -LiteralPath $package -Recurse -Filter '*.ps1' | ForEach-Object {
    $tokens = $null
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$errors)
    $parseErrors += $errors
}
if ($parseErrors.Count -ne 0) { $parseErrors | Format-List; throw 'PowerShell syntax validation failed.' }
& (Join-Path $package 'bin\core-tests.exe')
if ($LASTEXITCODE -ne 0) { throw 'Core tests failed.' }

$hostCanary = Join-Path $env:SystemRoot 'WinSandboxCtl-GuestOnly-Canary.txt'
$registryCanary = 'HKLM:\SOFTWARE\WinSandboxCtl-GuestOnly-Probe'
if ((Test-Path -LiteralPath $hostCanary) -or (Test-Path -LiteralPath $registryCanary)) {
    throw 'A host test marker already exists. Inspect it manually; this script will not overwrite or delete it.'
}
$box = 'Probe-' + $Identity + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
& $hostProgram init --root $Root --box $box
if ($LASTEXITCODE -ne 0) { throw 'Box initialization failed.' }
$boxDirectory = Join-Path $Root $box
$inputFolder = Join-Path $boxDirectory 'ReadOnlyBin'
Copy-Item -LiteralPath $probe -Destination (Join-Path $inputFolder 'DemoProbe.exe')
$sourceMarker = Join-Path $inputFolder 'readonly-canary.txt'
[IO.File]::WriteAllText($sourceMarker, 'original')
$sourceHash = (Get-FileHash -LiteralPath $sourceMarker -Algorithm SHA256).Hash
& $hostProgram run --root $Root --box $box --app DemoProbe.exe --identity $Identity --network off --data write --protected-client $ProtectedClient
if ($LASTEXITCODE -ne 0) { throw 'Sandbox launch request failed.' }
$id = (Get-Content -LiteralPath (Join-Path $boxDirectory 'last-run.txt') -Raw).Trim()
$resultFile = Join-Path $boxDirectory ('PersistData\probe-result-' + $id + '.json')
$statusFile = Join-Path $boxDirectory ('PersistData\Runs\' + $id + '\status.json')
$deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
$result = $null
Write-Host 'Waiting for the guest. If a UAC dialog appears, accept it INSIDE Windows Sandbox.'
while ([DateTime]::UtcNow -lt $deadline) {
    if (Test-Path -LiteralPath $resultFile) {
        try { $result = Get-Content -LiteralPath $resultFile -Raw -Encoding UTF8 | ConvertFrom-Json; break } catch { }
    }
    if (Test-Path -LiteralPath $statusFile) {
        try {
            $status = Get-Content -LiteralPath $statusFile -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($status.state -eq 'error') { throw ('GUEST_ERROR: ' + $status.message) }
        } catch {
            if ($_.Exception.Message -like 'GUEST_ERROR:*') { throw }
        }
    }
    Start-Sleep -Milliseconds 500
}
if (-not $result) { throw ('Guest test timed out. Inspect the Sandbox desktop and ' + $statusFile) }
$result | Format-List
if (-not $result.guestWindowsWrite -or -not $result.guestHKLMWrite -or
    -not $result.readOnlyInputProtected -or -not $result.persistentOutputWrite) { throw 'Guest probe assertions failed.' }
if (($Identity -eq 'system') -ne [bool]$result.isSystem) { throw 'Guest token identity does not match requested identity.' }
if ((Test-Path -LiteralPath $hostCanary) -or (Test-Path -LiteralPath $registryCanary)) { throw 'Unexpected HOST marker detected. Stop and inspect the host.' }
if ((Get-FileHash -LiteralPath $sourceMarker -Algorithm SHA256).Hash -ne $sourceHash) { throw 'Original input changed.' }
$snapshotMarker = Join-Path $boxDirectory ('Runtime\' + $id + '\input\readonly-canary.txt')
if ((Get-FileHash -LiteralPath $snapshotMarker -Algorithm SHA256).Hash -ne $sourceHash) { throw 'Read-only snapshot changed.' }
Write-Host 'PASS: guest writes succeeded, source stayed read-only, host markers stayed absent.' -ForegroundColor Green
Write-Host 'Close Windows Sandbox now; then check that the PersistData output file still exists.'
Write-Host ('Profile: ' + $boxDirectory)
Write-Host 'This is a functional integration test with a trusted probe, not an escape-resistance audit.'
