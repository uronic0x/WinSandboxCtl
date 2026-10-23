[CmdletBinding()]
param()
$ErrorActionPreference = 'Continue'
Write-Host 'WinSandboxCtl read-only Windows diagnostics'
Get-ComputerInfo -Property WindowsProductName, WindowsVersion, OsBuildNumber, OsArchitecture, HyperVisorPresent |
    Format-List
Get-CimInstance Win32_Processor |
    Select-Object Name, VirtualizationFirmwareEnabled, SecondLevelAddressTranslationExtensions |
    Format-List
$sandboxBinary = Join-Path $env:SystemRoot 'System32\WindowsSandbox.exe'
Write-Host ('WindowsSandbox.exe exists: ' + (Test-Path -LiteralPath $sandboxBinary))
try {
    Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -ErrorAction Stop |
        Select-Object FeatureName, State | Format-List
} catch {
    Write-Host 'Optional-feature query needs an elevated console on some systems. No settings were changed.'
    Write-Host $_.Exception.Message
}
Write-Host 'Inspect vEthernet IPv4 addresses for explicit proxy configuration:'
Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.InterfaceAlias -like '*vEthernet*' } |
    Select-Object InterfaceAlias, IPAddress, PrefixLength | Format-Table -AutoSize
Write-Host 'Windows Home is unsupported. No package sideload or feature bypass is attempted.'
