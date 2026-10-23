# Explicit one-time setup, to be run by the user in an Administrator console.
# This script does not reboot the machine automatically.
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param()
$ErrorActionPreference = 'Stop'
$edition = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').EditionID
if ($edition -notmatch '^(Professional|Enterprise|Education|IoTEnterprise)') {
    throw ('Unsupported or unrecognized Windows edition: ' + $edition + '. Use a supported Windows Pro/Enterprise/Education installation.')
}
if ($PSCmdlet.ShouldProcess('Windows Sandbox optional feature', 'Enable (no automatic reboot)')) {
    Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All -NoRestart
    Write-Host 'If Windows reports RestartNeeded, restart manually before testing.'
}
