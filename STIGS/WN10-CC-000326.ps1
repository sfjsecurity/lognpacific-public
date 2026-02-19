<#
.SYNOPSIS
    Remediates DISA STIG WN10-CC-000326 (Windows 10 STIG v3r5) by enabling
    PowerShell Script Block Logging.

.NOTES
    Author          : Sana Jafferi
    LinkedIn        : linkedin.com/in/sanajafferi/
    GitHub          : github.com/sfjsecurity
    Date Created    : 2026-02-18
    Last Modified   : 2026-02-19
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000326

.TESTED ON
    Systems Tested  : Windows 10 Enterprise 22H2
    PowerShell Ver. : 5.1+

.USAGE
    Run in an elevated PowerShell session:
    PS C:\> .\WN10-CC-000326.ps1
#>

# --- Safety: require admin ---
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

$RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$ValueName    = "EnableScriptBlockLogging"
$Required     = 1

try {
    # Ensure key exists
    if (-not (Test-Path $RegistryPath)) {
        New-Item -Path $RegistryPath -Force | Out-Null
    }

    # Enable Script Block Logging
    New-ItemProperty -Path $RegistryPath `
                     -Name $ValueName `
                     -PropertyType DWord `
                     -Value $Required `
                     -Force | Out-Null

    # Optional: enable invocation logging too (harmless if not required)
    New-ItemProperty -Path $RegistryPath `
                     -Name "EnableScriptBlockInvocationLogging" `
                     -PropertyType DWord `
                     -Value 1 `
                     -Force | Out-Null

    # Refresh policy
    gpupdate /target:computer /force | Out-Null

    # Verify
    $current = (Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction Stop).$ValueName
    if ([int]$current -eq $Required) {
        Write-Output "COMPLIANT: WN10-CC-000326 configured (PowerShell Script Block Logging enabled)."
        Write-Output "NOTE: Reboot recommended before rescanning Tenable."
        exit 0
    } else {
        Write-Error "NOT COMPLIANT: $ValueName is $current (expected $Required)."
        exit 2
    }
}
catch {
    Write-Error "Remediation failed: $($_.Exception.Message)"
    exit 3
}
