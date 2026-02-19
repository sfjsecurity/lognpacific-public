<#
.SYNOPSIS
    Remediates DISA STIG WN10-CC-000295 by limiting local account use of blank
    passwords to console logon only.

.NOTES
    Author          : Sana Jafferi
    LinkedIn        : linkedin.com/in/sanajafferi/
    GitHub          : github.com/sfjsecurity
    Date Created    : 2026-02-18
    Last Modified   : 2026-02-18
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000295

.TESTED ON
    Systems Tested  : Windows 10 Enterprise 22H2
    PowerShell Ver. : 5.1+

.USAGE
    Run in an elevated PowerShell session:
    PS C:\> .\WN10-CC-000295.ps1
#>

# --- Safety: require admin ---
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

$RegistryPath  = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$ValueName     = "LimitBlankPasswordUse"
$RequiredValue = 1

try {
    New-ItemProperty -Path $RegistryPath `
                     -Name $ValueName `
                     -PropertyType DWord `
                     -Value $RequiredValue `
                     -Force | Out-Null

    $current = (Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction Stop).$ValueName

    if ([int]$current -eq $RequiredValue) {
        Write-Output "COMPLIANT: WN10-CC-000295 configured (blank passwords restricted to console logon only)."
        exit 0
    } else {
        Write-Error "NOT COMPLIANT: $ValueName is $current (expected $RequiredValue)."
        exit 2
    }
}
catch {
    Write-Error "Remediation failed: $($_.Exception.Message)"
    exit 3
}

