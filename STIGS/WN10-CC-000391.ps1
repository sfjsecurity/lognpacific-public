<#
.SYNOPSIS
    Remediates DISA STIG WN10-CC-000391 by preventing the storage
    of passwords and credentials for network authentication.

.NOTES
    Author          : Sana Jafferi
    LinkedIn        : linkedin.com/in/sanajafferi/
    GitHub          : github.com/sfjsecurity
    Date Created    : 2026-02-18
    Last Modified   : 2026-02-18
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000391

.TESTED ON
    Systems Tested  : Windows 10 Enterprise 22H2
    PowerShell Ver. : 5.1+

.USAGE
    Run in an elevated PowerShell session:
    PS C:\> .\WN10-CC-000391.ps1
#>

# --- Safety: require admin ---
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

$RegistryPath  = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$ValueName     = "DisableDomainCreds"
$RequiredValue = 1

try {
    New-ItemProperty -Path $RegistryPath `
                     -Name $ValueName `
                     -PropertyType DWord `
                     -Value $RequiredValue `
                     -Force | Out-Null

    $current = (Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction Stop).$ValueName

    if ($current -eq $RequiredValue) {
        Write-Output "COMPLIANT: WN10-CC-000391 configured (DisableDomainCreds = 1)."
        exit 0
    }
    else {
        Write-Error "NOT COMPLIANT: DisableDomainCreds is $current (expected $RequiredValue)."
        exit 2
    }
}
catch {
    Write-Error "Remediation failed: $($_.Exception.Message)"
    exit 3
}

