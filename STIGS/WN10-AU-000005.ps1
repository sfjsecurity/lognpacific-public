<#
.SYNOPSIS
    Remediates DISA STIG WN10-AU-000005 by ensuring Audit Account Management
    is configured to log both Success and Failure events.

.NOTES
    Author          : Sana Jafferi
    LinkedIn        : linkedin.com/in/sanajafferi/
    GitHub          : github.com/sfjsecurity
    Date Created    : 2026-02-18
    Last Modified   : 2026-02-18
    Version         : 1.0
    STIG-ID         : WN10-AU-000005

.TESTED ON
    Systems Tested  : Windows 10 Enterprise 22H2
    PowerShell Ver. : 5.1+

.USAGE
    Run in an elevated PowerShell session:
    PS C:\> .\WN10-AU-000005.ps1
#>

# --- Safety: require admin ---
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

try {
    # Enable Success and Failure auditing for Account Management
    auditpol /set /subcategory:"Account Management" /success:enable /failure:enable | Out-Null

    # Verify configuration
    $result = auditpol /get /subcategory:"Account Management"

    if ($result -match "Success\s+Enabled" -and $result -match "Failure\s+Enabled") {
        Write-Output "COMPLIANT: WN10-AU-000005 successfully configured."
        exit 0
    }
    else {
        Write-Error "NOT COMPLIANT: Audit Account Management not properly configured."
        exit 2
    }
}
catch {
    Write-Error "Remediation failed: $($_.Exception.Message)"
    exit 3
}

