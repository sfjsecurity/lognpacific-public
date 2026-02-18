<#
.SYNOPSIS
    Remediates DISA STIG WN10-AU-000005 by ensuring Account Management auditing
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
    # Set Account Management category to log Success and Failure
    auditpol /set /category:"Account Management" /success:enable /failure:enable | Out-Null

    # Verify (use /r for consistent output)
    $result = auditpol /get /category:"Account Management" /r

    # If ANY subcategory still says "No Auditing", treat as not compliant
    if ($result -match "No Auditing") {
        Write-Error "NOT COMPLIANT: One or more Account Management audit policies are still set to 'No Auditing'."
        Write-Output $result
        exit 2
    }

    # Otherwise ensure Success and Failure are present somewhere in the category output
    if (($result -match "Success") -and ($result -match "Failure")) {
        Write-Output "COMPLIANT: WN10-AU-000005 successfully configured (Account Management auditing enabled)."
        exit 0
    } else {
        Write-Error "NOT COMPLIANT: Unable to verify Success/Failure auditing for Account Management."
        Write-Output $result
        exit 2
    }
}
catch {
    Write-Error "Remediation failed: $($_.Exception.Message)"
    exit 3
}
