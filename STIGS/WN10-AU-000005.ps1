<#
.SYNOPSIS
    Remediates DISA STIG WN10-AU-000005 by ensuring Audit Credential Validation
    is configured to log Failure events.

.NOTES
    Author          : Sana Jafferi
    LinkedIn        : linkedin.com/in/sanajafferi/
    GitHub          : github.com/sfjsecurity
    Date Created    : 2026-02-18
    Last Modified   : 2026-02-18
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
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
    # Enforce advanced audit policy (STIG-aligned)
    # Policy: "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings"
    $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Set-ItemProperty -Path $lsaPath -Name "SCENoApplyLegacyAuditPolicy" -Value 1 -Type DWord -Force

    # Enable FAILURE auditing for Account Logon category (includes Credential Validation)
    auditpol /set /category:"Account Logon" /failure:enable | Out-Null

    # Verify registry setting
    $force = (Get-ItemProperty -Path $lsaPath -Name "SCENoApplyLegacyAuditPolicy" -ErrorAction Stop).SCENoApplyLegacyAuditPolicy

    # Verify audit output (system shows "Credential Validation  Failure")
    $out = auditpol /get /category:"Account Logon"
    $credLine = ($out | Select-String -Pattern "Credential Validation" -CaseSensitive:$false).Line

    if ($force -eq 1 -and $credLine -match "\bFailure\b") {
        Write-Output "COMPLIANT: WN10-AU-000005 configured (Credential Validation = Failure; advanced audit enforced)."
        exit 0
    } else {
        Write-Error "NOT COMPLIANT: Unable to verify Credential Validation = Failure and/or advanced audit enforcement."
        Write-Output $out
        exit 2
    }
}
catch {
    Write-Error "Remediation failed: $($_.Exception.Message)"
    exit 3
}
