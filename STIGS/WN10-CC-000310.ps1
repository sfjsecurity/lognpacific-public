<#
.SYNOPSIS
    Remediates DISA STIG WN10-CC-000310 by disabling
    "Always install with elevated privileges" for Windows Installer.

.NOTES
    Author          : Sana Jafferi
    LinkedIn        : linkedin.com/in/sanajafferi/
    GitHub          : github.com/sfjsecurity
    Date Created    : 2026-02-18
    Last Modified   : 2026-02-18
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000310

.TESTED ON
    Systems Tested  : Windows 10 Enterprise 22H2
    PowerShell Ver. : 5.1+

.USAGE
    Run in an elevated PowerShell session:
    PS C:\> .\WN10-CC-000310.ps1
#>

# --- Safety: require admin ---
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

$Paths = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer",
    "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer"
)

$ValueName = "AlwaysInstallElevated"
$RequiredValue = 0

try {
    foreach ($Path in $Paths) {

        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }

        New-ItemProperty -Path $Path `
                         -Name $ValueName `
                         -PropertyType DWord `
                         -Value $RequiredValue `
                         -Force | Out-Null
    }

    # Verify
    $lm = (Get-ItemProperty -Path $Paths[0] -Name $ValueName -ErrorAction Stop).$ValueName
    $cu = (Get-ItemProperty -Path $Paths[1] -Name $ValueName -ErrorAction Stop).$ValueName

    if ($lm -eq 0 -and $cu -eq 0) {
        Write-Output "COMPLIANT: WN10-CC-000310 configured (AlwaysInstallElevated disabled)."
        exit 0
    }
    else {
        Write-Error "NOT COMPLIANT: AlwaysInstallElevated not properly disabled."
        exit 2
    }
}
catch {
    Write-Error "Remediation failed: $($_.Exception.Message)"
    exit 3
}

