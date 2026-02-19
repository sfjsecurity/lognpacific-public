<#
.SYNOPSIS
    Remediates DISA STIG WN10-CC-000052 (Windows 10 STIG v3r5)
    by configuring ECC Curve Order to prioritize NistP384 and NistP256.

.NOTES
    Author          : Sana Jafferi
    LinkedIn        : linkedin.com/in/sanajafferi/
    GitHub          : github.com/sfjsecurity
    Date Created    : 2026-02-18
    Last Modified   : 2026-02-19
    Version         : 1.0
    STIG-ID         : WN10-CC-000052

.TESTED ON
    Systems Tested  : Windows 10 Enterprise 22H2
    PowerShell Ver. : 5.1+

.USAGE
    Run in an elevated PowerShell session:
    PS C:\> .\WN10-CC-000052.ps1
#>

# --- Safety: require admin ---
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

$RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002"
$ValueName    = "EccCurves"
$Required     = @("NistP384","NistP256")

try {
    # Ensure path exists
    if (-not (Test-Path $RegistryPath)) {
        New-Item -Path $RegistryPath -Force | Out-Null
    }

    # Set ECC curve order (REG_MULTI_SZ)
    New-ItemProperty -Path $RegistryPath `
                     -Name $ValueName `
                     -PropertyType MultiString `
                     -Value $Required `
                     -Force | Out-Null

    # Verify
    $current = (Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction Stop).$ValueName

    if ($current[0] -eq "NistP384" -and $current[1] -eq "NistP256") {
        Write-Output "COMPLIANT: WN10-CC-000052 configured (ECC Curve Order set correctly)."
        Write-Output "NOTE: Reboot recommended before rescanning Tenable."
        exit 0
    } else {
        Write-Error "NOT COMPLIANT: ECC Curve Order incorrect."
        exit 2
    }
}
catch {
    Write-Error "Remediation failed: $($_.Exception.Message)"
    exit 3
}
