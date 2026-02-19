<#
.SYNOPSIS
    Remediates DISA STIG WN10-CC-000391 (Windows 10 STIG v3r5) by disabling
    Internet Explorer 11 as a standalone browser (redirect to Microsoft Edge IE mode).

.NOTES
    Author          : Sana Jafferi
    LinkedIn        : linkedin.com/in/sanajafferi/
    GitHub          : github.com/sfjsecurity
    Date Created    : 2026-02-18
    Last Modified   : 2026-02-18
    Version         : 1.0
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

$RegistryPath  = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main"
$ValueName     = "NotifyDisableIEOptions"
$RequiredValue = 0   # 0=Never, 1=Always, 2=Once per user

try {
    # Ensure key exists
    if (-not (Test-Path $RegistryPath)) {
        New-Item -Path $RegistryPath -Force | Out-Null
    }

    # Set policy value
    New-ItemProperty -Path $RegistryPath `
                     -Name $ValueName `
                     -PropertyType DWord `
                     -Value $RequiredValue `
                     -Force | Out-Null

    # Refresh policy (helps Tenable read the effective setting)
    & gpupdate /target:computer /force | Out-Null

    # Verify
    $current = (Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction Stop).$ValueName

    if ([int]$current -eq $RequiredValue) {
        Write-Output "COMPLIANT: WN10-CC-000391 configured (IE11 standalone disabled; NotifyDisableIEOptions = $RequiredValue)."
        Write-Output "NOTE: Reboot recommended before rescanning Tenable."
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
