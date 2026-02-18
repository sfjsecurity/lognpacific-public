<#
.SYNOPSIS
    Remediates DISA STIG WN10-00-000031 by configuring BitLocker policy to require
    a BitLocker PIN for pre-boot authentication (TPM+PIN).

.NOTES
    Author          : Sana Jafferi
    LinkedIn        : linkedin.com/in/sanajafferi/
    GitHub          : github.com/sfjsecurity
    Date Created    : 2026-02-18
    Last Modified   : 2026-02-18
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-00-000031

.TESTED ON
    Systems Tested  : Windows 10 Enterprise 22H2
    PowerShell Ver. : 5.1+

.USAGE
    Run in an elevated PowerShell session:
    PS C:\> .\WN10-00-000031.ps1
#>

# --- Safety: require admin ---
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"

# Per STIG checks for WN10-00-000031:
# UseAdvancedStartup = 1
# AND (UseTPMPIN = 1 OR UseTPMKeyPIN = 1)  [non-network-unlock scenario]
$Required = @{
    "UseAdvancedStartup" = 1
    "UseTPMPIN"          = 1
    "UseTPMKeyPIN"       = 1
}

try {
    # Ensure policy key exists
    if (-not (Test-Path $RegPath)) {
        New-Item -Path $RegPath -Force | Out-Null
    }

    # Set required DWORDs
    foreach ($kvp in $Required.GetEnumerator()) {
        New-ItemProperty -Path $RegPath -Name $kvp.Key -PropertyType DWord -Value $kvp.Value -Force | Out-Null
    }

    # Verify registry values
    $props = Get-ItemProperty -Path $RegPath -ErrorAction Stop

    $ok = $true
    foreach ($kvp in $Required.GetEnumerator()) {
        $current = $props.($kvp.Key)
        if ($null -eq $current -or [int]$current -ne [int]$kvp.Value) {
            $ok = $false
            Write-Error "NOT COMPLIANT: $($kvp.Key) is '$current' (expected '$($kvp.Value)')."
        }
    }

    if ($ok) {
        Write-Output "Policy values set: WN10-00-000031 registry requirements satisfied under $RegPath."
    } else {
        exit 2
    }

    # Helpful visibility: show BitLocker status (Tenable may also require TPM+PIN protector actually configured)
    Write-Output "`nCurrent BitLocker status for C: (informational):"
    & manage-bde -status C: 2>$null | Out-Host

    Write-Output "`nNOTE: If Tenable still fails, ensure the OS drive (C:) has a TPM+PIN protector and BitLocker is enabled."
    Write-Output "You may need: gpupdate /force, reboot, then rescan."
    exit 0
}
catch {
    Write-Error "Remediation failed: $($_.Exception.Message)"
    exit 3
}

