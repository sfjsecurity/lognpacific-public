<#
.SYNOPSIS
    Remediates DISA STIG WN10-AU-000500 by ensuring the Application event log maximum size
    is configured to 32768 KB (32 MB) or greater.

.NOTES
    Author          : Sana Jafferi
    LinkedIn        : linkedin.com/in/sanajafferi/
    GitHub          : github.com/sfjsecurity
    Date Created    : 2026-02-18
    Last Modified   : 2026-02-18
    Version         : 1.0
    STIG-ID         : WN10-AU-000500

.TESTED ON
    Systems Tested  : Windows 10 Enterprise 22H2
    PowerShell Ver. : 5.1+

.USAGE
    Run in an elevated PowerShell session:
    PS C:\> .\WN10-AU-000500.ps1
#>

# --- Safety: require admin ---
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

$RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
$ValueName    = "MaxSize"
$RequiredSize = 32768  # KB (0x00008000)

try {
    # Ensure key exists
    if (-not (Test-Path -Path $RegistryPath)) {
        New-Item -Path $RegistryPath -Force | Out-Null
    }

    # Read current value (if present)
    $current = $null
    try {
        $current = (Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction Stop).$ValueName
    } catch {
        $current = $null
    }

    # If missing, create with correct type
    if ($null -eq $current) {
        New-ItemProperty -Path $RegistryPath -Name $ValueName -PropertyType DWord -Value $RequiredSize -Force | Out-Null
        Write-Output "Created $ValueName (DWORD) = $RequiredSize at $RegistryPath"
    }
    # If present but noncompliant, set to required
    elseif ([int]$current -lt $RequiredSize) {
        Set-ItemProperty -Path $RegistryPath -Name $ValueName -Value $RequiredSize -Force
        Write-Output "Updated $ValueName from $current to $RequiredSize at $RegistryPath"
    }
    else {
        Write-Output "Already compliant: $ValueName is $current (>= $RequiredSize) at $RegistryPath"
    }

    # Verify
    $verify = (Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction Stop).$ValueName
    if ([int]$verify -ge $RequiredSize) {
        Write-Output "COMPLIANT: WN10-AU-000500 satisfied. $ValueName = $verify KB"
        exit 0
    } else {
        Write-Error "NOT COMPLIANT: Expected >= $RequiredSize but found $verify"
        exit 2
    }
}
catch {
    Write-Error "Remediation failed: $($_.Exception.Message)"
    exit 3
}
