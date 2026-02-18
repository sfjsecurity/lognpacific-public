# Vulnerability Remediations

## Overview

This repository contains remediation scripts and documentation for addressing security findings identified through vulnerability and compliance scanning.

The focus of this project is to demonstrate structured remediation methodology, including:

- Baseline vulnerability assessment
- Identification of security findings
- Manual remediation validation
- Automated remediation using PowerShell
- Rescan verification to confirm compliance

---

## STIG Implementations

The following DISA Windows 10 STIG controls have been implemented and automated:

- [WN10-AU-000500](STIG/WN10-AU-000500.ps1) – Application Event Log Size (≥ 32768 KB)
- [WN10-AU-000005](STIG/WN10-AU-000005.ps1) – Audit Credential Validation (Failure)
- [WN10-CC-000205](STIG/WN10-CC-000205.ps1) – Windows Telemetry Not Set to Full
- [WN10-00-000031](STIG/WN10-00-000031.ps1) – BitLocker Pre-Boot Authentication (TPM + PIN)
- [WN10-CC-000370](STIG/WN10-CC-000370.ps1) – Disable Convenience PIN Sign-In
- [WN10-CC-000391](STIG/WN10-CC-000391.ps1) – Prevent Storage of Network Credentials
- [WN10-CC-000310](STIG/WN10-CC-000310.ps1) – Disable Always Install with Elevated Privileges
- [WN10-CC-000052](STIG/WN10-CC-000052.ps1) – Enable Windows Defender Real-Time Protection
- [WN10-CC-000295](STIG/WN10-CC-000295.ps1) – Limit Blank Password Usage
- [WN10-CC-000326](STIG/WN10-CC-000326.ps1) – Disable Solicited Remote Assistance
  
---

## Lab Environment

- Windows 10 Enterprise 22H2 (x64 Gen2 VM)
- Tenable Cloud (Compliance & Vulnerability Scanning)
- DISA Windows 10 STIG Baseline
- PowerShell 5.1+

---

## Methodology

Each remediation follows this lifecycle:

1. Perform initial baseline scan
2. Identify failed control
3. Research remediation requirements
4. Implement manual fix
5. Validate via rescan
6. Revert to confirm failure state
7. Automate remediation with PowerShell
8. Perform final validation scan

---


> ⚠️ **Disclaimer:**  
> All activities were performed in a controlled lab environment for educational purposes only.  
> Scripts should not be deployed in production environments without proper testing and change management.
