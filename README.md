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

- [WN10-AU-000500](STIG/WN10-AU-000500.ps1) – Application Event Log Maximum Size
- [WN10-AU-000005](STIG/WN10-AU-000005.ps1) – Audit Credential Validation (Failure)


(Additional STIG implementations will be added as completed.)

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
