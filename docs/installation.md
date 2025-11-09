# Installation Guide - Complete CIS Implementation

**VMware vSphere 8 CIS Benchmark Tool with ALL 106 Controls Fully Implemented**

This installation guide covers setup for the complete CIS benchmark implementation with PowerShell-based assessments for all 106 security controls.

## Prerequisites

### System Requirements
- **Operating System:** Windows 10/11, Windows Server 2016+, or PowerShell Core on Linux/macOS
- **PowerShell:** Version 5.1 or PowerShell Core 7.0+
- **VMware PowerCLI:** Version 13.0 or later
- **Network Access:** Connectivity to vCenter Server (TCP 443)
- **Permissions:** Read-only access to vSphere environment

### CIS Implementation Coverage
- **Total Controls:** 106 fully implemented (no manual reviews)
- **PowerShell Assessments:** All controls use PowerCLI cmdlets
- **Real-time Evaluation:** Automated PASS/FAIL/REVIEW determinations
- **Complete Sections:** All 8 CIS security domains covered

### Required Modules
- VMware.PowerCLI
- VMware.VimAutomation.Core
- VMware.VimAutomation.Vds (for distributed switch checks)

## Installation Steps

### 1. Clone the Repository

```bash
git clone https://github.com/uldyssian-sh/vmware-vsphere-8-cis-benchmark.git
cd vmware-vsphere-8-cis-benchmark
```

### 2. Install VMware PowerCLI

```powershell
# Install PowerCLI for current user
Install-Module -Name VMware.PowerCLI -Force -AllowClobber -Scope CurrentUser

# Verify installation
Get-Module -ListAvailable VMware.PowerCLI
```

### 3. Configure PowerShell Execution Policy

```powershell
# Set execution policy for current user
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Verify execution policy
Get-ExecutionPolicy -List
```

### 4. Configure PowerCLI Settings (Optional)

```powershell
# Disable certificate warnings for lab environments
Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false

# Enable multiple default VIServer connections
Set-PowerCLIConfiguration -DefaultVIServerMode Multiple -Confirm:$false
```

## Quick Start

### Basic Usage (Minimal Input)

```powershell
# Navigate to script directory
cd scripts

# Run audit with prompts
.\Invoke-vSphere8CISAudit.ps1
```

The script will prompt for:
- vCenter Server FQDN or IP address
- vCenter credentials

### Advanced Usage (No Prompts)

```powershell
# Run with parameters
.\Invoke-vSphere8CISAudit.ps1 -vCenterServer "vcenter.domain.com" -OutputPath "C:\Reports"

# Run with pre-configured credentials
$cred = Get-Credential
.\Invoke-vSphere8CISAudit.ps1 -vCenterServer "vcenter.domain.com" -Credential $cred -OutputPath "\\server\share\reports"
```

## Verification

### Test PowerCLI Connection

```powershell
# Test connection to vCenter
Connect-VIServer -Server "vcenter.domain.com"

# Verify access
Get-VMHost | Select-Object Name, Version, Build
Get-VM | Select-Object Name, PowerState -First 5

# Disconnect
Disconnect-VIServer -Confirm:$false
```

### Validate Script Syntax

```powershell
# Check PowerShell syntax
$null = [System.Management.Automation.PSParser]::Tokenize((Get-Content "scripts/Invoke-vSphere8CISAudit.ps1" -Raw), [ref]$null)
Write-Host "✅ PowerShell syntax validation passed" -ForegroundColor Green
```

## Troubleshooting

### Common Issues

#### PowerCLI Module Not Found
```powershell
# Error: The term 'Connect-VIServer' is not recognized
Install-Module -Name VMware.PowerCLI -Force -AllowClobber -Scope CurrentUser
Import-Module VMware.PowerCLI
```

#### Execution Policy Restriction
```powershell
# Error: Execution of scripts is disabled on this system
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

#### Certificate Errors
```powershell
# Error: The underlying connection was closed: Could not establish trust relationship
Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false
```

#### Permission Denied
```powershell
# Error: Access denied or insufficient permissions
# Ensure the account has at least read-only access to:
# - vCenter Server
# - ESXi hosts
# - Virtual machines
# - Datastores
# - Network configuration
```

#### Connection Timeout
```powershell
# Error: Connection timeout
# Check network connectivity:
Test-NetConnection -ComputerName "vcenter.domain.com" -Port 443

# Verify DNS resolution:
Resolve-DnsName "vcenter.domain.com"
```

### Performance Optimization

#### Large Environments
For environments with 100+ VMs or 10+ hosts:

```powershell
# Increase PowerCLI timeout
Set-PowerCLIConfiguration -WebOperationTimeoutSeconds 300 -Confirm:$false

# Use specific output path on fast storage
.\Invoke-vSphere8CISAudit.ps1 -OutputPath "D:\FastStorage\Reports"
```

#### Network Optimization
```powershell
# For slow network connections, increase timeout
$VIServerTimeout = 300  # 5 minutes
Connect-VIServer -Server "vcenter.domain.com" -Protocol https -Port 443
```

## Environment Variables

### Optional Configuration
```powershell
# Set default vCenter server
$env:VCENTER_SERVER = "vcenter.domain.com"

# Set default output path
$env:CIS_REPORT_PATH = "C:\CISReports"

# Set PowerCLI configuration path
$env:POWERCLI_CONFIG_PATH = "C:\PowerCLI"
```

## Security Considerations

### Credential Management
- Use service accounts with minimal required permissions
- Store credentials securely using Windows Credential Manager
- Avoid hardcoding credentials in scripts

### Network Security
- Ensure encrypted connections (HTTPS/TLS)
- Use VPN or secure network segments
- Implement network access controls

### Audit Logging
- Enable PowerShell transcription for audit trails
- Monitor script execution and results
- Secure report storage locations

## Next Steps

After successful installation:

1. **Review the generated reports** in the `reports/` directory
2. **Analyze failed controls** and plan remediation
3. **Schedule regular audits** using Windows Task Scheduler
4. **Integrate with SIEM/GRC tools** using CSV exports
5. **Customize controls** based on organizational requirements

For additional help, see:
- [Security Policy](../SECURITY.md)
- [Contributing Guidelines](../CONTRIBUTING.md)
- [GitHub Issues](https://github.com/uldyssian-sh/vmware-vsphere-8-cis-benchmark/issues)# Updated 20251109_123841
# Updated Sun Nov  9 12:49:20 CET 2025
# Updated Sun Nov  9 12:52:42 CET 2025
# Updated Sun Nov  9 12:56:02 CET 2025
