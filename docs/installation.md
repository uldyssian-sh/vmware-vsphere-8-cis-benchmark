# Installation Guide

## Prerequisites

### System Requirements
- **Operating System**: Windows 10/11, Windows Server 2016+, Linux, or macOS
- **PowerShell**: Version 5.1 or later (PowerShell 7+ recommended)
- **Memory**: Minimum 4GB RAM
- **Network**: Access to vCenter Server and ESXi hosts

### VMware Requirements
- **vSphere Version**: VMware vSphere 8.0 or later
- **vCenter Server**: Accessible via HTTPS
- **Permissions**: Read-only access to vSphere inventory
- **Network**: Connectivity to vCenter Server (port 443)

## Installation Steps

### 1. Install PowerShell (if needed)

**Windows:**
PowerShell 5.1 is included with Windows 10/11. For PowerShell 7+:
```powershell
winget install Microsoft.PowerShell
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install -y wget apt-transport-https software-properties-common
wget -q https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
sudo apt update
sudo apt install -y powershell
```

**macOS:**
```bash
brew install powershell
```

### 2. Install VMware PowerCLI

Open PowerShell as Administrator and run:

```powershell
# Install PowerCLI from PowerShell Gallery
Install-Module -Name VMware.PowerCLI -Scope AllUsers -Force

# Verify installation
Get-Module -ListAvailable VMware.PowerCLI
```

### 3. Configure PowerCLI

```powershell
# Set execution policy (if needed)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Configure PowerCLI settings
Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false
Set-PowerCLIConfiguration -ParticipateInCEIP $false -Confirm:$false
```

### 4. Download the Audit Script

**Option A: Git Clone**
```bash
git clone https://github.com/uldyssian-sh/vmware-vsphere-8-cis-benchmark.git
cd vmware-vsphere-8-cis-benchmark
```

**Option B: Download ZIP**
1. Go to the [GitHub repository](https://github.com/uldyssian-sh/vmware-vsphere-8-cis-benchmark)
2. Click "Code" → "Download ZIP"
3. Extract to desired location

### 5. Verify Installation

```powershell
# Navigate to script directory
cd vmware-vsphere-8-cis-benchmark/scripts

# Test script syntax
Get-Content .\Invoke-vSphere8CISAudit.ps1 | Out-Null

# Check PowerCLI modules
Get-Module -ListAvailable VMware.*
```

## Configuration

### vSphere Permissions

The audit script requires read-only permissions. Create a dedicated service account with:

**vCenter Server Permissions:**
- Global → Read-only
- Datastore → Browse datastore
- Network → Assign network
- Virtual machine → Configuration → All read-only permissions

**ESXi Host Permissions:**
- Host → Configuration → All read-only permissions
- Host → Local operations → All read-only permissions

### Network Configuration

Ensure the following network connectivity:
- **vCenter Server**: Port 443 (HTTPS)
- **ESXi Hosts**: Port 443 (HTTPS) - if direct host access needed
- **DNS Resolution**: Proper FQDN resolution for all components

## Troubleshooting

### Common Issues

**PowerCLI Module Not Found:**
```powershell
# Reinstall PowerCLI
Uninstall-Module VMware.PowerCLI -Force
Install-Module VMware.PowerCLI -Force
```

**Certificate Errors:**
```powershell
# Ignore certificate warnings (lab environments only)
Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false
```

**Execution Policy Errors:**
```powershell
# Set appropriate execution policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Connection Timeouts:**
```powershell
# Increase timeout values
Set-PowerCLIConfiguration -WebOperationTimeoutSeconds 300 -Confirm:$false
```

### Verification Commands

```powershell
# Check PowerShell version
$PSVersionTable.PSVersion

# Check PowerCLI version
Get-PowerCLIVersion

# Test vCenter connectivity
Test-NetConnection -ComputerName "vcenter.domain.com" -Port 443

# Verify script permissions
Get-ExecutionPolicy -List
```

## Next Steps

After installation:
1. Review [Configuration Guide](configuration.md)
2. Read [User Manual](user-manual.md)
3. Run your first audit: `.\Invoke-vSphere8CISAudit.ps1`

## Support

For installation issues:
- Check [FAQ](faq.md)
- Review [Troubleshooting Guide](troubleshooting.md)
- Create an [Issue](https://github.com/uldyssian-sh/vmware-vsphere-8-cis-benchmark/issues)