# VMware vSphere 8 CIS Benchmark Implementation

[![CI/CD Pipeline](https://github.com/uldyssian-sh/vmware-vsphere-8-cis-benchmark/actions/workflows/ci.yml/badge.svg)](https://github.com/uldyssian-sh/vmware-vsphere-8-cis-benchmark/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security](https://img.shields.io/badge/Security-CIS%20Benchmark-blue.svg)](https://www.cisecurity.org/)
[![VMware](https://img.shields.io/badge/VMware-vSphere%208-green.svg)](https://www.vmware.com/products/vsphere.html)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://docs.microsoft.com/en-us/powershell/)

Enterprise-ready PowerShell implementation for comprehensive CIS (Center for Internet Security) Benchmark compliance assessment of VMware vSphere 8 environments with automated progress tracking, sectioned controls, and robust reporting.

## 🎯 Key Features

- **🔍 Comprehensive Assessment** - Complete CIS Benchmark coverage across 8 security sections
- **📊 Real-Time Progress** - Visual progress bar with percentage completion tracking
- **🎛️ Minimal User Input** - Automated execution requiring only vCenter credentials
- **📈 Robust Reporting** - HTML and CSV reports with executive summaries
- **🔒 Read-Only Mode** - Zero modifications to vSphere environment
- **⚡ Enterprise Ready** - Optimized for production environments
- **🏗️ Sectioned Controls** - Organized by CIS security domains

## 🚀 Quick Start

### Prerequisites
- PowerShell 5.1+ 
- VMware PowerCLI 13.0+
- vSphere 8.0+ environment
- Read-only vCenter access

### Installation
```bash
git clone https://github.com/uldyssian-sh/vmware-vsphere-8-cis-benchmark.git
cd vmware-vsphere-8-cis-benchmark
```

### Basic Usage
```powershell
# Run audit (minimal input - will prompt for vCenter details)
.\scripts\Invoke-vSphere8CISAudit.ps1

# Run with parameters (no prompts)
.\scripts\Invoke-vSphere8CISAudit.ps1 -vCenterServer "vcenter.domain.com" -OutputPath "C:\Reports"
```

### Performance Benchmarks

| Environment Size | Hosts | VMs | Duration | Description |
|------------------|-------|-----|----------|-------------|
| **Small Lab** | 1-3 | 5-20 | 5-8 minutes | Home lab or small test environment |
| **Medium Enterprise** | 4-10 | 50-200 | 15-25 minutes | Typical enterprise branch office |
| **Large Enterprise** | 10+ | 200+ | 35-60 minutes | Large datacenter or multi-cluster environment |

## 📋 CIS Security Sections

The script implements comprehensive coverage across all CIS Benchmark security domains:

| Section | Category | Controls | Description |
|---------|----------|----------|-------------|
| **1** | Initial Setup & Patching | 15+ | ESXi host software, patching, and VIB management |
| **2** | Communication & Network Services | 12+ | Network services, firewall, NTP, and MOB security |
| **3** | Logging & Monitoring | 8+ | Persistent logging, remote syslog, and audit trails |
| **4** | Access Control & Authentication | 18+ | SSH, shell access, and authentication controls |
| **5** | Console & Shell Access | 10+ | DCUI timeout, lockdown mode, and console security |
| **6** | Storage Security | 6+ | Storage I/O control and datastore security |
| **7** | Network Security Policies | 12+ | vSwitch policies, VLAN configuration, and port groups |
| **8** | Virtual Machine Configuration | 25+ | VM hardware, devices, and security settings |

## 🏗️ Architecture

```
vmware-vsphere-8-cis-benchmark/
├── scripts/
│   └── Invoke-vSphere8CISAudit.ps1    # Main audit script (2.0.0)
├── reports/                            # Generated reports directory
├── docs/                              # Documentation
│   └── installation.md               # Installation guide
├── .github/
│   ├── workflows/                    # CI/CD pipelines
│   └── dependabot.yml              # Dependency management
└── README.md                        # This file
```

## 📊 Sample Output

```
================================================================================
VMware vSphere 8 CIS Benchmark Audit Tool
================================================================================
Enterprise Security Compliance Assessment
Read-Only Mode - No Configuration Changes

[INIT] PowerCLI ready
[CONN] Successfully connected to vcenter.domain.com
[START] Beginning CIS Benchmark audit...

[████████████████████░] 85% - Completed: CIS-7.2.1 - Ensure port groups are not configured to VLAN 0 or 4095
[██████████████████████] 100% - Completed: CIS-8.3.1 - Ensure unnecessary floppy devices are removed

================================================================================
VMware vSphere 8 CIS Benchmark Audit - FINAL SUMMARY
================================================================================

🎯 OVERALL COMPLIANCE: 87.4% - GOOD ⚠️

📊 CONTROL RESULTS:
  ✅ PASSED:  83/95
  ❌ FAILED:  8/95
  ⚠️  REVIEW:  3/95
  ℹ️  INFO:    1/95
  ⚡ ERRORS:  0/95

🚨 PRIORITY ACTIONS:
  🔴 CRITICAL: 8 security controls FAILED
     ⚡ Immediate remediation required!
  🟡 REVIEW: 3 controls need manual review

📄 REPORTS GENERATED:
  📊 HTML Report: ./reports/vSphere8-CIS-Audit-20241201-143022.html
  📈 CSV Data:    ./reports/vSphere8-CIS-Audit-20241201-143022.csv

🔧 TOP RECOMMENDATIONS:
  • CIS-2.3.1: Disable Managed Object Browser
  • CIS-4.2.1: Disable ESXi Shell service
  • CIS-5.2.1: Enable lockdown mode
  • CIS-7.1.1: Disable promiscuous mode, forged transmits, and MAC changes
  • CIS-8.2.1: Set RemoteDisplay.maxConnections to 1

================================================================================
Audit completed in 4.2 minutes
================================================================================
```

## 🔧 Configuration

### Environment Variables (Optional)
```powershell
# Set default vCenter server
$env:VCENTER_SERVER = "vcenter.domain.com"

# Set default output path
$env:CIS_REPORT_PATH = "C:\CISReports"
```

### Advanced Parameters
```powershell
# Custom output location
.\Invoke-vSphere8CISAudit.ps1 -OutputPath "\\server\share\reports"

# Pre-configured credentials (use securely)
$cred = Get-Credential
.\Invoke-vSphere8CISAudit.ps1 -vCenterServer "vcenter.domain.com" -Credential $cred
```

## 📖 Documentation

- **[Installation Guide](docs/installation.md)** - Complete setup instructions
- **[Security Policy](SECURITY.md)** - Security guidelines and reporting
- **[Contributing](CONTRIBUTING.md)** - How to contribute to the project

## 🔒 Security Features

This tool operates in **strict read-only mode** with enterprise security features:

- ✅ **Zero Configuration Changes** - No modifications to vSphere environment
- 🔐 **Secure Credential Handling** - PowerShell credential objects only
- 🔗 **Encrypted Connections** - TLS/SSL connections to vCenter
- 📝 **Comprehensive Audit Logging** - Detailed execution tracking
- 🚫 **No Sensitive Data Exposure** - Reports contain no credentials or secrets
- 🛡️ **Regular Security Scanning** - Automated vulnerability assessments

## 🎨 Report Features

### HTML Report Includes:
- Executive summary with compliance percentage
- Visual statistics dashboard
- Sectioned results by CIS domains
- Priority recommendations
- Detailed findings with remediation guidance

### CSV Export Provides:
- Machine-readable data for analysis
- Integration with SIEM/GRC tools
- Historical compliance tracking
- Custom reporting capabilities

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Contributors
- [uldyssian-sh](https://github.com/uldyssian-sh) - Project maintainer
- [dependabot[bot]](https://github.com/dependabot) - Automated dependency updates
- [actions-user](https://github.com/actions-user) - CI/CD automation

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🏷️ Version

Current version: 3.0.0 - Complete CIS Coverage

## 📞 Support

- 🐛 [Report Issues](https://github.com/uldyssian-sh/vmware-vsphere-8-cis-benchmark/issues)
- 💬 [Discussions](https://github.com/uldyssian-sh/vmware-vsphere-8-cis-benchmark/discussions)
- 📚 [Documentation](docs/)

## 📚 References

- [CIS VMware vSphere 8 Benchmark PDF](https://learn.cisecurity.org/l/799323/2025-03-20/4v7qc6?_gl=1*1mrhnug*_gcl_au*MTEwNDkxOTMzNi4xNzU4Mzk4ODAx) - Official CIS Benchmark Document
- [CIS VMware vSphere 8 Benchmark](https://www.cisecurity.org/benchmark/vmware)
- [VMware vSphere 8 Documentation](https://docs.vmware.com/en/VMware-vSphere/8.0/)
- [VMware Security Hardening Guides](https://core.vmware.com/security)
- [VMware PowerCLI Documentation](https://developer.vmware.com/powercli)

---

**⭐ If this project helps you secure your VMware environment, please give it a star!**