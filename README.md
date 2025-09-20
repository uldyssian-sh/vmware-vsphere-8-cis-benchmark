# VMware vSphere 8 CIS Benchmark Implementation

[![CI/CD Pipeline](https://github.com/uldyssian-sh/vmware-vsphere-8-cis-benchmark/actions/workflows/ci.yml/badge.svg)](https://github.com/uldyssian-sh/vmware-vsphere-8-cis-benchmark/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security](https://img.shields.io/badge/Security-CIS%20Benchmark-blue.svg)](https://www.cisecurity.org/)
[![VMware](https://img.shields.io/badge/VMware-vSphere%208-green.svg)](https://www.vmware.com/products/vsphere.html)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://docs.microsoft.com/en-us/powershell/)

Enterprise-ready PowerShell implementation for auditing VMware vSphere 8 environments against CIS (Center for Internet Security) Benchmark controls with automated reporting and comprehensive security assessment.

## 🎯 Key Features

- **🔍 Comprehensive Audit** - Complete CIS Benchmark coverage for vSphere 8
- **📊 Progress Tracking** - Real-time progress indicators during execution
- **📈 Detailed Reporting** - HTML and CSV reports with executive summaries
- **🔒 Read-Only Mode** - No modifications to vSphere environment
- **⚡ Minimal Input** - Automated execution with minimal user interaction
- **🏢 Enterprise Ready** - Designed for production environments

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
# Run audit (will prompt for vCenter details)
.\scripts\Invoke-vSphere8CISAudit.ps1

# Run with parameters
.\scripts\Invoke-vSphere8CISAudit.ps1 -vCenterServer "vcenter.domain.com" -OutputPath "C:\Reports"
```

## 📋 CIS Controls Coverage

The script implements comprehensive coverage across all CIS Benchmark sections:

| Section | Category | Controls | Status |
|---------|----------|----------|--------|
| 1 | Initial Setup and Patching | 15+ | ✅ Implemented |
| 2 | Logging and Monitoring | 12+ | ✅ Implemented |
| 3 | Network Configuration | 18+ | ✅ Implemented |
| 4 | Access Control | 20+ | ✅ Implemented |
| 5 | System Configuration | 25+ | ✅ Implemented |
| 6 | Virtual Machine Configuration | 30+ | ✅ Implemented |

## 🏗️ Architecture

```
vmware-vsphere-8-cis-benchmark/
├── scripts/
│   └── Invoke-vSphere8CISAudit.ps1    # Main audit script
├── reports/                            # Generated reports
├── docs/                              # Documentation
│   ├── installation.md               # Installation guide
│   ├── configuration.md              # Configuration guide
│   └── user-manual.md               # User manual
├── .github/
│   ├── workflows/                    # CI/CD pipelines
│   └── dependabot.yml              # Dependency management
└── README.md                        # This file
```

## 📊 Sample Output

```
VMware vSphere 8 CIS Benchmark Audit Tool
=========================================
Enterprise Security Compliance Assessment

[25%] Completed: CIS-1.1.1 - Ensure ESXi host patches are up-to-date
[50%] Completed: CIS-2.1.1 - Ensure ESXi host logging is configured properly
[75%] Completed: CIS-4.1.1 - Ensure default administrator account is secured
[100%] Completed: CIS-6.1.1 - Ensure VM hardware version is current

================================================================================
VMware vSphere 8 CIS Benchmark Audit - FINAL SUMMARY
================================================================================

OVERALL COMPLIANCE: 85.5% - GOOD

CONTROL RESULTS:
  ✓ PASSED:  17/20
  ✗ FAILED:  2/20
  ⚠ REVIEW:  1/20
  ⚡ ERRORS:  0/20

PRIORITY ACTIONS:
  🔴 CRITICAL: 2 security controls failed
     Immediate remediation required!

REPORTS GENERATED:
  📄 HTML Report: ./reports/vSphere8-CIS-Audit-20241201-143022.html
  📊 CSV Data:    ./reports/vSphere8-CIS-Audit-20241201-143022.csv
```

## 🔧 Configuration

### Environment Variables
```powershell
# Optional: Set default vCenter server
$env:VCENTER_SERVER = "vcenter.domain.com"

# Optional: Set default output path
$env:CIS_REPORT_PATH = "C:\CISReports"
```

### Advanced Parameters
```powershell
# Custom output location
.\Invoke-vSphere8CISAudit.ps1 -OutputPath "\\server\share\reports"

# Pre-configured credentials (use carefully)
$cred = Get-Credential
.\Invoke-vSphere8CISAudit.ps1 -vCenterServer "vcenter.domain.com" -Credential $cred
```

## 📖 Documentation

- **[Installation Guide](docs/installation.md)** - Complete setup instructions
- **[Configuration Guide](docs/configuration.md)** - Advanced configuration options
- **[User Manual](docs/user-manual.md)** - Detailed usage guide
- **[Security Policy](SECURITY.md)** - Security guidelines and reporting
- **[Contributing](CONTRIBUTING.md)** - How to contribute to the project

## 🔒 Security

This tool operates in **read-only mode** and makes no changes to your vSphere environment. All security best practices are implemented:

- Secure credential handling
- Encrypted connections only
- Comprehensive audit logging
- No sensitive data in reports
- Regular security scanning

For security concerns, see [SECURITY.md](SECURITY.md).

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Contributors
- [uldyssian-sh](https://github.com/uldyssian-sh) - Project maintainer
- [dependabot[bot]](https://github.com/dependabot) - Automated dependency updates
- [actions-user](https://github.com/actions-user) - CI/CD automation

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🏷️ Version

Current version: 1.0.0

## 📞 Support

- 🐛 [Report Issues](https://github.com/uldyssian-sh/vmware-vsphere-8-cis-benchmark/issues)
- 💬 [Discussions](https://github.com/uldyssian-sh/vmware-vsphere-8-cis-benchmark/discussions)
- 📚 [Documentation](docs/)
- 🔍 [Wiki](https://github.com/uldyssian-sh/vmware-vsphere-8-cis-benchmark/wiki)

## 📚 References

- [CIS VMware vSphere 8 Benchmark](https://www.cisecurity.org/benchmark/vmware)
- [VMware vSphere 8 Documentation](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-esxi-vcenter-server-80-installation-setup-guide.pdf)
- [VMware Security Hardening Guides](https://core.vmware.com/security)
- [VMware PowerCLI Documentation](https://developer.vmware.com/powercli)

---

**⭐ If this project helps you, please give it a star!**