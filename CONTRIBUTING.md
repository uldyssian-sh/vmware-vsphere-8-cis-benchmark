# Contributing to VMware vSphere 8 CIS Benchmark

Thank you for your interest in contributing to this project! We welcome contributions from the community to help improve VMware vSphere security assessments.

## 🤝 How to Contribute

### Types of Contributions

We welcome several types of contributions:

- 🐛 **Bug Reports**: Report issues or unexpected behavior
- ✨ **Feature Requests**: Suggest new CIS controls or improvements
- 📝 **Documentation**: Improve guides, examples, or code comments
- 🔧 **Code Contributions**: Fix bugs or implement new features
- 🧪 **Testing**: Help test the script in different environments
- 🔒 **Security**: Report security vulnerabilities (see [SECURITY.md](SECURITY.md))

## 🚀 Getting Started

### Prerequisites

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/vmware-vsphere-8-cis-benchmark.git
   cd vmware-vsphere-8-cis-benchmark
   ```
3. **Set up the development environment**:
   ```powershell
   # Install required modules
   Install-Module -Name VMware.PowerCLI -Force -Scope CurrentUser
   Install-Module -Name PSScriptAnalyzer -Force -Scope CurrentUser
   ```

### Development Setup

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Configure Git** (if not already done):
   ```bash
   git config user.name "Your Name"
   git config user.email "your.email@example.com"
   ```

3. **Enable commit signing** (recommended):
   ```bash
   git config commit.gpgsign true
   ```

## 📋 Development Guidelines

### Code Standards

#### PowerShell Best Practices
- Use **approved PowerShell verbs** (Get-, Set-, New-, etc.)
- Follow **PowerShell naming conventions** (PascalCase for functions)
- Include **comprehensive error handling**
- Add **parameter validation** where appropriate
- Use **Write-Verbose** for detailed logging

#### Example Function Structure
```powershell
function Test-CIS-X-Y-Z {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ParameterName
    )
    
    $section = "X. Section Name"
    $controlID = "CIS-X.Y.Z"
    $title = "Descriptive control title"
    
    try {
        # Implementation logic here
        
        if ($complianceCondition) {
            Add-CISResult -ControlID $controlID -Section $section -Title $title -Status "PASS" -Details "Compliance details"
        } else {
            Add-CISResult -ControlID $controlID -Section $section -Title $title -Status "FAIL" -Details "Non-compliance details" -Recommendation "Remediation steps"
        }
    }
    catch {
        Add-CISResult -ControlID $controlID -Section $section -Title $title -Status "ERROR" -Details $_.Exception.Message
    }
}
```

#### Code Quality Requirements
- **PSScriptAnalyzer**: All code must pass PSScriptAnalyzer checks
- **Error Handling**: Comprehensive try-catch blocks
- **Documentation**: Inline comments for complex logic
- **Testing**: Test in multiple vSphere environments when possible

### CIS Control Implementation

#### Adding New CIS Controls

1. **Research the CIS Benchmark**: Understand the specific requirement
2. **Identify the PowerCLI commands** needed for assessment
3. **Implement the check function** following the template above
4. **Add to the appropriate section** in the main script
5. **Update documentation** with the new control

#### Control Status Guidelines
- **PASS**: Configuration meets CIS recommendation
- **FAIL**: Configuration violates CIS recommendation (requires remediation)
- **REVIEW**: Manual review required or informational finding
- **ERROR**: Technical error during assessment
- **INFO**: Informational finding (not a compliance issue)

### Testing Guidelines

#### Local Testing
```powershell
# Syntax validation
$null = [System.Management.Automation.PSParser]::Tokenize((Get-Content "scripts/Invoke-vSphere8CISAudit.ps1" -Raw), [ref]$null)

# PSScriptAnalyzer
Invoke-ScriptAnalyzer -Path "scripts/Invoke-vSphere8CISAudit.ps1" -Severity Error,Warning

# Test in lab environment
.\scripts\Invoke-vSphere8CISAudit.ps1 -vCenterServer "lab-vcenter.domain.com"
```

#### Test Environments
- **VMware vSphere 8.0+**: Primary target platform
- **Different PowerShell versions**: 5.1 and 7.x
- **Various vSphere configurations**: Standalone hosts, clusters, distributed switches

## 📝 Pull Request Process

### Before Submitting

1. **Update your fork**:
   ```bash
   git fetch upstream
   git checkout main
   git merge upstream/main
   ```

2. **Rebase your feature branch**:
   ```bash
   git checkout feature/your-feature-name
   git rebase main
   ```

3. **Run quality checks**:
   ```powershell
   # PSScriptAnalyzer
   Invoke-ScriptAnalyzer -Path "scripts/Invoke-vSphere8CISAudit.ps1"
   
   # Test execution
   .\scripts\Invoke-vSphere8CISAudit.ps1 -vCenterServer "test-vcenter"
   ```

### Pull Request Template

When creating a pull request, include:

```markdown
## Description
Brief description of changes made.

## Type of Change
- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## CIS Controls Affected
- CIS-X.Y.Z: Description of control

## Testing
- [ ] Tested in lab environment
- [ ] PSScriptAnalyzer passed
- [ ] No breaking changes to existing functionality

## Checklist
- [ ] Code follows PowerShell best practices
- [ ] Self-review completed
- [ ] Documentation updated (if applicable)
- [ ] No sensitive information in code or commits
```

### Review Process

1. **Automated Checks**: CI/CD pipeline runs automatically
2. **Code Review**: Maintainer reviews code quality and functionality
3. **Testing**: Changes tested in multiple environments
4. **Approval**: Approved changes are merged to main branch

## 🐛 Bug Reports

### Before Reporting
1. **Search existing issues** to avoid duplicates
2. **Test with latest version** to ensure bug still exists
3. **Gather environment information**

### Bug Report Template
```markdown
**Describe the Bug**
Clear description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior:
1. Run script with parameters '...'
2. See error

**Expected Behavior**
What you expected to happen.

**Environment:**
- PowerShell Version: [e.g., 5.1, 7.2]
- PowerCLI Version: [e.g., 13.0.0]
- vSphere Version: [e.g., 8.0 Update 2]
- Operating System: [e.g., Windows 11, Ubuntu 22.04]

**Error Output**
```
Paste error messages here
```

**Additional Context**
Any other context about the problem.
```

## ✨ Feature Requests

### Feature Request Template
```markdown
**Is your feature request related to a problem?**
Clear description of the problem.

**Describe the solution you'd like**
Clear description of what you want to happen.

**CIS Control Reference**
If applicable, reference specific CIS controls.

**Additional Context**
Any other context or screenshots about the feature request.
```

## 📚 Documentation Contributions

### Documentation Standards
- **Clear and Concise**: Easy to understand for all skill levels
- **Accurate**: Technically correct and up-to-date
- **Complete**: Cover all necessary information
- **Examples**: Include practical examples where helpful

### Areas for Documentation
- Installation guides
- Configuration examples
- Troubleshooting guides
- CIS control explanations
- PowerCLI usage examples

## 🏷️ Commit Guidelines

### Commit Message Format
```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types
- **feat**: New feature
- **fix**: Bug fix
- **docs**: Documentation changes
- **style**: Code style changes (formatting, etc.)
- **refactor**: Code refactoring
- **test**: Adding or updating tests
- **chore**: Maintenance tasks

### Examples
```bash
feat(cis-controls): add CIS-2.4.1 SNMP configuration check

Implement check for SNMP community string configuration
according to CIS Benchmark section 2.4.1.

Closes #123

fix(reporting): resolve HTML report generation error

Fix issue where special characters in VM names caused
HTML report generation to fail.

Fixes #456
```

## 🎯 Project Roadmap

### Current Priorities
1. **Complete CIS Coverage**: Implement all CIS Benchmark controls
2. **Enhanced Reporting**: Improve report formats and content
3. **Performance Optimization**: Optimize for large environments
4. **Multi-Platform Support**: Expand PowerShell Core compatibility

### Future Enhancements
- **Automated Remediation**: Optional remediation capabilities
- **Custom Controls**: Support for organization-specific controls
- **API Integration**: REST API for programmatic access
- **Continuous Monitoring**: Scheduled assessment capabilities

## 🤔 Questions and Support

### Getting Help
- **GitHub Discussions**: For general questions and community support
- **GitHub Issues**: For bug reports and feature requests
- **Documentation**: Check existing documentation first

### Community Guidelines
- **Be Respectful**: Treat all community members with respect
- **Be Constructive**: Provide helpful and constructive feedback
- **Be Patient**: Maintainers are volunteers with limited time
- **Follow Code of Conduct**: Adhere to our community standards

## 📄 License

By contributing to this project, you agree that your contributions will be licensed under the MIT License.

## 🙏 Recognition

Contributors are recognized in:
- **README.md**: Listed in the contributors section
- **Release Notes**: Mentioned in relevant releases
- **GitHub Contributors**: Automatic GitHub recognition

---

**Thank you for contributing to VMware vSphere security! Your efforts help organizations worldwide improve their security posture.**# Updated 20251109_123841
