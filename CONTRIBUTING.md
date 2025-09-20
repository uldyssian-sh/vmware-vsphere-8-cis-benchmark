# Contributing to VMware vSphere 8 CIS Benchmark

Thank you for your interest in contributing to this project! This document provides guidelines for contributing to the VMware vSphere 8 CIS Benchmark implementation.

## Code of Conduct

This project adheres to a code of conduct. By participating, you are expected to uphold this code.

## How to Contribute

### Reporting Issues

Before creating an issue, please:
1. Check existing issues to avoid duplicates
2. Use the issue templates provided
3. Provide detailed information about the problem
4. Include environment details (PowerShell version, PowerCLI version, vSphere version)

### Suggesting Enhancements

Enhancement suggestions are welcome! Please:
1. Use the feature request template
2. Explain the use case and benefits
3. Consider backward compatibility
4. Provide implementation details if possible

### Contributing Code

#### Prerequisites

- PowerShell 5.1 or later
- VMware PowerCLI 13.0+
- Git knowledge
- Understanding of CIS Benchmark controls

#### Development Process

1. **Fork the repository**
   ```bash
   git clone https://github.com/uldyssian-sh/vmware-vsphere-8-cis-benchmark.git
   cd vmware-vsphere-8-cis-benchmark
   ```

2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**
   - Follow PowerShell best practices
   - Add appropriate error handling
   - Include progress tracking for new controls
   - Update documentation as needed

4. **Test your changes**
   ```powershell
   # Run PSScriptAnalyzer
   Invoke-ScriptAnalyzer -Path "./scripts/" -Recurse
   
   # Test script syntax
   Get-ChildItem -Path "./scripts/" -Filter "*.ps1" | ForEach-Object {
       [System.Management.Automation.PSParser]::Tokenize((Get-Content $_.FullName -Raw), [ref]$null)
   }
   ```

5. **Commit your changes**
   ```bash
   git add .
   git commit -m "feat: add new CIS control implementation"
   ```

6. **Push and create pull request**
   ```bash
   git push origin feature/your-feature-name
   ```

#### Coding Standards

**PowerShell Guidelines:**
- Use approved verbs for function names
- Follow PascalCase for functions and variables
- Include comprehensive help documentation
- Use proper error handling with try/catch blocks
- Implement progress tracking for long-running operations
- Ensure read-only operations only

**Script Structure:**
- Place new CIS controls in appropriate sections
- Update `$script:TotalControls` count when adding controls
- Follow existing naming convention: `Test-CIS-X-Y-Z`
- Include proper categorization

**Documentation:**
- Update README.md for significant changes
- Add inline comments for complex logic
- Update help documentation
- Include examples where appropriate

#### Adding New CIS Controls

When adding new CIS controls:

1. **Function Template:**
   ```powershell
   function Test-CIS-X-Y-Z {
       $controlID = "CIS-X.Y.Z"
       $category = "Category Name"
       $title = "Control description"
       
       try {
           # Implementation logic here
           # Always read-only operations
           
           if ($complianceCondition) {
               Add-CISResult -ControlID $controlID -Category $category -Title $title -Status "PASS" -Details "Success details"
           } else {
               Add-CISResult -ControlID $controlID -Category $category -Title $title -Status "FAIL" -Details "Failure details" -Recommendation "Remediation steps"
           }
       }
       catch {
           Add-CISResult -ControlID $controlID -Category $category -Title $title -Status "ERROR" -Details $_.Exception.Message
       }
   }
   ```

2. **Add function call to Main execution section**
3. **Update total controls count**
4. **Test thoroughly**

### Pull Request Process

1. **PR Requirements:**
   - Clear description of changes
   - Reference related issues
   - Include test results
   - Update documentation if needed

2. **Review Process:**
   - All PRs require review
   - CI/CD checks must pass
   - Security scan must pass
   - Documentation must be updated

3. **Merge Requirements:**
   - All conversations resolved
   - CI/CD pipeline passes
   - Approved by maintainer
   - No merge conflicts

## Development Environment

### Required Tools
- PowerShell 5.1+
- VMware PowerCLI 13.0+
- Git
- Code editor (VS Code recommended)

### Recommended Extensions (VS Code)
- PowerShell
- GitLens
- Markdown All in One
- YAML

### Testing Environment
- Access to VMware vSphere 8 environment
- Appropriate permissions for read-only operations
- Test vCenter server (recommended)

## Release Process

Releases follow semantic versioning (SemVer):
- **MAJOR**: Breaking changes
- **MINOR**: New features, backward compatible
- **PATCH**: Bug fixes, backward compatible

## Questions?

If you have questions about contributing:
1. Check existing documentation
2. Search closed issues
3. Create a new issue with the question label
4. Contact maintainers

## Recognition

Contributors will be recognized in:
- CONTRIBUTORS.md file
- Release notes
- Project documentation

Thank you for contributing to making VMware environments more secure!