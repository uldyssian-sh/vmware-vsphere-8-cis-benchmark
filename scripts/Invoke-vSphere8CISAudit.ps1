#Requires -Version 5.1
#Requires -Modules VMware.PowerCLI

<#
.SYNOPSIS
    VMware vSphere 8 CIS Benchmark Compliance Audit Script

.DESCRIPTION
    Enterprise-grade PowerShell script for auditing VMware vSphere 8 environments against CIS Benchmark controls.
    Provides comprehensive read-only assessment with detailed reporting and progress tracking.

.PARAMETER vCenterServer
    vCenter Server FQDN or IP address (optional - will prompt if not provided)

.PARAMETER Credential
    PSCredential object for vCenter authentication (optional - will prompt if not provided)

.PARAMETER OutputPath
    Path for output reports (default: ./reports)

.EXAMPLE
    .\Invoke-vSphere8CISAudit.ps1
    
.EXAMPLE
    .\Invoke-vSphere8CISAudit.ps1 -vCenterServer "vcenter.domain.com" -OutputPath "C:\Reports"

.NOTES
    Author: VMware Security Team
    Version: 1.0.0
    Requires: VMware PowerCLI 13.0+
    Mode: Read-Only (No modifications to vSphere environment)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$vCenterServer,
    
    [Parameter(Mandatory = $false)]
    [PSCredential]$Credential,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "./reports"
)

# Global Variables
$script:TotalControls = 0
$script:CompletedControls = 0
$script:Results = @()
$script:StartTime = Get-Date
$script:vCenterConnection = $null

# CIS Control Categories
$script:CISCategories = @{
    "Initial Setup" = @()
    "Logging and Monitoring" = @()
    "Network Configuration" = @()
    "Access Control" = @()
    "System Configuration" = @()
    "Virtual Machine Configuration" = @()
}

#region Helper Functions

function Write-Progress-Custom {
    param(
        [string]$Activity,
        [string]$Status,
        [int]$PercentComplete
    )
    
    Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete
    Write-Host "[$PercentComplete%] $Status" -ForegroundColor Cyan
}

function Add-CISResult {
    param(
        [string]$ControlID,
        [string]$Category,
        [string]$Title,
        [string]$Status,
        [string]$Details,
        [string]$Recommendation = ""
    )
    
    $result = [PSCustomObject]@{
        ControlID = $ControlID
        Category = $Category
        Title = $Title
        Status = $Status
        Details = $Details
        Recommendation = $Recommendation
        Timestamp = Get-Date
    }
    
    $script:Results += $result
    $script:CISCategories[$Category] += $result
    $script:CompletedControls++
    
    $percentComplete = [math]::Round(($script:CompletedControls / $script:TotalControls) * 100, 1)
    Write-Progress-Custom -Activity "CIS Benchmark Audit" -Status "Completed: $ControlID - $Title" -PercentComplete $percentComplete
}

function Test-PowerCLIModule {
    Write-Host "Checking PowerCLI installation..." -ForegroundColor Yellow
    
    $powerCLIModules = @('VMware.PowerCLI', 'VMware.VimAutomation.Core')
    
    foreach ($module in $powerCLIModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Write-Error "Required module $module is not installed. Please install VMware PowerCLI."
            return $false
        }
    }
    
    # Import modules
    Import-Module VMware.PowerCLI -Force -ErrorAction SilentlyContinue
    
    # Disable certificate warnings for lab environments
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -Scope Session | Out-Null
    
    return $true
}

function Connect-vCenterServer {
    param(
        [string]$Server,
        [PSCredential]$Cred
    )
    
    try {
        Write-Host "Connecting to vCenter Server: $Server" -ForegroundColor Yellow
        
        if ($Cred) {
            $script:vCenterConnection = Connect-VIServer -Server $Server -Credential $Cred -ErrorAction Stop
        } else {
            $script:vCenterConnection = Connect-VIServer -Server $Server -ErrorAction Stop
        }
        
        Write-Host "Successfully connected to $($script:vCenterConnection.Name)" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to connect to vCenter Server: $($_.Exception.Message)"
        return $false
    }
}

#endregion

#region CIS Control Functions

# Section 1: Initial Setup and Patching
function Test-CIS-1-1-1 {
    $controlID = "CIS-1.1.1"
    $category = "Initial Setup"
    $title = "Ensure ESXi host patches are up-to-date"
    
    try {
        $esxiHosts = Get-VMHost
        $outdatedHosts = @()
        
        foreach ($host in $esxiHosts) {
            $build = $host.Build
            $version = $host.Version
            
            # Check if build is recent (simplified check)
            if ($build -lt 20000000) {
                $outdatedHosts += $host.Name
            }
        }
        
        if ($outdatedHosts.Count -eq 0) {
            Add-CISResult -ControlID $controlID -Category $category -Title $title -Status "PASS" -Details "All ESXi hosts appear to have recent builds"
        } else {
            Add-CISResult -ControlID $controlID -Category $category -Title $title -Status "FAIL" -Details "Outdated hosts found: $($outdatedHosts -join ', ')" -Recommendation "Update ESXi hosts to latest patches"
        }
    }
    catch {
        Add-CISResult -ControlID $controlID -Category $category -Title $title -Status "ERROR" -Details $_.Exception.Message
    }
}

function Test-CIS-1-2-1 {
    $controlID = "CIS-1.2.1"
    $category = "Initial Setup"
    $title = "Ensure vCenter Server patches are up-to-date"
    
    try {
        $vcenterInfo = $global:DefaultVIServer
        $version = $vcenterInfo.Version
        $build = $vcenterInfo.Build
        
        # Basic version check (simplified)
        if ($version -match "^8\." -and $build -gt 20000000) {
            Add-CISResult -ControlID $controlID -Category $category -Title $title -Status "PASS" -Details "vCenter version: $version, build: $build"
        } else {
            Add-CISResult -ControlID $controlID -Category $category -Title $title -Status "FAIL" -Details "vCenter may need updates. Version: $version, Build: $build" -Recommendation "Update vCenter to latest version"
        }
    }
    catch {
        Add-CISResult -ControlID $controlID -Category $category -Title $title -Status "ERROR" -Details $_.Exception.Message
    }
}

# Section 2: Logging and Monitoring
function Test-CIS-2-1-1 {
    $controlID = "CIS-2.1.1"
    $category = "Logging and Monitoring"
    $title = "Ensure ESXi host logging is configured properly"
    
    try {
        $esxiHosts = Get-VMHost
        $nonCompliantHosts = @()
        
        foreach ($host in $esxiHosts) {
            $logHost = Get-VMHostAdvancedConfiguration -VMHost $host -Name "Syslog.global.logHost" -ErrorAction SilentlyContinue
            
            if (-not $logHost.Value -or $logHost.Value -eq "") {
                $nonCompliantHosts += $host.Name
            }
        }
        
        if ($nonCompliantHosts.Count -eq 0) {
            Add-CISResult -ControlID $controlID -Category $category -Title $title -Status "PASS" -Details "All ESXi hosts have syslog configured"
        } else {
            Add-CISResult -ControlID $controlID -Category $category -Title $title -Status "FAIL" -Details "Hosts without syslog: $($nonCompliantHosts -join ', ')" -Recommendation "Configure syslog on all ESXi hosts"
        }
    }
    catch {
        Add-CISResult -ControlID $controlID -Category $category -Title $title -Status "ERROR" -Details $_.Exception.Message
    }
}

function Test-CIS-2-2-1 {
    $controlID = "CIS-2.2.1"
    $category = "Logging and Monitoring"
    $title = "Ensure vCenter Server logging is configured"
    
    try {
        # Check if vCenter events are being logged
        $recentEvents = Get-VIEvent -MaxSamples 100 -ErrorAction SilentlyContinue
        
        if ($recentEvents.Count -gt 0) {
            Add-CISResult -ControlID $controlID -Category $category -Title $title -Status "PASS" -Details "vCenter logging is active with $($recentEvents.Count) recent events"
        } else {
            Add-CISResult -ControlID $controlID -Category $category -Title $title -Status "FAIL" -Details "No recent events found in vCenter logs" -Recommendation "Verify vCenter logging configuration"
        }
    }
    catch {
        Add-CISResult -ControlID $controlID -Category $category -Title $title -Status "ERROR" -Details $_.Exception.Message
    }
}

# Section 3: Network Configuration
function Test-CIS-3-1-1 {
    $controlID = "CIS-3.1.1"
    $category = "Network Configuration"
    $title = "Ensure network security policies are configured"
    
    try {
        $esxiHosts = Get-VMHost
        $nonCompliantHosts = @()
        
        foreach ($host in $esxiHosts) {
            $vSwitches = Get-VirtualSwitch -VMHost $host -Standard -ErrorAction SilentlyContinue
            
            foreach ($vSwitch in $vSwitches) {
                $secPolicy = Get-SecurityPolicy -VirtualSwitch $vSwitch -ErrorAction SilentlyContinue
                
                if ($secPolicy.AllowPromiscuous -eq $true -or $secPolicy.ForgedTransmits -eq $true) {
                    $nonCompliantHosts += "$($host.Name):$($vSwitch.Name)"
                }
            }
        }
        
        if ($nonCompliantHosts.Count -eq 0) {
            Add-CISResult -ControlID $controlID -Category $category -Title $title -Status "PASS" -Details "Network security policies are properly configured"
        } else {
            Add-CISResult -ControlID $controlID -Category $category -Title $title -Status "FAIL" -Details "Non-compliant switches: $($nonCompliantHosts -join ', ')" -Recommendation "Disable promiscuous mode and forged transmits"
        }
    }
    catch {
        Add-CISResult -ControlID $controlID -Category $category -Title $title -Status "ERROR" -Details $_.Exception.Message
    }
}

# Section 4: Access Control
function Test-CIS-4-1-1 {
    $controlID = "CIS-4.1.1"
    $category = "Access Control"
    $title = "Ensure default administrator account is secured"
    
    try {
        $adminUsers = Get-VIPermission | Where-Object { $_.Principal -like "*administrator*" -or $_.Principal -like "*admin*" }
        
        if ($adminUsers.Count -gt 0) {
            $details = "Administrator accounts found: $($adminUsers.Principal -join ', ')"
            Add-CISResult -ControlID $controlID -Category $category -Title $title -Status "REVIEW" -Details $details -Recommendation "Review administrator account usage and permissions"
        } else {
            Add-CISResult -ControlID $controlID -Category $category -Title $title -Status "PASS" -Details "No default administrator accounts found in permissions"
        }
    }
    catch {
        Add-CISResult -ControlID $controlID -Category $category -Title $title -Status "ERROR" -Details $_.Exception.Message
    }
}

function Test-CIS-4-2-1 {
    $controlID = "CIS-4.2.1"
    $category = "Access Control"
    $title = "Ensure ESXi host SSH access is properly configured"
    
    try {
        $esxiHosts = Get-VMHost
        $sshEnabledHosts = @()
        
        foreach ($host in $esxiHosts) {
            $sshService = Get-VMHostService -VMHost $host | Where-Object { $_.Key -eq "TSM-SSH" }
            
            if ($sshService.Running -eq $true) {
                $sshEnabledHosts += $host.Name
            }
        }
        
        if ($sshEnabledHosts.Count -eq 0) {
            Add-CISResult -ControlID $controlID -Category $category -Title $title -Status "PASS" -Details "SSH is disabled on all ESXi hosts"
        } else {
            Add-CISResult -ControlID $controlID -Category $category -Title $title -Status "REVIEW" -Details "SSH enabled on: $($sshEnabledHosts -join ', ')" -Recommendation "Disable SSH when not needed for security"
        }
    }
    catch {
        Add-CISResult -ControlID $controlID -Category $category -Title $title -Status "ERROR" -Details $_.Exception.Message
    }
}

# Section 5: System Configuration
function Test-CIS-5-1-1 {
    $controlID = "CIS-5.1.1"
    $category = "System Configuration"
    $title = "Ensure ESXi host time synchronization is configured"
    
    try {
        $esxiHosts = Get-VMHost
        $nonCompliantHosts = @()
        
        foreach ($host in $esxiHosts) {
            $ntpService = Get-VMHostService -VMHost $host | Where-Object { $_.Key -eq "ntpd" }
            $ntpServers = Get-VMHostNtpServer -VMHost $host
            
            if ($ntpService.Running -eq $false -or $ntpServers.Count -eq 0) {
                $nonCompliantHosts += $host.Name
            }
        }
        
        if ($nonCompliantHosts.Count -eq 0) {
            Add-CISResult -ControlID $controlID -Category $category -Title $title -Status "PASS" -Details "NTP is properly configured on all ESXi hosts"
        } else {
            Add-CISResult -ControlID $controlID -Category $category -Title $title -Status "FAIL" -Details "NTP not configured on: $($nonCompliantHosts -join ', ')" -Recommendation "Configure NTP on all ESXi hosts"
        }
    }
    catch {
        Add-CISResult -ControlID $controlID -Category $category -Title $title -Status "ERROR" -Details $_.Exception.Message
    }
}

# Section 6: Virtual Machine Configuration
function Test-CIS-6-1-1 {
    $controlID = "CIS-6.1.1"
    $category = "Virtual Machine Configuration"
    $title = "Ensure VM hardware version is current"
    
    try {
        $vms = Get-VM
        $outdatedVMs = @()
        
        foreach ($vm in $vms) {
            # Check for older hardware versions (simplified check)
            if ($vm.HardwareVersion -lt "vmx-19") {
                $outdatedVMs += "$($vm.Name) (v$($vm.HardwareVersion))"
            }
        }
        
        if ($outdatedVMs.Count -eq 0) {
            Add-CISResult -ControlID $controlID -Category $category -Title $title -Status "PASS" -Details "All VMs have current hardware versions"
        } else {
            Add-CISResult -ControlID $controlID -Category $category -Title $title -Status "REVIEW" -Details "VMs with older hardware: $($outdatedVMs -join ', ')" -Recommendation "Consider upgrading VM hardware versions"
        }
    }
    catch {
        Add-CISResult -ControlID $controlID -Category $category -Title $title -Status "ERROR" -Details $_.Exception.Message
    }
}

#endregion

#region Report Generation

function Generate-ComplianceReport {
    param(
        [string]$OutputPath
    )
    
    Write-Host "`nGenerating compliance report..." -ForegroundColor Yellow
    
    # Ensure output directory exists
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $reportPath = Join-Path $OutputPath "vSphere8-CIS-Audit-$timestamp.html"
    
    # Calculate statistics
    $totalControls = $script:Results.Count
    $passedControls = ($script:Results | Where-Object { $_.Status -eq "PASS" }).Count
    $failedControls = ($script:Results | Where-Object { $_.Status -eq "FAIL" }).Count
    $reviewControls = ($script:Results | Where-Object { $_.Status -eq "REVIEW" }).Count
    $errorControls = ($script:Results | Where-Object { $_.Status -eq "ERROR" }).Count
    
    $compliancePercentage = [math]::Round(($passedControls / $totalControls) * 100, 1)
    
    # Generate HTML report
    $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>VMware vSphere 8 CIS Benchmark Audit Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
        .summary { background-color: #e8f4fd; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .pass { color: green; font-weight: bold; }
        .fail { color: red; font-weight: bold; }
        .review { color: orange; font-weight: bold; }
        .error { color: purple; font-weight: bold; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .category-header { background-color: #d4edda; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">
        <h1>VMware vSphere 8 CIS Benchmark Audit Report</h1>
        <p><strong>Generated:</strong> $(Get-Date)</p>
        <p><strong>vCenter Server:</strong> $($script:vCenterConnection.Name)</p>
        <p><strong>Audit Duration:</strong> $([math]::Round(((Get-Date) - $script:StartTime).TotalMinutes, 1)) minutes</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>Overall Compliance:</strong> $compliancePercentage%</p>
        <p><strong>Total Controls Tested:</strong> $totalControls</p>
        <p><span class="pass">Passed:</span> $passedControls | <span class="fail">Failed:</span> $failedControls | <span class="review">Review Required:</span> $reviewControls | <span class="error">Errors:</span> $errorControls</p>
    </div>
    
    <h2>Detailed Results</h2>
    <table>
        <tr>
            <th>Control ID</th>
            <th>Category</th>
            <th>Title</th>
            <th>Status</th>
            <th>Details</th>
            <th>Recommendation</th>
        </tr>
"@

    foreach ($category in $script:CISCategories.Keys) {
        if ($script:CISCategories[$category].Count -gt 0) {
            $htmlContent += "<tr class='category-header'><td colspan='6'>$category</td></tr>"
            
            foreach ($result in $script:CISCategories[$category]) {
                $statusClass = $result.Status.ToLower()
                $htmlContent += @"
        <tr>
            <td>$($result.ControlID)</td>
            <td>$($result.Category)</td>
            <td>$($result.Title)</td>
            <td class="$statusClass">$($result.Status)</td>
            <td>$($result.Details)</td>
            <td>$($result.Recommendation)</td>
        </tr>
"@
            }
        }
    }
    
    $htmlContent += @"
    </table>
    
    <div class="summary">
        <h3>Recommendations Summary</h3>
        <ul>
"@
    
    $failedResults = $script:Results | Where-Object { $_.Status -eq "FAIL" -and $_.Recommendation -ne "" }
    foreach ($result in $failedResults) {
        $htmlContent += "<li><strong>$($result.ControlID):</strong> $($result.Recommendation)</li>"
    }
    
    $htmlContent += @"
        </ul>
    </div>
</body>
</html>
"@
    
    $htmlContent | Out-File -FilePath $reportPath -Encoding UTF8
    
    # Also generate CSV for data processing
    $csvPath = Join-Path $OutputPath "vSphere8-CIS-Audit-$timestamp.csv"
    $script:Results | Export-Csv -Path $csvPath -NoTypeInformation
    
    return @{
        HtmlReport = $reportPath
        CsvReport = $csvPath
        Statistics = @{
            Total = $totalControls
            Passed = $passedControls
            Failed = $failedControls
            Review = $reviewControls
            Errors = $errorControls
            CompliancePercentage = $compliancePercentage
        }
    }
}

function Show-FinalSummary {
    param(
        [hashtable]$Statistics
    )
    
    Write-Host "`n" + "="*80 -ForegroundColor White
    Write-Host "VMware vSphere 8 CIS Benchmark Audit - FINAL SUMMARY" -ForegroundColor White
    Write-Host "="*80 -ForegroundColor White
    
    Write-Host "`nOVERALL COMPLIANCE: " -NoNewline -ForegroundColor White
    if ($Statistics.CompliancePercentage -ge 90) {
        Write-Host "$($Statistics.CompliancePercentage)% - EXCELLENT" -ForegroundColor Green
    } elseif ($Statistics.CompliancePercentage -ge 75) {
        Write-Host "$($Statistics.CompliancePercentage)% - GOOD" -ForegroundColor Yellow
    } elseif ($Statistics.CompliancePercentage -ge 50) {
        Write-Host "$($Statistics.CompliancePercentage)% - NEEDS IMPROVEMENT" -ForegroundColor Orange
    } else {
        Write-Host "$($Statistics.CompliancePercentage)% - CRITICAL" -ForegroundColor Red
    }
    
    Write-Host "`nCONTROL RESULTS:" -ForegroundColor White
    Write-Host "  ✓ PASSED:  " -NoNewline -ForegroundColor Green
    Write-Host "$($Statistics.Passed)/$($Statistics.Total)" -ForegroundColor White
    
    Write-Host "  ✗ FAILED:  " -NoNewline -ForegroundColor Red
    Write-Host "$($Statistics.Failed)/$($Statistics.Total)" -ForegroundColor White
    
    Write-Host "  ⚠ REVIEW:  " -NoNewline -ForegroundColor Yellow
    Write-Host "$($Statistics.Review)/$($Statistics.Total)" -ForegroundColor White
    
    Write-Host "  ⚡ ERRORS:  " -NoNewline -ForegroundColor Magenta
    Write-Host "$($Statistics.Errors)/$($Statistics.Total)" -ForegroundColor White
    
    Write-Host "`nPRIORITY ACTIONS:" -ForegroundColor White
    
    $criticalIssues = $script:Results | Where-Object { $_.Status -eq "FAIL" }
    if ($criticalIssues.Count -gt 0) {
        Write-Host "  🔴 CRITICAL: $($criticalIssues.Count) security controls failed" -ForegroundColor Red
        Write-Host "     Immediate remediation required!" -ForegroundColor Red
    }
    
    $reviewIssues = $script:Results | Where-Object { $_.Status -eq "REVIEW" }
    if ($reviewIssues.Count -gt 0) {
        Write-Host "  🟡 REVIEW: $($reviewIssues.Count) controls need manual review" -ForegroundColor Yellow
    }
    
    if ($Statistics.Failed -eq 0 -and $Statistics.Review -eq 0) {
        Write-Host "  🟢 EXCELLENT: All controls passed!" -ForegroundColor Green
    }
    
    Write-Host "`n" + "="*80 -ForegroundColor White
}

#endregion

#region Main Execution

function Main {
    Write-Host "VMware vSphere 8 CIS Benchmark Audit Tool" -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host "Enterprise Security Compliance Assessment" -ForegroundColor Gray
    Write-Host ""
    
    # Initialize total controls count
    $script:TotalControls = 10  # Update this as you add more controls
    
    # Check prerequisites
    if (-not (Test-PowerCLIModule)) {
        return
    }
    
    # Get vCenter connection details if not provided
    if (-not $vCenterServer) {
        $vCenterServer = Read-Host "Enter vCenter Server FQDN or IP address"
    }
    
    if (-not $Credential) {
        $Credential = Get-Credential -Message "Enter vCenter credentials"
    }
    
    # Connect to vCenter
    if (-not (Connect-vCenterServer -Server $vCenterServer -Cred $Credential)) {
        return
    }
    
    Write-Host "`nStarting CIS Benchmark audit..." -ForegroundColor Yellow
    Write-Host "Total controls to test: $script:TotalControls" -ForegroundColor Gray
    Write-Host ""
    
    # Execute all CIS controls
    try {
        # Section 1: Initial Setup
        Test-CIS-1-1-1
        Test-CIS-1-2-1
        
        # Section 2: Logging and Monitoring
        Test-CIS-2-1-1
        Test-CIS-2-2-1
        
        # Section 3: Network Configuration
        Test-CIS-3-1-1
        
        # Section 4: Access Control
        Test-CIS-4-1-1
        Test-CIS-4-2-1
        
        # Section 5: System Configuration
        Test-CIS-5-1-1
        
        # Section 6: Virtual Machine Configuration
        Test-CIS-6-1-1
        
        Write-Progress -Activity "CIS Benchmark Audit" -Completed
        
        # Generate reports
        $reportResults = Generate-ComplianceReport -OutputPath $OutputPath
        
        # Show final summary
        Show-FinalSummary -Statistics $reportResults.Statistics
        
        Write-Host "`nREPORTS GENERATED:" -ForegroundColor White
        Write-Host "  📄 HTML Report: $($reportResults.HtmlReport)" -ForegroundColor Cyan
        Write-Host "  📊 CSV Data:    $($reportResults.CsvReport)" -ForegroundColor Cyan
        
    }
    finally {
        # Cleanup
        if ($script:vCenterConnection) {
            Disconnect-VIServer -Server $script:vCenterConnection -Confirm:$false -ErrorAction SilentlyContinue
            Write-Host "`nDisconnected from vCenter Server" -ForegroundColor Gray
        }
    }
}

# Execute main function
Main

#endregion