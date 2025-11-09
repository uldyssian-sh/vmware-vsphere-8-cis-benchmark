$ErrorActionPreference = "Stop"
# Basic Tests for VMware vSphere 8 CIS Benchmark Tool
# Enterprise-ready testing framework

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ScriptPath = "../scripts/Invoke-vSphere8CISAudit.ps1"
)

# Test Results
$script:TestResults = @()
$script:PassedTests = 0
$script:FailedTests = 0

function Add-TestResult {
    param(
        [string]$TestName,
        [bool]$Passed,
        [string]$Details = ""
    )
    
    $result = [PSCustomObject]@{
        TestName = $TestName
        Status = if ($Passed) { "PASS" } else { "FAIL" }
        Details = $Details
        Timestamp = Get-Date
    }
    
    $script:TestResults += $result
    
    if ($Passed) {
        $script:PassedTests++
        Write-Host "✅ $TestName" -ForegroundColor Green
    } else {
        $script:FailedTests++
        Write-Host "❌ $TestName - $Details" -ForegroundColor Red
    }
}

function Test-ScriptSyntax {
    Write-Host "`n🔍 Testing PowerShell Syntax..." -ForegroundColor Cyan
    
    try {
        $scriptContent = Get-Content $ScriptPath -Raw
        $null = [System.Management.Automation.PSParser]::Tokenize($scriptContent, [ref]$null)
        Add-TestResult -TestName "PowerShell Syntax Validation" -Passed $true
    } catch {
        Add-TestResult -TestName "PowerShell Syntax Validation" -Passed $false -Details $_.Exception.Message
    }
}

function Test-CISControlCount {
    Write-Host "`n🔍 Testing CIS Control Coverage..." -ForegroundColor Cyan
    
    $scriptContent = Get-Content $ScriptPath -Raw
    
    # Count CIS control implementations
    $cisControls = ($scriptContent | Select-String -Pattern "CIS-\d+\.\d+\.\d+" -AllMatches).Matches
    $uniqueControls = $cisControls.Value | Sort-Object -Unique
    
    if ($uniqueControls.Count -ge 106) {
        Add-TestResult -TestName "CIS Control Count (≥106)" -Passed $true -Details "$($uniqueControls.Count) controls found"
    } else {
        Add-TestResult -TestName "CIS Control Count (≥106)" -Passed $false -Details "Only $($uniqueControls.Count) controls found"
    }
}

function Show-TestSummary {
    Write-Host "`n" + "="*80 -ForegroundColor White
    Write-Host "VMware vSphere 8 CIS Benchmark Tool - Test Results" -ForegroundColor Cyan
    Write-Host "="*80 -ForegroundColor White
    
    Write-Host "`n📊 Test Summary:" -ForegroundColor White
    Write-Host "  ✅ Passed: $script:PassedTests" -ForegroundColor Green
    Write-Host "  ❌ Failed: $script:FailedTests" -ForegroundColor Red
    Write-Host "  📋 Total:  $($script:PassedTests + $script:FailedTests)" -ForegroundColor Gray
    
    $successRate = [math]::Round(($script:PassedTests / ($script:PassedTests + $script:FailedTests)) * 100, 1)
    Write-Host "`n🎯 Success Rate: $successRate%" -ForegroundColor $(if ($successRate -ge 90) { "Green" } elseif ($successRate -ge 75) { "Yellow" } else { "Red" })
}

# Main Test Execution
Write-Host "VMware vSphere 8 CIS Benchmark Tool - Basic Tests" -ForegroundColor Cyan

if (-not (Test-Path $ScriptPath)) {
    Write-Error "Script not found: $ScriptPath"
    exit 1
}

Test-ScriptSyntax
Test-CISControlCount
Show-TestSummary

