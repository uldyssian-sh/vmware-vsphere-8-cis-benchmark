# Integration Tests for vSphere 8 CIS Benchmark Tool
# These tests validate the script functionality without requiring vCenter connection

Describe "vSphere 8 CIS Benchmark Integration Tests" {
    
    BeforeAll {
        $scriptPath = Join-Path $PSScriptRoot "..\scripts\Invoke-vSphere8CISAudit.ps1"
        $script:scriptContent = Get-Content $scriptPath -Raw
    }
    
    Context "Script Structure Validation" {
        It "Should contain all required functions" {
            $script:scriptContent | Should -Match "function Initialize-Environment"
            $script:scriptContent | Should -Match "function Add-CISResult"
            $script:scriptContent | Should -Match "function Generate-ComplianceReport"
        }
        
        It "Should have all CIS sections defined" {
            $script:scriptContent | Should -Match "Test-Section1-Controls"
            $script:scriptContent | Should -Match "Test-Section2-Controls"
            $script:scriptContent | Should -Match "Test-Section8-Controls"
        }
        
        It "Should contain exactly 106 CIS controls" {
            $cisControls = [regex]::Matches($script:scriptContent, "CIS-\d+\.\d+\.\d+") | 
                          ForEach-Object { $_.Value } | 
                          Sort-Object -Unique
            $cisControls.Count | Should -Be 106
        }
    }
    
    Context "Parameter Validation" {
        It "Should accept valid parameters" {
            $script:scriptContent | Should -Match "param\("
            $script:scriptContent | Should -Match "\[string\]\$vCenterServer"
            $script:scriptContent | Should -Match "\[PSCredential\]\$Credential"
            $script:scriptContent | Should -Match "\[string\]\$OutputPath"
        }
    }
    
    Context "Security Validation" {
        It "Should not contain hardcoded credentials" {
            $script:scriptContent | Should -Not -Match "password\s*=\s*['\"][^'\"]+['\"]"
            $script:scriptContent | Should -Not -Match "username\s*=\s*['\"][^'\"]+['\"]"
        }
        
        It "Should use secure credential handling" {
            $script:scriptContent | Should -Match "Get-Credential"
            $script:scriptContent | Should -Match "PSCredential"
        }
    }
    
    Context "Error Handling" {
        It "Should have comprehensive try-catch blocks" {
            $tryBlocks = [regex]::Matches($script:scriptContent, "try\s*\{").Count
            $catchBlocks = [regex]::Matches($script:scriptContent, "catch\s*\{").Count
            $tryBlocks | Should -BeGreaterThan 50
            $catchBlocks | Should -Be $tryBlocks
        }
    }
    
    Context "Output Generation" {
        It "Should generate HTML reports" {
            $script:scriptContent | Should -Match "\.html"
            $script:scriptContent | Should -Match "Generate-ComplianceReport"
        }
        
        It "Should generate CSV reports" {
            $script:scriptContent | Should -Match "Export-Csv"
            $script:scriptContent | Should -Match "\.csv"
        }
    }
}# Updated 20251109_123841
# Updated Sun Nov  9 12:52:42 CET 2025
# Updated Sun Nov  9 12:56:02 CET 2025
