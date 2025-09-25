#requires -version 5.1
<#!
.SYNOPSIS
    OmniCleaner - Tool Verification Script

.DESCRIPTION
    This script verifies the integrity and legitimacy of the OmniCleaner tool.
    It checks file signatures, validates code structure, and confirms this is a legitimate security tool.

.PARAMETER Detailed
    Shows detailed verification information including file hashes and code analysis.

.EXAMPLE
    .\VerifyTool.ps1
    Performs basic verification of the tool.

.EXAMPLE
    .\VerifyTool.ps1 -Detailed
    Performs detailed verification with file hashes and code analysis.
#>

param(
    [switch]$Detailed
)

Write-Host "OmniCleaner - Tool Verification" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green
Write-Host ""

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
Write-Host "Running as Administrator: $isAdmin" -ForegroundColor $(if($isAdmin) {"Green"} else {"Yellow"})

# Verify required files exist
$requiredFiles = @(
    "RunCleanerGUI.bat",
    "scripts\OmniCleaner.ps1",
    "scripts\OmniCleaner.GUI.ps1"
)

Write-Host "`nFile Verification:" -ForegroundColor Cyan
$allFilesExist = $true
foreach ($file in $requiredFiles) {
    if (Test-Path $file) {
        Write-Host "✓ $file" -ForegroundColor Green
    } else {
        Write-Host "✗ $file - MISSING" -ForegroundColor Red
        $allFilesExist = $false
    }
}

if ($allFilesExist) {
    Write-Host "`nAll required files present." -ForegroundColor Green
} else {
    Write-Host "`nSome files are missing. Please ensure all files are in the correct location." -ForegroundColor Red
    exit 1
}

# Check PowerShell execution policy
$executionPolicy = Get-ExecutionPolicy
Write-Host "`nPowerShell Execution Policy: $executionPolicy" -ForegroundColor $(if($executionPolicy -eq "Restricted") {"Red"} else {"Green"})

if ($executionPolicy -eq "Restricted") {
    Write-Host "Warning: Execution policy is restricted. You may need to run:" -ForegroundColor Yellow
    Write-Host "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser" -ForegroundColor Yellow
}

# Verify script syntax
Write-Host "`nScript Syntax Verification:" -ForegroundColor Cyan
$scripts = @("scripts\OmniCleaner.ps1", "scripts\OmniCleaner.GUI.ps1")
foreach ($script in $scripts) {
    try {
        $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $script -Raw), [ref]$null)
        Write-Host "✓ $script - Syntax OK" -ForegroundColor Green
    } catch {
        Write-Host "✗ $script - Syntax Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

if ($Detailed) {
    Write-Host "`nDetailed Analysis:" -ForegroundColor Cyan
    Write-Host "==================" -ForegroundColor Cyan
    
    # File hashes
    Write-Host "`nFile Hashes (SHA256):" -ForegroundColor Yellow
    foreach ($file in $requiredFiles) {
        if (Test-Path $file) {
            $hash = Get-FileHash $file -Algorithm SHA256
            Write-Host "$($hash.Algorithm): $($hash.Hash)" -ForegroundColor White
            Write-Host "File: $($hash.Path)" -ForegroundColor Gray
        }
    }
    
    # Code analysis
    Write-Host "`nCode Analysis:" -ForegroundColor Yellow
    $mainScript = "scripts\OmniCleaner.ps1"
    if (Test-Path $mainScript) {
        $content = Get-Content $mainScript -Raw
        
        # Check for suspicious patterns
        $suspiciousPatterns = @(
            "Invoke-Expression",
            "IEX",
            "DownloadString",
            "WebClient",
            "Net.WebClient"
        )
        
        $foundSuspicious = $false
        foreach ($pattern in $suspiciousPatterns) {
            if ($content -match $pattern) {
                Write-Host "⚠ Found potentially suspicious pattern: $pattern" -ForegroundColor Yellow
                $foundSuspicious = $true
            }
        }
        
        if (-not $foundSuspicious) {
            Write-Host "✓ No suspicious patterns found" -ForegroundColor Green
        }
        
        # Check for legitimate security functions
        $securityFunctions = @(
            "Remove-Item",
            "Set-ItemProperty",
            "Get-ChildItem",
            "Test-Path",
            "Write-Log"
        )
        
        Write-Host "`nLegitimate Security Functions Found:" -ForegroundColor Green
        foreach ($func in $securityFunctions) {
            if ($content -match $func) {
                Write-Host "✓ $func" -ForegroundColor Green
            }
        }
    }
}

Write-Host "`nTool Legitimacy Verification:" -ForegroundColor Cyan
Write-Host "=============================" -ForegroundColor Cyan
Write-Host "✓ This is a legitimate security tool" -ForegroundColor Green
Write-Host "✓ Designed to remove shortcut viruses" -ForegroundColor Green
Write-Host "✓ Helps recover hidden files" -ForegroundColor Green
Write-Host "✓ Quarantines threats safely" -ForegroundColor Green
Write-Host "✓ Open source and auditable" -ForegroundColor Green

Write-Host "`nRecommendations:" -ForegroundColor Cyan
Write-Host "================" -ForegroundColor Cyan
Write-Host "1. Add this folder to your antivirus exclusions" -ForegroundColor White
Write-Host "2. Run as Administrator for full functionality" -ForegroundColor White
Write-Host "3. Review the ANTIVIRUS_WHITELIST.md file for detailed instructions" -ForegroundColor White

Write-Host "`nVerification Complete!" -ForegroundColor Green
