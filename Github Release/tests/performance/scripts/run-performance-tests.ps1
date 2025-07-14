#!/usr/bin/env powershell
<#
.SYNOPSIS
    CAM Performance Test Runner - Comprehensive performance testing automation script

.DESCRIPTION
    This script provides comprehensive performance testing capabilities for the CAM system,
    including load testing, stress testing, benchmarking, and performance analysis.

.PARAMETER TestType
    Type of test to run: load, stress, benchmark, all

.PARAMETER Environment
    Target environment: dev, staging, prod

.PARAMETER Duration
    Test duration in minutes (default: 10)

.PARAMETER Concurrent
    Number of concurrent users/threads (default: 10)

.PARAMETER BaseUrl
    CAM system base URL (default: http://localhost:3000)

.PARAMETER ApiToken
    API token for authentication

.PARAMETER ReportFormat
    Report format: json, html, both (default: both)

.PARAMETER Baseline
    Path to baseline results file for comparison

.EXAMPLE
    .\run-performance-tests.ps1 -TestType load -Environment staging -Duration 15 -Concurrent 50

.EXAMPLE
    .\run-performance-tests.ps1 -TestType benchmark -BaseUrl https://api.cam-system.com -ApiToken $env:CAM_API_TOKEN
#>

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("load", "stress", "benchmark", "all")]
    [string]$TestType = "load",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("dev", "staging", "prod")]
    [string]$Environment = "dev",
    
    [Parameter(Mandatory=$false)]
    [int]$Duration = 10,
    
    [Parameter(Mandatory=$false)]
    [int]$Concurrent = 10,
    
    [Parameter(Mandatory=$false)]
    [string]$BaseUrl = "http://localhost:3000",
    
    [Parameter(Mandatory=$false)]
    [string]$ApiToken = "",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("json", "html", "both")]
    [string]$ReportFormat = "both",
    
    [Parameter(Mandatory=$false)]
    [string]$Baseline = "",
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipSystemCheck = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$EnableProfiling = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$ContinuousMode = $false
)

# Script configuration
$ErrorActionPreference = "Stop"
$ProgressPreference = "Continue"

# Constants
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$PROJECT_ROOT = Split-Path -Parent $SCRIPT_DIR
$RESULTS_DIR = Join-Path $PROJECT_ROOT "results"
$LOGS_DIR = Join-Path $PROJECT_ROOT "logs"
$TIMESTAMP = Get-Date -Format "yyyyMMdd_HHmmss"

# Create required directories
@($RESULTS_DIR, $LOGS_DIR) | ForEach-Object {
    if (!(Test-Path $_)) {
        New-Item -ItemType Directory -Path $_ -Force | Out-Null
    }
}

# Logging function
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    $color = switch ($Level) {
        "INFO" { "White" }
        "WARN" { "Yellow" }
        "ERROR" { "Red" }
        "SUCCESS" { "Green" }
    }
    
    Write-Host $logMessage -ForegroundColor $color
    
    # Write to log file
    $logFile = Join-Path $LOGS_DIR "performance-tests-$TIMESTAMP.log"
    Add-Content -Path $logFile -Value $logMessage
}

# System requirements check
function Test-SystemRequirements {
    Write-Log "Checking system requirements..." "INFO"
    
    $requirements = @{
        "k6" = "k6 version"
        "node" = "node --version"
        "python" = "python --version"
        "npm" = "npm --version"
    }
    
    $missing = @()
    foreach ($tool in $requirements.Keys) {
        try {
            $version = Invoke-Expression $requirements[$tool] 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Log "✓ $tool is installed: $($version.Split("`n")[0])" "SUCCESS"
            } else {
                $missing += $tool
            }
        } catch {
            $missing += $tool
        }
    }
    
    if ($missing.Count -gt 0) {
        Write-Log "Missing required tools: $($missing -join ', ')" "ERROR"
        Write-Log "Please install missing tools and try again." "ERROR"
        return $false
    }
    
    # Check Node.js dependencies
    $packageJsonPath = Join-Path $PROJECT_ROOT "package.json"
    if (Test-Path $packageJsonPath) {
        Write-Log "Installing Node.js dependencies..." "INFO"
        Set-Location $PROJECT_ROOT
        npm install 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Log "✓ Node.js dependencies installed successfully" "SUCCESS"
        } else {
            Write-Log "Failed to install Node.js dependencies" "WARN"
        }
    }
    
    # Check Python dependencies
    $requirementsPath = Join-Path $PROJECT_ROOT "requirements.txt"
    if (Test-Path $requirementsPath) {
        Write-Log "Checking Python dependencies..." "INFO"
        try {
            python -m pip install -r $requirementsPath 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Log "✓ Python dependencies installed successfully" "SUCCESS"
            } else {
                Write-Log "Failed to install Python dependencies" "WARN"
            }
        } catch {
            Write-Log "Python dependency installation failed: $_" "WARN"
        }
    }
    
    return $true
}

# CAM system health check
function Test-CAMHealth {
    param([string]$Url, [string]$Token)
    
    Write-Log "Checking CAM system health at $Url..." "INFO"
    
    try {
        $headers = @{}
        if ($Token) {
            $headers["Authorization"] = "Bearer $Token"
        }
        
        $response = Invoke-RestMethod -Uri "$Url/api/v1/status" -Headers $headers -TimeoutSec 10
        
        if ($response.status -eq "healthy") {
            Write-Log "✓ CAM system is healthy" "SUCCESS"
            return $true
        } else {
            Write-Log "CAM system status: $($response.status)" "WARN"
            return $false
        }
    } catch {
        Write-Log "CAM system health check failed: $_" "ERROR"
        return $false
    }
}

# Run K6 load tests
function Invoke-LoadTests {
    param([string]$Url, [string]$Token, [int]$Duration, [int]$Concurrent)
    
    Write-Log "Running K6 load tests..." "INFO"
    
    $k6ScriptPath = Join-Path $PROJECT_ROOT "k6\load-tests\cam-load-test.js"
    $resultsFile = Join-Path $RESULTS_DIR "load-test-results-$TIMESTAMP.json"
    
    $env:CAM_BASE_URL = $Url
    $env:CAM_API_TOKEN = $Token
    $env:CAM_DURATION = $Duration
    $env:CAM_CONCURRENT_USERS = $Concurrent
    
    $k6Command = "k6 run --out json=$resultsFile $k6ScriptPath"
    
    Write-Log "Executing: $k6Command" "INFO"
    
    try {
        Invoke-Expression $k6Command
        if ($LASTEXITCODE -eq 0) {
            Write-Log "✓ Load tests completed successfully" "SUCCESS"
            return $resultsFile
        } else {
            Write-Log "Load tests failed with exit code $LASTEXITCODE" "ERROR"
            return $null
        }
    } catch {
        Write-Log "Load test execution failed: $_" "ERROR"
        return $null
    }
}

# Run K6 stress tests
function Invoke-StressTests {
    param([string]$Url, [string]$Token, [int]$Duration)
    
    Write-Log "Running K6 stress tests..." "INFO"
    
    $k6ScriptPath = Join-Path $PROJECT_ROOT "k6\stress-tests\cam-stress-test.js"
    $resultsFile = Join-Path $RESULTS_DIR "stress-test-results-$TIMESTAMP.json"
    
    $env:CAM_BASE_URL = $Url
    $env:CAM_API_TOKEN = $Token
    $env:CAM_STRESS_DURATION = $Duration
    
    $k6Command = "k6 run --out json=$resultsFile $k6ScriptPath"
    
    Write-Log "Executing: $k6Command" "INFO"
    
    try {
        Invoke-Expression $k6Command
        if ($LASTEXITCODE -eq 0) {
            Write-Log "✓ Stress tests completed successfully" "SUCCESS"
            return $resultsFile
        } else {
            Write-Log "Stress tests failed with exit code $LASTEXITCODE" "ERROR"
            return $null
        }
    } catch {
        Write-Log "Stress test execution failed: $_" "ERROR"
        return $null
    }
}

# Run benchmarks
function Invoke-Benchmarks {
    param([string]$Url, [string]$Token)
    
    Write-Log "Running performance benchmarks..." "INFO"
    
    $benchmarkScripts = @(
        "arbitration-performance.js",
        "agent-collaboration.js",
        "cost-optimization.js"
    )
    
    $results = @()
    
    foreach ($script in $benchmarkScripts) {
        $scriptPath = Join-Path $PROJECT_ROOT "k6\benchmarks\$script"
        $resultsFile = Join-Path $RESULTS_DIR "benchmark-$($script.Replace('.js', ''))-$TIMESTAMP.json"
        
        $env:CAM_BASE_URL = $Url
        $env:CAM_API_TOKEN = $Token
        
        $k6Command = "k6 run --out json=$resultsFile $scriptPath"
        
        Write-Log "Running benchmark: $script" "INFO"
        
        try {
            Invoke-Expression $k6Command
            if ($LASTEXITCODE -eq 0) {
                Write-Log "✓ Benchmark $script completed successfully" "SUCCESS"
                $results += $resultsFile
            } else {
                Write-Log "Benchmark $script failed with exit code $LASTEXITCODE" "WARN"
            }
        } catch {
            Write-Log "Benchmark $script execution failed: $_" "WARN"
        }
    }
    
    return $results
}

# Run Artillery tests
function Invoke-ArtilleryTests {
    param([string]$Url, [string]$Token, [string]$TestType)
    
    Write-Log "Running Artillery $TestType tests..." "INFO"
    
    $configFile = switch ($TestType) {
        "load" { "cam-load-test.yml" }
        "stress" { "cam-stress-test.yml" }
        default { "cam-load-test.yml" }
    }
    
    $configPath = Join-Path $PROJECT_ROOT "artillery\$configFile"
    $resultsFile = Join-Path $RESULTS_DIR "artillery-$TestType-$TIMESTAMP.json"
    
    $env:CAM_BASE_URL = $Url
    $env:CAM_API_TOKEN = $Token
    
    if (Test-Path $configPath) {
        $artilleryCommand = "artillery run --config $configPath --output $resultsFile"
        
        Write-Log "Executing: $artilleryCommand" "INFO"
        
        try {
            Invoke-Expression $artilleryCommand
            if ($LASTEXITCODE -eq 0) {
                Write-Log "✓ Artillery $TestType tests completed successfully" "SUCCESS"
                return $resultsFile
            } else {
                Write-Log "Artillery $TestType tests failed with exit code $LASTEXITCODE" "ERROR"
                return $null
            }
        } catch {
            Write-Log "Artillery test execution failed: $_" "ERROR"
            return $null
        }
    } else {
        Write-Log "Artillery config file not found: $configPath" "WARN"
        return $null
    }
}

# Start performance profiling
function Start-PerformanceProfiling {
    param([string]$Url, [string]$Token, [int]$Duration)
    
    if (!$EnableProfiling) {
        return $null
    }
    
    Write-Log "Starting performance profiling..." "INFO"
    
    $profilerScript = Join-Path $PROJECT_ROOT "profiling\cam-profiler.py"
    $profilerOutput = Join-Path $RESULTS_DIR "profiling-$TIMESTAMP"
    
    if (Test-Path $profilerScript) {
        $profilerArgs = @(
            "--url", $Url,
            "--duration", ($Duration * 60),
            "--output", $profilerOutput
        )
        
        if ($Token) {
            $profilerArgs += @("--token", $Token)
        }
        
        $profilerCommand = "python `"$profilerScript`" $($profilerArgs -join ' ')"
        
        Write-Log "Starting profiler: $profilerCommand" "INFO"
        
        try {
            $job = Start-Job -ScriptBlock {
                param($Command)
                Invoke-Expression $Command
            } -ArgumentList $profilerCommand
            
            Write-Log "✓ Performance profiler started (Job ID: $($job.Id))" "SUCCESS"
            return $job
        } catch {
            Write-Log "Failed to start performance profiler: $_" "WARN"
            return $null
        }
    } else {
        Write-Log "Performance profiler script not found: $profilerScript" "WARN"
        return $null
    }
}

# Generate performance analysis report
function Invoke-PerformanceAnalysis {
    param([string[]]$ResultsFiles, [string]$BaselineFile)
    
    Write-Log "Generating performance analysis..." "INFO"
    
    $analyzerScript = Join-Path $PROJECT_ROOT "analysis\performance-analyzer.py"
    $outputDir = Join-Path $RESULTS_DIR "analysis-$TIMESTAMP"
    
    if (!(Test-Path $analyzerScript)) {
        Write-Log "Performance analyzer script not found: $analyzerScript" "WARN"
        return
    }
    
    foreach ($resultsFile in $ResultsFiles) {
        if (!(Test-Path $resultsFile)) {
            Write-Log "Results file not found: $resultsFile" "WARN"
            continue
        }
        
        $analyzerArgs = @(
            "--results", "`"$resultsFile`"",
            "--output-dir", "`"$outputDir`"",
            "--report", "`"$(Join-Path $outputDir 'analysis-report.json')`""
        )
        
        if ($BaselineFile -and (Test-Path $BaselineFile)) {
            $analyzerArgs += @("--baseline", "`"$BaselineFile`"")
        }
        
        $analyzerCommand = "python `"$analyzerScript`" $($analyzerArgs -join ' ')"
        
        Write-Log "Running analysis: $analyzerCommand" "INFO"
        
        try {
            Invoke-Expression $analyzerCommand
            if ($LASTEXITCODE -eq 0) {
                Write-Log "✓ Performance analysis completed" "SUCCESS"
            } else {
                Write-Log "Performance analysis failed with exit code $LASTEXITCODE" "WARN"
            }
        } catch {
            Write-Log "Performance analysis execution failed: $_" "WARN"
        }
    }
}

# Generate HTML report
function New-HTMLReport {
    param([string[]]$ResultsFiles, [string]$OutputPath)
    
    $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>CAM Performance Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; }
        .summary { background-color: #e3f2fd; padding: 20px; border-radius: 4px; margin-bottom: 20px; }
        .test-section { margin-bottom: 30px; }
        .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }
        .metric-card { background-color: #f8f9fa; padding: 15px; border-radius: 4px; border-left: 4px solid #007acc; }
        .metric-value { font-size: 24px; font-weight: bold; color: #007acc; }
        .metric-label { font-size: 14px; color: #666; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #f2f2f2; font-weight: bold; }
        .status-pass { color: #28a745; font-weight: bold; }
        .status-warn { color: #ffc107; font-weight: bold; }
        .status-fail { color: #dc3545; font-weight: bold; }
        .footer { text-align: center; margin-top: 30px; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>CAM Performance Test Report</h1>
            <p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
            <p>Environment: $Environment | Test Type: $TestType</p>
        </div>
        
        <div class="summary">
            <h2>Test Summary</h2>
            <div class="metrics-grid">
                <div class="metric-card">
                    <div class="metric-value">$($ResultsFiles.Count)</div>
                    <div class="metric-label">Test Suites Executed</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">$Duration min</div>
                    <div class="metric-label">Test Duration</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">$Concurrent</div>
                    <div class="metric-label">Concurrent Users</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">$(Get-Date -Format "HH:mm")</div>
                    <div class="metric-label">Completion Time</div>
                </div>
            </div>
        </div>
        
        <div class="test-section">
            <h2>Test Results</h2>
            <table>
                <tr>
                    <th>Test Suite</th>
                    <th>Status</th>
                    <th>Results File</th>
                    <th>Size</th>
                </tr>
"@
    
    foreach ($file in $ResultsFiles) {
        if (Test-Path $file) {
            $fileInfo = Get-Item $file
            $fileName = $fileInfo.Name
            $fileSize = [math]::Round($fileInfo.Length / 1KB, 2)
            $status = '<span class="status-pass">✓ COMPLETED</span>'
        } else {
            $fileName = Split-Path $file -Leaf
            $fileSize = "N/A"
            $status = '<span class="status-fail">✗ FAILED</span>'
        }
        
        $htmlContent += @"
                <tr>
                    <td>$fileName</td>
                    <td>$status</td>
                    <td>$file</td>
                    <td>$fileSize KB</td>
                </tr>
"@
    }
    
    $htmlContent += @"
            </table>
        </div>
        
        <div class="footer">
            <p>CAM Performance Testing Framework | Generated by run-performance-tests.ps1</p>
        </div>
    </div>
</body>
</html>
"@
    
    $htmlContent | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Log "✓ HTML report generated: $OutputPath" "SUCCESS"
}

# Continuous monitoring mode
function Start-ContinuousMonitoring {
    param([string]$Url, [string]$Token, [int]$IntervalMinutes)
    
    Write-Log "Starting continuous monitoring mode (interval: $IntervalMinutes minutes)..." "INFO"
    
    $iteration = 1
    while ($true) {
        Write-Log "=== Continuous Monitoring - Iteration $iteration ===" "INFO"
        
        # Run health check
        $isHealthy = Test-CAMHealth -Url $Url -Token $Token
        
        if ($isHealthy) {
            # Run quick load test
            $quickResults = Invoke-LoadTests -Url $Url -Token $Token -Duration 2 -Concurrent 5
            
            if ($quickResults) {
                Write-Log "✓ Continuous monitoring iteration $iteration completed" "SUCCESS"
            } else {
                Write-Log "✗ Continuous monitoring iteration $iteration failed" "WARN"
            }
        } else {
            Write-Log "✗ System unhealthy - skipping iteration $iteration" "WARN"
        }
        
        Write-Log "Waiting $IntervalMinutes minutes before next iteration..." "INFO"
        Start-Sleep -Seconds ($IntervalMinutes * 60)
        $iteration++
    }
}

# Main execution
function Main {
    Write-Log "=== CAM Performance Test Runner Started ===" "INFO"
    Write-Log "Test Type: $TestType | Environment: $Environment | Duration: $Duration min | Concurrent: $Concurrent" "INFO"
    
    # System requirements check
    if (!$SkipSystemCheck) {
        if (!(Test-SystemRequirements)) {
            Write-Log "System requirements check failed. Exiting." "ERROR"
            exit 1
        }
    }
    
    # CAM system health check
    if (!(Test-CAMHealth -Url $BaseUrl -Token $ApiToken)) {
        Write-Log "CAM system health check failed. Please verify the system is running." "ERROR"
        if ($Environment -ne "dev") {
            exit 1
        } else {
            Write-Log "Continuing in development mode..." "WARN"
        }
    }
    
    # Handle continuous monitoring mode
    if ($ContinuousMode) {
        Start-ContinuousMonitoring -Url $BaseUrl -Token $ApiToken -IntervalMinutes $Duration
        return
    }
    
    # Start performance profiling if enabled
    $profilerJob = $null
    if ($EnableProfiling) {
        $profilerJob = Start-PerformanceProfiling -Url $BaseUrl -Token $ApiToken -Duration $Duration
    }
    
    $allResults = @()
    
    try {
        # Execute tests based on type
        switch ($TestType) {
            "load" {
                Write-Log "Executing load tests..." "INFO"
                $loadResults = Invoke-LoadTests -Url $BaseUrl -Token $ApiToken -Duration $Duration -Concurrent $Concurrent
                if ($loadResults) { $allResults += $loadResults }
                
                $artilleryResults = Invoke-ArtilleryTests -Url $BaseUrl -Token $ApiToken -TestType "load"
                if ($artilleryResults) { $allResults += $artilleryResults }
            }
            
            "stress" {
                Write-Log "Executing stress tests..." "INFO"
                $stressResults = Invoke-StressTests -Url $BaseUrl -Token $ApiToken -Duration $Duration
                if ($stressResults) { $allResults += $stressResults }
                
                $artilleryResults = Invoke-ArtilleryTests -Url $BaseUrl -Token $ApiToken -TestType "stress"
                if ($artilleryResults) { $allResults += $artilleryResults }
            }
            
            "benchmark" {
                Write-Log "Executing benchmarks..." "INFO"
                $benchmarkResults = Invoke-Benchmarks -Url $BaseUrl -Token $ApiToken
                $allResults += $benchmarkResults
            }
            
            "all" {
                Write-Log "Executing comprehensive test suite..." "INFO"
                
                # Load tests
                $loadResults = Invoke-LoadTests -Url $BaseUrl -Token $ApiToken -Duration $Duration -Concurrent $Concurrent
                if ($loadResults) { $allResults += $loadResults }
                
                # Stress tests
                $stressResults = Invoke-StressTests -Url $BaseUrl -Token $ApiToken -Duration $Duration
                if ($stressResults) { $allResults += $stressResults }
                
                # Benchmarks
                $benchmarkResults = Invoke-Benchmarks -Url $BaseUrl -Token $ApiToken
                $allResults += $benchmarkResults
                
                # Artillery tests
                $artilleryLoadResults = Invoke-ArtilleryTests -Url $BaseUrl -Token $ApiToken -TestType "load"
                if ($artilleryLoadResults) { $allResults += $artilleryLoadResults }
                
                $artilleryStressResults = Invoke-ArtilleryTests -Url $BaseUrl -Token $ApiToken -TestType "stress"
                if ($artilleryStressResults) { $allResults += $artilleryStressResults }
            }
        }
        
        # Wait for profiler to complete
        if ($profilerJob) {
            Write-Log "Waiting for performance profiler to complete..." "INFO"
            Wait-Job $profilerJob -Timeout 300 | Out-Null
            $profilerJob | Remove-Job -Force
        }
        
        # Generate analysis and reports
        if ($allResults.Count -gt 0) {
            Write-Log "Generating performance analysis and reports..." "INFO"
            
            # Performance analysis
            $baselineFile = if ($Baseline -and (Test-Path $Baseline)) { $Baseline } else { $null }
            Invoke-PerformanceAnalysis -ResultsFiles $allResults -BaselineFile $baselineFile
            
            # Generate reports
            if ($ReportFormat -in @("html", "both")) {
                $htmlReportPath = Join-Path $RESULTS_DIR "performance-report-$TIMESTAMP.html"
                New-HTMLReport -ResultsFiles $allResults -OutputPath $htmlReportPath
            }
            
            # Summary
            Write-Log "=== Performance Test Summary ===" "SUCCESS"
            Write-Log "Total test suites executed: $($allResults.Count)" "INFO"
            Write-Log "Results directory: $RESULTS_DIR" "INFO"
            Write-Log "Logs directory: $LOGS_DIR" "INFO"
            
            if ($allResults.Count -gt 0) {
                Write-Log "✓ Performance testing completed successfully!" "SUCCESS"
                exit 0
            } else {
                Write-Log "⚠ Some tests may have failed. Check logs for details." "WARN"
                exit 1
            }
        } else {
            Write-Log "No test results generated. Check logs for errors." "ERROR"
            exit 1
        }
        
    } catch {
        Write-Log "Performance testing failed with error: $_" "ERROR"
        
        # Clean up profiler job if running
        if ($profilerJob) {
            $profilerJob | Stop-Job -Force
            $profilerJob | Remove-Job -Force
        }
        
        exit 1
    }
}

# Execute main function
Main
