# OWASP ZAP Security Scan Script for Windows
# This script runs a comprehensive security scan using OWASP ZAP

param(
    [string]$TargetUrl = "http://localhost:5118",
    [string]$ZapHost = "localhost",
    [int]$ZapPort = 8080,
    [int]$TimeoutMinutes = 30
)

$ErrorActionPreference = "Stop"

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "OWASP ZAP Security Scan" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Target URL: $TargetUrl" -ForegroundColor Yellow
Write-Host "ZAP Host: $ZapHost:$ZapPort" -ForegroundColor Yellow
Write-Host ""

# Check if ZAP is running
Write-Host "Checking ZAP connection..." -ForegroundColor Cyan
try {
    $zapStatus = Invoke-RestMethod -Uri "http://${ZapHost}:${ZapPort}/JSON/core/view/version/" -Method Get -ErrorAction Stop
    Write-Host "ZAP Version: $($zapStatus.version)" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Cannot connect to ZAP at $ZapHost:$ZapPort" -ForegroundColor Red
    Write-Host "Please ensure ZAP is running:" -ForegroundColor Yellow
    Write-Host "  docker run -d -p 8080:8080 owasp/zap2docker-stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true" -ForegroundColor Yellow
    exit 1
}

# Set ZAP API base URL
$zapApiUrl = "http://${ZapHost}:${ZapPort}"

# Function to call ZAP API
function Invoke-ZapApi {
    param(
        [string]$Endpoint,
        [string]$Method = "GET",
        [hashtable]$Params = @{}
    )
    
    $url = "$zapApiUrl$Endpoint"
    if ($Params.Count -gt 0) {
        $queryString = ($Params.GetEnumerator() | ForEach-Object { "$($_.Key)=$([System.Web.HttpUtility]::UrlEncode($_.Value))" }) -join "&"
        $url += "?$queryString"
    }
    
    try {
        return Invoke-RestMethod -Uri $url -Method $Method -ErrorAction Stop
    } catch {
        Write-Host "API Error: $_" -ForegroundColor Red
        return $null
    }
}

# Start spider scan
Write-Host "Starting spider scan..." -ForegroundColor Cyan
$spiderScan = Invoke-ZapApi -Endpoint "/JSON/spider/action/scan/" -Method "GET" -Params @{
    url = $TargetUrl
    maxChildren = "10"
    recurse = "true"
    subtreeOnly = "false"
}

if ($spiderScan.scan -eq $null) {
    Write-Host "ERROR: Failed to start spider scan" -ForegroundColor Red
    exit 1
}

$spiderScanId = $spiderScan.scan
Write-Host "Spider scan started with ID: $spiderScanId" -ForegroundColor Green

# Wait for spider scan to complete
Write-Host "Waiting for spider scan to complete..." -ForegroundColor Cyan
$spiderComplete = $false
$spiderStartTime = Get-Date
$spiderTimeout = New-TimeSpan -Minutes $TimeoutMinutes

while (-not $spiderComplete) {
    Start-Sleep -Seconds 5
    
    $spiderStatus = Invoke-ZapApi -Endpoint "/JSON/spider/view/status/" -Params @{ scanId = $spiderScanId }
    
    if ($spiderStatus.status -ne $null) {
        $progress = [int]$spiderStatus.status
        Write-Host "Spider progress: $progress%" -ForegroundColor Yellow
        
        if ($progress -ge 100) {
            $spiderComplete = $true
            Write-Host "Spider scan completed!" -ForegroundColor Green
        }
    }
    
    if ((Get-Date) - $spiderStartTime -gt $spiderTimeout) {
        Write-Host "WARNING: Spider scan timeout reached" -ForegroundColor Yellow
        break
    }
}

# Start active scan
Write-Host "Starting active scan..." -ForegroundColor Cyan
$activeScan = Invoke-ZapApi -Endpoint "/JSON/ascan/action/scan/" -Method "GET" -Params @{
    url = $TargetUrl
    recurse = "true"
    inScopeOnly = "false"
    scanPolicyName = "Default Policy"
}

if ($activeScan.scan -eq $null) {
    Write-Host "ERROR: Failed to start active scan" -ForegroundColor Red
    exit 1
}

$activeScanId = $activeScan.scan
Write-Host "Active scan started with ID: $activeScanId" -ForegroundColor Green

# Wait for active scan to complete
Write-Host "Waiting for active scan to complete..." -ForegroundColor Cyan
$activeComplete = $false
$activeStartTime = Get-Date

while (-not $activeComplete) {
    Start-Sleep -Seconds 10
    
    $activeStatus = Invoke-ZapApi -Endpoint "/JSON/ascan/view/status/" -Params @{ scanId = $activeScanId }
    
    if ($activeStatus.status -ne $null) {
        $progress = [int]$activeStatus.status
        Write-Host "Active scan progress: $progress%" -ForegroundColor Yellow
        
        if ($progress -ge 100) {
            $activeComplete = $true
            Write-Host "Active scan completed!" -ForegroundColor Green
        }
    }
    
    if ((Get-Date) - $activeStartTime -gt $spiderTimeout) {
        Write-Host "WARNING: Active scan timeout reached" -ForegroundColor Yellow
        break
    }
}

# Generate reports
Write-Host "Generating reports..." -ForegroundColor Cyan

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$reportDir = "reports/zap"
if (-not (Test-Path $reportDir)) {
    New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
}

# HTML Report
$htmlReport = Invoke-ZapApi -Endpoint "/OTHER/core/other/htmlreport/" -Method "GET"
$htmlReportPath = "$reportDir/zap-report-$timestamp.html"
[System.IO.File]::WriteAllText($htmlReportPath, $htmlReport)
Write-Host "HTML report saved: $htmlReportPath" -ForegroundColor Green

# JSON Report
$jsonReport = Invoke-ZapApi -Endpoint "/JSON/core/view/alerts/" -Method "GET" -Params @{ baseurl = $TargetUrl }
$jsonReportPath = "$reportDir/zap-report-$timestamp.json"
$jsonReport | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonReportPath -Encoding UTF8
Write-Host "JSON report saved: $jsonReportPath" -ForegroundColor Green

# Summary
Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Scan Summary" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

$alerts = $jsonReport.alerts
if ($alerts) {
    $highCount = ($alerts | Where-Object { $_.risk -eq "High" }).Count
    $mediumCount = ($alerts | Where-Object { $_.risk -eq "Medium" }).Count
    $lowCount = ($alerts | Where-Object { $_.risk -eq "Low" }).Count
    $infoCount = ($alerts | Where-Object { $_.risk -eq "Informational" }).Count
    
    Write-Host "High Risk: $highCount" -ForegroundColor $(if ($highCount -gt 0) { "Red" } else { "Green" })
    Write-Host "Medium Risk: $mediumCount" -ForegroundColor $(if ($mediumCount -gt 0) { "Yellow" } else { "Green" })
    Write-Host "Low Risk: $lowCount" -ForegroundColor Green
    Write-Host "Informational: $infoCount" -ForegroundColor Green
    Write-Host "Total Alerts: $($alerts.Count)" -ForegroundColor Cyan
} else {
    Write-Host "No alerts found" -ForegroundColor Green
}

Write-Host ""
Write-Host "Reports available in: $reportDir" -ForegroundColor Cyan
Write-Host "Scan completed!" -ForegroundColor Green

