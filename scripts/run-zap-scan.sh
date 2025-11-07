#!/bin/bash
# OWASP ZAP Security Scan Script for Linux/Mac
# This script runs a comprehensive security scan using OWASP ZAP

set -e

# Configuration
TARGET_URL="${TARGET_URL:-http://localhost:5118}"
ZAP_HOST="${ZAP_HOST:-localhost}"
ZAP_PORT="${ZAP_PORT:-8080}"
TIMEOUT_MINUTES="${TIMEOUT_MINUTES:-30}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}=========================================${NC}"
echo -e "${CYAN}OWASP ZAP Security Scan${NC}"
echo -e "${CYAN}=========================================${NC}"
echo -e "${YELLOW}Target URL: ${TARGET_URL}${NC}"
echo -e "${YELLOW}ZAP Host: ${ZAP_HOST}:${ZAP_PORT}${NC}"
echo ""

# Check if ZAP is running
echo -e "${CYAN}Checking ZAP connection...${NC}"
ZAP_VERSION=$(curl -s "http://${ZAP_HOST}:${ZAP_PORT}/JSON/core/view/version/" | grep -o '"version":"[^"]*"' | cut -d'"' -f4)

if [ -z "$ZAP_VERSION" ]; then
    echo -e "${RED}ERROR: Cannot connect to ZAP at ${ZAP_HOST}:${ZAP_PORT}${NC}"
    echo -e "${YELLOW}Please ensure ZAP is running:${NC}"
    echo -e "${YELLOW}  docker run -d -p 8080:8080 owasp/zap2docker-stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true${NC}"
    exit 1
fi

echo -e "${GREEN}ZAP Version: ${ZAP_VERSION}${NC}"

# ZAP API base URL
ZAP_API_URL="http://${ZAP_HOST}:${ZAP_PORT}"

# Function to call ZAP API
zap_api_call() {
    local endpoint="$1"
    local method="${2:-GET}"
    local params="$3"
    
    local url="${ZAP_API_URL}${endpoint}"
    if [ -n "$params" ]; then
        url="${url}?${params}"
    fi
    
    curl -s -X "$method" "$url"
}

# Start spider scan
echo -e "${CYAN}Starting spider scan...${NC}"
SPIDER_RESPONSE=$(zap_api_call "/JSON/spider/action/scan/" "GET" "url=${TARGET_URL}&maxChildren=10&recurse=true&subtreeOnly=false")
SPIDER_SCAN_ID=$(echo "$SPIDER_RESPONSE" | grep -o '"scan":"[^"]*"' | cut -d'"' -f4)

if [ -z "$SPIDER_SCAN_ID" ]; then
    echo -e "${RED}ERROR: Failed to start spider scan${NC}"
    exit 1
fi

echo -e "${GREEN}Spider scan started with ID: ${SPIDER_SCAN_ID}${NC}"

# Wait for spider scan to complete
echo -e "${CYAN}Waiting for spider scan to complete...${NC}"
SPIDER_COMPLETE=false
SPIDER_START_TIME=$(date +%s)
TIMEOUT_SECONDS=$((TIMEOUT_MINUTES * 60))

while [ "$SPIDER_COMPLETE" = false ]; do
    sleep 5
    
    SPIDER_STATUS=$(zap_api_call "/JSON/spider/view/status/" "GET" "scanId=${SPIDER_SCAN_ID}")
    PROGRESS=$(echo "$SPIDER_STATUS" | grep -o '"status":"[^"]*"' | cut -d'"' -f4 | sed 's/%//')
    
    if [ -n "$PROGRESS" ]; then
        echo -e "${YELLOW}Spider progress: ${PROGRESS}%${NC}"
        
        if [ "$PROGRESS" -ge 100 ]; then
            SPIDER_COMPLETE=true
            echo -e "${GREEN}Spider scan completed!${NC}"
        fi
    fi
    
    CURRENT_TIME=$(date +%s)
    ELAPSED=$((CURRENT_TIME - SPIDER_START_TIME))
    
    if [ $ELAPSED -gt $TIMEOUT_SECONDS ]; then
        echo -e "${YELLOW}WARNING: Spider scan timeout reached${NC}"
        break
    fi
done

# Start active scan
echo -e "${CYAN}Starting active scan...${NC}"
ACTIVE_RESPONSE=$(zap_api_call "/JSON/ascan/action/scan/" "GET" "url=${TARGET_URL}&recurse=true&inScopeOnly=false&scanPolicyName=Default Policy")
ACTIVE_SCAN_ID=$(echo "$ACTIVE_RESPONSE" | grep -o '"scan":"[^"]*"' | cut -d'"' -f4)

if [ -z "$ACTIVE_SCAN_ID" ]; then
    echo -e "${RED}ERROR: Failed to start active scan${NC}"
    exit 1
fi

echo -e "${GREEN}Active scan started with ID: ${ACTIVE_SCAN_ID}${NC}"

# Wait for active scan to complete
echo -e "${CYAN}Waiting for active scan to complete...${NC}"
ACTIVE_COMPLETE=false
ACTIVE_START_TIME=$(date +%s)

while [ "$ACTIVE_COMPLETE" = false ]; do
    sleep 10
    
    ACTIVE_STATUS=$(zap_api_call "/JSON/ascan/view/status/" "GET" "scanId=${ACTIVE_SCAN_ID}")
    PROGRESS=$(echo "$ACTIVE_STATUS" | grep -o '"status":"[^"]*"' | cut -d'"' -f4 | sed 's/%//')
    
    if [ -n "$PROGRESS" ]; then
        echo -e "${YELLOW}Active scan progress: ${PROGRESS}%${NC}"
        
        if [ "$PROGRESS" -ge 100 ]; then
            ACTIVE_COMPLETE=true
            echo -e "${GREEN}Active scan completed!${NC}"
        fi
    fi
    
    CURRENT_TIME=$(date +%s)
    ELAPSED=$((CURRENT_TIME - ACTIVE_START_TIME))
    
    if [ $ELAPSED -gt $TIMEOUT_SECONDS ]; then
        echo -e "${YELLOW}WARNING: Active scan timeout reached${NC}"
        break
    fi
done

# Generate reports
echo -e "${CYAN}Generating reports...${NC}"

TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
REPORT_DIR="reports/zap"
mkdir -p "$REPORT_DIR"

# HTML Report
HTML_REPORT=$(zap_api_call "/OTHER/core/other/htmlreport/")
HTML_REPORT_PATH="${REPORT_DIR}/zap-report-${TIMESTAMP}.html"
echo "$HTML_REPORT" > "$HTML_REPORT_PATH"
echo -e "${GREEN}HTML report saved: ${HTML_REPORT_PATH}${NC}"

# JSON Report
JSON_REPORT=$(zap_api_call "/JSON/core/view/alerts/" "GET" "baseurl=${TARGET_URL}")
JSON_REPORT_PATH="${REPORT_DIR}/zap-report-${TIMESTAMP}.json"
echo "$JSON_REPORT" | jq '.' > "$JSON_REPORT_PATH" 2>/dev/null || echo "$JSON_REPORT" > "$JSON_REPORT_PATH"
echo -e "${GREEN}JSON report saved: ${JSON_REPORT_PATH}${NC}"

# Summary
echo ""
echo -e "${CYAN}=========================================${NC}"
echo -e "${CYAN}Scan Summary${NC}"
echo -e "${CYAN}=========================================${NC}"

if command -v jq &> /dev/null; then
    HIGH_COUNT=$(echo "$JSON_REPORT" | jq '[.alerts[] | select(.risk == "High")] | length')
    MEDIUM_COUNT=$(echo "$JSON_REPORT" | jq '[.alerts[] | select(.risk == "Medium")] | length')
    LOW_COUNT=$(echo "$JSON_REPORT" | jq '[.alerts[] | select(.risk == "Low")] | length')
    INFO_COUNT=$(echo "$JSON_REPORT" | jq '[.alerts[] | select(.risk == "Informational")] | length')
    TOTAL_COUNT=$(echo "$JSON_REPORT" | jq '.alerts | length')
    
    echo -e "High Risk: ${HIGH_COUNT}"
    echo -e "Medium Risk: ${MEDIUM_COUNT}"
    echo -e "Low Risk: ${LOW_COUNT}"
    echo -e "Informational: ${INFO_COUNT}"
    echo -e "${CYAN}Total Alerts: ${TOTAL_COUNT}${NC}"
else
    echo -e "${YELLOW}Install jq for detailed summary${NC}"
fi

echo ""
echo -e "${CYAN}Reports available in: ${REPORT_DIR}${NC}"
echo -e "${GREEN}Scan completed!${NC}"

