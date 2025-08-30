#!/bin/bash

# ZAP Security Scanner Runner
# Usage: ./run-zap-scan.sh <URL> [scan-type]
# Example: ./run-zap-scan.sh https://dev-journal.netlify.app/about/ baseline

# Check if URL is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <URL> [scan-type]"
    echo "scan-type options: baseline (default), full"
    echo "Example: $0 https://dev-journal.netlify.app/about/ baseline"
    exit 1
fi

TARGET_URL=$1
SCAN_TYPE=${2:-baseline}

# Validate scan type
if [ "$SCAN_TYPE" != "baseline" ] && [ "$SCAN_TYPE" != "full" ]; then
    echo "Error: scan-type must be either 'baseline' or 'full'"
    exit 1
fi

echo "Starting ZAP $SCAN_TYPE scan for: $TARGET_URL"
echo "Reports will be saved in ./zap-reports/"

# Create reports directory if it doesn't exist
mkdir -p zap-reports

# Export environment variables and run docker compose
export TARGET_URL=$TARGET_URL
export SCAN_TYPE=$SCAN_TYPE

# Run the scan
docker compose up --build

echo ""
echo "Scan completed! Check the reports in ./zap-reports/"
echo "- HTML Report: ./zap-reports/zap-report.html"
echo "- Markdown Report: ./zap-reports/zap-report.md" 
echo "- JSON Report: ./zap-reports/zap-report.json"
