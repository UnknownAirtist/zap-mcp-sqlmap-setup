#!/bin/bash

# ZAP MCP Server with SQLMap Integration Setup Script
# This script sets up the necessary directories and configurations

set -e

echo "Setting up ZAP MCP Server with SQLMap Integration..."

# Create necessary directories
mkdir -p zap-data
mkdir -p zap-scripts
mkdir -p sqlmap-data
mkdir -p sqlmap-output
mkdir -p logs

# Set permissions
chmod 777 zap-data
chmod 777 zap-scripts
chmod 777 sqlmap-data
chmod 777 sqlmap-output
chmod 777 logs

# Create basic ZAP scripts directory structure
mkdir -p zap-scripts/active
mkdir -p zap-scripts/passive
mkdir -p zap-scripts/standalone

# Create default configuration files
echo "# ZAP Configuration
api.disablekey=true
api.addrs.addr.name=.*
api.addrs.addr.regex=true
connection.timeoutInSecs=120
scanner.threadPerHost=5" > zap-data/config.properties

# Create SQLMap helper script
cat > scripts/zap-sqlmap-bridge.py << 'EOF'
#!/usr/bin/env python3
"""
ZAP to SQLMap bridge script.
This script forwards ZAP findings to SQLMap for deeper testing.
"""
import json
import os
import sys
import argparse
import subprocess
import requests

def get_zap_alerts(zap_api_url):
    """Get alerts from ZAP API"""
    try:
        response = requests.get(f"{zap_api_url}/JSON/alert/view/alerts")
        return response.json()
    except Exception as e:
        print(f"Error getting ZAP alerts: {e}")
        return None

def run_sqlmap(target_url, proxy="http://localhost:8080"):
    """Run SQLMap against the target URL"""
    cmd = [
        "sqlmap",
        "-u", target_url,
        "--proxy", proxy,
        "--batch",
        "--forms",
        "--crawl=3",
        "--level=3",
        "--risk=2",
        "-o"
    ]
    
    print(f"Running SQLMap: {' '.join(cmd)}")
    subprocess.run(cmd)

def main():
    parser = argparse.ArgumentParser(description="ZAP to SQLMap bridge")
    parser.add_argument("--target", required=True, help="Target URL to scan")
    parser.add_argument("--zap-api", default="http://localhost:8090", help="ZAP API URL")
    parser.add_argument("--zap-proxy", default="http://localhost:8080", help="ZAP proxy URL")
    
    args = parser.parse_args()
    
    # First, check if there are SQL injection alerts from ZAP
    alerts = get_zap_alerts(args.zap_api)
    if alerts and "alerts" in alerts:
        sql_alerts = [a for a in alerts["alerts"] if "sql" in a["name"].lower()]
        if sql_alerts:
            print(f"Found {len(sql_alerts)} SQL injection alerts from ZAP")
            
    # Run SQLMap through the ZAP proxy
    run_sqlmap(args.target, args.zap_proxy)

if __name__ == "__main__":
    main()
EOF

# Create utility scripts directory
mkdir -p scripts
chmod +x scripts/zap-sqlmap-bridge.py

# Create start scan script
cat > scripts/start-scan.sh << 'EOF'
#!/bin/bash

if [ $# -lt 1 ]; then
    echo "Usage: $0 <target-url>"
    exit 1
fi

TARGET=$1

echo "Starting ZAP scan against $TARGET"
curl -s "http://localhost:8090/JSON/spider/action/scan/?url=$TARGET" | jq .

echo "Waiting for the scan to complete..."
sleep 30

echo "Running active scan..."
curl -s "http://localhost:8090/JSON/ascan/action/scan/?url=$TARGET" | jq .

echo "Scan started successfully. Use SQLMap integration for deeper testing."
EOF

chmod +x scripts/start-scan.sh

# Create full scan script with SQLMap integration
cat > scripts/full-scan.sh << 'EOF'
#!/bin/bash

if [ $# -lt 1 ]; then
    echo "Usage: $0 <target-url>"
    exit 1
fi

TARGET=$1

# Start ZAP scanning
echo "Starting ZAP scan against $TARGET"
curl -s "http://localhost:8090/JSON/spider/action/scan/?url=$TARGET" | jq .

echo "Waiting for the spider to complete..."
sleep 30

echo "Running active scan..."
curl -s "http://localhost:8090/JSON/ascan/action/scan/?url=$TARGET" | jq .

echo "Waiting for the active scan to complete..."
sleep 60

# Run SQLMap through ZAP
echo "Starting SQLMap scan through ZAP..."
docker exec sqlmap python /opt/sqlmap/sqlmap.py -u "$TARGET" --proxy=http://zap:8080 --batch --forms

echo "Scan completed!"
EOF

chmod +x scripts/full-scan.sh

echo "Setup completed successfully!"
echo "To start the ZAP MCP server, run: docker-compose up -d"
echo "After starting, you can run scans using the scripts in the scripts directory."
