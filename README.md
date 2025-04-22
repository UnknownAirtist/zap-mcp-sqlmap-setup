# ZAP MCP Server with SQLMap Integration Setup Guide

This repository contains setup instructions and configuration files for using OWASP ZAP as an MCP (Man-in-the-middle Proxy) server with SQLMap integration for legitimate security testing and vulnerability assessment.

## Prerequisites

- Docker installed on your system
- Basic understanding of web security testing
- Administrator/root access to your system

## Quick Setup

### 1. Clone this repository:

```bash
git clone https://github.com/UnknownAirtist/zap-mcp-sqlmap-setup.git
cd zap-mcp-sqlmap-setup
```

### 2. Run the setup script:

```bash
chmod +x setup.sh
./setup.sh
```

### 3. Start the ZAP MCP server:

```bash
docker-compose up -d
```

This will start the ZAP server on port 8080 and the API on port 8090.

## Manual Setup

### 1. Install OWASP ZAP

You can install ZAP using Docker (recommended):

```bash
docker pull owasp/zap2docker-stable
```

Or download it directly from the [official website](https://www.zaproxy.org/download/).

### 2. Install SQLMap

SQLMap can be installed from the repository:

```bash
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git
```

### 3. Configure ZAP as an MCP server:

Start ZAP in daemon mode:

```bash
docker run -u zap -p 8080:8080 -p 8090:8090 -i owasp/zap2docker-stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true
```

### 4. Set up SQLMap with ZAP:

Use SQLMap with ZAP as a proxy:

```bash
python sqlmap.py -u "http://target-website.com" --proxy=http://localhost:8080
```

## Advanced Configuration

### Custom ZAP Rules

The `zap-rules` directory contains custom ZAP rules for improving detection of SQL injection vulnerabilities:

- Copy the `.js` files to the ZAP scripts directory
- Enable them in the ZAP UI under Tools > Scripts

### SQLMap Integration Scripts

The `sqlmap-scripts` directory contains helper scripts for tighter integration:

- `zap-sqlmap-bridge.py`: Forwards ZAP findings to SQLMap for deeper testing
- `auto-scan.py`: Automated scanning of all forms found on a target site

## Usage Examples

### Basic Scan

```bash
./scripts/start-scan.sh http://example.com
```

### Full Scan with SQLMap Integration

```bash
./scripts/full-scan.sh http://vulnerable-website.com
```

### Continuous Integration Setup

See the `ci-example` directory for GitHub Actions and Jenkins configuration examples.

## Security Considerations

⚠️ **IMPORTANT**: Only use these tools on systems you own or have explicit permission to test. Unauthorized security testing is illegal in most jurisdictions.

## Troubleshooting

- Check `logs/zap.log` for ZAP-related issues
- Check `logs/sqlmap.log` for SQLMap-related issues
- If the server is not responding, ensure ports 8080 and 8090 are not in use by other applications

## License

This project is licensed under the MIT License - see the LICENSE file for details.
