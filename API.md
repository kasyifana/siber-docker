# API Documentation

## MCP Tools Reference

### 1. port_scan

Perform network port scanning on target.

**Parameters:**
- `target` (string, required): IP address or hostname
- `ports` (string, optional): Port range (default: "1-1000")
  - Examples: "80,443", "1-1000", "1-65535"
- `scan_type` (string, optional): Scan type (default: "quick")
  - Options: "quick", "full", "stealth", "version"

**Returns:**
```json
{
  "target": "example.com",
  "scan_time": "2.5s",
  "open_ports": [
    {
      "port": "80",
      "protocol": "tcp",
      "service": "http",
      "version": "Apache 2.4.41",
      "product": "Apache httpd"
    }
  ],
  "status": "completed"
}
```

**Example Usage:**
```
"Scan port 80,443,8080 pada example.com"
"Quick scan pada 192.168.1.1"
"Full port scan pada target.com"
```

---

### 2. sql_injection_test

Test for SQL injection vulnerabilities.

**Parameters:**
- `url` (string, required): Target URL with parameters
- `parameters` (string, optional): Specific parameters to test (comma-separated)
- `database` (string, optional): Database type (default: "auto")
  - Options: "auto", "mysql", "postgres", "mssql", "oracle", "sqlite"

**Returns:**
```json
{
  "url": "https://example.com/page?id=1",
  "vulnerable": true,
  "vulnerabilities": [
    {
      "parameter": "id",
      "injection_type": "boolean-based blind",
      "database": "MySQL",
      "payload": "1 AND 1=1",
      "risk_level": "critical"
    }
  ]
}
```

**Example Usage:**
```
"Test SQL injection pada https://site.com/products?id=1"
"Check SQLi vulnerability di https://site.com/login"
```

---

### 3. web_vuln_scan

Comprehensive web vulnerability scanning using Nikto.

**Parameters:**
- `url` (string, required): Target URL
- `scan_depth` (string, optional): Depth of scan (default: "standard")
  - Options: "quick", "standard", "thorough"

**Returns:**
```json
{
  "target": "https://example.com",
  "vulnerability_count": 15,
  "vulnerabilities": [
    {
      "title": "Directory listing enabled",
      "severity": "medium",
      "path": "/uploads/",
      "description": "...",
      "references": ["OSVDB-12345"]
    }
  ]
}
```

**Example Usage:**
```
"Scan web vulnerabilities pada https://example.com"
"Thorough web scan pada https://target.com"
```

---

### 4. xss_test

Test for Cross-Site Scripting vulnerabilities.

**Parameters:**
- `url` (string, required): Target URL
- `parameters` (array, required): List of parameters to test
- `payload_type` (string, optional): Type of XSS payloads (default: "all")
  - Options: "reflected", "stored", "dom", "all"

**Returns:**
```json
{
  "url": "https://example.com/search",
  "vulnerable": true,
  "vulnerabilities": [
    {
      "parameter": "q",
      "payload": "<script>alert(1)</script>",
      "type": "reflected",
      "context": "html_body",
      "severity": "high"
    }
  ]
}
```

**Example Usage:**
```
"Test XSS pada https://site.com/search?q="
"Check reflected XSS di parameter 'name' pada https://site.com/form"
```

---

### 5. enumerate_subdomains

Discover subdomains of target domain.

**Parameters:**
- `domain` (string, required): Target domain (e.g., "example.com")
- `method` (string, optional): Enumeration method (default: "all")
  - Options: "dns", "certificate", "brute", "all"

**Returns:**
```json
{
  "domain": "example.com",
  "count": 15,
  "subdomains": [
    {
      "name": "www.example.com",
      "ip": "93.184.216.34",
      "status": "200 OK"
    },
    {
      "name": "api.example.com",
      "ip": "93.184.216.35",
      "status": "200 OK"
    }
  ]
}
```

**Example Usage:**
```
"Find subdomains untuk example.com"
"Enumerate subdomains dengan DNS method pada target.com"
```

---

### 6. analyze_ssl

Analyze SSL/TLS configuration and certificate.

**Parameters:**
- `hostname` (string, required): Target hostname
- `port` (integer, optional): SSL port (default: 443)

**Returns:**
```json
{
  "hostname": "example.com",
  "port": 443,
  "grade": "A",
  "certificate": {
    "issuer": "Let's Encrypt",
    "valid_until": "2024-12-31",
    "signature_algorithm": "sha256WithRSAEncryption",
    "key_size": 2048
  },
  "protocols": [
    {"name": "TLSv1.2", "status": "supported", "secure": true},
    {"name": "TLSv1.3", "status": "supported", "secure": true}
  ],
  "issues": []
}
```

**Example Usage:**
```
"Analyze SSL certificate untuk example.com"
"Check TLS configuration pada target.com:8443"
```

---

### 7. check_security_headers

Analyze HTTP security headers.

**Parameters:**
- `url` (string, required): Target URL

**Returns:**
```json
{
  "url": "https://example.com",
  "score": 85,
  "headers": {
    "Strict-Transport-Security": {
      "present": true,
      "value": "max-age=31536000",
      "assessment": "Strong"
    },
    "Content-Security-Policy": {
      "present": false,
      "impact": "XSS attacks, data injection",
      "severity": "high"
    }
  },
  "issues": [
    "Missing Content-Security-Policy"
  ]
}
```

**Example Usage:**
```
"Check security headers pada https://example.com"
"Analyze HTTP headers untuk https://target.com"
```

---

### 8. full_security_audit

Comprehensive security audit (runs all tools).

**Parameters:**
- `target` (string, required): Target URL or domain
- `scope` (string, optional): Audit scope (default: "standard")
  - Options: "quick", "standard", "thorough"

**Returns:**
```markdown
# Security Audit Report

**Target:** https://example.com
**Scan Date:** 2024-11-07 12:00:00
**Scope:** standard

## Executive Summary
Total Vulnerabilities: 8
- Critical: 1
- High: 2
- Medium: 3
- Low: 2

## Findings by Severity
...

## Detailed Findings
...

## Recommendations
...
```

**Example Usage:**
```
"Lakukan full security audit pada https://example.com"
"Comprehensive scan dengan scope thorough pada https://target.com"
```

---

### 9. generate_report

Generate detailed report from previous scan.

**Parameters:**
- `scan_id` (string, required): Scan identifier
- `format` (string, optional): Report format (default: "markdown")
  - Options: "markdown", "html", "pdf", "json"

**Returns:**
Report in requested format.

**Example Usage:**
```
"Generate PDF report untuk scan ID 12345"
"Create HTML report dari last scan"
```

---

## Response Format

All tools return responses in this structure:

```json
{
  "type": "text",
  "text": "Formatted results in markdown"
}
```

## Error Handling

If an error occurs:

```json
{
  "type": "text",
  "text": "Error: [error message]"
}
```

Common errors:
- `Invalid target`: Target validation failed
- `Scan timeout`: Scan took too long
- `Tool error`: Security tool execution failed
- `Permission denied`: Insufficient permissions

## Rate Limiting

- Maximum concurrent scans: 5 (configurable)
- Scan timeout: 300 seconds (configurable)
- Rate limit: 100 requests per 60 seconds

## Security Considerations

### Blocked Targets
- Private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Localhost (127.0.0.0/8)
- Link-local addresses (169.254.0.0/16)
- Multicast addresses

### Input Validation
All inputs are validated and sanitized to prevent:
- Command injection
- Path traversal
- SQL injection in parameters
- XSS in output

### Audit Logging
All scans are logged with:
- Timestamp
- Target
- Tools used
- User/session
- Results summary

---

## Best Practices

### 1. Progressive Testing
Start with less intrusive scans:
```
1. check_security_headers
2. analyze_ssl
3. port_scan (quick)
4. web_vuln_scan (standard)
5. full_security_audit (if needed)
```

### 2. Authorization
Always get written authorization before scanning:
- Own your targets
- Have explicit permission
- Follow bug bounty program rules
- Respect scope limitations

### 3. Responsible Disclosure
If vulnerabilities found:
1. Document findings
2. Contact security team
3. Give time to fix
4. Don't disclose publicly before fix

### 4. Rate Limiting
Don't overwhelm targets:
- Use appropriate scan depths
- Space out scans
- Monitor target response
- Respect robots.txt

---

## Integration Examples

### Python
```python
import asyncio
from mcp import Client

async def scan_target():
    client = Client("security-audit")
    
    result = await client.call_tool(
        "port_scan",
        {
            "target": "example.com",
            "ports": "80,443",
            "scan_type": "quick"
        }
    )
    
    print(result)

asyncio.run(scan_target())
```

### Claude Desktop
```json
// ~/.config/Claude/claude_desktop_config.json
{
  "mcpServers": {
    "security-audit": {
      "command": "docker",
      "args": ["exec", "-i", "mcp-security-server", "python", "-m", "src.server"]
    }
  }
}
```

---

## Support

For issues or questions:
1. Check logs: `make logs`
2. Review this documentation
3. Check README.md
4. Verify target permissions

---

**Last Updated:** November 7, 2024
**Version:** 1.0.0
