# MCP Security Audit Server - Usage Guide

## Quick Start Guide

### 1. Start the Server

```bash
# Make scripts executable
chmod +x start.sh stop.sh logs.sh test.sh

# Start all services
./start.sh
```

### 2. Configure Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) atau file konfigurasi sesuai OS Anda:

```json
{
  "mcpServers": {
    "security-audit": {
      "command": "docker",
      "args": [
        "exec",
        "-i",
        "mcp-security-server",
        "python",
        "-m",
        "src.server"
      ]
    }
  }
}
```

### 3. Restart Claude Desktop

Setelah menambahkan konfigurasi, restart Claude Desktop.

## Common Use Cases

### Example 1: Basic Port Scan

**You:** "Scan port pada target example.com"

**Claude:** (memanggil `port_scan` tool)
```
Target: example.com
Open ports found:
- Port 80 (HTTP)
- Port 443 (HTTPS)
```

### Example 2: Check Security Headers

**You:** "Check security headers pada https://example.com"

**Claude:** (memanggil `check_security_headers` tool)
```
Security Score: 65/100

Missing Headers:
❌ Content-Security-Policy
❌ Strict-Transport-Security

Present Headers:
✓ X-Frame-Options: SAMEORIGIN
✓ X-Content-Type-Options: nosniff
```

### Example 3: Full Security Audit

**You:** "Lakukan comprehensive security audit pada https://example.com"

**Claude:** (memanggil `full_security_audit` tool)
```
Running full security audit...

1. Port Scanning... ✓
2. SSL/TLS Analysis... ✓
3. Security Headers Check... ✓
4. Subdomain Enumeration... ✓
5. Web Vulnerability Scan... ✓

Results:
- 3 Critical vulnerabilities
- 5 High severity issues
- 12 Medium severity issues
- 8 Low severity issues

Detailed report generated.
```

### Example 4: Test SQL Injection

**You:** "Test SQL injection pada https://example.com/products?id=1"

**Claude:** (memanggil `sql_injection_test` tool)
```
Testing URL: https://example.com/products?id=1
Parameter: id

⚠️ VULNERABLE!

Type: Boolean-based blind SQL injection
Database: MySQL
Risk Level: Critical

Payload: 1 AND 1=1
```

### Example 5: Enumerate Subdomains

**You:** "Find subdomains untuk example.com"

**Claude:** (memanggil `enumerate_subdomains` tool)
```
Found 15 subdomains:

1. www.example.com (93.184.216.34)
2. api.example.com (93.184.216.35)
3. admin.example.com (93.184.216.36)
4. dev.example.com (unreachable)
5. staging.example.com (93.184.216.38)
...
```

### Example 6: SSL/TLS Analysis

**You:** "Analyze SSL certificate untuk example.com"

**Claude:** (memanggil `analyze_ssl` tool)
```
SSL/TLS Analysis Results

Grade: A

Certificate:
- Issuer: Let's Encrypt
- Valid Until: 2024-12-31
- Key Size: 2048 bits

Supported Protocols:
✓ TLS 1.2
✓ TLS 1.3
❌ TLS 1.0 (disabled - good)
❌ TLS 1.1 (disabled - good)

No critical issues found.
```

## Advanced Usage

### Custom Scan Parameters

**You:** "Scan port 1-10000 pada target.com dengan stealth mode"

```json
{
  "tool": "port_scan",
  "parameters": {
    "target": "target.com",
    "ports": "1-10000",
    "scan_type": "stealth"
  }
}
```

### XSS Testing with Custom Payloads

**You:** "Test XSS pada https://site.com/search?q= dengan reflected payloads"

```json
{
  "tool": "xss_test",
  "parameters": {
    "url": "https://site.com/search",
    "parameters": ["q"],
    "payload_type": "reflected"
  }
}
```

### Thorough Web Vulnerability Scan

**You:** "Lakukan thorough scan pada https://target.com"

```json
{
  "tool": "web_vuln_scan",
  "parameters": {
    "url": "https://target.com",
    "scan_depth": "thorough"
  }
}
```

## Tips & Best Practices

### 1. Always Get Permission
```
❌ "Scan google.com"
✓ "Scan testsite.mydomain.com" (jika Anda pemiliknya)
```

### 2. Start with Quick Scans
```
✓ "Quick scan pada example.com"
   (lebih cepat, overview)
   
✓ "Thorough scan pada example.com"
   (jika perlu detail lengkap)
```

### 3. Progressive Testing
```
1. "Check security headers dulu"
2. "Scan port yang terbuka"
3. "Test SQL injection pada endpoint yang ditemukan"
4. "Full audit untuk comprehensive report"
```

### 4. Understand Output
```
Critical = Segera perbaiki
High = Prioritas tinggi
Medium = Perbaiki dalam sprint berikutnya
Low = Perbaiki jika sempat
```

## Viewing Results

### Check Logs
```bash
./logs.sh
```

### Access Reports
```bash
# Reports disimpan di:
ls -la data/reports/

# View report
cat data/reports/report_example_com_20241107_120000.md
```

### Database Reports
Reports juga tersimpan di PostgreSQL database untuk historical tracking.

## Troubleshooting

### "Target validation failed"
- Pastikan target bukan private IP
- Cek format URL sudah benar (http:// atau https://)
- Pastikan domain valid

### "Scan timeout"
- Target mungkin lambat atau down
- Increase timeout di .env: `SCAN_TIMEOUT=600`

### "Too many concurrent scans"
- Wait atau increase limit di .env: `MAX_CONCURRENT_SCANS=10`

### "Tool error"
- Check logs: `./logs.sh`
- Restart services: `docker-compose restart`

## Safety Features

### Built-in Protection
- ✓ Private IP blocking
- ✓ Localhost blocking
- ✓ Rate limiting
- ✓ Scan timeout
- ✓ Input validation
- ✓ Command injection prevention

### Audit Trail
Semua scan dicatat:
- Timestamp
- Target
- Tools used
- Results
- User (jika authenticated)

## Legal Notice

⚠️ **IMPORTANT**

This tool is for:
- ✓ Your own websites/applications
- ✓ Authorized penetration testing
- ✓ Educational purposes with proper lab setup
- ✓ Bug bounty programs (follow their rules)

This tool is NOT for:
- ❌ Unauthorized scanning
- ❌ Attacking systems you don't own
- ❌ Illegal activities

**You are responsible for your actions.**

## Support

### Getting Help
1. Check README.md
2. View logs: `./logs.sh`
3. Check container status: `docker-compose ps`
4. Review configuration: `.env`

### Common Issues
See README.md section "Troubleshooting"

---

**Happy Secure Testing! 🔐**
