# Quick Reference Guide

## 🚀 Quick Start

```bash
# Make scripts executable
chmod +x start.sh stop.sh logs.sh test.sh

# Start server
./start.sh

# Or using Make
make setup
```

## 📋 Common Commands

### Docker Compose
```bash
docker-compose up -d      # Start services
docker-compose down       # Stop services
docker-compose restart    # Restart services
docker-compose logs -f    # View logs
docker-compose ps         # Check status
```

### Makefile
```bash
make help       # Show all commands
make build      # Build images
make up         # Start services
make down       # Stop services
make logs       # View logs
make test       # Run tests
make shell      # Access shell
make clean      # Clean everything
```

### Shell Scripts
```bash
./start.sh      # Start all services
./stop.sh       # Stop all services
./logs.sh       # View logs
./test.sh       # Run tests
```

## 🔧 Configuration

### Environment Variables (.env)
```env
MCP_SERVER_HOST=0.0.0.0
MCP_SERVER_PORT=8080
LOG_LEVEL=INFO
MAX_CONCURRENT_SCANS=5
SCAN_TIMEOUT=300
```

### MCP Client Config
**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Linux:** `~/.config/Claude/claude_desktop_config.json`
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "security-audit": {
      "command": "docker",
      "args": ["exec", "-i", "mcp-security-server", "python", "-m", "src.server"]
    }
  }
}
```

## 🛠️ Tools Overview

| Tool | Purpose | Example |
|------|---------|---------|
| `port_scan` | Port scanning | "Scan port pada example.com" |
| `sql_injection_test` | SQLi testing | "Test SQLi pada URL..." |
| `web_vuln_scan` | Web vuln scan | "Scan web vulnerabilities..." |
| `xss_test` | XSS testing | "Test XSS pada parameter..." |
| `enumerate_subdomains` | Subdomain enum | "Find subdomains untuk..." |
| `analyze_ssl` | SSL/TLS check | "Analyze SSL certificate..." |
| `check_security_headers` | Header check | "Check security headers..." |
| `full_security_audit` | Full audit | "Full audit pada..." |

## 💬 Example Prompts

### Port Scanning
```
"Scan port pada example.com"
"Quick port scan pada 192.168.1.1"
"Full port scan 1-65535 pada target.com"
"Scan port 80,443,8080 dengan stealth mode"
```

### Web Vulnerabilities
```
"Check web vulnerabilities pada https://example.com"
"Thorough web scan pada https://target.com"
"Quick web vuln check untuk https://site.com"
```

### SQL Injection
```
"Test SQL injection pada https://site.com/products?id=1"
"Check SQLi vulnerability di https://site.com/search?q="
"Test semua parameter untuk SQLi di URL..."
```

### XSS Testing
```
"Test XSS pada https://site.com/search?q="
"Check reflected XSS di parameter 'name'"
"Test stored XSS pada form comment"
```

### Subdomain Enumeration
```
"Find subdomains untuk example.com"
"Enumerate subdomains dengan DNS method"
"Brute force subdomains untuk target.com"
```

### SSL/TLS Analysis
```
"Analyze SSL certificate untuk example.com"
"Check TLS configuration pada target.com"
"Test SSL pada example.com:8443"
```

### Security Headers
```
"Check security headers pada https://example.com"
"Analyze HTTP security headers untuk https://site.com"
"Test header configuration di https://target.com"
```

### Full Audit
```
"Lakukan full security audit pada https://example.com"
"Comprehensive scan dengan scope thorough"
"Quick audit untuk https://target.com"
```

## 🐛 Troubleshooting

### Container won't start
```bash
docker-compose down
docker-compose up --build
```

### Permission errors
```bash
sudo chown -R $(whoami):$(whoami) data/
chmod +x *.sh
```

### View logs
```bash
./logs.sh
# or
make logs
# or
docker-compose logs -f mcp-security-server
```

### Check container status
```bash
docker-compose ps
docker-compose top
```

### Restart specific service
```bash
docker-compose restart mcp-security-server
```

### Access shell
```bash
make shell
# or
docker-compose exec mcp-security-server /bin/bash
```

### Clean everything
```bash
make clean
# or
docker-compose down -v
rm -rf data/reports/*
```

## 📊 Output Locations

### Logs
```
/app/logs/security-audit.log (inside container)
docker-compose logs (host)
```

### Reports
```
data/reports/report_*.md
data/reports/report_*.html
data/reports/report_*.pdf
```

### Database
```
PostgreSQL: localhost:5432
Database: mcp_security
User: mcpuser
Password: changeme (change in .env)
```

## 🔒 Security Notes

### Always Get Permission
- ✅ Own websites/apps
- ✅ Written authorization
- ✅ Bug bounty programs (follow rules)
- ❌ Unauthorized testing

### Blocked by Default
- Private IPs (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
- Localhost (127.0.0.1)
- Link-local (169.254.x.x)
- Multicast addresses

### Enable Private IPs (if needed)
Edit `.env`:
```env
ALLOW_PRIVATE_NETWORKS=true
```

## 📝 Testing

### Run all tests
```bash
./test.sh
# or
make test
```

### Run specific test
```bash
docker-compose exec mcp-security-server pytest tests/test_tools.py::TestNmapScanner -v
```

### Test with coverage
```bash
docker-compose exec mcp-security-server pytest tests/ --cov=src --cov-report=html
```

## 🔗 Useful Links

- **MCP Documentation:** https://modelcontextprotocol.io
- **Nmap:** https://nmap.org/book/man.html
- **SQLMap:** https://sqlmap.org/
- **Nikto:** https://cirt.net/Nikto2
- **OWASP ZAP:** https://www.zaproxy.org/docs/

## 📱 Status Check

```bash
# Check if services are running
docker-compose ps

# Check resource usage
docker stats mcp-security-server

# Check logs in real-time
docker-compose logs -f --tail=100

# Test connection
curl http://localhost:8080/health
```

## 🆘 Getting Help

1. Check `README.md` for full documentation
2. Check `API.md` for tool details
3. Check `USAGE.md` for examples
4. View logs: `./logs.sh`
5. Check container: `make shell`

---

**Remember:** This tool is for authorized security testing only! 🔐
