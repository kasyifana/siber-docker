# MCP Security Audit Server

Server MCP (Model Context Protocol) untuk security audit blackbox testing. Server ini menyediakan berbagai tools untuk melakukan audit keamanan terhadap aplikasi web dan infrastruktur.

## 🚀 Fitur

### Security Scanning Tools
- **Port Scanner (Nmap)** - Scan port dan deteksi service
- **SQL Injection Testing (SQLMap)** - Test vulnerability SQL injection
- **Web Vulnerability Scanning (Nikto)** - Comprehensive web vulnerability scan
- **XSS Testing** - Test Cross-Site Scripting vulnerabilities
- **Subdomain Enumeration** - Discover subdomains
- **SSL/TLS Analysis** - Analyze SSL certificate dan configuration
- **Security Headers Check** - Analyze HTTP security headers
- **OWASP ZAP Integration** - Advanced web application security testing

### Fitur Tambahan
- Comprehensive reporting
- Multiple scan types (quick, standard, thorough)
- Full security audit mode
- Target validation untuk keamanan
- Rate limiting dan timeout protection

## 📋 Prerequisites

- Docker & Docker Compose
- Minimal 2GB RAM
- Koneksi internet untuk download tools

## 🛠️ Installation

### 1. Clone Repository
```bash
cd /Users/user/Campuss/Semester\ 5/SIBER/siber-docker
```

### 2. Build Docker Image
```bash
docker-compose build
```

### 3. Start Services
```bash
docker-compose up -d
```

## 🔧 Configuration

Edit `.env` file atau `docker-compose.yml` untuk konfigurasi:

```env
MCP_SERVER_HOST=0.0.0.0
MCP_SERVER_PORT=8080
LOG_LEVEL=INFO
MAX_CONCURRENT_SCANS=5
SCAN_TIMEOUT=300
```

## 📖 Usage

### Cara Menggunakan dengan LLM

1. **Setup MCP Client di LLM Anda**
   - Tambahkan server ini ke konfigurasi MCP client
   - Gunakan stdio transport untuk komunikasi

2. **Contoh Penggunaan**

```
User: "Tolong scan port pada target.example.com"

LLM akan memanggil tool: port_scan
- target: target.example.com
- ports: 1-1000
- scan_type: quick

User: "Lakukan full security audit pada https://example.com"

LLM akan memanggil tool: full_security_audit
- target: https://example.com
- scope: standard
```

### Available MCP Tools

#### 1. `port_scan`
Scan port pada target
```json
{
  "target": "example.com",
  "ports": "1-1000",
  "scan_type": "quick|full|stealth|version"
}
```

#### 2. `sql_injection_test`
Test SQL injection vulnerability
```json
{
  "url": "https://example.com/page?id=1",
  "parameters": "id,name",
  "database": "auto|mysql|postgres|mssql"
}
```

#### 3. `web_vuln_scan`
Scan web vulnerabilities dengan Nikto
```json
{
  "url": "https://example.com",
  "scan_depth": "quick|standard|thorough"
}
```

#### 4. `xss_test`
Test XSS vulnerabilities
```json
{
  "url": "https://example.com/search",
  "parameters": ["q", "search"],
  "payload_type": "reflected|stored|dom|all"
}
```

#### 5. `enumerate_subdomains`
Enumerate subdomains
```json
{
  "domain": "example.com",
  "method": "dns|certificate|brute|all"
}
```

#### 6. `analyze_ssl`
Analyze SSL/TLS configuration
```json
{
  "hostname": "example.com",
  "port": 443
}
```

#### 7. `check_security_headers`
Check security headers
```json
{
  "url": "https://example.com"
}
```

#### 8. `full_security_audit`
Comprehensive security audit
```json
{
  "target": "https://example.com",
  "scope": "quick|standard|thorough"
}
```

## 📊 Output Examples

### Port Scan Output
```markdown
# Port Scan Results

**Target:** example.com
**Scan Time:** 2.5s

## Open Ports

- **Port 80/tcp**
  - Service: http
  - Version: Apache 2.4.41
  
- **Port 443/tcp**
  - Service: https
  - Version: Apache 2.4.41
```

### Security Headers Output
```markdown
# Security Headers Analysis

**URL:** https://example.com
**Score:** 60/100

## Headers Status

✓ **Strict-Transport-Security**
   Value: `max-age=31536000`
   Status: Strong

❌ **Content-Security-Policy**
   Status: Missing
   Impact: XSS attacks, data injection
```

## 🏗️ Architecture

```
siber-docker/
├── docker-compose.yml          # Docker orchestration
├── Dockerfile                  # Container definition
├── requirements.txt            # Python dependencies
├── src/
│   ├── __init__.py
│   ├── __main__.py            # Entry point
│   ├── server.py              # MCP server implementation
│   ├── config/
│   │   ├── __init__.py
│   │   └── settings.py        # Configuration
│   ├── tools/                 # Security tools
│   │   ├── __init__.py
│   │   ├── nmap_scanner.py
│   │   ├── sqlmap_tool.py
│   │   ├── nikto_scanner.py
│   │   ├── zap_tool.py
│   │   ├── xss_tester.py
│   │   ├── subdomain_enum.py
│   │   ├── ssl_checker.py
│   │   └── header_analyzer.py
│   └── utils/                 # Utilities
│       ├── __init__.py
│       ├── logger.py
│       ├── validator.py
│       └── reporter.py
├── data/                      # Data directory
│   ├── payloads/             # Attack payloads
│   ├── wordlists/            # Wordlists for fuzzing
│   └── reports/              # Generated reports
└── tests/
    └── test_tools.py
```

## 🔒 Security Considerations

### Target Validation
Server ini memiliki built-in validator untuk mencegah scanning pada:
- Private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Localhost (127.0.0.0/8)
- Link-local addresses
- Multicast addresses

### Rate Limiting
- Maximum 5 concurrent scans (configurable)
- Timeout 300 seconds per scan (configurable)
- Rate limiting via Redis

### Logging
Semua aktivitas dicatat untuk audit trail:
- Target yang discan
- Tools yang digunakan
- Hasil scan
- Error yang terjadi

## 📝 Development

### Running Tests
```bash
docker-compose exec mcp-security-server pytest tests/
```

### View Logs
```bash
docker-compose logs -f mcp-security-server
```

### Access Shell
```bash
docker-compose exec mcp-security-server /bin/bash
```

## 🤝 Integration dengan Claude/LLMs

### Konfigurasi MCP di Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

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

### Contoh Interaksi dengan Claude

**User:** "Saya ingin melakukan security audit pada website https://testsite.com"

**Claude:** Saya akan melakukan comprehensive security audit. Ini akan mencakup:
1. Port scanning
2. SSL/TLS analysis
3. Security headers check
4. Subdomain enumeration
5. Web vulnerability scan

*[Claude memanggil tool full_security_audit]*

**Claude:** Hasil audit menunjukkan beberapa temuan:

**Critical Issues:**
- SQL Injection vulnerability pada parameter 'id'

**High Issues:**
- Missing Content-Security-Policy header
- Outdated SSL/TLS protocols enabled

**Recommendations:**
1. Patch SQL injection vulnerability immediately
2. Implement Content-Security-Policy header
3. Disable TLS 1.0 and 1.1

## 🐛 Troubleshooting

### Container tidak bisa start
```bash
docker-compose down
docker-compose up --build
```

### Permission errors
```bash
sudo chown -R $(whoami):$(whoami) data/
```

### ZAP tidak bisa scan
Pastikan port 8090 tidak digunakan aplikasi lain

## 📄 License

MIT License

## ⚠️ Disclaimer

Tool ini hanya untuk educational purposes dan authorized security testing. 
Penggunaan untuk unauthorized testing adalah ilegal dan melanggar hukum.

**PENTING:** 
- Selalu dapatkan izin tertulis sebelum melakukan security testing
- Jangan gunakan untuk target yang tidak Anda miliki/tidak authorized
- Patuhi hukum dan regulasi yang berlaku

## 🙋 Support

Untuk pertanyaan dan issue:
1. Check documentation
2. Review logs: `docker-compose logs mcp-security-server`
3. Restart services: `docker-compose restart`

---

**Happy Secure Testing! 🔐**
