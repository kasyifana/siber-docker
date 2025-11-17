# 🌐 HTTP REST API Access - MCP Security Audit

## 📋 Overview

MCP server di VPS Anda sekarang expose **HTTP REST API** di port 3000 untuk akses dari luar (browser, curl, Postman, aplikasi lain).

**Base URL:** `http://103.31.39.95:3000`

---

## 🚀 Quick Start

### 1. Test API Health
```bash
curl http://103.31.39.95:3000/health
```

Response:
```json
{
  "status": "healthy",
  "service": "mcp-security-audit"
}
```

### 2. List Available Tools
```bash
curl http://103.31.39.95:3000/tools
```

### 3. Run Port Scan
```bash
curl -X POST http://103.31.39.95:3000/scan/ports \
  -H "Content-Type: application/json" \
  -d '{"target": "scanme.nmap.org", "ports": "80,443"}'
```

---

## 📚 API Endpoints

### GET `/`
API info and endpoint list

```bash
curl http://103.31.39.95:3000/
```

### GET `/health`
Health check

```bash
curl http://103.31.39.95:3000/health
```

### GET `/tools`
List all available security tools

```bash
curl http://103.31.39.95:3000/tools
```

---

## 🔍 Scan Endpoints

### POST `/scan/ports`
**Scan network ports using Nmap**

```bash
curl -X POST http://103.31.39.95:3000/scan/ports \
  -H "Content-Type: application/json" \
  -d '{
    "target": "scanme.nmap.org",
    "ports": "1-1000"
  }'
```

**Parameters:**
- `target` (required): Target IP or hostname
- `ports` (optional): Port range, default "1-1000"

---

### POST `/scan/sql`
**Test for SQL injection vulnerabilities**

```bash
curl -X POST http://103.31.39.95:3000/scan/sql \
  -H "Content-Type: application/json" \
  -d '{
    "url": "http://testphp.vulnweb.com"
  }'
```

**Parameters:**
- `url` (required): Target URL to test

---

### POST `/scan/web`
**Scan web vulnerabilities using Nikto**

```bash
curl -X POST http://103.31.39.95:3000/scan/web \
  -H "Content-Type: application/json" \
  -d '{
    "url": "http://scanme.nmap.org"
  }'
```

**Parameters:**
- `url` (required): Target URL to scan

---

### POST `/scan/xss`
**Test for XSS vulnerabilities**

```bash
curl -X POST http://103.31.39.95:3000/scan/xss \
  -H "Content-Type: application/json" \
  -d '{
    "url": "http://example.com",
    "payloads": ["<script>alert(1)</script>"]
  }'
```

**Parameters:**
- `url` (required): Target URL
- `payloads` (optional): Custom XSS payloads

---

### POST `/scan/ssl`
**Check SSL/TLS certificate**

```bash
curl -X POST http://103.31.39.95:3000/scan/ssl \
  -H "Content-Type: application/json" \
  -d '{
    "host": "github.com",
    "port": 443
  }'
```

**Parameters:**
- `host` (required): Target hostname
- `port` (optional): Port number, default 443

---

### POST `/scan/headers`
**Check security headers**

```bash
curl -X POST http://103.31.39.95:3000/scan/headers \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://github.com"
  }'
```

**Parameters:**
- `url` (required): Target URL

---

### POST `/scan/tech`
**Detect technologies**

```bash
curl -X POST http://103.31.39.95:3000/scan/tech \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://wordpress.com"
  }'
```

**Parameters:**
- `url` (required): Target URL

---

### POST `/scan/subdomains`
**Enumerate subdomains**

```bash
curl -X POST http://103.31.39.95:3000/scan/subdomains \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "wordlist": "/path/to/wordlist.txt"
  }'
```

**Parameters:**
- `domain` (required): Target domain
- `wordlist` (optional): Custom wordlist path

---

### POST `/scan/multi`
**Run multiple scans simultaneously** (RECOMMENDED)

```bash
curl -X POST http://103.31.39.95:3000/scan/multi \
  -H "Content-Type: application/json" \
  -d '{
    "target": "scanme.nmap.org",
    "scans": ["ports", "ssl", "headers", "tech"],
    "ports": "80,443,8080"
  }'
```

**Parameters:**
- `target` (required): Target URL or hostname
- `scans` (optional): Array of scan types:
  - `"ports"` - Nmap port scan
  - `"sql"` - SQL injection test
  - `"web_vuln"` - Nikto web scan
  - `"xss"` - XSS test
  - `"ssl"` - SSL check
  - `"headers"` - Security headers
  - `"tech"` - Technology detection
- `ports` (optional): Port range for Nmap, default "80,443,8080,3000,8000"

---

### POST `/tool/call`
**Generic tool call (advanced)**

```bash
curl -X POST http://103.31.39.95:3000/tool/call \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "scan_ports",
    "arguments": {
      "target": "scanme.nmap.org",
      "ports": "80,443"
    }
  }'
```

**Parameters:**
- `tool` (required): Tool name
- `arguments` (required): Tool-specific arguments

---

## 🐍 Python Client Example

```python
import requests

# Base URL
BASE_URL = "http://103.31.39.95:3000"

# Health check
response = requests.get(f"{BASE_URL}/health")
print(response.json())

# Scan ports
response = requests.post(
    f"{BASE_URL}/scan/ports",
    json={
        "target": "scanme.nmap.org",
        "ports": "80,443,8080"
    }
)
result = response.json()
print(result["result"])

# Multi-scan
response = requests.post(
    f"{BASE_URL}/scan/multi",
    json={
        "target": "scanme.nmap.org",
        "scans": ["ports", "ssl", "headers"],
        "ports": "80,443"
    }
)
result = response.json()
print(result["result"])
```

---

## 🌐 JavaScript/Node.js Client Example

```javascript
const axios = require('axios');

const BASE_URL = 'http://103.31.39.95:3000';

// Health check
axios.get(`${BASE_URL}/health`)
  .then(res => console.log(res.data));

// Scan ports
axios.post(`${BASE_URL}/scan/ports`, {
  target: 'scanme.nmap.org',
  ports: '80,443,8080'
})
  .then(res => console.log(res.data.result));

// Multi-scan
axios.post(`${BASE_URL}/scan/multi`, {
  target: 'scanme.nmap.org',
  scans: ['ports', 'ssl', 'headers'],
  ports: '80,443'
})
  .then(res => console.log(res.data.result));
```

---

## 🔐 Security Considerations

### ⚠️ **IMPORTANT:**

1. **Firewall Protection**
   ```bash
   # Di VPS, restrict akses ke IP tertentu
   sudo ufw allow from YOUR_IP to any port 3000
   ```

2. **API Authentication** (TODO)
   - Tambahkan API key authentication
   - Implement rate limiting
   - Add CORS headers

3. **HTTPS/SSL**
   - Setup reverse proxy (Nginx/Caddy)
   - Use Let's Encrypt for SSL

4. **Authorized Testing Only**
   - Only scan targets you own or have permission
   - Respect rate limits
   - Follow responsible disclosure

---

## 🚀 Deploy HTTP API ke VPS

### 1. Update di VPS
```bash
ssh idcloudhost-mcp

cd /path/to/siber-docker
git pull origin main

# Rebuild dengan HTTP API enabled
docker compose down
docker compose up -d --build
```

### 2. Verify API Running
```bash
curl http://103.31.39.95:3000/health
```

### 3. Test dari Local Machine
```bash
curl http://103.31.39.95:3000/tools
```

---

## 📊 Response Format

**Success Response:**
```json
{
  "success": true,
  "result": "Scan results in markdown format..."
}
```

**Error Response:**
```json
{
  "success": false,
  "error": "Error message"
}
```

---

## 🔄 Switch Between HTTP and stdio Mode

**HTTP API mode (current):**
```yaml
# docker-compose.yml
environment:
  - HTTP_API=true
```

**stdio-only mode (for MCP clients):**
```yaml
# docker-compose.yml
environment:
  - HTTP_API=false
```

Then rebuild: `docker compose up -d --build`

---

## 📖 Interactive API Docs

Once deployed, access interactive API documentation:

**Swagger UI:** `http://103.31.39.95:3000/docs`
**ReDoc:** `http://103.31.39.95:3000/redoc`

---

## 🎯 Next Steps

1. **Deploy ke VPS** - Follow deploy instructions above
2. **Test dengan curl** - Try example commands
3. **Build client app** - Use Python/JS examples
4. **Add authentication** - Secure your API
5. **Setup HTTPS** - Use Nginx + Let's Encrypt

**Your MCP server is now accessible via HTTP REST API! 🚀**
