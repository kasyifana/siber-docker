# MCP Security Audit Server

Docker-based MCP server untuk blackbox security testing. Semua tools berjalan di dalam container.

## 🛠️ Tools

1. **Nmap** - Port scanning & service detection
2. **SQLMap** - SQL injection testing
3. **Nikto** - Web vulnerability scanning
4. **XSS Tester** - Cross-site scripting testing
5. **Subdomain Enum** - Subdomain discovery
6. **SSL Checker** - SSL/TLS analysis
7. **Header Analyzer** - Security headers check
8. **Tech Detector** - CMS & framework detection
9. **🚀 Multi-Scan Orchestrator** - Run multiple scans simultaneously with consolidated results

## 🚀 Quick Start

```bash
# Start containers
docker-compose up -d

# Test
docker exec -i mcp-security-server python -m src.stdio_server << 'EOF'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}
EOF
```

## 📝 Cara Pakai

### Via Docker MCP Gateway (Recommended)

Server sudah terdaftar di **Docker MCP Toolkit** dengan nama `security-audit`.

Claude Desktop (dan LLM clients lain) bisa langsung akses via Docker MCP Gateway. Tidak perlu config tambahan - tinggal enable di Docker Desktop UI.

### Verify Setup

```bash
# Check server enabled
docker mcp server list
# Output: security-audit

# Check container running  
docker-compose ps
# Output: mcp-security-server Up

# Test manual
docker exec -i mcp-security-server python -m src.stdio_server << 'EOF'
{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}
EOF
```

## 🔧 Management

```bash
# Start containers
docker-compose up -d

# Stop
docker-compose down

# Logs
docker-compose logs -f

# Rebuild
docker-compose up -d --build

# Docker MCP commands
docker mcp server list
docker mcp server enable security-audit
docker mcp server disable security-audit
docker mcp catalog show local-security
```

## 🐛 Troubleshooting

**Server tidak muncul di Claude:**
```bash
# Verify enabled
docker mcp server list

# Re-add if needed
docker mcp catalog add local-security security-audit ./mcp-server.yaml
docker mcp server enable security-audit
  security-audit:
    metadata:
      displayName: Security Audit Server
      description: Blackbox security testing tools
    transports:
      - type: stdio
        command: docker
        args:
          - exec
          - "-i"
          - mcp-security-server
          - python
          - "-m"
          - src.stdio_server
```

2. Register & enable:

```bash
docker mcp catalog create local
docker mcp catalog add local security-audit ./mcp-server.yaml
docker mcp server enable security-audit
```

3. Use in any MCP client:

```json
{
  "mcpServers": {
    "docker-gateway": {
      "command": "docker",
      "args": ["mcp", "gateway", "run"]
    }
  }
}
```

## 📁 Structure

```
siber-docker/
├── src/
│   ├── stdio_server.py       # MCP stdio server
│   ├── tools/                # Security tools
│   └── utils/                # Utilities
├── docker-compose.yml        # Container orchestration
├── Dockerfile               # Container build
└── README.md               # This file
```

## 🔧 Development

```bash
# Rebuild
docker-compose down && docker-compose up -d --build

# View logs
docker-compose logs -f mcp-security-server

# Stop
docker-compose down
```

## 📝 Example Tool Calls

```json
// Scan ports
{
  "tool": "scan_ports",
  "arguments": {
    "target": "example.com",
    "ports": "1-1000"
  }
}

// Check SQL injection
{
  "tool": "test_sql_injection",
  "arguments": {
    "url": "https://example.com/page?id=1",
    "level": 1
  }
}

// Check security headers
{
  "tool": "check_security_headers",
  "arguments": {
    "url": "https://example.com"
  }
}
```

## 🔒 Security

- Container runs as non-root user
- No-new-privileges security option
- Network isolation
- Tools isolated in container

## 📄 License

MIT
