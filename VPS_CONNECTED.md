# ✅ VPS Setup Complete - IDCloudHost

## 📋 Configuration Summary

**VPS Details:**
- IP Address: `103.31.39.95`
- Username: `sibers`
- SSH Alias: `idcloudhost-mcp`
- SSH Key: `~/.ssh/id_ed25519_idcloudhost`

**Containers Running:**
- ✅ mcp-security-server (port 3000)
- ✅ mcp-postgres (port 5432)
- ✅ mcp-redis (port 6379)
- ✅ jenkins-cicd (port 8080)

**MCP Tools Available:** 9 tools
1. scan_ports (Nmap)
2. test_sql_injection (SQLMap)
3. scan_web_vulnerabilities (Nikto)
4. test_xss
5. enumerate_subdomains
6. check_ssl
7. check_security_headers
8. detect_technologies
9. **multi_scan** (Parallel scanning)

---

## 🚀 Quick Access Commands

### SSH to VPS
```bash
ssh idcloudhost-mcp
```

### Check Container Status
```bash
ssh idcloudhost-mcp "docker compose ps"
```

### View MCP Logs
```bash
ssh idcloudhost-mcp "docker compose logs -f mcp-security-server"
```

### Restart MCP Server
```bash
ssh idcloudhost-mcp "docker compose restart mcp-security-server"
```

### Update & Redeploy
```bash
ssh idcloudhost-mcp "cd /path/to/siber-docker && git pull && docker compose up -d --build"
```

---

## 💻 Client Configuration

### Continue.dev (VS Code)
**Location:** `~/.continue/config.json`
**Status:** ✅ Configured

Config already updated to connect via SSH:
```json
{
  "experimental": {
    "modelContextProtocolServers": [
      {
        "transport": {
          "type": "stdio",
          "command": "ssh",
          "args": [
            "idcloudhost-mcp",
            "docker", "exec", "-i",
            "mcp-security-server",
            "python", "-m", "src.stdio_server"
          ]
        }
      }
    ]
  }
}
```

### Claude Desktop
**Location:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Status:** ✅ Configured

Config:
```json
{
  "mcpServers": {
    "security-audit-vps": {
      "command": "ssh",
      "args": [
        "idcloudhost-mcp",
        "docker", "exec", "-i",
        "mcp-security-server",
        "python", "-m", "src.stdio_server"
      ]
    }
  }
}
```

---

## ✅ Next Steps

### 1. Restart Clients to Load Config
```bash
# Restart VS Code (untuk Continue.dev)
# Command + Q, then reopen

# Restart Claude Desktop
# Command + Q, then reopen
```

### 2. Test MCP Tools

**In Continue.dev / Claude Desktop:**
```
"Scan ports on scanme.nmap.org"
"Check SSL certificate for google.com"
"Run multi_scan on scanme.nmap.org"
```

### 3. View Available Tools

**In Continue.dev / Claude Desktop:**
```
"What security audit tools are available?"
"Show me all MCP tools"
```

---

## 🔐 Security Notes

✅ **What's Secured:**
- SSH key authentication (no password needed)
- Passwordless SSH for automation
- SSH config with keepalive
- Docker containers isolated

⚠️ **Important:**
- Only scan authorized targets!
- Don't scan production systems without permission
- Keep VPS and containers updated
- Monitor logs regularly

---

## 🆘 Troubleshooting

### Issue: "Connection refused" or "Permission denied"
```bash
# Test SSH
ssh idcloudhost-mcp "echo OK"

# Check SSH key
ls -la ~/.ssh/id_ed25519_idcloudhost*

# Re-copy key if needed
ssh-copy-id -i ~/.ssh/id_ed25519_idcloudhost.pub sibers@103.31.39.95
```

### Issue: MCP tools not showing in Continue.dev
```bash
# Restart VS Code completely (Command + Q)
# Check Continue.dev logs: Command + Shift + P → "Continue: Show Logs"
```

### Issue: MCP tools not showing in Claude Desktop
```bash
# Check config exists
cat ~/Library/Application\ Support/Claude/claude_desktop_config.json

# Restart Claude Desktop completely (Command + Q)
# Check Claude logs in: ~/Library/Logs/Claude/
```

### Issue: Container not running
```bash
ssh idcloudhost-mcp "docker compose ps"
ssh idcloudhost-mcp "docker compose logs mcp-security-server"
ssh idcloudhost-mcp "docker compose restart mcp-security-server"
```

---

## 📊 Monitoring

### Container Health
```bash
ssh idcloudhost-mcp "docker stats --no-stream"
```

### Disk Usage
```bash
ssh idcloudhost-mcp "df -h"
ssh idcloudhost-mcp "docker system df"
```

### Recent Logs
```bash
ssh idcloudhost-mcp "docker compose logs --tail=50 mcp-security-server"
```

---

## 🎯 Usage Examples

### Basic Port Scan
```
"Scan ports 80,443,8080 on scanme.nmap.org"
```

### SSL Check
```
"Check SSL certificate for github.com"
```

### Security Headers
```
"Check security headers for https://example.com"
```

### Multi-Scan (Recommended)
```
"Run multi_scan on scanme.nmap.org with ports, ssl, and headers"
```

### Technology Detection
```
"Detect technologies used by https://wordpress.com"
```

---

## ✨ Success!

Your MCP Security Audit Server is now:
- ✅ Running on IDCloudHost VPS (103.31.39.95)
- ✅ Accessible via SSH without password
- ✅ Configured in Continue.dev (Gemini)
- ✅ Configured in Claude Desktop
- ✅ Ready for security auditing!

**Restart VS Code / Claude Desktop dan test dengan prompt di atas!** 🚀
