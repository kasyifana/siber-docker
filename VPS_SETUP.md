# 🚀 VPS Deployment Guide

## Prerequisites di VPS

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose
sudo apt install docker-compose-plugin -y

# Verify installation
docker --version
docker compose version

# Add user to docker group (agar tidak perlu sudo)
sudo usermod -aG docker $USER
newgrp docker

# Install Git
sudo apt install git -y
```

## Deployment Steps

### 1. Clone Repository di VPS

```bash
cd /opt  # atau directory pilihan Anda
git clone https://github.com/kasyifana/siber-docker.git
cd siber-docker
```

### 2. Configure Firewall

```bash
# Allow HTTP port untuk health check
sudo ufw allow 3000/tcp

# Allow Jenkins (optional, jika pakai Jenkins)
sudo ufw allow 8080/tcp

# Allow SSH (PENTING!)
sudo ufw allow 22/tcp

# Enable firewall
sudo ufw enable
sudo ufw status
```

### 3. Setup Environment Variables (Optional)

```bash
# Buat .env file untuk production
cat > .env << 'EOF'
LOG_LEVEL=INFO
DATABASE_URL=postgresql://mcpuser:CHANGE_THIS_PASSWORD@postgres:5432/mcp_security
REDIS_URL=redis://redis:6379/0
EOF

# IMPORTANT: Ganti password default!
nano .env
```

### 4. Build and Start Services

```bash
# Build images
docker compose build

# Start all services
docker compose up -d

# Check status
docker compose ps

# View logs
docker compose logs -f mcp-security-server
```

### 5. Verify Deployment

```bash
# Check health endpoint (jika sudah dibuat)
curl http://localhost:3000/health

# Check MCP server
docker exec -i mcp-security-server python -m src.stdio_server << 'EOF'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}
EOF
```

## Jenkins Setup di VPS

### 1. Start Jenkins

```bash
# Start Jenkins service
docker compose up -d jenkins

# Get initial password
docker exec jenkins-cicd cat /var/jenkins_home/secrets/initialAdminPassword
```

### 2. Configure Jenkins

1. Open `http://YOUR_VPS_IP:8080`
2. Paste initial admin password
3. Install suggested plugins
4. Install additional plugins:
   - **Docker Pipeline**
   - **Git Plugin**
5. Create admin user

### 3. Create Pipeline Job

1. Click **New Item**
2. Enter name: `MCP-Security-Deploy`
3. Select **Pipeline**
4. Click **OK**

5. In **Pipeline** section:
   - Definition: **Pipeline script from SCM**
   - SCM: **Git**
   - Repository URL: `https://github.com/kasyifana/siber-docker.git`
   - Branch: `*/main`
   - Script Path: `Jenkinsfile`

6. Click **Save**

### 4. Setup GitHub Webhook (Optional - Auto Deploy)

Di VPS:
```bash
# Install webhook receiver
sudo apt install webhook -y
```

Atau setup di Jenkins:
1. Manage Jenkins → Configure System
2. GitHub → Add GitHub Server
3. Di GitHub repo: Settings → Webhooks → Add webhook
4. Payload URL: `http://YOUR_VPS_IP:8080/github-webhook/`

## Auto-Start on Reboot

```bash
# Edit crontab
crontab -e

# Add this line
@reboot cd /opt/siber-docker && docker compose up -d
```

## Manual Deployment (Without Jenkins)

```bash
cd /opt/siber-docker

# Pull latest changes
git pull origin main

# Rebuild and restart
docker compose down
docker compose up -d --build

# Check logs
docker compose logs -f mcp-security-server
```

## Monitoring

```bash
# Check all containers
docker compose ps

# View logs
docker compose logs -f

# Check specific service
docker compose logs -f mcp-security-server

# Check resource usage
docker stats

# Check disk space
df -h
```

## Troubleshooting

### Docker not found in Jenkins
```bash
# Verify Docker socket permission
ls -la /var/run/docker.sock

# Should show: srw-rw---- 1 root docker
# If not, fix permission:
sudo chmod 666 /var/run/docker.sock
```

### Port already in use
```bash
# Find process using port 3000
sudo lsof -i :3000

# Kill process
sudo kill -9 <PID>
```

### Container won't start
```bash
# Check logs
docker compose logs mcp-security-server

# Rebuild from scratch
docker compose down -v
docker compose up -d --build --force-recreate
```

## Security Recommendations

1. **Change default passwords** in `docker-compose.yml`:
   - PostgreSQL: `POSTGRES_PASSWORD`

2. **Setup SSL/TLS** with Let's Encrypt:
```bash
sudo apt install certbot -y
sudo certbot certonly --standalone -d your-domain.com
```

3. **Restrict firewall** to only necessary ports

4. **Regular backups**:
```bash
# Backup script
docker exec mcp-postgres pg_dump -U mcpuser mcp_security > backup_$(date +%Y%m%d).sql
```

5. **Update regularly**:
```bash
cd /opt/siber-docker
git pull
docker compose pull
docker compose up -d --build
```

## Access from Claude Desktop / Continue.dev

Dari local machine, configure dengan VPS IP:

```json
{
  "mcpServers": {
    "security-audit-vps": {
      "command": "ssh",
      "args": [
        "user@YOUR_VPS_IP",
        "docker",
        "exec",
        "-i",
        "mcp-security-server",
        "python",
        "-m",
        "src.stdio_server"
      ]
    }
  }
}
```

⚠️ **IMPORTANT**: Setup SSH key authentication untuk security!

## Summary Commands

```bash
# Deploy
cd /opt/siber-docker && git pull && docker compose up -d --build

# Stop
docker compose down

# Restart
docker compose restart mcp-security-server

# Logs
docker compose logs -f

# Status
docker compose ps
```
