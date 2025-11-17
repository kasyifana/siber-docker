# 🚀 Quick Start - VPS Deployment

## 1️⃣ Persiapan VPS (One-time setup)

```bash
# SSH ke VPS Anda
ssh user@your-vps-ip

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose Plugin
sudo apt install docker-compose-plugin git -y

# Add user ke docker group
sudo usermod -aG docker $USER
newgrp docker

# Test Docker
docker run hello-world
```

## 2️⃣ Clone Repository

```bash
# Pilih directory (contoh: /opt atau ~)
cd /opt
sudo mkdir -p siber-docker
sudo chown $USER:$USER siber-docker

# Clone
git clone https://github.com/kasyifana/siber-docker.git
cd siber-docker
```

## 3️⃣ Configure Firewall

```bash
# Allow ports yang dibutuhkan
sudo ufw allow 22/tcp    # SSH (PENTING!)
sudo ufw allow 3000/tcp  # MCP Server
sudo ufw allow 8080/tcp  # Jenkins (optional)

# Enable firewall
sudo ufw enable
sudo ufw status
```

## 4️⃣ Deploy

```bash
# Make script executable
chmod +x deploy-vps.sh

# Run deployment
./deploy-vps.sh
```

Output yang diharapkan:
```
✅ Docker and Docker Compose found
📦 Pulling latest changes from Git...
🛑 Stopping old containers...
🔨 Building Docker images...
🚀 Starting services...
⏳ Waiting for services to start...
✅ MCP Server is running successfully!
✅ Deployment Complete!
```

## 5️⃣ Verify Deployment

```bash
# Check container status
docker compose ps

# View logs
docker compose logs -f mcp-security-server

# Test MCP server
docker exec -i mcp-security-server python -m src.stdio_server << 'EOF'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}
EOF
```

## 🔄 Update & Redeploy

```bash
cd /opt/siber-docker
./deploy-vps.sh
```

Script akan otomatis:
- Pull latest changes dari GitHub
- Stop old containers
- Build new images
- Start services
- Verify health

## 🤖 Setup Jenkins CI/CD (Optional)

### Start Jenkins:
```bash
docker compose up -d jenkins

# Get admin password
docker exec jenkins-cicd cat /var/jenkins_home/secrets/initialAdminPassword
```

### Configure:
1. Open `http://YOUR_VPS_IP:8080`
2. Paste admin password
3. Install suggested plugins + **Docker Pipeline**
4. Create Pipeline job:
   - Name: `MCP-Deploy`
   - Type: Pipeline
   - SCM: Git
   - Repo: `https://github.com/kasyifana/siber-docker.git`
   - Script Path: `Jenkinsfile`

### Test Pipeline:
Click "Build Now" di Jenkins dashboard

## 📊 Monitoring

```bash
# View all logs
docker compose logs -f

# View specific service
docker compose logs -f mcp-security-server

# Check resource usage
docker stats

# Check disk space
df -h
```

## 🛑 Stop Services

```bash
# Stop all
docker compose down

# Stop specific service
docker compose stop mcp-security-server

# Restart
docker compose restart mcp-security-server
```

## 🔐 Connect from Local Machine

### Option 1: SSH Tunnel (Recommended)
```bash
# Di local machine
ssh -L 3000:localhost:3000 user@your-vps-ip

# Now access via http://localhost:3000
```

### Option 2: Claude Desktop via SSH
Edit `claude_desktop_config.json`:
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

**⚠️ Setup SSH key authentication first!**

```bash
# Di local machine
ssh-keygen -t ed25519 -C "your_email@example.com"
ssh-copy-id user@your-vps-ip

# Test
ssh user@your-vps-ip
```

## 🆘 Troubleshooting

### Container won't start
```bash
docker compose logs mcp-security-server
docker compose down -v
docker compose up -d --build
```

### Port already in use
```bash
sudo lsof -i :3000
sudo kill -9 <PID>
```

### Permission denied for docker.sock
```bash
sudo chmod 666 /var/run/docker.sock
# Or restart Jenkins container
docker compose restart jenkins
```

### Out of disk space
```bash
# Clean old images
docker system prune -a

# Check space
df -h
du -sh /var/lib/docker
```

## 📋 Summary Commands

| Task | Command |
|------|---------|
| Deploy | `./deploy-vps.sh` |
| Status | `docker compose ps` |
| Logs | `docker compose logs -f` |
| Restart | `docker compose restart mcp-security-server` |
| Stop | `docker compose down` |
| Update | `git pull && ./deploy-vps.sh` |

## 🔒 Security Checklist

- [ ] Change default PostgreSQL password in `docker-compose.yml`
- [ ] Setup UFW firewall
- [ ] Configure SSH key authentication (disable password)
- [ ] Setup Let's Encrypt SSL (if exposing to internet)
- [ ] Regular backups of PostgreSQL data
- [ ] Keep Docker & system updated
- [ ] Monitor logs for suspicious activity

---

**Need help?** Check `VPS_SETUP.md` for detailed documentation.
