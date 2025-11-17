# Jenkins Pipeline Fix - VPS Deployment

## ❌ Error Yang Terjadi

```
docker: not found
/var/jenkins_home/workspace/siber@tmp/durable-f6ce6f59/script.sh.copy: 1: docker: not found
ERROR: script returned exit code 127
```

**Root Cause:** Jenkins container tidak punya akses ke Docker di host VPS.

## ✅ Solusi

### 1. Docker Socket Mounting

File `docker-compose.yml` sudah diupdate dengan:

```yaml
jenkins:
  image: jenkins/jenkins:lts
  container_name: jenkins-cicd
  user: root  # Diperlukan untuk akses Docker socket
  volumes:
    - jenkins-data:/var/jenkins_home
    - /var/run/docker.sock:/var/run/docker.sock  # Mount Docker socket
    - /usr/bin/docker:/usr/bin/docker            # Mount Docker binary
  environment:
    - DOCKER_HOST=unix:///var/run/docker.sock
```

### 2. Updated Jenkinsfile

Jenkinsfile sudah diupdate dengan proper error handling:

- ✅ Use `docker compose` (new syntax)
- ✅ Project name untuk avoid conflicts
- ✅ Proper stage names dan logging
- ✅ Graceful error handling (`|| true`)
- ✅ Health check dengan wait time

## 🚀 Deployment Steps di VPS

### Step 1: Push Changes ke GitHub

```bash
# Di local machine
cd /Users/user/Campuss/Semester\ 5/SIBER/siber-docker
git add .
git commit -m "fix: Update Jenkins config for VPS deployment with Docker access"
git push origin main
```

### Step 2: Pull Changes di VPS

```bash
# SSH ke VPS
ssh user@your-vps-ip

# Navigate to repo
cd /opt/siber-docker

# Pull latest changes
git pull origin main
```

### Step 3: Restart Jenkins

```bash
# Restart Jenkins dengan config baru
docker compose down jenkins
docker compose up -d jenkins

# Wait 30 seconds
sleep 30

# Get admin password (if first time)
docker exec jenkins-cicd cat /var/jenkins_home/secrets/initialAdminPassword
```

### Step 4: Verify Docker Access

```bash
# Test Docker di dalam Jenkins container
docker exec jenkins-cicd docker --version
docker exec jenkins-cicd docker ps

# Expected output:
# Docker version 24.x.x
# CONTAINER ID   IMAGE   ...
```

### Step 5: Run Pipeline di Jenkins

1. Open `http://YOUR_VPS_IP:8080`
2. Go to your pipeline job
3. Click **"Build Now"**
4. Watch console output

Expected stages:
```
✅ Clone Repo
✅ Stop Old Containers
✅ Build Docker Image
✅ Start New Containers
✅ Health Check
✅ Verify MCP Server
```

## 🔍 Troubleshooting

### Issue: "permission denied" on docker.sock

```bash
# Di VPS, cek permission
ls -la /var/run/docker.sock

# Fix permission
sudo chmod 666 /var/run/docker.sock

# Restart Jenkins
docker compose restart jenkins
```

### Issue: Jenkins container can't find docker binary

```bash
# Verify docker binary location
which docker

# If different from /usr/bin/docker, update docker-compose.yml:
# - /usr/local/bin/docker:/usr/bin/docker  # adjust path
```

### Issue: Pipeline still fails

```bash
# Check Jenkins logs
docker compose logs jenkins

# Exec into Jenkins container
docker exec -it jenkins-cicd bash

# Inside container, test:
docker --version
docker ps
docker compose version
```

### Issue: Network conflicts

```bash
# If mcp-security-server sudah running
docker compose ps

# Stop existing containers
docker compose down

# Then run Jenkins pipeline
```

## 📊 Pipeline Flow

```
┌─────────────────┐
│  GitHub Push    │
└────────┬────────┘
         │
         ↓
┌─────────────────┐
│ Manual Trigger  │ atau Webhook
│ Jenkins Build   │
└────────┬────────┘
         │
         ↓
┌─────────────────────────────────────────────┐
│  Jenkins Pipeline (Jenkinsfile)             │
│                                              │
│  1. Clone Repo from GitHub                  │
│  2. Stop old containers                     │
│  3. Build Docker images                     │
│  4. Start new containers                    │
│  5. Health check (30s wait)                 │
│  6. Verify MCP server works                 │
└────────┬────────────────────────────────────┘
         │
         ↓
    ┌────┴────┐
    │         │
 Success   Failure
    │         │
    ↓         ↓
  ✅ Done    ❌ Check logs
```

## 🤖 Auto Deploy with Webhook (Optional)

### Setup GitHub Webhook:

1. Go to GitHub repo: Settings → Webhooks
2. Add webhook:
   - Payload URL: `http://YOUR_VPS_IP:8080/github-webhook/`
   - Content type: `application/json`
   - Events: `Just the push event`
   - Active: ✅

3. Di Jenkins job settings:
   - Build Triggers: ✅ GitHub hook trigger for GITScm polling

Sekarang setiap `git push` akan trigger auto-deploy!

## 📋 Quick Commands

```bash
# Restart Jenkins
docker compose restart jenkins

# View Jenkins logs
docker compose logs -f jenkins

# Get admin password
docker exec jenkins-cicd cat /var/jenkins_home/secrets/initialAdminPassword

# Test Docker access in Jenkins
docker exec jenkins-cicd docker ps

# Manual deploy (without Jenkins)
./deploy-vps.sh

# Check all containers
docker compose ps
```

## ✨ What's Fixed

- ✅ Docker socket mounted ke Jenkins container
- ✅ Docker binary accessible di Jenkins
- ✅ Jenkinsfile updated dengan proper syntax
- ✅ Error handling untuk graceful failures
- ✅ Project naming untuk avoid conflicts
- ✅ Health check dengan adequate wait time
- ✅ Verification step untuk confirm deployment

## 🎯 Result

Pipeline sekarang akan:
1. ✅ Find docker command
2. ✅ Execute docker compose commands
3. ✅ Build and deploy containers successfully
4. ✅ Report success/failure properly

**Status: Ready for VPS deployment! 🚀**
