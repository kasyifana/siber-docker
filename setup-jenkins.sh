#!/bin/bash

echo "🔧 Setting up Jenkins with Docker access..."

# Stop existing Jenkins if running
docker stop jenkins-cicd 2>/dev/null || true
docker rm jenkins-cicd 2>/dev/null || true

# Start Jenkins with Docker socket mounted
docker compose up -d jenkins

echo "⏳ Waiting for Jenkins to start (this may take 1-2 minutes)..."
sleep 30

# Get initial admin password
echo ""
echo "🔑 Jenkins Initial Admin Password:"
docker exec jenkins-cicd cat /var/jenkins_home/secrets/initialAdminPassword

echo ""
echo "✅ Jenkins is starting at: http://localhost:8080"
echo ""
echo "📋 Next steps:"
echo "1. Open http://localhost:8080 in your browser"
echo "2. Use the password above to unlock Jenkins"
echo "3. Install suggested plugins"
echo "4. Create admin user"
echo "5. Install 'Docker Pipeline' plugin (if not already installed)"
echo "6. Create a new Pipeline job and point it to your Jenkinsfile"
echo ""
echo "🐳 Verifying Docker access inside Jenkins..."
docker exec jenkins-cicd docker --version || echo "⚠️  Docker not accessible - check mount"
