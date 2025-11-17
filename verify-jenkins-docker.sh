#!/bin/bash

# 🔧 Verify Jenkins Docker Access on VPS

echo "🔍 Checking Jenkins container Docker access..."
echo ""

# Check if Jenkins container is running
if ! ssh idcloudhost-mcp "docker ps --filter 'name=jenkins' --format '{{.Names}}'" | grep -q jenkins; then
    echo "❌ Jenkins container not running on VPS"
    echo "Start it with: ssh idcloudhost-mcp 'docker compose up -d jenkins'"
    exit 1
fi

echo "✅ Jenkins container is running"
echo ""

# Check Docker version inside Jenkins
echo "🐳 Checking Docker inside Jenkins container..."
ssh idcloudhost-mcp "docker exec jenkins-cicd docker --version" || {
    echo "❌ Docker not accessible inside Jenkins container"
    echo ""
    echo "🔧 Fix: Ensure Docker socket is mounted in docker-compose.yml:"
    echo "  volumes:"
    echo "    - /var/run/docker.sock:/var/run/docker.sock"
    echo "    - /usr/bin/docker:/usr/bin/docker"
    exit 1
}

echo "✅ Docker is accessible"
echo ""

# Check docker-compose or docker compose
echo "🔍 Checking Docker Compose..."
if ssh idcloudhost-mcp "docker exec jenkins-cicd docker compose version" 2>/dev/null; then
    echo "✅ 'docker compose' (new version) available"
elif ssh idcloudhost-mcp "docker exec jenkins-cicd docker-compose --version" 2>/dev/null; then
    echo "✅ 'docker-compose' (legacy) available"
else
    echo "⚠️  Docker Compose not found"
    echo ""
    echo "🔧 Install Docker Compose plugin in Jenkins container:"
    echo "  ssh idcloudhost-mcp"
    echo "  docker exec -u root jenkins-cicd apt-get update"
    echo "  docker exec -u root jenkins-cicd apt-get install -y docker-compose-plugin"
fi

echo ""
echo "📋 Summary:"
ssh idcloudhost-mcp "docker exec jenkins-cicd sh -c 'echo \"Docker: \$(docker --version)\"; docker compose version 2>/dev/null || docker-compose --version 2>/dev/null || echo \"Docker Compose: Not found\"'"

echo ""
echo "✅ Verification complete!"
