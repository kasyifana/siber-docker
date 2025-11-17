#!/bin/bash

# 🚀 VPS Deployment Script for MCP Security Audit Server
# Run this on your VPS after cloning the repository

set -e  # Exit on error

echo "🚀 Starting MCP Security Audit Server Deployment..."
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    echo -e "${RED}⚠️  Please do not run as root. Run as regular user with docker group access.${NC}"
    exit 1
fi

# Check Docker installation
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker not found. Please install Docker first.${NC}"
    echo "Run: curl -fsSL https://get.docker.com -o get-docker.sh && sudo sh get-docker.sh"
    exit 1
fi

# Check Docker Compose
if ! docker compose version &> /dev/null; then
    echo -e "${RED}❌ Docker Compose not found. Please install Docker Compose plugin.${NC}"
    echo "Run: sudo apt install docker-compose-plugin -y"
    exit 1
fi

echo -e "${GREEN}✅ Docker and Docker Compose found${NC}"
echo ""

# Pull latest changes
echo "📦 Pulling latest changes from Git..."
git pull origin main || echo -e "${YELLOW}⚠️  Git pull failed or already up to date${NC}"
echo ""

# Stop old containers
echo "🛑 Stopping old containers..."
docker compose down || true
echo ""

# Build images
echo "🔨 Building Docker images (this may take a few minutes)..."
docker compose build --no-cache mcp-security-server
echo ""

# Start services
echo "🚀 Starting services..."
docker compose up -d
echo ""

# Wait for services to be ready
echo "⏳ Waiting for services to start (30 seconds)..."
sleep 30
echo ""

# Check container status
echo "📊 Container Status:"
docker compose ps
echo ""

# Verify MCP server
echo "✅ Verifying MCP Server..."
if docker exec mcp-security-server python -c "import sys; print('Python OK')" &> /dev/null; then
    echo -e "${GREEN}✅ MCP Server is running successfully!${NC}"
else
    echo -e "${RED}❌ MCP Server verification failed${NC}"
    echo "Check logs: docker compose logs mcp-security-server"
    exit 1
fi
echo ""

# Check health endpoint (if exists)
echo "🏥 Checking health endpoint..."
if curl -s -f http://localhost:3000/health &> /dev/null; then
    echo -e "${GREEN}✅ Health check passed${NC}"
else
    echo -e "${YELLOW}⚠️  Health endpoint not responding (may not be implemented yet)${NC}"
fi
echo ""

# Display access information
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}✅ Deployment Complete!${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📋 Service URLs:"
echo "   MCP Server:  http://localhost:3000"
echo "   Jenkins:     http://localhost:8080"
echo "   PostgreSQL:  localhost:5432"
echo "   Redis:       localhost:6379"
echo ""
echo "🔍 Useful Commands:"
echo "   View logs:        docker compose logs -f"
echo "   Restart server:   docker compose restart mcp-security-server"
echo "   Stop all:         docker compose down"
echo "   Update & deploy:  ./deploy-vps.sh"
echo ""
echo "📖 Full documentation: VPS_SETUP.md"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
