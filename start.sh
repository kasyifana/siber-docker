#!/bin/bash

# MCP Security Audit Server - Quick Start Script

set -e

echo "🔒 MCP Security Audit Server Setup"
echo "=================================="
echo ""

# Check if docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if docker-compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

echo "✓ Docker and Docker Compose are installed"
echo ""

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p data/payloads
mkdir -p data/wordlists
mkdir -p data/reports
mkdir -p logs

echo "✓ Directories created"
echo ""

# Build docker image
echo "🏗️  Building Docker image..."
docker-compose build

echo "✓ Docker image built"
echo ""

# Start services
echo "🚀 Starting services..."
docker-compose up -d

echo "✓ Services started"
echo ""

# Wait for services to be ready
echo "⏳ Waiting for services to be ready..."
sleep 10

# Check if services are running
if docker-compose ps | grep -q "Up"; then
    echo "✓ All services are running"
else
    echo "❌ Some services failed to start"
    docker-compose logs
    exit 1
fi

echo ""
echo "=================================="
echo "✅ Setup Complete!"
echo ""
echo "Services:"
echo "  - MCP Security Server: localhost:8080"
echo "  - PostgreSQL: localhost:5432"
echo "  - Redis: localhost:6379"
echo ""
echo "Useful commands:"
echo "  - View logs: docker-compose logs -f"
echo "  - Stop services: docker-compose stop"
echo "  - Restart: docker-compose restart"
echo "  - Remove: docker-compose down"
echo ""
echo "Next steps:"
echo "  1. Configure your MCP client (Claude, etc)"
echo "  2. Start sending security audit requests"
echo ""
echo "⚠️  Remember: Only scan targets you own or have permission to test!"
echo "=================================="
