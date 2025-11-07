#!/bin/bash

# View logs
echo "📋 Viewing MCP Security Audit Server logs..."
echo "Press Ctrl+C to exit"
echo ""

docker-compose logs -f mcp-security-server
