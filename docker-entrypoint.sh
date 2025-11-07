#!/bin/bash
set -e

echo "🚀 MCP Security Audit Server (stdio mode)"
echo "📋 Use: docker exec -i mcp-security-server python -m src.stdio_server"
echo ""

# Keep container alive for docker exec connections
exec tail -f /dev/null
