#!/bin/bash
set -e

#!/bin/bash
set -e

echo "Starting MCP Security Audit Server..."

# Check if HTTP_API env is set
if [ "$HTTP_API" = "true" ]; then
    echo "Starting HTTP API wrapper on port 3000..."
    exec python -m uvicorn src.http_wrapper:app --host 0.0.0.0 --port 3000
else
    echo "Starting stdio server (default)..."
    exec python -m src.stdio_server
fi
echo "📋 Use: docker exec -i mcp-security-server python -m src.stdio_server"
echo ""

# Keep container alive for docker exec connections
exec tail -f /dev/null
