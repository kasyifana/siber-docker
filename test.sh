#!/bin/bash

# Run tests
echo "🧪 Running tests..."
docker-compose exec mcp-security-server pytest tests/ -v
