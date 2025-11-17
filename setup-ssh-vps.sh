#!/bin/bash

# 🔐 SSH Key Setup untuk IDCloudHost VPS
# Script ini akan setup SSH key authentication untuk MCP Server access

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   SSH Key Setup untuk IDCloudHost VPS - MCP Access  ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════╝${NC}"
echo ""

# Get VPS details
read -p "Enter VPS IP Address (contoh: 103.xxx.xxx.xxx): " VPS_IP
read -p "Enter SSH Username (biasanya: root atau ubuntu): " VPS_USER
read -p "Enter SSH Port (default: 22): " VPS_PORT
VPS_PORT=${VPS_PORT:-22}

echo ""
echo -e "${YELLOW}📋 VPS Details:${NC}"
echo "   IP:   $VPS_IP"
echo "   User: $VPS_USER"
echo "   Port: $VPS_PORT"
echo ""
read -p "Press Enter to continue or Ctrl+C to cancel..."

# Generate SSH key
echo ""
echo -e "${BLUE}🔑 Generating SSH key...${NC}"
SSH_KEY_PATH="$HOME/.ssh/id_ed25519_idcloudhost"

if [ -f "$SSH_KEY_PATH" ]; then
    echo -e "${YELLOW}⚠️  SSH key already exists: $SSH_KEY_PATH${NC}"
    read -p "Overwrite? (y/N): " OVERWRITE
    if [ "$OVERWRITE" != "y" ]; then
        echo "Using existing key..."
    else
        rm -f "$SSH_KEY_PATH" "$SSH_KEY_PATH.pub"
        ssh-keygen -t ed25519 -f "$SSH_KEY_PATH" -C "mcp-idcloudhost-$VPS_IP" -N ""
    fi
else
    ssh-keygen -t ed25519 -f "$SSH_KEY_PATH" -C "mcp-idcloudhost-$VPS_IP" -N ""
fi

echo -e "${GREEN}✅ SSH key generated!${NC}"
echo ""

# Copy key to VPS
echo -e "${BLUE}📤 Copying SSH key to VPS...${NC}"
echo -e "${YELLOW}You will be asked for VPS password (hanya sekali ini)${NC}"
echo ""

ssh-copy-id -i "$SSH_KEY_PATH.pub" -p "$VPS_PORT" "$VPS_USER@$VPS_IP"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ SSH key copied successfully!${NC}"
else
    echo -e "${RED}❌ Failed to copy SSH key. Check your password and try again.${NC}"
    exit 1
fi

# Test connection
echo ""
echo -e "${BLUE}🧪 Testing SSH connection...${NC}"
ssh -i "$SSH_KEY_PATH" -p "$VPS_PORT" "$VPS_USER@$VPS_IP" "echo 'Connection successful!'" 2>/dev/null

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ SSH connection works without password!${NC}"
else
    echo -e "${RED}❌ SSH test failed${NC}"
    exit 1
fi

# Create SSH config
echo ""
echo -e "${BLUE}⚙️  Creating SSH config...${NC}"

SSH_CONFIG="$HOME/.ssh/config"
ALIAS="idcloudhost-mcp"

# Backup existing config
if [ -f "$SSH_CONFIG" ]; then
    cp "$SSH_CONFIG" "$SSH_CONFIG.backup.$(date +%Y%m%d_%H%M%S)"
fi

# Add or update host config
if grep -q "Host $ALIAS" "$SSH_CONFIG" 2>/dev/null; then
    echo -e "${YELLOW}⚠️  SSH config for '$ALIAS' already exists, skipping...${NC}"
else
    cat >> "$SSH_CONFIG" << EOF

# IDCloudHost VPS for MCP Security Audit
Host $ALIAS
    HostName $VPS_IP
    User $VPS_USER
    Port $VPS_PORT
    IdentityFile $SSH_KEY_PATH
    ServerAliveInterval 60
    ServerAliveCountMax 3
    StrictHostKeyChecking accept-new
EOF
    echo -e "${GREEN}✅ SSH config created!${NC}"
fi

# Test with alias
echo ""
echo -e "${BLUE}🧪 Testing SSH with alias...${NC}"
ssh $ALIAS "echo 'Alias works!'" 2>/dev/null

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ SSH alias works!${NC}"
else
    echo -e "${RED}❌ SSH alias test failed${NC}"
fi

# Test Docker on VPS
echo ""
echo -e "${BLUE}🐳 Checking Docker on VPS...${NC}"
ssh $ALIAS "docker --version" 2>/dev/null

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Docker is installed on VPS${NC}"
else
    echo -e "${YELLOW}⚠️  Docker not found. Please install Docker on VPS first!${NC}"
fi

# Test MCP container
echo ""
echo -e "${BLUE}🔍 Checking MCP container...${NC}"
ssh $ALIAS "docker ps --filter 'name=mcp-security-server' --format '{{.Names}}'" 2>/dev/null | grep -q "mcp-security-server"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ MCP Security Server container is running!${NC}"
else
    echo -e "${YELLOW}⚠️  MCP container not found. Deploy it first with deploy-vps.sh${NC}"
fi

# Generate MCP configs
echo ""
echo -e "${BLUE}📝 Generating MCP configuration files...${NC}"
echo ""

# Continue.dev config
CONTINUE_CONFIG_DIR="$HOME/.continue"
mkdir -p "$CONTINUE_CONFIG_DIR"

cat > "$CONTINUE_CONFIG_DIR/config.json.mcp-vps" << EOF
{
  "models": [
    {
      "model": "gemini-2.0-flash-exp",
      "title": "Gemini 2.0 Flash",
      "apiKey": "YOUR_GEMINI_API_KEY",
      "provider": "gemini"
    }
  ],
  "experimental": {
    "modelContextProtocolServers": [
      {
        "transport": {
          "type": "stdio",
          "command": "ssh",
          "args": [
            "$ALIAS",
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
    ]
  }
}
EOF

echo -e "${GREEN}✅ Continue.dev config: $CONTINUE_CONFIG_DIR/config.json.mcp-vps${NC}"

# Claude Desktop config
CLAUDE_CONFIG_DIR="$HOME/Library/Application Support/Claude"
mkdir -p "$CLAUDE_CONFIG_DIR"

cat > "$CLAUDE_CONFIG_DIR/claude_desktop_config.json.mcp-vps" << EOF
{
  "mcpServers": {
    "security-audit-vps": {
      "command": "ssh",
      "args": [
        "$ALIAS",
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
EOF

echo -e "${GREEN}✅ Claude Desktop config: $CLAUDE_CONFIG_DIR/claude_desktop_config.json.mcp-vps${NC}"

# Summary
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              🎉 Setup Complete!                      ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}📋 What's been set up:${NC}"
echo "   ✅ SSH key: $SSH_KEY_PATH"
echo "   ✅ SSH config alias: $ALIAS"
echo "   ✅ Continue.dev config: ~/.continue/config.json.mcp-vps"
echo "   ✅ Claude Desktop config: ~/Library/Application Support/Claude/claude_desktop_config.json.mcp-vps"
echo ""
echo -e "${YELLOW}🔧 Next Steps:${NC}"
echo ""
echo "1. Test SSH connection:"
echo -e "   ${BLUE}ssh $ALIAS${NC}"
echo ""
echo "2. Test MCP via SSH:"
echo -e "   ${BLUE}ssh $ALIAS 'docker exec -i mcp-security-server python -m src.stdio_server'${NC}"
echo ""
echo "3. Apply Continue.dev config:"
echo -e "   ${BLUE}cp ~/.continue/config.json.mcp-vps ~/.continue/config.json${NC}"
echo -e "   ${YELLOW}⚠️  Remember to add your Gemini API key!${NC}"
echo ""
echo "4. Apply Claude Desktop config:"
echo -e "   ${BLUE}cp ~/Library/Application\\ Support/Claude/claude_desktop_config.json.mcp-vps \\${NC}"
echo -e "   ${BLUE}   ~/Library/Application\\ Support/Claude/claude_desktop_config.json${NC}"
echo ""
echo "5. Restart VS Code / Claude Desktop"
echo ""
echo -e "${GREEN}✨ You can now use MCP Security Audit tools from your VPS!${NC}"
echo ""
