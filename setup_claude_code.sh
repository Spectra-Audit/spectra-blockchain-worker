#!/bin/bash
# Setup script for claude-code CLI with GLM API on Railway
# This script configures claude-code to use GLM's API instead of Anthropic's

set -e

echo "Setting up claude-code CLI with GLM API..."

# Get configuration from environment variables
GLM_API_KEY="${GLM_API_KEY:-${ANTHROPIC_AUTH_TOKEN}}"
GLM_API_URL="${GLM_API_URL:-https://open.bigmodel.cn/api/paas/v4/chat/completions}"
GLM_MODEL="${GLM_MODEL:-glm-4.7}"

# Create config directory
CONFIG_DIR="/home/scout/.config/claude"
mkdir -p "$CONFIG_DIR"

# Create settings.json for claude-code with GLM configuration
cat > "$CONFIG_DIR/settings.json" << EOF
{
  "api_key": "${GLM_API_KEY}",
  "base_url": "${GLM_API_URL}",
  "model": "${GLM_MODEL}",
  "permission_mode": "bypassPermissions",
  "dangerously_skip_permissions": true
}
EOF

echo "✓ Created claude-code settings.json"
echo "  - API URL: ${GLM_API_URL}"
echo "  - Model: ${GLM_MODEL}"

# Verify claude-code is available
if command -v claude &> /dev/null; then
    echo "✓ claude-code CLI is available"
    claude --version
else
    echo "✗ claude-code CLI not found in PATH"
    echo "  This is expected if running outside the container"
fi

echo "Setup complete!"
