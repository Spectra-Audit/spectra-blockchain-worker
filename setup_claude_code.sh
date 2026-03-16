#!/bin/bash
# Setup script for claude-code CLI with GLM API on Railway
# This script configures claude-code to use GLM's API instead of Anthropic's

set -e

echo "Setting up claude-code CLI with GLM API..."

# Get configuration from environment variables
# Prefer ANTHROPIC_* variables for claude-code CLI compatibility
API_KEY="${ANTHROPIC_AUTH_TOKEN:-${GLM_API_KEY}}"
API_URL="${ANTHROPIC_BASE_URL:-${GLM_API_URL}}"
MODEL="${GLM_MODEL:-glm-4.7}"

# Default to Anthropic-compatible endpoint if not specified
if [[ "$API_URL" == *"v1/chat/completions"* ]]; then
    # GLM_API_URL is OpenAI-compatible, convert to Anthropic-compatible
    API_URL="https://api.z.ai/api/anthropic"
fi

# Validate API key is set
if [[ -z "$API_KEY" ]]; then
    echo "⚠️  WARNING: Neither ANTHROPIC_AUTH_TOKEN nor GLM_API_KEY is set"
    echo "   claude-code CLI will not work without an API key"
fi

# Create config directory
CONFIG_DIR="/home/scout/.config/claude"
mkdir -p "$CONFIG_DIR"

# Mask API key for logging
MASKED_KEY="${API_KEY:0:8}...${API_KEY: -4}"

# Create settings.json for claude-code with GLM configuration
cat > "$CONFIG_DIR/settings.json" << EOF
{
  "api_key": "${API_KEY}",
  "base_url": "${API_URL}",
  "model": "${MODEL}",
  "permission_mode": "bypassPermissions",
  "dangerously_skip_permissions": true
}
EOF

echo "✓ Created claude-code settings.json"
echo "  - API URL: ${API_URL}"
echo "  - Model: ${MODEL}"
echo "  - API Key: ${MASKED_KEY}"

# Verify claude-code is available
if command -v claude &> /dev/null; then
    echo "✓ claude-code CLI is available at: $(which claude)"
    claude --version 2>&1 || echo "  (version check failed, but CLI is installed)"
else
    echo "✗ claude-code CLI not found in PATH"
    echo "  This is expected if running outside the container"
fi

echo "Setup complete!"
