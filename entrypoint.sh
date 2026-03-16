#!/bin/bash
# Container entrypoint script for Railway deployment
# This script runs at container startup (not build time) when Railway env vars are available

set -e

echo "=========================================="
echo "Starting Spectra Blockchain Worker"
echo "=========================================="

# Run claude-code setup at startup when Railway env vars are available
echo "Configuring claude-code CLI with Railway environment variables..."
/app/setup_claude_code.sh || echo "⚠️  Claude-code setup failed, continuing anyway..."

echo "=========================================="
echo "Environment check:"
echo "  - GLM_API_KEY: ${GLM_API_KEY:+configured}"
echo "  - ANTHROPIC_AUTH_TOKEN: ${ANTHROPIC_AUTH_TOKEN:+configured}"
echo "  - GLM_MODEL: ${GLM_MODEL:-not set}"
echo "=========================================="

# Run the main server
exec python server.py
