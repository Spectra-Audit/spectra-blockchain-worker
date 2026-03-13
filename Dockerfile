FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    curl \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js for claude-code CLI
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Verify installations
RUN node --version && npm --version

# Install claude-code CLI globally
RUN npm install -g @anthropic-ai/claude-code

# Verify claude-code installation
RUN claude --version || echo "claude-code installed"

WORKDIR /app

# Copy requirements first (before user creation for better caching)
COPY requirements.txt requirements-audit.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt -r requirements-audit.txt

# Copy application code
COPY . .

# Create non-root user
RUN groupadd -r scout && useradd -r -g scout -s /bin/bash scout

# Create directory for database and claude config
RUN mkdir -p /app/data /home/scout/.config/claude

# Copy claude-code setup script
COPY setup_claude_code.sh /app/setup_claude_code.sh
RUN chmod +x /app/setup_claude_code.sh

# Copy custom agents for claude-code
RUN mkdir -p /home/scout/.config/claude/agents && \
    cp -r agents/* /home/scout/.config/claude/agents/ 2>/dev/null || true && \
    chown -R scout:scout /app /home/scout

# Change ownership
RUN chown -R scout:scout /app /home/scout

USER scout

# Run setup script (will configure claude-code CLI with GLM API)
RUN /app/setup_claude_code.sh || echo "Setup script skipped"

# Run the unified API server with audit orchestrator
CMD ["python", "server.py"]
