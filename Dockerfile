FROM python:3.11-slim

# Create non-root user
RUN groupadd -r scout && useradd -r -g scout scout

WORKDIR /app

# Install Node.js for claude-code CLI
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    curl \
    gnupg \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Verify Node.js installation
RUN node --version && npm --version

# Install claude-code CLI globally
RUN npm install -g @anthropic-ai/claude-code

# Verify claude-code installation
RUN claude --version

# Copy requirements and install Python dependencies
COPY requirements.txt requirements-audit.txt .
RUN pip install --no-cache-dir -r requirements.txt -r requirements-audit.txt

# Copy application code
COPY . .

# Create directory for database and claude config
RUN mkdir -p /app/data /home/scout/.config/claude && chown -R scout:scout /app /home/scout

# Copy claude-code setup script
COPY setup_claude_code.sh /app/setup_claude_code.sh
RUN chmod +x /app/setup_claude_code.sh

# Copy custom agents for claude-code
COPY agents /home/scout/.config/claude/agents 2>/dev/null || true
RUN chown -R scout:scout /home/scout/.config

USER scout

# Run setup script (will configure claude-code CLI with GLM API)
RUN /app/setup_claude_code.sh

# Run the blockchain worker
CMD ["python", "-m", "scout", "run"]
