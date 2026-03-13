#!/usr/bin/env python3
"""Railway server entry point - starts unified API server with audit orchestrator.

This script:
1. Creates the audit orchestrator with necessary scouts
2. Registers it with the unified API server
3. Starts the FastAPI server for Railway deployment

Environment Variables:
    API_BASE_URL: Backend API URL (for sending results)
    GLM_API_KEY: API key for GLM/Anthropic API
    RPC_HTTP_URL: RPC endpoint for blockchain queries
    LOG_LEVEL: Logging level (default: INFO)
    UNIFIED_API_PORT: Port for API server (default: 8080)
"""
from __future__ import annotations

import logging
import os
import sys

# Setup path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Configure logging
log_level = os.environ.get("LOG_LEVEL", "INFO")
logging.basicConfig(
    level=getattr(logging, log_level),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def main() -> int:
    """Main entry point for Railway deployment."""

    try:
        # Check for required dependencies
        try:
            from web3 import Web3
        except ImportError:
            logger.error("web3 required: pip install web3")
            return 1

        try:
            from fastapi import FastAPI
        except ImportError:
            logger.error("FastAPI required: pip install fastapi uvicorn")
            return 1

        # Setup Web3
        rpc_url = os.environ.get("RPC_HTTP_URL", "https://eth.llamarpc.com")
        logger.info(f"Connecting to RPC: {rpc_url}")
        w3 = Web3(Web3.HTTPProvider(rpc_url))
        if not w3.is_connected():
            logger.warning("Failed to connect to RPC, continuing anyway...")

        # Create database manager for unified audit service
        from scout.database_manager import DatabaseManager
        db_path = os.environ.get("DB_PATH", "/app/data/scout.db")
        database = DatabaseManager(db_path=db_path)
        logger.info(f"Database initialized: {db_path}")

        # Create backend client (optional - for sending results)
        backend_client = None
        api_base_url = os.environ.get("API_BASE_URL")
        # Skip Railway service references - they must be hardcoded
        if api_base_url and not api_base_url.startswith("{{"):
            try:
                from scout.backend_client import BackendClient
                from scout.siwe_authenticator import SiweAuthenticator
                from scout.auth_wallet import load_or_create_admin_wallet

                # Set skip prompt for Railway (non-interactive)
                os.environ["SCOUT_SKIP_WALLET_PROMPT"] = "1"

                admin_wallet = load_or_create_admin_wallet(database)
                authenticator = SiweAuthenticator(api_base_url, admin_wallet, database)

                # Create token provider function for BackendClient
                def token_provider(force_refresh: bool = False) -> tuple[str, str]:
                    """Get access and refresh tokens from authenticator."""
                    return authenticator.get_tokens()

                backend_client = BackendClient(
                    api_base_url,
                    token_provider=token_provider
                )
                logger.info(f"Backend client configured: {api_base_url}")
            except Exception as e:
                logger.warning(f"Failed to initialize backend client: {e}")
                logger.info("Continuing without backend client - audits will run but won't send results")
                backend_client = None
        else:
            if api_base_url:
                logger.debug(f"API_BASE_URL contains Railway service reference, skipping: {api_base_url[:50]}...")
            logger.info("Running without backend client - audits will respond via API only")

        # Import after Web3 check
        from scout.audit_orchestrator import create_audit_orchestrator
        from scout.unified_api import set_orchestrator, run_unified_api

        # Create audit orchestrator with unified audit service
        # We only need the contract audit capability for Railway
        logger.info("Creating audit orchestrator...")
        orchestrator = create_audit_orchestrator(
            database=database,
            backend_client=backend_client,
            w3=w3,
            # We only need unified_audit for code audits
            token_holder_scout=None,  # Not needed for triggered audits
            tokenomics_analyzer_scout=None,
            liquidity_analyzer_scout=None,
            unified_audit_service="auto",  # Auto-create with ClaudeCodeOrchestrator
        )

        # Register with unified API
        set_orchestrator(orchestrator)
        logger.info("Audit orchestrator registered with unified API server")

        # Get port from environment
        port = int(os.environ.get("PORT", os.environ.get("UNIFIED_API_PORT", "8080")))
        host = os.environ.get("UNIFIED_API_HOST", "0.0.0.0")

        logger.info(f"Starting unified API server on {host}:{port}")

        # Run the unified API server
        run_unified_api(host=host, port=port, log_level=log_level)

        return 0

    except ImportError as e:
        logger.error(f"Import error: {e}")
        logger.error("Ensure all dependencies are installed: pip install -r requirements-audit.txt")
        return 1
    except Exception as e:
        logger.exception(f"Failed to start server: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
