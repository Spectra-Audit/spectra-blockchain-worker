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


def _check_and_verify_missed_payments(w3, backend_client, database):
    """Check for pending submissions and verify payments that may have been missed.

    When the worker starts far behind and skips blocks, it might skip over
    payment events. This function queries the backend for pending submissions
    and checks if any payments were in blocks that were skipped.

    Args:
        w3: Web3 instance for blockchain queries
        backend_client: BackendClient for API calls
        database: DatabaseManager for state tracking
    """
    try:
        # Get pending submissions from backend
        response = backend_client.get("/admin/pending-submissions")
        if response.status_code != 200:
            logger.warning(f"Failed to fetch pending submissions: {response.status_code}")
            return

        data = response.json()
        submissions = data.get("submissions", [])

        if not submissions:
            logger.info("No pending submissions to check")
            return

        logger.info(f"Found {len(submissions)} pending submissions to check")

        # Get current block and the last processed block
        current_block = w3.eth.block_number
        featured_last_block_str = database.get_meta("featured_last_block")
        featured_last_block = int(featured_last_block_str) if featured_last_block_str else 0

        # Check if any pending payments were in blocks before our starting point
        for submission in submissions:
            submission_id = submission.get("submission_id")
            creator_address = submission.get("creator_address")
            tx_hash = submission.get("transaction_hash")

            if not tx_hash:
                logger.debug(f"Submission {submission_id} has no transaction hash, skipping")
                continue

            try:
                # Get transaction receipt to find block number
                receipt = w3.eth.get_transaction_receipt(tx_hash)
                tx_block = receipt.blockNumber

                # Check if this transaction was in a block we already processed
                # or if it was before our starting point
                if tx_block <= featured_last_block:
                    logger.info(
                        f"Payment at block {tx_block} was before worker starting point "
                        f"({featured_last_block}), verifying now"
                    )

                    # Decode the Paid event and verify payment
                    _verify_payment_from_receipt(w3, backend_client, receipt, creator_address)

            except Exception as e:
                logger.debug(f"Failed to check submission {submission_id}: {e}")

    except Exception as e:
        logger.warning(f"Error checking missed payments: {e}")


def _verify_payment_from_receipt(w3, backend_client, receipt, expected_creator):
    """Verify a payment from a transaction receipt and call the admin endpoint.

    Args:
        w3: Web3 instance
        backend_client: BackendClient for API calls
        receipt: Transaction receipt
        expected_creator: Expected creator address from submission
    """
    # Paid event signature
    PAID_TOPIC = w3.keccak(text="Paid(address,address,bytes32,uint256,uint8,uint256,uint64)").hex()

    for log in receipt.logs:
        if not log.topics:
            continue

        if log.topics[0].hex() == PAID_TOPIC:
            # Extract indexed parameters from topics
            creator = w3.to_checksum_address(log.topics[2][-20:])

            # Only process if creator matches expected
            if creator.lower() != expected_creator.lower():
                continue

            # Decode data
            data = w3.codec.decode(["uint256", "uint8", "uint256", "uint64"], log.data)
            amount_paid_fees = data[0]
            round_id = data[3]

            # Convert amount from wei to VERITAS
            amount_veritas = int(amount_paid_fees / 1e18)

            # Prepare payload for admin endpoint
            payload = {
                "creator_address": creator,
                "amount_paid": str(amount_veritas),
                "transaction_hash": receipt.transactionHash.hex(),
                "block_number": receipt.blockNumber,
                "round_id": round_id,
            }

            # Call admin endpoint to verify payment and create project
            response = backend_client.post("/admin/verify-payment-and-create", json=payload)

            if response.status_code == 200:
                result = response.json()
                logger.info(
                    f"Successfully verified missed payment: project_id={result.get('project_id')}, "
                    f"submission_id={result.get('submission_id')}"
                )
            else:
                logger.warning(
                    f"Failed to verify missed payment: {response.status_code} - {response.text}"
                )

            return  # Only process first matching Paid event

    logger.debug(f"No matching Paid event found in receipt {receipt.transactionHash.hex()}")


def _do_background_initialization():
    """Perform all heavy initialization in the background after the server starts.

    This runs in a daemon thread so the FastAPI server can start accepting
    connections immediately.  Railway's health check (/health) will succeed
    right away while the orchestrator, scouts, and backend client are being
    set up.  The /audit/trigger endpoint gracefully returns 503 until the
    orchestrator is registered.
    """
    import threading

    def _init():
        try:
            # ---- FastAPI / uvicorn are guaranteed available by this point ----
            from web3 import Web3  # noqa: F811 (already imported at top level)

            # Setup Web3
            rpc_url = os.environ.get("RPC_HTTP_URL", "https://eth.llamarpc.com")
            logger.info(f"[bg-init] Connecting to RPC: {rpc_url}")
            w3 = Web3(Web3.HTTPProvider(rpc_url))
            if not w3.is_connected():
                logger.warning("[bg-init] Failed to connect to RPC, continuing anyway...")

            # Create database manager
            from scout.database_manager import DatabaseManager
            db_path = os.environ.get("DB_PATH", "/app/data/scout.db")
            database = DatabaseManager(db_path=db_path)
            logger.info(f"[bg-init] Database initialized: {db_path}")

            # Create backend client (optional)
            backend_client = None
            api_base_url = os.environ.get("API_BASE_URL")
            if api_base_url and not api_base_url.startswith("{{"):
                try:
                    from scout.backend_client import BackendClient
                    from scout.siwe_authenticator import SiweAuthenticator
                    from scout.auth_wallet import load_or_create_admin_wallet

                    os.environ["SCOUT_SKIP_WALLET_PROMPT"] = "1"

                    admin_wallet = load_or_create_admin_wallet(database)
                    authenticator = SiweAuthenticator(api_base_url, admin_wallet, database)

                    def token_provider(force_refresh: bool = False) -> tuple[str, str]:
                        return authenticator.get_tokens()

                    backend_client = BackendClient(
                        api_base_url,
                        token_provider=token_provider
                    )
                    logger.info(f"[bg-init] Backend client configured: {api_base_url}")
                except Exception as e:
                    logger.warning(f"[bg-init] Failed to initialize backend client: {e}")
                    logger.info("[bg-init] Continuing without backend client")
                    backend_client = None
            else:
                logger.info("[bg-init] Running without backend client - audits will respond via API only")

            # Import after Web3 check
            from scout.audit_orchestrator import create_audit_orchestrator
            from scout.unified_api import set_orchestrator
            from scout.unified_audit_service import create_unified_audit_service
            from scout.main import ScoutApp

            # Create ScoutApp
            logger.info("[bg-init] Creating ScoutApp with blockchain monitoring scouts...")
            scout_app = ScoutApp.from_env()
            logger.info("[bg-init] ScoutApp created successfully")

            # Update last_block if too far behind
            try:
                current_block = w3.eth.block_number
                target_block = current_block - 2000

                featured_last_block_str = scout_app.database.get_meta("featured_last_block")
                if featured_last_block_str:
                    featured_last_block = int(featured_last_block_str)
                    blocks_behind = current_block - featured_last_block
                    if blocks_behind > 10000:
                        logger.warning(
                            f"[bg-init] FeaturedScout is {blocks_behind} blocks behind. "
                            f"Skipping to block {target_block}."
                        )
                        scout_app.database.set_meta("featured_last_block", str(target_block))

                pro_last_block_str = scout_app.database.get_meta("pro_last_block")
                if pro_last_block_str:
                    pro_last_block = int(pro_last_block_str)
                    blocks_behind = current_block - pro_last_block
                    if blocks_behind > 10000:
                        logger.warning(
                            f"[bg-init] ProScout is {blocks_behind} blocks behind. "
                            f"Skipping to block {target_block}."
                        )
                        scout_app.database.set_meta("pro_last_block", str(target_block))
            except Exception as e:
                logger.warning(f"[bg-init] Failed to check/update scout last_block values: {e}")

            # Check for missed payments
            if backend_client:
                try:
                    logger.info("[bg-init] Checking for pending submissions...")
                    _check_and_verify_missed_payments(w3, backend_client, scout_app.database)
                except Exception as e:
                    logger.warning(f"[bg-init] Failed to check for missed payments: {e}")

            # Start scouts
            logger.info("[bg-init] Starting blockchain monitoring scouts...")
            scout_app.start()
            logger.info("[bg-init] Scouts started - FeaturedScout will monitor for Paid events")

            # Get or create audit orchestrator
            if hasattr(scout_app, 'audit_orchestrator') and scout_app.audit_orchestrator:
                orchestrator = scout_app.audit_orchestrator
                logger.info("[bg-init] Using ScoutApp's audit orchestrator")
            else:
                logger.info("[bg-init] Creating unified audit service...")
                unified_audit_service = create_unified_audit_service(
                    database=scout_app.database,
                    w3=w3,
                    backend_client=scout_app.backend_client,
                    token_holder_scout=None,
                    liquidity_analyzer_scout=None,
                    tokenomics_analyzer_scout=None,
                )

                logger.info("[bg-init] Creating audit orchestrator...")
                orchestrator = create_audit_orchestrator(
                    database=scout_app.database,
                    backend_client=scout_app.backend_client,
                    w3=w3,
                    token_holder_scout=None,
                    tokenomics_analyzer_scout=None,
                    liquidity_analyzer_scout=None,
                    unified_audit_service=unified_audit_service,
                )

            # Register with unified API -- now /audit/trigger will work
            set_orchestrator(orchestrator)
            logger.info("[bg-init] Audit orchestrator registered - service is ready")

            # Store scout_app reference for shutdown
            global _scout_app_ref
            _scout_app_ref = scout_app

        except Exception as e:
            logger.exception(f"[bg-init] Background initialization failed: {e}")
            logger.error("[bg-init] Service will remain in 503 (not ready) state")

    t = threading.Thread(target=_init, name="bg-init", daemon=True)
    t.start()
    return t


# Module-level reference so signal handlers can shut down scouts
_scout_app_ref = None


def main() -> int:
    """Main entry point for Railway deployment."""

    try:
        # Check for required dependencies early
        try:
            from web3 import Web3  # noqa: F401
        except ImportError:
            logger.error("web3 required: pip install web3")
            return 1

        try:
            from fastapi import FastAPI  # noqa: F401
        except ImportError:
            logger.error("FastAPI required: pip install fastapi uvicorn")
            return 1

        # Register a FastAPI startup event so background init runs after
        # uvicorn binds the port -- Railway health checks will pass immediately.
        from scout.unified_api import app as fastapi_app

        @fastapi_app.on_event("startup")
        async def _launch_background_init():
            _do_background_initialization()

        # Get port from environment
        port = int(os.environ.get("PORT", os.environ.get("UNIFIED_API_PORT", "8080")))
        host = os.environ.get("UNIFIED_API_HOST", "0.0.0.0")

        logger.info(f"Starting unified API server on {host}:{port} (init deferred to background)")

        # Handle signals for graceful shutdown
        import signal
        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}, shutting down...")
            if _scout_app_ref:
                _scout_app_ref.shutdown()
            raise SystemExit(0)
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)

        # Start FastAPI server immediately -- heavy init runs in background
        from scout.unified_api import run_unified_api
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
