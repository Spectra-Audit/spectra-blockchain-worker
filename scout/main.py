"""Main entry point for orchestrating Scout services."""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import threading
import time
from collections.abc import Sequence
from dataclasses import replace
from typing import List, Optional

from web3 import Web3

from .async_runner import shutdown_shared_async_runner
from .auth_wallet import load_or_create_admin_wallet
from .backend_client import BackendClient
from .database_manager import DatabaseManager
from .env_loader import load_env_file
from .featured_scout import FeaturedScout, _load_config_from_env, resolve_ws_provider_class
from .payment_wallet_scout import PaymentWalletScout
from .pro_scout import DEFAULT_DB_PATH, ProScout
from .project_scout import ProjectScout
from .siwe_authenticator import SiweAuthenticator
from .token_distribution_scout import TokenDistributionScout
from .token_holder_scout import TokenHolderScout, TrackedToken
from .usdt_payment_scout import USDTPaymentScout
from .websocket_provider_pool import WebSocketProviderPool

LOGGER = logging.getLogger(__name__)


class ScoutApp:
    """Facade that wires ProScout, FeaturedScout, ProjectScout, TokenDistributionScout, TokenHolderScout, USDTPaymentScout, PaymentWalletScout, LiquidityAnalyzerScout, TokenomicsAnalyzerScout, AuditOrchestrator, and UnifiedAuditService around a shared database."""

    def __init__(
        self,
        *,
        database: DatabaseManager,
        pro_scout: ProScout,
        featured_scout: FeaturedScout,
        project_scout: ProjectScout,
        usdt_payment_scout: Optional[USDTPaymentScout],
        payment_wallet_scout: Optional["PaymentWalletScout"] = None,
        token_distribution_scout: Optional[TokenDistributionScout],
        token_holder_scout: Optional[TokenHolderScout],
        liquidity_analyzer_scout: Optional["LiquidityAnalyzerScout"] = None,
        tokenomics_analyzer_scout: Optional["TokenomicsAnalyzerScout"] = None,
        contract_audit_scout: Optional["ContractAuditScout"] = None,
        audit_orchestrator: Optional["AuditOrchestrator"] = None,
        unified_audit_service: Optional["UnifiedAuditService"] = None,
        backend_client: BackendClient,
    ) -> None:
        self.database = database
        self.pro_scout = pro_scout
        self.featured_scout = featured_scout
        self.project_scout = project_scout
        self.usdt_payment_scout = usdt_payment_scout
        self.payment_wallet_scout = payment_wallet_scout
        self.token_distribution_scout = token_distribution_scout
        self.token_holder_scout = token_holder_scout
        self.liquidity_analyzer_scout = liquidity_analyzer_scout
        self.tokenomics_analyzer_scout = tokenomics_analyzer_scout
        self.contract_audit_scout = contract_audit_scout
        self.audit_orchestrator = audit_orchestrator
        self.unified_audit_service = unified_audit_service  # NEW: Unified audit service
        self.backend_client = backend_client
        self._running = False
        self._closed = False

    @classmethod
    def from_env(cls) -> "ScoutApp":
        """Construct the application from environment configuration."""

        load_env_file()
        db_path = os.environ.get("SCOUT_DB_PATH") or os.environ.get("DB_PATH") or DEFAULT_DB_PATH
        database = DatabaseManager(db_path)
        admin_wallet = load_or_create_admin_wallet(database)
        featured_config = _load_config_from_env(database=database)
        api_base_url = os.environ.get("API_BASE_URL") or featured_config.api_root

        # Initialize authenticator and backend client (may fail if backend not running)
        authenticator = None
        backend_client = None
        try:
            authenticator = SiweAuthenticator(api_base_url, admin_wallet, database)
            backend_client = BackendClient(
                api_base_url,
                token_provider=authenticator.get_tokens,
                token_persistor=authenticator.persist_tokens,
            )
        except Exception as e:
            LOGGER.warning(f"Failed to initialize backend client (backend may not be running): {e}")

        shared_pool = WebSocketProviderPool(provider_resolver=resolve_ws_provider_class)
        pro_scout = ProScout.from_env(
            database=database,
            backend_client=backend_client,
            admin_wallet=admin_wallet,
            ws_provider_pool=shared_pool,
        )
        if featured_config.db_path != db_path:
            featured_config = replace(featured_config, db_path=db_path)
        featured_scout = FeaturedScout(
            featured_config,
            database=database,
            backend_client=backend_client,
            ws_provider_pool=shared_pool,
        )

        # Register FeaturedScout with unified API server for on-demand payment confirmation
        if os.environ.get("ENABLE_UNIFIED_API", "").lower() == "true":
            try:
                from .unified_api import set_featured_scout
                set_featured_scout(featured_scout)
                LOGGER.info("FeaturedScout registered with unified API server")
            except ImportError:
                LOGGER.warning("FastAPI not available, FeaturedScout not registered with unified API")
        project_scout = ProjectScout.from_env(backend_client, database)

        # Initialize USDT Payment Scout if configured
        usdt_payment_scout = None
        if os.environ.get("USDT_TARGET_WALLET"):
            try:
                usdt_payment_scout = USDTPaymentScout.from_env(database, backend_client, shared_pool)
            except Exception as e:
                LOGGER.warning(f"Failed to initialize USDT Payment Scout: {e}")

        # Initialize Payment Wallet Scout if configured
        payment_wallet_scout = None
        if os.environ.get("PAYMENT_WALLET_ADDRESS"):
            try:
                payment_wallet_scout = PaymentWalletScout.from_env(
                    database=database,
                    backend_client=backend_client,
                    ws_provider_pool=shared_pool
                )
                LOGGER.info("Payment Wallet Scout initialized")
            except Exception as e:
                LOGGER.warning(f"Failed to initialize Payment Wallet Scout: {e}")

        # Initialize Token Distribution Scout (works without backend client)
        token_distribution_scout = None
        try:
            token_distribution_scout = TokenDistributionScout.from_env(
                database=database,
                backend_client=backend_client,  # Can be None
            )
            LOGGER.info("Token Distribution Scout initialized")
        except Exception as e:
            LOGGER.warning(f"Failed to initialize Token Distribution Scout: {e}")

        # Initialize Token Holder Scout (Ethplorer works with freekey by default)
        token_holder_scout = None
        # Ethplorer is always available with freekey, others require API keys
        has_any_provider = (
            os.environ.get("NODEREAL_API_KEY") or
            os.environ.get("MORALIS_API_KEY") or
            os.environ.get("COINGECKO_API_KEY") or
            True  # Ethplorer always available with freekey
        )
        if has_any_provider:
            try:
                from .holder_api_manager import create_holder_api_manager

                api_manager = create_holder_api_manager(database=database)

                # Parse tracked tokens from environment
                tracked_tokens_str = os.environ.get("TRACKED_TOKENS", "")
                tracked_tokens: List[TrackedToken] = []

                if tracked_tokens_str:
                    for token in tracked_tokens_str.split(","):
                        token = token.strip()
                        if token:
                            # Parse "address:chain_id" format, default to chain_id 1
                            parts = token.split(":")
                            if len(parts) == 2:
                                tracked_tokens.append(TrackedToken(parts[0], int(parts[1])))
                            else:
                                tracked_tokens.append(TrackedToken(token, 1))  # Default ETH

                token_holder_scout = TokenHolderScout(
                    database=database,
                    api_manager=api_manager,
                    backend_client=backend_client,
                    scheduled_day_of_week=int(os.environ.get("HOLDER_COLLECTION_DAY", 0)),  # Monday
                    scheduled_hour=int(os.environ.get("HOLDER_COLLECTION_HOUR", 2)),  # 2 AM
                    top_holder_limit=int(os.environ.get("TOP_HOLDER_LIMIT", 100)),
                )

                # Start scheduled collection if tokens are configured
                if tracked_tokens:
                    token_holder_scout.start_scheduled_collection(tracked_tokens)
                    LOGGER.info(f"Token Holder Scout tracking {len(tracked_tokens)} tokens")

            except Exception as e:
                LOGGER.warning(f"Failed to initialize Token Holder Scout: {e}")

        # Initialize Audit Orchestrator if TokenHolderScout exists and backend client is available
        audit_orchestrator = None
        if token_holder_scout and backend_client:
            try:
                from .audit_orchestrator import create_audit_orchestrator

                audit_orchestrator = create_audit_orchestrator(
                    token_holder_scout=token_holder_scout,
                    tokenomics_analyzer_scout=tokenomics_analyzer_scout,
                    liquidity_analyzer_scout=liquidity_analyzer_scout,
                    contract_audit_scout=contract_audit_scout,
                    backend_client=backend_client,
                    database=database,
                )

                # Start weekly updates for all dynamic data
                if os.environ.get("ENABLE_AUDIT_ORCHESTRATOR", "true").lower() == "true":
                    audit_orchestrator.start_weekly_updates()
                    LOGGER.info("Audit Orchestrator started with weekly dynamic data updates (all scouts)")

                # Register orchestrator with unified API server if enabled
                if os.environ.get("ENABLE_UNIFIED_API", "").lower() == "true":
                    try:
                        from .unified_api import set_orchestrator
                        set_orchestrator(audit_orchestrator)
                        LOGGER.info("Audit orchestrator registered with unified API server")
                    except ImportError:
                        LOGGER.warning("FastAPI not available, unified API server not registered")
                else:
                    # Fallback to old webhook server for backwards compatibility
                    try:
                        from .payment_webhook import set_orchestrator
                        set_orchestrator(audit_orchestrator)
                        LOGGER.info("Audit orchestrator registered with legacy webhook server")
                    except ImportError:
                        LOGGER.debug("FastAPI not available, webhook server not registered")

            except Exception as e:
                LOGGER.warning(f"Failed to initialize Audit Orchestrator: {e}")

        # Initialize Liquidity Analyzer Scout if enabled
        liquidity_analyzer_scout = None
        if os.environ.get("ENABLE_LIQUIDITY_ANALYZER", "").lower() == "true":
            try:
                from .liquidity_analyzer_scout import LiquidityAnalyzerScout
                from .dexscreener_client import DexScreenerClient

                liquidity_analyzer_scout = LiquidityAnalyzerScout(
                    database=database,
                    client=DexScreenerClient(),
                )
                LOGGER.info("Liquidity Analyzer Scout initialized")

            except Exception as e:
                LOGGER.warning(f"Failed to initialize Liquidity Analyzer Scout: {e}")

        # Initialize Tokenomics Analyzer Scout if enabled
        # IMPORTANT: Use the same api_manager as TokenHolderScout to avoid duplicate API calls
        tokenomics_analyzer_scout = None
        if os.environ.get("ENABLE_TOKENOMICS_ANALYZER", "").lower() == "true":
            try:
                from .tokenomics_analyzer_scout import TokenomicsAnalyzerScout

                # Use the same api_manager that was created for TokenHolderScout
                # This prevents duplicate API calls when both scouts need holder data
                tokenomics_analyzer_scout = TokenomicsAnalyzerScout(
                    database=database,
                    holder_api_manager=api_manager if token_holder_scout else None,
                    rpc_url=rpc_http_urls[0] if rpc_http_urls else None,
                )
                LOGGER.info("Tokenomics Analyzer Scout initialized (sharing HolderAPIManager)")

            except Exception as e:
                LOGGER.warning(f"Failed to initialize Tokenomics Analyzer Scout: {e}")

        # Initialize Contract Auditor Scout if enabled
        contract_audit_scout = None
        if os.environ.get("ENABLE_CONTRACT_AUDITOR", "").lower() == "true":
            try:
                from .contract_audit_scout import ContractAuditScout

                contract_audit_scout = ContractAuditScout(
                    database=database,
                    w3=w3,
                )
                LOGGER.info("Contract Auditor Scout initialized")

            except Exception as e:
                LOGGER.warning(f"Failed to initialize Contract Auditor Scout: {e}")

        # Update Audit Orchestrator to include all new scouts
        if audit_orchestrator:
            scouts_updated = []
            if tokenomics_analyzer_scout and not audit_orchestrator.tokenomics_analyzer_scout:
                audit_orchestrator.tokenomics_analyzer_scout = tokenomics_analyzer_scout
                scouts_updated.append("Tokenomics Analyzer")

            if liquidity_analyzer_scout and not audit_orchestrator.liquidity_analyzer_scout:
                audit_orchestrator.liquidity_analyzer_scout = liquidity_analyzer_scout
                scouts_updated.append("Liquidity Analyzer")

            if contract_audit_scout and not audit_orchestrator.contract_audit_scout:
                audit_orchestrator.contract_audit_scout = contract_audit_scout
                scouts_updated.append("Contract Auditor")

            if scouts_updated:
                LOGGER.info(f"Audit Orchestrator updated with: {', '.join(scouts_updated)}")

        # Initialize Unified Audit Service if enabled (NEW)
        unified_audit_service = None
        if os.environ.get("ENABLE_UNIFIED_AUDIT", "").lower() == "true":
            try:
                from .unified_audit_service import create_unified_audit_service
                from .unified_glm_orchestrator import UnifiedGLMOrchestrator

                # Create unified GLM orchestrator
                glm_orchestrator = UnifiedGLMOrchestrator()

                unified_audit_service = create_unified_audit_service(
                    database=database,
                    w3=w3,
                    backend_client=backend_client,
                    token_holder_scout=token_holder_scout,
                    liquidity_analyzer_scout=liquidity_analyzer_scout,
                    tokenomics_analyzer_scout=tokenomics_analyzer_scout,
                )
                LOGGER.info("Unified Audit Service initialized with GLM orchestrator")

            except Exception as e:
                LOGGER.warning(f"Failed to initialize Unified Audit Service: {e}")

        return cls(
            database=database,
            pro_scout=pro_scout,
            featured_scout=featured_scout,
            project_scout=project_scout,
            usdt_payment_scout=usdt_payment_scout,
            payment_wallet_scout=payment_wallet_scout,
            token_distribution_scout=token_distribution_scout,
            token_holder_scout=token_holder_scout,
            liquidity_analyzer_scout=liquidity_analyzer_scout,
            tokenomics_analyzer_scout=tokenomics_analyzer_scout,
            contract_audit_scout=contract_audit_scout,
            unified_audit_service=unified_audit_service,
            backend_client=backend_client,
        )

    def __enter__(self) -> "ScoutApp":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001, D401 - standard context manager signature
        self.shutdown()

    def start(self) -> None:
        """Start the background services."""

        if self._running:
            raise RuntimeError("ScoutApp already running")

        self.pro_scout.start()
        self.featured_scout.start()

        # Start USDT Payment Scout if configured
        if self.usdt_payment_scout:
            self.usdt_payment_scout.start()

        # Start Payment Wallet Scout if configured
        if self.payment_wallet_scout:
            self.payment_wallet_scout.start()

        self._running = True

    def stop(self, timeout: float = 10.0) -> None:
        """Stop background services."""

        services_to_stop = [self.featured_scout, self.pro_scout]

        # Add USDT scout if configured
        if self.usdt_payment_scout:
            services_to_stop.append(self.usdt_payment_scout)

        # Add Payment Wallet Scout if configured
        if self.payment_wallet_scout:
            services_to_stop.append(self.payment_wallet_scout)

        for service in services_to_stop:
            try:
                service.stop(timeout=timeout)
            except Exception as e:
                LOGGER.warning(f"Error stopping service: {e}")

        self._running = False

    def shutdown(self) -> None:
        """Stop services if needed and close the shared database."""

        if self._closed:
            return
        if self._running:
            self.stop()

        # Close Token Distribution Scout
        if self.token_distribution_scout:
            try:
                self.token_distribution_scout.close()
            except Exception as e:
                LOGGER.warning(f"Error closing Token Distribution Scout: {e}")

        # Close Token Holder Scout
        if self.token_holder_scout:
            try:
                from .async_runner import get_shared_async_runner
                runner = get_shared_async_runner()
                runner.run(self.token_holder_scout.close())
            except Exception as e:
                LOGGER.warning(f"Error closing Token Holder Scout: {e}")

        # Close Liquidity Analyzer Scout
        if self.liquidity_analyzer_scout:
            try:
                from .async_runner import get_shared_async_runner
                runner = get_shared_async_runner()
                runner.run(self.liquidity_analyzer_scout.close())
            except Exception as e:
                LOGGER.warning(f"Error closing Liquidity Analyzer Scout: {e}")

        # Close Tokenomics Analyzer Scout
        if self.tokenomics_analyzer_scout:
            try:
                from .async_runner import get_shared_async_runner
                runner = get_shared_async_runner()
                runner.run(self.tokenomics_analyzer_scout.close())
            except Exception as e:
                LOGGER.warning(f"Error closing Tokenomics Analyzer Scout: {e}")

        # Close Contract Auditor Scout
        if self.contract_audit_scout:
            try:
                from .async_runner import get_shared_async_runner
                runner = get_shared_async_runner()
                runner.run(self.contract_audit_scout.close())
            except Exception as e:
                LOGGER.warning(f"Error closing Contract Auditor Scout: {e}")

        # Close Unified Audit Service (NEW)
        if self.unified_audit_service:
            try:
                from .async_runner import get_shared_async_runner
                runner = get_shared_async_runner()
                runner.run(self.unified_audit_service.close())
            except Exception as e:
                LOGGER.warning(f"Error closing Unified Audit Service: {e}")

        # Shutdown Audit Orchestrator
        if self.audit_orchestrator:
            try:
                self.audit_orchestrator.stop()
            except Exception as e:
                LOGGER.warning(f"Error stopping Audit Orchestrator: {e}")

        self.database.close()
        if self.backend_client:
            try:
                self.backend_client.close()
            except Exception as e:
                LOGGER.warning(f"Error closing backend client: {e}")
        shutdown_shared_async_runner()
        self._closed = True

    def run(self) -> None:
        """Run both services until interrupted."""

        self.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            LOGGER.info("Shutdown requested via keyboard interrupt")
        finally:
            self.shutdown()

    def scan_projects(self, force_refresh: bool = False) -> list:
        """Run a project scan and return the results."""
        return self.project_scout.scan(force_refresh=force_refresh)

    def get_project_report(self, format_type: str = "text") -> str:
        """Generate a project discovery report."""
        return self.project_scout.report(format_type)

    def get_top_projects(self, limit: int = 10, category: str = None) -> list:
        """Get top projects by score."""
        return self.project_scout.get_top_projects(limit, category)

    def status(self) -> str:
        """Summarize the last processed block for each service."""

        pro_value = self.database.get_meta("pro_last_block")
        featured_value = self.database.get_meta("featured_last_block")
        project_last_scan = self.database.get_meta("project_last_scan")

        def _format(value: str | None) -> str:
            if value is None:
                return "unknown"
            try:
                return str(int(value))
            except ValueError:
                return value

        def _format_timestamp(value: str | None) -> str:
            if value is None:
                return "never"
            try:
                timestamp = float(value)
                return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))
            except (ValueError, OSError):
                return value

        status_parts = [
            f"ProScout last block: {_format(pro_value)}",
            f"FeaturedScout last block: {_format(featured_value)}",
            f"ProjectScout last scan: {_format_timestamp(project_last_scan)}"
        ]

        # Add USDT Payment Scout status if configured
        if self.usdt_payment_scout:
            usdt_status = self.usdt_payment_scout.get_status()
            usdt_parts = []

            if usdt_status.get("unprocessed_events", 0) > 0:
                usdt_parts.append(f"{usdt_status['unprocessed_events']} pending payments")

            if usdt_status.get("running", False):
                usdt_parts.append("running")

            if usdt_parts:
                status_parts.append(f"USDT Payment Scout: {', '.join(usdt_parts)}")

        return "; ".join(status_parts)

    def get_usdt_status(self) -> dict:
        """Get detailed USDT payment scout status."""
        if self.usdt_payment_scout:
            return self.usdt_payment_scout.get_status()
        return {"configured": False}


def _install_signal_handlers(app: ScoutApp, stop_event: threading.Event) -> None:
    def _handler(signum: int, frame) -> None:  # noqa: ANN001
        LOGGER.info("Signal received", extra={"signal": signum})
        stop_event.set()
        app.stop()

    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)


def main(argv: Sequence[str] | None = None) -> int:
    """Console entry point used by ``python -m scout``."""

    parser = argparse.ArgumentParser(description="Scout command line interface")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Existing commands
    run_parser = subparsers.add_parser("run", help="Run the Scout services")
    status_parser = subparsers.add_parser("status", help="Show the current Scout status")

    # New project scouting commands
    scan_parser = subparsers.add_parser("scan-projects", help="Scan and analyze projects")
    scan_parser.add_argument("--force", action="store_true", help="Force refresh and bypass cache")
    scan_parser.add_argument("--limit", type=int, default=100, help="Maximum number of projects to analyze")
    scan_parser.add_argument("--category", help="Filter by specific category")
    scan_parser.add_argument("--min-funding", type=float, help="Minimum funding amount")
    scan_parser.add_argument("--min-backers", type=int, help="Minimum number of backers")

    report_parser = subparsers.add_parser("project-report", help="Generate project discovery report")
    report_parser.add_argument("--format", choices=["text", "json", "csv"], default="text",
                             help="Report output format")
    report_parser.add_argument("--output", help="Output file path (default: stdout)")

    top_parser = subparsers.add_parser("top-projects", help="Show top projects by score")
    top_parser.add_argument("--limit", type=int, default=10, help="Number of top projects to show")
    top_parser.add_argument("--category", help="Filter by specific category")

    # USDT payment monitoring commands
    usdt_status_parser = subparsers.add_parser("usdt-status", help="Show USDT payment monitor status")
    usdt_status_parser.add_argument("--network", help="Filter by specific network")

    usdt_events_parser = subparsers.add_parser("usdt-events", help="Show recent USDT payment events")
    usdt_events_parser.add_argument("--limit", type=int, default=20, help="Number of events to show")
    usdt_events_parser.add_argument("--network", help="Filter by specific network")
    usdt_events_parser.add_argument("--unprocessed", action="store_true", help="Show only unprocessed events")

    # Token Distribution Scout commands
    distribution_parser = subparsers.add_parser("analyze-distribution", help="Analyze token holder distribution")
    distribution_parser.add_argument("--token", required=True, help="Token contract address")
    distribution_parser.add_argument("--chain", type=int, default=1, help="Chain ID (default: 1 for Ethereum)")
    distribution_parser.add_argument("--force", action="store_true", help="Force refresh and bypass cache")
    distribution_parser.add_argument("--from-block", type=int, help="Starting block number")
    distribution_parser.add_argument("--to-block", type=int, help="Ending block number")

    distribution_status_parser = subparsers.add_parser("distribution-status", help="Show token distribution cache status")

    # Event indexing commands (new parallel architecture)
    index_events_parser = subparsers.add_parser("index-events", help="Index Transfer events for scalable distribution analysis")
    index_events_parser.add_argument("--token", required=True, help="Token contract address")
    index_events_parser.add_argument("--chain", type=int, default=1, help="Chain ID (default: 1)")
    index_events_parser.add_argument("--from-block", type=int, help="Starting block (default: resume from last)")
    index_events_parser.add_argument("--to-block", type=int, help="Ending block (default: current)")
    index_events_parser.add_argument("--force", action="store_true", help="Force rescan from deployment block")
    index_events_parser.add_argument("--chunk-size", type=int, default=100000, help="Blocks per chunk (default: 100000)")

    index_status_parser = subparsers.add_parser("indexing-status", help="Show event indexing progress")
    index_status_parser.add_argument("--token", required=True, help="Token contract address")
    index_status_parser.add_argument("--chain", type=int, default=1, help="Chain ID (default: 1)")

    schedule_updates_parser = subparsers.add_parser("schedule-updates", help="Schedule automatic event index updates")
    schedule_updates_parser.add_argument("--token", required=True, help="Token contract address")
    schedule_updates_parser.add_argument("--chain", type=int, default=1, help="Chain ID (default: 1)")
    schedule_updates_parser.add_argument("--interval", type=int, default=24, help="Update interval in hours (default: 24)")
    schedule_updates_parser.add_argument("--remove", action="store_true", help="Remove scheduled updates for this token")

    # Token Holder Scout commands
    collect_holders_parser = subparsers.add_parser("collect-holders", help="Collect token holder data via API")
    collect_holders_parser.add_argument("--token", required=True, help="Token contract address")
    collect_holders_parser.add_argument("--chain", type=int, default=1, help="Chain ID (default: 1 for Ethereum)")
    collect_holders_parser.add_argument("--force", action="store_true", help="Force collection even if recently collected")

    holder_history_parser = subparsers.add_parser("holder-history", help="Show historical holder snapshots")
    holder_history_parser.add_argument("--token", required=True, help="Token contract address")
    holder_history_parser.add_argument("--chain", type=int, default=1, help="Chain ID (default: 1)")
    holder_history_parser.add_argument("--type", choices=["weekly", "monthly", "yearly"], default="weekly", help="Snapshot type")
    holder_history_parser.add_argument("--from", help="Start date (YYYY-MM-DD or YYYY-MM)")
    holder_history_parser.add_argument("--to", help="End date (YYYY-MM-DD or YYYY-MM)")

    holder_status_parser = subparsers.add_parser("holder-status", help="Show token holder scout status")

    # Provider configuration commands
    providers_parser = subparsers.add_parser("providers", help="Show RPC provider configuration and rate limits")
    providers_parser.add_argument("--chain", type=int, default=1, help="Chain ID (default: 1)")
    providers_parser.add_argument("--detail", action="store_true", help="Show detailed provider information")

    # Liquidity Analysis commands
    liquidity_parser = subparsers.add_parser("analyze-liquidity", help="Analyze token liquidity using DexScreener")
    liquidity_parser.add_argument("--token", required=True, help="Token contract address")
    liquidity_parser.add_argument("--chain", default="ethereum", help="Chain ID (default: ethereum)")
    liquidity_parser.add_argument("--cross-chains", help="Comma-separated additional chains to check")

    liquidity_history_parser = subparsers.add_parser("liquidity-history", help="Show historical liquidity snapshots")
    liquidity_history_parser.add_argument("--token", required=True, help="Token contract address")
    liquidity_history_parser.add_argument("--chain", default="ethereum", help="Chain ID")
    liquidity_history_parser.add_argument("--limit", type=int, default=10, help="Number of snapshots to show")

    # Tokenomics Analysis commands
    tokenomics_parser = subparsers.add_parser("analyze-tokenomics", help="Analyze token tokenomics and supply mechanics")
    tokenomics_parser.add_argument("--token", required=True, help="Token contract address")
    tokenomics_parser.add_argument("--chain", default="ethereum", help="Chain ID (default: ethereum)")

    tokenomics_history_parser = subparsers.add_parser("tokenomics-history", help="Show historical tokenomics snapshots")
    tokenomics_history_parser.add_argument("--token", required=True, help="Token contract address")
    tokenomics_history_parser.add_argument("--chain", default="ethereum", help="Chain ID")
    tokenomics_history_parser.add_argument("--limit", type=int, default=10, help="Number of snapshots to show")

    # Unified Audit commands (NEW)
    unified_audit_parser = subparsers.add_parser("unified-audit", help="Run unified smart contract audit")
    unified_audit_parser.add_argument("--project-id", required=True, help="Project ID")
    unified_audit_parser.add_argument("--token", required=True, help="Token contract address")
    unified_audit_parser.add_argument("--chain", type=int, default=1, help="Chain ID (default: 1 for Ethereum)")
    unified_audit_parser.add_argument("--type", choices=["verified", "unverified"], default="verified",
                                    help="Contract type (default: verified - has source code)")
    unified_audit_parser.add_argument("--abi-file", help="Path to ABI JSON file (for unverified contracts)")
    unified_audit_parser.add_argument("--audit-types", help="Comma-separated audit types: code,distribution,liquidity,tokenomics")
    unified_audit_parser.add_argument("--force", action="store_true", help="Force re-audit")

    scan_bytecode_parser = subparsers.add_parser("scan-bytecode", help="Scan unverified contract bytecode+ABI")
    scan_bytecode_parser.add_argument("--token", required=True, help="Token contract address")
    scan_bytecode_parser.add_argument("--chain", type=int, default=1, help="Chain ID (default: 1)")
    scan_bytecode_parser.add_argument("--abi-file", help="Path to ABI JSON file")
    scan_bytecode_parser.add_argument("--depth", choices=["quick", "full", "hybrid"], default="hybrid",
                                     help="Scan depth (default: hybrid)")

    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    # Handle providers command before ScoutApp initialization (doesn't need app)
    if args.command == "providers":
        from .rpc_providers_config import (
            get_all_providers,
            get_optimized_chunk_size,
            get_total_rate_limit,
            print_provider_summary,
        )

        if args.detail:
            # Detailed view
            providers = get_all_providers(args.chain)
            print(f"\nDetailed RPC Provider Configuration (Chain {args.chain}):")
            print("=" * 100)
            for p in providers:
                print(f"\n{p.name}:")
                print(f"  URL: {p.url}")
                print(f"  Rate Limit: {p.rate_limit} req/s")
                print(f"  Max Block Range: {p.max_block_range:,} blocks")
                print(f"  Max Batch Size: {p.max_batch_size}")
                print(f"  Priority: {p.priority}")
                print(f"  Archive Support: {'Yes' if p.supports_archive else 'No'}")
                print(f"  WebSocket Support: {'Yes' if p.supports_websocket else 'No'}")
                if p.ws_url:
                    print(f"  WebSocket URL: {p.ws_url}")
                if p.credit_cost_method:
                    print(f"  Credit Costs: {len(p.credit_cost_method)} methods configured")
            print("\n" + "=" * 100)
        else:
            # Summary view
            print_provider_summary(args.chain)

        return 0

    with ScoutApp.from_env() as app:
        if args.command == "run":
            stop_event = threading.Event()
            _install_signal_handlers(app, stop_event)
            app.start()
            try:
                while not stop_event.is_set():
                    time.sleep(1)
            finally:
                app.shutdown()
            return 0

        if args.command == "status":
            print(app.status())
            return 0

        if args.command == "scan-projects":
            # Update config if filters provided
            if any([args.min_funding, args.min_backers, args.category]):
                from .project_scout import ScanConfig
                config = ScanConfig(
                    min_funding=args.min_funding or 0,
                    min_backers=args.min_backers or 0,
                    categories=[args.category] if args.category else None,
                    max_results=args.limit,
                )
                app.project_scout.update_config(config)

            projects = app.scan_projects(force_refresh=args.force)
            print(f"Scanned {len(projects)} projects")

            if projects:
                print("\nTop 10 projects:")
                for i, project in enumerate(projects[:10], 1):
                    print(f"{i:2d}. {project.name} (Score: {project.overall_score:.1f})")
                    print(f"    Funding: ${project.total_funding:,.2f}, Backers: {project.backer_count:,}")
                    print(f"    Category: {project.category or 'N/A'}")
            return 0

        if args.command == "project-report":
            report = app.get_project_report(args.format)
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(report)
                print(f"Report saved to {args.output}")
            else:
                print(report)
            return 0

        if args.command == "top-projects":
            projects = app.get_top_projects(args.limit, args.category)
            if not projects:
                print("No projects found. Run 'scan-projects' first.")
                return 1

            title = f"Top {len(projects)} Projects"
            if args.category:
                title += f" in '{args.category}'"
            print(f"{title}:\n")

            for i, project in enumerate(projects, 1):
                print(f"{i:2d}. {project.name} (Score: {project.overall_score:.1f})")
                print(f"    ID: {project.project_id}")
                print(f"    Category: {project.category or 'N/A'}")
                print(f"    Funding: ${project.total_funding:,.2f}")
                print(f"    Backers: {project.backer_count:,}")
                print(f"    Engagement: {project.engagement_score:.1f}/100")
                print(f"    Growth: {project.growth_score:.1f}/100")
                print(f"    Quality: {project.quality_score:.1f}/100")
                print(f"    Creator: {project.creator_address}")
                print()
            return 0

        if args.command == "usdt-status":
            usdt_status = app.get_usdt_status()

            if not app.usdt_payment_scout:
                print("USDT Payment Scout is not configured")
                print("Set the USDT_TARGET_WALLET environment variable to enable it")
                return 1

            print("USDT Payment Scout Status:")
            print(f"  Target Wallet: {usdt_status['target_wallet']}")
            print(f"  Running: {usdt_status['running']}")
            print(f"  Unprocessed Events: {usdt_status['unprocessed_events']}")

            if usdt_status.get("networks"):
                print("  Networks:")
                for network, network_status in usdt_status["networks"].items():
                    status_icon = "✅" if network_status["enabled"] else "❌"
                    connection_icon = "🔗" if network_status["connected"] else "❌"
                    print(f"    {status_icon} {network.upper()}: {connection_icon} "
                          f"Block {network_status['last_processed_block']}")

            return 0

        if args.command == "usdt-events":
            if not app.usdt_payment_scout:
                print("USDT Payment Scout is not configured")
                print("Set the USDT_TARGET_WALLET environment variable to enable it")
                return 1

            # Query database for events
            with app.database.read_connection() as conn:
                query = """
                    SELECT transaction_hash, from_address, to_address, amount, block_number,
                           timestamp, network, processed, backend_notified, error_message, created_at
                    FROM usdt_payment_events
                    WHERE 1=1
                """
                params = []

                if args.network:
                    query += " AND network = ?"
                    params.append(args.network)

                if args.unprocessed:
                    query += " AND processed = FALSE"

                query += " ORDER BY created_at DESC LIMIT ?"
                params.append(args.limit)

                cursor = conn.execute(query, params)
                events = cursor.fetchall()

            if not events:
                print("No USDT payment events found")
                return 0

            print(f"Recent USDT Payment Events (showing {len(events)}):")
            print("-" * 80)

            for event in events:
                (tx_hash, from_addr, to_addr, amount, block_num, timestamp,
                 network, processed, notified, error_msg, created_at) = event

                # Format USDT amount (6 decimals)
                amount_usdt = int(amount) / 1_000_000

                status_parts = []
                if processed:
                    status_parts.append("✅ processed")
                if notified:
                    status_parts.append("🔔 notified")
                if error_msg:
                    status_parts.append(f"❌ {error_msg}")

                status = ", ".join(status_parts) if status_parts else "⏳ pending"

                print(f"📅 {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(created_at))}")
                print(f"🌐 {network.upper():<10} | 💰 {amount_usdt:>12,.2f} USDT | 📍 Block {block_num}")
                print(f"👤 From: {from_addr[:10]}...{from_addr[-6:]} → To: {to_addr[:10]}...{to_addr[-6:]}")
                print(f"🔗 Tx: {tx_hash[:20]}...")
                print(f"📊 Status: {status}")
                print()

            return 0

        if args.command == "analyze-distribution":
            if not app.token_distribution_scout:
                print("Token Distribution Scout is not initialized")
                return 1

            from .async_runner import get_shared_async_runner

            runner = get_shared_async_runner()

            async def analyze():
                metrics = await app.token_distribution_scout.analyze_token_distribution(
                    token_address=args.token,
                    chain_id=args.chain,
                    from_block=args.from_block,
                    to_block=args.to_block,
                    force_refresh=args.force,
                )
                return metrics

            print("Starting analysis...", flush=True)
            try:
                metrics = runner.run(analyze())
                print("Analysis complete, printing results...", flush=True)
            except Exception as e:
                print(f"Error during analysis: {e}", flush=True)
                return 1

            print(f"Token Distribution Analysis for {args.token}", flush=True)
            print(f"Chain ID: {args.chain}", flush=True)
            print("-" * 60, flush=True)
            print(f"Holder Count: {metrics.holder_count:,}", flush=True)
            print(f"Gini Coefficient: {metrics.gini_coefficient:.4f}", flush=True)
            print(f"Nakamoto Coefficient: {metrics.nakamoto_coefficient}", flush=True)
            print(f"Top 10% Supply: {metrics.top_10_pct_supply:.3f}%", flush=True)
            print(f"Top 1% Supply: {metrics.top_1_pct_supply:.3f}%", flush=True)
            print(f"Max Balance: {metrics.max_balance:,}", flush=True)
            print(f"Total Supply: {metrics.total_supply:,}", flush=True)
            print(f"Transaction Count: {metrics.transaction_count:,}", flush=True)
            print(f"Last Scanned Block: {metrics.last_scanned_block or 'N/A'}", flush=True)
            print("Done printing, exiting...", flush=True)

            return 0

        if args.command == "distribution-status":
            if not app.token_distribution_scout:
                print("Token Distribution Scout is not initialized")
                return 1

            with app.database.read_connection() as conn:
                cursor = conn.execute("""
                    SELECT token_address, chain_id, holder_count, gini_coefficient,
                           nakamoto_coefficient, top_10_pct, transaction_count, cached_at
                    FROM token_distribution_cache
                    ORDER BY cached_at DESC
                    LIMIT 20
                """)
                rows = cursor.fetchall()

            if not rows:
                print("No cached distribution metrics found")
                return 0

            print("Token Distribution Cache Status:")
            print("-" * 100)
            for row in rows:
                (token_addr, chain_id, holder_count, gini, nakamoto, top_10, tx_count, cached_at) = row
                cached_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(cached_at))
                print(f"{token_addr[:10]}...{token_addr[-6:]:<8} | Chain {chain_id} | "
                      f"Holders: {holder_count:>6,} | Gini: {gini:.3f} | Txns: {tx_count:>6,} | Cached: {cached_time}")

            return 0

        if args.command == "index-events":
            from .parallel_event_indexer import index_token

            print("Starting event indexing...", flush=True)
            print(f"Token: {args.token}", flush=True)
            print(f"Chain: {args.chain}", flush=True)
            print(f"Chunk size: {args.chunk_size:,} blocks", flush=True)

            try:
                progress = index_token(
                    database=app.database,
                    token_address=args.token,
                    chain_id=args.chain,
                    deployment_block=args.from_block,
                    end_block=args.to_block,
                    force_rescan=args.force,
                )

                print("\nIndexing complete!", flush=True)
                print(f"Total events indexed: {progress.total_events:,}", flush=True)
                print(f"Blocks scanned: {progress.first_block:,} to {progress.last_block:,}", flush=True)
                print(f"Chunks processed: {progress.completed_chunks}/{progress.total_chunks}", flush=True)
                print(f"Failed chunks: {progress.failed_chunks}", flush=True)

                if progress.is_complete:
                    print("Status: Complete ✅", flush=True)
                else:
                    print(f"Status: {progress.percent_complete:.1f}% complete", flush=True)

                return 0

            except Exception as e:
                print(f"Error during indexing: {e}", flush=True)
                return 1

        if args.command == "indexing-status":
            from .async_runner import get_shared_async_runner

            # Check event scan progress
            event_progress = app.database.get_event_scan_progress(args.token, args.chain)

            print(f"Event Indexing Status for {args.token} on Chain {args.chain}:")
            print("-" * 60)

            if not event_progress:
                print("No indexing progress found.")
                print("To start indexing, run:")
                print(f"  python -m scout index-events --token {args.token} --chain {args.chain}")
                return 0

            print(f"Deployment Block: {event_progress['deployment_block']:,}")
            print(f"Current Block: {event_progress['current_block']:,}")
            print(f"Last Scanned Block: {event_progress['last_scanned_block']:,}" if event_progress['last_scanned_block'] else "Last Scanned Block: Not started")
            print(f"Total Events Indexed: {event_progress['total_events_indexed']:,}")
            print(f"Last Scan Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(event_progress['last_scan_time']))}")

            # Calculate progress
            if event_progress['last_scanned_block']:
                blocks_remaining = event_progress['current_block'] - event_progress['last_scanned_block']
                total_blocks = event_progress['current_block'] - event_progress['deployment_block']
                blocks_done = event_progress['last_scanned_block'] - event_progress['deployment_block']
                percent = (blocks_done / total_blocks * 100) if total_blocks > 0 else 0
                print(f"Progress: {percent:.1f}% ({blocks_done:,}/{total_blocks:,} blocks)")
                print(f"Blocks Remaining: {blocks_remaining:,}")

            # Count events in database
            event_count = app.database.get_transfer_event_count(args.token, args.chain)
            print(f"Events in Database: {event_count:,}")

            return 0

        if args.command == "schedule-updates":
            try:
                from .event_update_scheduler import create_scheduler
            except ImportError as e:
                print(f"Error: APScheduler not installed. Install with: pip install apscheduler")
                return 1

            if args.remove:
                # For removal, we'd need to track running schedulers differently
                # For now, just inform the user
                print("To remove scheduled updates, restart the scout service without the token.")
                return 0

            print(f"Scheduling updates for {args.token} on chain {args.chain}", flush=True)
            print(f"Update interval: {args.interval} hours", flush=True)

            scheduler = create_scheduler(app.database)
            scheduler.start()
            scheduler.schedule_token_updates(
                token_address=args.token,
                chain_id=args.chain,
                interval_hours=args.interval,
            )

            print(f"Scheduled updates configured successfully!", flush=True)
            print(f"Next update will run in {args.interval} hours.", flush=True)
            print("Note: The scheduler will stop when this process exits.", flush=True)
            print("For persistent scheduling, use a daemon service.", flush=True)

            # Keep the scheduler running
            try:
                print("\nPress Ctrl+C to stop the scheduler...", flush=True)
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\nStopping scheduler...", flush=True)
                scheduler.stop()
                print("Scheduler stopped.", flush=True)

            return 0

        if args.command == "collect-holders":
            if not app.token_holder_scout:
                print("Token Holder Scout is not initialized")
                print("Set NODEREAL_API_KEY or MORALIS_API_KEY environment variable to enable it")
                return 1

            from .async_runner import get_shared_async_runner

            runner = get_shared_async_runner()

            async def collect():
                data = await app.token_holder_scout.collect_and_store(
                    token_address=args.token,
                    chain_id=args.chain,
                    force=args.force,
                )
                return data

            print(f"Collecting holder data for {args.token} on chain {args.chain}...", flush=True)
            try:
                data = runner.run(collect())
            except Exception as e:
                print(f"Error during collection: {e}", flush=True)
                return 1

            if not data:
                print("No data collected (all providers failed or recently collected)")
                return 1

            print(f"Collection successful!", flush=True)
            print(f"Provider: {data['provider']}", flush=True)
            print(f"Holders: {data['holder_count']:,}", flush=True)
            print(f"Top holders collected: {len(data['top_holders'])}", flush=True)
            print(f"\nMetrics:", flush=True)
            print(f"  Gini Coefficient: {data['metrics']['gini_coefficient']:.4f}", flush=True)
            print(f"  Nakamoto Coefficient: {data['metrics']['nakamoto_coefficient']}", flush=True)
            print(f"  Top 10% Supply: {data['metrics']['top_10_pct_supply']:.3f}%", flush=True)
            print(f"  Top 1% Supply: {data['metrics']['top_1_pct_supply']:.3f}%", flush=True)
            print(f"  Estimated Total Supply: {data['metrics']['estimated_total_supply']:,}", flush=True)

            return 0

        if args.command == "holder-history":
            snapshots = app.database.get_historical_snapshots(
                token_address=args.token,
                chain_id=args.chain,
                from_date=getattr(args, "from"),
                to_date=args.to,
                snapshot_type=args.type,
            )

            if not snapshots:
                print(f"No {args.type} snapshots found for {args.token} on chain {args.chain}")
                return 0

            # Header based on snapshot type
            if args.type == "weekly":
                print(f"Weekly Snapshots for {args.token[:10]}...{args.token[-6:]} (Chain {args.chain}):")
                print("-" * 100)
                print(f"{'Week Start':<12} | {'Week End':<12} | {'Holders':>8} | {'Gini':>6} | {'Nakamoto':>9} | {'Top 10%':>7} | {'Top 1%':>7}")
                print("-" * 100)
                for snap in snapshots:
                    print(f"{snap['week_start']:<12} | {snap['week_end']:<12} | {snap['holder_count']:>8,} | "
                          f"{snap['gini_coefficient']:>6.3f} | {snap['nakamoto_coefficient']:>9} | "
                          f"{snap['top_10_pct_supply']:>6.2f}% | {snap['top_1_pct_supply']:>6.2f}%")
            elif args.type == "monthly":
                print(f"Monthly Snapshots for {args.token[:10]}...{args.token[-6:]} (Chain {args.chain}):")
                print("-" * 90)
                print(f"{'Month':<10} | {'Holders':>8} | {'Gini':>6} | {'Nakamoto':>9} | {'Top 10%':>7} | {'Top 1%':>7}")
                print("-" * 90)
                for snap in snapshots:
                    print(f"{snap['month']:<10} | {snap['holder_count']:>8,} | "
                          f"{snap['gini_coefficient']:>6.3f} | {snap['nakamoto_coefficient']:>9} | "
                          f"{snap['top_10_pct_supply']:>6.2f}% | {snap['top_1_pct_supply']:>6.2f}%")
            else:  # yearly
                print(f"Yearly Snapshots for {args.token[:10]}...{args.token[-6:]} (Chain {args.chain}):")
                print("-" * 90)
                print(f"{'Year':<6} | {'Holders':>8} | {'Gini':>6} | {'Nakamoto':>9} | {'Top 10%':>7} | {'Top 1%':>7}")
                print("-" * 90)
                for snap in snapshots:
                    print(f"{snap['year']:<6} | {snap['holder_count']:>8,} | "
                          f"{snap['gini_coefficient']:>6.3f} | {snap['nakamoto_coefficient']:>9} | "
                          f"{snap['top_10_pct_supply']:>6.2f}% | {snap['top_1_pct_supply']:>6.2f}%")

            return 0

        if args.command == "holder-status":
            if not app.token_holder_scout:
                print("Token Holder Scout is not configured")
                print("To enable it, set NODEREAL_API_KEY or MORALIS_API_KEY environment variable")
                return 0

            print("Token Holder Scout Status:")
            print(f"  Top Holder Limit: {app.token_holder_scout.top_holder_limit}")
            print(f"  Scheduled: Day {app.token_holder_scout.scheduled_day} at {app.token_holder_scout.scheduled_hour}:00")
            print(f"  Scheduler Running: {app.token_holder_scout.scheduler and app.token_holder_scout.scheduler.running}")

            # Show tracked tokens from environment
            tracked_tokens_str = os.environ.get("TRACKED_TOKENS", "")
            if tracked_tokens_str:
                print("  Tracked Tokens:")
                for token in tracked_tokens_str.split(","):
                    token = token.strip()
                    if token:
                        parts = token.split(":")
                        if len(parts) == 2:
                            print(f"    {parts[0][:10]}...{parts[0][-6:]} (Chain {parts[1]})")
                        else:
                            print(f"    {token[:10]}...{token[-6:]} (Chain 1)")
            else:
                print("  Tracked Tokens: None (set TRACKED_TOKENS environment variable)")

            # Show latest weekly snapshots
            with app.database.read_connection() as conn:
                cursor = conn.execute("""
                    SELECT token_address, chain_id, week_start, holder_count, gini_coefficient
                    FROM token_holder_weekly_snapshots
                    ORDER BY week_start DESC
                    LIMIT 10
                """)
                rows = cursor.fetchall()

            if rows:
                print("\n  Recent Weekly Snapshots:")
                for row in rows:
                    token_addr, chain_id, week_start, holder_count, gini = row
                    print(f"    {token_addr[:10]}...{token_addr[-6:]} (Chain {chain_id}): "
                          f"{holder_count} holders, Gini={gini:.3f}, Week of {week_start}")

            return 0

        if args.command == "analyze-liquidity":
            if not app.liquidity_analyzer_scout:
                print("Liquidity Analyzer Scout is not enabled")
                print("Set ENABLE_LIQUIDITY_ANALYZER=true environment variable")
                return 1

            from .async_runner import get_shared_async_runner

            runner = get_shared_async_runner()

            cross_chains = args.cross_chains.split(",") if args.cross_chains else None

            async def analyze():
                result = await app.liquidity_analyzer_scout.analyze_liquidity(
                    token_address=args.token,
                    chain_id=args.chain,
                    cross_chain_ids=cross_chains,
                )
                return result

            result = runner.run(analyze())

            print(f"\nLiquidity Analysis for {args.token} on {args.chain}", flush=True)
            print("=" * 60, flush=True)
            print(f"Score: {result.score:.1f}/100 ({result.risk_level.upper()} risk)", flush=True)
            print(f"TVL: ${result.metrics.total_tvl_usd:,.0f}", flush=True)
            print(f"Pairs: {result.metrics.total_pairs} across {result.metrics.unique_dexes} DEXes", flush=True)
            print(f"Largest pool: {result.metrics.largest_pool_tvl_pct:.1f}% of TVL", flush=True)
            print(f"24h Volume: ${result.metrics.total_volume_h24:,.0f}", flush=True)
            print(f"24h Transactions: {result.metrics.total_txns_h24:,}", flush=True)

            if result.metrics.flags:
                print(f"\nFlags: {', '.join(result.metrics.flags)}", flush=True)

            print(f"\nRecommendations:", flush=True)
            for rec in result.recommendations:
                print(f"  • {rec}", flush=True)

            return 0

        if args.command == "liquidity-history":
            if not app.liquidity_analyzer_scout:
                print("Liquidity Analyzer Scout is not enabled")
                print("Set ENABLE_LIQUIDITY_ANALYZER=true environment variable")
                return 1

            snapshots = app.database.get_liquidity_snapshots(
                token_address=args.token,
                chain_id=args.chain,
                limit=args.limit,
            )

            if not snapshots:
                print(f"No liquidity snapshots found for {args.token} on {args.chain}", flush=True)
                return 0

            print(f"Liquidity History for {args.token[:10]}...{args.token[-6:]} ({args.chain}):", flush=True)
            print("-" * 120, flush=True)
            print(f"{'Analyzed At':<20} | {'TVL':>15} | {'Score':>6} | {'Risk':<10} | {'Pairs':>5} | {'DEXes':>5} | {'Volume 24h':>15}", flush=True)
            print("-" * 120, flush=True)

            for snap in snapshots:
                # analyzed_at is now stored as ISO string format
                analyzed_at = snap['analyzed_at']
                # Parse ISO string and format nicely
                try:
                    from datetime import datetime
                    dt = datetime.fromisoformat(analyzed_at.replace('Z', '+00:00'))
                    analyzed_time = dt.strftime('%Y-%m-%d %H:%M:%S')
                except Exception:
                    analyzed_time = str(analyzed_at)[:19]  # Fallback to string slice

                print(f"{analyzed_time:<20} | ${snap['total_tvl_usd']:>14,.0f} | {snap['liquidity_score']:>5.1f}/100 | "
                      f"{snap['risk_level']:<10} | {snap['total_pairs']:>5} | {snap['unique_dexes']:>5} | "
                      f"${snap['total_volume_h24']:>14,.0f}", flush=True)

            return 0

        if args.command == "analyze-tokenomics":
            if not app.tokenomics_analyzer_scout:
                print("Tokenomics Analyzer Scout is not enabled")
                print("Set ENABLE_TOKENOMICS_ANALYZER=true environment variable")
                return 1

            from .async_runner import get_shared_async_runner

            runner = get_shared_async_runner()

            async def analyze():
                result = await app.tokenomics_analyzer_scout.analyze_tokenomics(
                    token_address=args.token,
                    chain_id=args.chain,
                )
                return result

            result = runner.run(analyze())

            print(f"\nTokenomics Analysis for {args.token} on {args.chain}", flush=True)
            print("=" * 60, flush=True)
            print(f"Score: {result.score:.1f}/100 ({result.risk_level.upper()} risk)", flush=True)
            print(f"Supply Tier: {result.metrics.supply_tier}", flush=True)
            print(f"Total Holders: {result.metrics.total_holders:,}", flush=True)
            print(f"Top 10 Holders: {result.metrics.top_10_holder_pct:.1f}%", flush=True)
            print(f"Contract Holders: {result.metrics.contract_holder_pct:.1f}%", flush=True)
            print(f"Staking Contracts: {result.metrics.staking_contract_pct:.1f}%", flush=True)

            if result.metrics.flags:
                print(f"\nFlags: {', '.join(result.metrics.flags)}", flush=True)

            print(f"\nRecommendations:", flush=True)
            for rec in result.recommendations:
                print(f"  • {rec}", flush=True)

            return 0

        if args.command == "tokenomics-history":
            if not app.tokenomics_analyzer_scout:
                print("Tokenomics Analyzer Scout is not enabled")
                print("Set ENABLE_TOKENOMICS_ANALYZER=true environment variable")
                return 1

            snapshots = app.database.get_tokenomics_snapshots(
                token_address=args.token,
                chain_id=args.chain,
                limit=args.limit,
            )

            if not snapshots:
                print(f"No tokenomics snapshots found for {args.token} on {args.chain}", flush=True)
                return 0

            print(f"Tokenomics History for {args.token[:10]}...{args.token[-6:]} ({args.chain}):", flush=True)
            print("-" * 120, flush=True)
            print(f"{'Analyzed At':<20} | {'Supply Tier':<12} | {'Score':>6} | {'Risk':<10} | {'Holders':>10} | {'Staking %':>10}", flush=True)
            print("-" * 120, flush=True)

            for snap in snapshots:
                analyzed_at = snap['analyzed_at']
                try:
                    from datetime import datetime
                    dt = datetime.fromisoformat(analyzed_at.replace('Z', '+00:00'))
                    analyzed_time = dt.strftime('%Y-%m-%d %H:%M:%S')
                except Exception:
                    analyzed_time = str(analyzed_at)[:19]

                print(f"{analyzed_time:<20} | {snap['supply_tier']:<12} | {snap['tokenomics_score']:>5.1f}/100 | "
                      f"{snap['risk_level']:<10} | {snap['total_holders']:>10,} | {snap['staking_contract_pct']:>9.1f}%", flush=True)

            return 0

        # Unified Audit command (NEW)
        if args.command == "unified-audit":
            if not app.unified_audit_service:
                print("Unified Audit Service is not enabled")
                print("Set ENABLE_UNIFIED_AUDIT=true environment variable")
                return 1

            from .async_runner import get_shared_async_runner
            from scout.bytecode_abi_scanner import ScanDepth

            runner = get_shared_async_runner()

            # Parse audit types
            audit_types = args.audit_types.split(",") if args.audit_types else ["code", "distribution", "liquidity", "tokenomics"]

            # Load ABI if provided
            abi = None
            if args.abi_file:
                with open(args.abi_file, 'r') as f:
                    abi = json.load(f)

            async def run_audit():
                result = await app.unified_audit_service.run_unified_audit(
                    project_id=args.project_id,
                    token_address=args.token,
                    chain_id=args.chain,
                    audit_types=audit_types,
                    force=args.force,
                    abi=abi,
                )
                return result

            result = runner.run(run_audit())

            print(f"\nUnified Audit for {args.token} (Chain {args.chain})", flush=True)
            print("=" * 60, flush=True)
            print(f"Project ID: {result.project_id}", flush=True)
            print(f"Overall Score: {result.overall_score:.1f}/100 ({result.risk_level.upper()} risk)", flush=True)

            if result.code_audit:
                code_audit = result.code_audit
                print(f"\nCode Audit:", flush=True)
                print(f"  Score: {code_audit.get('overall_score', 0):.1f}/100", flush=True)
                print(f"  Verified: {code_audit.get('is_verified', False)}", flush=True)
                print(f"  AI Findings: {len(code_audit.get('ai_audit_findings', []))}", flush=True)

            if result.distribution_metrics:
                print(f"\nDistribution Metrics:", flush=True)
                metrics = result.distribution_metrics.get('metrics', {})
                print(f"  Holders: {metrics.get('holder_count', 0):,}", flush=True)
                print(f"  Gini: {metrics.get('gini_coefficient', 0):.3f}", flush=True)

            if result.liquidity_metrics:
                print(f"\nLiquidity Metrics:", flush=True)
                print(f"  Score: {result.liquidity_metrics.get('score', 0):.1f}/100", flush=True)

            if result.tokenomics_metrics:
                print(f"\nTokenomics Metrics:", flush=True)
                print(f"  Score: {result.tokenomics_metrics.get('score', 0):.1f}/100", flush=True)

            if result.flags:
                print(f"\nFlags: {', '.join(result.flags)}", flush=True)

            if result.recommendations:
                print(f"\nRecommendations:", flush=True)
                for rec in result.recommendations[:5]:
                    print(f"  • {rec}", flush=True)

            return 0

        # Scan Bytecode command (NEW)
        if args.command == "scan-bytecode":
            from .async_runner import get_shared_async_runner
            from scout.bytecode_abi_scanner import ScanDepth
            from scout.unified_glm_orchestrator import UnifiedGLMOrchestrator

            runner = get_shared_async_runner()

            # Load ABI if provided
            abi = []
            if args.abi_file:
                with open(args.abi_file, 'r') as f:
                    abi = json.load(f)

            # Create scanner
            from scout.bytecode_abi_scanner import BytecodeAbiScanner
            glm_orchestrator = UnifiedGLMOrchestrator()
            scanner = BytecodeAbiScanner(w3=w3, glm_orchestrator=glm_orchestrator)

            async def scan():
                # Get bytecode
                checksum_address = Web3.to_checksum_address(args.token)
                bytecode = w3.eth.get_code(checksum_address).hex()

                # Map depth
                depth_map = {
                    "quick": ScanDepth.QUICK,
                    "full": ScanDepth.FULL,
                    "hybrid": ScanDepth.HYBRID,
                }
                scan_depth = depth_map[args.depth]

                result = await scanner.scan_unverified_contract(
                    contract_address=args.token,
                    chain_id=args.chain,
                    bytecode=bytecode,
                    abi=abi,
                    scan_depth=scan_depth,
                )
                return result

            result = runner.run(scan())

            print(f"\nBytecode+ABI Scan for {args.token} (Chain {args.chain})", flush=True)
            print("=" * 60, flush=True)
            print(f"Scan Depth: {result.scan_depth.value}", flush=True)
            print(f"Score: {result.overall_score:.1f}/100 ({result.risk_level.upper()} risk)", flush=True)
            print(f"Contract Type: {result.contract_type}", flush=True)
            print(f"Is Proxy: {result.is_proxy}", flush=True)
            if result.proxy_type:
                print(f"Proxy Type: {result.proxy_type}", flush=True)

            if result.detected_standards:
                print(f"Detected Standards: {', '.join(result.detected_standards)}", flush=True)

            print(f"\nBytecode Patterns: {len(result.bytecode_patterns)}", flush=True)
            for pattern in result.bytecode_patterns[:5]:
                print(f"  - [{pattern.severity}] {pattern.pattern_type}: {pattern.description}", flush=True)

            print(f"\nABI Analysis: {len(result.abi_analysis)}", flush=True)
            for analysis in result.abi_analysis[:5]:
                print(f"  - [{analysis.severity}] {analysis.function_signature}: {', '.join(analysis.risk_flags)}", flush=True)

            if result.glm_findings:
                print(f"\nGLM Findings: {len(result.glm_findings)}", flush=True)
                for finding in result.glm_findings[:5]:
                    print(f"  - [{finding.get('severity', 'info')}] {finding.get('description', '')}", flush=True)

            if result.flags:
                print(f"\nFlags: {', '.join(result.flags)}", flush=True)

            return 0

    return 1


if __name__ == "__main__":  # pragma: no cover - convenience for direct execution
    raise SystemExit(main())
