"""Audit orchestrator for coordinating multiple audit services.

This module coordinates multiple audit services to provide a full-spectrum audit:
- TokenHolderScout: Dynamic data (token distribution, holders)
- ContractAuditScout: Static data (contract code, deployments)
- UnifiedAuditService: Unified service for verified/unverified contract audits
- SecurityAuditScout: Vulnerability scanning
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger
    HAS_SCHEDULER = True
except ImportError:
    HAS_SCHEDULER = False
    BackgroundScheduler = None

from .audit_config import (
    get_dynamic_data_types,
    get_required_data_types,
    should_update_data,
)
from web3 import Web3

LOGGER = logging.getLogger(__name__)


@dataclass
class AuditRequest:
    """An audit request from the backend."""

    project_id: str
    token_address: str
    chain_id: int
    payment_id: str
    requested_at: datetime = field(default_factory=datetime.utcnow)

    def __str__(self) -> str:
        return f"AuditRequest(project={self.project_id[:8]}..., token={self.token_address[:10]}...)"


@dataclass
class AuditResult:
    """Results from an audit run."""

    project_id: str
    status: str  # "pending", "running", "completed", "failed"
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API response."""
        return {
            "project_id": self.project_id,
            "status": self.status,
            "data": self.data,
            "error": self.error,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class AuditOrchestrator:
    """Orchestrates multiple audit services for full-spectrum audits.

    The orchestrator:
    - Receives audit requests from backend (via webhook)
    - Runs all audit services in parallel
    - Aggregates results
    - Stores to backend
    - Triggers weekly updates for dynamic data

    Audit Services:
    - TokenHolderScout: Dynamic data (token distribution, holders)
    - TokenomicsAnalyzerScout: Supply mechanics, contract features, vesting
    - LiquidityAnalyzerScout: Pool data, TVL, trading metrics
    - UnifiedAuditService: Unified service for verified/unverified contract audits
    - SecurityAuditScout: Vulnerability scanning - TODO
    """

    def __init__(
        self,
        token_holder_scout: Any,  # TokenHolderScout
        tokenomics_analyzer_scout: Optional[Any] = None,  # TokenomicsAnalyzerScout
        liquidity_analyzer_scout: Optional[Any] = None,  # LiquidityAnalyzerScout
        contract_audit_scout: Optional[Any] = None,  # ContractAuditScout (DEPRECATED - use unified_audit)
        unified_audit_service: Optional[Any] = None,  # UnifiedAuditService
        backend_client: Any = None,  # BackendClient
        database: Any = None,  # DatabaseManager
        w3: Optional[Web3] = None,  # Web3 instance for blockchain interactions
    ):
        """Initialize the audit orchestrator.

        Args:
            token_holder_scout: Token holder scout for distribution data
            tokenomics_analyzer_scout: Optional tokenomics analyzer for supply mechanics
            liquidity_analyzer_scout: Optional liquidity analyzer for pool data
            contract_audit_scout: Optional contract audit scout (DEPRECATED - use unified_audit_service)
            unified_audit_service: Optional unified audit service for all contract audits
            backend_client: Backend API client
            database: Database manager
            w3: Optional Web3 instance for blockchain interactions
        """
        self.token_holder_scout = token_holder_scout
        self.tokenomics_analyzer_scout = tokenomics_analyzer_scout
        self.liquidity_analyzer_scout = liquidity_analyzer_scout
        self.contract_audit_scout = contract_audit_scout
        self.unified_audit_service = unified_audit_service
        self.backend_client = backend_client
        self.database = database
        self.w3 = w3
        self.scheduler: Optional[BackgroundScheduler] = None

        # Track running audits
        self._running_audits: Dict[str, AuditResult] = {}

    async def run_full_audit(
        self,
        project_id: str,
        token_address: str,
        chain_id: int,
        payment_id: Optional[str] = None,
    ) -> AuditResult:
        """Run full-spectrum audit for a project.

        Args:
            project_id: Backend project identifier
            token_address: Token contract address
            chain_id: Chain ID
            payment_id: Optional payment identifier

        Returns:
            AuditResult with aggregated results
        """
        request = AuditRequest(
            project_id=project_id,
            token_address=token_address,
            chain_id=chain_id,
            payment_id=payment_id or "",
        )

        LOGGER.info(f"Starting full audit: {request}")

        result = AuditResult(
            project_id=project_id,
            status="running",
            started_at=datetime.utcnow(),
        )
        self._running_audits[project_id] = result

        try:
            # Collect all audit data in parallel
            results = await self._collect_all_audit_data(
                token_address=token_address,
                chain_id=chain_id,
            )

            result.data = results
            result.status = "completed"
            result.completed_at = datetime.utcnow()

            # Store results to backend
            await self._store_audit_results(project_id, results)

            LOGGER.info(
                f"Completed full audit for {project_id[:8]}...",
                extra={
                    "project_id": project_id,
                    "data_keys": list(results.keys()),
                },
            )

        except Exception as e:
            result.status = "failed"
            result.error = str(e)
            result.completed_at = datetime.utcnow()

            LOGGER.error(
                f"Failed full audit for {project_id[:8]}...: {e}",
                exc_info=True,
            )

        finally:
            # Clean up from running audits
            self._running_audits.pop(project_id, None)

        return result

    async def _collect_all_audit_data(
        self,
        token_address: str,
        chain_id: int,
    ) -> Dict[str, Any]:
        """Collect data from all audit services in parallel.

        Args:
            token_address: Token contract address
            chain_id: Chain ID

        Returns:
            Dictionary with all collected audit data
        """
        results = {}
        tasks = []

        # Task 1: Token holder distribution (dynamic - weekly updates)
        if self.token_holder_scout:
            tasks.append(("token_distribution", self.token_holder_scout.collect_token_data(
                token_address=token_address,
                chain_id=chain_id,
            )))

        # Task 2: Tokenomics analysis (NEW!)
        # Note: TokenomicsAnalyzerScout will use cached holder data from database
        # if available, avoiding duplicate API calls with TokenHolderScout
        if self.tokenomics_analyzer_scout:
            tasks.append(("tokenomics", self.tokenomics_analyzer_scout.analyze_tokenomics(
                token_address=token_address,
                chain_id=str(chain_id),
            )))

        # Task 3: Liquidity analysis
        if self.liquidity_analyzer_scout:
            tasks.append(("liquidity", self.liquidity_analyzer_scout.analyze_liquidity(
                token_address=token_address,
                chain_id="ethereum" if chain_id == 1 else str(chain_id),
            )))

        # Task 4: Code audit (use unified audit service if available, otherwise fallback)
        if self.unified_audit_service:
            # Use new unified audit service (handles verified/unverified automatically)
            tasks.append(("code_audit", self.unified_audit_service._audit_verified_contract(
                token_address=token_address,
                chain_id=chain_id,
                force=False,
            )))
        elif self.contract_audit_scout:
            # Fallback to legacy contract audit scout
            tasks.append(("code_audit", self.contract_audit_scout.audit_contract(
                token_address=token_address,
                chain_id=chain_id,
                force=False,
            )))

        # Run all tasks in parallel and collect results
        if tasks:
            import asyncio
            completed = await asyncio.gather(
                *[task for _, task in tasks],
                return_exceptions=True,
            )

            for (key, _), result in zip(tasks, completed):
                if isinstance(result, Exception):
                    LOGGER.error(f"Failed to collect {key}: {result}")
                    results[key] = {
                        "error": str(result),
                        "collected_at": datetime.utcnow().isoformat(),
                    }
                elif result:
                    # Convert dataclass/result objects to dict for storage
                    if hasattr(result, "__dict__"):
                        results[key] = result.__dict__
                    elif hasattr(result, "to_dict"):
                        results[key] = result.to_dict()
                    else:
                        results[key] = result

        # Mark collection timestamp
        results["collected_at"] = datetime.utcnow().isoformat()

        return results

    async def _store_audit_results(
        self,
        project_id: str,
        results: Dict[str, Any],
    ) -> bool:
        """Store audit results to backend API.

        Args:
            project_id: Project identifier
            results: Audit results dictionary

        Returns:
            True if successful, False otherwise
        """
        import os

        endpoint = f"/admin/projects/{project_id}/audit-results"

        payload = {
            "audit_data": results,
            "completed_at": datetime.utcnow().isoformat(),
        }

        # Add internal API secret header for authentication
        internal_secret = os.environ.get("INTERNAL_API_SECRET")
        headers = {}
        if internal_secret:
            headers["X-Internal-Api-Secret"] = internal_secret

        try:
            # Use the backend client's PATCH method
            if hasattr(self.backend_client, "patch"):
                response = self.backend_client.patch(
                    endpoint,
                    json=payload,
                    headers=headers,
                )

                # Check response status
                if hasattr(response, "status_code"):
                    return response.status_code == 200
                return True

            # Fallback: try POST method
            elif hasattr(self.backend_client, "post"):
                response = self.backend_client.post(
                    endpoint,
                    json=payload,
                    headers=headers,
                )

                if hasattr(response, "status_code"):
                    return response.status_code == 200
                return True

            else:
                LOGGER.warning("Backend client has no patch/post method")
                return False

        except Exception as e:
            LOGGER.error(f"Failed to store audit results: {e}")
            return False

    def start_weekly_updates(self) -> None:
        """Start weekly updates for all dynamic data.

        Updates weekly:
        - TokenHolderScout (dynamic holder data)
        - TokenomicsAnalyzerScout (dynamic supply mechanics)
        - LiquidityAnalyzerScout (dynamic TVL/volume)

        Does NOT update:
        - ContractAuditScout (static - only runs on code change)

        Raises:
            ImportError: If APScheduler is not installed
        """
        if not HAS_SCHEDULER:
            raise ImportError(
                "APScheduler required for weekly updates: pip install apscheduler"
            )

        if self.scheduler is None:
            self.scheduler = BackgroundScheduler()
            self.scheduler.start()

        # Schedule all dynamic data updates every Monday at 2 AM
        self.scheduler.add_job(
            func=self._update_all_dynamic_data_job,
            trigger=CronTrigger(day_of_week=0, hour=2, minute=0),
            id="weekly_dynamic_updates",
            name="Weekly dynamic data updates (all scouts)",
            replace_existing=True,
        )

        LOGGER.info("Started weekly dynamic data updates (all scouts - Monday 2 AM)")

    def _update_all_dynamic_data_job(self) -> None:
        """Job wrapper for updating all dynamic data (runs in scheduler thread)."""
        # Run the async update in the event loop
        asyncio.create_task(self._update_all_dynamic_data())

    def _update_dynamic_data_job(self) -> None:
        """Job wrapper for updating dynamic data (runs in scheduler thread)."""
        # Run the async update in the event loop
        asyncio.create_task(self._update_dynamic_data())

    async def _update_dynamic_data(self) -> None:
        """Update dynamic data for all tracked projects.

        Only updates dynamic data (token holders), not static data.
        """
        LOGGER.info("Starting weekly dynamic data update")

        try:
            # Get all projects with token addresses
            projects = await self._get_tracked_projects()

            if not projects:
                LOGGER.info("No projects to update")
                return

            LOGGER.info(f"Updating {len(projects)} projects")

            for project in projects:
                token_address = project.get("token_address")
                chain_id = project.get("chain_id", 1)
                project_id = project.get("id")

                if not token_address or not project_id:
                    continue

                try:
                    # Only update dynamic data types
                    dynamic_results = {}

                    # Token distribution is dynamic weekly
                    if self.token_holder_scout:
                        holder_data = await self.token_holder_scout.collect_token_data(
                            token_address=token_address,
                            chain_id=chain_id,
                        )

                        if holder_data:
                            dynamic_results["token_distribution"] = holder_data

                    # Store updated results
                    if dynamic_results:
                        await self._store_audit_results(project_id, dynamic_results)
                        LOGGER.info(f"Updated dynamic data for {project_id[:8]}...")

                except Exception as e:
                    LOGGER.error(f"Failed to update {project_id[:8]}...: {e}")

        except Exception as e:
            LOGGER.error(f"Failed to update dynamic data: {e}", exc_info=True)

    async def _update_all_dynamic_data(self) -> None:
        """Update all dynamic data for tracked projects.

        Runs all dynamic scouts in parallel:
        - TokenHolderScout (runs first - fetches holder data)
        - TokenomicsAnalyzerScout (uses cached holder data from DB)
        - LiquidityAnalyzerScout (runs independently)

        Note: Does NOT include ContractAuditScout (static - only on code change).
        """
        LOGGER.info("Starting weekly dynamic data update (all scouts)")

        try:
            # Get all projects with token addresses
            projects = await self._get_tracked_projects()

            if not projects:
                LOGGER.info("No projects to update")
                return

            LOGGER.info(f"Updating {len(projects)} projects with all dynamic scouts")

            for project in projects:
                token_address = project.get("token_address")
                chain_id = project.get("chain_id", 1)
                project_id = project.get("id")

                if not token_address or not project_id:
                    continue

                try:
                    # Run all dynamic scouts in parallel
                    results = await self._collect_dynamic_audit_data(
                        token_address=token_address,
                        chain_id=chain_id,
                    )

                    # Store updated results
                    if results:
                        await self._store_audit_results(project_id, results)
                        LOGGER.info(
                            f"Updated all dynamic data for {project_id[:8]}... "
                            f"({len(results)} scout types updated)"
                        )

                except Exception as e:
                    LOGGER.error(f"Failed to update {project_id[:8]}...: {e}")

        except Exception as e:
            LOGGER.error(f"Failed to update all dynamic data: {e}", exc_info=True)

    async def _collect_dynamic_audit_data(
        self,
        token_address: str,
        chain_id: int,
    ) -> Dict[str, Any]:
        """Collect data from all DYNAMIC scouts only.

        Runs scouts in parallel, respecting data dependencies:
        - TokenHolderScout: Always runs (fetches holder data via shared HolderAPIManager)
        - TokenomicsAnalyzerScout: Always runs (uses cached holder data from DB if available)
        - LiquidityAnalyzerScout: Always runs (no dependencies)

        Excludes ContractAuditScout (static data - only runs on code change).

        Args:
            token_address: Token contract address
            chain_id: Chain ID

        Returns:
            Dictionary with all collected dynamic audit data
        """
        results = {}
        tasks = []

        # Task 1: Token holder distribution (always runs - caches data for other scouts)
        if self.token_holder_scout:
            tasks.append(
                (
                    "token_distribution",
                    self.token_holder_scout.collect_token_data(
                        token_address=token_address,
                        chain_id=chain_id,
                    ),
                )
            )

        # Task 2: Tokenomics analysis (uses cached holder data from DB)
        if self.tokenomics_analyzer_scout:
            tasks.append(
                (
                    "tokenomics",
                    self.tokenomics_analyzer_scout.analyze_tokenomics(
                        token_address=token_address,
                        chain_id=str(chain_id),
                    ),
                )
            )

        # Task 3: Liquidity analysis (runs independently)
        if self.liquidity_analyzer_scout:
            tasks.append(
                (
                    "liquidity",
                    self.liquidity_analyzer_scout.analyze_liquidity(
                        token_address=token_address,
                        chain_id="ethereum" if chain_id == 1 else str(chain_id),
                    ),
                )
            )

        # Run all tasks in parallel and collect results
        if tasks:
            completed = await asyncio.gather(
                *[task for _, task in tasks],
                return_exceptions=True,
            )

            for (key, _), result in zip(tasks, completed):
                if isinstance(result, Exception):
                    LOGGER.error(f"Failed to collect {key}: {result}")
                    results[key] = {
                        "error": str(result),
                        "collected_at": datetime.utcnow().isoformat(),
                    }
                elif result:
                    # Convert dataclass/result objects to dict for storage
                    if hasattr(result, "__dict__"):
                        results[key] = result.__dict__
                    elif hasattr(result, "to_dict"):
                        results[key] = result.to_dict()
                    else:
                        results[key] = result

        # Mark collection timestamp
        results["collected_at"] = datetime.utcnow().isoformat()

        return results

    async def _get_tracked_projects(self) -> List[Dict[str, Any]]:
        """Get list of projects from backend that need tracking.

        Returns:
            List of projects with token addresses
        """
        try:
            if hasattr(self.backend_client, "get"):
                response = await self.backend_client.get("/projects")

                if hasattr(response, "json"):
                    data = response.json()
                    # Filter projects with token addresses
                    return [
                        p
                        for p in data.get("projects", [])
                        if p.get("token_address")
                    ]

                elif isinstance(response, dict):
                    # Direct dict response
                    return [
                        p
                        for p in response.get("projects", [])
                        if p.get("token_address")
                    ]

        except Exception as e:
            LOGGER.error(f"Failed to get projects: {e}")

        return []

    def get_audit_status(self, project_id: str) -> Optional[AuditResult]:
        """Get status of a running or recently completed audit.

        Args:
            project_id: Project identifier

        Returns:
            AuditResult if found, None otherwise
        """
        return self._running_audits.get(project_id)

    def stop(self) -> None:
        """Stop the audit orchestrator and scheduler.

        Shuts down the background scheduler if running.
        """
        if self.scheduler and self.scheduler.running:
            self.scheduler.shutdown()
            LOGGER.info("Audit orchestrator stopped")

    def get_stats(self) -> Dict[str, Any]:
        """Get orchestrator statistics.

        Returns:
            Dictionary with stats
        """
        return {
            "running_audits": len(self._running_audits),
            "scheduler_running": self.scheduler is not None
            and self.scheduler.running,
            "dynamic_data_types": get_dynamic_data_types(),
            "required_data_types": get_required_data_types(),
        }


def create_audit_orchestrator(
    token_holder_scout: Any,
    tokenomics_analyzer_scout: Optional[Any] = None,
    liquidity_analyzer_scout: Optional[Any] = None,
    contract_audit_scout: Optional[Any] = None,
    unified_audit_service: Optional[Any] = None,
    backend_client: Any = None,
    database: Any = None,
    w3: Optional[Web3] = None,
) -> AuditOrchestrator:
    """Factory function to create an audit orchestrator.

    Args:
        token_holder_scout: Token holder scout instance
        tokenomics_analyzer_scout: Optional tokenomics analyzer scout instance
        liquidity_analyzer_scout: Optional liquidity analyzer scout instance
        contract_audit_scout: Optional contract audit scout instance (DEPRECATED - use unified_audit_service)
        unified_audit_service: Optional unified audit service instance (recommended)
        backend_client: Backend client instance
        database: Database manager instance
        w3: Optional Web3 instance for blockchain interactions

    Returns:
        AuditOrchestrator instance
    """
    return AuditOrchestrator(
        token_holder_scout=token_holder_scout,
        tokenomics_analyzer_scout=tokenomics_analyzer_scout,
        liquidity_analyzer_scout=liquidity_analyzer_scout,
        contract_audit_scout=contract_audit_scout,
        unified_audit_service=unified_audit_service,
        backend_client=backend_client,
        database=database,
        w3=w3,
    )
