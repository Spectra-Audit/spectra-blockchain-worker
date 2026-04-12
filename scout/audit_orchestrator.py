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

import httpx

import dataclasses


def _serialize_for_json(obj: Any) -> Any:
    """Recursively convert dataclass instances and other non-JSON types to dicts."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _serialize_for_json(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, dict):
        return {k: _serialize_for_json(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_serialize_for_json(item) for item in obj]
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, (int, float, str, bool)) or obj is None:
        return obj
    # Fallback: try __dict__ for objects that aren't standard types
    if hasattr(obj, "__dict__"):
        return _serialize_for_json(obj.__dict__)
    return str(obj)


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

        # Executive summary orchestrator (separate from code audit system)
        self._summary_orchestrator = None
        try:
            from executive_summary.orchestrator import SummaryOrchestrator
            self._summary_orchestrator = SummaryOrchestrator()
        except Exception as exc:
            LOGGER.warning("Executive summary orchestrator not available: %s", exc)

    async def run_full_audit(
        self,
        project_id: str,
        token_address: str,
        chain_id: int,
        payment_id: Optional[str] = None,
        token_addresses: Optional[List[str]] = None,
    ) -> AuditResult:
        """Run full-spectrum audit for a project.

        Supports multi-token projects: when token_addresses is provided,
        runs all scouts for each token and aggregates results.

        Args:
            project_id: Backend project identifier
            token_address: Primary token contract address
            chain_id: Chain ID
            payment_id: Optional payment identifier
            token_addresses: All token addresses for multi-token projects

        Returns:
            AuditResult with aggregated results
        """
        request = AuditRequest(
            project_id=project_id,
            token_address=token_address,
            chain_id=chain_id,
            payment_id=payment_id or "",
        )

        addresses = token_addresses or [token_address]
        LOGGER.info(f"Starting full audit: {request} ({len(addresses)} tokens)")

        result = AuditResult(
            project_id=project_id,
            status="running",
            started_at=datetime.utcnow(),
        )
        self._running_audits[project_id] = result

        try:
            if len(addresses) > 1:
                # Multi-token: run audits for each token and aggregate
                results = await self._collect_multi_token_audit_data(
                    token_addresses=addresses,
                    chain_id=chain_id,
                )
            else:
                # Single token: original path
                results = await self._collect_all_audit_data(
                    token_address=token_address,
                    chain_id=chain_id,
                )

            result.data = results
            result.status = "completed"
            result.completed_at = datetime.utcnow()

            # Store results to backend
            store_ok = await self._store_audit_results(project_id, results)
            if store_ok:
                LOGGER.info(
                    f"Audit results PATCH succeeded for {project_id[:8]}... "
                    f"(keys: {list(results.keys())})"
                )
            else:
                LOGGER.error(
                    f"Audit results PATCH FAILED for {project_id[:8]}... "
                    f"(keys: {list(results.keys())})"
                )

            # Generate executive summary after audit completes
            await self._generate_and_store_summary(project_id, results)

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
        skip_expensive: bool = False,
    ) -> Dict[str, Any]:
        """Collect data from all audit services in parallel.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            skip_expensive: If True, skip holder distribution and tokenomics
                collection. Used for secondary tokens in multi-token audits to
                avoid overwhelming Ethplorer freekey rate limits. Only code
                audit and liquidity are collected when True.

        Returns:
            Dictionary with all collected audit data
        """
        results = {}
        tasks = []

        # Task 1: Token holder distribution (dynamic - weekly updates)
        # force=True to always collect fresh data during audits
        # SKIPPED for secondary tokens in multi-token audits to save API budget
        if self.token_holder_scout and not skip_expensive:
            tasks.append(("token_distribution", self.token_holder_scout.collect_token_data(
                token_address=token_address,
                chain_id=chain_id,
                force=True,
            )))

        # Task 2: Tokenomics analysis (NEW!)
        # Note: TokenomicsAnalyzerScout will use cached holder data from database
        # if available, avoiding duplicate API calls with TokenHolderScout
        # SKIPPED for secondary tokens in multi-token audits to save API budget
        if self.tokenomics_analyzer_scout and not skip_expensive:
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
                    # Check if it's a Web3 RPC error
                    if hasattr(result, 'args') and result.args:
                        error_dict = result.args[0] if isinstance(result.args[0], dict) else {}
                        if 'code' in error_dict and error_dict['code'] == -32603:
                            LOGGER.error(f"RPC error collecting {key}: {error_dict.get('message', 'Unknown error')}. This may be due to rate limiting or network issues.")
                        else:
                            LOGGER.error(f"Failed to collect {key}: {result}")
                    else:
                        LOGGER.error(f"Failed to collect {key}: {result}")
                    results[key] = {
                        "error": str(result),
                        "error_type": type(result).__name__,
                        "collected_at": datetime.utcnow().isoformat(),
                    }
                elif result:
                    # Convert dataclass/result objects to dict for storage
                    if hasattr(result, "__dict__"):
                        results[key] = _serialize_for_json(result.__dict__)
                    elif hasattr(result, "to_dict"):
                        results[key] = _serialize_for_json(result.to_dict())
                    else:
                        results[key] = _serialize_for_json(result)

        # Mark collection timestamp
        results["collected_at"] = datetime.utcnow().isoformat()

        return results

    async def _collect_multi_token_audit_data(
        self,
        token_addresses: List[str],
        chain_id: int,
    ) -> Dict[str, Any]:
        """Collect audit data for multiple tokens and aggregate.

        Runs all scouts for each token with staggered starts to avoid
        RPC rate limiting, then aggregates per-token holder/pair data
        with token_address populated.

        Args:
            token_addresses: List of token contract addresses
            chain_id: Chain ID

        Returns:
            Dictionary with aggregated multi-token audit data
        """
        import asyncio as _asyncio

        # Stagger token audits to avoid burst RPC/API rate limiting.
        # Each audit fires multiple API calls (Ethplorer, RPC, DexScreener)
        # so launching 19+ simultaneously overwhelms free-tier providers.
        # Use 3s delay to stay within Ethplorer freekey rate limits (~1 req/sec).
        _STAGGER_DELAY = 3.0  # seconds between token audit starts

        async def _staggered_collect(
            addr: str, delay: float, skip_expensive: bool = False
        ) -> Dict[str, Any]:
            if delay > 0:
                await _asyncio.sleep(delay)
            return await self._collect_all_audit_data(
                token_address=addr,
                chain_id=chain_id,
                skip_expensive=skip_expensive,
            )

        per_token_tasks = []
        for idx, addr in enumerate(token_addresses):
            # Only the primary token (index 0) gets expensive holder/tokenomics
            # collection. Secondary tokens only get code audit + liquidity.
            # This prevents Ethplorer freekey rate limits from being exhausted
            # by 19 tokens each making 2+ API calls.
            is_primary = idx == 0
            per_token_tasks.append(
                _staggered_collect(
                    addr,
                    delay=idx * _STAGGER_DELAY,
                    skip_expensive=not is_primary,
                )
            )

        per_token_results = await _asyncio.gather(
            *per_token_tasks,
            return_exceptions=True,
        )

        # Aggregate results across tokens
        aggregated: Dict[str, Any] = {}
        per_token_holders: Dict[str, Any] = {}
        all_pairs: list = []
        all_findings: list = []

        for addr, token_result in zip(token_addresses, per_token_results):
            if isinstance(token_result, Exception):
                LOGGER.error(f"Failed to collect data for token {addr[:10]}...: {token_result}")
                continue

            # Collect per-token holder data with token_address
            token_dist = token_result.get("token_distribution", {})
            if isinstance(token_dist, dict) and token_dist:
                holders_raw = token_dist.get("top_holders") or token_dist.get("holders") or []
                holder_count = token_dist.get("holder_count") or token_dist.get("total_holders")
                dist_score = token_dist.get("score")
                dist_metrics = token_dist.get("metrics")
                market_cap = token_dist.get("market_cap_usd")
                # Only store if there's actual data (holders or metrics)
                if holders_raw or (isinstance(dist_metrics, dict) and dist_metrics):
                    per_token_holders[addr] = {
                        "holders": holders_raw,
                        "score": dist_score,
                        "holder_count": holder_count,
                        "metrics": dist_metrics,
                    }
                    if market_cap is not None:
                        per_token_holders[addr]["market_cap_usd"] = market_cap
                else:
                    LOGGER.warning(f"Skipping empty holder data for token {addr[:16]}...")
            elif isinstance(token_dist, dict) and not token_dist:
                LOGGER.warning(f"No token_distribution data for token {addr[:16]}...")

            # Collect liquidity pairs with token_address
            liq_data = token_result.get("liquidity", {})
            if isinstance(liq_data, dict):
                pairs = liq_data.get("pairs") or []
                for p in pairs:
                    if isinstance(p, dict):
                        p["token_address"] = addr
                    all_pairs.append(p)

            # Collect code audit findings
            code_data = token_result.get("code_audit", {})
            if isinstance(code_data, dict):
                findings = code_data.get("findings") or code_data.get("ai_audit_findings") or []
                all_findings.extend(findings)
                if "contract_audit" not in aggregated:
                    aggregated["contract_audit"] = code_data

            # Collect tokenomics per-token
            tok_data = token_result.get("tokenomics", {})
            if isinstance(tok_data, dict) and tok_data:
                # Only store if there's actual data (metrics or score)
                has_substantive = tok_data.get("metrics") or tok_data.get("score") is not None
                if has_substantive:
                    if "per_token_tokenomics" not in aggregated:
                        aggregated["per_token_tokenomics"] = {}
                    aggregated["per_token_tokenomics"][addr] = tok_data
                else:
                    LOGGER.warning(f"Skipping empty tokenomics data for token {addr[:16]}...")
            elif isinstance(tok_data, dict) and not tok_data:
                LOGGER.warning(f"No tokenomics data for token {addr[:16]}...")

        # Build aggregated output — only include per-token dicts when they have entries
        if per_token_holders:
            aggregated["per_token_holders"] = per_token_holders
        if "per_token_tokenomics" not in aggregated:
            # Ensure the key is absent if no token ever had substantive data
            aggregated.pop("per_token_tokenomics", None)
        aggregated["liquidity"] = {"pairs": all_pairs}
        if all_findings:
            aggregated.setdefault("contract_audit", {})["findings"] = all_findings

        aggregated["token_count"] = len(token_addresses)
        aggregated["collected_at"] = datetime.utcnow().isoformat()

        return aggregated

    async def _generate_and_store_summary(
        self,
        project_id: str,
        audit_data: Dict[str, Any],
    ) -> None:
        """Generate and persist an executive summary for a project.

        Safe wrapper — failures are logged but never propagate.
        """
        if not self._summary_orchestrator:
            return

        try:
            summary = await self._summary_orchestrator.generate_summary(
                project_id=project_id,
                audit_data=audit_data,
                backend_client=self.backend_client,
            )
            if summary:
                LOGGER.info(
                    "Summary generated for %s, attempting to store (keys: %s)",
                    project_id[:8], list(summary.keys()),
                )
                store_ok = await self._store_executive_summary(project_id, summary)
                LOGGER.info(
                    "Summary store result for %s: %s", project_id[:8], store_ok,
                )
            else:
                LOGGER.warning("Summary generation returned empty for %s", project_id[:8])
        except Exception as exc:
            LOGGER.warning(
                "Executive summary generation failed for %s: %s",
                project_id[:8], exc, exc_info=True,
            )

    async def _store_executive_summary(
        self,
        project_id: str,
        summary: Dict[str, Any],
    ) -> bool:
        """Persist executive summary fields to the backend.

        Uses direct httpx with INTERNAL_API_SECRET header.
        """
        import os
        import time

        start = time.monotonic()
        endpoint = f"/admin/projects/{project_id}/audit-results"

        payload = {
            "audit_data": {
                "executive_summary": summary.get("executive_summary", ""),
                "security_analysis": summary.get("security_analysis", ""),
                "recommendations": summary.get("recommendations", []),
                "safety_assessment": summary.get("safety_assessment", {}),
                "detailed_analysis": summary.get("detailed_analysis", {}),
                "project_notes": summary.get("project_notes", []),
                "confidence_score": summary.get("confidence_score", 0),
            },
        }

        internal_secret = os.environ.get("INTERNAL_API_SECRET")
        if not internal_secret:
            LOGGER.error("INTERNAL_API_SECRET not set — cannot store executive summary")
            return False

        headers = {
            "Content-Type": "application/json",
            "X-Internal-Api-Secret": internal_secret,
        }
        api_base_url = os.environ.get("API_BASE_URL", "http://localhost:8000/v1")
        url = f"{api_base_url.rstrip('/')}{endpoint}"

        try:
            LOGGER.info(
                "Storing executive summary for %s via httpx (INTERNAL_API_SECRET)",
                project_id[:8],
            )
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.patch(url, json=payload, headers=headers)
            elapsed = time.monotonic() - start
            LOGGER.info(
                "httpx PATCH for %s: HTTP %d (%.1fs)",
                project_id[:8], response.status_code, elapsed,
            )
            if response.status_code == 200:
                return True
            LOGGER.error(
                "httpx PATCH failed for %s: HTTP %d body=%s",
                project_id[:8], response.status_code, response.text[:300],
            )
        except Exception as exc:
            elapsed = time.monotonic() - start
            LOGGER.warning(
                "httpx PATCH error for %s after %.1fs: %s",
                project_id[:8], elapsed, exc,
            )

        elapsed = time.monotonic() - start
        LOGGER.error(
            "Failed to store executive summary for %s (%.1fs)",
            project_id[:8], elapsed,
        )
        return False

    async def _store_audit_results(
        self,
        project_id: str,
        results: Dict[str, Any],
    ) -> bool:
        """Store audit results to backend API via INTERNAL_API_SECRET.

        Args:
            project_id: Project identifier
            results: Audit results dictionary

        Returns:
            True if successful, False otherwise
        """
        import os

        endpoint = f"/admin/projects/{project_id}/audit-results"

        # Transform results to match backend expectations
        # Backend expects "contract_audit" not "code_audit"
        # Backend expects "findings" array in a specific format
        formatted_results = {}

        for key, value in results.items():
            if key == "code_audit" and isinstance(value, dict):
                # Rename code_audit to contract_audit for backend compatibility
                formatted_results["contract_audit"] = value

                # Also transform ai_audit_findings to findings format if present
                if "ai_audit_findings" in value:
                    findings = []
                    # Extract contract name from code_audit data for location fallback
                    contract_name = value.get("contract_name", "")
                    token_addr = value.get("token_address", "")
                    short_addr = token_addr[:10] + "..." if token_addr else ""

                    for finding in value["ai_audit_findings"]:
                        if isinstance(finding, dict):
                            loc = finding.get("location", "")
                            if not loc:
                                # Fallback: use contract name + function from description
                                desc = finding.get("description", "")
                                fn_match = __import__('re').search(r'(?:function\s+)(\w+)', desc)
                                fn_name = fn_match.group(1) if fn_match else finding.get("category", "")
                                if contract_name and fn_name:
                                    loc = f"{contract_name}:{fn_name}()"
                                elif contract_name:
                                    loc = f"{contract_name}"
                                else:
                                    loc = short_addr

                            findings.append({
                                "severity": finding.get("severity", "info"),
                                "type": finding.get("category", "Code Issue"),
                                "category": finding.get("category", "Code Issue"),
                                "code_location": loc,
                                "location": loc,
                                "description": finding.get("description", ""),
                                "recommendation": finding.get("recommendation", ""),
                                "agent_name": finding.get("agent_name", ""),
                                "code_snippet": finding.get("code_snippet"),
                                "location_detail": finding.get("location_detail"),
                                "highlight_start": finding.get("highlight_start"),
                                "highlight_end": finding.get("highlight_end"),
                            })
                    formatted_results["contract_audit"]["findings"] = findings
            else:
                formatted_results[key] = value

        payload = {
            "audit_data": formatted_results,
            "completed_at": datetime.utcnow().isoformat(),
        }

        # Debug logging
        LOGGER.info(f"Sending audit results to backend: project_id={project_id[:8]}..., "
                    f"keys={list(formatted_results.keys())}, "
                    f"contract_audit_score={formatted_results.get('contract_audit', {}).get('overall_score', 'N/A')}")

        # Direct HTTP with INTERNAL_API_SECRET
        internal_secret = os.environ.get("INTERNAL_API_SECRET")
        if not internal_secret:
            LOGGER.error("INTERNAL_API_SECRET not set — cannot store audit results")
            return False

        headers = {
            "Content-Type": "application/json",
            "X-Internal-Api-Secret": internal_secret,
        }
        api_base_url = os.environ.get("API_BASE_URL", "http://localhost:8000/v1")
        url = (
            f"{api_base_url.rstrip('/')}{endpoint}"
            if endpoint.startswith('/')
            else f"{api_base_url}/{endpoint}"
        )

        try:
            with httpx.Client(timeout=30.0) as client:
                response = client.patch(url, json=payload, headers=headers)
            LOGGER.info("Audit results stored: HTTP %s", response.status_code)
            if response.status_code == 200:
                return True
            LOGGER.error(
                "Failed to store audit results: HTTP %s %s",
                response.status_code,
                response.text[:200],
            )
        except Exception as exc:
            LOGGER.error("Direct HTTP delivery failed: %s", exc)

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
        # APScheduler runs jobs in a plain thread with no event loop.
        # Use asyncio.run() to create a fresh loop for the coroutine.
        try:
            asyncio.run(self._update_all_dynamic_data())
        except RuntimeError:
            # If there's already a loop (unlikely in scheduler thread), fall back
            loop = asyncio.get_event_loop()
            loop.create_task(self._update_all_dynamic_data())

    def _update_dynamic_data_job(self) -> None:
        """Job wrapper for updating dynamic data (runs in scheduler thread)."""
        try:
            asyncio.run(self._update_dynamic_data())
        except RuntimeError:
            loop = asyncio.get_event_loop()
            loop.create_task(self._update_dynamic_data())

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

                        # Regenerate executive summary with updated data
                        await self._generate_and_store_summary(project_id, results)

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
                    # Check if it's a Web3 RPC error
                    if hasattr(result, 'args') and result.args:
                        error_dict = result.args[0] if isinstance(result.args[0], dict) else {}
                        if 'code' in error_dict and error_dict['code'] == -32603:
                            LOGGER.error(f"RPC error collecting {key}: {error_dict.get('message', 'Unknown error')}. This may be due to rate limiting or network issues.")
                        else:
                            LOGGER.error(f"Failed to collect {key}: {result}")
                    else:
                        LOGGER.error(f"Failed to collect {key}: {result}")
                    results[key] = {
                        "error": str(result),
                        "error_type": type(result).__name__,
                        "collected_at": datetime.utcnow().isoformat(),
                    }
                elif result:
                    # Convert dataclass/result objects to dict for storage
                    if hasattr(result, "__dict__"):
                        results[key] = _serialize_for_json(result.__dict__)
                    elif hasattr(result, "to_dict"):
                        results[key] = _serialize_for_json(result.to_dict())
                    else:
                        results[key] = _serialize_for_json(result)

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
