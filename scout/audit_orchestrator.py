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
        contract_metadata: Optional[List[Dict[str, Any]]] = None,
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
            contract_metadata: Per-contract metadata [{address, is_token, name}]
                used to split tokens from non-token contracts.

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
                    contract_metadata=contract_metadata,
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
        """Collect data from all audit services.

        **Two-phase execution** to avoid event-loop starvation:
          Phase 1 (async HTTP):  token_distribution, tokenomics, liquidity
          Phase 2 (blocking):    code_audit (subprocess.run via claude-code CLI)

        The code audit calls ``subprocess.run()`` which blocks the event loop
        for up to 5 minutes per contract.  If token HTTP scouts and code audits
        run inside the same ``asyncio.gather()``, the blocking subprocess calls
        prevent async HTTP responses from being processed, causing token data
        to silently time out or return None.  Running token scouts first
        guarantees their results are available before the blocking phase starts.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            skip_expensive: If True, skip holder distribution and tokenomics
                collection. Used for non-token contracts in multi-contract
                audits. Only code audit and liquidity are collected when True.

        Returns:
            Dictionary with all collected audit data
        """
        results: Dict[str, Any] = {}

        # ── Phase 1: async HTTP tasks (non-blocking) ──────────────────────
        async_tasks: list = []

        if self.token_holder_scout and not skip_expensive:
            async_tasks.append(("token_distribution", self.token_holder_scout.collect_token_data(
                token_address=token_address,
                chain_id=chain_id,
                force=True,
            )))
            LOGGER.info("[PHASE1] Queued token_distribution for %s", token_address[:16])

        if self.tokenomics_analyzer_scout and not skip_expensive:
            async_tasks.append(("tokenomics", self.tokenomics_analyzer_scout.analyze_tokenomics(
                token_address=token_address,
                chain_id=str(chain_id),
            )))
            LOGGER.info("[PHASE1] Queued tokenomics for %s", token_address[:16])

        if self.liquidity_analyzer_scout and not skip_expensive:
            async_tasks.append(("liquidity", self.liquidity_analyzer_scout.analyze_liquidity(
                token_address=token_address,
                chain_id="ethereum" if chain_id == 1 else str(chain_id),
            )))
            LOGGER.info("[PHASE1] Queued liquidity for %s", token_address[:16])

        if async_tasks:
            completed = await asyncio.gather(
                *[task for _, task in async_tasks],
                return_exceptions=True,
            )
            for (key, _), result in zip(async_tasks, completed):
                self._store_task_result(results, key, result)

        LOGGER.info(
            "[PHASE1] Complete for %s: keys=%s",
            token_address[:16], list(results.keys()),
        )

        # ── Phase 2: code audit (blocking subprocess) ─────────────────────
        code_coro = None
        if self.unified_audit_service:
            code_coro = self.unified_audit_service._audit_verified_contract(
                token_address=token_address,
                chain_id=chain_id,
                force=False,
            )
        elif self.contract_audit_scout:
            code_coro = self.contract_audit_scout.audit_contract(
                token_address=token_address,
                chain_id=chain_id,
                force=False,
            )

        if code_coro:
            LOGGER.info("[PHASE2] Starting code_audit for %s", token_address[:16])
            try:
                code_result = await code_coro
                self._store_task_result(results, "code_audit", code_result)
            except Exception as exc:
                LOGGER.error("[PHASE2] code_audit failed for %s: %s", token_address[:16], exc)
                results["code_audit"] = {
                    "error": str(exc),
                    "error_type": type(exc).__name__,
                    "collected_at": datetime.utcnow().isoformat(),
                }
            LOGGER.info(
                "[PHASE2] code_audit done for %s: has_data=%s",
                token_address[:16],
                "code_audit" in results and "error" not in results.get("code_audit", {}),
            )

        # Mark collection timestamp
        results["collected_at"] = datetime.utcnow().isoformat()

        LOGGER.info(
            "[COLLECT] All data for %s: final_keys=%s",
            token_address[:16], list(results.keys()),
        )

        return results

    def _store_task_result(
        self,
        results: Dict[str, Any],
        key: str,
        result: Any,
    ) -> None:
        """Process a single task result and store it in the results dict.

        Handles exceptions, None returns, dataclass objects, and plain dicts.
        Always stores *something* for the key (error marker if needed) so that
        upstream aggregation can distinguish "scout ran but failed" from
        "scout was never scheduled".
        """
        if isinstance(result, Exception):
            if hasattr(result, 'args') and result.args:
                error_dict = result.args[0] if isinstance(result.args[0], dict) else {}
                if 'code' in error_dict and error_dict['code'] == -32603:
                    LOGGER.error(
                        "[TASK] RPC error collecting %s: %s. "
                        "This may be due to rate limiting or network issues.",
                        key, error_dict.get('message', 'Unknown error'),
                    )
                else:
                    LOGGER.error("[TASK] Failed to collect %s: %s", key, result)
            else:
                LOGGER.error("[TASK] Failed to collect %s: %s", key, result)
            results[key] = {
                "error": str(result),
                "error_type": type(result).__name__,
                "collected_at": datetime.utcnow().isoformat(),
            }
        elif result is None:
            # Scout returned None -- log clearly so upstream can differentiate
            # from "never scheduled".
            LOGGER.warning(
                "[TASK] Scout returned None for key=%s — no data available",
                key,
            )
            results[key] = {
                "error": "Scout returned None (no data)",
                "error_type": "NoneResult",
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
            LOGGER.info(
                "[TASK] Stored %s: result_keys=%s",
                key,
                list(results[key].keys()) if isinstance(results[key], dict) else type(results[key]).__name__,
            )

    async def _collect_multi_token_audit_data(
        self,
        token_addresses: List[str],
        chain_id: int,
        contract_metadata: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Collect audit data for multiple contracts and aggregate.

        Uses contract_metadata (with is_token flag) to split contracts into
        two groups:
          - Token contracts (is_token=True): full audit (code + tokenomics +
            distribution + liquidity)
          - Non-token contracts (is_token=False): code audit only

        If no metadata is provided, falls back to treating all contracts as
        tokens (legacy behaviour).

        Args:
            token_addresses: List of contract addresses
            chain_id: Chain ID
            contract_metadata: Per-contract metadata [{address, is_token, name}]

        Returns:
            Dictionary with aggregated multi-token audit data
        """
        import asyncio as _asyncio

        # Build is_token lookup from metadata
        is_token_map: Dict[str, bool] = {}
        if contract_metadata:
            for cm in contract_metadata:
                addr_key = (cm.get("address") or "").lower()
                is_token_map[addr_key] = cm.get("is_token", False)

        # Split addresses into tokens vs non-tokens
        token_addrs: List[str] = []
        non_token_addrs: List[str] = []
        for addr in token_addresses:
            if is_token_map.get(addr.lower(), True):
                token_addrs.append(addr)
            else:
                non_token_addrs.append(addr)

        LOGGER.info(
            f"Multi-contract audit: {len(token_addrs)} token contracts "
            f"(full audit), {len(non_token_addrs)} non-token contracts "
            f"(code-only), total={len(token_addresses)}"
        )

        # Stagger delays: tokens use 3s (Ethplorer/DexScreener rate limits),
        # non-tokens use 1s (code audit only, no external API calls).
        _TOKEN_STAGGER = 3.0
        _NONTOKEN_STAGGER = 1.0

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

        per_token_tasks: List = []
        addr_order: List[str] = []

        # Schedule token contracts first (full audit, longer stagger)
        for addr in token_addrs:
            delay = len(per_token_tasks) * _TOKEN_STAGGER
            per_token_tasks.append(
                _staggered_collect(addr, delay=delay, skip_expensive=False)
            )
            addr_order.append(addr)

        # Schedule non-token contracts (code audit only, shorter stagger)
        # Carry forward cumulative delay from token group so non-token
        # audits don't overlap with still-running token API calls.
        base_offset = len(token_addrs) * _TOKEN_STAGGER
        for addr in non_token_addrs:
            delay = base_offset + (len(per_token_tasks) - len(token_addrs)) * _NONTOKEN_STAGGER
            per_token_tasks.append(
                _staggered_collect(addr, delay=delay, skip_expensive=True)
            )
            addr_order.append(addr)

        per_token_results = await _asyncio.gather(
            *per_token_tasks,
            return_exceptions=True,
        )

        # Aggregate results across all contracts
        aggregated: Dict[str, Any] = {}
        per_token_holders: Dict[str, Any] = {}
        all_pairs: list = []
        all_findings: list = []

        for addr, token_result in zip(addr_order, per_token_results):
            is_token_addr = is_token_map.get(addr.lower(), True)

            if isinstance(token_result, Exception):
                LOGGER.error(
                    "[AGG] Exception for %s (is_token=%s): %s",
                    addr[:16], is_token_addr, token_result,
                )
                continue

            if not isinstance(token_result, dict):
                LOGGER.warning("[AGG] Non-dict result for %s: %s", addr[:16], type(token_result).__name__)
                continue

            # --- Token-specific data (distribution, liquidity, tokenomics) ---
            if is_token_addr:
                LOGGER.info(
                    "[AGG] Token contract %s: result_keys=%s",
                    addr[:16],
                    list(token_result.keys()),
                )

                # Collect per-token holder data
                token_dist = token_result.get("token_distribution")
                if isinstance(token_dist, dict) and token_dist and not token_dist.get("error_type"):
                    holders_raw = token_dist.get("top_holders") or token_dist.get("holders") or []
                    holder_count = token_dist.get("holder_count") or token_dist.get("total_holders")
                    dist_score = token_dist.get("score")
                    dist_metrics = token_dist.get("metrics")
                    market_cap = token_dist.get("market_cap_usd")
                    if holders_raw or (isinstance(dist_metrics, dict) and dist_metrics):
                        per_token_holders[addr] = {
                            "holders": holders_raw,
                            "score": dist_score,
                            "holder_count": holder_count,
                            "metrics": dist_metrics,
                        }
                        if market_cap is not None:
                            per_token_holders[addr]["market_cap_usd"] = market_cap
                        LOGGER.info(
                            "[AGG] Stored per_token_holders for %s: holders=%d",
                            addr[:16], len(holders_raw),
                        )
                elif token_dist and isinstance(token_dist, dict) and token_dist.get("error_type"):
                    LOGGER.warning(
                        "[AGG] token_distribution for %s has error: %s",
                        addr[:16], token_dist.get("error"),
                    )

                # Collect liquidity pairs
                liq_data = token_result.get("liquidity")
                if isinstance(liq_data, dict):
                    pairs = liq_data.get("pairs") or []
                    for p in pairs:
                        if isinstance(p, dict):
                            p["token_address"] = addr
                        all_pairs.append(p)

                # Collect tokenomics per-token
                tok_data = token_result.get("tokenomics")
                if isinstance(tok_data, dict) and tok_data:
                    if tok_data.get("error_type"):
                        LOGGER.warning(
                            "[AGG] tokenomics for %s has error: %s",
                            addr[:16], tok_data.get("error"),
                        )
                    elif tok_data.get("metrics") or tok_data.get("score") is not None:
                        if "per_token_tokenomics" not in aggregated:
                            aggregated["per_token_tokenomics"] = {}
                        aggregated["per_token_tokenomics"][addr] = tok_data
                        LOGGER.info(
                            "[AGG] Stored per_token_tokenomics for %s: score=%s",
                            addr[:16], tok_data.get("score"),
                        )
                    else:
                        LOGGER.warning(
                            "[AGG] Skipping empty tokenomics for %s: keys=%s",
                            addr[:16], list(tok_data.keys()),
                        )

            # --- Code audit findings from ALL contracts (token + non-token) ---
            code_data = token_result.get("code_audit")
            if isinstance(code_data, dict):
                findings = code_data.get("findings") or code_data.get("ai_audit_findings") or []
                all_findings.extend(findings)
                if "contract_audit" not in aggregated:
                    aggregated["contract_audit"] = code_data

        # Build aggregated output
        if per_token_holders:
            aggregated["per_token_holders"] = per_token_holders
        if "per_token_tokenomics" not in aggregated:
            aggregated.pop("per_token_tokenomics", None)
        aggregated["liquidity"] = {"pairs": all_pairs}
        if all_findings:
            aggregated.setdefault("contract_audit", {})["findings"] = all_findings

        aggregated["token_count"] = len(token_addresses)
        aggregated["collected_at"] = datetime.utcnow().isoformat()

        # Propagate top-level tokenomics and token_distribution from the first
        # TOKEN contract (not the first contract overall) so the backend merge
        # route and frontend can find them without per_token_* derivation.
        for primary_addr in token_addrs:
            idx = addr_order.index(primary_addr) if primary_addr in addr_order else None
            if idx is None:
                continue
            _primary_result = (
                per_token_results[idx]
                if per_token_results and not isinstance(per_token_results[idx], Exception)
                else None
            )
            if not isinstance(_primary_result, dict):
                LOGGER.warning(
                    "[PROPAGATE] Primary token %s result is %s, skipping",
                    primary_addr[:16],
                    type(per_token_results[idx]).__name__ if idx is not None and idx < len(per_token_results) else "None",
                )
                continue

            _primary_tok = _primary_result.get("tokenomics")
            if isinstance(_primary_tok, dict) and _primary_tok.get("metrics"):
                aggregated["tokenomics"] = _primary_tok
                LOGGER.info(
                    "[PROPAGATE] Set top-level tokenomics from %s: score=%s",
                    primary_addr[:16], _primary_tok.get("score"),
                )
            elif _primary_tok:
                LOGGER.warning(
                    "[PROPAGATE] tokenomics for %s exists but has no metrics: keys=%s",
                    primary_addr[:16],
                    list(_primary_tok.keys()) if isinstance(_primary_tok, dict) else type(_primary_tok).__name__,
                )

            _primary_dist = _primary_result.get("token_distribution")
            if isinstance(_primary_dist, dict) and (
                _primary_dist.get("metrics")
                or _primary_dist.get("top_holders")
                or _primary_dist.get("holders")
            ):
                aggregated["token_distribution"] = _primary_dist
                LOGGER.info(
                    "[PROPAGATE] Set top-level token_distribution from %s",
                    primary_addr[:16],
                )
            elif _primary_dist:
                LOGGER.warning(
                    "[PROPAGATE] token_distribution for %s exists but has no "
                    "metrics/holders: keys=%s",
                    primary_addr[:16],
                    list(_primary_dist.keys()) if isinstance(_primary_dist, dict) else type(_primary_dist).__name__,
                )

            # Use first token that has data; stop when both keys present
            if "tokenomics" in aggregated and "token_distribution" in aggregated:
                break

        LOGGER.info(
            "[MULTI-AGG] Final aggregated keys=%s, "
            "has_tokenomics=%s, has_token_distribution=%s, "
            "per_token_holders=%d addrs, per_token_tokenomics=%d addrs",
            list(aggregated.keys()),
            "tokenomics" in aggregated,
            "token_distribution" in aggregated,
            len(per_token_holders),
            len(aggregated.get("per_token_tokenomics", {})),
        )

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
