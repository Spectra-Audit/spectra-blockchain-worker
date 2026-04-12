"""Tokenomics analyzer scout — health-score model.

Scoring model:
1. Calculate health_ratio = (dead_address_balance + liquidity_pool_balances) / total_supply * 100
2. Start from health_ratio as base score
3. Deduct for red flags (mint, rebase, unlimited supply, centralized mint)

Holder concentration is handled by distribution scoring, NOT here.
Liquidity ratio and contract holder analysis belong in liquidity scoring.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from web3 import Web3

from scout.erc20_reader import ContractFeatures, ERC20Reader
from scout.holder_api_manager import HolderAPIManager

LOGGER = logging.getLogger(__name__)


@dataclass
class TokenomicsMetrics:
    """Tokenomics metrics for health-score model."""

    token_address: str
    chain_id: str

    # Contract features
    contract_features: ContractFeatures

    # Supply analysis
    total_supply: int
    max_supply: Optional[int]
    supply_tier: str  # "fixed", "capped", "uncapped", "rebasing"

    # Health-score inputs
    dead_address_balance: int = 0       # Balance of 0x...dEaD
    liquidity_pool_balance: int = 0     # Sum of token balances in known liquidity contracts

    # Holder analysis (kept for flag generation / recommendations only)
    total_holders: int = 0
    top_10_holder_pct: float = 0.0
    contract_holder_pct: float = 0.0
    staking_contract_pct: float = 0.0
    top_contract_holders: List[Dict[str, Any]] = field(default_factory=list)

    # Concentration metrics (kept for flag generation / recommendations only)
    gini_coefficient: float = 0.0
    nakamoto_coefficient: int = 0

    # Utility assessment
    utility_flags: List[str] = field(default_factory=list)

    # Vesting risks
    has_team_vesting: bool = False
    vesting_flags: List[str] = field(default_factory=list)

    # Risk flags
    flags: List[str] = field(default_factory=list)

    # Timestamp
    analyzed_at: str = ""


@dataclass
class TokenomicsAnalysisResult:
    """Complete tokenomics analysis result."""

    metrics: TokenomicsMetrics
    score: float  # 0-100
    risk_level: str  # "low", "medium", "high", "critical"
    recommendations: List[str]
    analyzed_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class TokenomicsAnalyzerScout:
    """Tokenomics analyzer scout.

    Analyzes token economics and contract mechanics for red flags.

    Integration Notes:
    - Uses shared HolderAPIManager (same instance as TokenHolderScout)
    - Can read cached holder data from database to avoid duplicate API calls
    - Performs new contract analysis (ERC20Reader for supply mechanics)
    - Designed to be called by AuditOrchestrator in parallel with other scouts

    Example:
        # In ScoutApp - share HolderAPIManager between scouts
        api_manager = create_holder_api_manager(database=database)

        token_holder_scout = TokenHolderScout(
            database=database,
            api_manager=api_manager,
        )

        tokenomics_scout = TokenomicsAnalyzerScout(
            database=database,
            holder_api_manager=api_manager,  # Shared!
        )

        # In AuditOrchestrator - run in parallel
        results = await asyncio.gather(
            token_holder_scout.collect_token_data(...),
            tokenomics_scout.analyze_tokenomics(...),
        )
    """

    def __init__(
        self,
        database: Any,  # DatabaseManager
        holder_api_manager: Optional[HolderAPIManager] = None,
        rpc_url: Optional[str] = None,
    ):
        """Initialize the tokenomics analyzer scout.

        Args:
            database: Database manager (shared across scouts)
            holder_api_manager: Shared HolderAPIManager (same as TokenHolderScout)
                             This avoids duplicate API calls when both scouts need holder data
            rpc_url: Optional RPC URL for Web3 contract reads
                     If None, uses environment RPC_HTTP_URL or default
        """
        self.database = database
        self.holder_api_manager = holder_api_manager

        # Create Web3 instance for contract reads
        if rpc_url is None:
            rpc_url = os.environ.get("RPC_HTTP_URL", "https://eth.llamarpc.com")
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.erc20_reader = ERC20Reader(self.w3)

        # Known staking contract patterns (function selectors)
        self.staking_selectors = [
            "0xa694fc3a",  # stake(uint256)
            "0x2e1a7d4d",  # withdraw(uint256)
            "0x4e71d92d",  # getStaked(address)
            "0x0bcbf256",  # stakingToken()
        ]

        # ERC-20 Transfer event ABI for vesting analysis
        self.transfer_event_abi = [{
            "anonymous": False,
            "inputs": [
                {"indexed": True, "name": "from", "type": "address"},
                {"indexed": True, "name": "to", "type": "address"},
                {"indexed": False, "name": "value", "type": "uint256"},
            ],
            "name": "Transfer",
            "type": "event",
        }]

    async def analyze_tokenomics(
        self,
        token_address: str,
        chain_id: str = "ethereum",
    ) -> TokenomicsAnalysisResult:
        """Analyze tokenomics for a token.

        Args:
            token_address: Token contract address
            chain_id: Chain ID

        Returns:
            TokenomicsAnalysisResult with comprehensive analysis
        """
        LOGGER.info(f"Analyzing tokenomics for {token_address} on {chain_id}")

        # Step 1: Read contract features
        contract_features = await self.erc20_reader.read_contract(token_address)
        if not contract_features:
            return self._create_error_result(token_address, chain_id, "Failed to read contract")

        # Step 2: Get holder data
        holder_data = await self._get_holder_data(token_address, chain_id)

        # Step 3: Calculate metrics
        metrics = await self._calculate_metrics(
            token_address, chain_id, contract_features, holder_data
        )

        # Step 4: Calculate score and risk level
        score = self._calculate_score(metrics)
        risk_level = self._determine_risk_level(score, metrics)

        # Step 5: Generate recommendations
        recommendations = self._generate_recommendations(metrics, score)

        # Step 6: Store results
        self._store_analysis_result(metrics, score, risk_level, recommendations)

        return TokenomicsAnalysisResult(
            metrics=metrics,
            score=score,
            risk_level=risk_level,
            recommendations=recommendations,
        )

    async def _get_holder_data(
        self,
        token_address: str,
        chain_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Get holder data, preferring cached database data to avoid duplicate API calls.

        Priority:
        1. Check database for recent snapshot (within 7 days)
        2. If no recent data, use HolderAPIManager to fetch fresh data
        3. If HolderAPIManager unavailable, return None (graceful degradation)

        Args:
            token_address: Token address
            chain_id: Chain ID (string like "ethereum" or int)

        Returns:
            Holder data dict or None
        """
        chain_id_int = 1 if chain_id == "ethereum" else int(chain_id)

        # Step 1: Try to get recent data from database (cached by TokenHolderScout)
        try:
            latest = self.database.get_latest_weekly_snapshot(token_address, chain_id_int)
            if latest:
                last_date = datetime.strptime(latest["week_start"], "%Y-%m-%d")
                days_since = (datetime.utcnow() - last_date).days

                # Use cached data if within 7 days
                if days_since <= 7:
                    LOGGER.info(f"Using cached holder data ({days_since} days old)")
                    return self._format_cached_holder_data(latest, token_address, chain_id_int)
        except Exception as e:
            LOGGER.debug(f"No cached holder data available: {e}")

        # Step 2: Fetch fresh data via HolderAPIManager (if available)
        if not self.holder_api_manager:
            LOGGER.debug("HolderAPIManager not available, skipping holder data")
            return None

        try:
            LOGGER.info("Fetching fresh holder data via HolderAPIManager")
            metrics = await self.holder_api_manager.get_holder_data(
                token_address=token_address,
                chain_id=chain_id_int,
                limit=100,
            )

            if metrics:
                # estimated_total_supply is stored as hex string in HolderMetrics
                total_supply_int = int(metrics.estimated_total_supply, 16) if metrics.estimated_total_supply else 0
                return {
                    "holders": [
                        {
                            "address": h.address,
                            "balance": h.balance,
                            "share": (h.balance / total_supply_int * 100)
                                   if total_supply_int > 0 else 0,
                        }
                        for h in metrics.top_holders
                    ],
                    "total_holders": metrics.total_holder_count,
                    "total_supply": total_supply_int,
                }
        except Exception as e:
            LOGGER.warning(f"Failed to get holder data from API: {e}")

        return None

    def _format_cached_holder_data(
        self,
        snapshot: Dict[str, Any],
        token_address: str,
        chain_id: int,
    ) -> Dict[str, Any]:
        """Format cached database snapshot into holder data format.

        Args:
            snapshot: Database snapshot dict
            token_address: Token address
            chain_id: Chain ID

        Returns:
            Formatted holder data dict
        """
        # Get top holders from database
        top_holders = self.database.get_top_holders(
            token_address=token_address,
            chain_id=chain_id,
            limit=100,
        )

        return {
            "holders": [
                {
                    "address": h["holder_address"],
                    "balance": int(h["holder_balance_hex"], 16)
                               if h.get("holder_balance_hex")
                               else h["holder_balance_int"],
                    "share": h["percent_supply"],
                }
                for h in top_holders
            ],
            "total_holders": snapshot["holder_count"],
            "total_supply": int(snapshot["estimated_total_supply"], 16)
                           if snapshot.get("estimated_total_supply")
                           else snapshot.get("estimated_total_supply", 0),
        }

    async def _calculate_metrics(
        self,
        token_address: str,
        chain_id: str,
        contract_features: ContractFeatures,
        holder_data: Optional[Dict[str, Any]],
    ) -> TokenomicsMetrics:
        """Calculate tokenomics metrics using health-score model."""

        # Determine supply tier
        if contract_features.has_rebase:
            supply_tier = "rebasing"
        elif contract_features.has_mint and not contract_features.has_max_supply:
            supply_tier = "uncapped"
        elif contract_features.has_max_supply:
            supply_tier = "capped"
        else:
            supply_tier = "fixed"

        # --- Health-score inputs ---
        dead_balance = await self._get_dead_address_balance(token_address)
        liquidity_balance = await self._get_liquidity_pool_balance(
            token_address, chain_id
        )

        # Process holder data (for flags / recommendations only, NOT scoring)
        total_holders = 0
        top_10_holder_pct = 0.0
        contract_holder_pct = 0.0
        staking_contract_pct = 0.0
        top_contract_holders = []

        if holder_data and holder_data.get("holders"):
            holders = holder_data["holders"]
            total_holders = holder_data.get("total_holders", len(holders))

            total_supply = contract_features.total_supply
            top_10_supply = sum(h.get("balance", 0) for h in holders[:10])
            top_10_holder_pct = (top_10_supply / total_supply * 100) if total_supply > 0 else 0

            contract_holders = []
            for holder in holders:
                address = holder.get("address", "")
                is_contract = await self.erc20_reader.is_contract_address(address)
                if is_contract:
                    contract_holders.append({
                        "address": address,
                        "balance": holder.get("balance", 0),
                        "percentage": holder.get("share", 0),
                    })

            contract_holder_pct = sum(h["percentage"] for h in contract_holders)

            staking_contracts = await self._identify_staking_contracts(
                token_address, contract_holders
            )
            staking_contract_pct = sum(h["percentage"] for h in staking_contracts)
            top_contract_holders = staking_contracts[:10]

        # Utility assessment
        utility_flags = self._assess_utility(contract_features, holder_data)

        # Vesting analysis
        vesting_flags = await self._analyze_vesting(
            token_address, contract_features, holder_data
        )

        # Combined flags
        flags = contract_features.flags.copy()
        flags.extend(utility_flags)
        flags.extend(vesting_flags)

        if staking_contract_pct > 90:
            flags.append("extreme_staking_ratio")
        elif staking_contract_pct > 70:
            flags.append("very_high_staking_ratio")

        return TokenomicsMetrics(
            token_address=token_address,
            chain_id=chain_id,
            contract_features=contract_features,
            total_supply=contract_features.total_supply,
            max_supply=contract_features.max_supply,
            supply_tier=supply_tier,
            dead_address_balance=dead_balance,
            liquidity_pool_balance=liquidity_balance,
            total_holders=total_holders,
            top_10_holder_pct=top_10_holder_pct,
            contract_holder_pct=contract_holder_pct,
            staking_contract_pct=staking_contract_pct,
            top_contract_holders=top_contract_holders,
            utility_flags=utility_flags,
            has_team_vesting=len(vesting_flags) > 0,
            vesting_flags=vesting_flags,
            flags=flags,
            analyzed_at=datetime.utcnow().isoformat(),
        )

    async def _get_dead_address_balance(self, token_address: str) -> int:
        """Get token balance of the dead address (0x0...dEaD).

        Tokens sent to the dead address are effectively burned.
        """
        DEAD_ADDRESS = "0x000000000000000000000000000000000000dEaD"
        try:
            checksummed = Web3.to_checksum_address(token_address)
            erc20 = self.w3.eth.contract(
                address=checksummed,
                abi=[{
                    "constant": True,
                    "inputs": [{"name": "_owner", "type": "address"}],
                    "name": "balanceOf",
                    "outputs": [{"name": "balance", "type": "uint256"}],
                    "type": "function",
                }],
            )
            return erc20.functions.balanceOf(
                Web3.to_checksum_address(DEAD_ADDRESS)
            ).call()
        except Exception as e:
            LOGGER.warning(f"Failed to get dead address balance for {token_address}: {e}")
            return 0

    async def _get_liquidity_pool_balance(
        self, token_address: str, chain_id: str
    ) -> int:
        """Get total token balance across known liquidity pool contracts.

        Uses DexScreener pair data to identify LP contract addresses, then
        queries balanceOf for each.
        """
        try:
            from scout.dexscreener_client import DexScreenerClient
            client = DexScreenerClient()
            pairs = await client.get_token_pairs(chain_id, token_address, fetch_detailed=False)
            if not pairs:
                return 0

            checksummed = Web3.to_checksum_address(token_address)
            erc20 = self.w3.eth.contract(
                address=checksummed,
                abi=[{
                    "constant": True,
                    "inputs": [{"name": "_owner", "type": "address"}],
                    "name": "balanceOf",
                    "outputs": [{"name": "balance", "type": "uint256"}],
                    "type": "function",
                }],
            )

            total = 0
            seen = set()
            for pair in pairs:
                addr = pair.pair_address
                if not addr or addr in seen:
                    continue
                seen.add(addr)
                try:
                    balance = erc20.functions.balanceOf(
                        Web3.to_checksum_address(addr)
                    ).call()
                    total += balance
                except Exception:
                    continue

            await client.close()
            return total
        except Exception as e:
            LOGGER.warning(f"Failed to get liquidity pool balances for {token_address}: {e}")
            return 0

    async def _identify_staking_contracts(
        self,
        token_address: str,
        contract_holders: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Identify which contract holders are staking contracts.

        Args:
            token_address: Token address
            contract_holders: List of contract holders

        Returns:
            List of staking contracts with details
        """
        staking_contracts = []

        for holder in contract_holders:
            address = holder["address"]

            # Check for staking function signatures
            try:
                code = self.w3.eth.get_code(address)
                if len(code.hex()) > 100:  # Has significant code
                    # Check for known staking selectors
                    for selector in self.staking_selectors:
                        if selector in code.hex():
                            staking_contracts.append(holder)
                            break
            except Exception:
                pass

        return staking_contracts

    def _assess_utility(
        self,
        contract_features: ContractFeatures,
        holder_data: Optional[Dict[str, Any]],
    ) -> List[str]:
        """Assess token utility.

        Returns flags indicating utility purpose.
        """
        utility_flags = []

        # Check if token has clear utility
        has_governance = contract_features.owner is not None
        has_mechanism_burn = contract_features.has_burn
        has_mechanism_mint = contract_features.has_mint

        # This is basic - can be enhanced with protocol-specific checks
        if not has_governance and not has_mechanism_burn:
            utility_flags.append("unclear_utility")

        if contract_features.has_rebase:
            utility_flags.append("rebasing_stablecoin")

        if contract_features.has_withdraw:
            utility_flags.append("revenue_extraction_possible")

        return utility_flags

    async def _analyze_vesting(
        self,
        token_address: str,
        contract_features: ContractFeatures,
        holder_data: Optional[Dict[str, Any]],
    ) -> List[str]:
        """Analyze vesting and unlock patterns using only on-chain data.

        Attempts to detect:
        - Large initial allocations (>20% to single address)
        - Concentrated holdings (top 3 addresses >50% of supply)
        - Potential cliff risks from transfer patterns

        Method: Parse on-chain Transfer events from early blocks to identify:
        1. Initial distribution patterns (large single transfers)
        2. Concentrated holdings (potential insider allocations)

        Returns list of vesting-related risk flags.
        """
        vesting_flags = []

        # Step 1: Parse Transfer events from on-chain data
        try:
            transfer_events = await self._get_early_transfers(token_address)

            # Step 2: Identify concentrated holdings from transfer patterns
            concentrated_candidates = self._identify_concentrated_holdings(
                transfer_events, contract_features.total_supply
            )

            # Step 3: Check for concentration risks
            if concentrated_candidates:
                # Check if any single address received >20% of supply
                for candidate in concentrated_candidates:
                    if candidate["percentage"] > 20:
                        vesting_flags.append(f"large_initial_allocation_{candidate['address'][:8]}")

                # Check concentration (top 3 holdings)
                top_3_pct = sum(c["percentage"] for c in concentrated_candidates[:3])
                if top_3_pct > 50:
                    vesting_flags.append("heavy_concentration_risk")

        except Exception as e:
            LOGGER.warning(f"Failed to analyze vesting via events: {e}")

        # Fallback: Basic concentration check from holder data
        if not vesting_flags and holder_data and holder_data.get("holders"):
            top_holder = holder_data["holders"][0]
            if top_holder.get("share", 0) > 30:
                vesting_flags.append("potential_cliff_risk_concentration")

        return vesting_flags

    async def _get_early_transfers(
        self,
        token_address: str,
        block_limit: int = 10000,
    ) -> List[Dict[str, Any]]:
        """Get Transfer events from early blocks (on-chain only).

        Args:
            token_address: Token contract address
            block_limit: Maximum number of blocks to scan from recent history

        Returns:
            List of transfer events from recent blocks
        """
        # Use RPC to get on-chain events
        events = []

        try:
            token_address = Web3.to_checksum_address(token_address)
            current_block = self.w3.eth.block_number

            # Create contract instance
            contract = self.w3.eth.contract(
                address=token_address,
                abi=self.transfer_event_abi
            )

            # Get events from recent history (limited by block_limit)
            from_block = max(0, current_block - block_limit)

            logs = contract.events.Transfer().get_logs(fromBlock=from_block)

            for log in logs:
                events.append({
                    "from": log['args']['from'],
                    "to": log['args']['to'],
                    "value": log['args']['value'],
                    "blockNumber": log['blockNumber'],
                    "transactionHash": log['transactionHash'].hex(),
                })

        except Exception as e:
            LOGGER.warning(f"Failed to get early transfers: {e}")

        return events

    def _identify_concentrated_holdings(
        self,
        transfer_events: List[Dict[str, Any]],
        total_supply: int,
    ) -> List[Dict[str, Any]]:
        """Identify concentrated holdings from transfer events (on-chain only).

        Args:
            transfer_events: Transfer events
            total_supply: Total token supply

        Returns:
            List of addresses with significant holdings (>5%)
        """
        # Track receiving addresses and amounts
        recipients = {}

        for event in transfer_events:
            to_address = event["to"]
            value = event["value"]

            if to_address not in recipients:
                recipients[to_address] = 0
            recipients[to_address] += value

        # Convert to percentages and filter for significant holders
        candidates = []
        for address, total_value in recipients.items():
            percentage = (total_value / total_supply * 100) if total_supply > 0 else 0

            # Filter for addresses with significant holdings (>5%)
            if percentage > 5:
                candidates.append({
                    "address": address,
                    "total_value": total_value,
                    "percentage": percentage,
                })

        # Sort by percentage descending
        candidates.sort(key=lambda x: x["percentage"], reverse=True)

        return candidates

    def _calculate_score(self, metrics: TokenomicsMetrics) -> float:
        """Calculate tokenomics score using health-score model (0-100).

        Model:
        1. health_ratio = (dead_address_balance + liquidity_pool_balances) / total_supply * 100
        2. Start score from health_ratio
        3. Deduct for supply red flags (mint, rebase, unlimited)
        4. Clamp to [0, 100]

        Holder concentration is NOT scored here — that's distribution's job.
        """
        # --- Rebase token: immediate zero ---
        if metrics.contract_features.has_rebase:
            return 0.0

        # --- Step 1: Calculate health ratio ---
        total_supply = metrics.total_supply
        if total_supply > 0:
            health_ratio = (
                metrics.dead_address_balance + metrics.liquidity_pool_balance
            ) / total_supply * 100
        else:
            health_ratio = 0.0

        # Start from the health ratio (capped at 100)
        score = min(health_ratio, 100.0)

        # --- Step 2: Deduct for supply red flags ---
        deductions = 0.0

        has_mint = metrics.contract_features.has_mint
        has_max_supply = metrics.contract_features.has_max_supply
        has_owner = metrics.contract_features.owner is not None

        # Mint function present
        if has_mint and not has_max_supply:
            # Unlimited minting — can inflate supply arbitrarily
            deductions += 40
        elif has_mint and has_max_supply:
            # Capped mint — less risky but still a concern
            deductions += 20

        # Centralized minting (owner-controlled)
        if has_mint and has_owner:
            deductions += 10

        # Flag-based deductions from _calculate_metrics
        if "unlimited_minting" in metrics.flags:
            deductions += 30
        if "controlled_minting" in metrics.flags:
            deductions += 10
        if "inflationary_no_burn" in metrics.flags:
            deductions += 10
        if "tiny_burn_relative_to_mint" in metrics.flags:
            deductions += 15

        score -= deductions

        return max(0.0, min(100.0, score))

    def _determine_risk_level(self, score: float, metrics: TokenomicsMetrics) -> str:
        """Determine risk level from score."""

        if metrics.contract_features.has_rebase:
            return "critical"

        if score >= 70:
            return "low"
        elif score >= 50:
            return "medium"
        elif score >= 30:
            return "high"
        else:
            return "critical"

    def _generate_recommendations(
        self,
        metrics: TokenomicsMetrics,
        score: float,
    ) -> List[str]:
        """Generate actionable recommendations based on health-score model."""

        recommendations = []

        # Health ratio insight
        total_supply = metrics.total_supply
        if total_supply > 0:
            health_ratio = (metrics.dead_address_balance + metrics.liquidity_pool_balance) / total_supply * 100
            recommendations.append(
                f"Health ratio: {health_ratio:.1f}% "
                f"(burned: {metrics.dead_address_balance / total_supply * 100:.1f}%, "
                f"in LPs: {metrics.liquidity_pool_balance / total_supply * 100:.1f}%)"
            )

        # Rebase warning
        if metrics.contract_features.has_rebase:
            recommendations.append("CRITICAL: Rebasing token — score forced to 0")

        # Mint warnings
        if metrics.contract_features.has_mint:
            if metrics.contract_features.has_max_supply:
                recommendations.append("Mint function present with supply cap — moderate risk")
            else:
                recommendations.append("Mint function with NO supply cap — unlimited inflation risk")

        if metrics.contract_features.has_mint and metrics.contract_features.owner:
            recommendations.append("Mint controlled by contract owner — centralization risk")

        if "unlimited_minting" in metrics.flags:
            recommendations.append("Unlimited minting detected — severe inflation risk")

        if "inflationary_no_burn" in metrics.flags:
            recommendations.append("Inflationary token with no burn mechanism")

        if "tiny_burn_relative_to_mint" in metrics.flags:
            recommendations.append("Burn rate negligible relative to mint rate")

        if score >= 70:
            recommendations.append("Tokenomics appear healthy — continue monitoring")

        if not recommendations:
            recommendations.append("Monitor for changes in tokenomics parameters")

        return recommendations

    def _create_error_result(
        self,
        token_address: str,
        chain_id: str,
        error_message: str,
    ) -> TokenomicsAnalysisResult:
        """Create error result."""
        return TokenomicsAnalysisResult(
            metrics=None,  # type: ignore
            score=0,
            risk_level="critical",
            recommendations=[error_message],
        )

    def _store_analysis_result(
        self,
        metrics: TokenomicsMetrics,
        score: float,
        risk_level: str,
        recommendations: List[str],
    ) -> None:
        """Store analysis result in database."""
        self.database.store_tokenomics_snapshot(
            token_address=metrics.token_address,
            chain_id=metrics.chain_id,
            total_supply=metrics.total_supply,
            max_supply=metrics.max_supply,
            supply_tier=metrics.supply_tier,
            total_holders=metrics.total_holders,
            top_10_holder_pct=metrics.top_10_holder_pct,
            contract_holder_pct=metrics.contract_holder_pct,
            staking_contract_pct=metrics.staking_contract_pct,
            gini_coefficient=metrics.gini_coefficient,
            nakamoto_coefficient=metrics.nakamoto_coefficient,
            utility_flags=json.dumps(metrics.utility_flags),
            vesting_flags=json.dumps(metrics.vesting_flags),
            tokenomics_score=score,
            risk_level=risk_level,
            flags=json.dumps(metrics.flags),
            recommendations=json.dumps(recommendations),
            analyzed_at=metrics.analyzed_at,
        )

    async def close(self) -> None:
        """Close resources."""
        # Web3 HTTP provider doesn't need explicit closing
        pass
