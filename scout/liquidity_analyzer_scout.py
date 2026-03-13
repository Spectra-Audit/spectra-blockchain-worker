"""Liquidity analyzer scout using DexScreener API.

This scout analyzes a project's liquidity across multiple dimensions:
- Liquidity depth & TVL
- Pool variety & source diversity
- Pool composition & balance
- Fee tier analysis
- Cross-chain liquidity
- On-chain activity patterns
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from scout.dexscreener_client import DexScreenerClient, DexPair, LiquidityMetrics

LOGGER = logging.getLogger(__name__)


@dataclass
class LiquidityAnalysisResult:
    """Complete liquidity analysis result.

    Attributes:
        metrics: Comprehensive liquidity metrics
        score: Overall liquidity score (0-100)
        risk_level: Risk level ("low", "medium", "high", "critical")
        recommendations: List of recommendations
        analyzed_at: Timestamp of analysis
    """

    metrics: LiquidityMetrics
    score: float
    risk_level: str
    recommendations: List[str]
    analyzed_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class LiquidityAnalyzerScout:
    """Liquidity analyzer scout using DexScreener API.

    Analyzes token liquidity across multiple dimensions:
    1. Liquidity depth (TVL, depth)
    2. Pool variety (DEX diversity, concentration)
    3. Pool composition (balance, fee tiers)
    4. Cross-chain liquidity
    5. On-chain activity (volume, transactions, inflows/outflows)

    Example:
        scout = LiquidityAnalyzerScout(
            database=DatabaseManager("scout.db"),
        )

        result = await scout.analyze_liquidity(
            token_address="0x...",
            chain_id="ethereum",
        )

        print(f"Score: {result.score}/100")
        print(f"Risk: {result.risk_level}")
        print(f"TVL: ${result.metrics.total_tvl_usd:,.0f}")
    """

    def __init__(
        self,
        database: Any,  # DatabaseManager
        client: Optional[DexScreenerClient] = None,
    ) -> None:
        """Initialize the liquidity analyzer scout.

        Args:
            database: Database manager
            client: Optional DexScreener client (created if None)
        """
        self.database = database
        self.client = client or DexScreenerClient()

    async def analyze_liquidity(
        self,
        token_address: str,
        chain_id: str = "ethereum",
        cross_chain_ids: Optional[List[str]] = None,
    ) -> LiquidityAnalysisResult:
        """Analyze liquidity for a token.

        Args:
            token_address: Token contract address
            chain_id: Primary chain ID
            cross_chain_ids: Optional list of additional chains to check

        Returns:
            LiquidityAnalysisResult with comprehensive analysis
        """
        LOGGER.info(f"Analyzing liquidity for {token_address} on {chain_id}")

        # Step 1: Fetch all pairs for the token (without detailed enrichment for speed)
        pairs = await self.client.get_token_pairs(chain_id, token_address, fetch_detailed=False)

        if not pairs:
            LOGGER.warning(f"No pairs found for {token_address} on {chain_id}")
            return self._create_empty_result(token_address, chain_id)

        # Step 2: Calculate metrics
        metrics = self._calculate_metrics(token_address, chain_id, pairs)

        # Step 3: Check cross-chain liquidity if requested
        if cross_chain_ids:
            for cc_chain in cross_chain_ids:
                cc_pairs = await self.client.get_token_pairs(cc_chain, token_address, fetch_detailed=False)
                if cc_pairs:
                    metrics.chains_with_liquidity.append(cc_chain)
                    # Add cross-chain pairs to totals
                    metrics.total_tvl_usd += sum(p.liquidity_usd for p in cc_pairs)
                    metrics.total_pairs += len(cc_pairs)
                    metrics.unique_dexes = len(set(p.dex_id for p in pairs + cc_pairs))

        # Step 4: Calculate score and risk level
        score = self._calculate_score(metrics)
        risk_level = self._determine_risk_level(score, metrics)

        # Step 5: Generate recommendations
        recommendations = self._generate_recommendations(metrics, score)

        # Step 6: Store results in database
        LOGGER.info("Storing liquidity analysis result in database...")
        self._store_analysis_result(metrics, score, risk_level, recommendations)
        LOGGER.info("Liquidity analysis result stored successfully")

        return LiquidityAnalysisResult(
            metrics=metrics,
            score=score,
            risk_level=risk_level,
            recommendations=recommendations,
        )

    def _calculate_metrics(
        self,
        token_address: str,
        chain_id: str,
        pairs: List[DexPair],
    ) -> LiquidityMetrics:
        """Calculate comprehensive liquidity metrics."""

        # Total TVL
        total_tvl = sum(p.liquidity_usd for p in pairs)

        # Unique DEXs
        unique_dexes = len(set(p.dex_id for p in pairs))

        # Concentration risk (largest pool %)
        if pairs:
            largest_pool_tvl = max(p.liquidity_usd for p in pairs)
            largest_pool_tvl_pct = (largest_pool_tvl / total_tvl * 100) if total_tvl > 0 else 0
        else:
            largest_pool_tvl_pct = 0

        # DEX diversity score (0-1)
        # More unique DEXs with balanced TVL = higher score
        if total_tvl > 0:
            dex_tvls = {}
            for p in pairs:
                dex_tvls[p.dex_id] = dex_tvls.get(p.dex_id, 0) + p.liquidity_usd

            # Calculate Herfindahl index for DEX concentration
            hhi = sum((tvl / total_tvl) ** 2 for tvl in dex_tvls.values())
            dex_diversity_score = 1 - hhi  # 0 = concentrated, 1 = diverse
        else:
            dex_diversity_score = 0

        # TVL tier
        if total_tvl < 100000:
            tvl_tier = "very_low"
        elif total_tvl < 1000000:
            tvl_tier = "low"
        elif total_tvl < 10000000:
            tvl_tier = "medium"
        else:
            tvl_tier = "high"

        # Pool balance analysis
        balance_scores = []
        imbalanced_count = 0
        for p in pairs:
            if p.token0_reserves > 0 and p.token1_reserves > 0:
                # Calculate ratio (closer to 1 = more balanced)
                ratio = min(p.token0_reserves, p.token1_reserves) / max(p.token0_reserves, p.token1_reserves)
                balance_scores.append(ratio)
                if ratio < 0.1:  # Highly imbalanced (90:10 or worse)
                    imbalanced_count += 1

        avg_balance = sum(balance_scores) / len(balance_scores) if balance_scores else 0

        # Activity metrics
        total_volume = sum(p.volume_h24 for p in pairs)
        total_txns = sum(p.txns_h24_buys + p.txns_h24_sells for p in pairs)

        # Risk flags (only critical issues that impact score)
        flags = []
        if total_tvl < 100000:
            flags.append("very_low_tvl")
        elif total_tvl < 500000:
            flags.append("low_tvl")

        if largest_pool_tvl_pct > 80:
            flags.append("concentrated_liquidity")

        if total_volume < 10000:
            flags.append("low_activity")

        return LiquidityMetrics(
            token_address=token_address,
            chain_id=chain_id,
            total_tvl_usd=total_tvl,
            total_pairs=len(pairs),
            unique_dexes=unique_dexes,
            largest_pool_tvl_pct=largest_pool_tvl_pct,
            dex_diversity_score=dex_diversity_score,
            tvl_tier=tvl_tier,
            average_pool_balance_score=avg_balance,
            imbalanced_pools_count=imbalanced_count,
            total_volume_h24=total_volume,
            total_txns_h24=total_txns,
            flags=flags,
            chains_with_liquidity=[chain_id],
            analyzed_at=datetime.utcnow().isoformat(),
        )

    def _calculate_score(self, metrics: LiquidityMetrics) -> float:
        """Calculate overall liquidity score (0-100).

        Revised scoring based on real liquidity health:
        - TVL: 0-40 points (primary indicator of liquidity depth)
        - Pool count: 0-25 points (more pools = more exit liquidity)
        - Activity: 0-25 points (volume indicates real trading interest)
        - Cross-chain bonus: 0-10 points (multi-chain = more resilient)

        Penalties only for critical issues:
        - Very low TVL (<$100k): -20 points
        - Concentrated liquidity (>80% in one pool): -15 points
        - Low activity (<$10k volume): -10 points
        """
        score = 0.0

        # TVL score (0-40 points) - primary indicator
        tvl_scores = {
            "very_low": 0,   # <$100k
            "low": 5,        # <$1M
            "medium": 20,    # <$10M
            "high": 40,      # >=$10M
        }
        score += tvl_scores.get(metrics.tvl_tier, 0)

        # Pool count score (0-25 points) - more pools = better
        # Having multiple pools even on one DEX provides depth
        if metrics.total_pairs >= 20:
            score += 25
        elif metrics.total_pairs >= 10:
            score += 20
        elif metrics.total_pairs >= 5:
            score += 15
        elif metrics.total_pairs >= 2:
            score += 10
        elif metrics.total_pairs >= 1:
            score += 5

        # Activity score (0-25 points) - shows real trading interest
        if metrics.total_volume_h24 > 10000000:
            score += 25
        elif metrics.total_volume_h24 > 1000000:
            score += 20
        elif metrics.total_volume_h24 > 100000:
            score += 15
        elif metrics.total_volume_h24 > 10000:
            score += 10
        elif metrics.total_volume_h24 > 1000:
            score += 5

        # Cross-chain bonus (0-10 points) - multi-chain is better
        chain_count = len(metrics.chains_with_liquidity)
        if chain_count >= 4:
            score += 10
        elif chain_count >= 3:
            score += 7
        elif chain_count == 2:
            score += 5

        # Critical risk penalties (only for severe issues)
        if "very_low_tvl" in metrics.flags:
            score -= 20
        elif "low_tvl" in metrics.flags:
            score -= 10

        if "concentrated_liquidity" in metrics.flags:
            score -= 15

        if "low_activity" in metrics.flags:
            score -= 10

        return max(0, min(100, score))

    def _determine_risk_level(self, score: float, metrics: LiquidityMetrics) -> str:
        """Determine risk level from score and metrics."""

        if score >= 70:
            return "low"
        elif score >= 40:
            return "medium"
        elif score >= 20:
            return "high"
        else:
            return "critical"

    def _generate_recommendations(self, metrics: LiquidityMetrics, score: float) -> List[str]:
        """Generate actionable recommendations."""

        recommendations = []

        if metrics.tvl_tier in ("very_low", "low"):
            recommendations.append("Add more liquidity to reduce slippage risk")

        if "concentrated_liquidity" in metrics.flags:
            recommendations.append("Diversify liquidity across multiple pools to reduce concentration risk")

        if "low_activity" in metrics.flags:
            recommendations.append("Increase trading activity through marketing or incentive programs")

        if len(metrics.chains_with_liquidity) == 1:
            recommendations.append("Consider cross-chain liquidity expansion for broader reach")

        if metrics.total_pairs < 3:
            recommendations.append("Create additional trading pairs on other DEXes to increase liquidity depth")

        if metrics.total_pairs >= 1 and score >= 70:
            recommendations.append("Liquidity looks healthy - continue monitoring")

        if not recommendations:
            recommendations.append("Liquidity looks adequate - maintain current levels")

        return recommendations

    def _create_empty_result(self, token_address: str, chain_id: str) -> LiquidityAnalysisResult:
        """Create result for tokens with no liquidity data."""
        metrics = LiquidityMetrics(
            token_address=token_address,
            chain_id=chain_id,
            total_tvl_usd=0,
            total_pairs=0,
            unique_dexes=0,
            largest_pool_tvl_pct=0,
            dex_diversity_score=0,
            tvl_tier="very_low",
            average_pool_balance_score=0,
            imbalanced_pools_count=0,
            total_volume_h24=0,
            total_txns_h24=0,
            flags=["no_liquidity_found"],
            chains_with_liquidity=[],
            analyzed_at=datetime.utcnow().isoformat(),
        )

        return LiquidityAnalysisResult(
            metrics=metrics,
            score=0,
            risk_level="critical",
            recommendations=["No trading pairs found - token may not be launched yet"],
        )

    def _store_analysis_result(
        self,
        metrics: LiquidityMetrics,
        score: float,
        risk_level: str,
        recommendations: List[str],
    ) -> None:
        """Store analysis result in database."""
        self.database.store_liquidity_snapshot(
            token_address=metrics.token_address,
            chain_id=metrics.chain_id,
            total_tvl_usd=metrics.total_tvl_usd,
            total_pairs=metrics.total_pairs,
            unique_dexes=metrics.unique_dexes,
            largest_pool_tvl_pct=metrics.largest_pool_tvl_pct,
            dex_diversity_score=metrics.dex_diversity_score,
            tvl_tier=metrics.tvl_tier,
            avg_pool_balance_score=metrics.average_pool_balance_score,
            imbalanced_pools_count=metrics.imbalanced_pools_count,
            total_volume_h24=metrics.total_volume_h24,
            total_txns_h24=metrics.total_txns_h24,
            liquidity_score=score,
            risk_level=risk_level,
            flags=metrics.flags,
            chains_with_liquidity=metrics.chains_with_liquidity,
            recommendations=recommendations,
            analyzed_at=metrics.analyzed_at,
        )

    async def close(self) -> None:
        """Close the DexScreener client."""
        await self.client.close()
