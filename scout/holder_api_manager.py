"""Holder API manager with automatic multi-provider failover.

This module provides a manager class that coordinates multiple holder API
providers (Ethplorer, NodeReal, Moralis, CoinGecko) with automatic failover
when providers fail, similar to the UnifiedRpcManager pattern.

Provider Priority Order:
1. Ethplorer (Highest) - Uses "freekey" by default, supports ETH, BSC, Linea, Blast
2. NodeReal - Requires API key, supports ETH and BSC
3. Moralis - Requires API key, supports multiple chains
4. CoinGecko (Lowest) - Requires API key, supports multiple chains

Features:
- Automatic failover between providers
- Result caching with configurable TTL
- Rate limiting per provider (respects API limits)
- Parallel token collection support
"""

from __future__ import annotations

import logging
import math
import os
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

from scout.cache_manager import HolderDataCache
from scout.coingecko_holder_provider import CoinGeckoHolderProvider
from scout.ethplorer_holder_provider import EthplorerHolderProvider
from scout.holder_api_providers import (
    HolderAPIProvider,
    HolderData,
    HolderMetrics,
    MoralisHolderProvider,
    NodeRealHolderProvider,
)
from scout.rate_limiter import AsyncRateLimiter, get_rate_limiter

if TYPE_CHECKING:
    from scout.database_manager import DatabaseManager

LOGGER = logging.getLogger(__name__)

# Holder tier thresholds for USD-based classification (Etherscan-style)
HOLDER_TIER_THRESHOLDS = [
    {"tier": "WHALE",   "label": "Whale (>$100K)",     "emoji": "🐋", "min_usd": 100_000},
    {"tier": "SHARK",   "label": "Shark ($10K-$100K)", "emoji": "🦈", "min_usd": 10_000},
    {"tier": "DOLPHIN", "label": "Dolphin ($1K-$10K)", "emoji": "🐬", "min_usd": 1_000},
    {"tier": "FISH",    "label": "Fish ($100-$1K)",    "emoji": "🐟", "min_usd": 100},
    {"tier": "CRAB",    "label": "Crab ($10-$100)",    "emoji": "🦀", "min_usd": 10},
    {"tier": "SHRIMP",  "label": "Shrimp (<$10)",      "emoji": "🦐", "min_usd": 0},
]

class HolderAPIManager:
    """Manages multiple holder API providers with automatic failover.

    Similar to UnifiedRpcManager but for holder data APIs. Automatically
    detects available providers from environment variables and provides
    failover when providers fail.

    Provider Priority Order:
    1. Ethplorer (Highest) - Uses "freekey" by default for free tier
    2. NodeReal - Requires NODEREAL_API_KEY
    3. Moralis - Requires MORALIS_API_KEY
    4. CoinGecko (Lowest) - Requires COINGECKO_API_KEY

    Example:
        manager = HolderAPIManager()
        metrics = await manager.get_holder_data(
            token_address="0x...",
            chain_id=1,
            limit=100
        )
        print(f"Holder count: {metrics.total_holder_count}")
        print(f"Gini: {metrics.gini_coefficient}")
    """

    def __init__(
        self,
        providers: Optional[List[HolderAPIProvider]] = None,
        database: Optional["DatabaseManager"] = None,
        cache_ttl: float = 3600.0,  # 1 hour default
        enable_cache: bool = True,
        enable_rate_limiting: bool = True,
    ) -> None:
        """Initialize the holder API manager.

        Args:
            providers: List of provider instances (auto-detected if None)
            database: Optional database manager for RPC calls (e.g., totalSupply)
            cache_ttl: Cache time-to-live in seconds (default: 1 hour)
            enable_cache: Whether to enable caching (default: True)
            enable_rate_limiting: Whether to enable rate limiting (default: True)
        """
        self.providers: Dict[str, HolderAPIProvider] = {}
        self.database = database
        self.enable_cache = enable_cache
        self.enable_rate_limiting = enable_rate_limiting

        # Initialize cache
        if enable_cache:
            self.cache = HolderDataCache(default_ttl=cache_ttl, max_size=1000)
            LOGGER.info(f"Holder data cache enabled (TTL: {cache_ttl}s)")
        else:
            self.cache = None

        # Initialize rate limiters per provider
        self.rate_limiters: Dict[str, AsyncRateLimiter] = {}

        if providers:
            for provider in providers:
                self.providers[provider.provider_name] = provider
                if enable_rate_limiting:
                    self._init_rate_limiter(provider)
        else:
            self._auto_detect_providers()

        # Initialize rate limiters for auto-detected providers
        if enable_rate_limiting:
            for provider_name in self.providers:
                provider = self.providers[provider_name]
                self._init_rate_limiter(provider)

    def _init_rate_limiter(self, provider: HolderAPIProvider) -> None:
        """Initialize rate limiter for a provider.

        Args:
            provider: Provider instance
        """
        # Determine if using free tier based on API key
        is_free_tier = True
        if hasattr(provider, 'api_key'):
            api_key = provider.api_key
            # Check if it's a free tier key
            if api_key and api_key != "freekey":
                # Assume paid tier if custom API key is set
                is_free_tier = False

        self.rate_limiters[provider.provider_name] = get_rate_limiter(
            provider.provider_name,
            is_free_tier=is_free_tier,
        )
        LOGGER.debug(
            f"Rate limiter initialized for {provider.provider_name} "
            f"({'free' if is_free_tier else 'paid'} tier)"
        )

    def _auto_detect_providers(self) -> None:
        """Auto-detect available providers from environment variables.

        Checks for (in priority order):
        - ETHPLORER_API_KEY: Initialize Ethplorer holder provider (defaults to "freekey" if not set)
        - NODEREAL_API_KEY: Initialize NodeReal holder provider
        - MORALIS_API_KEY: Initialize Moralis holder provider
        - COINGECKO_API_KEY: Initialize CoinGecko holder provider
        """
        # Ethplorer (Highest Priority - always initialized if supported chains needed)
        # Free tier uses "freekey" by default, no API key required
        ethplorer_key = os.environ.get("ETHPLORER_API_KEY", "freekey")
        try:
            self.providers["Ethplorer"] = EthplorerHolderProvider(ethplorer_key)
            LOGGER.info(f"Initialized Ethplorer holder provider (using {'freekey' if ethplorer_key == 'freekey' else 'custom API key'})")
        except Exception as e:
            LOGGER.warning(f"Failed to initialize Ethplorer: {e}")

        # NodeReal
        nodereal_key = os.environ.get("NODEREAL_API_KEY")
        if nodereal_key:
            try:
                self.providers["NodeReal"] = NodeRealHolderProvider(nodereal_key)
                LOGGER.info("Initialized NodeReal holder provider")
            except Exception as e:
                LOGGER.warning(f"Failed to initialize NodeReal: {e}")

        # Moralis
        moralis_key = os.environ.get("MORALIS_API_KEY")
        if moralis_key:
            try:
                self.providers["Moralis"] = MoralisHolderProvider(moralis_key)
                LOGGER.info("Initialized Moralis holder provider")
            except Exception as e:
                LOGGER.warning(f"Failed to initialize Moralis: {e}")

        # CoinGecko
        coingecko_key = os.environ.get("COINGECKO_API_KEY")
        if coingecko_key:
            try:
                self.providers["CoinGecko"] = CoinGeckoHolderProvider(coingecko_key)
                LOGGER.info("Initialized CoinGecko holder provider")
            except Exception as e:
                LOGGER.warning(f"Failed to initialize CoinGecko: {e}")

        if not self.providers:
            LOGGER.warning(
                "No holder API providers configured. "
                "Ethplorer will use freekey by default. "
                "Alternatively, set NODEREAL_API_KEY, MORALIS_API_KEY, or COINGECKO_API_KEY"
            )

    def get_provider_for_chain(
        self,
        chain_id: int,
        exclude_failed: Optional[List[str]] = None,
    ) -> Optional[HolderAPIProvider]:
        """Get best available provider for a chain.

        Args:
            chain_id: Chain ID
            exclude_failed: List of provider names to exclude

        Returns:
            Best available provider, or None if no provider supports this chain
        """
        for provider in self.providers.values():
            # Check if provider supports this chain
            if chain_id not in provider.supported_chains:
                continue

            # Check if excluded
            if exclude_failed and provider.provider_name in exclude_failed:
                continue

            return provider

        return None

    async def get_total_supply(
        self,
        token_address: str,
        chain_id: int,
    ) -> Optional[int]:
        """Get total supply from token contract via RPC.

        Uses eth_call to invoke the ERC20 totalSupply() function.
        The function selector for totalSupply() is 0x18160ddd.

        Args:
            token_address: Token contract address
            chain_id: Chain ID

        Returns:
            Total supply as integer, or None if call fails
        """
        if not self.database:
            LOGGER.warning("Cannot get totalSupply: no database manager configured")
            return None

        rpc_mgr = None
        try:
            from scout.shared_rpc_manager import create_rpc_manager

            # Create RPC manager for this chain
            rpc_mgr = create_rpc_manager(chain_id, self.database)

            # Get any healthy provider
            provider = rpc_mgr.get_healthy_providers()
            if not provider:
                LOGGER.warning(f"No healthy RPC providers for chain {chain_id}")
                return None

            provider = provider[0]  # Use first healthy provider

            # ERC20 totalSupply() function call
            # Function selector: 0x18160ddd (keccak256("totalSupply()")[:4])
            call_payload = {
                "to": token_address,
                "data": "0x18160ddd"
            }

            result = await provider.make_request(
                "eth_call",
                [call_payload, "latest"]
            )

            if result and isinstance(result, str):
                total_supply = int(result, 16) if result.startswith("0x") else int(result)
                LOGGER.info(f"Got totalSupply for {token_address[:10]}...: {total_supply}")
                return total_supply

        except Exception as e:
            LOGGER.error(f"Failed to get totalSupply for {token_address}: {e}")
        finally:
            # Clean up RPC manager to avoid unclosed session warnings
            if rpc_mgr:
                await rpc_mgr.close()

        return None

    async def get_token_decimals(
        self,
        token_address: str,
        chain_id: int,
    ) -> int:
        """Get token decimals from contract via RPC.

        Uses eth_call to invoke the ERC20 decimals() function.
        The function selector for decimals() is 0x313ce567.

        Args:
            token_address: Token contract address
            chain_id: Chain ID

        Returns:
            Token decimals (defaults to 18 if call fails)
        """
        if not self.database:
            LOGGER.debug("Cannot get decimals: no database manager configured, defaulting to 18")
            return 18

        rpc_mgr = None
        try:
            from scout.shared_rpc_manager import create_rpc_manager

            rpc_mgr = create_rpc_manager(chain_id, self.database)

            provider = rpc_mgr.get_healthy_providers()
            if not provider:
                LOGGER.warning(f"No healthy RPC providers for chain {chain_id}, defaulting decimals to 18")
                return 18

            provider = provider[0]

            # ERC20 decimals() function call
            # Function selector: 0x313ce567 (keccak256("decimals()")[:4])
            call_payload = {
                "to": token_address,
                "data": "0x313ce567"
            }

            result = await provider.make_request(
                "eth_call",
                [call_payload, "latest"]
            )

            if result and isinstance(result, str):
                decimals = int(result, 16) if result.startswith("0x") else int(result)
                LOGGER.info(f"Got decimals for {token_address[:10]}...: {decimals}")
                return decimals

        except Exception as e:
            LOGGER.warning(f"Failed to get decimals for {token_address}: {e}, defaulting to 18")
        finally:
            if rpc_mgr:
                await rpc_mgr.close()

        return 18

    async def get_holder_data(
        self,
        token_address: str,
        chain_id: int,
        limit: int = 100,
        bypass_cache: bool = False,
    ) -> Optional[HolderMetrics]:
        """Get holder data with automatic failover between providers.

        Tries each available provider that supports the chain, falling back
        to the next provider if one fails. Uses caching to reduce redundant
        API calls and rate limiting to respect provider limits.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            limit: Maximum number of top holders to fetch
            bypass_cache: Force fresh data, bypassing cache (default: False)

        Returns:
            HolderMetrics with data, or None if all providers fail
        """
        # Check cache first (if enabled and not bypassing)
        if not bypass_cache and self.enable_cache and self.cache:
            cached_holders = self.cache.get_top_holders(token_address, chain_id, limit)
            if cached_holders is not None:
                # We have cached holders, but we still want holder count
                cached_count = self.cache.get_holder_count(token_address, chain_id)
                if cached_count is not None:
                    # Calculate metrics from cached data
                    total_supply = await self.get_total_supply(token_address, chain_id)
                    decimals = await self.get_token_decimals(token_address, chain_id)
                    final_holder_count = cached_count if cached_count is not None else len(cached_holders)
                    price_usd = await self._fetch_price_usd(token_address, chain_id)
                    metrics_dict = self._calculate_metrics(
                        cached_holders,
                        final_holder_count,
                        total_supply,
                        price_usd=price_usd,
                        decimals=decimals,
                    )
                    LOGGER.info(
                        f"Cache hit for {token_address[:10]}... on chain {chain_id} "
                        f"(holders: {len(cached_holders)}, count: {cached_count})"
                    )
                    return HolderMetrics(
                        total_holder_count=final_holder_count,
                        top_holders=cached_holders,
                        **metrics_dict
                    )

        exclude_failed: List[str] = []
        max_retries = len(self.providers)

        for attempt in range(max_retries):
            provider = self.get_provider_for_chain(chain_id, exclude_failed)

            if not provider:
                LOGGER.warning(f"No provider available for chain {chain_id}")
                break

            try:
                # Apply rate limiting before making API call
                if self.enable_rate_limiting and provider.provider_name in self.rate_limiters:
                    await self.rate_limiters[provider.provider_name].acquire_or_wait(provider.provider_name)

                LOGGER.info(
                    f"Attempting {provider.provider_name} for {token_address} on chain {chain_id}"
                )

                # Check cache for holder count
                holder_count = None
                if not bypass_cache and self.enable_cache and self.cache:
                    holder_count = self.cache.get_holder_count(token_address, chain_id)
                    if holder_count is not None:
                        LOGGER.debug(f"Cache hit for holder count: {holder_count}")

                # Fetch holder count from API if not in cache
                if holder_count is None:
                    holder_count = await provider.get_holder_count(token_address, chain_id)
                    # Cache the result
                    if holder_count is not None and self.enable_cache and self.cache:
                        self.cache.set_holder_count(token_address, chain_id, holder_count)

                # Check cache for top holders
                top_holders = None
                if not bypass_cache and self.enable_cache and self.cache:
                    top_holders = self.cache.get_top_holders(token_address, chain_id, limit)
                    if top_holders is not None:
                        LOGGER.debug(f"Cache hit for top holders: {len(top_holders)} holders")

                # Fetch top holders from API if not in cache
                if top_holders is None:
                    top_holders = await provider.get_top_holders(token_address, chain_id, limit)
                    # Cache the result
                    if top_holders and self.enable_cache and self.cache:
                        self.cache.set_top_holders(token_address, chain_id, top_holders, limit)

                if top_holders:
                    # Get real total supply from contract
                    total_supply = await self.get_total_supply(token_address, chain_id)

                    # Use holder count from API, or fall back to len(top_holders)
                    final_holder_count = holder_count if holder_count is not None else len(top_holders)

                    if holder_count is None:
                        LOGGER.warning(
                            f"Holder count API returned None, using top holders count ({len(top_holders)}) as fallback"
                        )
                    else:
                        LOGGER.info(f"Using holder count from API: {holder_count}")

                    # Calculate metrics with real total supply
                    decimals = await self.get_token_decimals(token_address, chain_id)
                    price_usd = await self._fetch_price_usd(token_address, chain_id)
                    metrics_dict = self._calculate_metrics(
                        top_holders,
                        final_holder_count,
                        total_supply,
                        price_usd=price_usd,
                        decimals=decimals,
                    )

                    LOGGER.info(
                        f"Successfully fetched {len(top_holders)} top holders from {provider.provider_name}, "
                        f"total holder count: {final_holder_count}",
                        extra={
                            "provider": provider.provider_name,
                            "holder_count": final_holder_count,
                            "holder_count_from_api": holder_count,
                            "chain_id": chain_id,
                            "token": token_address,
                        }
                    )

                    return HolderMetrics(
                        total_holder_count=final_holder_count,
                        top_holders=top_holders,
                        **metrics_dict
                    )
                else:
                    LOGGER.warning(f"{provider.provider_name} returned no holders")
                    exclude_failed.append(provider.provider_name)

            except Exception as e:
                LOGGER.warning(f"{provider.provider_name} failed: {e}")
                exclude_failed.append(provider.provider_name)
                continue

        LOGGER.error(f"All providers failed for {token_address} on chain {chain_id}")
        return None

    async def _fetch_price_usd(
        self, token_address: str, chain_id: int,
    ) -> Optional[float]:
        """Fetch current token price from DexScreener for tier classification."""
        try:
            from scout.dexscreener_client import DexScreenerClient
            dex_client = DexScreenerClient()
            chain_str = "ethereum" if chain_id == 1 else str(chain_id)
            pairs = await dex_client.get_token_pairs(
                chain_str, token_address, fetch_detailed=False,
            )
            price = None
            if pairs and pairs[0].price_usd:
                price = float(pairs[0].price_usd)
            await dex_client.close()
            if price:
                LOGGER.info(f"DexScreener price for {token_address[:10]}...: ${price}")
            return price
        except Exception as e:
            LOGGER.warning(f"Failed to fetch price for tier classification: {e}")
            return None

    def _calculate_metrics(
        self,
        holders: List[HolderData],
        total_count: int,
        total_supply: Optional[int] = None,
        price_usd: Optional[float] = None,
        decimals: int = 18,
    ) -> Dict:
        """Calculate distribution metrics from holder data.

        Dead address (0x...dEaD) is excluded from gini/nakamoto calculations
        and its balance is subtracted from total supply (burned tokens).

        Args:
            holders: List of holder data (sorted by balance descending)
            total_count: Total holder count (for percentage calculations)
            total_supply: Optional total supply from contract call (estimated if None)
            price_usd: Optional token price in USD for tier classification
            decimals: Token decimals for converting raw balances (default: 18)

        Returns:
            Dictionary with calculated metrics
        """
        if not holders:
            return {
                "gini_coefficient": 0.0,
                "nakamoto_coefficient": 0,
                "top_10_pct_supply": 0.0,
                "top_1_pct_supply": 0.0,
                "top_100_balance_sum": "0x0",
                "estimated_total_supply": "0x0",
                "price_usd": price_usd,
            }

        # Exclude dead address from concentration metrics
        DEAD_ADDRESS = "0x000000000000000000000000000000000000dEaD".lower()
        dead_balance = 0
        filtered_holders = []
        for h in holders:
            if h.address.lower() == DEAD_ADDRESS:
                dead_balance = h.balance
                LOGGER.info(f"Excluding dead address from metrics: balance={h.balance}")
            else:
                filtered_holders.append(h)

        balances = [h.balance for h in filtered_holders]
        top_100_sum = sum(balances)

        # Subtract burned tokens from total supply
        if total_supply is not None:
            effective_supply = total_supply - dead_balance
            LOGGER.info(
                f"Adjusted total supply for burned tokens: "
                f"{total_supply} - {dead_balance} = {effective_supply}"
            )
            estimated_total_supply = max(effective_supply, 0)
        elif dead_balance > 0:
            # Estimate minus burned
            estimated_total_supply = max(top_100_sum * 2 - dead_balance, 0)
            LOGGER.debug("Using estimated supply adjusted for burned tokens")
        else:
            estimated_total_supply = top_100_sum * 2
            LOGGER.debug("Using estimated total supply (top_100_sum * 2)")

        # Convert to hex strings for TEXT storage in database
        top_100_sum_hex = f"0x{top_100_sum:x}"
        estimated_total_supply_hex = f"0x{estimated_total_supply:x}"

        # Gini coefficient (excludes dead address)
        gini = self._calculate_gini(balances)

        # Nakamoto coefficient (holders for 51%, excludes dead address)
        nakamoto = self._calculate_nakamoto(balances, top_100_sum)

        # Top 10% and 1% of holders (adjust count for dead address removal)
        effective_count = max(total_count - (1 if dead_balance > 0 else 0), 1)
        top_10_n = max(1, effective_count // 10) if effective_count > 0 else 10
        top_1_n = max(1, effective_count // 100) if effective_count > 0 else 1

        top_10_sum = sum(balances[:min(top_10_n, len(balances))])
        top_1_sum = sum(balances[:min(top_1_n, len(balances))])

        top_10_pct = (top_10_sum / estimated_total_supply * 100) if estimated_total_supply > 0 else 0
        top_1_pct = (top_1_sum / estimated_total_supply * 100) if estimated_total_supply > 0 else 0

        return {
            "gini_coefficient": round(max(0, min(1, gini)), 4),
            "nakamoto_coefficient": nakamoto,
            "top_10_pct_supply": round(top_10_pct, 3),
            "top_1_pct_supply": round(top_1_pct, 3),
            "top_100_balance_sum": top_100_sum_hex,
            "estimated_total_supply": estimated_total_supply_hex,
            "holder_tiers": self._calculate_holder_tiers(
                filtered_holders, total_count, estimated_total_supply, price_usd,
                decimals=decimals,
            ) if price_usd and price_usd > 0 else None,
            "price_usd": price_usd,
        }

    def _calculate_holder_tiers(
        self,
        holders: List[HolderData],
        total_count: int,
        total_supply: int,
        price_usd: float,
        decimals: int = 18,
    ) -> Optional[List[Dict]]:
        """Classify holders into USD-based tier buckets (Etherscan-style).

        Known holders (from API data) are classified exactly by their
        (balance / 10^decimals) * price_usd.  Remaining holders are
        distributed across tiers using a Pareto (power-law) model that
        reflects the heavy-tailed nature of crypto token holdings.

        Args:
            holders: Filtered holder data (dead address already excluded)
            total_count: Total holder count
            total_supply: Effective total supply (burned tokens already excluded)
            price_usd: Current token price in USD
            decimals: Token decimals for converting raw balances (default: 18)

        Returns:
            List of tier dicts or None if price_usd is invalid
        """
        if (
            not price_usd
            or not math.isfinite(price_usd)
            or price_usd <= 0
            or total_count <= 0
            or total_supply <= 0
        ):
            return None

        try:
            decimals = int(decimals)
        except (TypeError, ValueError):
            decimals = 18
        if decimals < 0:
            decimals = 18

        # Initialize tier buckets
        buckets = [
            {**t, "holders": 0, "supply": 0}
            for t in HOLDER_TIER_THRESHOLDS
        ]

        # ---- 1. Classify known holders exactly ----
        known_supply = 0
        decimals_divisor = 10 ** decimals
        for h in holders:
            usd_value = self._holder_usd_value(h.balance, decimals_divisor, price_usd)
            known_supply += h.balance

            bucket = self._tier_bucket_for_usd_value(buckets, usd_value)
            bucket["holders"] += 1
            bucket["supply"] += h.balance

        # ---- 2. Distribute remaining holders via Pareto model ----
        remaining_count = max(total_count - len(holders), 0)
        remaining_supply = max(total_supply - known_supply, 0)

        if remaining_count > 0:
            # Compute the average USD value for the remaining holders.
            # When known holders collectively hold less than total supply,
            # we can compute the exact average of the remaining group.
            # When they exceed total supply (e.g. due to staking/re-delegation),
            # fall back to the overall per-holder average (total_supply / total_count)
            # which gives a much more realistic estimate for small holders.
            if remaining_supply > 0:
                avg_balance = remaining_supply / remaining_count
            else:
                # Known holders exceed total supply — use the overall per-holder
                # average.  This is far lower than any top-100 balance and
                # correctly places most small holders in Fish/Crab/Shrimp.
                avg_balance = total_supply / total_count

            avg_token_amount = avg_balance / decimals_divisor
            avg_usd = avg_token_amount * price_usd

            # Pareto Type I distribution: P(X >= x) = (xm / x)^alpha
            # Mean = alpha * xm / (alpha - 1)  =>  xm = mean * (alpha-1) / alpha
            # alpha = 1.5 gives realistic crypto holder inequality
            alpha = 1.5

            if avg_usd <= 0:
                # Edge case: assign all to Shrimp
                buckets[-1]["holders"] += remaining_count
                if remaining_supply > 0:
                    buckets[-1]["supply"] += remaining_supply
            else:
                # Scale parameter from average
                xm = avg_usd * (alpha - 1) / alpha

                # Compute per-tier fraction using Pareto survival function
                # P(X in [lower, upper)) = P(X >= lower) - P(X >= upper)
                per_tier_frac = []
                for i, bucket in enumerate(buckets):
                    lower = bucket["min_usd"]
                    upper = buckets[i - 1]["min_usd"] if i > 0 else float("inf")

                    # Survival function at boundaries
                    if lower >= xm:
                        sf_lower = (xm / lower) ** alpha
                    else:
                        sf_lower = 1.0  # below scale → everyone exceeds

                    if upper >= xm:
                        sf_upper = (xm / upper) ** alpha
                    else:
                        sf_upper = 1.0

                    per_tier_frac.append(max(sf_lower - sf_upper, 0.0))

                total_frac = sum(per_tier_frac)
                if total_frac <= 0:
                    # Fallback: assign all to the tier matching avg_usd
                    bucket = self._tier_bucket_for_usd_value(buckets, avg_usd)
                    bucket["holders"] += remaining_count
                    if remaining_supply > 0:
                        bucket["supply"] += remaining_supply
                else:
                    counts = self._allocate_remaining_tier_counts(
                        remaining_count, per_tier_frac, total_frac,
                    )
                    for i, bucket in enumerate(buckets):
                        count = counts[i]
                        if count > 0:
                            bucket["holders"] += count
                            # Supply estimate: midpoint USD of tier × price
                            if i < len(buckets) - 1:
                                mid_usd = (bucket["min_usd"] + buckets[i + 1]["min_usd"]) / 2
                            else:
                                mid_usd = bucket["min_usd"] + 0.5
                            mid_balance = (mid_usd / price_usd) * decimals_divisor
                            bucket["supply"] += int(count * mid_balance)

        # ---- 3. Build result with percentages ----
        result = []
        for b in buckets:
            holders_pct = (b["holders"] / total_count * 100) if total_count > 0 else 0
            supply_pct = (b["supply"] / total_supply * 100) if total_supply > 0 else 0
            result.append({
                "tier": b["tier"],
                "label": b["label"],
                "emoji": b["emoji"],
                "holders": b["holders"],
                "holders_pct": round(holders_pct, 2),
                "supply_pct": round(supply_pct, 2),
            })

        return result

    def _holder_usd_value(
        self,
        raw_balance: int,
        decimals_divisor: int,
        price_usd: float,
    ) -> float:
        """Calculate USD value from a raw token balance."""
        if raw_balance <= 0 or decimals_divisor <= 0:
            return 0.0
        return (raw_balance / decimals_divisor) * price_usd

    def _tier_bucket_for_usd_value(self, buckets: List[Dict], usd_value: float) -> Dict:
        """Return the tier bucket for a holder's USD value."""
        for bucket in buckets:
            if usd_value >= bucket["min_usd"]:
                return bucket
        return buckets[-1]

    def _allocate_remaining_tier_counts(
        self,
        remaining_count: int,
        per_tier_frac: List[float],
        total_frac: float,
    ) -> List[int]:
        """Allocate synthetic holders across tiers without losing counts to rounding."""
        raw_counts = [
            (remaining_count * fraction / total_frac) if total_frac > 0 else 0.0
            for fraction in per_tier_frac
        ]
        counts = [int(math.floor(count)) for count in raw_counts]
        shortfall = remaining_count - sum(counts)

        if shortfall <= 0:
            return counts

        remainder_order = sorted(
            range(len(raw_counts)),
            key=lambda i: raw_counts[i] - counts[i],
            reverse=True,
        )
        for index in remainder_order[:shortfall]:
            counts[index] += 1

        return counts

    def _calculate_gini(self, balances: List[int]) -> float:
        """Calculate Gini coefficient from balance list.

        Args:
            balances: List of balances (sorted or unsorted)

        Returns:
            Gini coefficient (0 = perfect equality, 1 = perfect inequality)
        """
        if not balances:
            return 0.0

        n = len(balances)
        total = sum(balances)
        if total == 0:
            return 0.0

        # Ascending order for Gini calculation
        ascending = sorted(balances)

        weighted_sum = sum((i + 1) * b for i, b in enumerate(ascending))
        gini = (2 * weighted_sum) / (n * total) - (n + 1) / n

        return max(0.0, min(1.0, gini))

    def _calculate_nakamoto(self, balances: List[int], total: int) -> int:
        """Calculate Nakamoto coefficient.

        The Nakamoto coefficient is the minimum number of holders needed
        to control 51% of the supply.

        Args:
            balances: List of balances sorted by size (descending)
            total: Total supply (sum of all balances)

        Returns:
            Number of holders needed for 51% control
        """
        if total == 0:
            return 0

        cumulative = 0
        for i, balance in enumerate(balances):
            cumulative += balance
            if cumulative > total / 2:
                return i + 1

        return len(balances)

    async def get_holder_data_batch(
        self,
        tokens: List[Tuple[str, int]],  # List of (token_address, chain_id)
        limit: int = 100,
        bypass_cache: bool = False,
        max_concurrency: int = 5,
    ) -> Dict[Tuple[str, int], Optional[HolderMetrics]]:
        """Get holder data for multiple tokens in parallel.

        Uses asyncio.gather to fetch data for multiple tokens concurrently,
        with controlled concurrency to respect rate limits.

        Args:
            tokens: List of (token_address, chain_id) tuples
            limit: Maximum number of top holders to fetch per token
            bypass_cache: Force fresh data, bypassing cache
            max_concurrency: Maximum number of concurrent requests

        Returns:
            Dictionary mapping (token_address, chain_id) to HolderMetrics or None
        """
        results = {}

        # Split into batches to control concurrency
        for i in range(0, len(tokens), max_concurrency):
            batch = tokens[i:i + max_concurrency]

            # Create tasks for this batch
            tasks = []
            for token_address, chain_id in batch:
                task = self.get_holder_data(
                    token_address=token_address,
                    chain_id=chain_id,
                    limit=limit,
                    bypass_cache=bypass_cache,
                )
                tasks.append((token_address, chain_id, task))

            # Execute batch concurrently
            LOGGER.info(f"Fetching holder data for batch of {len(tasks)} tokens")
            for token_address, chain_id, task in tasks:
                try:
                    metrics = await task
                    results[(token_address, chain_id)] = metrics
                    status = "SUCCESS" if metrics else "FAILED"
                    LOGGER.info(
                        f"Completed {token_address[:10]}... on chain {chain_id}: {status}"
                    )
                except Exception as e:
                    LOGGER.error(f"Failed to fetch data for {token_address[:10]}... on chain {chain_id}: {e}")
                    results[(token_address, chain_id)] = None

        return results

    def clear_cache(self, token_address: Optional[str] = None, chain_id: Optional[int] = None) -> int:
        """Clear cached holder data.

        Args:
            token_address: Optional token address to clear (clears all if None)
            chain_id: Optional chain ID to clear (clears all if None)

        Returns:
            Number of cache entries cleared
        """
        if not self.enable_cache or not self.cache:
            return 0

        if token_address is None:
            # Clear all cache
            count = len(self.cache)
            self.cache.clear()
            LOGGER.info(f"Cleared all cache entries: {count} entries")
            return count
        else:
            # Clear specific token
            count = 0
            token_lower = token_address.lower()

            # Clear holder count entry
            holder_count_key = f"holder_count:{token_lower}:{chain_id or 1}"
            if self.cache.delete(holder_count_key):
                count += 1

            # Clear top holders entries (for various limits)
            for key in list(self.cache._cache.keys()):
                if key.startswith(f"top_holders:{token_lower}:{chain_id or 1}:"):
                    if self.cache.delete(key):
                        count += 1

            LOGGER.info(f"Cleared {count} cache entries for {token_address[:10]}... on chain {chain_id or 1}")
            return count

    def cleanup_cache(self) -> int:
        """Remove expired entries from the cache.

        Returns:
            Number of entries removed
        """
        if not self.enable_cache or not self.cache:
            return 0

        count = self.cache.cleanup()
        if count > 0:
            LOGGER.info(f"Cache cleanup: {count} expired entries removed")
        return count

    def get_cache_stats(self) -> Optional[Dict]:
        """Get cache statistics.

        Returns:
            Dictionary with cache stats, or None if cache is disabled
        """
        if not self.enable_cache or not self.cache:
            return None

        return self.cache.get_stats()

    async def close_all(self) -> None:
        """Close all provider HTTP clients and cleanup resources."""
        for provider in self.providers.values():
            await provider.close()


def create_holder_api_manager(
    database: Optional["DatabaseManager"] = None,
    cache_ttl: float = 3600.0,  # 1 hour default
    enable_cache: bool = True,
    enable_rate_limiting: bool = True,
) -> HolderAPIManager:
    """Factory function to create a holder API manager with auto-detected providers.

    This is the recommended way to create a HolderAPIManager instance.
    It automatically detects available providers from environment variables.

    Args:
        database: Optional database manager for RPC calls (e.g., totalSupply)
        cache_ttl: Cache time-to-live in seconds (default: 1 hour)
        enable_cache: Whether to enable result caching (default: True)
        enable_rate_limiting: Whether to enable rate limiting (default: True)

    Returns:
        HolderAPIManager instance with auto-detected providers

    Example:
        manager = create_holder_api_manager(database=db)
        metrics = await manager.get_holder_data("0x...", 1)

        # Batch collection
        results = await manager.get_holder_data_batch([
            ("0x...", 1),
            ("0x...", 56),
        ])

        # Cache management
        stats = manager.get_cache_stats()
        manager.clear_cache()

        await manager.close_all()
    """
    return HolderAPIManager(
        database=database,
        cache_ttl=cache_ttl,
        enable_cache=enable_cache,
        enable_rate_limiting=enable_rate_limiting,
    )
