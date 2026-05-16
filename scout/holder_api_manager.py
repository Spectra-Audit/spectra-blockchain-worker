"""Holder API manager with automatic multi-provider failover.

This module provides a manager class that coordinates multiple holder API
providers (Ethplorer, NodeReal, Moralis, CoinGecko) with automatic failover
when providers fail, similar to the UnifiedRpcManager pattern.

Provider Priority Order:
1. Ethplorer (Highest) - Uses "freekey" by default, supports ETH, BSC, Linea, Blast
2. NodeReal - Requires API key, supports ETH and BSC
3. Moralis - Requires API key, supports multiple chains
4. Dune Sim - Requires API key, supports multiple EVM chains
5. CoinGecko (Lowest) - Requires API key, supports multiple chains

Features:
- Automatic failover between providers
- Result caching with configurable TTL
- Rate limiting per provider (respects API limits)
- Parallel token collection support
"""

from __future__ import annotations

import asyncio
import logging
import math
import os
import time
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

from scout.cache_manager import HolderDataCache
from scout.coingecko_holder_provider import CoinGeckoHolderProvider
from scout.dune_holder_provider import DuneSimHolderProvider
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

DEFAULT_HOLDER_TIER_SCAN_LIMIT = 5000
DEFAULT_UNCONFIRMED_HOLDER_COUNT_FLOOR = 5000
SHRIMP_THRESHOLD_USD = 10
DEFAULT_NAKAMOTO_THRESHOLD_PCT = 51.0
EXCLUDED_LABEL_KEYWORDS = (
    "lp",
    "liquidity",
    "pool",
    "staking",
    "stake",
    "vesting",
    "bridge",
    "treasury",
    "exchange",
    "cex",
)
BURN_OR_DEAD_ADDRESSES = {
    "0x0000000000000000000000000000000000000000",
    "0x000000000000000000000000000000000000dead",
    "0x0000000000000000000000000000000000000001",
}

class HolderAPIManager:
    """Manages multiple holder API providers with automatic failover.

    Similar to UnifiedRpcManager but for holder data APIs. Automatically
    detects available providers from environment variables and provides
    failover when providers fail.

    Provider Priority Order:
    1. Ethplorer (Highest) - Uses "freekey" by default for free tier
    2. NodeReal - Requires NODEREAL_API_KEY
    3. Moralis - Requires MORALIS_API_KEY
    4. Dune Sim - Requires DUNE_SIM_API_KEY
    5. CoinGecko (Lowest) - Requires COINGECKO_API_KEY

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
        self.metadata_cache_ttl = cache_ttl
        self._total_supply_cache: dict[tuple[int, str], tuple[float, int | None]] = {}
        self._decimals_cache: dict[tuple[int, str], tuple[float, int]] = {}
        self._price_cache: dict[tuple[int, str], tuple[float, float | None]] = {}
        self._dexscreener_client = None

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
        - DUNE_SIM_API_KEY: Initialize Dune Sim holder provider
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

        # Dune Sim
        dune_key = (
            os.environ.get("DUNE_SIM_API_KEY")
            or os.environ.get("SIM_DUNE_API_KEY")
            or os.environ.get("DUNE_API_KEY")
        )
        if dune_key:
            try:
                self.providers["DuneSim"] = DuneSimHolderProvider(dune_key)
                LOGGER.info("Initialized Dune Sim holder provider")
            except Exception as e:
                LOGGER.warning(f"Failed to initialize Dune Sim: {e}")

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
                "Alternatively, set NODEREAL_API_KEY, MORALIS_API_KEY, "
                "DUNE_SIM_API_KEY, or COINGECKO_API_KEY"
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
        cache_key = (chain_id, token_address.lower())
        cached = self._total_supply_cache.get(cache_key)
        now = time.monotonic()
        if cached and now - cached[0] < self.metadata_cache_ttl:
            return cached[1]

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
                self._total_supply_cache[cache_key] = (now, total_supply)
                return total_supply

        except Exception as e:
            LOGGER.error(f"Failed to get totalSupply for {token_address}: {e}")
        finally:
            # Clean up RPC manager to avoid unclosed session warnings
            if rpc_mgr:
                await rpc_mgr.close()

        self._total_supply_cache[cache_key] = (now, None)
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
        cache_key = (chain_id, token_address.lower())
        cached = self._decimals_cache.get(cache_key)
        now = time.monotonic()
        if cached and now - cached[0] < self.metadata_cache_ttl:
            return cached[1]

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
                self._decimals_cache[cache_key] = (now, decimals)
                return decimals

        except Exception as e:
            LOGGER.warning(f"Failed to get decimals for {token_address}: {e}, defaulting to 18")
        finally:
            if rpc_mgr:
                await rpc_mgr.close()

        self._decimals_cache[cache_key] = (now, 18)
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
                    tier_holders, forced_remaining_tier, tier_metadata = await self._get_holder_tier_sample(
                        token_address=token_address,
                        chain_id=chain_id,
                        current_provider=None,
                        known_holders=cached_holders,
                        total_count=final_holder_count,
                        price_usd=price_usd,
                        decimals=decimals,
                    )
                    metrics_dict = self._calculate_metrics(
                        cached_holders,
                        final_holder_count,
                        total_supply,
                        price_usd=price_usd,
                        decimals=decimals,
                        tier_holders=tier_holders,
                        forced_remaining_tier=forced_remaining_tier,
                        tier_metadata=tier_metadata,
                    )
                    LOGGER.info(
                        f"Cache hit for {token_address[:10]}... on chain {chain_id} "
                        f"(holders: {len(cached_holders)}, count: {cached_count})"
                    )
                    return HolderMetrics(
                        total_holder_count=final_holder_count,
                        top_holders=cached_holders,
                        holder_count_confirmed=True,
                        **metrics_dict
                    )

        exclude_failed: List[str] = []
        max_retries = len(self.providers)

        for _attempt in range(max_retries):
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
                    if holder_count is None:
                        holder_count = await self._fetch_holder_count_from_other_providers(
                            token_address,
                            chain_id,
                            exclude_provider=provider.provider_name,
                        )
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
                    holder_count_confirmed = holder_count is not None
                    final_holder_count = (
                        holder_count
                        if holder_count_confirmed
                        else self._estimate_unconfirmed_holder_count(len(top_holders), limit)
                    )

                    if holder_count is None:
                        LOGGER.warning(
                            "Holder count API returned None; using conservative estimated count "
                            f"({final_holder_count}) instead of treating the {len(top_holders)}-holder "
                            "sample as the full population"
                        )
                    else:
                        LOGGER.info(f"Using holder count from API: {holder_count}")

                    # Calculate metrics with real total supply
                    decimals = await self.get_token_decimals(token_address, chain_id)
                    price_usd = await self._fetch_price_usd(token_address, chain_id)
                    tier_holders, forced_remaining_tier, tier_metadata = await self._get_holder_tier_sample(
                        token_address=token_address,
                        chain_id=chain_id,
                        current_provider=provider,
                        known_holders=top_holders,
                        total_count=final_holder_count,
                        price_usd=price_usd,
                        decimals=decimals,
                    )
                    metrics_dict = self._calculate_metrics(
                        top_holders,
                        final_holder_count,
                        total_supply,
                        price_usd=price_usd,
                        decimals=decimals,
                        tier_holders=tier_holders,
                        forced_remaining_tier=forced_remaining_tier,
                        tier_metadata=tier_metadata,
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
                        holder_count_confirmed=holder_count_confirmed,
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

    async def _fetch_holder_count_from_other_providers(
        self,
        token_address: str,
        chain_id: int,
        exclude_provider: str,
    ) -> Optional[int]:
        """Try non-current providers for a confirmed holder count.

        Some providers can return top holders but not a total count for a token.
        A confirmed count from another provider is still better than treating a
        top-100 sample as the entire holder population.
        """
        for candidate in self._tier_scan_providers(None, chain_id):
            if candidate.provider_name == exclude_provider:
                continue
            try:
                if self.enable_rate_limiting and candidate.provider_name in self.rate_limiters:
                    await self.rate_limiters[candidate.provider_name].acquire_or_wait(
                        candidate.provider_name,
                    )
                count = await candidate.get_holder_count(token_address, chain_id)
            except Exception as e:
                LOGGER.debug(
                    "Holder count fallback failed with %s for %s: %s",
                    candidate.provider_name,
                    token_address[:10],
                    e,
                )
                continue
            if count is not None and count > 0:
                LOGGER.info(
                    "Using holder count from fallback provider %s: %s",
                    candidate.provider_name,
                    count,
                )
                return int(count)
        return None

    def _estimate_unconfirmed_holder_count(self, sample_size: int, requested_limit: int) -> int:
        """Return a conservative count when no provider confirms total holders."""
        if sample_size <= 0:
            return 0
        if sample_size < requested_limit:
            return sample_size

        raw_floor = os.environ.get("HOLDER_TIER_UNCONFIRMED_COUNT_FLOOR")
        try:
            configured_floor = int(raw_floor) if raw_floor else DEFAULT_UNCONFIRMED_HOLDER_COUNT_FLOOR
        except (TypeError, ValueError):
            configured_floor = DEFAULT_UNCONFIRMED_HOLDER_COUNT_FLOOR

        return max(sample_size + 1, configured_floor)

    async def _fetch_price_usd(
        self, token_address: str, chain_id: int,
    ) -> Optional[float]:
        """Fetch current token price from DexScreener for tier classification."""
        cache_key = (chain_id, token_address.lower())
        cached = self._price_cache.get(cache_key)
        now = time.monotonic()
        if cached and now - cached[0] < self.metadata_cache_ttl:
            return cached[1]

        try:
            from scout.dexscreener_client import DexScreenerClient

            if self._dexscreener_client is None:
                self._dexscreener_client = DexScreenerClient()

            chain_map = {
                1: "ethereum",
                10: "optimism",
                56: "bsc",
                137: "polygon",
                8453: "base",
                42161: "arbitrum",
                43114: "avalanche",
                59144: "linea",
            }
            chain_str = chain_map.get(chain_id, str(chain_id))
            pairs = await self._dexscreener_client.get_token_pairs(
                chain_str, token_address, fetch_detailed=False,
            )
            price = None
            if pairs and pairs[0].price_usd:
                price = float(pairs[0].price_usd)
            if price:
                LOGGER.info(f"DexScreener price for {token_address[:10]}...: ${price}")
            self._price_cache[cache_key] = (now, price)
            return price
        except Exception as e:
            LOGGER.warning(f"Failed to fetch price for tier classification: {e}")
            self._price_cache[cache_key] = (now, None)
            return None

    async def _get_holder_tier_sample(
        self,
        token_address: str,
        chain_id: int,
        current_provider: Optional[HolderAPIProvider],
        known_holders: List[HolderData],
        total_count: int,
        price_usd: Optional[float],
        decimals: int,
    ) -> Tuple[List[HolderData], Optional[str], Dict[str, int | str | bool | None]]:
        """Fetch a deeper sorted holder sample for tier estimation.

        Holder APIs return balances sorted descending.  Once the lowest fetched
        holder is below the shrimp threshold, every holder after that page is
        also shrimp, so the remaining count can be assigned without fetching
        every holder.
        """
        metadata: Dict[str, int | str | bool | None] = {
            "holder_tier_estimation_method": "exact"
            if total_count <= len(known_holders)
            else "hybrid_model",
            "holder_tier_sample_size": len(known_holders),
            "holder_tier_total_count": total_count,
            "holder_tier_tail_forced": False,
        }

        if not price_usd or price_usd <= 0 or total_count <= len(known_holders):
            return known_holders, None, metadata

        scan_limit = self._holder_tier_scan_limit(total_count)
        if scan_limit <= len(known_holders):
            return known_holders, None, metadata

        try:
            decimals_int = int(decimals)
        except (TypeError, ValueError):
            decimals_int = 18
        decimals_divisor = 10 ** max(decimals_int, 0)
        shrimp_balance_threshold = (SHRIMP_THRESHOLD_USD / price_usd) * decimals_divisor

        best_holders = known_holders
        providers = self._tier_scan_providers(current_provider, chain_id)
        metadata["holder_tier_estimation_method"] = "threshold_scan"

        for provider in providers:
            try:
                if self.enable_rate_limiting and provider.provider_name in self.rate_limiters:
                    await self.rate_limiters[provider.provider_name].acquire_or_wait(
                        provider.provider_name,
                    )

                scanned_holders = await provider.get_top_holders(
                    token_address,
                    chain_id,
                    scan_limit,
                )
            except Exception as e:
                LOGGER.warning(
                    "Tier holder scan failed with %s for %s: %s",
                    provider.provider_name,
                    token_address[:10],
                    e,
                )
                continue

            if len(scanned_holders) <= len(best_holders):
                continue

            best_holders = scanned_holders
            last_balance = scanned_holders[-1].balance if scanned_holders else 0
            metadata["holder_tier_sample_size"] = len(scanned_holders)
            metadata["holder_tier_scan_provider"] = provider.provider_name
            LOGGER.info(
                "Tier holder scan with %s fetched %d/%d holders for %s",
                provider.provider_name,
                len(scanned_holders),
                total_count,
                token_address[:10],
            )

            if len(scanned_holders) >= total_count:
                metadata["holder_tier_estimation_method"] = "exact"
                return best_holders, None, metadata
            if last_balance < shrimp_balance_threshold:
                metadata["holder_tier_tail_forced"] = True
                return best_holders, "SHRIMP", metadata

        if len(best_holders) == len(known_holders):
            metadata["holder_tier_estimation_method"] = "hybrid_model"
        return best_holders, None, metadata

    def _holder_tier_scan_limit(self, total_count: int) -> int:
        """Return the max number of sorted holders to scan for tier estimation."""
        raw_limit = os.environ.get("HOLDER_TIER_SCAN_LIMIT")
        try:
            configured_limit = int(raw_limit) if raw_limit else DEFAULT_HOLDER_TIER_SCAN_LIMIT
        except (TypeError, ValueError):
            configured_limit = DEFAULT_HOLDER_TIER_SCAN_LIMIT
        return max(0, min(total_count, configured_limit))

    def _tier_scan_providers(
        self,
        current_provider: Optional[HolderAPIProvider],
        chain_id: int,
    ) -> List[HolderAPIProvider]:
        """Return providers to try for deep tier scans, preserving priority."""
        providers: List[HolderAPIProvider] = []
        seen = set()

        if current_provider and chain_id in current_provider.supported_chains:
            providers.append(current_provider)
            seen.add(current_provider.provider_name)

        for provider in self.providers.values():
            if provider.provider_name in seen:
                continue
            if chain_id not in provider.supported_chains:
                continue
            providers.append(provider)
            seen.add(provider.provider_name)

        return providers

    def _calculate_metrics(
        self,
        holders: List[HolderData],
        total_count: int,
        total_supply: Optional[int] = None,
        price_usd: Optional[float] = None,
        decimals: int = 18,
        tier_holders: Optional[List[HolderData]] = None,
        forced_remaining_tier: Optional[str] = None,
        tier_metadata: Optional[Dict[str, int | str | bool | None]] = None,
    ) -> Dict:
        """Calculate distribution metrics from holder data.

        Burn/dead addresses and labeled operational wallets are excluded from
        gini/nakamoto calculations and their known balances are subtracted
        from the effective supply.

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

        # Exclude burn/dead addresses and known operational wallets from
        # concentration metrics when labels are available on holder objects.
        excluded_balance = 0
        excluded_count = 0
        filtered_holders = []
        for h in holders:
            if self._should_exclude_holder_from_concentration(h):
                excluded_balance += h.balance
                excluded_count += 1
                LOGGER.info(
                    "Excluding holder from concentration metrics: address=%s balance=%s",
                    h.address,
                    h.balance,
                )
            else:
                filtered_holders.append(h)

        tier_filtered_holders = []
        for h in tier_holders or filtered_holders:
            if not self._should_exclude_holder_from_concentration(h):
                tier_filtered_holders.append(h)

        balances = [h.balance for h in filtered_holders]
        top_100_sum = sum(balances)

        # Subtract known excluded supply.
        if total_supply is not None:
            effective_supply = total_supply - excluded_balance
            LOGGER.info(
                "Adjusted total supply for excluded wallets: %s - %s = %s",
                total_supply,
                excluded_balance,
                effective_supply,
            )
            estimated_total_supply = max(effective_supply, 0)
        elif excluded_balance > 0:
            estimated_total_supply = max(top_100_sum * 2 - excluded_balance, 0)
            LOGGER.debug("Using estimated supply adjusted for excluded wallets")
        else:
            estimated_total_supply = top_100_sum * 2
            LOGGER.debug("Using estimated total supply (top_100_sum * 2)")

        # Convert to hex strings for TEXT storage in database
        top_100_sum_hex = f"0x{top_100_sum:x}"
        estimated_total_supply_hex = f"0x{estimated_total_supply:x}"

        effective_count = max(total_count - excluded_count, 1)
        distribution_groups = self._estimate_full_distribution_groups(
            known_holders=tier_filtered_holders,
            total_count=effective_count,
            total_supply=estimated_total_supply,
            price_usd=price_usd,
            decimals=decimals,
            forced_remaining_tier=forced_remaining_tier,
        )
        if not distribution_groups:
            distribution_groups = [(balance, 1) for balance in balances if balance > 0]

        # Gini coefficient over exact known balances plus estimated full tail.
        gini = self._calculate_weighted_gini(distribution_groups)

        nakamoto_threshold_pct = self._nakamoto_threshold_pct()
        nakamoto = self._calculate_weighted_nakamoto(
            distribution_groups,
            estimated_total_supply,
            threshold_pct=nakamoto_threshold_pct,
        )

        top_10_n = max(1, effective_count // 10) if effective_count > 0 else 10
        top_1_n = max(1, effective_count // 100) if effective_count > 0 else 1

        top_10_sum = self._sum_top_weighted_balances(distribution_groups, top_10_n)
        top_1_sum = self._sum_top_weighted_balances(distribution_groups, top_1_n)

        top_10_pct = (top_10_sum / estimated_total_supply * 100) if estimated_total_supply > 0 else 0
        top_1_pct = (top_1_sum / estimated_total_supply * 100) if estimated_total_supply > 0 else 0
        excluded_supply_pct = (
            excluded_balance / total_supply * 100
            if total_supply and total_supply > 0
            else 0.0
        )

        tier_metadata = tier_metadata or {}
        return {
            "gini_coefficient": round(max(0, min(1, gini)), 4),
            "nakamoto_coefficient": nakamoto,
            "top_10_pct_supply": round(top_10_pct, 3),
            "top_1_pct_supply": round(top_1_pct, 3),
            "top_100_balance_sum": top_100_sum_hex,
            "estimated_total_supply": estimated_total_supply_hex,
            "holder_tiers": self._calculate_holder_tiers(
                tier_filtered_holders, effective_count, estimated_total_supply, price_usd,
                decimals=decimals, forced_remaining_tier=forced_remaining_tier,
            ) if price_usd and price_usd > 0 else None,
            "price_usd": price_usd,
            "holder_tier_estimation_method": tier_metadata.get("holder_tier_estimation_method"),
            "holder_tier_sample_size": tier_metadata.get("holder_tier_sample_size"),
            "holder_tier_total_count": tier_metadata.get("holder_tier_total_count"),
            "nakamoto_threshold_pct": nakamoto_threshold_pct,
            "excluded_holder_count": excluded_count,
            "excluded_supply": excluded_balance,
            "excluded_supply_pct": round(excluded_supply_pct, 3),
        }

    def _nakamoto_threshold_pct(self) -> float:
        """Return configured Nakamoto supply threshold percentage."""
        raw_threshold = os.environ.get("NAKAMOTO_SUPPLY_THRESHOLD_PCT")
        try:
            threshold = float(raw_threshold) if raw_threshold else DEFAULT_NAKAMOTO_THRESHOLD_PCT
        except (TypeError, ValueError):
            threshold = DEFAULT_NAKAMOTO_THRESHOLD_PCT
        return max(0.01, min(100.0, threshold))

    def _should_exclude_holder_from_concentration(self, holder: HolderData) -> bool:
        """Exclude burn/dead and known operational wallets from concentration metrics."""
        address = (holder.address or "").lower()
        if address in BURN_OR_DEAD_ADDRESSES:
            return True

        label_parts: List[str] = []
        for attr in ("label", "category", "holder_type", "name"):
            value = getattr(holder, attr, None)
            if isinstance(value, str) and value.strip():
                label_parts.append(value.strip().lower())
        tags = getattr(holder, "tags", None)
        if isinstance(tags, list):
            for tag in tags:
                if isinstance(tag, str):
                    label_parts.append(tag.lower())
                elif isinstance(tag, dict):
                    label_parts.extend(
                        str(value).lower()
                        for value in tag.values()
                        if isinstance(value, str)
                    )

        label = " ".join(label_parts)
        if not label:
            return False

        return any(keyword in label for keyword in EXCLUDED_LABEL_KEYWORDS)

    def _estimate_full_distribution_groups(
        self,
        known_holders: List[HolderData],
        total_count: int,
        total_supply: int,
        price_usd: Optional[float],
        decimals: int,
        forced_remaining_tier: Optional[str] = None,
    ) -> List[Tuple[int, int]]:
        """Build exact known balances plus weighted synthetic tail groups."""
        groups: List[Tuple[int, int]] = [
            (max(0, h.balance), 1)
            for h in known_holders
            if h.balance > 0
        ]
        known_supply = sum(balance for balance, _ in groups)
        known_count = len(groups)
        if total_count <= known_count:
            return groups[:total_count]
        if total_count <= 0 or total_supply <= 0:
            return groups

        remaining_count = total_count - known_count
        remaining_supply = max(total_supply - known_supply, 0)
        if remaining_count <= 0:
            return groups
        if remaining_supply <= 0:
            return groups

        if not price_usd or price_usd <= 0 or not math.isfinite(price_usd):
            avg_balance = remaining_supply // remaining_count
            groups.append((avg_balance, remaining_count))
            return groups

        try:
            decimals = int(decimals)
        except (TypeError, ValueError):
            decimals = 18
        decimals_divisor = 10 ** max(decimals, 0)

        unseen_upper_balance = min(
            (known_holders[-1].balance if known_holders else remaining_supply),
            remaining_supply,
        )

        if forced_remaining_tier:
            target_bucket = next(
                (b for b in HOLDER_TIER_THRESHOLDS if b["tier"] == forced_remaining_tier),
                HOLDER_TIER_THRESHOLDS[-1],
            )
            max_balance = self._tier_max_balance(
                target_bucket,
                price_usd,
                decimals_divisor,
                unseen_upper_balance,
            )
            groups.extend(
                self._bounded_even_balance_groups(
                    remaining_supply,
                    remaining_count,
                    max_balance,
                )
            )
            return groups

        avg_balance = remaining_supply / remaining_count
        avg_usd = (avg_balance / decimals_divisor) * price_usd
        if avg_usd <= 0:
            groups.append((remaining_supply // remaining_count, remaining_count))
            return groups

        alpha = 1.5
        xm = avg_usd * (alpha - 1) / alpha
        per_tier_frac = []
        for i, bucket in enumerate(HOLDER_TIER_THRESHOLDS):
            lower = bucket["min_usd"]
            upper = HOLDER_TIER_THRESHOLDS[i - 1]["min_usd"] if i > 0 else float("inf")
            sf_lower = (xm / lower) ** alpha if lower and lower >= xm else 1.0
            sf_upper = (xm / upper) ** alpha if upper >= xm else 1.0
            per_tier_frac.append(max(sf_lower - sf_upper, 0.0))

        total_frac = sum(per_tier_frac)
        if total_frac <= 0:
            avg = remaining_supply // remaining_count
            groups.append((avg, remaining_count))
            return groups

        counts = self._allocate_remaining_tier_counts(remaining_count, per_tier_frac, total_frac)
        tier_allocations = [
            (bucket, count)
            for bucket, count in zip(HOLDER_TIER_THRESHOLDS, counts)
            if count > 0
        ]
        representative_weights = [
            self._tier_max_balance(bucket, price_usd, decimals_divisor, unseen_upper_balance) * count
            for bucket, count in tier_allocations
        ]
        total_weight = sum(representative_weights)

        tail_groups: List[Tuple[int, int]] = []
        allocated_supply = 0
        for index, ((bucket, count), weight) in enumerate(zip(tier_allocations, representative_weights)):
            if count <= 0:
                continue
            if total_weight > 0 and index < len(tier_allocations) - 1:
                tier_supply = int(remaining_supply * weight / total_weight)
                allocated_supply += tier_supply
            else:
                tier_supply = max(remaining_supply - allocated_supply, 0)
            max_balance = self._tier_max_balance(
                bucket,
                price_usd,
                decimals_divisor,
                unseen_upper_balance,
            )
            tail_groups.extend(
                self._bounded_even_balance_groups(tier_supply, count, max_balance)
            )

        groups.extend(tail_groups)
        return groups

    def _tier_max_balance(
        self,
        bucket: Dict,
        price_usd: float,
        decimals_divisor: int,
        upper_balance_cap: Optional[int] = None,
    ) -> int:
        """Return the maximum plausible raw balance for an unseen holder tier.

        Exact fetched holders are kept as-is.  For unseen holders, estimate the
        tier range using the largest value in that tier:
        - Shark max: $100K
        - Dolphin max: $10K
        - Fish max: $1K
        - Crab max: $100
        - Shrimp max: $10

        Whale is unbounded, so unseen whales are capped by the last fetched
        holder balance.  All unseen tiers are also capped by that last fetched
        holder balance because holder API pages are sorted descending.
        """
        if price_usd <= 0 or decimals_divisor <= 0:
            return 0

        bucket_index = next(
            (
                index
                for index, threshold in enumerate(HOLDER_TIER_THRESHOLDS)
                if threshold["tier"] == bucket["tier"]
            ),
            0,
        )
        if bucket_index == 0:
            raw_balance = upper_balance_cap or int((bucket["min_usd"] / price_usd) * decimals_divisor)
        else:
            upper_usd = HOLDER_TIER_THRESHOLDS[bucket_index - 1]["min_usd"]
            raw_balance = int((upper_usd / price_usd) * decimals_divisor)

        raw_balance = max(1, raw_balance)
        if upper_balance_cap and upper_balance_cap > 0:
            raw_balance = min(raw_balance, upper_balance_cap)
        return raw_balance

    def _tier_representative_balance(
        self,
        bucket: Dict,
        price_usd: float,
        decimals_divisor: int,
    ) -> int:
        """Return a representative raw balance for a USD tier."""
        min_usd = bucket["min_usd"]
        if bucket["tier"] == "WHALE":
            representative_usd = min_usd * 2
        elif bucket["tier"] == "SHRIMP":
            representative_usd = 5
        else:
            bucket_index = next(
                (
                    index
                    for index, threshold in enumerate(HOLDER_TIER_THRESHOLDS)
                    if threshold["tier"] == bucket["tier"]
                ),
                0,
            )
            upper_usd = HOLDER_TIER_THRESHOLDS[bucket_index - 1]["min_usd"]
            representative_usd = (min_usd + upper_usd) / 2

        return max(1, int((representative_usd / price_usd) * decimals_divisor))

    def _even_balance_groups(self, supply: int, count: int) -> List[Tuple[int, int]]:
        """Represent a supply split across holders without creating one fake giant holder."""
        if count <= 0 or supply <= 0:
            return []

        base = supply // count
        remainder = supply - (base * count)
        groups: List[Tuple[int, int]] = []
        if remainder > 0:
            groups.append((base + 1, remainder))
        if count - remainder > 0 and base > 0:
            groups.append((base, count - remainder))
        return groups

    def _bounded_even_balance_groups(
        self,
        supply: int,
        count: int,
        max_balance: int,
    ) -> List[Tuple[int, int]]:
        """Split supply across holders while respecting a per-holder max.

        If the tier-count upper bound cannot absorb the allocated supply, put
        every holder in that tier at the max.  The remaining supply is handled
        by later tiers or ignored if no tier can plausibly absorb it, preventing
        creation of a single fake whale.
        """
        if count <= 0 or supply <= 0 or max_balance <= 0:
            return []

        max_supply = max_balance * count
        capped_supply = min(supply, max_supply)
        return self._even_balance_groups(capped_supply, count)

    def _synthetic_balance_groups_for_tier(
        self,
        bucket: Dict,
        count: int,
        supply: int,
        price_usd: float,
        decimals_divisor: int,
    ) -> List[Tuple[int, int]]:
        """Create weighted synthetic holder balance groups for a tier."""
        if count <= 0:
            return []
        if supply <= 0:
            return []

        min_usd = bucket["min_usd"]
        if bucket["tier"] == "WHALE":
            representative_usd = max(min_usd, (supply / count / decimals_divisor) * price_usd)
        elif bucket["tier"] == "SHRIMP":
            representative_usd = 5
        else:
            next_min = HOLDER_TIER_THRESHOLDS[
                HOLDER_TIER_THRESHOLDS.index(bucket) - 1
            ]["min_usd"]
            representative_usd = (min_usd + next_min) / 2

        representative_balance = max(1, int((representative_usd / price_usd) * decimals_divisor))
        balance = min(representative_balance, max(1, supply // count))
        allocated = balance * count
        if allocated >= supply:
            return [(balance, count)]

        # Preserve the full supply without assigning the entire residual to a
        # single synthetic holder.  A one-holder residual was enough to create a
        # fake whale and corrupt Gini/Nakamoto for large holder populations.
        return self._even_balance_groups(supply, count)

    def _calculate_weighted_gini(self, balance_groups: List[Tuple[int, int]]) -> float:
        """Calculate Gini coefficient from weighted balance groups."""
        groups = [(balance, count) for balance, count in balance_groups if count > 0 and balance >= 0]
        if not groups:
            return 0.0

        n = sum(count for _, count in groups)
        total = sum(balance * count for balance, count in groups)
        if n <= 0 or total <= 0:
            return 0.0

        weighted_sum = 0.0
        seen = 0
        for balance, count in sorted(groups, key=lambda item: item[0]):
            index_sum = count * (2 * seen + count + 1) / 2
            weighted_sum += balance * index_sum
            seen += count

        gini = (2 * weighted_sum) / (n * total) - (n + 1) / n
        return max(0.0, min(1.0, gini))

    def _calculate_weighted_nakamoto(
        self,
        balance_groups: List[Tuple[int, int]],
        total: int,
        threshold_pct: float,
    ) -> int:
        """Calculate Nakamoto coefficient from weighted balance groups."""
        if total <= 0:
            return 0

        target = total * (threshold_pct / 100)
        cumulative = 0
        holders = 0
        for balance, count in sorted(balance_groups, key=lambda item: item[0], reverse=True):
            if count <= 0 or balance <= 0:
                continue
            remaining = target - cumulative
            needed = min(count, max(1, math.ceil(remaining / balance)))
            holders += needed
            cumulative += needed * balance
            if cumulative >= target:
                return holders

        return holders

    def _sum_top_weighted_balances(
        self,
        balance_groups: List[Tuple[int, int]],
        limit: int,
    ) -> int:
        """Sum the top N balances from weighted groups."""
        if limit <= 0:
            return 0

        remaining = limit
        total = 0
        for balance, count in sorted(balance_groups, key=lambda item: item[0], reverse=True):
            if remaining <= 0:
                break
            take = min(count, remaining)
            total += balance * take
            remaining -= take
        return total

    def _calculate_holder_tiers(
        self,
        holders: List[HolderData],
        total_count: int,
        total_supply: int,
        price_usd: float,
        decimals: int = 18,
        forced_remaining_tier: Optional[str] = None,
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
        unseen_upper_balance = min(
            holders[-1].balance if holders else remaining_supply,
            remaining_supply,
        )

        if remaining_count > 0 and forced_remaining_tier:
            bucket = next(
                (b for b in buckets if b["tier"] == forced_remaining_tier),
                buckets[-1],
            )
            bucket["holders"] += remaining_count
            if remaining_supply > 0:
                max_balance = self._tier_max_balance(
                    bucket,
                    price_usd,
                    decimals_divisor,
                    unseen_upper_balance,
                )
                bucket["supply"] += min(remaining_supply, max_balance * remaining_count)
        elif remaining_count > 0:
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
                    tier_capacities = [
                        self._tier_max_balance(
                            bucket,
                            price_usd,
                            decimals_divisor,
                            unseen_upper_balance,
                        ) * count
                        if count > 0
                        else 0
                        for bucket, count in zip(buckets, counts)
                    ]
                    total_capacity = sum(tier_capacities)
                    allocated_supply = 0
                    for i, bucket in enumerate(buckets):
                        count = counts[i]
                        if count > 0:
                            bucket["holders"] += count
                            if remaining_supply <= 0 or total_capacity <= 0:
                                continue
                            if i < len(buckets) - 1:
                                tier_supply = int(remaining_supply * tier_capacities[i] / total_capacity)
                                allocated_supply += tier_supply
                            else:
                                tier_supply = max(remaining_supply - allocated_supply, 0)
                            bucket["supply"] += min(tier_supply, tier_capacities[i])

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

    def _calculate_nakamoto(
        self,
        balances: List[int],
        total: int,
        threshold_pct: float = DEFAULT_NAKAMOTO_THRESHOLD_PCT,
    ) -> int:
        """Calculate Nakamoto coefficient.

        The Nakamoto coefficient is the minimum number of holders needed
        to control the configured percentage of supply.

        Args:
            balances: List of balances sorted by size (descending)
            total: Effective supply after exclusions
            threshold_pct: Supply threshold percentage

        Returns:
            Number of holders needed for threshold control
        """
        if total == 0:
            return 0

        target = total * (threshold_pct / 100)
        cumulative = 0
        for i, balance in enumerate(sorted(balances, reverse=True)):
            cumulative += balance
            if cumulative >= target:
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
        results: dict[tuple[str, int], HolderMetrics | None] = {}
        semaphore = asyncio.Semaphore(max(1, max_concurrency))

        async def fetch_one(
            token_address: str,
            chain_id: int,
        ) -> tuple[tuple[str, int], HolderMetrics | None]:
            async with semaphore:
                try:
                    metrics = await self.get_holder_data(
                        token_address=token_address,
                        chain_id=chain_id,
                        limit=limit,
                        bypass_cache=bypass_cache,
                    )
                    status = "SUCCESS" if metrics else "FAILED"
                    LOGGER.info(
                        f"Completed {token_address[:10]}... on chain {chain_id}: {status}"
                    )
                    return (token_address, chain_id), metrics
                except Exception as e:
                    LOGGER.error(f"Failed to fetch data for {token_address[:10]}... on chain {chain_id}: {e}")
                    return (token_address, chain_id), None

        LOGGER.info(
            "Fetching holder data for %d tokens with max_concurrency=%d",
            len(tokens),
            max_concurrency,
        )
        completed = await asyncio.gather(
            *(fetch_one(token_address, chain_id) for token_address, chain_id in tokens),
            return_exceptions=False,
        )
        for key, metrics in completed:
            results[key] = metrics

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
        if self._dexscreener_client is not None:
            await self._dexscreener_client.close()
            self._dexscreener_client = None


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
