"""DexScreener API client for liquidity analysis."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import aiohttp

LOGGER = logging.getLogger(__name__)

DEXSCREENER_BASE_URL = "https://api.dexscreener.com"


@dataclass
class DexPair:
    """DEX pair data from DexScreener."""

    chain_id: str
    dex_id: str
    pair_address: str
    token0_address: str
    token0_symbol: str
    token1_address: str
    token1_symbol: str
    liquidity_usd: float
    token0_reserves: float
    token1_reserves: float
    fdv_usd: float
    pair_created_at: int
    volume_h24: float
    volume_h24_change: float
    txns_h24_buys: int
    txns_h24_sells: int
    price_usd: Optional[float]
    price_change_m5: float
    price_change_h24: float

    # Additional fields from detailed pair endpoint
    fee_tier: Optional[str] = None
    tick_spacing: Optional[int] = None
    # For Uniswap v3 concentrated liquidity
    tick_range_lower: Optional[int] = None
    tick_range_upper: Optional[int] = None
    current_tick: Optional[int] = None


@dataclass
class LiquidityMetrics:
    """Comprehensive liquidity metrics for a token."""

    token_address: str
    chain_id: str

    # Overall liquidity
    total_tvl_usd: float
    total_pairs: int
    unique_dexes: int

    # Pool variety
    largest_pool_tvl_pct: float  # Concentration risk
    dex_diversity_score: float  # 0-1, higher = more diverse

    # TVL tiers
    tvl_tier: str  # "very_low" (<$100k), "low" (<$1M), "medium" (<$10M), "high" (>=$10M)

    # Balance analysis
    average_pool_balance_score: float  # 0-1, 1 = perfectly balanced
    imbalanced_pools_count: int

    # Activity
    total_volume_h24: float
    total_txns_h24: int

    # Risk flags
    flags: List[str]  # ["low_tvl", "concentrated", "low_activity", ...]

    # Cross-chain (if applicable)
    chains_with_liquidity: List[str]

    # Timestamps
    analyzed_at: str


class DexScreenerClient:
    """Async client for DexScreener API with multi-step data fetching."""

    BASE_URL = "https://api.dexscreener.com"
    RATE_LIMIT_RPM = 300  # Free tier: ~300 requests/minute

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout
        self._session: Optional[aiohttp.ClientSession] = None
        self._session_loop_id: Optional[int] = None
        # Rate limiting: max 300 requests per minute = 5 per second
        # We'll use a simple semaphore to limit concurrent requests
        self._rate_limiter = asyncio.Semaphore(5)

    async def _get_session(self) -> aiohttp.ClientSession:
        loop_id = id(asyncio.get_event_loop())
        if self._session is None or self._session_loop_id != loop_id:
            if self._session is not None:
                try:
                    await self._session.close()
                except Exception:
                    pass
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self._session = aiohttp.ClientSession(timeout=timeout)
            self._session_loop_id = loop_id
        return self._session

    async def get_token_pairs(
        self,
        chain_id: str,
        token_address: str,
        fetch_detailed: bool = True,
    ) -> List[DexPair]:
        """Get all trading pairs for a token using the 3-step API flow.

        Step 1: GET /tokens/v1/{chainId}/{tokenAddress} - Get available listings
        Step 2: GET /token-pairs/v1/{chainId}/{tokenAddress} - Get detailed pair info
        Step 3: GET /latest/dex/pairs/{chainId}/{pairId} - Get individual pair details

        Args:
            chain_id: Chain ID (e.g., "ethereum", "bsc", "polygon")
            token_address: Token contract address
            fetch_detailed: If True, fetch detailed info for each pair (Step 3)

        Returns:
            List of DexPair objects
        """
        # Step 1: Get available listings (returns pair addresses)
        listings = await self._get_token_listings(chain_id, token_address)

        if not listings:
            LOGGER.warning(f"No listings found for {token_address} on {chain_id}")
            return []

        # Step 2: Get detailed pair info for all pairs
        detailed_pairs = await self._get_detailed_pairs(chain_id, token_address)

        if not detailed_pairs:
            LOGGER.warning(f"No detailed pairs found for {token_address} on {chain_id}")
            return []

        # Step 3: Get individual pair details (optional, for more granular data)
        if fetch_detailed and detailed_pairs:
            LOGGER.debug(f"Step 3: Fetching individual pair details for {len(detailed_pairs)} pairs")
            enriched_pairs = await self._get_individual_pair_details(chain_id, detailed_pairs)
            LOGGER.debug(f"Step 3 complete: Enriched {len(enriched_pairs)} pairs")
            return enriched_pairs

        return detailed_pairs

    async def _get_token_listings(
        self,
        chain_id: str,
        token_address: str,
    ) -> List[Dict[str, Any]]:
        """Step 1: Get available listings (pair addresses) for a token.

        GET /tokens/v1/{chainId}/{tokenAddress}

        Args:
            chain_id: Chain ID
            token_address: Token contract address

        Returns:
            List of pair data dicts (minimal info)
        """
        session = await self._get_session()
        url = f"{self.BASE_URL}/tokens/v1/{chain_id}/{token_address}"

        try:
            LOGGER.debug(f"Requesting {url}")
            async with session.get(url) as response:
                response.raise_for_status()
                data = await response.json()
                LOGGER.debug(f"Got response of type {type(data).__name__}")

                # API can return either a list directly or a dict with "pairs" key
                if isinstance(data, list):
                    LOGGER.debug(f"Returning list of {len(data)} items")
                    return data
                elif isinstance(data, dict):
                    result = data.get("pairs", [])
                    LOGGER.debug(f"Returning dict with {len(result)} pairs")
                    return result
                else:
                    LOGGER.warning(f"Unexpected response type from token listings API: {type(data)}")
                    return []

        except Exception as e:
            LOGGER.error(f"Failed to fetch token listings for {token_address}: {e}")
            return []

    async def _get_detailed_pairs(
        self,
        chain_id: str,
        token_address: str,
    ) -> List[DexPair]:
        """Step 2: Get detailed pair info for all pairs of a token.

        GET /token-pairs/v1/{chainId}/{tokenAddress}

        Args:
            chain_id: Chain ID
            token_address: Token contract address

        Returns:
            List of DexPair objects
        """
        session = await self._get_session()
        url = f"{self.BASE_URL}/token-pairs/v1/{chain_id}/{token_address}"

        try:
            LOGGER.debug(f"Requesting {url}")
            async with session.get(url) as response:
                response.raise_for_status()
                data = await response.json()
                LOGGER.debug(f"Got response of type {type(data).__name__}")

                pairs = []

                # API can return either a list directly or a dict with "pairs" key
                if isinstance(data, list):
                    LOGGER.debug(f"Parsing {len(data)} pairs from list")
                    for pair_data in data:
                        pairs.append(self._parse_pair(pair_data))
                elif isinstance(data, dict):
                    pair_list = data.get("pairs", [])
                    LOGGER.debug(f"Parsing {len(pair_list)} pairs from dict")
                    for pair_data in pair_list:
                        pairs.append(self._parse_pair(pair_data))
                else:
                    LOGGER.warning(f"Unexpected response type from detailed pairs API: {type(data)}")

                LOGGER.debug(f"Returning {len(pairs)} parsed pairs")
                return pairs

        except Exception as e:
            LOGGER.error(f"Failed to fetch detailed pairs for {token_address}: {e}")
            return []

    async def _get_individual_pair_details(
        self,
        chain_id: str,
        pairs: List[DexPair],
    ) -> List[DexPair]:
        """Step 3: Get individual pair details for enhanced data.

        GET /latest/dex/pairs/{chainId}/{pairId}
        Rate limit: 300 requests per minute

        Args:
            chain_id: Chain ID
            pairs: List of DexPair objects to enrich

        Returns:
            List of DexPair objects with additional details
        """
        if not pairs:
            return pairs

        session = await self._get_session()
        enriched_pairs = []

        # Fetch details concurrently with rate limiting
        async def fetch_one(pair: DexPair) -> Optional[DexPair]:
            url = f"{self.BASE_URL}/latest/dex/pairs/{chain_id}/{pair.pair_address}"

            try:
                async with self._rate_limiter:  # Limit concurrent requests
                    async with session.get(url) as response:
                        if response.status == 200:
                            data = await response.json()
                            if data.get("pairs"):
                                return self._parse_pair(data["pairs"][0], enrich_existing=pair)
            except Exception as e:
                LOGGER.debug(f"Failed to fetch details for pair {pair.pair_address}: {e}")

            return pair  # Return original if enrichment fails

        # Run fetches concurrently
        results = await asyncio.gather(*[fetch_one(pair) for pair in pairs], return_exceptions=False)

        for result in results:
            if result:
                enriched_pairs.append(result)

        return enriched_pairs

    async def get_tokens_info(
        self,
        chain_id: str,
        token_addresses: List[str],
    ) -> List[DexPair]:
        """Get info for multiple tokens.

        Args:
            chain_id: Chain ID
            token_addresses: List of token addresses (comma-separated in URL)

        Returns:
            List of DexPair objects
        """
        session = await self._get_session()
        addresses = ",".join(token_addresses)
        url = f"{self.BASE_URL}/tokens/v1/{chain_id}/{addresses}"

        try:
            async with session.get(url) as response:
                response.raise_for_status()
                data = await response.json()

                pairs = []
                for pair_data in data.get("pairs", []):
                    pairs.append(self._parse_pair(pair_data))

                return pairs

        except Exception as e:
            LOGGER.error(f"Failed to fetch tokens info: {e}")
            return []

    async def search_pairs(
        self,
        query: str,
    ) -> List[DexPair]:
        """Search for token pairs.

        Args:
            query: Search query (token address, symbol, or pair address)

        Returns:
            List of DexPair objects
        """
        session = await self._get_session()
        url = f"{self.BASE_URL}/latest/dex/search"
        params = {"q": query}

        try:
            async with session.get(url, params=params) as response:
                response.raise_for_status()
                data = await response.json()

                pairs = []
                for pair_data in data.get("pairs", []):
                    pairs.append(self._parse_pair(pair_data))

                return pairs

        except Exception as e:
            LOGGER.error(f"Failed to search pairs for {query}: {e}")
            return []

    def _parse_pair(
        self,
        pair_data: Dict[str, Any],
        enrich_existing: Optional[DexPair] = None,
    ) -> DexPair:
        """Parse pair data from API response.

        Args:
            pair_data: Raw pair data from API
            enrich_existing: If provided, enrich this existing DexPair with additional fields

        Returns:
            DexPair object
        """
        # Extract liquidity
        liquidity = pair_data.get("liquidity", {})
        liquidity_usd = liquidity.get("usd", 0)

        # Extract reserves
        reserves = pair_data.get("reserve", pair_data.get("liquidity", {}))
        token0_reserves = float(reserves.get("token0", reserves.get("token0Amount", 0)))
        token1_reserves = float(reserves.get("token1", reserves.get("token1Amount", 0)))

        # Extract volume
        volume = pair_data.get("volume", {})
        volume_h24 = volume.get("h24", 0)

        # Extract transactions
        txns = pair_data.get("txns", {})
        h24 = txns.get("h24", {})
        txns_h24_buys = h24.get("buys", 0)
        txns_h24_sells = h24.get("sells", 0)

        # Extract price change
        price_change = pair_data.get("priceChange", {})
        price_change_m5 = price_change.get("m5", 0)
        price_change_h24 = price_change.get("h24", 0)

        # Extract additional fields for enriched data
        fee_tier = pair_data.get("feeTier")
        tick_spacing = pair_data.get("tickSpacing")

        # Uniswap v3 specific fields
        tick_range_lower = pair_data.get("tickRangeLower")
        tick_range_upper = pair_data.get("tickRangeUpper")
        current_tick = pair_data.get("currentTick")

        if enrich_existing:
            # Enrich existing pair with additional fields
            return DexPair(
                chain_id=enrich_existing.chain_id,
                dex_id=enrich_existing.dex_id,
                pair_address=enrich_existing.pair_address,
                token0_address=enrich_existing.token0_address,
                token0_symbol=enrich_existing.token0_symbol,
                token1_address=enrich_existing.token1_address,
                token1_symbol=enrich_existing.token1_symbol,
                liquidity_usd=enrich_existing.liquidity_usd,
                token0_reserves=enrich_existing.token0_reserves,
                token1_reserves=enrich_existing.token1_reserves,
                fdv_usd=enrich_existing.fdv_usd,
                pair_created_at=enrich_existing.pair_created_at,
                volume_h24=enrich_existing.volume_h24,
                volume_h24_change=enrich_existing.volume_h24_change,
                txns_h24_buys=enrich_existing.txns_h24_buys,
                txns_h24_sells=enrich_existing.txns_h24_sells,
                price_usd=enrich_existing.price_usd,
                price_change_m5=enrich_existing.price_change_m5,
                price_change_h24=enrich_existing.price_change_h24,
                fee_tier=fee_tier,
                tick_spacing=tick_spacing,
                tick_range_lower=tick_range_lower,
                tick_range_upper=tick_range_upper,
                current_tick=current_tick,
            )

        return DexPair(
            chain_id=pair_data.get("chainId", ""),
            dex_id=pair_data.get("dexId", ""),
            pair_address=pair_data.get("pairAddress", ""),
            token0_address=pair_data.get("token0", {}).get("address", ""),
            token0_symbol=pair_data.get("token0", {}).get("symbol", ""),
            token1_address=pair_data.get("token1", {}).get("address", ""),
            token1_symbol=pair_data.get("token1", {}).get("symbol", ""),
            liquidity_usd=liquidity_usd,
            token0_reserves=token0_reserves,
            token1_reserves=token1_reserves,
            fdv_usd=pair_data.get("fdv", 0),
            pair_created_at=pair_data.get("pairCreatedAt", 0),
            volume_h24=volume_h24,
            volume_h24_change=volume.get("h24Change", 0),
            txns_h24_buys=txns_h24_buys,
            txns_h24_sells=txns_h24_sells,
            price_usd=pair_data.get("priceUsd"),
            price_change_m5=price_change_m5,
            price_change_h24=price_change_h24,
            fee_tier=fee_tier,
            tick_spacing=tick_spacing,
            tick_range_lower=tick_range_lower,
            tick_range_upper=tick_range_upper,
            current_tick=current_tick,
        )

    async def close(self) -> None:
        """Close the HTTP session."""
        if self._session:
            await self._session.close()
            self._session = None
