"""CoinGecko holder API provider.

This module provides integration with CoinGecko's Token Holders API endpoints:
- Token Info (FREE): Total holder count + distribution percentages
- Top Token Holders (Analyst+): List of top holders with addresses
- Historical Holders Chart (Analyst+): Time-series holder count data

API Documentation: https://www.coingecko.com/en/documentation
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import aiohttp

from scout.holder_api_providers import HolderAPIProvider, HolderData

LOGGER = logging.getLogger(__name__)


# Chain ID to CoinGecko network ID mapping
CHAIN_ID_TO_COINGECKO_NETWORK = {
    1: "eth",           # Ethereum
    56: "bsc",          # Binance Smart Chain
    137: "polygon-pos", # Polygon
    42161: "arbitrum-one", # Arbitrum
    10: "optimism",     # Optimism
    43114: "avalanche", # Avalanche
    8453: "base",       # Base
    59144: "linea",     # Linea
    100: "xdai",        # Gnosis Chain
    250: "ftm",         # Fantom
    42262: "oasis",     # Oasis
    1284: "moonbeam",   # Moonbeam
    1287: "moonriver",  # Moonriver
    1088: "metis",      # Metis
    5: "goerli",        # Goerli Testnet
    80001: "berachain", # Berachain
}


class CoinGeckoHolderProvider(HolderAPIProvider):
    """CoinGecko holder API provider.

    Uses CoinGecko's Onchain Token Holders API endpoints:
    - /onchain/networks/{network}/tokens/{address}/info: FREE - holder count + distribution
    - /onchain/networks/{network}/tokens/{address}/top_holders: Analyst+ - top holders list
    - /onchain/networks/{network}/tokens/{address}/holders_chart: Analyst+ - historical data

    Supported networks: ETH, BSC, Polygon, Arbitrum, Optimism, Avalanche, Base, and more.
    """

    @property
    def provider_name(self) -> str:
        return "CoinGecko"

    @property
    def supported_chains(self) -> List[int]:
        return list(CHAIN_ID_TO_COINGECKO_NETWORK.keys())

    def __init__(
        self,
        api_key: str,
        **kwargs: Any,
    ) -> None:
        """Initialize CoinGecko provider.

        Args:
            api_key: CoinGecko API Pro key (required)
            **kwargs: Additional arguments passed to base class

        Raises:
            ValueError: If api_key is not provided
        """
        super().__init__(api_key=api_key, **kwargs)
        if not api_key:
            raise ValueError("CoinGecko API key is required")

        self.base_url = "https://pro-api.coingecko.com/api/v3"
        self._cg_session: Optional[aiohttp.ClientSession] = None

    async def _get_cg_session(self) -> aiohttp.ClientSession:
        """Get or create CoinGecko-specific HTTP session."""
        if self._cg_session is None:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            headers = {
                "accept": "application/json",
                "x-cg-pro-api-key": self.api_key,
            }
            self._cg_session = aiohttp.ClientSession(
                timeout=timeout,
                headers=headers
            )
        return self._cg_session

    async def close(self) -> None:
        """Close HTTP sessions."""
        if self._session:
            await self._session.close()
            self._session = None
        if self._cg_session:
            await self._cg_session.close()
            self._cg_session = None

    async def get_holder_count(
        self,
        token_address: str,
        chain_id: int,
    ) -> Optional[int]:
        """Get total holder count using CoinGecko Token Info endpoint (FREE).

        Args:
            token_address: Token contract address
            chain_id: Chain ID

        Returns:
            Total holder count, or None if request fails
        """
        network = CHAIN_ID_TO_COINGECKO_NETWORK.get(chain_id)
        if not network:
            LOGGER.warning(f"Chain {chain_id} not supported by CoinGecko")
            return None

        try:
            session = await self._get_cg_session()
            url = f"{self.base_url}/onchain/networks/{network}/tokens/{token_address}/info"

            async with session.get(url) as response:
                response.raise_for_status()
                data = await response.json()

                LOGGER.info(f"CoinGecko token info response: {data}")

                if "data" in data:
                    attributes = data["data"].get("attributes", {})
                    holders = attributes.get("holders", {})
                    count = holders.get("count")

                    if count is not None:
                        LOGGER.info(f"CoinGecko holder count: {count}")
                        return int(count)
                else:
                    LOGGER.warning(f"CoinGecko token info missing data for {token_address[:10]}...")

        except Exception as e:
            LOGGER.error(f"CoinGecko get_holder_count failed: {e}")

        return None

    async def get_top_holders(
        self,
        token_address: str,
        chain_id: int,
        limit: int = 100,
    ) -> List[HolderData]:
        """Get top N holders using CoinGecko Top Token Holders endpoint (Analyst+).

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            limit: Maximum number of holders to return

        Returns:
            List of holder data, sorted by balance (descending)
        """
        network = CHAIN_ID_TO_COINGECKO_NETWORK.get(chain_id)
        if not network:
            LOGGER.warning(f"Chain {chain_id} not supported by CoinGecko")
            return []

        try:
            session = await self._get_cg_session()
            url = f"{self.base_url}/onchain/networks/{network}/tokens/{token_address}/top_holders"

            params = {"holders": limit}
            async with session.get(url, params=params) as response:
                if response.status == 403:
                    LOGGER.warning(
                        f"CoinGecko top_holders requires Analyst tier or above. "
                        f"Falling back to empty list for {token_address[:10]}..."
                    )
                    return []

                response.raise_for_status()
                data = await response.json()

                LOGGER.info(f"CoinGecko top_holders response keys: {data.keys()}")

                holders = []

                # Parse response based on CoinGecko API structure
                if "data" in data:
                    attributes = data["data"].get("attributes", {})
                    holder_list = attributes.get("holders", [])

                    for holder_data in holder_list:
                        rank = holder_data.get("rank", 0)
                        address = holder_data.get("address", "")
                        amount_str = holder_data.get("amount", "0")
                        percentage_str = holder_data.get("percentage", "0")

                        # Convert amount (usually a string like "1000000.0")
                        # This may need token decimals adjustment - storing as-is for now
                        try:
                            amount_float = float(amount_str)
                            # Store as integer (may need adjustment for token decimals)
                            amount_int = int(amount_float)
                        except (ValueError, TypeError):
                            amount_int = 0

                        holders.append(HolderData(
                            address=address,
                            balance=amount_int,
                            rank=rank,
                        ))

                    LOGGER.info(f"CoinGecko returned {len(holders)} top holders")
                else:
                    LOGGER.warning(f"CoinGecko top_holders missing data for {token_address[:10]}...")

                return holders

        except Exception as e:
            LOGGER.error(f"CoinGecko get_top_holders failed: {e}")

        return []
