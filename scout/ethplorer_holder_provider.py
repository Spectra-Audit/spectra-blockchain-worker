"""Ethplorer holder API provider.

This module provides integration with Ethplorer's Token API endpoints:
- getTokenInfo: Returns token details including holder count
- getTopTokenHolders: Returns list of top holders with addresses and balances

API Documentation: https://github.com/EverexIO/Ethplorer/wiki/Ethplorer-API

Supported networks:
- Ethereum Mainnet (1): https://api.ethplorer.io/
- BNB Chain (56): https://api.binplorer.com/
- Linea (59144): https://api.lineaplorer.build/
- Blast (81457): https://api.blastplorer.info/

API Tiers:
- Free tier: Uses "freekey" as API key, 2 req/sec, 100 max holders
- Personal key: Higher limits (10 req/sec, 1000 max holders)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import aiohttp

from scout.holder_api_providers import HolderAPIProvider, HolderData

LOGGER = logging.getLogger(__name__)


# Chain ID to Ethplorer base URL mapping
CHAIN_ID_TO_ETHPLORER_URL = {
    1: "https://api.ethplorer.io",           # Ethereum Mainnet
    56: "https://api.binplorer.com",         # BNB Chain
    59144: "https://api.lineaplorer.build",  # Linea
    81457: "https://api.blastplorer.info",   # Blast
}


class EthplorerHolderProvider(HolderAPIProvider):
    """Ethplorer holder API provider (Highest Priority).

    Uses Ethplorer's Token API endpoints:
    - /getTokenInfo/{address}: Returns holder count + token details
    - /getTopTokenHolders/{address}: Returns top N holders with balances

    API tiers:
    - Free: "freekey" with 2 req/sec limit, 100 max holders
    - Personal: Custom key with 10 req/sec, 1000 max holders

    Supported networks: Ethereum, BNB Chain, Linea, Blast
    """

    @property
    def provider_name(self) -> str:
        return "Ethplorer"

    @property
    def supported_chains(self) -> List[int]:
        return list(CHAIN_ID_TO_ETHPLORER_URL.keys())

    def __init__(
        self,
        api_key: str = "freekey",
        **kwargs: Any,
    ) -> None:
        """Initialize Ethplorer provider.

        Args:
            api_key: Ethplorer API key (defaults to "freekey" for free tier)
            **kwargs: Additional arguments passed to base class

        Note:
            Free tier uses "freekey" as the API key with these limitations:
            - 2 requests per second
            - 100 maximum holders per request
        """
        super().__init__(api_key=api_key, **kwargs)
        self.base_url: Optional[str] = None
        self._ep_session: Optional[aiohttp.ClientSession] = None

    def _get_base_url(self, chain_id: int) -> str:
        """Get base URL for a given chain.

        Args:
            chain_id: Chain ID

        Returns:
            Base URL for the chain

        Raises:
            ValueError: If chain is not supported
        """
        base_url = CHAIN_ID_TO_ETHPLORER_URL.get(chain_id)
        if not base_url:
            raise ValueError(f"Chain {chain_id} not supported by Ethplorer")
        return base_url

    async def _get_ep_session(self, base_url: str) -> aiohttp.ClientSession:
        """Get or create Ethplorer HTTP session for a specific base URL.

        Args:
            base_url: Base URL for the session

        Returns:
            HTTP session with appropriate headers
        """
        # Create a key for this base URL to support multiple sessions
        if not hasattr(self, '_ep_sessions'):
            self._ep_sessions: Dict[str, aiohttp.ClientSession] = {}

        if base_url not in self._ep_sessions:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self._ep_sessions[base_url] = aiohttp.ClientSession(
                timeout=timeout,
                base_url=base_url
            )
        return self._ep_sessions[base_url]

    async def close(self) -> None:
        """Close all HTTP sessions."""
        if self._session:
            await self._session.close()
            self._session = None
        if hasattr(self, '_ep_sessions'):
            for session in self._ep_sessions.values():
                await session.close()
            self._ep_sessions.clear()

    async def get_holder_count(
        self,
        token_address: str,
        chain_id: int,
    ) -> Optional[int]:
        """Get total holder count using Ethplorer getTokenInfo endpoint.

        Args:
            token_address: Token contract address
            chain_id: Chain ID

        Returns:
            Total holder count, or None if request fails
        """
        base_url = self._get_base_url(chain_id)

        try:
            session = await self._get_ep_session(base_url)
            url = f"/getTokenInfo/{token_address}"

            params = {"apiKey": self.api_key}
            async with session.get(url, params=params) as response:
                response.raise_for_status()
                data = await response.json()

                LOGGER.info(f"Ethplorer getTokenInfo response: {data}")

                if "holdersCount" in data:
                    count = data["holdersCount"]
                    if count is not None:
                        LOGGER.info(f"Ethplorer holder count: {count}")
                        return int(count)
                else:
                    LOGGER.warning(f"Ethplorer token info missing holdersCount for {token_address[:10]}...")

        except aiohttp.ClientResponseError as e:
            LOGGER.error(f"Ethplorer get_holder_count HTTP error: {e}")
        except Exception as e:
            LOGGER.error(f"Ethplorer get_holder_count failed: {e}")

        return None

    async def get_top_holders(
        self,
        token_address: str,
        chain_id: int,
        limit: int = 100,
    ) -> List[HolderData]:
        """Get top N holders using Ethplorer getTopTokenHolders endpoint.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            limit: Maximum number of holders to return (max 100 for free tier)

        Returns:
            List of holder data, sorted by balance (descending)
        """
        base_url = self._get_base_url(chain_id)

        # Enforce free tier limit
        if self.api_key == "freekey" and limit > 100:
            LOGGER.warning("Ethplorer free tier limited to 100 holders, capping limit")
            limit = 100

        try:
            session = await self._get_ep_session(base_url)
            url = f"/getTopTokenHolders/{token_address}"

            params = {
                "apiKey": self.api_key,
                "limit": limit
            }
            async with session.get(url, params=params) as response:
                response.raise_for_status()
                data = await response.json()

                LOGGER.info(f"Ethplorer getTopTokenHolders response keys: {data.keys()}")

                holders = []

                # Parse response based on Ethplorer API structure
                if "holders" in data:
                    holder_list = data["holders"]

                    for i, holder_data in enumerate(holder_list):
                        address = holder_data.get("address", "")
                        raw_balance = holder_data.get("rawBalance", "0")
                        balance = holder_data.get("balance", 0)  # Float balance
                        share = holder_data.get("share", 0)  # Percentage share

                        # Convert rawBalance (hex string) to integer
                        try:
                            balance_int = int(raw_balance, 16) if isinstance(raw_balance, str) and raw_balance.startswith("0x") else int(raw_balance)
                        except (ValueError, TypeError):
                            # Fallback to balance field if rawBalance fails
                            try:
                                balance_int = int(balance) if isinstance(balance, (int, float)) else 0
                            except (ValueError, TypeError):
                                balance_int = 0

                        if balance_int > 0:  # Only include holders with balance
                            holders.append(HolderData(
                                address=address,
                                balance=balance_int,
                                balance_hex=raw_balance if isinstance(raw_balance, str) else f"0x{balance_int:x}",
                                rank=i + 1,
                            ))

                    LOGGER.info(f"Ethplorer returned {len(holders)} top holders")
                else:
                    LOGGER.warning(f"Ethplorer getTopTokenHolders missing holders for {token_address[:10]}...")

                return holders

        except aiohttp.ClientResponseError as e:
            LOGGER.error(f"Ethplorer get_top_holders HTTP error: {e}")
        except Exception as e:
            LOGGER.error(f"Ethplorer get_top_holders failed: {e}")

        return []

    async def get_token_info(
        self,
        token_address: str,
        chain_id: int,
    ) -> Optional[Dict[str, Any]]:
        """Get full token information from Ethplorer.

        This provides additional metadata beyond holder count:
        - Token name, symbol, decimals
        - Total supply
        - Owner address (if applicable)
        - Last updated timestamp

        Args:
            token_address: Token contract address
            chain_id: Chain ID

        Returns:
            Dictionary with token information, or None if request fails
        """
        base_url = self._get_base_url(chain_id)

        try:
            session = await self._get_ep_session(base_url)
            url = f"/getTokenInfo/{token_address}"

            params = {"apiKey": self.api_key}
            async with session.get(url, params=params) as response:
                response.raise_for_status()
                data = await response.json()

                LOGGER.debug(f"Ethplorer get_token_info response: {data}")

                return data

        except Exception as e:
            LOGGER.error(f"Ethplorer get_token_info failed: {e}")

        return None
