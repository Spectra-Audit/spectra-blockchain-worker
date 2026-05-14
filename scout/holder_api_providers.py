"""Holder API providers for token distribution analysis.

This module provides abstract base classes and concrete implementations
for multiple holder data APIs (NodeReal, Moralis, etc.) with automatic
failover support.
"""

from __future__ import annotations

import abc
import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import aiohttp

LOGGER = logging.getLogger(__name__)


@dataclass
class HolderData:
    """Individual holder data.

    Attributes:
        address: Holder wallet address
        balance: Balance as integer
        rank: Rank in top holders (1-based)
        balance_hex: Optional balance as hex string
    """

    address: str
    balance: int
    rank: int
    balance_hex: Optional[str] = None


@dataclass
class HolderMetrics:
    """Aggregated holder metrics.

    Attributes:
        total_holder_count: Total number of holders
        top_holders: List of top holder data
        gini_coefficient: Gini coefficient (0-1, higher = more unequal)
        nakamoto_coefficient: Number of holders needed for 51% control
        top_10_pct_supply: Percentage of supply held by top 10%
        top_1_pct_supply: Percentage of supply held by top 1%
        top_100_balance_sum: Sum of top 100 balances (hex string for TEXT storage)
        estimated_total_supply: Total supply from contract or estimate (hex string)
    """

    total_holder_count: int
    top_holders: List[HolderData]
    gini_coefficient: float
    nakamoto_coefficient: int
    top_10_pct_supply: float
    top_1_pct_supply: float
    top_100_balance_sum: str
    estimated_total_supply: str
    holder_tiers: Optional[List[Dict]] = None
    price_usd: Optional[float] = None
    holder_tier_estimation_method: Optional[str] = None
    holder_tier_sample_size: Optional[int] = None
    holder_tier_total_count: Optional[int] = None
    holder_count_confirmed: bool = True


class HolderAPIProvider(abc.ABC):
    """Abstract base class for holder API providers.

    Implementations must support:
    - Getting total holder count
    - Getting top N holders
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: float = 30.0,
    ) -> None:
        """Initialize the provider.

        Args:
            api_key: Optional API key for authentication
            timeout: HTTP request timeout in seconds
        """
        self.api_key = api_key
        self.timeout = timeout
        self._session: Optional[aiohttp.ClientSession] = None
        self._session_loop_id: Optional[int] = None

    @property
    @abc.abstractmethod
    def provider_name(self) -> str:
        """Return the provider name."""
        pass

    @property
    @abc.abstractmethod
    def supported_chains(self) -> List[int]:
        """Return list of supported chain IDs."""
        pass

    @abc.abstractmethod
    async def get_holder_count(
        self,
        token_address: str,
        chain_id: int,
    ) -> Optional[int]:
        """Get total holder count for a token.

        Args:
            token_address: Token contract address
            chain_id: Chain ID

        Returns:
            Total holder count, or None if not available
        """
        pass

    @abc.abstractmethod
    async def get_top_holders(
        self,
        token_address: str,
        chain_id: int,
        limit: int = 100,
    ) -> List[HolderData]:
        """Get top N holders for a token.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            limit: Maximum number of holders to return

        Returns:
            List of holder data, sorted by balance (descending)
        """
        pass

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session, handling event-loop binding.

        When the audit runs in a thread via asyncio.run(), a new event loop is
        created.  aiohttp sessions are bound to the loop where they were
        created, so we detect loop changes and create a fresh session.
        """
        current_loop = asyncio.get_running_loop()
        loop_id = id(current_loop)

        if self._session is not None and self._session_loop_id != loop_id:
            # Close stale session from a different loop
            try:
                await self._session.close()
            except Exception:
                pass
            self._session = None

        if self._session is None:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self._session = aiohttp.ClientSession(timeout=timeout)
            self._session_loop_id = loop_id

        return self._session

    async def close(self) -> None:
        """Close the HTTP session."""
        if self._session:
            await self._session.close()
            self._session = None


class NodeRealHolderProvider(HolderAPIProvider):
    """NodeReal holder API provider.

    Uses NodeReal's specialized RPC methods:
    - nr_getTokenHolders: Get top N holders (paginated)
    - nr_getTokenHolderCount: Get total holder count

    Supports: Ethereum (1), BSC (56)
    """

    @property
    def provider_name(self) -> str:
        return "NodeReal"

    @property
    def supported_chains(self) -> List[int]:
        return [1, 56]  # ETH and BSC

    def __init__(self, api_key: str, **kwargs: Any) -> None:
        """Initialize NodeReal provider.

        Args:
            api_key: NodeReal API key (required)
            **kwargs: Additional arguments passed to base class

        Raises:
            ValueError: If api_key is not provided
        """
        super().__init__(api_key=api_key, **kwargs)
        if not api_key:
            raise ValueError("NodeReal API key is required")

    def _get_endpoint(self, chain_id: int) -> str:
        """Get NodeReal endpoint for a chain.

        Args:
            chain_id: Chain ID

        Returns:
            Full RPC endpoint URL with API key

        Raises:
            ValueError: If chain is not supported
        """
        chain_endpoints = {
            1: "https://eth-mainnet.nodereal.io/v1",
            56: "https://bsc-mainnet.nodereal.io/v1",
        }
        if chain_id not in chain_endpoints:
            raise ValueError(f"Chain {chain_id} not supported by NodeReal")
        return f"{chain_endpoints[chain_id]}/{self.api_key}"

    async def get_holder_count(
        self,
        token_address: str,
        chain_id: int,
    ) -> Optional[int]:
        """Get total holder count using nr_getTokenHolderCount.

        Args:
            token_address: Token contract address
            chain_id: Chain ID

        Returns:
            Total holder count, or None if request fails
        """
        endpoint = self._get_endpoint(chain_id)

        try:
            session = await self._get_session()
            payload = {
                "jsonrpc": "2.0",
                "method": "nr_getTokenHolderCount",
                "params": [token_address],
                "id": 1
            }
            async with session.post(endpoint, json=payload) as response:
                response.raise_for_status()
                data = await response.json()

                # Log at INFO level so user can see what API returns
                LOGGER.info(f"NodeReal get_holder_count response: {data}")

                if "result" in data and data["result"]:
                    result = data["result"]
                    # Handle both hex string and dict response formats
                    if isinstance(result, dict):
                        # Some API responses return nested {"result": "0x..."}
                        # Try common key names
                        count_value = (
                            result.get("result") or  # Nested result
                            result.get("count") or
                            result.get("total") or
                            result.get("holderCount")
                        )
                        if count_value:
                            if isinstance(count_value, str):
                                count = int(count_value, 16) if count_value.startswith("0x") else int(count_value)
                                LOGGER.info(f"NodeReal holder count (dict): {count}")
                                return count
                            return int(count_value)
                    elif isinstance(result, str):
                        count = int(result, 16) if result.startswith("0x") else int(result)
                        LOGGER.info(f"NodeReal holder count (string): {count}")
                        return count
                    elif isinstance(result, int):
                        LOGGER.info(f"NodeReal holder count (int): {result}")
                        return result
                else:
                    LOGGER.warning(
                        f"NodeReal nr_getTokenHolderCount returned empty/None result. "
                        f"Response: {data}"
                    )

        except Exception as e:
            LOGGER.error(f"NodeReal get_holder_count failed: {e}")

        return None

    async def get_top_holders(
        self,
        token_address: str,
        chain_id: int,
        limit: int = 100,
    ) -> List[HolderData]:
        """Get top holders using nr_getTokenHolders.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            limit: Maximum number of holders to return

        Returns:
            List of holder data, sorted by balance (descending)
        """
        endpoint = self._get_endpoint(chain_id)

        holders = []
        page_size = min(limit, 100)  # NodeReal max is 100
        page_size_hex = f"0x{page_size:x}"  # Convert to hex
        page_key = ""  # Empty for first page

        try:
            session = await self._get_session()

            while len(holders) < limit and page_key is not None:
                payload = {
                    "jsonrpc": "2.0",
                    "method": "nr_getTokenHolders",
                    "params": [token_address, page_size_hex, page_key],
                    "id": 1
                }
                async with session.post(endpoint, json=payload) as response:
                    response.raise_for_status()
                    data = await response.json()

                    if "result" not in data or "details" not in data["result"]:
                        break

                    # Log if there's a total count in the response
                    result_obj = data["result"]
                    if "totalCount" in result_obj or "total" in result_obj or "count" in result_obj:
                        total_from_api = (
                            result_obj.get("totalCount") or
                            result_obj.get("total") or
                            result_obj.get("count")
                        )
                        LOGGER.info(f"NodeReal nr_getTokenHolders includes total count: {total_from_api}")

                    # Process holders in this page
                    for holder_data in data["result"]["details"]:
                        address = holder_data.get("accountAddress", "")
                        balance_hex = holder_data.get("tokenBalance", "0x0")

                        # Convert hex balance to integer
                        balance_int = int(balance_hex, 16) if balance_hex.startswith("0x") else 0

                        if balance_int > 0:  # Only include holders with balance
                            holders.append(HolderData(
                                address=address,
                                balance=balance_int,
                                balance_hex=balance_hex,
                                rank=len(holders) + 1,
                            ))

                    # Check for next page
                    page_key = data["result"].get("pageKey")

                    if not page_key:
                        break

        except Exception as e:
            LOGGER.error(f"NodeReal get_top_holders failed: {e}")

        return holders[:limit]


class MoralisHolderProvider(HolderAPIProvider):
    """Moralis holder API provider.

    Uses Moralis REST API endpoints:
    - /erc20/{address}/owners: Get top holders with pagination
    - Owner list includes total count

    Supports: ETH, BSC, Polygon, Arbitrum, Optimism, Avalanche, and more
    """

    @property
    def provider_name(self) -> str:
        return "Moralis"

    @property
    def supported_chains(self) -> List[int]:
        # Moralis supports many chains via API key
        return [1, 56, 137, 42161, 10, 43114]  # ETH, BSC, Polygon, Arbitrum, Optimism, Avalanche

    def __init__(self, api_key: str, **kwargs: Any) -> None:
        """Initialize Moralis provider.

        Args:
            api_key: Moralis API key (required)
            **kwargs: Additional arguments passed to base class

        Raises:
            ValueError: If api_key is not provided
        """
        super().__init__(api_key=api_key, **kwargs)
        if not api_key:
            raise ValueError("Moralis API key is required")
        self.base_url = "https://deep-index.moralis.io/api/v2.2"

    async def get_holder_count(
        self,
        token_address: str,
        chain_id: int,
    ) -> Optional[int]:
        """Get total holder count using Moralis owners endpoint.

        Args:
            token_address: Token contract address
            chain_id: Chain ID

        Returns:
            Total holder count, or None if request fails
        """
        try:
            session = await self._get_session()
            params = {
                "chain": self._chain_id_to_param(chain_id),
                "limit": 1,  # Minimal request to get count
            }
            headers = {"X-API-Key": self.api_key}
            async with session.get(
                f"{self.base_url}/erc20/{token_address}/owners",
                params=params,
                headers=headers
            ) as response:
                response.raise_for_status()
                data = await response.json()

                LOGGER.debug(f"Moralis get_holder_count raw response: {data}")

                if "total" in data:
                    count = data["total"]
                    LOGGER.info(f"Moralis holder count: {count}")
                    return count
                else:
                    LOGGER.warning(f"Moralis get_holder_count missing 'total' field for {token_address[:10]}...")

        except Exception as e:
            LOGGER.error(f"Moralis get_holder_count failed: {e}")

        return None

    async def get_top_holders(
        self,
        token_address: str,
        chain_id: int,
        limit: int = 100,
    ) -> List[HolderData]:
        """Get top holders using Moralis owners endpoint.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            limit: Maximum number of holders to return

        Returns:
            List of holder data, sorted by balance (descending)
        """
        try:
            session = await self._get_session()
            holders = []
            cursor = None
            page_size = min(max(limit, 1), 100)
            headers = {"X-API-Key": self.api_key}

            while len(holders) < limit:
                params = {
                    "chain": self._chain_id_to_param(chain_id),
                    "limit": min(page_size, limit - len(holders)),
                    "order": "DESC",  # Highest balance first
                }
                if cursor:
                    params["cursor"] = cursor

                async with session.get(
                    f"{self.base_url}/erc20/{token_address}/owners",
                    params=params,
                    headers=headers
                ) as response:
                    response.raise_for_status()
                    data = await response.json()

                page_results = data.get("result") or []
                if not page_results:
                    break

                for owner in page_results:
                    balance_hex = owner.get("balance", "0x0")
                    balance_int = int(balance_hex, 16) if balance_hex.startswith("0x") else 0

                    if balance_int > 0:
                        holders.append(HolderData(
                            address=owner.get("owner_address", ""),
                            balance=balance_int,
                            balance_hex=balance_hex,
                            rank=len(holders) + 1,
                        ))

                cursor = data.get("cursor")
                if not cursor:
                    break

            return holders[:limit]

        except Exception as e:
            LOGGER.error(f"Moralis get_top_holders failed: {e}")

        return []

    def _chain_id_to_param(self, chain_id: int) -> str:
        """Convert chain ID to Moralis API parameter.

        Args:
            chain_id: Chain ID

        Returns:
            Chain parameter string for Moralis API
        """
        chain_map = {
            1: "0x1",
            56: "0x38",
            137: "0x89",
            42161: "0xa4b1",
            10: "0xa",
            43114: "0xa86a4",
        }
        return chain_map.get(chain_id, f"0x{chain_id:x}")
