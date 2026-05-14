"""Dune Sim holder API provider.

Uses Dune's Sim API token holder endpoint as a cursor-paginated fallback for
ERC20 holder lists. The endpoint returns balances sorted descending.
"""

from __future__ import annotations

import logging
from typing import Any, List, Optional

from scout.holder_api_providers import HolderAPIProvider, HolderData

LOGGER = logging.getLogger(__name__)


# Dune Sim's EVM token-holders endpoint supports many EVM chains. Keep this
# broad; unsupported chains return a provider error and the manager fails over.
DUNE_SIM_SUPPORTED_CHAINS = [
    1,
    10,
    56,
    100,
    137,
    250,
    8453,
    42161,
    43114,
    59144,
    81457,
]


class DuneSimHolderProvider(HolderAPIProvider):
    """Dune Sim token holder provider.

    Required env var in production: DUNE_SIM_API_KEY.
    Legacy aliases accepted by the manager: SIM_DUNE_API_KEY, DUNE_API_KEY.
    """

    base_url = "https://api.sim.dune.com"

    @property
    def provider_name(self) -> str:
        return "DuneSim"

    @property
    def supported_chains(self) -> List[int]:
        return DUNE_SIM_SUPPORTED_CHAINS

    def __init__(self, api_key: str, **kwargs: Any) -> None:
        super().__init__(api_key=api_key, **kwargs)
        if not api_key:
            raise ValueError("Dune Sim API key is required")

    async def get_holder_count(
        self,
        token_address: str,
        chain_id: int,
    ) -> Optional[int]:
        """Dune's token-holders response does not expose total count."""
        return None

    async def get_top_holders(
        self,
        token_address: str,
        chain_id: int,
        limit: int = 100,
    ) -> List[HolderData]:
        """Get top holders from Dune Sim using cursor pagination."""
        if chain_id not in self.supported_chains:
            LOGGER.warning("Chain %s not supported by Dune Sim holder provider", chain_id)
            return []

        holders: List[HolderData] = []
        next_offset: Optional[str] = None
        page_size = min(max(limit, 1), 500)
        headers = {"X-Sim-Api-Key": self.api_key or ""}
        url = f"{self.base_url}/v1/evm/token-holders/{chain_id}/{token_address}"

        try:
            session = await self._get_session()
            while len(holders) < limit:
                params: dict[str, str | int] = {
                    "limit": min(page_size, limit - len(holders)),
                }
                if next_offset:
                    params["offset"] = next_offset

                async with session.get(url, params=params, headers=headers) as response:
                    if response.status == 429:
                        LOGGER.warning("Dune Sim holder API rate-limited for %s", token_address[:10])
                        return []
                    if response.status == 401:
                        LOGGER.warning("Dune Sim holder API rejected configured API key")
                        return []
                    if response.status == 404:
                        LOGGER.warning("Dune Sim holder API found no token holders for %s", token_address[:10])
                        return []
                    response.raise_for_status()
                    data = await response.json()

                page_holders = data.get("holders") or []
                if not page_holders:
                    break

                for holder in page_holders:
                    balance = self._parse_balance(holder.get("balance"))
                    if balance <= 0:
                        continue
                    address = holder.get("wallet_address") or holder.get("address") or ""
                    if not address:
                        continue
                    holders.append(
                        HolderData(
                            address=address,
                            balance=balance,
                            balance_hex=f"0x{balance:x}",
                            rank=len(holders) + 1,
                        )
                    )
                    if len(holders) >= limit:
                        break

                next_offset = data.get("next_offset")
                if not next_offset:
                    break

            LOGGER.info("Dune Sim returned %d top holders for %s", len(holders), token_address[:10])
            return holders[:limit]
        except Exception as e:
            LOGGER.error("Dune Sim get_top_holders failed: %s", e)
            return []

    @staticmethod
    def _parse_balance(value: Any) -> int:
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            try:
                return int(value, 16) if value.startswith("0x") else int(value)
            except ValueError:
                return 0
        return 0
