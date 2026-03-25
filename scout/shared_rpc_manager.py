"""Unified RPC manager with per-block failure tracking.

This module provides centralized RPC management across all scouts with
intelligent provider selection based on historical block-specific failures.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Dict, List, Optional

from .database_manager import DatabaseManager
from .rpc_pool import RpcProvider, create_rpc_pool
from .rpc_providers_config import ProviderConfig, get_all_providers

LOGGER = logging.getLogger(__name__)


class RpcProviderWithBlockTracking(RpcProvider):
    """Enhanced RPC provider with per-block failure tracking.

    Extends the base RpcProvider with database-backed tracking of failures
    at specific blocks, enabling intelligent retry with different providers.
    """

    def __init__(
        self,
        config: ProviderConfig,
        chain_id: int,
        db_manager: DatabaseManager,
    ) -> None:
        """Initialize a provider with block tracking.

        Args:
            config: Provider configuration
            chain_id: Chain ID
            db_manager: Database manager for failure tracking
        """
        # Initialize base RpcProvider with URL and chain_id
        super().__init__(url=config.url, chain_id=chain_id)
        self.config = config
        self.db_manager = db_manager

    def mark_block_failure(self, block_number: int, method: str, error: str) -> None:
        """Record a failure for this specific block.

        Args:
            block_number: Block number where failure occurred
            method: RPC method name (e.g., eth_getLogs)
            error: Error message
        """
        self.db_manager.record_rpc_failure(
            self.chain_id, self.config.url, block_number, method, error
        )
        # Also mark global failure for backward compatibility
        self.mark_failure()

    def is_healthy_for_block(self, block_number: int, method: str) -> bool:
        """Check if provider is healthy for a specific block.

        A provider is healthy for a block if:
        1. It's globally healthy (below failure threshold)
        2. It hasn't failed at this specific block+method

        Args:
            block_number: Block number to check
            method: RPC method name

        Returns:
            True if provider is healthy for this block
        """
        if not self.is_healthy():
            return False

        failures = self.db_manager.get_provider_failure_count_at_block(
            self.chain_id, self.config.url, block_number, method
        )
        return failures == 0

    def get_block_failure_count(self, block_number: int, method: str) -> int:
        """Get the number of failures for this provider at a specific block.

        Args:
            block_number: Block number
            method: RPC method name

        Returns:
            Number of failures
        """
        return self.db_manager.get_provider_failure_count_at_block(
            self.chain_id, self.config.url, block_number, method
        )

    async def make_request(self, method: str, params: List[Any]) -> Any:
        """Make a JSON-RPC request with automatic block failure tracking.

        Wraps the base make_request to track failures at the block level
        when the request is for a specific block.

        Args:
            method: RPC method name
            params: Request parameters

        Returns:
            RPC response result
        """
        try:
            result = await super().make_request(method, params)
            # Success - clear any block-specific failures
            self._clear_block_failures_if_applicable(method, params)
            return result
        except Exception as e:
            # Failure - record at block level if applicable
            self._record_block_failure_if_applicable(method, params, str(e))
            raise

    def _record_block_failure_if_applicable(
        self, method: str, params: List[Any], error: str
    ) -> None:
        """Record failure at block level if params contain block information.

        Args:
            method: RPC method name
            params: Request parameters
            error: Error message
        """
        block_number = self._extract_block_number(method, params)
        if block_number is not None:
            self.mark_block_failure(block_number, method, error)

    def _clear_block_failures_if_applicable(
        self, method: str, params: List[Any]
    ) -> None:
        """Clear failures at block level if params contain block information.

        Args:
            method: RPC method name
            params: Request parameters
        """
        block_number = self._extract_block_number(method, params)
        if block_number is not None:
            self.db_manager.clear_rpc_failures_for_block(
                self.chain_id, self.config.url, block_number, method
            )

    def _extract_block_number(self, method: str, params: List[Any]) -> Optional[int]:
        """Extract block number from RPC request parameters.

        Args:
            method: RPC method name
            params: Request parameters

        Returns:
            Block number if found, None otherwise
        """
        if method in ("eth_getLogs", "eth_getBlockByNumber"):
            # These methods have block as first or second parameter
            if len(params) > 0:
                block_param = params[0] if method == "eth_getBlockByNumber" else params[0].get("fromBlock") if isinstance(params[0], dict) else None
                if isinstance(block_param, str):
                    if block_param == "latest":
                        return None
                    try:
                        return int(block_param, 16)
                    except ValueError:
                        pass
                elif isinstance(block_param, int):
                    return block_param
        elif method in ("eth_call", "eth_getCode", "eth_getBalance"):
            # These have block as second parameter
            if len(params) > 1:
                block_param = params[1]
                if isinstance(block_param, str):
                    if block_param == "latest":
                        return None
                    try:
                        return int(block_param, 16)
                    except ValueError:
                        pass
                elif isinstance(block_param, int):
                    return block_param
        return None


class UnifiedRpcManager:
    """Central RPC manager with intelligent provider selection.

    Provides unified RPC configuration and per-block failure tracking
    for all scouts. Automatically selects the best provider based on
    historical failures at specific blocks.
    """

    def __init__(
        self,
        chain_id: int,
        db_manager: DatabaseManager,
        providers: Optional[List[ProviderConfig]] = None,
    ) -> None:
        """Initialize the unified RPC manager.

        Args:
            chain_id: Chain ID
            db_manager: Database manager for failure tracking
            providers: Optional list of provider configs (uses all if None)
        """
        self.chain_id = chain_id
        self.db_manager = db_manager
        self._lock = threading.RLock()

        # Ensure failure tracking schema exists
        db_manager.ensure_rpc_failure_schema()

        # Use provided configs or get all for this chain
        provider_configs = providers or get_all_providers(chain_id)

        if not provider_configs:
            raise ValueError(f"No RPC providers available for chain {chain_id}")

        # Create enhanced providers with block tracking
        self.providers: Dict[str, RpcProviderWithBlockTracking] = {}
        for config in provider_configs:
            self.providers[config.url] = RpcProviderWithBlockTracking(
                config=config,
                chain_id=chain_id,
                db_manager=db_manager,
            )

        # Track total requests and metrics
        self._total_requests = 0
        self._successful_requests = 0

        LOGGER.info(
            f"Initialized UnifiedRpcManager for chain {chain_id} "
            f"with {len(self.providers)} providers"
        )

    def get_provider_for_block(
        self,
        block_number: int,
        method: str,
        exclude_failed: bool = True,
    ) -> Optional[RpcProviderWithBlockTracking]:
        """Get best provider for a specific block and method.

        Selection algorithm:
        1. Filter providers that haven't failed at this block+method (if exclude_failed)
        2. Sort by: priority (asc), global failures (asc), rate limit (desc)
        3. Return first healthy provider
        4. Fallback to any healthy provider if all failed

        Args:
            block_number: Block number to query
            method: RPC method name
            exclude_failed: Whether to exclude providers that failed at this block

        Returns:
            Best provider for this block, or None if no healthy providers
        """
        with self._lock:
            candidates = []
            failed_providers = []

            for url, provider in self.providers.items():
                if not provider.is_healthy():
                    continue

                # Check block-specific failures
                if exclude_failed:
                    if provider.is_healthy_for_block(block_number, method):
                        # Provider hasn't failed at this block
                        candidates.append(provider)
                    else:
                        # Provider has failed at this block
                        failed_providers.append(provider)
                else:
                    candidates.append(provider)

            # If we have candidates that haven't failed, use them
            if candidates:
                # Sort by priority (lower = better), then failures, then rate limit
                candidates.sort(
                    key=lambda p: (
                        p.config.priority,
                        p.failures,
                        -p.config.rate_limit,
                    )
                )
                return candidates[0]

            # Fallback: use providers that have failed (all have failed)
            if failed_providers:
                # Still sort to pick the "least bad" option
                failed_providers.sort(
                    key=lambda p: (
                        p.config.priority,
                        p.get_block_failure_count(block_number, method),
                        -p.config.rate_limit,
                    )
                )
                LOGGER.warning(
                    f"All providers have failed at block {block_number} for {method}, "
                    f"using {failed_providers[0].config.name}"
                )
                return failed_providers[0]

            # No healthy providers at all
            LOGGER.error("No healthy RPC providers available")
            return None

    def mark_provider_block_failure(
        self,
        provider_url: str,
        block_number: int,
        method: str,
        error: str,
    ) -> None:
        """Record a provider failure at a specific block.

        Args:
            provider_url: Provider URL
            block_number: Block number
            method: RPC method name
            error: Error message
        """
        with self._lock:
            provider = self.providers.get(provider_url)
            if provider:
                provider.mark_block_failure(block_number, method, error)

    def mark_provider_block_success(
        self,
        provider_url: str,
        block_number: int,
        method: str,
    ) -> None:
        """Clear failures for a provider at a specific block.

        Args:
            provider_url: Provider URL
            block_number: Block number
            method: RPC method name
        """
        with self._lock:
            provider = self.providers.get(provider_url)
            if provider:
                self.db_manager.clear_rpc_failures_for_block(
                    self.chain_id, provider_url, block_number, method
                )

    def get_healthy_providers(
        self,
        block_number: Optional[int] = None,
        method: Optional[str] = None,
    ) -> List[RpcProviderWithBlockTracking]:
        """Get list of healthy providers, optionally filtered by block.

        Args:
            block_number: Optional block number to filter by
            method: Optional method name to filter by

        Returns:
            List of healthy providers, sorted by priority
        """
        with self._lock:
            healthy = []

            for provider in self.providers.values():
                if not provider.is_healthy():
                    continue

                # Filter by block if specified
                if block_number is not None and method is not None:
                    if not provider.is_healthy_for_block(block_number, method):
                        continue

                healthy.append(provider)

            # Sort by priority
            healthy.sort(key=lambda p: p.config.priority)
            return healthy

    def cleanup_old_failures(
        self, older_than_seconds: int = 7 * 24 * 3600
    ) -> int:
        """Clean up old failure records.

        Args:
            older_than_seconds: Remove failures older than this (default: 7 days)

        Returns:
            Number of records deleted
        """
        return self.db_manager.cleanup_old_rpc_failures(older_than_seconds)

    async def close(self) -> None:
        """Close all provider sessions."""
        with self._lock:
            for provider in self.providers.values():
                await provider.close()

    def __enter__(self) -> "UnifiedRpcManager":
        """Context manager entry."""
        return self

    async def __aexit__(self, *args) -> None:
        """Async context manager exit."""
        await self.close()


def create_rpc_manager(
    chain_id: int,
    db_manager: DatabaseManager,
    use_providers: Optional[List[ProviderConfig]] = None,
) -> UnifiedRpcManager:
    """Factory function to create a unified RPC manager.

    Args:
        chain_id: Chain ID for the manager
        db_manager: Database manager for failure tracking
        use_providers: Optional list of provider configs (uses all if None)

    Returns:
        Configured UnifiedRpcManager instance
    """
    return UnifiedRpcManager(
        chain_id=chain_id,
        db_manager=db_manager,
        providers=use_providers,
    )


# Global RPC manager instance for shared access across scouts
_global_rpc_manager: Optional[UnifiedRpcManager] = None
_global_rpc_manager_lock = threading.Lock()


def set_rpc_manager(manager: UnifiedRpcManager) -> None:
    """Set the global RPC manager instance.

    Args:
        manager: UnifiedRpcManager instance to set as global
    """
    global _global_rpc_manager
    with _global_rpc_manager_lock:
        _global_rpc_manager = manager
        LOGGER.debug("Global RPC manager updated")


def get_rpc_manager() -> Optional[UnifiedRpcManager]:
    """Get the global RPC manager instance.

    Returns:
        UnifiedRpcManager instance or None if not set
    """
    with _global_rpc_manager_lock:
        return _global_rpc_manager


async def get_token_holder_count_nodereal(
    token_address: str,
    chain_id: int,
    rpc_manager: UnifiedRpcManager,
) -> Optional[int]:
    """Get ERC20 token holder count using NodeReal's nr_getTokenHolderCount method.

    This is a NodeReal-specific method that returns the number of token holders
    for an ERC20 token. Only supported on Ethereum (chain_id=1) and BSC (chain_id=56).

    Args:
        token_address: The ERC20 token contract address
        chain_id: Chain ID (1 for Ethereum, 56 for BSC)
        rpc_manager: The UnifiedRpcManager instance to use

    Returns:
        The number of token holders, or None if the method is not supported

    Example:
        >>> manager = create_rpc_manager(chain_id=1, db_manager=db)
        >>> count = await get_token_holder_count_nodereal(
        ...     "0x2170ed0880ac9a755fd29b2688956bd959f933f8",  # USDT
        ...     1,
        ...     manager
        ... )
        >>> print(f"Token holders: {count}")
    """
    # Only supported on ETH and BSC
    if chain_id not in (1, 56):
        LOGGER.warning(f"nr_getTokenHolderCount not supported for chain {chain_id}")
        return None

    # Find a NodeReal provider
    nodereal_provider = None
    for provider in rpc_manager.providers.values():
        if "nodereal" in provider.config.name.lower():
            nodereal_provider = provider
            break

    if not nodereal_provider:
        LOGGER.warning("No NodeReal provider available for nr_getTokenHolderCount")
        return None

    try:
        result = await nodereal_provider.make_request(
            "nr_getTokenHolderCount",
            [token_address]
        )

        # Result is hex-encoded, convert to int
        if isinstance(result, str) and result.startswith("0x"):
            return int(result, 16)
        elif isinstance(result, int):
            return result
        else:
            LOGGER.warning(f"Unexpected result type from nr_getTokenHolderCount: {type(result)}")
            return None

    except Exception as e:
        LOGGER.error(f"Failed to get token holder count via NodeReal: {e}")
        return None
