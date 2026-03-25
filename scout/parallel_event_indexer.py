"""Parallel event indexer for scalable token distribution analysis.

This module provides coordinated parallel scanning of blockchain Transfer events
across multiple RPC providers, enabling efficient indexing of high-volume tokens
like USDT (11.8M+ holders).

Uses unified provider configuration from rpc_providers_config.py for accurate
rate limits and optimal chunk sizing per provider.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from eth_abi import decode
from eth_utils import to_checksum_address
from web3 import Web3
from web3.exceptions import Web3Exception

from .async_runner import get_shared_async_runner
from .database_manager import DatabaseManager
from .rpc_pool import RpcProvider, create_rpc_pool
from .shared_rpc_manager import UnifiedRpcManager, create_rpc_manager
from .rpc_providers_config import (
    get_all_providers,
    get_optimized_chunk_size,
    ProviderConfig,
)

LOGGER = logging.getLogger(__name__)

# ERC20 Transfer event signature
# Transfer(address indexed from, address indexed to, uint256 value)
TRANSFER_EVENT_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

# Default configuration (will be overridden by provider configs)
DEFAULT_MAX_WORKERS_PER_PROVIDER = 1  # One active request per provider at a time


@dataclass
class IndexProgress:
    """Progress tracking for event indexing."""

    total_chunks: int
    completed_chunks: int
    pending_chunks: int
    failed_chunks: int
    total_events: int
    first_block: int
    last_block: int
    current_block: int
    last_scanned_block: Optional[int]

    @property
    def percent_complete(self) -> float:
        if self.total_chunks == 0:
            return 0.0
        return (self.completed_chunks / self.total_chunks) * 100

    @property
    def is_complete(self) -> bool:
        return self.completed_chunks == self.total_chunks

    @property
    def blocks_remaining(self) -> int:
        if self.last_scanned_block is None:
            return self.last_block - self.first_block + 1
        return self.last_block - self.last_scanned_block


@dataclass
class IndexedChunk:
    """Result of indexing a single block chunk."""

    provider_id: str
    from_block: int
    to_block: int
    last_scanned_block: int
    events_found: int
    status: str
    duration_seconds: float


class ParallelEventIndexer:
    """Coordinates parallel Transfer event scanning across multiple RPC providers.

    This indexer divides the block range into chunks and assigns them to available
    RPC providers, scanning in parallel for maximum throughput. Progress is tracked
    in the database for resilience and resumption.

    Uses unified provider configuration for accurate rate limits and optimal
    chunk sizing per provider.
    """

    def __init__(
        self,
        database: DatabaseManager,
        chain_id: int = 1,
        chunk_size: Optional[int] = None,
        max_workers_per_provider: int = DEFAULT_MAX_WORKERS_PER_PROVIDER,
        use_unified_manager: bool = True,
    ) -> None:
        """Initialize the parallel event indexer.

        Args:
            database: Database manager for storing events and progress
            chain_id: Chain ID to scan
            chunk_size: Blocks per chunk (auto-calculated from provider limits if None)
            max_workers_per_provider: Concurrent requests per provider (default: 1)
            use_unified_manager: Use UnifiedRpcManager with per-block failure tracking
        """
        self.database = database
        self.chain_id = chain_id
        self.max_workers = max_workers_per_provider
        self.use_unified_manager = use_unified_manager

        # Load unified provider configurations
        self.provider_configs: List[ProviderConfig] = get_all_providers(chain_id)

        # Use optimal chunk size based on provider constraints if not specified
        if chunk_size is None:
            self.chunk_size = get_optimized_chunk_size(chain_id)
        else:
            self.chunk_size = chunk_size

        # Create unified RPC manager with block tracking or legacy pool
        if use_unified_manager:
            self.rpc_manager: UnifiedRpcManager = create_rpc_manager(
                chain_id, database
            )
            self.rpc_pool = None  # Not used when unified manager is active
            self.providers: List[RpcProvider] = []
        else:
            # Legacy behavior: use ParallelRpcPool
            rpc_urls = [p.url for p in self.provider_configs]
            self.rpc_pool = create_rpc_pool(chain_id, rpc_urls=rpc_urls)
            self.providers = self.rpc_pool.providers
            self.rpc_manager = None  # Not used when legacy pool is active

        # Map provider URLs to their configurations
        self.provider_config_map: Dict[str, ProviderConfig] = {
            p.url: p for p in self.provider_configs
        }

        # Provider rate limit tracking
        self.provider_last_request: Dict[str, float] = {}

        # Log initialization details
        total_rate_limit = sum(p.rate_limit for p in self.provider_configs)
        LOGGER.info(
            f"Initialized ParallelEventIndexer with {len(self.provider_configs)} providers, "
            f"total rate limit: {total_rate_limit:.1f} req/s, "
            f"chunk size: {self.chunk_size:,} blocks, "
            f"unified manager: {use_unified_manager}"
        )

        # Current scan ID (set during indexing)
        self._current_scan_id: Optional[str] = None

    @property
    def scan_id(self) -> str:
        """Get the current scan ID, generating one if needed."""
        if self._current_scan_id is None:
            self._current_scan_id = str(uuid.uuid4())
        return self._current_scan_id

    async def close(self) -> None:
        """Close all RPC provider connections."""
        if self.rpc_manager:
            await self.rpc_manager.close()
        elif self.rpc_pool:
            await self.rpc_pool.close()

    def get_provider_count(self) -> int:
        """Get the number of available RPC providers."""
        if self.rpc_manager:
            return len(self.rpc_manager.get_healthy_providers())
        return len([p for p in self.providers if p.is_healthy()])

    def _get_provider_for_chunk(
        self,
        chunk_from_block: int,
        provider_id: Optional[str] = None,
    ) -> RpcProvider:
        """Get a provider for a chunk, using block-aware selection if available.

        Args:
            chunk_from_block: Starting block of the chunk
            provider_id: Optional assigned provider ID

        Returns:
            RpcProvider to use for this chunk
        """
        if self.rpc_manager:
            # Use unified manager with block-aware selection
            provider = self.rpc_manager.get_provider_for_block(
                block_number=chunk_from_block,
                method='eth_getLogs',
                exclude_failed=True,
            )
            if provider:
                return provider
            # Fallback: create legacy provider wrapper
            raise Exception("No healthy providers available")
        else:
            # Legacy behavior: use assigned provider or healthy from pool
            if provider_id:
                provider = next((p for p in self.providers if p.url == provider_id), None)
                if provider:
                    return provider
            # Use first healthy provider
            healthy = [p for p in self.providers if p.is_healthy()]
            if healthy:
                return healthy[0]
            raise Exception("No healthy providers available")

    async def index_token_transfers(
        self,
        token_address: str,
        deployment_block: Optional[int] = None,
        end_block: Optional[int] = None,
        force_rescan: bool = False,
        chunk_size: Optional[int] = None,
    ) -> IndexProgress:
        """Index all Transfer events for a token using parallel RPC providers.

        Args:
            token_address: Token contract address
            deployment_block: Deployment block (auto-discovered if None)
            end_block: Last block to scan (current block if None)
            force_rescan: If True, rescan even if already indexed
            chunk_size: Override default chunk size

        Returns:
            IndexProgress with final statistics
        """
        # Normalize address
        token_address = to_checksum_address(token_address)

        # Discover deployment block if not provided
        if deployment_block is None:
            deployment_block = await self._discover_deployment_block(token_address)
            LOGGER.info(f"Discovered deployment block: {deployment_block}")

        # Get current block if not provided
        if end_block is None:
            end_block = await self._get_current_block()
            LOGGER.info(f"Current block: {end_block}")

        # Check for existing scan
        if not force_rescan:
            existing = self.database.get_event_scan_progress(token_address, self.chain_id)
            if existing and existing["last_scanned_block"]:
                LOGGER.info(
                    f"Resuming from block {existing['last_scanned_block']}, "
                    f"{existing['total_events_indexed']} events already indexed"
                )
                deployment_block = existing["last_scanned_block"] + 1

        # Use custom chunk size if provided
        if chunk_size:
            self.chunk_size = chunk_size

        # Generate scan ID
        self._current_scan_id = str(uuid.uuid4())
        scan_id = self.scan_id

        # Create chunks and assign to providers
        chunks = self._create_chunks(
            deployment_block,
            end_block,
            self.get_provider_count(),
        )

        # Store chunks in database
        self.database.create_parallel_scan(token_address, self.chain_id, scan_id, chunks)

        LOGGER.info(
            f"Starting parallel scan: {len(chunks)} chunks across "
            f"{self.get_provider_count()} providers "
            f"(blocks {deployment_block:,} to {end_block:,})"
        )

        # Process chunks in parallel
        total_events = 0
        start_time = time.time()

        while True:
            # Get pending chunks
            pending = self.database.get_pending_scan_chunks(
                token_address, self.chain_id, scan_id, limit=self.get_provider_count() * self.max_workers
            )

            if not pending:
                # Check if any chunks are still in progress
                status = self.database.get_scan_status(token_address, self.chain_id, scan_id)
                if status["in_progress"] == 0:
                    # All chunks done
                    break
                # Wait for in-progress chunks
                await asyncio.sleep(1)
                continue

            # Launch tasks for pending chunks
            tasks: List[Awaitable[IndexedChunk]] = []
            for chunk in pending:
                task = self._index_chunk(
                    token_address,
                    chunk["from_block"],
                    chunk["to_block"],
                    chunk["provider_id"],
                )
                tasks.append(task)

            # Execute in parallel with limited concurrency
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Process results
            for result in results:
                if isinstance(result, Exception):
                    LOGGER.error(f"Chunk indexing failed: {result}")
                    continue

                total_events += result.events_found

                # Update chunk status in database
                self.database.update_scan_chunk(
                    token_address,
                    self.chain_id,
                    scan_id,
                    result.provider_id,
                    result.from_block,
                    result.last_scanned_block,
                    result.events_found,
                    result.status,
                )

                # Log progress
                progress = self.database.get_scan_status(token_address, self.chain_id, scan_id)
                LOGGER.info(
                    f"Progress: {progress['completed']}/{progress['total_chunks']} chunks, "
                    f"{progress['total_events']:,} events, "
                    f"{progress['pending']} pending, {progress['in_progress']} in progress"
                )

        # Update overall progress
        duration = time.time() - start_time
        final_status = self.database.get_scan_status(token_address, self.chain_id, scan_id)

        # Update event scan progress
        self.database.update_event_scan_progress(
            token_address,
            self.chain_id,
            deployment_block,
            end_block,
            end_block,
            final_status["total_events"],
        )

        LOGGER.info(
            f"Scan complete: {final_status['total_events']:,} events indexed "
            f"in {duration:.1f}s ({final_status['total_events']/duration:.0f} events/s)"
        )

        return IndexProgress(
            total_chunks=final_status["total_chunks"],
            completed_chunks=final_status["completed"],
            pending_chunks=final_status["pending"],
            failed_chunks=final_status["failed"],
            total_events=final_status["total_events"],
            first_block=deployment_block,
            last_block=end_block,
            current_block=end_block,
            last_scanned_block=end_block,
        )

    async def _index_chunk(
        self,
        token_address: str,
        from_block: int,
        to_block: int,
        provider_id: str,
    ) -> IndexedChunk:
        """Index a single block chunk using block-aware provider selection.

        Args:
            token_address: Token contract address
            from_block: Start block
            to_block: End block
            provider_id: Provider identifier (preferred, may be overridden by block tracking)

        Returns:
            IndexedChunk with results
        """
        start_time = time.time()
        scan_id = self.scan_id

        # Get provider using block-aware selection
        # If using unified manager, this may switch providers based on past failures
        try:
            provider = self._get_provider_for_chunk(from_block, provider_id)
        except Exception as e:
            LOGGER.error(
                f"Failed to get provider for chunk {from_block}-{to_block}: {e}"
            )
            return IndexedChunk(
                provider_id=provider_id,
                from_block=from_block,
                to_block=to_block,
                last_scanned_block=from_block,
                events_found=0,
                status="failed",
                duration_seconds=time.time() - start_time,
            )

        # Use the actual provider URL (may differ from assigned provider_id)
        actual_provider_id = provider.url

        try:
            # Respect rate limiting
            await self._rate_limit_delay(actual_provider_id)

            # Update status to in_progress
            self.database.update_scan_chunk(
                token_address, self.chain_id, scan_id, actual_provider_id,
                from_block, from_block, 0, "in_progress"
            )

            # Fetch logs for this chunk
            logs = await self._get_transfer_logs(
                provider, token_address, from_block, to_block
            )

            # Parse and store events
            events = []
            for log in logs:
                event = self._parse_transfer_log(log, token_address)
                if event:
                    events.append(event)

            # Batch store events
            if events:
                self.database.store_transfer_events_batch(events)

            # Mark success for this block (clears failures)
            if self.rpc_manager:
                self.rpc_manager.mark_provider_block_success(
                    actual_provider_id, from_block, "eth_getLogs"
                )

            last_scanned = to_block
            if logs:
                last_scanned = max(log.get("blockNumber", to_block) for log in logs)

            duration = time.time() - start_time

            return IndexedChunk(
                provider_id=actual_provider_id,
                from_block=from_block,
                to_block=to_block,
                last_scanned_block=last_scanned,
                events_found=len(events),
                status="completed",
                duration_seconds=duration,
            )

        except Exception as e:
            # Mark failure for this block
            if self.rpc_manager:
                self.rpc_manager.mark_provider_block_failure(
                    actual_provider_id, from_block, "eth_getLogs", str(e)
                )

            LOGGER.error(
                f"Failed to index chunk {from_block}-{to_block} "
                f"with {actual_provider_id}: {e}"
            )
            return IndexedChunk(
                provider_id=actual_provider_id,
                from_block=from_block,
                to_block=to_block,
                last_scanned_block=from_block,
                events_found=0,
                status="failed",
                duration_seconds=time.time() - start_time,
            )

    async def _get_transfer_logs(
        self,
        provider: RpcProvider,
        token_address: str,
        from_block: int,
        to_block: int,
    ) -> List[dict]:
        """Fetch Transfer event logs for a block range.

        Args:
            provider: RPC provider to use
            token_address: Token contract address
            from_block: Start block
            to_block: End block

        Returns:
            List of log dicts
        """
        params = [
            {
                "address": token_address,
                "fromBlock": f"0x{from_block:x}",
                "toBlock": f"0x{to_block:x}",
                "topics": [TRANSFER_EVENT_TOPIC],
            }
        ]

        result = await provider.make_request("eth_getLogs", params)

        if not result:
            return []

        return result if isinstance(result, list) else [result]

    def _parse_transfer_log(self, log: dict, token_address: str) -> Optional[dict]:
        """Parse a Transfer event log into a structured dict.

        Args:
            log: Raw log dict from RPC
            token_address: Token contract address

        Returns:
            Event dict or None if parsing fails
        """
        try:
            block_number = int(log.get("blockNumber", 0), 16)
            tx_hash = log.get("transactionHash", "")
            tx_index = int(log.get("transactionIndex", 0), 16)
            log_index = int(log.get("logIndex", 0), 16)

            # Parse topics
            topics = log.get("topics", [])
            if len(topics) < 3:
                return None

            # from_address (indexed, topic 1)
            from_address = "0x" + topics[1][-40:]
            # to_address (indexed, topic 2)
            to_address = "0x" + topics[2][-40:]

            # Parse value from data (uint256)
            data = log.get("data", "0x")
            if data.startswith("0x"):
                data = data[2:]
            # Pad to 64 chars (32 bytes)
            data = data.zfill(64)
            value = int(data, 16)

            return {
                "token_address": token_address,
                "chain_id": self.chain_id,
                "block_number": block_number,
                "tx_hash": tx_hash,
                "tx_index": tx_index,
                "log_index": log_index,
                "from_address": from_address,
                "to_address": to_address,
                "value": value,
                "timestamp": 0,  # Will be filled by batch processor if needed
            }

        except (ValueError, KeyError, IndexError) as e:
            LOGGER.warning(f"Failed to parse log: {e}")
            return None

    async def _discover_deployment_block(self, token_address: str) -> int:
        """Discover the deployment block of a token using binary search.

        Args:
            token_address: Token contract address

        Returns:
            Deployment block number
        """
        # Binary search for the first block where code exists
        lo, hi = 0, await self._get_current_block()

        # Get provider (block 0 = any block for deployment discovery)
        if self.rpc_manager:
            provider = self.rpc_manager.get_provider_for_block(0, "eth_getCode")
        else:
            healthy = [p for p in self.providers if p.is_healthy()]
            if not healthy:
                raise Exception("No healthy providers available")
            provider = healthy[0]

        if not provider:
            raise Exception("No provider available for deployment discovery")

        while lo < hi:
            mid = (lo + hi) // 2
            code = await provider.make_request(
                "eth_getCode",
                [token_address, f"0x{mid:x}"]
            )

            if code and code != "0x":
                hi = mid
            else:
                lo = mid + 1

        return lo

    async def _get_current_block(self) -> int:
        """Get the current block number.

        Returns:
            Current block number
        """
        if self.rpc_manager:
            provider = self.rpc_manager.get_provider_for_block(0, "eth_blockNumber")
        else:
            healthy = [p for p in self.providers if p.is_healthy()]
            if not healthy:
                raise Exception("No healthy providers available")
            provider = healthy[0]

        if not provider:
            raise Exception("No provider available for current block")

        result = await provider.make_request("eth_blockNumber", [])
        return int(result, 16) if result else 0

    async def _rate_limit_delay(self, provider_id: str) -> None:
        """Apply rate limiting delay for a provider based on its configuration.

        Args:
            provider_id: Provider URL
        """
        # Get provider config to determine rate limit
        provider_config = self.provider_config_map.get(provider_id)
        if provider_config:
            # Use provider's specific rate limit
            min_delay = provider_config.min_request_delay
        else:
            # Fallback to conservative default
            min_delay = 0.1

        last_request = self.provider_last_request.get(provider_id, 0)
        elapsed = time.time() - last_request

        if elapsed < min_delay:
            await asyncio.sleep(min_delay - elapsed)

        self.provider_last_request[provider_id] = time.time()

    def _create_chunks(
        self,
        from_block: int,
        to_block: int,
        num_providers: int,
    ) -> List[dict]:
        """Create block chunks distributed across providers.

        Each chunk size is determined by the assigned provider's max_block_range
        constraint. This ensures optimal performance by respecting each provider's
        capabilities.

        Args:
            from_block: Start block
            to_block: End block
            num_providers: Number of providers to distribute across

        Returns:
            List of chunk dicts with provider_id, from_block, to_block
        """
        chunks = []
        current_block = from_block
        provider_index = 0

        # Get healthy providers
        if self.rpc_manager:
            healthy_providers = self.rpc_manager.get_healthy_providers()
            provider_urls = [p.url for p in healthy_providers] if healthy_providers else []
        else:
            healthy_providers = [p for p in self.providers if p.is_healthy()]
            provider_urls = [p.url for p in healthy_providers] if healthy_providers else []

        if not provider_urls:
            # Fallback to all provider URLs
            provider_urls = [p.url for p in self.provider_configs]

        while current_block <= to_block:
            # Get the provider for this chunk
            provider_url = provider_urls[provider_index % len(provider_urls)]
            provider_config = self.provider_config_map.get(provider_url)

            # Determine chunk size based on provider's max_block_range
            if provider_config:
                # Use the smaller of configured chunk_size or provider's max_block_range
                provider_chunk_size = min(self.chunk_size, provider_config.max_block_range)
            else:
                provider_chunk_size = self.chunk_size

            chunk_end = min(current_block + provider_chunk_size - 1, to_block)

            chunks.append({
                "provider_id": provider_url,
                "from_block": current_block,
                "to_block": chunk_end,
            })

            current_block = chunk_end + 1
            provider_index += 1

        return chunks


# Convenience function for one-shot indexing
def index_token(
    database: DatabaseManager,
    token_address: str,
    chain_id: int = 1,
    deployment_block: Optional[int] = None,
    end_block: Optional[int] = None,
    force_rescan: bool = False,
) -> IndexProgress:
    """Synchronous wrapper for indexing token transfers.

    Args:
        database: Database manager
        token_address: Token contract address
        chain_id: Chain ID (default: 1)
        deployment_block: Deployment block (auto-discovered if None)
        end_block: Last block to scan (current block if None)
        force_rescan: Force rescan even if already indexed

    Returns:
        IndexProgress with final statistics
    """
    indexer = ParallelEventIndexer(database, chain_id)
    runner = get_shared_async_runner()

    async def _index():
        try:
            return await indexer.index_token_transfers(
                token_address, deployment_block, end_block, force_rescan
            )
        finally:
            await indexer.close()

    return runner.run(_index())
