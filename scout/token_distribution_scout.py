"""Token Distribution Scout for fetching holder data and calculating metrics.

This module supports two approaches for token distribution analysis:
1. RPC-based: Fetches balances directly via Multicall3 (original approach)
2. Event-based: Indexes Transfer events and replays them (scalable for high-volume tokens)

The event-based approach uses ParallelEventIndexer and BalanceReplayer for tokens
with millions of holders like USDT.
"""

from __future__ import annotations

import asyncio
import logging
import math
import os
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

import eth_abi
from web3 import Web3
from eth_utils import to_checksum_address

from .backend_client import BackendClient
from .balance_replayer import BalanceReplayer, DistributionMetrics as EventDistributionMetrics
from .database_manager import DatabaseManager
from .parallel_event_indexer import ParallelEventIndexer, index_token
from .rpc_pool import DEFAULT_RPC_ENDPOINTS, create_rpc_pool

LOGGER = logging.getLogger(__name__)

# ERC-20 Transfer event signature
TRANSFER_EVENT_SIGNATURE = Web3.keccak(text="Transfer(address,address,uint256)").hex()

# ERC-20 ABI for balanceOf function
ERC20_ABI = [
    {
        "constant": True,
        "inputs": [{"name": "_owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "balance", "type": "uint256"}],
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [],
        "name": "totalSupply",
        "outputs": [{"name": "totalSupply", "type": "uint256"}],
        "type": "function",
    },
]

# Multicall3 ABI (minimal - only the aggregate function)
MULTICALL3_ABI = [
    {
        "inputs": [
            {
                "components": [
                    {"internalType": "address", "name": "target", "type": "address"},
                    {"internalType": "bytes", "name": "callData", "type": "bytes"}
                ],
                "internalType": "struct Multicall3.Call[]",
                "name": "calls",
                "type": "tuple[]"
            }
        ],
        "name": "aggregate",
        "outputs": [
            {"internalType": "uint256", "name": "blockNumber", "type": "uint256"},
            {"internalType": "bytes[]", "name": "returnData", "type": "bytes[]"}
        ],
        "stateMutability": "payable",
        "type": "function"
    }
]

# balanceOf function signature for ERC20
BALANCE_OF_SIGNATURE = Web3.keccak(text="balanceOf(address,uint256)").hex()


@dataclass
class DistributionMetrics:
    """Token holder distribution metrics."""

    holder_count: int
    gini_coefficient: float
    nakamoto_coefficient: int
    top_10_pct_supply: float
    top_1_pct_supply: float
    max_balance: int
    total_supply: int
    transaction_count: int = 0
    last_scanned_block: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API serialization."""
        return {
            "holder_count": self.holder_count,
            "gini_coefficient": self.gini_coefficient,
            "nakamoto_coefficient": self.nakamoto_coefficient,
            "top_10_pct_supply": self.top_10_pct_supply,
            "top_1_pct_supply": self.top_1_pct_supply,
            "max_balance": str(self.max_balance),
            "total_supply": str(self.total_supply),
            "transaction_count": self.transaction_count,
            "last_scanned_block": self.last_scanned_block,
        }


@dataclass
class HolderData:
    """Individual token holder data."""

    address: str
    balance: int
    is_contract: bool
    percent_supply: float


class TokenDistributionScout:
    """Scout for fetching token holder distribution metrics.

    Supports two approaches:
    1. RPC-based: Direct balance fetching via Multicall3 (fast for small tokens)
    2. Event-based: Index + replay (scalable for tokens with 100K+ holders)
    """

    def __init__(
        self,
        database: DatabaseManager,
        backend_client: Optional[BackendClient] = None,
        rpc_pool_factory: Optional[Callable[[int], Any]] = None,
        max_parallel: int = 5,
        batch_size: int = 500,
        cache_hours: int = 24,
        use_event_replay: bool = False,
    ) -> None:
        """Initialize the Token Distribution Scout.

        Args:
            database: Database manager for state persistence
            backend_client: Optional HTTP client for backend API (only needed for sending results)
            rpc_pool_factory: Optional factory for creating RPC pools
            max_parallel: Maximum parallel RPC providers
            batch_size: Addresses per Multicall3 batch
            cache_hours: Cache validity in hours
            use_event_replay: If True, use event indexing approach (scalable for large tokens)
        """
        self.database = database
        self.backend_client = backend_client
        self.max_parallel = max_parallel
        self.batch_size = batch_size
        self.cache_hours = cache_hours
        self.use_event_replay = use_event_replay

        # RPC pool factory (use default if not provided)
        self.rpc_pool_factory = rpc_pool_factory or (
            lambda chain_id: create_rpc_pool(
                chain_id=chain_id,
                max_parallel=max_parallel,
                batch_size=batch_size,
            )
        )

        # Active RPC pools by chain
        self.rpc_pools: Dict[int, Any] = {}

        # Event-based components (lazy initialization)
        self._balance_replayer: Optional[BalanceReplayer] = None

        # Ensure schema exists
        self.database.ensure_token_distribution_schema()

    @property
    def balance_replayer(self) -> BalanceReplayer:
        """Get or create the balance replayer (lazy initialization)."""
        if self._balance_replayer is None:
            self._balance_replayer = BalanceReplayer(self.database)
        return self._balance_replayer

    def _get_rpc_pool(self, chain_id: int) -> Any:
        """Get or create RPC pool for a chain."""
        if chain_id not in self.rpc_pools:
            self.rpc_pools[chain_id] = self.rpc_pool_factory(chain_id)
        return self.rpc_pools[chain_id]

    async def analyze_token_distribution(
        self,
        token_address: str,
        chain_id: int = 1,
        from_block: Optional[int] = None,
        to_block: Optional[int] = None,
        force_refresh: bool = False,
        use_events: Optional[bool] = None,
    ) -> DistributionMetrics:
        """Analyze token holder distribution for a token.

        Args:
            token_address: Token contract address
            chain_id: Blockchain network ID
            from_block: Starting block for Transfer events (None for contract creation)
            to_block: Ending block (None for latest)
            force_refresh: Skip cache and force fresh analysis
            use_events: Force event-based mode (None = auto-detect based on indexed events)

        Returns:
            DistributionMetrics object with calculated metrics
        """
        # Check if events are indexed
        event_progress = self.database.get_event_scan_progress(token_address, chain_id)
        has_indexed_events = event_progress is not None and event_progress.get("last_scanned_block")

        # Determine which approach to use
        will_use_events = use_events if use_events is not None else (has_indexed_events or self.use_event_replay)

        if will_use_events and has_indexed_events:
            # Event-based approach: Use balance replayer (fast, no RPC calls)
            LOGGER.info(
                "Using event-based analysis (indexed events available)",
                extra={"token": token_address, "chain_id": chain_id},
            )
            return self._analyze_from_events(
                token_address, chain_id, to_block, force_refresh
            )
        elif will_use_events:
            # Events requested but not indexed - need to index first
            LOGGER.info(
                "Events requested but not indexed - triggering parallel indexing",
                extra={"token": token_address, "chain_id": chain_id},
            )
            await self._ensure_events_indexed(token_address, chain_id, from_block, to_block)
            return self._analyze_from_events(
                token_address, chain_id, to_block, force_refresh
            )
        else:
            # RPC-based approach (original method)
            LOGGER.info(
                "Using RPC-based analysis",
                extra={"token": token_address, "chain_id": chain_id},
            )
            return await self._analyze_via_rpc(
                token_address, chain_id, from_block, to_block, force_refresh
            )

    def _analyze_from_events(
        self,
        token_address: str,
        chain_id: int,
        to_block: Optional[int],
        force_refresh: bool,
    ) -> DistributionMetrics:
        """Analyze distribution using indexed events (no RPC calls).

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            to_block: Only include events up to this block
            force_refresh: Whether to refresh balance cache

        Returns:
            DistributionMetrics with calculated metrics
        """
        start_time = time.time()

        # Calculate metrics from stored events
        event_metrics = self.balance_replayer.calculate_distribution_metrics(
            token_address, chain_id, to_block
        )

        elapsed = time.time() - start_time
        LOGGER.info(
            "Event-based analysis complete",
            extra={
                "token": token_address,
                "chain_id": chain_id,
                "holders": event_metrics.holder_count,
                "elapsed_seconds": elapsed,
            },
        )

        # Convert to DistributionMetrics format
        return DistributionMetrics(
            holder_count=event_metrics.holder_count,
            gini_coefficient=event_metrics.gini_coefficient,
            nakamoto_coefficient=event_metrics.nakamoto_coefficient,
            top_10_pct_supply=event_metrics.top_10_pct_supply,
            top_1_pct_supply=event_metrics.top_1_pct_supply,
            max_balance=event_metrics.max_balance,
            total_supply=event_metrics.total_supply,
            transaction_count=event_metrics.transaction_count,
            last_scanned_block=event_metrics.last_scanned_block,
        )

    async def _ensure_events_indexed(
        self,
        token_address: str,
        chain_id: int,
        from_block: Optional[int],
        to_block: Optional[int],
    ) -> None:
        """Ensure Transfer events are indexed for a token.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            from_block: Start block (None for deployment)
            to_block: End block (None for current)
        """
        # Check if already indexed
        progress = self.database.get_event_scan_progress(token_address, chain_id)
        if progress and progress["last_scanned_block"]:
            LOGGER.info(
                f"Events already indexed up to block {progress['last_scanned_block']}, "
                f"updating to latest..."
            )
            from_block = progress["last_scanned_block"] + 1

        # Run parallel indexer
        indexer = ParallelEventIndexer(self.database, chain_id)
        try:
            index_progress = await indexer.index_token_transfers(
                token_address,
                deployment_block=from_block,
                end_block=to_block,
            )
            LOGGER.info(
                f"Event indexing complete: {index_progress.total_events:,} events, "
                f"blocks {index_progress.first_block:,} to {index_progress.last_block:,}"
            )
        finally:
            await indexer.close()

    async def _analyze_via_rpc(
        self,
        token_address: str,
        chain_id: int,
        from_block: Optional[int],
        to_block: Optional[int],
        force_refresh: bool,
    ) -> DistributionMetrics:
        """Analyze distribution using RPC calls (original approach).

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            from_block: Starting block for Transfer events
            to_block: Ending block (None for latest)
            force_refresh: Skip cache and force fresh analysis

        Returns:
            DistributionMetrics with calculated metrics
        """
        # Check cache first
        if not force_refresh:
            cached = self._get_cached_metrics(token_address, chain_id)
            if cached:
                LOGGER.info(
                    "Using cached metrics",
                    extra={"token": token_address, "chain_id": chain_id},
                )
                return cached

        LOGGER.info(
            "Starting token distribution analysis via RPC",
            extra={"token": token_address, "chain_id": chain_id},
        )

        start_time = time.time()

        # Step 1: Discover holders from Transfer events
        holders, transaction_count, last_scanned_block, last_tx_hash = await self._discover_holders(
            token_address, chain_id, from_block, to_block
        )

        if not holders:
            LOGGER.warning(f"No holders found for token {token_address}")
            # Return empty metrics
            return DistributionMetrics(
                holder_count=0,
                gini_coefficient=0.0,
                nakamoto_coefficient=0,
                top_10_pct_supply=0.0,
                top_1_pct_supply=0.0,
                max_balance=0,
                total_supply=0,
                transaction_count=transaction_count,
                last_scanned_block=last_scanned_block,
            )

        # Step 2: Fetch balances in parallel
        balances = await self._fetch_balances(
            token_address, chain_id, list(holders), to_block or "latest"
        )

        # Step 3: Detect smart contracts
        contract_status = await self._detect_contracts(
            chain_id, list(balances.keys()), to_block or "latest"
        )

        # Step 4: Calculate metrics (with transaction count)
        metrics = self._calculate_metrics(balances, transaction_count)

        # Update metrics with last scanned block
        metrics.last_scanned_block = last_scanned_block

        # Step 5: Store in database
        self._store_results(
            token_address, chain_id, balances, contract_status, metrics
        )

        # Step 5.5: Store scan progress for incremental scanning
        actual_from_block = from_block
        if actual_from_block is None:
            # Get the actual from_block used
            progress = self.database.get_token_scan_progress(token_address, chain_id)
            if progress["last_scanned_block"]:
                actual_from_block = progress["last_scanned_block"] + 1
            else:
                latest_block = last_scanned_block or to_block
                actual_from_block = max(0, latest_block - 100000)

        self.database.update_token_scan_progress(
            token_address=token_address,
            chain_id=chain_id,
            from_block=actual_from_block,
            to_block=to_block or last_scanned_block,
            last_scanned_block=last_scanned_block,
            transaction_count=transaction_count,
            last_tx_hash=last_tx_hash
        )

        # Step 6: Send to backend if project ID is known
        await self._send_to_backend(token_address, chain_id, metrics)

        elapsed = time.time() - start_time
        LOGGER.info(
            "Token distribution analysis complete",
            extra={
                "token": token_address,
                "chain_id": chain_id,
                "holders": metrics.holder_count,
                "transactions": transaction_count,
                "last_scanned_block": last_scanned_block,
                "elapsed_seconds": elapsed,
            },
        )

        return metrics

    async def _discover_holders(
        self,
        token_address: str,
        chain_id: int,
        from_block: Optional[int],
        to_block: Optional[int],
    ) -> tuple:
        """Discover unique holder addresses from Transfer events.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            from_block: Starting block (None for last scanned block or default)
            to_block: Ending block (None for latest)

        Returns:
            Tuple of (holders set, transaction count, last scanned block, last tx hash)
        """
        rpc_pool = self._get_rpc_pool(chain_id)

        # Get a healthy provider
        providers = rpc_pool.get_healthy_providers()
        if not providers:
            LOGGER.error("No healthy RPC providers available")
            return set(), 0, None, None

        provider = providers[0]

        # Get block range - check for incremental scanning
        if from_block is None:
            # Check if we have a previous scan to continue from
            progress = self.database.get_token_scan_progress(token_address, chain_id)
            if progress["last_scanned_block"]:
                # Continue from where we left off
                from_block = progress["last_scanned_block"] + 1
                LOGGER.info(f"Continuing from last scanned block: {from_block}")
            else:
                # For simplicity, use a recent block range (last 100k blocks)
                # In production, you'd want to find the contract deployment block
                latest_block = await self._get_latest_block(provider)
                from_block = max(0, latest_block - 100000)

        if to_block is None or to_block == "latest":
            to_block = await self._get_latest_block(provider)

        LOGGER.info(
            "Discovering holders from Transfer events",
            extra={
                "token": token_address,
                "chain_id": chain_id,
                "from_block": from_block,
                "to_block": to_block,
            },
        )

        holders = set()
        total_transactions = 0
        last_scanned_block = from_block
        last_tx_hash = None

        # Fetch Transfer events using getLogs
        try:
            # Use eth_getLogs to fetch Transfer events
            # Use smaller chunk size (5k blocks) for better compatibility with free RPCs
            chunk_size = 5000
            current_from = from_block

            chunk_count = 0
            failed_chunks = 0
            max_consecutive_failures = 3

            while current_from <= to_block:
                current_to = min(current_from + chunk_size - 1, to_block)
                chunk_count += 1

                try:
                    LOGGER.debug(f"Fetching logs for blocks {current_from}-{current_to} (chunk {chunk_count})")
                    logs = await self._get_logs(
                        provider,
                        token_address,
                        TRANSFER_EVENT_SIGNATURE,
                        current_from,
                        current_to
                    )

                    # Reset consecutive failure counter on success
                    failed_chunks = 0

                    # Extract addresses from logs and count transactions
                    for log in logs:
                        topics = log.get("topics", [])
                        data = log.get("data", "")
                        tx_hash = log.get("transactionHash", "")
                        block_num = log.get("blockNumber", "")

                        # Count transactions
                        total_transactions += 1
                        last_tx_hash = tx_hash
                        if block_num:
                            last_scanned_block = int(block_num, 16)

                        # topics[0] is the event signature
                        # topics[1] is the from address (indexed)
                        # topics[2] is the to address (indexed)
                        # data is the value (uint256, not indexed)

                        if len(topics) >= 3:
                            from_addr = topics[1]
                            to_addr = topics[2]

                            # Add "from" address (except zero address which is burning/minting)
                            if from_addr and from_addr != "0x0000000000000000000000000000000000000000":
                                # Remove padding and convert to checksum address
                                from_addr_clean = "0x" + from_addr[-40:]
                                holders.add(to_checksum_address(from_addr_clean))

                            # Add "to" address (except zero address)
                            if to_addr and to_addr != "0x0000000000000000000000000000000000000000":
                                to_addr_clean = "0x" + to_addr[-40:]
                                holders.add(to_checksum_address(to_addr_clean))

                    LOGGER.debug(f"Fetched {len(logs)} Transfer events from blocks {current_from}-{current_to}")

                except Exception as exc:
                    failed_chunks += 1
                    LOGGER.warning(f"Failed to fetch logs for blocks {current_from}-{current_to}: {exc}")

                    # Stop if too many consecutive failures
                    if failed_chunks >= max_consecutive_failures:
                        LOGGER.error(f"Too many consecutive failures ({max_consecutive_failures}), stopping holder discovery")
                        break

                    # Try next provider if available
                    providers = self._get_rpc_pool(chain_id).get_healthy_providers()
                    if len(providers) > 1:
                        provider = providers[chunk_count % len(providers)]
                        LOGGER.info(f"Switching to different RPC provider")

                current_from = current_to + 1

            LOGGER.info(f"Discovered {len(holders)} unique holder addresses and {total_transactions} transactions")

        except Exception as exc:
            LOGGER.error(f"Failed to discover holders: {exc}")

        return holders, total_transactions, last_scanned_block, last_tx_hash

    async def _get_latest_block(self, provider: Any) -> int:
        """Get the latest block number from a provider."""
        try:
            result = await provider.make_request("eth_blockNumber", [])
            if result and isinstance(result, str):
                return int(result, 16)
            return 0
        except Exception as exc:
            LOGGER.error(f"Failed to get latest block: {exc}")
            return 0

    async def _get_logs(
        self,
        provider: Any,
        address: str,
        topic: str,
        from_block: int,
        to_block: int
    ) -> List[Dict]:
        """Get logs using eth_getLogs."""
        try:
            # Ensure address is checksummed
            checksum_address = to_checksum_address(address)

            # Ensure topic has 0x prefix
            if not topic.startswith("0x"):
                topic = "0x" + topic

            result = await provider.make_request(
                "eth_getLogs",
                [{
                    "address": checksum_address,
                    "topics": [topic],
                    "fromBlock": f"0x{from_block:x}",
                    "toBlock": f"0x{to_block:x}",
                }]
            )

            if result and isinstance(result, list):
                return result
            return []
        except Exception as exc:
            LOGGER.error(f"eth_getLogs failed: {exc}")
            return []

    async def _get_deployment_block(
        self, token_address: str, chain_id: int
    ) -> Optional[int]:
        """Get the block number when a contract was deployed.

        Args:
            token_address: Token contract address
            chain_id: Chain ID

        Returns:
            Block number or None
        """
        # This would use an explorer API or scan backwards
        # For now, return None to scan from genesis
        return None

    async def _fetch_balances(
        self,
        token_address: str,
        chain_id: int,
        addresses: List[str],
        block_number: Any,
    ) -> Dict[str, int]:
        """Fetch balances for multiple addresses in parallel.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            addresses: List of holder addresses
            block_number: Block number

        Returns:
            Dictionary mapping address to balance
        """
        rpc_pool = self._get_rpc_pool(chain_id)

        # Use RPC pool's batch balanceOf calls
        balances = await rpc_pool.batch_balance_of_calls(
            token_address, addresses, block_number
        )

        # Filter out zero balances
        return {addr: bal for addr, bal in balances.items() if bal > 0}

    async def _detect_contracts(
        self, chain_id: int, addresses: List[str], block_number: Any
    ) -> Dict[str, bool]:
        """Detect which addresses are smart contracts.

        Args:
            chain_id: Chain ID
            addresses: List of addresses to check
            block_number: Block number

        Returns:
            Dictionary mapping address to is_contract boolean
        """
        rpc_pool = self._get_rpc_pool(chain_id)

        # Use RPC pool's batch eth_getCode calls
        return await rpc_pool.batch_is_contract_calls(addresses, block_number)

    def _calculate_metrics(self, balances: Dict[str, int], transaction_count: int = 0) -> DistributionMetrics:
        """Calculate distribution metrics from balances.

        Args:
            balances: Dictionary mapping address to balance
            transaction_count: Total number of Transfer events found

        Returns:
            DistributionMetrics object
        """
        if not balances:
            return DistributionMetrics(
                holder_count=0,
                gini_coefficient=0.0,
                nakamoto_coefficient=0,
                top_10_pct_supply=0.0,
                top_1_pct_supply=0.0,
                max_balance=0,
                total_supply=0,
                transaction_count=transaction_count,
            )

        # Sort balances descending
        sorted_balances = sorted(balances.values(), reverse=True)
        total_supply = sum(sorted_balances)
        holder_count = len(sorted_balances)

        # Gini coefficient
        gini = self._calculate_gini(sorted_balances)

        # Nakamoto coefficient (holders for 51%)
        nakamoto = self._calculate_nakamoto(sorted_balances, total_supply)

        # Top 1% and 10% concentration
        top_n_10_pct = max(1, holder_count // 10)
        top_n_1_pct = max(1, holder_count // 100)

        top_10_supply = sum(sorted_balances[:top_n_10_pct])
        top_1_supply = sum(sorted_balances[:top_n_1_pct])

        top_10_pct = (top_10_supply / total_supply * 100) if total_supply > 0 else 0
        top_1_pct = (top_1_supply / total_supply * 100) if total_supply > 0 else 0

        return DistributionMetrics(
            holder_count=holder_count,
            gini_coefficient=round(gini, 4),
            nakamoto_coefficient=nakamoto,
            top_10_pct_supply=round(top_10_pct, 3),
            top_1_pct_supply=round(top_1_pct, 3),
            max_balance=sorted_balances[0],
            total_supply=total_supply,
            transaction_count=transaction_count,
        )

    def _calculate_gini(self, sorted_balances: List[int]) -> float:
        """Calculate Gini coefficient from sorted balances.

        Args:
            sorted_balances: List of balances sorted descending

        Returns:
            Gini coefficient (0-1)
        """
        n = len(sorted_balances)
        if n == 0:
            return 0.0

        total = sum(sorted_balances)
        if total == 0:
            return 0.0

        # Gini formula requires ascending order (smallest to largest)
        # Reverse the descending-sorted balances for the calculation
        ascending_balances = list(reversed(sorted_balances))

        # Calculate Gini using formula
        # G = (2 * sum of (i * x_i)) / (n * sum(x_i)) - (n + 1) / n
        # where i is rank (1 to n) and x_i is balance at rank i (ascending order)

        weighted_sum = sum(
            (i + 1) * balance for i, balance in enumerate(ascending_balances)
        )
        gini = (2 * weighted_sum) / (n * total) - (n + 1) / n

        return max(0.0, min(1.0, gini))

    def _calculate_nakamoto(
        self, sorted_balances: List[int], total_supply: int
    ) -> int:
        """Calculate Nakamoto coefficient (holders for 51%).

        Args:
            sorted_balances: List of balances sorted descending
            total_supply: Total token supply

        Returns:
            Nakamoto coefficient
        """
        if total_supply == 0:
            return 0

        cumulative = 0
        for i, balance in enumerate(sorted_balances):
            cumulative += balance
            if cumulative > total_supply / 2:
                return i + 1

        return len(sorted_balances)

    def _store_results(
        self,
        token_address: str,
        chain_id: int,
        balances: Dict[str, int],
        contract_status: Dict[str, bool],
        metrics: DistributionMetrics,
    ) -> None:
        """Store analysis results in database.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            balances: Balance data
            contract_status: Smart contract detection results
            metrics: Calculated metrics
        """
        with self.database.write_connection() as conn:
            # Store metrics cache
            conn.execute(
                """
                INSERT OR REPLACE INTO token_distribution_cache
                (token_address, chain_id, holder_count, gini_coefficient,
                 nakamoto_coefficient, top_10_pct, cached_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    token_address.lower(),
                    chain_id,
                    metrics.holder_count,
                    metrics.gini_coefficient,
                    metrics.nakamoto_coefficient,
                    metrics.top_10_pct_supply,
                    int(time.time()),
                ),
            )

            # Store holder data
            for address, balance in balances.items():
                conn.execute(
                    """
                    INSERT OR REPLACE INTO token_holders_processed
                    (token_address, chain_id, holder_address, balance, is_contract, processed_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        token_address.lower(),
                        chain_id,
                        address.lower(),
                        str(balance),
                        1 if contract_status.get(address, False) else 0,
                        int(time.time()),
                    ),
                )

        LOGGER.info(
            "Stored results in database",
            extra={
                "token": token_address,
                "chain_id": chain_id,
                "holders": metrics.holder_count,
            },
        )

    def _get_cached_metrics(
        self, token_address: str, chain_id: int
    ) -> Optional[DistributionMetrics]:
        """Get cached metrics if available and not expired.

        Args:
            token_address: Token contract address
            chain_id: Chain ID

        Returns:
            Cached metrics or None
        """
        with self.database.read_connection() as conn:
            row = conn.execute(
                """
                SELECT holder_count, gini_coefficient, nakamoto_coefficient,
                       top_10_pct, cached_at
                FROM token_distribution_cache
                WHERE token_address = ? AND chain_id = ?
                """,
                (token_address.lower(), chain_id),
            ).fetchone()

        if not row:
            return None

        # Check if cache is still valid
        cache_age = (time.time() - row["cached_at"]) / 3600  # Convert to hours
        if cache_age > self.cache_hours:
            return None

        return DistributionMetrics(
            holder_count=row["holder_count"],
            gini_coefficient=row["gini_coefficient"],
            nakamoto_coefficient=row["nakamoto_coefficient"],
            top_10_pct_supply=row["top_10_pct"],
            top_1_pct_supply=0.0,  # Not cached
            max_balance=0,  # Not cached
            total_supply=0,  # Not cached
        )

    async def _send_to_backend(
        self, token_address: str, chain_id: int, metrics: DistributionMetrics
    ) -> None:
        """Send metrics to backend API.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            metrics: Calculated metrics
        """
        # Skip if backend client not configured
        if not self.backend_client:
            LOGGER.debug("Backend client not configured, skipping metrics upload")
            return

        # Check if we have a project mapping
        project_id = self.database.get_project_mapping(token_address.lower())
        if not project_id:
            LOGGER.info(f"No project mapping for token {token_address}")
            return

        try:
            response = self.backend_client.patch(
                f"projects/{project_id}/distribution-metrics",
                json=metrics.to_dict(),
            )

            if response and response.status_code == 200:
                LOGGER.info(f"Sent metrics to backend for project {project_id}")
            else:
                LOGGER.warning(f"Failed to send metrics: {response.status_code if response else 'No response'}")

        except Exception as exc:
            LOGGER.error(f"Failed to send metrics to backend: {exc}")

    async def close_async(self) -> None:
        """Close all RPC pools asynchronously."""
        for pool in self.rpc_pools.values():
            try:
                await pool.close()
            except Exception as exc:
                LOGGER.error(f"Failed to close RPC pool: {exc}")

    def close(self) -> None:
        """Close all RPC pools (synchronous wrapper).

        Note: This should be called from the async runner to ensure proper cleanup.
        """
        # Get the shared async runner and submit the close coroutine
        from .async_runner import get_shared_async_runner
        try:
            runner = get_shared_async_runner()
            # Submit and don't wait for completion to avoid deadlock
            runner.submit(self.close_async())
        except Exception as exc:
            LOGGER.error(f"Failed to initiate RPC pool cleanup: {exc}")

    @classmethod
    def from_env(
        cls,
        database: DatabaseManager,
        backend_client: Optional[BackendClient] = None,
    ) -> "TokenDistributionScout":
        """Create TokenDistributionScout from environment configuration.

        Args:
            database: Database manager
            backend_client: Backend API client (optional, only needed for sending results)

        Returns:
            Configured TokenDistributionScout instance
        """
        max_parallel = int(os.getenv("DISTRIBUTION_MAX_PARALLEL", "5"))
        batch_size = int(os.getenv("DISTRIBUTION_BATCH_SIZE", "500"))
        cache_hours = int(os.getenv("DISTRIBUTION_CACHE_HOURS", "24"))
        use_event_replay = os.getenv("DISTRIBUTION_USE_EVENT_REPLAY", "").lower() == "true"

        return cls(
            database=database,
            backend_client=backend_client,
            max_parallel=max_parallel,
            batch_size=batch_size,
            cache_hours=cache_hours,
            use_event_replay=use_event_replay,
        )

