"""USDT Payment Scout module implementing payment event monitoring across multiple networks."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import logging
import os
import signal
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, NewType, Optional, Sequence, Tuple, Union

import requests
from requests import Response
from web3 import Web3
from web3._utils.events import get_event_data
from web3.datastructures import AttributeDict
from web3.types import FilterParams, LogReceipt

try:  # pragma: no cover - compatibility with older web3 versions
    from web3.types import HexStr
except ImportError:  # pragma: no cover - fallback for environments without HexStr
    HexStr = NewType("HexStr", str)

from .async_runner import get_shared_async_runner
from .backend_client import BackendClient
from .database_manager import DatabaseManager
from .env_loader import load_env_file
from .shared_rpc_manager import create_rpc_manager
from .websocket_helpers import iter_websocket_messages
from .websocket_provider_pool import WebSocketProviderHandle, WebSocketProviderPool

LOGGER = logging.getLogger(__name__)

# USDT Contract Addresses by Network
USDT_CONTRACTS = {
    "ethereum": "0xdAC17F958D2ee523a2206206994597C13D831ec7",  # Ethereum mainnet
    "polygon": "0xc2132D05D31c914a87C6611C10748AEb04B58e8F",   # Polygon mainnet
    "bsc": "0x55d398326f99059fF775485246999027B3197955",        # BNB Chain
    "arbitrum": "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9",   # Arbitrum One
    "optimism": "0x94b008aA00579c1307B0EF2c499aD98a8ce58e58",   # Optimism
    "avalanche": "0x9702230A8Ea53601f5cD5dc609C4D663bC8fA6a6",  # Avalanche
}

# Network to Chain ID mapping for unified RPC manager
NETWORK_CHAIN_IDS = {
    "ethereum": 1,
    "polygon": 137,
    "bsc": 56,
    "arbitrum": 42161,
    "optimism": 10,
    "avalanche": 43114,
}

# ERC-20 USDT Transfer Event ABI
USDT_TRANSFER_EVENT_ABI = {
    "anonymous": False,
    "inputs": [
        {"indexed": True, "name": "from", "type": "address"},
        {"indexed": True, "name": "to", "type": "address"},
        {"indexed": False, "name": "value", "type": "uint256"},
    ],
    "name": "Transfer",
    "type": "event",
}

# Network-specific RPC configurations
NETWORK_RPCS = {
    "ethereum": [
        "https://rpc.coinsdo.net/eth",
        "https://ethereum.public.blockpi.network/v1/rpc/public",
        "https://ethereum-rpc.publicnode.com",
    ],
    "polygon": [
        "https://polygon-rpc.com",
        "https://rpc.ankr.com/polygon",
        "https://polygonapi.terminet.io/rpc",
        "https://rpc-mainnet.matic.network",
    ],
    "bsc": [
        "https://bsc-dataseed.binance.org",
        "https://bsc-dataseed1.defibit.io",
        "https://bsc-dataseed1.ninicoin.io",
        "https://rpc.ankr.com/bsc",
    ],
    "arbitrum": [
        "https://arb1.arbitrum.io/rpc",
        "https://arbitrum.gateway.tenderly.co",
        "https://rpc.ankr.com/arbitrum",
        "https://endpoints.omniatech.io/v1/arbitrum/093e28c96c4a46a8bdc9d1b3e5a273f9",
    ],
    "optimism": [
        "https://mainnet.optimism.io",
        "https://rpc.ankr.com/optimism",
        "https://optimism.gateway.tenderly.co",
        "https://rpc-mainnet.maticvigil.com",
    ],
    "avalanche": [
        "https://api.avax.network/ext/bc/C/rpc",
        "https://rpc.ankr.com/avalanche",
        "https://ava-mainnet.rpc.ankr.com",
        "https://endpoints.omniatech.io/v1/avax/mainnet/053581764d2949b8bfce04e36103c35f",
    ],
}

@dataclass
class USDTNetworkConfig:
    """Configuration for a specific USDT network."""
    network: str
    contract_address: str
    rpc_urls: List[str]
    ws_urls: Optional[List[str]] = None
    enabled: bool = True
    start_block: Optional[int] = None
    confirmations: int = 12  # Number of blocks to wait for confirmation

@dataclass
class PaymentEvent:
    """Represents a USDT payment event."""
    transaction_hash: str
    from_address: str
    to_address: str
    amount: str  # USDT amount in smallest units (6 decimals)
    block_number: int
    transaction_index: int
    log_index: int
    timestamp: Optional[int] = None
    network: str = "ethereum"
    processed: bool = False
    backend_notified: bool = False
    error_message: Optional[str] = None
    created_at: float = field(default_factory=time.time)

@dataclass
class USDTConfig:
    """Configuration for USDT payment monitoring."""
    # Wallet monitoring
    target_wallet: str
    networks: List[str] = field(default_factory=lambda: ["ethereum"])

    # Event processing
    confirmations: int = 12
    poll_interval: int = 8
    batch_size: int = 1000
    max_block_range: int = 50000

    # Pro subscription settings
    pro_tier_duration_days: int = 30
    pro_tier_level: int = 3  # Maximum pro tier

    # Retry and error handling
    max_retries: int = 5
    retry_delay: float = 1.0
    notification_timeout: int = 30

def resolve_ws_provider_class() -> Optional[type]:
    """Return the first available websocket provider class for the current web3 install."""

    with contextlib.suppress(ImportError, AttributeError):
        from web3.providers.persistent import WebSocketProvider as provider

        if isinstance(provider, type):
            return provider
    with contextlib.suppress(ImportError, AttributeError):
        # Web3's persistent AsyncWebSocketProvider exposes coroutine-based APIs
        # that are incompatible with the synchronous workflow used by the
        # project.
        from web3.providers.websocket import WebSocketProvider as provider

        if isinstance(provider, type):
            return provider
    with contextlib.suppress(ImportError, AttributeError):
        # The WebSocket provider was renamed in v6 of Web3.
        from web3.providers.rpc import HTTPProvider as provider

        if isinstance(provider, type):
            return None
    with contextlib.suppress(ImportError, AttributeError):
        # Web3 v6 introduced a new module structure for providers.
        from web3.providers.websocket import WebsocketProviderV2 as provider

        if isinstance(provider, type):
            return provider
    return None


class USDTPaymentScout:
    """Scout responsible for monitoring USDT payments to the admin wallet."""

    def __init__(
        self,
        config: USDTConfig,
        database: DatabaseManager,
        backend_client: BackendClient,
        *,
        ws_provider_pool: Optional[WebSocketProviderPool] = None,
    ) -> None:
        """Initialize the USDT Payment Scout.

        Args:
            config: Configuration for USDT payment monitoring
            database: Database manager for persistent storage
            backend_client: Backend client for API communication
            ws_provider_pool: Optional WebSocket provider pool for real-time monitoring
        """
        self._config = config
        self._database = database
        self._backend = backend_client
        self._ws_provider_pool = ws_provider_pool

        # Feature flag for unified RPC manager
        self._use_unified_rpc = os.environ.get("USE_UNIFIED_RPC", "false").lower() == "true"

        # Unified RPC managers per network (when feature flag is enabled)
        self._rpc_managers: Dict[str, Any] = {}

        # Network configurations
        self._network_configs = {}
        for network in config.networks:
            if network in USDT_CONTRACTS:
                rpc_urls = NETWORK_RPCS.get(network, [])

                # Use unified RPC manager if feature flag is enabled
                if self._use_unified_rpc and network in NETWORK_CHAIN_IDS:
                    try:
                        chain_id = NETWORK_CHAIN_IDS[network]
                        rpc_manager = create_rpc_manager(
                            chain_id=chain_id,
                            db_manager=database
                        )
                        self._rpc_managers[network] = rpc_manager
                        # Get RPC URLs from unified providers
                        rpc_urls = [p.url for p in rpc_manager.providers.values()]
                        LOGGER.info(f"Using unified RPC manager for {network} ({chain_id}) with {len(rpc_urls)} providers")
                    except Exception as e:
                        LOGGER.warning(f"Failed to create unified RPC manager for {network}: {e}, falling back to hardcoded URLs")

                if not rpc_urls:
                    LOGGER.warning(f"No RPC URLs available for {network}, skipping network")
                    continue

                self._network_configs[network] = USDTNetworkConfig(
                    network=network,
                    contract_address=USDT_CONTRACTS[network],
                    rpc_urls=rpc_urls,
                    confirmations=config.confirmations,
                    enabled=True
                )

        # State management
        self._lock = threading.RLock()
        self._running = False
        self._stopped = threading.Event()
        self._web3_connections: Dict[str, Web3] = {}
        self._active_rpc_indices: Dict[str, int] = {}

        # Ensure database schema
        self._ensure_database_schema()

        LOGGER.info("USDT Payment Scout initialized for wallet %s on networks %s",
                   config.target_wallet, list(self._network_configs.keys()))

    def _ensure_database_schema(self) -> None:
        """Create database tables needed for USDT payment monitoring."""
        with self._database.write_connection() as conn:
            # Payment events table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS usdt_payment_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    transaction_hash TEXT NOT NULL,
                    from_address TEXT NOT NULL,
                    to_address TEXT NOT NULL,
                    amount TEXT NOT NULL,
                    block_number INTEGER NOT NULL,
                    transaction_index INTEGER NOT NULL,
                    log_index INTEGER NOT NULL,
                    timestamp INTEGER,
                    network TEXT NOT NULL DEFAULT 'ethereum',
                    processed BOOLEAN DEFAULT FALSE,
                    backend_notified BOOLEAN DEFAULT FALSE,
                    error_message TEXT,
                    created_at REAL NOT NULL,
                    UNIQUE(transaction_hash, log_index, network)
                )
            """)

            # Indexes for performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_usdt_events_to_address ON usdt_payment_events(to_address)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_usdt_events_processed ON usdt_payment_events(processed)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_usdt_events_network ON usdt_payment_events(network)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_usdt_events_block ON usdt_payment_events(block_number)")

            # Network progress tracking
            conn.execute("""
                CREATE TABLE IF NOT EXISTS usdt_network_progress (
                    network TEXT PRIMARY KEY,
                    last_processed_block INTEGER NOT NULL,
                    last_updated REAL NOT NULL
                )
            """)

            conn.commit()

    def _get_or_create_web3_connection(self, network: str, block_number: Optional[int] = None) -> Web3:
        """Get or create a Web3 connection for a specific network.

        When using unified RPC manager, selects the best provider for the given block.
        """
        if network not in self._web3_connections:
            network_config = self._network_configs[network]
            rpc_urls = network_config.rpc_urls

            # Use block-aware provider selection if unified RPC is enabled
            if self._use_unified_rpc and network in self._rpc_managers:
                rpc_manager = self._rpc_managers[network]
                try:
                    current_block = block_number or 0
                    # Get best provider for this block
                    provider = rpc_manager.get_provider_for_block(
                        block_number=current_block,
                        method='eth_getLogs'
                    )
                    if provider:
                        # Find the index of this provider in our URLs list
                        try:
                            preferred_url = provider.url
                            if preferred_url in rpc_urls:
                                rpc_index = rpc_urls.index(preferred_url)
                                self._active_rpc_indices[network] = rpc_index
                                LOGGER.debug(f"Using unified RPC selection for {network} at block {current_block}: {preferred_url}")
                        except ValueError:
                            pass  # Provider URL not in our list, use default
                except Exception as e:
                    LOGGER.debug(f"Block-aware provider selection failed for {network}: {e}")

            rpc_index = self._active_rpc_indices.get(network, 0)
            rpc_urls = network_config.rpc_urls

            # Try RPC URLs in sequence until we find a working one
            for i, rpc_url in enumerate(rpc_urls):
                try:
                    w3 = Web3(Web3.HTTPProvider(rpc_url))
                    if w3.is_connected():
                        self._web3_connections[network] = w3
                        self._active_rpc_indices[network] = i
                        LOGGER.info(f"Connected to {network} via {rpc_url}")
                        break
                except Exception as e:
                    LOGGER.warning(f"Failed to connect to {network} RPC {rpc_url}: {e}")
                    continue

            if network not in self._web3_connections:
                raise Exception(f"Failed to connect to any {network} RPC")

        return self._web3_connections[network]

    def _get_last_processed_block(self, network: str) -> int:
        """Get the last processed block number for a network."""
        with self._database.read_connection() as conn:
            cursor = conn.execute(
                "SELECT last_processed_block FROM usdt_network_progress WHERE network = ?",
                (network,)
            )
            result = cursor.fetchone()
            return result[0] if result else self._network_configs[network].start_block or 0

    def _update_last_processed_block(self, network: str, block_number: int) -> None:
        """Update the last processed block number for a network."""
        with self._database.write_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO usdt_network_progress (network, last_processed_block, last_updated)
                VALUES (?, ?, ?)
            """, (network, block_number, time.time()))
            conn.commit()

    def _process_payment_event(self, event: PaymentEvent) -> bool:
        """Process a USDT payment event and notify the backend."""
        try:
            LOGGER.info(f"Processing USDT payment: {event.amount} USDT from {event.from_address} to {event.to_address}")

            # Get user information for the sender
            user_address = event.from_address.lower()

            # Update user's pro status in backend
            user_data = {
                "wallet_address": user_address,
                "pro_status": True,
                "pro_tier": self._config.pro_tier_level,
                "pro_expires_at": int(time.time()) + (self._config.pro_tier_duration_days * 24 * 60 * 60)
            }

            # Try to update user's pro status
            response = self._backend.patch(f"/users/{user_address}", json=user_data)

            if response.ok:
                LOGGER.info(f"Successfully granted pro status to user {user_address} for USDT payment {event.transaction_hash}")

                # Mark event as processed
                self._mark_event_processed(event, None)
                return True
            else:
                error_msg = f"Failed to update user pro status: {response.status_code}"
                self._mark_event_processed(event, error_msg)
                return False

        except Exception as e:
            error_msg = f"Error processing payment event: {e}"
            LOGGER.error(f"{error_msg} - Event: {event.transaction_hash}")
            self._mark_event_processed(event, error_msg)
            return False

    def _mark_event_processed(self, event: PaymentEvent, error_message: Optional[str]) -> None:
        """Mark an event as processed in the database."""
        with self._database.write_connection() as conn:
            conn.execute("""
                UPDATE usdt_payment_events
                SET processed = TRUE,
                    backend_notified = ?,
                    error_message = ?
                WHERE transaction_hash = ? AND log_index = ? AND network = ?
            """, (error_message is None, error_message, event.transaction_hash, event.log_index, event.network))
            conn.commit()

    def _fetch_payment_events(self, network: str, from_block: int, to_block: int) -> List[PaymentEvent]:
        """Fetch USDT transfer events for a network and block range."""
        try:
            # Get web3 connection with block-aware provider selection
            w3 = self._get_or_create_web3_connection(network, block_number=from_block)
            contract_address = self._network_configs[network].contract_address
            target_wallet = self._config.target_wallet.lower()

            # Get current RPC URL for failure tracking
            current_rpc_index = self._active_rpc_indices.get(network, 0)
            current_rpc_url = self._network_configs[network].rpc_urls[current_rpc_index]

            # Create filter for transfers TO the target wallet
            filter_params = {
                "address": contract_address,
                "topics": [
                    Web3.keccak(text="Transfer(address,address,uint256)").hex(),
                    None,
                    f"0x{target_wallet[2:].rjust(64, '0')}",  # Pad to 32 bytes
                ],
                "fromBlock": from_block,
                "toBlock": to_block,
            }

            # Get logs
            logs = w3.eth.get_logs(filter_params)

            # Mark success for unified RPC manager
            if self._use_unified_rpc and network in self._rpc_managers:
                try:
                    chain_id = NETWORK_CHAIN_IDS[network]
                    self._rpc_managers[network].mark_provider_block_success(
                        current_rpc_url, from_block, 'eth_getLogs'
                    )
                except Exception as e:
                    LOGGER.debug(f"Failed to mark RPC success: {e}")

            events = []
            for log in logs:
                try:
                    # Decode the log
                    event_data = get_event_data(USDT_TRANSFER_EVENT_ABI, log)

                    event = PaymentEvent(
                        transaction_hash=log["transactionHash"].hex(),
                        from_address=event_data["args"]["from"],
                        to_address=event_data["args"]["to"],
                        amount=str(event_data["args"]["value"]),
                        block_number=log["blockNumber"],
                        transaction_index=log["transactionIndex"],
                        log_index=log["logIndex"],
                        network=network,
                    )
                    events.append(event)

                except Exception as e:
                    LOGGER.warning(f"Failed to decode event {log['transactionHash'].hex()}: {e}")
                    continue

            return events

        except Exception as e:
            error_msg = str(e)
            LOGGER.error(f"Failed to fetch events for {network} blocks {from_block}-{to_block}: {error_msg}")

            # Mark failure for unified RPC manager
            if self._use_unified_rpc and network in self._rpc_managers:
                try:
                    current_rpc_index = self._active_rpc_indices.get(network, 0)
                    current_rpc_url = self._network_configs[network].rpc_urls[current_rpc_index]
                    chain_id = NETWORK_CHAIN_IDS[network]
                    self._rpc_managers[network].mark_provider_block_failure(
                        current_rpc_url, from_block, 'eth_getLogs', error_msg
                    )
                except Exception as track_err:
                    LOGGER.debug(f"Failed to mark RPC failure: {track_err}")

            return []

    def _store_payment_events(self, events: List[PaymentEvent]) -> None:
        """Store payment events in the database."""
        if not events:
            return

        with self._database.write_connection() as conn:
            for event in events:
                try:
                    conn.execute("""
                        INSERT OR IGNORE INTO usdt_payment_events
                        (transaction_hash, from_address, to_address, amount, block_number,
                         transaction_index, log_index, timestamp, network, processed, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        event.transaction_hash,
                        event.from_address,
                        event.to_address,
                        event.amount,
                        event.block_number,
                        event.transaction_index,
                        event.log_index,
                        event.timestamp,
                        event.network,
                        event.processed,
                        event.created_at
                    ))
                except Exception as e:
                    LOGGER.warning(f"Failed to store event {event.transaction_hash}: {e}")

            conn.commit()

    def _get_unprocessed_events(self, limit: int = 100) -> List[PaymentEvent]:
        """Get unprocessed payment events from the database."""
        with self._database.read_connection() as conn:
            cursor = conn.execute("""
                SELECT transaction_hash, from_address, to_address, amount, block_number,
                       transaction_index, log_index, timestamp, network, processed,
                       backend_notified, error_message, created_at
                FROM usdt_payment_events
                WHERE processed = FALSE
                ORDER BY block_number ASC, transaction_index ASC, log_index ASC
                LIMIT ?
            """, (limit,))

            events = []
            for row in cursor.fetchall():
                event = PaymentEvent(
                    transaction_hash=row[0],
                    from_address=row[1],
                    to_address=row[2],
                    amount=row[3],
                    block_number=row[4],
                    transaction_index=row[5],
                    log_index=row[6],
                    timestamp=row[7],
                    network=row[8],
                    processed=bool(row[9]),
                    backend_notified=bool(row[10]),
                    error_message=row[11],
                    created_at=row[12],
                )
                events.append(event)

            return events

    def _process_network_events(self, network: str) -> None:
        """Process events for a specific network."""
        try:
            # Get current block number
            w3 = self._get_or_create_web3_connection(network)
            current_block = w3.eth.block_number
            last_processed = self._get_last_processed_block(network)

            # Account for confirmations
            safe_block = max(0, current_block - self._network_configs[network].confirmations)

            if last_processed >= safe_block:
                return  # Nothing to process yet

            LOGGER.info(f"Processing {network} events from block {last_processed} to {safe_block}")

            # Process in batches
            from_block = last_processed
            while from_block < safe_block:
                to_block = min(from_block + self._config.max_block_range, safe_block)

                # Fetch events
                events = self._fetch_payment_events(network, from_block, to_block)

                # Store events
                self._store_payment_events(events)

                # Update progress
                self._update_last_processed_block(network, to_block)

                from_block = to_block + 1

                # Rate limiting
                time.sleep(0.1)

            LOGGER.info(f"Finished processing {network} events up to block {safe_block}")

        except Exception as e:
            LOGGER.error(f"Error processing {network} events: {e}")

    def _process_payment_queue(self) -> None:
        """Process the queue of unprocessed payment events."""
        try:
            events = self._get_unprocessed_events(self._config.batch_size)

            for event in events:
                if not self._stopped.is_set():
                    self._process_payment_event(event)
                else:
                    break

        except Exception as e:
            LOGGER.error(f"Error processing payment queue: {e}")

    def start(self) -> None:
        """Start the USDT payment monitoring service."""
        with self._lock:
            if self._running:
                raise RuntimeError("USDT Payment Scout is already running")

            self._running = True
            self._stopped.clear()

        LOGGER.info("Starting USDT Payment Scout")

        # Start processing threads for each network
        self._network_threads = {}
        for network in self._network_configs:
            if self._network_configs[network].enabled:
                thread = threading.Thread(
                    target=self._network_monitor_loop,
                    args=(network,),
                    name=f"usdt-{network}",
                    daemon=True
                )
                thread.start()
                self._network_threads[network] = thread

        # Start payment processing thread
        self._payment_thread = threading.Thread(
            target=self._payment_processing_loop,
            name="usdt-payments",
            daemon=True
        )
        self._payment_thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        """Stop the USDT payment monitoring service."""
        with self._lock:
            if not self._running:
                return

            self._running = False
            self._stopped.set()

        LOGGER.info("Stopping USDT Payment Scout")

        # Wait for threads to stop
        all_threads = list(self._network_threads.values()) + [self._payment_thread]
        for thread in all_threads:
            thread.join(timeout=timeout)
            if thread.is_alive():
                LOGGER.warning(f"Thread {thread.name} did not stop within {timeout}s")

        # Close RPC managers if using unified RPC
        if self._use_unified_rpc:
            for network, rpc_manager in self._rpc_managers.items():
                try:
                    # Close the async RPC manager
                    import asyncio
                    try:
                        loop = asyncio.get_running_loop()
                        # If there's a running loop, schedule close
                        asyncio.create_task(rpc_manager.close())
                    except RuntimeError:
                        # No running loop, create a new one
                        asyncio.run(rpc_manager.close())
                except Exception as e:
                    LOGGER.warning(f"Error closing RPC manager for {network}: {e}")

        # Close Web3 connections
        for network, w3 in self._web3_connections.items():
            try:
                w3.provider.disconnect()
            except Exception as e:
                LOGGER.warning(f"Error disconnecting from {network}: {e}")

        self._web3_connections.clear()

    def _network_monitor_loop(self, network: str) -> None:
        """Main monitoring loop for a specific network."""
        LOGGER.info(f"Starting network monitor for {network}")

        while not self._stopped.is_set():
            try:
                self._process_network_events(network)
                time.sleep(self._config.poll_interval)

            except Exception as e:
                LOGGER.error(f"Error in {network} monitor loop: {e}")
                time.sleep(self._config.poll_interval * 2)  # Back off on error

    def _payment_processing_loop(self) -> None:
        """Main payment processing loop."""
        LOGGER.info("Starting payment processing loop")

        while not self._stopped.is_set():
            try:
                self._process_payment_queue()
                time.sleep(2)  # Check every 2 seconds

            except Exception as e:
                LOGGER.error(f"Error in payment processing loop: {e}")
                time.sleep(5)  # Back off on error

    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the USDT payment monitor."""
        status = {
            "running": self._running,
            "target_wallet": self._config.target_wallet,
            "networks": {},
            "unprocessed_events": 0,
        }

        # Get network status
        for network, config in self._network_configs.items():
            last_block = self._get_last_processed_block(network)
            status["networks"][network] = {
                "enabled": config.enabled,
                "contract_address": config.contract_address,
                "last_processed_block": last_block,
                "connected": network in self._web3_connections,
            }

        # Get unprocessed event count
        with self._database.read_connection() as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM usdt_payment_events WHERE processed = FALSE")
            status["unprocessed_events"] = cursor.fetchone()[0]

        return status

    @classmethod
    def from_env(
        cls,
        database: DatabaseManager,
        backend_client: BackendClient,
        ws_provider_pool: Optional[WebSocketProviderPool] = None,
    ) -> "USDTPaymentScout":
        """Create USDTPaymentScout from environment configuration."""
        load_env_file()

        # Get configuration from environment
        target_wallet = os.environ.get("USDT_TARGET_WALLET")
        if not target_wallet:
            raise ValueError("USDT_TARGET_WALLET environment variable is required")

        networks = os.environ.get("USDT_NETWORKS", "ethereum").split(",")
        networks = [n.strip() for n in networks if n.strip()]

        config = USDTConfig(
            target_wallet=target_wallet,
            networks=networks,
            confirmations=int(os.environ.get("USDT_CONFIRMATIONS", "12")),
            poll_interval=int(os.environ.get("USDT_POLL_INTERVAL", "8")),
            batch_size=int(os.environ.get("USDT_BATCH_SIZE", "1000")),
            max_block_range=int(os.environ.get("USDT_MAX_BLOCK_RANGE", "50000")),
            pro_tier_duration_days=int(os.environ.get("USDT_PRO_TIER_DAYS", "30")),
            pro_tier_level=int(os.environ.get("USDT_PRO_TIER_LEVEL", "3")),
            max_retries=int(os.environ.get("USDT_MAX_RETRIES", "5")),
            retry_delay=float(os.environ.get("USDT_RETRY_DELAY", "1.0")),
            notification_timeout=int(os.environ.get("USDT_NOTIFICATION_TIMEOUT", "30")),
        )

        return cls(config, database, backend_client, ws_provider_pool=ws_provider_pool)


def _install_signal_handlers(usdt_scout: USDTPaymentScout, stop_event: threading.Event) -> None:
    def _handler(signum: int, frame) -> None:  # noqa: ANN001
        LOGGER.info("Signal received", extra={"signal": signum})
        stop_event.set()
        usdt_scout.stop()

    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)


def main(argv: Sequence[str] | None = None) -> int:
    """Console entry point used by ``python -m scout.usdt_payment_scout``."""

    parser = argparse.ArgumentParser(description="USDT Payment Scout command line interface")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Run command
    run_parser = subparsers.add_parser("run", help="Run the USDT payment monitor")
    run_parser.add_argument("--once", action="store_true", help="Process events once then exit")
    run_parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                           default="INFO", help="Log level")

    # Status command
    status_parser = subparsers.add_parser("status", help="Show USDT payment monitor status")

    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )

    # Create scout instance
    from .database_manager import DatabaseManager
    from .backend_client import BackendClient

    # This would need proper initialization in a real deployment
    db_path = os.environ.get("USDT_DB_PATH", "usdt_payments.db")
    database = DatabaseManager(db_path)

    # Initialize with dummy backend client for CLI usage
    backend_client = BackendClient("http://localhost:8000/v1")

    usdt_scout = USDTPaymentScout.from_env(database, backend_client)

    try:
        if args.command == "run":
            if args.once:
                # Process events once and exit
                for network in usdt_scout._network_configs:
                    usdt_scout._process_network_events(network)
                usdt_scout._process_payment_queue()
                return 0
            else:
                # Run continuously
                stop_event = threading.Event()
                _install_signal_handlers(usdt_scout, stop_event)
                usdt_scout.start()

                try:
                    while not stop_event.is_set():
                        time.sleep(1)
                finally:
                    usdt_scout.stop()
                return 0

        if args.command == "status":
            status = usdt_scout.get_status()
            print(json.dumps(status, indent=2))
            return 0

    finally:
        database.close()

    return 1


if __name__ == "__main__":  # pragma: no cover - convenience for direct execution
    raise SystemExit(main())
