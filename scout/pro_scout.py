# file: scout/pro_scout.py
"""Production-ready module for the ProScout staking synchronizer."""
from __future__ import annotations

import argparse
import contextlib
import json
import logging
import os
import signal
import threading
import time
from dataclasses import dataclass
from heapq import heappop, heappush
from typing import Any, Dict, Iterable, List, Optional, Tuple

from requests import Response
from web3 import Web3
from web3.contract import Contract

try:  # pragma: no cover - compatibility shim for web3<7
    from web3.contract import ContractEvent
except ImportError:  # pragma: no cover - ContractEvent moved in newer web3 releases
    try:
        from web3.contract.contract import ContractEvent  # type: ignore[attr-defined]
    except ImportError:  # pragma: no cover - fallback for environments without ContractEvent
        ContractEvent = Any  # type: ignore[misc,assignment]
from web3.datastructures import AttributeDict
from web3.types import EventData, FilterParams, LogReceipt

try:  # pragma: no cover - optional at import time
    from web3.providers.websocket import WebsocketProvider
except ImportError:  # pragma: no cover - websocket extras not installed
    WebsocketProvider = None  # type: ignore[assignment]

from .auth_wallet import AdminWallet, load_or_create_admin_wallet
from .backend_client import BackendClient
from .database_manager import DatabaseManager
from .env_loader import load_env_file

EVENT_ABI = [
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "address", "name": "account", "type": "address"},
            {"indexed": True, "internalType": "uint8", "name": "tier", "type": "uint8"},
            {"indexed": False, "internalType": "uint256", "name": "amount", "type": "uint256"},
            {"indexed": False, "internalType": "uint256", "name": "stakedAt", "type": "uint256"},
            {"indexed": False, "internalType": "uint256", "name": "activatesAt", "type": "uint256"},
            {"indexed": False, "internalType": "uint256", "name": "earliestUnstakeAt", "type": "uint256"},
        ],
        "name": "StakeStarted",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "address", "name": "account", "type": "address"},
            {"indexed": True, "internalType": "uint8", "name": "oldTier", "type": "uint8"},
            {"indexed": True, "internalType": "uint8", "name": "newTier", "type": "uint8"},
            {"indexed": False, "internalType": "uint256", "name": "newAmount", "type": "uint256"},
            {"indexed": False, "internalType": "uint256", "name": "stakedAt", "type": "uint256"},
            {"indexed": False, "internalType": "uint256", "name": "activatesAt", "type": "uint256"},
            {"indexed": False, "internalType": "uint256", "name": "earliestUnstakeAt", "type": "uint256"},
        ],
        "name": "TierUpgraded",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "address", "name": "account", "type": "address"},
            {"indexed": True, "internalType": "uint8", "name": "tier", "type": "uint8"},
            {"indexed": False, "internalType": "uint256", "name": "amount", "type": "uint256"},
            {"indexed": False, "internalType": "uint256", "name": "unstakeRequestedAt", "type": "uint256"},
            {"indexed": False, "internalType": "uint256", "name": "withdrawAvailableAt", "type": "uint256"},
            {"indexed": False, "internalType": "uint16", "name": "feeBps", "type": "uint16"},
            {"indexed": False, "internalType": "uint256", "name": "feeAmount", "type": "uint256"},
            {"indexed": False, "internalType": "uint256", "name": "netAmount", "type": "uint256"},
        ],
        "name": "UnstakeRequested",
        "type": "event",
    },
]

DEFAULT_CONTRACT_ADDRESS = "0xe6733635aF5Ce7a1E022fbD87670EADa95397558"
DEFAULT_POLL_INTERVAL = 8
DEFAULT_REORG_CONF = 5
DEFAULT_DB_PATH = "pro_scout.db"
DEFAULT_USER_TIER = "free"
MAX_HTTP_RETRIES = 5
HTTP_TIMEOUT = 10
ACTIVATION_RETRY_DELAY = 60
LOG_FORMAT = "%(asctime)s %(levelname)s %(threadName)s %(message)s"


@dataclass
class Activation:
    """Representation of an activation intent persisted in SQLite."""

    activation_id: int
    wallet: str
    tier: str
    activates_at: int
    tx_hash: str
    log_index: int


class ProScout:
    """Service responsible for syncing staking events to the backend."""

    def __init__(
        self,
        *,
        rpc_http_urls: Iterable[str],
        rpc_ws_urls: Optional[Iterable[str]] = None,
        api_base_url: str,
        admin_access_token: Optional[str] = None,
        admin_refresh_token: Optional[str] = None,
        admin_wallet_address: Optional[str] = None,
        admin_wallet_private_key: Optional[str] = None,
        contract_address: str = DEFAULT_CONTRACT_ADDRESS,
        db_path: str = DEFAULT_DB_PATH,
        database: Optional[DatabaseManager] = None,
        backend_client: Optional[BackendClient] = None,
        poll_interval: int = DEFAULT_POLL_INTERVAL,
        reorg_conf: int = DEFAULT_REORG_CONF,
        default_user_tier: str = DEFAULT_USER_TIER,
        pro_tier_set: Optional[Iterable[str]] = None,
        log_level: str = "INFO",
        chain_id: Optional[int] = None,
        start_block: Optional[int] = None,
        block_batch_size: int = 1000,
    ) -> None:
        http_urls = [url.strip() for url in rpc_http_urls if url]
        if not http_urls:
            raise ValueError("At least one rpc_http_url is required")
        if not api_base_url:
            raise ValueError("api_base_url is required")
        if not admin_access_token or not admin_refresh_token:
            if not admin_wallet_address or not admin_wallet_private_key:
                raise ValueError("Admin wallet credentials are required")
            admin_access_token = admin_access_token or admin_wallet_address
            admin_refresh_token = admin_refresh_token or admin_wallet_private_key

        logging.basicConfig(level=getattr(logging, log_level.upper(), logging.INFO), format=LOG_FORMAT)
        self.logger = logging.getLogger("ProScout")

        self.rpc_http_urls = http_urls
        self.rpc_ws_urls = [url for url in (rpc_ws_urls or []) if url]
        self.api_base_url = api_base_url.rstrip("/")
        self.admin_access_token = admin_access_token
        self.admin_refresh_token = admin_refresh_token
        self.admin_wallet_address = admin_wallet_address or admin_access_token
        self.admin_wallet_private_key = admin_wallet_private_key or admin_refresh_token
        self.contract_address = Web3.to_checksum_address(contract_address)
        self.poll_interval = poll_interval
        self.reorg_conf = max(reorg_conf, 0)
        self.default_user_tier = default_user_tier
        self.chain_id = chain_id
        self.block_batch_size = max(block_batch_size, 1)
        self._provider_lock = threading.Lock()
        self._rpc_fail_counts = [0 for _ in self.rpc_http_urls]
        self._rpc_backoff_until = [0.0 for _ in self.rpc_http_urls]
        self._needs_provider_reset = False

        self.event_handlers = {
            "StakeStarted": self._handle_stake_started,
            "TierUpgraded": self._handle_tier_upgraded,
            "UnstakeRequested": self._handle_unstake_requested,
        }
        self.event_topics: List[str] = []
        self._topic_to_event: Dict[str, ContractEvent] = {}

        self.backend_client = backend_client or BackendClient(
            self.api_base_url,
            self.admin_access_token,
            self.admin_refresh_token,
            admin_wallet_address=self.admin_wallet_address,
            admin_wallet_private_key=self.admin_wallet_private_key,
            max_attempts=MAX_HTTP_RETRIES,
        )

        self.pro_tier_set = {tier.strip() for tier in pro_tier_set or [] if tier.strip()}
        self.db_manager = database or DatabaseManager(db_path)
        self._owns_db_manager = database is None
        self._meta_key = "pro_last_block"
        self._meta_provider_key = "pro_active_rpc_index"

        self._activation_lock = threading.Lock()
        self._activation_cond = threading.Condition(self._activation_lock)
        self._activation_heap: List[Tuple[int, int]] = []
        self._activations: Dict[int, Activation] = {}

        self._stop_event = threading.Event()
        self._stopped = threading.Event()
        self._poller_thread: Optional[threading.Thread] = None
        self._scheduler_thread: Optional[threading.Thread] = None
        self._ws_thread: Optional[threading.Thread] = None
        self._ws_reconnect_delay = max(self.poll_interval, 1)

        persisted_index = self._load_active_rpc_index()
        if persisted_index:
            self.logger.debug(
                "Ignoring persisted RPC index on startup",
                extra={"index": persisted_index},
            )
        self._active_rpc_index = 0
        self._should_persist_provider_index = False
        provider_ready = False
        last_error: Optional[Exception] = None
        for _ in range(len(self.rpc_http_urls)):
            web3 = self._ensure_provider()
            if web3 is None:
                break
            try:
                if not web3.is_connected():
                    raise ConnectionError("Unable to connect to RPC node")
                if self.chain_id is not None:
                    node_chain_id = web3.eth.chain_id
                    if node_chain_id != self.chain_id:
                        raise ValueError(
                            f"Connected to chain {node_chain_id}, expected {self.chain_id}"
                        )
            except Exception as exc:  # noqa: BLE001 - startup fallback handling
                last_error = exc
                self._handle_provider_error(exc)
                continue
            provider_ready = True
            break
        if not provider_ready:
            if last_error is not None:
                raise last_error
            raise RuntimeError("No RPC HTTP providers are available")

        self.contract = self.web3.eth.contract(address=self.contract_address, abi=EVENT_ABI)
        self._setup_event_registry()

        stored_last_block = self._load_last_block()
        if stored_last_block is None:
            initial_block = start_block if start_block is not None else self.web3.eth.block_number
            self._last_block = max(initial_block - 1, -1)
            self._save_last_block(self._last_block)
        else:
            self._last_block = stored_last_block

        self._load_pending_activations()
        self.logger.info(
            "ProScout initialized",
            extra={"last_block": self._last_block, "contract": self.contract_address},
        )

    def start(self) -> None:
        if self._poller_thread and self._poller_thread.is_alive():
            raise RuntimeError("ProScout already started")
        self._stop_event.clear()
        self._stopped.clear()
        self._poller_thread = threading.Thread(target=self._poller_loop, name="ProScoutPoller", daemon=True)
        self._scheduler_thread = threading.Thread(
            target=self._activation_scheduler, name="ProScoutScheduler", daemon=True
        )
        self._poller_thread.start()
        self._scheduler_thread.start()
        if self.rpc_ws_urls:
            self._start_ws_listener()
        self.logger.info("ProScout service started")

    def stop(self, timeout: float = 10.0) -> None:
        if self._stopped.is_set():
            return
        self._stopped.set()
        self._stop_event.set()
        with self._activation_cond:
            self._activation_cond.notify_all()
        if self._poller_thread:
            self._poller_thread.join(timeout=timeout)
            self._poller_thread = None
        if self._scheduler_thread:
            self._scheduler_thread.join(timeout=timeout)
            self._scheduler_thread = None
        if self._ws_thread:
            self._ws_thread.join(timeout=timeout)
            self._ws_thread = None
        if self._owns_db_manager:
            self.db_manager.close()
        self.logger.info("ProScout service stopped")

    # Poller loop -----------------------------------------------------------------

    def _poller_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._poll_once()
            except Exception as exc:  # pragma: no cover - defensive logging
                self.logger.exception("Poller error", extra={"error": str(exc)})
                time.sleep(self.poll_interval)

    def _poll_once(self) -> None:
        web3 = self._ensure_provider()
        if web3 is None:
            time.sleep(self.poll_interval)
            return
        try:
            latest_block = web3.eth.block_number
        except Exception as exc:  # noqa: BLE001
            self._handle_provider_error(exc)
            time.sleep(self.poll_interval)
            return
        self._mark_provider_success()
        safe_block = latest_block - self.reorg_conf
        from_block = self._last_block + 1
        if safe_block < from_block:
            time.sleep(self.poll_interval)
            return

        to_block = min(safe_block, from_block + self.block_batch_size - 1)
        filter_params: FilterParams = {
            "fromBlock": from_block,
            "toBlock": to_block,
            "address": self.contract_address,
            "topics": [self.event_topics],
        }

        self.logger.debug("Fetching logs", extra={"from_block": from_block, "to_block": to_block})
        try:
            logs: List[LogReceipt] = web3.eth.get_logs(filter_params)
        except Exception as exc:  # noqa: BLE001
            self.logger.exception(
                "Failed to fetch logs",
                extra={"from_block": from_block, "to_block": to_block},
            )
            self._handle_provider_error(exc)
            time.sleep(self.poll_interval)
            return
        self._mark_provider_success()
        for log in logs:
            self._process_log_entry(log)

        self._last_block = to_block
        self._save_last_block(self._last_block)

    def _process_log_entry(self, log: LogReceipt) -> None:
        tx_hash = self._coerce_hex_str(log.get("transactionHash"))
        log_index = self._coerce_int(log.get("logIndex"))
        block_number = self._coerce_int(log.get("blockNumber"))
        if self._is_log_processed(tx_hash, log_index):
            self.logger.debug(
                "Skipping already processed log",
                extra={"tx_hash": tx_hash, "log_index": log_index, "block": block_number},
            )
            return

        topic_value = log.get("topics", [None])[0]
        if topic_value is None:
            self.logger.warning("Log missing topic", extra={"tx_hash": tx_hash})
            return
        topic_hex = Web3.to_hex(topic_value)
        event = self._topic_to_event.get(topic_hex)
        if event is None:
            self.logger.warning("Unknown topic", extra={"topic": topic_hex})
            return

        try:
            decoded: EventData = event().processLog(log)
        except Exception as exc:  # pragma: no cover - decoding failure is rare
            self.logger.exception("Failed to decode log", extra={"error": str(exc), "tx_hash": tx_hash})
            return

        handler = self.event_handlers.get(decoded.event)
        if handler is None:
            self.logger.warning("No handler for event", extra={"event": decoded.event})
            return

        if handler(decoded, tx_hash, log_index, block_number):
            self._mark_log_processed(tx_hash, log_index)
        else:
            self.logger.debug(
                "Handler indicated log retry", extra={"tx_hash": tx_hash, "log_index": log_index}
            )

    # Event handlers --------------------------------------------------------------

    def _handle_stake_started(
        self, event: EventData, tx_hash: str, log_index: int, block_number: int
    ) -> bool:
        wallet = event.args["account"]
        tier = str(event.args["tier"])
        activates_at = int(event.args["activatesAt"])
        self.logger.info(
            "StakeStarted event",
            extra={
                "wallet": wallet,
                "tier": tier,
                "activates_at": activates_at,
                "tx_hash": tx_hash,
                "block": block_number,
            },
        )
        self._enqueue_activation(wallet, tier, activates_at, tx_hash, log_index)
        return True

    def _handle_tier_upgraded(
        self, event: EventData, tx_hash: str, log_index: int, block_number: int
    ) -> bool:
        wallet = event.args["account"]
        tier = str(event.args["newTier"])
        activates_at = int(event.args["activatesAt"])
        self.logger.info(
            "TierUpgraded event",
            extra={
                "wallet": wallet,
                "tier": tier,
                "activates_at": activates_at,
                "tx_hash": tx_hash,
                "block": block_number,
            },
        )
        self._enqueue_activation(wallet, tier, activates_at, tx_hash, log_index)
        return True

    def _handle_unstake_requested(
        self, event: EventData, tx_hash: str, log_index: int, block_number: int
    ) -> bool:
        wallet = event.args["account"]
        tier = str(event.args["tier"])
        self.logger.info(
            "UnstakeRequested event",
            extra={"wallet": wallet, "tier": tier, "tx_hash": tx_hash, "block": block_number},
        )
        self._cancel_pending_for_wallet(wallet)
        payload = {"tier": self.default_user_tier, "is_pro": False}
        if not self._patch_user(wallet, payload):
            self.logger.error(
                "Failed to patch user for unstake", extra={"wallet": wallet, "tx_hash": tx_hash}
            )
            return False
        return True

    # Activation queue -----------------------------------------------------------

    def _enqueue_activation(
        self, wallet: str, tier: str, activates_at: int, tx_hash: str, log_index: int
    ) -> None:
        wallet = Web3.to_checksum_address(wallet)
        activation_id = self._insert_activation(wallet, tier, activates_at, tx_hash, log_index)
        activation = Activation(
            activation_id=activation_id,
            wallet=wallet,
            tier=tier,
            activates_at=activates_at,
            tx_hash=tx_hash,
            log_index=log_index,
        )
        with self._activation_cond:
            self._activations[activation_id] = activation
            heappush(self._activation_heap, (activates_at, activation_id))
            self._activation_cond.notify()
        self.logger.info(
            "Activation enqueued",
            extra={"wallet": wallet, "tier": tier, "activates_at": activates_at, "activation_id": activation_id},
        )

    def _activation_scheduler(self) -> None:
        while not self._stop_event.is_set():
            with self._activation_cond:
                next_item: Optional[Tuple[int, int]] = None
                while not next_item and not self._stop_event.is_set():
                    if not self._activation_heap:
                        self._activation_cond.wait(timeout=self.poll_interval)
                        continue
                    activates_at, activation_id = self._activation_heap[0]
                    now = int(time.time())
                    if activates_at > now:
                        timeout = activates_at - now
                        self._activation_cond.wait(timeout=timeout)
                        continue
                    next_item = heappop(self._activation_heap)
                if self._stop_event.is_set():
                    return
                if next_item is None:
                    continue
                _, activation_id = next_item
                activation = self._activations.pop(activation_id, None)

            if activation is None:
                continue

            if not self._is_activation_pending(activation.activation_id):
                continue

            payload = {
                "tier": activation.tier,
                "is_pro": self._compute_is_pro(activation.tier),
            }
            success = self._patch_user(activation.wallet, payload)
            if success:
                self.logger.info(
                    "Activation applied",
                    extra={
                        "wallet": activation.wallet,
                        "tier": activation.tier,
                        "activation_id": activation.activation_id,
                        "tx_hash": activation.tx_hash,
                    },
                )
                self._update_activation_status(activation.activation_id, "applied")
            else:
                self.logger.error(
                    "Activation patch failed",
                    extra={
                        "wallet": activation.wallet,
                        "tier": activation.tier,
                        "activation_id": activation.activation_id,
                    },
                )
                self._requeue_activation(activation)

    def _requeue_activation(self, activation: Activation) -> None:
        with self._activation_cond:
            self._activations[activation.activation_id] = activation
            new_time = int(time.time()) + ACTIVATION_RETRY_DELAY
            heappush(self._activation_heap, (new_time, activation.activation_id))
            self._activation_cond.notify()

    def _cancel_pending_for_wallet(self, wallet: str) -> None:
        wallet = Web3.to_checksum_address(wallet)
        ids = self.db_manager.cancel_pending_activations(wallet)
        if not ids:
            return
        with self._activation_cond:
            for activation_id in ids:
                self._activations.pop(activation_id, None)
        self.logger.info("Cancelled pending activations", extra={"wallet": wallet, "count": len(ids)})

    # Database helpers -----------------------------------------------------------

    def _insert_activation(self, wallet: str, tier: str, activates_at: int, tx_hash: str, log_index: int) -> int:
        return self.db_manager.add_pending_activation(wallet, tier, activates_at, tx_hash, log_index)

    def _update_activation_status(self, activation_id: int, status: str) -> None:
        self.db_manager.update_pending_activation_status(activation_id, status)

    def _is_activation_pending(self, activation_id: int) -> bool:
        status = self.db_manager.get_pending_activation_status(activation_id)
        return status == "pending"

    def _load_pending_activations(self) -> None:
        rows = self.db_manager.list_pending_activations()
        now = int(time.time())
        with self._activation_cond:
            for row in rows:
                activation = Activation(
                    activation_id=int(row["id"]),
                    wallet=str(row["wallet"]),
                    tier=str(row["tier"]),
                    activates_at=int(row["activates_at"]),
                    tx_hash=str(row["tx_hash"]),
                    log_index=int(row["log_index"]),
                )
                self._activations[activation.activation_id] = activation
                heappush(self._activation_heap, (max(activation.activates_at, now), activation.activation_id))
            if rows:
                self._activation_cond.notify()

    def _mark_log_processed(self, tx_hash: str, log_index: int) -> None:
        self.db_manager.mark_log_processed(tx_hash, log_index)

    def _is_log_processed(self, tx_hash: str, log_index: int) -> bool:
        return self.db_manager.is_log_processed(tx_hash, log_index)

    def _save_last_block(self, block: int) -> None:
        self.db_manager.set_meta(self._meta_key, str(block))

    def _load_last_block(self) -> Optional[int]:
        value = self.db_manager.get_meta(self._meta_key)
        if value is None:
            legacy = self.db_manager.get_meta("last_block")
            if legacy is not None:
                self.db_manager.set_meta(self._meta_key, legacy)
                value = legacy
        return int(value) if value is not None else None

    # HTTP helpers ----------------------------------------------------------------

    def _patch_user(self, wallet: str, payload: Dict[str, object]) -> bool:
        url = f"{self.api_base_url}/v1/user/{wallet}"
        response = self.backend_client.patch(
            url,
            json=payload,
            timeout=HTTP_TIMEOUT,
            raise_for_status=False,
            should_retry=lambda: not self._stop_event.is_set(),
        )
        if response is None:
            return False
        if response.status_code >= 400:
            self.logger.error(
                "HTTP client error",
                extra={
                    "wallet": wallet,
                    "status": response.status_code,
                    "response": response.text,
                },
            )
            return False
        return True

    def _compute_is_pro(self, tier: str) -> bool:
        return tier in self.pro_tier_set

    # Event utilities -------------------------------------------------------------

    def _setup_event_registry(self) -> None:
        topics: List[str] = []
        mapping: Dict[str, ContractEvent] = {}
        for event_abi in EVENT_ABI:
            name = event_abi["name"]
            signature = self._event_signature(name, event_abi["inputs"])
            digest = self.web3.keccak(text=signature)
            topic = Web3.to_hex(digest)
            event_cls: ContractEvent = getattr(self.contract.events, name)
            topics.append(topic)
            mapping[topic] = event_cls
        self.event_topics = topics
        self._topic_to_event = mapping

    @staticmethod
    def _event_signature(name: str, inputs: List[Dict[str, str]]) -> str:
        types = ",".join(param["type"] for param in inputs)
        return f"{name}({types})"

    def _load_active_rpc_index(self) -> int:
        stored = None
        with contextlib.suppress(Exception):
            stored = self.db_manager.get_meta(self._meta_provider_key)
        if stored is not None:
            try:
                index = int(stored)
            except ValueError:
                index = 0
        else:
            index = 0
        if not self.rpc_http_urls:
            return 0
        return max(0, min(index, len(self.rpc_http_urls) - 1))

    def _save_active_rpc_index(self, index: int) -> None:
        self.db_manager.set_meta(self._meta_provider_key, str(index))

    def _select_provider_index(self, now: float) -> Optional[int]:
        count = len(self.rpc_http_urls)
        if count == 0:
            return None
        current = self._active_rpc_index if self._active_rpc_index is not None else 0
        offsets = range(count) if not self._needs_provider_reset else range(1, count + 1)
        for offset in offsets:
            idx = (current + offset) % count
            if self._rpc_backoff_until[idx] <= now:
                return idx
        return None

    def _activate_provider(self, index: int) -> None:
        url = self.rpc_http_urls[index]
        self.logger.info("Switching RPC provider", extra={"url": url, "index": index})
        self.web3 = Web3(Web3.HTTPProvider(url))
        self.contract = self.web3.eth.contract(address=self.contract_address, abi=EVENT_ABI)
        self._setup_event_registry()
        self._active_rpc_index = index
        self._rpc_fail_counts[index] = 0
        self._rpc_backoff_until[index] = 0.0
        self._needs_provider_reset = False
        if self._should_persist_provider_index:
            self._save_active_rpc_index(index)

    def _ensure_provider(self) -> Optional[Web3]:
        with self._provider_lock:
            now = time.time()
            if (
                self._active_rpc_index is not None
                and not self._needs_provider_reset
                and self._rpc_backoff_until[self._active_rpc_index] <= now
                and getattr(self, "web3", None) is not None
            ):
                return self.web3
            next_index = self._select_provider_index(now)
            if next_index is None:
                retry_in = min(self._rpc_backoff_until) - now
                self.logger.warning(
                    "All RPC providers are in backoff", extra={"retry_in": max(retry_in, 0.0)}
                )
                return None
            if (
                getattr(self, "web3", None) is None
                or self._active_rpc_index != next_index
                or self._needs_provider_reset
            ):
                self._activate_provider(next_index)
            return self.web3

    def _mark_provider_success(self) -> None:
        index = self._active_rpc_index
        if index is None:
            return
        if not self._should_persist_provider_index:
            self._should_persist_provider_index = True
            self._save_active_rpc_index(index)
        self._rpc_fail_counts[index] = 0
        self._rpc_backoff_until[index] = 0.0

    def _handle_provider_error(self, exc: Exception) -> None:
        self.logger.warning("RPC provider error", exc_info=exc)
        index = self._active_rpc_index
        if index is None:
            return
        self._rpc_fail_counts[index] += 1
        backoff = min(self.poll_interval * (2 ** (self._rpc_fail_counts[index] - 1)), 60)
        self._rpc_backoff_until[index] = time.time() + backoff
        self._needs_provider_reset = True
        self.logger.info(
            "Scheduled RPC provider backoff",
            extra={
                "url": self.rpc_http_urls[index],
                "index": index,
                "backoff": backoff,
            },
        )

    # CLI ------------------------------------------------------------------------

    @classmethod
    def from_env(
        cls,
        *,
        database: Optional[DatabaseManager] = None,
        backend_client: Optional[BackendClient] = None,
        admin_wallet: Optional[AdminWallet] = None,
    ) -> "ProScout":
        load_env_file()
        rpc_http_env = os.environ.get("RPC_HTTP_URLS")
        if rpc_http_env:
            rpc_http_urls = [url.strip() for url in rpc_http_env.split(",") if url.strip()]
        else:
            rpc_http_url = os.environ.get("RPC_HTTP_URL", "")
            rpc_http_urls = [rpc_http_url] if rpc_http_url else []
        rpc_ws_env = os.environ.get("RPC_WS_URLS", "")
        rpc_ws_urls = [url.strip() for url in rpc_ws_env.split(",") if url.strip()]
        api_base_url = os.environ.get("API_BASE_URL", "")
        admin_access_token = os.environ.get("ADMIN_ACCESS_TOKEN", "")
        admin_refresh_token = os.environ.get("ADMIN_REFRESH_TOKEN", "")
        contract_address = os.environ.get("CONTRACT_ADDRESS", DEFAULT_CONTRACT_ADDRESS)
        db_path = os.environ.get("DB_PATH", DEFAULT_DB_PATH)
        poll_interval = int(os.environ.get("POLL_INTERVAL_SEC", str(DEFAULT_POLL_INTERVAL)))
        reorg_conf = int(os.environ.get("REORG_CONF", str(DEFAULT_REORG_CONF)))
        default_tier = os.environ.get("DEFAULT_USER_TIER", DEFAULT_USER_TIER)
        log_level = os.environ.get("LOG_LEVEL", "INFO")
        pro_tier_env = os.environ.get("PRO_TIER_SET", "")
        pro_tier_set = [tier.strip() for tier in pro_tier_env.split(",") if tier.strip()]
        chain_id_env = os.environ.get("CHAIN_ID")
        chain_id = int(chain_id_env) if chain_id_env else None
        start_block_env = os.environ.get("START_BLOCK")
        start_block = int(start_block_env) if start_block_env else None
        if database is not None:
            wallet = admin_wallet or load_or_create_admin_wallet(database)
        else:
            if admin_wallet is not None:
                wallet = admin_wallet
            else:
                temp_db = DatabaseManager(db_path)
                try:
                    wallet = load_or_create_admin_wallet(temp_db)
                finally:
                    temp_db.close()
        if backend_client is not None:
            if not api_base_url:
                api_base_url = backend_client.base_url
            if not admin_access_token:
                admin_access_token = getattr(backend_client, "_access_token", "")
            if not admin_refresh_token:
                admin_refresh_token = getattr(backend_client, "_refresh_token", "")
        if not admin_access_token:
            admin_access_token = wallet.address
        if not admin_refresh_token:
            admin_refresh_token = wallet.private_key

        return cls(
            rpc_http_urls=rpc_http_urls,
            api_base_url=api_base_url,
            admin_access_token=admin_access_token,
            admin_refresh_token=admin_refresh_token,
            admin_wallet_address=wallet.address,
            admin_wallet_private_key=wallet.private_key,
            contract_address=contract_address,
            db_path=db_path,
            database=database,
            backend_client=backend_client,
            poll_interval=poll_interval,
            reorg_conf=reorg_conf,
            default_user_tier=default_tier,
            pro_tier_set=pro_tier_set,
            log_level=log_level,
            chain_id=chain_id,
            start_block=start_block,
            rpc_ws_urls=rpc_ws_urls,
        )

    def _start_ws_listener(self) -> None:
        if not self.rpc_ws_urls:
            return
        if WebsocketProvider is None:
            self.logger.warning("web3 websocket provider unavailable; disabling live subscriptions")
            return
        if self._ws_thread and self._ws_thread.is_alive():
            return
        self._ws_thread = threading.Thread(target=self._websocket_loop, name="ProScoutWS", daemon=True)
        self._ws_thread.start()

    def _websocket_loop(self) -> None:
        while not self._stop_event.is_set():
            for url in self.rpc_ws_urls:
                if self._stop_event.is_set():
                    return
                for attempt in range(3):
                    if self._stop_event.is_set():
                        return
                    try:
                        self._consume_ws_url(url)
                    except Exception as exc:  # pragma: no cover - defensive logging
                        self.logger.exception(
                            "WebSocket listener error",
                            extra={"url": url, "error": str(exc), "attempt": attempt + 1},
                        )
                        if attempt == 2:
                            if self._stop_event.is_set():
                                return
                            time.sleep(self._ws_reconnect_delay)
                        continue
                    else:
                        break

    def _consume_ws_url(self, url: str) -> None:
        provider = WebsocketProvider(url, websocket_timeout=30)  # type: ignore[call-arg]
        filter_params = {
            "address": self.contract_address,
            "topics": [self.event_topics],
        }
        response = provider.make_request("eth_subscribe", ["logs", filter_params])
        subscription_id = response.get("result") if isinstance(response, dict) else None
        if not subscription_id:
            raise RuntimeError("Failed to subscribe to websocket logs")
        try:
            while not self._stop_event.is_set():
                message = provider.ws.recv()
                if not message:
                    continue
                try:
                    payload = json.loads(message)
                except json.JSONDecodeError:
                    self.logger.debug("Ignoring malformed websocket payload", extra={"payload": message})
                    continue
                if payload.get("method") != "eth_subscription":
                    continue
                self._handle_ws_payload(payload)
        finally:
            with contextlib.suppress(Exception):
                provider.make_request("eth_unsubscribe", [subscription_id])
            with contextlib.suppress(Exception):
                provider.disconnect()

    def _handle_ws_payload(self, payload: Dict[str, Any]) -> None:
        params = payload.get("params") if isinstance(payload, dict) else None
        if not isinstance(params, dict):
            return
        result = params.get("result")
        if not isinstance(result, dict):
            return
        if result.get("removed"):
            self.logger.debug(
                "Skipping removed websocket log", extra={"tx_hash": result.get("transactionHash")}
            )
            return
        log_entry = self._convert_ws_result(result)
        if log_entry is None:
            return
        self._process_log_entry(log_entry)

    def _convert_ws_result(self, result: Dict[str, Any]) -> Optional[LogReceipt]:
        try:
            topics = [self._ensure_hex_bytes(topic) for topic in result.get("topics", [])]
            log_entry: Dict[str, Any] = {
                "address": Web3.to_checksum_address(result.get("address", self.contract_address)),
                "blockHash": self._ensure_hex_bytes(result.get("blockHash")),
                "blockNumber": self._coerce_int(result.get("blockNumber", 0)),
                "data": self._ensure_hex_bytes(result.get("data")),
                "logIndex": self._coerce_int(result.get("logIndex", 0)),
                "topics": topics,
                "transactionHash": self._ensure_hex_bytes(result.get("transactionHash")),
                "transactionIndex": self._coerce_int(result.get("transactionIndex", 0)),
            }
        except Exception as exc:  # pragma: no cover - defensive logging
            self.logger.exception("Failed to normalize websocket log", extra={"error": str(exc)})
            return None
        return AttributeDict(log_entry)

    @staticmethod
    def _ensure_hex_bytes(value: Any) -> bytes:
        if value is None:
            return b""
        if isinstance(value, (bytes, bytearray)):
            return bytes(value)
        if isinstance(value, str):
            cleaned = value[2:] if value.startswith("0x") else value
            if not cleaned:
                return b""
            return bytes.fromhex(cleaned)
        if hasattr(value, "hex") and callable(getattr(value, "hex")):
            return bytes(value)
        raise TypeError(f"Cannot convert value to bytes: {value!r}")

    @staticmethod
    def _coerce_hex_str(value: Any) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, bytes):
            return "0x" + value.hex()
        if hasattr(value, "hex") and callable(getattr(value, "hex")):
            return value.hex()
        raise TypeError(f"Cannot convert value to hex string: {value!r}")

    @staticmethod
    def _coerce_int(value: Any) -> int:
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            return int(value, 16 if value.startswith("0x") else 10)
        if value is None:
            return 0
        if hasattr(value, "__int__"):
            return int(value)
        raise TypeError(f"Cannot convert value to int: {value!r}")

    # TODO: Add unit tests for event decoding and HTTP patch behavior using mocks.


def _run_service() -> None:
    parser = argparse.ArgumentParser(description="Run the ProScout service")
    parser.add_argument("--once", action="store_true", help="Process a single block range then exit")
    args = parser.parse_args()

    service = ProScout.from_env()

    if args.once:
        try:
            service._poll_once()
        finally:
            service.stop()
        return

    stop_event = threading.Event()

    def _signal_handler(signum: int, frame: Optional[object]) -> None:  # pragma: no cover - runtime handler
        service.logger.info("Signal received", extra={"signal": signum})
        stop_event.set()
        service.stop()

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    service.start()
    try:
        while not stop_event.is_set():
            time.sleep(1)
    finally:
        service.stop()


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    _run_service()
