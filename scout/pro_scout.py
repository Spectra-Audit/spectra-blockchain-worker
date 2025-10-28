# file: scout/pro_scout.py
"""Production-ready module for the ProScout staking synchronizer."""
from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import threading
import time
from dataclasses import dataclass
from heapq import heappop, heappush
from typing import Dict, Iterable, List, Optional, Tuple

import requests
from requests import Response, Session
from web3 import Web3
from web3.contract import Contract, ContractEvent
from web3.types import EventData, FilterParams, LogReceipt

from .database_manager import DatabaseManager

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
        rpc_http_url: str,
        api_base_url: str,
        admin_access_token: str,
        contract_address: str = DEFAULT_CONTRACT_ADDRESS,
        db_path: str = DEFAULT_DB_PATH,
        database: Optional[DatabaseManager] = None,
        poll_interval: int = DEFAULT_POLL_INTERVAL,
        reorg_conf: int = DEFAULT_REORG_CONF,
        default_user_tier: str = DEFAULT_USER_TIER,
        pro_tier_set: Optional[Iterable[str]] = None,
        log_level: str = "INFO",
        chain_id: Optional[int] = None,
        start_block: Optional[int] = None,
        block_batch_size: int = 1000,
    ) -> None:
        if not rpc_http_url:
            raise ValueError("rpc_http_url is required")
        if not api_base_url:
            raise ValueError("api_base_url is required")
        if not admin_access_token:
            raise ValueError("admin_access_token is required")

        logging.basicConfig(level=getattr(logging, log_level.upper(), logging.INFO), format=LOG_FORMAT)
        self.logger = logging.getLogger("ProScout")

        self.rpc_http_url = rpc_http_url
        self.api_base_url = api_base_url.rstrip("/")
        self.admin_access_token = admin_access_token
        self.contract_address = Web3.to_checksum_address(contract_address)
        self.poll_interval = poll_interval
        self.reorg_conf = max(reorg_conf, 0)
        self.default_user_tier = default_user_tier
        self.chain_id = chain_id
        self.block_batch_size = max(block_batch_size, 1)
        self.web3 = Web3(Web3.HTTPProvider(rpc_http_url))
        if not self.web3.is_connected():
            raise ConnectionError("Unable to connect to RPC node")
        if self.chain_id is not None:
            node_chain_id = self.web3.eth.chain_id
            if node_chain_id != self.chain_id:
                raise ValueError(f"Connected to chain {node_chain_id}, expected {self.chain_id}")

        self.contract: Contract = self.web3.eth.contract(address=self.contract_address, abi=EVENT_ABI)
        self.event_handlers = {
            "StakeStarted": self._handle_stake_started,
            "TierUpgraded": self._handle_tier_upgraded,
            "UnstakeRequested": self._handle_unstake_requested,
        }
        self.event_topics: List[str] = []
        self._topic_to_event: Dict[str, ContractEvent] = {}
        self._setup_event_registry()

        self.session: Session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {self.admin_access_token}",
                "Content-Type": "application/json",
            }
        )
        self._http_lock = threading.Lock()

        self.pro_tier_set = {tier.strip() for tier in pro_tier_set or [] if tier.strip()}
        self.db_manager = database or DatabaseManager(db_path)
        self._owns_db_manager = database is None
        self._meta_key = "pro_last_block"

        self._activation_lock = threading.Lock()
        self._activation_cond = threading.Condition(self._activation_lock)
        self._activation_heap: List[Tuple[int, int]] = []
        self._activations: Dict[int, Activation] = {}

        self._stop_event = threading.Event()
        self._stopped = threading.Event()
        self._poller_thread: Optional[threading.Thread] = None
        self._scheduler_thread: Optional[threading.Thread] = None

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
        with self._http_lock:
            self.session.close()
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
        latest_block = self.web3.eth.block_number
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
        logs: List[LogReceipt] = self.web3.eth.get_logs(filter_params)
        for log in logs:
            self._process_log(log)

        self._last_block = to_block
        self._save_last_block(self._last_block)

    def _process_log(self, log: LogReceipt) -> None:
        tx_hash = log["transactionHash"].hex()
        log_index = log["logIndex"]
        block_number = log["blockNumber"]
        if self._is_log_processed(tx_hash, log_index):
            self.logger.debug(
                "Skipping already processed log",
                extra={"tx_hash": tx_hash, "log_index": log_index, "block": block_number},
            )
            return

        topic_hex = Web3.to_hex(log["topics"][0])
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
        body = json.dumps(payload)
        delay = 0.5
        for attempt in range(1, MAX_HTTP_RETRIES + 1):
            if self._stop_event.is_set():
                return False
            try:
                with self._http_lock:
                    response: Response = self.session.patch(url, data=body, timeout=HTTP_TIMEOUT)
            except (requests.Timeout, requests.ConnectionError) as exc:
                self.logger.warning(
                    "HTTP request failed",
                    extra={"wallet": wallet, "attempt": attempt, "error": str(exc)},
                )
                time.sleep(delay)
                delay = min(delay * 2, 8)
                continue

            if response.status_code == 429:
                retry_after = self._retry_after_delay(response)
                self.logger.warning(
                    "HTTP 429 received",
                    extra={"wallet": wallet, "attempt": attempt, "retry_after": retry_after},
                )
                time.sleep(retry_after)
                continue

            if 500 <= response.status_code < 600:
                self.logger.warning(
                    "HTTP server error",
                    extra={"wallet": wallet, "status": response.status_code, "attempt": attempt},
                )
                time.sleep(delay)
                delay = min(delay * 2, 8)
                continue

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

        return False

    @staticmethod
    def _retry_after_delay(response: Response) -> float:
        retry_after = response.headers.get("Retry-After")
        if retry_after is None:
            return 1.0
        try:
            return float(retry_after)
        except ValueError:
            return 1.0

    def _compute_is_pro(self, tier: str) -> bool:
        return tier in self.pro_tier_set

    # Event utilities -------------------------------------------------------------

    def _setup_event_registry(self) -> None:
        topics: List[str] = []
        mapping: Dict[str, ContractEvent] = {}
        for event_abi in EVENT_ABI:
            name = event_abi["name"]
            signature = self._event_signature(name, event_abi["inputs"])
            topic = self.web3.keccak(text=signature).hex()
            event_cls: ContractEvent = getattr(self.contract.events, name)
            topics.append(topic)
            mapping[topic] = event_cls
        self.event_topics = topics
        self._topic_to_event = mapping

    @staticmethod
    def _event_signature(name: str, inputs: List[Dict[str, str]]) -> str:
        types = ",".join(param["type"] for param in inputs)
        return f"{name}({types})"

    # CLI ------------------------------------------------------------------------

    @classmethod
    def from_env(cls, *, database: Optional[DatabaseManager] = None) -> "ProScout":
        rpc_http_url = os.environ.get("RPC_HTTP_URL", "")
        api_base_url = os.environ.get("API_BASE_URL", "")
        admin_access_token = os.environ.get("ADMIN_ACCESS_TOKEN", "")
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
        return cls(
            rpc_http_url=rpc_http_url,
            api_base_url=api_base_url,
            admin_access_token=admin_access_token,
            contract_address=contract_address,
            db_path=db_path,
            database=database,
            poll_interval=poll_interval,
            reorg_conf=reorg_conf,
            default_user_tier=default_tier,
            pro_tier_set=pro_tier_set,
            log_level=log_level,
            chain_id=chain_id,
            start_block=start_block,
        )

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
