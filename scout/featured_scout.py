"""FeaturedScout module implementing on-chain event consumption."""

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
from typing import Any, Dict, Iterable, List, NewType, Optional, Sequence, Tuple

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

from .auth_wallet import load_or_create_admin_wallet
from .backend_client import BackendClient
from .database_manager import DatabaseManager
from .env_loader import load_env_file

LOGGER = logging.getLogger(__name__)


def resolve_ws_provider_class() -> Optional[type]:
    """Return the first available websocket provider class for the current web3 install."""

    with contextlib.suppress(ImportError, AttributeError):
        from web3.providers.persistent import WebSocketProvider as provider

        if isinstance(provider, type):
            return provider
    with contextlib.suppress(ImportError, AttributeError):
        from web3.providers.persistent import AsyncWebSocketProvider as async_provider

        if isinstance(async_provider, type):
            return async_provider
    with contextlib.suppress(ImportError, AttributeError):
        from web3.providers.websocket import WebsocketProvider as provider

        if isinstance(provider, type):
            return provider
    with contextlib.suppress(ImportError, AttributeError):
        from web3.providers.websocket import WebsocketProviderV2 as provider_v2

        if isinstance(provider_v2, type):
            return provider_v2
    with contextlib.suppress(ImportError, AttributeError):
        legacy_provider = getattr(Web3, "WebsocketProvider", None)

        if isinstance(legacy_provider, type):
            return legacy_provider
    return None

EVENT_ABI: List[Dict[str, Any]] = [
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "uint64", "name": "roundId", "type": "uint64"},
            {
                "indexed": False,
                "internalType": "struct LeaderEntry[10]",
                "name": "winners",
                "type": "tuple[10]",
                "components": [
                    {"internalType": "address", "name": "creator", "type": "address"},
                    {"internalType": "bytes32", "name": "projectId", "type": "bytes32"},
                    {"internalType": "uint256", "name": "featuredBid", "type": "uint256"},
                ],
            },
            {"indexed": False, "internalType": "uint8", "name": "count", "type": "uint8"},
            {"indexed": False, "internalType": "uint256", "name": "totalToAdmin", "type": "uint256"},
        ],
        "name": "RoundFinalized",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "address", "name": "payer", "type": "address"},
            {"indexed": True, "internalType": "address", "name": "creator", "type": "address"},
            {"indexed": True, "internalType": "bytes32", "name": "projectId", "type": "bytes32"},
            {"indexed": False, "internalType": "uint256", "name": "amountPaidFees", "type": "uint256"},
            {"indexed": False, "internalType": "uint8", "name": "numberOfContracts", "type": "uint8"},
            {"indexed": False, "internalType": "uint256", "name": "featuredBid", "type": "uint256"},
            {"indexed": False, "internalType": "uint64", "name": "roundId", "type": "uint64"},
        ],
        "name": "Paid",
        "type": "event",
    },
]


@dataclass(frozen=True)
class ScoutConfig:
    rpc_http_urls: Sequence[str]
    rpc_ws_urls: Sequence[str]
    contract_address: str
    chain_id: Optional[int]
    api_root: str
    admin_token: str
    admin_refresh_token: str
    admin_wallet_address: str
    admin_wallet_private_key: str
    project_id_resolver_url: Optional[str]
    db_path: str
    poll_interval_sec: int
    reorg_confirmations: int
    start_block: Optional[int]
    start_block_latest: bool
    block_batch_size: int = 1000


class FeaturedScout:
    """Consumes Featured contract events and mirrors them to the backend."""

    def __init__(
        self,
        config: ScoutConfig,
        once: bool = False,
        *,
        database: Optional[DatabaseManager] = None,
        backend_client: Optional[BackendClient] = None,
    ) -> None:
        self._config = config
        self._once = once
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._ws_thread: Optional[threading.Thread] = None
        self._provider_lock = threading.Lock()
        self._web3: Optional[Web3] = None
        self._rpc_urls = [url for url in config.rpc_http_urls if url]
        if not self._rpc_urls:
            raise ValueError("At least one RPC HTTP URL must be configured")
        if config.block_batch_size <= 0:
            raise ValueError("block_batch_size must be a positive integer")
        self._rpc_fail_counts = [0 for _ in self._rpc_urls]
        self._rpc_backoff_until = [0.0 for _ in self._rpc_urls]
        self._needs_provider_reset = False
        self._db = database or DatabaseManager(config.db_path)
        self._owns_db = database is None
        self._lock = threading.Lock()
        self._meta_key = "featured_last_block"
        self._meta_provider_key = "featured_active_rpc_index"
        self._client = backend_client or BackendClient(
            config.api_root,
            config.admin_token,
            config.admin_refresh_token,
        )
        self._checksum_contract_address = Web3.to_checksum_address(
            self._config.contract_address
        )
        self._ws_urls = [url for url in config.rpc_ws_urls if url]
        self._ws_reconnect_delay = max(config.poll_interval_sec, 1)
        self._poll_gate = threading.Event()
        self._poll_gate.set()
        self._last_safe_block = 0
        self._last_block = 0
        self._ws_ready = threading.Event()
        self._ws_state_lock = threading.Lock()
        self._ws_last_block = 0
        self._ws_last_message = 0.0
        self._ws_pause_logged = False
        self._ws_stale_threshold = max(
            self._config.poll_interval_sec * 3, self._config.poll_interval_sec + 2
        )
        self._ws_provider_class: Optional[type] = None
        persisted_index = self._load_active_rpc_index()
        if persisted_index:
            LOGGER.debug(
                "Ignoring persisted RPC index on startup",
                extra={"index": persisted_index},
            )
        self._active_rpc_index = 0
        self._should_persist_provider_index = False
        self._activate_provider(self._active_rpc_index)
        self._ensure_schema()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            raise RuntimeError("FeaturedScout already running")
        self._thread = threading.Thread(target=self._run, name="FeaturedScout", daemon=True)
        self._thread.start()
        if self._ws_urls:
            self._start_ws_listener()

    def stop(self, timeout: float = 10.0) -> None:
        self._stop_event.set()
        self._poll_gate.set()
        if self._thread:
            self._thread.join(timeout=timeout)
        if self._ws_thread:
            self._ws_thread.join(timeout=timeout)
            self._ws_thread = None
        if self._owns_db:
            self._db.close()

    def _ensure_schema(self) -> None:
        self._db.ensure_featured_schema()

    def _refresh_event_topic_map(self) -> None:
        self._event_topic_map = {
            Web3.to_hex(
                self._web3.keccak(
                    text=event["name"]
                    + "("
                    + ",".join(inp["type"] for inp in event["inputs"])
                    + ")"
                )
            ): event
            for event in EVENT_ABI
        }

    def _load_active_rpc_index(self) -> int:
        stored = None
        with contextlib.suppress(Exception):
            stored = self._db.get_meta(self._meta_provider_key)
        if stored is not None:
            try:
                index = int(stored)
            except ValueError:
                index = 0
        else:
            index = 0
        if not self._rpc_urls:
            return 0
        return max(0, min(index, len(self._rpc_urls) - 1))

    def _save_active_rpc_index(self, index: int) -> None:
        self._db.set_meta(self._meta_provider_key, str(index))

    def _select_provider_index(self, now: float) -> Optional[int]:
        count = len(self._rpc_urls)
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
        url = self._rpc_urls[index]
        LOGGER.info(
            "Switching RPC provider", extra={"url": url, "index": index}
        )
        self._web3 = Web3(
            Web3.HTTPProvider(url, request_kwargs={"timeout": 30})
        )
        self._contract = self._web3.eth.contract(
            address=self._checksum_contract_address, abi=EVENT_ABI
        )
        self._active_rpc_index = index
        self._rpc_fail_counts[index] = 0
        self._rpc_backoff_until[index] = 0.0
        self._needs_provider_reset = False
        if self._should_persist_provider_index:
            self._save_active_rpc_index(index)
        self._refresh_event_topic_map()

    def _ensure_provider(self) -> Optional[Web3]:
        with self._provider_lock:
            now = time.time()
            if (
                self._active_rpc_index is not None
                and not self._needs_provider_reset
                and self._rpc_backoff_until[self._active_rpc_index] <= now
                and self._web3 is not None
            ):
                return self._web3
            next_index = self._select_provider_index(now)
            if next_index is None:
                retry_in = min(self._rpc_backoff_until) - now
                LOGGER.warning(
                    "All RPC providers are in backoff", extra={"retry_in": max(retry_in, 0.0)}
                )
                return None
            if (
                self._web3 is None
                or self._active_rpc_index != next_index
                or self._needs_provider_reset
            ):
                self._activate_provider(next_index)
            return self._web3

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
        LOGGER.warning("RPC provider error", exc_info=exc)
        index = self._active_rpc_index
        if index is None:
            return
        self._rpc_fail_counts[index] += 1
        backoff = min(
            self._config.poll_interval_sec * (2 ** (self._rpc_fail_counts[index] - 1)),
            60,
        )
        self._rpc_backoff_until[index] = time.time() + backoff
        self._needs_provider_reset = True
        LOGGER.info(
            "Scheduled RPC provider backoff",
            extra={
                "url": self._rpc_urls[index],
                "index": index,
                "backoff": backoff,
            },
        )

    def _run(self) -> None:
        LOGGER.info("FeaturedScout loop started")
        try:
            while not self._stop_event.is_set():
                if not self._poll_gate.wait(timeout=self._config.poll_interval_sec):
                    self._evaluate_polling_state()
                    continue
                success = self._poll_once()
                if self._once:
                    break
                if not success:
                    time.sleep(self._config.poll_interval_sec)
                    continue
                time.sleep(self._config.poll_interval_sec)
        finally:
            LOGGER.info("FeaturedScout loop exited")

    def _poll_once(self) -> bool:
        web3 = self._ensure_provider()
        if web3 is None:
            return False
        try:
            latest_block = web3.eth.block_number
        except Exception as exc:  # noqa: BLE001
            self._handle_provider_error(exc)
            return False
        self._mark_provider_success()
        safe_block = max(latest_block - (self._config.reorg_confirmations - 1), 0)
        self._last_safe_block = safe_block
        with self._lock:
            last_block = self._load_last_block()
            if last_block is None:
                if self._config.start_block_latest:
                    last_block = max(safe_block - 1, 0)
                else:
                    last_block = max((self._config.start_block or 0) - 1, 0)
                self._save_last_block(last_block)
            self._last_block = last_block
        if safe_block <= last_block:
            LOGGER.debug("No new finalized blocks", extra={"safe_block": safe_block, "last_block": last_block})
            self._evaluate_polling_state()
            return True
        window_start = last_block + 1
        window_end = safe_block
        batch_size = self._config.block_batch_size
        total_logs = 0
        current_from = window_start
        while current_from <= window_end:
            if self._stop_event.is_set():
                return False
            current_to = min(current_from + batch_size - 1, window_end)
            from_block = self._to_hex_block(current_from)
            to_block = self._to_hex_block(current_to)
            filter_params: FilterParams = {
                "address": self._checksum_contract_address,
                "fromBlock": from_block,
                "toBlock": to_block,
                "topics": [[topic for topic in self._event_topic_map]],
            }
            try:
                logs: Sequence[LogReceipt] = web3.eth.get_logs(filter_params)
            except Exception as exc:  # noqa: BLE001
                LOGGER.exception(
                    "Failed to fetch logs",
                    extra={"from_block": current_from, "to_block": current_to},
                    exc_info=exc,
                )
                self._handle_provider_error(exc)
                return False
            self._mark_provider_success()
            sorted_logs = sorted(
                logs, key=lambda entry: (entry["blockNumber"], entry["logIndex"])
            )
            for log_entry in sorted_logs:
                if self._stop_event.is_set():
                    return False
                if not self._process_log_entry(log_entry):
                    return False
            with self._lock:
                self._save_last_block(current_to)
                self._last_block = current_to
            total_logs += len(sorted_logs)
            LOGGER.info(
                "Processed block chunk",
                extra={
                    "from_block": current_from,
                    "to_block": current_to,
                    "log_count": len(sorted_logs),
                },
            )
            current_from = current_to + 1
        LOGGER.info(
            "Processed blocks",
            extra={"from_block": window_start, "to_block": window_end, "log_count": total_logs},
        )
        self._evaluate_polling_state()
        return True

    def _to_hex_block(self, value: int) -> HexStr:
        to_hex_fn = Web3.to_hex
        if self._web3 is not None:
            to_hex_fn = getattr(self._web3, "to_hex", to_hex_fn)
        try:
            converted = to_hex_fn(value)  # type: ignore[misc]
        except TypeError:
            converted = hex(value)
        if not isinstance(converted, str):
            converted = str(converted)
        if not converted.startswith("0x"):
            converted = hex(value)
        return HexStr(converted)

    def _handle_log(self, log_entry: LogReceipt) -> bool:
        topic0 = Web3.to_hex(log_entry["topics"][0])
        event_abi = self._event_topic_map.get(topic0)
        if event_abi is None:
            LOGGER.warning("Unknown event topic", extra={"topic": topic0})
            return True
        try:
            event_data = get_event_data(self._web3.codec, event_abi, log_entry)
        except Exception as exc:  # noqa: BLE001
            LOGGER.exception("Failed to decode log", extra={"topic": topic0}, exc_info=exc)
            return False
        event_name = event_data["event"]
        if event_name == "RoundFinalized":
            return self._handle_round_finalized(event_data)
        if event_name == "Paid":
            return self._handle_paid(event_data)
        LOGGER.debug("Unhandled event", extra={"event": event_name})
        return True

    def _handle_round_finalized(self, event_data: AttributeDict) -> bool:
        args = event_data["args"]
        round_id = int(args.get("roundId"))
        winners_raw = list(args.get("winners", []))
        count = int(args.get("count", len(winners_raw)))
        winners = winners_raw[:count]
        block = int(event_data.get("blockNumber", 0))
        tx_hash = event_data.get("transactionHash", b"").hex()
        projects_current: List[str] = []
        for index, winner in enumerate(winners):
            project_id_value = winner.get("projectId") if isinstance(winner, dict) else winner[1]
            project_hex = self._normalize_project_hex(project_id_value)
            if project_hex is None:
                LOGGER.warning(
                    "Winner projectId decode failed",
                    extra={"roundId": round_id, "winner_index": index},
                )
                continue
            projects_current.append(project_hex)
            backend_id = self._resolve_backend_project_id(project_hex)
            if backend_id is None:
                LOGGER.warning(
                    "No backend mapping for project",
                    extra={"project_hex": project_hex, "roundId": round_id},
                )
                continue
            payload = {"is_featured": True}
            if not self._patch_project(backend_id, payload):
                return False
            LOGGER.info(
                "Marked project as featured",
                extra={
                    "roundId": round_id,
                    "project_hex": project_hex,
                    "backend_id": backend_id,
                    "action": "feature",
                    "block": block,
                    "tx": tx_hash,
                },
            )
        previous_round = self._get_previous_round_id(round_id)
        if previous_round is not None:
            previous_projects = self._list_featured_projects(previous_round)
            for project_hex in previous_projects:
                backend_id = self._resolve_backend_project_id(project_hex)
                if backend_id is None:
                    LOGGER.warning(
                        "Cannot unfeature project without backend mapping",
                        extra={"project_hex": project_hex, "roundId": previous_round},
                    )
                    continue
                if not self._patch_project(backend_id, {"is_featured": False}):
                    return False
                LOGGER.info(
                    "Cleared featured flag",
                    extra={
                        "roundId": previous_round,
                        "project_hex": project_hex,
                        "backend_id": backend_id,
                        "action": "unfeature",
                        "block": block,
                        "tx": tx_hash,
                    },
                )
        self._upsert_featured_projects(round_id, projects_current)
        return True

    def _process_log_entry(self, log_entry: LogReceipt) -> bool:
        tx_hash = self._coerce_hex_str(log_entry.get("transactionHash"))
        log_index = self._coerce_int(log_entry.get("logIndex"))
        if self._is_log_processed(tx_hash, log_index):
            return True
        try:
            handled = self._handle_log(log_entry)
        except Exception:  # noqa: BLE001
            LOGGER.exception(
                "Unhandled error while processing log",
                extra={
                    "tx_hash": tx_hash,
                    "log_index": log_index,
                    "block": int(self._coerce_int(log_entry.get("blockNumber", 0))),
                },
            )
            return False
        if handled:
            self._mark_log_processed(tx_hash, log_index)
        return handled

    def _start_ws_listener(self) -> None:
        if not self._ws_urls:
            return
        provider_class = self._get_ws_provider_class()
        if provider_class is None:
            LOGGER.warning("web3 websocket provider unavailable; disabling live subscriptions")
            return
        if self._ws_thread and self._ws_thread.is_alive():
            return
        self._ws_thread = threading.Thread(target=self._websocket_loop, name="FeaturedScoutWS", daemon=True)
        self._ws_thread.start()

    def _get_ws_provider_class(self) -> Optional[type]:
        if self._ws_provider_class is None:
            self._ws_provider_class = resolve_ws_provider_class()
        return self._ws_provider_class

    def _websocket_loop(self) -> None:
        while not self._stop_event.is_set():
            for url in self._ws_urls:
                if self._stop_event.is_set():
                    return
                for attempt in range(3):
                    if self._stop_event.is_set():
                        return
                    try:
                        self._consume_ws_url(url)
                    except Exception:  # noqa: BLE001
                        LOGGER.exception(
                            "WebSocket listener failed",
                            extra={"url": url, "attempt": attempt + 1},
                        )
                        if attempt == 2:
                            if self._stop_event.is_set():
                                return
                            time.sleep(self._ws_reconnect_delay)
                        continue
                    else:
                        break

    def _consume_ws_url(self, url: str) -> None:
        provider_class = self._get_ws_provider_class()
        if provider_class is None:
            raise RuntimeError("Websocket provider class unavailable")
        provider = provider_class(url, websocket_timeout=30)  # type: ignore[call-arg]
        filter_params = {
            "address": self._checksum_contract_address,
            "topics": [[topic for topic in self._event_topic_map]],
        }
        response = provider.make_request("eth_subscribe", ["logs", filter_params])
        subscription_id = response.get("result") if isinstance(response, dict) else None
        if not subscription_id:
            raise RuntimeError("Failed to subscribe to websocket logs")
        self._notify_ws_connected()
        try:
            while not self._stop_event.is_set():
                message = provider.ws.recv()
                if not message:
                    continue
                try:
                    payload = json.loads(message)
                except json.JSONDecodeError:
                    LOGGER.debug("Ignoring non-JSON websocket payload", extra={"payload": message})
                    continue
                if payload.get("method") != "eth_subscription":
                    continue
                self._handle_ws_payload(payload)
        finally:
            self._notify_ws_disconnected()
            with contextlib.suppress(Exception):
                provider.make_request("eth_unsubscribe", [subscription_id])
            with contextlib.suppress(Exception):
                if hasattr(provider, "disconnect"):
                    provider.disconnect()
            with contextlib.suppress(Exception):
                if hasattr(provider, "ws") and hasattr(provider.ws, "close"):
                    provider.ws.close()

    def _handle_ws_payload(self, payload: Dict[str, Any]) -> None:
        params = payload.get("params") if isinstance(payload, dict) else None
        if not isinstance(params, dict):
            return
        result = params.get("result")
        if not isinstance(result, dict):
            return
        if result.get("removed"):
            LOGGER.debug("Skipping removed websocket log", extra={"tx": result.get("transactionHash")})
            return
        log_entry = self._convert_ws_result(result)
        if log_entry is None:
            return
        self._process_log_entry(log_entry)
        block_number = self._coerce_int(result.get("blockNumber", 0))
        self._update_ws_progress(block_number)

    def _convert_ws_result(self, result: Dict[str, Any]) -> Optional[LogReceipt]:
        try:
            topics = [self._ensure_hex_bytes(topic) for topic in result.get("topics", [])]
            log_entry: Dict[str, Any] = {
                "address": Web3.to_checksum_address(result.get("address", self._config.contract_address)),
                "blockHash": self._ensure_hex_bytes(result.get("blockHash")),
                "blockNumber": self._coerce_int(result.get("blockNumber", 0)),
                "data": self._ensure_hex_bytes(result.get("data")),
                "logIndex": self._coerce_int(result.get("logIndex", 0)),
                "topics": topics,
                "transactionHash": self._ensure_hex_bytes(result.get("transactionHash")),
                "transactionIndex": self._coerce_int(result.get("transactionIndex", 0)),
            }
        except Exception:  # noqa: BLE001
            LOGGER.exception("Failed to normalize websocket log")
            return None
        return AttributeDict(log_entry)

    def _notify_ws_connected(self) -> None:
        with self._ws_state_lock:
            self._ws_ready.set()
            self._ws_last_block = max(self._last_block, 0)
            self._ws_last_message = time.time()
        self._evaluate_polling_state()

    def _notify_ws_disconnected(self) -> None:
        with self._ws_state_lock:
            self._ws_ready.clear()
            self._ws_last_block = max(self._last_block, 0)
            self._ws_last_message = 0.0
        self._resume_http_polling()

    def _update_ws_progress(self, block_number: int) -> None:
        with self._ws_state_lock:
            self._ws_last_block = max(self._ws_last_block, block_number)
            self._ws_last_message = time.time()
        confirmations_buffer = max(self._config.reorg_confirmations - 1, 0)
        confirmed_block = max(block_number - confirmations_buffer, 0)
        if confirmed_block > self._last_block:
            with self._lock:
                if confirmed_block > self._last_block:
                    self._save_last_block(confirmed_block)
                    self._last_block = confirmed_block
        self._evaluate_polling_state()

    def _evaluate_polling_state(self) -> None:
        if self._stop_event.is_set():
            self._resume_http_polling()
            return
        with self._ws_state_lock:
            ws_ready = self._ws_ready.is_set()
            if ws_ready and self._ws_last_block < self._last_block:
                self._ws_last_block = self._last_block
            ws_last_block = self._ws_last_block
            ws_last_message = self._ws_last_message
        if not ws_ready:
            self._resume_http_polling()
            return
        if self._last_safe_block <= 0:
            self._resume_http_polling()
            return
        now = time.time()
        if ws_last_message == 0.0 or (now - ws_last_message) > self._ws_stale_threshold:
            self._resume_http_polling()
            return
        if ws_last_block < self._last_block:
            self._resume_http_polling()
            return
        if self._last_block >= self._last_safe_block:
            self._pause_http_polling()
        else:
            self._resume_http_polling()

    def _pause_http_polling(self) -> None:
        if self._poll_gate.is_set():
            if not self._ws_pause_logged:
                LOGGER.info("HTTP poller caught up; relying on websocket stream")
                self._ws_pause_logged = True
            self._poll_gate.clear()

    def _resume_http_polling(self) -> None:
        if not self._poll_gate.is_set():
            if self._ws_pause_logged:
                LOGGER.info("Resuming HTTP polling after websocket stall")
            self._ws_pause_logged = False
            self._poll_gate.set()

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

    def _handle_paid(self, event_data: AttributeDict) -> bool:
        args = event_data["args"]
        project_hex = self._normalize_project_hex(args.get("projectId"))
        round_id = int(args.get("roundId", 0))
        block = int(event_data.get("blockNumber", 0))
        tx_hash = event_data.get("transactionHash", b"").hex()
        if project_hex is None:
            LOGGER.warning("Paid event project decode failed", extra={"roundId": round_id})
            return True
        backend_id = self._resolve_backend_project_id(project_hex)
        if backend_id is None:
            LOGGER.warning(
                "No backend mapping for Paid event",
                extra={"project_hex": project_hex, "roundId": round_id},
            )
            return True
        payload = {"pending_pay": False, "last_paid_round_id": round_id}
        if not self._patch_project(backend_id, payload):
            return False
        LOGGER.info(
            "Marked project as paid",
            extra={
                "roundId": round_id,
                "project_hex": project_hex,
                "backend_id": backend_id,
                "action": "paid",
                "block": block,
                "tx": tx_hash,
            },
        )
        return True

    def _normalize_project_hex(self, value: Any) -> Optional[str]:
        if value is None:
            return None
        if isinstance(value, bytes):
            return Web3.to_hex(value)
        if hasattr(value, "hex"):
            return value.hex()
        if isinstance(value, str):
            if value.startswith("0x") and len(value) == 66:
                return value
            try:
                return Web3.to_hex(bytes.fromhex(value))
            except ValueError:
                return None
        return None

    def _patch_project(self, backend_id: str, payload: Dict[str, Any]) -> bool:
        if not backend_id:
            return False
        url = f"{self._config.api_root}/admin/projects/{backend_id}"
        try:
            response = self._client.patch(
                url,
                json=payload,
                timeout=10,
                raise_for_status=False,
            )
        except requests.RequestException:
            LOGGER.exception("Failed to PATCH project", extra={"backend_id": backend_id})
            return False
        if response is None:
            LOGGER.error("PATCH project returned no response", extra={"backend_id": backend_id})
            return False
        if response.status_code >= 400:
            LOGGER.error(
                "PATCH project failed",
                extra={"backend_id": backend_id, "status": response.status_code, "response": response.text},
            )
            return False
        return True

    def _resolve_backend_project_id(self, project_hex: str) -> Optional[str]:
        if not project_hex:
            return None
        cached = self._db.get_project_mapping(project_hex)
        if cached:
            return cached
        resolver_url = self._config.project_id_resolver_url
        if not resolver_url:
            return None
        try:
            response = self._client.get(
                resolver_url,
                params={"project_id_hex": project_hex},
                timeout=10,
                raise_for_status=False,
            )
        except requests.RequestException:
            LOGGER.exception(
                "Resolver request failed",
                extra={"project_hex": project_hex},
            )
            return None
        if response is None:
            return None
        if response.status_code >= 400:
            LOGGER.error(
                "Resolver returned error",
                extra={"project_hex": project_hex, "status": response.status_code},
            )
            return None
        try:
            payload = response.json()
        except ValueError:
            LOGGER.error("Resolver returned non-JSON", extra={"project_hex": project_hex})
            return None
        backend_id = payload.get("backend_id") or payload.get("id")
        if isinstance(backend_id, str) and backend_id:
            self._cache_project_mapping(project_hex, backend_id)
            return backend_id
        LOGGER.warning("Resolver missing backend_id", extra={"project_hex": project_hex})
        return None

    def _cache_project_mapping(self, project_hex: str, backend_id: str) -> None:
        self._db.set_project_mapping(project_hex, backend_id)

    def _get_previous_round_id(self, current_round: int) -> Optional[int]:
        return self._db.previous_featured_round(current_round)

    def _list_featured_projects(self, round_id: int) -> List[str]:
        return self._db.list_featured_projects(round_id)

    def _upsert_featured_projects(self, round_id: int, project_hex_list: Iterable[str]) -> None:
        self._db.replace_featured_projects(round_id, project_hex_list)

    def _mark_log_processed(self, tx_hash: str, log_index: int) -> None:
        self._db.mark_log_processed(tx_hash, log_index)

    def _is_log_processed(self, tx_hash: str, log_index: int) -> bool:
        return self._db.is_log_processed(tx_hash, log_index)

    def _load_last_block(self) -> Optional[int]:
        value = self._db.get_meta(self._meta_key)
        if value is None:
            legacy = self._db.get_meta("last_block")
            if legacy is not None:
                self._db.set_meta(self._meta_key, legacy)
                value = legacy
        return int(value) if value is not None else None

    def _save_last_block(self, block_number: int) -> None:
        self._db.set_meta(self._meta_key, str(block_number))

    def seed_mapping(self, mapping_items: Sequence[Tuple[str, str]]) -> None:
        for project_hex, backend_id in mapping_items:
            normalized = self._normalize_project_hex(project_hex)
            if not normalized:
                LOGGER.error("Invalid project hex for seeding", extra={"project_hex": project_hex})
                continue
            self._cache_project_mapping(normalized, backend_id)
            LOGGER.info(
                "Seeded project mapping",
                extra={"project_hex": normalized, "backend_id": backend_id},
            )


def _load_config_from_env(database: Optional[DatabaseManager] = None) -> ScoutConfig:
    load_env_file()
    rpc_urls_env = os.environ.get("RPC_HTTP_URLS")
    if rpc_urls_env:
        rpc_http_urls = tuple(url.strip() for url in rpc_urls_env.split(",") if url.strip())
    else:
        rpc_url = os.environ.get("RPC_HTTP_URL")
        if not rpc_url:
            raise RuntimeError("RPC_HTTP_URL is required")
        rpc_http_urls = (rpc_url,)
    rpc_ws_urls_env = os.environ.get("RPC_WS_URLS", "")
    rpc_ws_urls = tuple(url.strip() for url in rpc_ws_urls_env.split(",") if url.strip())
    contract_address = os.environ.get("CONTRACT_ADDRESS", "0xe6733635aF5Ce7a1E022fbD87670EADa95397558")
    chain_id_env = os.environ.get("CHAIN_ID")
    chain_id = int(chain_id_env) if chain_id_env else None
    api_root = os.environ.get("API_BASE_URL", "http://localhost:8000/v1")
    resolver_url = os.environ.get("PROJECT_ID_RESOLVER_URL")
    db_path = os.environ.get("DB_PATH", "featured_scout.db")
    if database is not None:
        wallet = load_or_create_admin_wallet(database)
    else:
        temp_db = DatabaseManager(db_path)
        try:
            wallet = load_or_create_admin_wallet(temp_db)
        finally:
            temp_db.close()
    admin_token = os.environ.get("ADMIN_ACCESS_TOKEN") or wallet.address
    admin_refresh_token = os.environ.get("ADMIN_REFRESH_TOKEN") or wallet.private_key
    poll_interval = int(os.environ.get("POLL_INTERVAL_SEC", "8"))
    block_batch_size = int(os.environ.get("BLOCK_BATCH_SIZE", "1000"))
    reorg_conf = int(os.environ.get("REORG_CONF", "5"))
    start_block_env = os.environ.get("START_BLOCK", "latest")
    start_block_latest = start_block_env.lower() == "latest"
    start_block = None
    if not start_block_latest:
        start_block = int(start_block_env, 0)
    return ScoutConfig(
        rpc_http_urls=rpc_http_urls,
        rpc_ws_urls=rpc_ws_urls,
        contract_address=contract_address,
        chain_id=chain_id,
        api_root=api_root,
        admin_token=admin_token,
        admin_refresh_token=admin_refresh_token,
        admin_wallet_address=wallet.address,
        admin_wallet_private_key=wallet.private_key,
        project_id_resolver_url=resolver_url,
        db_path=db_path,
        poll_interval_sec=poll_interval,
        reorg_confirmations=reorg_conf,
        start_block=start_block,
        start_block_latest=start_block_latest,
        block_batch_size=block_batch_size,
    )


def _parse_cli_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="FeaturedScout service")
    parser.add_argument("--once", action="store_true", help="Process a single polling window then exit")
    parser.add_argument(
        "--seed-mapping",
        action="append",
        default=[],
        metavar="PROJECT_HEX=UUID",
        help="Seed project id to backend id mapping",
    )
    parser.add_argument(
        "--log-level",
        default=os.environ.get("LOG_LEVEL", "INFO"),
        help="Logging level",
    )
    return parser.parse_args(argv)


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_cli_args(argv)
    _setup_logging(args.log_level)
    config = _load_config_from_env()
    scout = FeaturedScout(config, once=args.once)
    if args.seed_mapping:
        mapping: List[Tuple[str, str]] = []
        for item in args.seed_mapping:
            if "=" not in item:
                LOGGER.error("Invalid --seed-mapping format", extra={"value": item})
                continue
            project_hex, backend_id = item.split("=", 1)
            mapping.append((project_hex, backend_id))
        scout.seed_mapping(mapping)
        return 0
    scout.start()

    def _signal_handler(signum: int, frame: Any) -> None:  # noqa: ARG001
        LOGGER.info("Signal received, shutting down", extra={"signal": signum})
        scout.stop()

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    try:
        if scout._thread:
            scout._thread.join()
    except KeyboardInterrupt:
        LOGGER.info("KeyboardInterrupt received, stopping")
        scout.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
