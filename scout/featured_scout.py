"""FeaturedScout module implementing on-chain event consumption."""

from __future__ import annotations

import argparse
import logging
import os
import signal
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import requests
from requests import Response
from web3 import Web3
from web3._utils.events import get_event_data
from web3.datastructures import AttributeDict
from web3.types import FilterParams, LogReceipt

from .backend_client import BackendClient
from .database_manager import DatabaseManager

LOGGER = logging.getLogger(__name__)

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
    rpc_url: str
    contract_address: str
    chain_id: Optional[int]
    api_root: str
    admin_token: str
    project_id_resolver_url: Optional[str]
    db_path: str
    poll_interval_sec: int
    reorg_confirmations: int
    start_block: Optional[int]
    start_block_latest: bool


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
        self._web3 = Web3(Web3.HTTPProvider(config.rpc_url, request_kwargs={"timeout": 30}))
        self._contract = self._web3.eth.contract(address=Web3.to_checksum_address(config.contract_address), abi=EVENT_ABI)
        self._event_topic_map = {
            self._web3.keccak(text=event["name"] + "(" + ",".join(inp["type"] for inp in event["inputs"]) + ")").hex(): event
            for event in EVENT_ABI
        }
        self._db = database or DatabaseManager(config.db_path)
        self._owns_db = database is None
        self._lock = threading.Lock()
        self._meta_key = "featured_last_block"
        self._client = backend_client or BackendClient(config.api_root, config.admin_token)
        self._ensure_schema()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            raise RuntimeError("FeaturedScout already running")
        self._thread = threading.Thread(target=self._run, name="FeaturedScout", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=timeout)
        if self._owns_db:
            self._db.close()

    def _ensure_schema(self) -> None:
        self._db.ensure_featured_schema()

    def _run(self) -> None:
        LOGGER.info("FeaturedScout loop started")
        try:
            while not self._stop_event.is_set():
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
        try:
            latest_block = self._web3.eth.block_number
        except Exception as exc:  # noqa: BLE001
            LOGGER.exception("Failed to fetch latest block", exc_info=exc)
            return False
        safe_block = max(latest_block - (self._config.reorg_confirmations - 1), 0)
        with self._lock:
            last_block = self._load_last_block()
            if last_block is None:
                if self._config.start_block_latest:
                    last_block = max(safe_block - 1, 0)
                else:
                    last_block = max((self._config.start_block or 0) - 1, 0)
                self._save_last_block(last_block)
        if safe_block <= last_block:
            LOGGER.debug("No new finalized blocks", extra={"safe_block": safe_block, "last_block": last_block})
            return True
        from_block = last_block + 1
        to_block = safe_block
        filter_params: FilterParams = {
            "address": Web3.to_checksum_address(self._config.contract_address),
            "fromBlock": from_block,
            "toBlock": to_block,
            "topics": [[topic for topic in self._event_topic_map]],
        }
        try:
            logs: Sequence[LogReceipt] = self._web3.eth.get_logs(filter_params)
        except Exception as exc:  # noqa: BLE001
            LOGGER.exception(
                "Failed to fetch logs",
                extra={"from_block": from_block, "to_block": to_block},
                exc_info=exc,
            )
            return False
        sorted_logs = sorted(logs, key=lambda entry: (entry["blockNumber"], entry["logIndex"]))
        for log_entry in sorted_logs:
            if self._stop_event.is_set():
                return False
            tx_hash = log_entry["transactionHash"].hex()
            log_index = int(log_entry["logIndex"])
            if self._is_log_processed(tx_hash, log_index):
                continue
            try:
                handled = self._handle_log(log_entry)
            except Exception:  # noqa: BLE001
                LOGGER.exception(
                    "Unhandled error while processing log",
                    extra={
                        "tx_hash": tx_hash,
                        "log_index": log_index,
                        "block": int(log_entry["blockNumber"]),
                    },
                )
                return False
            if handled:
                self._mark_log_processed(tx_hash, log_index)
        with self._lock:
            self._save_last_block(to_block)
        LOGGER.info(
            "Processed blocks",
            extra={"from_block": from_block, "to_block": to_block, "log_count": len(sorted_logs)},
        )
        return True

    def _handle_log(self, log_entry: LogReceipt) -> bool:
        topic0 = log_entry["topics"][0].hex()
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


def _load_config_from_env() -> ScoutConfig:
    rpc_url = os.environ.get("RPC_HTTP_URL")
    if not rpc_url:
        raise RuntimeError("RPC_HTTP_URL is required")
    contract_address = os.environ.get("CONTRACT_ADDRESS", "0xe6733635aF5Ce7a1E022fbD87670EADa95397558")
    chain_id_env = os.environ.get("CHAIN_ID")
    chain_id = int(chain_id_env) if chain_id_env else None
    api_root = os.environ.get("API_BASE_URL", "http://localhost:8000/v1")
    admin_token = os.environ.get("ADMIN_ACCESS_TOKEN")
    if not admin_token:
        raise RuntimeError("ADMIN_ACCESS_TOKEN is required")
    resolver_url = os.environ.get("PROJECT_ID_RESOLVER_URL")
    db_path = os.environ.get("DB_PATH", "featured_scout.db")
    poll_interval = int(os.environ.get("POLL_INTERVAL_SEC", "8"))
    reorg_conf = int(os.environ.get("REORG_CONF", "5"))
    start_block_env = os.environ.get("START_BLOCK", "latest")
    start_block_latest = start_block_env.lower() == "latest"
    start_block = None
    if not start_block_latest:
        start_block = int(start_block_env, 0)
    return ScoutConfig(
        rpc_url=rpc_url,
        contract_address=contract_address,
        chain_id=chain_id,
        api_root=api_root,
        admin_token=admin_token,
        project_id_resolver_url=resolver_url,
        db_path=db_path,
        poll_interval_sec=poll_interval,
        reorg_confirmations=reorg_conf,
        start_block=start_block,
        start_block_latest=start_block_latest,
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
