"""Regression tests for the shared scout database manager."""

from __future__ import annotations

import logging
import sys
import threading
import types
from pathlib import Path
from typing import Iterator

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class _StubSession:
    def __init__(self) -> None:
        self.headers: dict[str, str] = {}

    def close(self) -> None:  # pragma: no cover - simple stub
        pass


requests_stub = types.SimpleNamespace(
    Session=_StubSession,
    Response=object,
    RequestException=Exception,
    Timeout=Exception,
    ConnectionError=Exception,
    HTTPError=Exception,
)

sys.modules.setdefault("requests", requests_stub)


class _Web3:
    HTTPProvider = staticmethod(lambda *args, **kwargs: object())
    to_checksum_address = staticmethod(lambda value: value)
    to_hex = staticmethod(lambda value: value if isinstance(value, str) else "0x0")

    def __init__(self, *args, **kwargs) -> None:
        self.eth = types.SimpleNamespace(
            chain_id=1,
            contract=lambda *a, **k: types.SimpleNamespace(events=types.SimpleNamespace()),
            get_logs=lambda *a, **k: [],
        )

    def is_connected(self) -> bool:  # pragma: no cover - simple stub
        return True

    def keccak(self, text: str) -> bytes:  # pragma: no cover - simple stub
        return b"\x00" * 32


web3_stub = types.ModuleType("web3")
web3_stub.Web3 = _Web3
sys.modules.setdefault("web3", web3_stub)

contract_module = types.ModuleType("web3.contract")
contract_module.Contract = type("Contract", (), {})


class _ContractEvent:
    def __call__(self, *args, **kwargs):  # pragma: no cover - simple stub
        return types.SimpleNamespace(processLog=lambda log: types.SimpleNamespace(event="", args={}))


contract_module.ContractEvent = _ContractEvent
sys.modules.setdefault("web3.contract", contract_module)

types_module = types.ModuleType("web3.types")
types_module.EventData = dict
types_module.FilterParams = dict
types_module.LogReceipt = dict
sys.modules.setdefault("web3.types", types_module)

datastructures_module = types.ModuleType("web3.datastructures")
datastructures_module.AttributeDict = dict
sys.modules.setdefault("web3.datastructures", datastructures_module)

utils_module = types.ModuleType("web3._utils")
events_module = types.ModuleType("web3._utils.events")
events_module.get_event_data = lambda *args, **kwargs: {}  # type: ignore[assignment]
sys.modules.setdefault("web3._utils", utils_module)
sys.modules.setdefault("web3._utils.events", events_module)

import pytest

from scout.database_manager import DatabaseManager
from scout.featured_scout import FeaturedScout
from scout.pro_scout import ProScout


@pytest.fixture()
def shared_manager(tmp_path: Path) -> Iterator[DatabaseManager]:
    manager = DatabaseManager(str(tmp_path / "scout.db"))
    try:
        yield manager
    finally:
        manager.close()


def _make_pro_stub(manager: DatabaseManager) -> ProScout:
    pro = ProScout.__new__(ProScout)
    pro.logger = logging.getLogger("ProScoutTest")
    pro.db_manager = manager
    pro._owns_db_manager = False  # type: ignore[attr-defined]
    pro._meta_key = "pro_last_block"  # type: ignore[attr-defined]
    pro._activation_lock = threading.Lock()
    pro._activation_cond = threading.Condition(pro._activation_lock)
    pro._activation_heap = []
    pro._activations = {}
    return pro  # type: ignore[return-value]


def _make_featured_stub(manager: DatabaseManager) -> FeaturedScout:
    featured = FeaturedScout.__new__(FeaturedScout)
    featured._db = manager  # type: ignore[attr-defined]
    featured._owns_db = False  # type: ignore[attr-defined]
    featured._meta_key = "featured_last_block"  # type: ignore[attr-defined]
    featured._stop_event = threading.Event()
    featured._thread = None
    featured._session = None
    featured._lock = threading.Lock()
    return featured  # type: ignore[return-value]


def test_meta_entries_are_isolated(shared_manager: DatabaseManager) -> None:
    pro = _make_pro_stub(shared_manager)
    featured = _make_featured_stub(shared_manager)

    assert pro._load_last_block() is None
    assert featured._load_last_block() is None

    pro._save_last_block(101)
    assert pro._load_last_block() == 101
    assert featured._load_last_block() is None

    featured._save_last_block(202)
    assert featured._load_last_block() == 202
    assert pro._load_last_block() == 101


def test_processed_logs_shared_between_services(shared_manager: DatabaseManager) -> None:
    pro = _make_pro_stub(shared_manager)
    featured = _make_featured_stub(shared_manager)

    pro._mark_log_processed("0xabc", 1)
    assert pro._is_log_processed("0xabc", 1)
    assert featured._is_log_processed("0xabc", 1)


def test_tables_do_not_clobber_each_other(shared_manager: DatabaseManager) -> None:
    pro = _make_pro_stub(shared_manager)
    featured = _make_featured_stub(shared_manager)

    activation_id = pro._insert_activation("0x123", "gold", 123, "0xtx", 5)
    pending = shared_manager.list_pending_activations()
    assert [row["id"] for row in pending] == [activation_id]

    featured._upsert_featured_projects(7, ["0xproject"])
    assert shared_manager.list_featured_projects(7) == ["0xproject"]

    pending_after = shared_manager.list_pending_activations()
    assert [row["id"] for row in pending_after] == [activation_id]

