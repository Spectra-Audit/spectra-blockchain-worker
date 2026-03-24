"""Tests for RPC provider selection behavior in scout services."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Iterable, List, Optional

import pytest

from scout.database_manager import DatabaseManager
from scout.featured_scout import FeaturedScout, ScoutConfig
from scout import featured_scout as featured_module
from scout import pro_scout as pro_module
from scout.pro_scout import ProScout


class DummyHTTPProvider:
    """Minimal stand-in for :class:`web3.HTTPProvider`."""

    def __init__(self, url: str, request_kwargs: Optional[Dict[str, Any]] = None) -> None:
        self.url = url
        self.request_kwargs = request_kwargs or {}


class DummyEvent:
    """Simple contract event placeholder returning a decoded event."""

    def __init__(self, name: str) -> None:
        self.event = name

    def processLog(self, log: Dict[str, Any]) -> SimpleNamespace:  # noqa: N802 - match web3 API
        return SimpleNamespace(event=self.event, args={})


class DummyEvents:
    """Attribute access returns a callable producing :class:`DummyEvent`."""

    def __getattr__(self, name: str):  # noqa: D401 - simple proxy method
        return lambda: DummyEvent(name)


class DummyContract:
    """Contract wrapper exposing an ``events`` namespace."""

    events = DummyEvents()


class DummyEth:
    """Subset of the :class:`web3.eth` API used by the scouts."""

    def __init__(self, block_number: int = 10, chain_id: int = 1) -> None:
        self.block_number = block_number
        self.chain_id = chain_id

    def contract(self, address: str, abi: Iterable[Dict[str, Any]]) -> DummyContract:
        return DummyContract()

    def get_logs(self, filter_params: Dict[str, Any]) -> List[Dict[str, Any]]:
        return []


class DummyKeccak:
    """Simple object exposing a ``hex`` method."""

    def __init__(self, text: str) -> None:
        self._text = text

    def hex(self) -> str:
        return f"0x{self._text}"


class DummyWeb3:
    """Web3 replacement capturing the selected provider URL."""

    HTTPProvider = DummyHTTPProvider
    to_checksum_address = staticmethod(lambda addr: addr)
    @staticmethod
    def to_hex(value: Any) -> Any:
        return value.hex() if hasattr(value, "hex") else value

    def __init__(self, provider: DummyHTTPProvider) -> None:
        self.provider = provider
        self.eth = DummyEth()
        self.codec = object()

    def keccak(self, text: str) -> DummyKeccak:
        return DummyKeccak(text)

    def is_connected(self) -> bool:
        return True


@dataclass
class DummyBackendClient:
    """Backend client stub satisfying the scout interfaces."""

    def patch(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover - not exercised
        return SimpleNamespace(status_code=200, text="")

    def post(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover - not exercised
        return SimpleNamespace(status_code=200, text="")

    def get(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover - not exercised
        return SimpleNamespace(status_code=200, json=lambda: {})


@pytest.fixture(autouse=True)
def _patch_web3(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace the Web3 dependency in scout modules with :class:`DummyWeb3`."""

    monkeypatch.setattr(featured_module, "Web3", DummyWeb3)
    monkeypatch.setattr(pro_module, "Web3", DummyWeb3)


def test_featured_scout_prefers_first_rpc_on_start(tmp_path: Path) -> None:
    db_path = tmp_path / "featured.db"
    db = DatabaseManager(str(db_path))
    db.set_meta("featured_active_rpc_index", "1")

    config = ScoutConfig(
        rpc_http_urls=["http://first", "http://second"],
        rpc_ws_urls=[],
        contract_address="0x123",
        chain_id=None,
        api_root="https://api",
        admin_token="token",
        admin_refresh_token="refresh",
        admin_wallet_address="0x0000000000000000000000000000000000000001",
        admin_wallet_private_key="0x01",
        project_id_resolver_url=None,
        db_path=str(db_path),
        poll_interval_sec=1,
        reorg_confirmations=1,
        start_block=None,
        start_block_latest=True,
        etherscan_api_key="test_key",
    )

    scout = FeaturedScout(config, database=db, backend_client=DummyBackendClient())

    assert scout._web3.provider.url == "http://first"
    assert scout._active_rpc_index == 0
    assert db.get_meta("featured_active_rpc_index") == "1"

    assert scout._poll_once() is True
    assert db.get_meta("featured_active_rpc_index") == "0"


def test_pro_scout_prefers_first_rpc_on_start(tmp_path: Path) -> None:
    db_path = tmp_path / "pro.db"
    db = DatabaseManager(str(db_path))
    db.set_meta("pro_active_rpc_index", "2")

    scout = ProScout(
        rpc_http_urls=["http://first", "http://second"],
        api_base_url="https://api",
        admin_access_token="token",
        admin_refresh_token="refresh",
        contract_address="0x0000000000000000000000000000000000000000",
        database=db,
        backend_client=DummyBackendClient(),
        poll_interval=0,
        reorg_conf=0,
        block_batch_size=10,
    )

    assert scout.web3.provider.url == "http://first"
    assert scout._active_rpc_index == 0
    assert db.get_meta("pro_active_rpc_index") == "2"

    scout._poll_once()
    assert db.get_meta("pro_active_rpc_index") == "0"
