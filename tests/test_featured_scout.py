"""Unit tests for :mod:`scout.featured_scout`."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Iterable, List, Optional

import pytest

from scout.featured_scout import FeaturedScout, ScoutConfig


class DummyHTTPProvider:
    """HTTP provider placeholder used by :class:`DummyWeb3`."""

    def __init__(self, url: str, request_kwargs: Optional[Dict[str, Any]] = None) -> None:
        self.url = url
        self.request_kwargs = request_kwargs or {}


class DummyKeccak:
    """Mimic the minimal HexBytes interface required by the scout."""

    def __init__(self, text: str) -> None:
        self._text = text

    def hex(self) -> str:
        return "0x" + self._text.encode("utf-8").hex()[:64]


class DummyContract:
    """Contract stub returning a namespace for events."""

    events = SimpleNamespace()


class DummyEth:
    """Subset of the ``web3.eth`` API exercised by the tests."""

    def __init__(self) -> None:
        self.block_number = 0
        self._log_requests: List[Dict[str, Any]] = []

    def contract(self, address: str, abi: Iterable[Dict[str, Any]]) -> DummyContract:
        return DummyContract()

    def get_logs(self, filter_params: Dict[str, Any]) -> List[Dict[str, Any]]:
        self._log_requests.append(filter_params)
        return []

    @property
    def log_requests(self) -> List[Dict[str, Any]]:
        return self._log_requests


class DummyWeb3:
    """Minimal Web3 replacement providing deterministic behaviour."""

    HTTPProvider = DummyHTTPProvider
    to_checksum_address = staticmethod(lambda addr: addr)

    def __init__(self, provider: DummyHTTPProvider) -> None:
        self.provider = provider
        self.eth = DummyEth()

    def keccak(self, *, text: str) -> DummyKeccak:  # type: ignore[override]
        return DummyKeccak(text)

    @staticmethod
    def to_hex(value: Any) -> str:
        if hasattr(value, "hex"):
            return value.hex()
        return hex(int(value))

    def is_connected(self) -> bool:
        return True


@dataclass
class DummyBackendClient:
    """Stub backend client satisfying :class:`FeaturedScout` dependencies."""

    def post(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover - unused
        return SimpleNamespace(status_code=200, text="")

    def patch(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover - unused
        return SimpleNamespace(status_code=200, text="")

    def get(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover - unused
        return SimpleNamespace(status_code=200, json=lambda: {})


def test_reorg_confirmation_is_normalized(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Ensure a zero reorg confirmation count is normalized to the chain head."""

    monkeypatch.setattr("scout.featured_scout.Web3", DummyWeb3)

    config = ScoutConfig(
        rpc_http_urls=("http://dummy",),
        rpc_ws_urls=(),
        contract_address="0x0123456789012345678901234567890123456789",
        chain_id=1,
        api_root="https://api",
        admin_token="token",
        admin_refresh_token="refresh",
        admin_wallet_address="0x0000000000000000000000000000000000000000",
        admin_wallet_private_key="0x0",
        project_id_resolver_url=None,
        db_path=str(tmp_path / "featured.db"),
        poll_interval_sec=1,
        reorg_confirmations=0,
        start_block=None,
        start_block_latest=True,
        block_batch_size=10,
        etherscan_api_key="test_key",
    )

    scout = FeaturedScout(config, backend_client=DummyBackendClient())
    dummy_eth = scout._web3.eth  # type: ignore[attr-defined]
    dummy_eth.block_number = 10

    try:
        assert scout._poll_once() is True
    finally:
        scout.stop()

    assert dummy_eth.log_requests, "Expected a log request to be issued"
    to_block = dummy_eth.log_requests[0]["toBlock"]
    # toBlock is a hex string, convert to int for comparison
    assert int(str(to_block), 16) == 10
    assert scout._last_safe_block == 10
