"""Unit tests for the ProScout service."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Iterable, List, Optional

import pytest

from scout import pro_scout as pro_module
from scout.pro_scout import ProScout


class DummyHTTPProvider:
    """Minimal HTTP provider capturing the URL used by the scout."""

    def __init__(self, url: str, request_kwargs: Optional[Dict[str, Any]] = None) -> None:
        self.url = url
        self.request_kwargs = request_kwargs or {}


class DummyEvent:
    """Placeholder event object returned by the dummy contract."""

    def __init__(self, name: str) -> None:
        self.event = name

    def processLog(self, log: Dict[str, Any]) -> SimpleNamespace:  # noqa: N802 - match web3 API
        return SimpleNamespace(event=self.event, args={})


class DummyEvents:
    """Expose callable attributes that produce :class:`DummyEvent` instances."""

    def __getattr__(self, name: str):  # noqa: D401 - simple proxy method
        return lambda: DummyEvent(name)


class DummyContract:
    """Contract wrapper exposing an ``events`` namespace."""

    events = DummyEvents()


class DummyEth:
    """Subset of the :class:`web3.eth` API used by :class:`ProScout`."""

    def __init__(self, block_number: int = 10, chain_id: int = 1) -> None:
        self.block_number = block_number
        self.chain_id = chain_id

    def contract(self, address: str, abi: Iterable[Dict[str, Any]]) -> DummyContract:
        return DummyContract()

    def get_logs(self, filter_params: Dict[str, Any]) -> List[Dict[str, Any]]:  # pragma: no cover - not used
        return []


class DummyKeccak:
    """Dummy object mirroring the ``HexBytes`` interface used by Web3."""

    def __init__(self, text: str) -> None:
        self._text = text

    def hex(self) -> str:
        return f"0x{text_hash(self._text)}"


def text_hash(value: str) -> str:
    """Create a deterministic fake hash for the provided value."""

    return value.encode("utf-8").hex()[:64]


class DummyWeb3:
    """Web3 replacement used to make the scout deterministic during testing."""

    HTTPProvider = DummyHTTPProvider
    to_checksum_address = staticmethod(lambda addr: addr)

    def __init__(self, provider: DummyHTTPProvider) -> None:
        self.provider = provider
        self.eth = DummyEth()

    @staticmethod
    def to_hex(value: Any) -> Any:
        return value.hex() if hasattr(value, "hex") else value

    def keccak(self, *, text: str) -> DummyKeccak:  # type: ignore[override]
        return DummyKeccak(text)

    def is_connected(self) -> bool:
        return True


@dataclass
class DummyBackendClient:
    """Backend client stub satisfying the minimal ProScout interface."""

    def patch(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover - not exercised
        return SimpleNamespace(status_code=200, text="")

    def post(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover - not exercised
        return SimpleNamespace(status_code=200, text="")

    def get(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover - not exercised
        return SimpleNamespace(status_code=200, json=lambda: {})


def test_pro_scout_event_topics_are_prefixed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Ensure topics registered by :class:`ProScout` include the ``0x`` prefix."""

    monkeypatch.setattr(pro_module, "Web3", DummyWeb3)

    scout = ProScout(
        rpc_http_urls=["http://dummy"],
        rpc_ws_urls=[],
        api_base_url="https://api",
        admin_access_token="token",
        admin_refresh_token="refresh",
        contract_address="0x0123456789012345678901234567890123456789",
        db_path=str(tmp_path / "pro.db"),
        backend_client=DummyBackendClient(),
    )

    try:
        assert scout.event_topics
        assert all(topic.startswith("0x") for topic in scout.event_topics)
    finally:
        scout.db_manager.close()
