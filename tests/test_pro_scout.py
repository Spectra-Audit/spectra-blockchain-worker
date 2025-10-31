"""Unit tests for the ProScout service."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Iterable, List, Optional, Tuple

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


def test_pro_scout_idle_websocket_keeps_http_paused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Ensure idle websocket connections do not trigger HTTP polling resumptions."""

    class FakeTime:
        def __init__(self, start: float = 1_000_000.0) -> None:
            self._now = start

        def time(self) -> float:
            return self._now

        def sleep(self, seconds: float) -> None:  # pragma: no cover - convenience for code paths
            self._now += seconds

        def advance(self, seconds: float) -> None:
            self._now += seconds

    monkeypatch.setattr(pro_module, "Web3", DummyWeb3)

    fake_time = FakeTime()
    monkeypatch.setattr(pro_module, "time", fake_time)

    scout = ProScout(
        rpc_http_urls=["http://dummy"],
        rpc_ws_urls=["ws://dummy"],
        api_base_url="https://api",
        admin_access_token="token",
        admin_refresh_token="refresh",
        contract_address="0x0123456789012345678901234567890123456789",
        db_path=str(tmp_path / "pro_idle.db"),
        backend_client=DummyBackendClient(),
        poll_interval=2,
        reorg_conf=0,
    )

    try:
        scout._last_block = 12
        scout._last_safe_block = 12
        scout._notify_ws_connected()

        fake_time.advance(scout._http_resume_grace_period + 5)
        scout._last_http_resume_time = fake_time.time() - (scout._http_resume_grace_period + 1)
        with scout._ws_state_lock:
            scout._ws_healthy_since_time = fake_time.time() - (
                scout._ws_healthy_time_requirement + 1
            )
            scout._ws_healthy_since_block = scout._ws_last_block

        scout._evaluate_polling_state()
        assert not scout._poll_gate.is_set()

        for _ in range(3):
            fake_time.advance(scout.poll_interval)
            scout._evaluate_polling_state()
            assert not scout._poll_gate.is_set()

        scout._notify_ws_disconnected()
        assert scout._poll_gate.is_set()
    finally:
        scout.db_manager.close()


def test_pro_scout_handles_async_websocket_provider(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Ensure websocket providers returning coroutines are awaited by the scout."""

    monkeypatch.setattr(pro_module, "Web3", DummyWeb3)

    scout = ProScout(
        rpc_http_urls=["http://dummy"],
        rpc_ws_urls=["ws://dummy"],
        api_base_url="https://api",
        admin_access_token="token",
        admin_refresh_token="refresh",
        contract_address="0x0123456789012345678901234567890123456789",
        db_path=str(tmp_path / "pro.db"),
        backend_client=DummyBackendClient(),
    )

    class AsyncProvider:
        instances: List["AsyncProvider"] = []
        stop_event: Optional[threading.Event] = None

        class _WebSocket:
            def __init__(self, stop_event: Optional[threading.Event]) -> None:
                self._stop_event = stop_event
                self.recv_calls = 0

            def recv(self) -> Optional[str]:
                self.recv_calls += 1
                if self._stop_event is not None:
                    self._stop_event.set()
                return None

        def __init__(self, url: str, **kwargs: Any) -> None:
            self.url = url
            self.kwargs = kwargs
            self.requests: List[Tuple[str, Any]] = []
            self.subscribe_awaited = False
            self.unsubscribe_awaited = False
            self.handshake_calls = 0
            self.cleanup_calls = 0
            self.disconnect_calls = 0
            self.handshake_ready = False
            self.ws = self._WebSocket(self.stop_event)
            AsyncProvider.instances.append(self)

        def make_request(self, method: str, params: Any) -> Any:
            async def _call() -> Dict[str, Any]:
                if not self.handshake_ready:
                    raise RuntimeError("handshake not completed")
                self.requests.append((method, params))
                if method == "eth_subscribe":
                    self.subscribe_awaited = True
                    return {"result": "sub-id"}
                if method == "eth_unsubscribe":
                    self.unsubscribe_awaited = True
                    return {"result": True}
                return {}

            return _call()

        async def socket_connect(self) -> None:
            self.handshake_calls += 1
            self.handshake_ready = True

        async def socket_disconnect(self) -> None:
            self.cleanup_calls += 1
            self.handshake_ready = False

        def disconnect(self) -> None:
            self.disconnect_calls += 1

    monkeypatch.setattr(pro_module, "resolve_ws_provider_class", lambda: AsyncProvider)

    from scout import websocket_helpers
    from scout.websocket_helpers import _await_if_awaitable

    async def fake_async_iter(
        provider: Any,
        stop_event: Any,
        *,
        subscription_params: Optional[dict[str, Any]] = None,
        on_connect=None,
        on_disconnect=None,
    ):
        if stop_event.is_set():
            return
        if on_connect is not None:
            on_connect()
        await _await_if_awaitable(
            provider.make_request("eth_subscribe", ["logs", subscription_params or {}])
        )
        if stop_event.is_set():
            return
        yield "{\"method\": \"eth_subscription\", \"params\": {}}"
        await _await_if_awaitable(provider.make_request("eth_unsubscribe", ["sub-id"]))
        if on_disconnect is not None:
            on_disconnect()

    monkeypatch.setattr(websocket_helpers, "async_iter_websocket_messages", fake_async_iter)

    scout._stop_event.clear()
    AsyncProvider.instances.clear()
    AsyncProvider.stop_event = scout._stop_event

    try:
        scout._consume_ws_url("ws://dummy")
        assert AsyncProvider.instances, "provider was not instantiated"
        provider = AsyncProvider.instances[-1]
        assert provider.subscribe_awaited
        assert provider.unsubscribe_awaited
        methods = [method for method, _ in provider.requests]
        assert methods.count("eth_subscribe") == 1
        assert "eth_unsubscribe" in methods
        assert provider.handshake_calls == 1
        assert provider.cleanup_calls == 1
        assert provider.disconnect_calls == 1
    finally:
        scout.db_manager.close()
