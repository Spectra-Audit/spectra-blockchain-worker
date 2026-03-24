from __future__ import annotations

from importlib import import_module
from pathlib import Path
from typing import Iterator, List, Tuple
from unittest.mock import Mock

import pytest

main_module = import_module("scout.main")
from scout.main import ScoutApp
from scout.siwe_authenticator import ACCESS_TOKEN_META_KEY, REFRESH_TOKEN_META_KEY


class _StubAuthenticator:
    token_batches: List[List[Tuple[str, str]]] = []
    instances: List["_StubAuthenticator"] = []

    def __init__(self, base_url: str, wallet, database) -> None:  # type: ignore[override]
        self.base_url = base_url
        self.wallet = wallet
        self.database = database
        self.calls: List[bool] = []
        if not _StubAuthenticator.token_batches:
            raise AssertionError("No token batches configured for stub authenticator")
        self._queue = list(_StubAuthenticator.token_batches.pop(0))
        _StubAuthenticator.instances.append(self)

    def get_tokens(self, force: bool = False) -> Tuple[str, str]:
        self.calls.append(force)
        if not self._queue:
            raise AssertionError("Stub authenticator queue exhausted")
        access, refresh = self._queue.pop(0)
        self.database.set_meta(ACCESS_TOKEN_META_KEY, access)
        self.database.set_meta(REFRESH_TOKEN_META_KEY, refresh)
        return access, refresh

    def persist_tokens(self, access: str, refresh: str) -> None:
        self.database.set_meta(ACCESS_TOKEN_META_KEY, access)
        self.database.set_meta(REFRESH_TOKEN_META_KEY, refresh)


@pytest.fixture()
def env_setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    db_path = tmp_path / "scout.db"
    monkeypatch.setenv("SCOUT_DB_PATH", str(db_path))
    monkeypatch.setenv("RPC_HTTP_URL", "http://rpc.local")
    monkeypatch.setenv("API_BASE_URL", "http://api.local")
    monkeypatch.setenv("PROJECT_ID_RESOLVER_URL", "http://resolver.local")
    monkeypatch.setenv("ETHERSCAN_API_KEY", "test_key")
    yield db_path
    monkeypatch.delenv("SCOUT_DB_PATH", raising=False)
    monkeypatch.delenv("RPC_HTTP_URL", raising=False)
    monkeypatch.delenv("API_BASE_URL", raising=False)
    monkeypatch.delenv("PROJECT_ID_RESOLVER_URL", raising=False)
    monkeypatch.delenv("ETHERSCAN_API_KEY", raising=False)


@pytest.fixture()
def stub_auth(monkeypatch: pytest.MonkeyPatch) -> Iterator[_StubAuthenticator]:
    _StubAuthenticator.token_batches = []
    _StubAuthenticator.instances = []
    monkeypatch.setattr(main_module, "SiweAuthenticator", _StubAuthenticator)

    class _ProScoutStub:
        instances: List["_ProScoutStub"] = []

        def __init__(self, **kwargs):
            self.backend_client = kwargs.get("backend_client")
            self.ws_provider_pool = kwargs.get("ws_provider_pool")
            self.kwargs = kwargs
            _ProScoutStub.instances.append(self)

        @classmethod
        def from_env(cls, **kwargs):
            return cls(**kwargs)

        def start(self) -> None:  # pragma: no cover - simple stub
            pass

        def stop(self, timeout: float = 0.0) -> None:  # pragma: no cover - simple stub
            pass

    class _FeaturedScoutStub:
        instances: List["_FeaturedScoutStub"] = []

        def __init__(self, *_args, **kwargs):
            self.backend_client = kwargs.get("backend_client")
            self.ws_provider_pool = kwargs.get("ws_provider_pool")
            self.args = _args
            self.kwargs = kwargs
            _FeaturedScoutStub.instances.append(self)

        def start(self) -> None:  # pragma: no cover - simple stub
            pass

        def stop(self, timeout: float = 0.0) -> None:  # pragma: no cover - simple stub
            pass

    monkeypatch.setattr(main_module, "ProScout", _ProScoutStub)
    monkeypatch.setattr(main_module, "FeaturedScout", _FeaturedScoutStub)
    yield _StubAuthenticator
    _StubAuthenticator.token_batches = []
    _StubAuthenticator.instances = []
    _ProScoutStub.instances = []
    _FeaturedScoutStub.instances = []


def test_scout_app_from_env_bootstraps_tokens(
    env_setup: Path, stub_auth: _StubAuthenticator
) -> None:
    stub_auth.token_batches = [[("access-1", "refresh-1")]]

    app = ScoutApp.from_env()
    try:
        auth = stub_auth.instances[0]
        assert auth.calls == [False]
        assert app.database.get_meta(ACCESS_TOKEN_META_KEY) == "access-1"
        assert app.database.get_meta(REFRESH_TOKEN_META_KEY) == "refresh-1"
        assert getattr(app.backend_client, "_refresh_token") == "refresh-1"
    finally:
        app.shutdown()


def test_scout_app_refresh_fallback_persists_tokens(
    env_setup: Path, stub_auth: _StubAuthenticator
) -> None:
    # Seed existing tokens from a previous run.
    stub_auth.token_batches = [[("seed-access", "seed-refresh")]]
    first_app = ScoutApp.from_env()
    first_app.shutdown()

    # Next invocation should attempt a refresh using the stored token and fall back to SIWE.
    stub_auth.token_batches = [[("refresh-access", "refresh-refresh")]]
    app = ScoutApp.from_env()
    auth = stub_auth.instances[-1]

    # Prepare a follow-up token pair for the forced handshake triggered after refresh failure.
    auth._queue.append(("handshake-access", "handshake-refresh"))

    refresh_response = Mock()
    refresh_response.status_code = 401
    refresh_response.json.side_effect = ValueError("no payload")
    app.backend_client._session.request = Mock(return_value=refresh_response)

    app.backend_client._refresh_access_token()

    assert auth.calls == [False, True]
    assert app.database.get_meta(ACCESS_TOKEN_META_KEY) == "handshake-access"
    assert app.database.get_meta(REFRESH_TOKEN_META_KEY) == "handshake-refresh"
    assert getattr(app.backend_client, "_refresh_token") == "handshake-refresh"
    app.shutdown()


def test_scout_app_shares_websocket_pool(env_setup: Path, stub_auth: _StubAuthenticator) -> None:
    stub_auth.token_batches = [[("access", "refresh")]]

    app = ScoutApp.from_env()
    try:
        pro_instance = main_module.ProScout.instances[-1]
        featured_instance = main_module.FeaturedScout.instances[-1]
        assert pro_instance.ws_provider_pool is not None
        assert featured_instance.ws_provider_pool is pro_instance.ws_provider_pool
    finally:
        app.shutdown()
