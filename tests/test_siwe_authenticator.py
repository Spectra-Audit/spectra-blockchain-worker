from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, List

import pytest

from scout.auth_wallet import AdminWallet
from scout.database_manager import DatabaseManager
from scout.siwe_authenticator import (
    ACCESS_TOKEN_META_KEY,
    REFRESH_TOKEN_META_KEY,
    SiweAuthenticator,
)


class _StubResponse:
    def __init__(self, status: int, payload: dict | None = None) -> None:
        self.status_code = status
        self._payload = payload

    def json(self) -> dict:
        if self._payload is None:
            raise ValueError("No payload available")
        return self._payload


@dataclass
class _Call:
    url: str
    kwargs: dict


class _StubSession:
    def __init__(self, responses: List[_StubResponse]) -> None:
        self._responses = responses
        self.headers: dict[str, str] = {}
        self.calls: list[_Call] = []

    def post(self, url: str, **kwargs):
        if not self._responses:
            raise AssertionError("Unexpected request")
        self.calls.append(_Call(url=url, kwargs=kwargs))
        return self._responses.pop(0)


@pytest.fixture()
def temp_db(tmp_path: Path) -> Iterator[DatabaseManager]:
    db_path = tmp_path / "auth.db"
    manager = DatabaseManager(str(db_path))
    try:
        yield manager
    finally:
        manager.close()


def test_siwe_authenticator_performs_handshake(temp_db: DatabaseManager) -> None:
    session = _StubSession(
        [
            _StubResponse(200, {"message": "Sign this"}),
            _StubResponse(200, {"access_token": "access", "refresh_token": "refresh"}),
        ]
    )
    wallet = AdminWallet(address="0xabc", private_key="0x1")
    authenticator = SiweAuthenticator(
        "http://api.local/v1",
        wallet,
        temp_db,
        session_factory=lambda: session,
    )

    access, refresh = authenticator.get_tokens()

    assert access == "access"
    assert refresh == "refresh"
    assert temp_db.get_meta(ACCESS_TOKEN_META_KEY) == "access"
    assert temp_db.get_meta(REFRESH_TOKEN_META_KEY) == "refresh"
    assert [call.url for call in session.calls] == [
        "http://api.local/v1/auth/nonce",
        "http://api.local/v1/auth/verify",
    ]


def test_siwe_authenticator_reuses_refresh_token(temp_db: DatabaseManager) -> None:
    temp_db.set_meta(REFRESH_TOKEN_META_KEY, "stored-refresh")
    session = _StubSession(
        [_StubResponse(200, {"access_token": "fresh", "refresh_token": "updated"})]
    )
    wallet = AdminWallet(address="0xabc", private_key="0x1")
    authenticator = SiweAuthenticator(
        "http://api.local/v1",
        wallet,
        temp_db,
        session_factory=lambda: session,
    )

    access, refresh = authenticator.get_tokens()

    assert access == "fresh"
    assert refresh == "updated"
    assert temp_db.get_meta(ACCESS_TOKEN_META_KEY) == "fresh"
    assert temp_db.get_meta(REFRESH_TOKEN_META_KEY) == "updated"
    assert [call.url for call in session.calls] == ["http://api.local/v1/auth/refresh"]


def test_siwe_authenticator_refresh_failure_triggers_handshake(temp_db: DatabaseManager) -> None:
    temp_db.set_meta(REFRESH_TOKEN_META_KEY, "stored-refresh")
    session = _StubSession(
        [
            _StubResponse(401),
            _StubResponse(200, {"message": "Sign this"}),
            _StubResponse(200, {"access_token": "new", "refresh_token": "new-refresh"}),
        ]
    )
    wallet = AdminWallet(address="0xabc", private_key="0x1")
    authenticator = SiweAuthenticator(
        "http://api.local/v1",
        wallet,
        temp_db,
        session_factory=lambda: session,
    )

    access, refresh = authenticator.get_tokens()

    assert access == "new"
    assert refresh == "new-refresh"
    assert temp_db.get_meta(ACCESS_TOKEN_META_KEY) == "new"
    assert temp_db.get_meta(REFRESH_TOKEN_META_KEY) == "new-refresh"
    assert [call.url for call in session.calls] == [
        "http://api.local/v1/auth/refresh",
        "http://api.local/v1/auth/nonce",
        "http://api.local/v1/auth/verify",
    ]


def test_siwe_authenticator_force_handshake(temp_db: DatabaseManager) -> None:
    temp_db.set_meta(ACCESS_TOKEN_META_KEY, "stale-access")
    temp_db.set_meta(REFRESH_TOKEN_META_KEY, "stale-refresh")
    session = _StubSession(
        [
            _StubResponse(200, {"message": "Sign"}),
            _StubResponse(200, {"access_token": "forced", "refresh_token": "forced-refresh"}),
        ]
    )
    wallet = AdminWallet(address="0xabc", private_key="0x1")
    authenticator = SiweAuthenticator(
        "http://api.local/v1",
        wallet,
        temp_db,
        session_factory=lambda: session,
    )

    access, refresh = authenticator.get_tokens(force=True)

    assert access == "forced"
    assert refresh == "forced-refresh"
    assert temp_db.get_meta(ACCESS_TOKEN_META_KEY) == "forced"
    assert temp_db.get_meta(REFRESH_TOKEN_META_KEY) == "forced-refresh"
