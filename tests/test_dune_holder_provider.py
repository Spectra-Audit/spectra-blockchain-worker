from __future__ import annotations

import pytest
from scout.dune_holder_provider import DuneSimHolderProvider


class _FakeResponse:
    def __init__(self, status: int, payload: dict) -> None:
        self.status = status
        self._payload = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):  # noqa: ANN001
        return False

    def raise_for_status(self) -> None:
        if self.status >= 400:
            raise RuntimeError(f"HTTP {self.status}")

    async def json(self) -> dict:
        return self._payload


class _FakeSession:
    def __init__(self, responses: list[_FakeResponse]) -> None:
        self.responses = responses
        self.calls: list[dict] = []

    def get(self, url: str, **kwargs):  # noqa: ANN001
        self.calls.append({"url": url, **kwargs})
        return self.responses.pop(0)


@pytest.mark.asyncio
async def test_dune_provider_fetches_cursor_paginated_holders(monkeypatch):
    provider = DuneSimHolderProvider("test-key")
    session = _FakeSession(
        [
            _FakeResponse(
                200,
                {
                    "holders": [
                        {
                            "wallet_address": "0x0000000000000000000000000000000000000001",
                            "balance": "100",
                        }
                    ],
                    "next_offset": "cursor-2",
                },
            ),
            _FakeResponse(
                200,
                {
                    "holders": [
                        {
                            "address": "0x0000000000000000000000000000000000000002",
                            "balance": "0x32",
                        }
                    ],
                    "next_offset": None,
                },
            ),
        ]
    )
    async def _get_session():
        return session

    monkeypatch.setattr(provider, "_get_session", _get_session)

    holders = await provider.get_top_holders(
        "0x00000000000000000000000000000000000000aa",
        1,
        limit=2,
    )

    assert [holder.balance for holder in holders] == [100, 50]
    assert [holder.rank for holder in holders] == [1, 2]
    assert session.calls[0]["headers"] == {"X-Sim-Api-Key": "test-key"}
    assert session.calls[0]["params"] == {"limit": 2}
    assert session.calls[1]["params"] == {"limit": 1, "offset": "cursor-2"}


@pytest.mark.asyncio
async def test_dune_provider_returns_empty_on_rate_limit(monkeypatch):
    provider = DuneSimHolderProvider("test-key")
    session = _FakeSession([_FakeResponse(429, {"error": "rate limited"})])
    async def _get_session():
        return session

    monkeypatch.setattr(provider, "_get_session", _get_session)

    holders = await provider.get_top_holders(
        "0x00000000000000000000000000000000000000aa",
        1,
        limit=500,
    )

    assert holders == []
