from __future__ import annotations

from pathlib import Path
from typing import Iterator
from unittest.mock import MagicMock

import pytest

from scout.auth_wallet import (
    ADMIN_WALLET_ADDRESS_META,
    ADMIN_WALLET_PRIVATE_KEY_META,
    load_or_create_admin_wallet,
)
from scout.database_manager import DatabaseManager


@pytest.fixture
def temp_db(tmp_path: Path) -> Iterator[DatabaseManager]:
    db_path = tmp_path / "wallet.sqlite"
    manager = DatabaseManager(str(db_path))
    try:
        yield manager
    finally:
        manager.close()


def test_load_or_create_admin_wallet_creates_and_persists(temp_db: DatabaseManager, monkeypatch: pytest.MonkeyPatch) -> None:
    prompts: list[str] = []
    monkeypatch.delenv("SCOUT_SKIP_WALLET_PROMPT", raising=False)
    monkeypatch.setattr("builtins.input", lambda message="": prompts.append(message) or "")

    wallet = load_or_create_admin_wallet(temp_db)

    assert wallet.address.startswith("0x")
    assert wallet.private_key.startswith("0x")
    assert temp_db.get_meta(ADMIN_WALLET_ADDRESS_META) == wallet.address
    assert temp_db.get_meta(ADMIN_WALLET_PRIVATE_KEY_META) == wallet.private_key
    assert prompts, "prompt should be shown when creating a wallet"


def test_load_or_create_admin_wallet_reuses_existing(temp_db: DatabaseManager, monkeypatch: pytest.MonkeyPatch) -> None:
    prompt_mock = MagicMock()
    monkeypatch.setattr("builtins.input", prompt_mock)
    wallet_first = load_or_create_admin_wallet(temp_db)
    assert prompt_mock.call_count == 0

    def _fail_prompt(*_args, **_kwargs):  # pragma: no cover - defensive
        raise AssertionError("prompt should not be triggered on reuse")

    monkeypatch.setattr("builtins.input", _fail_prompt)

    wallet_second = load_or_create_admin_wallet(temp_db)

    assert wallet_second == wallet_first


def test_load_or_create_admin_wallet_respects_skip_flag(temp_db: DatabaseManager, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SCOUT_SKIP_WALLET_PROMPT", "1")

    def _fail_prompt(*_args, **_kwargs):  # pragma: no cover - defensive
        raise AssertionError("prompt should be skipped when flag set")

    monkeypatch.setattr("builtins.input", _fail_prompt)

    wallet = load_or_create_admin_wallet(temp_db)

    assert wallet.address == temp_db.get_meta(ADMIN_WALLET_ADDRESS_META)
