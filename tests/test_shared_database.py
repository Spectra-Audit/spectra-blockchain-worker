"""Regression tests for the shared scout database manager."""

from __future__ import annotations

import logging
import threading
import types
from pathlib import Path
from typing import Iterator

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
    featured._lock = threading.Lock()
    featured._client = None  # type: ignore[attr-defined]
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

