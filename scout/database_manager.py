"""Shared SQLite database manager for scout services."""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from typing import Iterable, Iterator, List, Optional


class DatabaseManager:
    """Coordinate access to the shared scout SQLite database."""

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute("PRAGMA foreign_keys=ON;")
            self._conn.commit()
        self._closed = False
        self._ensure_core_schema()

    @property
    def path(self) -> str:
        """Return the backing database path."""

        return self._db_path

    def close(self) -> None:
        """Close the underlying SQLite connection."""

        with self._lock:
            if self._closed:
                return
            self._conn.close()
            self._closed = True

    @contextmanager
    def read_connection(self) -> Iterator[sqlite3.Connection]:
        """Yield a connection protected by the manager lock for read operations."""

        with self._lock:
            yield self._conn

    @contextmanager
    def write_connection(self) -> Iterator[sqlite3.Connection]:
        """Yield a connection protected by the manager lock for write operations."""

        with self._lock:
            try:
                yield self._conn
                self._conn.commit()
            except Exception:  # pragma: no cover - defensive rollback
                self._conn.rollback()
                raise

    # Schema helpers -----------------------------------------------------

    def _ensure_core_schema(self) -> None:
        """Create the shared tables used by the scout services."""

        with self.write_connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS processed_logs (
                    tx_hash TEXT NOT NULL,
                    log_index INTEGER NOT NULL,
                    PRIMARY KEY (tx_hash, log_index)
                );
                CREATE TABLE IF NOT EXISTS pending_activations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    wallet TEXT NOT NULL,
                    tier TEXT NOT NULL,
                    activates_at INTEGER NOT NULL,
                    tx_hash TEXT NOT NULL,
                    log_index INTEGER NOT NULL,
                    status TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS featured_projects (
                    round_id INTEGER NOT NULL,
                    project_hex TEXT NOT NULL,
                    PRIMARY KEY (round_id, project_hex)
                );
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )

    def ensure_featured_schema(self) -> None:
        """Ensure auxiliary tables required by :class:`FeaturedScout` exist."""

        with self.write_connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS project_id_map (
                    project_hex TEXT PRIMARY KEY,
                    backend_id TEXT NOT NULL
                );
                """
            )

    # processed_logs helpers ---------------------------------------------

    def mark_log_processed(self, tx_hash: str, log_index: int) -> None:
        """Record that a log has been processed."""

        with self.write_connection() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO processed_logs (tx_hash, log_index) VALUES (?, ?)",
                (tx_hash, log_index),
            )

    def is_log_processed(self, tx_hash: str, log_index: int) -> bool:
        """Return whether the given transaction log has already been processed."""

        with self.read_connection() as conn:
            row = conn.execute(
                "SELECT 1 FROM processed_logs WHERE tx_hash = ? AND log_index = ?",
                (tx_hash, log_index),
            ).fetchone()
        return row is not None

    # pending_activations helpers ----------------------------------------

    def add_pending_activation(
        self, wallet: str, tier: str, activates_at: int, tx_hash: str, log_index: int
    ) -> int:
        """Insert a pending activation row and return its identifier."""

        with self.write_connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO pending_activations (wallet, tier, activates_at, tx_hash, log_index, status)
                VALUES (?, ?, ?, ?, ?, 'pending')
                """,
                (wallet, tier, activates_at, tx_hash, log_index),
            )
            return int(cur.lastrowid)

    def update_pending_activation_status(self, activation_id: int, status: str) -> None:
        """Update the status of a pending activation."""

        with self.write_connection() as conn:
            conn.execute(
                "UPDATE pending_activations SET status = ? WHERE id = ?",
                (status, activation_id),
            )

    def get_pending_activation_status(self, activation_id: int) -> Optional[str]:
        """Fetch the status for the given activation identifier."""

        with self.read_connection() as conn:
            row = conn.execute(
                "SELECT status FROM pending_activations WHERE id = ?",
                (activation_id,),
            ).fetchone()
        return str(row["status"]) if row else None

    def list_pending_activations(self) -> List[dict]:
        """Return a list of dictionaries describing all pending activations."""

        with self.read_connection() as conn:
            rows = conn.execute(
                """
                SELECT id, wallet, tier, activates_at, tx_hash, log_index
                FROM pending_activations
                WHERE status = 'pending'
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def cancel_pending_activations(self, wallet: str) -> List[int]:
        """Cancel all pending activations for *wallet* and return their identifiers."""

        with self.write_connection() as conn:
            cur = conn.execute(
                "SELECT id FROM pending_activations WHERE wallet = ? AND status = 'pending'",
                (wallet,),
            )
            ids = [int(row["id"]) for row in cur.fetchall()]
            if ids:
                conn.execute(
                    "UPDATE pending_activations SET status = 'cancelled' WHERE wallet = ? AND status = 'pending'",
                    (wallet,),
                )
        return ids

    # featured_projects helpers -----------------------------------------

    def list_featured_projects(self, round_id: int) -> List[str]:
        """Return all featured project ids for *round_id*."""

        with self.read_connection() as conn:
            rows = conn.execute(
                "SELECT project_hex FROM featured_projects WHERE round_id = ?",
                (round_id,),
            ).fetchall()
        return [str(row["project_hex"]) for row in rows]

    def replace_featured_projects(self, round_id: int, project_hex_list: Iterable[str]) -> None:
        """Replace the featured projects for *round_id* with *project_hex_list*."""

        data = [(round_id, project_hex) for project_hex in project_hex_list]
        with self.write_connection() as conn:
            conn.execute("DELETE FROM featured_projects WHERE round_id = ?", (round_id,))
            if data:
                conn.executemany(
                    "INSERT INTO featured_projects(round_id, project_hex) VALUES (?, ?)",
                    data,
                )

    def previous_featured_round(self, current_round: int) -> Optional[int]:
        """Return the most recent round id before *current_round* that has entries."""

        with self.read_connection() as conn:
            row = conn.execute(
                """
                SELECT DISTINCT round_id
                FROM featured_projects
                WHERE round_id < ?
                ORDER BY round_id DESC
                LIMIT 1
                """,
                (current_round,),
            ).fetchone()
        return int(row["round_id"]) if row else None

    # project_id_map helpers --------------------------------------------

    def get_project_mapping(self, project_hex: str) -> Optional[str]:
        """Return the cached backend id for the given project hex."""

        with self.read_connection() as conn:
            row = conn.execute(
                "SELECT backend_id FROM project_id_map WHERE project_hex = ?",
                (project_hex,),
            ).fetchone()
        return str(row["backend_id"]) if row else None

    def set_project_mapping(self, project_hex: str, backend_id: str) -> None:
        """Persist a mapping between a project hex and backend identifier."""

        with self.write_connection() as conn:
            conn.execute(
                """
                INSERT INTO project_id_map(project_hex, backend_id) VALUES (?, ?)
                ON CONFLICT(project_hex) DO UPDATE SET backend_id=excluded.backend_id
                """,
                (project_hex, backend_id),
            )

    # meta helpers -------------------------------------------------------

    def get_meta(self, key: str) -> Optional[str]:
        """Fetch a raw meta value."""

        with self.read_connection() as conn:
            row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return str(row["value"]) if row else None

    def set_meta(self, key: str, value: str) -> None:
        """Persist a meta value."""

        with self.write_connection() as conn:
            conn.execute(
                """
                INSERT INTO meta(key, value) VALUES(?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value
                """,
                (key, value),
            )

    def clear_meta(self, key: str) -> None:
        """Remove a meta entry."""

        with self.write_connection() as conn:
            conn.execute("DELETE FROM meta WHERE key = ?", (key,))

