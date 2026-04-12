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

    # token distribution helpers -------------------------------------------

    def ensure_token_distribution_schema(self) -> None:
        """Create tables for token distribution tracking if they don't exist."""

        with self.write_connection() as conn:
            conn.executescript("""
                -- Token distribution metrics cache
                CREATE TABLE IF NOT EXISTS token_distribution_cache (
                    token_address TEXT NOT NULL,
                    chain_id INTEGER NOT NULL,
                    holder_count INTEGER,
                    gini_coefficient REAL,
                    nakamoto_coefficient REAL,
                    top_10_pct REAL,
                    transaction_count INTEGER DEFAULT 0,
                    cached_at INTEGER NOT NULL,
                    PRIMARY KEY (token_address, chain_id)
                );

                -- All token holders (from direct blockchain fetching)
                CREATE TABLE IF NOT EXISTS token_holders_processed (
                    token_address TEXT NOT NULL,
                    chain_id INTEGER NOT NULL,
                    holder_address TEXT NOT NULL,
                    balance TEXT NOT NULL,
                    is_contract INTEGER NOT NULL,
                    processed_at INTEGER NOT NULL,
                    PRIMARY KEY (token_address, chain_id, holder_address)
                );

                -- Token scan progress tracking for incremental scanning
                CREATE TABLE IF NOT EXISTS token_scan_progress (
                    token_address TEXT NOT NULL,
                    chain_id INTEGER NOT NULL,
                    from_block INTEGER NOT NULL,
                    to_block INTEGER NOT NULL,
                    last_scanned_block INTEGER,
                    total_transactions INTEGER DEFAULT 0,
                    last_transaction_hash TEXT,
                    scanned_at INTEGER NOT NULL,
                    PRIMARY KEY (token_address, chain_id, from_block, to_block)
                );

                -- Enrichment data from Moralis (only when labels present)
                CREATE TABLE IF NOT EXISTS holder_enrichment (
                    holder_address TEXT NOT NULL,
                    chain_id INTEGER NOT NULL,
                    label TEXT,
                    holder_type TEXT,
                    is_whale INTEGER,
                    transaction_count INTEGER,
                    first_seen INTEGER,
                    last_updated INTEGER NOT NULL,
                    PRIMARY KEY (holder_address, chain_id)
                );

                -- Indexes for better query performance
                CREATE INDEX IF NOT EXISTS idx_token_holders_token
                    ON token_holders_processed(token_address, chain_id);
                CREATE INDEX IF NOT EXISTS idx_holder_enrichment_label
                    ON holder_enrichment(label);
                CREATE INDEX IF NOT EXISTS idx_token_scan_progress_token
                    ON token_scan_progress(token_address, chain_id);

                -- Event indexing tables for scalable distribution analysis
                CREATE TABLE IF NOT EXISTS token_transfers (
                    token_address TEXT NOT NULL,
                    chain_id INTEGER NOT NULL,
                    block_number INTEGER NOT NULL,
                    tx_hash TEXT NOT NULL,
                    tx_index INTEGER NOT NULL,
                    log_index INTEGER NOT NULL,
                    from_address TEXT NOT NULL,
                    to_address TEXT NOT NULL,
                    value TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    PRIMARY KEY (token_address, chain_id, block_number, tx_index, log_index)
                );

                CREATE TABLE IF NOT EXISTS token_holder_balances (
                    token_address TEXT NOT NULL,
                    chain_id INTEGER NOT NULL,
                    holder_address TEXT NOT NULL,
                    balance TEXT NOT NULL,
                    last_tx_block INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (token_address, chain_id, holder_address)
                );

                CREATE TABLE IF NOT EXISTS parallel_scan_state (
                    token_address TEXT NOT NULL,
                    chain_id INTEGER NOT NULL,
                    scan_id TEXT NOT NULL,
                    provider_id TEXT NOT NULL,
                    from_block INTEGER NOT NULL,
                    to_block INTEGER NOT NULL,
                    last_scanned_block INTEGER,
                    events_found INTEGER DEFAULT 0,
                    status TEXT NOT NULL,
                    started_at INTEGER,
                    completed_at INTEGER,
                    PRIMARY KEY (token_address, chain_id, scan_id, provider_id, from_block)
                );

                CREATE TABLE IF NOT EXISTS token_event_scan_progress (
                    token_address TEXT NOT NULL,
                    chain_id INTEGER NOT NULL,
                    deployment_block INTEGER NOT NULL,
                    current_block INTEGER NOT NULL,
                    last_scanned_block INTEGER,
                    total_events_indexed INTEGER DEFAULT 0,
                    last_scan_time INTEGER NOT NULL,
                    PRIMARY KEY (token_address, chain_id)
                );

                -- Indexes for event storage tables
                CREATE INDEX IF NOT EXISTS idx_token_transfers_token
                    ON token_transfers(token_address, chain_id);
                CREATE INDEX IF NOT EXISTS idx_token_transfers_from
                    ON token_transfers(from_address);
                CREATE INDEX IF NOT EXISTS idx_token_transfers_to
                    ON token_transfers(to_address);
                CREATE INDEX IF NOT EXISTS idx_token_transfers_block
                    ON token_transfers(block_number);
                CREATE INDEX IF NOT EXISTS idx_parallel_scan_token
                    ON parallel_scan_state(token_address, chain_id);
                CREATE INDEX IF NOT EXISTS idx_parallel_scan_status
                    ON parallel_scan_state(status);
            """)

    def get_token_scan_progress(self, token_address: str, chain_id: int) -> dict:
        """Get the latest scan progress for a token.

        Args:
            token_address: Token contract address
            chain_id: Chain ID

        Returns:
            Dict with last_scanned_block, total_transactions, or defaults if no prior scan
        """
        with self.read_connection() as conn:
            cursor = conn.execute("""
                SELECT last_scanned_block, total_transactions
                FROM token_scan_progress
                WHERE token_address = ? AND chain_id = ?
                ORDER BY scanned_at DESC
                LIMIT 1
            """, (token_address.lower(), chain_id))
            row = cursor.fetchone()

            if row:
                return {
                    "last_scanned_block": row[0],
                    "total_transactions": row[1] or 0
                }
            return {
                "last_scanned_block": None,
                "total_transactions": 0
            }

    def update_token_scan_progress(
        self,
        token_address: str,
        chain_id: int,
        from_block: int,
        to_block: int,
        last_scanned_block: int,
        transaction_count: int,
        last_tx_hash: str = None
    ) -> None:
        """Update scan progress for a token.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            from_block: Start block of scan range
            to_block: End block of scan range
            last_scanned_block: Last block successfully scanned
            transaction_count: Total transactions found in this scan
            last_tx_hash: Last transaction hash processed
        """
        import time
        with self.write_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO token_scan_progress
                (token_address, chain_id, from_block, to_block, last_scanned_block,
                 total_transactions, last_transaction_hash, scanned_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                token_address.lower(), chain_id, from_block, to_block, last_scanned_block,
                transaction_count, last_tx_hash, int(time.time())
            ))

    # Event indexing helpers -------------------------------------------

    def store_transfer_event(
        self,
        token_address: str,
        chain_id: int,
        block_number: int,
        tx_hash: str,
        tx_index: int,
        log_index: int,
        from_address: str,
        to_address: str,
        value: int,
        timestamp: int,
    ) -> None:
        """Store a Transfer event in the database.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            block_number: Block number of the event
            tx_hash: Transaction hash
            tx_index: Transaction index in block
            log_index: Log index in transaction
            from_address: Address sending tokens
            to_address: Address receiving tokens
            value: Amount transferred (as integer)
            timestamp: Block timestamp
        """
        with self.write_connection() as conn:
            conn.execute("""
                INSERT OR IGNORE INTO token_transfers
                (token_address, chain_id, block_number, tx_hash, tx_index, log_index,
                 from_address, to_address, value, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                token_address.lower(), chain_id, block_number, tx_hash.lower(),
                tx_index, log_index, from_address.lower(), to_address.lower(),
                str(value), timestamp
            ))

    def store_transfer_events_batch(
        self,
        events: List[dict],
    ) -> int:
        """Store multiple Transfer events in a single transaction.

        Args:
            events: List of event dicts with keys: token_address, chain_id,
                    block_number, tx_hash, tx_index, log_index, from_address,
                    to_address, value, timestamp

        Returns:
            Number of events stored
        """
        if not events:
            return 0

        import time
        with self.write_connection() as conn:
            cursor = conn.executemany("""
                INSERT OR IGNORE INTO token_transfers
                (token_address, chain_id, block_number, tx_hash, tx_index, log_index,
                 from_address, to_address, value, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                (
                    e["token_address"].lower(),
                    e["chain_id"],
                    e["block_number"],
                    e["tx_hash"].lower(),
                    e["tx_index"],
                    e["log_index"],
                    e["from_address"].lower(),
                    e["to_address"].lower(),
                    str(e["value"]),
                    e["timestamp"]
                )
                for e in events
            ])
            return cursor.rowcount

    def get_transfer_event_count(
        self,
        token_address: str,
        chain_id: int,
        from_block: Optional[int] = None,
        to_block: Optional[int] = None,
    ) -> int:
        """Get the count of Transfer events for a token.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            from_block: Optional start block (inclusive)
            to_block: Optional end block (inclusive)

        Returns:
            Number of events stored
        """
        with self.read_connection() as conn:
            query = """
                SELECT COUNT(*) FROM token_transfers
                WHERE token_address = ? AND chain_id = ?
            """
            params = [token_address.lower(), chain_id]

            if from_block is not None:
                query += " AND block_number >= ?"
                params.append(from_block)
            if to_block is not None:
                query += " AND block_number <= ?"
                params.append(to_block)

            cursor = conn.execute(query, params)
            return cursor.fetchone()[0]

    def get_event_scan_progress(
        self,
        token_address: str,
        chain_id: int,
    ) -> Optional[dict]:
        """Get event scan progress for a token.

        Args:
            token_address: Token contract address
            chain_id: Chain ID

        Returns:
            Dict with deployment_block, current_block, last_scanned_block,
                 total_events_indexed, last_scan_time, or None if no prior scan
        """
        with self.read_connection() as conn:
            cursor = conn.execute("""
                SELECT deployment_block, current_block, last_scanned_block,
                       total_events_indexed, last_scan_time
                FROM token_event_scan_progress
                WHERE token_address = ? AND chain_id = ?
            """, (token_address.lower(), chain_id))
            row = cursor.fetchone()

            if row:
                return {
                    "deployment_block": row[0],
                    "current_block": row[1],
                    "last_scanned_block": row[2],
                    "total_events_indexed": row[3],
                    "last_scan_time": row[4],
                }
            return None

    def update_event_scan_progress(
        self,
        token_address: str,
        chain_id: int,
        deployment_block: int,
        current_block: int,
        last_scanned_block: Optional[int],
        total_events_indexed: int,
    ) -> None:
        """Update event scan progress for a token.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            deployment_block: Deployment block of the token
            current_block: Current tip of the chain
            last_scanned_block: Last block scanned (None if not started)
            total_events_indexed: Total events indexed so far
        """
        import time
        with self.write_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO token_event_scan_progress
                (token_address, chain_id, deployment_block, current_block,
                 last_scanned_block, total_events_indexed, last_scan_time)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                token_address.lower(), chain_id, deployment_block, current_block,
                last_scanned_block, total_events_indexed, int(time.time())
            ))

    # Parallel scan coordination ----------------------------------------

    def create_parallel_scan(
        self,
        token_address: str,
        chain_id: int,
        scan_id: str,
        chunks: List[dict],
    ) -> None:
        """Create parallel scan tasks for multiple providers.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            scan_id: Unique scan identifier (UUID)
            chunks: List of chunk dicts with provider_id, from_block, to_block
        """
        import time
        now = int(time.time())
        with self.write_connection() as conn:
            conn.executemany("""
                INSERT INTO parallel_scan_state
                (token_address, chain_id, scan_id, provider_id, from_block, to_block,
                 last_scanned_block, events_found, status, started_at, completed_at)
                VALUES (?, ?, ?, ?, ?, ?, NULL, 0, 'pending', ?, NULL)
            """, [
                (token_address.lower(), chain_id, scan_id, chunk["provider_id"],
                 chunk["from_block"], chunk["to_block"], now)
                for chunk in chunks
            ])

    def get_pending_scan_chunks(
        self,
        token_address: str,
        chain_id: str,
        scan_id: str,
        limit: int = 10,
    ) -> List[dict]:
        """Get pending chunks for a parallel scan.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            scan_id: Scan identifier
            limit: Maximum number of chunks to return

        Returns:
            List of chunk dicts with provider_id, from_block, to_block
        """
        with self.read_connection() as conn:
            cursor = conn.execute("""
                SELECT provider_id, from_block, to_block
                FROM parallel_scan_state
                WHERE token_address = ? AND chain_id = ? AND scan_id = ? AND status = 'pending'
                ORDER BY from_block
                LIMIT ?
            """, (token_address.lower(), chain_id, scan_id, limit))

            return [
                {
                    "provider_id": row[0],
                    "from_block": row[1],
                    "to_block": row[2],
                }
                for row in cursor.fetchall()
            ]

    def update_scan_chunk(
        self,
        token_address: str,
        chain_id: int,
        scan_id: str,
        provider_id: str,
        from_block: int,
        last_scanned_block: int,
        events_found: int,
        status: str,
    ) -> None:
        """Update progress of a scan chunk.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            scan_id: Scan identifier
            provider_id: Provider identifier
            from_block: Chunk start block (part of key)
            last_scanned_block: Last block successfully scanned
            events_found: Number of events found in this chunk
            status: New status (in_progress, completed, failed)
        """
        import time
        with self.write_connection() as conn:
            if status == "completed":
                conn.execute("""
                    UPDATE parallel_scan_state
                    SET last_scanned_block = ?, events_found = ?, status = ?, completed_at = ?
                    WHERE token_address = ? AND chain_id = ? AND scan_id = ?
                          AND provider_id = ? AND from_block = ?
                """, (last_scanned_block, events_found, status, int(time.time()),
                      token_address.lower(), chain_id, scan_id, provider_id, from_block))
            else:
                conn.execute("""
                    UPDATE parallel_scan_state
                    SET last_scanned_block = ?, events_found = ?, status = ?
                    WHERE token_address = ? AND chain_id = ? AND scan_id = ?
                          AND provider_id = ? AND from_block = ?
                """, (last_scanned_block, events_found, status,
                      token_address.lower(), chain_id, scan_id, provider_id, from_block))

    def get_scan_status(
        self,
        token_address: str,
        chain_id: int,
        scan_id: str,
    ) -> dict:
        """Get overall status of a parallel scan.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            scan_id: Scan identifier

        Returns:
            Dict with status summary
        """
        with self.read_connection() as conn:
            cursor = conn.execute("""
                SELECT
                    COUNT(*) as total_chunks,
                    SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending,
                    SUM(CASE WHEN status = 'in_progress' THEN 1 ELSE 0 END) as in_progress,
                    SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
                    SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed,
                    SUM(events_found) as total_events,
                    MIN(from_block) as first_block,
                    MAX(to_block) as last_block
                FROM parallel_scan_state
                WHERE token_address = ? AND chain_id = ? AND scan_id = ?
            """, (token_address.lower(), chain_id, scan_id))
            row = cursor.fetchone()

            return {
                "total_chunks": row[0] or 0,
                "pending": row[1] or 0,
                "in_progress": row[2] or 0,
                "completed": row[3] or 0,
                "failed": row[4] or 0,
                "total_events": row[5] or 0,
                "first_block": row[6],
                "last_block": row[7],
            }

    # Balance cache helpers ---------------------------------------------

    def update_holder_balance(
        self,
        token_address: str,
        chain_id: int,
        holder_address: str,
        balance: int,
        last_tx_block: int,
    ) -> None:
        """Update the balance cache for a single holder.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            holder_address: Holder address
            balance: Current balance (as integer)
            last_tx_block: Block number of last transaction affecting this balance
        """
        import time
        with self.write_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO token_holder_balances
                (token_address, chain_id, holder_address, balance, last_tx_block, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                token_address.lower(), chain_id, holder_address.lower(),
                str(balance), last_tx_block, int(time.time())
            ))

    def get_holder_balance(
        self,
        token_address: str,
        chain_id: int,
        holder_address: str,
    ) -> Optional[int]:
        """Get the cached balance for a holder.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            holder_address: Holder address

        Returns:
            Balance as integer, or None if not cached
        """
        with self.read_connection() as conn:
            cursor = conn.execute("""
                SELECT balance FROM token_holder_balances
                WHERE token_address = ? AND chain_id = ? AND holder_address = ?
            """, (token_address.lower(), chain_id, holder_address.lower()))
            row = cursor.fetchone()

            if row:
                return int(row[0])
            return None

    def get_all_holder_balances(
        self,
        token_address: str,
        chain_id: int,
        min_balance: int = 0,
    ) -> List[tuple]:
        """Get all cached holder balances for a token.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            min_balance: Minimum balance (default 0 = all holders)

        Returns:
            List of (holder_address, balance, last_tx_block) tuples, ordered by balance desc
        """
        with self.read_connection() as conn:
            cursor = conn.execute("""
                SELECT holder_address, balance, last_tx_block
                FROM token_holder_balances
                WHERE token_address = ? AND chain_id = ? AND CAST(balance AS INTEGER) >= ?
                ORDER BY CAST(balance AS INTEGER) DESC
            """, (token_address.lower(), chain_id, min_balance))

            return [
                (row[0], int(row[1]), row[2])
                for row in cursor.fetchall()
            ]

    def clear_balance_cache(
        self,
        token_address: str,
        chain_id: int,
    ) -> None:
        """Clear the balance cache for a token.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
        """
        with self.write_connection() as conn:
            conn.execute("""
                DELETE FROM token_holder_balances
                WHERE token_address = ? AND chain_id = ?
            """, (token_address.lower(), chain_id))

    # RPC provider failure tracking helpers -----------------------------------

    def ensure_rpc_failure_schema(self) -> None:
        """Create tables for RPC provider per-block failure tracking."""
        with self.write_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS rpc_provider_failures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chain_id INTEGER NOT NULL,
                    provider_url TEXT NOT NULL,
                    block_number INTEGER NOT NULL,
                    method TEXT NOT NULL,
                    error_message TEXT,
                    failed_at REAL NOT NULL,
                    retry_count INTEGER DEFAULT 0,
                    last_retry_at REAL,
                    UNIQUE(chain_id, provider_url, block_number, method)
                );

                CREATE INDEX IF NOT EXISTS idx_rpc_failures_lookup
                    ON rpc_provider_failures(chain_id, block_number, method);
                CREATE INDEX IF NOT EXISTS idx_rpc_failures_provider
                    ON rpc_provider_failures(provider_url, chain_id);
                CREATE INDEX IF NOT EXISTS idx_rpc_failures_time
                    ON rpc_provider_failures(failed_at);
            """)

    def record_rpc_failure(
        self,
        chain_id: int,
        provider_url: str,
        block_number: int,
        method: str,
        error_message: str,
    ) -> int:
        """Record an RPC provider failure at a specific block.

        Args:
            chain_id: Chain ID
            provider_url: Provider URL
            block_number: Block number where failure occurred
            method: RPC method name (e.g., eth_getLogs, eth_call)
            error_message: Error message

        Returns:
            The failure record ID
        """
        import time
        self.ensure_rpc_failure_schema()
        with self.write_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO rpc_provider_failures
                (chain_id, provider_url, block_number, method, error_message, failed_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(chain_id, provider_url, block_number, method)
                DO UPDATE SET
                    error_message = excluded.error_message,
                    failed_at = excluded.failed_at,
                    retry_count = retry_count + 1,
                    last_retry_at = excluded.failed_at
            """, (chain_id, provider_url, block_number, method, error_message, time.time()))
            return cursor.lastrowid

    def clear_rpc_failures_for_block(
        self,
        chain_id: int,
        provider_url: str,
        block_number: int,
        method: Optional[str] = None,
    ) -> int:
        """Clear failures for a provider at a specific block.

        Args:
            chain_id: Chain ID
            provider_url: Provider URL
            block_number: Block number
            method: Optional method filter (clears all methods if None)

        Returns:
            Number of rows cleared
        """
        self.ensure_rpc_failure_schema()
        with self.write_connection() as conn:
            if method:
                cursor = conn.execute("""
                    DELETE FROM rpc_provider_failures
                    WHERE chain_id = ? AND provider_url = ?
                          AND block_number = ? AND method = ?
                """, (chain_id, provider_url, block_number, method))
            else:
                cursor = conn.execute("""
                    DELETE FROM rpc_provider_failures
                    WHERE chain_id = ? AND provider_url = ? AND block_number = ?
                """, (chain_id, provider_url, block_number))
            return cursor.rowcount

    def get_providers_that_failed_at_block(
        self,
        chain_id: int,
        block_number: int,
        method: Optional[str] = None,
    ) -> List[str]:
        """Get list of provider URLs that failed at a specific block.

        Args:
            chain_id: Chain ID
            block_number: Block number
            method: Optional method filter

        Returns:
            List of provider URLs
        """
        self.ensure_rpc_failure_schema()
        with self.read_connection() as conn:
            if method:
                cursor = conn.execute("""
                    SELECT DISTINCT provider_url
                    FROM rpc_provider_failures
                    WHERE chain_id = ? AND block_number = ? AND method = ?
                """, (chain_id, block_number, method))
            else:
                cursor = conn.execute("""
                    SELECT DISTINCT provider_url
                    FROM rpc_provider_failures
                    WHERE chain_id = ? AND block_number = ?
                """, (chain_id, block_number))
            return [row[0] for row in cursor.fetchall()]

    def get_provider_failure_count_at_block(
        self,
        chain_id: int,
        provider_url: str,
        block_number: int,
        method: Optional[str] = None,
    ) -> int:
        """Get failure count for a provider at a specific block.

        Args:
            chain_id: Chain ID
            provider_url: Provider URL
            block_number: Block number
            method: Optional method filter

        Returns:
            Number of failure records (1 if exists, 0 if not)
        """
        self.ensure_rpc_failure_schema()
        with self.read_connection() as conn:
            if method:
                cursor = conn.execute("""
                    SELECT COUNT(*) FROM rpc_provider_failures
                    WHERE chain_id = ? AND provider_url = ?
                          AND block_number = ? AND method = ?
                """, (chain_id, provider_url, block_number, method))
            else:
                cursor = conn.execute("""
                    SELECT COUNT(*) FROM rpc_provider_failures
                    WHERE chain_id = ? AND provider_url = ? AND block_number = ?
                """, (chain_id, provider_url, block_number))
            return cursor.fetchone()[0]

    def cleanup_old_rpc_failures(self, older_than_seconds: int = 7 * 24 * 3600) -> int:
        """Clean up old RPC failure records.

        Args:
            older_than_seconds: Remove failures older than this (default: 7 days)

        Returns:
            Number of rows deleted
        """
        import time
        self.ensure_rpc_failure_schema()
        cutoff = time.time() - older_than_seconds
        with self.write_connection() as conn:
            cursor = conn.execute("""
                DELETE FROM rpc_provider_failures WHERE failed_at < ?
            """, (cutoff,))
            return cursor.rowcount

    # Token holder data API provider helpers -----------------------------------

    def ensure_holder_data_schema(self) -> None:
        """Create tables for multi-provider token holder data with historical tracking."""
        with self.write_connection() as conn:
            conn.executescript("""
                -- Top holders (raw data from any provider)
                CREATE TABLE IF NOT EXISTS token_holder_top_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token_address TEXT NOT NULL,
                    chain_id INTEGER NOT NULL,
                    snapshot_date TEXT NOT NULL,
                    provider_name TEXT NOT NULL,
                    holder_rank INTEGER NOT NULL,
                    holder_address TEXT NOT NULL,
                    holder_balance TEXT NOT NULL,
                    holder_balance_int INTEGER NOT NULL,
                    percent_supply REAL,
                    is_contract INTEGER,
                    created_at REAL NOT NULL,
                    UNIQUE(token_address, chain_id, snapshot_date, provider_name, holder_rank)
                );

                -- Weekly snapshots (aggregated metrics)
                CREATE TABLE IF NOT EXISTS token_holder_weekly_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token_address TEXT NOT NULL,
                    chain_id INTEGER NOT NULL,
                    week_start TEXT NOT NULL,
                    week_end TEXT NOT NULL,
                    provider_name TEXT NOT NULL,
                    holder_count INTEGER NOT NULL,
                    gini_coefficient REAL NOT NULL,
                    nakamoto_coefficient INTEGER NOT NULL,
                    top_10_pct_supply REAL NOT NULL,
                    top_1_pct_supply REAL NOT NULL,
                    top_100_balance_sum TEXT NOT NULL,
                    estimated_total_supply TEXT,
                    created_at REAL NOT NULL,
                    UNIQUE(token_address, chain_id, week_start)
                );

                -- Monthly snapshots (last weekly record of each month)
                CREATE TABLE IF NOT EXISTS token_holder_monthly_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token_address TEXT NOT NULL,
                    chain_id INTEGER NOT NULL,
                    month TEXT NOT NULL,
                    holder_count INTEGER NOT NULL,
                    gini_coefficient REAL NOT NULL,
                    nakamoto_coefficient INTEGER NOT NULL,
                    top_10_pct_supply REAL NOT NULL,
                    top_1_pct_supply REAL NOT NULL,
                    top_100_balance_sum TEXT NOT NULL,
                    estimated_total_supply TEXT,
                    source_week_id INTEGER,
                    created_at REAL NOT NULL,
                    UNIQUE(token_address, chain_id, month)
                );

                -- Yearly snapshots (single snapshot per year, averaged from monthly)
                CREATE TABLE IF NOT EXISTS token_holder_yearly_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token_address TEXT NOT NULL,
                    chain_id INTEGER NOT NULL,
                    year INTEGER NOT NULL,
                    holder_count INTEGER NOT NULL,
                    gini_coefficient REAL NOT NULL,
                    nakamoto_coefficient INTEGER NOT NULL,
                    top_10_pct_supply REAL NOT NULL,
                    top_1_pct_supply REAL NOT NULL,
                    top_100_balance_sum TEXT NOT NULL,
                    estimated_total_supply TEXT,
                    is_average INTEGER DEFAULT 1,
                    created_at REAL NOT NULL,
                    UNIQUE(token_address, chain_id, year)
                );

                -- Indexes for efficient queries
                CREATE INDEX IF NOT EXISTS idx_top_data_token_date
                    ON token_holder_top_data(token_address, chain_id, snapshot_date);
                CREATE INDEX IF NOT EXISTS idx_weekly_token_week
                    ON token_holder_weekly_snapshots(token_address, chain_id, week_start);
                CREATE INDEX IF NOT EXISTS idx_monthly_token_month
                    ON token_holder_monthly_snapshots(token_address, chain_id, month);
                CREATE INDEX IF NOT EXISTS idx_yearly_token_year
                    ON token_holder_yearly_snapshots(token_address, chain_id, year);
            """)

    def store_top_holder_data(
        self,
        token_address: str,
        chain_id: int,
        snapshot_date: str,
        provider_name: str,
        holder_rank: int,
        holder_address: str,
        holder_balance_hex: str,
        holder_balance_int: int,
        percent_supply: float = 0.0,
        is_contract: bool = False,
    ) -> None:
        """Store raw top holder data from any provider.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            snapshot_date: ISO date string (YYYY-MM-DD)
            provider_name: Name of the provider (NodeReal, Moralis, etc.)
            holder_rank: Rank of the holder (1-100)
            holder_address: Holder wallet address
            holder_balance_hex: Balance as hex string
            holder_balance_int: Balance as integer
            percent_supply: Percentage of total supply
            is_contract: Whether the holder is a contract
        """
        import time
        self.ensure_holder_data_schema()
        with self.write_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO token_holder_top_data
                (token_address, chain_id, snapshot_date, provider_name, holder_rank,
                 holder_address, holder_balance, holder_balance_int, percent_supply,
                 is_contract, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                token_address.lower(), chain_id, snapshot_date, provider_name,
                holder_rank, holder_address.lower(), holder_balance_hex,
                holder_balance_int, percent_supply, int(is_contract), time.time()
            ))

    def store_weekly_snapshot(
        self,
        token_address: str,
        chain_id: int,
        week_start: str,
        week_end: str,
        provider_name: str,
        holder_count: int,
        gini_coefficient: float,
        nakamoto_coefficient: int,
        top_10_pct_supply: float,
        top_1_pct_supply: float,
        top_100_balance_sum: str,
        estimated_total_supply: str,
    ) -> int:
        """Store weekly aggregated snapshot.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            week_start: ISO date (YYYY-MM-DD)
            week_end: ISO date (YYYY-MM-DD)
            provider_name: Name of the provider used
            holder_count: Total holder count
            gini_coefficient: Gini coefficient (0-1)
            nakamoto_coefficient: Nakamoto coefficient
            top_10_pct_supply: Top 10% holders' supply percentage
            top_1_pct_supply: Top 1% holders' supply percentage
            top_100_balance_sum: Sum of top 100 balances as hex string
            estimated_total_supply: Total supply as hex string (from totalSupply call)

        Returns:
            The snapshot record ID
        """
        import time
        self.ensure_holder_data_schema()
        with self.write_connection() as conn:
            cursor = conn.execute("""
                INSERT OR REPLACE INTO token_holder_weekly_snapshots
                (token_address, chain_id, week_start, week_end, provider_name,
                 holder_count, gini_coefficient, nakamoto_coefficient,
                 top_10_pct_supply, top_1_pct_supply, top_100_balance_sum,
                 estimated_total_supply, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                token_address.lower(), chain_id, week_start, week_end, provider_name,
                holder_count, gini_coefficient, nakamoto_coefficient,
                top_10_pct_supply, top_1_pct_supply, top_100_balance_sum,
                estimated_total_supply, time.time()
            ))
            return cursor.lastrowid

    def get_latest_weekly_snapshot(
        self,
        token_address: str,
        chain_id: int,
    ) -> Optional[dict]:
        """Get the latest weekly snapshot for a token.

        Args:
            token_address: Token contract address
            chain_id: Chain ID

        Returns:
            Dict with snapshot data or None
        """
        self.ensure_holder_data_schema()
        with self.read_connection() as conn:
            cursor = conn.execute("""
                SELECT id, token_address, chain_id, week_start, week_end, provider_name,
                       holder_count, gini_coefficient, nakamoto_coefficient,
                       top_10_pct_supply, top_1_pct_supply, top_100_balance_sum,
                       estimated_total_supply
                FROM token_holder_weekly_snapshots
                WHERE token_address = ? AND chain_id = ?
                ORDER BY week_start DESC
                LIMIT 1
            """, (token_address.lower(), chain_id))
            row = cursor.fetchone()

            if row:
                return {
                    "id": row[0],
                    "token_address": row[1],
                    "chain_id": row[2],
                    "week_start": row[3],
                    "week_end": row[4],
                    "provider_name": row[5],
                    "holder_count": row[6],
                    "gini_coefficient": row[7],
                    "nakamoto_coefficient": row[8],
                    "top_10_pct_supply": row[9],
                    "top_1_pct_supply": row[10],
                    "top_100_balance_sum": row[11],
                    "estimated_total_supply": row[12],
                }
            return None

    def store_monthly_snapshot(
        self,
        token_address: str,
        chain_id: int,
        month: str,
        holder_count: int,
        gini_coefficient: float,
        nakamoto_coefficient: int,
        top_10_pct_supply: float,
        top_1_pct_supply: float,
        top_100_balance_sum: str,
        estimated_total_supply: str,
        source_week_id: Optional[int] = None,
    ) -> int:
        """Store monthly snapshot.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            month: ISO month (YYYY-MM)
            holder_count: Total holder count
            gini_coefficient: Gini coefficient (0-1)
            nakamoto_coefficient: Nakamoto coefficient
            top_10_pct_supply: Top 10% holders' supply percentage
            top_1_pct_supply: Top 1% holders' supply percentage
            top_100_balance_sum: Sum of top 100 balances as hex string
            estimated_total_supply: Total supply as hex string (from totalSupply call)
            source_week_id: Optional reference to source weekly snapshot

        Returns:
            The snapshot record ID
        """
        import time
        self.ensure_holder_data_schema()
        with self.write_connection() as conn:
            cursor = conn.execute("""
                INSERT OR REPLACE INTO token_holder_monthly_snapshots
                (token_address, chain_id, month, holder_count, gini_coefficient,
                 nakamoto_coefficient, top_10_pct_supply, top_1_pct_supply,
                 top_100_balance_sum, estimated_total_supply, source_week_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                token_address.lower(), chain_id, month, holder_count, gini_coefficient,
                nakamoto_coefficient, top_10_pct_supply, top_1_pct_supply,
                top_100_balance_sum, estimated_total_supply, source_week_id, time.time()
            ))
            return cursor.lastrowid

    def get_monthly_snapshots_for_year(
        self,
        token_address: str,
        chain_id: int,
        year: int,
    ) -> List[dict]:
        """Get all monthly snapshots for a specific year.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            year: Year (e.g., 2024)

        Returns:
            List of monthly snapshot dicts
        """
        self.ensure_holder_data_schema()
        with self.read_connection() as conn:
            cursor = conn.execute("""
                SELECT id, token_address, chain_id, month, holder_count,
                       gini_coefficient, nakamoto_coefficient,
                       top_10_pct_supply, top_1_pct_supply, top_100_balance_sum,
                       estimated_total_supply
                FROM token_holder_monthly_snapshots
                WHERE token_address = ? AND chain_id = ? AND month LIKE ?
                ORDER BY month
            """, (token_address.lower(), chain_id, f"{year}-%"))

            return [
                {
                    "id": row[0],
                    "token_address": row[1],
                    "chain_id": row[2],
                    "month": row[3],
                    "holder_count": row[4],
                    "gini_coefficient": row[5],
                    "nakamoto_coefficient": row[6],
                    "top_10_pct_supply": row[7],
                    "top_1_pct_supply": row[8],
                    "top_100_balance_sum": row[9],
                    "estimated_total_supply": row[10],
                }
                for row in cursor.fetchall()
            ]

    def store_yearly_snapshot(
        self,
        token_address: str,
        chain_id: int,
        year: int,
        holder_count: int,
        gini_coefficient: float,
        nakamoto_coefficient: int,
        top_10_pct_supply: float,
        top_1_pct_supply: float,
        top_100_balance_sum: str,
        estimated_total_supply: str,
        is_average: bool = True,
    ) -> int:
        """Store yearly snapshot.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            year: Year (e.g., 2024)
            holder_count: Total holder count
            gini_coefficient: Gini coefficient (0-1)
            nakamoto_coefficient: Nakamoto coefficient
            top_10_pct_supply: Top 10% holders' supply percentage
            top_1_pct_supply: Top 1% holders' supply percentage
            top_100_balance_sum: Sum of top 100 balances as hex string
            estimated_total_supply: Total supply as hex string (from totalSupply call)
            is_average: Whether this is averaged from monthly data

        Returns:
            The snapshot record ID
        """
        import time
        self.ensure_holder_data_schema()
        with self.write_connection() as conn:
            cursor = conn.execute("""
                INSERT OR REPLACE INTO token_holder_yearly_snapshots
                (token_address, chain_id, year, holder_count, gini_coefficient,
                 nakamoto_coefficient, top_10_pct_supply, top_1_pct_supply,
                 top_100_balance_sum, estimated_total_supply, is_average, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                token_address.lower(), chain_id, year, holder_count, gini_coefficient,
                nakamoto_coefficient, top_10_pct_supply, top_1_pct_supply,
                top_100_balance_sum, estimated_total_supply, int(is_average), time.time()
            ))
            return cursor.lastrowid

    def get_historical_snapshots(
        self,
        token_address: str,
        chain_id: int,
        from_date: Optional[str] = None,
        to_date: Optional[str] = None,
        snapshot_type: str = "weekly",
    ) -> List[dict]:
        """Get historical snapshots for a token.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            from_date: Optional start date (YYYY-MM-DD or YYYY-MM)
            to_date: Optional end date (YYYY-MM-DD or YYYY-MM)
            snapshot_type: Type of snapshot ('weekly', 'monthly', or 'yearly')

        Returns:
            List of snapshot dicts ordered by date descending
        """
        self.ensure_holder_data_schema()

        table_map = {
            "weekly": "token_holder_weekly_snapshots",
            "monthly": "token_holder_monthly_snapshots",
            "yearly": "token_holder_yearly_snapshots",
        }

        if snapshot_type not in table_map:
            raise ValueError(f"Invalid snapshot_type: {snapshot_type}")

        table = table_map[snapshot_type]
        date_column = "week_start" if snapshot_type == "weekly" else ("month" if snapshot_type == "monthly" else "year")

        query = f"""
            SELECT id, token_address, chain_id, {date_column}, holder_count,
                   gini_coefficient, nakamoto_coefficient,
                   top_10_pct_supply, top_1_pct_supply, top_100_balance_sum,
                   estimated_total_supply
            FROM {table}
            WHERE token_address = ? AND chain_id = ?
        """
        params = [token_address.lower(), chain_id]

        if from_date:
            query += f" AND {date_column} >= ?"
            params.append(from_date)
        if to_date:
            query += f" AND {date_column} <= ?"
            params.append(to_date)

        query += f" ORDER BY {date_column} DESC"

        with self.read_connection() as conn:
            cursor = conn.execute(query, params)
            rows = cursor.fetchall()

            if snapshot_type == "weekly":
                return [
                    {
                        "id": row[0],
                        "token_address": row[1],
                        "chain_id": row[2],
                        "week_start": row[3],
                        "holder_count": row[4],
                        "gini_coefficient": row[5],
                        "nakamoto_coefficient": row[6],
                        "top_10_pct_supply": row[7],
                        "top_1_pct_supply": row[8],
                        "top_100_balance_sum": row[9],
                        "estimated_total_supply": row[10],
                    }
                    for row in rows
                ]
            elif snapshot_type == "monthly":
                return [
                    {
                        "id": row[0],
                        "token_address": row[1],
                        "chain_id": row[2],
                        "month": row[3],
                        "holder_count": row[4],
                        "gini_coefficient": row[5],
                        "nakamoto_coefficient": row[6],
                        "top_10_pct_supply": row[7],
                        "top_1_pct_supply": row[8],
                        "top_100_balance_sum": row[9],
                        "estimated_total_supply": row[10],
                    }
                    for row in rows
                ]
            else:  # yearly
                return [
                    {
                        "id": row[0],
                        "token_address": row[1],
                        "chain_id": row[2],
                        "year": row[3],
                        "holder_count": row[4],
                        "gini_coefficient": row[5],
                        "nakamoto_coefficient": row[6],
                        "top_10_pct_supply": row[7],
                        "top_1_pct_supply": row[8],
                        "top_100_balance_sum": row[9],
                        "estimated_total_supply": row[10],
                    }
                    for row in rows
                ]

    def cleanup_old_snapshots(
        self,
        weekly_months: int = 13,
        monthly_months: int = 25,
        top_data_months: int = 13,
    ) -> dict:
        """Implement retention policy for old snapshots.

        Retention rules:
        - Weekly snapshots: Keep specified months (default 13)
        - Monthly snapshots: Keep specified months (default 25)
        - Yearly snapshots: Keep forever (historical data)
        - Top holder raw data: Keep specified months (default 13)

        Args:
            weekly_months: Months to keep weekly snapshots (default 13)
            monthly_months: Months to keep monthly snapshots (default 25)
            top_data_months: Months to keep top holder raw data (default 13)

        Returns:
            Dictionary with cleanup counts
        """
        from datetime import datetime, timedelta

        counts = {
            "weekly_deleted": 0,
            "monthly_deleted": 0,
            "top_data_deleted": 0,
        }

        self.ensure_holder_data_schema()
        cutoff_date = datetime.utcnow()

        # Delete weekly snapshots older than specified months
        weekly_cutoff = cutoff_date - timedelta(days=weekly_months * 30)
        with self.write_connection() as conn:
            cursor = conn.execute("""
                DELETE FROM token_holder_weekly_snapshots
                WHERE week_start < ?
            """, (weekly_cutoff.strftime("%Y-%m-%d"),))
            counts["weekly_deleted"] = cursor.rowcount

        # Delete monthly snapshots older than specified months
        monthly_cutoff = cutoff_date - timedelta(days=monthly_months * 30)
        with self.write_connection() as conn:
            cursor = conn.execute("""
                DELETE FROM token_holder_monthly_snapshots
                WHERE month < ?
            """, (monthly_cutoff.strftime("%Y-%m"),))
            counts["monthly_deleted"] = cursor.rowcount

        # Delete top 100 raw data older than specified months
        top_data_cutoff = cutoff_date - timedelta(days=top_data_months * 30)
        with self.write_connection() as conn:
            cursor = conn.execute("""
                DELETE FROM token_holder_top_data
                WHERE snapshot_date < ?
            """, (top_data_cutoff.strftime("%Y-%m-%d"),))
            counts["top_data_deleted"] = cursor.rowcount

        return counts

    # Liquidity analysis helpers ---------------------------------------------

    def ensure_liquidity_schema(self) -> None:
        """Create tables for liquidity analysis snapshots."""
        with self.write_connection() as conn:
            conn.executescript("""
                -- Liquidity analysis snapshots
                CREATE TABLE IF NOT EXISTS liquidity_analysis_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token_address TEXT NOT NULL,
                    chain_id TEXT NOT NULL,
                    total_tvl_usd REAL NOT NULL,
                    total_pairs INTEGER NOT NULL,
                    unique_dexes INTEGER NOT NULL,
                    largest_pool_tvl_pct REAL NOT NULL,
                    dex_diversity_score REAL NOT NULL,
                    tvl_tier TEXT NOT NULL,
                    avg_pool_balance_score REAL NOT NULL,
                    imbalanced_pools_count INTEGER NOT NULL,
                    total_volume_h24 REAL NOT NULL,
                    total_txns_h24 INTEGER NOT NULL,
                    liquidity_score REAL NOT NULL,
                    risk_level TEXT NOT NULL,
                    flags TEXT,
                    chains_with_liquidity TEXT,
                    recommendations TEXT,
                    analyzed_at TEXT NOT NULL,
                    UNIQUE(token_address, chain_id, analyzed_at)
                );

                -- Indexes for efficient queries
                CREATE INDEX IF NOT EXISTS idx_liquidity_token_chain
                    ON liquidity_analysis_snapshots(token_address, chain_id);
                CREATE INDEX IF NOT EXISTS idx_liquidity_analyzed_at
                    ON liquidity_analysis_snapshots(analyzed_at DESC);
                CREATE INDEX IF NOT EXISTS idx_liquidity_score
                    ON liquidity_analysis_snapshots(liquidity_score);
            """)

    def get_liquidity_snapshots(
        self,
        token_address: str,
        chain_id: str,
        limit: int = 10,
    ) -> List[dict]:
        """Get historical liquidity snapshots for a token.

        Args:
            token_address: Token contract address
            chain_id: Chain ID (e.g., "ethereum", "bsc")
            limit: Maximum number of snapshots to return

        Returns:
            List of snapshot dicts ordered by analyzed_at descending
        """
        self.ensure_liquidity_schema()
        with self.read_connection() as conn:
            cursor = conn.execute("""
                SELECT id, token_address, chain_id, total_tvl_usd, total_pairs, unique_dexes,
                       largest_pool_tvl_pct, dex_diversity_score, tvl_tier,
                       avg_pool_balance_score, imbalanced_pools_count, total_volume_h24,
                       total_txns_h24, liquidity_score, risk_level, flags,
                       chains_with_liquidity, recommendations, analyzed_at
                FROM liquidity_analysis_snapshots
                WHERE token_address = ? AND chain_id = ?
                ORDER BY analyzed_at DESC
                LIMIT ?
            """, (token_address.lower(), chain_id, limit))

            return [
                {
                    "id": row[0],
                    "token_address": row[1],
                    "chain_id": row[2],
                    "total_tvl_usd": row[3],
                    "total_pairs": row[4],
                    "unique_dexes": row[5],
                    "largest_pool_tvl_pct": row[6],
                    "dex_diversity_score": row[7],
                    "tvl_tier": row[8],
                    "avg_pool_balance_score": row[9],
                    "imbalanced_pools_count": row[10],
                    "total_volume_h24": row[11],
                    "total_txns_h24": row[12],
                    "liquidity_score": row[13],
                    "risk_level": row[14],
                    "flags": row[15],
                    "chains_with_liquidity": row[16],
                    "recommendations": row[17],
                    "analyzed_at": row[18],
                }
                for row in cursor.fetchall()
            ]

    def store_liquidity_snapshot(
        self,
        token_address: str,
        chain_id: str,
        total_tvl_usd: float,
        total_pairs: int,
        unique_dexes: int,
        largest_pool_tvl_pct: float,
        dex_diversity_score: float,
        tvl_tier: str,
        avg_pool_balance_score: float,
        imbalanced_pools_count: int,
        total_volume_h24: float,
        total_txns_h24: int,
        liquidity_score: float,
        risk_level: str,
        flags: List[str],
        chains_with_liquidity: List[str],
        recommendations: List[str],
        analyzed_at: str,
    ) -> int:
        """Store a liquidity analysis snapshot.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            total_tvl_usd: Total value locked in USD
            total_pairs: Number of trading pairs
            unique_dexes: Number of unique DEXs
            largest_pool_tvl_pct: Largest pool as percentage of TVL
            dex_diversity_score: DEX diversity score (0-1)
            tvl_tier: TVL tier classification
            avg_pool_balance_score: Average pool balance score
            imbalanced_pools_count: Number of imbalanced pools
            total_volume_h24: Total 24h volume
            total_txns_h24: Total 24h transactions
            liquidity_score: Overall liquidity score (0-100)
            risk_level: Risk level (low/medium/high/critical)
            flags: List of risk flags
            chains_with_liquidity: List of chains with liquidity
            recommendations: List of recommendations
            analyzed_at: ISO timestamp of analysis

        Returns:
            The snapshot record ID
        """
        import json
        import logging
        LOGGER = logging.getLogger(__name__)
        LOGGER.info(f"store_liquidity_snapshot called for {token_address} on {chain_id}")
        self.ensure_liquidity_schema()
        with self.write_connection() as conn:
            cursor = conn.execute("""
                INSERT OR REPLACE INTO liquidity_analysis_snapshots
                (token_address, chain_id, total_tvl_usd, total_pairs, unique_dexes,
                 largest_pool_tvl_pct, dex_diversity_score, tvl_tier, avg_pool_balance_score,
                 imbalanced_pools_count, total_volume_h24, total_txns_h24,
                 liquidity_score, risk_level, flags, chains_with_liquidity, recommendations, analyzed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                token_address.lower(), chain_id, total_tvl_usd, total_pairs, unique_dexes,
                largest_pool_tvl_pct, dex_diversity_score, tvl_tier, avg_pool_balance_score,
                imbalanced_pools_count, total_volume_h24, total_txns_h24,
                liquidity_score, risk_level, json.dumps(flags),
                json.dumps(chains_with_liquidity), json.dumps(recommendations),
                analyzed_at,
            ))
            return cursor.lastrowid

    def cleanup_old_liquidity_snapshots(
        self,
        months: int = 13,
    ) -> int:
        """Clean up old liquidity snapshots.

        Args:
            months: Number of months to keep (default: 13)

        Returns:
            Number of snapshots deleted
        """
        from datetime import datetime, timedelta

        self.ensure_liquidity_schema()
        cutoff = datetime.utcnow() - timedelta(days=months * 30)

        with self.write_connection() as conn:
            cursor = conn.execute("""
                DELETE FROM liquidity_analysis_snapshots
                WHERE analyzed_at < ?
            """, (cutoff.isoformat(),))
            return cursor.rowcount

    # Tokenomics analysis -----------------------------------------------

    def ensure_tokenomics_schema(self) -> None:
        """Ensure tokenomics analysis tables exist."""

        with self.write_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS tokenomics_analysis_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token_address TEXT NOT NULL,
                    chain_id TEXT NOT NULL,
                    total_supply TEXT NOT NULL,
                    max_supply TEXT,
                    supply_tier TEXT NOT NULL,
                    total_holders INTEGER NOT NULL,
                    top_10_holder_pct REAL NOT NULL,
                    contract_holder_pct REAL NOT NULL,
                    staking_contract_pct REAL NOT NULL,
                    gini_coefficient REAL NOT NULL,
                    nakamoto_coefficient INTEGER NOT NULL,
                    utility_flags TEXT,
                    vesting_flags TEXT,
                    tokenomics_score REAL NOT NULL,
                    risk_level TEXT NOT NULL,
                    flags TEXT,
                    recommendations TEXT,
                    analyzed_at TEXT NOT NULL,
                    UNIQUE(token_address, chain_id, analyzed_at)
                );

                CREATE INDEX IF NOT EXISTS idx_tokenomics_token_chain
                    ON tokenomics_analysis_snapshots(token_address, chain_id);
                CREATE INDEX IF NOT EXISTS idx_tokenomics_analyzed_at
                    ON tokenomics_analysis_snapshots(analyzed_at DESC);
                CREATE INDEX IF NOT EXISTS idx_tokenomics_score
                    ON tokenomics_analysis_snapshots(tokenomics_score);
            """)

    def get_tokenomics_snapshots(
        self,
        token_address: str,
        chain_id: str,
        limit: int = 10,
    ) -> List[dict]:
        """Get historical tokenomics snapshots for a token.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            limit: Maximum number of snapshots

        Returns:
            List of snapshot dicts ordered by analyzed_at descending
        """
        import json
        self.ensure_tokenomics_schema()
        with self.read_connection() as conn:
            cursor = conn.execute("""
                SELECT id, token_address, chain_id, total_supply, max_supply, supply_tier,
                       total_holders, top_10_holder_pct, contract_holder_pct, staking_contract_pct,
                       gini_coefficient, nakamoto_coefficient, utility_flags, vesting_flags,
                       tokenomics_score, risk_level, flags, recommendations, analyzed_at
                FROM tokenomics_analysis_snapshots
                WHERE token_address = ? AND chain_id = ?
                ORDER BY analyzed_at DESC
                LIMIT ?
            """, (token_address.lower(), chain_id, limit))

            return [
                {
                    "id": row[0],
                    "token_address": row[1],
                    "chain_id": row[2],
                    "total_supply": row[3],
                    "max_supply": row[4],
                    "supply_tier": row[5],
                    "total_holders": row[6],
                    "top_10_holder_pct": row[7],
                    "contract_holder_pct": row[8],
                    "staking_contract_pct": row[9],
                    "gini_coefficient": row[10],
                    "nakamoto_coefficient": row[11],
                    "utility_flags": json.loads(row[12]) if row[12] else [],
                    "vesting_flags": json.loads(row[13]) if row[13] else [],
                    "tokenomics_score": row[14],
                    "risk_level": row[15],
                    "flags": json.loads(row[16]) if row[16] else [],
                    "recommendations": json.loads(row[17]) if row[17] else [],
                    "analyzed_at": row[18],
                }
                for row in cursor.fetchall()
            ]

    def store_tokenomics_snapshot(
        self,
        token_address: str,
        chain_id: str,
        total_supply: int,
        max_supply: Optional[int],
        supply_tier: str,
        total_holders: int,
        top_10_holder_pct: float,
        contract_holder_pct: float,
        staking_contract_pct: float,
        gini_coefficient: float,
        nakamoto_coefficient: int,
        utility_flags: str,
        vesting_flags: str,
        tokenomics_score: float,
        risk_level: str,
        flags: str,
        recommendations: str,
        analyzed_at: str,
    ) -> int:
        """Store a tokenomics analysis snapshot.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            total_supply: Total supply
            max_supply: Max supply (optional)
            supply_tier: Supply tier classification
            total_holders: Total holder count
            top_10_holder_pct: Top 10 holders percentage
            contract_holder_pct: Contract holders percentage
            staking_contract_pct: Staking contract percentage
            gini_coefficient: Gini coefficient
            nakamoto_coefficient: Nakamoto coefficient
            utility_flags: Utility flags (JSON string)
            vesting_flags: Vesting flags (JSON string)
            tokenomics_score: Overall score (0-100)
            risk_level: Risk level (low/medium/high/critical)
            flags: Risk flags (JSON string)
            recommendations: Recommendations (JSON string)
            analyzed_at: ISO timestamp of analysis

        Returns:
            The snapshot record ID
        """
        import json
        import logging
        LOGGER = logging.getLogger(__name__)
        LOGGER.info(f"store_tokenomics_snapshot called for {token_address} on {chain_id}")
        self.ensure_tokenomics_schema()
        with self.write_connection() as conn:
            cursor = conn.execute("""
                INSERT OR REPLACE INTO tokenomics_analysis_snapshots
                (token_address, chain_id, total_supply, max_supply, supply_tier,
                 total_holders, top_10_holder_pct, contract_holder_pct, staking_contract_pct,
                 gini_coefficient, nakamoto_coefficient, utility_flags, vesting_flags,
                 tokenomics_score, risk_level, flags, recommendations, analyzed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                token_address.lower(), chain_id, str(total_supply), str(max_supply) if max_supply is not None else None, supply_tier,
                total_holders, top_10_holder_pct, contract_holder_pct, staking_contract_pct,
                gini_coefficient, nakamoto_coefficient, utility_flags, vesting_flags,
                tokenomics_score, risk_level, flags, recommendations, analyzed_at,
            ))
            return cursor.lastrowid

    # ========================================================================
    # Contract Audit Schema (for ContractAuditScout)
    # ========================================================================

    def ensure_contract_audit_schema(self) -> None:
        """Ensure contract audit tables exist."""
        with self.write_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS contract_audit_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token_address TEXT NOT NULL,
                    chain_id TEXT NOT NULL,
                    contract_code_hash TEXT NOT NULL,
                    contract_exists INTEGER NOT NULL,
                    is_verified INTEGER NOT NULL,
                    compiler_version TEXT,
                    optimization_runs INTEGER,
                    contract_size INTEGER NOT NULL,
                    libraries_used TEXT,
                    ai_audit_enabled INTEGER NOT NULL,
                    ai_audit_findings TEXT,
                    overall_score REAL NOT NULL,
                    risk_level TEXT NOT NULL,
                    flags TEXT,
                    analyzed_at TEXT NOT NULL,
                    UNIQUE(token_address, chain_id, contract_code_hash)
                );

                CREATE INDEX IF NOT EXISTS idx_contract_audit_token_chain
                    ON contract_audit_snapshots(token_address, chain_id);
                CREATE INDEX IF NOT EXISTS idx_contract_audit_analyzed_at
                    ON contract_audit_snapshots(analyzed_at DESC);
                CREATE INDEX IF NOT EXISTS idx_contract_audit_score
                    ON contract_audit_snapshots(overall_score);
                CREATE INDEX IF NOT EXISTS idx_contract_audit_code_hash
                    ON contract_audit_snapshots(contract_code_hash);
            """)

    def store_contract_audit(
        self,
        token_address: str,
        chain_id: str,
        contract_code_hash: str,
        contract_exists: bool,
        is_verified: bool,
        compiler_version: Optional[str],
        optimization_runs: Optional[int],
        contract_size: int,
        libraries_used: List[str],
        ai_audit_enabled: bool,
        ai_audit_findings: List[Dict[str, Any]],
        overall_score: float,
        risk_level: str,
        flags: List[str],
        analyzed_at: str,
    ) -> int:
        """Store a contract audit snapshot.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            contract_code_hash: SHA256 hash of contract bytecode
            contract_exists: Whether contract exists on-chain
            is_verified: Whether source code is verified
            compiler_version: Compiler version (if verified)
            optimization_runs: Optimization runs (if verified)
            contract_size: Bytecode size in bytes
            libraries_used: List of libraries used
            ai_audit_enabled: Whether AI audit was performed
            ai_audit_findings: List of AI agent findings
            overall_score: Overall security score (0-100)
            risk_level: Risk level (low/medium/high/critical)
            flags: Risk flags
            analyzed_at: ISO timestamp of analysis

        Returns:
            The snapshot record ID
        """
        import json

        self.ensure_contract_audit_schema()
        with self.write_connection() as conn:
            cursor = conn.execute("""
                INSERT OR REPLACE INTO contract_audit_snapshots
                (token_address, chain_id, contract_code_hash, contract_exists, is_verified,
                 compiler_version, optimization_runs, contract_size, libraries_used,
                 ai_audit_enabled, ai_audit_findings, overall_score, risk_level, flags, analyzed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                token_address.lower(),
                str(chain_id),
                contract_code_hash,
                1 if contract_exists else 0,
                1 if is_verified else 0,
                compiler_version,
                optimization_runs,
                contract_size,
                json.dumps(libraries_used) if libraries_used else None,
                1 if ai_audit_enabled else 0,
                json.dumps(ai_audit_findings) if ai_audit_findings else None,
                overall_score,
                risk_level,
                json.dumps(flags) if flags else None,
                analyzed_at,
            ))
            return cursor.lastrowid

    def get_last_contract_audit(
        self,
        token_address: str,
        chain_id: int,
    ) -> Optional[Dict[str, Any]]:
        """Get the most recent contract audit for a token.

        Args:
            token_address: Token contract address
            chain_id: Chain ID

        Returns:
            Contract audit dict or None
        """
        import json

        self.ensure_contract_audit_schema()
        with self.read_connection() as conn:
            cursor = conn.execute("""
                SELECT id, token_address, chain_id, contract_code_hash, contract_exists,
                       is_verified, compiler_version, optimization_runs, contract_size,
                       libraries_used, ai_audit_enabled, ai_audit_findings, overall_score,
                       risk_level, flags, analyzed_at
                FROM contract_audit_snapshots
                WHERE token_address = ? AND chain_id = ?
                ORDER BY analyzed_at DESC
                LIMIT 1
            """, (token_address.lower(), str(chain_id)))

            row = cursor.fetchone()
            if row:
                return {
                    "id": row[0],
                    "token_address": row[1],
                    "chain_id": row[2],
                    "contract_code_hash": row[3],
                    "contract_exists": bool(row[4]),
                    "is_verified": bool(row[5]),
                    "compiler_version": row[6],
                    "optimization_runs": row[7],
                    "contract_size": row[8],
                    "libraries_used": json.loads(row[9]) if row[9] else [],
                    "ai_audit_enabled": bool(row[10]),
                    "ai_audit_findings": json.loads(row[11]) if row[11] else [],
                    "overall_score": row[12],
                    "risk_level": row[13],
                    "flags": json.loads(row[14]) if row[14] else [],
                    "analyzed_at": row[15],
                }

        return None

    def get_last_contract_code_hash(
        self,
        token_address: str,
        chain_id: int,
    ) -> Optional[str]:
        """Get the last stored contract code hash for a token.

        Args:
            token_address: Token contract address
            chain_id: Chain ID

        Returns:
            Contract code hash or None
        """
        self.ensure_contract_audit_schema()
        with self.read_connection() as conn:
            cursor = conn.execute("""
                SELECT contract_code_hash
                FROM contract_audit_snapshots
                WHERE token_address = ? AND chain_id = ?
                ORDER BY analyzed_at DESC
                LIMIT 1
            """, (token_address.lower(), str(chain_id)))

            row = cursor.fetchone()
            return row[0] if row else None

    # ========================================================================
    # Unified Query Methods (for Unified API)
    # ========================================================================

    def get_unified_audit_data(
        self,
        project_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Get all audit data for a project in one call.

        Queries all scout tables and returns unified response.

        Args:
            project_id: Project UUID

        Returns:
            Unified audit data dict with all scout results, or None if not found
        """
        import json
        from datetime import datetime

        # First, try to get project info from meta table
        project_info = self._get_project_info(project_id)

        if not project_info or not project_info.get("token_address"):
            return None

        token_address = project_info["token_address"]
        chain_id = project_info.get("chain_id", 1)

        results = {
            "project_id": project_id,
            "token_address": token_address,
            "chain_id": chain_id,
        }

        # Get latest data from each scout
        results["token_distribution"] = self._get_latest_token_holder_data(token_address, chain_id)
        results["tokenomics"] = self._get_latest_tokenomics_data(token_address, chain_id)
        results["liquidity"] = self._get_latest_liquidity_data(token_address, chain_id)
        results["contract_audit"] = self._get_latest_contract_audit_data(token_address, chain_id)

        results["collected_at"] = datetime.utcnow().isoformat()

        return results

    def _get_project_info(
        self,
        project_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Get project info from meta table.

        Args:
            project_id: Project UUID

        Returns:
            Project info dict or None
        """
        try:
            self.ensure_schema()
            with self.read_connection() as conn:
                cursor = conn.execute("""
                    SELECT project_id, token_address, chain_id
                    FROM featured_projects
                    WHERE project_id = ?
                    LIMIT 1
                """, (project_id,))

                row = cursor.fetchone()
                if row:
                    return {
                        "project_id": row[0],
                        "token_address": row[1],
                        "chain_id": row[2],
                    }
        except Exception as e:
            LOGGER.debug(f"Failed to get project info: {e}")

        return None

    def _get_latest_token_holder_data(
        self,
        token_address: str,
        chain_id: int,
    ) -> Optional[Dict[str, Any]]:
        """Get latest token holder snapshot data."""
        try:
            snapshot = self.get_latest_weekly_snapshot(token_address, chain_id)
            if snapshot:
                return {
                    "type": "token_distribution",
                    "week_start": snapshot.get("week_start"),
                    "holder_count": snapshot.get("holder_count"),
                    "estimated_total_supply": snapshot.get("estimated_total_supply"),
                    "collected_at": snapshot.get("collected_at"),
                }
        except Exception as e:
            LOGGER.debug(f"Failed to get token holder data: {e}")
        return None

    def _get_latest_tokenomics_data(
        self,
        token_address: str,
        chain_id: int,
    ) -> Optional[Dict[str, Any]]:
        """Get latest tokenomics snapshot data."""
        try:
            snapshots = self.get_tokenomics_snapshots(token_address, str(chain_id), limit=1)
            if snapshots:
                snap = snapshots[0]
                return {
                    "type": "tokenomics",
                    "supply_tier": snap.get("supply_tier"),
                    "total_supply": snap.get("total_supply"),
                    "total_holders": snap.get("total_holders"),
                    "top_10_holder_pct": snap.get("top_10_holder_pct"),
                    "staking_contract_pct": snap.get("staking_contract_pct"),
                    "tokenomics_score": snap.get("tokenomics_score"),
                    "risk_level": snap.get("risk_level"),
                    "analyzed_at": snap.get("analyzed_at"),
                }
        except Exception as e:
            LOGGER.debug(f"Failed to get tokenomics data: {e}")
        return None

    def _get_latest_liquidity_data(
        self,
        token_address: str,
        chain_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Get latest liquidity snapshot data."""
        try:
            snapshot = self.get_latest_liquidity_snapshot(token_address, chain_id)
            if snapshot:
                return {
                    "type": "liquidity",
                    "tvl_usd": snapshot.get("tvl_usd"),
                    "pair_address": snapshot.get("pair_address"),
                    "dex_name": snapshot.get("dex_name"),
                    "price_usd": snapshot.get("price_usd"),
                    "collected_at": snapshot.get("collected_at"),
                }
        except Exception as e:
            LOGGER.debug(f"Failed to get liquidity data: {e}")
        return None

    def _get_latest_contract_audit_data(
        self,
        token_address: str,
        chain_id: int,
    ) -> Optional[Dict[str, Any]]:
        """Get latest contract audit data."""
        try:
            audit = self.get_last_contract_audit(token_address, chain_id)
            if audit:
                return {
                    "type": "contract_audit",
                    "contract_code_hash": audit.get("contract_code_hash"),
                    "contract_exists": audit.get("contract_exists"),
                    "is_verified": audit.get("is_verified"),
                    "contract_size": audit.get("contract_size"),
                    "ai_audit_enabled": audit.get("ai_audit_enabled"),
                    "overall_score": audit.get("overall_score"),
                    "risk_level": audit.get("risk_level"),
                    "ai_findings_count": len(audit.get("ai_audit_findings", [])),
                    "analyzed_at": audit.get("analyzed_at"),
                }
        except Exception as e:
            LOGGER.debug(f"Failed to get contract audit data: {e}")
        return None

    def get_unified_audit_history(
        self,
        project_id: str,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """Get historical unified audit snapshots for a project.

        Args:
            project_id: Project UUID
            limit: Max number of snapshots

        Returns:
            List of historical snapshots with all scout data
        """
        project_info = self._get_project_info(project_id)

        if not project_info or not project_info.get("token_address"):
            return []

        token_address = project_info["token_address"]
        chain_id = project_info.get("chain_id", 1)

        # Get historical snapshots from each scout
        # For now, return token holder history as the primary timeline
        try:
            history = self.get_token_holder_snapshots(
                token_address=token_address,
                chain_id=chain_id,
                limit=limit,
            )

            # Enhance with other scout data
            snapshots = []
            for snap in history:
                snapshots.append({
                    "week_start": snap.get("week_start"),
                    "holder_count": snap.get("holder_count"),
                    "collected_at": snap.get("collected_at"),
                })

            return snapshots

        except Exception as e:
            LOGGER.error(f"Failed to get unified history: {e}")
            return []

