"""Balance replay engine for calculating token distribution from stored events.

This module provides efficient SQL-based balance calculation by replaying Transfer
events stored in the database, eliminating the need for RPC balanceOf calls.
"""

from __future__ import annotations

import logging
import math
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple

from .database_manager import DatabaseManager

LOGGER = logging.getLogger(__name__)


@dataclass
class DistributionMetrics:
    """Metrics describing token distribution across holders."""

    holder_count: int
    gini_coefficient: float
    nakamoto_coefficient: int
    top_10_pct_supply: float
    top_1_pct_supply: float
    max_balance: int
    total_supply: int
    transaction_count: int = 0
    last_scanned_block: Optional[int] = None


@dataclass
class HolderBalance:
    """Balance information for a single holder."""

    address: str
    balance: int
    last_tx_block: int


class BalanceReplayer:
    """Calculates token balances by replaying stored Transfer events.

    This class provides pure SQL-based balance calculation from events stored
    in the token_transfers table. No RPC calls are required.
    """

    def __init__(self, database: DatabaseManager) -> None:
        """Initialize the balance replayer.

        Args:
            database: Database manager with event storage
        """
        self.database = database

    def calculate_balances(
        self,
        token_address: str,
        chain_id: int,
        as_of_block: Optional[int] = None,
        min_balance: int = 0,
        update_cache: bool = True,
    ) -> List[HolderBalance]:
        """Calculate holder balances by replaying Transfer events.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            as_of_block: Only include events up to this block (default: all)
            min_balance: Minimum balance to include (default: 0 = all)
            update_cache: Whether to update the balance cache table

        Returns:
            List of HolderBalance objects, ordered by balance descending
        """
        LOGGER.info(
            f"Calculating balances for {token_address} on chain {chain_id}"
            + (f" as of block {as_of_block}" if as_of_block else "")
        )

        start_time = time.time()

        # Check cache first
        if min_balance == 0 and not as_of_block:
            cached = self.database.get_all_holder_balances(token_address, chain_id)
            if cached:
                LOGGER.info(f"Using cached balances: {len(cached)} holders")
                return [
                    HolderBalance(address=addr, balance=bal, last_tx_block=block)
                    for addr, bal, block in cached
                ]

        # Calculate from events using SQL
        balances = self._replay_from_events(
            token_address, chain_id, as_of_block, min_balance
        )

        # Update cache if requested
        if update_cache and min_balance == 0 and not as_of_block:
            self._update_balance_cache(
                token_address, chain_id, balances
            )

        duration = time.time() - start_time
        LOGGER.info(
            f"Calculated {len(balances)} balances in {duration:.2f}s "
            f"({len(balances)/duration:.0f} balances/s)"
        )

        return balances

    def calculate_distribution_metrics(
        self,
        token_address: str,
        chain_id: int,
        as_of_block: Optional[int] = None,
    ) -> DistributionMetrics:
        """Calculate full distribution metrics for a token.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            as_of_block: Only include events up to this block (default: all)

        Returns:
            DistributionMetrics with all calculated metrics
        """
        LOGGER.info(f"Calculating distribution metrics for {token_address}")

        start_time = time.time()

        # Get balances
        balances = self.calculate_balances(
            token_address, chain_id, as_of_block, update_cache=True
        )

        if not balances:
            return DistributionMetrics(
                holder_count=0,
                gini_coefficient=0.0,
                nakamoto_coefficient=0,
                top_10_pct_supply=0.0,
                top_1_pct_supply=0.0,
                max_balance=0,
                total_supply=0,
            )

        # Extract balance values
        balance_values = [b.balance for b in balances]
        total_supply = sum(balance_values)

        # Calculate metrics
        gini = self._calculate_gini(balance_values)
        nakamoto = self._calculate_nakamoto(balance_values, total_supply)
        top_10_pct = self._calculate_top_concentration(balance_values, total_supply, 0.10)
        top_1_pct = self._calculate_top_concentration(balance_values, total_supply, 0.01)

        # Get transaction count and last scanned block
        progress = self.database.get_event_scan_progress(token_address, chain_id)
        transaction_count = progress["total_events_indexed"] if progress else 0
        last_scanned_block = progress["last_scanned_block"] if progress else None

        duration = time.time() - start_time
        LOGGER.info(
            f"Metrics calculated in {duration:.2f}s: "
            f"{len(balances):,} holders, "
            f"Gini: {gini:.4f}, "
            f"Nakamoto: {nakamoto}, "
            f"Total supply: {total_supply:,}"
        )

        return DistributionMetrics(
            holder_count=len(balances),
            gini_coefficient=gini,
            nakamoto_coefficient=nakamoto,
            top_10_pct_supply=top_10_pct,
            top_1_pct_supply=top_1_pct,
            max_balance=max(balance_values),
            total_supply=total_supply,
            transaction_count=transaction_count,
            last_scanned_block=last_scanned_block,
        )

    def _replay_from_events(
        self,
        token_address: str,
        chain_id: int,
        as_of_block: Optional[int],
        min_balance: int,
    ) -> List[HolderBalance]:
        """Replay Transfer events using SQL to calculate balances.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            as_of_block: Only include events up to this block
            min_balance: Minimum balance to include

        Returns:
            List of HolderBalance objects
        """
        # SQL query to replay all transfer events and calculate balances
        # Uses a UNION to process both from and to addresses, then sums by holder
        query = """
            WITH all_transfers AS (
                -- All outgoing transfers (subtract from balance)
                SELECT
                    from_address as holder_address,
                    -CAST(value AS INTEGER) as balance_change,
                    block_number
                FROM token_transfers
                WHERE token_address = ? AND chain_id = ?
                AND (? IS NULL OR block_number <= ?)

                UNION ALL

                -- All incoming transfers (add to balance)
                SELECT
                    to_address as holder_address,
                    CAST(value AS INTEGER) as balance_change,
                    block_number
                FROM token_transfers
                WHERE token_address = ? AND chain_id = ?
                AND (? IS NULL OR block_number <= ?)
            ),
            balances AS (
                SELECT
                    holder_address,
                    SUM(balance_change) as final_balance,
                    MAX(block_number) as last_tx_block
                FROM all_transfers
                GROUP BY holder_address
                HAVING final_balance > ?
                ORDER BY final_balance DESC
            )
            SELECT
                holder_address,
                final_balance,
                last_tx_block
            FROM balances
        """

        params = [
            token_address.lower(), chain_id,
            as_of_block, as_of_block,
            token_address.lower(), chain_id,
            as_of_block, as_of_block,
            min_balance
        ]

        with self.database.read_connection() as conn:
            cursor = conn.execute(query, params)
            rows = cursor.fetchall()

        return [
            HolderBalance(
                address=row[0],
                balance=row[1],
                last_tx_block=row[2],
            )
            for row in rows
        ]

    def _update_balance_cache(
        self,
        token_address: str,
        chain_id: int,
        balances: List[HolderBalance],
    ) -> None:
        """Update the balance cache table with calculated balances.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            balances: List of HolderBalance objects
        """
        LOGGER.info(f"Updating balance cache for {len(balances)} holders")

        # Clear old cache
        self.database.clear_balance_cache(token_address, chain_id)

        # Insert new balances
        for holder in balances:
            self.database.update_holder_balance(
                token_address,
                chain_id,
                holder.address,
                holder.balance,
                holder.last_tx_block,
            )

        LOGGER.info("Balance cache updated")

    def _calculate_gini(self, balances: List[int]) -> float:
        """Calculate Gini coefficient for wealth inequality.

        Args:
            balances: List of holder balances (sorted descending)

        Returns:
            Gini coefficient (0 = perfect equality, 1 = perfect inequality)
        """
        if not balances:
            return 0.0

        n = len(balances)
        total = sum(balances)

        if total == 0:
            return 0.0

        # Gini formula requires ascending order (smallest to largest)
        ascending_balances = list(reversed(balances))

        weighted_sum = sum(
            (i + 1) * balance for i, balance in enumerate(ascending_balances)
        )

        gini = (2 * weighted_sum) / (n * total) - (n + 1) / n

        return max(0.0, min(1.0, gini))

    def _calculate_nakamoto(
        self,
        balances: List[int],
        total_supply: int,
    ) -> int:
        """Calculate Nakamoto coefficient (min holders for 51% control).

        Args:
            balances: List of holder balances (sorted descending)
            total_supply: Total token supply

        Returns:
            Minimum number of holders needed to control 51% of supply
        """
        if not balances or total_supply == 0:
            return 0

        target = total_supply * 51 // 100  # 51%
        cumulative = 0

        for i, balance in enumerate(balances):
            cumulative += balance
            if cumulative >= target:
                return i + 1

        return len(balances)

    def _calculate_top_concentration(
        self,
        balances: List[int],
        total_supply: int,
        top_fraction: float,
    ) -> float:
        """Calculate supply concentration in top X% of holders.

        Args:
            balances: List of holder balances (sorted descending)
            total_supply: Total token supply
            top_fraction: Fraction of top holders (e.g., 0.01 for top 1%)

        Returns:
            Percentage of supply held by top X% of holders
        """
        if not balances or total_supply == 0:
            return 0.0

        n = len(balances)
        top_n = max(1, int(n * top_fraction))

        top_supply = sum(balances[:top_n])
        percentage = (top_supply / total_supply) * 100

        return round(percentage, 2)

    def get_holder_balance(
        self,
        token_address: str,
        chain_id: int,
        holder_address: str,
    ) -> Optional[int]:
        """Get the balance of a specific holder.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            holder_address: Holder address

        Returns:
            Balance as integer, or None if not found
        """
        # Check cache first
        cached = self.database.get_holder_balance(
            token_address, chain_id, holder_address
        )
        if cached is not None:
            return cached

        # Calculate from events
        query = """
            WITH all_transfers AS (
                SELECT from_address, -CAST(value AS INTEGER) as balance_change
                FROM token_transfers
                WHERE token_address = ? AND chain_id = ?
                AND (from_address = ? OR to_address = ?)

                UNION ALL

                SELECT to_address, CAST(value AS INTEGER) as balance_change
                FROM token_transfers
                WHERE token_address = ? AND chain_id = ?
                AND (from_address = ? OR to_address = ?)
            )
            SELECT SUM(balance_change)
            FROM all_transfers
            GROUP BY holder_address
            HAVING SUM(balance_change) > 0
        """

        with self.database.read_connection() as conn:
            cursor = conn.execute(
                query,
                [
                    token_address.lower(), chain_id,
                    holder_address.lower(), holder_address.lower(),
                    token_address.lower(), chain_id,
                    holder_address.lower(), holder_address.lower(),
                ]
            )
            row = cursor.fetchone()

        return int(row[0]) if row and row[0] else None

    def get_top_holders(
        self,
        token_address: str,
        chain_id: int,
        limit: int = 100,
    ) -> List[HolderBalance]:
        """Get the top holders by balance.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            limit: Maximum number of holders to return

        Returns:
            List of top HolderBalance objects
        """
        balances = self.calculate_balances(token_address, chain_id)
        return balances[:limit]


# Convenience functions
def calculate_distribution(
    database: DatabaseManager,
    token_address: str,
    chain_id: int = 1,
) -> DistributionMetrics:
    """Calculate distribution metrics for a token.

    Args:
        database: Database manager
        token_address: Token contract address
        chain_id: Chain ID (default: 1)

    Returns:
        DistributionMetrics with all calculated metrics
    """
    replayer = BalanceReplayer(database)
    return replayer.calculate_distribution_metrics(token_address, chain_id)


def get_holder_balances(
    database: DatabaseManager,
    token_address: str,
    chain_id: int = 1,
    min_balance: int = 0,
) -> List[HolderBalance]:
    """Get all holder balances for a token.

    Args:
        database: Database manager
        token_address: Token contract address
        chain_id: Chain ID (default: 1)
        min_balance: Minimum balance to include (default: 0)

    Returns:
        List of HolderBalance objects, ordered by balance descending
    """
    replayer = BalanceReplayer(database)
    return replayer.calculate_balances(token_address, chain_id, min_balance=min_balance)
