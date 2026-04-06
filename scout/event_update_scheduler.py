"""Scheduler for automatic event indexing updates.

This module provides scheduled updates for indexed tokens, ensuring the
Transfer event index stays current with the blockchain.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Awaitable, Callable, Dict, List, Optional

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.interval import IntervalTrigger
    HAS_SCHEDULER = True
except ImportError:
    HAS_SCHEDULER = False
    BackgroundScheduler = None
    IntervalTrigger = None

from .database_manager import DatabaseManager
from .parallel_event_indexer import ParallelEventIndexer

LOGGER = logging.getLogger(__name__)


@dataclass
class ScheduledToken:
    """Configuration for a scheduled token update."""

    token_address: str
    chain_id: int
    interval_hours: int
    enabled: bool = True


class EventUpdateScheduler:
    """Schedules periodic incremental updates for indexed tokens.

    This scheduler runs in the background and updates the event index
    for configured tokens at regular intervals.
    """

    def __init__(
        self,
        database: DatabaseManager,
        max_workers_per_provider: int = 2,
    ) -> None:
        """Initialize the event update scheduler.

        Args:
            database: Database manager
            max_workers_per_provider: Concurrent requests per provider

        Raises:
            ImportError: If APScheduler is not installed
        """
        if not HAS_SCHEDULER:
            raise ImportError(
                "APScheduler is required for scheduled updates. "
                "Install with: pip install apscheduler"
            )

        self.database = database
        self.max_workers = max_workers_per_provider

        # Create background scheduler
        self.scheduler = BackgroundScheduler()

        # Track scheduled tokens
        self.scheduled_tokens: Dict[str, ScheduledToken] = {}

    def start(self) -> None:
        """Start the scheduler."""
        if not self.scheduler.running:
            self.scheduler.start()
            LOGGER.info("Event update scheduler started")

    def stop(self) -> None:
        """Stop the scheduler."""
        if self.scheduler.running:
            self.scheduler.shutdown()
            LOGGER.info("Event update scheduler stopped")

    def schedule_token_updates(
        self,
        token_address: str,
        chain_id: int,
        interval_hours: int = 24,
    ) -> None:
        """Schedule automatic updates for a token.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            interval_hours: Update interval in hours (default: 24)
        """
        job_id = f"update_{token_address}_{chain_id}"

        # Remove existing job if present
        if self.scheduler.get_job(job_id):
            self.scheduler.remove_job(job_id)

        # Create update function for this token
        async def update():
            await self._update_token(token_address, chain_id)

        # Schedule the job — APScheduler runs in a plain thread with no event loop,
        # so we need asyncio.run() to create a fresh loop for the coroutine.
        self.scheduler.add_job(
            lambda: asyncio.run(update()),
            trigger=IntervalTrigger(hours=interval_hours),
            id=job_id,
            name=f"Update {token_address} on chain {chain_id}",
            replace_existing=True,
        )

        # Track the scheduled token
        self.scheduled_tokens[job_id] = ScheduledToken(
            token_address=token_address,
            chain_id=chain_id,
            interval_hours=interval_hours,
            enabled=True,
        )

        LOGGER.info(
            f"Scheduled updates for {token_address} on chain {chain_id} "
            f"every {interval_hours} hours"
        )

    def unschedule_token_updates(
        self,
        token_address: str,
        chain_id: int,
    ) -> None:
        """Remove scheduled updates for a token.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
        """
        job_id = f"update_{token_address}_{chain_id}"

        if self.scheduler.get_job(job_id):
            self.scheduler.remove_job(job_id)
            LOGGER.info(f"Unscheduled updates for {token_address} on chain {chain_id}")

        # Remove from tracking
        self.scheduled_tokens.pop(job_id, None)

    def list_scheduled_tokens(self) -> List[ScheduledToken]:
        """Get list of scheduled tokens.

        Returns:
            List of ScheduledToken objects
        """
        return list(self.scheduled_tokens.values())

    async def _update_token(
        self,
        token_address: str,
        chain_id: int,
    ) -> None:
        """Perform incremental update for a token.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
        """
        LOGGER.info(
            f"Running scheduled update for {token_address} on chain {chain_id}"
        )

        start_time = asyncio.get_event_loop().time()

        try:
            # Get current progress
            progress = self.database.get_event_scan_progress(token_address, chain_id)

            if not progress:
                LOGGER.warning(
                    f"No existing scan progress for {token_address}, "
                    f"skipping scheduled update. Run initial scan first."
                )
                return

            last_scanned = progress["last_scanned_block"]

            # Create indexer
            indexer = ParallelEventIndexer(
                self.database,
                chain_id,
                max_workers_per_provider=self.max_workers,
            )

            try:
                # Run incremental update (from last scanned to current)
                index_progress = await indexer.index_token_transfers(
                    token_address=token_address,
                    deployment_block=last_scanned + 1,
                    force_rescan=False,
                )

                elapsed = asyncio.get_event_loop().time() - start_time

                LOGGER.info(
                    f"Scheduled update complete for {token_address}: "
                    f"{index_progress.total_events:,} new events indexed "
                    f"in {elapsed:.1f}s"
                )

            finally:
                await indexer.close()

        except Exception as e:
            LOGGER.error(
                f"Scheduled update failed for {token_address}: {e}",
                exc_info=True,
            )

    def get_job_status(self) -> Dict[str, dict]:
        """Get status of all scheduled jobs.

        Returns:
            Dict mapping job_id to job status dict
        """
        jobs = self.scheduler.get_jobs()
        return {
            job.id: {
                "name": job.name,
                "next_run_time": job.next_run_time.isoformat() if job.next_run_time else None,
                "trigger": str(job.trigger),
            }
            for job in jobs
        }


# Convenience functions
def create_scheduler(
    database: DatabaseManager,
    max_workers_per_provider: int = 2,
) -> EventUpdateScheduler:
    """Create an event update scheduler.

    Args:
        database: Database manager
        max_workers_per_provider: Concurrent requests per provider

    Returns:
        Configured EventUpdateScheduler instance
    """
    return EventUpdateScheduler(
        database=database,
        max_workers_per_provider=max_workers_per_provider,
    )


def schedule_token(
    database: DatabaseManager,
    token_address: str,
    chain_id: int = 1,
    interval_hours: int = 24,
) -> EventUpdateScheduler:
    """Create scheduler and schedule a single token.

    Args:
        database: Database manager
        token_address: Token contract address
        chain_id: Chain ID
        interval_hours: Update interval in hours

    Returns:
        Configured and started EventUpdateScheduler
    """
    scheduler = create_scheduler(database)
    scheduler.start()
    scheduler.schedule_token_updates(token_address, chain_id, interval_hours)
    return scheduler
