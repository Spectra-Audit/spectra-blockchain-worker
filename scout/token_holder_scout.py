"""Token holder scout using multiple API providers with automatic failover.

This scout uses multiple free APIs (NodeReal, Moralis, etc.) to:
- Get total holder count
- Get top N holders (default 100+ for Gini analysis)
- Calculate distribution metrics (Gini, Nakamoto, etc.)
- Store with historical retention (weekly/monthly/yearly)

Runs weekly and stores data with automatic failover between providers.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger

    HAS_SCHEDULER = True
except ImportError:
    HAS_SCHEDULER = False

from scout.backend_client import BackendClient
from scout.database_manager import DatabaseManager
from scout.holder_api_manager import HolderAPIManager, create_holder_api_manager

LOGGER = logging.getLogger(__name__)


@dataclass
class TrackedToken:
    """A token being tracked by the holder scout.

    Attributes:
        address: Token contract address
        chain_id: Chain ID (default 1 for Ethereum)
    """

    address: str
    chain_id: int = 1


class TokenHolderScout:
    """Token holder scout using multiple API providers.

    Uses multiple free APIs (NodeReal, Moralis, etc.) to:
    - Get total holder count
    - Get top N holders (default 100+ for Gini analysis)
    - Calculate distribution metrics
    - Store with historical retention (weekly/monthly/yearly)

    Runs weekly and stores data with automatic failover between providers.

    Example:
        scout = TokenHolderScout(
            database=DatabaseManager("scout.db"),
            api_manager=create_holder_api_manager(),
        )

        # Collect data for a token
        data = await scout.collect_token_data(
            token_address="0x2170ed0880ac9a755fd29b2688956bd959f933f8",
            chain_id=1,
        )

        # Start scheduled weekly collection
        scout.start_scheduled_collection([
            TrackedToken("0x2170ed0880ac9a755fd29b2688956bd959f933f8", 1),
        ])
    """

    def __init__(
        self,
        database: DatabaseManager,
        api_manager: HolderAPIManager,
        backend_client: Optional[BackendClient] = None,
        scheduled_day_of_week: int = 0,  # Monday
        scheduled_hour: int = 2,  # 2 AM
        top_holder_limit: int = 100,
    ) -> None:
        """Initialize the Token Holder Scout.

        Args:
            database: Database manager
            api_manager: Multi-provider API manager
            backend_client: Optional backend client for API updates
            scheduled_day_of_week: Day of week (0=Monday, 6=Sunday)
            scheduled_hour: Hour to run (0-23)
            top_holder_limit: Number of top holders to fetch
        """
        self.database = database
        self.api_manager = api_manager
        self.backend_client = backend_client
        self.scheduled_day = scheduled_day_of_week
        self.scheduled_hour = scheduled_hour
        self.top_holder_limit = top_holder_limit
        self.scheduler: Optional[BackgroundScheduler] = None

        # Ensure schema exists
        self.database.ensure_holder_data_schema()

        LOGGER.info(
            f"TokenHolderScout initialized with {len(api_manager.providers)} providers, "
            f"scheduled for day {scheduled_day_of_week} at {scheduled_hour}:00"
        )

    async def collect_token_data(
        self,
        token_address: str,
        chain_id: int,
        force: bool = False,
    ) -> Optional[Dict[str, Any]]:
        """Collect token holder data using available APIs.

        Tries each available provider with automatic failover.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            force: Force collection even if recently collected

        Returns:
            Dictionary with collected data, or None if all providers fail
        """
        LOGGER.info(f"Collecting holder data for {token_address} on chain {chain_id}")

        # Check if we recently collected data (skip if within 6 days)
        if not force:
            latest = self.database.get_latest_weekly_snapshot(token_address, chain_id)
            if latest:
                last_date = datetime.strptime(latest["week_start"], "%Y-%m-%d")
                days_since = (datetime.utcnow() - last_date).days
                if days_since < 6:
                    LOGGER.info(f"Skipping {token_address}: collected {days_since} days ago")
                    return None

        # Use API manager with automatic failover
        metrics = await self.api_manager.get_holder_data(
            token_address=token_address,
            chain_id=chain_id,
            limit=self.top_holder_limit,
        )

        if not metrics:
            LOGGER.error(f"All providers failed for {token_address}")
            return None

        return {
            "provider": "auto",  # Manager picks best provider
            "holder_count": metrics.total_holder_count,
            "top_holders": metrics.top_holders,
            "metrics": {
                "gini_coefficient": metrics.gini_coefficient,
                "nakamoto_coefficient": metrics.nakamoto_coefficient,
                "top_10_pct_supply": metrics.top_10_pct_supply,
                "top_1_pct_supply": metrics.top_1_pct_supply,
                "top_100_balance_sum": int(metrics.top_100_balance_sum, 16) if metrics.top_100_balance_sum else 0,
                "estimated_total_supply": int(metrics.estimated_total_supply, 16) if metrics.estimated_total_supply else 0,
                **({"holder_tiers": metrics.holder_tiers} if metrics.holder_tiers else {}),
                **({"price_usd": metrics.price_usd} if metrics.price_usd is not None else {}),
                **(
                    {"holder_tier_estimation_method": metrics.holder_tier_estimation_method}
                    if metrics.holder_tier_estimation_method
                    else {}
                ),
                **(
                    {"holder_tier_sample_size": metrics.holder_tier_sample_size}
                    if metrics.holder_tier_sample_size is not None
                    else {}
                ),
                **(
                    {"holder_tier_total_count": metrics.holder_tier_total_count}
                    if metrics.holder_tier_total_count is not None
                    else {}
                ),
                "holder_count_confirmed": metrics.holder_count_confirmed,
            }
        }

    def start_scheduled_collection(
        self,
        tokens_to_track: List[TrackedToken],
    ) -> None:
        """Start scheduled weekly collection for tracked tokens.

        Args:
            tokens_to_track: List of TrackedToken objects

        Raises:
            ImportError: If APScheduler is not installed
        """
        if not HAS_SCHEDULER:
            raise ImportError(
                "APScheduler required for scheduled collection. "
                "Install with: pip install apscheduler"
            )

        if self.scheduler and self.scheduler.running:
            LOGGER.warning("Scheduler already running")
            return

        self.scheduler = BackgroundScheduler()
        self.scheduler.start()

        for token in tokens_to_track:
            job_id = f"holder_collect_{token.address}_{token.chain_id}"

            # Schedule weekly job using CronTrigger
            self.scheduler.add_job(
                func=lambda t=token: self._run_collection_job(t.address, t.chain_id),
                trigger=CronTrigger(
                    day_of_week=self.scheduled_day,
                    hour=self.scheduled_hour,
                    minute=0,
                ),
                id=job_id,
                name=f"Weekly holder collection for {token.address[:10]}... on chain {token.chain_id}",
                replace_existing=True,
            )

        LOGGER.info(
            f"Scheduled weekly collection for {len(tokens_to_track)} tokens "
            f"(day {self.scheduled_day} at {self.scheduled_hour}:00)"
        )

    def _run_collection_job(self, token_address: str, chain_id: int) -> None:
        """Run collection job (scheduled task).

        This method is called by the scheduler. It runs async collection
        and stores the results in the database.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
        """
        from scout.async_runner import get_shared_async_runner

        async def collect():
            try:
                data = await self.collect_token_data(token_address, chain_id)

                if data:
                    # Store weekly snapshot
                    self._store_weekly_snapshot(token_address, chain_id, data)

                    # Check if last week of month
                    if self._is_last_week_of_month():
                        self._promote_to_monthly(token_address, chain_id)

                    LOGGER.info(
                        f"Completed weekly collection for {token_address[:10]}... "
                        f"(holders={data['holder_count']}, gini={data['metrics']['gini_coefficient']:.3f})",
                        extra={
                            "token_address": token_address,
                            "chain_id": chain_id,
                            "holder_count": data["holder_count"],
                            "gini_coefficient": data["metrics"]["gini_coefficient"],
                        }
                    )
                else:
                    LOGGER.warning(f"No data collected for {token_address} on chain {chain_id}")

            except Exception as e:
                LOGGER.error(f"Collection job failed for {token_address}: {e}", exc_info=True)

        runner = get_shared_async_runner()
        runner.submit(collect())

    def _store_weekly_snapshot(
        self,
        token_address: str,
        chain_id: int,
        data: Dict[str, Any],
    ) -> None:
        """Store weekly snapshot in database.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            data: Collected data from collect_token_data()
        """
        today = datetime.utcnow()
        week_start = today - timedelta(days=today.weekday())
        week_end = week_start + timedelta(days=6)

        # Store metrics
        self.database.store_weekly_snapshot(
            token_address=token_address,
            chain_id=chain_id,
            week_start=week_start.strftime("%Y-%m-%d"),
            week_end=week_end.strftime("%Y-%m-%d"),
            provider_name=data.get("provider", "unknown"),
            holder_count=data["holder_count"],
            gini_coefficient=data["metrics"]["gini_coefficient"],
            nakamoto_coefficient=data["metrics"]["nakamoto_coefficient"],
            top_10_pct_supply=data["metrics"]["top_10_pct_supply"],
            top_1_pct_supply=data["metrics"]["top_1_pct_supply"],
            top_100_balance_sum=data["metrics"]["top_100_balance_sum"],
            estimated_total_supply=data["metrics"]["estimated_total_supply"],
        )

        # Store raw top holders
        # Convert hex supply to int for percentage calculation
        total_supply_hex = data["metrics"]["estimated_total_supply"]
        total_supply_int = int(total_supply_hex, 16) if total_supply_hex.startswith("0x") else int(total_supply_hex)

        for holder in data["top_holders"]:
            self.database.store_top_holder_data(
                token_address=token_address,
                chain_id=chain_id,
                snapshot_date=today.strftime("%Y-%m-%d"),
                provider_name=data.get("provider", "unknown"),
                holder_rank=holder.rank,
                holder_address=holder.address,
                holder_balance_hex=holder.balance_hex or f"0x{holder.balance:x}",
                holder_balance_int=holder.balance,
                percent_supply=(holder.balance / total_supply_int * 100)
                              if total_supply_int > 0 else 0,
            )

    def _is_last_week_of_month(self) -> bool:
        """Check if current week is the last week of month.

        Returns:
            True if next week is in a different month
        """
        today = datetime.utcnow()
        next_week = today + timedelta(days=7)
        return next_week.month != today.month

    def _promote_to_monthly(self, token_address: str, chain_id: int) -> None:
        """Promote latest weekly snapshot to monthly.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
        """
        today = datetime.utcnow()
        month = today.strftime("%Y-%m")

        # Get latest weekly snapshot
        weekly = self.database.get_latest_weekly_snapshot(token_address, chain_id)

        if weekly:
            self.database.store_monthly_snapshot(
                token_address=token_address,
                chain_id=chain_id,
                month=month,
                holder_count=weekly["holder_count"],
                gini_coefficient=weekly["gini_coefficient"],
                nakamoto_coefficient=weekly["nakamoto_coefficient"],
                top_10_pct_supply=weekly["top_10_pct_supply"],
                top_1_pct_supply=weekly["top_1_pct_supply"],
                top_100_balance_sum=weekly["top_100_balance_sum"],
                estimated_total_supply=weekly["estimated_total_supply"],
                source_week_id=weekly["id"],
            )

            LOGGER.info(
                f"Promoted to monthly snapshot for {token_address[:10]}... month={month}"
            )

            # Check if we need to create yearly average (for data > 1 year old)
            self._update_yearly_data(token_address, chain_id)

    def _update_yearly_data(self, token_address: str, chain_id: int) -> None:
        """Update yearly snapshots (average of monthly data).

        Args:
            token_address: Token contract address
            chain_id: Chain ID
        """
        current_year = datetime.utcnow().year
        last_year = current_year - 1

        # Get all monthly data for last year
        monthly_snapshots = self.database.get_monthly_snapshots_for_year(
            token_address, chain_id, last_year
        )

        if len(monthly_snapshots) >= 6:  # Only average if we have 6+ months
            # Calculate averages
            avg_holder_count = sum(s["holder_count"] for s in monthly_snapshots) // len(monthly_snapshots)
            avg_gini = sum(s["gini_coefficient"] for s in monthly_snapshots) / len(monthly_snapshots)
            avg_nakamoto = sum(s["nakamoto_coefficient"] for s in monthly_snapshots) // len(monthly_snapshots)
            avg_top_10 = sum(s["top_10_pct_supply"] for s in monthly_snapshots) / len(monthly_snapshots)
            avg_top_1 = sum(s["top_1_pct_supply"] for s in monthly_snapshots) / len(monthly_snapshots)
            avg_top_100_sum = sum(s["top_100_balance_sum"] for s in monthly_snapshots) // len(monthly_snapshots)
            avg_total_supply = sum(s["estimated_total_supply"] for s in monthly_snapshots) // len(monthly_snapshots)

            self.database.store_yearly_snapshot(
                token_address=token_address,
                chain_id=chain_id,
                year=last_year,
                holder_count=avg_holder_count,
                gini_coefficient=round(avg_gini, 4),
                nakamoto_coefficient=avg_nakamoto,
                top_10_pct_supply=round(avg_top_10, 3),
                top_1_pct_supply=round(avg_top_1, 3),
                top_100_balance_sum=avg_top_100_sum,
                estimated_total_supply=avg_total_supply,
            )

            LOGGER.info(
                f"Created yearly snapshot for {token_address[:10]}... year={last_year} "
                f"(averaged from {len(monthly_snapshots)} months)"
            )

    async def collect_and_store(
        self,
        token_address: str,
        chain_id: int = 1,
        force: bool = False,
    ) -> Optional[Dict[str, Any]]:
        """Collect and store token holder data in one operation.

        This is a convenience method that combines collect_token_data
        and store_weekly_snapshot.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            force: Force collection even if recently collected

        Returns:
            Dictionary with collected data, or None if all providers fail
        """
        data = await self.collect_token_data(token_address, chain_id, force)

        if data:
            self._store_weekly_snapshot(token_address, chain_id, data)

            # Check if last week of month
            if self._is_last_week_of_month():
                self._promote_to_monthly(token_address, chain_id)

        return data

    def stop(self) -> None:
        """Stop scheduled collection."""
        if self.scheduler and self.scheduler.running:
            self.scheduler.shutdown(wait=True)
            LOGGER.info("TokenHolderScout scheduler stopped")

    async def close(self) -> None:
        """Close all resources including API manager connections."""
        self.stop()
        await self.api_manager.close_all()
        LOGGER.info("TokenHolderScout closed")


def create_token_holder_scout(
    database: DatabaseManager,
    api_manager: Optional[HolderAPIManager] = None,
    backend_client: Optional[BackendClient] = None,
    **kwargs: Any,
) -> TokenHolderScout:
    """Factory function to create a TokenHolderScout instance.

    Args:
        database: Database manager
        api_manager: Optional API manager (created if None)
        backend_client: Optional backend client
        **kwargs: Additional arguments passed to TokenHolderScout

    Returns:
        TokenHolderScout instance
    """
    if api_manager is None:
        api_manager = create_holder_api_manager(database=database)

    return TokenHolderScout(
        database=database,
        api_manager=api_manager,
        backend_client=backend_client,
        **kwargs
    )
