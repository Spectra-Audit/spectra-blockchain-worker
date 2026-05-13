"""Tests for holder tier classification in HolderAPIManager."""

from scout.holder_api_manager import HolderAPIManager
from scout.holder_api_providers import HolderData


def _make_manager() -> HolderAPIManager:
    """Create a minimal HolderAPIManager instance for testing tier logic."""
    return HolderAPIManager(providers=[], enable_cache=False, enable_rate_limiting=False)


def _make_holder(balance: int, address: str = "0xabc", rank: int = 1) -> HolderData:
    """Create a HolderData instance."""
    return HolderData(address=address, balance=balance, rank=rank)


class TestCalculateHolderTiers:
    """Tests for _calculate_holder_tiers distribution logic."""

    def test_returns_none_for_zero_price(self) -> None:
        manager = _make_manager()
        result = manager._calculate_holder_tiers([], 100, 10**18, 0.0)
        assert result is None

    def test_returns_none_for_zero_count(self) -> None:
        manager = _make_manager()
        result = manager._calculate_holder_tiers([], 0, 10**18, 1.0)
        assert result is None

    def test_single_whale_holder(self) -> None:
        """A single known whale should be classified correctly."""
        manager = _make_manager()
        # 1,000,000 tokens * $10 = $10M → Whale
        balance = 1_000_000 * 10**18
        holders = [_make_holder(balance, "0xwhale")]
        result = manager._calculate_holder_tiers(holders, total_count=1, total_supply=balance, price_usd=10.0)
        assert result is not None
        whale = next(t for t in result if t["tier"] == "WHALE")
        assert whale["holders"] == 1

    def test_single_shrimp_holder(self) -> None:
        """A holder with very small balance should be Shrimp."""
        manager = _make_manager()
        # 0.5 tokens * $1 = $0.5 → Shrimp
        balance = int(0.5 * 10**18)
        holders = [_make_holder(balance, "0xshrimp")]
        result = manager._calculate_holder_tiers(holders, total_count=1, total_supply=balance, price_usd=1.0)
        assert result is not None
        shrimp = next(t for t in result if t["tier"] == "SHRIMP")
        assert shrimp["holders"] == 1

    def test_remaining_holders_distributed_not_single_tier(self) -> None:
        """Bug fix: remaining holders should NOT all be dumped into a single tier.

        The old code classified ALL remaining holders into a single bucket based
        on average balance, causing everyone to appear as Whale or Dolphin.
        The Pareto fix distributes holders across multiple tiers.
        """
        manager = _make_manager()
        price_usd = 10.0
        decimals = 18
        divisor = 10**decimals

        # 5 known whale holders, realistic scenario
        whale_balance = 500_000 * divisor
        holders = [_make_holder(whale_balance, f"0xw{i}", i + 1) for i in range(5)]
        # Total supply = 10M tokens, total 10K holders
        total_supply = 10_000_000 * divisor
        total_count = 10_000

        result = manager._calculate_holder_tiers(
            holders, total_count=total_count, total_supply=total_supply,
            price_usd=price_usd, decimals=decimals,
        )
        assert result is not None

        # Count tiers that have holders
        populated_tiers = [t for t in result if t["holders"] > 0]
        assert len(populated_tiers) >= 3, (
            f"Only {len(populated_tiers)} tier(s) populated — "
            "remaining holders should be spread across multiple tiers, not one"
        )

        # Whale count should not include all remaining holders
        whale_tier = next(t for t in result if t["tier"] == "WHALE")
        assert whale_tier["holders"] < total_count * 0.5, (
            f"Whale count {whale_tier['holders']} is too high — "
            "most remaining holders should be in lower tiers"
        )

    def test_remaining_holders_not_all_dolphin(self) -> None:
        """When average is ~$5K, don't dump ALL remaining into Dolphin.

        The Pareto model should spread holders across multiple tiers
        even when the average is in the Dolphin range.
        """
        manager = _make_manager()
        price_usd = 1.0
        decimals = 18
        divisor = 10**decimals

        # 5 known holders with $5K each (Dolphin)
        dolphin_balance = 5_000 * divisor
        holders = [_make_holder(dolphin_balance, f"0xd{i}", i + 1) for i in range(5)]
        # Many more holders with less — avg should be lower
        total_supply = 1_000_000 * divisor  # 1M tokens total
        total_count = 10_000

        result = manager._calculate_holder_tiers(
            holders, total_count=total_count, total_supply=total_supply,
            price_usd=price_usd, decimals=decimals,
        )
        assert result is not None

        dolphin_tier = next(t for t in result if t["tier"] == "DOLPHIN")
        # Should NOT have all 9,995 remaining holders as Dolphin
        assert dolphin_tier["holders"] < 9000, (
            f"Dolphin count {dolphin_tier['holders']} is too high — "
            "remaining holders should be distributed across tiers"
        )

    def test_low_avg_mostly_shrimp(self) -> None:
        """When average is very low, most remaining holders should be Shrimp."""
        manager = _make_manager()
        price_usd = 0.001
        decimals = 18
        divisor = 10**decimals

        # 2 holders with $500 each
        holder_balance = 500_000 * divisor
        holders = [_make_holder(holder_balance, f"0xf{i}", i + 1) for i in range(2)]
        total_supply = 1_000_000_000 * divisor
        total_count = 100_000

        result = manager._calculate_holder_tiers(
            holders, total_count=total_count, total_supply=total_supply,
            price_usd=price_usd, decimals=decimals,
        )
        assert result is not None

        shrimp_tier = next(t for t in result if t["tier"] == "SHRIMP")
        # Most remaining holders should be Shrimp (allowing for some spread)
        assert shrimp_tier["holders"] > 50_000, (
            f"Shrimp count {shrimp_tier['holders']} is too low — "
            "most small holders should be Shrimp when avg is <$1"
        )

    def test_tier_percentages_sum_reasonably(self) -> None:
        """Holder percentages should approximately sum to 100%."""
        manager = _make_manager()
        price_usd = 10.0
        decimals = 18
        divisor = 10**decimals

        holders = [_make_holder(100_000 * divisor, f"0x{i:040x}", i + 1) for i in range(20)]
        total_supply = 10_000_000 * divisor
        total_count = 5_000

        result = manager._calculate_holder_tiers(
            holders, total_count=total_count, total_supply=total_supply,
            price_usd=price_usd, decimals=decimals,
        )
        assert result is not None

        total_pct = sum(t["holders_pct"] for t in result)
        assert abs(total_pct - 100.0) < 2.0, (
            f"Holder percentages sum to {total_pct}, expected ~100%"
        )

    def test_all_known_tiers_classified_correctly(self) -> None:
        """Each known holder should land in the correct tier."""
        manager = _make_manager()
        price_usd = 1.0
        decimals = 18
        divisor = 10**decimals

        holders = [
            _make_holder(200_000 * divisor, "0xwhale", 1),     # $200K → Whale
            _make_holder(50_000 * divisor, "0xshark", 2),      # $50K → Shark
            _make_holder(5_000 * divisor, "0xdolphin", 3),     # $5K → Dolphin
            _make_holder(500 * divisor, "0xfish", 4),          # $500 → Fish
            _make_holder(50 * divisor, "0xcrab", 5),           # $50 → Crab
            _make_holder(1 * divisor, "0xshrimp", 6),          # $1 → Shrimp
        ]
        total_supply = 1_000_000 * divisor
        total_count = 6

        result = manager._calculate_holder_tiers(
            holders, total_count=total_count, total_supply=total_supply,
            price_usd=price_usd, decimals=decimals,
        )
        assert result is not None

        tier_map = {t["tier"]: t["holders"] for t in result}
        assert tier_map["WHALE"] >= 1
        assert tier_map["SHARK"] >= 1
        assert tier_map["DOLPHIN"] >= 1
        assert tier_map["FISH"] >= 1
        assert tier_map["CRAB"] >= 1
        assert tier_map["SHRIMP"] >= 1

    def test_mixed_top_100_holders_are_not_all_whales(self) -> None:
        """Fetched holders should be bucketed by USD value, not by being in the top 100."""
        manager = _make_manager()
        price_usd = 2.0
        decimals = 18
        divisor = 10**decimals

        holder_values_usd = (
            [200_000] * 10
            + [50_000] * 20
            + [5_000] * 20
            + [500] * 20
            + [50] * 20
            + [5] * 10
        )
        holders = [
            _make_holder(int((usd_value / price_usd) * divisor), f"0x{i:040x}", i + 1)
            for i, usd_value in enumerate(holder_values_usd)
        ]
        total_supply = sum(h.balance for h in holders)

        result = manager._calculate_holder_tiers(
            holders,
            total_count=len(holders),
            total_supply=total_supply,
            price_usd=price_usd,
            decimals=decimals,
        )
        assert result is not None

        tier_map = {t["tier"]: t["holders"] for t in result}
        assert tier_map == {
            "WHALE": 10,
            "SHARK": 20,
            "DOLPHIN": 20,
            "FISH": 20,
            "CRAB": 20,
            "SHRIMP": 10,
        }

    def test_non_18_decimal_token_uses_token_decimals(self) -> None:
        """Raw balances must be normalized with the token's actual decimals."""
        manager = _make_manager()
        price_usd = 0.5
        decimals = 6
        divisor = 10**decimals

        holders = [
            _make_holder(250_000 * divisor, "0xwhale", 1),   # $125K -> Whale
            _make_holder(15_000 * divisor, "0xdolphin", 2),  # $7.5K -> Dolphin
            _make_holder(15 * divisor, "0xshrimp", 3),       # $7.50 -> Shrimp
        ]
        total_supply = sum(h.balance for h in holders)

        result = manager._calculate_holder_tiers(
            holders,
            total_count=len(holders),
            total_supply=total_supply,
            price_usd=price_usd,
            decimals=decimals,
        )
        assert result is not None

        tier_map = {t["tier"]: t["holders"] for t in result}
        assert tier_map["WHALE"] == 1
        assert tier_map["DOLPHIN"] == 1
        assert tier_map["SHRIMP"] == 1
