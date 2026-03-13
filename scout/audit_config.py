"""Audit data type configurations.

This module defines which data types are dynamic (need updates) vs static (one-time collection).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Dict

LOGGER = logging.getLogger(__name__)


class DataType(Enum):
    """Data update frequency classification.

    DYNAMIC_WEEKLY: Data that changes weekly (token holder distribution)
    DYNAMIC_DAILY: Data that changes daily (prices, volumes)
    STATIC_ONCE: Data that never changes (contract deployments, source code)
    """

    DYNAMIC_WEEKLY = "dynamic_weekly"
    DYNAMIC_DAILY = "dynamic_daily"
    STATIC_ONCE = "static_once"


@dataclass
class AuditDataConfig:
    """Configuration for an audit data type.

    Attributes:
        data_type: How often this data should be updated
        service_name: Name of the service that collects this data
        required_for_audit: Whether this data is required for a complete audit
    """

    data_type: DataType
    service_name: str
    required_for_audit: bool = True


# Configuration for all audit data types
AUDIT_DATA_CONFIGS: Dict[str, AuditDataConfig] = {
    "token_distribution": AuditDataConfig(
        data_type=DataType.DYNAMIC_WEEKLY,
        service_name="token_holder_scout",
        required_for_audit=True,
    ),
    "contract_deployment": AuditDataConfig(
        data_type=DataType.STATIC_ONCE,
        service_name="contract_audit_scout",
        required_for_audit=True,
    ),
    "security_scan": AuditDataConfig(
        data_type=DataType.STATIC_ONCE,
        service_name="security_audit_scout",
        required_for_audit=True,
    ),
    "price_data": AuditDataConfig(
        data_type=DataType.DYNAMIC_DAILY,
        service_name="price_scout",
        required_for_audit=False,
    ),
    "liquidity_analysis": AuditDataConfig(
        data_type=DataType.DYNAMIC_WEEKLY,
        service_name="liquidity_scout",
        required_for_audit=True,
    ),
}


def should_update_data(data_key: str) -> bool:
    """Check if a data type should be auto-updated.

    Args:
        data_key: Key from AUDIT_DATA_CONFIGS (e.g., "token_distribution")

    Returns:
        True if data should be auto-updated (weekly or daily)
    """
    config = AUDIT_DATA_CONFIGS.get(data_key)
    if not config:
        LOGGER.warning(f"Unknown data key: {data_key}")
        return False

    return config.data_type in (DataType.DYNAMIC_WEEKLY, DataType.DYNAMIC_DAILY)


def get_update_frequency(data_key: str) -> DataType:
    """Get the update frequency for a data type.

    Args:
        data_key: Key from AUDIT_DATA_CONFIGS

    Returns:
        The DataType enum value for this data type
    """
    config = AUDIT_DATA_CONFIGS.get(data_key)
    if not config:
        return DataType.STATIC_ONCE

    return config.data_type


def get_required_data_types() -> list[str]:
    """Get list of data types required for a complete audit.

    Returns:
        List of data keys where required_for_audit=True
    """
    return [
        key
        for key, config in AUDIT_DATA_CONFIGS.items()
        if config.required_for_audit
    ]


def get_dynamic_data_types() -> list[str]:
    """Get list of data types that are dynamic (require updates).

    Returns:
        List of data keys that are DYNAMIC_WEEKLY or DYNAMIC_DAILY
    """
    return [
        key
        for key, config in AUDIT_DATA_CONFIGS.items()
        if config.data_type in (DataType.DYNAMIC_WEEKLY, DataType.DYNAMIC_DAILY)
    ]


def get_static_data_types() -> list[str]:
    """Get list of data types that are static (one-time collection).

    Returns:
        List of data keys that are STATIC_ONCE
    """
    return [
        key
        for key, config in AUDIT_DATA_CONFIGS.items()
        if config.data_type == DataType.STATIC_ONCE
    ]
