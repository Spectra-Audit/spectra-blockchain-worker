"""Compatibility wrapper for the shared RPC manager module."""

from scout.database_manager import DatabaseManager
from scout.rpc_providers_config import ProviderConfig, get_all_providers
from scout.shared_rpc_manager import (
    RpcProviderWithBlockTracking,
    UnifiedRpcManager as _SharedUnifiedRpcManager,
    get_rpc_manager,
    get_token_holder_count_nodereal,
    set_rpc_manager,
)


class UnifiedRpcManager(_SharedUnifiedRpcManager):
    """Wrapper that keeps legacy patch points under ``scout.rpc_manager`` working."""

    def __init__(self, chain_id: int, db_manager: DatabaseManager, providers=None) -> None:
        provider_configs = providers if providers is not None else get_all_providers(chain_id)
        if not provider_configs:
            raise ValueError(f"No RPC providers available for chain {chain_id}")
        super().__init__(
            chain_id=chain_id,
            db_manager=db_manager,
            providers=provider_configs,
        )


def create_rpc_manager(
    chain_id: int,
    db_manager: DatabaseManager,
    use_providers: list[ProviderConfig] | None = None,
) -> UnifiedRpcManager:
    return UnifiedRpcManager(
        chain_id=chain_id,
        db_manager=db_manager,
        providers=use_providers,
    )


__all__ = [
    "RpcProviderWithBlockTracking",
    "UnifiedRpcManager",
    "create_rpc_manager",
    "get_all_providers",
    "get_rpc_manager",
    "get_token_holder_count_nodereal",
    "set_rpc_manager",
]
