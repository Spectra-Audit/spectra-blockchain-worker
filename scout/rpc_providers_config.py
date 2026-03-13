"""Unified RPC provider configuration with accurate rate limits and capabilities.

This module centralizes all RPC provider configuration including rate limits,
block ranges, batch sizes, and priority ordering. It enables the parallel event
indexer to optimize requests per provider based on their specific constraints.

Rate Limit Information:
- NodeReal: ~10-20 req/s (free tier), supports nr_getTokenHolderCount for ETH/BSC
- Ankr (Public): ~30 req/s, max block range 1000, max batch 10
- Infura (Free): 500 credits/sec, eth_getLogs = 255 credits (~2 req/s for logs)
- QuickNode (Free): ~10 req/s, max block range varies
- PublicNode: ~10 req/s
- Other public nodes: ~5 req/s

NodeReal Special Methods:
- nr_getTokenHolderCount: Get ERC20 token holder count (ETH and BSC only)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class ProviderConfig:
    """Configuration for a single RPC provider.

    Attributes:
        name: Human-readable provider name
        url: RPC endpoint URL
        rate_limit: Requests per second (0 = unlimited)
        max_block_range: Maximum blocks in eth_getLogs range
        max_batch_size: Maximum batch size for requests
        requires_auth: Whether API key is required
        auth_type: Type of authentication ('api_key', 'bearer', 'basic', None)
        priority: Priority (lower = tried first)
        supports_archive: Whether provider has full archive data
        supports_websocket: Whether provider supports WebSocket connections
        ws_url: WebSocket URL (if different from HTTP)
        credit_cost_method: For Infura, dict of method -> credit cost
    """

    name: str
    url: str
    rate_limit: float = 10.0  # requests per second
    max_block_range: int = 1000
    max_batch_size: int = 10
    requires_auth: bool = False
    auth_type: Optional[str] = None
    priority: int = 100
    supports_archive: bool = True
    supports_websocket: bool = False
    ws_url: Optional[str] = None
    credit_cost_method: Dict[str, int] = field(default_factory=dict)

    @property
    def min_request_delay(self) -> float:
        """Minimum delay between requests in seconds."""
        if self.rate_limit <= 0:
            return 0.0
        return 1.0 / self.rate_limit

    @property
    def max_logs_per_second(self) -> float:
        """Maximum eth_getLogs calls per second considering rate limits."""
        # For Infura, eth_getLogs costs 255 credits, limit is 500/sec
        if 'infura' in self.name.lower() and self.credit_cost_method:
            get_logs_cost = self.credit_cost_method.get('eth_getLogs', 255)
            credits_per_second = 500  # Infura free tier limit
            return max(1.0, credits_per_second / get_logs_cost)
        return self.rate_limit


# Infura credit costs for common methods (from official docs)
INFURA_CREDIT_COSTS = {
    # Standard methods
    'eth_blockNumber': 80,
    'eth_call': 80,
    'eth_chainId': 5,
    'eth_getBalance': 80,
    'eth_getBlockByHash': 80,
    'eth_getBlockByNumber': 80,
    'eth_getBlockReceipts': 1000,
    'eth_getCode': 80,
    'eth_getLogs': 255,  # Key for event indexing
    'eth_getTransactionByHash': 80,
    'eth_getTransactionCount': 80,
    'eth_getTransactionReceipt': 80,
    'eth_estimateGas': 300,
    'eth_feeHistory': 80,
    'eth_gasPrice': 80,
    # Filter methods
    'eth_getFilterChanges': 140,
    'eth_getFilterLogs': 255,
    'eth_newBlockFilter': 80,
    'eth_newFilter': 80,
    # Subscription events (per block/interval)
    'logs': 300,
    'newHeads': 50,
    'newPendingTransaction': 200,
}


def get_premium_providers(chain_id: int = 1) -> List[ProviderConfig]:
    """Get premium provider configurations from environment variables.

    Priority order (lower = tried first):
    1. NodeReal (first choice, supports nr_getTokenHolderCount for ETH/BSC)
    2. Infura (most reliable, higher rate limit for logs)
    3. Alchemy
    4. QuickNode
    5. Chainstack
    6. Ankr

    Returns:
        List of ProviderConfig objects, sorted by priority
    """
    providers = []

    # NodeReal - HIGHEST PRIORITY (supports nr_getTokenHolderCount for token holder counts)
    # API Endpoint format: https://{chain}-{network}.nodereal.io/v1/{API-key}
    # - ETH mainnet: https://eth-mainnet.nodereal.io/v1/{API-key}
    # - BSC mainnet: https://bsc-mainnet.nodereal.io/v1/{API-key}
    # Special method: nr_getTokenHolderCount(tokenAddress) -> holder count (hex)
    nodereal_key = os.environ.get("NODEREAL_API_KEY")
    if nodereal_key:
        if chain_id == 1:  # Ethereum Mainnet
            providers.append(ProviderConfig(
                name="nodereal-ethereum",
                url=f"https://eth-mainnet.nodereal.io/v1/{nodereal_key}",
                ws_url=f"wss://eth-mainnet.nodereal.io/v1/{nodereal_key}",
                rate_limit=15.0,  # Free tier rate limit
                max_block_range=5000,
                max_batch_size=100,
                requires_auth=True,
                auth_type="api_key",
                priority=0,  # HIGHEST PRIORITY - first choice
                supports_archive=True,
                supports_websocket=True,
            ))
        elif chain_id == 56:  # BNB Chain (BSC)
            providers.append(ProviderConfig(
                name="nodereal-bsc",
                url=f"https://bsc-mainnet.nodereal.io/v1/{nodereal_key}",
                ws_url=f"wss://bsc-mainnet.nodereal.io/v1/{nodereal_key}",
                rate_limit=15.0,  # Free tier rate limit
                max_block_range=5000,
                max_batch_size=100,
                requires_auth=True,
                auth_type="api_key",
                priority=0,  # HIGHEST PRIORITY - first choice
                supports_archive=True,
                supports_websocket=True,
            ))
        elif chain_id == 137:  # Polygon (also supported by NodeReal)
            providers.append(ProviderConfig(
                name="nodereal-polygon",
                url=f"https://polygon-mainnet.nodereal.io/v1/{nodereal_key}",
                ws_url=f"wss://polygon-mainnet.nodereal.io/v1/{nodereal_key}",
                rate_limit=15.0,
                max_block_range=5000,
                max_batch_size=100,
                requires_auth=True,
                auth_type="api_key",
                priority=0,
                supports_archive=True,
                supports_websocket=True,
            ))
        elif chain_id == 42161:  # Arbitrum
            providers.append(ProviderConfig(
                name="nodereal-arbitrum",
                url=f"https://arbitrum-one.nodereal.io/v1/{nodereal_key}",
                ws_url=f"wss://arbitrum-one.nodereal.io/v1/{nodereal_key}",
                rate_limit=15.0,
                max_block_range=5000,
                max_batch_size=100,
                requires_auth=True,
                auth_type="api_key",
                priority=0,
                supports_archive=True,
                supports_websocket=True,
            ))
        elif chain_id == 10:  # Optimism
            providers.append(ProviderConfig(
                name="nodereal-optimism",
                url=f"https://opt-mainnet.nodereal.io/v1/{nodereal_key}",
                ws_url=f"wss://opt-mainnet.nodereal.io/v1/{nodereal_key}",
                rate_limit=15.0,
                max_block_range=5000,
                max_batch_size=100,
                requires_auth=True,
                auth_type="api_key",
                priority=0,
                supports_archive=True,
                supports_websocket=True,
            ))
        elif chain_id == 43114:  # Avalanche
            providers.append(ProviderConfig(
                name="nodereal-avalanche",
                url=f"https://avalanche-mainnet.nodereal.io/v1/{nodereal_key}",
                ws_url=f"wss://avalanche-mainnet.nodereal.io/v1/{nodereal_key}",
                rate_limit=15.0,
                max_block_range=5000,
                max_batch_size=100,
                requires_auth=True,
                auth_type="api_key",
                priority=0,
                supports_archive=True,
                supports_websocket=True,
            ))

    # Infura - High priority for logs (255 credits, ~2 req/s for getLogs)
    infura_key = os.environ.get("INFURA_API_KEY")
    if infura_key:
        if chain_id == 1:  # Ethereum Mainnet
            providers.append(ProviderConfig(
                name="infura-ethereum",
                url=f"https://mainnet.infura.io/v3/{infura_key}",
                ws_url=f"wss://mainnet.infura.io/ws/v3/{infura_key}",
                rate_limit=2.0,  # ~500 credits/sec / 255 credits per getLogs
                max_block_range=10000,  # Infura supports larger ranges
                max_batch_size=100,  # Supports batching
                requires_auth=True,
                auth_type="api_key",
                priority=10,  # Highest priority
                supports_archive=True,
                supports_websocket=True,
                credit_cost_method=INFURA_CREDIT_COSTS,
            ))
        elif chain_id == 137:  # Polygon
            providers.append(ProviderConfig(
                name="infura-polygon",
                url=f"https://polygon-mainnet.infura.io/v3/{infura_key}",
                ws_url=f"wss://polygon-mainnet.infura.io/ws/v3/{infura_key}",
                rate_limit=2.0,
                max_block_range=1000,  # Polygon has temporary limit
                max_batch_size=100,
                requires_auth=True,
                auth_type="api_key",
                priority=10,
                supports_archive=True,
                supports_websocket=True,
                credit_cost_method=INFURA_CREDIT_COSTS,
            ))

    # Alchemy
    alchemy_key = os.environ.get("ALCHEMY_API_KEY")
    if alchemy_key:
        if chain_id == 1:
            providers.append(ProviderConfig(
                name="alchemy-ethereum",
                url=f"https://eth-mainnet.g.alchemy.com/v2/{alchemy_key}",
                ws_url=f"wss://eth-mainnet.g.alchemy.com/v2/{alchemy_key}",
                rate_limit=10.0,  # Approximate for free tier
                max_block_range=5000,
                max_batch_size=50,
                requires_auth=True,
                auth_type="api_key",
                priority=20,
                supports_archive=True,
                supports_websocket=True,
            ))
        elif chain_id == 137:
            providers.append(ProviderConfig(
                name="alchemy-polygon",
                url=f"https://polygon-mainnet.g.alchemy.com/v2/{alchemy_key}",
                ws_url=f"wss://polygon-mainnet.g.alchemy.com/v2/{alchemy_key}",
                rate_limit=10.0,
                max_block_range=5000,
                max_batch_size=50,
                requires_auth=True,
                auth_type="api_key",
                priority=20,
                supports_archive=True,
                supports_websocket=True,
            ))

    # QuickNode
    quicknode_url = os.environ.get("QUICKNODE_API_KEY")
    if quicknode_url:
        providers.append(ProviderConfig(
            name="quicknode",
            url=quicknode_url,
            rate_limit=10.0,  # Free tier limit
            max_block_range=3000,
            max_batch_size=100,
            requires_auth=True,
            auth_type="api_key",
            priority=30,
            supports_archive=True,
            supports_websocket=True,
        ))

    # Chainstack
    chainstack_key = os.environ.get("CHAINSTACK_API_KEY")
    if chainstack_key:
        providers.append(ProviderConfig(
            name="chainstack",
            url=f"https://{chainstack_key}.eth.chainstack.net",
            rate_limit=10.0,
            max_block_range=5000,
            max_batch_size=50,
            requires_auth=True,
            auth_type="api_key",
            priority=40,
            supports_archive=True,
            supports_websocket=False,
        ))

    # Ankr - Using accurate rate limits from user's data
    # Public tier: ~1800 req/min = ~30 req/s, max block range 1000, max batch 10
    ankr_key = os.environ.get("ANKR_API_KEY")
    if chain_id == 1:
        ankr_url = f"https://rpc.ankr.com/eth/{ankr_key}" if ankr_key else "https://rpc.ankr.com/eth"
        providers.append(ProviderConfig(
            name="ankr-ethereum",
            url=ankr_url,
            rate_limit=30.0,  # ~1800 requests/minute guaranteed
            max_block_range=1000,  # Public tier limit
            max_batch_size=10,  # Public tier limit
            requires_auth=bool(ankr_key),
            auth_type="api_key" if ankr_key else None,
            priority=50,  # Good rate limit but smaller block range
            supports_archive=True,
            supports_websocket=False,
        ))
    elif chain_id == 137:
        ankr_url = f"https://rpc.ankr.com/polygon/{ankr_key}" if ankr_key else "https://rpc.ankr.com/polygon"
        providers.append(ProviderConfig(
            name="ankr-polygon",
            url=ankr_url,
            rate_limit=30.0,
            max_block_range=1000,  # Temporary Polygon limit
            max_batch_size=10,
            requires_auth=bool(ankr_key),
            auth_type="api_key" if ankr_key else None,
            priority=50,
            supports_archive=True,
            supports_websocket=False,
        ))

    return sorted(providers, key=lambda p: p.priority)


def get_public_providers(chain_id: int = 1) -> List[ProviderConfig]:
    """Get free public provider configurations.

    These are fallback providers with no API key required.
    Rate limits are estimates based on typical public node limits.

    Returns:
        List of ProviderConfig objects, sorted by priority
    """
    if chain_id == 1:  # Ethereum Mainnet
        return [
            ProviderConfig(
                name="noderpc",
                url="https://api.noderpc.xyz/rpc-mainnet/FvVNN6WcGcsQ2Jl8UBO38gEtGQZ8Tqmq49878i9GNuY",
                ws_url="wss://api.noderpc.xyz/rpc-mainnet/ws/FvVNN6WcGcsQ2Jl8UBO38gEtGQZ8Tqmq49878i9GNuY",
                rate_limit=10.0,
                max_block_range=5000,
                max_batch_size=50,
                priority=90,
                supports_archive=True,
                supports_websocket=True,
            ),
            ProviderConfig(
                name="publicnode",
                url="https://ethereum-rpc.publicnode.com",
                ws_url="wss://ethereum-rpc.publicnode.com",
                rate_limit=10.0,
                max_block_range=5000,
                max_batch_size=50,
                priority=100,
                supports_archive=True,
                supports_websocket=True,
            ),
            ProviderConfig(
                name="llamarpc",
                url="https://eth.llamarpc.com",
                rate_limit=10.0,
                max_block_range=5000,
                max_batch_size=50,
                priority=110,
                supports_archive=True,
                supports_websocket=False,
            ),
            ProviderConfig(
                name="drpc",
                url="https://eth.drpc.org",
                rate_limit=10.0,
                max_block_range=5000,
                max_batch_size=50,
                priority=120,
                supports_archive=True,
                supports_websocket=False,
            ),
            ProviderConfig(
                name="0xrpc",
                url="https://0xrpc.io/eth",
                ws_url="wss://0xrpc.io/eth",
                rate_limit=5.0,
                max_block_range=3000,
                max_batch_size=10,
                priority=130,
                supports_archive=True,
                supports_websocket=True,
            ),
            ProviderConfig(
                name="1rpc",
                url="https://1rpc.io/eth",
                rate_limit=5.0,
                max_block_range=3000,
                max_batch_size=10,
                priority=140,
                supports_archive=True,
                supports_websocket=False,
            ),
            ProviderConfig(
                name="blockpi",
                url="https://ethereum.blockpi.network/v1/rpc/public",
                rate_limit=10.0,
                max_block_range=5000,
                max_batch_size=50,
                priority=150,
                supports_archive=True,
                supports_websocket=False,
            ),
            ProviderConfig(
                name="cloudflare",
                url="https://cloudflare-eth.com/v1/mainnet",
                rate_limit=50.0,  # Cloudflare is quite fast
                max_block_range=1000,  # But limited archive data (~12M blocks)
                max_batch_size=10,
                priority=160,  # Lower priority due to archive limitation
                supports_archive=False,  # Only last ~12M blocks
                supports_websocket=False,
            ),
            ProviderConfig(
                name="blinklabs",
                url="https://ethereum.blinklabs.xyz/",
                rate_limit=5.0,
                max_block_range=3000,
                max_batch_size=10,
                priority=170,
                supports_archive=True,
                supports_websocket=False,
            ),
            ProviderConfig(
                name="meowrpc",
                url="https://eth.meowrpc.com",
                rate_limit=10.0,
                max_block_range=3000,
                max_batch_size=10,
                priority=180,
                supports_archive=True,
                supports_websocket=False,
            ),
            ProviderConfig(
                name="leorpc",
                url="https://eth.leorpc.com/?api_key=FREE",
                rate_limit=5.0,
                max_block_range=3000,
                max_batch_size=10,
                priority=190,
                supports_archive=True,
                supports_websocket=False,
            ),
            ProviderConfig(
                name="tenderly",
                url="https://mainnet.gateway.tenderly.co",
                ws_url="wss://mainnet.gateway.tenderly.co",
                rate_limit=10.0,
                max_block_range=5000,
                max_batch_size=50,
                priority=200,
                supports_archive=True,
                supports_websocket=True,
            ),
        ]
    elif chain_id == 137:  # Polygon
        return [
            ProviderConfig(
                name="polygon-rpc",
                url="https://polygon-rpc.com",
                rate_limit=10.0,
                max_block_range=5000,
                max_batch_size=50,
                priority=100,
                supports_archive=True,
                supports_websocket=False,
            ),
            ProviderConfig(
                name="polygon-publicnode",
                url="https://polygon-rpc.publicnode.com",
                rate_limit=10.0,
                max_block_range=5000,
                max_batch_size=50,
                priority=110,
                supports_archive=True,
                supports_websocket=False,
            ),
            ProviderConfig(
                name="polygon-llamarpc",
                url="https://polygon.llamarpc.com",
                rate_limit=10.0,
                max_block_range=5000,
                max_batch_size=50,
                priority=120,
                supports_archive=True,
                supports_websocket=False,
            ),
            ProviderConfig(
                name="polygon-tenderly",
                url="https://polygon.gateway.tenderly.co",
                rate_limit=10.0,
                max_block_range=5000,
                max_batch_size=50,
                priority=130,
                supports_archive=True,
                supports_websocket=False,
            ),
            ProviderConfig(
                name="polygon-noderpc",
                url="https://api.noderpc.xyz/rpc-polygon-pos/public",
                rate_limit=10.0,
                max_block_range=5000,
                max_batch_size=50,
                priority=130,
                supports_archive=True,
                supports_websocket=False,
            ),
        ]
    elif chain_id == 56:  # BNB Chain (BSC)
        return [
            ProviderConfig(
                name="bsc-dataseed",
                url="https://bsc-dataseed.binance.org",
                rate_limit=10.0,
                max_block_range=5000,
                max_batch_size=50,
                priority=100,
                supports_archive=True,
                supports_websocket=False,
            ),
            ProviderConfig(
                name="bsc-dataseed1",
                url="https://bsc-dataseed1.defibit.io",
                rate_limit=10.0,
                max_block_range=5000,
                max_batch_size=50,
                priority=110,
                supports_archive=True,
                supports_websocket=False,
            ),
            ProviderConfig(
                name="bsc-dataseed2",
                url="https://bsc-dataseed2.defibit.io",
                rate_limit=10.0,
                max_block_range=5000,
                max_batch_size=50,
                priority=120,
                supports_archive=True,
                supports_websocket=False,
            ),
            ProviderConfig(
                name="bsc-dataseed3",
                url="https://bsc-dataseed3.defibit.io",
                rate_limit=10.0,
                max_block_range=5000,
                max_batch_size=50,
                priority=130,
                supports_archive=True,
                supports_websocket=False,
            ),
            ProviderConfig(
                name="bsc-dataseed4",
                url="https://bsc-dataseed4.defibit.io",
                rate_limit=10.0,
                max_block_range=5000,
                max_batch_size=50,
                priority=140,
                supports_archive=True,
                supports_websocket=False,
            ),
            ProviderConfig(
                name="bsc-rpc-org",
                url="https://bsc-rpc.publicnode.com",
                rate_limit=10.0,
                max_block_range=5000,
                max_batch_size=50,
                priority=150,
                supports_archive=True,
                supports_websocket=False,
            ),
            ProviderConfig(
                name="bsc-ankr",
                url="https://rpc.ankr.com/bsc",
                rate_limit=30.0,  # Ankr has good rate limits
                max_block_range=1000,
                max_batch_size=10,
                priority=160,
                supports_archive=True,
                supports_websocket=False,
            ),
            ProviderConfig(
                name="bsc-omniatech",
                url="https://endpoints.omniatech.io/v1/bsc/mainnet/053581764d2949b8bfce04e36103c35f",
                rate_limit=10.0,
                max_block_range=5000,
                max_batch_size=50,
                priority=170,
                supports_archive=True,
                supports_websocket=False,
            ),
        ]
    elif chain_id == 42161:  # Arbitrum
        return [
            ProviderConfig(
                name="arbitrum-rpc",
                url="https://arb1.arbitrum.io/rpc",
                rate_limit=10.0,
                max_block_range=5000,
                max_batch_size=50,
                priority=100,
                supports_archive=True,
                supports_websocket=False,
            ),
            ProviderConfig(
                name="arbitrum-tenderly",
                url="https://arbitrum.gateway.tenderly.co",
                rate_limit=10.0,
                max_block_range=5000,
                max_batch_size=50,
                priority=110,
                supports_archive=True,
                supports_websocket=False,
            ),
            ProviderConfig(
                name="arbitrum-ankr",
                url="https://rpc.ankr.com/arbitrum",
                rate_limit=30.0,
                max_block_range=1000,
                max_batch_size=10,
                priority=120,
                supports_archive=True,
                supports_websocket=False,
            ),
            ProviderConfig(
                name="arbitrum-omniatech",
                url="https://endpoints.omniatech.io/v1/arbitrum/093e28c96c4a46a8bdc9d1b3e5a273f9",
                rate_limit=10.0,
                max_block_range=5000,
                max_batch_size=50,
                priority=130,
                supports_archive=True,
                supports_websocket=False,
            ),
        ]
    elif chain_id == 10:  # Optimism
        return [
            ProviderConfig(
                name="optimism-rpc",
                url="https://mainnet.optimism.io",
                rate_limit=10.0,
                max_block_range=5000,
                max_batch_size=50,
                priority=100,
                supports_archive=True,
                supports_websocket=False,
            ),
            ProviderConfig(
                name="optimism-ankr",
                url="https://rpc.ankr.com/optimism",
                rate_limit=30.0,
                max_block_range=1000,
                max_batch_size=10,
                priority=110,
                supports_archive=True,
                supports_websocket=False,
            ),
            ProviderConfig(
                name="optimism-tenderly",
                url="https://optimism.gateway.tenderly.co",
                rate_limit=10.0,
                max_block_range=5000,
                max_batch_size=50,
                priority=120,
                supports_archive=True,
                supports_websocket=False,
            ),
        ]
    elif chain_id == 43114:  # Avalanche
        return [
            ProviderConfig(
                name="avalanche-rpc",
                url="https://api.avax.network/ext/bc/C/rpc",
                rate_limit=10.0,
                max_block_range=5000,
                max_batch_size=50,
                priority=100,
                supports_archive=True,
                supports_websocket=False,
            ),
            ProviderConfig(
                name="avalanche-ankr",
                url="https://rpc.ankr.com/avalanche",
                rate_limit=30.0,
                max_block_range=1000,
                max_batch_size=10,
                priority=110,
                supports_archive=True,
                supports_websocket=False,
            ),
            ProviderConfig(
                name="avalanche-omniatech",
                url="https://endpoints.omniatech.io/v1/avax/mainnet/053581764d2949b8bfce04e36103c35f",
                rate_limit=10.0,
                max_block_range=5000,
                max_batch_size=50,
                priority=120,
                supports_archive=True,
                supports_websocket=False,
            ),
        ]

    return []


def get_all_providers(chain_id: int = 1) -> List[ProviderConfig]:
    """Get all available providers (premium + public).

    Returns:
        List of ProviderConfig objects, sorted by priority
    """
    providers = get_premium_providers(chain_id) + get_public_providers(chain_id)
    return sorted(providers, key=lambda p: p.priority)


def get_optimized_chunk_size(
    chain_id: int = 1,
    default_chunk_size: int = 100000,
) -> int:
    """Get optimal chunk size based on available providers' block range limits.

    For parallel indexing, we want to use a chunk size that:
    1. Fits within the smallest provider's max_block_range
    2. Is large enough to be efficient
    3. Considers the rate limits of providers

    Args:
        chain_id: Chain ID
        default_chunk_size: Default if no providers available

    Returns:
        Optimal chunk size in blocks
    """
    providers = get_all_providers(chain_id)
    if not providers:
        return default_chunk_size

    # Find the smallest max_block_range among providers
    min_range = min(p.max_block_range for p in providers)

    # Use a chunk size that's a fraction of the smallest range
    # This ensures all providers can handle any chunk
    optimal_size = min(min_range // 2, default_chunk_size)

    # Ensure minimum reasonable size
    return max(1000, optimal_size)


def get_total_rate_limit(chain_id: int = 1) -> float:
    """Calculate total rate limit across all providers.

    Args:
        chain_id: Chain ID

    Returns:
        Total requests per second across all providers
    """
    providers = get_all_providers(chain_id)
    return sum(p.rate_limit for p in providers)


def print_provider_summary(chain_id: int = 1) -> None:
    """Print a summary of available providers and their capabilities.

    Args:
        chain_id: Chain ID
    """
    providers = get_all_providers(chain_id)

    print(f"\n{'='*80}")
    print(f"RPC Provider Configuration Summary (Chain {chain_id})")
    print(f"{'='*80}\n")

    print(f"{'Provider':<20} {'Rate':<10} {'Block Range':<15} {'Batch':<10} {'Archive':<10}")
    print("-" * 80)

    for p in providers:
        archive = "✅ Yes" if p.supports_archive else "❌ No"
        print(f"{p.name:<20} {p.rate_limit:<10.1f} {p.max_block_range:<15,} {p.max_batch_size:<10} {archive:<10}")

    total_rate = get_total_rate_limit(chain_id)
    print("-" * 80)
    print(f"{'TOTAL':<20} {total_rate:<10.1f}")
    print(f"\nOptimal chunk size: {get_optimized_chunk_size(chain_id):,} blocks")
    print(f"{'='*80}\n")
