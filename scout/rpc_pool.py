"""Parallel RPC pool for managing multiple free blockchain RPC endpoints.

This module provides load balancing and parallel execution across multiple
free RPC providers to maximize throughput when fetching blockchain data.
"""

from __future__ import annotations

import asyncio
import logging
import os
import random
import ssl
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

import aiohttp
import web3
from eth_abi import encode, decode
from eth_utils import to_checksum_address
from web3 import Web3
from web3.exceptions import Web3Exception

LOGGER = logging.getLogger(__name__)

def get_premium_rpc_endpoints(chain_id: int) -> List[str]:
    """Get premium free-tier RPC endpoints with optional API keys.

    Checks environment variables for API keys and returns endpoints with keys.
    Falls back to endpoints without keys if keys are not available.

    Environment variables:
    - INFURA_API_KEY: Infura project ID
    - ALCHEMY_API_KEY: Alchemy API key
    - QUICKNODE_API_KEY: QuickNode endpoint URL
    - CHAINSTACK_API_KEY: Chainstack API key
    """
    endpoints = []

    infura_key = os.environ.get("INFURA_API_KEY")
    alchemy_key = os.environ.get("ALCHEMY_API_KEY")
    quicknode_url = os.environ.get("QUICKNODE_API_KEY")
    chainstack_key = os.environ.get("CHAINSTACK_API_KEY")

    if chain_id == 1:  # Ethereum Mainnet
        # Infura (only include if API key is provided - requires authentication)
        if infura_key:
            endpoints.append(f"https://mainnet.infura.io/v3/{infura_key}")

        # Alchemy (only include if API key is provided - requires authentication)
        if alchemy_key:
            endpoints.append(f"https://eth-mainnet.g.alchemy.com/v2/{alchemy_key}")

        # QuickNode (requires key, skip if not provided)
        if quicknode_url:
            endpoints.append(quicknode_url)

        # Chainstack (requires key, skip if not provided)
        if chainstack_key:
            endpoints.append(f"https://{chainstack_key}.eth.chainstack.net")

        # PublicNode (premium free tier, no key required)
        endpoints.append("https://ethereum-rpc.publicnode.com")

        # Ankr (premium free tier, no key required)
        endpoints.append("https://rpc.ankr.com/eth")

    elif chain_id == 137:  # Polygon
        # Infura (only include if API key is provided)
        if infura_key:
            endpoints.append(f"https://polygon-mainnet.infura.io/v3/{infura_key}")

        # Alchemy (only include if API key is provided)
        if alchemy_key:
            endpoints.append(f"https://polygon-mainnet.g.alchemy.com/v2/{alchemy_key}")

        # PublicNode (premium free tier, no key required)
        endpoints.append("https://polygon-rpc.publicnode.com")

        # Ankr (premium free tier, no key required)
        endpoints.append("https://rpc.ankr.com/polygon")

    return endpoints

# Default RPC endpoints by chain ID (free, no API key required)
# Used as fallback when premium endpoints are not available or fail
DEFAULT_RPC_ENDPOINTS = {
    1: [  # Ethereum
        "https://ethereum-rpc.publicnode.com",
        "https://rpc.ankr.com/eth",
        "https://eth.llamarpc.com",
        "https://eth.drpc.org",
        "https://0xrpc.io/eth",
        "https://1rpc.io/eth",
        "https://ethereum.publicnode.com",
        "https://eth-mainnet.public.blastapi.io",
        "https://ethereum.blinklabs.xyz/",
        "https://ethereum.blockpi.network/v1/rpc/public",
        "https://eth-protect.rpc.blxrbdn.com",
        "https://cloudflare-eth.com/v1/mainnet",
        "https://api.edennetwork.io/v1/rocket",
        "https://eth.rpc.hypersync.xyz/",
        "https://ethereum-api.flare.network/",
        "https://rpc.flashbots.net/",
        "https://rpc.graffiti.farm/",
        "https://eth.meowrpc.com",
        "https://eth.leorpc.com/?api_key=FREE",
        "https://eth.merkle.io/",
        "https://rpc.mevblocker.io",
        "https://api.noderpc.xyz/rpc-mainnet/public",
        "https://lb.nodies.app/v1/5e9daed367d1454fab7c75f0ec8aceff",
        "https://public-eth.nownodes.io/",
        "https://endpoints.omniatech.io/v1/eth/mainnet/public",
        "https://eth.api.onfinality.io/public",
        "https://ethereum-rpc.polkachu.com/",
        "https://rpc.propellerheads.xyz/eth",
        "https://eth-mainnet.reddio.com/",
        "https://mainnet.gateway.tenderly.co",
        "https://ethereum.rpc.thirdweb.com/",
        # Add your custom providers below:
        # "https://your-custom-rpc-provider.com",
    ],
    137: [  # Polygon
        "https://polygon-rpc.com",
        "https://rpc.ankr.com/polygon",
        "https://polygon.llamarpc.com",
        "https://polygon.drpc.org",
        "https://1rpc.io/matic",
        "https://polygon-bor.publicnode.com",
        "https://polygon-mainnet.public.blastapi.io",
        "https://api.blockeden.xyz/polygon/67nCBdZQSH9z3YqDDjdm",
        "https://polygon.rpc.hypersync.xyz/",
        "https://polygon-api.flare.network/",
        "https://pol.leorpc.com/?api_key=FREE",
        "https://api.noderpc.xyz/rpc-polygon-pos/public",
        "https://lb.nodies.app/v1/975f16c52f5f4732b20b6692137eec17",
        "https://endpoints.omniatech.io/v1/matic/mainnet/public",
        "https://polygon.api.onfinality.io/public",
        "https://polygon-pokt.nodies.app/",
        "https://rpc-mainnet.matic.quiknode.pro",
        "https://polygon-mainnet.rpcfast.com?api_key=xbhWBI1Wkguk8SNMu1bvvLurPGLXmgwYeC4S6g2H7WdwFigZSmPWVZRxrskEQwIf",
        "https://polygon.rpc.subquery.network/public",
        "https://polygon.gateway.tenderly.co",
        "https://137.rpc.thirdweb.com/",
    ],
    56: [  # BSC
        "https://bsc-dataseed.binance.org",
        "https://bsc-dataseed1.binance.org",
        "https://bsc-dataseed2.binance.org",
        "https://bsc-dataseed3.binance.org",
        "https://bsc-dataseed4.binance.org",
        "https://rpc.ankr.com/bsc",
        "https://bsc.llamarpc.com",
        "https://bsc.drpc.org",
        "https://1rpc.io/bnb",
        "https://bsc-rpc.publicnode.com",
        "https://bsc.blockpi.network/v1/rpc/public",
        "https://bsc.rpc.hypersync.xyz/",
        "https://bsc-api.flare.network/",
        "https://bsc.leorpc.com/?api_key=FREE",
        "https://api.noderpc.xyz/rpc-bsc/public",
        "https://lb.nodies.app/v1/2a2c6b8873ce46248e8d44cdcd1f8e54",
        "https://endpoints.omniatech.io/v1/bsc/mainnet/public",
        "https://bsc.api.onfinality.io/public",
        "https://bsc.rpc.subquery.network/public",
        "https://bsc.gateway.tenderly.co",
        "https://56.rpc.thirdweb.com/",
    ],
    42161: [  # Arbitrum
        "https://arb1.arbitrum.io/rpc",
        "https://rpc.ankr.com/arbitrum",
        "https://arbitrum.llamarpc.com",
        "https://arbitrum.drpc.org",
        "https://1rpc.io/arb",
        "https://arbitrum-one-rpc.publicnode.com",
        "https://arbitrum-one.public.blastapi.io",
        "https://arbitrum.blockpi.network/v1/rpc/public",
        "https://arbitrum.rpc.hypersync.xyz/",
        "https://arbitrum-api.flare.network/",
        "https://arb.leorpc.com/?api_key=FREE",
        "https://api.noderpc.xyz/rpc-arbitrum-one/public",
        "https://lb.nodies.app/v1/a85fbaa7e2e1462c9dc3311b0c7f7f7f",
        "https://endpoints.omniatech.io/v1/arbitrum/mainnet/public",
        "https://arbitrum.api.onfinality.io/public",
        "https://rpc-subnet-arbitrum.onfinality.io",
        "https://arbitrum-one.rpc.subquery.network/public",
        "https://arbitrum-one.gateway.tenderly.co",
        "https://42161.rpc.thirdweb.com/",
    ],
    10: [  # Optimism
        "https://mainnet.optimism.io",
        "https://rpc.ankr.com/optimism",
        "https://optimism.llamarpc.com",
        "https://optimism.drpc.org",
        "https://1rpc.io/op",
        "https://optimism-rpc.publicnode.com",
        "https://optimism.public.blastapi.io",
        "https://optimism.blockpi.network/v1/rpc/public",
        "https://optimism.rpc.hypersync.xyz/",
        "https://optimism-api.flare.network/",
        "https://op.leorpc.com/?api_key=FREE",
        "https://api.noderpc.xyz/rpc-optimism/public",
        "https://lb.nodies.app/v1/0e3da269896c4616b0e2aa5eb5dd56e8",
        "https://endpoints.omniatech.io/v1/op/mainnet/public",
        "https://optimism.api.onfinality.io/public",
        "https://optimism.rpc.subquery.network/public",
        "https://optimism.gateway.tenderly.co",
        "https://10.rpc.thirdweb.com/",
    ],
    43114: [  # Avalanche
        "https://api.avax.network/ext/bc/C/rpc",
        "https://rpc.ankr.com/avalanche",
        "https://avalanche.llamarpc.com",
        "https://avalanche.drpc.org",
        "https://1rpc.io/avax",
        "https://avalanche-c-chain-rpc.publicnode.com",
        "https://avalanche.public.blastapi.io",
        "https://avalanche.blockpi.network/v1/rpc/public",
        "https://ava.rpc.hypersync.xyz/",
        "https://avalanche-api.flare.network/",
        "https://c-chain.leorpc.com/?api_key=FREE",
        "https://api.noderpc.xyz/rpc-avalanche-c/public",
        "https://lb.nodies.app/v1/f56c337a596a4313ba7c0e624796c77e",
        "https://endpoints.omniatech.io/v1/avax/mainnet/public",
        "https://avax.api.onfinality.io/public",
        "https://avalanche.rpc.subquery.network/public",
        "https://avalanche.gateway.tenderly.co",
        "https://43114.rpc.thirdweb.com/",
    ],
}

# Multicall3 contract addresses (same address on all chains)
MULTICALL3_ADDRESSES = {
    1: "0xcA11bde05977b3631167028862bE2a173976CA11",
    137: "0xcA11bde05977b3631167028862bE2a173976CA11",
    56: "0xcA11bde05977b3631167028862bE2a173976CA11",
    42161: "0xcA11bde05977b3631167028862bE2a173976CA11",
    10: "0xcA11bde05977b3631167028862bE2a173976CA11",
    43114: "0xcA11bde05977b3631167028862bE2a173976CA11",
}

# Multicall3 ABI (minimal - only the aggregate function)
MULTICALL3_ABI = [
    {
        "inputs": [
            {"internalType": "struct Multicall3.Call[]", "name": "calls", "type": "tuple"}
        ],
        "name": "aggregate",
        "outputs": [
            {"internalType": "uint256", "name": "blockNumber", "type": "uint256"},
            {"internalType": "bytes[]", "name": "returnData", "type": "bytes[]"}
        ],
        "stateMutability": "payable",
        "type": "function"
    }
]


@dataclass
class RpcProvider:
    """Represents a single RPC provider with health tracking."""

    url: str
    chain_id: int
    _session: Optional[aiohttp.ClientSession] = None
    _session_loop_id: Optional[int] = None
    failures: int = 0
    max_failures: int = 5
    timeout: float = 30.0

    @property
    def session(self) -> aiohttp.ClientSession:
        """Lazy session creation - only creates when first accessed.

        Detects event-loop changes (e.g. when audit runs via asyncio.run()
        in a worker thread) and creates a fresh session bound to the new loop.
        """
        try:
            current_loop = asyncio.get_running_loop()
            current_loop_id = id(current_loop)
        except RuntimeError:
            current_loop_id = None

        if self._session is not None and self._session_loop_id != current_loop_id:
            # Session was created on a different loop — discard it
            LOGGER.debug("Discarding stale aiohttp session (loop changed)")
            self._session = None

        if self._session is None:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            # Create SSL context that's more permissive for certificate issues
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            connector = aiohttp.TCPConnector(ssl=ssl_context)
            self._session = aiohttp.ClientSession(timeout=timeout, connector=connector)
            self._session_loop_id = current_loop_id
        return self._session

    async def close(self) -> None:
        """Close the HTTP session."""
        if self._session is None:
            return
        try:
            await self._session.close()
        except Exception:
            pass
        self._session = None
        self._session_loop_id = None

    def is_healthy(self) -> bool:
        """Check if provider is healthy (below failure threshold)."""
        return self.failures < self.max_failures

    def mark_failure(self) -> None:
        """Mark a failure for this provider."""
        self.failures += 1
        LOGGER.warning(
            "RPC provider failure",
            extra={"url": self.url, "chain_id": self.chain_id, "failures": self.failures}
        )

    def mark_success(self) -> None:
        """Reset failure count on successful request."""
        if self.failures > 0:
            self.failures = max(0, self.failures - 1)

    async def make_request(self, method: str, params: List[Any]) -> Any:
        """Make a JSON-RPC request to this provider."""
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }

        try:
            async with self.session.post(                self.url,
                json=payload,
                headers={"Content-Type": "application/json"},
            ) as response:
                if response.status != 200:
                    raise Web3Exception(f"HTTP {response.status}")
                data = await response.json()
                if "error" in data:
                    error = data["error"]
                    # Extract message from error dict or use string representation
                    if isinstance(error, dict):
                        error_msg = error.get("message", str(error))
                        error_code = error.get("code", "N/A")
                        raise Web3Exception(f"RPC Error {error_code}: {error_msg}")
                    else:
                        raise Web3Exception(str(error))
                self.mark_success()
                return data.get("result")
        except (aiohttp.ClientError, Web3Exception, asyncio.TimeoutError, Exception) as exc:
            self.mark_failure()
            exc_str = str(exc) if str(exc) else exc.__class__.__name__
            raise Web3Exception(f"{self.url}: {exc_str}") from exc


class ParallelRpcPool:
    """Manages multiple RPC providers with parallel execution support."""

    def __init__(
        self,
        chain_id: int,
        rpc_urls: Optional[List[str]] = None,
        max_parallel: int = 5,
        batch_size: int = 50,  # Reduced for free RPC providers
    ) -> None:
        """Initialize the RPC pool.

        Args:
            chain_id: Chain ID for this pool
            rpc_urls: List of RPC endpoint URLs (uses defaults if None)
            max_parallel: Maximum number of parallel requests
            batch_size: Number of addresses per batch
        """
        self.chain_id = chain_id
        self.max_parallel = max_parallel
        self.batch_size = batch_size

        # Use provided URLs or combine premium + default endpoints
        if rpc_urls:
            self.urls = rpc_urls
        else:
            # Get premium endpoints (with API keys if available)
            premium_urls = get_premium_rpc_endpoints(chain_id)
            # Get default public endpoints
            default_urls = DEFAULT_RPC_ENDPOINTS.get(chain_id, [])
            # Combine: premium first, then defaults (deduplicated)
            seen = set()
            self.urls = []
            for url_list in [premium_urls, default_urls]:
                for url in url_list:
                    if url not in seen:
                        seen.add(url)
                        self.urls.append(url)

        if not self.urls:
            raise ValueError(f"No RPC endpoints available for chain {chain_id}")

        # Create providers
        self.providers: List[RpcProvider] = [
            RpcProvider(url=url, chain_id=chain_id) for url in self.urls
        ]

        # Shuffle for load balancing (but keep premium endpoints at front)
        # We want premium endpoints to be tried first, so only shuffle the public ones
        premium_count = len(get_premium_rpc_endpoints(chain_id))
        if premium_count < len(self.providers):
            # Keep premium providers in order at the front, shuffle the rest
            premium_providers = self.providers[:premium_count]
            public_providers = self.providers[premium_count:]
            random.shuffle(public_providers)
            self.providers = premium_providers + public_providers

        # Multicall3 contract
        self.multicall3_address = MULTICALL3_ADDRESSES.get(chain_id)
        if not self.multicall3_address:
            raise ValueError(f"No Multicall3 address for chain {chain_id}")

    async def close(self) -> None:
        """Close all provider sessions."""
        await asyncio.gather(*[p.close() for p in self.providers], return_exceptions=True)

    def get_healthy_providers(self) -> List[RpcProvider]:
        """Get list of healthy providers, sorted by fewest failures."""
        healthy = [p for p in self.providers if p.is_healthy()]
        return sorted(healthy, key=lambda p: p.failures)

    async def batch_balance_of_calls(
        self,
        token_address: str,
        holder_addresses: List[str],
        block_number: int = "latest",
    ) -> Dict[str, int]:
        """Fetch balances for multiple addresses in parallel using Multicall3.

        Args:
            token_address: Token contract address
            holder_addresses: List of holder addresses to query
            block_number: Block number (default: latest)

        Returns:
            Dictionary mapping address to balance (as integer)
        """
        if not holder_addresses:
            return {}

        # Split addresses into chunks
        chunks = [
            holder_addresses[i : i + self.batch_size]
            for i in range(0, len(holder_addresses), self.batch_size)
        ]

        # Get healthy providers
        providers = self.get_healthy_providers()
        if not providers:
            raise Web3Exception("No healthy RPC providers available")

        # Limit parallelism
        providers = providers[: self.max_parallel]

        # Create tasks for each chunk
        tasks = []
        for i, chunk in enumerate(chunks):
            provider = providers[i % len(providers)]
            task = self._fetch_chunk_balances(
                provider, token_address, chunk, block_number
            )
            tasks.append(task)

        # Execute all tasks in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Merge results and track failures
        balances = {}
        failed_chunks = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                LOGGER.error(f"Chunk {i} fetch failed: {result}")
                failed_chunks.append((i, chunks[i]))
                continue
            if not result:  # Empty result
                LOGGER.warning(f"Chunk {i} returned empty balances")
                failed_chunks.append((i, chunks[i]))
                continue
            balances.update(result)

        # Fallback: Try individual calls for failed chunks
        if failed_chunks:
            LOGGER.info(f"Trying {len(failed_chunks)} failed chunks with individual calls")
            for chunk_idx, chunk in failed_chunks:
                provider = providers[chunk_idx % len(providers)]
                for address in chunk:
                    try:
                        individual_balance = await self._fetch_single_balance(
                            provider, token_address, address, block_number
                        )
                        if individual_balance is not None:
                            checksum_addr = to_checksum_address(address)
                            balances[checksum_addr] = individual_balance
                    except Exception as exc:
                        LOGGER.error(f"Individual call failed for {address[:10]}...: {exc}")

        return balances

    async def _fetch_single_balance(
        self,
        provider: RpcProvider,
        token_address: str,
        address: str,
        block_number: int,
    ) -> Optional[int]:
        """Fetch balance for a single address using individual eth_call.

        Fallback method when Multicall3 fails.

        Args:
            provider: RPC provider to use
            token_address: Token contract address
            address: Holder address to query
            block_number: Block number

        Returns:
            Balance as integer, or None if failed
        """
        try:
            # ERC20 balanceOf function selector
            BALANCE_OF_SELECTOR = "0x70a08231"

            # Encode address parameter
            checksum_addr = to_checksum_address(address)
            address_encoded = checksum_addr[2:].lower().zfill(64)
            call_data = "0x" + BALANCE_OF_SELECTOR[2:] + address_encoded

            # Format block number for RPC call
            block_param = "latest" if block_number == "latest" else f"0x{block_number:x}"

            result = await provider.make_request(
                "eth_call",
                [
                    {
                        "to": token_address,
                        "data": call_data,
                    },
                    block_param,
                ],
            )

            if result and isinstance(result, str) and result != "0x":
                # Parse the balance (uint256 = 32 bytes)
                balance_int = int(result, 16)
                return balance_int

            return 0

        except Exception as exc:
            LOGGER.debug(f"Single balance fetch failed for {address[:10]}...: {exc}")
            return None

    async def _fetch_chunk_balances(
        self,
        provider: RpcProvider,
        token_address: str,
        addresses: List[str],
        block_number: int,
    ) -> Dict[str, int]:
        """Fetch balances for a chunk of addresses from a single provider.

        Uses Multicall3 to batch all balanceOf calls into one RPC request.
        """
        # ERC20 balanceOf function signature
        # balanceOf(address) returns uint256
        BALANCE_OF_SELECTOR = "0x70a08231"  # keccak256("balanceOf(address)")[0:4]

        calls = []
        for address in addresses:
            # Properly encode the address parameter for balanceOf call
            # The address needs to be padded to 32 bytes (64 hex chars)
            checksum_addr = to_checksum_address(address)
            address_encoded = checksum_addr[2:].lower().zfill(64)

            # Function selector (4 bytes) + encoded address (32 bytes)
            call_data = "0x" + BALANCE_OF_SELECTOR[2:] + address_encoded
            calls.append((token_address, call_data))

        # Build aggregate call data
        encoded_calls = self._encode_multicall_calls(calls)

        try:
            # Format block number for RPC call
            block_param = "latest" if block_number == "latest" else f"0x{block_number:x}"

            result = await provider.make_request(
                "eth_call",
                [
                    {
                        "to": self.multicall3_address,
                        "data": encoded_calls,
                    },
                    block_param,
                ],
            )

            if not result:
                return {}

            # Decode Multicall3 response
            return self._decode_multicall_result(result, addresses)

        except Exception as exc:
            LOGGER.error(f"Multicall batch failed: {exc}")
            raise

    def _encode_multicall_calls(self, calls: List[tuple]) -> str:
        """Encode Multicall3 aggregate calls.

        Args:
            calls: List of (target, call_data) tuples

        Returns:
            Encoded call data hex string
        """
        # Multicall3 aggregate function signature:
        # function aggregate(tuple(address target, bytes call_data)[] calls)
        #         public returns (uint256 blockNumber, bytes[] returnData)

        # Function selector: first 4 bytes of keccak256("aggregate((address,bytes)[])")
        # = 0x82ad56cb
        function_selector = bytes.fromhex("82ad56cb")

        # Encode the calls array
        # Each call is a tuple: (address, bytes)
        encoded_calls = []
        for target, call_data in calls:
            # Ensure target is checksum address
            target_checksum = to_checksum_address(target)
            # Convert call_data to bytes if it's a hex string
            if isinstance(call_data, str):
                call_bytes = bytes.fromhex(call_data.replace("0x", ""))
            else:
                call_bytes = call_data
            encoded_calls.append((target_checksum, call_bytes))

        # Encode the array of tuples: (address,bytes)[]
        # Types: address = address, bytes = bytes
        params = encode(["(address,bytes)[]"], [encoded_calls])

        # Combine function selector + encoded parameters
        call_data = function_selector + params

        return "0x" + call_data.hex()

    def _decode_multicall_result(self, result: str, addresses: List[str]) -> Dict[str, int]:
        """Decode Multicall3 aggregate result.

        Args:
            result: Raw hex result from Multicall3
            addresses: List of addresses that were queried

        Returns:
            Dictionary mapping address to balance
        """
        # Multicall3 aggregate returns: (uint256 blockNumber, bytes[] returnData)
        if not result or result == "0x":
            return {}

        # Convert hex to bytes
        result_bytes = bytes.fromhex(result.replace("0x", ""))

        try:
            # Decode the outer tuple: (uint256, bytes[])
            # Skip the first 32 bytes (offset to the array data)
            # The blockNumber is in the first 32 bytes
            block_number_bytes = result_bytes[0:32]
            block_number = int.from_bytes(block_number_bytes, byteorder="big")

            # The offset to the bytes array is at bytes 32-64
            offset = int.from_bytes(result_bytes[32:64], byteorder="big")

            # The array length is at the offset position
            array_length_bytes = result_bytes[offset:offset + 32]
            array_length = int.from_bytes(array_length_bytes, byteorder="big")

            # Decode each bytes element in the array
            balances = {}
            for i in range(min(array_length, len(addresses))):
                # Each element starts with an offset (relative to array start)
                elem_offset_pos = offset + 32 + (i * 32)
                elem_offset = offset + int.from_bytes(
                    result_bytes[elem_offset_pos:elem_offset_pos + 32],
                    byteorder="big"
                )

                # The length of the bytes data is at elem_offset
                data_length = int.from_bytes(
                    result_bytes[elem_offset:elem_offset + 32],
                    byteorder="big"
                )

                # The actual data follows the length
                data_start = elem_offset + 32
                data_end = data_start + data_length
                return_data = result_bytes[data_start:data_end]

                # balanceOf returns uint256, decode it
                if len(return_data) == 32:
                    balance = int.from_bytes(return_data, byteorder="big")
                    checksum_addr = to_checksum_address(addresses[i])
                    balances[checksum_addr] = balance

            return balances

        except Exception as exc:
            LOGGER.error(f"Failed to decode Multicall result: {exc}")
            return {}

    async def batch_is_contract_calls(
        self,
        addresses: List[str],
        block_number: int = "latest",
    ) -> Dict[str, bool]:
        """Check if multiple addresses are contracts using eth_getCode.

        Args:
            addresses: List of addresses to check
            block_number: Block number (default: latest)

        Returns:
            Dictionary mapping address to is_contract boolean
        """
        if not addresses:
            return {}

        # Split into chunks
        chunks = [
            addresses[i : i + self.batch_size]
            for i in range(0, len(addresses), self.batch_size)
        ]

        # Get healthy providers
        providers = self.get_healthy_providers()
        if not providers:
            raise Web3Exception("No healthy RPC providers available")

        providers = providers[: self.max_parallel]

        # Create tasks
        tasks = []
        for i, chunk in enumerate(chunks):
            provider = providers[i % len(providers)]
            task = self._fetch_chunk_codes(provider, chunk, block_number)
            tasks.append(task)

        # Execute in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Merge results
        contract_status = {}
        for result in results:
            if isinstance(result, Exception):
                LOGGER.error(f"Chunk code check failed: {result}")
                continue
            contract_status.update(result)

        return contract_status

    async def _fetch_chunk_codes(
        self,
        provider: RpcProvider,
        addresses: List[str],
        block_number: int,
    ) -> Dict[str, bool]:
        """Fetch code for a chunk of addresses from a single provider."""
        results = {}

        for address in addresses:
            try:
                code = await provider.make_request(
                    "eth_getCode",
                    [address, block_number if block_number != "latest" else "latest"],
                )
                # Empty address has "0x", contracts have bytecode
                results[address] = code and code != "0x"
            except Exception as exc:
                LOGGER.error(f"Failed to get code for {address}: {exc}")
                results[address] = False

        return results


def create_rpc_pool(
    chain_id: int,
    rpc_urls: Optional[List[str]] = None,
    max_parallel: int = 5,
    batch_size: int = 50,  # Reduced for free RPC providers
) -> ParallelRpcPool:
    """Factory function to create an RPC pool.

    Args:
        chain_id: Chain ID for the pool
        rpc_urls: Optional list of RPC URLs (uses defaults if None)
        max_parallel: Maximum parallel requests
        batch_size: Addresses per batch

    Returns:
        Configured ParallelRpcPool instance
    """
    return ParallelRpcPool(
        chain_id=chain_id,
        rpc_urls=rpc_urls,
        max_parallel=max_parallel,
        batch_size=batch_size,
    )
