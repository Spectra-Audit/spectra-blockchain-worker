"""ERC-20 contract reader for tokenomics analysis."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from web3 import Web3
from web3.contract import Contract

LOGGER = logging.getLogger(__name__)

# Standard ERC-20 ABI
ERC20_ABI = [
    {
        "constant": True,
        "inputs": [],
        "name": "name",
        "outputs": [{"name": "", "type": "string"}],
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [],
        "name": "symbol",
        "outputs": [{"name": "", "type": "string"}],
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [],
        "name": "decimals",
        "outputs": [{"name": "", "type": "uint8"}],
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [],
        "name": "totalSupply",
        "outputs": [{"name": "", "type": "uint256"}],
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [{"name": "_owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "balance", "type": "uint256"}],
        "type": "function"
    },
]

# Extension functions to detect
EXTENSION_ABIS = {
    "maxSupply": [{
        "constant": True,
        "inputs": [],
        "name": "maxSupply",
        "outputs": [{"name": "", "type": "uint256"}],
        "type": "function"
    }],
    "owner": [{
        "constant": True,
        "inputs": [],
        "name": "owner",
        "outputs": [{"name": "", "type": "address"}],
        "type": "function"
    }],
    "mint": [{
        "inputs": [
            {"name": "to", "type": "address"},
            {"name": "amount", "type": "uint256"}
        ],
        "name": "mint",
        "outputs": [{"name": "", "type": "bool"}],
        "type": "function"
    }],
    "burn": [{
        "inputs": [{"name": "amount", "type": "uint256"}],
        "name": "burn",
        "outputs": [],
        "type": "function"
    }],
    "rebase": [{
        "inputs": [
            {"name": "epoch", "type": "uint256"},
            {"name": "supplyDelta", "type": "int256"}
        ],
        "name": "rebase",
        "outputs": [{"name": "", "type": "int256"}],
        "type": "function"
    }],
    "deflation": [{
        "constant": True,
        "inputs": [],
        "name": "deflationEnabled",
        "outputs": [{"name": "", "type": "bool"}],
        "type": "function"
    }],
    "autoBurnPercentage": [{
        "constant": True,
        "inputs": [],
        "name": "autoBurnPercentage",
        "outputs": [{"name": "", "type": "uint256"}],
        "type": "function"
    }],
    "getOwner": [{
        "constant": True,
        "inputs": [],
        "name": "getOwner",
        "outputs": [{"name": "", "type": "address"}],
        "type": "function"
    }],
    "withdraw": [{
        "inputs": [],
        "name": "withdraw",
        "outputs": [],
        "type": "function"
    }],
}


@dataclass
class ContractFeatures:
    """Features detected in token contract."""

    # Basic info
    name: str
    symbol: str
    decimals: int
    total_supply: int

    # Supply mechanics
    has_max_supply: bool
    max_supply: Optional[int]
    has_mint: bool
    has_burn: bool
    has_rebase: bool

    # Deflationary features
    deflation_enabled: Optional[bool]
    auto_burn_percentage: Optional[int]

    # Governance/ownership
    owner: Optional[str]
    has_withdraw: bool

    # Risk flags
    flags: List[str]


class ERC20Reader:
    """Reader for ERC-20 token contracts.

    Detects supply mechanics, governance features, and red flags.
    """

    def __init__(self, w3: Web3):
        """Initialize the ERC-20 reader.

        Args:
            w3: Web3 instance
        """
        self.w3 = w3

    async def read_contract(
        self,
        token_address: str,
    ) -> Optional[ContractFeatures]:
        """Read and analyze an ERC-20 contract.

        Args:
            token_address: Token contract address

        Returns:
            ContractFeatures with detected information
        """
        token_address = Web3.to_checksum_address(token_address)

        try:
            # Create contract with base ABI
            contract = self.w3.eth.contract(
                address=token_address,
                abi=ERC20_ABI
            )

            # Read basic info
            name = contract.functions.name().call()
            symbol = contract.functions.symbol().call()
            decimals = contract.functions.decimals().call()
            total_supply = contract.functions.totalSupply().call()

            # Check for extension functions
            features = await self._detect_extensions(
                token_address, contract, name, symbol, decimals, total_supply
            )

            return features

        except Exception as e:
            LOGGER.error(f"Failed to read contract {token_address}: {e}")
            return None

    async def _detect_extensions(
        self,
        token_address: str,
        base_contract: Contract,
        name: str,
        symbol: str,
        decimals: int,
        total_supply: int,
    ) -> ContractFeatures:
        """Detect contract extension functions and features.

        Args:
            token_address: Contract address
            base_contract: Base ERC-20 contract
            name: Token name
            symbol: Token symbol
            decimals: Token decimals
            total_supply: Total supply

        Returns:
            ContractFeatures with detected extensions
        """
        flags = []
        max_supply = None
        has_max_supply = False
        has_mint = False
        has_burn = False
        has_rebase = False
        deflation_enabled = None
        auto_burn_percentage = None
        owner = None
        has_withdraw = False

        # Try each extension
        for func_name, abi in EXTENSION_ABIS.items():
            try:
                contract = self.w3.eth.contract(
                    address=token_address,
                    abi=ERC20_ABI + [abi]
                )

                if func_name == "maxSupply":
                    max_supply = contract.functions.maxSupply().call()
                    has_max_supply = True
                    # Check if max supply is absurdly high or equals total supply
                    if max_supply >= 2**256 - 1:
                        flags.append("uncapped_max_supply")
                    elif max_supply == total_supply:
                        flags.append("max_supply_equals_total")

                elif func_name == "owner":
                    owner = contract.functions.owner().call()
                    flags.append("has_owner")

                elif func_name == "getOwner":
                    owner = contract.functions.getOwner().call()
                    flags.append("has_getOwner")

                elif func_name == "mint":
                    # Just check if function exists
                    has_mint = True
                    flags.append("has_mint_function")

                elif func_name == "burn":
                    has_burn = True

                elif func_name == "rebase":
                    # Critical red flag - rebasing token
                    has_rebase = True
                    flags.append("REBASE_TOKEN_CRITICAL")

                elif func_name == "deflation":
                    deflation_enabled = contract.functions.deflationEnabled().call()
                    if deflation_enabled:
                        flags.append("deflationary_mechanism")

                elif func_name == "autoBurnPercentage":
                    auto_burn_percentage = contract.functions.autoBurnPercentage().call()

                elif func_name == "withdraw":
                    has_withdraw = True
                    flags.append("has_withdraw_function")

            except Exception:
                # Function doesn't exist or failed
                pass

        # Analysis flags
        if has_mint and not has_max_supply:
            flags.append("unlimited_minting")

        if has_mint and owner:
            flags.append("controlled_minting")

        if has_burn and auto_burn_percentage:
            # Check if burn is tiny (<1%) while minting exists
            if auto_burn_percentage < 100 and has_mint:
                flags.append("tiny_burn_relative_to_mint")

        if not has_burn and not has_rebase and has_mint:
            flags.append("inflationary_no_burn")

        return ContractFeatures(
            name=name,
            symbol=symbol,
            decimals=decimals,
            total_supply=total_supply,
            has_max_supply=has_max_supply,
            max_supply=max_supply,
            has_mint=has_mint,
            has_burn=has_burn,
            has_rebase=has_rebase,
            deflation_enabled=deflation_enabled,
            auto_burn_percentage=auto_burn_percentage,
            owner=owner,
            has_withdraw=has_withdraw,
            flags=flags,
        )

    async def is_contract_address(self, address: str) -> bool:
        """Check if an address is a contract (not EOA).

        Args:
            address: Address to check

        Returns:
            True if address has code (contract), False if EOA
        """
        address = Web3.to_checksum_address(address)
        code = self.w3.eth.get_code(address)
        return len(code.hex()) > 2  # More than "0x"
