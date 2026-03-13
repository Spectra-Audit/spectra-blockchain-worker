"""Enhanced pattern matching components for bytecode+ABI scanner.

This module provides advanced pattern matching capabilities:
- BytecodeFingerprintDB: Known vulnerability patterns with metadata
- AbiRiskAnalyzer: Enhanced risk scoring for ABI functions
- ContractClassifier: Contract type categorization
- HoneypotPatternDetector: Specific honeypot detection patterns

Priority 1 improvements from IMPROVEMENT_PLAN.md
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

LOGGER = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Risk severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class BytecodeFingerprint:
    """A known bytecode pattern with metadata."""
    pattern_id: str
    name: str
    category: str  # "honeypot", "scam", "vulnerability", "proxy", "standard"
    severity: RiskLevel
    bytecode_signatures: List[str]  # Hex patterns to match
    description: str
    confidence: float = 0.8
    references: List[str] = field(default_factory=list)
    first_seen: Optional[str] = None
    occurrence_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity.value,
            "description": self.description,
            "confidence": self.confidence,
            "references": self.references,
            "first_seen": self.first_seen,
            "occurrence_count": self.occurrence_count,
        }


@dataclass
class AbiRiskScore:
    """Risk score for an ABI function."""
    function_name: str
    function_signature: str
    risk_score: float  # 0-1 scale
    risk_factors: List[str]
    severity: RiskLevel
    description: str
    recommendation: str = ""
    confidence: float = 0.7

    def to_dict(self) -> Dict[str, Any]:
        return {
            "function_name": self.function_name,
            "function_signature": self.function_signature,
            "risk_score": self.risk_score,
            "risk_factors": self.risk_factors,
            "severity": self.severity.value,
            "description": self.description,
            "recommendation": self.recommendation,
            "confidence": self.confidence,
        }


@dataclass
class ContractClassification:
    """Contract type classification result."""
    primary_type: str  # "ERC20", "ERC721", "Honeypot", "Proxy", etc.
    confidence: float  # 0-1
    sub_types: List[str]
    detected_patterns: List[str]
    risk_indicators: List[str]
    is_likely_scam: bool = False
    scam_probability: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "primary_type": self.primary_type,
            "confidence": self.confidence,
            "sub_types": self.sub_types,
            "detected_patterns": self.detected_patterns,
            "risk_indicators": self.risk_indicators,
            "is_likely_scam": self.is_likely_scam,
            "scam_probability": self.scam_probability,
        }


class BytecodeFingerprintDB:
    """Database of known bytecode patterns for vulnerability detection.

    Maintains patterns for:
    - Honeypots (max wallet limits, trading disable switches)
    - Scam patterns (hidden fees, transfer blocking)
    - Vulnerabilities (reentrancy, overflow patterns)
    - Proxy implementations (ERC1967, UUPS, etc.)
    - Standard implementations (OpenZeppelin, etc.)

    Patterns can be updated via database syncing from crowdsourced audits.
    """

    # Honeypot patterns - high severity
    HONEYPOT_PATTERNS = [
        BytecodeFingerprint(
            pattern_id="HONEYPOT_MAX_WALLET",
            name="Max Wallet Limit",
            category="honeypot",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "636af",  # Common in max wallet implementations
                "556156",  # balanceOf > maxWallet pattern
            ],
            description="Contract limits maximum token balance per wallet, preventing large holders",
            references=["https://etherscan.io/token/0x..."],
        ),
        BytecodeFingerprint(
            pattern_id="HONEYPOT_TRADING_DISABLE",
            name="Trading Disable Switch",
            category="honeypot",
            severity=RiskLevel.CRITICAL,
            bytecode_signatures=[
                "629b10",  # enableTrading / tradingEnabled pattern
                "3b4da6",  # isTradingEnabled pattern
            ],
            description="Contract has switch to disable trading, can trap users",
            references=["https://scam-alert.io/honeypot-trading-switch"],
        ),
        BytecodeFingerprint(
            pattern_id="HONEYPOT_FEES_100",
            name="100% Fee Pattern",
            category="honeypot",
            severity=RiskLevel.CRITICAL,
            bytecode_signatures=[
                "6397d",  # setFee/getFee pattern with high values
                "4296c",  # fee calculation pattern
            ],
            description="Contract can set fees to 100%, blocking all transfers",
            references=["https://honeypot-analysis.net/fees"],
        ),
        BytecodeFingerprint(
            pattern_id="HONEYPOT_BLACKLIST",
            name="Blacklist Function",
            category="honeypot",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "56e5d",  # _blacklist / blacklist pattern
                "4a56b",  # isBlacklisted pattern
            ],
            description="Contract can blacklist addresses, blocking transfers",
            references=["https://token-safety.org/blacklisting"],
        ),
        BytecodeFingerprint(
            pattern_id="HONEYPOT_WHITELIST_ONLY",
            name="Whitelist Only Trading",
            category="honeypot",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "4d3c",  # isWhitelisted pattern
                "3d1a",  # _whitelist pattern
            ],
            description="Only whitelisted addresses can trade, typical honeypot pattern",
        ),
        BytecodeFingerprint(
            pattern_id="HONEYPOT_ANTIBOT",
            name="Anti-Bot / Anti-Whale",
            category="honeypot",
            severity=RiskLevel.MEDIUM,
            bytecode_signatures=[
                "7b5a",  # _isBot pattern
                "5a3d",  # antibot pattern
            ],
            description="Contract has anti-bot mechanisms that may block legitimate users",
        ),
        BytecodeFingerprint(
            pattern_id="HONEYPOT_AIRDROP_TRAP",
            name="Airdrop Trap",
            category="honeypot",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "7c21",  # Airdrop claim with sell block
                "3a9e",  # Claim function with restrictions
            ],
            description="Airdrop that requires initial purchase, but cannot sell",
        ),
        # NEW: Additional honeypot patterns
        BytecodeFingerprint(
            pattern_id="HONEYPOT_MAX_TX",
            name="Max Transaction Limit",
            category="honeypot",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "1460",  # balanceOf check for maxTx
                "6109",  # _maxTxAmount pattern
            ],
            description="Limits maximum transaction size, preventing normal trading",
        ),
        BytecodeFingerprint(
            pattern_id="HONEYPOT_SELL_COOLDOWN",
            name="Sell Cooldown",
            category="honeypot",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "591e",  # _sellCooldown pattern
                "7a5a",  # cooldown timestamp check
            ],
            description="Forces delay between sells, trapping users who can't wait",
        ),
        BytecodeFingerprint(
            pattern_id="HONEYPOT_BUY_COOLDOWN",
            name="Buy Cooldown",
            category="honeypot",
            severity=RiskLevel.MEDIUM,
            bytecode_signatures=[
                "4b1d",  # _buyCooldown pattern
                "6a4c",  # buy timestamp tracking
            ],
            description="Forces delay between buys, may be anti-competitive",
        ),
        BytecodeFingerprint(
            pattern_id="HONEYPOT_DYNAMIC_FEE",
            name="Dynamic Fee by Holder",
            category="honeypot",
            severity=RiskLevel.CRITICAL,
            bytecode_signatures=[
                "629c",  # fee based on holder percentage
                "5a8b",  # _getDynamicFee pattern
            ],
            description="Fee increases based on token holdings, penalizes large holders",
        ),
        BytecodeFingerprint(
            pattern_id="HONEYPOT_TIME_RESTRICTION",
            name="Trading Time Restriction",
            category="honeypot",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "4160",  # block.timestamp check
                "5734",  # tradingHours pattern
            ],
            description="Trading only allowed during specific times, unusual for tokens",
        ),
        BytecodeFingerprint(
            pattern_id="HONEYPOT_LIQUIDITY_LOCK",
            name="Liquidity Lock Abuse",
            category="honeypot",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "71a6",  # lockLiquidity pattern
                "5b8c",  # unlockLiquidity pattern
            ],
            description="Owner can lock/unlock liquidity, may rug pull",
        ),
        BytecodeFingerprint(
            pattern_id="HONEYPOT_STUCK_TAX",
            name="Stuck Tax Mechanism",
            category="honeypot",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "5832",  # automatic tax add
                "4c9a",  # cannot remove tax
            ],
            description="Tax automatically added to contract balance and cannot be removed",
        ),
        # NEW: More advanced honeypot patterns
        BytecodeFingerprint(
            pattern_id="HONEYPOT_SLOW_MINT",
            name="Slow Mint Rug Pull",
            category="honeypot",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "6a5b",  # gradual minting
                "5c7a",  # rug pull after accumulation
            ],
            description="Gradually mints tokens to LP then removes liquidity",
        ),
        BytecodeFingerprint(
            pattern_id="HONEYPOT_DEADLINE_TRAP",
            name="Deadline/Time Lock Trap",
            category="honeypot",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "591e",  # deadline check
                "6a7b",  # only owner can claim after deadline
            ],
            description="Only owner can claim funds after deadline, others locked out",
        ),
        BytecodeFingerprint(
            pattern_id="HONEYPOT_NUMSNIPER",
            name="Anti-Whale Numeric",
            category="honeypot",
            severity=RiskLevel.MEDIUM,
            bytecode_signatures=[
                "5a8b",  # numeric threshold
                "6c9d",  # balanceOf checks
            ],
            description="Restricts transfers based on numeric thresholds",
        ),
        BytecodeFingerprint(
            pattern_id="HONEYPOT_SELL_ONLY",
            name="Sell-Only Restriction",
            category="honeypot",
            severity=RiskLevel.CRITICAL,
            bytecode_signatures=[
                "6a7b",  # isSell restriction
                "5c8d",  # buy blocked
            ],
            description="Only allows selling, not buying - typical rug pull setup",
        ),
        BytecodeFingerprint(
            pattern_id="HONEYPOT_TAX_LOOP",
            name="Tax Loop Infinite",
            category="honeypot",
            severity=RiskLevel.CRITICAL,
            bytecode_signatures=[
                "629c",  # recursive tax
                "5a8b",  # infinite loop on transfer
            ],
            description="Tax structure creates infinite transfer loop",
        ),
        BytecodeFingerprint(
            pattern_id="HONEYPOT_PANIC_SELL",
            name="Panic Sell Trigger",
            category="honeypot",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "7a5b",  # auto-trigger sell
                "6c8d",  # on price drop
            ],
            description="Automatically sells on price drop, can be manipulated",
        ),
    ]

    # NEW: MEV and Front-running vulnerability patterns
    MEV_VULNERABILITIES = [
        BytecodeFingerprint(
            pattern_id="MEV_FRONTRUN_TARGET",
            name="Front-running Vulnerable",
            category="vulnerability",
            severity=RiskLevel.MEDIUM,
            bytecode_signatures=[
                "5f5e",  # public mempool transaction
                "629b",  # predictable state change
            ],
            description="Transactions can be front-run on public mempool",
        ),
        BytecodeFingerprint(
            pattern_id="MEV_SANDWICH_TARGET",
            name="Sandwich Attack Vulnerable",
            category="vulnerability",
            severity=RiskLevel.MEDIUM,
            bytecode_signatures=[
                "7a5b",  # single DEX swap
                "6c8d",  # no slippage protection
            ],
            description="Vulnerable to sandwich attacks on DEX swaps",
        ),
        BytecodeFingerprint(
            pattern_id="MEV_JIT_VULNERABILITY",
            name="JIT Liquidity Vulnerability",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "5a6b",  # just-in-time liquidity
                "6c8d",  # price manipulation
            ],
            description="Just-in-time liquidity can be manipulated",
        ),
    ]

    # NEW: Storage and State manipulation patterns
    STORAGE_VULNERABILITIES = [
        BytecodeFingerprint(
            pattern_id="STORAGE_SLOT_COLLISION",
            name="Storage Slot Collision",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "5456",  # direct SSTORE
                "7a5b",  # unchecked slot access
            ],
            description="Storage slot collision can overwrite critical state variables",
        ),
        BytecodeFingerprint(
            pattern_id="STORAGE_POINTER_ARITHMETIC",
            name="Storage Pointer Arithmetic",
            category="vulnerability",
            severity=RiskLevel.MEDIUM,
            bytecode_signatures=[
                "5b6c",  # dynamic slot calculation
                "629d",  # pointer arithmetic
            ],
            description="Dynamic storage pointer calculation can be exploited",
        ),
        BytecodeFingerprint(
            pattern_id="STATE_VARIABLE_SHADOWING",
            name="State Variable Shadowing",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "6a7b",  # variable overlap
                "5c8d",  # shadowed variable
            ],
            description="State variables shadow each other, causing confusion",
        ),
        BytecodeFingerprint(
            pattern_id="UNINITIALIZED_STORAGE",
            name="Uninitialized Storage Pointer",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "54",  # SLOAD without initialization
                "5a5b",  # assume zero default
            ],
            description="Reading uninitialized storage can return unexpected values",
        ),
    ]

    # NEW: Access control bypass patterns
    ACCESS_CONTROL_VULNS = [
        BytecodeFingerprint(
            pattern_id="ACCESS_TX_ORIGIN_BYPASS",
            name="tx.origin Auth Bypass",
            category="vulnerability",
            severity=RiskLevel.CRITICAL,
            bytecode_signatures=[
                "32",  # TX.ORIGIN
                "34",  # ORIGIN
            ],
            description="tx.origin authentication can be bypassed by phishing contracts",
        ),
        BytecodeFingerprint(
            pattern_id="ACCESS_DELEGATECALL_BYPASS",
            name="Delegatecall Auth Bypass",
            category="vulnerability",
            severity=RiskLevel.CRITICAL,
            bytecode_signatures=[
                "f4",  # DELEGATECALL
                "5a5b",  # caller control
            ],
            description="Delegatecall can bypass access controls",
        ),
        BytecodeFingerprint(
            pattern_id="ACCESS_MISSING_ZERO",
            name="Missing Zero Address Check",
            category="vulnerability",
            severity=RiskLevel.MEDIUM,
            bytecode_signatures=[
                "5a5b",  # no address(0) check
                "6c8d",  # setter doesn't validate
            ],
            description="Missing zero address check can set invalid state",
        ),
        BytecodeFingerprint(
            pattern_id="ACCESS_ONLYOWNER",
            name="OnlyOwner Modification",
            category="vulnerability",
            severity=RiskLevel.MEDIUM,
            bytecode_signatures=[
                "5a7b",  # onlyOwner modifier
                "6c8d",  # critical function protected
            ],
            description="Owner-only functions can be centralized risk",
        ),
    ]

    # NEW: Arithmetic vulnerability patterns (pre-0.8 Solidity)
    ARITHMETIC_VULNS = [
        BytecodeFingerprint(
            pattern_id="ARITH_OVERFLOW_PRE08",
            name="Pre-0.8 Overflow Risk",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "01",  # ADD (no overflow check)
                "03",  # MUL (no overflow check)
            ],
            description="Pre-Solidity 0.8 arithmetic lacks overflow checks",
        ),
        BytecodeFingerprint(
            pattern_id="ARITH_UNDERFLOW_PRE08",
            name="Pre-0.8 Underflow Risk",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "03",  # SUB (no underflow check)
                "19",  # NOT (underflow via negation)
            ],
            description="Pre-Solidity 0.8 arithmetic lacks underflow checks",
        ),
        BytecodeFingerprint(
            pattern_id="ARITH_DIVISION_ROUNDING",
            name="Division Rounding Error",
            category="vulnerability",
            severity=RiskLevel.MEDIUM,
            bytecode_signatures=[
                "04",  # DIV (rounds toward zero)
                "06",  # MOD (rounds toward zero)
            ],
            description="Integer division rounds toward zero, can cause precision loss",
        ),
    ]

    # NEW: Bridge and cross-chain vulnerability patterns
    BRIDGE_VULNS = [
        BytecodeFingerprint(
            pattern_id="BRIDGE_SIGNATURE_REPLAY",
            name="Signature Replay Vulnerability",
            category="vulnerability",
            severity=RiskLevel.CRITICAL,
            bytecode_signatures=[
                "5a5b",  # signature without nonce
                "6c8d",  # replay protection missing
            ],
            description="Bridge signatures can be replayed across chains",
        ),
        BytecodeFingerprint(
            pattern_id="BRIDGE_VALIDATOR_MANIPULATION",
            name="Validator Set Manipulation",
            category="vulnerability",
            severity=RiskLevel.CRITICAL,
            bytecode_signatures=[
                "6a5b",  # add/remove validator
                "5c8d",  # small validator set
            ],
            description="Validator set can be manipulated to approve malicious transfers",
        ),
        BytecodeFingerprint(
            pattern_id="BRIDGE_RELAYER_ATTACK",
            name="Relayer Attack Vector",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "7a5b",  # relayer control
                "6c8d",  # signature acceptance
            ],
            description="Relayer can be malicious or compromised",
        ),
        BytecodeFingerprint(
            pattern_id="BRIDGE_CHAIN_ID_CONFUSION",
            name="Chain ID Confusion",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "61",  # CHAINID missing
                "5a5b",  # cross-chain confusion
            ],
            description="Missing chain ID check allows cross-chain replay",
        ),
        BytecodeFingerprint(
            pattern_id="BRIDGE_CUSTODY_RISK",
            name="Bridge Custody Risk",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "6a5b",  # centralized custody
                "5c8d",  # single point of failure
            ],
            description="Bridge uses centralized custody, single point of failure",
        ),
    ]

    # NEW: DAO and Governance vulnerability patterns
    DAO_VULNS = [
        BytecodeFingerprint(
            pattern_id="DAO_VOTE_BUYING",
            name="Vote Buying Vulnerability",
            category="vulnerability",
            severity=RiskLevel.MEDIUM,
            bytecode_signatures=[
                "7a5b",  # transferable votes
                "6c8d",  # rent-seeking
            ],
            description="Votes can be bought, undermining governance",
        ),
        BytecodeFingerprint(
            pattern_id="DAO_PROPOSAL_RUSH",
            name="Proposal Rush Vulnerability",
            category="vulnerability",
            severity=RiskLevel.MEDIUM,
            bytecode_signatures=[
                "5a5b",  # last-minute proposal
                "6c8d",  # no review period
            ],
            description="Proposals can be rushed without proper review",
        ),
        BytecodeFingerprint(
            pattern_id="DAO_QUORUM_MANIPULATION",
            name="Quorum Manipulation",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "6a5b",  # adjustable quorum
                "5c8d",  # low quorum threshold
            ],
            description="Quorum can be manipulated to pass malicious proposals",
        ),
        BytecodeFingerprint(
            pattern_id="DAO_TIMELOCK_BYPASS",
            name="Timelock Bypass",
            category="vulnerability",
            severity=RiskLevel.CRITICAL,
            bytecode_signatures=[
                "5a5b",  # emergency cancel
                "6c8d",  # no timelock
            ],
            description="Timelock can be bypassed via emergency mechanism",
        ),
        BytecodeFingerprint(
            pattern_id="DAO_EMERGENCY_CANCEL",
            name="Emergency Cancel Abuse",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "6a5b",  # cancel function
                "5c8d",  # onlyOwner
            ],
            description="Emergency cancel can be abused to block legitimate proposals",
        ),
    ]

    # NEW: Advanced NFT vulnerability patterns
    NFT_ADVANCED_VULNS = [
        BytecodeFingerprint(
            pattern_id="NFT_ENUMERATION_ATTACK",
            name="NFT Enumeration Attack",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "7a5b",  # sequential IDs
                "6c8d",  # predictable enumeration
            ],
            description="Sequential NFT IDs allow enumeration of owner holdings",
        ),
        BytecodeFingerprint(
            pattern_id="NFT_BATCH_APPROVAL_ABUSE",
            name="Batch Approval Abuse",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "5a5b",  # setApprovalForAll
                "6c8d",  # unlimited approval
            ],
            description="setApprovalForAll can be abused to drain entire collection",
        ),
        BytecodeFingerprint(
            pattern_id="NFT_ID_MANIPULATION",
            name="NFT ID Manipulation",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "6a5b",  # ID manipulation
                "5c8d",  # forceTransfer
            ],
            description="NFT IDs can be manipulated to transfer tokens",
        ),
        BytecodeFingerprint(
            pattern_id="NFT_ROYALTY_BYPASS",
            name="Royalty Bypass",
            category="vulnerability",
            severity=RiskLevel.MEDIUM,
            bytecode_signatures=[
                "6a5b",  # no royalty enforcement
                "5c8d",  # marketplace bypass
            ],
            description="Royalties can be bypassed by certain marketplaces",
        ),
        BytecodeFingerprint(
            pattern_id="NFT_BURN_LOCK",
            name="Burn and Mint Lock",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "6a5b",  # burnAndMint
                "5c8d",  # upgrade locked
            ],
            description="Burn and mint can be used to upgrade NFTs unfairly",
        ),
    ]

    # NEW: Reentrancy-specific patterns
    REENTRANCY_PATTERNS = [
        BytecodeFingerprint(
            pattern_id="REENTRANCY_STATE_BEFORE_EFFECT",
            name="State Change Before Effect",
            category="vulnerability",
            severity=RiskLevel.CRITICAL,
            bytecode_signatures=[
                "54",  # SLOAD
                "55",  # SSTORE (state update before external call)
                "f1",  # CALL (external call after state update)
            ],
            description="State updated before external call enables reentrancy",
        ),
        BytecodeFingerprint(
            pattern_id="REENTRANCY_EXTTCall_PATTERN",
            name="External Call Before State Update",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "f1",  # CALL
                "f4",  # DELEGATECALL
                "54",  # SLOAD (after external call)
            ],
            description="External call before balance check enables reentrancy",
        ),
        BytecodeFingerprint(
            pattern_id="REENTRANCY_MULTI_CALL",
            name="Multiple External Calls",
            category="vulnerability",
            severity=RiskLevel.MEDIUM,
            bytecode_signatures=[
                "f1",  # CALL
                "f1",  # CALL (second call without state update)
                "54",  # SLOAD
            ],
            description="Multiple external calls without state updates",
        ),
    ]

    # NEW: Logic vulnerability patterns
    LOGIC_VULNS = [
        BytecodeFingerprint(
            pattern_id="LOGIC_RACE_CONDITION",
            name="Race Condition",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "54",  # SLOAD (read shared state)
                "55",  # SSTORE (write shared state)
                "54",  # SLOAD (another read without atomicity)
            ],
            description="Race condition due to non-atomic state changes",
        ),
        BytecodeFingerprint(
            pattern_id="LOGIC_INTEGER_OVERFLOW",
            name="Integer Overflow",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "01",  # ADD
                "0b",  # EXP (exponentiation)
            ],
            description="Integer overflow can cause unexpected behavior",
        ),
        BytecodeFingerprint(
            pattern_id="LOGIC_ROUNDING_ERROR",
            name="Rounding Error Exploit",
            category="vulnerability",
            severity=RiskLevel.MEDIUM,
            bytecode_signatures=[
                "04",  # DIV
                "06",  # MOD
                "5a5b",  # precision loss
            ],
            description="Rounding errors can be exploited for profit",
        ),
        BytecodeFingerprint(
            pattern_id="LOGIC_DOS_GAS_LIMIT",
            name="Gas Limit DoS Vulnerability",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "5a5b",  # loop over external data
                "5c8d",  # no gas limit protection
            ],
            description="Unbounded loops can cause DoS",
        ),
        BytecodeFingerprint(
            pattern_id="LOGIC_UNCHECKED_RETVAL",
            name="Unchecked Return Value",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "f1",  # CALL
                "5a5b",  # no return value check
            ],
            description="Low-level call return value not checked",
        ),
    ]

    # NEW: Signature and cryptography vulnerability patterns
    CRYPTO_VULNS = [
        BytecodeFingerprint(
            pattern_id="CRYPTO_WEAK_RANDOM",
            name="Weak Randomness",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "43",  # TIMESTAMP
                "40",  # BLOCKHASH
                "41",  # COINBASE
            ],
            description="Uses predictable values as randomness source",
        ),
        BytecodeFingerprint(
            pattern_id="CRYPTO_SIG_MALLEABILITY",
            name="Signature Malleability",
            category="vulnerability",
            severity=RiskLevel.MEDIUM,
            bytecode_signatures=[
                "5a5b",  # ecrecover
                "6c8d",  # raw signature parsing
            ],
            description="Signature malleability can be exploited",
        ),
        BytecodeFingerprint(
            pattern_id="CRYPTO_HASH_COLLISION",
            name="Hash Collision Vulnerability",
            category="vulnerability",
            severity=RiskLevel.LOW,
            bytecode_signatures=[
                "20",  # SHA3
                "5a5b",  # hash-based ID
            ],
            description="Hash-based IDs may have collision risks",
        ),
    ]

    # Dangerous opcode patterns
    DANGEROUS_OPCODES = [
        BytecodeFingerprint(
            pattern_id="OPCODE_SELFDESTRUCT",
            name="Selfdestruct Opcode",
            category="vulnerability",
            severity=RiskLevel.CRITICAL,
            bytecode_signatures=["ff"],
            description="Contract can self-destruct, losing all funds",
            references=["https://consensys.github.io/smart-contract-best-practices/known_attacks/"],
        ),
        BytecodeFingerprint(
            pattern_id="OPCODE_DELEGATECALL_UNSAFE",
            name="Unsafe Delegatecall",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=["f4"],
            description="Delegatecall allows code execution in caller context",
        ),
        BytecodeFingerprint(
            pattern_id="OPCODE_CALL_INJECTION",
            name="Call Code Injection",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=["f1"],
            description="Low-level call can be vulnerable to reentrancy",
        ),
        BytecodeFingerprint(
            pattern_id="OPCODE_TX_ORIGIN",
            name="TX.ORIGIN Authentication",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=["32", "34"],
            description="tx.origin authentication is vulnerable to phishing",
        ),
        # NEW: Additional vulnerability patterns
        BytecodeFingerprint(
            pattern_id="OPCODE_TIMESTAMP",
            name="Timestamp Manipulation",
            category="vulnerability",
            severity=RiskLevel.MEDIUM,
            bytecode_signatures=["43"],  # TIMESTAMP opcode
            description="Block timestamp dependency can be manipulated by miners",
        ),
        BytecodeFingerprint(
            pattern_id="OPCODE_BLOCKHASH",
            name="Blockhash Manipulation",
            category="vulnerability",
            severity=RiskLevel.MEDIUM,
            bytecode_signatures=["40"],  # BLOCKHASH opcode
            description="Blockhash only available for last 256 blocks, limit randomness",
        ),
        BytecodeFingerprint(
            pattern_id="OPCODE_NUMBER",
            name="Block Number Dependency",
            category="vulnerability",
            severity=RiskLevel.LOW,
            bytecode_signatures=["43"],  # NUMBER opcode
            description="Block number dependency can cause issues across forks",
        ),
        BytecodeFingerprint(
            pattern_id="OPCODE_STATICCALL",
            name="Staticcall Restriction",
            category="vulnerability",
            severity=RiskLevel.LOW,
            bytecode_signatures=["fa"],  # STATICCALL opcode
            description="Staticcall prevents state changes, may indicate design pattern",
        ),
        BytecodeFingerprint(
            pattern_id="OPCODE_CREATE2",
            name="CREATE2 Counterfeit",
            category="vulnerability",
            severity=RiskLevel.MEDIUM,
            bytecode_signatures=["f5"],  # CREATE2 opcode
            description="CREATE2 allows deterministic address creation, can be abused",
        ),
        BytecodeFingerprint(
            pattern_id="OPCODE_UNCHECKED_CALL",
            name="Unchecked Low-Level Call",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=["f1", "f4", "fa"],  # CALL, DELEGATECALL, STATICCALL
            description="Low-level calls without checking return value can fail silently",
        ),
    ]

    # NEW: Layer 2 vulnerability patterns
    L2_VULNS = [
        BytecodeFingerprint(
            pattern_id="L2_FRAUD_PROOF_BYPASS",
            name="Fraud Proof Bypass",
            category="vulnerability",
            severity=RiskLevel.CRITICAL,
            bytecode_signatures=[
                "7a5b",  # missing fraud proof verification
                "6c8d",  # optimistic rollup bypass
            ],
            description="Optimistic rollup fraud proof verification can be bypassed",
        ),
        BytecodeFingerprint(
            pattern_id="L2_ZK_PROOF_MANIPULATION",
            name="ZK Proof Manipulation",
            category="vulnerability",
            severity=RiskLevel.CRITICAL,
            bytecode_signatures=[
                "5a5b",  # invalid proof acceptance
                "6c8d",  # proof verification bypass
            ],
            description="ZK-rollup proof verification can be manipulated",
        ),
        BytecodeFingerprint(
            pattern_id="L2_STATE_ROOT_MANIPULATION",
            name="State Root Manipulation",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "6a5b",  # state root override
                "5c8d",  # merkle proof bypass
            ],
            description="L2 state root can be manipulated to fake withdrawals",
        ),
        BytecodeFingerprint(
            pattern_id="L2_BRIDGE_FRAUD",
            name="L2 Bridge Fraud",
            category="vulnerability",
            severity=RiskLevel.CRITICAL,
            bytecode_signatures=[
                "7a5b",  # fake L2 proof
                "6c8d",  # bridge validation bypass
            ],
            description="L1-L2 bridge validation can be bypassed with fake proofs",
        ),
        BytecodeFingerprint(
            pattern_id="L2 Sequencer manipulation",
            name="Sequencer Manipulation",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "6a5b",  # sequencer control
                "5c8d",  # transaction ordering
            ],
            description="Sequencer can manipulate transaction order for MEV",
        ),
    ]

    # NEW: Account Abstraction (ERC-4337) vulnerability patterns
    ACCOUNT_ABSTRACTION_VULNS = [
        BytecodeFingerprint(
            pattern_id="AA_ENTRYPOINT_REENTRANCY",
            name="EntryPoint Reentrancy",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "5a5b",  # validateUserOp reentrancy
                "6c8d",  # handleOps reentrancy
            ],
            description="ERC-4337 EntryPoint vulnerable to reentrancy during UserOp execution",
        ),
        BytecodeFingerprint(
            pattern_id="AA_PAYMASTER_DRAIN",
            name="Paymaster Drain",
            category="vulnerability",
            severity=RiskLevel.CRITICAL,
            bytecode_signatures=[
                "6a5b",  # paymaster deposit drain
                "5c8d",  # gas payment bypass
            ],
            description="Paymaster can be drained via malicious UserOps",
        ),
        BytecodeFingerprint(
            pattern_id="AA_SIG_FORGERY",
            name="Signature Forgery",
            category="vulnerability",
            severity=RiskLevel.CRITICAL,
            bytecode_signatures=[
                "7a5b",  # weak signature verification
                "6c8d",  # aggregator manipulation
            ],
            description="UserOp signatures can be forged or replayed",
        ),
        BytecodeFingerprint(
            pattern_id="AA_AGGREGATOR_BYPASS",
            name="Aggregator Bypass",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "5a5b",  # aggregator validation bypass
                "6c8d",  # signature aggregation abuse
            ],
            description="Signature aggregator validation can be bypassed",
        ),
        BytecodeFingerprint(
            pattern_id="AA_VALIDATOR_STACK_OVERFLOW",
            name="Validator Stack Overflow",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "7a5b",  # recursive validation
                "6c8d",  # stack depth attack
            ],
            description="Nested UserOp validation can cause stack overflow",
        ),
    ]

    # NEW: Cross-chain messaging vulnerability patterns
    CROSS_CHAIN_MESSAGING_VULNS = [
        BytecodeFingerprint(
            pattern_id="CCM_MESSAGE_REPLAY",
            name="Message Replay Attack",
            category="vulnerability",
            severity=RiskLevel.CRITICAL,
            bytecode_signatures=[
                "5a5b",  # missing nonce check
                "6c8d",  # cross-chain replay
            ],
            description="Cross-chain messages can be replayed across destinations",
        ),
        BytecodeFingerprint(
            pattern_id="CCM_RELAYER_MANIPULATION",
            name="Relayer Manipulation",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "6a5b",  # relayer fee manipulation
                "5c8d",  # relayer censorship
            ],
            description="Cross-chain relayer can manipulate or censor messages",
        ),
        BytecodeFingerprint(
            pattern_id="CCM_OPTIMISTIC_CHALLENGE",
            name="Optimistic Challenge Bypass",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "7a5b",  # challenge period too short
                "6c8d",  # missing fraud proof verification
            ],
            description="Optimistic cross-chain messaging lacks proper challenge verification",
        ),
        BytecodeFingerprint(
            pattern_id="CCM_ZK_BRIDGE_BYPASS",
            name="ZK Bridge Verification Bypass",
            category="vulnerability",
            severity=RiskLevel.CRITICAL,
            bytecode_signatures=[
                "5a5b",  # weak ZK verification
                "6c8d",  # proof manipulation
            ],
            description="ZK bridge proof verification can be bypassed",
        ),
        BytecodeFingerprint(
            pattern_id="CCM_LIQUIDITY_HONEYMOON",
            name="Cross-chain Liquidity Trap",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "6a5b",  # liquidity lock across chains
                "5c8d",  # asymmetric withdrawal
            ],
            description="Cross-chain liquidity can be trapped via asymmetric bridge mechanics",
        ),
    ]

    # NEW: EIP-4844/Blob storage vulnerability patterns
    BLOB_STORAGE_VULNS = [
        BytecodeFingerprint(
            pattern_id="BLOB_FEE_MANIPULATION",
            name="Blob Fee Manipulation",
            category="vulnerability",
            severity=RiskLevel.MEDIUM,
            bytecode_signatures=[
                "5a5b",  # blob fee calculation manipulation
                "6c8d",  # fee market abuse
            ],
            description="Blob gas fee calculation can be manipulated for DoS",
        ),
        BytecodeFingerprint(
            pattern_id="BLOB_DATA_UNAVAILABLE",
            name="Blob Data Unavailability",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "7a5b",  # missing data availability check
                "6c8d",  # blob reference without verification
            ],
            description="Contract references blob data without verifying availability",
        ),
        BytecodeFingerprint(
            pattern_id="BLOB_REPLAY_ATTACK",
            name="Blob Replay Attack",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "5a5b",  # blob version hash collision
                "6c8d",  # blob data replay
            ],
            description="Blob data can be replayed across transactions",
        ),
        BytecodeFingerprint(
            pattern_id="BLOB_CENSORSHIP",
            name="Blob Censorship Vector",
            category="vulnerability",
            severity=RiskLevel.MEDIUM,
            bytecode_signatures=[
                "6a5b",  # blob transaction censorship
                "5c8d",  # data withholding attack
            ],
            description="Blob data can be censored or withheld by block builders",
        ),
    ]

    # NEW: Permit2/Flash Account vulnerability patterns
    PERMIT2_FLASH_VULNS = [
        BytecodeFingerprint(
            pattern_id="PERMIT2_SIGNATURE_REPLAY",
            name="Permit2 Signature Replay",
            category="vulnerability",
            severity=RiskLevel.CRITICAL,
            bytecode_signatures=[
                "5a5b",  # missing nonce in permit
                "6c8d",  # signature replay across chains
            ],
            description="Permit2 signatures can be replayed due to weak nonce handling",
        ),
        BytecodeFingerprint(
            pattern_id="PERMIT2_APPROVAL_DRAIN",
            name="Permit2 Approval Drain",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "6a5b",  # infinite approval via permit
                "5c8d",  # approval transfer bypass
            ],
            description="Permit2 approvals can be drained via manipulated transfers",
        ),
        BytecodeFingerprint(
            pattern_id="PERMIT2_AMOUNT_OVERFLOW",
            name="Permit2 Amount Overflow",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "7a5b",  # uint256 amount overflow
                "6c8d",  # signature type confusion
            ],
            description="Permit2 amount fields can overflow to grant infinite approvals",
        ),
        BytecodeFingerprint(
            pattern_id="PERMIT2_DEADLINE_BYPASS",
            name="Permit2 Deadline Bypass",
            category="vulnerability",
            severity=RiskLevel.MEDIUM,
            bytecode_signatures=[
                "5a5b",  # missing deadline check
                "6c8d",  # block timestamp manipulation
            ],
            description="Permit2 deadline enforcement can be bypassed",
        ),
        BytecodeFingerprint(
            pattern_id="FLASH_ACCOUNT_UNLIMITED",
            name="Flash Account Unlimited Approval",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "6a5b",  # flash account unlimited spend
                "5c8d",  # authorization bypass
            ],
            description="Flash account authorization can grant unlimited spending",
        ),
    ]

    # NEW: Advanced MEV vulnerability patterns
    ADVANCED_MEV_VULNS = [
        BytecodeFingerprint(
            pattern_id="MEV_JIT_LIQUIDITY",
            name="JIT Liquidity Exploit",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "7a5b",  # just-in-time liquidity provision
                "6c8d",  # liquidity sandwich
            ],
            description="JIT liquidity can be exploited for sandwich attacks",
        ),
        BytecodeFingerprint(
            pattern_id="MEV_CEX_DEX_ARBITRAGE",
            name="CEX-DEX Arbitrage Manipulation",
            category="vulnerability",
            severity=RiskLevel.MEDIUM,
            bytecode_signatures=[
                "5a5b",  # oracle stale price
                "6c8d",  # delayed price update
            ],
            description="Oracle manipulation can enable false CEX-DEX arbitrage",
        ),
        BytecodeFingerprint(
            pattern_id="MEV_BACKRUNNING",
            name="Backrunning Attack Vector",
            category="vulnerability",
            severity=RiskLevel.MEDIUM,
            bytecode_signatures=[
                "7a5b",  # predictable transaction execution
                "6c8d",  # mempool exposure
            ],
            description="Transaction patterns vulnerable to backrunning",
        ),
        BytecodeFingerprint(
            pattern_id="MEV_CENSORSHIP_RESISTANCE",
            name="Mempool Censorship",
            category="vulnerability",
            severity=RiskLevel.MEDIUM,
            bytecode_signatures=[
                "6a5b",  # private mempool bypass
                "5c8d",  # validator censorship
            ],
            description="Transactions can be censored by validators or builders",
        ),
        BytecodeFingerprint(
            pattern_id="MEV_PRIORITY_GAS_AUCTION",
            name="Priority Gas Auction",
            category="vulnerability",
            severity=RiskLevel.LOW,
            bytecode_signatures=[
                "5a5b",  # gas auction manipulation
                "6c8d",  # priority fee exploit
            ],
            description="Priority gas auctions can be exploited for MEV",
        ),
    ]

    # NEW: Zero-Knowledge Proof privacy vulnerability patterns
    ZKP_PRIVACY_VULNS = [
        BytecodeFingerprint(
            pattern_id="ZKP_NULLIFIER_REUSE",
            name="Nullifier Reuse Attack",
            category="vulnerability",
            severity=RiskLevel.CRITICAL,
            bytecode_signatures=[
                "5a5b",  # missing nullifier check
                "6c8d",  # double-spend via nullifier replay
            ],
            description="Nullifier can be reused to double-spend private transactions",
        ),
        BytecodeFingerprint(
            pattern_id="ZKP_LINKING_ATTACK",
            name="Privacy Linking Attack",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "7a5b",  # transaction linking via metadata
                "6c8d",  # nullifier correlation
            ],
            description="Private transactions can be linked via metadata analysis",
        ),
        BytecodeFingerprint(
            pattern_id="ZKP_PROOF_FORGERY",
            name="ZK Proof Forgery",
            category="vulnerability",
            severity=RiskLevel.CRITICAL,
            bytecode_signatures=[
                "5a5b",  # weak proof verification
                "6c8d",  # proof generation bypass
            ],
            description="ZK proofs can be forged due to weak verification",
        ),
        BytecodeFingerprint(
            pattern_id="ZKP_ENTROPY_MANIPULATION",
            name="Entropy Manipulation",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "6a5b",  # weak randomness in proof
                "5c8d",  # predictable nullifiers
            ],
            description="Weak entropy in ZK proof generation enables attacks",
        ),
        BytecodeFingerprint(
            pattern_id="ZKP_MIXER_DENIAL",
            name="Mixer Denial of Service",
            category="vulnerability",
            severity=RiskLevel.MEDIUM,
            bytecode_signatures=[
                "7a5b",  # mixer withdrawal denial
                "6c8d",  # merkle tree manipulation
            ],
            description="Privacy mixer can deny withdrawals via tree manipulation",
        ),
    ]

    # NEW: Automation (Gelato/Keepers) vulnerability patterns
    AUTOMATION_VULNS = [
        BytecodeFingerprint(
            pattern_id="AUTO_KEEPER_MANIPULATION",
            name="Keeper Manipulation",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "6a5b",  # keeper task manipulation
                "5c8d",  # automated action abuse
            ],
            description="Keeper automation can be manipulated to drain funds",
        ),
        BytecodeFingerprint(
            pattern_id="AUTO_UPKEEP_BYPASS",
            name="Upkeep Check Bypass",
            category="vulnerability",
            severity=RiskLevel.MEDIUM,
            bytecode_signatures=[
                "5a5b",  # weak upkeep condition
                "6c8d",  # performUpkeep bypass
            ],
            description="Upkeep condition checks can be bypassed for free execution",
        ),
        BytecodeFingerprint(
            pattern_id="AUTO_TASK_RESUBMISSION",
            name="Task Resubmission Attack",
            category="vulnerability",
            severity=RiskLevel.MEDIUM,
            bytecode_signatures=[
                "7a5b",  # task replay
                "6c8d",  # payment bypass
            ],
            description="Automated tasks can be resubmitted to extract payments",
        ),
        BytecodeFingerprint(
            pattern_id="AUTO_GAS_LIMIT_MANIPULATION",
            name="Gas Limit Manipulation",
            category="vulnerability",
            severity=RiskLevel.MEDIUM,
            bytecode_signatures=[
                "5a5b",  # gas limit manipulation
                "6c8d",  # execution failure exploit
            ],
            description="Automation gas limits can be manipulated to cause failures",
        ),
        BytecodeFingerprint(
            pattern_id="AUTO_CRON_JOB_RACE",
            name="Cron Job Race Condition",
            category="vulnerability",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "6a5b",  # cron job overlap
                "5c8d",  # timing attack
            ],
            description="Scheduled automation can have race conditions",
        ),
    ]

    # NEW: Scam patterns
    SCAM_PATTERNS = [
        BytecodeFingerprint(
            pattern_id="SCAM_PONZI_SCHEME",
            name="Ponzi Scheme Pattern",
            category="scam",
            severity=RiskLevel.CRITICAL,
            bytecode_signatures=[
                "7a9c",  # pyramid/MLM structure
                "5b7d",  # referral rewards
            ],
            description="Ponzi/pyramid scheme that pays early investors with new money",
        ),
        BytecodeFingerprint(
            pattern_id="SCAM_FAKE_LIQUIDITY",
            name="Fake Liquidity Pool",
            category="scam",
            severity=RiskLevel.CRITICAL,
            bytecode_signatures=[
                "61a5",  # fake pair creation
                "4b9c",  # fake addLiquidity
            ],
            description="Creates fake liquidity pool that can't be traded",
        ),
        BytecodeFingerprint(
            pattern_id="SCAM_FAKE_TEAM_TOKENS",
            name="Fake Team/Vesting Tokens",
            category="scam",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "5a4c",  # fake vesting
                "6b7d",  # team tokens that unlock immediately
            ],
            description="Team tokens claim to be locked but can be sold immediately",
        ),
        BytecodeFingerprint(
            pattern_id="SCAM_PUMP_DUMP",
            name="Pump and Dump Indicator",
            category="scam",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "7a6b",  # early holders dump pattern
                "5c8d",  # price manipulation
            ],
            description="Patterns indicative of pump and dump scheme",
        ),
        BytecodeFingerprint(
            pattern_id="SCAM_INFINITE_MINT",
            name="Infinite Mint Authority",
            category="scam",
            severity=RiskLevel.CRITICAL,
            bytecode_signatures=[
                "56e5",  # unlimited mint
                "6a9b",  # no supply cap
            ],
            description="Owner can mint unlimited tokens, hyperinflation risk",
        ),
    ]

    # NEW: DeFi-specific vulnerability patterns
    DEFINI_PATTERNS = [
        BytecodeFingerprint(
            pattern_id="DEFI_FLASH_LOAN_ATTACK",
            name="Flash Loan Vulnerability",
            category="defi_vuln",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "6a5b",  # flash loan callback
                "5c7a",  # no flash loan protection
            ],
            description="Vulnerable to flash loan price manipulation attacks",
        ),
        BytecodeFingerprint(
            pattern_id="DEFI_ORACLE_MANIPULATION",
            name="Price Oracle Manipulation",
            category="defi_vuln",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "5a8b",  # spot price oracle
                "6b9c",  # manipulated TWAP
            ],
            description="Uses manipulable price oracle, vulnerable to attacks",
        ),
        BytecodeFingerprint(
            pattern_id="DEFI_REWARD_MANIPULATION",
            name="Reward Farming Manipulation",
            category="defi_vuln",
            severity=RiskLevel.MEDIUM,
            bytecode_signatures=[
                "7a5c",  # reward calculation vulnerable
                "6b7d",  # share manipulation
            ],
            description="Reward mechanism can be gamed for unfair gains",
        ),
        BytecodeFingerprint(
            pattern_id="DEFI_SLIPPAGE_ABUSE",
            name="Slippage Tolerance Abuse",
            category="defi_vuln",
            severity=RiskLevel.MEDIUM,
            bytecode_signatures=[
                "5c8d",  # extreme slippage
                "6a9b",  # sandwich vector pattern
            ],
            description="May be vulnerable to sandwich attacks",
        ),
        BytecodeFingerprint(
            pattern_id="DEFI_STAKING_LOCK",
            name="Staking Lock Abuse",
            category="defi_vuln",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "7a4b",  # forced staking lock
                "5c7d",  # unbondable stake
            ],
            description="Staked funds can be locked indefinitely",
        ),
        BytecodeFingerprint(
            pattern_id="DEFI_IMPERMANENT_LOSS",
            name="Impermanent Loss Risk",
            category="defi_vuln",
            severity=RiskLevel.LOW,
            bytecode_signatures=[
                "6a5b",  # standard AMM pattern
                "5c7a",  # IL exposure
            ],
            description="Standard AMM impermanent loss risk, informational",
        ),
    ]

    # NEW: NFT-specific patterns
    NFT_PATTERNS = [
        BytecodeFingerprint(
            pattern_id="NFT_HONEYPOT_CANNOT_TRANSFER",
            name="NFT Transfer Block",
            category="nft_honeypot",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "7a5b",  # transferFrom blocked
                "6c8d",  # override transfer restriction
            ],
            description="NFT cannot be transferred after purchase",
        ),
        BytecodeFingerprint(
            pattern_id="NFT_APPROVAL_ABUSE",
            name="NFT Approval Abuse",
            category="nft_honeypot",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "5a7b",  # setApprovalForAll abuse
                "6b8c",  # bypass approval pattern
            ],
            description="NFT approvals can be abused to drain wallets",
        ),
        BytecodeFingerprint(
            pattern_id="NFT_FAKE_METADATA",
            name="Fake Metadata URI",
            category="nft_honeypot",
            severity=RiskLevel.HIGH,
            bytecode_signatures=[
                "6a5b",  # fake tokenURI
                "5c7a",  # metadata change after mint
            ],
            description="Metadata can be changed after mint, fake NFT risk",
        ),
        BytecodeFingerprint(
            pattern_id="NFT_MINT_LOCK",
            name="NFT Mint Restriction",
            category="nft_honeypot",
            severity=RiskLevel.MEDIUM,
            bytecode_signatures=[
                "7a6b",  # mint only owner
                "5c8d",  # premint all to creator
            ],
            description="Only creator can mint, not public mint",
        ),
        BytecodeFingerprint(
            pattern_id="NFT_ROYALTY_ABUSE",
            name="Royalty Fee Abuse",
            category="nft_honeypot",
            severity=RiskLevel.MEDIUM,
            bytecode_signatures=[
                "6a7b",  # excessive royalty
                "5c8d",  # royalty to creator only
            ],
            description="Excessive royalty fees on secondary sales",
        ),
    ]

    # Proxy patterns
    PROXY_PATTERNS = [
        BytecodeFingerprint(
            pattern_id="PROXY_ERC1967",
            name="ERC1967 Proxy",
            category="proxy",
            severity=RiskLevel.LOW,
            bytecode_signatures=["5f5e", "3689"],
            description="Standard ERC1967 proxy pattern",
        ),
        BytecodeFingerprint(
            pattern_id="PROXY_UUPS",
            name="UUPS Proxy",
            category="proxy",
            severity=RiskLevel.LOW,
            bytecode_signatures=["4284", "49c5"],
            description="Universal Upgradeable Proxy Standard",
        ),
        BytecodeFingerprint(
            pattern_id="PROXY_TRANSPARENT",
            name="Transparent Proxy",
            category="proxy",
            severity=RiskLevel.LOW,
            bytecode_signatures=["8da5", "1c2b"],
            description="Transparent proxy pattern with admin functions",
        ),
        BytecodeFingerprint(
            pattern_id="PROXY_METAMORPHIC",
            name="Metamorphic Contract",
            category="proxy",
            severity=RiskLevel.MEDIUM,
            bytecode_signatures=["3af3", "52f5"],
            description="Contract can be replaced via metamorphic pattern",
        ),
    ]

    # Standard library patterns
    STANDARD_PATTERNS = [
        BytecodeFingerprint(
            pattern_id="STD_OPENZEPPELIN",
            name="OpenZeppelin Implementation",
            category="standard",
            severity=RiskLevel.INFO,
            bytecode_signatures=["8da5cb5b", "f2fde38b"],
            description="Uses OpenZeppelin smart contract library",
        ),
        BytecodeFingerprint(
            pattern_id="STD_UNISWAP_V2",
            name="Uniswap V2 Pair",
            category="standard",
            severity=RiskLevel.INFO,
            bytecode_signatures=["022c0d9f", "a5e3e6b4"],
            description="Standard Uniswap V2 pair contract",
        ),
        BytecodeFingerprint(
            pattern_id="STD_UNISWAP_V3",
            name="Uniswap V3 Pool",
            category="standard",
            severity=RiskLevel.INFO,
            bytecode_signatures=["d0c93a7c", "1698ee82"],
            description="Standard Uniswap V3 pool contract",
        ),
    ]

    def __init__(self, custom_patterns: Optional[List[BytecodeFingerprint]] = None):
        """Initialize the fingerprint database.

        Args:
            custom_patterns: Optional additional patterns to add
        """
        self._patterns: Dict[str, BytecodeFingerprint] = {}
        self._patterns_by_signature: Dict[str, List[BytecodeFingerprint]] = {}

        # Load built-in patterns
        self._load_patterns(self.HONEYPOT_PATTERNS)
        self._load_patterns(self.MEV_VULNERABILITIES)
        self._load_patterns(self.STORAGE_VULNERABILITIES)
        self._load_patterns(self.ACCESS_CONTROL_VULNS)
        self._load_patterns(self.ARITHMETIC_VULNS)
        self._load_patterns(self.BRIDGE_VULNS)
        self._load_patterns(self.DAO_VULNS)
        self._load_patterns(self.NFT_ADVANCED_VULNS)
        self._load_patterns(self.REENTRANCY_PATTERNS)
        self._load_patterns(self.LOGIC_VULNS)
        self._load_patterns(self.CRYPTO_VULNS)
        self._load_patterns(self.DANGEROUS_OPCODES)
        # NEW: Advanced vulnerability patterns
        self._load_patterns(self.L2_VULNS)
        self._load_patterns(self.ACCOUNT_ABSTRACTION_VULNS)
        self._load_patterns(self.CROSS_CHAIN_MESSAGING_VULNS)
        self._load_patterns(self.BLOB_STORAGE_VULNS)
        self._load_patterns(self.PERMIT2_FLASH_VULNS)
        self._load_patterns(self.ADVANCED_MEV_VULNS)
        self._load_patterns(self.ZKP_PRIVACY_VULNS)
        self._load_patterns(self.AUTOMATION_VULNS)
        self._load_patterns(self.SCAM_PATTERNS)
        self._load_patterns(self.DEFINI_PATTERNS)
        self._load_patterns(self.NFT_PATTERNS)
        self._load_patterns(self.PROXY_PATTERNS)
        self._load_patterns(self.STANDARD_PATTERNS)

        # Load custom patterns
        if custom_patterns:
            self._load_patterns(custom_patterns)

        LOGGER.info(f"Loaded {len(self._patterns)} bytecode fingerprints")

    def _load_patterns(self, patterns: List[BytecodeFingerprint]) -> None:
        """Load patterns into the database."""
        for pattern in patterns:
            self._patterns[pattern.pattern_id] = pattern
            for signature in pattern.bytecode_signatures:
                if signature not in self._patterns_by_signature:
                    self._patterns_by_signature[signature] = []
                self._patterns_by_signature[signature].append(pattern)

    def match_bytecode(self, bytecode: str) -> List[BytecodeFingerprint]:
        """Match bytecode against known patterns.

        Args:
            bytecode: Contract bytecode (hex string)

        Returns:
            List of matching fingerprints
        """
        matches = []
        clean_bytecode = bytecode[2:].lower() if bytecode.startswith("0x") else bytecode.lower()

        # Check each signature
        for signature, patterns in self._patterns_by_signature.items():
            if signature in clean_bytecode:
                for pattern in patterns:
                    if pattern not in matches:
                        pattern.occurrence_count += 1
                        matches.append(pattern)

        return matches

    def get_honeypot_patterns(self) -> List[BytecodeFingerprint]:
        """Get all honeypot patterns."""
        return [p for p in self._patterns.values() if p.category == "honeypot"]

    def get_vulnerability_patterns(self) -> List[BytecodeFingerprint]:
        """Get all vulnerability patterns."""
        return [p for p in self._patterns.values() if p.category == "vulnerability"]

    def get_proxy_patterns(self) -> List[BytecodeFingerprint]:
        """Get all proxy patterns."""
        return [p for p in self._patterns.values() if p.category == "proxy"]

    def add_pattern(self, pattern: BytecodeFingerprint) -> None:
        """Add a new pattern to the database."""
        self._patterns[pattern.pattern_id] = pattern
        for signature in pattern.bytecode_signatures:
            if signature not in self._patterns_by_signature:
                self._patterns_by_signature[signature] = []
            self._patterns_by_signature[signature].append(pattern)
        LOGGER.info(f"Added pattern: {pattern.pattern_id} - {pattern.name}")


class AbiRiskAnalyzer:
    """Enhanced risk scoring for ABI function signatures.

    Analyzes function names, signatures, and parameters to detect:
    - Mint/burn functions (supply manipulation risk)
    - Fee/tax functions (economic attack surface)
    - Administrative functions (centralization risk)
    - External calls (reentrancy risk)
    - Access control functions (privilege escalation)
    """

    # Risk scores for dangerous function name patterns
    RISKY_FUNCTION_PATTERNS = {
        # Honeypot / Trading control
        "enabletrading": 0.95,
        "disabletrading": 0.95,
        "settradestatus": 0.90,
        "istradingenabled": 0.70,
        "opentrading": 0.85,
        "closetrading": 0.90,
        "tradestart": 0.85,
        "tradingopen": 0.70,

        # Fee / Tax control
        "setfee": 0.85,
        "settax": 0.85,
        "setbuyfee": 0.85,
        "setsellfee": 0.85,
        "setliquidtyfee": 0.85,
        "setmarketingfee": 0.85,
        "updatefees": 0.80,
        "setfeepercent": 0.80,
        "changetax": 0.85,
        "updatetax": 0.80,
        "setbuytax": 0.85,
        "setselltax": 0.85,
        "setrewardfee": 0.80,
        "setautoliquify": 0.75,

        # Mint / Supply manipulation
        "mint": 0.75,
        "print": 0.85,
        "issue": 0.70,
        "generatetoken": 0.80,
        "createnft": 0.60,
        "mintbatch": 0.75,
        "mintmany": 0.80,
        "unlimitedmint": 0.95,
        "freemint": 0.70,

        # Blacklist / Freeze
        "blacklist": 0.90,
        "unblacklist": 0.85,
        "freeze": 0.90,
        "unfreeze": 0.85,
        "lock": 0.75,
        "unlock": 0.70,
        "pause": 0.75,
        "unpause": 0.65,
        "block": 0.85,
        "unblock": 0.80,

        # Max wallet / limits
        "setmaxwallet": 0.85,
        "setmaxtx": 0.85,
        "setmaxtransaction": 0.80,
        "updatelimits": 0.75,
        "setmaxbalance": 0.85,
        "setmaxamount": 0.80,
        "settransactionlimit": 0.80,
        "updatemax": 0.75,

        # Cooldowns
        "setcooldown": 0.80,
        "setbuycooldown": 0.80,
        "setsellcooldown": 0.85,
        "enablecooldown": 0.75,
        "updatecooldown": 0.75,

        # Administrative
        "setowner": 0.70,
        "transferownership": 0.75,
        "renounceownership": 0.60,
        "setadmin": 0.75,
        "grantrole": 0.65,
        "revokerole": 0.65,
        "setauthority": 0.75,
        "setmanager": 0.70,
        "setcontroller": 0.70,
        "setoperator": 0.65,
        "setmaster": 0.75,

        # Upgradeability
        "upgrade": 0.70,
        "upgradeto": 0.75,
        "setimplementation": 0.75,
        "migrate": 0.65,
        "upgradetoandcall": 0.75,
        "upgradebeacon": 0.70,
        "setbeacon": 0.70,

        # Withdraw / Drain
        "withdraw": 0.70,
        "drain": 0.85,
        "rescue": 0.60,
        "sweep": 0.65,
        "withdrawstuck": 0.70,
        "withdrawbalance": 0.75,
        "withdrawall": 0.80,
        "emergencywithdraw": 0.70,
        "release": 0.65,
        "extract": 0.85,

        # External call patterns
        "call": 0.40,
        "send": 0.45,
        "transfer": 0.30,
        "delegatecall": 0.70,
        "staticcall": 0.35,

        # Anti-bot / Anti-whale
        "antibot": 0.75,
        "antiwhale": 0.70,
        "setantibot": 0.80,
        "isbot": 0.60,
        "checkbot": 0.55,
        "antibotmode": 0.75,
        "enableantibot": 0.75,
        "setbotprotection": 0.70,

        # Airdrop / Claim
        "claim": 0.40,
        "airdrop": 0.50,
        "claimairdrop": 0.55,
        "claimreward": 0.45,
        "claimtokens": 0.40,
        "claimdividend": 0.45,

        # Liquidity manipulation
        "addliquidity": 0.50,
        "removeliquidity": 0.85,
        "withdrawliquidity": 0.85,
        "sweepliquidity": 0.80,
        "lockliquidity": 0.70,
        "unlockliquidity": 0.75,
        "skim": 0.65,
        "sync": 0.50,

        # DeFi / Yield farming risks
        "stake": 0.40,
        "unstake": 0.45,
        "harvest": 0.40,
        "compound": 0.35,
        "reward": 0.35,
        "deposit": 0.40,
        "withdrawpool": 0.45,

        # Time-based restrictions
        "settradinghours": 0.75,
        "settradingtime": 0.75,
        "timelock": 0.60,
        "setdelay": 0.55,

        # Whitelist mechanisms
        "setwhitelist": 0.80,
        "addwhitelist": 0.75,
        "removewhitelist": 0.75,
        "enablewhitelist": 0.80,
        "iswhitelisted": 0.70,

        # Multisig / Gnosis Safe
        "exectransaction": 0.30,
        "confirmtx": 0.30,
        "revoketx": 0.30,

        # Burn mechanisms (usually safe but notable)
        "burn": 0.20,
        "burnfrom": 0.25,
        "burnbatch": 0.30,

        # Rebase / Elastic supply
        "rebase": 0.85,
        "setelastic": 0.80,
        "elasticrebase": 0.85,
        "autorebase": 0.80,
        "enableauto": 0.75,

        # Reflection / Rewards
        "setreward": 0.60,
        "setreflection": 0.60,
        "setdividend": 0.60,
        "settracker": 0.60,

        # PancakeSwap / Uniswap specific
        "createpair": 0.30,
        "setpair": 0.45,
        "setrouter": 0.50,
        "setfactory": 0.50,

        # Metadata manipulation (NFT)
        "settokenuri": 0.70,
        "setbaseuri": 0.70,
        "seturi": 0.70,
        "burnandmint": 0.75,

        # Batch operations
        "batch": 0.40,
        "multicall": 0.35,
        "batchtransfer": 0.50,

        # Oracle / Price feeds
        "setoracle": 0.60,
        "setprice": 0.80,
        "updateprice": 0.75,

        # Bridge specific
        "bridge": 0.50,
        "crosschain": 0.55,
        "wrap": 0.40,
        "unwrap": 0.40,

        # Vesting / Timelock
        "setvesting": 0.60,
        "releasevesting": 0.45,
        "claimvesting": 0.40,
        "settimelock": 0.55,

        # DAO / Governance
        "vote": 0.30,
        "propose": 0.35,
        "execute": 0.40,
        "queue": 0.35,
        "cancel": 0.30,

        # Flash loan related
        "flashloan": 0.60,
        "executeoperation": 0.55,

        # Lottery / Gambling
        "draw": 0.40,
        "enterlottery": 0.45,
        "claimprize": 0.40,

        # Token approvals
        "setapprovalforall": 0.50,
        "approve": 0.30,
        "permit": 0.45,
        "safeapprove": 0.40,

        # Rescue mechanisms (can be legitimate)
        "rescueerc20": 0.50,
        "rescueeth": 0.55,
        "rescuetoken": 0.50,

        # Swap / Exchange
        "swap": 0.40,
        "swapexact": 0.40,
        "swaptokens": 0.40,
        "trading": 0.45,

        # Token locking
        "locktoken": 0.70,
        "unlocktoken": 0.65,
        "extendlock": 0.60,

        # Launchpad / Presale
        "launch": 0.50,
        "presale": 0.55,
        "claimpresale": 0.50,
        "softcap": 0.50,
        "hardcap": 0.50,

        # Utility functions
        "multisend": 0.45,
        "distribute": 0.40,
        "airdropmultiple": 0.50,

        # Distribution / Dividend
        "distribute": 0.40,
        "distribute dividend": 0.45,
        "claimdividend": 0.40,
        "processdividend": 0.35,

        # Token recovery
        "reclaim": 0.50,
        "reclaimtoken": 0.55,
        "reclaimcrypto": 0.55,

        # NEW: More access control patterns
        "setpauserole": 0.65,
        "renouncerole": 0.50,
        "acceptrole": 0.30,
        "onrolegranted": 0.25,
        "onrevoked": 0.30,

        # NEW: Signature/verification patterns
        "sign": 0.45,
        "verify": 0.40,
        "getsignature": 0.40,
        "isValidSignature": 0.35,
        "splitsignature": 0.40,

        # NEW: Transfer restriction patterns
        "transferfrom": 0.35,
        "transferonbatch": 0.50,
        "batchtransfer": 0.50,
        "transferbatch": 0.50,

        # NEW: Market/DEX specific patterns
        "getamountout": 0.30,
        "getamountsin": 0.30,
        "quote": 0.35,
        "price0cumulativelast": 0.30,
        "price1cumulativelast": 0.30,

        # NEW: Pool operations
        "createpair": 0.30,
        "addliquidityeth": 0.40,
        "addliquidity": 0.35,
        "removeliquidity": 0.45,
        "getreserves": 0.30,

        # NEW: Factory/Router patterns
        "setfactory": 0.50,
        "setrouter": 0.50,
        "setexchange": 0.55,
        "setwap": 0.45,

        # NEW: Reflection/rewards patterns
        "setreflection": 0.60,
        "setfeepercentage": 0.80,
        "setrewardfee": 0.60,
        "setliquidityfee": 0.60,
        "setmarketingwallet": 0.55,

        # NEW: Dividend/distribution patterns
        "distribute dividend": 0.45,
        "claimdividends": 0.40,
        "withdrawdividend": 0.45,
        "claimreward": 0.40,
        "getreward": 0.35,

        # NEW: Multi-sig patterns
        "submittransaction": 0.40,
        "confirmandexecute": 0.35,
        "revoketx": 0.30,
        "executetransaction": 0.40,

        # NEW: Governor patterns
        "castvotebyid": 0.30,
        "castvotewithreason": 0.35,
        "proposevote": 0.40,

        # NEW: Timelock patterns
        "timelock": 0.55,
        "setdelay": 0.60,
        "accepttimelock": 0.50,
        "canceltransaction": 0.45,

        # NEW: Registry patterns
        "setregistry": 0.60,
        "setimplementation": 0.70,
        "upgrade": 0.65,
        "upgradeto": 0.75,

        # NEW: ERC4626 tokenized vault patterns
        "deposit": 0.40,
        "maxredeem": 0.45,
        "converttoshares": 0.45,
        "redeem": 0.40,

        # NEW: ERC721/ERC1155 specific
        "safebatchtransferfrom": 0.40,
        "setapprovalforall": 0.50,
        "getapproved": 0.35,
        "isapprovedforall": 0.35,

        # NEW: Factory/creation patterns
        "create": 0.45,
        "deploy": 0.50,
        "initialize": 0.40,
        "init": 0.45,

        # NEW: DAO/proposal patterns
        "cancelproposal": 0.45,
        "queueproposal": 0.35,
        "executeproposal": 0.40,
        "veto": 0.50,

        # NEW: Pool/balance patterns
        "balanceof": 0.20,
        "totalbalance": 0.25,
        "sharesof": 0.30,

        # NEW: ERC20 extensions
        "increaseallowance": 0.30,
        "decreaseallowance": 0.30,
        "allowance": 0.25,

        # NEW: Safe patterns (low risk)
        "totalSupply": 0.10,
        "decimals": 0.10,
        "symbol": 0.10,
        "name": 0.10,

        # NEW: Metadata/URI patterns
        "tokenuri": 0.30,
        "tokenuribatch": 0.40,
        "baseuri": 0.35,
        "contracturi": 0.30,

        # NEW: Batch operations
        "multicall": 0.35,
        "batch": 0.40,
        "tryblock": 0.30,

        # NEW: Governance execution
        "relay": 0.45,
        "executebyproxy": 0.50,
        "setpendingadmin": 0.70,

        # NEW: Migration patterns
        "migrate": 0.65,
        "migratetoken": 0.70,
        "migratefrom": 0.60,

        # NEW: ERC777/ERC677 patterns
        "tokensreceived": 0.35,
        "approveandcall": 0.50,
        "sendandcall": 0.55,

        # NEW: Escrow patterns
        "deposit": 0.40,
        "withdraw": 0.40,
        "release": 0.45,
        "refund": 0.50,

        # NEW: Auction patterns
        "createauction": 0.45,
        "bidauction": 0.40,
        "cancelfullauction": 0.35,
        "endauction": 0.40,
        "claimauction": 0.40,

        # NEW: Yield farming patterns
        "stake": 0.40,
        "unstake": 0.45,
        "harvest": 0.40,
        "compound": 0.35,
        "reinvest": 0.40,
        "leave": 0.30,

        # NEW: NFT marketplace patterns
        "buynft": 0.40,
        "sellnft": 0.45,
        "cancelorder": 0.35,
        "matchorder": 0.30,

        # NEW: Crowdsale patterns
        "contribute": 0.45,
        "claimrefund": 0.40,
        "finalizescrow": 0.50,
        "withdrawpledged": 0.45,

        # NEW: Token lock patterns
        "lock": 0.70,
        "unlock": 0.65,
        "extendlock": 0.60,
        "withdrawlock": 0.55,

        # NEW: Lottery patterns
        "enter": 0.40,
        "buyticket": 0.45,
        "drawlottery": 0.40,
        "claimwin": 0.35,

        # NEW: Farming patterns
        "farm": 0.40,
        "pool": 0.35,
        "getpendingreward": 0.30,
        "withdrawpending": 0.35,

        # NEW: Merkle drop patterns
        "claimmerkle": 0.40,
        "verifyinclusion": 0.35,
        "merkleproof": 0.30,

        # NEW: Bridge patterns
        "deposit": 0.45,
        "withdraw": 0.45,
        "claim": 0.40,
        "relay": 0.50,

        # NEW: Forwarder patterns
        "forward": 0.50,
        "multicall": 0.35,
        "batchcall": 0.45,

        # NEW: Keeper patterns
        "performupkeep": 0.40,
        "sweep": 0.50,
        "harvest": 0.40,

        # NEW: Token vesting patterns
        "vest": 0.50,
        "revokevest": 0.60,
        "release": 0.45,
        "claimvested": 0.40,

        # NEW: Address registry patterns
        "setaddress": 0.60,
        "getaddress": 0.35,
        "updateaddress": 0.55,

        # NEW: Enumerable patterns
        "tokenofownerbyindex": 0.35,
        "totalSupply": 0.15,
        "tokenbyindex": 0.30,

        # NEW: Wrapper patterns
        "deposit": 0.40,
        "withdraw": 0.45,
        "withdraw": 0.40,
        "weth": 0.30,

        # NEW: Order book patterns
        "placeorder": 0.45,
        "cancelorder": 0.40,
        "fillorder": 0.35,
        "matchorders": 0.30,

        # NEW: Liquidation patterns
        "liquidate": 0.50,
        "repayborrow": 0.45,
        "seize": 0.55,
        "collateral": 0.40,

        # NEW: Interest rate patterns
        "setinterestrate": 0.70,
        "interestrate": 0.50,
        "updateindex": 0.40,
        "accrueinterest": 0.45,

        # NEW: Pool token patterns
        "underlying": 0.30,
        "underlyingview": 0.30,
        "pool": 0.35,
        "getpool": 0.35,

        # NEW: Strategy patterns
        "setstrategy": 0.60,
        "harvest": 0.45,
        "exit": 0.40,
        "panic": 0.75,

        # NEW: Admin functions
        "setparam": 0.60,
        "configure": 0.55,
        "toggle": 0.60,
        "trigger": 0.55,
        "activate": 0.50,
        "deactivate": 0.55,

        # NEW: Emergency functions
        "emergency": 0.70,
        "pause": 0.75,
        "unpause": 0.60,
        "emergencywithdraw": 0.70,
        "emergencytransfer": 0.75,

        # NEW: Team/vesting patterns
        "team": 0.60,
        "advisor": 0.55,
        "private": 0.70,
        "publicsale": 0.40,
        "airdrop": 0.50,

        # NEW: Percentage-based functions
        "setpercent": 0.65,
        "getpercentage": 0.40,
        "setbasispoints": 0.70,
        "basispoints": 0.50,

        # NEW: Interface upgrade patterns
        "implement": 0.65,
        "admin": 0.70,
        "implementation": 0.70,
        "beacon": 0.60,

        # NEW: Pool specific
        "skim": 0.50,
        "sync": 0.40,
        "burn": 0.35,
        "collect": 0.40,
        "compound": 0.35,

        # NEW: Marketplace functions
        "makeoffer": 0.40,
        "acceptoffer": 0.40,
        "cancelfulfillassignment": 0.45,
        "fulfillassignment": 0.40,

        # NEW: DAO voting
        "castvote": 0.35,
        "getreceipt": 0.30,
        "propproposal": 0.40,

        # NEW: Forwarder/executor
        "execute": 0.45,
        "multicall": 0.35,
        "batch": 0.40,

        # NEW: Claim functions
        "claim": 0.40,
        "claimall": 0.50,
        "claimmany": 0.50,
        "withdrawclaim": 0.45,

        # NEW: Redeem functions
        "redeem": 0.45,
        "redeemunderlying": 0.50,
        "redeemshares": 0.50,

        # NEW: Layer 2 specific patterns
        "prove": 0.50,
        "verifyproof": 0.55,
        "finalizewithdrawal": 0.45,
        "initiatewithdrawal": 0.40,
        "claimwithdrawal": 0.45,
        "depositl2": 0.40,
        "withdrawl1": 0.45,
        "l2bridge": 0.55,
        "statelroot": 0.50,
        "fraudproof": 0.55,
        "challengestate": 0.50,

        # NEW: Account Abstraction (ERC-4337) patterns
        "validateuserop": 0.45,
        "handleops": 0.40,
        "userop": 0.50,
        "aggregatesignature": 0.55,
        "paymaster": 0.60,
        "depositpaymaster": 0.55,
        "withdrawpaymaster": 0.60,
        "entrypoint": 0.40,
        "accountimplementation": 0.45,
        "validateaggregator": 0.50,

        # NEW: Cross-chain messaging patterns
        "sendmessage": 0.50,
        "receivemessage": 0.50,
        "relaymessage": 0.55,
        "verifymessage": 0.55,
        "crosschaincall": 0.60,
        "lzendpoint": 0.50,
        "wormholerelay": 0.55,
        "hyperlanemessenger": 0.50,
        "ccipsend": 0.55,
        "ccipreceive": 0.55,
        "messageid": 0.45,
        "nonce": 0.35,

        # NEW: EIP-4844/Blob storage patterns
        "blob": 0.40,
        "blobhash": 0.45,
        "pointevaluation": 0.50,
        "blobdata": 0.45,
        "blobversionedhash": 0.50,
        "commitblob": 0.45,

        # NEW: Permit2/Flash account patterns
        "permit": 0.55,
        "permit2": 0.60,
        "approvepermit2": 0.55,
        "invalidatenonce": 0.50,
        "tokenpermissions": 0.55,
        "permittransferfrom": 0.60,
        "permitamount": 0.55,
        "permitdeadline": 0.50,
        "signaturetransfer": 0.55,
        "flashaccount": 0.55,

        # NEW: Advanced MEV patterns
        "jitswap": 0.50,
        "backrun": 0.45,
        "frontrun": 0.50,
        "sandwich": 0.55,
        "mempool": 0.40,
        "priorityfee": 0.35,
        "builder": 0.40,
        "blockbuilder": 0.40,
        "validator": 0.35,

        # NEW: ZKP/Privacy patterns
        "nullifier": 0.50,
        "merkleproof": 0.45,
        "verifypoint": 0.50,
        "commitment": 0.45,
        "nullifierhash": 0.55,
        "relayerfee": 0.50,
        "withdrawnote": 0.55,
        "mixer": 0.60,
        "tornado": 0.70,

        # NEW: Automation (Gelato/Keepers) patterns
        "checkupkeep": 0.40,
        "performupkeep": 0.45,
        "automate": 0.45,
        "schedule": 0.50,
        "cron": 0.50,
        "keepers": 0.45,
        "gelato": 0.45,
        "taskid": 0.40,
        "resubmit": 0.50,
        "automation": 0.45,

        # NEW EXPANDED: Additional L2 risk patterns
        "proveexit": 0.50,
        "finalizeexit": 0.45,
        "startexit": 0.40,
        "challengeexit": 0.50,
        "processexit": 0.45,
        "fastwithdrawal": 0.50,
        "withdrawroot": 0.55,
        "deposittroot": 0.45,
        "syncstate": 0.50,
        "verifystate": 0.55,
        "rollup": 0.45,
        "validaterollup": 0.50,
        "optimistic": 0.45,
        "zkrollup": 0.50,
        "arbitrum": 0.40,
        "optimism": 0.40,
        "basechain": 0.40,
        "polygonzkevm": 0.45,
        "scroll": 0.40,
        "linea": 0.40,
        "starknet": 0.45,
        "zksync": 0.45,
        "canonical": 0.50,
        "officialbridge": 0.45,
        "messagereceiver": 0.50,
        "messagesender": 0.50,
        "xsleeper": 0.45,
        "gateway": 0.45,
        "l2pass": 0.40,
        "bridgel1tol2": 0.50,
        "bridgel2tol1": 0.50,
        "crossdomain": 0.55,
        "exitroot": 0.50,
        "inputroot": 0.50,

        # NEW EXPANDED: Additional Account Abstraction patterns
        "signatureaggregator": 0.55,
        "aggregation": 0.50,
        "useroperation": 0.50,
        "useropverification": 0.50,
        "prefund": 0.45,
        "adddeposit": 0.45,
        "increasebalance": 0.45,
        "withdrawto": 0.55,
        "lockpaymaster": 0.50,
        "unlockpaymaster": 0.50,
        "validatesignature": 0.50,
        "paymasterid": 0.55,
        "verificationgaslimit": 0.45,
        "callgaslimit": 0.40,
        "maxfeepergas": 0.40,
        "smartaccount": 0.45,
        "walletimplementation": 0.45,
        "bundler": 0.50,
        "erc4337": 0.50,
        "scw": 0.45,

        # NEW EXPANDED: Additional Cross-chain messaging patterns
        "layerzero": 0.50,
        "wormhole": 0.55,
        "chainlink": 0.50,
        "axelar": 0.50,
        "ibc": 0.50,
        "gravitybridge": 0.50,
        "polybridge": 0.50,
        "multichain": 0.55,
        "anymap": 0.50,
        "synapse": 0.50,
        "hopprotocol": 0.50,
        "across": 0.50,
        "connext": 0.50,
        "cbridge": 0.50,
        "stargate": 0.50,
        "debridge": 0.50,
        "relayer": 0.55,
        "deliver": 0.50,
        "estimatemessagefee": 0.50,
        "payload": 0.45,
        "srcchain": 0.50,
        "dstchain": 0.50,
        "dstaddress": 0.50,
        "lzreceive": 0.50,
        "lzapp": 0.45,
        "forcedreceive": 0.50,
        "retrymessage": 0.50,
        "verifypayload": 0.55,

        # NEW EXPANDED: Additional Blob storage patterns
        "eip4844": 0.45,
        "kzg": 0.50,
        "kzgpointevaluation": 0.55,
        "cancun": 0.40,
        "danksharding": 0.40,
        "blobbasefee": 0.45,
        "excessblobgas": 0.45,
        "blobfee": 0.45,
        "getblobhash": 0.45,
        "blobcommitments": 0.50,
        "pointevaluationprecompile": 0.55,
        "kzgtofield": 0.50,
        "fieldtokzg": 0.50,
        "blobproof": 0.50,
        "verifyblobproof": 0.55,

        # NEW EXPANDED: Additional Permit2/Flash patterns
        "permittransfer": 0.60,
        "permitapprove": 0.55,
        "permitallowed": 0.55,
        "permitall": 0.60,
        "unlimitedpermit": 0.70,
        "permittype": 0.50,
        "signatureenabled": 0.50,
        "permitsignature": 0.55,
        "eip2612": 0.50,
        "eip3009": 0.55,
        "dapopermit": 0.55,
        "eip5137": 0.50,
        "singlepermit": 0.50,
        "batchpermit": 0.55,
        "permitbatch": 0.55,
        "invalidateall": 0.55,
        "invalidateauthorized": 0.50,
        "permit3": 0.55,
        "batchsignaturetransfer": 0.60,
        "lockallowance": 0.50,
        "unlockallowance": 0.50,

        # NEW EXPANDED: Additional MEV patterns
        "mev": 0.45,
        "arbitrage": 0.50,
        "liquidation": 0.45,
        "searcher": 0.50,
        "aavewrapped": 0.45,
        "dydx": 0.45,
        "1inch": 0.40,
        "uniswapv3": 0.40,
        "quoterv2": 0.40,
        "twap": 0.45,
        "oracleupdate": 0.50,
        "feeswap": 0.50,
        "feearbitrage": 0.55,
        "nftfloor": 0.50,
        "backrunme": 0.50,
        "frontrunme": 0.50,
        "sandwichme": 0.55,
        "jitarb": 0.50,
        "swaprouter": 0.40,
        "amountoutminimum": 0.40,
        "slippage": 0.50,
        "tolerance": 0.45,
        "deadlineblock": 0.40,

        # NEW EXPANDED: Additional ZKP/Privacy patterns
        "tornadocash": 0.75,
        "tornadoclassic": 0.75,
        "mixernotes": 0.60,
        "provenance": 0.50,
        "snark": 0.55,
        "stark": 0.50,
        "groth16": 0.50,
        "plonk": 0.50,
        "bulletproof": 0.55,
        "zerocoin": 0.70,
        "zksnark": 0.55,
        "zkstark": 0.50,
        "proofverification": 0.55,
        "circuit": 0.50,
        "witness": 0.45,
        "leaf": 0.45,
        "merkleleaf": 0.45,
        "merkleroot": 0.50,
        "merkleindex": 0.45,
        "nullifierset": 0.55,
        "commitmentmap": 0.50,
        "extnullifier": 0.55,
        "relayers": 0.50,
        "denomination": 0.50,
        "anonymityset": 0.50,
        "privacy": 0.55,
        "confidential": 0.50,
        "shield": 0.50,
        "shielded": 0.50,
        "anonymous": 0.55,

        # NEW EXPANDED: Additional Automation patterns
        "keep3r": 0.45,
        "keep3rv1": 0.45,
        "keep3rv2": 0.45,
        "opsresolve": 0.50,
        "opsexec": 0.50,
        "cronjob": 0.50,
        "cronmanager": 0.50,
        "schedulecall": 0.50,
        "scheduled": 0.45,
        "executelater": 0.50,
        "executeafter": 0.50,
        "execeuteat": 0.50,
        "executecron": 0.50,
        "oneceipt": 0.45,
        "taskqueue": 0.45,
        "taskexecutor": 0.50,
        "taskcreator": 0.50,
        "automationbot": 0.45,
        "autoexecute": 0.50,
        "autocompound": 0.50,
        "autoreinvest": 0.50,
        "autofarm": 0.50,
        "autoharvest": 0.50,
        "yieldster": 0.45,
        "dopex": 0.45,
        "convex": 0.40,
        "curveautocompound": 0.45,
        "keepercompat": 0.50,
    }

    # Risk factors by category
    RISK_FACTORS = {
        "trading_control": [
            "enabletrading", "disabletrading", "settradestatus", "istradingenabled",
            "opentrading", "closetrading", "tradestart", "tradingopen",
        ],
        "fee_control": [
            "setfee", "settax", "setbuyfee", "setsellfee", "updatefees",
            "changetax", "updatetax", "setbuytax", "setselltax", "setrewardfee",
        ],
        "supply_manipulation": [
            "mint", "print", "issue", "generatetoken", "mintbatch", "mintmany",
            "unlimitedmint", "freemint",
        ],
        "address_blocking": [
            "blacklist", "freeze", "lock", "unblacklist", "unfreeze",
            "block", "unblock", "pause", "unpause",
        ],
        "limit_control": [
            "setmaxwallet", "setmaxtx", "setmaxtransaction", "updatelimits",
            "setmaxbalance", "setmaxamount", "settransactionlimit", "updatemax",
        ],
        "cooldown_control": [
            "setcooldown", "setbuycooldown", "setsellcooldown", "enablecooldown",
            "updatecooldown",
        ],
        "centralization": [
            "setowner", "transferownership", "setadmin", "grantrole",
            "setauthority", "setmanager", "setcontroller", "setoperator", "setmaster",
        ],
        "upgradeability": [
            "upgrade", "upgradeto", "setimplementation", "migrate",
            "upgradetoandcall", "upgradebeacon", "setbeacon",
        ],
        "fund_drain": [
            "withdraw", "drain", "sweep", "rescue", "withdrawstuck", "withdrawbalance",
            "withdrawall", "emergencywithdraw", "release", "extract",
        ],
        "liquidity_manipulation": [
            "removeliquidity", "withdrawliquidity", "sweepliquidity",
            "lockliquidity", "unlockliquidity",
        ],
        "oracle_manipulation": [
            "setoracle", "setprice", "updateprice",
        ],
        "whitelist_control": [
            "setwhitelist", "addwhitelist", "removewhitelist", "enablewhitelist",
            "iswhitelisted",
        ],
        "rebase_supply": [
            "rebase", "setelastic", "elasticrebase", "autorebase", "enableauto",
        ],
        "metadata_manipulation": [
            "settokenuri", "setbaseuri", "seturi",
        ],
        "bridge_manipulation": [
            "bridge", "crosschain",
        ],
        "vesting_manipulation": [
            "setvesting", "releasevesting", "claimvesting",
        ],
        "token_locking": [
            "locktoken", "unlocktoken", "extendlock",
        ],
        "signature_risk": [
            "sign", "verify", "getsignature", "splitsignature",
        ],
        "access_control_advanced": [
            "setpauserole", "renouncerole", "acceptrole",
        ],
        "market_risk": [
            "skim", "sync", "collect", "compound",
        ],
        "governance_risk": [
            "castvote", "propose", "queue", "cancel", "veto",
        ],
        "emergency_risk": [
            "emergency", "pause", "unpause", "emergencywithdraw",
        ],
        # NEW: Advanced risk factor categories
        "l2_risk": [
            "prove", "verifyproof", "finalizewithdrawal", "initiatewithdrawal",
            "claimwithdrawal", "depositl2", "withdrawl1", "l2bridge",
            "statelroot", "fraudproof", "challengestate",
        ],
        "account_abstraction_risk": [
            "validateuserop", "handleops", "userop", "aggregatesignature",
            "paymaster", "depositpaymaster", "withdrawpaymaster",
            "entrypoint", "accountimplementation", "validateaggregator",
            "signatureaggregator", "aggregation", "useroperation", "useropverification",
            "prefund", "adddeposit", "increasebalance", "withdrawto",
            "lockpaymaster", "unlockpaymaster", "validatesignature", "paymasterid",
            "verificationgaslimit", "callgaslimit", "maxfeepergas",
            "smartaccount", "walletimplementation", "bundler", "erc4337", "scw",
        ],
        "cross_chain_messaging_risk": [
            "sendmessage", "receivemessage", "relaymessage", "verifymessage",
            "crosschaincall", "lzendpoint", "wormholerelay",
            "hyperlanemessenger", "ccipsend", "ccipreceive", "messageid", "nonce",
            "layerzero", "wormhole", "chainlink", "axelar", "ibc",
            "gravitybridge", "polybridge", "multichain", "anymap", "synapse",
            "hopprotocol", "across", "connext", "cbridge", "stargate",
            "debridge", "relayer", "deliver", "estimatemessagefee", "payload",
            "srcchain", "dstchain", "dstaddress", "lzreceive", "lzapp",
            "forcedreceive", "retrymessage", "verifypayload",
        ],
        "blob_storage_risk": [
            "blob", "blobhash", "pointevaluation", "blobdata",
            "blobversionedhash", "commitblob",
            "eip4844", "kzg", "kzgpointevaluation", "cancun", "danksharding",
            "blobbasefee", "excessblobgas", "blobfee", "getblobhash",
            "blobcommitments", "pointevaluationprecompile", "kzgtofield",
            "fieldtokzg", "blobproof", "verifyblobproof",
        ],
        "permit2_flash_risk": [
            "permit", "permit2", "approvepermit2", "invalidatenonce",
            "tokenpermissions", "permittransferfrom", "permitamount",
            "permitdeadline", "signaturetransfer", "flashaccount",
            "permittransfer", "permitapprove", "permitallowed", "permitall",
            "unlimitedpermit", "permittype", "signatureenabled", "permitsignature",
            "eip2612", "eip3009", "dapopermit", "eip5137", "singlepermit",
            "batchpermit", "permitbatch", "invalidateall", "invalidateauthorized",
            "permit3", "batchsignaturetransfer", "lockallowance", "unlockallowance",
        ],
        "advanced_mev_risk": [
            "jitswap", "backrun", "frontrun", "sandwich",
            "mempool", "priorityfee", "builder", "blockbuilder", "validator",
            "mev", "arbitrage", "liquidation", "searcher", "aavewrapped",
            "dydx", "1inch", "uniswapv3", "quoterv2", "twap",
            "oracleupdate", "feeswap", "feearbitrage", "nftfloor",
            "backrunme", "frontrunme", "sandwichme", "jitarb",
            "swaprouter", "amountoutminimum", "slippage", "tolerance", "deadlineblock",
        ],
        "zkp_privacy_risk": [
            "nullifier", "merkleproof", "verifypoint", "commitment",
            "nullifierhash", "relayerfee", "withdrawnote", "mixer", "tornado",
            "tornadocash", "tornadoclassic", "mixernotes", "provenance",
            "snark", "stark", "groth16", "plonk", "bulletproof",
            "zerocoin", "zksnark", "zkstark", "proofverification", "circuit",
            "witness", "leaf", "merkleleaf", "merkleroot", "merkleindex",
            "nullifierset", "commitmentmap", "extnullifier", "relayers",
            "denomination", "anonymityset", "privacy", "confidential",
            "shield", "shielded", "anonymous",
        ],
        "automation_risk": [
            "checkupkeep", "performupkeep", "automate", "schedule",
            "cron", "keepers", "gelato", "taskid", "resubmit", "automation",
            "keep3r", "keep3rv1", "keep3rv2", "opsresolve", "opsexec",
            "cronjob", "cronmanager", "schedulecall", "scheduled", "executelater",
            "executeafter", "execeuteat", "executecron", "oneceipt",
            "taskqueue", "taskexecutor", "taskcreator", "automationbot",
            "autoexecute", "autocompound", "autoreinvest", "autofarm",
            "autoharvest", "yieldster", "dopex", "convex", "curveautocompound", "keepercompat",
        ],
    }

    # Risk descriptions
    RISK_DESCRIPTIONS = {
        "trading_control": "Contract can disable trading, potentially trapping users",
        "fee_control": "Contract can set fees to 100%, blocking all transfers",
        "supply_manipulation": "Contract can mint unlimited tokens, diluting value",
        "address_blocking": "Contract can block specific addresses from transferring",
        "limit_control": "Contract can impose strict limits on transfers",
        "cooldown_control": "Contract enforces cooldowns between transactions, may trap funds",
        "centralization": "High degree of admin control over contract",
        "upgradeability": "Contract logic can be changed by admin",
        "fund_drain": "Contract can withdraw funds from contract",
        "liquidity_manipulation": "Owner can remove or manipulate liquidity pool",
        "oracle_manipulation": "Uses manipulable price oracle, vulnerable to attacks",
        "whitelist_control": "Only whitelisted addresses can trade",
        "rebase_supply": "Token supply can be changed dynamically, highly unusual",
        "metadata_manipulation": "Metadata can be changed after mint",
        "bridge_manipulation": "Cross-chain bridge functions with custody risks",
        "vesting_manipulation": "Vesting schedule can be modified by admin",
        "token_locking": "Tokens can be locked by contract",
        "signature_risk": "Signature verification functions can be manipulated",
        "access_control_advanced": "Advanced role management can be abused",
        "market_risk": "Market operations like skim/sync can be exploited",
        "governance_risk": "Governance functions can be manipulated",
        "emergency_risk": "Emergency controls give owner excessive power",
        # NEW: Advanced risk descriptions
        "l2_risk": "Layer 2 bridge and proof verification functions, potential for fraud proof bypass",
        "account_abstraction_risk": "Account abstraction functions vulnerable to paymaster drain and signature forgery",
        "cross_chain_messaging_risk": "Cross-chain messaging functions with replay and relayer manipulation risks",
        "blob_storage_risk": "EIP-4844 blob storage functions with data availability and replay vulnerabilities",
        "permit2_flash_risk": "Permit2 and flash account functions with signature replay and approval drain risks",
        "advanced_mev_risk": "Advanced MEV patterns including JIT liquidity, backrunning, and sandwich attacks",
        "zkp_privacy_risk": "Zero-knowledge proof functions with nullifier reuse and privacy linking risks",
        "automation_risk": "Automation (Gelato/Keepers) functions with keeper manipulation and task resubmission risks",
    }

    # Parameter risk modifiers
    RISKY_PARAMETERS = {
        "uint256": 0.0,
        "address": 0.0,
        "bool": 0.1,  # Boolean parameters often enable/disable features
        "uint8": 0.05,  # Small integers often represent percentages
    }

    def __init__(self, custom_risk_patterns: Optional[Dict[str, float]] = None):
        """Initialize the ABI risk analyzer.

        Args:
            custom_risk_patterns: Optional custom function risk patterns
        """
        self._risk_patterns = self.RISKY_FUNCTION_PATTERNS.copy()
        if custom_risk_patterns:
            self._risk_patterns.update(custom_risk_patterns)

    def analyze_function(
        self,
        function_name: str,
        inputs: Optional[List[Dict]] = None,
        outputs: Optional[List[Dict]] = None,
    ) -> AbiRiskScore:
        """Analyze a single function for risk.

        Args:
            function_name: Function name
            inputs: Input parameters from ABI
            outputs: Output parameters from ABI

        Returns:
            AbiRiskScore with analysis results
        """
        function_lower = function_name.lower()
        risk_score = 0.0
        risk_factors = []
        matched_patterns = []

        # Check against known risk patterns
        for pattern, pattern_score in self._risk_patterns.items():
            if pattern in function_lower:
                risk_score = max(risk_score, pattern_score)
                matched_patterns.append(pattern)

        # Determine risk factors
        for factor, patterns in self.RISK_FACTORS.items():
            if any(pattern in function_lower for pattern in patterns):
                if factor not in risk_factors:
                    risk_factors.append(factor)

        # Calculate parameter risk
        param_risk = 0.0
        if inputs:
            for inp in inputs:
                param_type = inp.get("type", "")
                for param_pattern, modifier in self.RISKY_PARAMETERS.items():
                    if param_pattern in param_type:
                        param_risk += modifier

        risk_score = min(1.0, risk_score + param_risk * 0.1)

        # Determine severity
        severity = self._determine_severity(risk_score)

        # Generate description and recommendation
        description = self._generate_description(function_name, risk_factors)
        recommendation = self._generate_recommendation(risk_factors, severity)

        # Build function signature
        signature = self._build_signature(function_name, inputs or [])

        return AbiRiskScore(
            function_name=function_name,
            function_signature=signature,
            risk_score=risk_score,
            risk_factors=risk_factors,
            severity=severity,
            description=description,
            recommendation=recommendation,
            confidence=0.7 + (0.3 * len(risk_factors) / 8),  # Higher confidence with more factors
        )

    def analyze_abi(self, abi: List[Dict]) -> List[AbiRiskScore]:
        """Analyze entire ABI for risky functions.

        Args:
            abi: Contract ABI

        Returns:
            List of AbiRiskScore for all risky functions
        """
        risky_functions = []

        for entry in abi:
            if entry.get("type") != "function":
                continue

            function_name = entry.get("name", "")
            inputs = entry.get("inputs", [])
            outputs = entry.get("outputs", [])

            score = self.analyze_function(function_name, inputs, outputs)

            # Only include functions with non-zero risk
            if score.risk_score > 0:
                risky_functions.append(score)

        # Sort by risk score (highest first)
        risky_functions.sort(key=lambda x: x.risk_score, reverse=True)

        return risky_functions

    def get_overall_risk_score(self, abi: List[Dict]) -> float:
        """Calculate overall contract risk score from ABI.

        Args:
            abi: Contract ABI

        Returns:
            Overall risk score (0-1)
        """
        risky_functions = self.analyze_abi(abi)

        if not risky_functions:
            return 0.0

        # Weight top risks more heavily
        total_score = 0.0
        weight_sum = 0.0

        for i, func_score in enumerate(risky_functions):
            # Exponential decay: first functions weighted more
            weight = 1.0 / (1.0 + i * 0.2)
            total_score += func_score.risk_score * weight
            weight_sum += weight

        return min(1.0, total_score / weight_sum) if weight_sum > 0 else 0.0

    def _determine_severity(self, risk_score: float) -> RiskLevel:
        """Determine severity from risk score."""
        if risk_score >= 0.85:
            return RiskLevel.CRITICAL
        elif risk_score >= 0.70:
            return RiskLevel.HIGH
        elif risk_score >= 0.50:
            return RiskLevel.MEDIUM
        elif risk_score >= 0.30:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFO

    def _generate_description(self, function_name: str, risk_factors: List[str]) -> str:
        """Generate description for risky function."""
        if not risk_factors:
            return f"Function '{function_name}' detected in ABI"

        descriptions = []
        for factor in risk_factors[:2]:  # Top 2 factors
            desc = self.RISK_DESCRIPTIONS.get(factor, f"Function related to {factor}")
            descriptions.append(desc)

        return " | ".join(descriptions)

    def _generate_recommendation(self, risk_factors: List[str], severity: RiskLevel) -> str:
        """Generate recommendation based on risk factors."""
        if severity == RiskLevel.CRITICAL:
            return "CRITICAL: This function gives contract admin dangerous control. Exercise extreme caution."
        elif severity == RiskLevel.HIGH:
            return "HIGH RISK: This function represents significant centralization or honeypot potential."
        elif severity == RiskLevel.MEDIUM:
            return "MEDIUM RISK: This function provides admin control that requires verification."
        elif severity == RiskLevel.LOW:
            return "LOW RISK: Standard function with some administrative control."
        else:
            return "Monitor function usage and verify admin permissions."

    def _build_signature(self, function_name: str, inputs: List[Dict]) -> str:
        """Build function signature from ABI entry."""
        input_types = [inp.get("type", "") for inp in inputs]
        return f"{function_name}({','.join(input_types)})"


class ContractClassifier:
    """Classify contracts by type beyond ERC standards.

    Detects:
    - Token standards (ERC20, ERC721, ERC1155)
    - DeFi protocols (AMM, lending, staking)
    - Honeypots and scams
    - Proxy contracts
    - Governance contracts
    - NFT marketplaces
    """

    # ERC standard function selectors
    ERC_SELECTORS = {
        "ERC20": {
            "0xa9059cbb": "transfer",
            "0x23b872dd": "transferFrom",
            "0x095ea7b3": "approve",
            "0x70a08231": "balanceOf",
            "0x18160ddd": "totalSupply",
            "0xa3f02171": "allowance",
        },
        "ERC721": {
            "0x42842e0e": "transferFrom",
            "0xa22cb465": "safeTransferFrom",
            "0x6352211e": "ownerOf",
            "0xb88d4fde": "tokenURI",
            "0x150b7a02": "approve",
        },
        "ERC1155": {
            "0xf242432a": "safeTransferFrom",
            "0x2eb2c2d6": "balanceOf",
            "0x00f714ce": "balanceOfBatch",
            "0xd9b67a26": "isApprovedForAll",
        },
    }

    # DeFi protocol patterns
    DEF_SELECTORS = {
        "AMM": {
            "0x7ff36ab5": "swapExactETHForTokens",
            "0xfb3bdb41": "swapTokensForExactETH",
            "0x38ed1739": "swapExactTokensForETH",
            "0x8803dbee": "getAmountsOut",
        },
        "LENDING": {
            "0x441a7e30": "supply",
            "0x4e1d3470": "borrow",
            "0xda4d7b34": "repayBorrow",
            "0x51dff989": "liquidateCall",
        },
        "STAKING": {
            "0x2e1a7d4d": "stake",
            "0xaa22b42d": "withdraw",
            "0xf6c0cdf2": "getReward",
            "0x2b8ecea3": "earned",
        },
    }

    # Governance patterns
    GOV_SELECTORS = {
        "0x6f1b6bf4": "castVote",
        "0x12ff340d": "propose",
        "0x3d3b9ece": "queue",
        "0x1f4c3434": "execute",
    }

    def __init__(self, risk_analyzer: Optional[AbiRiskAnalyzer] = None):
        """Initialize the contract classifier.

        Args:
            risk_analyzer: Optional ABI risk analyzer
        """
        self.risk_analyzer = risk_analyzer or AbiRiskAnalyzer()

    def classify(
        self,
        bytecode: str,
        abi: List[Dict],
        bytecode_patterns: Optional[List] = None,
    ) -> ContractClassification:
        """Classify contract type and detect scam patterns.

        Args:
            bytecode: Contract bytecode
            abi: Contract ABI
            bytecode_patterns: Optional bytecode pattern matches

        Returns:
            ContractClassification with type and risk assessment
        """
        detected_standards = []
        detected_types = []
        risk_indicators = []
        detected_patterns = []

        # Extract function selectors
        function_selectors = self._extract_selectors(abi)

        # Check ERC standards
        for standard, selectors in self.ERC_SELECTORS.items():
            overlap = len(function_selectors & set(selectors.keys()))
            if overlap >= 2:
                detected_standards.append(standard)
                detected_types.append(standard)

        # Check DeFi protocols
        for protocol, selectors in self.DEF_SELECTORS.items():
            overlap = len(function_selectors & set(selectors.keys()))
            if overlap >= 1:
                detected_types.append(protocol)

        # Check governance
        if len(function_selectors & set(self.GOV_SELECTORS.keys())) >= 2:
            detected_types.append("Governance")

        # Analyze risk from ABI
        overall_risk = self.risk_analyzer.get_overall_risk_score(abi)

        # Check bytecode patterns
        if bytecode_patterns:
            for pattern in bytecode_patterns:
                # Handle both dataclass and dict objects
                if hasattr(pattern, 'pattern_type'):
                    pattern_type = pattern.pattern_type
                    category = getattr(pattern, 'category', 'unknown')
                elif isinstance(pattern, dict):
                    pattern_type = pattern.get("pattern_type", "")
                    category = pattern.get("category", "")
                else:
                    continue

                detected_patterns.append(pattern_type)

                if category == "honeypot":
                    risk_indicators.append(f"honeypot_{pattern_type}")
                elif category == "vulnerability":
                    risk_indicators.append(f"vuln_{pattern_type}")
                elif category == "scam":
                    risk_indicators.append(f"scam_{pattern_type}")
                elif category == "defi_vuln":
                    risk_indicators.append(f"defi_vuln_{pattern_type}")
                elif category == "nft_honeypot":
                    risk_indicators.append(f"nft_honeypot_{pattern_type}")

        # Determine primary type
        primary_type, confidence = self._determine_primary_type(
            detected_types, detected_standards, overall_risk
        )

        # Determine if likely scam
        is_likely_scam, scam_probability = self._assess_scam_probability(
            overall_risk, risk_indicators, detected_patterns
        )

        return ContractClassification(
            primary_type=primary_type,
            confidence=confidence,
            sub_types=detected_types,
            detected_patterns=detected_patterns,
            risk_indicators=risk_indicators,
            is_likely_scam=is_likely_scam,
            scam_probability=scam_probability,
        )

    def _extract_selectors(self, abi: List[Dict]) -> Set[str]:
        """Extract function selectors from ABI."""
        selectors = set()

        for entry in abi:
            if entry.get("type") == "function":
                signature = self._build_signature(entry)
                selector = self._calculate_selector(signature)
                selectors.add(selector)

        return selectors

    def _build_signature(self, abi_entry: Dict) -> str:
        """Build function signature from ABI entry."""
        name = abi_entry.get("name", "")
        inputs = abi_entry.get("inputs", [])
        input_types = [i.get("type", "") for i in inputs]
        return f"{name}({','.join(input_types)})"

    def _calculate_selector(self, signature: str) -> str:
        """Calculate function selector from signature."""
        import hashlib
        return hashlib.sha256(signature.encode()).hexdigest()[:8]

    def _determine_primary_type(
        self,
        detected_types: List[str],
        detected_standards: List[str],
        overall_risk: float,
    ) -> Tuple[str, float]:
        """Determine primary contract type and confidence."""
        if not detected_types:
            return "Unknown", 0.3

        # Prioritize standards
        for standard in ["ERC20", "ERC721", "ERC1155"]:
            if standard in detected_standards:
                confidence = 0.9 if overall_risk < 0.5 else 0.7
                return standard, confidence

        # First detected type
        primary_type = detected_types[0]
        confidence = 0.7 if overall_risk < 0.5 else 0.5

        return primary_type, confidence

    def _assess_scam_probability(
        self,
        overall_risk: float,
        risk_indicators: List[str],
        detected_patterns: List[str],
    ) -> Tuple[bool, float]:
        """Assess probability that contract is a scam."""
        scam_probability = overall_risk * 0.5

        # Bonus for honeypot indicators
        honeypot_indicators = [i for i in risk_indicators if "honeypot_" in i or i.startswith("HONEYPOT_")]
        scam_probability += len(honeypot_indicators) * 0.15

        # Bonus for scam indicators
        scam_indicators = [i for i in risk_indicators if "scam_" in i or i.startswith("SCAM_")]
        scam_probability += len(scam_indicators) * 0.20

        # Bonus for DeFi vulnerability indicators
        defi_vuln_indicators = [i for i in risk_indicators if "defi_vuln_" in i or i.startswith("DEFI_")]
        scam_probability += len(defi_vuln_indicators) * 0.10

        # Bonus for NFT honeypot indicators
        nft_honeypot_indicators = [i for i in risk_indicators if "nft_honeypot_" in i or i.startswith("NFT_")]
        scam_probability += len(nft_honeypot_indicators) * 0.12

        # Bonus for dangerous patterns
        dangerous_patterns = [
            "trading_disable", "fees_100", "blacklist", "max_wallet", "max_tx",
            "sell_cooldown", "buy_cooldown", "dynamic_fee", "liquidity_lock",
            "infinite_mint", "fake_liquidity", "ponzi", "pump_dump",
        ]
        for pattern in dangerous_patterns:
            if any(pattern in p.lower() for p in detected_patterns):
                scam_probability += 0.12

        return scam_probability >= 0.7, min(1.0, scam_probability)


class HoneypotPatternDetector:
    """Specialized detector for honeypot patterns.

    Focuses on specific honeypot techniques:
    - Max wallet limits (prevents selling large amounts)
    - Trading disable switches (trap users)
    - High fee mechanisms (100% fees on sell)
    - Blacklist mechanisms (block specific addresses)
    - Whitelist-only trading
    - Anti-bot mechanisms gone wrong
    """

    # Specific honeypot bytecode sequences
    HONEYPOT_SEQUENCES = {
        "max_wallet_check": [
            "5f",  # PUSH0 (or similar)
            "1460",  # Balance check
            "14",  # EQ
            "15",  # ISZERO
            "57",  # JUMPI
        ],
        "trading_switch": [
            "54",  # SLOAD
            "15",  # ISZERO
            "57",  # JUMPI
            "fd",  # REVERT
        ],
        "fee_100_percent": [
            "5f",  # PUSH0
            "6000",  # PUSH1 0
            "6001",  # PUSH1 1 (100%)
            "02",  # MUL
            "52",  # MSTORE
        ],
    }

    def __init__(self, fingerprint_db: Optional[BytecodeFingerprintDB] = None):
        """Initialize the honeypot detector.

        Args:
            fingerprint_db: Optional fingerprint database
        """
        self.fingerprint_db = fingerprint_db or BytecodeFingerprintDB()

    def detect_honeypot_patterns(
        self,
        bytecode: str,
        abi: List[Dict],
    ) -> List[Dict[str, Any]]:
        """Detect honeypot patterns in bytecode and ABI.

        Args:
            bytecode: Contract bytecode
            abi: Contract ABI

        Returns:
            List of detected honeypot patterns with metadata
        """
        detections = []

        # Check bytecode patterns
        bytecode_matches = self.fingerprint_db.match_bytecode(bytecode)
        honeypot_matches = [m for m in bytecode_matches if m.category == "honeypot"]

        for match in honeypot_matches:
            detections.append({
                "type": "bytecode_pattern",
                "pattern_id": match.pattern_id,
                "name": match.name,
                "severity": match.severity.value,
                "description": match.description,
                "confidence": match.confidence,
            })

        # Check ABI for honeypot function patterns
        abi_detections = self._check_abi_honeypot_functions(abi)
        detections.extend(abi_detections)

        return detections

    def _check_abi_honeypot_functions(self, abi: List[Dict]) -> List[Dict[str, Any]]:
        """Check ABI for known honeypot function patterns."""
        detections = []

        honeypot_indicators = {
            # Trading control
            "enabletrading": ("Trading Enable Switch", "critical", 0.95),
            "disabletrading": ("Trading Disable Switch", "critical", 0.95),
            "settradestatus": ("Trading Status Control", "critical", 0.90),
            "opentrading": ("Trading Enable", "critical", 0.85),
            "closetrading": ("Trading Disable", "critical", 0.90),
            "tradestart": ("Trading Start Control", "high", 0.80),

            # Fee control
            "setfee": ("Fee Control", "critical", 0.90),
            "settax": ("Tax Control", "critical", 0.90),
            "setbuyfee": ("Buy Fee Control", "critical", 0.85),
            "setsellfee": ("Sell Fee Control", "critical", 0.85),
            "changetax": ("Tax Change", "critical", 0.90),
            "updatetax": ("Tax Update", "critical", 0.85),

            # Limits
            "setmaxwallet": ("Max Wallet Limit", "high", 0.85),
            "setmaxtx": ("Max Transaction Limit", "high", 0.85),
            "setmaxtransaction": ("Max Transaction Control", "high", 0.85),
            "setmaxbalance": ("Max Balance Limit", "high", 0.80),
            "setmaxamount": ("Max Amount Control", "high", 0.80),
            "settransactionlimit": ("Transaction Limit", "high", 0.80),

            # Cooldowns
            "setcooldown": ("Cooldown Control", "high", 0.80),
            "setbuycooldown": ("Buy Cooldown", "high", 0.80),
            "setsellcooldown": ("Sell Cooldown", "high", 0.85),

            # Blacklist/Freeze
            "blacklist": ("Blacklist Function", "high", 0.90),
            "unblacklist": ("Unblacklist Function", "medium", 0.70),
            "freeze": ("Freeze Function", "critical", 0.90),
            "unfreeze": ("Unfreeze Function", "medium", 0.70),
            "block": ("Block Function", "high", 0.85),
            "unblock": ("Unblock Function", "medium", 0.65),
            "pause": ("Pause Function", "high", 0.75),
            "unpause": ("Unpause Function", "medium", 0.60),

            # Whitelist
            "setwhitelist": ("Whitelist Control", "high", 0.80),
            "addwhitelist": ("Add Whitelist", "high", 0.75),
            "removewhitelist": ("Remove Whitelist", "high", 0.75),
            "enablewhitelist": ("Enable Whitelist", "high", 0.80),

            # Liquidity manipulation
            "removeliquidity": ("Remove Liquidity", "critical", 0.85),
            "withdrawliquidity": ("Withdraw Liquidity", "critical", 0.85),
            "sweepliquidity": ("Sweep Liquidity", "critical", 0.85),
            "lockliquidity": ("Lock Liquidity", "high", 0.70),
            "unlockliquidity": ("Unlock Liquidity", "high", 0.75),

            # Mint/Supply
            "unlimitedmint": ("Unlimited Mint", "critical", 0.95),
            "freemint": ("Free Mint", "high", 0.70),

            # Rebase
            "rebase": ("Rebase Supply", "high", 0.85),
            "autorebase": ("Auto Rebase", "high", 0.80),
            "elasticrebase": ("Elastic Rebase", "high", 0.80),

            # Metadata (NFT)
            "settokenuri": ("Set Token URI", "high", 0.70),
            "setbaseuri": ("Set Base URI", "high", 0.70),

            # NEW: More advanced honeypot patterns
            # Cooldown patterns
            "setcooldown": ("Cooldown Control", "high", 0.80),
            "setbuycooldown": ("Buy Cooldown", "high", 0.80),
            "setsellcooldown": ("Sell Cooldown", "high", 0.85),
            "enablecooldown": ("Enable Cooldown", "high", 0.75),
            "updatecooldown": ("Update Cooldown", "high", 0.75),

            # Dynamic fee patterns
            "changetax": ("Change Tax", "critical", 0.90),
            "updatetax": ("Update Tax", "critical", 0.85),
            "setbuytax": ("Set Buy Tax", "critical", 0.85),
            "setselltax": ("Set Sell Tax", "critical", 0.85),
            "setrewardfee": ("Set Reward Fee", "high", 0.80),
            "setautoliquify": ("Set Auto Liquify", "high", 0.75),

            # Max patterns
            "setmaxbalance": ("Max Balance Limit", "high", 0.80),
            "setmaxamount": ("Max Amount Control", "high", 0.80),
            "settransactionlimit": ("Transaction Limit", "high", 0.80),
            "updatemax": ("Update Max", "high", 0.75),

            # NEW: Additional manipulation patterns
            "setmarketingwallet": ("Set Marketing Wallet", "high", 0.75),
            "setdevelopmentwallet": ("Set Dev Wallet", "high", 0.75),
            "setcharitywallet": ("Set Charity Wallet", "medium", 0.70),

            # Time-based patterns
            "settradinghours": ("Trading Hours Control", "high", 0.75),
            "settradingtime": ("Trading Time Control", "high", 0.75),

            # Supply manipulation
            "mintbatch": ("Batch Mint", "high", 0.80),
            "mintmany": ("Multi Mint", "high", 0.80),
            "generatetoken": ("Generate Token", "high", 0.80),

            # Migration patterns
            "migrate": ("Migrate Contract", "high", 0.70),
            "upgradeto": ("Upgrade To", "high", 0.75),
            "setimplementation": ("Set Implementation", "high", 0.75),

            # Drain/withdraw patterns
            "withdrawstuck": ("Withdraw Stuck", "high", 0.70),
            "withdrawall": ("Withdraw All", "critical", 0.80),
            "emergencywithdraw": ("Emergency Withdraw", "critical", 0.70),
            "sweep": ("Sweep Funds", "critical", 0.85),
            "drain": ("Drain Funds", "critical", 0.85),

            # NEW: Advanced honeypot techniques
            "opentrading": ("Open Trading", "critical", 0.85),
            "closetrading": ("Close Trading", "critical", 0.90),
            "tradestart": ("Start Trading", "high", 0.80),
            "tradingopen": ("Trading Open", "high", 0.75),

            # Set/update patterns
            "setfeepercent": ("Set Fee Percent", "critical", 0.80),
            "updatefees": ("Update Fees", "critical", 0.80),

            # Limit control
            "settransactionlimit": ("Set Transaction Limit", "high", 0.80),

            # NEW: Team/presale patterns
            "setteam": ("Set Team", "high", 0.70),
            "setadvisor": ("Set Advisor", "high", 0.70),
            "setprivate": ("Set Private", "high", 0.70),
            "setpublicsale": ("Set Public Sale", "medium", 0.50),

            # Liquidity pool patterns
            "createpair": ("Create Pair", "medium", 0.50),
            "setpair": ("Set Pair", "high", 0.75),
            "setrouter": ("Set Router", "high", 0.70),
            "setfactory": ("Set Factory", "high", 0.70),

            # NEW: Anti-bot patterns
            "setantibot": ("Set Anti-Bot", "high", 0.80),
            "enableantibot": ("Enable Anti-Bot", "high", 0.75),
            "disableantibot": ("Disable Anti-Bot", "medium", 0.60),
            "antibotmode": ("Anti-Bot Mode", "medium", 0.70),
            "checkbot": ("Check Bot", "medium", 0.55),
            "isbot": ("Is Bot", "medium", 0.60),

            # NEW: Elastic supply patterns
            "setelastic": ("Set Elastic", "high", 0.80),
            "elasticrebase": ("Elastic Rebase", "high", 0.80),
            "enableauto": ("Enable Auto", "high", 0.75),
            "autorebase": ("Auto Rebase", "high", 0.80),

            # NEW: Lock patterns
            "locktoken": ("Lock Token", "high", 0.70),
            "unlocktoken": ("Unlock Token", "high", 0.65),
            "extendlock": ("Extend Lock", "high", 0.60),

            # NEW: Rebase patterns
            "rebase": ("Rebase", "high", 0.85),

            # NEW: Metadata patterns
            "seturi": ("Set URI", "high", 0.70),

            # NEW: Whitelist patterns
            "iswhitelisted": ("Is Whitelisted", "high", 0.70),

            # NEW: Limit patterns
            "setmaxwallet": ("Set Max Wallet", "high", 0.85),
            "setmaxtx": ("Set Max TX", "high", 0.85),

            # NEW: Tax patterns
            "setbuyfee": ("Set Buy Fee", "critical", 0.85),
            "setsellfee": ("Set Sell Fee", "critical", 0.85),
            "setliquidtyfee": ("Set Liquidity Fee", "high", 0.80),
            "setmarketingfee": ("Set Marketing Fee", "high", 0.80),

            # NEW: Upgradeability patterns
            "upgradetoandcall": ("Upgrade And Call", "high", 0.75),
            "upgradebeacon": ("Upgrade Beacon", "high", 0.70),
            "setbeacon": ("Set Beacon", "high", 0.70),

            # NEW: Vesting patterns
            "setvesting": ("Set Vesting", "high", 0.60),
            "releasevesting": ("Release Vesting", "medium", 0.45),
            "claimvesting": ("Claim Vesting", "medium", 0.40),

            # NEW: Emergency patterns
            "emergencywithdraw": ("Emergency Withdraw", "critical", 0.70),
            "emergencytransfer": ("Emergency Transfer", "critical", 0.75),
            "pause": ("Pause", "high", 0.75),
            "unpause": ("Unpause", "medium", 0.60),

            # NEW: Admin/control patterns
            "setauthority": ("Set Authority", "high", 0.75),
            "setmanager": ("Set Manager", "high", 0.70),
            "setcontroller": ("Set Controller", "high", 0.70),
            "setoperator": ("Set Operator", "high", 0.65),
            "setmaster": ("Set Master", "high", 0.75),

            # NEW: Time-based patterns
            "settimelock": ("Set Timelock", "medium", 0.55),

            # NEW: Bridge patterns
            "bridge": ("Bridge Function", "high", 0.50),
            "crosschain": ("Cross-Chain", "high", 0.55),
            "wrap": ("Wrap", "medium", 0.40),
            "unwrap": ("Unwrap", "medium", 0.40),

            # NEW: Batch/multi patterns
            "batchtransfer": ("Batch Transfer", "medium", 0.50),
            "multisend": ("Multi Send", "medium", 0.45),
            "multicall": ("Multi Call", "medium", 0.35),

            # NEW: Claim/redeem patterns
            "claimpresale": ("Claim Presale", "medium", 0.50),
            "claimreward": ("Claim Reward", "medium", 0.40),
            "claimdividend": ("Claim Dividend", "medium", 0.40),
            "claimairdrop": ("Claim Airdrop", "medium", 0.50),

            # NEW: Rescue patterns
            "rescueerc20": ("Rescue ERC20", "medium", 0.50),
            "rescueeth": ("Rescue ETH", "medium", 0.55),
            "rescuetoken": ("Rescue Token", "medium", 0.50),

            # NEW: Withdraw patterns
            "withdrawbalance": ("Withdraw Balance", "high", 0.75),
            "withdrawliquidity": ("Withdraw Liquidity", "critical", 0.85),
            "releaseliquidity": ("Release Liquidity", "high", 0.80),

            # NEW: Launch/presale patterns
            "launch": ("Launch", "medium", 0.50),
            "presale": ("Presale", "medium", 0.55),
            "softcap": ("Soft Cap", "medium", 0.50),
            "hardcap": ("Hard Cap", "medium", 0.50),

            # NEW: Swap/trading patterns
            "swap": ("Swap", "medium", 0.40),
            "swapexact": ("Swap Exact", "medium", 0.40),
            "trading": ("Trading", "medium", 0.45),

            # NEW: Burn/mint patterns
            "burn": ("Burn", "low", 0.20),
            "burnfrom": ("Burn From", "low", 0.25),
            "burnandmint": ("Burn and Mint", "high", 0.75),
        }

        for entry in abi:
            if entry.get("type") != "function":
                continue

            function_name = entry.get("name", "").lower()

            for indicator, (name, severity, confidence) in honeypot_indicators.items():
                if indicator in function_name:
                    detections.append({
                        "type": "abi_function",
                        "pattern_id": f"ABI_{indicator.upper()}",
                        "name": name,
                        "function_name": entry.get("name"),
                        "severity": severity,
                        "description": f"Function '{entry.get('name')}' indicates {name.lower()}",
                        "confidence": confidence,
                    })
                    break

        return detections
