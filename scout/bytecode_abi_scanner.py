"""Bytecode + ABI scanner for unverified smart contracts.

Analyzes contracts WITHOUT verified source code using:
- Tier 1: Quick pattern matching (bytecode fingerprints, ABI signatures, proxy detection)
- Tier 2: Full GLM analysis (via UnifiedGLMOrchestrator)

This enables security auditing for closed-source contracts.

Enhanced with:
- BytecodeFingerprintDB: Known vulnerability patterns
- AbiRiskAnalyzer: Enhanced risk scoring
- ContractClassifier: Type classification beyond ERC standards
- HoneypotPatternDetector: Specialized honeypot detection
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import httpx
from web3 import Web3

from scout.pattern_matching_enhanced import (
    AbiRiskAnalyzer,
    AbiRiskScore,
    BytecodeFingerprint,
    BytecodeFingerprintDB,
    ContractClassification,
    ContractClassifier,
    HoneypotPatternDetector,
)

LOGGER = logging.getLogger(__name__)


class ScanDepth(Enum):
    """Scan depth levels."""
    QUICK = "quick"  # Pattern matching only
    FULL = "full"  # Pattern matching + GLM analysis
    HYBRID = "hybrid"  # Quick first, full if issues found


@dataclass
class BytecodePatternMatch:
    """Result from bytecode pattern matching."""
    pattern_type: str  # "proxy", "reentrancy", "delegatecall", "selfdestruct", etc.
    severity: str  # "critical", "high", "medium", "low", "info"
    description: str
    bytecode_offset: Optional[int] = None
    confidence: float = 0.5  # 0-1
    recommendation: str = ""
    category: Optional[str] = None  # "honeypot", "vulnerability", "proxy", "standard", etc.

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern_type": self.pattern_type,
            "severity": self.severity,
            "description": self.description,
            "bytecode_offset": self.bytecode_offset,
            "confidence": self.confidence,
            "recommendation": self.recommendation,
        }


@dataclass
class AbiFunctionAnalysis:
    """Result from ABI function signature analysis."""
    function_signature: str
    risk_flags: List[str] = field(default_factory=list)
    severity: str = "info"
    description: str = ""
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "function_signature": self.function_signature,
            "risk_flags": self.risk_flags,
            "severity": self.severity,
            "description": self.description,
            "recommendation": self.recommendation,
        }


@dataclass
class ContractScanResult:
    """Complete contract scan result from bytecode+ABI analysis."""
    contract_address: str
    chain_id: int
    scan_depth: ScanDepth

    # Pattern matching results
    bytecode_patterns: List[BytecodePatternMatch] = field(default_factory=list)
    abi_analysis: List[AbiFunctionAnalysis] = field(default_factory=list)

    # Proxy detection
    is_proxy: bool = False
    proxy_type: Optional[str] = None  # "ERC1967", "UUPS", "Transparent", etc.
    implementation_address: Optional[str] = None

    # Contract type inference
    contract_type: str = "unknown"  # "ERC20", "ERC721", "Proxy", etc.
    detected_standards: List[str] = field(default_factory=list)

    # GLM analysis results (if full scan)
    glm_findings: List[Dict[str, Any]] = field(default_factory=list)

    # Overall assessment
    overall_score: float = 50.0  # 0-100
    risk_level: str = "medium"  # "low", "medium", "high", "critical"
    flags: List[str] = field(default_factory=list)

    # Metadata
    bytecode_hash: Optional[str] = None
    bytecode_size: int = 0
    analyzed_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "contract_address": self.contract_address,
            "chain_id": self.chain_id,
            "scan_depth": self.scan_depth.value,
            "bytecode_patterns": [p.to_dict() for p in self.bytecode_patterns],
            "abi_analysis": [a.to_dict() for a in self.abi_analysis],
            "is_proxy": self.is_proxy,
            "proxy_type": self.proxy_type,
            "implementation_address": self.implementation_address,
            "contract_type": self.contract_type,
            "detected_standards": self.detected_standards,
            "glm_findings": self.glm_findings,
            "overall_score": self.overall_score,
            "risk_level": self.risk_level,
            "flags": self.flags,
            "bytecode_hash": self.bytecode_hash,
            "bytecode_size": self.bytecode_size,
            "analyzed_at": self.analyzed_at,
        }


class BytecodeAbiScanner:
    """Analyzes unverified smart contracts using bytecode + ABI with GLM agents.

    Hybrid scan approach:
    - Tier 1 (Quick): Pattern matching for known vulnerability patterns
    - Tier 2 (Full): Full GLM analysis via UnifiedGLMOrchestrator

    Example:
        scanner = BytecodeAbiScanner(w3=Web3(), glm_orchestrator=orchestrator)

        # Quick scan
        result = await scanner.scan_unverified_contract(
            contract_address="0x...",
            chain_id=1,
            bytecode=bytecode_hex,
            abi=abi_json,
            scan_depth=ScanDepth.QUICK,
        )

        # Full hybrid scan
        result = await scanner.scan_unverified_contract(
            contract_address="0x...",
            chain_id=1,
            bytecode=bytecode_hex,
            abi=abi_json,
            scan_depth=ScanDepth.HYBRID,
        )
    """

    # Bytecode patterns for vulnerability detection
    # These are simplified EVM opcode patterns
    VULNERABILITY_PATTERNS = {
        "delegatecall_risk": {
            "opcodes": ["f4"],  # DELEGATECALL
            "severity": "high",
            "description": "Delegatecall detected - allows code execution in context of caller",
            "recommendation": "Ensure delegatecall targets are trusted and validated",
        },
        "selfdestruct_risk": {
            "opcodes": ["ff"],  # SELFDESTRUCT
            "severity": "critical",
            "description": "Selfdestruct detected - contract can be destroyed",
            "recommendation": "Ensure selfdestruct is properly access-controlled",
        },
        "call_risk": {
            "opcodes": ["f1"],  # CALL
            "severity": "medium",
            "description": "Low-level call detected - reentrancy risk if not handled properly",
            "recommendation": "Use ReentrancyGuard and checks-effects-interactions pattern",
        },
        "tx_origin_auth": {
            "opcodes": ["32", "34"],  # CALLVALUE + TX.ORIGIN
            "severity": "high",
            "description": "Potential tx.origin authentication detected",
            "recommendation": "Use msg.sender instead of tx.origin for authentication",
        },
        "block_timestamp": {
            "opcodes": ["43"],  # TIMESTAMP
            "severity": "low",
            "description": "Block timestamp dependency detected",
            "recommendation": "Be aware timestamp can be manipulated by miners",
        },
    }

    # Proxy detection patterns (ERC-1967, UUPS, etc.)
    PROXY_PATTERNS = {
        "ERC1967_ADMIN": {
            "slot": "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
            "type": "ERC1967",
        },
        "ERC1967_IMPLEMENTATION": {
            "slot": "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
            "type": "ERC1967",
        },
        "UUPS_UPGRADE_INTERFACE": {
            "selector": "49c576a7",  # upgradeToAndCall
            "type": "UUPS",
        },
        "TRANSPARENT_PROXY_LOGIC": {
            "selector": "8da5cb5b",  # admin()
            "type": "Transparent",
        },
    }

    # ERC standard function selectors
    ERC_SELECTORS = {
        "ERC20": {
            "0xa9059cbb": "transfer",
            "0x23b872dd": "transferFrom",
            "0x095ea7b3": "approve",
            "0x70a08231": "balanceOf",
            "0x18160ddd": "totalSupply",
        },
        "ERC721": {
            "0x42842e0e": "transferFrom",
            "0xa22cb465": "transferFrom",
            "0x6352211e": "ownerOf",
            "0xb88d4fde": "tokenURI",
        },
        "ERC1155": {
            "0xf242432a": "safeTransferFrom",
            "0x2eb2c2d6": "balanceOf",
            "0x00f714ce": "balanceOfBatch",
        },
        "ACCESS_CONTROL": {
            "0x5c19a95c": "hasRole",
            "0x2f2ff15d": "getRoleAdmin",
            "0x248a9ca3": "grantRole",
            "0x9cf2e2c9": "revokeRole",
        },
    }

    def __init__(
        self,
        w3: Web3,
        glm_orchestrator: Optional[Any] = None,  # UnifiedGLMOrchestrator
        fingerprint_db: Optional[BytecodeFingerprintDB] = None,
        risk_analyzer: Optional[AbiRiskAnalyzer] = None,
        classifier: Optional[ContractClassifier] = None,
        honeypot_detector: Optional[HoneypotPatternDetector] = None,
    ):
        """Initialize the bytecode+ABI scanner with enhanced pattern matching.

        Args:
            w3: Web3 instance for blockchain interactions
            glm_orchestrator: Optional GLM orchestrator for full scans
            fingerprint_db: Optional bytecode fingerprint database
            risk_analyzer: Optional ABI risk analyzer
            classifier: Optional contract classifier
            honeypot_detector: Optional honeypot pattern detector
        """
        self.w3 = w3
        self.glm_orchestrator = glm_orchestrator

        # Enhanced pattern matching components
        self.fingerprint_db = fingerprint_db or BytecodeFingerprintDB()
        self.risk_analyzer = risk_analyzer or AbiRiskAnalyzer()
        self.classifier = classifier or ContractClassifier(risk_analyzer=self.risk_analyzer)
        self.honeypot_detector = honeypot_detector or HoneypotPatternDetector(
            fingerprint_db=self.fingerprint_db
        )

        LOGGER.info(
            "BytecodeAbiScanner initialized with enhanced pattern matching: "
            f"{len(self.fingerprint_db._patterns)} fingerprints, "
            f"{len(self.risk_analyzer._risk_patterns)} risk patterns"
        )

    async def scan_unverified_contract(
        self,
        contract_address: str,
        chain_id: int,
        bytecode: str,
        abi: List[Dict],
        scan_depth: ScanDepth = ScanDepth.HYBRID,
    ) -> ContractScanResult:
        """Scan an unverified contract using bytecode + ABI.

        Args:
            contract_address: Contract address
            chain_id: Chain ID
            bytecode: Contract bytecode (hex string with 0x prefix)
            abi: Contract ABI (list of ABI entries)
            scan_depth: Scan depth (QUICK, FULL, or HYBRID)

        Returns:
            ContractScanResult with findings
        """
        LOGGER.info(
            f"Scanning unverified contract {contract_address} on chain {chain_id} "
            f"with depth {scan_depth.value}"
        )

        # Initialize result
        result = ContractScanResult(
            contract_address=contract_address,
            chain_id=chain_id,
            scan_depth=scan_depth,
            bytecode_hash=self._hash_bytecode(bytecode),
            bytecode_size=len(bytecode) // 2 if bytecode.startswith("0x") else len(bytecode),
        )

        # Tier 1: Enhanced pattern matching
        LOGGER.info("Running Tier 1: Enhanced pattern matching scan...")

        # Use enhanced fingerprint database for bytecode patterns
        result.bytecode_patterns = self._scan_bytecode_enhanced(bytecode)

        # Use enhanced risk analyzer for ABI analysis
        result.abi_analysis = self._analyze_abi_enhanced(abi)

        # Detect honeypot patterns
        honeypot_detections = self.honeypot_detector.detect_honeypot_patterns(
            bytecode, abi
        )
        if honeypot_detections:
            LOGGER.warning(f"Detected {len(honeypot_detections)} honeypot indicators")
            result.flags.extend([f"honeypot_{d['pattern_id']}" for d in honeypot_detections])

        # Detect proxy
        await self._detect_proxy(result, contract_address, bytecode, abi)

        # Use enhanced classifier for contract type detection
        classification = self.classifier.classify(
            bytecode, abi, result.bytecode_patterns
        )
        result.contract_type = classification.primary_type
        result.detected_standards = classification.sub_types

        # Add scam probability to flags
        if classification.is_likely_scam:
            result.flags.append(f"likely_scam_{int(classification.scam_probability * 100)}%")

        # Calculate initial score from patterns
        result.overall_score = self._calculate_pattern_score(result)
        result.risk_level = self._determine_risk_level(result.overall_score)
        result.flags = self._generate_flags(result)

        # Tier 2: Full GLM analysis (if requested or hybrid with issues)
        if scan_depth == ScanDepth.FULL or (scan_depth == ScanDepth.HYBRID and result.overall_score < 70):
            if self.glm_orchestrator:
                LOGGER.info("Running Tier 2: Full GLM analysis...")
                result.glm_findings = await self._run_glm_analysis(
                    contract_address, bytecode, abi, result
                )

                # Recalculate score with GLM findings
                result.overall_score = self._calculate_combined_score(result)
                result.risk_level = self._determine_risk_level(result.overall_score)

        LOGGER.info(
            f"Scan complete for {contract_address}: "
            f"score={result.overall_score:.1f}, risk={result.risk_level}"
        )

        return result

    def _hash_bytecode(self, bytecode: str) -> str:
        """Hash bytecode for caching."""
        clean_bytecode = bytecode[2:] if bytecode.startswith("0x") else bytecode
        return hashlib.sha256(bytes.fromhex(clean_bytecode)).hexdigest()

    def _scan_bytecode_patterns(self, bytecode: str) -> List[BytecodePatternMatch]:
        """Scan bytecode for known vulnerability patterns."""
        matches = []

        # Clean bytecode
        clean_bytecode = bytecode[2:] if bytecode.startswith("0x") else bytecode

        # Check each vulnerability pattern
        for pattern_name, pattern_info in self.VULNERABILITY_PATTERNS.items():
            for opcode in pattern_info["opcodes"]:
                # Find opcode occurrences
                offset = 0
                while True:
                    pos = clean_bytecode.lower().find(opcode, offset)
                    if pos == -1:
                        break

                    matches.append(BytecodePatternMatch(
                        pattern_type=pattern_name,
                        severity=pattern_info["severity"],
                        description=pattern_info["description"],
                        bytecode_offset=pos // 2,  # Convert to byte offset
                        confidence=0.6,
                        recommendation=pattern_info["recommendation"],
                    ))
                    offset = pos + len(opcode)

        # Deduplicate similar matches
        if matches:
            # Group by pattern type and keep highest severity
            grouped = {}
            for match in matches:
                if match.pattern_type not in grouped:
                    grouped[match.pattern_type] = match
                elif match.severity == "critical":
                    grouped[match.pattern_type] = match

            matches = list(grouped.values())

        return matches

    def _analyze_abi(self, abi: List[Dict]) -> List[AbiFunctionAnalysis]:
        """Analyze ABI function signatures for risk patterns."""
        analyses = []

        for entry in abi:
            if entry.get("type") != "function":
                continue

            function_name = entry.get("name", "")
            signature = self._get_function_signature(entry)

            # Check for risky functions
            risk_flags = []
            severity = "info"
            description = ""
            recommendation = ""

            # Check for sensitive functions
            if any(keyword in function_name.lower() for keyword in
                   ["admin", "owner", "only", "auth", "permission"]):
                risk_flags.append("admin_function")
                severity = "medium"
                description = f"{function_name} appears to be an admin/owner function"
                recommendation = "Ensure proper access control"

            # Check for external calls
            if any(keyword in function_name.lower() for keyword in
                   ["call", "send", "transfer", "withdraw"]):
                risk_flags.append("external_call")
                severity = "high" if severity == "info" else severity
                description = f"{function_name} performs external value transfer"
                recommendation = "Check for reentrancy protection"

            # Check for upgrade functions
            if any(keyword in function_name.lower() for keyword in
                   ["upgrade", "migrate", "implement"]):
                risk_flags.append("upgrade_function")
                severity = "critical"
                description = f"{function_name} can upgrade contract logic"
                recommendation = "Ensure upgrade is properly secured"

            # Check for mint/burn
            if any(keyword in function_name.lower() for keyword in
                   ["mint", "print", "issue"]):
                risk_flags.append("mint_function")
                severity = "medium"
                description = f"{function_name} can increase token supply"
                recommendation = "Check for supply limits and access control"

            if risk_flags:
                analyses.append(AbiFunctionAnalysis(
                    function_signature=signature,
                    risk_flags=risk_flags,
                    severity=severity,
                    description=description,
                    recommendation=recommendation,
                ))

        return analyses

    def _get_function_signature(self, abi_entry: Dict) -> str:
        """Get function signature from ABI entry."""
        name = abi_entry.get("name", "")
        inputs = abi_entry.get("inputs", [])
        input_types = [i.get("type", "") for i in inputs]
        return f"{name}({','.join(input_types)})"

    def _scan_bytecode_enhanced(self, bytecode: str) -> List[BytecodePatternMatch]:
        """Enhanced bytecode scanning using fingerprint database.

        Uses BytecodeFingerprintDB for known vulnerability patterns
        with better confidence scoring and metadata.

        Args:
            bytecode: Contract bytecode (hex string)

        Returns:
            List of BytecodePatternMatch objects
        """
        matches = []
        clean_bytecode = bytecode[2:].lower() if bytecode.startswith("0x") else bytecode.lower()

        # Use enhanced fingerprint database
        fingerprints = self.fingerprint_db.match_bytecode(bytecode)

        for fingerprint in fingerprints:
            # Find all occurrences of this pattern
            for signature in fingerprint.bytecode_signatures:
                offset = 0
                while True:
                    pos = clean_bytecode.find(signature, offset)
                    if pos == -1:
                        break

                    matches.append(BytecodePatternMatch(
                        pattern_type=fingerprint.pattern_id,
                        severity=fingerprint.severity.value,
                        description=fingerprint.description,
                        bytecode_offset=pos // 2,
                        confidence=fingerprint.confidence,
                        recommendation=f"Pattern: {fingerprint.name}",
                        category=fingerprint.category,
                    ))
                    offset = pos + len(signature)

        # Also run legacy pattern matching for backward compatibility
        legacy_matches = self._scan_bytecode_patterns(bytecode)

        # Merge and deduplicate
        all_matches = matches + legacy_matches
        if all_matches:
            # Group by pattern type and keep highest confidence
            grouped = {}
            for match in all_matches:
                if match.pattern_type not in grouped:
                    grouped[match.pattern_type] = match
                elif match.confidence > grouped[match.pattern_type].confidence:
                    grouped[match.pattern_type] = match

            all_matches = list(grouped.values())

        return all_matches

    def _analyze_abi_enhanced(self, abi: List[Dict]) -> List[AbiFunctionAnalysis]:
        """Enhanced ABI analysis using AbiRiskAnalyzer.

        Provides risk scoring (0-1 scale) for each function
        with detailed risk factors and recommendations.

        Args:
            abi: Contract ABI

        Returns:
            List of AbiFunctionAnalysis objects with enhanced scoring
        """
        # Use enhanced risk analyzer
        risk_scores = self.risk_analyzer.analyze_abi(abi)

        # Convert to AbiFunctionAnalysis format
        analyses = []
        for risk_score in risk_scores:
            analyses.append(AbiFunctionAnalysis(
                function_signature=risk_score.function_signature,
                risk_flags=risk_score.risk_factors,
                severity=risk_score.severity.value,
                description=risk_score.description,
                recommendation=risk_score.recommendation,
            ))

        return analyses

    async def _detect_proxy(
        self,
        result: ContractScanResult,
        contract_address: str,
        bytecode: str,
        abi: List[Dict],
    ) -> None:
        """Detect if contract is a proxy and extract implementation."""
        # Only check storage if w3 is available
        if self.w3 is not None:
            try:
                checksum_address = Web3.to_checksum_address(contract_address)

                # Check ERC-1967 proxy slots
                for slot_name, slot_info in self.PROXY_PATTERNS.items():
                    if "slot" in slot_info:
                        try:
                            slot_value = self.w3.eth.get_storage_at(
                                checksum_address,
                                int(slot_info["slot"], 16)
                            )
                            if slot_value != b"\x00" * 32:
                                result.is_proxy = True
                                result.proxy_type = slot_info["type"]
                                if "IMPLEMENTATION" in slot_name:
                                    result.implementation_address = "0x" + slot_value.hex()[-40:]
                                break
                        except Exception:
                            pass
            except Exception:
                # Invalid address or w3 issue, skip storage check
                pass

        # Check for proxy-like function selectors in ABI (works without w3)
        if not result.is_proxy:
            for entry in abi:
                if entry.get("type") == "function":
                    name = entry.get("name", "")
                    if name in ["admin", "implementation", "upgradeTo", "upgradeToAndCall"]:
                        result.is_proxy = True
                        if name == "upgradeToAndCall":
                            result.proxy_type = "UUPS"
                        else:
                            result.proxy_type = "Transparent"
                        break

    def _detect_contract_type(self, abi: List[Dict]) -> Tuple[str, List[str]]:
        """Detect contract type and implemented standards from ABI."""
        detected_standards = []
        function_selectors = set()

        # Extract function selectors
        for entry in abi:
            if entry.get("type") == "function":
                signature = self._get_function_signature(entry)
                selector = self._calculate_selector(signature)
                function_selectors.add(selector)

        # Check for ERC standards
        for standard, selectors in self.ERC_SELECTORS.items():
            overlap = len(function_selectors & set(selectors.keys()))
            if overlap >= 2:  # Require at least 2 matching functions
                detected_standards.append(standard)

        # Determine primary contract type
        if "ERC20" in detected_standards:
            contract_type = "ERC20"
        elif "ERC721" in detected_standards:
            contract_type = "ERC721"
        elif "ERC1155" in detected_standards:
            contract_type = "ERC1155"
        elif "ACCESS_CONTROL" in detected_standards:
            contract_type = "AccessControl"
        else:
            contract_type = "Custom"

        return contract_type, detected_standards

    def _calculate_selector(self, signature: str) -> str:
        """Calculate function selector from signature."""
        return Web3.keccak(text=signature).hex()[:8]

    def _calculate_pattern_score(self, result: ContractScanResult) -> float:
        """Calculate score from enhanced pattern matching results.

        Uses confidence-weighted scoring for more accurate risk assessment.
        """
        score = 100.0

        # Deduct for bytecode patterns (confidence-weighted)
        for pattern in result.bytecode_patterns:
            base_penalty = {
                "critical": 25,
                "high": 15,
                "medium": 8,
                "low": 3,
                "info": 0,
            }.get(pattern.severity, 5)

            # Apply confidence modifier
            confidence = max(0.3, min(1.0, pattern.confidence))
            adjusted_penalty = base_penalty * confidence
            score -= adjusted_penalty

        # Deduct for ABI risks (confidence-weighted)
        for abi_risk in result.abi_analysis:
            base_penalty = {
                "critical": 20,
                "high": 10,
                "medium": 5,
                "low": 2,
                "info": 0,
            }.get(abi_risk.severity, 5)

            # If risk_score is available (from enhanced analyzer), use it
            if hasattr(abi_risk, 'risk_score'):
                confidence = max(0.3, min(1.0, abi_risk.risk_score))
                adjusted_penalty = base_penalty * confidence * 1.5  # Risk scores are more accurate
            else:
                adjusted_penalty = base_penalty

            score -= adjusted_penalty

        # Bonus for detected standards (shows likely legitimate contract)
        score += len(result.detected_standards) * 2

        # Proxy penalty/reward
        if result.is_proxy:
            if result.proxy_type in ["ERC1967", "UUPS"]:
                score -= 5  # Modern proxy patterns are safer
            else:
                score -= 10  # Unknown proxy patterns are riskier

        # Additional penalties for specific scam indicators
        for flag in result.flags:
            if flag.startswith("likely_scam_"):
                # Extract percentage from flag like "likely_scam_85%"
                try:
                    scam_pct = int(flag.split("_")[2].replace("%", ""))
                    score -= scam_pct * 0.3
                except (ValueError, IndexError):
                    score -= 15
            elif flag.startswith("honeypot_"):
                score -= 20
            elif flag.startswith("scam_"):
                score -= 25  # Scam patterns are very dangerous
            elif flag.startswith("defi_vuln_"):
                score -= 15  # DeFi vulnerabilities are high risk
            elif flag.startswith("nft_honeypot_"):
                score -= 18  # NFT honeypots are high risk

        return max(0, min(100, score))

    def _calculate_combined_score(self, result: ContractScanResult) -> float:
        """Calculate combined score from patterns and GLM findings."""
        # Start with pattern score
        score = self._calculate_pattern_score(result)

        # Apply GLM findings
        for finding in result.glm_findings:
            severity = finding.get("severity", "info").lower()
            if severity == "critical":
                score -= 20
            elif severity == "high":
                score -= 12
            elif severity == "medium":
                score -= 6
            elif severity == "low":
                score -= 2

        return max(0, min(100, score))

    def _determine_risk_level(self, score: float) -> str:
        """Determine risk level from score."""
        if score >= 80:
            return "low"
        elif score >= 60:
            return "medium"
        elif score >= 40:
            return "high"
        else:
            return "critical"

    def _generate_flags(self, result: ContractScanResult) -> List[str]:
        """Generate risk flags from analysis."""
        flags = []

        # Pattern flags
        for pattern in result.bytecode_patterns:
            flag = f"{pattern.pattern_type}_detected"
            if flag not in flags:
                flags.append(flag)

        # ABI flags
        for abi_risk in result.abi_analysis:
            flags.extend(abi_risk.risk_flags)

        # Proxy flags
        if result.is_proxy:
            flags.append(f"proxy_{result.proxy_type.lower() if result.proxy_type else 'unknown'}")

        # Standard flags
        for standard in result.detected_standards:
            flags.append(standard.lower() + "_detected")

        return flags

    async def _run_glm_analysis(
        self,
        contract_address: str,
        bytecode: str,
        abi: List[Dict],
        result: ContractScanResult,
    ) -> List[Dict[str, Any]]:
        """Run GLM analysis for bytecode+ABI via unified orchestrator."""
        if not self.glm_orchestrator:
            LOGGER.warning("GLM orchestrator not available, skipping Tier 2 analysis")
            return []

        try:
            # Prepare context for GLM analysis
            context = self._build_glm_context(contract_address, bytecode, abi, result)

            # Call GLM orchestrator with bytecode+ABI input type
            findings = await self.glm_orchestrator.analyze_contract(
                contract_address=contract_address,
                input_type="BYTECODE_ABI",
                data=(bytecode, abi, context),
            )

            return findings

        except Exception as e:
            LOGGER.error(f"GLM analysis failed: {e}")
            return []

    def _build_glm_context(
        self,
        contract_address: str,
        bytecode: str,
        abi: List[Dict],
        result: ContractScanResult,
    ) -> Dict[str, Any]:
        """Build context dict for GLM analysis."""
        return {
            "contract_address": contract_address,
            "contract_type": result.contract_type,
            "detected_standards": result.detected_standards,
            "is_proxy": result.is_proxy,
            "proxy_type": result.proxy_type,
            "bytecode_size": result.bytecode_size,
            "pattern_findings": [p.to_dict() for p in result.bytecode_patterns],
            "abi_findings": [a.to_dict() for a in result.abi_analysis],
            "function_count": len([e for e in abi if e.get("type") == "function"]),
            "event_count": len([e for e in abi if e.get("type") == "event"]),
        }
