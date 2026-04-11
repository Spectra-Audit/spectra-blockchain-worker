"""Unified smart contract audit service.

Consolidates all audit capabilities into a single service:
- Verified contract audits (source code available)
- Unverified contract audits (bytecode + ABI only)
- Token distribution analysis
- Liquidity analysis
- Tokenomics analysis

Minimizes external API calls by:
- Using on-chain data where possible
- Caching results in SQLite database
- Batch processing multiple contracts
- Avoiding duplicate API calls across scouts
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from web3 import Web3

from scout.bytecode_abi_scanner import (
    BytecodeAbiScanner,
    ContractScanResult,
    ScanDepth,
)
from scout.contract_audit_scout import (
    BlockExplorerClient,
    ContractAuditResult,
    ContractAuditScout,
)
from scout.claude_orchestrator import (
    ClaudeCodeOrchestrator,
    ClaudeAgentFinding,
)

LOGGER = logging.getLogger(__name__)


@dataclass
class UnifiedAuditRequest:
    """Request for unified audit."""
    project_id: str
    token_address: str
    chain_id: int
    audit_types: List[str] = field(default_factory=list)  # ["code", "distribution", "liquidity", "tokenomics"]
    force: bool = False
    abi: Optional[List[Dict]] = None  # Optional ABI for unverified contracts


@dataclass
class UnifiedAuditResult:
    """Complete unified audit result."""
    project_id: str
    token_address: str
    chain_id: int

    # Code audit results
    code_audit: Optional[Dict[str, Any]] = None  # From ContractAuditScout or BytecodeAbiScanner

    # Other analysis results
    distribution_metrics: Optional[Dict[str, Any]] = None
    liquidity_metrics: Optional[Dict[str, Any]] = None
    tokenomics_metrics: Optional[Dict[str, Any]] = None

    # Overall assessment
    overall_score: float = 50.0  # 0-100
    risk_level: str = "medium"
    flags: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    # Metadata
    completed_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class UnifiedAuditService:
    """Unified smart contract audit service.

    Handles all audit types through a single interface:
    - Verified contract audits (via ContractAuditScout)
    - Unverified contract audits (via BytecodeAbiScanner)
    - Token distribution analysis (delegates to TokenHolderScout)
    - Liquidity analysis (delegates to LiquidityAnalyzerScout)
    - Tokenomics analysis (delegates to TokenomicsAnalyzerScout)

    Key Features:
    - Single entry point for all audits
    - Automatic detection of verified vs unverified contracts
    - Shared GLM orchestrator for all AI analysis
    - Cached results to avoid duplicate API calls
    - Batch processing support

    Example:
        service = UnifiedAuditService(
            database=database,
            w3=w3,
            backend_client=backend_client,
        )

        # Full audit (automatically detects verified/unverified)
        result = await service.run_unified_audit(
            project_id="uuid",
            token_address="0x...",
            chain_id=1,
        )

        # Specific audit types
        result = await service.run_unified_audit(
            project_id="uuid",
            token_address="0x...",
            chain_id=1,
            audit_types=["code", "liquidity"],
        )
    """

    def __init__(
        self,
        database: Any,  # DatabaseManager
        w3: Web3,
        backend_client: Any,  # BackendClient
        claude_orchestrator: Optional[ClaudeCodeOrchestrator] = None,
        token_holder_scout: Optional[Any] = None,  # TokenHolderScout
        liquidity_analyzer_scout: Optional[Any] = None,  # LiquidityAnalyzerScout
        tokenomics_analyzer_scout: Optional[Any] = None,  # TokenomicsAnalyzerScout
    ):
        """Initialize the unified audit service.

        Args:
            database: Database manager for caching
            w3: Web3 instance for blockchain interactions
            backend_client: Backend API client
            claude_orchestrator: Claude Code orchestrator for AI analysis (with GLM API)
            token_holder_scout: Optional token holder scout
            liquidity_analyzer_scout: Optional liquidity analyzer scout
            tokenomics_analyzer_scout: Optional tokenomics analyzer scout
        """
        self.database = database
        self.w3 = w3
        self.backend_client = backend_client

        # Initialize claude-code orchestrator (primary method for AI-powered audits)
        self.claude_orchestrator = claude_orchestrator or ClaudeCodeOrchestrator()

        # Initialize scanners (pattern matching for unverified contracts)
        # The BytecodeAbiScanner uses bytecode fingerprints and ABI analysis
        self.bytecode_scanner = BytecodeAbiScanner(
            w3=w3,
            glm_orchestrator=None,  # Using ClaudeCodeOrchestrator instead
        )

        # Use existing ContractAuditScout for verified contracts
        # Now uses ClaudeCodeOrchestrator for AI-powered audits via claude-code CLI
        self.contract_audit_scout = ContractAuditScout(
            database=database,
            w3=w3,
            glm_orchestrator=None,  # Deprecated - using claude_orchestrator instead
            claude_orchestrator=self.claude_orchestrator,
            explorer_client=BlockExplorerClient(),
        )

        # Optional analyzers for other data types
        self.token_holder_scout = token_holder_scout
        self.liquidity_analyzer_scout = liquidity_analyzer_scout
        self.tokenomics_analyzer_scout = tokenomics_analyzer_scout

    async def run_unified_audit(
        self,
        project_id: str,
        token_address: str,
        chain_id: int,
        audit_types: Optional[List[str]] = None,
        force: bool = False,
        abi: Optional[List[Dict]] = None,
    ) -> UnifiedAuditResult:
        """Run unified audit for a project.

        Automatically detects whether contract is verified and routes to
        appropriate scanner.

        Args:
            project_id: Project ID
            token_address: Token contract address
            chain_id: Chain ID
            audit_types: List of audit types to run (default: all)
            force: Force re-audit even if cached
            abi: Optional ABI for unverified contracts

        Returns:
            UnifiedAuditResult with all findings
        """
        if audit_types is None:
            audit_types = ["code", "distribution", "liquidity", "tokenomics"]

        LOGGER.info(
            f"Running unified audit for {project_id}: "
            f"{token_address} on chain {chain_id}"
        )

        result = UnifiedAuditResult(
            project_id=project_id,
            token_address=token_address,
            chain_id=chain_id,
        )

        # Step 1: Check if contract is verified
        is_verified = await self._is_contract_verified(token_address, chain_id)

        # Step 2: Run code audit
        if "code" in audit_types:
            LOGGER.info(f"Contract verification status: {is_verified}")
            if is_verified:
                result.code_audit = await self._audit_verified_contract(
                    token_address, chain_id, force
                )
            else:
                result.code_audit = await self._audit_unverified_contract(
                    token_address, chain_id, abi, force
                )

        # Step 3: Run other audits if scouts available
        if "distribution" in audit_types and self.token_holder_scout:
            result.distribution_metrics = await self._get_token_distribution(
                token_address, chain_id, force
            )

        if "liquidity" in audit_types and self.liquidity_analyzer_scout:
            result.liquidity_metrics = await self._get_liquidity_analysis(
                token_address, chain_id, force
            )

        if "tokenomics" in audit_types and self.tokenomics_analyzer_scout:
            result.tokenomics_metrics = await self._get_tokenomics_analysis(
                token_address, chain_id, force
            )

        # Step 4: Calculate overall score and recommendations
        result.overall_score = self._calculate_overall_score(result)
        result.risk_level = self._determine_risk_level(result.overall_score)
        result.flags = self._aggregate_flags(result)
        result.recommendations = self._generate_recommendations(result)

        # Step 5: Store to backend
        await self._store_result(result)

        LOGGER.info(
            f"Unified audit complete for {project_id}: "
            f"score={result.overall_score:.1f}, risk={result.risk_level}"
        )

        return result

    async def _is_contract_verified(
        self,
        token_address: str,
        chain_id: int,
    ) -> bool:
        """Check if contract has verified source code."""
        try:
            source_info = await self.contract_audit_scout.explorer_client.get_source_code(
                token_address, chain_id
            )
            return source_info is not None and source_info.get("source_code")
        except Exception as e:
            LOGGER.debug(f"Failed to check verification status: {e}")
            return False

    async def _audit_verified_contract(
        self,
        token_address: str,
        chain_id: int,
        force: bool,
    ) -> Dict[str, Any]:
        """Audit a verified contract using source code.

        Process:
        1. Run ContractAuditScout for basic audit (may include some AI analysis)
        2. If verified, run ClaudeCodeOrchestrator for comprehensive claude-code CLI analysis
        3. Combine findings and recalculate score
        4. Return legible, structured results for frontend
        """
        LOGGER.info(f"Auditing verified contract {token_address}")

        # Step 1: Run ContractAuditScout for initial audit
        contract_result = await self.contract_audit_scout.audit_contract(
            token_address=token_address,
            chain_id=chain_id,
            force=force,
        )

        # Step 2: If verified, run comprehensive claude-code CLI analysis
        if contract_result.is_verified and contract_result.ai_audit_enabled:
            try:
                # Get source code for claude-code analysis
                source_info = await self.contract_audit_scout.explorer_client.get_source_code(
                    token_address, chain_id
                )
                if source_info and source_info.get("source_code"):
                    LOGGER.info(f"Running claude-code CLI analysis for {token_address}")

                    # Run claude-code CLI with custom security agents
                    claude_findings = await self.claude_orchestrator.analyze_contract(
                        contract_address=token_address,
                        input_type="SOURCE_CODE",
                        data=source_info["source_code"],
                    )

                    # Step 3: Convert and merge claude findings with existing findings
                    # Convert ClaudeAgentFinding to dict format for frontend
                    contract_name = source_info.get("contract_name", "")
                    source_code = source_info.get("source_code", "")
                    short_addr = token_address[:10] + "..." if token_address else ""

                    for finding in claude_findings:
                        finding_dict = finding.to_dict()

                        # Populate location fallback when the AI agent did not
                        # return a specific code location.  Use
                        #   ContractName:line_number  if available, otherwise
                        #   ContractName:functionName  from description, or  0xAddr...
                        if not finding_dict.get("location"):
                            desc = finding_dict.get("description", "")
                            # Try to extract function name from description
                            fn_match = re.search(r'(?:function\s+)(\w+)', desc)
                            fn_name = fn_match.group(1) if fn_match else finding.category
                            if contract_name:
                                finding_dict["location"] = (
                                    f"{contract_name}:{fn_name}()"
                                )
                            else:
                                finding_dict["location"] = short_addr

                        # Enrich with code snippet, location detail, and highlight
                        self._enrich_finding_with_snippet(
                            finding_dict, source_code, contract_name, is_verified=True
                        )

                        contract_result.ai_audit_findings.append(finding_dict)

                    # Recalculate score with combined findings
                    contract_result.overall_score = (
                        self.contract_audit_scout._calculate_score(
                            [self._dict_to_finding(f) for f in contract_result.ai_audit_findings],
                            is_verified=True,
                        )
                    )
                    contract_result.risk_level = (
                        self.contract_audit_scout._determine_risk_level(
                            contract_result.overall_score
                        )
                    )

                    LOGGER.info(
                        f"Claude-code CLI analysis complete: {len(claude_findings)} findings, "
                        f"new score: {contract_result.overall_score:.1f}, "
                        f"risk level: {contract_result.risk_level}"
                    )

            except Exception as e:
                LOGGER.error(f"Claude-code CLI analysis failed: {e}")
                # Continue with basic audit results

        result_dict = contract_result.to_dict()
        LOGGER.info(f"Audit result keys: {list(result_dict.keys())}")
        LOGGER.info(f"Audit result overall_score: {result_dict.get('overall_score')}")
        return result_dict

    def _dict_to_finding(self, d: Dict) -> Any:
        """Convert dict back to AgentFinding for score calculation.

        The frontend expects findings in dict format, but score calculation
        requires AgentFinding objects. This method converts between formats.
        """
        from scout.contract_audit_scout import AgentFinding
        return AgentFinding(
            agent_name=d.get("agent_name", ""),
            severity=d.get("severity", "info"),
            category=d.get("category", ""),
            description=d.get("description", ""),
            location=d.get("location"),
            recommendation=d.get("recommendation", ""),
            confidence=d.get("confidence", "medium"),
        )

    # ------------------------------------------------------------------
    # Code-snippet enrichment helpers
    # ------------------------------------------------------------------

    def _parse_location(self, location: str, default_contract_name: str) -> dict:
        """Parse a location string into structured components.

        Supported patterns:
        - ``"ContractName:142"``
        - ``"ContractName:functionName()"``
        - ``"functionName()"``
        - bare string (returned as-is with default contract name)
        """
        result: dict = {"contract_name": default_contract_name}

        if not location:
            return result

        # "ContractName:lineNumber"
        match = re.match(r"^(.+?):(\d+)$", location.strip())
        if match:
            result["contract_name"] = match.group(1)
            result["line_number"] = int(match.group(2))
            return result

        # "ContractName:functionName()"  (may contain args inside parens)
        match = re.match(r"^(.+?):(\w+)\(.*\)$", location.strip())
        if match:
            result["contract_name"] = match.group(1)
            result["function_name"] = match.group(2)
            return result

        # "functionName()" alone
        match = re.match(r"^(\w+)\(.*\)$", location.strip())
        if match:
            result["function_name"] = match.group(1)
            return result

        return result

    def _extract_function_snippet(
        self,
        source_code: str,
        function_name: Optional[str] = None,
        line_number: Optional[int] = None,
    ) -> Optional[str]:
        """Extract the relevant function body from Solidity source code.

        Strategy 1: locate by ``function_name``.
        Strategy 2: locate by ``line_number`` (context window around the line).
        """
        if not source_code:
            return None

        lines = source_code.split("\n")

        # Strategy 1 — match by function / modifier / event / error name
        if function_name:
            pattern = rf"(?:function|modifier|event|error)\s+{re.escape(function_name)}\b"
            for i, line in enumerate(lines):
                if re.search(pattern, line):
                    return self._extract_block(lines, i)

        # Strategy 2 — context around the target line number (1-based)
        if line_number and 0 < line_number <= len(lines):
            start = max(0, line_number - 10)
            return self._extract_block(lines, start)

        return None

    def _extract_block(self, lines: list, start_line: int) -> Optional[str]:
        """Extract a braced code block starting from *start_line*.

        Walks forward counting braces until the block closes.  Returns at most
        50 lines as a safety limit.
        """
        brace_count = 0
        found_open = False
        snippet_lines: list = []
        max_lines = 50

        for i in range(start_line, min(len(lines), start_line + max_lines)):
            line = lines[i]
            snippet_lines.append(line)
            brace_count += line.count("{") - line.count("}")
            if "{" in line:
                found_open = True
            if found_open and brace_count <= 0:
                break

        return "\n".join(snippet_lines) if snippet_lines else None

    def _compute_highlight(self, snippet: str, description: str) -> tuple:
        """Return ``(highlight_start, highlight_end)`` char offsets.

        Picks the line inside *snippet* whose identifiers best overlap with
        keywords extracted from *description*.
        """
        if not snippet:
            return (0, 0)

        # Tokenise description and filter common English words
        keywords = re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", description)
        common = {
            "the", "a", "an", "is", "are", "was", "were", "be", "been",
            "being", "have", "has", "had", "do", "does", "did", "will",
            "would", "could", "should", "may", "might", "must", "shall",
            "can", "need", "dare", "to", "of", "in", "for", "on", "with",
            "at", "by", "from", "as", "into", "through", "during", "before",
            "after", "above", "below", "between", "and", "but", "or", "nor",
            "not", "so", "yet", "both", "either", "neither", "each", "every",
            "all", "any", "few", "more", "most", "other", "some", "such",
            "no", "only", "own", "same", "than", "too", "very", "just",
            "because", "this", "that", "these", "those", "it", "its", "if",
            "else", "when", "where", "which", "who", "whom", "what", "how",
            "function", "contract", "should", "recommendation",
        }
        keywords = [k for k in keywords if k.lower() not in common and len(k) > 2][:5]

        lines = snippet.split("\n")
        best_line = 0
        best_score = 0

        for i, line in enumerate(lines):
            score = sum(1 for kw in keywords if kw in line)
            if score > best_score:
                best_score = score
                best_line = i

        # Calculate char offsets for the best-matching line
        char_offset = sum(len(lines[j]) + 1 for j in range(best_line))
        line_text = lines[best_line] if best_line < len(lines) else ""

        if best_score > 0:
            return (char_offset, char_offset + len(line_text))

        # Fallback: highlight first non-empty, non-comment line
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped and not stripped.startswith("//") and not stripped.startswith("/*"):
                offset = sum(len(lines[j]) + 1 for j in range(i))
                return (offset, offset + len(line))

        return (0, 0)

    def _enrich_finding_with_snippet(
        self,
        finding_dict: dict,
        source_code: str,
        contract_name: str,
        is_verified: bool,
    ) -> dict:
        """Add ``code_snippet``, ``location_detail`` and highlight offsets."""
        location = finding_dict.get("location", "")

        parsed = self._parse_location(location, contract_name)

        finding_dict["location_detail"] = {
            "contract_name": parsed["contract_name"],
            "line_number": parsed.get("line_number"),
            "function_name": parsed.get("function_name"),
            "is_verified": is_verified,
        }

        if not is_verified or not source_code:
            finding_dict["code_snippet"] = None
            finding_dict["highlight_start"] = None
            finding_dict["highlight_end"] = None
            return finding_dict

        snippet = self._extract_function_snippet(
            source_code,
            parsed.get("function_name"),
            parsed.get("line_number"),
        )
        finding_dict["code_snippet"] = snippet

        if snippet:
            hl_start, hl_end = self._compute_highlight(
                snippet, finding_dict.get("description", "")
            )
            finding_dict["highlight_start"] = hl_start
            finding_dict["highlight_end"] = hl_end
        else:
            finding_dict["highlight_start"] = None
            finding_dict["highlight_end"] = None

        return finding_dict

    async def _audit_unverified_contract(
        self,
        token_address: str,
        chain_id: int,
        abi: Optional[List[Dict]],
        force: bool,
    ) -> Dict[str, Any]:
        """Audit an unverified contract using bytecode+ABI."""
        LOGGER.info(f"Auditing unverified contract {token_address}")

        # Get bytecode
        checksum_address = Web3.to_checksum_address(token_address)
        bytecode = self.w3.eth.get_code(checksum_address).hex()

        if not bytecode or bytecode == "0x":
            return {
                "error": "No bytecode found",
                "token_address": token_address,
                "chain_id": str(chain_id),
                "overall_score": 0,
                "risk_level": "critical",
            }

        # If ABI not provided, try to fetch from explorer
        if not abi:
            try:
                source_info = await self.contract_audit_scout.explorer_client.get_source_code(
                    token_address, chain_id
                )
                if source_info and source_info.get("abi"):
                    abi_str = source_info["abi"]
                    if isinstance(abi_str, str):
                        abi = json.loads(abi_str)
                    else:
                        abi = abi_str
            except Exception as e:
                LOGGER.debug(f"Could not fetch ABI: {e}")

        # Use BytecodeAbiScanner for hybrid scan
        scan_result = await self.bytecode_scanner.scan_unverified_contract(
            contract_address=token_address,
            chain_id=chain_id,
            bytecode=bytecode,
            abi=abi or [],
            scan_depth=ScanDepth.HYBRID,
        )

        return scan_result.to_dict()

    async def _get_token_distribution(
        self,
        token_address: str,
        chain_id: int,
        force: bool,
    ) -> Optional[Dict[str, Any]]:
        """Get token holder distribution metrics."""
        if not self.token_holder_scout:
            return None

        try:
            data = await self.token_holder_scout.collect_and_store(
                token_address=token_address,
                chain_id=chain_id,
                force=force,
            )

            if data:
                return {
                    "provider": data.get("provider"),
                    "holder_count": data.get("holder_count"),
                    "metrics": data.get("metrics"),
                    "collected_at": datetime.utcnow().isoformat(),
                }
        except Exception as e:
            LOGGER.error(f"Token distribution collection failed: {e}")

        return None

    async def _get_liquidity_analysis(
        self,
        token_address: str,
        chain_id: int,
        force: bool,
    ) -> Optional[Dict[str, Any]]:
        """Get liquidity analysis metrics."""
        if not self.liquidity_analyzer_scout:
            return None

        try:
            chain_str = "ethereum" if chain_id == 1 else str(chain_id)
            result = await self.liquidity_analyzer_scout.analyze_liquidity(
                token_address=token_address,
                chain_id=chain_str,
            )

            return {
                "score": result.score,
                "risk_level": result.risk_level,
                "metrics": result.metrics.__dict__ if hasattr(result.metrics, '__dict__') else result.metrics,
                "recommendations": result.recommendations,
                "analyzed_at": result.analyzed_at,
            }
        except Exception as e:
            LOGGER.error(f"Liquidity analysis failed: {e}")

        return None

    async def _get_tokenomics_analysis(
        self,
        token_address: str,
        chain_id: int,
        force: bool,
    ) -> Optional[Dict[str, Any]]:
        """Get tokenomics analysis metrics."""
        if not self.tokenomics_analyzer_scout:
            return None

        try:
            chain_str = "ethereum" if chain_id == 1 else str(chain_id)
            result = await self.tokenomics_analyzer_scout.analyze_tokenomics(
                token_address=token_address,
                chain_id=chain_str,
            )

            return {
                "score": result.score,
                "risk_level": result.risk_level,
                "metrics": result.metrics.__dict__ if hasattr(result.metrics, '__dict__') else result.metrics,
                "recommendations": result.recommendations,
                "analyzed_at": result.analyzed_at,
            }
        except Exception as e:
            LOGGER.error(f"Tokenomics analysis failed: {e}")

        return None

    def _calculate_overall_score(self, result: UnifiedAuditResult) -> float:
        """Calculate overall score from all audit results."""
        scores = []

        # Code audit score (highest weight)
        if result.code_audit:
            scores.append(("code", result.code_audit.get("overall_score", 50), 0.4))

        # Distribution score (blended Gini + Nakamoto)
        if result.distribution_metrics:
            metrics = result.distribution_metrics.get("metrics", {})
            gini = metrics.get("gini_coefficient", 1.0)
            nakamoto = metrics.get("nakamoto_coefficient", 0)

            gini_score = max(0, 100 - (gini * 100))
            # Nakamoto scaling: score = min(nakamoto * 5, 100), so nakamoto=20 -> 100
            nakamoto_score = min(nakamoto * 5, 100)

            alpha = 0.6
            dist_score = alpha * gini_score + (1 - alpha) * nakamoto_score
            dist_score = max(0, min(100, dist_score))
            scores.append(("distribution", dist_score, 0.2))

        # Liquidity score
        if result.liquidity_metrics:
            scores.append(("liquidity", result.liquidity_metrics.get("score", 50), 0.2))

        # Tokenomics score
        if result.tokenomics_metrics:
            scores.append(("tokenomics", result.tokenomics_metrics.get("score", 50), 0.2))

        # Calculate weighted average
        if scores:
            total_weight = sum(weight for _, _, weight in scores)
            weighted_sum = sum(score * weight for _, score, weight in scores)
            return weighted_sum / total_weight

        return 50.0

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

    def _aggregate_flags(self, result: UnifiedAuditResult) -> List[str]:
        """Aggregate flags from all audit results."""
        flags = []

        if result.code_audit:
            flags.extend(result.code_audit.get("flags", []))

        if result.liquidity_metrics:
            metrics = result.liquidity_metrics.get("metrics", {})
            if hasattr(metrics, 'flags'):
                flags.extend(metrics.flags)
            elif isinstance(metrics, dict):
                flags.extend(metrics.get("flags", []))

        if result.tokenomics_metrics:
            metrics = result.tokenomics_metrics.get("metrics", {})
            if hasattr(metrics, 'flags'):
                flags.extend(metrics.flags)
            elif isinstance(metrics, dict):
                flags.extend(metrics.get("flags", []))

        # Deduplicate
        seen = set()
        unique_flags = []
        for flag in flags:
            if flag not in seen:
                seen.add(flag)
                unique_flags.append(flag)

        return unique_flags

    def _generate_recommendations(self, result: UnifiedAuditResult) -> List[str]:
        """Generate unified recommendations from all audits."""
        recommendations = []

        # Code audit recommendations
        if result.code_audit:
            for finding in result.code_audit.get("ai_audit_findings", []):
                rec = finding.get("recommendation")
                if rec and rec not in recommendations:
                    recommendations.append(rec)

        # Liquidity recommendations
        if result.liquidity_metrics:
            for rec in result.liquidity_metrics.get("recommendations", []):
                if rec not in recommendations:
                    recommendations.append(rec)

        # Tokenomics recommendations
        if result.tokenomics_metrics:
            for rec in result.tokenomics_metrics.get("recommendations", []):
                if rec not in recommendations:
                    recommendations.append(rec)

        return recommendations[:10]  # Limit to top 10

    async def _store_result(self, result: UnifiedAuditResult) -> None:
        """Store unified audit result to backend."""
        import os
        import json

        try:
            endpoint = f"/admin/projects/{result.project_id}/audit-results"

            # Transform code_audit to match backend expectations
            # Backend expects: "contract_audit" with "findings" array
            contract_audit = result.code_audit.copy() if result.code_audit else {}

            # Transform ai_audit_findings to findings format expected by backend
            if "ai_audit_findings" in contract_audit:
                findings = []
                # Contract name / address for location fallback
                contract_name = contract_audit.get("contract_name", "")
                token_addr = contract_audit.get("token_address", result.token_address)
                short_addr = token_addr[:10] + "..." if token_addr else ""

                for finding in contract_audit["ai_audit_findings"]:
                    loc = finding.get("location", "")
                    if not loc:
                        desc = finding.get("description", "")
                        fn_match = re.search(r'(?:function\s+)(\w+)', desc)
                        fn_name = fn_match.group(1) if fn_match else finding.get("category", "")
                        if contract_name and fn_name:
                            loc = f"{contract_name}:{fn_name}()"
                        elif contract_name:
                            loc = f"{contract_name}"
                        else:
                            loc = short_addr

                    findings.append({
                        "severity": finding.get("severity", "info"),
                        "type": finding.get("category", "Code Issue"),
                        "category": finding.get("category", "Code Issue"),
                        "code_location": loc,
                        "location": loc,
                        "description": finding.get("description", ""),
                        "recommendation": finding.get("recommendation", ""),
                        "agent_name": finding.get("agent_name", ""),
                        "code_snippet": finding.get("code_snippet"),
                        "location_detail": finding.get("location_detail"),
                        "highlight_start": finding.get("highlight_start"),
                        "highlight_end": finding.get("highlight_end"),
                    })
                contract_audit["findings"] = findings

            payload = {
                "audit_data": {
                    "contract_audit": contract_audit,  # Backend expects "contract_audit" not "code_audit"
                    "distribution_metrics": result.distribution_metrics,
                    "liquidity_metrics": result.liquidity_metrics,
                    "tokenomics_metrics": result.tokenomics_metrics,
                    "overall_score": result.overall_score,
                    "risk_level": result.risk_level,
                    "flags": result.flags,
                    "recommendations": result.recommendations,
                },
                "completed_at": result.completed_at,
            }

            # Debug logging to see what's being sent
            LOGGER.debug(f"Sending audit results to backend: {json.dumps(payload, indent=2, default=str)[:1000]}")
            LOGGER.info(f"Code audit score: {result.code_audit.get('overall_score') if result.code_audit else 'N/A'}")

            # Add internal API secret header for authentication
            internal_secret = os.environ.get("INTERNAL_API_SECRET")
            headers = {}
            if internal_secret:
                headers["X-Internal-Api-Secret"] = internal_secret

            response = self.backend_client.patch(endpoint, json=payload, headers=headers)
            LOGGER.info(f"Stored unified audit result for {result.project_id}, response: {response}")

        except Exception as e:
            LOGGER.error(f"Failed to store unified audit result: {e}")

    async def close(self) -> None:
        """Close resources."""
        if self.liquidity_analyzer_scout:
            await self.liquidity_analyzer_scout.close()
        if self.tokenomics_analyzer_scout:
            await self.tokenomics_analyzer_scout.close()


def create_unified_audit_service(
    database: Any,
    w3: Web3,
    backend_client: Any,
    token_holder_scout: Optional[Any] = None,
    liquidity_analyzer_scout: Optional[Any] = None,
    tokenomics_analyzer_scout: Optional[Any] = None,
) -> UnifiedAuditService:
    """Factory function to create a unified audit service."""
    return UnifiedAuditService(
        database=database,
        w3=w3,
        backend_client=backend_client,
        token_holder_scout=token_holder_scout,
        liquidity_analyzer_scout=liquidity_analyzer_scout,
        tokenomics_analyzer_scout=tokenomics_analyzer_scout,
    )
