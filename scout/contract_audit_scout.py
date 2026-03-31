"""Contract auditor scout for static code analysis with GLM-powered AI audit.

Analyzes:
- Contract bytecode (size, hash, existence)
- Source code verification (via block explorers)
- AI-powered security audit using GLM with specialized agents
- Contract version tracking

Only runs when:
- First audit for a project
- Contract code hash changes
- Manually triggered via /audit/contract-update

AI Audit Process:
If verified Solidity source code is available:
1. Fetch source code from block explorer (Etherscan, etc.)
2. Orchestrate GLM to run specialized auditor agents:
   - ReentrancyAgent: Detects reentrancy vulnerabilities
   - AccessControlAgent: Analyzes ownership/permission patterns
   - ArithmeticAgent: Checks for overflow/underflow risks
   - GasOptimizationAgent: Identifies gas inefficiencies
   - LogicAgent: Analyzes business logic flaws
3. Aggregate findings into comprehensive audit report

Closed Source Penalty:
- Contracts without verified source code receive -30 point penalty
- Base score drops from 100.0 to 20.0 for closed-source contracts
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx
from web3 import Web3

LOGGER = logging.getLogger(__name__)

# GLM API Configuration
# Note: Use the OpenAI-compatible endpoint for chat completions format
GLM_API_KEY = os.environ.get("GLM_API_KEY")
GLM_API_URL = os.environ.get(
    "GLM_API_URL", "https://api.z.ai/v1/chat/completions"
)


@dataclass
class AgentFinding:
    """Finding from a specialized audit agent."""

    agent_name: str
    severity: str  # "info", "low", "medium", "high", "critical"
    category: str  # "reentrancy", "access_control", "arithmetic", "gas", "logic"
    description: str
    location: Optional[str]  # Function/line reference
    recommendation: str
    confidence: str = "medium"  # "high", "medium", "low"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "agent_name": self.agent_name,
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "location": self.location,
            "recommendation": self.recommendation,
            "confidence": self.confidence,
        }


@dataclass
class ContractAuditResult:
    """Contract audit results (including AI findings)."""

    token_address: str
    chain_id: str
    contract_code_hash: str
    contract_exists: bool
    is_verified: bool
    compiler_version: Optional[str]
    optimization_runs: Optional[int]
    contract_size: int
    libraries_used: List[str]

    # AI Audit Results
    ai_audit_enabled: bool
    ai_audit_findings: List[Dict[str, Any]]  # Individual agent findings
    overall_score: float  # 0-100
    risk_level: str  # "low", "medium", "high", "critical"

    flags: List[str]
    analyzed_at: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "token_address": self.token_address,
            "chain_id": self.chain_id,
            "contract_code_hash": self.contract_code_hash,
            "contract_exists": self.contract_exists,
            "is_verified": self.is_verified,
            "compiler_version": self.compiler_version,
            "optimization_runs": self.optimization_runs,
            "contract_size": self.contract_size,
            "libraries_used": self.libraries_used,
            "ai_audit_enabled": self.ai_audit_enabled,
            "ai_audit_findings": self.ai_audit_findings,
            "overall_score": self.overall_score,
            "risk_level": self.risk_level,
            "flags": self.flags,
            "analyzed_at": self.analyzed_at,
        }


class GLMAuditOrchestrator:
    """Orchestrates GLM-powered audit with specialized agents."""

    def __init__(self, api_key: str = None):
        self.api_key = api_key or GLM_API_KEY
        if not self.api_key:
            LOGGER.warning("GLM_API_KEY not set - AI audit will be disabled")

    async def run_audit(
        self,
        source_code: str,
        contract_address: str,
    ) -> List[AgentFinding]:
        """Run AI-powered audit using GLM with specialized agents.

        Args:
            source_code: Solidity source code
            contract_address: Contract address for context

        Returns:
            List of findings from all agents
        """
        if not self.api_key:
            LOGGER.warning("GLM API key not available - skipping AI audit")
            return []

        findings = []

        # Define specialized agents
        agents = [
            {
                "name": "ReentrancyGuard",
                "prompt": self._build_reentrancy_prompt(source_code, contract_address),
            },
            {
                "name": "AccessControl",
                "prompt": self._build_access_control_prompt(source_code, contract_address),
            },
            {
                "name": "ArithmeticSafety",
                "prompt": self._build_arithmetic_prompt(source_code, contract_address),
            },
            {
                "name": "GasOptimization",
                "prompt": self._build_gas_prompt(source_code, contract_address),
            },
            {
                "name": "LogicAnalysis",
                "prompt": self._build_logic_prompt(source_code, contract_address),
            },
        ]

        # Run each agent
        for agent in agents:
            try:
                agent_findings = await self._run_agent(agent["name"], agent["prompt"])
                findings.extend(agent_findings)
                LOGGER.info(f"Agent {agent['name']} completed: {len(agent_findings)} findings")
            except Exception as e:
                LOGGER.error(f"Agent {agent['name']} failed: {e}")

        return findings

    def _build_reentrancy_prompt(self, code: str, address: str) -> str:
        return f"""Analyze this Solidity contract for reentrancy vulnerabilities.

Contract Address: {address}

Source Code:
{code}

Focus on:
1. External calls before state changes (calls-effect patterns)
2. Low-level calls (call, delegatecall, staticcall)
3. ETH transfer patterns
4. ReentrancyGuard usage or lack thereof

Return findings as JSON array with this exact structure:
[{{"severity": "high|medium|low", "location": "function_name", "description": "...", "recommendation": "..."}}]

Only return the JSON array, no other text."""

    def _build_access_control_prompt(self, code: str, address: str) -> str:
        return f"""Analyze this Solidity contract for access control issues.

Contract Address: {address}

Source Code:
{code}

Focus on:
1. onlyOwner / onlyAdmin modifiers
2. public vs external vs internal functions
3. uninitialized ownership
4. centralized control risks

Return findings as JSON array with this exact structure:
[{{"severity": "high|medium|low", "location": "function_name", "description": "...", "recommendation": "..."}}]

Only return the JSON array, no other text."""

    def _build_arithmetic_prompt(self, code: str, address: str) -> str:
        return f"""Analyze this Solidity contract for arithmetic safety issues.

Contract Address: {address}

Source Code:
{code}

Focus on:
1. Solidity 0.8+ overflow protection (or lack thereof)
2. Division by zero risks
3. Rounding errors (especially in token/financial calculations)
4. Unchecked arithmetic operations

Return findings as JSON array with this exact structure:
[{{"severity": "high|medium|low", "location": "function_name", "description": "...", "recommendation": "..."}}]

Only return the JSON array, no other text."""

    def _build_gas_prompt(self, code: str, address: str) -> str:
        return f"""Analyze this Solidity contract for gas optimization opportunities.

Contract Address: {address}

Source Code:
{code}

Focus on:
1. Unnecessary storage reads/writes
2. Loops that could be optimized
3. Redundant calculations
4. Memory vs storage usage

Return findings as JSON array with this exact structure:
[{{"severity": "low|info", "location": "function_name", "description": "...", "recommendation": "..."}}]

Only return the JSON array, no other text."""

    def _build_logic_prompt(self, code: str, address: str) -> str:
        return f"""Analyze this Solidity contract for business logic flaws.

Contract Address: {address}

Source Code:
{code}

Focus on:
1. Token burning/minting logic
2. Voting/governance logic
3. Time-based exploits
4. Front-running opportunities

Return findings as JSON array with this exact structure:
[{{"severity": "high|medium|low", "location": "function_name", "description": "...", "recommendation": "..."}}]

Only return the JSON array, no other text."""

    async def _run_agent(self, agent_name: str, prompt: str) -> List[AgentFinding]:
        """Run a single agent via GLM API.

        Args:
            agent_name: Name of the agent
            prompt: Analysis prompt

        Returns:
            List of findings from the agent
        """
        timeout = httpx.Timeout(60.0)

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(
                    GLM_API_URL,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": "glm-4.7",
                        "messages": [
                            {
                                "role": "system",
                                "content": f"You are {agent_name}, a Solidity smart contract security expert. Analyze code and return ONLY valid JSON arrays. No explanations, no markdown, just the JSON array.",
                            },
                            {"role": "user", "content": prompt},
                        ],
                        "temperature": 0.1,  # Low temperature for consistent analysis
                        "max_tokens": 2000,
                    },
                )

                if response.status_code != 200:
                    # Log the actual response for debugging
                    LOGGER.warning(f"GLM API returned status {response.status_code}: {response.text[:200]}")
                    raise Exception(f"GLM API error: {response.status_code}")

                data = response.json()

                # Handle different API response formats
                # Zhipu GLM format: {"code": 0, "data": {"choices": [...]}}
                # OpenAI format: {"choices": [{"message": {"content": "..."}}]}
                # Anthropic format: {"content": [{"type": "text", "text": "..."}]}

                # Debug logging
                if "code" in data and data.get("code") != 0:
                    LOGGER.error(f"GLM API error response: URL={GLM_API_URL}, response={data}")

                if "code" in data:
                    # Zhipu GLM format
                    if data.get("code") == 0 and "data" in data:
                        inner_data = data["data"]
                        if "choices" in inner_data:
                            content = inner_data["choices"][0]["message"]["content"]
                        else:
                            raise Exception(f"Unexpected Zhipu API response: {list(inner_data.keys())}")
                    else:
                        raise Exception(f"GLM API error: {data.get('msg', 'Unknown error')}")
                elif "choices" in data:
                    # OpenAI-compatible format
                    content = data["choices"][0]["message"]["content"]
                elif "content" in data and isinstance(data["content"], list):
                    # Anthropic format
                    text_blocks = [block.get("text", "") for block in data["content"] if block.get("type") == "text"]
                    content = "\n".join(text_blocks)
                else:
                    raise Exception(f"Unexpected API response format: {list(data.keys())}")

                # Try to parse JSON response
                try:
                    # Extract JSON array from response (handle markdown code blocks)
                    content = content.strip()
                    if content.startswith("```"):
                        # Remove markdown code block markers
                        content = content.split("\n", 1)[1]
                        if content.endswith("```"):
                            content = content.rsplit("\n", 1)[0]
                        content = content.strip()

                    findings_data = json.loads(content)
                    return [
                        AgentFinding(
                            agent_name=agent_name,
                            severity=f.get("severity", "info"),
                            category=self._map_agent_to_category(agent_name),
                            description=f.get("description", ""),
                            location=f.get("location"),
                            recommendation=f.get("recommendation", ""),
                        )
                        for f in findings_data
                    ]
                except json.JSONDecodeError as e:
                    LOGGER.warning(
                        f"Failed to parse agent {agent_name} response as JSON: {e}"
                    )
                    # Try to extract JSON from the response
                    try:
                        import re
                        json_match = re.search(r"\[.*\]", content, re.DOTALL)
                        if json_match:
                            findings_data = json.loads(json_match.group())
                            return [
                                AgentFinding(
                                    agent_name=agent_name,
                                    severity=f.get("severity", "info"),
                                    category=self._map_agent_to_category(agent_name),
                                    description=f.get("description", ""),
                                    location=f.get("location"),
                                    recommendation=f.get("recommendation", ""),
                                )
                                for f in findings_data
                            ]
                    except Exception:
                        pass

                    LOGGER.warning(f"Could not extract JSON from {agent_name} response")
                    return []

        except httpx.TimeoutException:
            LOGGER.error(f"GLM API timeout for agent {agent_name}")
            return []
        except Exception as e:
            LOGGER.error(f"GLM API error for agent {agent_name}: {e}")
            return []

    def _map_agent_to_category(self, agent_name: str) -> str:
        """Map agent name to category."""
        mapping = {
            "ReentrancyGuard": "reentrancy",
            "AccessControl": "access_control",
            "ArithmeticSafety": "arithmetic",
            "GasOptimization": "gas",
            "LogicAnalysis": "logic",
        }
        return mapping.get(agent_name, "general")


class BlockExplorerClient:
    """Fetches verified source code from Etherscan API.

    Uses the Etherscan API V2 endpoint that supports multiple chains.
    Documentation: https://docs.etherscan.io/v2-migration

    Note: Only calls the API once per contract to avoid rate limits.
    """

    ETHERSCAN_API_URL = "https://api.etherscan.io/v2/api"

    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.environ.get("ETHERSCAN_API_KEY")
        # Cache to avoid duplicate API calls
        self._cache: Dict[str, Optional[Dict[str, Any]]] = {}

    async def get_source_code(
        self,
        contract_address: str,
        chain_id: int = 1,
    ) -> Optional[Dict[str, Any]]:
        """Get verified source code from Etherscan.

        API Endpoint: https://api.etherscan.io/api
        Parameters:
        - module=contract
        - action=getsourcecode
        - address={contract_address}
        - chainid={chain_id}
        - apikey={API_KEY}

        Args:
            contract_address: Contract address
            chain_id: Chain ID (1=Ethereum, 8453=Base, etc.)

        Returns:
            Dict with source code info or None if not verified

        Note: Results are cached to avoid duplicate API calls.
        """
        cache_key = f"{chain_id}:{contract_address}"

        # Return cached result if available
        if cache_key in self._cache:
            return self._cache[cache_key]

        async with httpx.AsyncClient() as client:
            params = {
                "module": "contract",
                "action": "getsourcecode",
                "address": contract_address,
                "chainid": str(chain_id),
                "apikey": self.api_key or "YourApiKeyToken",
            }

            try:
                response = await client.get(self.ETHERSCAN_API_URL, params=params)
                data = response.json()

                result = None
                if data.get("status") == "1" and data.get("result"):
                    contract_data = data["result"][0]
                    if contract_data.get("SourceCode"):
                        result = {
                            "source_code": contract_data["SourceCode"],
                            "abi": contract_data.get("ABI"),
                            "contract_name": contract_data.get("ContractName"),
                            "compiler_version": contract_data.get("CompilerVersion"),
                            "optimization_used": contract_data.get("OptimizationUsed") == "1",
                            "optimization_runs": int(contract_data.get("Runs", "200")),
                            "constructor_arguments": contract_data.get("ConstructorArguments"),
                            "evm_version": contract_data.get("EVMVersion"),
                            "library": contract_data.get("Library"),
                            "license_type": contract_data.get("LicenseType"),
                            "proxy": contract_data.get("Proxy"),
                            "implementation": contract_data.get("Implementation"),
                            "swarm_source": contract_data.get("SwarmSource"),
                        }
                        LOGGER.info(f"Retrieved verified source code for {contract_address}")
                    else:
                        LOGGER.warning(f"Contract {contract_address} has no verified source code")
                        result = None
                else:
                    LOGGER.warning(f"Etherscan API error: {data.get('message')}")
                    result = None

                # Cache the result (even if None, to avoid retrying)
                self._cache[cache_key] = result
                return result

            except Exception as e:
                LOGGER.error(f"Failed to fetch source code for {contract_address}: {e}")
                self._cache[cache_key] = None
                return None


class ContractAuditScout:
    """Audits contract code and tracks changes.

    Only runs on:
    - First audit
    - Contract code change detected
    - Manual trigger

    This scout performs initial contract analysis and retrieves verified source code.
    Comprehensive AI-powered analysis via claude-code CLI is handled by
    UnifiedAuditService after the initial audit.
    """

    def __init__(
        self,
        database: Any,
        w3: Web3,
        glm_orchestrator: GLMAuditOrchestrator = None,
        claude_orchestrator: "ClaudeCodeOrchestrator" = None,
        explorer_client: BlockExplorerClient = None,
    ):
        """Initialize the contract audit scout.

        Args:
            database: Database manager instance
            w3: Web3 instance
            glm_orchestrator: Optional GLM audit orchestrator (deprecated)
            claude_orchestrator: Optional Claude Code orchestrator (NOT used internally,
                handled by UnifiedAuditService for comprehensive analysis)
            explorer_client: Optional block explorer client
        """
        self.database = database
        self.w3 = w3
        self.glm_orchestrator = glm_orchestrator
        # Note: claude_orchestrator is NOT used internally in ContractAuditScout
        # It's passed through for UnifiedAuditService to use after initial audit
        self.explorer_client = explorer_client or BlockExplorerClient()

    async def audit_contract(
        self,
        token_address: str,
        chain_id: int,
        force: bool = False,
    ) -> ContractAuditResult:
        """Audit contract code.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            force: Force re-audit even if code unchanged

        Returns:
            Contract audit results
        """
        # Get current code hash
        code_hash = await self._get_code_hash(token_address)

        # Check if code changed
        if not force:
            last_hash = self.database.get_last_contract_code_hash(token_address, chain_id)
            if last_hash and last_hash == code_hash:
                LOGGER.info(f"Contract code unchanged for {token_address}")
                # Return cached result
                last_audit = self.database.get_last_contract_audit(token_address, chain_id)
                if last_audit:
                    return ContractAuditResult(
                        token_address=last_audit["token_address"],
                        chain_id=last_audit["chain_id"],
                        contract_code_hash=last_audit["contract_code_hash"],
                        contract_exists=last_audit["contract_exists"],
                        is_verified=last_audit["is_verified"],
                        compiler_version=last_audit["compiler_version"],
                        optimization_runs=last_audit["optimization_runs"],
                        contract_size=last_audit["contract_size"],
                        libraries_used=last_audit["libraries_used"],
                        ai_audit_enabled=last_audit["ai_audit_enabled"],
                        ai_audit_findings=last_audit["ai_audit_findings"],
                        overall_score=last_audit["overall_score"],
                        risk_level=last_audit["risk_level"],
                        flags=last_audit["flags"],
                        analyzed_at=last_audit["analyzed_at"],
                    )

        # Perform audit
        result = await self._analyze_contract(token_address, chain_id, code_hash)

        # Store result
        self.database.store_contract_audit(
            token_address=result.token_address,
            chain_id=result.chain_id,
            contract_code_hash=result.contract_code_hash,
            contract_exists=result.contract_exists,
            is_verified=result.is_verified,
            compiler_version=result.compiler_version,
            optimization_runs=result.optimization_runs,
            contract_size=result.contract_size,
            libraries_used=result.libraries_used,
            ai_audit_enabled=result.ai_audit_enabled,
            ai_audit_findings=result.ai_audit_findings,
            overall_score=result.overall_score,
            risk_level=result.risk_level,
            flags=result.flags,
            analyzed_at=result.analyzed_at,
        )

        return result

    async def _get_code_hash(self, token_address: str) -> str:
        """Get contract code hash.

        Args:
            token_address: Token contract address

        Returns:
            SHA256 hash of contract bytecode
        """
        checksum_address = Web3.to_checksum_address(token_address)

        # Retry logic for RPC calls
        max_retries = 3
        for attempt in range(max_retries):
            try:
                code = self.w3.eth.get_code(checksum_address)
                if code:
                    return hashlib.sha256(code).hexdigest()
                else:
                    LOGGER.warning(f"No code found for {checksum_address}, attempt {attempt + 1}/{max_retries}")
                    if attempt < max_retries - 1:
                        await asyncio.sleep(1)  # Wait before retry
            except Exception as e:
                LOGGER.warning(f"RPC error getting code for {checksum_address}, attempt {attempt + 1}/{max_retries}: {e}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                else:
                    # Final retry failed, return empty hash
                    LOGGER.error(f"Failed to get code for {checksum_address} after {max_retries} attempts")
                    return hashlib.sha256(b"").hexdigest()

        return hashlib.sha256(b"").hexdigest()

    async def _analyze_contract(
        self,
        token_address: str,
        chain_id: int,
        code_hash: str,
    ) -> ContractAuditResult:
        """Analyze contract code.

        Args:
            token_address: Token contract address
            chain_id: Chain ID
            code_hash: Contract code hash

        Returns:
            Contract audit result
        """
        # Basic bytecode analysis
        code = self.w3.eth.get_code(Web3.to_checksum_address(token_address))
        contract_exists = len(code.hex()) > 2
        contract_size = len(code)

        flags = []

        if not contract_exists:
            flags.append("contract_not_found")
            return ContractAuditResult(
                token_address=token_address,
                chain_id=str(chain_id),
                contract_code_hash=code_hash,
                contract_exists=False,
                is_verified=False,
                compiler_version=None,
                optimization_runs=None,
                contract_size=0,
                libraries_used=[],
                ai_audit_enabled=False,
                ai_audit_findings=[],
                overall_score=0,
                risk_level="critical",
                flags=flags,
                analyzed_at=datetime.utcnow().isoformat(),
            )

        # Try to get verified source code (single API call - cached in explorer_client)
        source_info = await self.explorer_client.get_source_code(token_address, chain_id)
        is_verified = source_info is not None

        ai_findings = []
        ai_audit_enabled = False  # Will be set to True if source code is available
        overall_score = 50.0  # Base score
        risk_level = "medium"

        # Run AI audit if source code is available
        # Note: Comprehensive AI analysis via claude-code CLI is handled by
        # UnifiedAuditService after this initial audit completes.
        if source_info and source_info.get("source_code"):
            LOGGER.info(f"Source code available for {token_address} - AI audit will be run by UnifiedAuditService")

            # Set AI audit as enabled so UnifiedAuditService knows to run claude-code CLI
            ai_audit_enabled = True

            # No findings here - UnifiedAuditService will populate them
            ai_findings = []
            overall_score = 50.0  # Base score, will be recalculated after claude-code analysis
            risk_level = "medium"

        else:
            # CLOSED SOURCE PENALTY: -30 points for contracts without verified source code
            # This is a significant security risk as code cannot be independently audited
            ai_audit_enabled = False
            flags.append("source_not_verified")
            flags.append("closed_source_penalty:-30")
            overall_score = 20.0  # Low base score for closed-source contracts
            risk_level = "high"
            LOGGER.warning(f"Contract {token_address} has no verified source code - applying penalty")

        return ContractAuditResult(
            token_address=token_address,
            chain_id=str(chain_id),
            contract_code_hash=code_hash,
            contract_exists=True,
            is_verified=is_verified,
            compiler_version=source_info.get("compiler_version") if source_info else None,
            optimization_runs=source_info.get("optimization_runs") if source_info else None,
            contract_size=contract_size,
            libraries_used=source_info.get("library", "").split(",") if source_info and source_info.get("library") else [],
            ai_audit_enabled=ai_audit_enabled,  # Set by the if/else block above
            ai_audit_findings=[f.to_dict() for f in ai_findings],
            overall_score=overall_score,
            risk_level=risk_level,
            flags=flags,
            analyzed_at=datetime.utcnow().isoformat(),
        )

    def _calculate_score(self, findings: List[AgentFinding], is_verified: bool = True) -> float:
        """Calculate overall security score from findings.

        Scoring:
        - Base score: 100.0 for verified, 20.0 for unverified (closed source)
        - Critical findings: -25 each (or -12.5 with low confidence)
        - High findings: -15 each (or -7.5 with low confidence)
        - Medium findings: -8 each (or -4 with low confidence)
        - Low findings: -3 each (or -1.5 with low confidence)
        - Info findings: -1 each (or -0.5 with low confidence)
        - Closed source penalty: -30 (applied via base score)

        Confidence multipliers:
        - high confidence: 100% penalty (1.0x)
        - medium confidence: 75% penalty (0.75x)
        - low confidence: 50% penalty (0.5x)

        Args:
            findings: List of agent findings
            is_verified: Whether source code is verified (default: True)

        Returns:
            Score from 0-100
        """
        # Base score depends on whether source is verified
        score = 100.0 if is_verified else 20.0

        # Confidence multipliers
        confidence_multipliers = {
            "high": 1.0,
            "medium": 0.75,
            "low": 0.5,
            None: 1.0  # Default if not specified
        }

        # Severity penalties (before confidence adjustment)
        severity_penalties = {
            "critical": 25,
            "high": 15,
            "medium": 8,
            "low": 3,
            "info": 1
        }

        # Apply penalties for findings with confidence adjustment
        for finding in findings:
            severity = finding.severity.lower()
            confidence = finding.confidence.lower() if finding.confidence else None

            # Get penalty and confidence multiplier
            penalty = severity_penalties.get(severity, 0)
            multiplier = confidence_multipliers.get(confidence, 1.0)

            # Apply adjusted penalty
            score -= penalty * multiplier

        return max(0, score)

    def _determine_risk_level(self, score: float) -> str:
        """Determine risk level from score.

        Args:
            score: Overall security score (0-100)

        Returns:
            Risk level (low/medium/high/critical)
        """
        if score >= 80:
            return "low"
        elif score >= 60:
            return "medium"
        elif score >= 40:
            return "high"
        else:
            return "critical"
