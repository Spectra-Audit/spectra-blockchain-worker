"""Unified GLM agent orchestrator for ALL contract analysis.

Routes to specialized agents based on input type:
- SOURCE_CODE → VerifiedContractAgents (ReentrancyGuard, AccessControl, etc.)
- BYTECODE_ABI → BytecodeAnalysisAgents (BytecodePattern, AbiFunction, etc.)

Shared Agent Base Classes:
- ReentrancyAgent (works with both source and bytecode)
- AccessControlAgent (works with both source and bytecode)
- ArithmeticSafetyAgent (works with both source and bytecode)

Specialized Bytecode-Only Agents:
- BytecodePatternAgent (fingerprint matching, proxy detection)
- AbiFunctionAgent (function signature risk analysis)
- StorageLayoutAgent (storage slot inference from ABI)
"""
from __future__ import annotations

import httpx
import json
import logging
import os
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union

LOGGER = logging.getLogger(__name__)

# GLM API Configuration
GLM_API_KEY = os.environ.get("GLM_API_KEY")
GLM_API_URL = os.environ.get(
    "GLM_API_URL", "https://open.bigmodel.cn/api/paas/v4/chat/completions"
)


@dataclass
class AgentFinding:
    """Finding from a specialized audit agent."""
    agent_name: str
    severity: str  # "info", "low", "medium", "high", "critical"
    category: str  # "reentrancy", "access_control", "arithmetic", "gas", "logic", "bytecode", "abi"
    description: str
    location: Optional[str]  # Function/line reference
    recommendation: str
    confidence: str = "medium"  # "high", "medium", "low"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_name": self.agent_name,
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "location": self.location,
            "recommendation": self.recommendation,
            "confidence": self.confidence,
        }


class BaseAuditAgent(ABC):
    """Base class for all audit agents.

    Shared agents work with both source code and bytecode+ABI inputs.
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or GLM_API_KEY
        if not self.api_key:
            LOGGER.warning(f"{self.__class__.__name__}: GLM_API_KEY not set")

    @abstractmethod
    async def analyze(
        self,
        contract_address: str,
        input_type: str,
        data: Union[str, Tuple],
    ) -> List[AgentFinding]:
        """Analyze contract and return findings.

        Args:
            contract_address: Contract address
            input_type: "SOURCE_CODE" or "BYTECODE_ABI"
            data: Source code string OR (bytecode, abi, context) tuple

        Returns:
            List of AgentFinding objects
        """
        pass

    async def _call_glm(self, prompt: str, agent_name: str) -> str:
        """Call GLM API with prompt."""
        if not self.api_key:
            return "[]"

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
                        "temperature": 0.1,
                        "max_tokens": 2000,
                    },
                )

                if response.status_code != 200:
                    LOGGER.error(f"GLM API error: {response.status_code}")
                    return "[]"

                data = response.json()
                return data["choices"][0]["message"]["content"]

        except Exception as e:
            LOGGER.error(f"GLM API error for {agent_name}: {e}")
            return "[]"

    def _parse_findings(self, response: str, agent_name: str) -> List[AgentFinding]:
        """Parse GLM response into findings."""
        findings = []

        try:
            # Extract JSON from response
            content = response.strip()
            if content.startswith("```"):
                content = content.split("\n", 1)[1]
                if content.endswith("```"):
                    content = content.rsplit("\n", 1)[0]
                content = content.strip()

            findings_data = json.loads(content)

            for f in findings_data:
                findings.append(AgentFinding(
                    agent_name=agent_name,
                    severity=f.get("severity", "info"),
                    category=self._get_category(),
                    description=f.get("description", ""),
                    location=f.get("location"),
                    recommendation=f.get("recommendation", ""),
                    confidence=f.get("confidence", "medium"),
                ))

        except (json.JSONDecodeError, KeyError) as e:
            LOGGER.warning(f"Failed to parse {agent_name} response: {e}")

        return findings

    @abstractmethod
    def _get_category(self) -> str:
        """Return the agent category."""
        pass


class ReentrancyAgent(BaseAuditAgent):
    """Shared reentrancy agent - works with source code and bytecode+ABI."""

    async def analyze(
        self,
        contract_address: str,
        input_type: str,
        data: Union[str, Tuple],
    ) -> List[AgentFinding]:
        """Analyze for reentrancy vulnerabilities."""
        prompt = self._build_prompt(contract_address, input_type, data)
        response = await self._call_glm(prompt, "ReentrancyGuard")
        return self._parse_findings(response, "ReentrancyGuard")

    def _build_prompt(
        self,
        contract_address: str,
        input_type: str,
        data: Union[str, Tuple],
    ) -> str:
        """Build reentrancy analysis prompt."""
        if input_type == "SOURCE_CODE":
            source_code = data
            return f"""Analyze this Solidity contract for reentrancy vulnerabilities.

Contract Address: {contract_address}

Source Code:
{source_code}

Focus on:
1. External calls before state changes (calls-effect patterns)
2. Low-level calls (call, delegatecall, staticcall)
3. ETH transfer patterns
4. ReentrancyGuard usage or lack thereof

Return findings as JSON array:
[{{"severity": "high|medium|low", "location": "function_name", "description": "...", "recommendation": "..."}}]
Only return the JSON array, no other text."""
        else:
            # BYTECODE_ABI input
            bytecode, abi, context = data
            abi_summary = self._summarize_abi(abi)

            return f"""Analyze this contract for reentrancy risks based on bytecode and ABI.

Contract Address: {contract_address}
Contract Type: {context.get('contract_type', 'Unknown')}
Is Proxy: {context.get('is_proxy', False)}

Bytecode Patterns Detected:
{json.dumps(context.get('pattern_findings', []), indent=2)}

ABI Functions with External Calls:
{abi_summary}

Analyze for reentrancy risks:
1. Look for functions with external call capabilities
2. Check for state change operations before/after calls
3. Assess proxy-specific reentrancy risks

Return findings as JSON array:
[{{"severity": "high|medium|low", "location": "function_name", "description": "...", "recommendation": "..."}}]
Only return the JSON array, no other text."""

    def _summarize_abi(self, abi: List[Dict]) -> str:
        """Summarize ABI for analysis."""
        risky_functions = []
        for entry in abi:
            if entry.get("type") == "function":
                name = entry.get("name", "")
                if any(kw in name.lower() for kw in ["call", "send", "transfer", "withdraw"]):
                    risky_functions.append(name)
        return json.dumps(risky_functions, indent=2)

    def _get_category(self) -> str:
        return "reentrancy"


class AccessControlAgent(BaseAuditAgent):
    """Shared access control agent - works with source code and bytecode+ABI."""

    async def analyze(
        self,
        contract_address: str,
        input_type: str,
        data: Union[str, Tuple],
    ) -> List[AgentFinding]:
        """Analyze for access control issues."""
        prompt = self._build_prompt(contract_address, input_type, data)
        response = await self._call_glm(prompt, "AccessControl")
        return self._parse_findings(response, "AccessControl")

    def _build_prompt(
        self,
        contract_address: str,
        input_type: str,
        data: Union[str, Tuple],
    ) -> str:
        """Build access control analysis prompt."""
        if input_type == "SOURCE_CODE":
            source_code = data
            return f"""Analyze this Solidity contract for access control issues.

Contract Address: {contract_address}

Source Code:
{source_code}

Focus on:
1. onlyOwner / onlyAdmin modifiers
2. public vs external vs internal functions
3. uninitialized ownership
4. centralized control risks

Return findings as JSON array:
[{{"severity": "high|medium|low", "location": "function_name", "description": "...", "recommendation": "..."}}]
Only return the JSON array, no other text."""
        else:
            # BYTECODE_ABI input
            bytecode, abi, context = data
            admin_functions = self._find_admin_functions(abi)

            return f"""Analyze this contract for access control risks based on ABI.

Contract Address: {contract_address}
Contract Type: {context.get('contract_type', 'Unknown')}
Is Proxy: {context.get('is_proxy', False)}

Admin/Privileged Functions:
{json.dumps(admin_functions, indent=2)}

Analyze for access control risks:
1. Functions with admin-like names
2. Upgrade/critical functions
3. Centralization risks

Return findings as JSON array:
[{{"severity": "high|medium|low", "location": "function_name", "description": "...", "recommendation": "..."}}]
Only return the JSON array, no other text."""

    def _find_admin_functions(self, abi: List[Dict]) -> List[str]:
        """Find admin-like functions in ABI."""
        admin_funcs = []
        for entry in abi:
            if entry.get("type") == "function":
                name = entry.get("name", "")
                if any(kw in name.lower() for kw in
                       ["admin", "owner", "only", "auth", "grant", "revoke", "upgrade"]):
                    admin_funcs.append(name)
        return admin_funcs

    def _get_category(self) -> str:
        return "access_control"


class ArithmeticSafetyAgent(BaseAuditAgent):
    """Shared arithmetic safety agent - works with source code and bytecode+ABI."""

    async def analyze(
        self,
        contract_address: str,
        input_type: str,
        data: Union[str, Tuple],
    ) -> List[AgentFinding]:
        """Analyze for arithmetic safety issues."""
        prompt = self._build_prompt(contract_address, input_type, data)
        response = await self._call_glm(prompt, "ArithmeticSafety")
        return self._parse_findings(response, "ArithmeticSafety")

    def _build_prompt(
        self,
        contract_address: str,
        input_type: str,
        data: Union[str, Tuple],
    ) -> str:
        """Build arithmetic safety prompt."""
        if input_type == "SOURCE_CODE":
            source_code = data
            return f"""Analyze this Solidity contract for arithmetic safety issues.

Contract Address: {contract_address}

Source Code:
{source_code}

Focus on:
1. Solidity 0.8+ overflow protection (or lack thereof)
2. Division by zero risks
3. Rounding errors (especially in token/financial calculations)
4. Unchecked arithmetic operations

Return findings as JSON array:
[{{"severity": "high|medium|low", "location": "function_name", "description": "...", "recommendation": "..."}}]
Only return the JSON array, no other text."""
        else:
            # BYTECODE_ABI - Limited analysis for bytecode
            bytecode, abi, context = data
            math_functions = self._find_math_functions(abi)

            return f"""Analyze this contract for arithmetic risks based on ABI.

Contract Address: {contract_address}
Contract Type: {context.get('contract_type', 'Unknown')}

Mathematical Functions:
{json.dumps(math_functions, indent=2)}

Note: Full arithmetic analysis requires source code. Based on function signatures,
assess potential arithmetic risks in financial/token operations.

Return findings as JSON array:
[{{"severity": "high|medium|low", "location": "function_name", "description": "...", "recommendation": "..."}}]
Only return the JSON array, no other text."""

    def _find_math_functions(self, abi: List[Dict]) -> List[str]:
        """Find math-related functions in ABI."""
        math_funcs = []
        for entry in abi:
            if entry.get("type") == "function":
                name = entry.get("name", "")
                if any(kw in name.lower() for kw in
                       ["add", "sub", "mul", "div", "calc", "compute", "percent"]):
                    math_funcs.append(name)
        return math_funcs

    def _get_category(self) -> str:
        return "arithmetic"


class BytecodePatternAgent(BaseAuditAgent):
    """Specialized bytecode-only agent for deep bytecode analysis."""

    async def analyze(
        self,
        contract_address: str,
        input_type: str,
        data: Union[str, Tuple],
    ) -> List[AgentFinding]:
        """Analyze bytecode patterns."""
        if input_type != "BYTECODE_ABI":
            return []

        bytecode, abi, context = data
        prompt = self._build_prompt(contract_address, bytecode, context)
        response = await self._call_glm(prompt, "BytecodePattern")
        return self._parse_findings(response, "BytecodePattern")

    def _build_prompt(
        self,
        contract_address: str,
        bytecode: str,
        context: Dict,
    ) -> str:
        """Build bytecode pattern analysis prompt."""
        return f"""Analyze this contract bytecode for security patterns.

Contract Address: {contract_address}
Bytecode Size: {context.get('bytecode_size', 0)} bytes
Contract Type: {context.get('contract_type', 'Unknown')}
Is Proxy: {context.get('is_proxy', False)}
Proxy Type: {context.get('proxy_type', 'N/A')}

Known Patterns Detected:
{json.dumps(context.get('pattern_findings', []), indent=2)}

Based on the bytecode patterns and metadata:
1. Assess severity of detected opcodes (delegatecall, selfdestruct, etc.)
2. Analyze proxy-specific risks
3. Identify unusual bytecode characteristics

Return findings as JSON array:
[{{"severity": "high|medium|low", "description": "...", "recommendation": "..."}}]
Only return the JSON array, no other text."""

    def _get_category(self) -> str:
        return "bytecode"


class AbiFunctionAgent(BaseAuditAgent):
    """Specialized ABI function risk analysis agent."""

    async def analyze(
        self,
        contract_address: str,
        input_type: str,
        data: Union[str, Tuple],
    ) -> List[AgentFinding]:
        """Analyze ABI function risks."""
        if input_type != "BYTECODE_ABI":
            return []

        bytecode, abi, context = data
        prompt = self._build_prompt(contract_address, abi, context)
        response = await self._call_glm(prompt, "AbiFunction")
        return self._parse_findings(response, "AbiFunction")

    def _build_prompt(
        self,
        contract_address: str,
        abi: List[Dict],
        context: Dict,
    ) -> str:
        """Build ABI function analysis prompt."""
        risky_funcs = context.get('abi_findings', [])

        return f"""Analyze this contract's ABI for function-level security risks.

Contract Address: {contract_address}
Contract Type: {context.get('contract_type', 'Unknown')}
Detected Standards: {context.get('detected_standards', [])}

Risky Functions Identified:
{json.dumps(risky_funcs, indent=2)}

Analyze:
1. Critical functions (mint, burn, upgrade, etc.)
2. Access control risks
3. External call risks
4. Proxy interaction risks

Return findings as JSON array:
[{{"severity": "high|medium|low", "location": "function_name", "description": "...", "recommendation": "..."}}]
Only return the JSON array, no other text."""

    def _get_category(self) -> str:
        return "abi"


class ContractCapabilitiesAgent(BaseAuditAgent):
    """Maps contract capabilities - detects minting, burning, pausing, blacklisting."""

    async def analyze(
        self,
        contract_address: str,
        input_type: str,
        data: Union[str, Tuple],
    ) -> List[AgentFinding]:
        """Analyze contract capabilities."""
        if input_type != "BYTECODE_ABI":
            return []

        bytecode, abi, context = data
        prompt = self._build_prompt(contract_address, abi, context)
        response = await self._call_glm(prompt, "ContractCapabilities")
        return self._parse_findings(response, "ContractCapabilities")

    def _build_prompt(
        self,
        contract_address: str,
        abi: List[Dict],
        context: Dict,
    ) -> str:
        """Build capabilities analysis prompt."""
        return f"""Analyze this contract's capabilities and identify potential risks.

Contract Address: {contract_address}
Contract Type: {context.get('contract_type', 'Unknown')}
Detected Standards: {context.get('detected_standards', [])}

Full ABI:
{json.dumps(abi, indent=2)}

Map the contract's capabilities and identify risks:

1. **MINTING CAPABILITIES** - Look for functions that indicate:
   - Mint function (increase supply)
   - Who can call mint (admin only or public)
   - Any mint limits or caps

2. **BURNING CAPABILITIES** - Look for:
   - Burn function (decrease supply)
   - Who can call burn
   - Whether burn is from supply or specific holders

3. **PAUSING CAPABILITIES** - Look for:
   - Pause/unpause functions
   - Trading enable/disable switches
   - Who has control over pausing

4. **BLACKLISTING CAPABILITIES** - Look for:
   - Blacklist/addBlacklist functions
   - Freeze user assets capabilities
   - Who can blacklist users

For each capability found, return a finding with:
- severity: "critical" if admin-only mint/pause/blacklist, "high" if public mint, "medium" otherwise
- location: function name
- description: What the capability does and who controls it
- recommendation: Security implications

Return findings as JSON array:
[{{"severity": "critical|high|medium|low", "location": "function_name", "description": "...", "recommendation": "..."}}]
Only return the JSON array, no other text."""

    def _get_category(self) -> str:
        return "capabilities"


class FeeTaxAgent(BaseAuditAgent):
    """Finds fee/tax logic in contracts."""

    async def analyze(
        self,
        contract_address: str,
        input_type: str,
        data: Union[str, Tuple],
    ) -> List[AgentFinding]:
        """Analyze fee/tax logic."""
        if input_type != "BYTECODE_ABI":
            return []

        bytecode, abi, context = data
        prompt = self._build_prompt(contract_address, abi, context)
        response = await self._call_glm(prompt, "FeeTaxAnalysis")
        return self._parse_findings(response, "FeeTaxAnalysis")

    def _build_prompt(
        self,
        contract_address: str,
        abi: List[Dict],
        context: Dict,
    ) -> str:
        """Build fee/tax analysis prompt."""
        return f"""Analyze this contract for fee and tax mechanisms.

Contract Address: {contract_address}
Contract Type: {context.get('contract_type', 'Unknown')}
Detected Standards: {context.get('detected_standards', [])}

Full ABI:
{json.dumps(abi, indent=2)}

Identify FEE/TAX logic:

1. **TRANSFER FES** - Look for functions that:
   - Take a fee on transfers (fee parameter or automatic deduction)
   - Return less than transferred amount to recipient
   - Common patterns: getFee, setFee, feeOnTransfer, _transfer

2. **TAX MECHANISMS** - Look for:
   - Buy/sell tax percentages
   - Reflection mechanisms
   - Auto-liquidity features
   - Dynamic tax change capabilities

3. **FEE RECIPIENTS** - Identify:
   - Where fees are sent (wallet address, dead address, liquidity pool)
   - Whether fees go to owner vs protocol vs burn

4. **DYNAMIC FEES** - Check for:
   - Functions that can change fee percentages
   - Who can modify fees
   - Any maximum fee limits

For each fee mechanism found:
- severity: "critical" if owner can set arbitrarily high fees, "high" if high fixed fees, "medium" otherwise
- location: relevant function names
- description: Fee mechanism and how it works
- recommendation: Security concerns

Return findings as JSON array:
[{{"severity": "critical|high|medium|low", "location": "function_name", "description": "...", "recommendation": "..."}}]
Only return the JSON array, no other text."""

    def _get_category(self) -> str:
        return "fee_tax"


class HoneypotDetectorAgent(BaseAuditAgent):
    """Identifies honeypot-style transfer restrictions."""

    async def analyze(
        self,
        contract_address: str,
        input_type: str,
        data: Union[str, Tuple],
    ) -> List[AgentFinding]:
        """Analyze for honeypot patterns."""
        if input_type != "BYTECODE_ABI":
            return []

        bytecode, abi, context = data
        prompt = self._build_prompt(contract_address, abi, context)
        response = await self._call_glm(prompt, "HoneypotDetector")
        return self._parse_findings(response, "HoneypotDetector")

    def _build_prompt(
        self,
        contract_address: str,
        abi: List[Dict],
        context: Dict,
    ) -> str:
        """Build honeypot detection prompt."""
        return f"""Analyze this contract for honeypot-style transfer restrictions.

Contract Address: {contract_address}
Contract Type: {context.get('contract_type', 'Unknown')}
Detected Standards: {context.get('detected_standards', [])}

Full ABI:
{json.dumps(abi, indent=2)}

Detect HONEYPOT patterns:

1. **MAX WALLET LIMITS** - Look for:
   - Functions that set max balance per wallet
   - _maxWallet, maxWallet, setMaxWallet patterns
   - If trading is blocked when limit reached

2. **MAX TRANSACTION LIMITS** - Look for:
   - Functions limiting max transaction size
   - _maxTx, maxTransaction, setMaxTx patterns
   - Whether large transfers are blocked

3. **TRADING ENABLE SWITCHES** - Look for:
   - Functions that enable/disable trading
   - tradingEnabled, setTrading, enableTrading patterns
   - If trading can be turned off by admin
   - _isTradingEnabled, _tradingOpen bool variables

4. **SELL RESTRICTIONS** - Look for:
   - Different rules for buying vs selling
   - Functions blocking sells (blockSell, isSellExempt)
   - Cooldown periods on sells

5. **WHITELIST/BLACKLIST TRAPS** - Look for:
   - Functions that can blacklist specific addresses
   - Whether blacklist can be applied after purchase
   - Trapping user funds

For each honeypot indicator found:
- severity: "critical" for trading switches + max limits, "high" for sell restrictions, "medium" for cooldowns
- location: relevant function names
- description: What restriction exists and how it traps users
- recommendation: Why this is dangerous and what to check

Return findings as JSON array:
[{{"severity": "critical|high|medium|low", "location": "function_name", "description": "...", "recommendation": "..."}}]
Only return the JSON array, no other text."""

    def _get_category(self) -> str:
        return "honeypot"


class UpgradeabilityAgent(BaseAuditAgent):
    """Detects upgradeability patterns and implementation slots."""

    async def analyze(
        self,
        contract_address: str,
        input_type: str,
        data: Union[str, Tuple],
    ) -> List[AgentFinding]:
        """Analyze upgradeability."""
        if input_type != "BYTECODE_ABI":
            return []

        bytecode, abi, context = data
        prompt = self._build_prompt(contract_address, bytecode, abi, context)
        response = await self._call_glm(prompt, "UpgradeabilityDetector")
        return self._parse_findings(response, "UpgradeabilityDetector")

    def _build_prompt(
        self,
        contract_address: str,
        bytecode: str,
        abi: List[Dict],
        context: Dict,
    ) -> str:
        """Build upgradeability analysis prompt."""
        return f"""Analyze this contract for upgradeability and proxy patterns.

Contract Address: {contract_address}
Bytecode Size: {context.get('bytecode_size', 0)} bytes
Is Proxy: {context.get('is_proxy', False)}
Proxy Type: {context.get('proxy_type', 'N/A')}
Implementation Address: {context.get('implementation_address', 'N/A')}

Full ABI:
{json.dumps(abi, indent=2)}

Detect UPGRADEABILITY:

1. **PROXY PATTERNS** - Check for:
   - upgradeTo, upgradeToAndCall functions (UUPS pattern)
   - admin, implementation functions (Transparent proxy)
   - Whether proxy is detected

2. **IMPLEMENTATION SLOTS** - Look for:
   - Functions that return implementation address
   - _implementation, getImplementation patterns
   - Whether implementation can be changed

3. **UPGRADE AUTHORITY** - Identify:
   - Who can trigger upgrades
   - Any timelock or delay on upgrades
   - Multi-sig requirements for upgrades

4. **BEACON/ DIAMOND PATTERNS** - Check for:
   - Diamond cut function signatures
   - Beacon proxy patterns
   - Fallback handlers

5. **RISK ASSESSMENT**:
   - Critical: Owner can upgrade to arbitrary code
   - High: Upgrade requires multi-sig or timelock
   - Medium: Upgrade pattern detected with safeguards
   - Low: Non-upgradeable immutable contract

Return findings as JSON array:
[{{"severity": "critical|high|medium|low", "location": "function_name", "description": "...", "recommendation": "..."}}]
Only return the JSON array, no other text."""

    def _get_category(self) -> str:
        return "upgradeability"


class DangerousOpcodeAgent(BaseAuditAgent):
    """Spots delegatecall, selfdestruct, and other dangerous opcodes."""

    async def analyze(
        self,
        contract_address: str,
        input_type: str,
        data: Union[str, Tuple],
    ) -> List[AgentFinding]:
        """Analyze for dangerous opcodes."""
        if input_type != "BYTECODE_ABI":
            return []

        bytecode, abi, context = data
        prompt = self._build_prompt(contract_address, bytecode, context)
        response = await self._call_glm(prompt, "DangerousOpcodeDetector")
        return self._parse_findings(response, "DangerousOpcodeDetector")

    def _build_prompt(
        self,
        contract_address: str,
        bytecode: str,
        context: Dict,
    ) -> str:
        """Build dangerous opcode analysis prompt."""
        return f"""Analyze this contract's bytecode for dangerous opcodes and patterns.

Contract Address: {contract_address}
Bytecode Size: {context.get('bytecode_size', 0)} bytes
Contract Type: {context.get('contract_type', 'Unknown')}

Known bytecode patterns detected:
{json.dumps(context.get('pattern_findings', []), indent=2)}

Scan for DANGEROUS OPCODES:

1. **DELEGATECALL (0xF4)** - Most dangerous:
   - Allows code execution in context of caller
   - Can be used for malicious proxy upgrades
   - High risk if target is user-supplied

2. **CALL/CALLCODE (0xF1/0xF2)** - Medium risk:
   - Low-level calls to arbitrary addresses
   - Reentrancy risk if not protected
   - Check if calls include value transfers

3. **SELFDESTRUCT (0xFF)** - Critical:
   - Contract can be destroyed
   - Funds can be lost if triggered
   - Check if properly access-controlled

4. **STATICCALL (0xFA)** - Low-Medium risk:
   - Read-only call to arbitrary contract
   - Safer than delegatecall but still needs caution

5. **CREATE/CREATE2 (0xF0/0xF5)**:
   - Can deploy arbitrary contracts
   - Check if creation is controlled

6. **TX.ORIGIN (0x32/0x34)**:
   - tx.origin authentication is vulnerable
   - Check if used for authorization

For each dangerous opcode found:
- severity: "critical" for selfdestruct/tx.origin, "high" for delegatecall, "medium" for call
- description: What the opcode does and why it's dangerous
- recommendation: How to use it safely or if it should be removed

Return findings as JSON array:
[{{"severity": "critical|high|medium|low", "description": "...", "recommendation": "..."}}]
Only return the JSON array, no other text."""

    def _get_category(self) -> str:
        return "dangerous_opcodes"


class PrivilegeRugRiskAgent(BaseAuditAgent):
    """Analyzes privilege & rug pull risks."""

    async def analyze(
        self,
        contract_address: str,
        input_type: str,
        data: Union[str, Tuple],
    ) -> List[AgentFinding]:
        """Analyze privilege and rug risks."""
        if input_type != "BYTECODE_ABI":
            return []

        bytecode, abi, context = data
        prompt = self._build_prompt(contract_address, abi, context)
        response = await self._call_glm(prompt, "PrivilegeRugRiskAnalyzer")
        return self._parse_findings(response, "PrivilegeRugRiskAnalyzer")

    def _build_prompt(
        self,
        contract_address: str,
        abi: List[Dict],
        context: Dict,
    ) -> str:
        """Build privilege/rug risk analysis prompt."""
        return f"""Analyze this contract for privilege concentration and rug pull risks.

Contract Address: {contract_address}
Contract Type: {context.get('contract_type', 'Unknown')}
Detected Standards: {context.get('detected_standards', [])}

Full ABI:
{json.dumps(abi, indent=2)}

Analyze PRIVILEGE & RUG RISK:

1. **OWNERSHIP STRUCTURE** - Identify:
   - owner() function and who it returns
   - onlyOwner/onlyAdmin modifier usage
   - Whether ownership is renounceable
   - Multi-sig or single owner

2. **CONTROL PATHS** - Map what admin can do:
   - Can admin change fees? (setFee, updateFee)
   - Can admin mint supply? (mint, issue)
   - Can admin freeze users? (pause, blacklist, freeze)
   - Can admin upgrade logic? (upgradeTo, setImplementation)
   - Can admin drain funds? (withdraw, drain, extract)

3. **ROLE-BASED ACCESS** - Check for:
   - Roles system (DEFAULT_ADMIN_ROLE, etc.)
   - Who can grant/revoke roles
   - Whether role assignments are protected

4. **RUG PULL INDICATORS** - Assess:
   - Centralized control >70% of supply
   - Can admin mint unlimited tokens?
   - Can admin disable trading?
   - Can admin drain liquidity?
   - Any stealth mechanisms?

5. **RISK SCORING**:
   - Critical: Admin can mint + drain + disable trading
   - High: Admin can mint + drain OR disable trading
   - Medium: Admin can drain OR disable trading
   - Low: Limited admin controls

Return findings as JSON array:
[{{"severity": "critical|high|medium|low", "location": "admin_function", "description": "...", "recommendation": "..."}}]
Only return the JSON array, no other text."""

    def _get_category(self) -> str:
        return "privilege_risk"


class BackdoorHunterAgent(BaseAuditAgent):
    """Hunts for backdoors: hidden hooks, trading switches, dynamic taxes, stealth mint."""

    async def analyze(
        self,
        contract_address: str,
        input_type: str,
        data: Union[str, Tuple],
    ) -> List[AgentFinding]:
        """Analyze for backdoors."""
        if input_type != "BYTECODE_ABI":
            return []

        bytecode, abi, context = data
        prompt = self._build_prompt(contract_address, abi, context)
        response = await self._call_glm(prompt, "BackdoorHunter")
        return self._parse_findings(response, "BackdoorHunter")

    def _build_prompt(
        self,
        contract_address: str,
        abi: List[Dict],
        context: Dict,
    ) -> str:
        """Build backdoor hunting prompt."""
        return f"""Hunt for backdoors and stealth mechanisms in this contract.

Contract Address: {contract_address}
Contract Type: {context.get('contract_type', 'Unknown')}
Detected Standards: {context.get('detected_standards', [])}

Full ABI:
{json.dumps(abi, indent=2)}

Hunt for BACKDOORS:

1. **HIDDEN OWNER-ONLY TRANSFER HOOKS** - Look for:
   - Custom transfer functions (not standard ERC20)
   - Functions that can block transfers based on hidden conditions
   - _beforeTokenTransfer, _afterTokenTransfer hooks with special logic
   - Any boolean flags that control transfers

2. **TRADING ENABLE SWITCHES** - Find:
   - Boolean variables like _tradingOpen, _isEnabled
   - Functions that toggle trading (setTrading, enableTrading)
   - Whether trading can be disabled AFTER purchase (rug pull trap)

3. **DYNAMIC TAX CHANGES** - Check for:
   - Functions that modify buy/sell tax percentages
   - setBuyTax, setSellTax, updateTax patterns
   - Whether admin can set tax to 100% (block trading)
   - Any tax that can be changed post-deployment

4. **STEALTH MINT MECHANISMS** - Look for:
   - Mint functions without events (stealth mint to hidden address)
   - Mint functions that bypass normal limits
   - Functions that increase supply without standard emit
   - Any backdoors to add supply

5. **PROXY UPGRADE BACKDOORS** - Check for:
   - upgradeTo functions that skip standard checks
   - Implementation changes that don't emit events
   - Any way to change logic without user awareness

6. **EMERGENCY WITHDRAW** - Find:
   - Emergency withdraw functions
   - Who can call them and under what conditions
   - Whether they can drain user funds

For each backdoor found:
- severity: "critical" if it can rug users, "high" if it can abuse users
- location: suspicious function names and patterns
- description: What the backdoor does and how it could be abused
- recommendation: Why this is dangerous and what to check

Return findings as JSON array:
[{{"severity": "critical|high|medium|low", "location": "suspicious_function", "description": "...", "recommendation": "..."}}]
Only return the JSON array, no other text."""

    def _get_category(self) -> str:
        return "backdoor"


class StructuralSecurityAgent(BaseAuditAgent):
    """Structural security checks: reentrancy, external calls, delegatecall trust, storage risks."""

    async def analyze(
        self,
        contract_address: str,
        input_type: str,
        data: Union[str, Tuple],
    ) -> List[AgentFinding]:
        """Analyze structural security."""
        if input_type != "BYTECODE_ABI":
            return []

        bytecode, abi, context = data
        prompt = self._build_prompt(contract_address, bytecode, abi, context)
        response = await self._call_glm(prompt, "StructuralSecurityChecker")
        return self._parse_findings(response, "StructuralSecurityChecker")

    def _build_prompt(
        self,
        contract_address: str,
        bytecode: str,
        abi: List[Dict],
        context: Dict,
    ) -> str:
        """Build structural security analysis prompt."""
        return f"""Analyze this contract's structural security patterns.

Contract Address: {contract_address}
Bytecode Size: {context.get('bytecode_size', 0)} bytes
Is Proxy: {context.get('is_proxy', False)}
Proxy Type: {context.get('proxy_type', 'N/A')}
Implementation Address: {context.get('implementation_address', 'N/A')}

Full ABI:
{json.dumps(abi, indent=2)}

Bytecode patterns detected:
{json.dumps(context.get('pattern_findings', []), indent=2)}

Check STRUCTURAL SECURITY:

1. **REENTRANCY RISK PATTERNS** - Based on ABI:
   - Functions with external call capabilities (call, delegatecall, send, transfer)
   - Withdraw-like functions that move funds
   - Whether there are balance checks before external calls
   - Any state change patterns visible in function signatures

2. **EXTERNAL CALL PATTERNS** - Identify:
   - Functions making calls to external addresses
   - approve, call, delegatecall, send, transferFrom usage
   - Low-level calls with address parameters
   - Whether external calls return values are checked

3. **DELEGATECALL TRUST BOUNDARIES** - Assess:
   - If contract is a proxy, where delegatecalls go
   - Whether delegatecall targets are user-controlled
   - Any ability to redirect delegatecall to malicious contracts

4. **STORAGE SLOT RISKS** (for upgradeable contracts):
   - If proxy, analyze storage slot patterns
   - Look for uninitialized storage slots that could be hijacked
   - Check for storage collisions in implementation changes
   - Whether admin-controlled storage slots can override critical data

5. **CALL STACK DEPTH** - Check for:
   - Functions that make multiple external calls
   - Risk of call stack overflow
   - Whether external calls are looped

6. **UNCHECKED RETURN VALUES** - Look for:
   - Low-level calls without checking success
   - transferFrom calls without return checks
   - delegatecall without verification

For each structural issue:
- severity: "critical" for unchecked delegatecall, "high" for reentrancy-prone patterns
- location: function names showing the pattern
- description: What structural vulnerability exists
- recommendation: How to fix or mitigate the issue

Return findings as JSON array:
[{{"severity": "critical|high|medium|low", "location": "function_pattern", "description": "...", "recommendation": "..."}}]
Only return the JSON array, no other text."""

    def _get_category(self) -> str:
        return "structural_security"


# ============================================================================
# SOURCE-CODE-ONLY AGENTS (13 Phases of Comprehensive Audit)
# ============================================================================

class SystemUnderstandingAgent(BaseAuditAgent):
    """Phase 1: System Understanding - identifies invariants, assumptions, and core mechanics."""

    async def analyze(
        self,
        contract_address: str,
        input_type: str,
        data: Union[str, Tuple],
    ) -> List[AgentFinding]:
        """Analyze system understanding elements."""
        if input_type != "SOURCE_CODE":
            return []

        source_code = data
        prompt = self._build_prompt(contract_address, source_code)
        response = await self._call_glm(prompt, "SystemUnderstandingAnalyzer")
        return self._parse_findings(response, "SystemUnderstandingAnalyzer")

    def _build_prompt(self, contract_address: str, source_code: str) -> str:
        """Build system understanding analysis prompt."""
        return f"""Analyze this Solidity contract for system understanding elements.

Contract Address: {contract_address}

Source Code:
{source_code}

Phase 1: SYSTEM UNDERSTANDING

Extract and analyze:

1. **INVARIANTS** - Identify:
   - What conditions should ALWAYS be true?
   - Total supply caps (if token contract)
   - Balance relationships (totalSupply = sum of all balances)
   - Ownership constraints
   - State variable relationships that must hold

2. **ASSUMPTIONS** - Document:
   - Trusted addresses (owner, admin, contracts)
   - External dependencies (oracle, other contracts)
   - Price feed assumptions
   - Block timestamp/block number assumptions
   - Caller assumptions (msg.sender expectations)

3. **CORE MECHANICS** - Map:
   - Primary data structures and their purpose
   - State machines (if any)
   - Role/permission system
   - Token economics (if applicable)
   - Reward/distribution mechanisms

4. **ENTRY/EXIT POINTS** - Identify:
   - User-facing functions (public/external)
   - Admin functions
   - Internal/private helper functions
   - Callback/hook functions

Return findings as JSON array:
[{{"severity": "info|low|medium", "location": "element_name", "description": "...", "recommendation": "..."}}]
Focus on documenting what the system does and what it assumes.

Only return the JSON array, no other text."""

    def _get_category(self) -> str:
        return "system_understanding"


class ArchitectureTrustBoundariesAgent(BaseAuditAgent):
    """Phase 2: Architecture & Trust Boundaries - identifies components and trust relationships."""

    async def analyze(
        self,
        contract_address: str,
        input_type: str,
        data: Union[str, Tuple],
    ) -> List[AgentFinding]:
        """Analyze architecture and trust boundaries."""
        if input_type != "SOURCE_CODE":
            return []

        source_code = data
        prompt = self._build_prompt(contract_address, source_code)
        response = await self._call_glm(prompt, "ArchitectureAnalyzer")
        return self._parse_findings(response, "ArchitectureAnalyzer")

    def _build_prompt(self, contract_address: str, source_code: str) -> str:
        """Build architecture analysis prompt."""
        return f"""Analyze this Solidity contract's architecture and trust boundaries.

Contract Address: {contract_address}

Source Code:
{source_code}

Phase 2: ARCHITECTURE & TRUST BOUNDARIES

Analyze:

1. **COMPONENT STRUCTURE** - Identify:
   - Is this a single contract or multi-contract system?
   - Import statements and external contract dependencies
   - Interface usage and what they expect
   - Inheritance hierarchy

2. **TRUST BOUNDARIES** - Map:
   - Which addresses are trusted (owner, admin, allowed contracts)?
   - External contract calls and trust assumptions
   - Which user inputs are considered trusted vs untrusted?
   - Bridge/cross-chain boundaries (if applicable)

3. **DATA FLOW** - Trace:
   - How does data enter the contract? (user input, oracle, external call)
   - How is data validated?
   - How does data flow between components?
   - Where does data exit the contract?

4. **ATTACK SURFACE** - Identify:
   - All external call points
   - All user-input entry points
   - State-changing functions
   - Privileged operations

5. **SECURITY BOUNDARIES** - Assess:
   - Access control boundaries
   - Reentrancy boundaries
   - Integer overflow/underflow boundaries
   - Gas limits/DoS boundaries

Return findings as JSON array:
[{{"severity": "critical|high|medium|low", "location": "function_name", "description": "...", "recommendation": "..."}}]
Focus on identifying weak trust boundaries and architectural risks.

Only return the JSON array, no other text."""

    def _get_category(self) -> str:
        return "architecture_trust"


class AccessControlRugSurfaceAgent(BaseAuditAgent):
    """Phase 3: Access Control (Rug Surface) - identifies rug pull vectors through privilege analysis."""

    async def analyze(
        self,
        contract_address: str,
        input_type: str,
        data: Union[str, Tuple],
    ) -> List[AgentFinding]:
        """Analyze access control and rug surface."""
        if input_type != "SOURCE_CODE":
            return []

        source_code = data
        prompt = self._build_prompt(contract_address, source_code)
        response = await self._call_glm(prompt, "AccessControlRugAnalyzer")
        return self._parse_findings(response, "AccessControlRugAnalyzer")

    def _build_prompt(self, contract_address: str, source_code: str) -> str:
        """Build access control rug surface analysis prompt."""
        return f"""Analyze this Solidity contract's access control and rug pull surface.

Contract Address: {contract_address}

Source Code:
{source_code}

Phase 3: ACCESS CONTROL (RUG SURFACE)

Map all RUG PULL VECTORS:

1. **OWNERSHIP STRUCTURE** - Identify:
   - Who is the owner/admin?
   - Can ownership be renounced?
   - Is there multi-sig or timelock protection?
   - Can admin privileges be transferred?

2. **PRIVILEGED OPERATIONS** - List all functions admin can call:
   - MINTING: Can admin mint tokens? Any limits?
   - BURNING: Can admin burn tokens (including user tokens)?
   - PAUSING: Can admin pause trading/transfers?
   - FEES: Can admin set fees to 100%?
   - BLACKLIST: Can admin freeze user accounts?
   - WITHDRAW: Can admin drain contract funds?
   - UPGRADE: Can admin change contract logic?

3. **RUG PULL PATHS** - For each privileged operation:
   - What happens if admin acts maliciously?
   - Are there any checks/limits on admin power?
   - Can users exit before admin acts?
   - Is there any notification/mechanism to detect abuse?

4. **ACCESS CONTROL PATTERNS** - Assess:
   - onlyOwner/onlyAdmin usage
   - Role-based access (AccessControl, Ownable)
   - Multi-sig requirements (if any)
   - Timelock on sensitive operations

5. **CENTRALIZATION RISKS** - Score:
   - Critical: Owner can rug (mint+drain+pause+blacklist)
   - High: Owner can drain or disable trading
   - Medium: Owner has significant control but limits exist
   - Low: Decentralized or immutable

Return findings as JSON array:
[{{"severity": "critical|high|medium|low", "location": "admin_function", "description": "Rug vector: ...", "recommendation": "..."}}]
Each finding should describe a specific rug pull path.

Only return the JSON array, no other text."""

    def _get_category(self) -> str:
        return "access_control_rug"


class StateLogicCorrectnessAgent(BaseAuditAgent):
    """Phase 4: State & Logic Correctness - identifies logic bugs and state inconsistencies."""

    async def analyze(
        self,
        contract_address: str,
        input_type: str,
        data: Union[str, Tuple],
    ) -> List[AgentFinding]:
        """Analyze state and logic correctness."""
        if input_type != "SOURCE_CODE":
            return []

        source_code = data
        prompt = self._build_prompt(contract_address, source_code)
        response = await self._call_glm(prompt, "StateLogicAnalyzer")
        return self._parse_findings(response, "StateLogicAnalyzer")

    def _build_prompt(self, contract_address: str, source_code: str) -> str:
        """Build state logic correctness analysis prompt."""
        return f"""Analyze this Solidity contract's state and logic correctness.

Contract Address: {contract_address}

Source Code:
{source_code}

Phase 4: STATE & LOGIC CORRECTNESS

Find LOGIC BUGS:

1. **STATE CONSISTENCY** - Check:
   - Are all state variables initialized properly?
   - Can state variables reach invalid values?
   - Are there contradictory state conditions?
   - Can state variables overflow/underflow?

2. **BUSINESS LOGIC ERRORS** - Look for:
   - Off-by-one errors in calculations
   - Incorrect rounding (especially in financial calculations)
   - Token balance accounting errors
   - Reward distribution bugs
   - Deadline/timestamp handling errors

3. **EDGE CASES** - Test:
   - What happens with zero values?
   - What happens with max values (type(uint256).max)?
   - What happens when arrays are empty/full?
   - What happens with division by zero?
   - What happens with address(0)?

4. **ORDERING ISSUES** - Check:
   - Are operations performed in correct order?
   - Should effects happen before or after external calls?
   - Are there race conditions between functions?
   - Can multiple transactions interfere?

5. **BOOLEAN LOGIC** - Verify:
   - Are if/else conditions correct?
   - Are AND/OR conditions properly grouped?
   - Are negation operators (!) correctly placed?
   - Are require/assert messages clear?

6. **DATA STRUCTURE ISSUES** - Check:
   - Array index out of bounds
   - Mapping key existence checks
   - Uninitialized storage pointers
   - Struct field ordering (storage packing)

Return findings as JSON array:
[{{"severity": "critical|high|medium|low", "location": "function_name", "description": "Logic bug: ...", "recommendation": "..."}}]
Focus on actual bugs, not style issues.

Only return the JSON array, no other text."""

    def _get_category(self) -> str:
        return "state_logic"


class ExternalCallsReentrancyAgent(BaseAuditAgent):
    """Phase 5: External Calls & Reentrancy - identifies external call vulnerabilities."""

    async def analyze(
        self,
        contract_address: str,
        input_type: str,
        data: Union[str, Tuple],
    ) -> List[AgentFinding]:
        """Analyze external calls and reentrancy."""
        if input_type != "SOURCE_CODE":
            return []

        source_code = data
        prompt = self._build_prompt(contract_address, source_code)
        response = await self._call_glm(prompt, "ExternalCallsReentrancyAnalyzer")
        return self._parse_findings(response, "ExternalCallsReentrancyAnalyzer")

    def _build_prompt(self, contract_address: str, source_code: str) -> str:
        """Build external calls and reentrancy analysis prompt."""
        return f"""Analyze this Solidity contract for external calls and reentrancy vulnerabilities.

Contract Address: {contract_address}

Source Code:
{source_code}

Phase 5: EXTERNAL CALLS & REENTRANCY

Find EXTERNAL CALL VULNERABILITIES:

1. **LOW-LEVEL CALLS** - Identify all instances of:
   - call{{}}, delegatecall{{}}, staticcall{{}}
   - send{{}}, transfer{{}}
   - address.call{{value: ...}}
   - Are return values checked?
   - Is gas specified or left to default?

2. **REENTRANCY VULNERABILITIES** - Check:
   - External calls BEFORE state changes (CEI pattern violation)
   - Functions that call external contracts
   - ETH transfers that aren't the last operation
   - Is ReentrancyGuard used? Where is it missing?

3. **CROSS-FUNCTION REENTRANCY** - Look for:
   - Can one function be reentered through another?
   - Shared state across external calls
   - Functions that call external contracts which call back

4. **READ-ONLY REENTRANCY** - Check:
   - Can external calls manipulate view/pure function results?
   - Are view functions actually view (no state changes)?
   - Can state be read mid-transaction during external call?

5. **CALL FAILURES** - Verify:
   - Are call return values checked?
   - What happens if call fails?
   - Is there proper error handling?
   - Can failed calls cause state corruption?

6. **DELEGATECALL RISKS** - Assess:
   - Where is delegatecall used?
   - Can delegatecall target be user-controlled?
   - Is delegatecall used with untrusted contracts?
   - Storage layout compatibility

Return findings as JSON array:
[{{"severity": "critical|high|medium|low", "location": "function_name", "description": "...", "recommendation": "..."}}]
Critical for unhandled reentrancy, high for unchecked calls.

Only return the JSON array, no other text."""

    def _get_category(self) -> str:
        return "external_calls_reentrancy"


class EconomicAttackSurfaceAgent(BaseAuditAgent):
    """Phase 6: Economic Attack Surface - identifies price manipulation and economic vulnerabilities."""

    async def analyze(
        self,
        contract_address: str,
        input_type: str,
        data: Union[str, Tuple],
    ) -> List[AgentFinding]:
        """Analyze economic attack surface."""
        if input_type != "SOURCE_CODE":
            return []

        source_code = data
        prompt = self._build_prompt(contract_address, source_code)
        response = await self._call_glm(prompt, "EconomicAttackAnalyzer")
        return self._parse_findings(response, "EconomicAttackAnalyzer")

    def _build_prompt(self, contract_address: str, source_code: str) -> str:
        """Build economic attack surface analysis prompt."""
        return f"""Analyze this Solidity contract's economic attack surface.

Contract Address: {contract_address}

Source Code:
{source_code}

Phase 6: ECONOMIC ATTACK SURFACE

Find ECONOMIC VULNERABILITIES:

1. **PRICE MANIPULATION** - Check:
   - Does contract use oracles? (Chainlink, TWAP, etc.)
   - Can prices be manipulated?
   - Are there stale price checks?
   - Is there a circuit breaker for price anomalies?
   - Can flash loans affect prices?

2. **FLASH LOAN ATTACKS** - Look for:
   - Does contract integrate with lending protocols?
   - Can state be updated in same block as loan?
   - Are there reentrancy risks from flash loans?
   - Is there minimum time delay between operations?

3. **LIQUIDITY ISSUES** - Assess:
   - Can liquidity be drained?
   - Are there liquidity locks?
   - Can admin remove liquidity?
   - Is liquidity distributed or centralized?

4. **FEE MANIPULATION** - Check:
   - Can fees be set to 100%?
   - Can fee recipients be changed?
   - Are there maximum fee caps?
   - Can fees be diverted to wrong addresses?

5. **TOKEN SUPPLY ATTACKS** - Identify:
   - Unlimited minting capabilities
   - Can supply be inflated to dilute users?
   - Are there minting limits or caps?
   - Can minting be triggered by attackers?

6. **ARBITRAGE/MEV** - Assess:
   - Are there profitable MEV opportunities?
   - Can transactions be front-run?
   - Are there sandwich attack risks?
   - Is there slippage protection?

7. **ECONOMIC EXPLOITS** - Look for:
   - Integer rounding in attacker's favor
   - Reward gaming mechanisms
   - Collateralization issues
   - Debt/leverage vulnerabilities

Return findings as JSON array:
[{{"severity": "critical|high|medium|low", "location": "function_name", "description": "...", "recommendation": "..."}}]
Critical for unbounded minting/fees, high for oracle manipulation.

Only return the JSON array, no other text."""

    def _get_category(self) -> str:
        return "economic_attack"


class UpgradeabilitySafetyAgent(BaseAuditAgent):
    """Phase 7: Upgradeability Safety - identifies upgrade risks and implementation issues."""

    async def analyze(
        self,
        contract_address: str,
        input_type: str,
        data: Union[str, Tuple],
    ) -> List[AgentFinding]:
        """Analyze upgradeability safety."""
        if input_type != "SOURCE_CODE":
            return []

        source_code = data
        prompt = self._build_prompt(contract_address, source_code)
        response = await self._call_glm(prompt, "UpgradeabilitySafetyAnalyzer")
        return self._parse_findings(response, "UpgradeabilitySafetyAnalyzer")

    def _build_prompt(self, contract_address: str, source_code: str) -> str:
        """Build upgradeability safety analysis prompt."""
        return f"""Analyze this Solidity contract's upgradeability safety.

Contract Address: {contract_address}

Source Code:
{source_code}

Phase 7: UPGRADEABILITY SAFETY

Analyze UPGRADE MECHANISMS:

1. **PROXY PATTERN** - Identify:
   - What proxy pattern? (Transparent, UUPS, Beacon, Diamond)
   - Is proxy code correct or buggy?
   - Where is implementation stored?
   - How are upgrades triggered?

2. **UPGRADE AUTHORITY** - Check:
   - Who can upgrade? (owner, admin, governance, timelock)
   - Is there multi-sig protection?
   - Is there a timelock delay on upgrades?
   - Can upgrade authority be transferred?

3. **STORAGE LAYOUT** - Verify:
   - Are storage variables properly ordered?
   - Is there a gap for future variables?
   - Can storage collisions occur on upgrade?
   - Are inherited contracts laid out correctly?

4. **INITIALIZATION** - Check:
   - Is initialize() function instead of constructor?
   - Can initialize() be called multiple times?
   - Is there an initialized guard?
   - Are all critical variables initialized?

5. **UPGRADE RISKS** - Assess:
   - Can implementation be upgraded to malicious code?
   - Is there a way to rescue funds if upgrade breaks?
   - Are users notified of upgrades?
   - Is there a rollback mechanism?

6. **IMPLEMENTATION COMPATIBILITY** - Check:
   - Can upgrade break existing functionality?
   - Are function signatures preserved?
   - Can storage layout changes brick the contract?
   - Are there upgrade tests?

Return findings as JSON array:
[{{"severity": "critical|high|medium|low", "location": "upgrade_function", "description": "...", "recommendation": "..."}}]
Critical for owner-upgradeable with no timelock, high for storage collision risks.

Only return the JSON array, no other text."""

    def _get_category(self) -> str:
        return "upgradeability_safety"


class DoSAndGasRisksAgent(BaseAuditAgent):
    """Phase 8: DoS & Gas Risks - identifies denial of service and gas issues."""

    async def analyze(
        self,
        contract_address: str,
        input_type: str,
        data: Union[str, Tuple],
    ) -> List[AgentFinding]:
        """Analyze DoS and gas risks."""
        if input_type != "SOURCE_CODE":
            return []

        source_code = data
        prompt = self._build_prompt(contract_address, source_code)
        response = await self._call_glm(prompt, "DoSGasAnalyzer")
        return self._parse_findings(response, "DoSGasAnalyzer")

    def _build_prompt(self, contract_address: str, source_code: str) -> str:
        """Build DoS and gas risks analysis prompt."""
        return f"""Analyze this Solidity contract for DoS and gas risks.

Contract Address: {contract_address}

Source Code:
{source_code}

Phase 8: DOS & GAS RISKS

Find DOS and GAS VULNERABILITIES:

1. **UNBOUNDED LOOPS** - Identify:
   - Loops that can grow arbitrarily large
   - Loops over array/map entries that users can populate
   - Nested loops (O(n²) or worse)
   - Can loops hit block gas limit?

2. **GAS GRIEFING** - Check:
   - Can users make operations expensive for others?
   - Are there gas-dependent operations?
   - Can users fill data structures to cause DoS?

3. **BLOCK GAS LIMIT** - Assess:
   - Can operations exceed block gas limit?
   - Are there bulk operations that risk DoS?
   - Is there pagination for large datasets?

4. **CALLSTACK ATTACK** - Check:
   - Deep call chains that can hit stack limit
   - Recursive calls
   - Can attackers force deep calls?

5. **ETHER FLOOD** - Look for:
   - Can users force contract to hold ETH?
   - Is there a way to withdraw forced ETH?
   - Can forced ETH brick the contract?

6. **INSUFFICIENT GAS** - Check:
   - External calls without enough gas
   - transfer() vs call() for ETH sends
   - Can operations fail due to gas limits?

7. **GAS OPTIMIZATION** - Identify:
   - Unnecessary storage reads/writes
   - Loops that can be optimized
   - Redundant calculations
   - Expensive operations in critical paths

Return findings as JSON array:
[{{"severity": "critical|high|medium|low", "location": "function_name", "description": "...", "recommendation": "..."}}]
Critical for unbounded user-controlled loops, high for gas griefing vectors.

Only return the JSON array, no other text."""

    def _get_category(self) -> str:
        return "dos_gas"


class TokenStandardComplianceAgent(BaseAuditAgent):
    """Phase 9: Token & Standard Compliance - identifies compliance issues with ERC standards."""

    async def analyze(
        self,
        contract_address: str,
        input_type: str,
        data: Union[str, Tuple],
    ) -> List[AgentFinding]:
        """Analyze token and standard compliance."""
        if input_type != "SOURCE_CODE":
            return []

        source_code = data
        prompt = self._build_prompt(contract_address, source_code)
        response = await self._call_glm(prompt, "TokenComplianceAnalyzer")
        return self._parse_findings(response, "TokenComplianceAnalyzer")

    def _build_prompt(self, contract_address: str, source_code: str) -> str:
        """Build token and standard compliance analysis prompt."""
        return f"""Analyze this Solidity contract's token and standard compliance.

Contract Address: {contract_address}

Source Code:
{source_code}

Phase 9: TOKEN & STANDARD COMPLIANCE

Check STANDARD COMPLIANCE:

1. **ERC20 COMPLIANCE** (if token contract):
   - transfer(), transferFrom(), approve()
   - balanceOf(), allowance(), totalSupply()
   - Return true/false on success/failure
   - Events: Transfer, Approval

2. **ERC721 COMPLIANCE** (if NFT contract):
   - transferFrom(), safeTransferFrom()
   - approve(), setApprovalForAll(), getApproved()
   - ownerOf(), balanceOf()
   - Events: Transfer, Approval, ApprovalForAll

3. **ERC1155 COMPLIANCE** (if multi-token):
   - safeTransferFrom(), safeBatchTransferFrom()
   - balanceOf(), balanceOfBatch()
   - setApprovalForAll()
   - Events: TransferSingle, TransferBatch, ApprovalForAll

4. **STANDARD VIOLATIONS** - Check:
   - Modified return values (doesn't return bool)
   - Missing events
   - Non-standard function signatures
   - Broken approval patterns

5. **METADATA COMPLIANCE**:
   - name(), symbol(), decimals() for ERC20
   - name(), symbol(), tokenURI() for ERC721
   - uri() for ERC1155
   - Metadata extensions

6. **SAFETY VIOLATIONS** - Look for:
   - Missing return value checks
   - Unsafe transfers (no safeTransfer)
   - Approval race conditions
   - Burning from zero address

7. **CUSTOM IMPLEMENTATIONS** - Assess:
   - What deviations from standard exist?
   - Are they justified or suspicious?
   - Do they break integrations?

Return findings as JSON array:
[{{"severity": "critical|high|medium|low", "location": "function_name", "description": "...", "recommendation": "..."}}]
Critical for broken transfer/approval, high for missing events/returns.

Only return the JSON array, no other text."""

    def _get_category(self) -> str:
        return "token_compliance"


class InitializationDeploymentAgent(BaseAuditAgent):
    """Phase 10: Initialization & Deployment - identifies initialization and deployment issues."""

    async def analyze(
        self,
        contract_address: str,
        input_type: str,
        data: Union[str, Tuple],
    ) -> List[AgentFinding]:
        """Analyze initialization and deployment."""
        if input_type != "SOURCE_CODE":
            return []

        source_code = data
        prompt = self._build_prompt(contract_address, source_code)
        response = await self._call_glm(prompt, "InitializationAnalyzer")
        return self._parse_findings(response, "InitializationAnalyzer")

    def _build_prompt(self, contract_address: str, source_code: str) -> str:
        """Build initialization and deployment analysis prompt."""
        return f"""Analyze this Solidity contract's initialization and deployment.

Contract Address: {contract_address}

Source Code:
{source_code}

Phase 10: INITIALIZATION & DEPLOYMENT

Check INITIALIZATION:

1. **CONSTRUCTOR vs INITIALIZER** - Identify:
   - Is constructor() used for deployment-time setup?
   - Is initialize() used for proxies?
   - Can both be called?
   - Are they properly separated?

2. **INITIALIZATION ISSUES** - Check:
   - Are all state variables initialized?
   - Can initialize() be called multiple times?
   - Is there an initialized guard?
   - Are critical parameters set properly?

3. **DEPLOYMENT ORDER** - Verify:
   - Are contracts deployed in correct order?
   - Are constructor parameters correct?
   - Are constructor args validated?
   - Can deployment fail leaving system broken?

4. **IMMUTABLE VS CONFIGURABLE** - Assess:
   - What should be immutable but isn't?
   - What can be changed that shouldn't be?
   - Are constants actually constant?
   - Are constructor parameters properly stored?

5. **UPGRADEABLE CONTRACTS** - Check:
   - Does proxy delegate to uninitialized implementation?
   - Is initialize() called after proxy deployment?
   - Can implementation be changed before initialization?

6. **CONSTRUCTOR VULNERABILITIES** - Look for:
   - Unchecked constructor parameters
   - Delegatecall in constructor
   - External calls in constructor
   - Missing zero address checks

7. **POST-DEPLOYMENT** - Verify:
   - Are there required setup steps after deployment?
   - Can contract be used immediately after deployment?
   - Are there missing configurations?

Return findings as JSON array:
[{{"severity": "critical|high|medium|low", "location": "constructor/init", "description": "...", "recommendation": "..."}}]
Critical for missing initialization, high for re-initialization risks.

Only return the JSON array, no other text."""

    def _get_category(self) -> str:
        return "initialization"


class LibrariesLowLevelCodeAgent(BaseAuditAgent):
    """Phase 11: Libraries & Low-Level Code - identifies library usage and low-level code risks."""

    async def analyze(
        self,
        contract_address: str,
        input_type: str,
        data: Union[str, Tuple],
    ) -> List[AgentFinding]:
        """Analyze libraries and low-level code."""
        if input_type != "SOURCE_CODE":
            return []

        source_code = data
        prompt = self._build_prompt(contract_address, source_code)
        response = await self._call_glm(prompt, "LibrariesLowLevelAnalyzer")
        return self._parse_findings(response, "LibrariesLowLevelAnalyzer")

    def _build_prompt(self, contract_address: str, source_code: str) -> str:
        """Build libraries and low-level code analysis prompt."""
        return f"""Analyze this Solidity contract's library usage and low-level code.

Contract Address: {contract_address}

Source Code:
{source_code}

Phase 11: LIBRARIES & LOW-LEVEL CODE

Check LIBRARY and LOW-LEVEL CODE:

1. **LIBRARY USAGE** - Identify:
   - Which libraries are imported?
   - Are they trusted (OpenZeppelin, etc.) or custom?
   - For what purpose are they used?
   - Are they using for or delegatecall?

2. **INLINE ASSEMBLY** - Find:
   - All assembly {{ }} blocks
   - What does the assembly code do?
   - Is it necessary or could Solidity be used?
   - Are there assembly bugs?

3. **LOW-LEVEL CALLS** - Check all instances of:
   - call{{}}, delegatecall{{}}, staticcall{{}}
   - send{{}}, transfer{{}}
   - create{{}}, create2{{}}
   - selfdestruct (if pre-Paris)
   - Are they used safely?

4. **YUL/YUL-ADVANCED** - Assess:
   - Yul code in "using for" statements
   - Yul functions and their safety
   - Memory management in Yul
   - Stack management issues

5. **LIBRARY VULNERABILITIES** - Look for:
   - Reentrancy in library functions
   - Integer overflows in custom libraries
   - Untrusted library calls
   - Library logic bugs

6. **STORAGE POINTER DANGERS** - Check:
   - Storage pointers in libraries
   - Struct storage pointer confusion
   - Array storage pointer issues
   - Delegatecall storage overlap

Return findings as JSON array:
[{{"severity": "critical|high|medium|low", "location": "code_location", "description": "...", "recommendation": "..."}}]
Critical for unsafe assembly, high for untrusted libraries.

Only return the JSON array, no other text."""

    def _get_category(self) -> str:
        return "libraries_lowlevel"


class InvariantBreakingAttemptsAgent(BaseAuditAgent):
    """Phase 12: Invariant Breaking Attempts - identifies paths that could break system invariants."""

    async def analyze(
        self,
        contract_address: str,
        input_type: str,
        data: Union[str, Tuple],
    ) -> List[AgentFinding]:
        """Analyze invariant breaking attempts."""
        if input_type != "SOURCE_CODE":
            return []

        source_code = data
        prompt = self._build_prompt(contract_address, source_code)
        response = await self._call_glm(prompt, "InvariantBreakingAnalyzer")
        return self._parse_findings(response, "InvariantBreakingAnalyzer")

    def _build_prompt(self, contract_address: str, source_code: str) -> str:
        """Build invariant breaking attempts analysis prompt."""
        return f"""Analyze this Solidity contract for invariant breaking attempts.

Contract Address: {contract_address}

Source Code:
{source_code}

Phase 12: INVARIANT BREAKING ATTEMPTS

Find PATHS TO BREAK INVARIANTS:

1. **IDENTIFY INVARIANTS** - First determine:
   - Total supply should equal sum of all balances (ERC20)
   - No tokens should be created/destroyed without mint/burn
   - Sum of collateral should equal sum of borrows (lending)
   - Balance should never overflow/underflow
   - What other invariants exist?

2. **TEST EACH INFARIANT** - For each invariant:
   - Can state be manipulated to violate it?
   - Are there functions that can break it?
   - Can external calls trigger violation?
   - Can reentrancy cause violation?

3. **OVERFLOW/UNDERFLOW** - Check:
   - Can arithmetic cause wrapping?
   - Are SafeMath or Solidity 0.8+ checks used?
   - Can addition cause overflow?
   - Can subtraction cause underflow?

4. **STATE CORRUPTION** - Look for:
   - Direct storage writes
   - Unchecked external calls modifying state
   - Delegatecall to malicious contracts
   - Storage pointer manipulation

5. **ACCOUNTING GAPS** - Check:
   - Can balance diverge from actual tokens?
   - Can rewards be claimed without earning?
   - Can fees be bypassed?
   - Can voting power be gamed?

6. **CROSS-CONTRACT INVARIANTS** - Assess:
   - If multi-contract system, are invariants maintained across calls?
   - Can one contract break another's invariants?
   - Are there atomic operations that span contracts?

Return findings as JSON array:
[{{"severity": "critical|high|medium|low", "location": "function_name", "description": "Invariant: ... can be broken by ...", "recommendation": "..."}}]
Critical for any breakable invariant, high for potential violations.

Only return the JSON array, no other text."""

    def _get_category(self) -> str:
        return "invariant_breaking"


class TestingQualityAgent(BaseAuditAgent):
    """Phase 13: Testing Quality Review - identifies test gaps and quality issues."""

    async def analyze(
        self,
        contract_address: str,
        input_type: str,
        data: Union[str, Tuple],
    ) -> List[AgentFinding]:
        """Analyze testing quality."""
        if input_type != "SOURCE_CODE":
            return []

        source_code = data
        prompt = self._build_prompt(contract_address, source_code)
        response = await self._call_glm(prompt, "TestingQualityAnalyzer")
        return self._parse_findings(response, "TestingQualityAnalyzer")

    def _build_prompt(self, contract_address: str, source_code: str) -> str:
        """Build testing quality analysis prompt."""
        return f"""Analyze this Solidity contract's testing quality based on the code.

Contract Address: {contract_address}

Source Code:
{source_code}

Phase 13: TESTING QUALITY REVIEW

Assess TESTING QUALITY (based on code evidence):

1. **TEST COVERAGE GAPS** - Identify untested areas:
   - Complex functions that need thorough testing
   - Edge cases that might be missed
   - External call scenarios
   - Error conditions and revert cases
   - Access control paths

2. **CRITICAL PATHS TO TEST** - List what must be tested:
   - All privileged/admin functions
   - All external calls
   - All state changes
   - All arithmetic operations
   - All access control checks

3. **PROPERTY TESTS NEEDED** - Identify:
   - Invariants that should be property tested
   - Fuzzing targets (user inputs)
   - State transition properties
   - Mathematical relationships

4. **INTEGRATION TESTS NEEDED** - Check:
   - Multi-contract interactions
   - Upgrade scenarios (if upgradeable)
   - Cross-contract calls
   - External protocol integrations

5. **EDGE CASES TO TEST** - List:
   - Zero values
   - Max values
   - Empty arrays
   - Boundary conditions
   - Reentrancy scenarios

6. **SECURITY TESTS NEEDED** - Identify:
   - Reentrancy attempts
   - Access control bypasses
   - Overflow/underflow attempts
   - Front-running scenarios
   - Gas griefing attempts

Return findings as JSON array:
[{{"severity": "high|medium|low|info", "location": "function/area", "description": "Test gap: ...", "recommendation": "Test should cover ..."}}]
These are recommendations, not critical issues in production code.

Only return the JSON array, no other text."""

    def _get_category(self) -> str:
        return "testing_quality"


class UnifiedGLMOrchestrator:
    """Unified GLM agent orchestrator for ALL contract analysis.

    Routes to specialized agents based on input type:
    - SOURCE_CODE: Verified contract agents (13 source-code-only + shared agents)
    - BYTECODE_ABI: Unverified contract agents (bytecode-only + shared agents)

    Shared agents work with both input types (with specialized prompts).
    """

    def __init__(self, api_key: Optional[str] = None):
        """Initialize the unified GLM orchestrator."""
        self.api_key = api_key or GLM_API_KEY

        # Initialize shared agents (work with both input types)
        self.shared_agents = [
            ReentrancyAgent(api_key),
            AccessControlAgent(api_key),
            ArithmeticSafetyAgent(api_key),
        ]

        # Initialize bytecode-only agents
        self.bytecode_agents = [
            BytecodePatternAgent(api_key),
            AbiFunctionAgent(api_key),
            ContractCapabilitiesAgent(api_key),  # Minting, burning, pausing, blacklisting
            FeeTaxAgent(api_key),  # Fee/tax logic
            HoneypotDetectorAgent(api_key),  # Max wallet, trading switches
            UpgradeabilityAgent(api_key),  # Proxy patterns, implementation slots
            DangerousOpcodeAgent(api_key),  # Delegatecall, selfdestruct
            PrivilegeRugRiskAgent(api_key),  # Control paths, admin capabilities
            BackdoorHunterAgent(api_key),  # Hidden hooks, stealth mechanisms
            StructuralSecurityAgent(api_key),  # Storage slot risks, call patterns
        ]

        # Initialize source-code-only agents (13 comprehensive audit phases)
        self.source_code_agents = [
            SystemUnderstandingAgent(api_key),  # Phase 1: Invariants, assumptions
            ArchitectureTrustBoundariesAgent(api_key),  # Phase 2: Components, trust boundaries
            AccessControlRugSurfaceAgent(api_key),  # Phase 3: Rug pull vectors
            StateLogicCorrectnessAgent(api_key),  # Phase 4: Logic bugs, state inconsistencies
            ExternalCallsReentrancyAgent(api_key),  # Phase 5: External call vulnerabilities
            EconomicAttackSurfaceAgent(api_key),  # Phase 6: Price manipulation, economic vulnerabilities
            UpgradeabilitySafetyAgent(api_key),  # Phase 7: Upgrade risks
            DoSAndGasRisksAgent(api_key),  # Phase 8: DoS, gas issues
            TokenStandardComplianceAgent(api_key),  # Phase 9: ERC standard compliance
            InitializationDeploymentAgent(api_key),  # Phase 10: Initialization, deployment issues
            LibrariesLowLevelCodeAgent(api_key),  # Phase 11: Libraries, low-level code
            InvariantBreakingAttemptsAgent(api_key),  # Phase 12: Invariant breaking paths
            TestingQualityAgent(api_key),  # Phase 13: Test gaps, quality issues
        ]

    async def analyze_contract(
        self,
        contract_address: str,
        input_type: str,  # "SOURCE_CODE" or "BYTECODE_ABI"
        data: Union[str, Tuple],
    ) -> List[Dict[str, Any]]:
        """Route to appropriate specialized agents based on input type.

        For VERIFIED contracts (SOURCE_CODE):
        - Uses shared agents with source code prompts
        - Uses 13 specialized source-code-only agents
        - Comprehensive 13-phase audit coverage

        For UNVERIFIED contracts (BYTECODE_ABI):
        - Uses shared agents with bytecode-specialized prompts
        - Uses 10 bytecode-specific agents
        - Pattern matching + GLM inference

        Args:
            contract_address: Contract address for context
            input_type: Type of input ("SOURCE_CODE" or "BYTECODE_ABI")
            data: Source code string OR (bytecode, abi, context) tuple

        Returns:
            List of finding dicts
        """
        LOGGER.info(
            f"GLM analysis for {contract_address} with input_type={input_type}"
        )

        all_findings = []

        # Select agents based on input type
        if input_type == "SOURCE_CODE":
            # For verified contracts: shared agents + source-code-only agents
            agents = self.shared_agents + self.source_code_agents
        elif input_type == "BYTECODE_ABI":
            # For unverified contracts: shared agents + bytecode-only agents
            agents = self.shared_agents + self.bytecode_agents
        else:
            LOGGER.error(f"Unknown input_type: {input_type}")
            return []

        # Run all agents
        for agent in agents:
            try:
                findings = await agent.analyze(contract_address, input_type, data)
                all_findings.extend([f.to_dict() for f in findings])
                LOGGER.info(f"{agent.__class__.__name__}: {len(findings)} findings")
            except Exception as e:
                LOGGER.error(f"Agent {agent.__class__.__name__} failed: {e}")

        LOGGER.info(f"Total GLM findings: {len(all_findings)}")
        return all_findings

    def get_agent_info(self) -> Dict[str, Any]:
        """Get information about available agents."""
        return {
            "shared_agents": [a.__class__.__name__ for a in self.shared_agents],
            "bytecode_agents": [a.__class__.__name__ for a in self.bytecode_agents],
            "source_code_agents": [a.__class__.__name__ for a in self.source_code_agents],
            "total_agents": len(self.shared_agents) + len(self.bytecode_agents) + len(self.source_code_agents),
        }
