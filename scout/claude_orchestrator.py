"""Claude Code CLI Orchestrator for smart contract audits.

This orchestrator wraps claude-code CLI to run security analysis
using custom agents configured to work with GLM API.

Replaces the GLM API direct calls with claude-code CLI invocations,
allowing you to use your custom agent definitions.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

LOGGER = logging.getLogger(__name__)


@dataclass
class ClaudeAgentFinding:
    """Finding from a claude-code agent analysis."""
    agent_name: str
    severity: str  # "info", "low", "medium", "high", "critical"
    category: str  # "reentrancy", "access_control", "arithmetic", "gas", "logic"
    description: str
    location: Optional[str]  # Function/line reference
    recommendation: str
    confidence: str = "medium"

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


class ClaudeCodeOrchestrator:
    """Orchestrator for running claude-code CLI with custom agents.

    This replaces the direct GLM API calls with claude-code CLI invocations,
    allowing you to use your custom security audit agents.
    """

    def __init__(self):
        """Initialize the orchestrator."""
        LOGGER.info("=" * 80)
        LOGGER.info("INITIALIZING CLAUDE-CODE ORCHESTRATOR")
        LOGGER.info("=" * 80)

        # Step 1: Find claude-code CLI
        self.claude_path = self._find_claude_cli()
        LOGGER.info(f"[CLI] Using claude-code CLI at: {self.claude_path}")

        # Verify CLI is accessible
        try:
            import subprocess
            result = subprocess.run([self.claude_path, "--version"], capture_output=True, timeout=10)
            if result.returncode == 0:
                version_output = result.stdout.decode().strip()
                LOGGER.info(f"[CLI] claude-code CLI version: {version_output}")
            else:
                LOGGER.warning(f"[CLI] claude-code CLI exists but --version failed: {result.stderr.decode()[:100]}")
        except Exception as e:
            LOGGER.error(f"[CLI] Failed to verify claude-code CLI: {e}")

        # Step 2: Load agent configurations
        self.agents_config = self._load_agents_config()
        LOGGER.info(f"[AGENTS] Loaded {len(self.agents_config)} custom agents:")
        for agent_name, config in self.agents_config.items():
            LOGGER.info(f"  - {agent_name}: {config.get('description', 'No description')}")

        # Step 3: Check GLM API configuration
        glm_api_key = os.getenv("GLM_API_KEY") or os.getenv("ANTHROPIC_AUTH_TOKEN")
        glm_api_url = os.getenv("GLM_API_URL") or os.getenv("ANTHROPIC_BASE_URL")
        glm_model = os.getenv("GLM_MODEL", "glm-4.7")

        if glm_api_key:
            masked_key = f"{glm_api_key[:8]}...{glm_api_key[-4:]}" if len(glm_api_key) > 12 else "***"
            LOGGER.info(f"[API] GLM API Key configured: {masked_key}")
            LOGGER.info(f"[API] GLM API URL: {glm_api_url}")
            LOGGER.info(f"[API] GLM Model: {glm_model}")
        else:
            LOGGER.warning("[API] GLM API Key not configured - analyses may fail")

        LOGGER.info("=" * 80)
        LOGGER.info("CLAUDE-CODE ORCHESTRATOR INITIALIZATION COMPLETE")
        LOGGER.info("=" * 80)

    def _find_claude_cli(self) -> str:
        """Find the claude-code CLI executable."""
        # Try common paths
        possible_paths = [
            "/usr/bin/claude",
            "/usr/local/bin/claude",
            "/home/scout/.local/bin/claude",
            "claude",  # Hope it's in PATH
        ]

        for path in possible_paths:
            if os.path.exists(path) or path == "claude":
                return path

        # Default to claude and hope it's in PATH
        return "claude"

    def _load_agents_config(self) -> Dict[str, Dict]:
        """Load custom agent configurations.

        Returns dict mapping agent names to their configurations.
        """
        agents = {}

        # Default security audit agents
        default_agents = {
            "reentrancy-guard": {
                "description": "Detects reentrancy vulnerabilities in smart contracts",
                "prompt": """You are a smart contract security expert specializing in reentrancy attacks.

Analyze the following Solidity code for reentrancy vulnerabilities.

IMPORTANT: Focus on ACTUAL EXPLOITABILITY. Check the logic flow to determine if there's a real path to fund loss.

{code}

SEVERITY GUIDELINES - Use these criteria when assigning severity:

CRITICAL - Direct fund loss requiring immediate fix before deployment:
- External call to user-controlled address BEFORE state update (e.g., balance deduction)
- State update happens AFTER external call returns
- Attacker can recursively call to drain funds/tokens
- Clear exploit path: attacker can call back before state changes complete

HIGH - Potential for significant financial loss, must fix before deployment:
- External call pattern that could be exploited with specific conditions
- Missing or broken checks-effects-interactions pattern in fund-transfer functions
- Low-level calls (call, delegatecall) without proper reentrancy guards

MEDIUM - Limited fund exposure or minor logical flaws, strongly recommended to fix:
- Potential reentrancy in non-critical functions with limited impact
- External calls in complex logic where exploit path is unclear
- Missing reentrancy guards in functions that don't directly handle funds

LOW - Minor issues with minimal risk, consider fixing:
- Theoretical reentrancy concerns with mitigating factors
- Non-external calls that could be made safer
- Best practice improvements for reentrancy prevention

INFORMATIONAL - Best practices or code quality improvements, optional:
- Using OpenZeppelin's ReentrancyGuard (recommendation, not a finding)
- Comments explaining reentrancy safety
- General code quality improvements

CONFIDENCE GUIDELINES:
- high: Certain this is exploitable with clear fund loss scenario
- medium: Likely exploitable but specific conditions may be required
- low: Theoretical concern but exploit path may not exist in practice

Return a JSON array of findings with this structure:
[
  {{
    "severity": "critical|high|medium|low|info",
    "confidence": "high|medium|low",
    "category": "reentrancy",
    "description": "Description of the potential vulnerability",
    "location": "ContractName.functionName() or line reference",
    "recommendation": "How to fix the issue"
  }}
]

CRITICAL: Only mark as CRITICAL if you can trace the exact exploit path that leads to fund loss.
Do NOT flag patterns that are protected by checks-effects-interactions or mutex locks.
Only return the JSON array, no other text."""
            },
            "access-control": {
                "description": "Analyzes access control and permission issues",
                "prompt": """You are a smart contract security expert specializing in access control.

Analyze the following Solidity code for access control vulnerabilities.

IMPORTANT: Focus on ACTUAL EXPLOITABILITY. Check if missing access control leads to fund loss or critical function abuse.

{code}

SEVERITY GUIDELINES - Use these criteria when assigning severity:

CRITICAL - Direct fund loss requiring immediate fix before deployment:
- Anyone can call critical functions: withdraw, mint, burn, pause, transferOwnership
- Missing onlyOwner/onlyRole modifier on fund-handling functions
- Public functions that should be private/protected (e.g., emergencyWithdraw with no auth)
- Clear path for attacker to steal funds or tokens

HIGH - Potential for significant financial loss, must fix before deployment:
- Critical functions (affecting funds/ownership) accessible to unintended users
- Missing role-based access control where needed for fund operations
- Centralization risk: single point of failure in critical functions
- Functions that can be called to break protocol invariants

MEDIUM - Limited fund exposure or minor logical flaws, strongly recommended to fix:
- Inappropriate function visibility (public instead of internal/external)
- Missing access control on non-critical but important functions
- Weak access control patterns that could be improved

LOW - Minor issues with minimal risk, consider fixing:
- Missing events for sensitive state changes
- Overly restrictive permissions that limit functionality
- Minor access control improvements

INFORMATIONAL - Best practices or code quality improvements, optional:
- Suggesting use of AccessControl for role management
- Recommendations for multisig or DAO governance
- General access control design improvements

CONFIDENCE GUIDELINES:
- high: Certain this is exploitable to cause fund loss or protocol takeover
- medium: Likely exploitable but specific conditions or privileged user required
- low: Possible concern but impact may be limited or theoretical

Return a JSON array of findings with this structure:
[
  {{
    "severity": "critical|high|medium|low|info",
    "confidence": "high|medium|low",
    "category": "access_control",
    "description": "Description of the potential vulnerability",
    "location": "ContractName.functionName() or line reference",
    "recommendation": "How to fix the issue"
  }}
]

CRITICAL: Only mark as CRITICAL if missing access control directly enables fund theft.
Do NOT flag missing events or design suggestions as CRITICAL.
Only return the JSON array, no other text."""
            },
            "arithmetic-safety": {
                "description": "Detects arithmetic overflow/underflow issues",
                "prompt": """You are a smart contract security expert specializing in arithmetic safety.

Analyze the following Solidity code for arithmetic issues.

IMPORTANT: Focus on ACTUAL EXPLOITABILITY. Check if arithmetic errors can lead to fund loss or state manipulation.

{code}

SEVERITY GUIDELINES - Use these criteria when assigning severity:

CRITICAL - Direct fund loss requiring immediate fix before deployment:
- Unchecked arithmetic on user input that affects balances/totals (Solidity <0.8 or unchecked blocks)
- Overflow/underflow that can be exploited to mint unlimited tokens or steal funds
- Wrap-around that allows bypassing critical checks (e.g., balance checks)

HIGH - Potential for significant financial loss, must fix before deployment:
- Arithmetic operations on user input without overflow protection in critical paths
- Custom math functions with potential overflow in fund-handling logic
- Unchecked blocks in Solidity 0.8+ that bypass built-in protection

MEDIUM - Limited fund exposure or minor logical flaws, strongly recommended to fix:
- Overflow/underflow in non-critical state variables
- Arithmetic operations with practical constraints that make exploitation difficult
- Missing bounds checks in edge cases

LOW - Minor issues with minimal risk, consider fixing:
- Theoretical overflow concerns with minimal impact
- Minor arithmetic improvements
- Missing explicit checks where built-in protection exists

INFORMATIONAL - Best practices or code quality improvements, optional:
- Using SafeMath recommendations (Solidity <0.8)
- Suggesting explicit checks for clarity
- General arithmetic safety improvements

IMPORTANT VERSION CHECK:
- Solidity 0.8+ has built-in overflow protection for +, -, *, /, %
- Only flag CRITICAL/HIGH if: unchecked blocks used, pre-0.8 code, or custom math
- Array indexing and storage operations can still overflow even in 0.8+

CONFIDENCE GUIDELINES:
- high: Certain this is exploitable to cause fund loss or state manipulation
- medium: Likely exploitable but specific conditions or inputs required
- low: Theoretical concern but practical constraints may prevent exploitation

Return a JSON array of findings with this structure:
[
  {{
    "severity": "critical|high|medium|low|info",
    "confidence": "high|medium|low",
    "category": "arithmetic",
    "description": "Description of the potential vulnerability",
    "location": "ContractName.functionName() or line reference",
    "recommendation": "How to fix the issue"
  }}
]

CRITICAL: Only flag as CRITICAL if overflow/underflow directly enables fund theft.
Check the Solidity version - 0.8+ has built-in protection for standard arithmetic.
Only return the JSON array, no other text."""
            },
            "gas-optimization": {
                "description": "Identifies gas optimization opportunities",
                "prompt": """You are a smart contract expert specializing in gas optimization.

Analyze the following Solidity code for gas optimization opportunities:

{code}

SEVERITY GUIDELINES - Use these criteria when assigning severity:
- LOW: Significant gas savings (>10% per operation) in frequently called functions
- INFO: Minor gas savings or best practice improvements

NOTE: Gas findings should never be CRITICAL or HIGH severity since they don't affect security.

CONFIDENCE GUIDELINES:
- high: Certain this optimization will save significant gas
- medium: Likely to save gas but magnitude may vary
- low: Possible gas savings

Return a JSON array of findings with this structure:
[
  {{
    "severity": "low|info",
    "confidence": "high|medium|low",
    "category": "gas",
    "description": "Description of the optimization opportunity",
    "location": "ContractName.functionName() or line reference",
    "recommendation": "How to optimize",
    "gas_savings": "Estimate gas savings (e.g., 'saves ~5000 gas per call')"
  }}
]

IMPORTANT: Only report optimizations that save at least 2000 gas per operation. Focus on frequently called functions.
Only return the JSON array, no other text."""
            },
            "logic-analysis": {
                "description": "Analyzes business logic and design patterns",
                "prompt": """You are a smart contract security expert specializing in business logic analysis.

Analyze the following Solidity code for logic issues.

IMPORTANT: Focus on ACTUAL EXPLOITABILITY. Check if logic flaws can be exploited to cause fund loss or protocol damage.

{code}

SEVERITY GUIDELINES - Use these criteria when assigning severity:

CRITICAL - Direct fund loss requiring immediate fix before deployment:
- Logic error allowing direct fund theft or drain
- Bypassing critical restrictions (e.g., withdrawal limits, lock periods)
- Broken invariant that enables minting unlimited tokens or draining pools
- Flaw in core protocol logic that attacker can exploit
- Clear exploit path with specific steps to cause fund loss

HIGH - Potential for significant financial loss, must fix before deployment:
- Logic error that could cause fund loss with specific conditions
- Broken invariant in critical business logic with exploitable edge cases
- Incorrect fee/tax calculation that could be exploited
- Flaw in reward/claim mechanism that allows excessive claims
- Validation bypass that affects fund operations

MEDIUM - Limited fund exposure or minor logical flaws, strongly recommended to fix:
- Logic error causing unexpected behavior with limited impact
- Incorrect but not exploitable calculations
- Edge cases in non-critical functions
- Missing validation in non-fund operations
- Confusing or unclear logic that could lead to bugs

LOW - Minor issues with minimal risk, consider fixing:
- Minor logic improvements or code clarity issues
- Non-critical edge cases with minimal impact
- Suboptimal but not incorrect logic

INFORMATIONAL - Best practices or code quality improvements, optional:
- Suggestions for code organization or readability
- Recommendations for design patterns
- General logic improvements not related to security

CONFIDENCE GUIDELINES:
- high: Certain this is a logic error with clear exploit path to fund loss
- medium: Likely a logic error but specific conditions or timing required
- low: Possible concern but exploit may not be practical

Return a JSON array of findings with this structure:
[
  {{
    "severity": "critical|high|medium|low|info",
    "confidence": "high|medium|low",
    "category": "logic",
    "description": "Description of the potential issue",
    "location": "ContractName.functionName() or line reference",
    "recommendation": "How to fix or improve"
  }}
]

CRITICAL: Only flag as CRITICAL if you can trace the exact logic flaw that leads to fund loss.
Do NOT flag unconventional patterns or minor code quality issues as HIGH or CRITICAL.
Distinguish between "this code is unusual" (INFO) and "this code is exploitable" (CRITICAL/HIGH).
Only return the JSON array, no other text."""
            }
        }

        # Try to load from agents directory if it exists
        agents_dir = "/home/scout/.config/claude/agents"
        if os.path.exists(agents_dir):
            for filename in os.listdir(agents_dir):
                if filename.endswith(".md"):
                    try:
                        with open(os.path.join(agents_dir, filename), "r") as f:
                            content = f.read()
                            # Simple extraction: first line after 'name: ' is the agent name
                            for line in content.split("\n")[:10]:
                                if line.strip().startswith("name:"):
                                    name = line.split(":", 1)[1].strip()
                                    # Extract prompt between --- markers
                                    prompt_start = content.find('---') + 3
                                    prompt_end = content.find('---', prompt_start)
                                    if prompt_start > 0 and prompt_end > 0:
                                        prompt = content[prompt_start:prompt_end].strip()
                                        agents[name] = {
                                            "description": f"Custom agent from {filename}",
                                            "prompt": prompt
                                        }
                                    break
                    except Exception as e:
                        LOGGER.debug(f"Failed to load agent from {filename}: {e}")

        return {**default_agents, **agents}

    async def analyze_contract(
        self,
        contract_address: str,
        input_type: str,
        data: Any,
        agents: Optional[List[str]] = None,
    ) -> List[ClaudeAgentFinding]:
        """Analyze contract using claude-code CLI with custom agents.

        Args:
            contract_address: Contract address being analyzed
            input_type: "SOURCE_CODE" or "BYTECODE_ABI"
            data: Source code string OR (bytecode, abi, context) tuple
            agents: List of agent names to run (default: all)

        Returns:
            List of ClaudeAgentFinding objects
        """
        if agents is None:
            agents = ["reentrancy-guard", "access-control", "arithmetic-safety", "gas-optimization", "logic-analysis"]

        all_findings = []

        # Prepare the code for analysis
        if input_type == "SOURCE_CODE":
            code = data if isinstance(data, str) else str(data)
        else:  # BYTECODE_ABI
            code = f"Contract Address: {contract_address}\n"
            if isinstance(data, tuple) and len(data) >= 2:
                bytecode, abi = data[0], data[1]
                code += f"Bytecode: {bytecode[:100]}...\n"
                code += f"ABI: {json.dumps(abi[:5] if abi else [], indent=2)}...\n"
                code += "\nNote: This is an unverified contract. Analysis is limited to bytecode patterns and ABI function signatures."

        # Run each agent sequentially
        for agent_name in agents:
            if agent_name not in self.agents_config:
                LOGGER.warning(f"Agent '{agent_name}' not found, skipping")
                continue

            try:
                findings = await self._run_agent(agent_name, code, input_type)
                all_findings.extend(findings)
            except Exception as e:
                LOGGER.error(f"Error running agent '{agent_name}': {e}")

        return all_findings

    async def _run_agent(self, agent_name: str, code: str, input_type: str = "SOURCE_CODE") -> List[ClaudeAgentFinding]:
        """Run a single agent using claude-code CLI with file-based input.

        The source code is written to a temporary file to avoid "Argument list too long"
        errors when analyzing large contracts.

        The code content is read from the temp file and combined with the agent prompt,
        then passed to claude-code CLI via stdin.

        Args:
            agent_name: Name of the agent to run
            code: Solidity code or bytecode context to analyze
            input_type: "SOURCE_CODE" or "BYTECODE_ABI"

        Returns:
            List of findings from this agent
        """
        import tempfile

        agent_config = self.agents_config[agent_name]

        # Create temporary file for the code
        # Use .sol extension for source code, .txt for bytecode/ABI
        suffix = '.sol' if input_type == "SOURCE_CODE" else '.txt'
        with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False) as f:
            f.write(code)
            temp_file_path = f.name

        try:
            # Read the code back from the temp file
            with open(temp_file_path, 'r') as f:
                code_content = f.read()

            # Format prompt with the actual code content
            # The agent prompts use {code} placeholder which we replace with actual code
            prompt = agent_config["prompt"].format(
                code=code_content,
                file=temp_file_path
            )

            # Build claude-code CLI command
            # The file path is passed as context but the prompt contains actual code via stdin
            cmd = [
                self.claude_path,
                "--print",  # Non-interactive mode
                "--model", os.getenv("GLM_MODEL", "glm-4.7"),
            ]

            LOGGER.info(f"Running claude-code CLI for agent: {agent_name} ({len(code_content)} chars from {temp_file_path})")

            # Run claude-code CLI with the complete prompt (including code) via stdin
            result = subprocess.run(
                cmd,
                input=prompt,
                capture_output=True,
                text=True,
                timeout=180,  # 3 minute timeout for large contracts
                env=os.environ | {
                    "ANTHROPIC_AUTH_TOKEN": os.getenv("GLM_API_KEY", os.getenv("ANTHROPIC_AUTH_TOKEN", "")),
                    "ANTHROPIC_BASE_URL": os.getenv("GLM_API_URL", os.getenv("ANTHROPIC_BASE_URL", "")),
                }
            )

            # Log stderr for debugging (contains API errors if any)
            if result.stderr:
                LOGGER.debug(f"Claude-code CLI stderr: {result.stderr[:500]}")

            # Parse the output
            return self._parse_claude_output(result.stdout, agent_name)

        except subprocess.TimeoutExpired:
            LOGGER.error(f"Agent '{agent_name}' timed out after 180 seconds")
            return []
        except Exception as e:
            LOGGER.error(f"Error running agent '{agent_name}': {e}")
            return []
        finally:
            # Clean up temporary file
            try:
                os.unlink(temp_file_path)
            except Exception as e:
                LOGGER.debug(f"Failed to delete temp file {temp_file_path}: {e}")

    def _parse_claude_output(self, output: str, agent_name: str) -> List[ClaudeAgentFinding]:
        """Parse claude-code CLI output into findings.

        Args:
            output: Raw output from claude-code CLI
            agent_name: Name of the agent that produced the output

        Returns:
            List of ClaudeAgentFinding objects
        """
        findings = []

        try:
            # Try to parse as JSON first
            parsed = json.loads(output)

            # Handle different response formats
            if isinstance(parsed, dict):
                # Single response with data field
                if "data" in parsed:
                    data = parsed["data"]
                    if isinstance(data, list):
                        items = data
                    elif isinstance(data, str):
                        items = json.loads(data)
                    else:
                        items = []
                elif "completion" in parsed:
                    data = parsed["completion"]
                    items = json.loads(data) if isinstance(data, str) else data
                else:
                    items = [parsed]
            elif isinstance(parsed, list):
                items = parsed
            else:
                items = []

            # Convert to ClaudeAgentFinding objects
            for item in items:
                if isinstance(item, dict):
                    findings.append(ClaudeAgentFinding(
                        agent_name=agent_name,
                        severity=item.get("severity", "info"),
                        category=item.get("category", "general"),
                        description=item.get("description", ""),
                        location=item.get("location"),
                        recommendation=item.get("recommendation", ""),
                        confidence=item.get("confidence", "medium"),
                    ))

        except json.JSONDecodeError:
            # Fallback: try to extract JSON from the output
            try:
                # Look for JSON array in the output
                start_idx = output.find("[")
                end_idx = output.rfind("]") + 1
                if start_idx >= 0 and end_idx > start_idx:
                    json_str = output[start_idx:end_idx]
                    items = json.loads(json_str)

                    for item in items:
                        if isinstance(item, dict):
                            findings.append(ClaudeAgentFinding(
                                agent_name=agent_name,
                                severity=item.get("severity", "info"),
                                category=item.get("category", "general"),
                                description=item.get("description", ""),
                                location=item.get("location"),
                                recommendation=item.get("recommendation", ""),
                                confidence=item.get("confidence", "medium"),
                            ))
            except Exception as e:
                LOGGER.debug(f"Failed to parse output from {agent_name}: {e}")

        return self._normalize_findings(findings, agent_name)

    def _normalize_findings(self, findings: List[ClaudeAgentFinding], agent_name: str) -> List[ClaudeAgentFinding]:
        """Normalize findings to prevent overly harsh severity classifications.

        Applies the following normalization rules:
        1. Limit the number of critical/high findings per agent
        2. Downgrade severity when confidence is low
        3. Ensure severity distribution is reasonable
        4. Apply category-specific severity caps

        Args:
            findings: List of parsed findings from an agent
            agent_name: Name of the agent that produced the findings

        Returns:
            Normalized list of findings
        """
        if not findings:
            return findings

        normalized = []

        # Count findings by severity for this agent
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        # Severity order (higher to lower)
        severity_order = ["critical", "high", "medium", "low", "info"]

        for finding in findings:
            original_severity = finding.severity
            severity_counts[original_severity] = severity_counts.get(original_severity, 0) + 1

            # Rule 1: Downgrade low confidence findings
            if finding.confidence == "low" and original_severity in ["critical", "high"]:
                finding.severity = "medium"
                finding.confidence = "medium"
                LOGGER.debug(f"[{agent_name}] Downgraded low-confidence {original_severity} to medium")
                severity_counts["medium"] += 1
                severity_counts[original_severity] -= 1
            elif finding.confidence == "medium" and original_severity == "critical":
                finding.severity = "high"
                finding.confidence = "medium"
                LOGGER.debug(f"[{agent_name}] Downgraded medium-confidence critical to high")
                severity_counts["high"] += 1
                severity_counts["critical"] -= 1

            # Rule 2: Apply agent-specific severity caps
            # Gas optimization should never have critical/high
            if agent_name == "gas-optimization" and finding.severity in ["critical", "high"]:
                finding.severity = "low"
                LOGGER.debug(f"[{agent_name}] Gas finding severity capped at low")
                severity_counts["low"] += 1
                if original_severity in severity_counts:
                    severity_counts[original_severity] -= 1

            # Rule 3: Limit critical findings per agent
            max_critical_per_agent = 2  # Maximum 2 critical findings per agent
            if original_severity == "critical" and severity_counts["critical"] > max_critical_per_agent:
                # Downgrade excess critical findings to high
                finding.severity = "high"
                finding.confidence = "medium"
                LOGGER.debug(f"[{agent_name}] Capped critical findings at {max_critical_per_agent}, downgraded to high")
                severity_counts["high"] += 1
                severity_counts["critical"] -= 1

            # Rule 4: Limit high findings per agent
            max_high_per_agent = 4  # Maximum 4 high findings per agent
            if original_severity == "high" and severity_counts["high"] > max_high_per_agent:
                # Downgrade excess high findings to medium
                finding.severity = "medium"
                LOGGER.debug(f"[{agent_name}] Capped high findings at {max_high_per_agent}, downgraded to medium")
                severity_counts["medium"] += 1
                severity_counts["high"] -= 1

            # Rule 5: For non-security agents, further limit severity
            if agent_name == "gas-optimization" or agent_name == "logic-analysis":
                # These agents should produce mostly low/info findings
                if original_severity == "critical":
                    finding.severity = "medium"
                    LOGGER.debug(f"[{agent_name}] Non-security agent critical downgraded to medium")
                elif original_severity == "high":
                    finding.severity = "low"
                    LOGGER.debug(f"[{agent_name}] Non-security agent high downgraded to low")

            normalized.append(finding)

        # Log normalization summary
        if len(normalized) > 0:
            final_counts = {}
            for f in normalized:
                final_counts[f.severity] = final_counts.get(f.severity, 0) + 1
            LOGGER.debug(f"[{agent_name}] Normalized findings: {final_counts}")

        return normalized


def create_claude_orchestrator() -> ClaudeCodeOrchestrator:
    """Factory function to create a claude-code orchestrator."""
    return ClaudeCodeOrchestrator()
