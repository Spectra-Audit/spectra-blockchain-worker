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

Analyze the following Solidity code for reentrancy vulnerabilities:

{code}

SEVERITY GUIDELINES - Use these criteria when assigning severity:
- CRITICAL: Direct external call to user-supplied address before state changes, with clear exploit path
- HIGH: External call pattern exists but checks-effects-interactions pattern is broken or missing
- MEDIUM: Potential reentrancy in complex logic or indirect external calls
- LOW: Minor reentrancy concerns in non-critical functions or with mitigating factors
- INFO: Best practice suggestions or theoretical concerns

CONFIDENCE GUIDELINES:
- high: Certain this is a vulnerability with clear exploit scenario
- medium: Likely a vulnerability but exploit path may be complex
- low: Possible concern but might not be exploitable

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

IMPORTANT: Be conservative with severity. Only mark as CRITICAL if you're certain there's an exploitable vulnerability.
Only return the JSON array, no other text."""
            },
            "access-control": {
                "description": "Analyzes access control and permission issues",
                "prompt": """You are a smart contract security expert specializing in access control.

Analyze the following Solidity code for access control vulnerabilities:

{code}

SEVERITY GUIDELINES - Use these criteria when assigning severity:
- CRITICAL: Anyone can call critical functions (mint, burn, pause, withdraw) with no access control
- HIGH: Only owner/admin can access but missing proper events or upgradeability mechanism; centralization risks in critical functions
- MEDIUM: Missing role-based access control where it would be appropriate; function visibility issues
- LOW: Minor access control improvements or overly restrictive permissions
- INFO: Best practice suggestions for access control design

CONFIDENCE GUIDELINES:
- high: Certain this is a vulnerability with clear exploit scenario
- medium: Likely a vulnerability but impact may be limited
- low: Possible concern or design consideration

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

IMPORTANT: Be conservative with severity. Only mark as CRITICAL for clearly exploitable missing access control.
Only return the JSON array, no other text."""
            },
            "arithmetic-safety": {
                "description": "Detects arithmetic overflow/underflow issues",
                "prompt": """You are a smart contract security expert specializing in arithmetic safety.

Analyze the following Solidity code for arithmetic issues:

{code}

SEVERITY GUIDELINES - Use these criteria when assigning severity:
- CRITICAL: Unprotected arithmetic operation on user input that could overflow/underflow and affect critical state (balances, totals, etc.)
- HIGH: Arithmetic on user input without SafeMath or built-in overflow protection in Solidity <0.8
- MEDIUM: Arithmetic operations that could theoretically overflow but have practical constraints
- LOW: Minor arithmetic concerns or missing explicit checks where impact is limited
- INFO: Best practice suggestions for arithmetic safety

NOTE: Solidity 0.8+ has built-in overflow protection for arithmetic operations. Only flag as HIGH/CRITICAL if custom arithmetic or pre-0.8 patterns are used.

CONFIDENCE GUIDELINES:
- high: Certain this is a vulnerability with clear exploit scenario
- medium: Likely a vulnerability but exploit path may be complex
- low: Possible concern but practical constraints may prevent exploitation

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

IMPORTANT: Be conservative with severity. Check Solidity version and built-in protections.
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

Analyze the following Solidity code for logic issues:

{code}

SEVERITY GUIDELINES - Use these criteria when assigning severity:
- CRITICAL: Logic error that allows stealing funds, bypassing critical restrictions, or breaking core functionality
- HIGH: Logic error that could cause loss of funds with specific conditions; broken invariant in critical logic
- MEDIUM: Logic error that could cause unexpected behavior with limited impact; unclear or confusing logic
- LOW: Minor logic improvements or unclear code that doesn't affect functionality
- INFO: Best practice suggestions for logic design or code clarity

CONFIDENCE GUIDELINES:
- high: Certain this is a logic error with clear impact scenario
- medium: Likely a logic error but edge cases may prevent exploitation
- low: Possible concern or design consideration

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

IMPORTANT: Be conservative with severity. Focus on actual bugs, not just unconventional patterns.
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
