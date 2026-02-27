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
        self.claude_path = self._find_claude_cli()
        self.agents_config = self._load_agents_config()
        LOGGER.info(f"ClaudeCodeOrchestrator initialized with CLI: {self.claude_path}")
        LOGGER.info(f"Loaded {len(self.agents_config)} custom agents")

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

Return a JSON array of findings with this structure:
[
  {{
    "severity": "high|medium|low|info",
    "category": "reentrancy",
    "description": "Description of the potential vulnerability",
    "location": "ContractName.functionName() or line reference",
    "recommendation": "How to fix the issue"
  }}
]

Only return the JSON array, no other text."""
            },
            "access-control": {
                "description": "Analyzes access control and permission issues",
                "prompt": """You are a smart contract security expert specializing in access control.

Analyze the following Solidity code for access control vulnerabilities:

{code}

Return a JSON array of findings with this structure:
[
  {{
    "severity": "high|medium|low|info",
    "category": "access_control",
    "description": "Description of the potential vulnerability",
    "location": "ContractName.functionName() or line reference",
    "recommendation": "How to fix the issue"
  }}
]

Only return the JSON array, no other text."""
            },
            "arithmetic-safety": {
                "description": "Detects arithmetic overflow/underflow issues",
                "prompt": """You are a smart contract security expert specializing in arithmetic safety.

Analyze the following Solidity code for arithmetic issues:

{code}

Return a JSON array of findings with this structure:
[
  {{
    "severity": "high|medium|low|info",
    "category": "arithmetic",
    "description": "Description of the potential vulnerability",
    "location": "ContractName.functionName() or line reference",
    "recommendation": "How to fix the issue"
  }}
]

Only return the JSON array, no other text."""
            },
            "gas-optimization": {
                "description": "Identifies gas optimization opportunities",
                "prompt": """You are a smart contract expert specializing in gas optimization.

Analyze the following Solidity code for gas optimization opportunities:

{code}

Return a JSON array of findings with this structure:
[
  {{
    "severity": "info|low",
    "category": "gas",
    "description": "Description of the optimization opportunity",
    "location": "ContractName.functionName() or line reference",
    "recommendation": "How to optimize"
  }}
]

Only return the JSON array, no other text."""
            },
            "logic-analysis": {
                "description": "Analyzes business logic and design patterns",
                "prompt": """You are a smart contract security expert specializing in business logic analysis.

Analyze the following Solidity code for logic issues:

{code}

Return a JSON array of findings with this structure:
[
  {{
    "severity": "high|medium|low|info",
    "category": "logic",
    "description": "Description of the potential issue",
    "location": "ContractName.functionName() or line reference",
    "recommendation": "How to fix or improve"
  }}
]

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
                findings = await self._run_agent(agent_name, code)
                all_findings.extend(findings)
            except Exception as e:
                LOGGER.error(f"Error running agent '{agent_name}': {e}")

        return all_findings

    async def _run_agent(self, agent_name: str, code: str) -> List[ClaudeAgentFinding]:
        """Run a single agent using claude-code CLI.

        Args:
            agent_name: Name of the agent to run
            code: Solidity code to analyze

        Returns:
            List of findings from this agent
        """
        agent_config = self.agents_config[agent_name]
        prompt = agent_config["prompt"].format(code=code)

        # Build claude-code CLI command
        cmd = [
            self.claude_path,
            "--print",  # Non-interactive mode
            "--agent", agent_name,
            "--agents", json.dumps({agent_name: agent_config}),
            "--output-format", "json",
            "--permission-mode", "bypassPermissions",
            "--model", os.getenv("GLM_MODEL", "glm-4-plus"),
            prompt
        ]

        LOGGER.debug(f"Running claude-code CLI for agent: {agent_name}")

        try:
            # Run claude-code CLI
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,  # 2 minute timeout
                env=os.environ | {
                    "ANTHROPIC_AUTH_TOKEN": os.getenv("GLM_API_KEY", os.getenv("ANTHROPIC_AUTH_TOKEN", "")),
                    "ANTHROPIC_BASE_URL": os.getenv("GLM_API_URL", os.getenv("ANTHROPIC_BASE_URL", "")),
                }
            )

            # Parse the output
            return self._parse_claude_output(result.stdout, agent_name)

        except subprocess.TimeoutExpired:
            LOGGER.error(f"Agent '{agent_name}' timed out after 120 seconds")
            return []
        except Exception as e:
            LOGGER.error(f"Error running agent '{agent_name}': {e}")
            return []

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

        return findings


def create_claude_orchestrator() -> ClaudeCodeOrchestrator:
    """Factory function to create a claude-code orchestrator."""
    return ClaudeCodeOrchestrator()
