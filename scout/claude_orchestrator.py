"""Claude Code CLI Orchestrator for smart contract audits.

Two-agent architecture:
1. knowledge-context.md — Static vulnerability knowledge base + learned lessons
2. audit-agent.md — Unified comprehensive security audit agent

The orchestrator loads both agent definitions from the agents/ directory,
injects the knowledge context into the audit prompt, and runs a single
comprehensive analysis pass instead of 5 sequential agent calls.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .audit_self_improver import AuditSelfImprover

LOGGER = logging.getLogger(__name__)

# Resolve agents directory relative to the project root
_AGENTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "agents",
)


@dataclass
class ClaudeAgentFinding:
    """Finding from a claude-code agent analysis."""
    agent_name: str
    severity: str  # "info", "low", "medium", "high", "critical"
    category: str
    description: str
    location: Optional[str]
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
    """Orchestrator for running claude-code CLI with the 2-agent system.

    Agent 1 (knowledge-context.md) provides the vulnerability knowledge base
    and false-positive avoidance rules. Its content is injected into Agent 2's
    prompt.

    Agent 2 (audit-agent.md) is the unified audit agent that performs all
    vulnerability analysis in a single pass.
    """

    def __init__(self):
        """Initialize the orchestrator."""
        LOGGER.info("=" * 80)
        LOGGER.info("INITIALIZING CLAUDE-CODE ORCHESTRATOR (2-Agent Architecture)")
        LOGGER.info("=" * 80)

        # Step 1: Find claude-code CLI
        self.claude_path = self._find_claude_cli()
        LOGGER.info("[CLI] Using claude-code CLI at: %s", self.claude_path)

        # Verify CLI is accessible
        try:
            result = subprocess.run(
                [self.claude_path, "--version"],
                capture_output=True, timeout=10,
            )
            if result.returncode == 0:
                version_output = result.stdout.decode().strip()
                LOGGER.info("[CLI] claude-code CLI version: %s", version_output)
            else:
                LOGGER.warning(
                    "[CLI] claude-code CLI exists but --version failed: %s",
                    result.stderr.decode()[:100],
                )
        except Exception as exc:
            LOGGER.error("[CLI] Failed to verify claude-code CLI: %s", exc)

        # Step 2: Load agent configurations from markdown files
        self.agents_config = self._load_agents_config()
        LOGGER.info("[AGENTS] Loaded %d agent(s):", len(self.agents_config))
        for agent_name, config in self.agents_config.items():
            LOGGER.info("  - %s: %s", agent_name, config.get("description", "No description"))

        # Step 3: Initialize self-improver (must be before loading knowledge context)
        self.self_improver = AuditSelfImprover()

        # Step 4: Load knowledge context (uses self.self_improver)
        self.knowledge_context = self._load_knowledge_context()

        # Step 5: Check GLM API configuration
        glm_api_key = os.getenv("GLM_API_KEY") or os.getenv("ANTHROPIC_AUTH_TOKEN")
        glm_api_url = os.getenv("GLM_API_URL") or os.getenv("ANTHROPIC_BASE_URL")
        glm_model = os.getenv("GLM_MODEL", "glm-4.7")

        if glm_api_key:
            masked_key = f"{glm_api_key[:8]}...{glm_api_key[-4:]}" if len(glm_api_key) > 12 else "***"
            LOGGER.info("[API] GLM API Key configured: %s", masked_key)
            LOGGER.info("[API] GLM API URL: %s", glm_api_url)
            LOGGER.info("[API] GLM Model: %s", glm_model)
        else:
            LOGGER.warning("[API] GLM API Key not configured - analyses may fail")

        LOGGER.info("=" * 80)
        LOGGER.info("CLAUDE-CODE ORCHESTRATOR INITIALIZATION COMPLETE")
        LOGGER.info("=" * 80)

    # ------------------------------------------------------------------
    # Agent loading
    # ------------------------------------------------------------------

    def _find_claude_cli(self) -> str:
        """Find the claude-code CLI executable."""
        possible_paths = [
            "/usr/bin/claude",
            "/usr/local/bin/claude",
            "/home/scout/.local/bin/claude",
            "claude",
        ]
        for path in possible_paths:
            if os.path.exists(path) or path == "claude":
                return path
        return "claude"

    def _load_agents_config(self) -> Dict[str, Dict]:
        """Load agent configurations from markdown files in the agents/ directory."""
        agents: Dict[str, Dict] = {}

        if not os.path.isdir(_AGENTS_DIR):
            LOGGER.warning("[AGENTS] Directory not found: %s", _AGENTS_DIR)
            return agents

        for filename in sorted(os.listdir(_AGENTS_DIR)):
            if not filename.endswith(".md"):
                continue
            filepath = os.path.join(_AGENTS_DIR, filename)
            try:
                with open(filepath, "r") as fh:
                    content = fh.read()
                name, prompt = self._parse_agent_markdown(content, filename)
                agents[name] = {
                    "description": f"Agent from {filename}",
                    "prompt": prompt,
                    "source": filepath,
                }
                LOGGER.debug("[AGENTS] Loaded %s from %s", name, filename)
            except Exception as exc:
                LOGGER.debug("[AGENTS] Failed to load %s: %s", filename, exc)

        return agents

    @staticmethod
    def _parse_agent_markdown(content: str, filename: str) -> tuple:
        """Parse a markdown agent file into (name, prompt_body)."""
        name = filename.replace(".md", "")
        # Extract body after the second --- (end of frontmatter)
        parts = content.split("---")
        if len(parts) >= 3:
            frontmatter = parts[1]
            for line in frontmatter.strip().splitlines():
                if line.strip().startswith("name:"):
                    name = line.split(":", 1)[1].strip()
            body = "---".join(parts[2:]).strip()
        else:
            body = content
        return name, body

    def _load_knowledge_context(self) -> str:
        """Load and assemble the full knowledge context for the audit agent.

        Combines:
        1. The static knowledge from knowledge-context.md
        2. Dynamic lessons from the self-improver module
        """
        base_context = ""
        agent = self.agents_config.get("knowledge-context")
        if agent:
            base_context = agent["prompt"]
        else:
            LOGGER.warning("[KNOWLEDGE] knowledge-context agent not found")

        # Inject self-improvement lessons into the LESSONS markers
        lessons_context = self.self_improver.get_lessons_for_context()
        if "<!-- LESSONS_START -->" in base_context:
            base_context = base_context.replace(
                "<!-- LESSONS_START -->\n<!-- LESSONS_END -->",
                f"<!-- LESSONS_START -->\n{lessons_context}\n<!-- LESSONS_END -->",
            )
        elif "<!-- LESSONS_START -->" in base_context:
            # Handle case where there might be existing content between markers
            start_marker = "<!-- LESSONS_START -->"
            end_marker = "<!-- LESSONS_END -->"
            start_idx = base_context.find(start_marker)
            end_idx = base_context.find(end_marker)
            if start_idx >= 0 and end_idx > start_idx:
                base_context = (
                    base_context[:start_idx + len(start_marker)]
                    + "\n" + lessons_context + "\n"
                    + base_context[end_idx:]
                )

        LOGGER.info(
            "[KNOWLEDGE] Context loaded: %d chars, %d lessons",
            len(base_context),
            len(self.self_improver.lessons),
        )
        return base_context

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    async def analyze_contract(
        self,
        contract_address: str,
        input_type: str,
        data: Any,
        agents: Optional[List[str]] = None,
        additional_contracts: Optional[List[Dict[str, str]]] = None,
    ) -> List[ClaudeAgentFinding]:
        """Analyze contract using the unified audit agent.

        Args:
            contract_address: Primary contract address being analyzed
            input_type: "SOURCE_CODE" or "BYTECODE_ABI"
            data: Source code string OR (bytecode, abi, context) tuple
            agents: Ignored (kept for backward compatibility)
            additional_contracts: Optional list of {"address": ..., "source_code": ...}
                                  for cross-contract synthesis analysis

        Returns:
            List of ClaudeAgentFinding objects
        """
        # Prepare code context
        if input_type == "SOURCE_CODE":
            code = data if isinstance(data, str) else str(data)
            if additional_contracts:
                code = self._build_cross_contract_context(
                    contract_address, code, additional_contracts
                )
        else:  # BYTECODE_ABI
            code = f"Contract Address: {contract_address}\n"
            if isinstance(data, tuple) and len(data) >= 2:
                bytecode, abi = data[0], data[1]
                code += f"Bytecode: {bytecode[:100]}...\n"
                code += f"ABI: {json.dumps(abi[:5] if abi else [], indent=2)}...\n"
                code += (
                    "\nNote: This is an unverified contract. "
                    "Analysis is limited to bytecode patterns and ABI function signatures."
                )

        # Run the unified audit agent
        audit_agent = self.agents_config.get("audit-agent")
        if not audit_agent:
            LOGGER.error("[AUDIT] audit-agent not found in configuration")
            return []

        findings = await self._run_unified_agent(code, input_type, audit_agent)
        return findings

    async def _run_unified_agent(
        self,
        code: str,
        input_type: str,
        agent_config: Dict,
    ) -> List[ClaudeAgentFinding]:
        """Run the unified audit agent using claude-code CLI.

        This is a single comprehensive call that replaces the previous
        5 sequential agent calls.
        """
        prompt_template = agent_config.get("prompt", "")

        # Build the full prompt by injecting knowledge context and code
        try:
            prompt = prompt_template.format(
                knowledge_context=self.knowledge_context,
                code=code,
            )
        except KeyError as exc:
            LOGGER.warning("[AUDIT] Prompt template formatting error: %s", exc)
            # Fallback: simple string replacement
            prompt = prompt_template
            prompt = prompt.replace("{knowledge_context}", self.knowledge_context)
            prompt = prompt.replace("{code}", code)

        # Write code to temp file for reference
        suffix = '.sol' if input_type == "SOURCE_CODE" else '.txt'
        with tempfile.NamedTemporaryFile(
            mode='w', suffix=suffix, delete=False
        ) as tmp:
            tmp.write(code)
            temp_file_path = tmp.name

        try:
            cmd = [
                self.claude_path,
                "--print",
                "--model", os.getenv("GLM_MODEL", "glm-4.7"),
            ]

            LOGGER.info(
                "[AUDIT] Running unified audit agent (%d chars)",
                len(code),
            )

            result = subprocess.run(
                cmd,
                input=prompt,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minutes for comprehensive analysis
                env=os.environ | {
                    "ANTHROPIC_AUTH_TOKEN": os.getenv(
                        "GLM_API_KEY",
                        os.getenv("ANTHROPIC_AUTH_TOKEN", ""),
                    ),
                    "ANTHROPIC_BASE_URL": os.getenv(
                        "GLM_API_URL",
                        os.getenv("ANTHROPIC_BASE_URL", ""),
                    ),
                },
            )

            if result.stderr:
                LOGGER.debug(
                    "[AUDIT] CLI stderr: %s",
                    result.stderr[:500],
                )

            findings = self._parse_claude_output(result.stdout, "audit-agent")
            LOGGER.info(
                "[AUDIT] Unified agent returned %d findings",
                len(findings),
            )
            return findings

        except subprocess.TimeoutExpired:
            LOGGER.error("[AUDIT] Unified agent timed out after 300 seconds")
            return []
        except Exception as exc:
            LOGGER.error("[AUDIT] Error running unified agent: %s", exc)
            return []
        finally:
            try:
                os.unlink(temp_file_path)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Cross-contract support
    # ------------------------------------------------------------------

    @staticmethod
    def _build_cross_contract_context(
        primary_address: str,
        primary_code: str,
        additional: List[Dict[str, str]],
    ) -> str:
        """Build context string for multi-contract analysis."""
        parts = [
            f"=== PRIMARY CONTRACT ({primary_address}) ===\n{primary_code}\n",
        ]
        for idx, contract in enumerate(additional):
            addr = contract.get("address", f"additional_{idx}")
            src = contract.get("source_code", "")
            parts.append(
                f"\n=== ADDITIONAL CONTRACT ({addr}) ===\n{src}\n"
            )

        parts.append(
            "\n=== SYNTHESIS INSTRUCTIONS ===\n"
            "Analyze each contract individually, then perform cross-contract analysis:\n"
            "1. Check for privilege escalation across boundaries\n"
            "2. Verify access control consistency across inherited contracts\n"
            "3. Look for state inconsistencies between inter-contract calls\n"
            "4. Analyze composability risks\n"
            "5. Check for flash loan attack vectors across pairs\n"
            "Mark cross-contract findings with: "
            "'ContractA -> ContractB.functionName()'\n",
        )
        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Output parsing
    # ------------------------------------------------------------------

    def _parse_claude_output(
        self, output: str, agent_name: str,
    ) -> List[ClaudeAgentFinding]:
        """Parse claude-code CLI output into findings."""
        findings: List[ClaudeAgentFinding] = []

        if not output or not output.strip():
            return findings

        try:
            parsed = json.loads(output)
        except json.JSONDecodeError:
            # Fallback: try to extract JSON from the output
            try:
                start_idx = output.find("[")
                end_idx = output.rfind("]") + 1
                if start_idx >= 0 and end_idx > start_idx:
                    parsed = json.loads(output[start_idx:end_idx])
                else:
                    LOGGER.debug(
                        "[PARSE] No JSON found in output from %s", agent_name,
                    )
                    return findings
            except Exception as exc:
                LOGGER.debug(
                    "[PARSE] Failed to extract JSON from %s: %s", agent_name, exc,
                )
                return findings

        # Handle different response formats
        items: List = []
        if isinstance(parsed, dict):
            if "data" in parsed:
                data = parsed["data"]
                items = data if isinstance(data, list) else []
            elif "completion" in parsed:
                data = parsed["completion"]
                try:
                    items = json.loads(data) if isinstance(data, str) else data
                except Exception:
                    items = []
            elif "findings" in parsed:
                items = parsed["findings"]
            else:
                items = [parsed]
        elif isinstance(parsed, list):
            items = parsed

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

        return self._normalize_findings(findings, agent_name)

    @staticmethod
    def _normalize_findings(
        findings: List[ClaudeAgentFinding], agent_name: str,
    ) -> List[ClaudeAgentFinding]:
        """Normalize findings to prevent overly harsh severity classifications.

        Rules:
        1. Low-confidence critical/high → downgrade
        2. Gas findings capped at low/info
        3. Maximum 2 critical and 4 high findings per analysis
        """
        if not findings:
            return findings

        severity_counts: Dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        }

        for finding in findings:
            original = finding.severity
            severity_counts[original] = severity_counts.get(original, 0) + 1

            # Rule 1: Downgrade low confidence
            if finding.confidence == "low" and original in ("critical", "high"):
                finding.severity = "medium"
                finding.confidence = "medium"
                severity_counts["medium"] += 1
                severity_counts[original] -= 1

            elif finding.confidence == "medium" and original == "critical":
                finding.severity = "high"
                severity_counts["high"] += 1
                severity_counts["critical"] -= 1

            # Rule 2: Gas findings capped at low
            if finding.category == "gas" and finding.severity in ("critical", "high"):
                finding.severity = "low"
                severity_counts["low"] += 1
                severity_counts[original] -= 1

            # Rule 3: Cap critical findings at 2
            if severity_counts.get("critical", 0) > 2:
                finding.severity = "high"
                finding.confidence = "medium"
                severity_counts["high"] += 1
                severity_counts["critical"] -= 1

            # Rule 4: Cap high findings at 4
            if severity_counts.get("high", 0) > 4:
                finding.severity = "medium"
                severity_counts["medium"] += 1
                severity_counts["high"] -= 1

        return findings


def create_claude_orchestrator() -> ClaudeCodeOrchestrator:
    """Factory function to create a claude-code orchestrator."""
    return ClaudeCodeOrchestrator()
