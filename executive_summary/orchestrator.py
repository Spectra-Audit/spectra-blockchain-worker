"""Orchestrator for executive summary generation.

Architecturally separate from scout/claude_orchestrator.py. Uses the same
subprocess pattern (claude --print) but with its own agents, knowledge base,
and self-improvement loop.

Lifecycle:
1. Load agent definitions from executive_summary/agents/
2. Build prompt with project data + learned lessons
3. Run claude --print subprocess with GLM API config
4. Parse structured JSON output
5. Record assessment in self-improver for future learning
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from typing import Any, Dict, Optional

from .self_improver import SummarySelfImprover

LOGGER = logging.getLogger(__name__)

_AGENTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agents")


class SummaryOrchestrator:
    """Orchestrator for generating AI-powered executive summaries.

    Uses a two-agent architecture:
    1. summary-knowledge.md — Static scoring interpretation rules
    2. executive-summary-agent.md — The summary generation agent

    The knowledge base is prepended to the agent prompt along with
    dynamic lessons from the self-improver.
    """

    def __init__(self) -> None:
        LOGGER.info("Initializing SummaryOrchestrator")
        self.claude_path = self._find_claude_cli()
        self.agents_config = self._load_agents()
        self.self_improver = SummarySelfImprover()

        LOGGER.info(
            "SummaryOrchestrator ready: %d agents loaded",
            len(self.agents_config),
        )

    # ------------------------------------------------------------------
    # Agent loading
    # ------------------------------------------------------------------

    @staticmethod
    def _find_claude_cli() -> str:
        possible = [
            "/usr/bin/claude",
            "/usr/local/bin/claude",
            "/home/scout/.local/bin/claude",
            "claude",
        ]
        for path in possible:
            if os.path.exists(path) or path == "claude":
                return path
        return "claude"

    def _load_agents(self) -> Dict[str, Dict[str, str]]:
        agents: Dict[str, Dict[str, str]] = {}
        if not os.path.isdir(_AGENTS_DIR):
            LOGGER.warning("Agents directory not found: %s", _AGENTS_DIR)
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
                    "prompt": prompt,
                    "source": filepath,
                }
            except Exception as exc:
                LOGGER.debug("Failed to load agent %s: %s", filename, exc)

        return agents

    @staticmethod
    def _parse_agent_markdown(content: str, filename: str) -> tuple:
        name = filename.replace(".md", "")
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

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def generate_summary(
        self,
        project_id: str,
        audit_data: Dict[str, Any],
        backend_client: Any = None,
    ) -> Dict[str, Any]:
        """Generate an executive summary for a project.

        Args:
            project_id: Backend project identifier
            audit_data: Current audit results (scores, findings, etc.)
            backend_client: Optional BackendClient for fetching additional data

        Returns:
            Dict with executive_summary, security_analysis, recommendations, etc.
        """
        LOGGER.info("Generating executive summary for %s", project_id[:8])

        # 1. Build project data context
        project_data_str = self._build_project_context(project_id, audit_data, backend_client)

        # 2. Get learned lessons
        lessons_str = self.self_improver.get_lessons_for_context()

        # Add cross-project patterns
        cross_project_patterns = self.self_improver.find_cross_project_patterns()
        if cross_project_patterns:
            lessons_str += "\n\n## Cross-Project Patterns\n" + "\n".join(
                f"- {p}" for p in cross_project_patterns
            )

        # 3. Build prompt
        agent = self.agents_config.get("executive-summary-agent")
        if not agent:
            LOGGER.error("executive-summary-agent not found")
            return {}

        knowledge = self.agents_config.get("summary-knowledge", {}).get("prompt", "")

        prompt = agent["prompt"]
        # Inject knowledge base at the top of the prompt
        if knowledge:
            prompt = f"{knowledge}\n\n{prompt}"
        # Use str.replace (not str.format) to avoid issues with curly braces in data
        prompt = prompt.replace("{learned_lessons}", lessons_str)
        prompt = prompt.replace("{project_data}", project_data_str)

        # 4. Run subprocess
        result = await self._run_subprocess(prompt)

        if not result:
            LOGGER.warning("No output from executive summary agent for %s", project_id[:8])
            return {}

        # 5. Parse output
        parsed = self._parse_output(result)

        # 6. Record assessment for self-improvement
        if parsed:
            # Attach source scores for drift detection
            scores = audit_data.get("contract_audit", {}).get("scores", {})
            parsed["_source_scores"] = scores
            self.self_improver.record_assessment(project_id, parsed)

            # Check for new findings vs previous
            current_findings = audit_data.get("contract_audit", {}).get("findings", [])
            previous = self.self_improver._get_previous_assessment(project_id)
            if previous and current_findings:
                prev_count = len(previous.get("_source_findings", []))
                if len(current_findings) > prev_count:
                    self.self_improver.record_new_findings(
                        project_id, current_findings[prev_count:], prev_count,
                    )

        return parsed

    # ------------------------------------------------------------------
    # Context building
    # ------------------------------------------------------------------

    def _build_project_context(
        self,
        project_id: str,
        audit_data: Dict[str, Any],
        backend_client: Any,
    ) -> str:
        """Build a structured project data context for the agent prompt."""
        lines = [f"Project ID: {project_id}"]
        lines.append("")

        # Scores
        scores = audit_data.get("contract_audit", {}).get("scores", {})
        if scores:
            lines.append("### Security Scores")
            for key, value in scores.items():
                lines.append(f"- {key}: {value}")
            lines.append("")

        # Findings
        findings = audit_data.get("contract_audit", {}).get("findings", [])
        if findings:
            lines.append(f"### Technical Findings ({len(findings)} total)")
            severity_counts: Dict[str, int] = {}
            for f in findings:
                sev = f.get("severity", "info")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            for sev in ["critical", "high", "medium", "low", "info"]:
                if sev in severity_counts:
                    lines.append(f"- {sev.title()}: {severity_counts[sev]}")
            lines.append("")

            # List top findings
            lines.append("### Top Findings")
            for f in findings[:10]:
                lines.append(
                    f"- [{f.get('severity', 'info').upper()}] "
                    f"{f.get('category', 'N/A')}: "
                    f"{f.get('description', 'N/A')[:150]}"
                )
            lines.append("")

        # Token distribution
        distribution = audit_data.get("token_distribution", {})
        if distribution:
            lines.append("### Token Distribution")
            holders = distribution.get("holders", [])
            if holders:
                lines.append(f"- Total holders: {len(holders)}")
                # Top holder concentration
                if holders:
                    top_1 = holders[0].get("percent_total_supply", 0) or 0
                    top_10_pct = sum(
                        h.get("percent_total_supply", 0) or 0 for h in holders[:10]
                    )
                    lines.append(f"- Top holder: {top_1:.1f}%")
                    lines.append(f"- Top 10 holders: {top_10_pct:.1f}%")
            lines.append("")

        # Liquidity
        liquidity = audit_data.get("liquidity", {})
        if liquidity:
            lines.append("### Liquidity")
            pairs = liquidity.get("pairs", [])
            if pairs:
                total_liquidity = sum(p.get("value_usd", 0) or 0 for p in pairs)
                lines.append(f"- Total liquidity: ${total_liquidity:,.0f}")
                lines.append(f"- Number of pairs: {len(pairs)}")
            lines.append("")

        # Tokenomics
        tokenomics = audit_data.get("tokenomics", {})
        if tokenomics:
            lines.append("### Tokenomics")
            supply = tokenomics.get("total_supply")
            if supply:
                lines.append(f"- Total supply: {supply}")
            buy_tax = tokenomics.get("buy_tax")
            if buy_tax is not None:
                lines.append(f"- Buy tax: {buy_tax}%")
            sell_tax = tokenomics.get("sell_tax")
            if sell_tax is not None:
                lines.append(f"- Sell tax: {sell_tax}%")
            lines.append("")

        # Market data from audit_data
        market_cap = audit_data.get("market_cap_usd")
        tvl = audit_data.get("tvl_usd")
        volume = audit_data.get("volume_usd")
        if any(v is not None for v in [market_cap, tvl, volume]):
            lines.append("### Market Data")
            if market_cap is not None:
                lines.append(f"- Market cap: ${market_cap:,.0f}")
            if tvl is not None:
                lines.append(f"- TVL: ${tvl:,.0f}")
            if volume is not None:
                lines.append(f"- 24h Volume: ${volume:,.0f}")
            lines.append("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Subprocess execution
    # ------------------------------------------------------------------

    async def _run_subprocess(self, prompt: str) -> str:
        """Run the claude CLI subprocess with the given prompt."""
        model = os.getenv("GLM_MODEL", "glm-4.7")
        cmd = [self.claude_path, "--print", "--model", model]

        env = dict(os.environ)
        glm_api_key = os.getenv("GLM_API_KEY") or os.getenv("ANTHROPIC_AUTH_TOKEN")
        glm_api_url = os.getenv("GLM_API_URL") or os.getenv("ANTHROPIC_BASE_URL")

        if glm_api_key:
            env["ANTHROPIC_AUTH_TOKEN"] = glm_api_key
        if glm_api_url:
            env["ANTHROPIC_BASE_URL"] = glm_api_url

        LOGGER.info(
            "Running executive summary agent (prompt: %d chars)",
            len(prompt),
        )

        try:
            result = subprocess.run(
                cmd,
                input=prompt,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minutes
                env=env,
            )

            if result.stderr:
                LOGGER.debug("Summary agent stderr: %s", result.stderr[:500])

            return result.stdout

        except subprocess.TimeoutExpired:
            LOGGER.error("Executive summary agent timed out after 300 seconds")
            return ""
        except Exception as exc:
            LOGGER.error("Executive summary agent error: %s", exc)
            return ""

    # ------------------------------------------------------------------
    # Output parsing
    # ------------------------------------------------------------------

    def _parse_output(self, output: str) -> Dict[str, Any]:
        """Parse the agent output into a structured dict.

        Handles common AI model output patterns:
        1. Raw JSON (ideal case)
        2. JSON wrapped in markdown code blocks (```json ... ```)
        3. JSON with leading/trailing explanatory text
        4. JSON with unbalanced text containing extra braces

        Strategy order:
        1. Direct JSON parse
        2. Strip markdown fences then balanced-brace extraction
        3. Balanced-brace extraction on raw output
        4. Each strategy has a JSON repair fallback
        """
        if not output or not output.strip():
            return {}

        # Strategy 1: Direct JSON parse
        try:
            parsed = json.loads(output.strip())
            LOGGER.info("Parsed summary via Strategy 1 (direct JSON)")
            return self._normalize_parsed(parsed)
        except json.JSONDecodeError as e:
            LOGGER.debug("Strategy 1 failed: %s", e)

        # Strategy 2: Strip markdown fences, then balanced-brace extract
        stripped = self._strip_markdown_fences(output)
        if stripped != output.strip():
            json_candidate = self._extract_json_balanced(stripped)
            if json_candidate:
                result = self._try_parse_json(json_candidate, "Strategy 2 (strip fences + balanced braces)")
                if result:
                    return result

        # Strategy 3: Balanced-brace extraction on raw output
        json_from_braces = self._extract_json_balanced(output)
        if json_from_braces:
            result = self._try_parse_json(json_from_braces, "Strategy 3 (balanced braces)")
            if result:
                return result
        else:
            LOGGER.debug("Strategy 3: no balanced JSON object found")

        # Strategy 4: Aggressive — strip everything before first { and after last }
        json_aggressive = self._extract_json_aggressive(output)
        if json_aggressive:
            result = self._try_parse_json(json_aggressive, "Strategy 4 (aggressive extraction)")
            if result:
                return result

        LOGGER.warning(
            "Failed to parse executive summary output as JSON "
            "(output length: %d, last 200 chars: ...%s)",
            len(output),
            output[-200:],
        )
        LOGGER.debug("Full unparsed output:\n%s", output[:2000])
        return {}

    @staticmethod
    def _strip_markdown_fences(text: str) -> str:
        """Remove markdown code fences and surrounding prose from text.

        Handles common AI output patterns:
        1. ```json\\n{...}\\n```             (full fence with language tag)
        2. ```\\n{...}\\n```                 (fence without language tag)
        3. {...}```                           (trailing fence only, no newline)
        4. prose\\n```json\\n{...}\\n```     (prose before fence)
        5. Raw {...}                          (no fences at all)

        The old implementation used ^.*?``` with re.DOTALL to strip leading
        fences, which incorrectly consumed the entire JSON body when only a
        trailing fence was present (the regex matched from ^ to the *first*
        ```, which was the trailing one).

        Fix: detect whether the string STARTS with a fence (possibly after
        short prose) to decide which stripping strategy to apply.
        """
        stripped = text.strip()

        # Fast path: no backticks at all
        if "```" not in stripped:
            return stripped

        # Strategy A: The string contains BOTH a leading and trailing fence.
        # Match: optional short prose, ```json, then capture everything until
        # the LAST ``` in the string.  The captured group is the JSON body.
        m = re.match(
            r"(?:.*?\n)?```(?:json)?\s*\n(.*?)\n?\s*```\s*.*$",
            stripped,
            re.DOTALL,
        )
        if m:
            return m.group(1).strip()

        # Strategy B: Only a trailing fence (the production bug case).
        # The JSON body runs from the start of the string up to the last ```.
        # We find the LAST occurrence of ``` and truncate there.
        last_fence = stripped.rfind("```")
        if last_fence > 0:
            candidate = stripped[:last_fence].strip()
            if candidate.startswith("{") or candidate.startswith("["):
                return candidate

        return stripped

    def _try_parse_json(self, text: str, label: str) -> Optional[Dict[str, Any]]:
        """Try to parse text as JSON, with repair fallback.

        Args:
            text: Candidate JSON string
            label: Label for logging which strategy produced this candidate

        Returns:
            Parsed + normalized dict, or None if parsing fails
        """
        try:
            parsed = json.loads(text)
            LOGGER.info("Parsed summary via %s", label)
            return self._normalize_parsed(parsed)
        except json.JSONDecodeError as e:
            LOGGER.debug(
                "%s: JSON decode failed: %s (length: %d, first 300: %s)",
                label, e, len(text), text[:300],
            )
            # Try repair
            repaired = self._try_repair_json(text)
            if repaired and repaired != text:
                try:
                    parsed = json.loads(repaired)
                    LOGGER.info("Parsed summary via %s + repair", label)
                    return self._normalize_parsed(parsed)
                except json.JSONDecodeError:
                    LOGGER.debug("%s: repair also failed", label)
        return None

    @staticmethod
    def _extract_json_aggressive(text: str) -> Optional[str]:
        """Extract JSON by finding first { and last } — no brace balancing.

        This is the last-resort strategy when balanced extraction fails,
        possibly because the AI output has unusual escape sequences or
        characters that confuse the brace counter.
        """
        first = text.find("{")
        last = text.rfind("}")
        if first >= 0 and last > first:
            return text[first : last + 1]
        return None

    @staticmethod
    def _try_repair_json(text: str) -> Optional[str]:
        """Attempt to repair common JSON formatting issues from AI models.

        Fixes:
        - Trailing commas before } or ]
        - Single quotes instead of double quotes
        - Comments (// or /* */)
        """
        # Remove trailing commas before } or ]
        repaired = re.sub(r",\s*([}\]])", r"\1", text)
        # Remove JS-style comments
        repaired = re.sub(r"//.*$", "", repaired, flags=re.MULTILINE)
        repaired = re.sub(r"/\*.*?\*/", "", repaired, flags=re.DOTALL)
        return repaired

    @staticmethod
    def _extract_json_balanced(text: str) -> Optional[str]:
        """Extract the first complete JSON object using brace counting.

        More robust than simple find/rfind because it tracks brace depth
        to avoid cutting off early on internal braces or including text
        after the closing brace.
        """
        start = text.find("{")
        if start < 0:
            return None

        depth = 0
        in_string = False
        escape_next = False
        i = start

        while i < len(text):
            char = text[i]

            if escape_next:
                escape_next = False
                i += 1
                continue

            if char == "\\":
                escape_next = True
                i += 1
                continue

            if char == '"' and not escape_next:
                in_string = not in_string
                i += 1
                continue

            if in_string:
                i += 1
                continue

            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return text[start : i + 1]

            i += 1

        return None

    @staticmethod
    def _normalize_parsed(parsed: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize the parsed output into a consistent format."""
        result: Dict[str, Any] = {}

        # Safety assessment
        safety = parsed.get("safety_assessment", {})
        if isinstance(safety, dict):
            result["safety_assessment"] = safety
        else:
            result["safety_assessment"] = {
                "rating": str(safety),
                "rationale": "",
            }

        # Executive summary text
        result["executive_summary"] = parsed.get("executive_summary", "")

        # Detailed analysis
        result["detailed_analysis"] = parsed.get("detailed_analysis", {})

        # Security recommendations
        recs = parsed.get("security_recommendations", [])
        if isinstance(recs, list):
            result["security_recommendations"] = recs
        else:
            result["security_recommendations"] = []

        # Project notes
        notes = parsed.get("project_notes", [])
        if isinstance(notes, list):
            result["project_notes"] = notes
        else:
            result["project_notes"] = []

        # Confidence score
        conf = parsed.get("confidence_score", 0.5)
        result["confidence_score"] = float(conf) if conf else 0.5

        # Derive security_analysis from detailed_analysis for DB storage
        detailed = result.get("detailed_analysis", {})
        if detailed:
            parts = []
            for dimension, text in detailed.items():
                if text:
                    parts.append(f"**{dimension.title()}**: {text}")
            result["security_analysis"] = "\n\n".join(parts)
        else:
            result["security_analysis"] = ""

        # Derive recommendations as string list for DB storage
        rec_texts = [
            f"[{r.get('priority', 'medium').upper()}] {r.get('title', '')}: {r.get('description', '')}"
            for r in result.get("security_recommendations", [])
            if isinstance(r, dict)
        ]
        result["recommendations"] = rec_texts

        return result
