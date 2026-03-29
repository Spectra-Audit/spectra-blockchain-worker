"""Self-improvement module for the audit agent.

Maintains a lessons file that is injected into the knowledge context,
allowing the audit agent to learn from past mistakes and improve
detection accuracy over time.

Lesson sources:
1. External audit comparisons (when external audit reports are available)
2. False positive analysis (when findings are dismissed by reviewers)
3. Manual lesson additions (when developers identify patterns)
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

LOGGER = logging.getLogger(__name__)

# Resolve lessons file relative to this module's parent directory
_AGENTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "agents",
)
LESSONS_FILE = os.path.join(_AGENTS_DIR, "audit_lessons.json")


class AuditSelfImprover:
    """Manages audit lessons for self-improvement.

    Lessons are stored as JSON in agents/audit_lessons.json and
    injected into the knowledge context at audit time.
    """

    def __init__(self, lessons_file: Optional[str] = None):
        self._lessons_file = lessons_file or LESSONS_FILE
        self.lessons: List[Dict[str, Any]] = self._load_lessons()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load_lessons(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self._lessons_file):
            return []
        try:
            with open(self._lessons_file, "r") as fh:
                data = json.load(fh)
            if isinstance(data, list):
                return data
        except Exception as exc:
            LOGGER.warning("Failed to load audit lessons: %s", exc)
        return []

    def _save_lessons(self) -> None:
        os.makedirs(os.path.dirname(self._lessons_file), exist_ok=True)
        try:
            with open(self._lessons_file, "w") as fh:
                json.dump(self.lessons, fh, indent=2, default=str)
        except Exception as exc:
            LOGGER.error("Failed to save audit lessons: %s", exc)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_lesson(
        self,
        pattern: str,
        lesson_type: str,  # "false_positive", "missed_finding", "severity_adjustment"
        description: str,
        correct_action: str,
        contract_context: str = "",
    ) -> None:
        """Add a new lesson to the knowledge base."""
        lesson = {
            "id": f"lesson_{len(self.lessons) + 1:04d}",
            "pattern": pattern,
            "type": lesson_type,
            "description": description,
            "correct_action": correct_action,
            "contract_context": contract_context,
            "added_at": datetime.utcnow().isoformat(),
        }
        self.lessons.append(lesson)
        self._save_lessons()
        LOGGER.info("Added audit lesson: %s (%s)", lesson["id"], lesson_type)

    def get_lessons_for_context(self, max_lessons: int = 20) -> str:
        """Format recent lessons for injection into the audit prompt."""
        if not self.lessons:
            return "No lessons learned yet. This is the first audit with this agent."

        recent = self.lessons[-max_lessons:]
        parts = ["## Learned Lessons (Apply These Rules)\n"]
        for lesson in recent:
            parts.append(
                f"- **{lesson['type'].replace('_', ' ').title()}**: {lesson['description']}\n"
                f"  Correct action: {lesson['correct_action']}\n"
            )
        return "\n".join(parts)

    def analyze_audit_comparison(
        self,
        our_findings: List[Dict[str, Any]],
        external_findings: List[Dict[str, Any]],
    ) -> int:
        """Compare our audit with an external audit and generate lessons.

        Returns the number of new lessons added.
        """
        our_locations = {f.get("location", "") for f in our_findings}
        external_locations = {f.get("location", "") for f in external_findings}

        false_positives = our_locations - external_locations
        missed = external_locations - our_locations

        for fp_loc in false_positives:
            our_finding = next(
                (f for f in our_findings if f.get("location") == fp_loc), {}
            )
            self.add_lesson(
                pattern=f"False positive at {fp_loc}",
                lesson_type="false_positive",
                description=(
                    f"Our audit flagged {fp_loc} as "
                    f"{our_finding.get('severity', 'unknown')} "
                    f"({our_finding.get('category', 'unknown')}) "
                    f"but external audit did not flag it."
                ),
                correct_action=(
                    f"Do not flag similar patterns at {fp_loc} "
                    f"unless absolutely certain."
                ),
            )

        for miss_loc in missed:
            ext_finding = next(
                (f for f in external_findings if f.get("location") == miss_loc), {}
            )
            self.add_lesson(
                pattern=f"Missed finding at {miss_loc}",
                lesson_type="missed_finding",
                description=(
                    f"Our audit missed "
                    f"{ext_finding.get('severity', 'unknown')} "
                    f"({ext_finding.get('category', 'unknown')}) at {miss_loc}: "
                    f"{ext_finding.get('description', '')[:200]}"
                ),
                correct_action=(
                    f"Check for similar patterns: "
                    f"{ext_finding.get('description', '')[:200]}"
                ),
            )

        # Compare severities for overlapping locations
        for loc in our_locations & external_locations:
            our_f = next((f for f in our_findings if f.get("location") == loc), {})
            ext_f = next((f for f in external_findings if f.get("location") == loc), {})
            our_sev = our_f.get("severity", "")
            ext_sev = ext_f.get("severity", "")
            if our_sev != ext_sev:
                self.add_lesson(
                    pattern=f"Severity mismatch at {loc}",
                    lesson_type="severity_adjustment",
                    description=(
                        f"We rated {loc} as {our_sev} but external audit rated it "
                        f"as {ext_sev}."
                    ),
                    correct_action=(
                        f"For similar patterns, assign {ext_sev} severity."
                    ),
                )

        return len(false_positives) + len(missed)
