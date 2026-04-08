"""Self-improvement module for the executive summary agent.

Maintains lessons from three sources:
1. Assessment accuracy — compares past assessments with current data
2. New vulnerability patterns — discovered during re-audits
3. Cross-project patterns — correlations across the project portfolio

Lessons are stored in executive_summary/lessons/ and injected into the
agent prompt to improve future assessment quality.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

LOGGER = logging.getLogger(__name__)

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_LESSONS_FILE = os.path.join(_BASE_DIR, "lessons", "lessons.json")
_HISTORY_FILE = os.path.join(_BASE_DIR, "lessons", "assessment_history.json")

MAX_LESSONS_IN_PROMPT = 15
MAX_HISTORY_PER_PROJECT = 5


class SummarySelfImprover:
    """Self-learning system for executive summary generation.

    Tracks assessment accuracy, cross-project patterns, and new vulnerability
    discoveries to improve future executive summary quality.
    """

    def __init__(
        self,
        lessons_file: Optional[str] = None,
        history_file: Optional[str] = None,
    ) -> None:
        self._lessons_file = lessons_file or _LESSONS_FILE
        self._history_file = history_file or _HISTORY_FILE
        self.lessons: List[Dict[str, Any]] = self._load_json(self._lessons_file)
        self._history: List[Dict[str, Any]] = self._load_json(self._history_file)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    @staticmethod
    def _load_json(path: str) -> List[Dict[str, Any]]:
        if not os.path.exists(path):
            return []
        try:
            with open(path, "r") as fh:
                data = json.load(fh)
            return data if isinstance(data, list) else []
        except Exception as exc:
            LOGGER.warning("Failed to load %s: %s", path, exc)
        return []

    def _save_json(self, path: str, data: Any) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        try:
            with open(path, "w") as fh:
                json.dump(data, fh, indent=2, default=str)
        except Exception as exc:
            LOGGER.error("Failed to save %s: %s", path, exc)

    def _save_lessons(self) -> None:
        self._save_json(self._lessons_file, self.lessons)

    def _save_history(self) -> None:
        self._save_json(self._history_file, self._history)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_lessons_for_context(self, max_lessons: int = MAX_LESSONS_IN_PROMPT) -> str:
        """Format recent lessons for injection into the agent prompt."""
        if not self.lessons:
            return "No lessons learned yet. This is the first assessment with this agent."

        recent = self.lessons[-max_lessons:]
        parts = ["## Learned Lessons (Apply These Rules)\n"]
        for lesson in recent:
            lesson_type = lesson.get("type", "general").replace("_", " ").title()
            parts.append(
                f"- **{lesson_type}**: {lesson.get('description', '')}\n"
                f"  Action: {lesson.get('correct_action', '')}\n"
            )
        return "\n".join(parts)

    def record_assessment(
        self,
        project_id: str,
        assessment: Dict[str, Any],
    ) -> None:
        """Record an assessment for future accuracy tracking.

        Compares with previous assessment and generates lessons if drift detected.
        """
        previous = self._get_previous_assessment(project_id)

        entry = {
            "project_id": project_id,
            "safety_rating": assessment.get("safety_assessment", {}).get("rating", "N/A"),
            "confidence_score": assessment.get("confidence_score", 0),
            "general_score": assessment.get("_source_scores", {}).get("general"),
            "recorded_at": datetime.utcnow().isoformat(),
        }

        self._history.append(entry)
        self._trim_history(project_id)
        self._save_history()

        # Compare with previous and generate lessons
        if previous:
            self._compare_assessments(project_id, previous, entry)

    def record_new_findings(
        self,
        project_id: str,
        new_findings: List[Dict[str, Any]],
        previous_findings_count: int,
    ) -> None:
        """Record lessons from newly discovered findings during re-audit.

        If new findings appeared that weren't in the previous assessment,
        record what was missed.
        """
        if not new_findings:
            return

        new_critical = [f for f in new_findings if f.get("severity") == "critical"]
        new_high = [f for f in new_findings if f.get("severity") == "high"]

        if new_critical:
            self._add_lesson(
                lesson_type="missed_vulnerability",
                description=(
                    f"Project {project_id[:8]}... had {len(new_critical)} new CRITICAL "
                    f"findings discovered in re-audit (previously had {previous_findings_count} findings). "
                    f"Categories: {', '.join(f.get('category', 'unknown') for f in new_critical[:3])}"
                ),
                correct_action=(
                    "When assessing projects with similar score profiles, pay extra attention "
                    "to these vulnerability categories and flag them more aggressively."
                ),
            )

        if new_high and len(new_high) >= 3:
            self._add_lesson(
                lesson_type="missed_vulnerability",
                description=(
                    f"Project {project_id[:8]}... had {len(new_high)} new HIGH findings "
                    f"in re-audit. Previous assessment may have underestimated risk."
                ),
                correct_action=(
                    "For projects with similar code scores but ambiguous patterns, "
                    "apply more conservative safety ratings."
                ),
            )

    def find_cross_project_patterns(self) -> List[str]:
        """Identify patterns across the project portfolio.

        Returns list of human-readable pattern descriptions.
        """
        if len(self._history) < 5:
            return []

        patterns: List[str] = []

        # Pattern 1: Score ranges that correlate with safety downgrades
        downgraded = []
        for i in range(1, len(self._history)):
            prev = self._history[i - 1]
            curr = self._history[i]
            if (
                prev.get("project_id") == curr.get("project_id")
                and prev.get("safety_rating") != curr.get("safety_rating")
            ):
                rating_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "CRITICAL": 3}
                prev_rank = rating_order.get(prev.get("safety_rating", ""), 1)
                curr_rank = rating_order.get(curr.get("safety_rating", ""), 1)
                if curr_rank > prev_rank:
                    downgraded.append(curr)

        if len(downgraded) >= 2:
            patterns.append(
                f"Cross-project alert: {len(downgraded)} projects had safety downgrades "
                f"after data updates. Consider being more conservative with initial assessments."
            )

        return patterns

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _get_previous_assessment(self, project_id: str) -> Optional[Dict[str, Any]]:
        """Get the most recent assessment for a project."""
        project_entries = [
            h for h in self._history if h.get("project_id") == project_id
        ]
        return project_entries[-1] if project_entries else None

    def _trim_history(self, project_id: str) -> None:
        """Keep only the last MAX_HISTORY_PER_PROJECT entries per project."""
        project_entries = [
            h for h in self._history if h.get("project_id") == project_id
        ]
        if len(project_entries) > MAX_HISTORY_PER_PROJECT:
            # Remove oldest entries for this project
            to_remove = project_entries[: len(project_entries) - MAX_HISTORY_PER_PROJECT]
            remove_ids = {id(e) for e in to_remove}
            self._history = [h for h in self._history if id(h) not in remove_ids]

    def _compare_assessments(
        self,
        project_id: str,
        previous: Dict[str, Any],
        current: Dict[str, Any],
    ) -> None:
        """Compare two assessments and generate lessons if significant drift detected."""
        prev_rating = previous.get("safety_rating", "N/A")
        curr_rating = current.get("safety_rating", "N/A")

        rating_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "CRITICAL": 3}
        prev_rank = rating_order.get(prev_rating, 1)
        curr_rank = rating_order.get(curr_rating, 1)

        # Major drift: 2+ levels change
        if abs(curr_rank - prev_rank) >= 2:
            direction = "downgraded" if curr_rank > prev_rank else "upgraded"
            self._add_lesson(
                lesson_type="assessment_drift",
                description=(
                    f"Project {project_id[:8]}... safety {direction} from {prev_rating} to "
                    f"{curr_rating}. Previous assessment may have been "
                    f"{'too optimistic' if curr_rank > prev_rank else 'too pessimistic'}."
                ),
                correct_action=(
                    f"For similar score profiles, consider assigning "
                    f"{curr_rating if curr_rank > prev_rank else prev_rating} "
                    f"rather than {prev_rating if curr_rank > prev_rank else curr_rating} "
                    f"to avoid large swings."
                ),
            )

        # Confidence drift
        prev_conf = previous.get("confidence_score", 0) or 0
        curr_conf = current.get("confidence_score", 0) or 0
        if abs(curr_conf - prev_conf) > 0.3:
            self._add_lesson(
                lesson_type="confidence_drift",
                description=(
                    f"Project {project_id[:8]}... confidence changed by "
                    f"{abs(curr_conf - prev_conf):.1f} (from {prev_conf:.2f} to "
                    f"{curr_conf:.2f}). Significant data changes occurred."
                ),
                correct_action=(
                    "When data changes significantly between assessments, "
                    "note the specific data sources that changed and how they "
                    "affected the assessment."
                ),
            )

    def _add_lesson(
        self,
        lesson_type: str,
        description: str,
        correct_action: str,
    ) -> None:
        """Add a new lesson and persist."""
        lesson = {
            "id": f"summary_lesson_{len(self.lessons) + 1:04d}",
            "type": lesson_type,
            "description": description,
            "correct_action": correct_action,
            "added_at": datetime.utcnow().isoformat(),
        }
        self.lessons.append(lesson)
        self._save_lessons()
        LOGGER.info("Added summary lesson: %s (%s)", lesson["id"], lesson_type)
