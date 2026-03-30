"""Self-improvement module for the audit agent.

Maintains a lessons file that is injected into the knowledge context,
allowing the audit agent to learn from past mistakes and improve
detection accuracy over time.

Lesson sources:
1. External audit comparisons (when external audit reports are available)
2. False positive analysis (when findings are dismissed by reviewers)
3. Manual lesson additions (when developers identify patterns)

Enhanced with:
- Category-level accuracy tracking (precision/recall per category)
- Dynamic prompt weight adjustment based on category performance
- Full comparison engine integration via AuditComparisonEngine
"""
from __future__ import annotations

import json
import logging
import os
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

LOGGER = logging.getLogger(__name__)

# Resolve lessons file relative to this module's parent directory
_AGENTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "agents",
)
LESSONS_FILE = os.path.join(_AGENTS_DIR, "audit_lessons.json")
ACCURACY_FILE = os.path.join(_AGENTS_DIR, "category_accuracy.json")


class AuditSelfImprover:
    """Manages audit lessons and category accuracy for self-improvement.

    Lessons are stored as JSON in agents/audit_lessons.json and
    injected into the knowledge context at audit time.

    Category accuracy is tracked in agents/category_accuracy.json and
    used to dynamically adjust prompt weights for weak categories.
    """

    def __init__(self, lessons_file: Optional[str] = None):
        self._lessons_file = lessons_file or LESSONS_FILE
        self._accuracy_file = ACCURACY_FILE
        self.lessons: List[Dict[str, Any]] = self._load_lessons()
        self._category_accuracy: Dict[str, Dict[str, float]] = self._load_accuracy()

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

    # ------------------------------------------------------------------
    # Accuracy tracking & category-level metrics
    # ------------------------------------------------------------------

    def _load_accuracy(self) -> Dict[str, Dict[str, float]]:
        """Load category accuracy data from JSON file."""
        if not os.path.exists(self._accuracy_file):
            return {}
        try:
            with open(self._accuracy_file, "r") as fh:
                return json.load(fh)
        except Exception as exc:
            LOGGER.warning("Failed to load category accuracy: %s", exc)
        return {}

    def _save_accuracy(self) -> None:
        """Persist category accuracy data."""
        os.makedirs(os.path.dirname(self._accuracy_file), exist_ok=True)
        try:
            with open(self._accuracy_file, "w") as fh:
                json.dump(self._category_accuracy, fh, indent=2, default=str)
        except Exception as exc:
            LOGGER.error("Failed to save category accuracy: %s", exc)

    def update_category_accuracy(
        self,
        category: str,
        is_correct: bool,
        finding_type: str = "detection",
    ) -> None:
        """Update per-category accuracy after a comparison result.

        Args:
            category: Normalized vulnerability category (e.g., "reentrancy")
            is_correct: Whether the AI got it right (matched + correct severity)
            finding_type: "detection", "severity", "false_positive", "missed"
        """
        if category not in self._category_accuracy:
            self._category_accuracy[category] = {
                "total_comparisons": 0,
                "correct": 0,
                "false_positives": 0,
                "missed": 0,
                "severity_correct": 0,
                "severity_total": 0,
                "last_updated": datetime.utcnow().isoformat(),
            }

        stats = self._category_accuracy[category]
        stats["total_comparisons"] = stats.get("total_comparisons", 0) + 1

        if finding_type == "detection" and is_correct:
            stats["correct"] = stats.get("correct", 0) + 1
        elif finding_type == "false_positive":
            stats["false_positives"] = stats.get("false_positives", 0) + 1
        elif finding_type == "missed":
            stats["missed"] = stats.get("missed", 0) + 1
        elif finding_type == "severity":
            stats["severity_total"] = stats.get("severity_total", 0) + 1
            if is_correct:
                stats["severity_correct"] = stats.get("severity_correct", 0) + 1

        stats["last_updated"] = datetime.utcnow().isoformat()
        self._save_accuracy()

    def get_category_accuracy(self) -> Dict[str, Dict[str, float]]:
        """Get per-category accuracy metrics.

        Returns dict mapping category -> {precision, recall, f1, severity_accuracy, ...}
        """
        result = {}
        for cat, stats in self._category_accuracy.items():
            total = stats.get("total_comparisons", 0)
            if total == 0:
                continue
            correct = stats.get("correct", 0)
            fp = stats.get("false_positives", 0)
            missed = stats.get("missed", 0)
            sev_correct = stats.get("severity_correct", 0)
            sev_total = stats.get("severity_total", 0)

            precision = correct / (correct + fp) if (correct + fp) > 0 else 0.0
            recall = correct / (correct + missed) if (correct + missed) > 0 else 0.0
            f1 = (
                2 * precision * recall / (precision + recall)
                if (precision + recall) > 0
                else 0.0
            )
            sev_acc = sev_correct / sev_total if sev_total > 0 else 1.0

            result[cat] = {
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1": round(f1, 4),
                "severity_accuracy": round(sev_acc, 4),
                "total_comparisons": total,
                "correct": correct,
                "false_positives": fp,
                "missed": missed,
            }
        return result

    def get_prompt_weight_adjustments(self) -> Dict[str, float]:
        """Calculate dynamic prompt weight adjustments per category.

        Categories with low recall get increased weight (more attention needed).
        Categories with low precision get decreased weight (too many false alarms).

        The weight is a multiplier applied to the prompt's attention directive.
        - 1.0 = baseline (no adjustment)
        - > 1.0 = pay extra attention to this category
        - < 1.0 = be more conservative with this category

        Returns:
            Dict mapping category -> weight multiplier (0.5 - 2.0)
        """
        adjustments: Dict[str, float] = {}
        cat_accuracy = self.get_category_accuracy()

        for cat, metrics in cat_accuracy.items():
            recall = metrics.get("recall", 1.0)
            precision = metrics.get("precision", 1.0)
            total = metrics.get("total_comparisons", 0)

            # Need at least 3 comparisons to start adjusting
            if total < 3:
                adjustments[cat] = 1.0
                continue

            # Low recall -> increase attention (weight > 1.0)
            # Low precision -> decrease sensitivity (weight < 1.0)
            recall_factor = max(0.5, min(2.0, 1.0 / max(recall, 0.1)))
            precision_factor = max(0.5, min(1.5, precision))

            weight = round(recall_factor * precision_factor, 2)
            weight = max(0.5, min(2.0, weight))
            adjustments[cat] = weight

        return adjustments

    def get_accuracy_report(self) -> Dict[str, Any]:
        """Get comprehensive accuracy report across all categories."""
        cat_accuracy = self.get_category_accuracy()
        weight_adj = self.get_prompt_weight_adjustments()

        total_comparisons = sum(
            m.get("total_comparisons", 0) for m in cat_accuracy.values()
        )
        total_correct = sum(
            m.get("correct", 0) for m in cat_accuracy.values()
        )

        return {
            "total_lessons": len(self.lessons),
            "total_comparisons": total_comparisons,
            "overall_accuracy": (
                round(total_correct / total_comparisons, 4)
                if total_comparisons > 0
                else None
            ),
            "category_accuracy": cat_accuracy,
            "prompt_weight_adjustments": weight_adj,
            "categories_needing_attention": [
                cat
                for cat, metrics in cat_accuracy.items()
                if metrics.get("recall", 1.0) < 0.7 or metrics.get("total_comparisons", 0) >= 3
            ],
        }

    def format_weight_adjustments_for_prompt(self) -> str:
        """Format category weights for injection into knowledge context.

        This section is placed between <!-- CATEGORY_WEIGHTS_START --> and
        <!-- CATEGORY_WEIGHTS_END --> markers in knowledge-context.md.
        """
        adjustments = self.get_prompt_weight_adjustments()
        if not adjustments:
            return "No category weight adjustments yet."

        parts = ["### Category Attention Weights (Auto-Adjusted)\n"]
        parts.append(
            "Based on comparison with external audits, apply these attention "
            "multipliers when analyzing each vulnerability category:\n"
        )
        for cat, weight in sorted(adjustments.items(), key=lambda x: -x[1]):
            if weight > 1.2:
                directive = "PAY EXTRA ATTENTION"
            elif weight < 0.8:
                directive = "BE MORE CONSERVATIVE"
            else:
                directive = "Standard attention"
            parts.append(f"- **{cat}**: {weight}x weight ({directive})")

        return "\n".join(parts)

    def get_category_weights_for_context(self) -> str:
        """Format category weights as markdown for injection into the audit prompt.

        Produces human-readable lines like:
            - **Reentrancy**: boost attention by 1.5x (low recall - 60% of external findings missed)
        Only includes categories where weight != 1.0 (i.e. needing adjustment).
        """
        adjustments = self.get_prompt_weight_adjustments()
        cat_accuracy = self.get_category_accuracy()

        if not adjustments:
            return ""

        parts: List[str] = []
        for cat, weight in sorted(adjustments.items(), key=lambda x: -x[1]):
            if abs(weight - 1.0) < 0.01:
                continue

            metrics = cat_accuracy.get(cat, {})
            recall = metrics.get("recall", 1.0)
            precision = metrics.get("precision", 1.0)

            if weight > 1.0:
                missed_pct = round((1.0 - recall) * 100)
                parts.append(
                    f"- **{cat}**: boost attention by {weight}x "
                    f"(low recall - {missed_pct}% of external findings missed)"
                )
            else:
                fp_pct = round((1.0 - precision) * 100)
                parts.append(
                    f"- **{cat}**: reduce sensitivity to {weight}x "
                    f"(high false positive rate - {fp_pct}% of flags were incorrect)"
                )

        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Enhanced comparison using AuditComparisonEngine
    # ------------------------------------------------------------------

    def compare_and_learn(
        self,
        ai_findings: List[Dict[str, Any]],
        human_findings: List[Dict[str, Any]],
        contract_address: str = "",
    ) -> Dict[str, Any]:
        """High-level: compare AI vs human findings, generate lessons, update accuracy.

        Uses AuditComparisonEngine for sophisticated matching, then feeds
        results into lesson generation and category accuracy tracking.

        Args:
            ai_findings: Findings from the Spectra AI audit
            human_findings: Findings from an external/human audit
            contract_address: Contract being audited

        Returns:
            Dict with comparison result and lesson generation stats
        """
        from .audit_comparison_engine import AuditComparisonEngine

        engine = AuditComparisonEngine()
        comparison = engine.compare_audits(
            ai_findings=ai_findings,
            human_findings=human_findings,
            contract_address=contract_address,
        )

        # Generate lessons from comparison results
        lessons_added = 0

        # False positive lessons
        for fp in comparison.false_positives:
            self.add_lesson(
                pattern=f"False positive: {fp.get('category', 'unknown')} at {fp.get('location', 'unknown')}",
                lesson_type="false_positive",
                description=(
                    f"AI flagged {fp.get('location', 'unknown')} as "
                    f"{fp.get('severity', 'unknown')} "
                    f"({fp.get('category', 'unknown')}) "
                    f"but external audit did not confirm it. "
                    f"Detail: {fp.get('description', '')[:200]}"
                ),
                correct_action=(
                    f"Be more conservative when flagging similar "
                    f"{fp.get('category', 'unknown')} patterns. "
                    f"Verify exploitability before flagging."
                ),
                contract_context=contract_address,
            )
            self.update_category_accuracy(
                category=fp.get("category", "unknown").lower(),
                is_correct=False,
                finding_type="false_positive",
            )
            lessons_added += 1

        # Missed finding lessons
        for miss in comparison.missed_findings:
            self.add_lesson(
                pattern=f"Missed: {miss.get('category', 'unknown')} at {miss.get('location', 'unknown')}",
                lesson_type="missed_finding",
                description=(
                    f"AI missed {miss.get('severity', 'unknown')} "
                    f"({miss.get('category', 'unknown')}) at "
                    f"{miss.get('location', 'unknown')}: "
                    f"{miss.get('description', '')[:200]}"
                ),
                correct_action=(
                    f"Actively check for similar "
                    f"{miss.get('category', 'unknown')} patterns: "
                    f"{miss.get('description', '')[:200]}"
                ),
                contract_context=contract_address,
            )
            self.update_category_accuracy(
                category=miss.get("category", "unknown").lower(),
                is_correct=False,
                finding_type="missed",
            )
            lessons_added += 1

        # Severity mismatch lessons
        for pair in comparison.severity_mismatches:
            ai_sev = pair.ai_finding.get("severity", "unknown")
            human_sev = pair.human_finding.get("severity", "unknown")
            cat = pair.ai_finding.get("category", "unknown").lower()
            self.add_lesson(
                pattern=f"Severity mismatch: {cat}",
                lesson_type="severity_adjustment",
                description=(
                    f"AI rated {pair.ai_finding.get('location', 'unknown')} "
                    f"as {ai_sev}, but external audit rated it as {human_sev} "
                    f"(category: {cat})."
                ),
                correct_action=f"For similar {cat} patterns, assign {human_sev} severity.",
                contract_context=contract_address,
            )
            self.update_category_accuracy(
                category=cat,
                is_correct=False,
                finding_type="severity",
            )
            lessons_added += 1

        # Update matched findings as correct
        for pair in comparison.matched_pairs:
            if pair.severity_match:
                self.update_category_accuracy(
                    category=pair.ai_finding.get("category", "unknown").lower(),
                    is_correct=True,
                    finding_type="detection",
                )

        LOGGER.info(
            "Comparison and learn complete: %d lessons added, "
            "%.1f%% coverage, %.4f precision, %.4f recall",
            lessons_added,
            comparison.coverage_percent,
            comparison.overall_precision,
            comparison.overall_recall,
        )

        return {
            "comparison": comparison.to_dict(),
            "lessons_added": lessons_added,
            "total_lessons": len(self.lessons),
        }
