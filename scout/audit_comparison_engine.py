"""Audit Comparison Engine for AI vs Human/External Audit findings.

Compares AI-generated audit findings against human/external audit findings,
identifying matches, false positives, missed findings, and severity mismatches.
Generates structured comparison results and feeds them into AuditSelfImprover
for automatic lesson generation and prompt weight adjustment.

Architecture:
    AuditComparisonEngine.compare_audits()
        -> _match_findings()          : fuzzy matching by location + category
        -> _classify_comparisons()    : matched / false_positive / missed
        -> _compare_severities()      : severity alignment analysis
        -> _calculate_category_accuracy() : per-category precision/recall
        -> returns ComparisonResult

Usage:
    engine = AuditComparisonEngine()
    result = engine.compare_audits(
        ai_findings=[{"severity": "high", "category": "reentrancy", ...}],
        human_findings=[{"severity": "critical", "category": "reentrancy", ...}],
        contract_address="0x..."
    )
    # result.matched, result.false_positives, result.missed, etc.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Tuple

LOGGER = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class MatchedPair:
    """A pair of AI and human findings that were matched."""

    ai_finding: Dict[str, Any]
    human_finding: Dict[str, Any]
    match_score: float  # 0-1, how confident the match is
    match_type: str  # "exact", "similar", "category_match"
    severity_match: bool  # True if severities agree


@dataclass
class CategoryAccuracy:
    """Per-category accuracy metrics."""

    category: str
    total_ai_findings: int = 0
    total_human_findings: int = 0
    matched: int = 0
    false_positives: int = 0  # AI flagged, human didn't
    missed: int = 0  # Human flagged, AI didn't
    precision: float = 0.0  # matched / (matched + false_positives)
    recall: float = 0.0  # matched / (matched + missed)
    severity_accuracy: float = 0.0  # % of matched with correct severity


@dataclass
class ComparisonResult:
    """Full comparison result between AI and human audit findings."""

    total_ai_findings: int = 0
    total_human_findings: int = 0
    matched_pairs: List[MatchedPair] = field(default_factory=list)
    false_positives: List[Dict[str, Any]] = field(default_factory=list)
    missed_findings: List[Dict[str, Any]] = field(default_factory=list)
    severity_mismatches: List[MatchedPair] = field(default_factory=list)
    category_accuracy: List[CategoryAccuracy] = field(default_factory=list)

    # Aggregate metrics
    overall_precision: float = 0.0
    overall_recall: float = 0.0
    overall_f1: float = 0.0
    severity_accuracy: float = 0.0
    coverage_percent: float = 0.0

    # Metadata
    contract_address: str = ""
    compared_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary for API responses and storage."""
        return {
            "total_ai_findings": self.total_ai_findings,
            "total_human_findings": self.total_human_findings,
            "matched_count": len(self.matched_pairs),
            "false_positive_count": len(self.false_positives),
            "missed_count": len(self.missed_findings),
            "severity_mismatch_count": len(self.severity_mismatches),
            "overall_precision": round(self.overall_precision, 4),
            "overall_recall": round(self.overall_recall, 4),
            "overall_f1": round(self.overall_f1, 4),
            "severity_accuracy": round(self.severity_accuracy, 4),
            "coverage_percent": round(self.coverage_percent, 2),
            "category_accuracy": [
                {
                    "category": ca.category,
                    "total_ai": ca.total_ai_findings,
                    "total_human": ca.total_human_findings,
                    "matched": ca.matched,
                    "false_positives": ca.false_positives,
                    "missed": ca.missed,
                    "precision": round(ca.precision, 4),
                    "recall": round(ca.recall, 4),
                    "severity_accuracy": round(ca.severity_accuracy, 4),
                }
                for ca in self.category_accuracy
            ],
            "matched_pairs": [
                {
                    "ai_severity": p.ai_finding.get("severity"),
                    "human_severity": p.human_finding.get("severity"),
                    "category": p.ai_finding.get("category", "unknown"),
                    "match_score": round(p.match_score, 4),
                    "match_type": p.match_type,
                    "severity_match": p.severity_match,
                }
                for p in self.matched_pairs
            ],
            "false_positives": [
                {
                    "severity": f.get("severity"),
                    "category": f.get("category"),
                    "title": f.get("title", f.get("description", "")[:80]),
                    "location": f.get("location"),
                }
                for f in self.false_positives
            ],
            "missed_findings": [
                {
                    "severity": f.get("severity"),
                    "category": f.get("category"),
                    "title": f.get("title", f.get("description", "")[:80]),
                    "location": f.get("location"),
                }
                for f in self.missed_findings
            ],
            "severity_mismatches": [
                {
                    "ai_severity": p.ai_finding.get("severity"),
                    "human_severity": p.human_finding.get("severity"),
                    "category": p.ai_finding.get("category"),
                }
                for p in self.severity_mismatches
            ],
            "contract_address": self.contract_address,
            "compared_at": self.compared_at,
        }


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

# Severity ranking for comparison
_SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
    "informational": 0,
}


class AuditComparisonEngine:
    """Compares AI audit findings against human/external audit findings.

    Finding matching strategy:
        1. Exact match on location (function name, contract) + category
        2. Fuzzy match on location + category (SequenceMatcher >= 0.6)
        3. Category-only match (same category, overlapping description keywords)

    After matching, findings are classified as:
        - matched: both AI and human found the same issue
        - false_positive: AI flagged, but human didn't
        - missed: human flagged, but AI didn't
    """

    # Minimum similarity score for fuzzy matching (0-1)
    LOCATION_MATCH_THRESHOLD = 0.6
    CATEGORY_MATCH_THRESHOLD = 0.7

    def compare_audits(
        self,
        ai_findings: List[Dict[str, Any]],
        human_findings: List[Dict[str, Any]],
        contract_address: str = "",
    ) -> ComparisonResult:
        """Main comparison entry point.

        Args:
            ai_findings: Findings from the Spectra AI audit
            human_findings: Findings from an external/human audit
            contract_address: Contract being audited (for context)

        Returns:
            ComparisonResult with full analysis
        """
        result = ComparisonResult(
            total_ai_findings=len(ai_findings),
            total_human_findings=len(human_findings),
            contract_address=contract_address,
            compared_at=datetime.utcnow().isoformat(),
        )

        if not ai_findings and not human_findings:
            return result

        # Step 1: Match findings
        matched_pairs, unmatched_ai, unmatched_human = self._match_findings(
            ai_findings, human_findings,
        )

        result.matched_pairs = matched_pairs
        result.false_positives = unmatched_ai
        result.missed_findings = unmatched_human

        # Step 2: Analyze severity mismatches among matched pairs
        result.severity_mismatches = [
            p for p in matched_pairs if not p.severity_match
        ]

        # Step 3: Calculate category-level accuracy
        result.category_accuracy = self._calculate_category_accuracy(
            matched_pairs, unmatched_ai, unmatched_human,
        )

        # Step 4: Calculate aggregate metrics
        self._calculate_aggregate_metrics(result)

        LOGGER.info(
            "Audit comparison complete: %d AI, %d human, %d matched, "
            "%d false_positives, %d missed, %.1f%% coverage",
            result.total_ai_findings,
            result.total_human_findings,
            len(matched_pairs),
            len(result.false_positives),
            len(result.missed_findings),
            result.coverage_percent,
        )

        return result

    # ------------------------------------------------------------------
    # Matching logic
    # ------------------------------------------------------------------

    def _match_findings(
        self,
        ai_findings: List[Dict[str, Any]],
        human_findings: List[Dict[str, Any]],
    ) -> Tuple[List[MatchedPair], List[Dict], List[Dict]]:
        """Match AI findings to human findings by location + category.

        Uses a greedy matching strategy: for each AI finding, find the best
        matching human finding. Each human finding can only match once.

        Returns:
            (matched_pairs, unmatched_ai, unmatched_human)
        """
        matched_pairs: List[MatchedPair] = []
        used_human_indices: set = set()

        # Track best matches for each AI finding
        for ai_f in ai_findings:
            best_match_idx = -1
            best_match_score = 0.0
            best_match_type = "none"

            for h_idx, human_f in enumerate(human_findings):
                if h_idx in used_human_indices:
                    continue

                score, match_type = self._compute_match_score(ai_f, human_f)

                if score > best_match_score and score >= self.LOCATION_MATCH_THRESHOLD:
                    best_match_score = score
                    best_match_idx = h_idx
                    best_match_type = match_type

            if best_match_idx >= 0:
                human_f = human_findings[best_match_idx]
                used_human_indices.add(best_match_idx)

                ai_sev = self._normalize_severity(ai_f.get("severity", ""))
                human_sev = self._normalize_severity(human_f.get("severity", ""))

                matched_pairs.append(MatchedPair(
                    ai_finding=ai_f,
                    human_finding=human_f,
                    match_score=best_match_score,
                    match_type=best_match_type,
                    severity_match=(ai_sev == human_sev),
                ))

        # Collect unmatched
        unmatched_ai = [
            f for i, f in enumerate(ai_findings)
            if not any(p.ai_finding is f for p in matched_pairs)
        ]
        unmatched_human = [
            f for i, f in enumerate(human_findings)
            if i not in used_human_indices
        ]

        return matched_pairs, unmatched_ai, unmatched_human

    def _compute_match_score(
        self,
        ai_f: Dict[str, Any],
        human_f: Dict[str, Any],
    ) -> Tuple[float, str]:
        """Compute similarity score between two findings.

        Matching strategy (in priority order):
        1. Exact location + category match -> score = 1.0
        2. Fuzzy location match + same category -> score = location_similarity
        3. Category match + overlapping description -> score = category_sim * 0.8

        Returns:
            (score, match_type) where score is 0-1 and match_type describes the match
        """
        ai_location = self._normalize_location(ai_f.get("location", ""))
        human_location = self._normalize_location(human_f.get("location", ""))
        ai_category = self._normalize_category(ai_f.get("category", ""))
        human_category = self._normalize_category(human_f.get("category", ""))

        # Strategy 1: Exact location + category match
        if ai_location and human_location and ai_location == human_location:
            if ai_category and human_category and ai_category == human_category:
                return 1.0, "exact"
            # Same location, different category -- still strong match
            if ai_location:
                return 0.9, "exact"

        # Strategy 2: Fuzzy location + same category
        if ai_location and human_location:
            loc_sim = SequenceMatcher(None, ai_location, human_location).ratio()
            if loc_sim >= self.LOCATION_MATCH_THRESHOLD:
                if ai_category == human_category:
                    return loc_sim, "similar"
                # Different category but similar location
                cat_sim = SequenceMatcher(None, ai_category, human_category).ratio()
                if cat_sim >= self.CATEGORY_MATCH_THRESHOLD:
                    return loc_sim * 0.85, "similar"

        # Strategy 3: Category match + description overlap
        if ai_category and human_category:
            cat_sim = SequenceMatcher(None, ai_category, human_category).ratio()
            if cat_sim >= self.CATEGORY_MATCH_THRESHOLD:
                # Check description overlap
                ai_desc = self._normalize_text(ai_f.get("description", ""))
                human_desc = self._normalize_text(human_f.get("description", ""))
                if ai_desc and human_desc:
                    desc_sim = SequenceMatcher(None, ai_desc[:200], human_desc[:200]).ratio()
                    combined = cat_sim * 0.6 + desc_sim * 0.4
                    if combined >= self.CATEGORY_MATCH_THRESHOLD:
                        return combined, "category_match"

        # Strategy 4: Check file path overlap (for external findings with file_path)
        ai_file = ai_f.get("file_path", "") or ai_f.get("code_affected", "")
        human_file = human_f.get("file_path", "") or human_f.get("code_affected", "")
        if ai_file and human_file:
            file_sim = SequenceMatcher(
                None,
                self._normalize_text(ai_file),
                self._normalize_text(human_file),
            ).ratio()
            if file_sim >= 0.7 and ai_category == human_category:
                return file_sim * 0.8, "similar"

        return 0.0, "none"

    # ------------------------------------------------------------------
    # Category accuracy
    # ------------------------------------------------------------------

    def _calculate_category_accuracy(
        self,
        matched_pairs: List[MatchedPair],
        false_positives: List[Dict],
        missed: List[Dict],
    ) -> List[CategoryAccuracy]:
        """Calculate per-category precision, recall, and severity accuracy."""
        category_data: Dict[str, Dict] = {}

        # Aggregate matched pairs by category
        for pair in matched_pairs:
            cat = self._normalize_category(
                pair.ai_finding.get("category", "unknown"),
            )
            if cat not in category_data:
                category_data[cat] = {
                    "matched": 0,
                    "severity_correct": 0,
                    "total_ai": 0,
                    "total_human": 0,
                }
            category_data[cat]["matched"] += 1
            if pair.severity_match:
                category_data[cat]["severity_correct"] += 1

        # Count false positives by category
        for fp in false_positives:
            cat = self._normalize_category(fp.get("category", "unknown"))
            if cat not in category_data:
                category_data[cat] = {
                    "matched": 0,
                    "severity_correct": 0,
                    "total_ai": 0,
                    "total_human": 0,
                }
            category_data[cat].setdefault("false_positives", 0)
            category_data[cat]["false_positives"] = category_data[cat].get("false_positives", 0) + 1

        # Count missed by category
        for miss in missed:
            cat = self._normalize_category(miss.get("category", "unknown"))
            if cat not in category_data:
                category_data[cat] = {
                    "matched": 0,
                    "severity_correct": 0,
                    "total_ai": 0,
                    "total_human": 0,
                }
            category_data[cat].setdefault("missed", 0)
            category_data[cat]["missed"] = category_data[cat].get("missed", 0) + 1

        # Build CategoryAccuracy objects
        results: List[CategoryAccuracy] = []
        for cat, data in category_data.items():
            matched = data.get("matched", 0)
            fp = data.get("false_positives", 0)
            missed_count = data.get("missed", 0)
            sev_correct = data.get("severity_correct", 0)

            precision = matched / (matched + fp) if (matched + fp) > 0 else 0.0
            recall = matched / (matched + missed_count) if (matched + missed_count) > 0 else 0.0
            sev_acc = sev_correct / matched if matched > 0 else 0.0

            results.append(CategoryAccuracy(
                category=cat,
                total_ai_findings=matched + fp,
                total_human_findings=matched + missed_count,
                matched=matched,
                false_positives=fp,
                missed=missed_count,
                precision=precision,
                recall=recall,
                severity_accuracy=sev_acc,
            ))

        return sorted(results, key=lambda x: x.recall)

    # ------------------------------------------------------------------
    # Aggregate metrics
    # ------------------------------------------------------------------

    def _calculate_aggregate_metrics(self, result: ComparisonResult) -> None:
        """Calculate aggregate precision, recall, F1, and coverage."""
        matched = len(result.matched_pairs)
        fp = len(result.false_positives)
        missed = len(result.missed_findings)

        result.overall_precision = matched / (matched + fp) if (matched + fp) > 0 else 0.0
        result.overall_recall = matched / (matched + missed) if (matched + missed) > 0 else 0.0

        if result.overall_precision + result.overall_recall > 0:
            result.overall_f1 = (
                2 * result.overall_precision * result.overall_recall
                / (result.overall_precision + result.overall_recall)
            )
        else:
            result.overall_f1 = 0.0

        # Severity accuracy: % of matched pairs with correct severity
        if matched > 0:
            correct_sev = sum(1 for p in result.matched_pairs if p.severity_match)
            result.severity_accuracy = correct_sev / matched

        # Coverage: % of human findings that AI detected
        if result.total_human_findings > 0:
            result.coverage_percent = (matched / result.total_human_findings) * 100

    # ------------------------------------------------------------------
    # Normalization helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_severity(severity: str) -> str:
        """Normalize severity to standard levels."""
        sev = (severity or "").lower().strip()
        mapping = {
            "informational": "info",
            "information": "info",
            "minor": "low",
            "major": "high",
            "medium": "medium",
            "moderate": "medium",
        }
        return mapping.get(sev, sev) if sev in mapping else sev

    @staticmethod
    def _normalize_location(location: Any) -> str:
        """Normalize location to a comparable string."""
        if isinstance(location, dict):
            parts = [
                str(location.get("file", "")),
                str(location.get("function", "")),
                str(location.get("line_start", "")),
                str(location.get("contract", "")),
            ]
            return ":".join(p for p in parts if p and p != "None").lower()
        if isinstance(location, str):
            return location.lower().strip()
        return ""

    @staticmethod
    def _normalize_category(category: str) -> str:
        """Normalize category to a standard form."""
        cat = (category or "").lower().strip()
        # Common category name variations
        mappings = {
            "re-entrancy": "reentrancy",
            "reentrancy guard": "reentrancy",
            "access control": "access_control",
            "access-control": "access_control",
            "centralization": "centralization_risk",
            "front running": "front_running",
            "front-running": "front_running",
            "mev": "front_running",
            "dos": "denial_of_service",
            "denial of service": "denial_of_service",
            "unchecked return": "unchecked_returns",
            "unchecked returns": "unchecked_returns",
            "oracle manipulation": "oracle",
            "flash loan": "flash_loan",
            "token issue": "token_issues",
            "arithmetic": "arithmetic",
            "integer overflow": "arithmetic",
            "integer underflow": "arithmetic",
            "gas optimization": "gas",
            "proxy": "proxy_pattern",
            "governance": "governance",
        }
        return mappings.get(cat, cat)

    @staticmethod
    def _normalize_text(text: str) -> str:
        """Normalize text for comparison."""
        return (text or "").lower().strip()
