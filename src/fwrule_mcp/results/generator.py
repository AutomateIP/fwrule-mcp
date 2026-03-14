"""
Result assembly layer — converts raw AnalysisResult into a compact AnalysisResponse.

Pipeline inside generate():
  1. Convert each RuleRelationship → Finding (with severity + compact dimensions)
  2. Sort findings by severity (CRITICAL first), then by existing rule position
  3. Truncate to MAX_FINDINGS_PER_RESPONSE if needed
  4. Build AnalysisMetadata with timing and rule counts
  5. Return AnalysisResponse
"""

from __future__ import annotations

import logging
from typing import Optional

from fwrule_mcp.analysis.classifier import DimensionAnalysis, RuleRelationship
from fwrule_mcp.analysis.engine import AnalysisResult
from fwrule_mcp.models.common import Action
from fwrule_mcp.models.response import (
    AnalysisMetadata,
    AnalysisResponse,
    Finding,
    OverlapType,
    Severity,
)
from fwrule_mcp.utils.limits import MAX_FINDINGS_PER_RESPONSE

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Severity scoring table
# ---------------------------------------------------------------------------

_BASE_SEVERITY: dict[OverlapType, Severity] = {
    OverlapType.EXACT_DUPLICATE: Severity.HIGH,
    OverlapType.SHADOWED: Severity.CRITICAL,
    OverlapType.SHADOWS_EXISTING: Severity.HIGH,
    OverlapType.CONFLICT: Severity.CRITICAL,
    OverlapType.SUPERSET: Severity.MEDIUM,
    OverlapType.SUBSET: Severity.LOW,
    OverlapType.PARTIAL_OVERLAP: Severity.MEDIUM,
}

_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


# ---------------------------------------------------------------------------
# ResultGenerator
# ---------------------------------------------------------------------------


class ResultGenerator:
    """
    Assembles raw analysis findings into a compact AnalysisResponse.

    Stateless — safe to reuse across multiple generate() calls.
    """

    def generate(
        self,
        analysis_result: AnalysisResult,
        vendor: str,
        os_version: Optional[str],
        start_time_monotonic: float,
        end_time_monotonic: float,
        parser_id: Optional[str] = None,
    ) -> AnalysisResponse:
        duration_ms = (end_time_monotonic - start_time_monotonic) * 1000.0

        # --- Build Finding objects from overlapping relationships ---
        overlap_rels = analysis_result.overlap_relationships
        findings: list[Finding] = [
            self._relationship_to_finding(rel, analysis_result.candidate.action)
            for rel in overlap_rels
        ]

        # --- Sort: severity first (critical before low), then existing rule position ---
        findings.sort(key=lambda f: (
            _SEVERITY_ORDER.get(f.severity, 99),
            f.existing_rule_position,
        ))

        # --- Truncate if over the per-response limit ---
        if len(findings) > MAX_FINDINGS_PER_RESPONSE:
            logger.warning(
                "Truncating findings from %d to %d (limit=%d)",
                len(findings), MAX_FINDINGS_PER_RESPONSE, MAX_FINDINGS_PER_RESPONSE,
            )
            findings = findings[:MAX_FINDINGS_PER_RESPONSE]

        # --- Build metadata ---
        enabled_count = (
            analysis_result.existing_rule_count - analysis_result.disabled_rule_count
        )
        metadata = AnalysisMetadata(
            vendor=vendor,
            existing_rule_count=analysis_result.existing_rule_count,
            enabled_rule_count=enabled_count,
            analysis_duration_ms=round(duration_ms, 2),
        )

        return AnalysisResponse(
            overlap_exists=len(findings) > 0,
            findings=findings,
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Finding construction
    # ------------------------------------------------------------------

    def _relationship_to_finding(
        self,
        rel: RuleRelationship,
        candidate_action: Action,
    ) -> Finding:
        rule = rel.existing_rule
        action_conflict = not rel.action_same
        severity = self._assign_severity(rel.overlap_type, action_conflict)

        # Compact dimensions: {dimension_name: relationship}
        dimensions = {
            da.dimension_name: da.relationship
            for da in rel.dimension_analyses
        }

        return Finding(
            existing_rule_id=rule.rule_id,
            existing_rule_position=rule.position,
            overlap_type=rel.overlap_type,
            severity=severity,
            dimensions=dimensions,
            candidate_action=candidate_action.value,
            existing_action=rule.action.value,
            is_implicit_rule=getattr(rule, "is_implicit", False),
        )

    # ------------------------------------------------------------------
    # Severity assignment
    # ------------------------------------------------------------------

    def _assign_severity(
        self, overlap_type: OverlapType, action_conflict: bool
    ) -> Severity:
        base = _BASE_SEVERITY.get(overlap_type, Severity.INFO)

        # Downgrade PARTIAL_OVERLAP to LOW when there is no action conflict
        if overlap_type == OverlapType.PARTIAL_OVERLAP and not action_conflict:
            return Severity.LOW

        # Escalate SHADOWS_EXISTING to CRITICAL when actions differ
        if overlap_type == OverlapType.SHADOWS_EXISTING and action_conflict:
            return Severity.CRITICAL

        return base
