"""
Result assembly layer — converts raw AnalysisResult into a structured AnalysisResponse.

This module is the bridge between the analysis engine (which produces RuleRelationship
objects) and the MCP tool response (which requires Finding objects with human-readable
explanations, severity scores, and remediation guidance).

Pipeline inside generate():
  1. Convert each RuleRelationship → Finding (with severity, explanation, remediation)
  2. Sort findings by severity (CRITICAL first), then by existing rule position
  3. Truncate to MAX_FINDINGS_PER_RESPONSE if needed
  4. Generate analysis_summary
  5. Build AnalysisMetadata with timing and rule counts
  6. Return AnalysisResponse
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from fwrule_mcp.analysis.classifier import DimensionAnalysis, RuleRelationship
from fwrule_mcp.analysis.engine import AnalysisResult
from fwrule_mcp.models.common import Action, BLOCKING_ACTIONS
from fwrule_mcp.models.response import (
    AnalysisMetadata,
    AnalysisResponse,
    DimensionDetail,
    Finding,
    OverlapType,
    Severity,
)
from fwrule_mcp.results.explanations import generate_explanation
from fwrule_mcp.results.remediation import suggest_remediation
from fwrule_mcp.utils.limits import MAX_FINDINGS_PER_RESPONSE

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Severity scoring table
# ---------------------------------------------------------------------------

# Base severity by overlap type
_BASE_SEVERITY: dict[OverlapType, Severity] = {
    OverlapType.EXACT_DUPLICATE: Severity.HIGH,
    OverlapType.SHADOWED: Severity.CRITICAL,
    OverlapType.SHADOWS_EXISTING: Severity.HIGH,
    OverlapType.CONFLICT: Severity.CRITICAL,
    OverlapType.SUPERSET: Severity.MEDIUM,
    OverlapType.SUBSET: Severity.LOW,
    OverlapType.PARTIAL_OVERLAP: Severity.MEDIUM,
}

# Severity ordering for sorting (lower number = higher severity)
_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


# ---------------------------------------------------------------------------
# Action helpers
# ---------------------------------------------------------------------------


def _action_conflict(action_same: bool) -> bool:
    """Convert action_same flag to action_conflict for explanation/remediation."""
    return not action_same


def _candidate_action_value(rel: RuleRelationship) -> str:
    """Extract candidate action string from a RuleRelationship."""
    # The classifier stores candidate action indirectly via action_same + existing action.
    # We can recover it from the AnalysisResult.candidate, but it's also embedded
    # in finding_data by the generator. Here we use the existing rule + action_same
    # to reconstruct a plausible action label.
    # NOTE: The full action value is passed through finding_data, not the relationship.
    return "unknown"


# ---------------------------------------------------------------------------
# ResultGenerator
# ---------------------------------------------------------------------------


class ResultGenerator:
    """
    Assembles raw analysis findings into a structured AnalysisResponse.

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
        """
        Convert a raw AnalysisResult into a structured AnalysisResponse.

        Args:
            analysis_result:       The output of analysis.engine.analyze().
            vendor:                The vendor identifier from the request.
            os_version:            The OS version string from the request, if any.
            start_time_monotonic:  time.monotonic() at the start of the pipeline.
            end_time_monotonic:    time.monotonic() after analysis completed.
            parser_id:             Optional parser class name for metadata.

        Returns:
            A fully populated AnalysisResponse ready to be serialized and returned.
        """
        duration_ms = (end_time_monotonic - start_time_monotonic) * 1000.0

        candidate = analysis_result.candidate

        # --- Build Finding objects from overlapping relationships ---
        overlap_rels = analysis_result.overlap_relationships
        findings: list[Finding] = [
            self._relationship_to_finding(rel, candidate.action)
            for rel in overlap_rels
        ]

        # --- Sort: severity first (critical before low), then existing rule position ---
        findings.sort(key=lambda f: (
            _SEVERITY_ORDER.get(f.severity, 99),
            f.existing_rule_position,
        ))

        # --- Truncate if over the per-response limit ---
        total_finding_count = len(findings)
        truncated = False
        if len(findings) > MAX_FINDINGS_PER_RESPONSE:
            logger.warning(
                "Truncating findings from %d to %d (limit=%d)",
                len(findings), MAX_FINDINGS_PER_RESPONSE, MAX_FINDINGS_PER_RESPONSE,
            )
            findings = findings[:MAX_FINDINGS_PER_RESPONSE]
            truncated = True

        # --- Count unresolvable references from candidate ---
        unresolvable_count = len(candidate.metadata.unresolvable_references)

        # --- Build metadata ---
        enabled_count = (
            analysis_result.existing_rule_count - analysis_result.disabled_rule_count
        )
        metadata = AnalysisMetadata(
            timestamp=datetime.now(timezone.utc),
            vendor=vendor,
            os_version=os_version,
            existing_rule_count=analysis_result.existing_rule_count,
            enabled_rule_count=enabled_count,
            analysis_duration_ms=round(duration_ms, 2),
            parser_id=parser_id,
            unresolvable_reference_count=unresolvable_count,
        )

        # --- Generate summary ---
        summary = self._generate_summary(
            findings=findings,
            rule_count=analysis_result.existing_rule_count,
            truncated=truncated,
            total_finding_count=total_finding_count,
            skipped_count=analysis_result.skipped_count,
            warnings=analysis_result.warnings,
        )

        return AnalysisResponse(
            overlap_exists=len(findings) > 0,
            findings=findings,
            analysis_summary=summary,
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
        """
        Convert a RuleRelationship into a Finding with severity, explanation,
        and remediation populated.

        Args:
            rel:              The RuleRelationship from the analysis engine.
            candidate_action: The Action of the candidate rule (from AnalysisResult.candidate).
        """
        rule = rel.existing_rule
        action_conflict = not rel.action_same

        severity = self._assign_severity(rel.overlap_type, action_conflict)

        finding_data = {
            "existing_rule_id": rule.rule_id,
            "existing_rule_pos": rule.position,
            "candidate_action": candidate_action.value,
            "existing_action": rule.action.value,
            "dimensions": self._dimension_analyses_to_legacy(rel.dimension_analyses),
        }

        explanation = generate_explanation(rel.overlap_type, finding_data)
        remediation = suggest_remediation(rel.overlap_type, finding_data)
        dimensions = self._build_dimension_details(rel.dimension_analyses)

        return Finding(
            existing_rule_id=rule.rule_id,
            existing_rule_position=rule.position,
            overlap_type=rel.overlap_type,
            severity=severity,
            dimensions=dimensions,
            explanation=explanation,
            remediation=remediation,
            candidate_action=candidate_action.value,
            existing_action=rule.action.value,
        )

    def _dimension_analyses_to_legacy(
        self, dimension_analyses: list[DimensionAnalysis]
    ) -> list:
        """
        Convert DimensionAnalysis objects to the dict-like structure expected
        by explanations.py and remediation.py (which were written to consume
        a list of objects with .dimension, .candidate_value, .existing_value,
        .intersection_description attributes).

        We return a list of simple namespace objects that satisfy the attribute
        access pattern used in the template functions.
        """

        class _DA:
            """Lightweight shim — adapts DimensionAnalysis to the legacy attribute names."""
            __slots__ = (
                "dimension", "relationship", "candidate_value",
                "existing_value", "intersection_description",
            )

            def __init__(self, da: DimensionAnalysis) -> None:
                self.dimension = da.dimension_name
                self.relationship = da.relationship
                # DimensionAnalysis does not carry candidate_value / existing_value
                # (those live in the description string). Provide empty strings so
                # the explanation templates don't crash.
                self.candidate_value = ""
                self.existing_value = ""
                self.intersection_description = da.description

        return [_DA(da) for da in dimension_analyses]

    def _build_dimension_details(
        self, dimension_analyses: list[DimensionAnalysis]
    ) -> list[DimensionDetail]:
        """
        Convert DimensionAnalysis objects from the classifier into DimensionDetail
        objects for the response schema.
        """
        details: list[DimensionDetail] = []
        for da in dimension_analyses:
            details.append(DimensionDetail(
                dimension=da.dimension_name,
                relationship=da.relationship,
                # DimensionAnalysis carries the full info in da.description
                candidate_value=None,
                existing_value=None,
                intersection_value=(
                    da.description
                    if da.relationship in ("intersecting", "subset", "superset", "equal")
                    else None
                ),
                description=da.description,
            ))
        return details

    # ------------------------------------------------------------------
    # Severity assignment
    # ------------------------------------------------------------------

    def _assign_severity(
        self, overlap_type: OverlapType, action_conflict: bool
    ) -> Severity:
        """
        Assign severity based on overlap type and whether actions conflict.

        Severity table:
          EXACT_DUPLICATE                       → HIGH
          SHADOWED                              → CRITICAL (rule will never fire)
          SHADOWS_EXISTING + action conflict    → CRITICAL (overrides existing behavior)
          SHADOWS_EXISTING (same action)        → HIGH
          CONFLICT                              → CRITICAL
          SUPERSET                              → MEDIUM
          SUBSET                                → LOW
          PARTIAL_OVERLAP + action conflict     → MEDIUM
          PARTIAL_OVERLAP (same action)         → LOW
        """
        base = _BASE_SEVERITY.get(overlap_type, Severity.INFO)

        # Downgrade PARTIAL_OVERLAP to LOW when there is no action conflict
        if overlap_type == OverlapType.PARTIAL_OVERLAP and not action_conflict:
            return Severity.LOW

        # Escalate SHADOWS_EXISTING to CRITICAL when actions differ
        if overlap_type == OverlapType.SHADOWS_EXISTING and action_conflict:
            return Severity.CRITICAL

        return base

    # ------------------------------------------------------------------
    # Summary generation
    # ------------------------------------------------------------------

    def _generate_summary(
        self,
        findings: list[Finding],
        rule_count: int,
        truncated: bool = False,
        total_finding_count: int = 0,
        skipped_count: int = 0,
        warnings: Optional[list[str]] = None,
    ) -> str:
        """
        Generate a human-readable analysis summary paragraph.

        The summary covers:
          - Whether any overlap was found
          - Count and severity distribution of findings
          - Most severe finding (highlighted first)
          - Notable shadow / conflict findings
          - Truncation and skip warnings if applicable
        """
        warnings = warnings or []

        if not findings:
            base = (
                f"No overlaps detected. The candidate rule does not conflict with, "
                f"duplicate, or shadow any of the {rule_count} rules analyzed in the "
                f"existing policy."
            )
            if skipped_count:
                base += (
                    f" Note: {skipped_count} rule(s) were not analyzed due to "
                    f"per-request limits — results may be incomplete."
                )
            if warnings:
                base += " Warnings: " + "; ".join(warnings[:3])
                if len(warnings) > 3:
                    base += f" (and {len(warnings) - 3} more)"
            return base

        # Severity distribution
        sev_counts: dict[Severity, int] = {}
        for f in findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

        dist_parts: list[str] = []
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
            count = sev_counts.get(sev, 0)
            if count:
                dist_parts.append(f"{count} {sev.value}")
        dist_str = ", ".join(dist_parts)

        # Lead sentence with top finding
        top = findings[0]  # Already sorted by severity
        top_type = top.overlap_type.value.replace("_", " ")
        lead = (
            f"Found {total_finding_count or len(findings)} overlap finding(s) across "
            f"{rule_count} analyzed rules ({dist_str}). "
            f"Most severe: {top_type} with existing rule '{top.existing_rule_id}' "
            f"at position {top.existing_rule_position} [{top.severity.value.upper()}]."
        )

        # Highlight shadow findings
        shadow_findings = [f for f in findings if f.overlap_type == OverlapType.SHADOWED]
        if shadow_findings:
            shadowed_by = shadow_findings[0].existing_rule_id
            lead += (
                f" The candidate would be completely shadowed by rule '{shadowed_by}' "
                f"and would never match any traffic."
            )

        # Highlight conflicts
        conflict_findings = [f for f in findings if f.overlap_type == OverlapType.CONFLICT]
        if conflict_findings:
            conflict_rule = conflict_findings[0].existing_rule_id
            lead += (
                f" A direct action conflict exists with rule '{conflict_rule}' — "
                f"review rule ordering to ensure the intended behavior is achieved."
            )

        # Exact duplicate note
        dup_findings = [f for f in findings if f.overlap_type == OverlapType.EXACT_DUPLICATE]
        if dup_findings:
            dup_rule = dup_findings[0].existing_rule_id
            lead += (
                f" The candidate is an exact duplicate of rule '{dup_rule}' and "
                f"would have no policy effect if added."
            )

        # Truncation notice
        if truncated and total_finding_count > len(findings):
            lead += (
                f" Note: results truncated to {len(findings)} findings "
                f"(total detected: {total_finding_count})."
            )

        if skipped_count:
            lead += (
                f" Note: {skipped_count} rule(s) were skipped due to analysis limits — "
                f"results may be incomplete."
            )

        if warnings:
            lead += " Parse warnings: " + "; ".join(warnings[:3])
            if len(warnings) > 3:
                lead += f" (and {len(warnings) - 3} more)"

        return lead
