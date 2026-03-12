"""
Response schema for the analyze_firewall_rule_overlap MCP tool.

AnalysisResponse is the top-level output returned to the MCP client.
All types are Pydantic v2 models designed for JSON serialization.

The response hierarchy:
  AnalysisResponse
  ├── overlap_exists: bool
  ├── findings: list[Finding]
  │   ├── existing_rule_id / position
  │   ├── overlap_type: OverlapType
  │   ├── severity: Severity
  │   ├── dimensions: list[DimensionDetail]
  │   ├── explanation: str
  │   └── remediation: str | None
  ├── analysis_summary: str
  └── metadata: AnalysisMetadata
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class OverlapType(str, Enum):
    """
    Classification of how the candidate rule interacts with an existing rule.

    Values are ordered from most-severe to informational to assist with
    result sorting.
    """

    EXACT_DUPLICATE = "exact_duplicate"
    """Candidate match set is set-theoretically equal to the existing rule across
    all dimensions AND the actions are the same."""

    SHADOWED = "shadowed"
    """The existing rule (above the candidate's position) is a superset of the
    candidate across all dimensions.  The candidate would never be reached for
    any traffic it intends to match."""

    SHADOWS_EXISTING = "shadows_existing"
    """The candidate (above the existing rule's position) is a superset of the
    existing rule.  If inserted, the candidate would make the existing rule
    unreachable for all its traffic."""

    CONFLICT = "conflict"
    """The candidate and an existing rule have overlapping match criteria but
    opposing actions (PERMIT vs. DENY/DROP/REJECT).  Traffic in the intersection
    would be affected differently depending on rule ordering."""

    PARTIAL_OVERLAP = "partial_overlap"
    """Candidate and existing rule share a non-empty intersection across all
    dimensions, but neither is a full superset/subset of the other."""

    SUPERSET = "superset"
    """The candidate's match set is a strict superset of the existing rule's —
    the candidate would match all traffic the existing rule matches, plus more."""

    SUBSET = "subset"
    """The candidate's match set is a strict subset of the existing rule's —
    the existing rule already handles all traffic the candidate would handle."""

    NO_OVERLAP = "no_overlap"
    """No intersection exists between the candidate and this existing rule.
    This type is not normally emitted in findings (rules with no overlap are
    simply not included) but may appear in exhaustive analysis modes."""


class Severity(str, Enum):
    """
    Severity of the finding from an operational / risk standpoint.

    The scoring logic in the result generator assigns severity based on
    the combination of OverlapType, action conflict, and rule ordering.
    """

    CRITICAL = "critical"
    """Immediate policy impact: shadow/conflict that changes effective traffic
    handling for a broad address set, or an exact duplicate adding config bloat."""

    HIGH = "high"
    """Significant overlap with policy effect: shadows traffic or conflicts
    with an existing rule for a meaningful portion of the candidate's scope."""

    MEDIUM = "medium"
    """Partial overlap with notable policy effect: partial intersection exists
    and at least one of the rules is a permit, creating potential unintended
    allow or block windows."""

    LOW = "low"
    """Minor overlap: small intersection, both rules have same action, or the
    intersection is for a low-risk protocol/address class."""

    INFO = "info"
    """Informational: overlap noted for awareness but poses no operational risk
    (e.g., identical action, small subset of low-risk traffic)."""


# ---------------------------------------------------------------------------
# Detail structures
# ---------------------------------------------------------------------------


class DimensionDetail(BaseModel):
    """
    Describes the relationship between the candidate and an existing rule on
    one specific match dimension.

    Produced for every dimension that contributes to an overlap finding.  The
    ``description`` field provides human-readable specifics (e.g., the
    overlapping IP prefixes or port ranges).
    """

    dimension: str = Field(
        description=(
            "Which dimension this detail describes. "
            "One of: 'source_zone', 'destination_zone', 'source_address', "
            "'destination_address', 'service', 'application'."
        )
    )
    relationship: str = Field(
        description=(
            "Set-theoretic relationship between candidate and existing rule "
            "on this dimension. "
            "One of: 'equal', 'subset', 'superset', 'intersecting', 'disjoint'."
        )
    )
    candidate_value: Optional[str] = Field(
        default=None,
        description="Human-readable summary of the candidate's value for this dimension.",
    )
    existing_value: Optional[str] = Field(
        default=None,
        description="Human-readable summary of the existing rule's value for this dimension.",
    )
    intersection_value: Optional[str] = Field(
        default=None,
        description=(
            "Human-readable description of the intersection (populated when "
            "relationship is 'intersecting', 'subset', or 'superset')."
        ),
    )
    description: str = Field(
        description=(
            "Natural-language explanation of the dimensional relationship, "
            "e.g., 'Candidate source 10.0.1.0/24 is fully contained within "
            "existing source 10.0.0.0/22'."
        )
    )

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


class Finding(BaseModel):
    """
    A single interaction finding between the candidate rule and one existing rule.

    The analysis engine produces one Finding per (candidate, existing_rule) pair
    that has any non-disjoint relationship.  The result generator then enriches
    findings with explanations and remediation suggestions.
    """

    existing_rule_id: str = Field(
        description="The rule_id of the existing rule that interacts with the candidate.",
    )
    existing_rule_position: int = Field(
        ge=1,
        description="1-based position of the existing rule in the policy.",
    )
    overlap_type: OverlapType = Field(
        description="Classification of the overlap relationship.",
    )
    severity: Severity = Field(
        description="Operational severity of this finding.",
    )
    dimensions: list[DimensionDetail] = Field(
        default_factory=list,
        description=(
            "Per-dimension breakdown of how the candidate and existing rule "
            "relate on each match criterion."
        ),
    )
    explanation: str = Field(
        description=(
            "Natural-language explanation of the finding — what the overlap means "
            "in operational terms and what traffic is affected."
        ),
    )
    remediation: Optional[str] = Field(
        default=None,
        description=(
            "Optional remediation suggestion.  Populated when the analysis "
            "engine can determine a concrete corrective action (e.g., 'Remove "
            "this rule — it is fully shadowed by rule 12 and would never match "
            "any traffic')."
        ),
    )
    candidate_action: Optional[str] = Field(
        default=None,
        description="Action of the candidate rule (for conflict context).",
    )
    existing_action: Optional[str] = Field(
        default=None,
        description="Action of the existing rule (for conflict context).",
    )

    model_config = {"extra": "forbid"}

    @property
    def is_critical_or_high(self) -> bool:
        return self.severity in (Severity.CRITICAL, Severity.HIGH)


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


class AnalysisMetadata(BaseModel):
    """
    Metadata about the analysis run.  Included in every response for
    auditability and debugging.  Never contains configuration payload content.
    """

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the analysis completed.",
    )
    vendor: str = Field(
        description="Vendor identifier that was analyzed.",
    )
    os_version: Optional[str] = Field(
        default=None,
        description="OS version string from the request, if provided.",
    )
    existing_rule_count: int = Field(
        ge=0,
        description="Number of rules in the submitted existing policy.",
    )
    enabled_rule_count: int = Field(
        ge=0,
        description="Number of enabled rules (disabled rules do not participate in analysis).",
    )
    analysis_duration_ms: float = Field(
        ge=0.0,
        description="Wall-clock time in milliseconds for the complete analysis pipeline.",
    )
    parser_id: Optional[str] = Field(
        default=None,
        description="Identifier of the parser module selected for this vendor/version.",
    )
    unresolvable_reference_count: int = Field(
        default=0,
        ge=0,
        description=(
            "Number of object references in the policy that could not be resolved. "
            "Non-zero values indicate incomplete context objects were supplied."
        ),
    )

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# Top-level response
# ---------------------------------------------------------------------------


class AnalysisResponse(BaseModel):
    """
    The complete structured output of the firewall rule overlap analysis.

    ``overlap_exists`` provides a quick boolean answer.  ``findings`` provides
    the detailed per-rule breakdown.  ``analysis_summary`` provides a human-
    readable overview.  ``metadata`` provides audit trail information.
    """

    overlap_exists: bool = Field(
        description=(
            "True if any overlap, conflict, or shadow relationship was detected "
            "between the candidate rule and the existing policy."
        ),
    )
    findings: list[Finding] = Field(
        default_factory=list,
        description=(
            "Ordered list of findings.  Each finding describes the relationship "
            "between the candidate and one existing rule.  Empty when no overlaps "
            "were detected.  Sorted by severity (CRITICAL first) then by "
            "existing rule position."
        ),
    )
    analysis_summary: str = Field(
        description=(
            "Natural-language summary of the overall analysis result.  Suitable "
            "for direct display to operators.  Example: 'Candidate rule would be "
            "fully shadowed by rule 5 (permit any any). The candidate would never "
            "match any traffic.'"
        ),
    )
    metadata: AnalysisMetadata = Field(
        description="Analysis run metadata.",
    )

    model_config = {"extra": "forbid"}

    def critical_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.CRITICAL]

    def high_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.HIGH]

    def findings_by_type(self, overlap_type: OverlapType) -> list[Finding]:
        return [f for f in self.findings if f.overlap_type == overlap_type]

    def has_shadows(self) -> bool:
        return any(
            f.overlap_type in (OverlapType.SHADOWED, OverlapType.SHADOWS_EXISTING)
            for f in self.findings
        )

    def has_conflicts(self) -> bool:
        return any(f.overlap_type == OverlapType.CONFLICT for f in self.findings)

    def has_exact_duplicates(self) -> bool:
        return any(f.overlap_type == OverlapType.EXACT_DUPLICATE for f in self.findings)
