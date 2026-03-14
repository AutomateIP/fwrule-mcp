"""
Response schema for the analyze_firewall_rule_overlap MCP tool.

Optimized for AI agent consumption — compact, machine-readable, no prose.

The response hierarchy:
  AnalysisResponse
  ├── overlap_exists: bool
  ├── findings: list[Finding]
  │   ├── existing_rule_id / position
  │   ├── overlap_type: OverlapType
  │   ├── severity: Severity
  │   ├── candidate_action / existing_action
  │   └── dimensions: dict[str, str]   (dimension → relationship)
  └── metadata: AnalysisMetadata
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class OverlapType(str, Enum):
    """Classification of how the candidate rule interacts with an existing rule."""

    EXACT_DUPLICATE = "exact_duplicate"
    SHADOWED = "shadowed"
    SHADOWS_EXISTING = "shadows_existing"
    CONFLICT = "conflict"
    PARTIAL_OVERLAP = "partial_overlap"
    SUPERSET = "superset"
    SUBSET = "subset"
    NO_OVERLAP = "no_overlap"


class Severity(str, Enum):
    """Severity of the finding from an operational / risk standpoint."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


class Finding(BaseModel):
    """
    A single interaction finding between the candidate rule and one existing rule.

    Compact format: the AI agent can reason about overlap_type + severity +
    dimensions without needing verbose prose.
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
    dimensions: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Per-dimension relationship map. Keys are dimension names "
            "(source_zones, destination_zones, source_addresses, destination_addresses, "
            "services, applications). Values are set-theoretic relationships: "
            "'equal', 'subset', 'superset', 'intersecting', 'disjoint'."
        ),
    )
    candidate_action: Optional[str] = Field(
        default=None,
        description="Action of the candidate rule.",
    )
    existing_action: Optional[str] = Field(
        default=None,
        description="Action of the existing rule.",
    )
    is_implicit_rule: bool = Field(
        default=False,
        description=(
            "True when the existing rule is a vendor-synthesized implicit default "
            "(e.g., implicit deny-all at end of Cisco ACL). The rule does not "
            "appear in the configuration export."
        ),
    )

    model_config = {"extra": "forbid"}

    @property
    def is_critical_or_high(self) -> bool:
        return self.severity in (Severity.CRITICAL, Severity.HIGH)


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


class AnalysisMetadata(BaseModel):
    """Compact metadata about the analysis run."""

    vendor: str = Field(description="Vendor identifier that was analyzed.")
    existing_rule_count: int = Field(ge=0, description="Number of rules in the submitted existing policy.")
    enabled_rule_count: int = Field(ge=0, description="Number of enabled rules analyzed.")
    analysis_duration_ms: float = Field(ge=0.0, description="Wall-clock time in milliseconds.")

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# Top-level response
# ---------------------------------------------------------------------------


class AnalysisResponse(BaseModel):
    """
    The complete structured output of the firewall rule overlap analysis.

    Compact format optimized for AI agent consumption.
    """

    overlap_exists: bool = Field(
        description="True if any overlap was detected.",
    )
    findings: list[Finding] = Field(
        default_factory=list,
        description="Ordered list of findings, sorted by severity (CRITICAL first).",
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
