"""
Normalized rule model — vendor-agnostic, fully resolved, order-preserving.

After passing through the normalization layer, every rule is expressed as a
NormalizedRule.  The candidate rule is wrapped in NormalizedCandidate (same
structure, different type to make function signatures explicit).

Design principles (from Architecture §4.1):
- Vendor-agnostic: no vendor field names survive beyond the ``metadata`` block.
- Fully resolved: all object references have been expanded to concrete values.
- Order-preserving: ``position`` carries the 1-based index in the policy.
- Dimension-complete: every match dimension relevant to overlap analysis is present.
- Extensible: new dimensions can be added to MatchSpec without breaking the engine.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field

from fwrule_mcp.models.common import (
    Action,
    AddressSet,
    ApplicationSet,
    ServiceSet,
    ZoneSet,
)


class RuleMetadata(BaseModel):
    """
    Vendor-specific traceability data preserved alongside the normalized rule.
    Nothing in this structure influences overlap analysis logic.
    """

    original_name: Optional[str] = Field(
        default=None,
        description="The rule name as it appears in the vendor configuration.",
    )
    description: Optional[str] = Field(
        default=None,
        description="Optional human-readable description from the vendor config.",
    )
    vendor_tags: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Arbitrary key-value pairs from the vendor config preserved for "
            "traceability (e.g., hit counts, tags, zones before mapping, "
            "application-default flags).  Not used by analysis logic."
        ),
    )
    parsed_from: Optional[str] = Field(
        default=None,
        description="Identifier of the parser module that produced this rule.",
    )
    unresolvable_references: list[str] = Field(
        default_factory=list,
        description=(
            "Names of any address/service/zone objects that could not be "
            "resolved.  Dimensions containing unresolvable references are "
            "marked conservatively (treated as UNKNOWN) by the analysis engine."
        ),
    )

    model_config = {"extra": "allow"}


class MatchSpec(BaseModel):
    """
    The complete set of match criteria for a single firewall rule, normalized
    into vendor-agnostic set structures.

    All dimensions are required.  If a vendor's rule does not specify a
    dimension (e.g., no zone information), it defaults to the ``any`` sentinel
    for that dimension.

    Dimensions:
    - source_zones / destination_zones: security zone identifiers
    - source_addresses / destination_addresses: IP address/prefix sets
    - services: protocol + port set
    - applications: application-layer identifiers (optional, opaque strings)
    """

    model_config = {"arbitrary_types_allowed": True}

    source_zones: ZoneSet = Field(
        default_factory=ZoneSet.any,
        description="Source security zones. ZoneSet.any() if zone info is unavailable.",
    )
    destination_zones: ZoneSet = Field(
        default_factory=ZoneSet.any,
        description="Destination security zones.",
    )
    source_addresses: AddressSet = Field(
        default_factory=AddressSet.any,
        description="Source IP addresses. AddressSet.any() for unrestricted source.",
    )
    destination_addresses: AddressSet = Field(
        default_factory=AddressSet.any,
        description="Destination IP addresses.",
    )
    services: ServiceSet = Field(
        default_factory=ServiceSet.any,
        description="Protocol and port match criteria.",
    )
    applications: ApplicationSet = Field(
        default_factory=ApplicationSet.any,
        description=(
            "Application-layer identifiers (App-ID, NBAR, etc.). "
            "Defaults to any — the analysis engine skips app checks when both "
            "sides are is_any=True."
        ),
    )

    def intersects(self, other: "MatchSpec") -> bool:
        """
        Return True if there exists at least one packet that would match BOTH
        this MatchSpec and ``other`` simultaneously.

        Uses a fail-fast strategy: evaluates the cheapest dimensions first
        (zones, applications) and short-circuits on the first empty intersection.
        """
        # Zone check first — set intersection on strings, very fast
        if not self.source_zones.intersects(other.source_zones):
            return False
        if not self.destination_zones.intersects(other.destination_zones):
            return False
        # Application check — also string-based
        if not self.applications.intersects(other.applications):
            return False
        # Service check — protocol + port ranges
        if not self.services.intersects(other.services):
            return False
        # Address checks — most expensive, done last
        if not self.source_addresses.intersects(other.source_addresses):
            return False
        if not self.destination_addresses.intersects(other.destination_addresses):
            return False
        return True

    def is_subset_of(self, other: "MatchSpec") -> bool:
        """
        Return True if every packet matching self would also match other.

        Formally: self.match_set ⊆ other.match_set across all dimensions.
        This is the superset check used for shadow detection.
        """
        return (
            self.source_zones.is_subset_of(other.source_zones)
            and self.destination_zones.is_subset_of(other.destination_zones)
            and self.source_addresses.is_subset_of(other.source_addresses)
            and self.destination_addresses.is_subset_of(other.destination_addresses)
            and self.services.is_subset_of(other.services)
            and self.applications.is_subset_of(other.applications)
        )

    def is_superset_of(self, other: "MatchSpec") -> bool:
        """Return True if self.match_set ⊇ other.match_set."""
        return other.is_subset_of(self)

    def equals(self, other: "MatchSpec") -> bool:
        """
        Return True if the two MatchSpec objects represent exactly the same
        traffic set.  Used for exact duplicate detection.
        """
        return self.is_subset_of(other) and other.is_subset_of(self)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MatchSpec):
            return NotImplemented
        return self.equals(other)


class NormalizedRule(BaseModel):
    """
    A single firewall rule in fully normalized, vendor-agnostic form.

    Instances are created by the normalization layer and consumed by the analysis
    engine.  They are never created directly from user input.
    """

    model_config = {"arbitrary_types_allowed": True}

    rule_id: str = Field(
        description=(
            "Stable identifier for this rule.  Populated from the vendor rule "
            "name when available, or from the 1-based position index otherwise "
            "(e.g., 'rule_42')."
        )
    )
    position: int = Field(
        ge=1,
        description="1-based ordinal position of this rule in the policy.",
    )
    enabled: bool = Field(
        default=True,
        description=(
            "Whether this rule is active.  Disabled rules are retained in the "
            "normalized list so that position indices remain stable, but the "
            "analysis engine treats them as non-participating."
        ),
    )
    is_implicit: bool = Field(
        default=False,
        description=(
            "True if this rule was synthesized by the normalization layer to "
            "represent a vendor-specific implicit default (e.g., implicit "
            "deny-all at end of a Cisco ACL). Implicit rules are not present "
            "in the original configuration text."
        ),
    )
    match: MatchSpec = Field(
        description="The complete, resolved match criteria for this rule.",
    )
    action: Action = Field(
        description="The canonical action this rule takes when matched.",
    )
    metadata: RuleMetadata = Field(
        default_factory=RuleMetadata,
        description="Traceability data from the original vendor configuration.",
    )

    def is_blocking(self) -> bool:
        """Return True if this rule drops or rejects traffic (any deny variant)."""
        from fwrule_mcp.models.common import BLOCKING_ACTIONS
        return self.action in BLOCKING_ACTIONS

    def is_permitting(self) -> bool:
        return self.action == Action.PERMIT

    def __repr__(self) -> str:
        return (
            f"NormalizedRule(id={self.rule_id!r}, pos={self.position}, "
            f"action={self.action.value}, enabled={self.enabled})"
        )


class NormalizedCandidate(BaseModel):
    """
    The candidate rule being evaluated for overlap against an existing policy.

    Structurally identical to NormalizedRule.  The distinct type makes function
    signatures self-documenting and prevents accidentally passing an existing
    rule as the candidate.

    ``intended_position`` indicates where the operator intends to insert the
    rule (1-based).  If None, the analysis assumes insertion at the end of the
    policy (i.e., no existing rule can shadow by position alone).
    """

    model_config = {"arbitrary_types_allowed": True}

    rule_id: str = Field(default="candidate")
    intended_position: Optional[int] = Field(
        default=None,
        ge=1,
        description=(
            "1-based position at which the candidate would be inserted. "
            "Governs which existing rules are above it (can shadow it) vs. "
            "below it (would be shadowed by it)."
        ),
    )
    enabled: bool = Field(default=True)
    match: MatchSpec = Field(
        description="The complete, resolved match criteria for the candidate rule.",
    )
    action: Action = Field(
        description="The canonical action the candidate rule would take.",
    )
    metadata: RuleMetadata = Field(default_factory=RuleMetadata)

    def is_blocking(self) -> bool:
        from fwrule_mcp.models.common import BLOCKING_ACTIONS
        return self.action in BLOCKING_ACTIONS

    def is_permitting(self) -> bool:
        return self.action == Action.PERMIT

    def as_normalized_rule(self, position: Optional[int] = None) -> NormalizedRule:
        """
        Return a NormalizedRule view of this candidate for use in symmetric
        comparisons.  ``position`` defaults to ``intended_position`` if set.
        """
        pos = position or self.intended_position or 0
        return NormalizedRule(
            rule_id=self.rule_id,
            position=pos,
            enabled=self.enabled,
            match=self.match,
            action=self.action,
            metadata=self.metadata,
        )

    def __repr__(self) -> str:
        return (
            f"NormalizedCandidate(id={self.rule_id!r}, "
            f"intended_pos={self.intended_position}, "
            f"action={self.action.value})"
        )
