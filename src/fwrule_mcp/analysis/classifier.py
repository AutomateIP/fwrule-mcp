"""
Overlap type classifier for the analysis engine.

classify_overlap() takes a NormalizedCandidate and a NormalizedRule and returns
a RuleRelationship describing every match dimension and the final OverlapType.

Classification algorithm:
  1. Compare all six dimensions independently.
  2. If ANY dimension is disjoint → NO_OVERLAP (fail-fast — skip remaining work).
  3. Determine the overall match relationship across all dimensions:
       all_equal     = every dimension is 'equal'
       all_subset    = every dimension is 'equal' or 'subset'   (candidate ⊆ existing)
       all_superset  = every dimension is 'equal' or 'superset' (candidate ⊇ existing)
  4. Action comparison:
       - DENY / DROP / REJECT are all considered "blocking" — treat as equivalent
         for the purpose of "same action" classification.
  5. OverlapType assignment:
       all_equal + same action class  → EXACT_DUPLICATE
       all_equal + diff action class  → CONFLICT
       all_subset + existing precedes → SHADOWED
       all_subset + candidate precedes→ SUBSET
       all_superset                   → SHADOWS_EXISTING / SUPERSET (by position)
       otherwise + diff action class  → CONFLICT (partial)
       otherwise + same action class  → PARTIAL_OVERLAP

Position semantics:
  - existing_rule.position is the 1-based index in the current policy.
  - candidate_position is where the candidate would be inserted.  None means
    "append at the end", i.e., every existing rule precedes the candidate.
  - "existing precedes candidate" = existing.position < effective_candidate_pos
  - Shadowing by position: an existing rule with LOWER position (evaluated first)
    that is a superset of the candidate shadows the candidate.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from fwrule_mcp.models.common import (
    ApplicationSet,
    BLOCKING_ACTIONS,
    Action,
)
from fwrule_mcp.models.normalized import NormalizedCandidate, NormalizedRule
from fwrule_mcp.models.response import OverlapType
from fwrule_mcp.analysis.address import compare_address_sets
from fwrule_mcp.analysis.service import compare_service_sets
from fwrule_mcp.analysis.zone import compare_zone_sets


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

# Sentinel representing an impossibly large position (append-at-end semantics)
_APPEND_POSITION = 10_000_000


@dataclass
class DimensionAnalysis:
    """Analysis of a single match dimension."""

    dimension_name: str
    """Machine identifier for the dimension (e.g., 'source_zones')."""

    relationship: str
    """Set-theoretic relationship: 'equal', 'subset', 'superset', 'intersecting', 'disjoint'."""

    description: str
    """Human-readable description of the dimensional relationship."""


@dataclass
class RuleRelationship:
    """Complete analysis of the relationship between candidate and one existing rule."""

    existing_rule: NormalizedRule
    """The existing rule this result describes."""

    overlap_type: OverlapType
    """Classification of the overall relationship."""

    dimension_analyses: list[DimensionAnalysis] = field(default_factory=list)
    """Per-dimension breakdown."""

    action_same: bool = False
    """True if candidate and existing rule have the same effective action class."""

    candidate_precedes: bool = False
    """True if the candidate would be evaluated before the existing rule."""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _actions_are_equivalent(a: Action, b: Action) -> bool:
    """Return True if two actions belong to the same effective class.

    DENY, DROP, and REJECT are all treated as "blocking" and are considered
    equivalent for overlap classification purposes.  PERMIT is its own class.
    """
    a_blocking = a in BLOCKING_ACTIONS
    b_blocking = b in BLOCKING_ACTIONS
    if a_blocking and b_blocking:
        return True
    if not a_blocking and not b_blocking:
        return True  # e.g., both PERMIT or both LOG_ONLY
    return False


def _compare_applications(
    candidate: ApplicationSet,
    existing: ApplicationSet,
) -> DimensionAnalysis:
    """Compare the application dimension and return a DimensionAnalysis."""
    # When both sides are is_any, skip the application dimension entirely
    # (it does not affect overlap classification).
    if candidate.is_any and existing.is_any:
        return DimensionAnalysis(
            dimension_name="applications",
            relationship="equal",
            description="applications: both are 'any' (application check skipped)",
        )

    if candidate.is_any:
        existing_apps = sorted(existing.applications)
        return DimensionAnalysis(
            dimension_name="applications",
            relationship="superset",
            description=(
                f"applications: candidate is 'any' (superset), "
                f"existing restricts to {{{', '.join(existing_apps)}}}"
            ),
        )

    if existing.is_any:
        cand_apps = sorted(candidate.applications)
        return DimensionAnalysis(
            dimension_name="applications",
            relationship="subset",
            description=(
                f"applications: candidate restricts to "
                f"{{{', '.join(cand_apps)}}}, existing is 'any'"
            ),
        )

    # Both specific
    cand_apps = sorted(candidate.applications)
    exist_apps = sorted(existing.applications)

    if not candidate.intersects(existing):
        return DimensionAnalysis(
            dimension_name="applications",
            relationship="disjoint",
            description=(
                f"applications: candidate {{{', '.join(cand_apps)}}} and "
                f"existing {{{', '.join(exist_apps)}}} share no common applications"
            ),
        )

    cand_sub = candidate.is_subset_of(existing)
    exist_sub = existing.is_subset_of(candidate)

    if cand_sub and exist_sub:
        return DimensionAnalysis(
            dimension_name="applications",
            relationship="equal",
            description=(
                f"applications: candidate {{{', '.join(cand_apps)}}} equals "
                f"existing {{{', '.join(exist_apps)}}}"
            ),
        )

    if cand_sub:
        return DimensionAnalysis(
            dimension_name="applications",
            relationship="subset",
            description=(
                f"applications: candidate {{{', '.join(cand_apps)}}} is a "
                f"subset of existing {{{', '.join(exist_apps)}}}"
            ),
        )

    if exist_sub:
        return DimensionAnalysis(
            dimension_name="applications",
            relationship="superset",
            description=(
                f"applications: candidate {{{', '.join(cand_apps)}}} is a "
                f"superset of existing {{{', '.join(exist_apps)}}}"
            ),
        )

    common = sorted(candidate.applications & existing.applications)
    return DimensionAnalysis(
        dimension_name="applications",
        relationship="intersecting",
        description=(
            f"applications: candidate {{{', '.join(cand_apps)}}} and "
            f"existing {{{', '.join(exist_apps)}}} share "
            f"{{{', '.join(common)}}}"
        ),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def classify_overlap(
    candidate: NormalizedCandidate,
    existing: NormalizedRule,
    candidate_position: int | None = None,
) -> RuleRelationship:
    """
    Classify the overlap relationship between a candidate rule and an existing rule.

    Parameters
    ----------
    candidate:
        The proposed new rule.
    existing:
        One rule from the existing policy.
    candidate_position:
        1-based position where the candidate would be inserted.  None means
        it would be appended at the end (i.e., all existing rules precede it).

    Returns
    -------
    RuleRelationship
        Contains the OverlapType, per-dimension analyses, action comparison,
        and position information.
    """
    # Resolve effective candidate position for ordering decisions.
    # If candidate_position is None, use append-at-end sentinel.
    eff_cand_pos = candidate_position if candidate_position is not None else _APPEND_POSITION
    candidate_precedes = eff_cand_pos < existing.position

    # ------------------------------------------------------------------
    # Phase 1: Compare all six dimensions
    # ------------------------------------------------------------------
    # Order: zones first (cheapest), applications, services, then addresses (costliest).

    src_zone_cmp = compare_zone_sets(
        candidate.match.source_zones,
        existing.match.source_zones,
        dimension_label="source zones",
    )
    dst_zone_cmp = compare_zone_sets(
        candidate.match.destination_zones,
        existing.match.destination_zones,
        dimension_label="destination zones",
    )
    app_cmp = _compare_applications(
        candidate.match.applications,
        existing.match.applications,
    )
    svc_cmp = compare_service_sets(
        candidate.match.services,
        existing.match.services,
    )
    src_addr_cmp = compare_address_sets(
        candidate.match.source_addresses,
        existing.match.source_addresses,
        dimension_label="source addresses",
    )
    dst_addr_cmp = compare_address_sets(
        candidate.match.destination_addresses,
        existing.match.destination_addresses,
        dimension_label="destination addresses",
    )

    # Build the ordered dimension analyses list
    dimension_analyses: list[DimensionAnalysis] = [
        DimensionAnalysis(
            dimension_name="source_zones",
            relationship=src_zone_cmp.relationship,
            description=src_zone_cmp.intersection_description,
        ),
        DimensionAnalysis(
            dimension_name="destination_zones",
            relationship=dst_zone_cmp.relationship,
            description=dst_zone_cmp.intersection_description,
        ),
        DimensionAnalysis(
            dimension_name="applications",
            relationship=app_cmp.relationship,
            description=app_cmp.description,
        ),
        DimensionAnalysis(
            dimension_name="services",
            relationship=svc_cmp.relationship,
            description=svc_cmp.intersection_description,
        ),
        DimensionAnalysis(
            dimension_name="source_addresses",
            relationship=src_addr_cmp.relationship,
            description=src_addr_cmp.intersection_description,
        ),
        DimensionAnalysis(
            dimension_name="destination_addresses",
            relationship=dst_addr_cmp.relationship,
            description=dst_addr_cmp.intersection_description,
        ),
    ]

    all_relationships = [da.relationship for da in dimension_analyses]

    # ------------------------------------------------------------------
    # Phase 2: Fail-fast on disjoint
    # ------------------------------------------------------------------
    if "disjoint" in all_relationships:
        return RuleRelationship(
            existing_rule=existing,
            overlap_type=OverlapType.NO_OVERLAP,
            dimension_analyses=dimension_analyses,
            action_same=_actions_are_equivalent(candidate.action, existing.action),
            candidate_precedes=candidate_precedes,
        )

    # ------------------------------------------------------------------
    # Phase 3: Determine aggregate match relationship
    # ------------------------------------------------------------------
    action_same = _actions_are_equivalent(candidate.action, existing.action)

    # Candidate is a subset of existing on this dimension if its relationship
    # is 'equal' or 'subset' (equal means both subset and superset).
    all_subset = all(r in ("equal", "subset") for r in all_relationships)
    all_superset = all(r in ("equal", "superset") for r in all_relationships)
    all_equal = all(r == "equal" for r in all_relationships)

    # ------------------------------------------------------------------
    # Phase 4: OverlapType assignment
    # ------------------------------------------------------------------

    # --- Exact duplicate / conflict on identical match set --------------
    if all_equal:
        overlap_type = OverlapType.EXACT_DUPLICATE if action_same else OverlapType.CONFLICT
        return RuleRelationship(
            existing_rule=existing,
            overlap_type=overlap_type,
            dimension_analyses=dimension_analyses,
            action_same=action_same,
            candidate_precedes=candidate_precedes,
        )

    # --- Candidate is fully inside existing match set -------------------
    if all_subset:
        if candidate_precedes:
            # Candidate fires first — it is the more-specific rule above a
            # broader existing rule.  The candidate is a SUBSET (it handles
            # a narrow slice of what the existing rule handles).
            overlap_type = OverlapType.SUBSET
        else:
            # Existing rule is above (evaluated first) and covers everything
            # the candidate covers → candidate is SHADOWED.
            overlap_type = OverlapType.SHADOWED
        return RuleRelationship(
            existing_rule=existing,
            overlap_type=overlap_type,
            dimension_analyses=dimension_analyses,
            action_same=action_same,
            candidate_precedes=candidate_precedes,
        )

    # --- Candidate fully covers existing match set ----------------------
    if all_superset:
        if candidate_precedes:
            # Candidate is above (evaluated first) and is broader — it would
            # swallow all traffic that the existing rule handles.
            overlap_type = OverlapType.SHADOWS_EXISTING
        else:
            # Candidate is below — it is a superset but the existing rule
            # fires first for its own traffic.  Still note it as SUPERSET.
            overlap_type = OverlapType.SUPERSET
        return RuleRelationship(
            existing_rule=existing,
            overlap_type=overlap_type,
            dimension_analyses=dimension_analyses,
            action_same=action_same,
            candidate_precedes=candidate_precedes,
        )

    # --- Partial intersection -------------------------------------------
    # At least one dimension is 'intersecting' (or a mix of subset/superset
    # across different dimensions).
    if not action_same:
        # Opposing actions with partial overlap create a CONFLICT: depending
        # on position, some traffic gets permitted where it should be denied
        # (or vice versa).
        overlap_type = OverlapType.CONFLICT
    else:
        overlap_type = OverlapType.PARTIAL_OVERLAP

    return RuleRelationship(
        existing_rule=existing,
        overlap_type=overlap_type,
        dimension_analyses=dimension_analyses,
        action_same=action_same,
        candidate_precedes=candidate_precedes,
    )
