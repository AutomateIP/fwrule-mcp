"""
Natural-language explanation templates for each overlap type.

Each function accepts a ``finding_data`` dict produced by ResultGenerator._build_finding_data()
and returns a fully-rendered explanation string.  The dict keys are documented
at the top of this module.

Finding data keys
-----------------
existing_rule_id   : str    — rule_id of the existing rule
existing_rule_pos  : int    — 1-based position of the existing rule
candidate_action   : str    — candidate rule action string
existing_action    : str    — existing rule action string
dimensions         : list   — list of DimensionComparison objects
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fwrule_mcp.models.response import OverlapType

if TYPE_CHECKING:
    from fwrule_mcp.analysis.engine import DimensionComparison


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dim_summary(dimensions: list["DimensionComparison"]) -> str:
    """
    Produce a bullet-list dimension breakdown suitable for embedding in an explanation.

    Only dimensions with non-equal, non-any relationships are included to
    keep explanations focused on the contributing factors.
    """
    lines: list[str] = []
    for dim in dimensions:
        # Skip dimensions that are trivially 'any' on both sides (not interesting)
        if dim.candidate_value == "any" and dim.existing_value == "any":
            continue
        lines.append(f"  - {dim.intersection_description}")
    if not lines:
        return "  - All dimensions match (both rules cover identical traffic space)"
    return "\n".join(lines)


def _action_phrase(action: str) -> str:
    """Return a human-readable verb phrase for an action string."""
    action_lower = action.lower()
    if action_lower == "permit":
        return "permits (allows)"
    if action_lower in ("deny", "drop", "reject"):
        return f"blocks ({action_lower}s)"
    return f"performs action '{action}' on"


# ---------------------------------------------------------------------------
# Explanation functions — one per OverlapType
# ---------------------------------------------------------------------------


def explain_duplicate(finding_data: dict) -> str:
    """
    EXACT_DUPLICATE: Candidate is set-theoretically identical to an existing rule
    with the same action.  It is redundant — adding it would have no policy effect.
    """
    rule_id = finding_data["existing_rule_id"]
    pos = finding_data["existing_rule_pos"]
    action = finding_data["existing_action"]

    dims = finding_data.get("dimensions", [])
    dim_block = _dim_summary(dims)

    return (
        f"The candidate rule is an exact duplicate of existing rule '{rule_id}' "
        f"at position {pos}. Both rules match identical traffic across all "
        f"dimensions and perform the same action ({action}). Adding this rule "
        f"would have no policy effect — it would be evaluated only if rule "
        f"'{rule_id}' were removed.\n"
        f"Dimension breakdown:\n{dim_block}"
    )


def explain_shadowed(finding_data: dict) -> str:
    """
    SHADOWED: An existing rule above the candidate's position matches a superset
    of the candidate's traffic.  The candidate would never be reached.
    """
    rule_id = finding_data["existing_rule_id"]
    pos = finding_data["existing_rule_pos"]
    existing_action = finding_data["existing_action"]
    candidate_action = finding_data["candidate_action"]

    dims = finding_data.get("dimensions", [])
    dim_block = _dim_summary(dims)

    conflict_note = ""
    if existing_action != candidate_action:
        conflict_note = (
            f" Note: the actions differ (candidate {_action_phrase(candidate_action)}, "
            f"existing {_action_phrase(existing_action)}), meaning the shadowing also "
            f"changes the effective policy."
        )

    return (
        f"The candidate rule would be completely shadowed by existing rule '{rule_id}' "
        f"at position {pos}, which appears earlier in the policy. All traffic that the "
        f"candidate would match is already handled by rule '{rule_id}', so the candidate "
        f"rule would never be evaluated.{conflict_note}\n"
        f"Dimension breakdown:\n{dim_block}"
    )


def explain_shadows_existing(finding_data: dict) -> str:
    """
    SHADOWS_EXISTING: The candidate (positioned above an existing rule) would
    match a superset of that existing rule's traffic, rendering it unreachable.
    """
    rule_id = finding_data["existing_rule_id"]
    pos = finding_data["existing_rule_pos"]
    existing_action = finding_data["existing_action"]
    candidate_action = finding_data["candidate_action"]

    dims = finding_data.get("dimensions", [])
    dim_block = _dim_summary(dims)

    conflict_note = ""
    if existing_action != candidate_action:
        conflict_note = (
            f" The actions differ (candidate {_action_phrase(candidate_action)}, "
            f"existing {_action_phrase(existing_action)}), so inserting the candidate "
            f"would change the effective handling for all traffic currently matched by "
            f"rule '{rule_id}'."
        )

    return (
        f"If inserted at its intended position, the candidate rule would shadow existing "
        f"rule '{rule_id}' at position {pos}. The candidate's match criteria are a "
        f"superset of rule '{rule_id}', meaning rule '{rule_id}' would become unreachable "
        f"— no traffic would ever reach it.{conflict_note}\n"
        f"Dimension breakdown:\n{dim_block}"
    )


def explain_conflict(finding_data: dict) -> str:
    """
    CONFLICT: Candidate and existing rule have overlapping match criteria but
    opposing actions.  Traffic in the intersection is affected differently
    depending on which rule wins (first-match semantics).
    """
    rule_id = finding_data["existing_rule_id"]
    pos = finding_data["existing_rule_pos"]
    candidate_action = finding_data["candidate_action"]
    existing_action = finding_data["existing_action"]

    dims = finding_data.get("dimensions", [])
    dim_block = _dim_summary(dims)

    return (
        f"The candidate rule conflicts with existing rule '{rule_id}' at position {pos}. "
        f"Both rules match overlapping traffic but with opposing actions: the candidate "
        f"{_action_phrase(candidate_action)} traffic, while rule '{rule_id}' "
        f"{_action_phrase(existing_action)} the same traffic. Under first-match semantics, "
        f"whichever rule appears first in the policy determines the effective behavior "
        f"for the conflicting traffic class.\n"
        f"Dimension breakdown:\n{dim_block}"
    )


def explain_superset(finding_data: dict) -> str:
    """
    SUPERSET: The candidate's match criteria are a strict superset of an existing
    rule.  The candidate would match all traffic the existing rule matches, plus more.
    """
    rule_id = finding_data["existing_rule_id"]
    pos = finding_data["existing_rule_pos"]
    candidate_action = finding_data["candidate_action"]
    existing_action = finding_data["existing_action"]

    dims = finding_data.get("dimensions", [])
    dim_block = _dim_summary(dims)

    action_note = ""
    if candidate_action != existing_action:
        action_note = (
            f" The candidate {_action_phrase(candidate_action)} traffic while rule "
            f"'{rule_id}' {_action_phrase(existing_action)} traffic. "
            f"Depending on rule ordering, the broader candidate may override "
            f"the more specific existing rule."
        )

    return (
        f"The candidate rule's match criteria are a superset of existing rule '{rule_id}' "
        f"at position {pos}. The candidate would match all traffic that rule '{rule_id}' "
        f"matches, plus additional traffic.{action_note} Consider whether the existing "
        f"rule is still needed or if it is now redundant.\n"
        f"Dimension breakdown:\n{dim_block}"
    )


def explain_subset(finding_data: dict) -> str:
    """
    SUBSET: The candidate's match criteria are a strict subset of an existing rule.
    The existing rule already handles all traffic the candidate would handle.
    """
    rule_id = finding_data["existing_rule_id"]
    pos = finding_data["existing_rule_pos"]
    candidate_action = finding_data["candidate_action"]
    existing_action = finding_data["existing_action"]

    dims = finding_data.get("dimensions", [])
    dim_block = _dim_summary(dims)

    action_note = ""
    if candidate_action != existing_action:
        action_note = (
            f" The candidate {_action_phrase(candidate_action)} traffic while rule "
            f"'{rule_id}' {_action_phrase(existing_action)} it. "
            f"The candidate would create a more specific exception to the existing rule, "
            f"provided it is positioned before rule '{rule_id}' in the policy."
        )
    else:
        action_note = (
            f" Both rules have the same action ({candidate_action}), so the candidate "
            f"would be effectively redundant if rule '{rule_id}' already appears earlier "
            f"in the policy."
        )

    return (
        f"The candidate rule's match criteria are a strict subset of existing rule "
        f"'{rule_id}' at position {pos}. The existing rule already handles all traffic "
        f"the candidate would match.{action_note}\n"
        f"Dimension breakdown:\n{dim_block}"
    )


def explain_partial_overlap(finding_data: dict) -> str:
    """
    PARTIAL_OVERLAP: Candidate and existing rule share a non-empty intersection
    across all dimensions, but neither is a full superset/subset of the other.
    """
    rule_id = finding_data["existing_rule_id"]
    pos = finding_data["existing_rule_pos"]
    candidate_action = finding_data["candidate_action"]
    existing_action = finding_data["existing_action"]

    dims = finding_data.get("dimensions", [])
    dim_block = _dim_summary(dims)

    action_note = ""
    if candidate_action != existing_action:
        action_note = (
            f" The overlapping traffic class is affected differently: the candidate "
            f"{_action_phrase(candidate_action)} while rule '{rule_id}' "
            f"{_action_phrase(existing_action)}. Under first-match semantics, "
            f"the rule that appears first will handle the overlapping traffic."
        )

    return (
        f"The candidate rule partially overlaps with existing rule '{rule_id}' at "
        f"position {pos}. There is a non-empty intersection between the two rules "
        f"across all match dimensions, but neither rule is a complete subset or "
        f"superset of the other.{action_note}\n"
        f"Dimension breakdown:\n{dim_block}"
    )


# ---------------------------------------------------------------------------
# Dispatch map
# ---------------------------------------------------------------------------

EXPLANATION_MAP: dict = {
    OverlapType.EXACT_DUPLICATE: explain_duplicate,
    OverlapType.SHADOWED: explain_shadowed,
    OverlapType.SHADOWS_EXISTING: explain_shadows_existing,
    OverlapType.CONFLICT: explain_conflict,
    OverlapType.SUPERSET: explain_superset,
    OverlapType.SUBSET: explain_subset,
    OverlapType.PARTIAL_OVERLAP: explain_partial_overlap,
}


def generate_explanation(overlap_type: "OverlapType", finding_data: dict) -> str:
    """
    Route to the appropriate explanation function and return the rendered string.

    Falls back to a generic message if the overlap type is not in the dispatch map.
    """
    fn = EXPLANATION_MAP.get(overlap_type)
    if fn is None:
        rule_id = finding_data.get("existing_rule_id", "unknown")
        return (
            f"Overlap of type '{overlap_type.value}' detected with existing rule "
            f"'{rule_id}'. Refer to dimension breakdown for details."
        )
    return fn(finding_data)
