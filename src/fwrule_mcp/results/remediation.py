"""
Remediation suggestion generator.

Each function accepts a ``finding_data`` dict (same structure as explanations.py)
and returns a concrete remediation string or None.

Remediation suggestions are intentionally conservative — they describe what an
operator CAN do, not what they MUST do, and include enough context to make the
suggestion actionable without additional lookups.
"""

from __future__ import annotations

from fwrule_mcp.models.response import OverlapType


# ---------------------------------------------------------------------------
# Per-type remediation functions
# ---------------------------------------------------------------------------


def _remediate_duplicate(finding_data: dict) -> str:
    rule_id = finding_data["existing_rule_id"]
    return (
        f"Remove the candidate rule — it is redundant with existing rule '{rule_id}'. "
        f"Both rules match identical traffic with the same action, so the candidate "
        f"provides no additional policy coverage and adds unnecessary configuration complexity."
    )


def _remediate_shadowed(finding_data: dict) -> str:
    rule_id = finding_data["existing_rule_id"]
    pos = finding_data["existing_rule_pos"]
    candidate_action = finding_data["candidate_action"]
    existing_action = finding_data["existing_action"]

    if candidate_action == existing_action:
        return (
            f"Remove the candidate rule — it would be completely shadowed by rule "
            f"'{rule_id}' at position {pos} and would never match any traffic. "
            f"If the intent was to create an additional rule with the same effect, "
            f"it is unnecessary."
        )
    else:
        return (
            f"Either remove the candidate rule or move it above rule '{rule_id}' "
            f"at position {pos}. Currently rule '{rule_id}' would intercept all "
            f"matching traffic before the candidate is reached. If the candidate's "
            f"action ({candidate_action}) is the intended behavior, it must appear "
            f"before rule '{rule_id}' ({existing_action}) in the policy."
        )


def _remediate_shadows_existing(finding_data: dict) -> str:
    rule_id = finding_data["existing_rule_id"]
    pos = finding_data["existing_rule_pos"]
    candidate_action = finding_data["candidate_action"]
    existing_action = finding_data["existing_action"]

    if candidate_action == existing_action:
        return (
            f"Warning: adding this rule at its intended position would shadow existing "
            f"rule '{rule_id}' at position {pos}. Rule '{rule_id}' would become "
            f"unreachable. Consider whether rule '{rule_id}' is still needed. If it "
            f"is redundant, remove it to keep the policy clean. If it should remain "
            f"active, narrow the candidate rule so it does not cover all of '{rule_id}'s "
            f"traffic."
        )
    else:
        return (
            f"Warning: adding this rule at its intended position would shadow existing "
            f"rule '{rule_id}' at position {pos}, changing its effective action from "
            f"{existing_action} to {candidate_action} for all traffic the existing rule "
            f"handles. Options: (1) remove rule '{rule_id}' if the new behavior is "
            f"intended; (2) narrow the candidate's match criteria so it does not "
            f"completely cover rule '{rule_id}'; or (3) reorder the candidate to appear "
            f"after rule '{rule_id}'."
        )


def _remediate_conflict(finding_data: dict) -> str:
    rule_id = finding_data["existing_rule_id"]
    pos = finding_data["existing_rule_pos"]
    candidate_action = finding_data["candidate_action"]
    existing_action = finding_data["existing_action"]

    return (
        f"Review the intended action for the overlapping traffic class. "
        f"Options: (1) if the candidate's action ({candidate_action}) should take "
        f"precedence, position the candidate before rule '{rule_id}' at position {pos}; "
        f"(2) if the existing rule's action ({existing_action}) is correct, either "
        f"discard the candidate or narrow it so the conflicting traffic is excluded; "
        f"(3) if both rules are needed for different traffic subsets, split the "
        f"candidate to cover only the non-overlapping portion."
    )


def _remediate_superset(finding_data: dict) -> str:
    rule_id = finding_data["existing_rule_id"]
    pos = finding_data["existing_rule_pos"]
    candidate_action = finding_data["candidate_action"]
    existing_action = finding_data["existing_action"]

    if candidate_action == existing_action:
        return (
            f"The candidate is broader than existing rule '{rule_id}' at position {pos} "
            f"with the same action. Consider whether rule '{rule_id}' is still needed. "
            f"If the candidate subsumes all of '{rule_id}'s intended coverage, rule "
            f"'{rule_id}' may be safely removed."
        )
    else:
        return (
            f"The candidate's match criteria cover all traffic matched by rule '{rule_id}' "
            f"at position {pos}, plus additional traffic. The two rules have different "
            f"actions ({candidate_action} vs {existing_action}). Review whether existing "
            f"rule '{rule_id}' should remain as a more specific override, or whether "
            f"the candidate should be narrowed to avoid covering traffic already handled "
            f"by '{rule_id}'."
        )


def _remediate_subset(finding_data: dict) -> str:
    rule_id = finding_data["existing_rule_id"]
    pos = finding_data["existing_rule_pos"]
    candidate_action = finding_data["candidate_action"]
    existing_action = finding_data["existing_action"]

    if candidate_action == existing_action:
        return (
            f"The candidate is narrower than existing rule '{rule_id}' at position {pos} "
            f"and has the same action. If rule '{rule_id}' already provides the intended "
            f"coverage, the candidate is redundant and can be omitted. If the candidate "
            f"was intended to be more specific for documentation or audit purposes, "
            f"ensure it is positioned before rule '{rule_id}'."
        )
    else:
        return (
            f"The candidate creates a more specific exception to existing rule '{rule_id}' "
            f"at position {pos}. The candidate ({candidate_action}) narrows the effect of "
            f"rule '{rule_id}' ({existing_action}) for a traffic subset. Ensure the "
            f"candidate is positioned before rule '{rule_id}' in the policy so it is "
            f"evaluated first and acts as the intended exception."
        )


def _remediate_partial_overlap(finding_data: dict) -> str:
    rule_id = finding_data["existing_rule_id"]
    pos = finding_data["existing_rule_pos"]
    candidate_action = finding_data["candidate_action"]
    existing_action = finding_data["existing_action"]

    if candidate_action == existing_action:
        return (
            f"The candidate partially overlaps with rule '{rule_id}' at position {pos} "
            f"with the same action. Consider whether both rules are needed or if they "
            f"can be consolidated into a single, more precise rule to reduce policy "
            f"complexity."
        )
    else:
        return (
            f"The candidate partially overlaps with rule '{rule_id}' at position {pos} "
            f"with different actions ({candidate_action} vs {existing_action}). "
            f"Review the overlapping traffic class carefully. Under first-match semantics, "
            f"whichever rule appears first handles the overlap. Options: (1) reorder "
            f"the rules based on intended priority; (2) narrow one or both rules to "
            f"eliminate the overlap; or (3) accept the ordering-dependent behavior "
            f"if it is intentional."
        )


# ---------------------------------------------------------------------------
# Dispatch map and public API
# ---------------------------------------------------------------------------


_REMEDIATION_MAP: dict = {
    OverlapType.EXACT_DUPLICATE: _remediate_duplicate,
    OverlapType.SHADOWED: _remediate_shadowed,
    OverlapType.SHADOWS_EXISTING: _remediate_shadows_existing,
    OverlapType.CONFLICT: _remediate_conflict,
    OverlapType.SUPERSET: _remediate_superset,
    OverlapType.SUBSET: _remediate_subset,
    OverlapType.PARTIAL_OVERLAP: _remediate_partial_overlap,
}


def suggest_remediation(overlap_type: OverlapType, finding_data: dict) -> str | None:
    """
    Return a remediation suggestion string for the given overlap type, or None
    if no suggestion is applicable.

    Args:
        overlap_type:  The classified overlap type from the analysis engine.
        finding_data:  Dict with keys: existing_rule_id, existing_rule_pos,
                       candidate_action, existing_action, dimensions.

    Returns:
        A human-readable remediation suggestion, or None for NO_OVERLAP.
    """
    if overlap_type == OverlapType.NO_OVERLAP:
        return None

    fn = _REMEDIATION_MAP.get(overlap_type)
    if fn is None:
        return None

    try:
        return fn(finding_data)
    except (KeyError, TypeError):
        # Guard against unexpected finding_data shapes — never crash the pipeline
        return (
            f"Review the candidate rule's interaction with existing rule "
            f"'{finding_data.get('existing_rule_id', 'unknown')}' "
            f"(overlap type: {overlap_type.value})."
        )
