"""
Unit tests for analysis/engine.py and analysis/classifier.py.

Tests every OverlapType plus edge cases (disabled rules, max_rules limit,
ANY vs specific, multiple relationships, unresolvable-reference warnings).
"""

from __future__ import annotations

import pytest

from fwrule_mcp.models.common import (
    Action,
    AddressSet,
    ApplicationSet,
    PortRange,
    ServiceSet,
    ZoneSet,
)
from fwrule_mcp.models.normalized import (
    MatchSpec,
    NormalizedCandidate,
    NormalizedRule,
    RuleMetadata,
)
from fwrule_mcp.models.response import OverlapType
from fwrule_mcp.analysis.engine import OverlapAnalysisEngine, analyze
from fwrule_mcp.analysis.classifier import classify_overlap


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _match(
    src_cidrs: list[str] | None = None,
    dst_cidrs: list[str] | None = None,
    src_zones: list[str] | None = None,
    dst_zones: list[str] | None = None,
    svc_set: ServiceSet | None = None,
    apps: list[str] | None = None,
) -> MatchSpec:
    return MatchSpec(
        source_zones=ZoneSet.from_names(src_zones) if src_zones else ZoneSet.any(),
        destination_zones=ZoneSet.from_names(dst_zones) if dst_zones else ZoneSet.any(),
        source_addresses=AddressSet.from_cidrs(src_cidrs) if src_cidrs else AddressSet.any(),
        destination_addresses=AddressSet.from_cidrs(dst_cidrs) if dst_cidrs else AddressSet.any(),
        services=svc_set if svc_set is not None else ServiceSet.any(),
        applications=ApplicationSet.from_names(apps) if apps else ApplicationSet.any(),
    )


def _rule(
    rule_id: str,
    position: int,
    action: Action = Action.PERMIT,
    enabled: bool = True,
    match: MatchSpec | None = None,
    unresolvable: list[str] | None = None,
) -> NormalizedRule:
    return NormalizedRule(
        rule_id=rule_id,
        position=position,
        enabled=enabled,
        match=match or _match(),
        action=action,
        metadata=RuleMetadata(unresolvable_references=unresolvable or []),
    )


def _candidate(
    action: Action = Action.PERMIT,
    intended_position: int | None = None,
    match: MatchSpec | None = None,
    unresolvable: list[str] | None = None,
) -> NormalizedCandidate:
    return NormalizedCandidate(
        action=action,
        intended_position=intended_position,
        match=match or _match(),
        metadata=RuleMetadata(unresolvable_references=unresolvable or []),
    )


ENGINE = OverlapAnalysisEngine()


# ---------------------------------------------------------------------------
# EXACT_DUPLICATE — identical match + same action
# ---------------------------------------------------------------------------


def test_exact_duplicate_any_any():
    """Two rules matching all traffic with same permit action → EXACT_DUPLICATE."""
    existing = _rule("existing", 1, action=Action.PERMIT)
    cand = _candidate(action=Action.PERMIT)
    result = ENGINE.analyze([existing], cand)
    assert result.has_overlaps
    assert result.relationships[0].overlap_type == OverlapType.EXACT_DUPLICATE


def test_exact_duplicate_specific_cidrs():
    """Identical specific source/dst/service match → EXACT_DUPLICATE."""
    m = _match(
        src_cidrs=["10.0.0.0/24"],
        dst_cidrs=["192.168.1.0/24"],
        svc_set=ServiceSet.tcp(PortRange(443, 443)),
    )
    existing = _rule("r1", 1, match=m)
    cand = _candidate(match=m)
    result = ENGINE.analyze([existing], cand)
    assert result.relationships[0].overlap_type == OverlapType.EXACT_DUPLICATE


def test_exact_duplicate_blocking_actions_are_same_class():
    """DENY + DROP are same blocking class → EXACT_DUPLICATE not CONFLICT."""
    m = _match(src_cidrs=["10.0.0.0/24"])
    existing = _rule("r1", 1, action=Action.DENY, match=m)
    cand = _candidate(action=Action.DROP, match=m)
    result = ENGINE.analyze([existing], cand)
    assert result.relationships[0].overlap_type == OverlapType.EXACT_DUPLICATE


# ---------------------------------------------------------------------------
# SHADOWED — candidate is subset of existing, existing precedes
# ---------------------------------------------------------------------------


def test_shadowed_narrow_below_broad_permit():
    """Narrow candidate inserted after a broad permit → SHADOWED."""
    broad = _rule("broad", 1, action=Action.PERMIT, match=_match())
    narrow_m = _match(src_cidrs=["10.0.0.1/32"], dst_cidrs=["192.168.1.0/24"])
    cand = _candidate(action=Action.PERMIT, intended_position=2, match=narrow_m)
    result = ENGINE.analyze([broad], cand, candidate_position=2)
    assert result.relationships[0].overlap_type == OverlapType.SHADOWED


def test_shadowed_subnet_inside_supernet_at_lower_position():
    """/24 candidate after /16 existing → SHADOWED."""
    supernet_m = _match(src_cidrs=["10.0.0.0/16"])
    subnet_m = _match(src_cidrs=["10.0.1.0/24"])
    existing = _rule("r1", 1, match=supernet_m)
    cand = _candidate(intended_position=5, match=subnet_m)
    result = ENGINE.analyze([existing], cand, candidate_position=5)
    assert result.relationships[0].overlap_type == OverlapType.SHADOWED


# ---------------------------------------------------------------------------
# SUBSET — candidate is subset of existing, candidate precedes
# ---------------------------------------------------------------------------


def test_subset_candidate_precedes():
    """Narrow candidate inserted BEFORE broad existing rule → SUBSET."""
    broad = _rule("broad", 5, action=Action.PERMIT, match=_match())
    narrow_m = _match(src_cidrs=["10.0.0.0/24"])
    cand = _candidate(action=Action.PERMIT, intended_position=1, match=narrow_m)
    result = ENGINE.analyze([broad], cand, candidate_position=1)
    assert result.relationships[0].overlap_type == OverlapType.SUBSET


# ---------------------------------------------------------------------------
# SHADOWS_EXISTING — candidate is superset, candidate precedes
# ---------------------------------------------------------------------------


def test_shadows_existing_broad_candidate_before_narrow_existing():
    """Broad candidate placed before narrow existing rule → SHADOWS_EXISTING."""
    narrow_m = _match(src_cidrs=["10.0.0.0/24"])
    existing = _rule("narrow", 3, match=narrow_m)
    cand = _candidate(intended_position=1, match=_match())  # any/any
    result = ENGINE.analyze([existing], cand, candidate_position=1)
    assert result.relationships[0].overlap_type == OverlapType.SHADOWS_EXISTING


# ---------------------------------------------------------------------------
# SUPERSET — candidate is superset, existing precedes
# ---------------------------------------------------------------------------


def test_superset_broad_candidate_after_narrow_existing():
    """Broad candidate appended after narrow existing → SUPERSET."""
    narrow_m = _match(src_cidrs=["10.0.0.0/24"])
    existing = _rule("narrow", 1, match=narrow_m)
    cand = _candidate(match=_match())  # any/any — appended at end
    result = ENGINE.analyze([existing], cand)
    assert result.relationships[0].overlap_type == OverlapType.SUPERSET


# ---------------------------------------------------------------------------
# PARTIAL_OVERLAP — same action, neither fully contains the other
# ---------------------------------------------------------------------------


def test_partial_overlap_same_action():
    """Two overlapping but not containment rules, same action → PARTIAL_OVERLAP."""
    m1 = _match(src_cidrs=["10.0.0.0/22"])   # covers 10.0.0.0–10.0.3.255
    m2 = _match(src_cidrs=["10.0.1.0/24"])   # subset — but let's use intersecting
    # Use zones to create a partial scenario
    m_existing = _match(src_zones=["trust", "dmz"])
    m_cand = _match(src_zones=["dmz", "untrust"])
    existing = _rule("r1", 1, action=Action.PERMIT, match=m_existing)
    cand = _candidate(action=Action.PERMIT, match=m_cand)
    result = ENGINE.analyze([existing], cand)
    otypes = {r.overlap_type for r in result.relationships}
    assert OverlapType.PARTIAL_OVERLAP in otypes


# ---------------------------------------------------------------------------
# CONFLICT — overlapping match, different action
# ---------------------------------------------------------------------------


def test_conflict_identical_match_different_action():
    """Identical match but candidate denies where existing permits → CONFLICT."""
    m = _match(src_cidrs=["10.0.0.0/24"])
    existing = _rule("r1", 1, action=Action.PERMIT, match=m)
    cand = _candidate(action=Action.DENY, match=m)
    result = ENGINE.analyze([existing], cand)
    assert result.relationships[0].overlap_type == OverlapType.CONFLICT


def test_conflict_partial_overlap_different_action():
    """Partial overlap with different action → CONFLICT."""
    m_existing = _match(src_zones=["trust", "dmz"])
    m_cand = _match(src_zones=["dmz", "untrust"])
    existing = _rule("r1", 1, action=Action.PERMIT, match=m_existing)
    cand = _candidate(action=Action.DENY, match=m_cand)
    result = ENGINE.analyze([existing], cand)
    otypes = {r.overlap_type for r in result.relationships}
    assert OverlapType.CONFLICT in otypes


# ---------------------------------------------------------------------------
# NO_OVERLAP — completely disjoint rules
# ---------------------------------------------------------------------------


def test_no_overlap_disjoint_source_addresses():
    """Completely disjoint source subnets → no overlapping relationships."""
    m1 = _match(src_cidrs=["10.0.0.0/24"])
    m2 = _match(src_cidrs=["192.168.0.0/24"])
    existing = _rule("r1", 1, match=m1)
    cand = _candidate(match=m2)
    result = ENGINE.analyze([existing], cand)
    assert not result.has_overlaps


def test_no_overlap_disjoint_zones():
    """Source zones trust vs untrust → no overlap."""
    m1 = _match(src_zones=["trust"])
    m2 = _match(src_zones=["untrust"])
    existing = _rule("r1", 1, match=m1)
    cand = _candidate(match=m2)
    result = ENGINE.analyze([existing], cand)
    assert not result.has_overlaps


def test_no_overlap_disjoint_services():
    """TCP/80 vs TCP/443 → no overlap."""
    m1 = _match(svc_set=ServiceSet.tcp(PortRange(80, 80)))
    m2 = _match(svc_set=ServiceSet.tcp(PortRange(443, 443)))
    existing = _rule("r1", 1, match=m1)
    cand = _candidate(match=m2)
    result = ENGINE.analyze([existing], cand)
    assert not result.has_overlaps


# ---------------------------------------------------------------------------
# Disabled rules → skipped
# ---------------------------------------------------------------------------


def test_disabled_rule_is_skipped():
    """Disabled existing rule must not appear in relationships."""
    disabled = _rule("disabled_rule", 1, enabled=False, match=_match())
    cand = _candidate()
    result = ENGINE.analyze([disabled], cand)
    assert result.disabled_rule_count == 1
    assert not result.has_overlaps


def test_disabled_and_enabled_mixed():
    """One disabled (skipped) and one enabled (processed) rule."""
    disabled = _rule("d", 1, enabled=False)
    enabled = _rule("e", 2, enabled=True)
    cand = _candidate()
    result = ENGINE.analyze([disabled, enabled], cand)
    assert result.disabled_rule_count == 1
    assert result.existing_rule_count == 2
    assert any(r.existing_rule.rule_id == "e" for r in result.relationships)


# ---------------------------------------------------------------------------
# max_rules limit
# ---------------------------------------------------------------------------


def test_max_rules_limit():
    """max_rules stops analysis after N enabled rules."""
    rules = [_rule(f"r{i}", i) for i in range(1, 6)]
    cand = _candidate()
    result = ENGINE.analyze(rules, cand, max_rules=2)
    assert result.skipped_count == 3


# ---------------------------------------------------------------------------
# Multiple existing rules with mixed relationships
# ---------------------------------------------------------------------------


def test_multiple_relationships_detected():
    """Candidate interacts differently with multiple existing rules."""
    # r1: any/any permit — candidate is subset → SHADOWED when candidate is at pos 5
    r1 = _rule("r1", 1, action=Action.PERMIT, match=_match())
    # r2: disjoint → no overlap
    r2 = _rule("r2", 2, match=_match(src_cidrs=["172.16.0.0/24"]))
    cand = _candidate(
        action=Action.PERMIT,
        intended_position=5,
        match=_match(src_cidrs=["10.0.0.0/24"]),
    )
    result = ENGINE.analyze([r1, r2], cand, candidate_position=5)
    # r1 should be SHADOWED, r2 might be no_overlap
    overlap_rels = result.overlap_relationships
    assert any(r.existing_rule.rule_id == "r1" for r in overlap_rels)


# ---------------------------------------------------------------------------
# Unresolvable reference warnings
# ---------------------------------------------------------------------------


def test_unresolvable_reference_warning_from_candidate():
    """Candidate with unresolvable references → warning in result."""
    cand = _candidate(unresolvable=["UnknownObject"])
    result = ENGINE.analyze([], cand)
    assert any("UnknownObject" in w for w in result.warnings)


def test_unresolvable_reference_warning_from_existing():
    """Existing rule with unresolvable reference → warning in result."""
    rule = _rule("r1", 1, unresolvable=["BadRef"])
    cand = _candidate()
    result = ENGINE.analyze([rule], cand)
    assert any("BadRef" in w for w in result.warnings)


# ---------------------------------------------------------------------------
# ANY vs specific edge cases
# ---------------------------------------------------------------------------


def test_any_src_vs_specific_existing():
    """Candidate with any source, existing with specific → SUPERSET."""
    existing = _rule("r1", 1, match=_match(src_cidrs=["10.0.0.0/24"]))
    cand = _candidate(match=_match())  # any source
    result = ENGINE.analyze([existing], cand)
    assert result.relationships[0].overlap_type in (
        OverlapType.SUPERSET, OverlapType.EXACT_DUPLICATE
    )


def test_single_host_vs_network():
    """Host /32 inside /24 → SHADOWED (existing precedes)."""
    net_m = _match(src_cidrs=["10.0.0.0/24"])
    host_m = _match(src_cidrs=["10.0.0.5/32"])
    existing = _rule("r1", 1, match=net_m)
    cand = _candidate(intended_position=2, match=host_m)
    result = ENGINE.analyze([existing], cand, candidate_position=2)
    assert result.relationships[0].overlap_type == OverlapType.SHADOWED


# ---------------------------------------------------------------------------
# Module-level convenience function
# ---------------------------------------------------------------------------


def test_module_level_analyze_function():
    """analyze() module-level function returns AnalysisResult."""
    existing = _rule("r1", 1)
    cand = _candidate()
    result = analyze(cand, [existing])
    assert result.existing_rule_count == 1


# ---------------------------------------------------------------------------
# AnalysisResult helpers
# ---------------------------------------------------------------------------


def test_analysis_result_relationships_by_type():
    """relationships_by_type() filters correctly."""
    existing = _rule("r1", 1, action=Action.PERMIT)
    cand = _candidate(action=Action.DENY)
    result = ENGINE.analyze([existing], cand)
    conflicts = result.relationships_by_type(OverlapType.CONFLICT)
    assert len(conflicts) >= 1


def test_analysis_result_overlap_relationships_excludes_no_overlap():
    """overlap_relationships should exclude NO_OVERLAP entries."""
    existing = _rule("r1", 1, match=_match(src_cidrs=["10.0.0.0/24"]))
    cand = _candidate(match=_match(src_cidrs=["192.168.0.0/24"]))
    result = ENGINE.analyze([existing], cand)
    for rel in result.overlap_relationships:
        assert rel.overlap_type != OverlapType.NO_OVERLAP


# ---------------------------------------------------------------------------
# classify_overlap direct tests
# ---------------------------------------------------------------------------


def test_classify_overlap_equal_same_action():
    existing = _rule("r1", 1, action=Action.PERMIT)
    cand = _candidate(action=Action.PERMIT)
    rel = classify_overlap(cand, existing)
    assert rel.overlap_type == OverlapType.EXACT_DUPLICATE
    assert rel.action_same is True


def test_classify_overlap_equal_different_action():
    existing = _rule("r1", 1, action=Action.PERMIT)
    cand = _candidate(action=Action.DENY)
    rel = classify_overlap(cand, existing)
    assert rel.overlap_type == OverlapType.CONFLICT
    assert rel.action_same is False


def test_classify_overlap_candidate_precedes_flag():
    existing = _rule("r1", 10, action=Action.PERMIT)
    cand = _candidate(action=Action.PERMIT)
    rel = classify_overlap(cand, existing, candidate_position=1)
    assert rel.candidate_precedes is True


def test_classify_overlap_no_overlap_disjoint():
    m1 = _match(src_cidrs=["10.0.0.0/24"])
    m2 = _match(src_cidrs=["192.168.0.0/24"])
    existing = _rule("r1", 1, match=m1)
    cand = _candidate(match=m2)
    rel = classify_overlap(cand, existing)
    assert rel.overlap_type == OverlapType.NO_OVERLAP


def test_classify_overlap_dimension_analyses_populated():
    existing = _rule("r1", 1)
    cand = _candidate()
    rel = classify_overlap(cand, existing)
    assert len(rel.dimension_analyses) == 6
    names = {da.dimension_name for da in rel.dimension_analyses}
    assert "source_zones" in names
    assert "destination_addresses" in names
