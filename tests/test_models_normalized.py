"""
Unit tests for models/normalized.py — MatchSpec, NormalizedRule, NormalizedCandidate.
"""

from __future__ import annotations

import pytest

from fwrule_mcp.models.common import (
    Action,
    AddressSet,
    ApplicationSet,
    ServiceSet,
    ZoneSet,
    PortRange,
)
from fwrule_mcp.models.normalized import (
    MatchSpec,
    NormalizedCandidate,
    NormalizedRule,
    RuleMetadata,
)


def _make_match(
    src_cidrs: list[str] | None = None,
    dst_cidrs: list[str] | None = None,
    src_zones: list[str] | None = None,
    dst_zones: list[str] | None = None,
    any_service: bool = True,
) -> MatchSpec:
    """Helper: build a MatchSpec with sensible defaults."""
    return MatchSpec(
        source_zones=ZoneSet.from_names(src_zones) if src_zones else ZoneSet.any(),
        destination_zones=ZoneSet.from_names(dst_zones) if dst_zones else ZoneSet.any(),
        source_addresses=AddressSet.from_cidrs(src_cidrs) if src_cidrs else AddressSet.any(),
        destination_addresses=AddressSet.from_cidrs(dst_cidrs) if dst_cidrs else AddressSet.any(),
        services=ServiceSet.any() if any_service else ServiceSet.tcp(PortRange(443, 443)),
        applications=ApplicationSet.any(),
    )


class TestMatchSpec:
    def test_all_any_intersects_all_any(self):
        m1 = _make_match()
        m2 = _make_match()
        assert m1.intersects(m2)

    def test_specific_intersects_specific_overlap(self):
        m1 = _make_match(src_cidrs=["10.0.0.0/16"])
        m2 = _make_match(src_cidrs=["10.0.1.0/24"])
        assert m1.intersects(m2)

    def test_disjoint_source_addresses_no_intersect(self):
        m1 = _make_match(src_cidrs=["10.0.0.0/24"])
        m2 = _make_match(src_cidrs=["192.168.1.0/24"])
        assert not m1.intersects(m2)

    def test_disjoint_zones_no_intersect(self):
        m1 = _make_match(src_zones=["trust"])
        m2 = _make_match(src_zones=["untrust"])
        assert not m1.intersects(m2)

    def test_subset_of_broader_match(self):
        broad = _make_match()  # all any
        narrow = _make_match(src_cidrs=["10.0.0.0/24"], dst_cidrs=["192.168.1.0/24"])
        assert narrow.is_subset_of(broad)
        assert not broad.is_subset_of(narrow)

    def test_superset_of(self):
        broad = _make_match()
        narrow = _make_match(src_cidrs=["10.0.0.0/24"])
        assert broad.is_superset_of(narrow)

    def test_equals_identical(self):
        m1 = _make_match(src_cidrs=["10.0.0.0/24"])
        m2 = _make_match(src_cidrs=["10.0.0.0/24"])
        assert m1.equals(m2)
        assert m1 == m2


class TestNormalizedRule:
    def test_basic_construction(self):
        rule = NormalizedRule(
            rule_id="rule_1",
            position=1,
            enabled=True,
            match=_make_match(),
            action=Action.PERMIT,
        )
        assert rule.rule_id == "rule_1"
        assert rule.position == 1
        assert rule.is_permitting()
        assert not rule.is_blocking()

    def test_deny_rule_is_blocking(self):
        rule = NormalizedRule(
            rule_id="deny_all",
            position=99,
            enabled=True,
            match=_make_match(),
            action=Action.DENY,
        )
        assert rule.is_blocking()
        assert not rule.is_permitting()

    def test_drop_is_blocking(self):
        rule = NormalizedRule(
            rule_id="r", position=1, enabled=True, match=_make_match(), action=Action.DROP
        )
        assert rule.is_blocking()

    def test_reject_is_blocking(self):
        rule = NormalizedRule(
            rule_id="r", position=1, enabled=True, match=_make_match(), action=Action.REJECT
        )
        assert rule.is_blocking()

    def test_position_must_be_gte_1(self):
        with pytest.raises(Exception):  # pydantic ValidationError
            NormalizedRule(
                rule_id="r",
                position=0,
                enabled=True,
                match=_make_match(),
                action=Action.PERMIT,
            )


class TestNormalizedCandidate:
    def test_construction(self):
        candidate = NormalizedCandidate(
            rule_id="candidate",
            intended_position=5,
            enabled=True,
            match=_make_match(src_cidrs=["10.0.0.0/24"]),
            action=Action.PERMIT,
        )
        assert candidate.intended_position == 5

    def test_as_normalized_rule(self):
        candidate = NormalizedCandidate(
            intended_position=3,
            match=_make_match(),
            action=Action.DENY,
        )
        rule = candidate.as_normalized_rule()
        assert rule.position == 3
        assert rule.action == Action.DENY

    def test_as_normalized_rule_explicit_position(self):
        candidate = NormalizedCandidate(match=_make_match(), action=Action.PERMIT)
        rule = candidate.as_normalized_rule(position=7)
        assert rule.position == 7
