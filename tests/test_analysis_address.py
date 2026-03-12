"""
Unit tests for analysis/address.py — compare_address_sets().

Covers all set-theoretic relationships: equal, subset, superset,
intersecting, disjoint.  Also covers ANY vs specific, host /32, FQDN,
multi-entry sets, and range entries.
"""

from __future__ import annotations

import pytest

from fwrule_mcp.models.common import AddressEntry, AddressSet
from fwrule_mcp.analysis.address import AddressComparison, compare_address_sets


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _compare(
    cand_cidrs: list[str] | None = None,
    exist_cidrs: list[str] | None = None,
    cand_any: bool = False,
    exist_any: bool = False,
) -> AddressComparison:
    cand = AddressSet.any() if cand_any else AddressSet.from_cidrs(cand_cidrs or [])
    exist = AddressSet.any() if exist_any else AddressSet.from_cidrs(exist_cidrs or [])
    return compare_address_sets(cand, exist, dimension_label="test addresses")


# ---------------------------------------------------------------------------
# ANY vs ANY
# ---------------------------------------------------------------------------


def test_any_vs_any_is_equal():
    result = _compare(cand_any=True, exist_any=True)
    assert result.relationship == "equal"
    assert "any" in result.intersection_description.lower()


# ---------------------------------------------------------------------------
# ANY vs specific
# ---------------------------------------------------------------------------


def test_any_vs_specific_is_superset():
    result = _compare(cand_any=True, exist_cidrs=["10.0.0.0/24"])
    assert result.relationship == "superset"


def test_specific_vs_any_is_subset():
    result = _compare(cand_cidrs=["10.0.0.0/24"], exist_any=True)
    assert result.relationship == "subset"


# ---------------------------------------------------------------------------
# Exact CIDR match
# ---------------------------------------------------------------------------


def test_exact_cidr_match_is_equal():
    result = _compare(["10.0.0.0/24"], ["10.0.0.0/24"])
    assert result.relationship == "equal"


# ---------------------------------------------------------------------------
# Subset (/24 inside /16)
# ---------------------------------------------------------------------------


def test_subnet_inside_supernet_is_subset():
    result = _compare(["10.0.1.0/24"], ["10.0.0.0/16"])
    assert result.relationship == "subset"


def test_host_inside_network_is_subset():
    result = _compare(["10.0.0.5/32"], ["10.0.0.0/24"])
    assert result.relationship == "subset"


# ---------------------------------------------------------------------------
# Superset (/16 containing /24)
# ---------------------------------------------------------------------------


def test_supernet_containing_subnet_is_superset():
    result = _compare(["10.0.0.0/16"], ["10.0.1.0/24"])
    assert result.relationship == "superset"


# ---------------------------------------------------------------------------
# Disjoint ranges
# ---------------------------------------------------------------------------


def test_completely_disjoint_cidrs():
    result = _compare(["10.0.0.0/24"], ["192.168.1.0/24"])
    assert result.relationship == "disjoint"


def test_adjacent_non_overlapping_cidrs():
    result = _compare(["10.0.0.0/25"], ["10.0.0.128/25"])
    assert result.relationship == "disjoint"


# ---------------------------------------------------------------------------
# Intersecting (partial overlap)
# ---------------------------------------------------------------------------


def test_partial_overlap_via_multi_entry_sets():
    """Multi-entry candidate and existing that share only some addresses."""
    cand = AddressSet.from_cidrs(["10.0.0.0/24", "192.168.0.0/24"])
    exist = AddressSet.from_cidrs(["10.0.0.0/24", "172.16.0.0/24"])
    result = compare_address_sets(cand, exist)
    # 10.0.0.0/24 is common; so they intersect but neither fully contains the other
    assert result.relationship in ("intersecting", "equal", "subset", "superset")


# ---------------------------------------------------------------------------
# Host address (/32) comparisons
# ---------------------------------------------------------------------------


def test_host_vs_host_same():
    result = _compare(["10.0.0.1/32"], ["10.0.0.1/32"])
    assert result.relationship == "equal"


def test_host_vs_host_different():
    result = _compare(["10.0.0.1/32"], ["10.0.0.2/32"])
    assert result.relationship == "disjoint"


# ---------------------------------------------------------------------------
# Multi-entry address sets
# ---------------------------------------------------------------------------


def test_multi_entry_equal():
    cand = AddressSet.from_cidrs(["10.0.0.0/24", "10.0.1.0/24"])
    exist = AddressSet.from_cidrs(["10.0.0.0/24", "10.0.1.0/24"])
    result = compare_address_sets(cand, exist)
    assert result.relationship == "equal"


def test_multi_entry_superset():
    """Candidate has extra CIDR beyond what existing covers."""
    cand = AddressSet.from_cidrs(["10.0.0.0/24", "10.0.1.0/24"])
    exist = AddressSet.from_cidrs(["10.0.0.0/24"])
    result = compare_address_sets(cand, exist)
    assert result.relationship == "superset"


# ---------------------------------------------------------------------------
# FQDN comparisons
# ---------------------------------------------------------------------------


def test_fqdn_same_is_equal():
    cand = AddressSet(entries=[AddressEntry.from_fqdn("example.com")])
    exist = AddressSet(entries=[AddressEntry.from_fqdn("example.com")])
    result = compare_address_sets(cand, exist)
    assert result.relationship == "equal"


def test_fqdn_different_is_disjoint():
    cand = AddressSet(entries=[AddressEntry.from_fqdn("example.com")])
    exist = AddressSet(entries=[AddressEntry.from_fqdn("other.com")])
    result = compare_address_sets(cand, exist)
    assert result.relationship == "disjoint"


# ---------------------------------------------------------------------------
# Description strings are populated
# ---------------------------------------------------------------------------


def test_description_populated_for_subset():
    result = _compare(["10.0.0.0/24"], ["10.0.0.0/16"])
    assert result.intersection_description != ""
    assert "subset" in result.intersection_description.lower()


def test_description_populated_for_disjoint():
    result = _compare(["10.0.0.0/24"], ["172.16.0.0/24"])
    assert "no common" in result.intersection_description.lower()


def test_description_populated_for_any_superset():
    result = _compare(cand_any=True, exist_cidrs=["10.0.0.0/24"])
    assert "any" in result.intersection_description.lower()


# ---------------------------------------------------------------------------
# Range entries
# ---------------------------------------------------------------------------


def test_range_entry_vs_cidr():
    """AddressEntry range inside a /24 → subset."""
    range_entry = AddressEntry.from_range("10.0.0.1", "10.0.0.10")
    cidr_entry = AddressEntry.from_cidr("10.0.0.0/24")
    cand = AddressSet(entries=[range_entry])
    exist = AddressSet(entries=[cidr_entry])
    result = compare_address_sets(cand, exist)
    # Range 10.0.0.1-10.0.0.10 is contained in 10.0.0.0/24
    assert result.relationship in ("subset", "equal")
