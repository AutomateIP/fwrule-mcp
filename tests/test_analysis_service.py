"""
Unit tests for analysis/service.py — compare_service_sets().

Covers: equal, subset, superset, intersecting, disjoint for TCP/UDP services,
ICMP, ANY vs specific, multi-service sets, and different protocols.
"""

from __future__ import annotations

import pytest

from fwrule_mcp.models.common import PortRange, ServiceEntry, ServiceSet
from fwrule_mcp.analysis.service import ServiceComparison, compare_service_sets


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _tcp(start: int, end: int | None = None) -> ServiceSet:
    return ServiceSet.tcp(PortRange(start, end if end is not None else start))


def _udp(start: int, end: int | None = None) -> ServiceSet:
    return ServiceSet.udp(PortRange(start, end if end is not None else start))


def _compare(cand: ServiceSet, exist: ServiceSet) -> ServiceComparison:
    return compare_service_sets(cand, exist)


# ---------------------------------------------------------------------------
# ANY vs ANY
# ---------------------------------------------------------------------------


def test_any_vs_any_is_equal():
    result = _compare(ServiceSet.any(), ServiceSet.any())
    assert result.relationship == "equal"


# ---------------------------------------------------------------------------
# ANY vs specific
# ---------------------------------------------------------------------------


def test_any_vs_specific_is_superset():
    result = _compare(ServiceSet.any(), _tcp(443))
    assert result.relationship == "superset"


def test_specific_vs_any_is_subset():
    result = _compare(_tcp(443), ServiceSet.any())
    assert result.relationship == "subset"


# ---------------------------------------------------------------------------
# Same port → equal
# ---------------------------------------------------------------------------


def test_same_port_tcp_equal():
    result = _compare(_tcp(80), _tcp(80))
    assert result.relationship == "equal"


def test_same_port_udp_equal():
    result = _compare(_udp(53), _udp(53))
    assert result.relationship == "equal"


# ---------------------------------------------------------------------------
# Port subset (80 inside 1-65535)
# ---------------------------------------------------------------------------


def test_single_port_inside_wide_range_is_subset():
    result = _compare(_tcp(80), ServiceSet.tcp(PortRange(1, 65535)))
    assert result.relationship == "subset"


def test_narrow_range_inside_wide_range_is_subset():
    result = _compare(_tcp(8080, 8090), ServiceSet.tcp(PortRange(1024, 65535)))
    assert result.relationship == "subset"


# ---------------------------------------------------------------------------
# Port superset
# ---------------------------------------------------------------------------


def test_wide_range_contains_narrow_is_superset():
    result = _compare(ServiceSet.tcp(PortRange(1, 65535)), _tcp(443))
    assert result.relationship == "superset"


# ---------------------------------------------------------------------------
# Disjoint ports
# ---------------------------------------------------------------------------


def test_port_80_vs_443_disjoint():
    result = _compare(_tcp(80), _tcp(443))
    assert result.relationship == "disjoint"


def test_non_overlapping_ranges_disjoint():
    result = _compare(_tcp(80, 90), _tcp(100, 110))
    assert result.relationship == "disjoint"


# ---------------------------------------------------------------------------
# Intersecting ports
# ---------------------------------------------------------------------------


def test_overlapping_ranges_intersecting():
    result = _compare(_tcp(80, 100), _tcp(90, 120))
    assert result.relationship == "intersecting"


# ---------------------------------------------------------------------------
# Different protocols
# ---------------------------------------------------------------------------


def test_tcp_vs_udp_same_port_disjoint():
    result = _compare(_tcp(80), _udp(80))
    assert result.relationship == "disjoint"


def test_tcp_and_udp_in_same_set_vs_tcp():
    """Multi-protocol candidate vs TCP-only existing."""
    cand = ServiceSet(entries=[
        ServiceEntry(protocol="tcp", ports=(PortRange(80, 80),)),
        ServiceEntry(protocol="udp", ports=(PortRange(80, 80),)),
    ])
    exist = _tcp(80)
    result = compare_service_sets(cand, exist)
    # Candidate is a superset (has TCP/80 + UDP/80, existing only has TCP/80)
    assert result.relationship in ("superset", "intersecting")


# ---------------------------------------------------------------------------
# ICMP comparisons
# ---------------------------------------------------------------------------


def test_icmp_any_vs_icmp_any_equal():
    cand = ServiceSet(entries=[ServiceEntry(protocol="icmp")])
    exist = ServiceSet(entries=[ServiceEntry(protocol="icmp")])
    result = compare_service_sets(cand, exist)
    assert result.relationship == "equal"


def test_icmp_vs_tcp_disjoint():
    cand = ServiceSet(entries=[ServiceEntry(protocol="icmp")])
    exist = _tcp(80)
    result = compare_service_sets(cand, exist)
    assert result.relationship == "disjoint"


# ---------------------------------------------------------------------------
# TCP with no port restriction (any port) vs specific
# ---------------------------------------------------------------------------


def test_tcp_any_port_vs_specific_port_is_superset():
    cand = ServiceSet(entries=[ServiceEntry(protocol="tcp", ports=None)])
    exist = _tcp(443)
    result = compare_service_sets(cand, exist)
    assert result.relationship == "superset"


def test_specific_port_vs_tcp_any_port_is_subset():
    cand = _tcp(443)
    exist = ServiceSet(entries=[ServiceEntry(protocol="tcp", ports=None)])
    result = compare_service_sets(cand, exist)
    assert result.relationship == "subset"


# ---------------------------------------------------------------------------
# Multi-service sets
# ---------------------------------------------------------------------------


def test_multi_service_equal():
    cand = ServiceSet(entries=[
        ServiceEntry(protocol="tcp", ports=(PortRange(80, 80),)),
        ServiceEntry(protocol="tcp", ports=(PortRange(443, 443),)),
    ])
    exist = ServiceSet(entries=[
        ServiceEntry(protocol="tcp", ports=(PortRange(80, 80),)),
        ServiceEntry(protocol="tcp", ports=(PortRange(443, 443),)),
    ])
    result = compare_service_sets(cand, exist)
    assert result.relationship == "equal"


# ---------------------------------------------------------------------------
# Description strings populated
# ---------------------------------------------------------------------------


def test_description_populated_for_disjoint():
    result = _compare(_tcp(80), _tcp(443))
    assert result.intersection_description != ""
    assert "disjoint" in result.relationship


def test_description_populated_for_subset():
    result = _compare(_tcp(443), ServiceSet.any())
    assert "subset" in result.intersection_description.lower()


def test_description_populated_for_any_vs_any():
    result = _compare(ServiceSet.any(), ServiceSet.any())
    assert "any" in result.intersection_description.lower()
