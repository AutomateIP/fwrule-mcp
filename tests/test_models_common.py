"""
Unit tests for models/common.py — AddressEntry, PortRange, ServiceEntry,
AddressSet, ServiceSet, ZoneSet, ApplicationSet.

These tests are the ground-truth specification for the set-theoretic logic
that the analysis engine depends on.  All tests must pass before any
higher-layer work begins.
"""

from __future__ import annotations

import pytest
from ipaddress import IPv4Network

from fwrule_mcp.models.common import (
    Action,
    AddressEntry,
    AddressFamily,
    AddressSet,
    AddressType,
    ApplicationSet,
    BLOCKING_ACTIONS,
    PortRange,
    ServiceEntry,
    ServiceSet,
    ZoneSet,
    _intersect_port_range_lists,
    _merge_port_ranges,
)


# ---------------------------------------------------------------------------
# PortRange tests
# ---------------------------------------------------------------------------


class TestPortRange:
    def test_single_port(self):
        pr = PortRange(443, 443)
        assert pr.start == 443
        assert pr.end == 443

    def test_range(self):
        pr = PortRange(1024, 65535)
        assert pr.start == 1024
        assert pr.end == 65535

    def test_invalid_start_greater_than_end(self):
        with pytest.raises(ValueError):
            PortRange(100, 99)

    def test_invalid_port_out_of_range(self):
        with pytest.raises(ValueError):
            PortRange(0, 70000)

    def test_intersects_overlapping(self):
        assert PortRange(80, 90).intersects(PortRange(85, 100))

    def test_intersects_adjacent_nonoverlapping(self):
        assert not PortRange(80, 89).intersects(PortRange(90, 99))

    def test_intersects_exact_match(self):
        assert PortRange(443, 443).intersects(PortRange(443, 443))

    def test_intersection_result(self):
        result = PortRange(80, 90).intersection(PortRange(85, 100))
        assert result == PortRange(85, 90)

    def test_intersection_disjoint(self):
        assert PortRange(80, 89).intersection(PortRange(90, 99)) is None

    def test_is_subset_of(self):
        assert PortRange(443, 443).is_subset_of(PortRange(1, 65535))

    def test_is_not_subset_of(self):
        assert not PortRange(1, 65535).is_subset_of(PortRange(443, 443))

    def test_is_superset_of(self):
        assert PortRange(1, 65535).is_superset_of(PortRange(443, 443))


class TestMergePortRanges:
    def test_adjacent_ranges_merged(self):
        result = _merge_port_ranges([PortRange(80, 89), PortRange(90, 99)])
        assert result == [PortRange(80, 99)]

    def test_overlapping_ranges_merged(self):
        result = _merge_port_ranges([PortRange(80, 100), PortRange(90, 120)])
        assert result == [PortRange(80, 120)]

    def test_disjoint_ranges_not_merged(self):
        result = _merge_port_ranges([PortRange(80, 89), PortRange(100, 110)])
        assert result == [PortRange(80, 89), PortRange(100, 110)]

    def test_empty_list(self):
        assert _merge_port_ranges([]) == []


class TestIntersectPortRangeLists:
    def test_simple_intersection(self):
        a = [PortRange(80, 100)]
        b = [PortRange(90, 120)]
        result = _intersect_port_range_lists(a, b)
        assert result == [PortRange(90, 100)]

    def test_disjoint(self):
        a = [PortRange(80, 89)]
        b = [PortRange(90, 99)]
        assert _intersect_port_range_lists(a, b) == []

    def test_subset(self):
        a = [PortRange(443, 443)]
        b = [PortRange(1, 65535)]
        result = _intersect_port_range_lists(a, b)
        assert result == [PortRange(443, 443)]


# ---------------------------------------------------------------------------
# AddressEntry tests
# ---------------------------------------------------------------------------


class TestAddressEntry:
    def test_from_cidr_ipv4(self):
        e = AddressEntry.from_cidr("10.0.0.0/24")
        assert e.addr_type == AddressType.CIDR
        assert e.addr_family == AddressFamily.IPV4
        assert e.cidr == IPv4Network("10.0.0.0/24")

    def test_from_cidr_host(self):
        e = AddressEntry.from_cidr("192.168.1.1/32")
        assert e.addr_type == AddressType.HOST

    def test_from_range(self):
        e = AddressEntry.from_range("10.0.0.1", "10.0.0.100")
        assert e.addr_type == AddressType.RANGE
        assert e.range_start is not None
        assert e.range_end is not None

    def test_any_sentinel(self):
        e = AddressEntry.any_sentinel()
        assert e.addr_type == AddressType.ANY

    def test_contains_any_contains_everything(self):
        any_e = AddressEntry.any_sentinel()
        specific = AddressEntry.from_cidr("10.0.0.0/24")
        assert any_e.contains(specific)

    def test_specific_does_not_contain_any(self):
        any_e = AddressEntry.any_sentinel()
        specific = AddressEntry.from_cidr("10.0.0.0/24")
        assert not specific.contains(any_e)

    def test_cidr_contains_subnet(self):
        supernet = AddressEntry.from_cidr("10.0.0.0/16")
        subnet = AddressEntry.from_cidr("10.0.1.0/24")
        assert supernet.contains(subnet)

    def test_cidr_not_contains_disjoint(self):
        a = AddressEntry.from_cidr("10.0.0.0/24")
        b = AddressEntry.from_cidr("192.168.1.0/24")
        assert not a.contains(b)

    def test_intersects_overlapping_cidrs(self):
        a = AddressEntry.from_cidr("10.0.0.0/22")
        b = AddressEntry.from_cidr("10.0.1.0/24")
        assert a.intersects(b)
        assert b.intersects(a)

    def test_intersects_disjoint_cidrs(self):
        a = AddressEntry.from_cidr("10.0.0.0/24")
        b = AddressEntry.from_cidr("192.168.1.0/24")
        assert not a.intersects(b)

    def test_to_prefixes_cidr(self):
        e = AddressEntry.from_cidr("10.0.0.0/24")
        prefixes = e.to_prefixes()
        assert len(prefixes) == 1
        assert prefixes[0] == IPv4Network("10.0.0.0/24")

    def test_to_prefixes_any_returns_empty(self):
        e = AddressEntry.any_sentinel()
        assert e.to_prefixes() == []

    def test_fqdn_intersects_same(self):
        a = AddressEntry.from_fqdn("example.com")
        b = AddressEntry.from_fqdn("example.com")
        assert a.intersects(b)

    def test_fqdn_does_not_intersect_different(self):
        a = AddressEntry.from_fqdn("example.com")
        b = AddressEntry.from_fqdn("other.com")
        assert not a.intersects(b)


# ---------------------------------------------------------------------------
# AddressSet tests
# ---------------------------------------------------------------------------


class TestAddressSet:
    def test_any_intersects_everything(self):
        any_set = AddressSet.any()
        specific = AddressSet.from_cidrs(["10.0.0.0/24"])
        assert any_set.intersects(specific)
        assert specific.intersects(any_set)

    def test_disjoint_sets_do_not_intersect(self):
        a = AddressSet.from_cidrs(["10.0.0.0/24"])
        b = AddressSet.from_cidrs(["192.168.1.0/24"])
        assert not a.intersects(b)

    def test_overlapping_sets_intersect(self):
        a = AddressSet.from_cidrs(["10.0.0.0/22"])
        b = AddressSet.from_cidrs(["10.0.1.0/24"])
        assert a.intersects(b)

    def test_subset_of_any(self):
        specific = AddressSet.from_cidrs(["10.0.0.0/24"])
        assert specific.is_subset_of(AddressSet.any())

    def test_any_is_not_subset_of_specific(self):
        any_set = AddressSet.any()
        specific = AddressSet.from_cidrs(["10.0.0.0/24"])
        assert not any_set.is_subset_of(specific)

    def test_subnet_is_subset_of_supernet(self):
        supernet = AddressSet.from_cidrs(["10.0.0.0/16"])
        subnet = AddressSet.from_cidrs(["10.0.1.0/24"])
        assert subnet.is_subset_of(supernet)
        assert not supernet.is_subset_of(subnet)

    def test_superset_of(self):
        supernet = AddressSet.from_cidrs(["10.0.0.0/16"])
        subnet = AddressSet.from_cidrs(["10.0.1.0/24"])
        assert supernet.is_superset_of(subnet)

    def test_intersection_returns_correct_cidrs(self):
        a = AddressSet.from_cidrs(["10.0.0.0/22"])
        b = AddressSet.from_cidrs(["10.0.1.0/24"])
        result = a.intersection(b)
        assert result.intersects(b)
        # The intersection should be contained in both
        assert result.is_subset_of(a)
        assert result.is_subset_of(b)

    def test_intersection_any_returns_other(self):
        any_set = AddressSet.any()
        specific = AddressSet.from_cidrs(["10.0.0.0/24"])
        result = any_set.intersection(specific)
        assert result == specific

    def test_is_any_propagated_from_entry(self):
        entries_with_any = [AddressEntry.any_sentinel(), AddressEntry.from_cidr("10.0.0.0/24")]
        addr_set = AddressSet(entries=entries_with_any)
        assert addr_set.is_any

    def test_equality(self):
        a = AddressSet.from_cidrs(["10.0.0.0/24"])
        b = AddressSet.from_cidrs(["10.0.0.0/24"])
        assert a == b

    def test_hash_consistent(self):
        a = AddressSet.from_cidrs(["10.0.0.0/24"])
        b = AddressSet.from_cidrs(["10.0.0.0/24"])
        assert hash(a) == hash(b)


# ---------------------------------------------------------------------------
# ServiceSet tests
# ---------------------------------------------------------------------------


class TestServiceSet:
    def test_any_intersects_everything(self):
        any_svc = ServiceSet.any()
        https = ServiceSet.tcp(PortRange(443, 443))
        assert any_svc.intersects(https)

    def test_different_protocols_do_not_intersect(self):
        tcp = ServiceSet.tcp(PortRange(80, 80))
        udp = ServiceSet.udp(PortRange(80, 80))
        assert not tcp.intersects(udp)

    def test_same_protocol_overlapping_ports_intersect(self):
        a = ServiceSet.tcp(PortRange(80, 100))
        b = ServiceSet.tcp(PortRange(90, 120))
        assert a.intersects(b)

    def test_same_protocol_disjoint_ports_no_intersect(self):
        a = ServiceSet.tcp(PortRange(80, 89))
        b = ServiceSet.tcp(PortRange(90, 99))
        assert not a.intersects(b)

    def test_tcp_any_ports_intersects_specific(self):
        any_tcp = ServiceSet(entries=[ServiceEntry(protocol="tcp", ports=None)])
        https = ServiceSet.tcp(PortRange(443, 443))
        assert any_tcp.intersects(https)

    def test_is_subset_of_any(self):
        https = ServiceSet.tcp(PortRange(443, 443))
        assert https.is_subset_of(ServiceSet.any())

    def test_any_not_subset_of_specific(self):
        assert not ServiceSet.any().is_subset_of(ServiceSet.tcp(PortRange(443, 443)))

    def test_port_subset_is_subset(self):
        https = ServiceSet.tcp(PortRange(443, 443))
        any_tcp = ServiceSet(entries=[ServiceEntry(protocol="tcp", ports=None)])
        assert https.is_subset_of(any_tcp)

    def test_intersection_tcp(self):
        a = ServiceSet.tcp(PortRange(80, 100))
        b = ServiceSet.tcp(PortRange(90, 120))
        result = a.intersection(b)
        assert result.intersects(a)
        assert result.intersects(b)

    def test_intersection_any_returns_other(self):
        https = ServiceSet.tcp(PortRange(443, 443))
        result = ServiceSet.any().intersection(https)
        assert result == https


# ---------------------------------------------------------------------------
# ZoneSet tests
# ---------------------------------------------------------------------------


class TestZoneSet:
    def test_any_intersects_everything(self):
        assert ZoneSet.any().intersects(ZoneSet.from_names(["trust"]))

    def test_same_zone_intersects(self):
        a = ZoneSet.from_names(["trust", "dmz"])
        b = ZoneSet.from_names(["trust"])
        assert a.intersects(b)

    def test_disjoint_zones_no_intersect(self):
        a = ZoneSet.from_names(["trust"])
        b = ZoneSet.from_names(["untrust"])
        assert not a.intersects(b)

    def test_subset_of_any(self):
        assert ZoneSet.from_names(["trust"]).is_subset_of(ZoneSet.any())

    def test_subset_relation(self):
        sub = ZoneSet.from_names(["trust"])
        sup = ZoneSet.from_names(["trust", "dmz"])
        assert sub.is_subset_of(sup)
        assert not sup.is_subset_of(sub)

    def test_intersection(self):
        a = ZoneSet.from_names(["trust", "dmz"])
        b = ZoneSet.from_names(["dmz", "untrust"])
        result = a.intersection(b)
        assert result.zones == {"dmz"}

    def test_equality(self):
        assert ZoneSet.from_names(["trust", "dmz"]) == ZoneSet.from_names(["dmz", "trust"])


# ---------------------------------------------------------------------------
# ApplicationSet tests
# ---------------------------------------------------------------------------


class TestApplicationSet:
    def test_defaults_to_any(self):
        app_set = ApplicationSet()
        assert app_set.is_any

    def test_any_intersects_everything(self):
        assert ApplicationSet.any().intersects(ApplicationSet.from_names(["ssl"]))

    def test_same_apps_intersect(self):
        a = ApplicationSet.from_names(["ssl", "http"])
        b = ApplicationSet.from_names(["ssl"])
        assert a.intersects(b)

    def test_disjoint_apps_no_intersect(self):
        a = ApplicationSet.from_names(["ssl"])
        b = ApplicationSet.from_names(["dns"])
        assert not a.intersects(b)

    def test_subset(self):
        sub = ApplicationSet.from_names(["ssl"])
        sup = ApplicationSet.from_names(["ssl", "http"])
        assert sub.is_subset_of(sup)


# ---------------------------------------------------------------------------
# Action enum tests
# ---------------------------------------------------------------------------


class TestAction:
    def test_blocking_actions_set(self):
        assert Action.DENY in BLOCKING_ACTIONS
        assert Action.DROP in BLOCKING_ACTIONS
        assert Action.REJECT in BLOCKING_ACTIONS
        assert Action.PERMIT not in BLOCKING_ACTIONS
        assert Action.LOG_ONLY not in BLOCKING_ACTIONS
