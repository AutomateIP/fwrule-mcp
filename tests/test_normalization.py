"""
Unit tests for normalization/resolver.py, normalization/normalizer.py,
and normalization/mappers.py.

Covers:
- Simple object resolution
- Recursive group expansion
- Circular reference detection
- Missing object warning
- Max depth protection
- Action mapping (all vendors)
- Well-known service resolution
- Address literal parsing (CIDR, host, range, FQDN, any)
- Service literal parsing (tcp/80, udp/53, icmp)
- Full normalizer pipeline with VendorRule input
"""

from __future__ import annotations

import pytest

from fwrule_mcp.parsers.base import ObjectTable, VendorRule
from fwrule_mcp.normalization.resolver import ObjectResolver, ResolutionWarning
from fwrule_mcp.normalization.normalizer import PolicyNormalizer
from fwrule_mcp.normalization.mappers import (
    ACTION_MAP,
    WELL_KNOWN_SERVICES,
    map_action,
    parse_address_literal,
    parse_service_literal,
    wildcard_to_prefix,
)
from fwrule_mcp.models.common import Action, AddressType


# ---------------------------------------------------------------------------
# mappers.py — map_action
# ---------------------------------------------------------------------------


def test_map_action_allow():
    assert map_action("allow") == Action.PERMIT


def test_map_action_permit():
    assert map_action("permit") == Action.PERMIT


def test_map_action_accept():
    assert map_action("accept") == Action.PERMIT


def test_map_action_deny():
    assert map_action("deny") == Action.DENY


def test_map_action_drop():
    assert map_action("drop") == Action.DROP


def test_map_action_reject():
    assert map_action("reject") == Action.REJECT


def test_map_action_block():
    assert map_action("block") == Action.DENY


def test_map_action_trust():
    assert map_action("trust") == Action.PERMIT


def test_map_action_monitor():
    assert map_action("monitor") == Action.LOG_ONLY


def test_map_action_case_insensitive():
    assert map_action("ALLOW") == Action.PERMIT
    assert map_action("DENY") == Action.DENY


def test_map_action_unknown():
    result = map_action("something_crazy")
    assert result == Action.UNKNOWN


# ---------------------------------------------------------------------------
# mappers.py — parse_address_literal
# ---------------------------------------------------------------------------


def test_parse_address_literal_cidr_ipv4():
    entry = parse_address_literal("10.0.0.0/24")
    assert entry is not None
    assert entry.addr_type == AddressType.CIDR


def test_parse_address_literal_host_cidr():
    entry = parse_address_literal("10.0.0.1/32")
    assert entry is not None
    assert entry.addr_type == AddressType.HOST


def test_parse_address_literal_bare_host():
    entry = parse_address_literal("192.168.1.1")
    assert entry is not None
    assert entry.addr_type == AddressType.HOST


def test_parse_address_literal_any():
    entry = parse_address_literal("any")
    assert entry is not None
    assert entry.addr_type == AddressType.ANY


def test_parse_address_literal_any4():
    entry = parse_address_literal("any4")
    assert entry is not None
    assert entry.addr_type == AddressType.ANY


def test_parse_address_literal_zero_cidr():
    entry = parse_address_literal("0.0.0.0/0")
    assert entry is not None
    assert entry.addr_type == AddressType.ANY


def test_parse_address_literal_ip_range():
    entry = parse_address_literal("10.0.0.1-10.0.0.100")
    assert entry is not None
    assert entry.addr_type == AddressType.RANGE


def test_parse_address_literal_fqdn():
    entry = parse_address_literal("www.example.com")
    assert entry is not None
    assert entry.addr_type == AddressType.FQDN


def test_parse_address_literal_cisco_host_keyword():
    entry = parse_address_literal("host 10.0.0.1")
    assert entry is not None
    assert entry.addr_type == AddressType.HOST


def test_parse_address_literal_wildcard_mask():
    entry = parse_address_literal("10.0.0.0 0.0.0.255")
    assert entry is not None
    # 0.0.0.255 wildcard = /24
    assert entry.addr_type in (AddressType.CIDR, AddressType.HOST)


def test_parse_address_literal_invalid_returns_none():
    assert parse_address_literal("not_an_ip_or_cidr_or_fqdn") is None


def test_parse_address_literal_empty_returns_none():
    assert parse_address_literal("") is None


# ---------------------------------------------------------------------------
# mappers.py — parse_service_literal
# ---------------------------------------------------------------------------


def test_parse_service_literal_tcp_port():
    entry = parse_service_literal("tcp/80")
    assert entry is not None
    assert entry.protocol == "tcp"
    assert entry.ports is not None
    assert entry.ports[0].start == 80


def test_parse_service_literal_udp_port():
    entry = parse_service_literal("udp/53")
    assert entry is not None
    assert entry.protocol == "udp"
    assert entry.ports[0].start == 53


def test_parse_service_literal_tcp_range():
    entry = parse_service_literal("tcp/8080-8090")
    assert entry is not None
    assert entry.protocol == "tcp"
    assert entry.ports[0].start == 8080
    assert entry.ports[0].end == 8090


def test_parse_service_literal_any():
    entry = parse_service_literal("any")
    assert entry is not None
    assert entry.protocol == "any"


def test_parse_service_literal_icmp():
    entry = parse_service_literal("icmp")
    assert entry is not None
    assert entry.protocol == "icmp"


def test_parse_service_literal_icmp_type():
    entry = parse_service_literal("icmp/8")
    assert entry is not None
    assert entry.protocol == "icmp"
    assert entry.icmp_type == 8


def test_parse_service_literal_icmpv6():
    entry = parse_service_literal("icmpv6")
    assert entry is not None
    assert entry.protocol == "icmpv6"


def test_parse_service_literal_well_known_http():
    entry = parse_service_literal("http")
    assert entry is not None
    assert entry.protocol == "tcp"
    assert entry.ports[0].start == 80


def test_parse_service_literal_well_known_https():
    entry = parse_service_literal("https")
    assert entry is not None
    assert entry.ports[0].start == 443


def test_parse_service_literal_tcp_any_port():
    entry = parse_service_literal("tcp")
    assert entry is not None
    assert entry.protocol == "tcp"
    # ports should be None (any port)
    assert entry.ports is None


# ---------------------------------------------------------------------------
# mappers.py — wildcard_to_prefix
# ---------------------------------------------------------------------------


def test_wildcard_to_prefix_slash24():
    result = wildcard_to_prefix("10.0.0.0", "0.0.0.255")
    assert result == "10.0.0.0/24"


def test_wildcard_to_prefix_slash8():
    result = wildcard_to_prefix("10.0.0.0", "0.255.255.255")
    assert result == "10.0.0.0/8"


def test_wildcard_to_prefix_non_contiguous_returns_none():
    result = wildcard_to_prefix("10.0.0.0", "0.0.0.254")
    assert result is None


# ---------------------------------------------------------------------------
# resolver.py — simple object resolution
# ---------------------------------------------------------------------------


def _make_table(**kwargs) -> ObjectTable:
    table = ObjectTable()
    for k, v in kwargs.items():
        setattr(table, k, v)
    return table


def test_resolve_address_literal_cidr():
    table = ObjectTable()
    resolver = ObjectResolver(table)
    result = resolver.resolve_address("10.0.0.0/24")
    assert result == ["10.0.0.0/24"]


def test_resolve_address_any_keyword():
    table = ObjectTable()
    resolver = ObjectResolver(table)
    result = resolver.resolve_address("any")
    assert result == ["any"]


def test_resolve_address_named_object():
    table = ObjectTable()
    table.address_objects["WebServers"] = ["10.1.2.0/24"]
    resolver = ObjectResolver(table)
    result = resolver.resolve_address("WebServers")
    assert result == ["10.1.2.0/24"]


def test_resolve_address_group_expansion():
    table = ObjectTable()
    table.address_objects["Server1"] = ["10.0.0.1/32"]
    table.address_objects["Server2"] = ["10.0.0.2/32"]
    table.address_groups["AppServers"] = ["Server1", "Server2"]
    resolver = ObjectResolver(table)
    result = resolver.resolve_address("AppServers")
    assert "10.0.0.1/32" in result
    assert "10.0.0.2/32" in result


def test_resolve_address_recursive_group():
    """Nested group expansion: GroupA → GroupB → 10.0.0.0/24."""
    table = ObjectTable()
    table.address_objects["Host"] = ["10.0.0.0/24"]
    table.address_groups["Inner"] = ["Host"]
    table.address_groups["Outer"] = ["Inner"]
    resolver = ObjectResolver(table)
    result = resolver.resolve_address("Outer")
    assert "10.0.0.0/24" in result


def test_resolve_address_missing_object_emits_warning():
    table = ObjectTable()
    resolver = ObjectResolver(table)
    result = resolver.resolve_address("NonExistentObject")
    assert result == []
    assert any(w.warning_type == "unresolvable" for w in resolver.warnings)


def test_resolve_address_circular_reference_detected():
    table = ObjectTable()
    table.address_groups["GroupA"] = ["GroupB"]
    table.address_groups["GroupB"] = ["GroupA"]
    resolver = ObjectResolver(table)
    result = resolver.resolve_address("GroupA")
    # Should not raise; should emit circular warning
    assert any(w.warning_type == "circular" for w in resolver.warnings)


def test_resolve_address_cache_hit():
    """Second call for same reference uses cache."""
    table = ObjectTable()
    table.address_objects["Host"] = ["10.0.0.1/32"]
    resolver = ObjectResolver(table)
    r1 = resolver.resolve_address("Host")
    r2 = resolver.resolve_address("Host")
    assert r1 == r2


# ---------------------------------------------------------------------------
# resolver.py — service resolution
# ---------------------------------------------------------------------------


def test_resolve_service_literal_tcp():
    table = ObjectTable()
    resolver = ObjectResolver(table)
    result = resolver.resolve_service("tcp/443")
    assert len(result) == 1
    assert result[0]["protocol"] == "tcp"


def test_resolve_service_any():
    table = ObjectTable()
    resolver = ObjectResolver(table)
    result = resolver.resolve_service("any")
    assert result[0]["protocol"] == "any"


def test_resolve_service_well_known_name():
    table = ObjectTable()
    resolver = ObjectResolver(table)
    result = resolver.resolve_service("https")
    assert result[0]["protocol"] == "tcp"
    assert result[0]["ports"] == "443"


def test_resolve_service_named_object():
    table = ObjectTable()
    table.service_objects["HTTPS"] = {"protocol": "tcp", "ports": "443"}
    resolver = ObjectResolver(table)
    result = resolver.resolve_service("HTTPS")
    assert result[0]["protocol"] == "tcp"


def test_resolve_service_group():
    table = ObjectTable()
    table.service_objects["HTTP"] = {"protocol": "tcp", "ports": "80"}
    table.service_objects["HTTPS"] = {"protocol": "tcp", "ports": "443"}
    table.service_groups["WEB"] = ["HTTP", "HTTPS"]
    resolver = ObjectResolver(table)
    result = resolver.resolve_service("WEB")
    protocols = {d["protocol"] for d in result}
    assert "tcp" in protocols


def test_resolve_service_missing_emits_warning():
    table = ObjectTable()
    resolver = ObjectResolver(table)
    result = resolver.resolve_service("NONEXISTENT")
    assert result == []
    assert any(w.warning_type == "unresolvable" for w in resolver.warnings)


# ---------------------------------------------------------------------------
# resolver.py — max depth protection
# ---------------------------------------------------------------------------


def test_max_depth_protection():
    """Deeply nested groups beyond MAX_DEPTH emit depth_exceeded warning."""
    table = ObjectTable()
    # Create a chain of 60 groups
    for i in range(60):
        table.address_groups[f"G{i}"] = [f"G{i+1}"]
    table.address_objects["G60"] = ["10.0.0.0/24"]
    resolver = ObjectResolver(table)
    result = resolver.resolve_address("G0")
    # Should have a depth_exceeded warning
    assert any(w.warning_type == "depth_exceeded" for w in resolver.warnings)


# ---------------------------------------------------------------------------
# normalizer.py — full pipeline with VendorRule
# ---------------------------------------------------------------------------


def _make_vendor_rule(
    name: str = "test-rule",
    action: str = "permit",
    src_addrs: list[str] | None = None,
    dst_addrs: list[str] | None = None,
    services: list[str] | None = None,
    src_zones: list[str] | None = None,
    dst_zones: list[str] | None = None,
    apps: list[str] | None = None,
    enabled: bool = True,
    position: int = 0,
) -> VendorRule:
    return VendorRule(
        name=name,
        position=position,
        enabled=enabled,
        source_zones=src_zones or ["any"],
        destination_zones=dst_zones or ["any"],
        source_addresses=src_addrs or ["any"],
        destination_addresses=dst_addrs or ["any"],
        services=services or ["any"],
        applications=apps or ["any"],
        action=action,
    )


def test_normalize_rule_basic():
    """VendorRule with literals normalizes to NormalizedRule."""
    from fwrule_mcp.parsers.base import ParsedPolicy
    vr = _make_vendor_rule(
        src_addrs=["10.0.0.0/24"],
        dst_addrs=["192.168.1.0/24"],
        services=["tcp/443"],
        src_zones=["trust"],
        dst_zones=["untrust"],
        action="permit",
    )
    policy = ParsedPolicy(rules=[vr], object_table=ObjectTable(), vendor="panos")
    normalizer = PolicyNormalizer()
    rules = normalizer.normalize_policy(policy)
    assert len(rules) == 1
    rule = rules[0]
    assert rule.position == 1
    assert rule.action == Action.PERMIT
    assert not rule.match.source_zones.is_any
    assert not rule.match.source_addresses.is_any
    assert not rule.match.services.is_any


def test_normalize_rule_any_addresses():
    """any addresses → AddressSet.any()."""
    from fwrule_mcp.parsers.base import ParsedPolicy
    vr = _make_vendor_rule(src_addrs=["any"], dst_addrs=["any"])
    policy = ParsedPolicy(rules=[vr], object_table=ObjectTable(), vendor="panos")
    normalizer = PolicyNormalizer()
    rules = normalizer.normalize_policy(policy)
    assert rules[0].match.source_addresses.is_any
    assert rules[0].match.destination_addresses.is_any


def test_normalize_rule_with_named_object():
    """Named object resolved through ObjectTable."""
    from fwrule_mcp.parsers.base import ParsedPolicy
    table = ObjectTable()
    table.address_objects["WebServers"] = ["10.1.2.0/24"]
    vr = _make_vendor_rule(dst_addrs=["WebServers"])
    policy = ParsedPolicy(rules=[vr], object_table=table, vendor="panos")
    normalizer = PolicyNormalizer()
    rules = normalizer.normalize_policy(policy)
    assert not rules[0].match.destination_addresses.is_any


def test_normalize_rule_disabled():
    """Disabled VendorRule → enabled=False in NormalizedRule."""
    from fwrule_mcp.parsers.base import ParsedPolicy
    vr = _make_vendor_rule(enabled=False)
    policy = ParsedPolicy(rules=[vr], object_table=ObjectTable(), vendor="panos")
    normalizer = PolicyNormalizer()
    rules = normalizer.normalize_policy(policy)
    assert rules[0].enabled is False


def test_normalize_candidate():
    """normalize_candidate returns NormalizedCandidate."""
    from fwrule_mcp.normalization.resolver import ObjectResolver
    vr = _make_vendor_rule(
        name="candidate",
        src_addrs=["10.0.0.0/24"],
        services=["tcp/80"],
        action="deny",
    )
    table = ObjectTable()
    resolver = ObjectResolver(table)
    normalizer = PolicyNormalizer()
    candidate = normalizer.normalize_candidate(vr, resolver, intended_position=3)
    assert candidate.rule_id == "candidate"
    assert candidate.intended_position == 3
    assert candidate.action == Action.DENY


def test_normalize_candidate_unresolvable_references_recorded():
    """Unresolvable references are recorded in metadata."""
    from fwrule_mcp.normalization.resolver import ObjectResolver
    vr = _make_vendor_rule(dst_addrs=["UnknownGroup"])
    table = ObjectTable()
    resolver = ObjectResolver(table)
    normalizer = PolicyNormalizer()
    candidate = normalizer.normalize_candidate(vr, resolver)
    assert "UnknownGroup" in candidate.metadata.unresolvable_references


def test_normalize_rule_negate_flags_in_vendor_tags():
    """negate_source/negate_destination are recorded in vendor_tags."""
    from fwrule_mcp.parsers.base import ParsedPolicy
    vr = _make_vendor_rule()
    vr.negate_source = True
    vr.negate_destination = True
    policy = ParsedPolicy(rules=[vr], object_table=ObjectTable(), vendor="panos")
    normalizer = PolicyNormalizer()
    rules = normalizer.normalize_policy(policy)
    assert rules[0].metadata.vendor_tags.get("negate_source") is True
    assert rules[0].metadata.vendor_tags.get("negate_destination") is True


def test_normalize_position_one_based():
    """VendorRule.position 0-based → NormalizedRule.position 1-based."""
    from fwrule_mcp.parsers.base import ParsedPolicy
    vr = _make_vendor_rule(position=0)
    policy = ParsedPolicy(rules=[vr], object_table=ObjectTable(), vendor="panos")
    normalizer = PolicyNormalizer()
    rules = normalizer.normalize_policy(policy)
    assert rules[0].position == 1


def test_normalize_application_any():
    """any application → ApplicationSet.any()."""
    from fwrule_mcp.parsers.base import ParsedPolicy
    vr = _make_vendor_rule(apps=["any"])
    policy = ParsedPolicy(rules=[vr], object_table=ObjectTable(), vendor="panos")
    normalizer = PolicyNormalizer()
    rules = normalizer.normalize_policy(policy)
    assert rules[0].match.applications.is_any
