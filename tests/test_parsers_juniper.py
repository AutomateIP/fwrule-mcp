"""
Unit tests for parsers/vendors/juniper/parser.py — JuniperParser.

Uses realistic Juniper SRX set-command format fixtures.
"""

from __future__ import annotations

import pytest

from fwrule_mcp.parsers.vendors.juniper.parser import JuniperParser


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

BASIC_JUNIPER_CONFIG = """\
set version 20.4R1.12
set security address-book global address WebServer 10.1.2.10/32
set security address-book global address AppNet 10.2.0.0/24
set security address-book global address-set WebGroup address WebServer
set security address-book global address-set WebGroup address AppNet
set applications application HTTPS protocol tcp
set applications application HTTPS destination-port 443
set applications application DNS protocol udp
set applications application DNS destination-port 53
set applications application-set WEB-APPS application HTTPS
set applications application-set WEB-APPS application DNS
set security policies from-zone trust to-zone untrust policy allow-https match source-address any
set security policies from-zone trust to-zone untrust policy allow-https match destination-address WebServer
set security policies from-zone trust to-zone untrust policy allow-https match application HTTPS
set security policies from-zone trust to-zone untrust policy allow-https then permit
set security policies from-zone trust to-zone untrust policy deny-all match source-address any
set security policies from-zone trust to-zone untrust policy deny-all match destination-address any
set security policies from-zone trust to-zone untrust policy deny-all match application any
set security policies from-zone trust to-zone untrust policy deny-all then deny
set security policies from-zone dmz to-zone trust policy allow-dns match source-address AppNet
set security policies from-zone dmz to-zone trust policy allow-dns match destination-address any
set security policies from-zone dmz to-zone trust policy allow-dns match application DNS
set security policies from-zone dmz to-zone trust policy allow-dns then permit
set security policies from-zone untrust to-zone trust policy reject-bad match source-address any
set security policies from-zone untrust to-zone trust policy reject-bad match destination-address any
set security policies from-zone untrust to-zone trust policy reject-bad match application any
set security policies from-zone untrust to-zone trust policy reject-bad then reject
"""

CANDIDATE_SET = """\
set security policies from-zone trust to-zone untrust policy new-rule match source-address AppNet
set security policies from-zone trust to-zone untrust policy new-rule match destination-address WebServer
set security policies from-zone trust to-zone untrust policy new-rule match application HTTPS
set security policies from-zone trust to-zone untrust policy new-rule then permit
"""

EMPTY_CONFIG = ""

COMMENT_ONLY = "# This is a comment\n# Another comment\n"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_parse_policy_rule_count():
    parser = JuniperParser()
    result = parser.parse_policy(BASIC_JUNIPER_CONFIG)
    assert len(result.rules) == 4


def test_parse_policy_rule_names():
    parser = JuniperParser()
    result = parser.parse_policy(BASIC_JUNIPER_CONFIG)
    names = [r.name for r in result.rules]
    assert "allow-https" in names
    assert "deny-all" in names
    assert "allow-dns" in names
    assert "reject-bad" in names


def test_parse_policy_permit_action():
    parser = JuniperParser()
    result = parser.parse_policy(BASIC_JUNIPER_CONFIG)
    rule = next(r for r in result.rules if r.name == "allow-https")
    assert rule.action == "permit"


def test_parse_policy_deny_action():
    parser = JuniperParser()
    result = parser.parse_policy(BASIC_JUNIPER_CONFIG)
    rule = next(r for r in result.rules if r.name == "deny-all")
    assert rule.action == "deny"


def test_parse_policy_reject_action():
    parser = JuniperParser()
    result = parser.parse_policy(BASIC_JUNIPER_CONFIG)
    rule = next(r for r in result.rules if r.name == "reject-bad")
    assert rule.action == "reject"


def test_parse_policy_zone_preservation():
    """Zone-based addressing: from-zone/to-zone populate source/destination zones."""
    parser = JuniperParser()
    result = parser.parse_policy(BASIC_JUNIPER_CONFIG)
    rule = next(r for r in result.rules if r.name == "allow-https")
    assert "trust" in rule.source_zones
    assert "untrust" in rule.destination_zones


def test_parse_policy_zone_dmz_to_trust():
    parser = JuniperParser()
    result = parser.parse_policy(BASIC_JUNIPER_CONFIG)
    rule = next(r for r in result.rules if r.name == "allow-dns")
    assert "dmz" in rule.source_zones
    assert "trust" in rule.destination_zones


def test_parse_policy_source_address():
    parser = JuniperParser()
    result = parser.parse_policy(BASIC_JUNIPER_CONFIG)
    rule = next(r for r in result.rules if r.name == "allow-dns")
    assert "AppNet" in rule.source_addresses


def test_parse_policy_destination_address():
    parser = JuniperParser()
    result = parser.parse_policy(BASIC_JUNIPER_CONFIG)
    rule = next(r for r in result.rules if r.name == "allow-https")
    assert "WebServer" in rule.destination_addresses


def test_parse_policy_any_address():
    parser = JuniperParser()
    result = parser.parse_policy(BASIC_JUNIPER_CONFIG)
    rule = next(r for r in result.rules if r.name == "deny-all")
    assert "any" in rule.source_addresses
    assert "any" in rule.destination_addresses


def test_parse_policy_application_extracted():
    parser = JuniperParser()
    result = parser.parse_policy(BASIC_JUNIPER_CONFIG)
    rule = next(r for r in result.rules if r.name == "allow-https")
    assert "HTTPS" in rule.applications


def test_parse_policy_address_object_extracted():
    parser = JuniperParser()
    result = parser.parse_policy(BASIC_JUNIPER_CONFIG)
    table = result.object_table
    assert "WebServer" in table.address_objects
    assert "10.1.2.10/32" in table.address_objects["WebServer"]


def test_parse_policy_address_object_network():
    parser = JuniperParser()
    result = parser.parse_policy(BASIC_JUNIPER_CONFIG)
    table = result.object_table
    assert "AppNet" in table.address_objects
    assert "10.2.0.0/24" in table.address_objects["AppNet"]


def test_parse_policy_address_set_extracted():
    parser = JuniperParser()
    result = parser.parse_policy(BASIC_JUNIPER_CONFIG)
    table = result.object_table
    assert "WebGroup" in table.address_groups
    members = table.address_groups["WebGroup"]
    assert "WebServer" in members
    assert "AppNet" in members


def test_parse_policy_application_definition():
    """Custom HTTPS application → service_objects entry."""
    parser = JuniperParser()
    result = parser.parse_policy(BASIC_JUNIPER_CONFIG)
    table = result.object_table
    assert "HTTPS" in table.service_objects
    svc = table.service_objects["HTTPS"]
    assert svc.get("protocol") == "tcp"


def test_parse_policy_application_set_expanded():
    """Application-set WEB-APPS → service_groups entry."""
    parser = JuniperParser()
    result = parser.parse_policy(BASIC_JUNIPER_CONFIG)
    table = result.object_table
    assert "WEB-APPS" in table.service_groups
    members = table.service_groups["WEB-APPS"]
    assert "HTTPS" in members
    assert "DNS" in members


def test_parse_policy_vendor_is_juniper():
    parser = JuniperParser()
    result = parser.parse_policy(BASIC_JUNIPER_CONFIG)
    assert result.vendor == "juniper"


def test_parse_policy_version_detected():
    parser = JuniperParser()
    result = parser.parse_policy(BASIC_JUNIPER_CONFIG)
    assert result.os_version == "20.4R1.12"


def test_parse_policy_empty_config():
    parser = JuniperParser()
    result = parser.parse_policy(EMPTY_CONFIG)
    assert isinstance(result.rules, list)
    assert len(result.rules) == 0


def test_parse_policy_comments_skipped():
    parser = JuniperParser()
    result = parser.parse_policy(COMMENT_ONLY)
    assert len(result.rules) == 0


def test_parse_single_rule():
    parser = JuniperParser()
    rule = parser.parse_single_rule(CANDIDATE_SET)
    assert rule.name == "new-rule"
    assert rule.action == "permit"
    assert "AppNet" in rule.source_addresses
    assert "WebServer" in rule.destination_addresses


def test_parse_single_rule_application():
    parser = JuniperParser()
    rule = parser.parse_single_rule(CANDIDATE_SET)
    assert "HTTPS" in rule.applications


def test_parse_single_rule_zones():
    parser = JuniperParser()
    rule = parser.parse_single_rule(CANDIDATE_SET)
    assert "trust" in rule.source_zones
    assert "untrust" in rule.destination_zones


def test_parse_single_rule_no_policy_lines_raises():
    parser = JuniperParser()
    with pytest.raises(ValueError):
        parser.parse_single_rule("set version 20.4R1.12")


def test_parse_policy_rule_ordering_preserved():
    """Rules should be returned in config order."""
    parser = JuniperParser()
    result = parser.parse_policy(BASIC_JUNIPER_CONFIG)
    names = [r.name for r in result.rules]
    # allow-https comes before deny-all in the config
    assert names.index("allow-https") < names.index("deny-all")


def test_parse_policy_vendor_tags_include_zones():
    parser = JuniperParser()
    result = parser.parse_policy(BASIC_JUNIPER_CONFIG)
    rule = next(r for r in result.rules if r.name == "allow-https")
    assert rule.vendor_tags.get("from_zone") == "trust"
    assert rule.vendor_tags.get("to_zone") == "untrust"


def test_supported_vendors():
    parser = JuniperParser()
    vendors = parser.supported_vendors()
    assert any(v[0] == "juniper" for v in vendors)
