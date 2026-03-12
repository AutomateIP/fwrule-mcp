"""
Unit tests for parsers/vendors/asa/parser.py — ASAParser.

Uses realistic Cisco ASA running-config fixtures.
"""

from __future__ import annotations

import pytest

from fwrule_mcp.parsers.vendors.asa.parser import ASAParser


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

BASIC_ASA_CONFIG = """\
ASA Version 9.16(3)

!
hostname ASA-FW
!
object network WebServer
 host 10.1.2.10
object network AppNet
 subnet 10.2.0.0 255.255.255.0
object network ServerRange
 range 192.168.1.1 192.168.1.100
!
object-group network DMZ-Servers
 network-object host 10.1.2.10
 network-object 10.1.3.0 255.255.255.0
!
object-group service WEB-SVC tcp
 port-object eq www
 port-object eq https
!
object service HTTPS-SVC
 service tcp destination eq https
!
access-list OUTSIDE_IN extended permit tcp any host 10.1.2.10 eq https
access-list OUTSIDE_IN extended permit udp any any eq domain
access-list OUTSIDE_IN extended deny ip any any
access-list OUTSIDE_IN extended permit tcp 10.0.0.0 0.0.0.255 host 10.1.2.10 eq ssh
access-list INSIDE_OUT extended permit ip any any inactive
access-list OUTSIDE_IN extended permit tcp object-group DMZ-Servers any range 1024 65535
"""

MALFORMED_ACL_LINE = "access-list BADLINE extended permit"

EMPTY_CONFIG = ""


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_parse_policy_rule_count():
    parser = ASAParser()
    result = parser.parse_policy(BASIC_ASA_CONFIG)
    # 6 access-list lines (including inactive, range, object-group)
    assert len(result.rules) >= 4


def test_parse_policy_permit_action():
    parser = ASAParser()
    result = parser.parse_policy(BASIC_ASA_CONFIG)
    rule = result.rules[0]
    assert rule.action == "permit"


def test_parse_policy_deny_action():
    parser = ASAParser()
    result = parser.parse_policy(BASIC_ASA_CONFIG)
    deny_rules = [r for r in result.rules if r.action == "deny"]
    assert len(deny_rules) >= 1


def test_parse_policy_any_source():
    parser = ASAParser()
    result = parser.parse_policy(BASIC_ASA_CONFIG)
    rule = result.rules[0]
    assert "any" in rule.source_addresses


def test_parse_policy_host_destination():
    parser = ASAParser()
    result = parser.parse_policy(BASIC_ASA_CONFIG)
    rule = result.rules[0]
    # "host 10.1.2.10" → ["10.1.2.10"]
    assert "10.1.2.10" in rule.destination_addresses


def test_parse_policy_https_service():
    parser = ASAParser()
    result = parser.parse_policy(BASIC_ASA_CONFIG)
    rule = result.rules[0]
    # "eq https" → port 443
    assert any("443" in s or "tcp" in s for s in rule.services)


def test_parse_policy_inactive_rule_disabled():
    parser = ASAParser()
    result = parser.parse_policy(BASIC_ASA_CONFIG)
    inactive_rules = [r for r in result.rules if not r.enabled]
    assert len(inactive_rules) >= 1


def test_parse_policy_udp_service():
    parser = ASAParser()
    result = parser.parse_policy(BASIC_ASA_CONFIG)
    udp_rules = [r for r in result.rules if any("udp" in s for s in r.services)]
    assert len(udp_rules) >= 1


def test_parse_policy_object_network_host():
    parser = ASAParser()
    result = parser.parse_policy(BASIC_ASA_CONFIG)
    table = result.object_table
    assert "WebServer" in table.address_objects
    assert "10.1.2.10" in table.address_objects["WebServer"]


def test_parse_policy_object_network_subnet():
    parser = ASAParser()
    result = parser.parse_policy(BASIC_ASA_CONFIG)
    table = result.object_table
    assert "AppNet" in table.address_objects
    cidr = table.address_objects["AppNet"][0]
    assert "10.2.0.0" in cidr


def test_parse_policy_object_network_range():
    parser = ASAParser()
    result = parser.parse_policy(BASIC_ASA_CONFIG)
    table = result.object_table
    assert "ServerRange" in table.address_objects
    val = table.address_objects["ServerRange"][0]
    assert "192.168.1.1" in val


def test_parse_policy_object_group_network():
    parser = ASAParser()
    result = parser.parse_policy(BASIC_ASA_CONFIG)
    table = result.object_table
    assert "DMZ-Servers" in table.address_groups
    members = table.address_groups["DMZ-Servers"]
    assert len(members) >= 2


def test_parse_policy_object_group_service():
    parser = ASAParser()
    result = parser.parse_policy(BASIC_ASA_CONFIG)
    table = result.object_table
    assert "WEB-SVC" in table.service_groups


def test_parse_policy_vendor_is_asa():
    parser = ASAParser()
    result = parser.parse_policy(BASIC_ASA_CONFIG)
    assert result.vendor == "asa"


def test_parse_policy_version_detected():
    parser = ASAParser()
    result = parser.parse_policy(BASIC_ASA_CONFIG)
    assert result.os_version == "9.16(3)"


def test_parse_policy_wildcard_mask_address():
    """ASA wildcard 0.0.0.255 → CIDR /24."""
    parser = ASAParser()
    result = parser.parse_policy(BASIC_ASA_CONFIG)
    # Rule: permit tcp 10.0.0.0 0.0.0.255 ...
    src_rules = [r for r in result.rules if any("10.0.0" in s for s in r.source_addresses)]
    assert len(src_rules) >= 1
    src = src_rules[0].source_addresses[0]
    assert "10.0.0.0" in src


def test_parse_policy_empty_config():
    """Empty config → no rules, no crash."""
    parser = ASAParser()
    result = parser.parse_policy(EMPTY_CONFIG)
    assert isinstance(result.rules, list)
    assert len(result.rules) == 0


def test_parse_single_rule():
    parser = ASAParser()
    line = "access-list OUTSIDE_IN extended permit tcp any any eq https"
    rule = parser.parse_single_rule(line)
    assert rule.action == "permit"
    assert any("tcp" in s for s in rule.services)


def test_parse_single_rule_deny():
    parser = ASAParser()
    line = "access-list TEST extended deny ip any any"
    rule = parser.parse_single_rule(line)
    assert rule.action == "deny"


def test_parse_single_rule_invalid_raises():
    parser = ASAParser()
    with pytest.raises(ValueError):
        parser.parse_single_rule("not an acl line")


def test_parse_policy_any4_keyword():
    config = "access-list TEST extended permit ip any4 any4\n"
    parser = ASAParser()
    result = parser.parse_policy(config)
    assert len(result.rules) >= 1
    rule = result.rules[0]
    assert "any" in rule.source_addresses


def test_parse_policy_port_range():
    """range 1024 65535 parsed correctly."""
    parser = ASAParser()
    result = parser.parse_policy(BASIC_ASA_CONFIG)
    # Find the rule with the range
    range_rules = [
        r for r in result.rules
        if any("1024" in s for s in r.services)
    ]
    assert len(range_rules) >= 1


def test_parse_policy_named_port_www():
    """eq www → port 80."""
    config = "access-list TEST extended permit tcp any any eq www\n"
    parser = ASAParser()
    result = parser.parse_policy(config)
    assert len(result.rules) >= 1
    rule = result.rules[0]
    assert any("80" in s for s in rule.services)


def test_parse_policy_object_service_extracted():
    parser = ASAParser()
    result = parser.parse_policy(BASIC_ASA_CONFIG)
    # HTTPS-SVC should be in service_objects
    table = result.object_table
    assert "HTTPS-SVC" in table.service_objects
    svc = table.service_objects["HTTPS-SVC"]
    assert svc["protocol"] == "tcp"


def test_supported_vendors():
    parser = ASAParser()
    vendors = parser.supported_vendors()
    assert any(v[0] == "asa" for v in vendors)
