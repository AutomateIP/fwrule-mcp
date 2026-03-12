"""
Unit tests for parsers/vendors/checkpoint/parser.py — CheckPointParser.

Uses realistic Check Point JSON package export fixtures.
"""

from __future__ import annotations

import json
import pytest

from fwrule_mcp.parsers.vendors.checkpoint.parser import CheckPointParser, CP_ANY_UID


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

CHECKPOINT_POLICY_JSON = json.dumps({
    "objects-dictionary": [
        {
            "uid": "host-001",
            "name": "WebServer",
            "type": "host",
            "ipv4-address": "10.1.2.10"
        },
        {
            "uid": "net-001",
            "name": "AppNet",
            "type": "network",
            "subnet4": "10.2.0.0",
            "mask-length4": "24"
        },
        {
            "uid": "range-001",
            "name": "ServerRange",
            "type": "address-range",
            "ipv4-address-first": "192.168.1.1",
            "ipv4-address-last": "192.168.1.100"
        },
        {
            "uid": "grp-001",
            "name": "WebGroup",
            "type": "group",
            "members": [
                {"uid": "host-001", "name": "WebServer"},
                {"uid": "net-001", "name": "AppNet"}
            ]
        },
        {
            "uid": "svc-001",
            "name": "HTTPS",
            "type": "service-tcp",
            "port": "443"
        },
        {
            "uid": "svc-002",
            "name": "DNS",
            "type": "service-udp",
            "port": "53"
        },
        {
            "uid": "svcgrp-001",
            "name": "WEB-SERVICES",
            "type": "service-group",
            "members": [
                {"uid": "svc-001", "name": "HTTPS"},
                {"uid": "svc-002", "name": "DNS"}
            ]
        },
        {
            "uid": "icmp-001",
            "name": "ICMP-Echo",
            "type": "service-icmp",
            "icmp-type": 8,
            "icmp-code": 0
        },
    ],
    "rulebase": [
        {
            "type": "access-rule",
            "uid": "rule-001",
            "name": "allow-https",
            "action": {"name": "Accept"},
            "enabled": True,
            "source": [{"uid": "97aeb369-9aea-11d5-bd16-0090272ccb30", "name": "Any"}],
            "destination": [{"uid": "host-001", "name": "WebServer"}],
            "service": [{"uid": "svc-001", "name": "HTTPS"}],
            "from-zone": {"name": "trust"},
            "to-zone": {"name": "untrust"},
            "comments": "Allow HTTPS to web server",
        },
        {
            "type": "access-rule",
            "uid": "rule-002",
            "name": "drop-all",
            "action": {"name": "Drop"},
            "enabled": True,
            "source": [{"name": "Any"}],
            "destination": [{"name": "Any"}],
            "service": [{"name": "Any"}],
        },
        {
            "type": "access-rule",
            "uid": "rule-003",
            "name": "reject-specific",
            "action": {"name": "Reject"},
            "enabled": False,
            "source": [{"uid": "net-001", "name": "AppNet"}],
            "destination": [{"uid": "net-001", "name": "AppNet"}],
            "service": [{"uid": "svc-002", "name": "DNS"}],
            "source-negate": True,
        },
        {
            "type": "access-section",
            "uid": "section-001",
            "name": "Management Section",
            "rulebase": [
                {
                    "type": "access-rule",
                    "uid": "rule-004",
                    "name": "nested-rule",
                    "action": {"name": "Accept"},
                    "enabled": True,
                    "source": [{"uid": "net-001", "name": "AppNet"}],
                    "destination": [{"name": "Any"}],
                    "service": [{"uid": "svc-001", "name": "HTTPS"}],
                }
            ]
        }
    ]
})

CANDIDATE_RULE_JSON = json.dumps({
    "type": "access-rule",
    "uid": "cand-001",
    "name": "new-permit",
    "action": {"name": "Accept"},
    "enabled": True,
    "source": [{"name": "AppNet"}],
    "destination": [{"name": "WebServer"}],
    "service": [{"name": "HTTPS"}],
})


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_parse_policy_rule_count():
    parser = CheckPointParser()
    result = parser.parse_policy(CHECKPOINT_POLICY_JSON)
    # 3 top-level rules + 1 nested in section = 4 total
    assert len(result.rules) == 4


def test_parse_policy_accept_action():
    parser = CheckPointParser()
    result = parser.parse_policy(CHECKPOINT_POLICY_JSON)
    rule = next(r for r in result.rules if r.name == "allow-https")
    assert rule.action == "permit"


def test_parse_policy_drop_action():
    parser = CheckPointParser()
    result = parser.parse_policy(CHECKPOINT_POLICY_JSON)
    rule = next(r for r in result.rules if r.name == "drop-all")
    assert rule.action == "drop"


def test_parse_policy_reject_action():
    parser = CheckPointParser()
    result = parser.parse_policy(CHECKPOINT_POLICY_JSON)
    rule = next(r for r in result.rules if r.name == "reject-specific")
    assert rule.action == "reject"


def test_parse_policy_any_source():
    """Source 'Any' or CP_ANY_UID → ['any']."""
    parser = CheckPointParser()
    result = parser.parse_policy(CHECKPOINT_POLICY_JSON)
    rule = next(r for r in result.rules if r.name == "allow-https")
    assert "any" in rule.source_addresses


def test_parse_policy_specific_destination():
    parser = CheckPointParser()
    result = parser.parse_policy(CHECKPOINT_POLICY_JSON)
    rule = next(r for r in result.rules if r.name == "allow-https")
    assert "WebServer" in rule.destination_addresses


def test_parse_policy_service_resolved():
    parser = CheckPointParser()
    result = parser.parse_policy(CHECKPOINT_POLICY_JSON)
    rule = next(r for r in result.rules if r.name == "allow-https")
    assert "HTTPS" in rule.services


def test_parse_policy_zone_from():
    parser = CheckPointParser()
    result = parser.parse_policy(CHECKPOINT_POLICY_JSON)
    rule = next(r for r in result.rules if r.name == "allow-https")
    assert "trust" in rule.source_zones


def test_parse_policy_zone_to():
    parser = CheckPointParser()
    result = parser.parse_policy(CHECKPOINT_POLICY_JSON)
    rule = next(r for r in result.rules if r.name == "allow-https")
    assert "untrust" in rule.destination_zones


def test_parse_policy_disabled_rule():
    parser = CheckPointParser()
    result = parser.parse_policy(CHECKPOINT_POLICY_JSON)
    rule = next(r for r in result.rules if r.name == "reject-specific")
    assert rule.enabled is False


def test_parse_policy_negate_source():
    parser = CheckPointParser()
    result = parser.parse_policy(CHECKPOINT_POLICY_JSON)
    rule = next(r for r in result.rules if r.name == "reject-specific")
    assert rule.negate_source is True


def test_parse_policy_description():
    parser = CheckPointParser()
    result = parser.parse_policy(CHECKPOINT_POLICY_JSON)
    rule = next(r for r in result.rules if r.name == "allow-https")
    assert "HTTPS" in rule.description


def test_parse_policy_nested_section_flattened():
    parser = CheckPointParser()
    result = parser.parse_policy(CHECKPOINT_POLICY_JSON)
    names = [r.name for r in result.rules]
    assert "nested-rule" in names


def test_parse_policy_host_object_in_table():
    parser = CheckPointParser()
    result = parser.parse_policy(CHECKPOINT_POLICY_JSON)
    table = result.object_table
    assert "WebServer" in table.address_objects
    assert table.address_objects["WebServer"] == ["10.1.2.10"]


def test_parse_policy_network_object_in_table():
    parser = CheckPointParser()
    result = parser.parse_policy(CHECKPOINT_POLICY_JSON)
    table = result.object_table
    assert "AppNet" in table.address_objects
    assert "10.2.0.0/24" in table.address_objects["AppNet"]


def test_parse_policy_range_object_in_table():
    parser = CheckPointParser()
    result = parser.parse_policy(CHECKPOINT_POLICY_JSON)
    table = result.object_table
    assert "ServerRange" in table.address_objects
    val = table.address_objects["ServerRange"][0]
    assert "192.168.1.1" in val


def test_parse_policy_group_in_table():
    parser = CheckPointParser()
    result = parser.parse_policy(CHECKPOINT_POLICY_JSON)
    table = result.object_table
    assert "WebGroup" in table.address_groups
    members = table.address_groups["WebGroup"]
    assert "WebServer" in members
    assert "AppNet" in members


def test_parse_policy_tcp_service_in_table():
    parser = CheckPointParser()
    result = parser.parse_policy(CHECKPOINT_POLICY_JSON)
    table = result.object_table
    assert "HTTPS" in table.service_objects
    svc = table.service_objects["HTTPS"]
    assert svc["protocol"] == "tcp"
    assert svc["ports"] == "443"


def test_parse_policy_udp_service_in_table():
    parser = CheckPointParser()
    result = parser.parse_policy(CHECKPOINT_POLICY_JSON)
    table = result.object_table
    assert "DNS" in table.service_objects
    svc = table.service_objects["DNS"]
    assert svc["protocol"] == "udp"


def test_parse_policy_service_group_in_table():
    parser = CheckPointParser()
    result = parser.parse_policy(CHECKPOINT_POLICY_JSON)
    table = result.object_table
    assert "WEB-SERVICES" in table.service_groups


def test_parse_policy_icmp_service_in_table():
    parser = CheckPointParser()
    result = parser.parse_policy(CHECKPOINT_POLICY_JSON)
    table = result.object_table
    assert "ICMP-Echo" in table.service_objects
    svc = table.service_objects["ICMP-Echo"]
    assert svc["protocol"] == "icmp"
    assert svc["icmp_type"] == "8"


def test_parse_policy_vendor_is_checkpoint():
    parser = CheckPointParser()
    result = parser.parse_policy(CHECKPOINT_POLICY_JSON)
    assert result.vendor == "checkpoint"


def test_parse_policy_malformed_json_returns_empty():
    parser = CheckPointParser()
    result = parser.parse_policy("{bad json")
    assert len(result.rules) == 0
    assert len(result.warnings) > 0


def test_parse_single_rule():
    parser = CheckPointParser()
    rule = parser.parse_single_rule(CANDIDATE_RULE_JSON)
    assert rule.name == "new-permit"
    assert rule.action == "permit"
    assert "AppNet" in rule.source_addresses


def test_parse_single_rule_malformed_raises():
    parser = CheckPointParser()
    with pytest.raises(ValueError):
        parser.parse_single_rule("{invalid}")


def test_parse_single_rule_section_header_raises():
    """Section headers (not access-rules) should raise ValueError."""
    parser = CheckPointParser()
    section = json.dumps({
        "type": "access-section",
        "uid": "sec-001",
        "name": "Header",
    })
    with pytest.raises(ValueError):
        parser.parse_single_rule(section)


def test_parse_policy_flat_rules_array():
    """Flat array of rule objects without objects-dictionary."""
    rules_only = json.dumps([
        {
            "type": "access-rule",
            "uid": "r-001",
            "name": "r1",
            "action": {"name": "Accept"},
            "enabled": True,
            "source": [{"name": "Any"}],
            "destination": [{"name": "Any"}],
            "service": [{"name": "Any"}],
        }
    ])
    parser = CheckPointParser()
    result = parser.parse_policy(rules_only)
    assert len(result.rules) == 1


def test_supported_vendors():
    parser = CheckPointParser()
    vendors = parser.supported_vendors()
    assert any(v[0] == "checkpoint" for v in vendors)
