"""
Unit tests for parsers/vendors/ftd/parser.py — FTDParser.

Uses realistic FTD/FMC JSON fixtures.
"""

from __future__ import annotations

import json
import pytest

from fwrule_mcp.parsers.vendors.ftd.parser import FTDParser


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FTD_POLICY_JSON = json.dumps({
    "metadata": {
        "ftdVersion": "7.2.0",
    },
    "objects": [
        {
            "id": "addr-001",
            "name": "WebServer",
            "type": "Host",
            "value": "10.1.2.10"
        },
        {
            "id": "addr-002",
            "name": "AppNet",
            "type": "Network",
            "value": "10.2.0.0/24"
        },
        {
            "id": "addr-003",
            "name": "ServerGroup",
            "type": "NetworkGroup",
            "objects": [
                {"name": "WebServer"},
                {"name": "AppNet"},
            ],
            "literals": []
        },
        {
            "id": "svc-001",
            "name": "HTTPS-PORT",
            "type": "ProtocolPortObject",
            "protocol": "6",
            "port": "443"
        },
    ],
    "rules": [
        {
            "id": "rule-001",
            "name": "allow-https",
            "action": "ALLOW",
            "enabled": True,
            "sourceNetworks": {
                "objects": [],
                "literals": [{"type": "Network", "value": "10.0.0.0/24"}]
            },
            "destinationNetworks": {
                "objects": [{"id": "addr-001", "name": "WebServer"}],
                "literals": []
            },
            "destinationPorts": {
                "objects": [{"id": "svc-001", "name": "HTTPS-PORT"}],
                "literals": []
            },
            "sourcePorts": {},
            "sourceZones": {
                "objects": [{"id": "zone-001", "name": "trust"}]
            },
            "destinationZones": {
                "objects": [{"id": "zone-002", "name": "untrust"}]
            },
            "applications": {},
        },
        {
            "id": "rule-002",
            "name": "block-all",
            "action": "BLOCK",
            "enabled": True,
            "sourceNetworks": {},
            "destinationNetworks": {},
            "destinationPorts": {},
            "sourcePorts": {},
            "sourceZones": {},
            "destinationZones": {},
            "applications": {},
        },
        {
            "id": "rule-003",
            "name": "trust-internal",
            "action": "TRUST",
            "enabled": False,
            "sourceNetworks": {
                "literals": [{"type": "Network", "value": "192.168.0.0/16"}]
            },
            "destinationNetworks": {},
            "destinationPorts": {},
            "sourcePorts": {},
            "sourceZones": {},
            "destinationZones": {},
            "applications": {
                "applications": [{"id": "app-001", "name": "ssl"}]
            },
        },
        {
            "id": "rule-004",
            "name": "monitor-rule",
            "action": "MONITOR",
            "enabled": True,
            "sourceNetworks": {},
            "destinationNetworks": {},
            "destinationPorts": {
                "literals": [
                    {"type": "PortLiteral", "protocol": "6", "port": "80"}
                ]
            },
            "sourcePorts": {},
            "sourceZones": {},
            "destinationZones": {},
            "applications": {},
        }
    ]
})

CANDIDATE_RULE_JSON = json.dumps({
    "id": "cand-001",
    "name": "new-rule",
    "action": "ALLOW",
    "enabled": True,
    "sourceNetworks": {
        "literals": [{"type": "Network", "value": "10.5.0.0/24"}]
    },
    "destinationNetworks": {
        "objects": [{"name": "WebServer"}]
    },
    "destinationPorts": {
        "literals": [{"type": "PortLiteral", "protocol": "6", "port": "443"}]
    },
    "sourcePorts": {},
    "sourceZones": {},
    "destinationZones": {},
    "applications": {},
})

MALFORMED_JSON = "{bad json"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_parse_policy_rule_count():
    parser = FTDParser()
    result = parser.parse_policy(FTD_POLICY_JSON)
    assert len(result.rules) == 4


def test_parse_policy_allow_action():
    parser = FTDParser()
    result = parser.parse_policy(FTD_POLICY_JSON)
    rule = next(r for r in result.rules if r.name == "allow-https")
    assert rule.action == "permit"


def test_parse_policy_block_action():
    parser = FTDParser()
    result = parser.parse_policy(FTD_POLICY_JSON)
    rule = next(r for r in result.rules if r.name == "block-all")
    assert rule.action == "deny"


def test_parse_policy_trust_action():
    parser = FTDParser()
    result = parser.parse_policy(FTD_POLICY_JSON)
    rule = next(r for r in result.rules if r.name == "trust-internal")
    assert rule.action == "permit"


def test_parse_policy_monitor_action():
    parser = FTDParser()
    result = parser.parse_policy(FTD_POLICY_JSON)
    rule = next(r for r in result.rules if r.name == "monitor-rule")
    assert rule.action == "log_only"


def test_parse_policy_disabled_rule():
    parser = FTDParser()
    result = parser.parse_policy(FTD_POLICY_JSON)
    rule = next(r for r in result.rules if r.name == "trust-internal")
    assert rule.enabled is False


def test_parse_policy_source_literal():
    parser = FTDParser()
    result = parser.parse_policy(FTD_POLICY_JSON)
    rule = next(r for r in result.rules if r.name == "allow-https")
    assert "10.0.0.0/24" in rule.source_addresses


def test_parse_policy_destination_object_reference():
    parser = FTDParser()
    result = parser.parse_policy(FTD_POLICY_JSON)
    rule = next(r for r in result.rules if r.name == "allow-https")
    assert "WebServer" in rule.destination_addresses


def test_parse_policy_source_zones():
    parser = FTDParser()
    result = parser.parse_policy(FTD_POLICY_JSON)
    rule = next(r for r in result.rules if r.name == "allow-https")
    assert "trust" in rule.source_zones


def test_parse_policy_destination_zones():
    parser = FTDParser()
    result = parser.parse_policy(FTD_POLICY_JSON)
    rule = next(r for r in result.rules if r.name == "allow-https")
    assert "untrust" in rule.destination_zones


def test_parse_policy_service_object_ref():
    parser = FTDParser()
    result = parser.parse_policy(FTD_POLICY_JSON)
    rule = next(r for r in result.rules if r.name == "allow-https")
    assert "HTTPS-PORT" in rule.services


def test_parse_policy_service_literal():
    parser = FTDParser()
    result = parser.parse_policy(FTD_POLICY_JSON)
    rule = next(r for r in result.rules if r.name == "monitor-rule")
    # Port literal tcp/80 → "tcp:80"
    assert any("80" in s or "tcp" in s for s in rule.services)


def test_parse_policy_application_extracted():
    parser = FTDParser()
    result = parser.parse_policy(FTD_POLICY_JSON)
    rule = next(r for r in result.rules if r.name == "trust-internal")
    assert "ssl" in rule.applications


def test_parse_policy_address_objects_in_table():
    parser = FTDParser()
    result = parser.parse_policy(FTD_POLICY_JSON)
    table = result.object_table
    assert "WebServer" in table.address_objects
    assert table.address_objects["WebServer"] == ["10.1.2.10"]


def test_parse_policy_network_object_in_table():
    parser = FTDParser()
    result = parser.parse_policy(FTD_POLICY_JSON)
    table = result.object_table
    assert "AppNet" in table.address_objects
    assert table.address_objects["AppNet"] == ["10.2.0.0/24"]


def test_parse_policy_service_object_in_table():
    parser = FTDParser()
    result = parser.parse_policy(FTD_POLICY_JSON)
    table = result.object_table
    assert "HTTPS-PORT" in table.service_objects
    svc = table.service_objects["HTTPS-PORT"]
    assert svc["protocol"] == "tcp"


def test_parse_policy_group_object_in_table():
    parser = FTDParser()
    result = parser.parse_policy(FTD_POLICY_JSON)
    table = result.object_table
    assert "ServerGroup" in table.address_groups


def test_parse_policy_vendor_is_ftd():
    parser = FTDParser()
    result = parser.parse_policy(FTD_POLICY_JSON)
    assert result.vendor == "ftd"


def test_parse_policy_version_detected():
    parser = FTDParser()
    result = parser.parse_policy(FTD_POLICY_JSON)
    assert result.os_version == "7.2.0"


def test_parse_policy_malformed_json_returns_empty():
    parser = FTDParser()
    result = parser.parse_policy(MALFORMED_JSON)
    assert len(result.rules) == 0
    assert len(result.warnings) > 0


def test_parse_policy_empty_rules():
    parser = FTDParser()
    data = json.dumps({"rules": []})
    result = parser.parse_policy(data)
    assert len(result.rules) == 0


def test_parse_single_rule():
    parser = FTDParser()
    rule = parser.parse_single_rule(CANDIDATE_RULE_JSON)
    assert rule.name == "new-rule"
    assert rule.action == "permit"
    assert "10.5.0.0/24" in rule.source_addresses


def test_parse_single_rule_service_literal():
    parser = FTDParser()
    rule = parser.parse_single_rule(CANDIDATE_RULE_JSON)
    # tcp:443 literal
    assert any("443" in s or "tcp" in s for s in rule.services)


def test_parse_single_rule_malformed_raises():
    parser = FTDParser()
    with pytest.raises(ValueError):
        parser.parse_single_rule("{invalid json}")


def test_parse_single_rule_non_dict_raises():
    parser = FTDParser()
    with pytest.raises(ValueError):
        parser.parse_single_rule("[1, 2, 3]")


def test_supported_vendors():
    parser = FTDParser()
    vendors = parser.supported_vendors()
    assert any(v[0] == "ftd" for v in vendors)
