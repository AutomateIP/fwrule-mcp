"""
Unit tests for parsers/vendors/panos/parser.py — PANOSParser.

Uses realistic PAN-OS XML config fixtures (minimal but representative).
"""

from __future__ import annotations

import pytest

from fwrule_mcp.parsers.vendors.panos.parser import PANOSParser


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

BASIC_PANOS_CONFIG = """\
<config version="10.2.0">
  <devices>
    <entry name="localhost.localdomain">
      <vsys>
        <entry name="vsys1">
          <address>
            <entry name="WebServer">
              <ip-netmask>10.1.2.10/32</ip-netmask>
            </entry>
            <entry name="AppNet">
              <ip-netmask>10.2.0.0/24</ip-netmask>
            </entry>
            <entry name="range-obj">
              <ip-range>192.168.1.1-192.168.1.100</ip-range>
            </entry>
          </address>
          <address-group>
            <entry name="WebGroup">
              <static>
                <member>WebServer</member>
                <member>AppNet</member>
              </static>
            </entry>
          </address-group>
          <service>
            <entry name="svc-https">
              <protocol>
                <tcp>
                  <port>443</port>
                </tcp>
              </protocol>
            </entry>
            <entry name="svc-dns">
              <protocol>
                <udp>
                  <port>53</port>
                </udp>
              </protocol>
            </entry>
          </service>
          <service-group>
            <entry name="WEB-SVC">
              <members>
                <member>svc-https</member>
                <member>svc-dns</member>
              </members>
            </entry>
          </service-group>
          <rulebase>
            <security>
              <rules>
                <entry name="allow-web">
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>any</member></source>
                  <destination><member>WebGroup</member></destination>
                  <service><member>svc-https</member></service>
                  <application><member>ssl</member></application>
                  <action>allow</action>
                  <description>Allow HTTPS to web servers</description>
                </entry>
                <entry name="deny-all">
                  <from><member>any</member></from>
                  <to><member>any</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <service><member>any</member></service>
                  <application><member>any</member></application>
                  <action>deny</action>
                </entry>
                <entry name="disabled-rule">
                  <from><member>dmz</member></from>
                  <to><member>trust</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <service><member>any</member></service>
                  <application><member>any</member></application>
                  <action>allow</action>
                  <disabled>yes</disabled>
                </entry>
                <entry name="negate-rule">
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>WebServer</member></source>
                  <destination><member>any</member></destination>
                  <negate-source>yes</negate-source>
                  <negate-destination>no</negate-destination>
                  <service><member>any</member></service>
                  <application><member>any</member></application>
                  <action>deny</action>
                </entry>
              </rules>
            </security>
          </rulebase>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>
"""

CANDIDATE_RULE_XML = """\
<entry name="candidate-rule">
  <from><member>trust</member></from>
  <to><member>untrust</member></to>
  <source><member>10.0.0.0/24</member></source>
  <destination><member>any</member></destination>
  <service><member>svc-https</member></service>
  <application><member>any</member></application>
  <action>allow</action>
</entry>
"""

MALFORMED_XML = "<config><unclosed>"

EMPTY_CONFIG = "<config/>"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_parse_policy_rule_count():
    parser = PANOSParser()
    result = parser.parse_policy(BASIC_PANOS_CONFIG)
    assert len(result.rules) == 4


def test_parse_policy_rule_names():
    parser = PANOSParser()
    result = parser.parse_policy(BASIC_PANOS_CONFIG)
    names = [r.name for r in result.rules]
    assert "allow-web" in names
    assert "deny-all" in names
    assert "disabled-rule" in names


def test_parse_policy_rule_action():
    parser = PANOSParser()
    result = parser.parse_policy(BASIC_PANOS_CONFIG)
    rule_by_name = {r.name: r for r in result.rules}
    assert rule_by_name["allow-web"].action == "permit"
    assert rule_by_name["deny-all"].action == "deny"


def test_parse_policy_rule_zones():
    parser = PANOSParser()
    result = parser.parse_policy(BASIC_PANOS_CONFIG)
    rule = next(r for r in result.rules if r.name == "allow-web")
    assert "trust" in rule.source_zones
    assert "untrust" in rule.destination_zones


def test_parse_policy_rule_addresses():
    parser = PANOSParser()
    result = parser.parse_policy(BASIC_PANOS_CONFIG)
    rule = next(r for r in result.rules if r.name == "allow-web")
    assert "any" in rule.source_addresses
    assert "WebGroup" in rule.destination_addresses


def test_parse_policy_rule_services():
    parser = PANOSParser()
    result = parser.parse_policy(BASIC_PANOS_CONFIG)
    rule = next(r for r in result.rules if r.name == "allow-web")
    assert "svc-https" in rule.services


def test_parse_policy_rule_applications():
    parser = PANOSParser()
    result = parser.parse_policy(BASIC_PANOS_CONFIG)
    rule = next(r for r in result.rules if r.name == "allow-web")
    assert "ssl" in rule.applications


def test_parse_policy_disabled_rule():
    parser = PANOSParser()
    result = parser.parse_policy(BASIC_PANOS_CONFIG)
    rule = next(r for r in result.rules if r.name == "disabled-rule")
    assert rule.enabled is False


def test_parse_policy_enabled_rule():
    parser = PANOSParser()
    result = parser.parse_policy(BASIC_PANOS_CONFIG)
    rule = next(r for r in result.rules if r.name == "allow-web")
    assert rule.enabled is True


def test_parse_policy_negate_source():
    parser = PANOSParser()
    result = parser.parse_policy(BASIC_PANOS_CONFIG)
    rule = next(r for r in result.rules if r.name == "negate-rule")
    assert rule.negate_source is True
    assert rule.negate_destination is False


def test_parse_policy_address_objects_extracted():
    parser = PANOSParser()
    result = parser.parse_policy(BASIC_PANOS_CONFIG)
    assert "WebServer" in result.object_table.address_objects
    assert result.object_table.address_objects["WebServer"] == ["10.1.2.10/32"]


def test_parse_policy_address_object_range():
    parser = PANOSParser()
    result = parser.parse_policy(BASIC_PANOS_CONFIG)
    assert "range-obj" in result.object_table.address_objects
    assert "192.168.1.1-192.168.1.100" in result.object_table.address_objects["range-obj"]


def test_parse_policy_address_group_extracted():
    parser = PANOSParser()
    result = parser.parse_policy(BASIC_PANOS_CONFIG)
    assert "WebGroup" in result.object_table.address_groups
    members = result.object_table.address_groups["WebGroup"]
    assert "WebServer" in members
    assert "AppNet" in members


def test_parse_policy_service_object_extracted():
    parser = PANOSParser()
    result = parser.parse_policy(BASIC_PANOS_CONFIG)
    assert "svc-https" in result.object_table.service_objects
    svc = result.object_table.service_objects["svc-https"]
    assert svc["protocol"] == "tcp"
    assert svc["ports"] == "443"


def test_parse_policy_service_group_extracted():
    parser = PANOSParser()
    result = parser.parse_policy(BASIC_PANOS_CONFIG)
    assert "WEB-SVC" in result.object_table.service_groups
    members = result.object_table.service_groups["WEB-SVC"]
    assert "svc-https" in members
    assert "svc-dns" in members


def test_parse_policy_vendor_set():
    parser = PANOSParser()
    result = parser.parse_policy(BASIC_PANOS_CONFIG)
    assert result.vendor == "panos"


def test_parse_policy_description_extracted():
    parser = PANOSParser()
    result = parser.parse_policy(BASIC_PANOS_CONFIG)
    rule = next(r for r in result.rules if r.name == "allow-web")
    assert "HTTPS" in rule.description


def test_parse_policy_rule_positions():
    parser = PANOSParser()
    result = parser.parse_policy(BASIC_PANOS_CONFIG)
    positions = [r.position for r in result.rules]
    assert positions == list(range(len(positions)))


def test_parse_single_rule():
    parser = PANOSParser()
    rule = parser.parse_single_rule(CANDIDATE_RULE_XML)
    assert rule.name == "candidate-rule"
    assert rule.action == "permit"
    assert "trust" in rule.source_zones


def test_parse_single_rule_malformed_raises():
    parser = PANOSParser()
    with pytest.raises((ValueError, Exception)):
        parser.parse_single_rule("<bad_xml_no_entry/>")


def test_parse_policy_malformed_xml_returns_empty():
    """Malformed XML → empty rules list with warning."""
    parser = PANOSParser()
    result = parser.parse_policy(MALFORMED_XML)
    assert len(result.rules) == 0
    assert len(result.warnings) > 0


def test_parse_policy_empty_config():
    """Empty config element → no rules, no crash."""
    parser = PANOSParser()
    result = parser.parse_policy(EMPTY_CONFIG)
    assert isinstance(result.rules, list)


def test_parse_policy_deny_action_mapped():
    """deny action should be mapped to canonical 'deny'."""
    parser = PANOSParser()
    result = parser.parse_policy(BASIC_PANOS_CONFIG)
    rule = next(r for r in result.rules if r.name == "deny-all")
    assert rule.action == "deny"


def test_supported_vendors():
    parser = PANOSParser()
    vendors = parser.supported_vendors()
    assert any(v[0] == "panos" for v in vendors)
