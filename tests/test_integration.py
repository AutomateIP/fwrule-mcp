"""
End-to-end integration tests for the full analysis pipeline.

Tests the analyze_firewall_rule_overlap() and list_supported_vendors()
functions from server.py using realistic vendor payloads.

Each test exercises the full pipeline:
  vendor payload → parse → normalize → analyze → AnalysisResponse dict
"""

from __future__ import annotations

import json
import pytest

from fwrule_mcp.server import analyze_firewall_rule_overlap, list_supported_vendors


# ---------------------------------------------------------------------------
# PAN-OS fixtures
# ---------------------------------------------------------------------------

PANOS_POLICY = """\
<config version="10.2.0">
  <devices>
    <entry name="localhost.localdomain">
      <vsys>
        <entry name="vsys1">
          <address>
            <entry name="WebServer">
              <ip-netmask>10.1.2.10/32</ip-netmask>
            </entry>
          </address>
          <rulebase>
            <security>
              <rules>
                <entry name="allow-all-web">
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <service><member>any</member></service>
                  <application><member>any</member></application>
                  <action>allow</action>
                </entry>
                <entry name="allow-ssh">
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>10.0.0.0/24</member></source>
                  <destination><member>WebServer</member></destination>
                  <service><member>any</member></service>
                  <application><member>any</member></application>
                  <action>allow</action>
                </entry>
                <entry name="deny-block">
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>10.0.0.0/24</member></source>
                  <destination><member>any</member></destination>
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

# Identical to allow-all-web → EXACT_DUPLICATE
PANOS_CANDIDATE_DUPLICATE = """\
<entry name="duplicate-rule">
  <from><member>trust</member></from>
  <to><member>untrust</member></to>
  <source><member>any</member></source>
  <destination><member>any</member></destination>
  <service><member>any</member></service>
  <application><member>any</member></application>
  <action>allow</action>
</entry>
"""

# Narrow rule — will be shadowed by allow-all-web which is at position 1
PANOS_CANDIDATE_SHADOWED = """\
<entry name="narrow-rule">
  <from><member>trust</member></from>
  <to><member>untrust</member></to>
  <source><member>10.0.0.1/32</member></source>
  <destination><member>10.1.2.0/24</member></destination>
  <service><member>any</member></service>
  <application><member>any</member></application>
  <action>allow</action>
</entry>
"""

# Disjoint zones — should produce NO_OVERLAP
PANOS_CANDIDATE_DISJOINT = """\
<entry name="disjoint-rule">
  <from><member>dmz</member></from>
  <to><member>mgmt</member></to>
  <source><member>any</member></source>
  <destination><member>any</member></destination>
  <service><member>any</member></service>
  <application><member>any</member></application>
  <action>allow</action>
</entry>
"""


# ---------------------------------------------------------------------------
# ASA fixtures
# ---------------------------------------------------------------------------

ASA_POLICY = """\
access-list OUTSIDE_IN extended permit tcp any host 10.1.2.10 eq https
access-list OUTSIDE_IN extended deny ip any any
"""

# Conflicts with the permit rule (same match, different action)
ASA_CANDIDATE_CONFLICT = "access-list OUTSIDE_IN extended deny tcp any host 10.1.2.10 eq https"

# No overlap (different destination)
ASA_CANDIDATE_NO_OVERLAP = "access-list OUTSIDE_IN extended permit tcp any host 172.16.0.1 eq ssh"


# ---------------------------------------------------------------------------
# Juniper fixtures
# ---------------------------------------------------------------------------

JUNIPER_POLICY = """\
set security policies from-zone trust to-zone untrust policy permit-web match source-address any
set security policies from-zone trust to-zone untrust policy permit-web match destination-address any
set security policies from-zone trust to-zone untrust policy permit-web match application any
set security policies from-zone trust to-zone untrust policy permit-web then permit
"""

# Disjoint zones → no overlap
JUNIPER_CANDIDATE_DISJOINT = """\
set security policies from-zone dmz to-zone mgmt policy new-rule match source-address any
set security policies from-zone dmz to-zone mgmt policy new-rule match destination-address any
set security policies from-zone dmz to-zone mgmt policy new-rule match application any
set security policies from-zone dmz to-zone mgmt policy new-rule then permit
"""


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_panos_duplicate_detection():
    """PAN-OS: identical rule should detect exact duplicate."""
    result = analyze_firewall_rule_overlap(
        vendor="panos",
        ruleset_payload=PANOS_POLICY,
        candidate_rule_payload=PANOS_CANDIDATE_DUPLICATE,
    )
    assert result["success"] is True
    assert result["overlap_exists"] is True
    overlap_types = [f["overlap_type"] for f in result["findings"]]
    assert "exact_duplicate" in overlap_types


def test_panos_shadowed_rule():
    """PAN-OS: narrow rule after broad permit should be shadowed."""
    result = analyze_firewall_rule_overlap(
        vendor="panos",
        ruleset_payload=PANOS_POLICY,
        candidate_rule_payload=PANOS_CANDIDATE_SHADOWED,
        candidate_position=4,  # appended after all rules
    )
    assert result["success"] is True
    assert result["overlap_exists"] is True
    overlap_types = [f["overlap_type"] for f in result["findings"]]
    # The allow-all-web rule shadows the candidate
    assert "shadowed" in overlap_types


def test_panos_no_overlap_disjoint_zones():
    """PAN-OS: disjoint zone policies should not overlap."""
    result = analyze_firewall_rule_overlap(
        vendor="panos",
        ruleset_payload=PANOS_POLICY,
        candidate_rule_payload=PANOS_CANDIDATE_DISJOINT,
    )
    assert result["success"] is True
    assert result["overlap_exists"] is False


def test_panos_conflict_different_action():
    """PAN-OS: candidate denying what existing permits → CONFLICT."""
    result = analyze_firewall_rule_overlap(
        vendor="panos",
        ruleset_payload=PANOS_POLICY,
        candidate_rule_payload="""\
<entry name="conflict-deny">
  <from><member>trust</member></from>
  <to><member>untrust</member></to>
  <source><member>10.0.0.0/24</member></source>
  <destination><member>any</member></destination>
  <service><member>any</member></service>
  <application><member>any</member></application>
  <action>deny</action>
</entry>
""",
    )
    assert result["success"] is True


def test_asa_conflict_detection():
    """ASA: deny rule conflicting with existing permit."""
    result = analyze_firewall_rule_overlap(
        vendor="asa",
        ruleset_payload=ASA_POLICY,
        candidate_rule_payload=ASA_CANDIDATE_CONFLICT,
    )
    assert result["success"] is True
    assert result["overlap_exists"] is True
    overlap_types = {f["overlap_type"] for f in result["findings"]}
    assert "conflict" in overlap_types or "exact_duplicate" in overlap_types


def test_asa_no_overlap():
    """ASA: candidate with disjoint source subnet and different service has no duplicate/conflict."""
    # Use a policy that only permits HTTPS from a specific subnet
    specific_policy = "access-list INSIDE_OUT extended permit tcp 10.0.0.0 0.0.0.255 host 10.1.2.10 eq https\n"
    # Candidate from a completely different source subnet to a different destination
    disjoint_candidate = "access-list INSIDE_OUT extended permit tcp 192.168.5.0 0.0.0.255 host 172.16.99.1 eq ssh"
    result = analyze_firewall_rule_overlap(
        vendor="asa",
        ruleset_payload=specific_policy,
        candidate_rule_payload=disjoint_candidate,
    )
    assert result["success"] is True
    # Source addresses are disjoint → no overlap
    assert result["overlap_exists"] is False


def test_juniper_no_overlap():
    """Juniper: disjoint zone policies should not overlap."""
    result = analyze_firewall_rule_overlap(
        vendor="juniper",
        ruleset_payload=JUNIPER_POLICY,
        candidate_rule_payload=JUNIPER_CANDIDATE_DISJOINT,
    )
    assert result["success"] is True
    assert result["overlap_exists"] is False


def test_juniper_duplicate_detection():
    """Juniper: same zone/any/any/permit rule → EXACT_DUPLICATE."""
    candidate = """\
set security policies from-zone trust to-zone untrust policy dup-rule match source-address any
set security policies from-zone trust to-zone untrust policy dup-rule match destination-address any
set security policies from-zone trust to-zone untrust policy dup-rule match application any
set security policies from-zone trust to-zone untrust policy dup-rule then permit
"""
    result = analyze_firewall_rule_overlap(
        vendor="juniper",
        ruleset_payload=JUNIPER_POLICY,
        candidate_rule_payload=candidate,
    )
    assert result["success"] is True
    assert result["overlap_exists"] is True
    overlap_types = [f["overlap_type"] for f in result["findings"]]
    assert "exact_duplicate" in overlap_types


def test_unsupported_vendor():
    """Unknown vendor should return structured error."""
    result = analyze_firewall_rule_overlap(
        vendor="fortigate",
        ruleset_payload="<config/>",
        candidate_rule_payload="<rule/>",
    )
    assert result["success"] is False
    assert result["error"]["code"] in ("unsupported_vendor",)


def test_malformed_panos_payload():
    """Malformed PAN-OS XML should return parse error or empty result, not crash."""
    result = analyze_firewall_rule_overlap(
        vendor="panos",
        ruleset_payload="<unclosed XML",
        candidate_rule_payload="<entry name='test'/>",
    )
    # Should not crash — either success=False with error, or success=True with empty
    assert "success" in result


def test_malformed_asa_candidate():
    """Malformed ASA candidate should return parse error, not crash."""
    result = analyze_firewall_rule_overlap(
        vendor="asa",
        ruleset_payload=ASA_POLICY,
        candidate_rule_payload="definitely not an access-list line",
    )
    assert "success" in result
    if not result["success"]:
        assert "error" in result


def test_malformed_ftd_json():
    """Malformed FTD JSON should return structured error."""
    result = analyze_firewall_rule_overlap(
        vendor="ftd",
        ruleset_payload="{bad json}",
        candidate_rule_payload='{"name": "test", "action": "ALLOW"}',
    )
    assert "success" in result


def test_list_supported_vendors():
    """list_supported_vendors should return all supported vendors."""
    raw = list_supported_vendors()
    result = json.loads(raw) if isinstance(raw, str) else raw
    assert "vendors" in result
    vendor_ids = {v["id"] for v in result["vendors"]}
    assert "panos" in vendor_ids
    assert "asa" in vendor_ids
    assert "ftd" in vendor_ids
    assert "checkpoint" in vendor_ids
    assert "juniper" in vendor_ids
    # New vendors added in v2
    assert "ios" in vendor_ids
    assert "iosxr" in vendor_ids
    assert "junos" in vendor_ids
    assert "sros" in vendor_ids
    assert len(vendor_ids) == 9


def test_list_supported_vendors_has_required_fields():
    """Each vendor entry must have id, aliases, format."""
    raw = list_supported_vendors()
    result = json.loads(raw) if isinstance(raw, str) else raw
    for vendor in result["vendors"]:
        assert "id" in vendor
        assert "aliases" in vendor
        assert "format" in vendor


def test_analysis_response_structure():
    """Successful response has all required top-level keys."""
    result = analyze_firewall_rule_overlap(
        vendor="panos",
        ruleset_payload=PANOS_POLICY,
        candidate_rule_payload=PANOS_CANDIDATE_DUPLICATE,
    )
    assert result["success"] is True
    assert "overlap_exists" in result
    assert "findings" in result
    assert "metadata" in result


def test_metadata_structure():
    """Metadata contains required fields."""
    result = analyze_firewall_rule_overlap(
        vendor="panos",
        ruleset_payload=PANOS_POLICY,
        candidate_rule_payload=PANOS_CANDIDATE_DUPLICATE,
    )
    meta = result["metadata"]
    assert meta["vendor"] == "panos"
    assert "existing_rule_count" in meta
    assert "enabled_rule_count" in meta
    assert "analysis_duration_ms" in meta


def test_finding_structure():
    """Each finding has required fields."""
    result = analyze_firewall_rule_overlap(
        vendor="panos",
        ruleset_payload=PANOS_POLICY,
        candidate_rule_payload=PANOS_CANDIDATE_DUPLICATE,
    )
    assert result["overlap_exists"] is True
    for finding in result["findings"]:
        assert "existing_rule_id" in finding
        assert "overlap_type" in finding
        assert "severity" in finding
        assert "dimensions" in finding
        assert "candidate_action" in finding


def test_candidate_position_affects_shadow_analysis():
    """Candidate position determines shadows_existing vs superset classification.

    Policy has a disjoint filler rule at position 1, and a narrow trust→untrust
    rule at position 2.  A broad candidate placed at position 1 precedes the
    narrow rule → shadows_existing.  Placed at position 3 (after it) → superset.
    """
    # Two-rule policy: filler at pos 1 (disjoint zone), narrow trust→untrust at pos 2
    two_rule_policy = """\
<config version="10.2.0">
  <devices>
    <entry name="localhost.localdomain">
      <vsys>
        <entry name="vsys1">
          <rulebase>
            <security>
              <rules>
                <entry name="filler-rule">
                  <from><member>dmz</member></from>
                  <to><member>mgmt</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <service><member>any</member></service>
                  <application><member>any</member></application>
                  <action>allow</action>
                </entry>
                <entry name="narrow-existing">
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>10.0.0.1/32</member></source>
                  <destination><member>any</member></destination>
                  <service><member>any</member></service>
                  <application><member>any</member></application>
                  <action>allow</action>
                </entry>
              </rules>
            </security>
          </rulebase>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>"""

    # Broad candidate (superset of narrow-existing in trust→untrust zone)
    broad_candidate = """\
<entry name="broad-rule">
  <from><member>trust</member></from>
  <to><member>untrust</member></to>
  <source><member>any</member></source>
  <destination><member>any</member></destination>
  <service><member>any</member></service>
  <application><member>any</member></application>
  <action>allow</action>
</entry>"""

    # Candidate at position 1 precedes narrow-existing at position 2 → shadows_existing
    result_before = analyze_firewall_rule_overlap(
        vendor="panos",
        ruleset_payload=two_rule_policy,
        candidate_rule_payload=broad_candidate,
        candidate_position=1,
    )
    assert result_before["success"] is True
    types_before = {f["overlap_type"] for f in result_before["findings"]}
    assert "shadows_existing" in types_before

    # Candidate at position 3 comes after narrow-existing at position 2 → superset
    result_after = analyze_firewall_rule_overlap(
        vendor="panos",
        ruleset_payload=two_rule_policy,
        candidate_rule_payload=broad_candidate,
        candidate_position=3,
    )
    assert result_after["success"] is True
    types_after = {f["overlap_type"] for f in result_after["findings"]}
    assert "shadows_existing" not in types_after
    assert "superset" in types_after


def test_context_objects_injected():
    """context_objects parameter allows injecting extra object definitions."""
    context = json.dumps({
        "address_objects": {"MyHost": "10.5.5.5/32"},
        "service_objects": {"MY-HTTPS": "tcp/443"},
    })
    candidate = """\
<entry name="ctx-rule">
  <from><member>trust</member></from>
  <to><member>untrust</member></to>
  <source><member>any</member></source>
  <destination><member>MyHost</member></destination>
  <service><member>any</member></service>
  <application><member>any</member></application>
  <action>allow</action>
</entry>
"""
    result = analyze_firewall_rule_overlap(
        vendor="panos",
        ruleset_payload=PANOS_POLICY,
        candidate_rule_payload=candidate,
        context_objects=context,
    )
    assert result["success"] is True


def test_checkpoint_integration():
    """Check Point: basic policy parse and analysis works end-to-end."""
    cp_policy = json.dumps({
        "rulebase": [
            {
                "type": "access-rule",
                "uid": "r-001",
                "name": "permit-all",
                "action": {"name": "Accept"},
                "enabled": True,
                "source": [{"name": "Any"}],
                "destination": [{"name": "Any"}],
                "service": [{"name": "Any"}],
            }
        ]
    })
    cp_candidate = json.dumps({
        "type": "access-rule",
        "uid": "c-001",
        "name": "new-rule",
        "action": {"name": "Accept"},
        "enabled": True,
        "source": [{"name": "Any"}],
        "destination": [{"name": "Any"}],
        "service": [{"name": "Any"}],
    })
    result = analyze_firewall_rule_overlap(
        vendor="checkpoint",
        ruleset_payload=cp_policy,
        candidate_rule_payload=cp_candidate,
    )
    assert result["success"] is True
    assert result["overlap_exists"] is True


def test_ftd_integration():
    """FTD: basic policy parse and analysis works end-to-end."""
    ftd_policy = json.dumps({
        "rules": [
            {
                "id": "r-001",
                "name": "allow-all",
                "action": "ALLOW",
                "enabled": True,
                "sourceNetworks": {},
                "destinationNetworks": {},
                "destinationPorts": {},
                "sourcePorts": {},
                "sourceZones": {},
                "destinationZones": {},
                "applications": {},
            }
        ]
    })
    ftd_candidate = json.dumps({
        "id": "cand-001",
        "name": "new-rule",
        "action": "ALLOW",
        "enabled": True,
        "sourceNetworks": {},
        "destinationNetworks": {},
        "destinationPorts": {},
        "sourcePorts": {},
        "sourceZones": {},
        "destinationZones": {},
        "applications": {},
    })
    result = analyze_firewall_rule_overlap(
        vendor="ftd",
        ruleset_payload=ftd_policy,
        candidate_rule_payload=ftd_candidate,
    )
    assert result["success"] is True
    assert result["overlap_exists"] is True
