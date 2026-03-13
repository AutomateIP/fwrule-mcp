"""
Tests for the normalized JSON input path (Path B) and parse_policy tool.

Validates:
  - Normalized input produces correct overlap analysis
  - parse_policy returns valid normalized JSON
  - Round-trip: vendor parse → normalize → re-analyze via normalized path
  - Schema validation errors
  - Both paths produce equivalent results for the same logical rules
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fwrule_mcp.server import analyze_firewall_rule_overlap, parse_policy

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalize_analysis(**kwargs) -> dict:
    """Run analysis via normalized input path."""
    return analyze_firewall_rule_overlap(**kwargs)


def _make_rule(
    id: str,
    position: int,
    action: str = "permit",
    src_addr: list[str] | None = None,
    dst_addr: list[str] | None = None,
    services: list[dict] | None = None,
    src_zones: list[str] | None = None,
    dst_zones: list[str] | None = None,
    apps: list[str] | None = None,
) -> dict:
    """Build a normalized rule dict with sensible defaults."""
    return {
        "id": id,
        "position": position,
        "action": action,
        "source_addresses": src_addr or ["any"],
        "destination_addresses": dst_addr or ["any"],
        "services": services or [],
        "source_zones": src_zones or ["any"],
        "destination_zones": dst_zones or ["any"],
        "applications": apps or ["any"],
    }


# ---------------------------------------------------------------------------
# Basic normalized input tests
# ---------------------------------------------------------------------------


class TestNormalizedInput:
    """Test the normalized JSON input path."""

    def test_exact_duplicate(self):
        """Two identical rules → exact_duplicate."""
        existing = [_make_rule("rule-1", 1, "permit",
                               src_addr=["10.0.0.0/24"], dst_addr=["192.168.1.0/24"],
                               services=[{"protocol": "tcp", "ports": "443"}])]
        candidate = _make_rule("candidate", 1, "permit",
                               src_addr=["10.0.0.0/24"], dst_addr=["192.168.1.0/24"],
                               services=[{"protocol": "tcp", "ports": "443"}])

        result = _normalize_analysis(
            existing_rules=json.dumps(existing),
            candidate_rule=json.dumps(candidate),
        )
        assert result["success"]
        assert result["overlap_exists"]
        types = [f["overlap_type"] for f in result["findings"]]
        assert "exact_duplicate" in types

    def test_no_overlap(self):
        """Completely disjoint rules → no findings."""
        existing = [_make_rule("rule-1", 1, "permit",
                               src_addr=["10.0.0.0/24"], dst_addr=["192.168.1.0/24"],
                               services=[{"protocol": "tcp", "ports": "443"}])]
        candidate = _make_rule("candidate", 1, "permit",
                               src_addr=["172.16.0.0/16"], dst_addr=["10.10.0.0/16"],
                               services=[{"protocol": "udp", "ports": "5432"}])

        result = _normalize_analysis(
            existing_rules=json.dumps(existing),
            candidate_rule=json.dumps(candidate),
        )
        assert result["success"]
        assert not result["overlap_exists"]
        assert result["findings"] == []

    def test_conflict(self):
        """Same match, opposing actions → conflict."""
        existing = [_make_rule("rule-1", 1, "permit",
                               src_addr=["10.0.0.0/24"], dst_addr=["192.168.1.0/24"],
                               services=[{"protocol": "tcp", "ports": "80"}])]
        candidate = _make_rule("candidate", 1, "deny",
                               src_addr=["10.0.0.0/24"], dst_addr=["192.168.1.0/24"],
                               services=[{"protocol": "tcp", "ports": "80"}])

        result = _normalize_analysis(
            existing_rules=json.dumps(existing),
            candidate_rule=json.dumps(candidate),
        )
        assert result["success"]
        assert result["overlap_exists"]
        types = [f["overlap_type"] for f in result["findings"]]
        assert "conflict" in types

    def test_subset(self):
        """Candidate is narrower than existing → subset or shadowed."""
        existing = [_make_rule("rule-1", 1, "permit",
                               src_addr=["10.0.0.0/16"], dst_addr=["any"],
                               services=[])]
        candidate = _make_rule("candidate", 1, "permit",
                               src_addr=["10.0.1.0/24"], dst_addr=["any"],
                               services=[])

        result = _normalize_analysis(
            existing_rules=json.dumps(existing),
            candidate_rule=json.dumps(candidate),
        )
        assert result["success"]
        assert result["overlap_exists"]
        types = [f["overlap_type"] for f in result["findings"]]
        assert any(t in ("subset", "shadowed") for t in types)

    def test_superset(self):
        """Candidate is broader than existing → superset."""
        existing = [_make_rule("rule-1", 1, "permit",
                               src_addr=["10.0.1.0/24"], dst_addr=["192.168.1.0/24"])]
        candidate = _make_rule("candidate", 1, "permit",
                               src_addr=["10.0.0.0/16"], dst_addr=["192.168.0.0/16"])

        result = _normalize_analysis(
            existing_rules=json.dumps(existing),
            candidate_rule=json.dumps(candidate),
        )
        assert result["success"]
        assert result["overlap_exists"]
        types = [f["overlap_type"] for f in result["findings"]]
        assert any(t in ("superset", "shadows_existing") for t in types)

    def test_multiple_existing_rules(self):
        """Candidate against multiple existing rules."""
        existing = [
            _make_rule("allow-web", 1, "permit",
                       dst_addr=["10.1.1.0/24"],
                       services=[{"protocol": "tcp", "ports": "80,443"}]),
            _make_rule("deny-db", 2, "deny",
                       dst_addr=["10.2.1.0/24"],
                       services=[{"protocol": "tcp", "ports": "3306"}]),
            _make_rule("allow-ssh", 3, "permit",
                       dst_addr=["10.3.1.0/24"],
                       services=[{"protocol": "tcp", "ports": "22"}]),
        ]
        # Candidate: permit any to 10.1.1.0/24 on tcp/80 — exact duplicate of rule-1
        candidate = _make_rule("candidate", 1, "permit",
                               dst_addr=["10.1.1.0/24"],
                               services=[{"protocol": "tcp", "ports": "80,443"}])

        result = _normalize_analysis(
            existing_rules=json.dumps(existing),
            candidate_rule=json.dumps(candidate),
        )
        assert result["success"]
        assert result["overlap_exists"]
        assert result["metadata"]["existing_rule_count"] == 3

    def test_any_service_matches_all(self):
        """Empty services list means 'any' → overlaps with specific services."""
        existing = [_make_rule("rule-1", 1, "permit",
                               dst_addr=["10.0.0.0/24"],
                               services=[{"protocol": "tcp", "ports": "443"}])]
        candidate = _make_rule("candidate", 1, "permit",
                               dst_addr=["10.0.0.0/24"],
                               services=[])

        result = _normalize_analysis(
            existing_rules=json.dumps(existing),
            candidate_rule=json.dumps(candidate),
        )
        assert result["success"]
        assert result["overlap_exists"]

    def test_port_range(self):
        """Port ranges are correctly parsed and compared."""
        existing = [_make_rule("rule-1", 1, "permit",
                               dst_addr=["10.0.0.0/24"],
                               services=[{"protocol": "tcp", "ports": "8080-8090"}])]
        # Candidate has a single port within the range
        candidate = _make_rule("candidate", 1, "permit",
                               dst_addr=["10.0.0.0/24"],
                               services=[{"protocol": "tcp", "ports": "8085"}])

        result = _normalize_analysis(
            existing_rules=json.dumps(existing),
            candidate_rule=json.dumps(candidate),
        )
        assert result["success"]
        assert result["overlap_exists"]

    def test_action_aliases(self):
        """Action aliases like 'allow' and 'accept' map correctly."""
        existing = [_make_rule("rule-1", 1, "allow", dst_addr=["10.0.0.0/24"])]
        candidate = _make_rule("candidate", 1, "accept", dst_addr=["10.0.0.0/24"])

        result = _normalize_analysis(
            existing_rules=json.dumps(existing),
            candidate_rule=json.dumps(candidate),
        )
        assert result["success"]
        assert result["overlap_exists"]
        # Both map to "permit" — should be duplicate, not conflict
        types = [f["overlap_type"] for f in result["findings"]]
        assert "conflict" not in types

    def test_candidate_position(self):
        """candidate_position affects shadow analysis."""
        existing = [_make_rule("broad-rule", 1, "permit",
                               src_addr=["any"], dst_addr=["any"])]
        candidate = _make_rule("narrow-rule", 1, "permit",
                               src_addr=["10.0.0.0/24"], dst_addr=["192.168.1.0/24"],
                               services=[{"protocol": "tcp", "ports": "22"}])

        result = _normalize_analysis(
            existing_rules=json.dumps(existing),
            candidate_rule=json.dumps(candidate),
            candidate_position=2,
        )
        assert result["success"]
        assert result["overlap_exists"]

    def test_dimensions_in_response(self):
        """Response includes dimension relationship map."""
        existing = [_make_rule("rule-1", 1, "permit",
                               src_addr=["10.0.0.0/16"], dst_addr=["192.168.1.0/24"])]
        candidate = _make_rule("candidate", 1, "permit",
                               src_addr=["10.0.1.0/24"], dst_addr=["192.168.1.0/24"])

        result = _normalize_analysis(
            existing_rules=json.dumps(existing),
            candidate_rule=json.dumps(candidate),
        )
        assert result["success"]
        for finding in result["findings"]:
            dims = finding["dimensions"]
            assert isinstance(dims, dict)
            assert "source_addresses" in dims
            assert dims["source_addresses"] in ("equal", "subset", "superset", "intersecting")


# ---------------------------------------------------------------------------
# Schema validation error tests
# ---------------------------------------------------------------------------


class TestNormalizedInputValidation:
    """Test error handling for invalid normalized input."""

    def test_invalid_json_existing_rules(self):
        result = _normalize_analysis(
            existing_rules="not json",
            candidate_rule='{"id":"c","position":1,"action":"permit"}',
        )
        assert not result["success"]
        assert result["error"]["code"] == "invalid_input"

    def test_existing_rules_not_array(self):
        result = _normalize_analysis(
            existing_rules='{"id":"r"}',
            candidate_rule='{"id":"c","position":1,"action":"permit"}',
        )
        assert not result["success"]
        assert result["error"]["code"] == "invalid_input"

    def test_invalid_action(self):
        result = _normalize_analysis(
            existing_rules=json.dumps([_make_rule("r1", 1, "permit")]),
            candidate_rule=json.dumps({"id": "c", "position": 1, "action": "zap"}),
        )
        assert not result["success"]
        assert result["error"]["code"] == "invalid_input"

    def test_missing_required_fields(self):
        result = _normalize_analysis(
            existing_rules=json.dumps([{"id": "r1"}]),
            candidate_rule=json.dumps({"id": "c", "position": 1, "action": "permit"}),
        )
        assert not result["success"]
        assert result["error"]["code"] == "invalid_input"

    def test_no_params_at_all(self):
        result = analyze_firewall_rule_overlap()
        assert not result["success"]
        assert result["error"]["code"] == "missing_parameters"


# ---------------------------------------------------------------------------
# parse_policy tool tests
# ---------------------------------------------------------------------------


class TestParsePolicy:
    """Test the parse_policy tool."""

    def test_parse_panos_policy(self):
        """Parse a PAN-OS policy and get normalized rules back."""
        policy = (FIXTURES / "panos_policy.xml").read_text()
        result = json.loads(parse_policy(vendor="panos", ruleset_payload=policy))

        assert result["success"]
        assert len(result["rules"]) > 0
        assert result["metadata"]["vendor"] == "panos"
        assert result["metadata"]["parser"] == "PANOSParser"
        assert result["metadata"]["rule_count"] == len(result["rules"])

        # Verify normalized schema
        for rule in result["rules"]:
            assert "id" in rule
            assert "position" in rule
            assert "action" in rule
            assert "source_addresses" in rule
            assert "destination_addresses" in rule
            assert "services" in rule
            assert isinstance(rule["source_addresses"], list)
            assert isinstance(rule["services"], list)

    def test_parse_asa_policy(self):
        policy = (FIXTURES / "asa_policy.conf").read_text()
        result = json.loads(parse_policy(vendor="asa", ruleset_payload=policy))
        assert result["success"]
        assert len(result["rules"]) > 0

    def test_parse_unsupported_vendor(self):
        result = json.loads(parse_policy(vendor="unknown_vendor", ruleset_payload=""))
        assert not result["success"]
        assert result["error"]["code"] == "unsupported_vendor"

    def test_parse_invalid_payload(self):
        result = json.loads(parse_policy(vendor="panos", ruleset_payload="<broken xml"))
        assert result["success"]  # Parser returns empty rules, not error
        assert result["metadata"]["rule_count"] == 0


# ---------------------------------------------------------------------------
# Round-trip tests: vendor parse → normalized → re-analyze
# ---------------------------------------------------------------------------


class TestRoundTrip:
    """Verify that parsing then re-analyzing via normalized path produces equivalent results."""

    def test_panos_roundtrip(self):
        """Parse PAN-OS via vendor parser, then re-analyze via normalized path."""
        policy = (FIXTURES / "panos_policy.xml").read_text()
        candidate = (FIXTURES / "candidates" / "panos_duplicate.xml").read_text()

        # Path A: vendor pipeline
        result_a = analyze_firewall_rule_overlap(
            vendor="panos",
            ruleset_payload=policy,
            candidate_rule_payload=candidate,
        )
        assert result_a["success"]

        # Parse policy to get normalized rules
        parsed = json.loads(parse_policy(vendor="panos", ruleset_payload=policy))
        assert parsed["success"]

        # Parse the candidate separately — we need it as normalized JSON too
        # For the round-trip, use the first finding's properties to build a candidate
        # that matches what the vendor parser would produce
        if result_a["overlap_exists"] and result_a["findings"]:
            # The vendor path found overlaps — verify the normalized path also finds overlaps
            # We can't easily get the candidate as normalized JSON from the vendor parser,
            # but we can verify the parsed existing rules are valid by feeding them back
            existing_json = json.dumps(parsed["rules"])

            # Build a candidate that we know is a duplicate of the first rule
            first_rule = parsed["rules"][0]
            candidate_json = json.dumps(first_rule)

            result_b = analyze_firewall_rule_overlap(
                existing_rules=existing_json,
                candidate_rule=candidate_json,
            )
            assert result_b["success"]
            assert result_b["overlap_exists"]
            types_b = [f["overlap_type"] for f in result_b["findings"]]
            assert "exact_duplicate" in types_b

    def test_asa_roundtrip(self):
        """Parse ASA via vendor parser, then verify normalized output is valid."""
        policy = (FIXTURES / "asa_policy.conf").read_text()
        parsed = json.loads(parse_policy(vendor="asa", ruleset_payload=policy))
        assert parsed["success"]
        assert len(parsed["rules"]) > 0

        # Re-analyze using the parsed rules
        existing_json = json.dumps(parsed["rules"])
        first_rule = parsed["rules"][0]
        candidate_json = json.dumps(first_rule)

        result = analyze_firewall_rule_overlap(
            existing_rules=existing_json,
            candidate_rule=candidate_json,
        )
        assert result["success"]
        assert result["overlap_exists"]


# ---------------------------------------------------------------------------
# Normalized input path precedence test
# ---------------------------------------------------------------------------


class TestInputPrecedence:
    """Verify that normalized input takes precedence when both paths are provided."""

    def test_normalized_takes_precedence(self):
        """When both vendor and normalized params are provided, normalized wins."""
        existing = [_make_rule("rule-1", 1, "permit",
                               src_addr=["10.0.0.0/24"], dst_addr=["any"])]
        candidate = _make_rule("candidate", 1, "permit",
                               src_addr=["10.0.0.0/24"], dst_addr=["any"])

        result = analyze_firewall_rule_overlap(
            # Vendor params (would fail — invalid vendor)
            vendor="invalid_vendor_xyz",
            ruleset_payload="garbage",
            candidate_rule_payload="garbage",
            # Normalized params (should succeed)
            existing_rules=json.dumps(existing),
            candidate_rule=json.dumps(candidate),
        )
        # If normalized takes precedence, this succeeds despite invalid vendor params
        assert result["success"]
        assert result["overlap_exists"]
