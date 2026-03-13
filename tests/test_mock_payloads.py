"""
Tests using realistic mock payloads from fixtures/.

Each vendor class tests five overlap scenarios using the fixture files in
tests/fixtures/ and tests/fixtures/candidates/.

Run with:
    uv run pytest tests/test_mock_payloads.py -v
    uv run pytest tests/test_mock_payloads.py -v -k panos
    uv run pytest tests/test_mock_payloads.py -v -k duplicate
"""

from __future__ import annotations

from pathlib import Path

import pytest

from fwrule_mcp.server import analyze_firewall_rule_overlap

# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

FIXTURES = Path(__file__).parent / "fixtures"
CANDIDATES = FIXTURES / "candidates"


def _load(path: str) -> str:
    """Load a fixture from the fixtures/ directory."""
    return (FIXTURES / path).read_text()


def _load_candidate(path: str) -> str:
    """Load a candidate fixture from the fixtures/candidates/ directory."""
    return (CANDIDATES / path).read_text()


def _run(vendor: str, policy_file: str, candidate_file: str) -> dict:
    """Helper to run the full analysis pipeline and return the result dict."""
    return analyze_firewall_rule_overlap(
        vendor=vendor,
        ruleset_payload=_load(policy_file),
        candidate_rule_payload=_load_candidate(candidate_file),
    )


def _overlap_types(result: dict) -> list[str]:
    """Extract list of overlap_type strings from all findings."""
    return [f["overlap_type"] for f in result.get("findings", [])]


# ---------------------------------------------------------------------------
# PAN-OS Tests
# ---------------------------------------------------------------------------


class TestPANOSMockPayloads:
    """Test realistic PAN-OS policy with five candidate scenarios."""

    VENDOR = "panos"
    POLICY = "panos_policy.xml"

    def test_parse_succeeds(self):
        """Policy parses without error before any candidate testing."""
        result = _run(self.VENDOR, self.POLICY, "panos_duplicate.xml")
        assert result["success"], f"Pipeline failed: {result.get('error')}"

    def test_duplicate(self):
        """Exact copy of an existing rule → exact_duplicate finding."""
        result = _run(self.VENDOR, self.POLICY, "panos_duplicate.xml")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert result["overlap_exists"], "Expected overlap_exists=True for duplicate"
        types = _overlap_types(result)
        assert "exact_duplicate" in types, (
            f"Expected 'exact_duplicate' in findings, got: {types}"
        )

    def test_shadowed(self):
        """Narrower candidate covered by existing broad rule → shadowed finding."""
        result = _run(self.VENDOR, self.POLICY, "panos_shadowed.xml")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert result["overlap_exists"], "Expected overlap_exists=True for shadowed rule"
        types = _overlap_types(result)
        # shadowed means an existing rule above the candidate covers it entirely
        assert any(t in ("shadowed", "subset") for t in types), (
            f"Expected 'shadowed' or 'subset' in findings, got: {types}"
        )

    def test_conflict(self):
        """Same match, opposing action → conflict finding."""
        result = _run(self.VENDOR, self.POLICY, "panos_conflict.xml")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert result["overlap_exists"], "Expected overlap_exists=True for conflict"
        types = _overlap_types(result)
        assert "conflict" in types, (
            f"Expected 'conflict' in findings, got: {types}"
        )

    def test_partial_overlap(self):
        """Candidate overlaps but is not a subset/superset → partial or superset finding."""
        result = _run(self.VENDOR, self.POLICY, "panos_partial.xml")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert result["overlap_exists"], "Expected overlap_exists=True for partial overlap"
        types = _overlap_types(result)
        assert any(t in ("partial_overlap", "superset", "subset", "conflict") for t in types), (
            f"Expected overlap finding, got: {types}"
        )

    def test_no_overlap(self):
        """Completely disjoint candidate → no findings."""
        result = _run(self.VENDOR, self.POLICY, "panos_no_overlap.xml")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert not result["overlap_exists"], (
            f"Expected overlap_exists=False for disjoint rule, findings: {_overlap_types(result)}"
        )
        assert result["findings"] == [], (
            f"Expected empty findings for disjoint rule, got: {result['findings']}"
        )


# ---------------------------------------------------------------------------
# Cisco ASA Tests
# ---------------------------------------------------------------------------


class TestASAMockPayloads:
    """Test realistic ASA policy with five candidate scenarios."""

    VENDOR = "asa"
    POLICY = "asa_policy.conf"

    def test_parse_succeeds(self):
        """Policy parses without error before any candidate testing."""
        result = _run(self.VENDOR, self.POLICY, "asa_duplicate.conf")
        assert result["success"], f"Pipeline failed: {result.get('error')}"

    def test_duplicate(self):
        """Exact copy of an existing ACL rule → exact_duplicate finding."""
        result = _run(self.VENDOR, self.POLICY, "asa_duplicate.conf")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert result["overlap_exists"], "Expected overlap_exists=True for duplicate"
        types = _overlap_types(result)
        assert "exact_duplicate" in types, (
            f"Expected 'exact_duplicate' in findings, got: {types}"
        )

    def test_shadowed(self):
        """Host-specific rule inside a broader existing subnet rule → shadowed/subset."""
        result = _run(self.VENDOR, self.POLICY, "asa_shadowed.conf")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert result["overlap_exists"], "Expected overlap_exists=True for shadowed rule"
        types = _overlap_types(result)
        assert any(t in ("shadowed", "subset") for t in types), (
            f"Expected 'shadowed' or 'subset' in findings, got: {types}"
        )

    def test_conflict(self):
        """Same match criteria, deny vs permit → conflict finding."""
        result = _run(self.VENDOR, self.POLICY, "asa_conflict.conf")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert result["overlap_exists"], "Expected overlap_exists=True for conflict"
        types = _overlap_types(result)
        assert "conflict" in types, (
            f"Expected 'conflict' in findings, got: {types}"
        )

    def test_partial_overlap(self):
        """Broader destination subnet overlapping existing narrower rule → overlap."""
        result = _run(self.VENDOR, self.POLICY, "asa_partial.conf")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert result["overlap_exists"], "Expected overlap_exists=True for partial overlap"
        types = _overlap_types(result)
        assert any(t in ("partial_overlap", "superset", "shadows_existing", "conflict") for t in types), (
            f"Expected overlap finding, got: {types}"
        )

    def test_no_overlap(self):
        """Completely different subnet/port space → no findings."""
        result = _run(self.VENDOR, self.POLICY, "asa_no_overlap.conf")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert not result["overlap_exists"], (
            f"Expected overlap_exists=False for disjoint rule, findings: {_overlap_types(result)}"
        )


# ---------------------------------------------------------------------------
# Cisco FTD Tests
# ---------------------------------------------------------------------------


class TestFTDMockPayloads:
    """Test realistic FTD/FMC JSON policy with five candidate scenarios."""

    VENDOR = "ftd"
    POLICY = "ftd_policy.json"

    def test_parse_succeeds(self):
        """Policy parses without error before any candidate testing."""
        result = _run(self.VENDOR, self.POLICY, "ftd_duplicate.json")
        assert result["success"], f"Pipeline failed: {result.get('error')}"

    def test_duplicate(self):
        """Exact duplicate of FTD allow-web-inbound rule."""
        result = _run(self.VENDOR, self.POLICY, "ftd_duplicate.json")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert result["overlap_exists"], "Expected overlap_exists=True for duplicate"
        types = _overlap_types(result)
        assert "exact_duplicate" in types, (
            f"Expected 'exact_duplicate' in findings, got: {types}"
        )

    def test_shadowed(self):
        """Single-host rule inside a /24 subnet rule → shadowed/subset."""
        result = _run(self.VENDOR, self.POLICY, "ftd_shadowed.json")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert result["overlap_exists"], "Expected overlap_exists=True for shadowed rule"
        types = _overlap_types(result)
        assert any(t in ("shadowed", "subset") for t in types), (
            f"Expected 'shadowed' or 'subset' in findings, got: {types}"
        )

    def test_conflict(self):
        """BLOCK candidate vs ALLOW existing with same match → conflict."""
        result = _run(self.VENDOR, self.POLICY, "ftd_conflict.json")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert result["overlap_exists"], "Expected overlap_exists=True for conflict"
        types = _overlap_types(result)
        assert "conflict" in types, (
            f"Expected 'conflict' in findings, got: {types}"
        )

    def test_partial_overlap(self):
        """Same source/service as existing rule but broader /16 destination."""
        result = _run(self.VENDOR, self.POLICY, "ftd_partial.json")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert result["overlap_exists"], "Expected overlap_exists=True for partial overlap"
        types = _overlap_types(result)
        assert any(t in ("partial_overlap", "superset", "shadows_existing", "conflict") for t in types), (
            f"Expected overlap finding, got: {types}"
        )

    def test_no_overlap(self):
        """Completely different zone pair and subnet → no findings."""
        result = _run(self.VENDOR, self.POLICY, "ftd_no_overlap.json")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert not result["overlap_exists"], (
            f"Expected overlap_exists=False for disjoint rule, findings: {_overlap_types(result)}"
        )


# ---------------------------------------------------------------------------
# Check Point Tests
# ---------------------------------------------------------------------------


class TestCheckPointMockPayloads:
    """Test realistic Check Point JSON rulebase with five candidate scenarios."""

    VENDOR = "checkpoint"
    POLICY = "checkpoint_policy.json"

    def test_parse_succeeds(self):
        """Policy parses without error before any candidate testing."""
        result = _run(self.VENDOR, self.POLICY, "checkpoint_duplicate.json")
        assert result["success"], f"Pipeline failed: {result.get('error')}"

    def test_duplicate(self):
        """Exact duplicate of the allow-web-inbound rule."""
        result = _run(self.VENDOR, self.POLICY, "checkpoint_duplicate.json")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert result["overlap_exists"], "Expected overlap_exists=True for duplicate"
        types = _overlap_types(result)
        assert "exact_duplicate" in types, (
            f"Expected 'exact_duplicate' in findings, got: {types}"
        )

    def test_shadowed(self):
        """Single host inside web-servers /24 → shadowed/subset."""
        result = _run(self.VENDOR, self.POLICY, "checkpoint_shadowed.json")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert result["overlap_exists"], "Expected overlap_exists=True for shadowed rule"
        types = _overlap_types(result)
        assert any(t in ("shadowed", "subset") for t in types), (
            f"Expected 'shadowed' or 'subset' in findings, got: {types}"
        )

    def test_conflict(self):
        """Drop vs Accept with identical match → conflict."""
        result = _run(self.VENDOR, self.POLICY, "checkpoint_conflict.json")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert result["overlap_exists"], "Expected overlap_exists=True for conflict"
        types = _overlap_types(result)
        assert "conflict" in types, (
            f"Expected 'conflict' in findings, got: {types}"
        )

    def test_partial_overlap(self):
        """Broader /16 destination overlapping existing /24 DB rule."""
        result = _run(self.VENDOR, self.POLICY, "checkpoint_partial.json")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert result["overlap_exists"], "Expected overlap_exists=True for partial overlap"
        types = _overlap_types(result)
        assert any(t in ("partial_overlap", "superset", "shadows_existing", "conflict") for t in types), (
            f"Expected overlap finding, got: {types}"
        )

    def test_no_overlap(self):
        """Different zones (vpn/isolated-backend) and subnets → no findings."""
        result = _run(self.VENDOR, self.POLICY, "checkpoint_no_overlap.json")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert not result["overlap_exists"], (
            f"Expected overlap_exists=False for disjoint rule, findings: {_overlap_types(result)}"
        )


# ---------------------------------------------------------------------------
# Juniper SRX Tests
# ---------------------------------------------------------------------------


class TestJuniperMockPayloads:
    """Test realistic Juniper SRX set-format policy with five candidate scenarios."""

    VENDOR = "juniper"
    POLICY = "juniper_policy.txt"

    def test_parse_succeeds(self):
        """Policy parses without error before any candidate testing."""
        result = _run(self.VENDOR, self.POLICY, "juniper_duplicate.txt")
        assert result["success"], f"Pipeline failed: {result.get('error')}"

    def test_duplicate(self):
        """Exact duplicate of allow-web-inbound Juniper policy."""
        result = _run(self.VENDOR, self.POLICY, "juniper_duplicate.txt")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert result["overlap_exists"], "Expected overlap_exists=True for duplicate"
        types = _overlap_types(result)
        assert "exact_duplicate" in types, (
            f"Expected 'exact_duplicate' in findings, got: {types}"
        )

    def test_shadowed(self):
        """Single-host candidate inside web-servers /24 → shadowed/subset."""
        result = _run(self.VENDOR, self.POLICY, "juniper_shadowed.txt")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert result["overlap_exists"], "Expected overlap_exists=True for shadowed rule"
        types = _overlap_types(result)
        assert any(t in ("shadowed", "subset") for t in types), (
            f"Expected 'shadowed' or 'subset' in findings, got: {types}"
        )

    def test_conflict(self):
        """deny vs permit for same zone pair and traffic match → conflict."""
        result = _run(self.VENDOR, self.POLICY, "juniper_conflict.txt")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert result["overlap_exists"], "Expected overlap_exists=True for conflict"
        types = _overlap_types(result)
        assert "conflict" in types, (
            f"Expected 'conflict' in findings, got: {types}"
        )

    def test_partial_overlap(self):
        """Broader /16 destination (db-supernet) overlapping existing /24 DB rule."""
        result = _run(self.VENDOR, self.POLICY, "juniper_partial.txt")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert result["overlap_exists"], "Expected overlap_exists=True for partial overlap"
        types = _overlap_types(result)
        assert any(t in ("partial_overlap", "superset", "shadows_existing", "conflict") for t in types), (
            f"Expected overlap finding, got: {types}"
        )

    def test_no_overlap(self):
        """Completely different zone pair (vpn/isolated) and subnets → no findings."""
        result = _run(self.VENDOR, self.POLICY, "juniper_no_overlap.txt")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert not result["overlap_exists"], (
            f"Expected overlap_exists=False for disjoint rule, findings: {_overlap_types(result)}"
        )


# ---------------------------------------------------------------------------
# Cisco IOS Tests
# ---------------------------------------------------------------------------


class TestIOSMockPayloads:
    """Test realistic IOS/IOS-XE policy with five candidate scenarios."""

    VENDOR = "ios"
    POLICY = "ios_policy.conf"

    def test_parse_succeeds(self):
        """Policy parses without error before any candidate testing."""
        result = _run(self.VENDOR, self.POLICY, "ios_duplicate.conf")
        assert result["success"], f"Pipeline failed: {result.get('error')}"

    def test_duplicate(self):
        """Exact copy of the allow-web rule → exact_duplicate finding."""
        result = _run(self.VENDOR, self.POLICY, "ios_duplicate.conf")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert result["overlap_exists"], "Expected overlap_exists=True for duplicate"
        types = _overlap_types(result)
        assert "exact_duplicate" in types, (
            f"Expected 'exact_duplicate' in findings, got: {types}"
        )

    def test_shadowed(self):
        """Host-specific rule inside broader /24 rule → shadowed/subset finding."""
        result = _run(self.VENDOR, self.POLICY, "ios_shadowed.conf")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert result["overlap_exists"], "Expected overlap_exists=True for shadowed rule"
        types = _overlap_types(result)
        assert any(t in ("shadowed", "subset") for t in types), (
            f"Expected 'shadowed' or 'subset' in findings, got: {types}"
        )

    def test_conflict(self):
        """Same match criteria, deny vs permit → conflict finding."""
        result = _run(self.VENDOR, self.POLICY, "ios_conflict.conf")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert result["overlap_exists"], "Expected overlap_exists=True for conflict"
        types = _overlap_types(result)
        assert "conflict" in types, (
            f"Expected 'conflict' in findings, got: {types}"
        )

    def test_partial_overlap(self):
        """Broader /16 destination overlapping existing /24 allow-web rule → overlap."""
        result = _run(self.VENDOR, self.POLICY, "ios_partial.conf")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert result["overlap_exists"], "Expected overlap_exists=True for partial overlap"
        types = _overlap_types(result)
        assert any(t in ("partial_overlap", "superset", "shadows_existing", "conflict") for t in types), (
            f"Expected overlap finding, got: {types}"
        )

    def test_no_overlap(self):
        """Completely different subnet and port → no findings."""
        result = _run(self.VENDOR, self.POLICY, "ios_no_overlap.conf")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert not result["overlap_exists"], (
            f"Expected overlap_exists=False for disjoint rule, findings: {_overlap_types(result)}"
        )
        assert result["findings"] == [], (
            f"Expected empty findings for disjoint rule, got: {result['findings']}"
        )


# ---------------------------------------------------------------------------
# Cisco IOS-XR Tests
# ---------------------------------------------------------------------------


class TestIOSXRMockPayloads:
    """Test realistic IOS-XR policy with five candidate scenarios."""

    VENDOR = "iosxr"
    POLICY = "iosxr_policy.conf"

    def test_parse_succeeds(self):
        """Policy parses without error before any candidate testing."""
        result = _run(self.VENDOR, self.POLICY, "iosxr_duplicate.conf")
        assert result["success"], f"Pipeline failed: {result.get('error')}"

    def test_duplicate(self):
        """Exact copy of the allow-web rule → exact_duplicate finding."""
        result = _run(self.VENDOR, self.POLICY, "iosxr_duplicate.conf")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert result["overlap_exists"], "Expected overlap_exists=True for duplicate"
        types = _overlap_types(result)
        assert "exact_duplicate" in types, (
            f"Expected 'exact_duplicate' in findings, got: {types}"
        )

    def test_shadowed(self):
        """Host-specific rule inside broader /24 rule → shadowed/subset finding."""
        result = _run(self.VENDOR, self.POLICY, "iosxr_shadowed.conf")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert result["overlap_exists"], "Expected overlap_exists=True for shadowed rule"
        types = _overlap_types(result)
        assert any(t in ("shadowed", "subset") for t in types), (
            f"Expected 'shadowed' or 'subset' in findings, got: {types}"
        )

    def test_conflict(self):
        """Same match criteria, deny vs permit → conflict finding."""
        result = _run(self.VENDOR, self.POLICY, "iosxr_conflict.conf")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert result["overlap_exists"], "Expected overlap_exists=True for conflict"
        types = _overlap_types(result)
        assert "conflict" in types, (
            f"Expected 'conflict' in findings, got: {types}"
        )

    def test_partial_overlap(self):
        """Broader /16 destination overlapping existing /24 rule → overlap."""
        result = _run(self.VENDOR, self.POLICY, "iosxr_partial.conf")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert result["overlap_exists"], "Expected overlap_exists=True for partial overlap"
        types = _overlap_types(result)
        assert any(t in ("partial_overlap", "superset", "shadows_existing", "conflict") for t in types), (
            f"Expected overlap finding, got: {types}"
        )

    def test_no_overlap(self):
        """Completely different subnet and port → no findings."""
        result = _run(self.VENDOR, self.POLICY, "iosxr_no_overlap.conf")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert not result["overlap_exists"], (
            f"Expected overlap_exists=False for disjoint rule, findings: {_overlap_types(result)}"
        )
        assert result["findings"] == [], (
            f"Expected empty findings for disjoint rule, got: {result['findings']}"
        )


# ---------------------------------------------------------------------------
# Juniper Junos Router Filter Tests
# ---------------------------------------------------------------------------


class TestJunosMockPayloads:
    """Test realistic Junos router firewall filter with five candidate scenarios."""

    VENDOR = "junos"
    POLICY = "junos_policy.txt"

    def test_parse_succeeds(self):
        """Policy parses without error before any candidate testing."""
        result = _run(self.VENDOR, self.POLICY, "junos_duplicate.txt")
        assert result["success"], f"Pipeline failed: {result.get('error')}"

    def test_duplicate(self):
        """Exact copy of the allow-web term → exact_duplicate finding."""
        result = _run(self.VENDOR, self.POLICY, "junos_duplicate.txt")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert result["overlap_exists"], "Expected overlap_exists=True for duplicate"
        types = _overlap_types(result)
        assert "exact_duplicate" in types, (
            f"Expected 'exact_duplicate' in findings, got: {types}"
        )

    def test_shadowed(self):
        """Single-host /32 inside /24 allow-web term → shadowed/subset finding."""
        result = _run(self.VENDOR, self.POLICY, "junos_shadowed.txt")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert result["overlap_exists"], "Expected overlap_exists=True for shadowed rule"
        types = _overlap_types(result)
        assert any(t in ("shadowed", "subset") for t in types), (
            f"Expected 'shadowed' or 'subset' in findings, got: {types}"
        )

    def test_conflict(self):
        """discard vs accept for same match → conflict finding."""
        result = _run(self.VENDOR, self.POLICY, "junos_conflict.txt")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert result["overlap_exists"], "Expected overlap_exists=True for conflict"
        types = _overlap_types(result)
        assert "conflict" in types, (
            f"Expected 'conflict' in findings, got: {types}"
        )

    def test_partial_overlap(self):
        """Broader /16 destination overlapping existing /24 allow-web term → overlap."""
        result = _run(self.VENDOR, self.POLICY, "junos_partial.txt")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert result["overlap_exists"], "Expected overlap_exists=True for partial overlap"
        types = _overlap_types(result)
        assert any(t in ("partial_overlap", "superset", "shadows_existing", "conflict") for t in types), (
            f"Expected overlap finding, got: {types}"
        )

    def test_no_overlap(self):
        """Completely disjoint subnets and port → no findings."""
        result = _run(self.VENDOR, self.POLICY, "junos_no_overlap.txt")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert not result["overlap_exists"], (
            f"Expected overlap_exists=False for disjoint rule, findings: {_overlap_types(result)}"
        )
        assert result["findings"] == [], (
            f"Expected empty findings for disjoint rule, got: {result['findings']}"
        )


# ---------------------------------------------------------------------------
# Nokia SR OS Tests
# ---------------------------------------------------------------------------


class TestSROSMockPayloads:
    """Test realistic Nokia SR OS MD-CLI policy with five candidate scenarios."""

    VENDOR = "sros"
    POLICY = "sros_policy.txt"

    def test_parse_succeeds(self):
        """Policy parses without error before any candidate testing."""
        result = _run(self.VENDOR, self.POLICY, "sros_duplicate.txt")
        assert result["success"], f"Pipeline failed: {result.get('error')}"

    def test_duplicate(self):
        """Exact copy of entry 10 (allow HTTP to web servers) → exact_duplicate finding."""
        result = _run(self.VENDOR, self.POLICY, "sros_duplicate.txt")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert result["overlap_exists"], "Expected overlap_exists=True for duplicate"
        types = _overlap_types(result)
        assert "exact_duplicate" in types, (
            f"Expected 'exact_duplicate' in findings, got: {types}"
        )

    def test_shadowed(self):
        """Single-host /32 inside /24 accept entry → shadowed/subset finding."""
        result = _run(self.VENDOR, self.POLICY, "sros_shadowed.txt")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert result["overlap_exists"], "Expected overlap_exists=True for shadowed rule"
        types = _overlap_types(result)
        assert any(t in ("shadowed", "subset") for t in types), (
            f"Expected 'shadowed' or 'subset' in findings, got: {types}"
        )

    def test_conflict(self):
        """drop vs accept for same dst match → conflict finding."""
        result = _run(self.VENDOR, self.POLICY, "sros_conflict.txt")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert result["overlap_exists"], "Expected overlap_exists=True for conflict"
        types = _overlap_types(result)
        assert "conflict" in types, (
            f"Expected 'conflict' in findings, got: {types}"
        )

    def test_partial_overlap(self):
        """Broader /16 destination overlapping existing /24 accept entry → overlap."""
        result = _run(self.VENDOR, self.POLICY, "sros_partial.txt")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert result["overlap_exists"], "Expected overlap_exists=True for partial overlap"
        types = _overlap_types(result)
        assert any(t in ("partial_overlap", "superset", "shadows_existing", "conflict") for t in types), (
            f"Expected overlap finding, got: {types}"
        )

    def test_no_overlap(self):
        """Completely disjoint subnets and port → no findings."""
        result = _run(self.VENDOR, self.POLICY, "sros_no_overlap.txt")
        assert result["success"], f"Pipeline failed: {result.get('error')}"
        assert not result["overlap_exists"], (
            f"Expected overlap_exists=False for disjoint rule, findings: {_overlap_types(result)}"
        )
        assert result["findings"] == [], (
            f"Expected empty findings for disjoint rule, got: {result['findings']}"
        )
