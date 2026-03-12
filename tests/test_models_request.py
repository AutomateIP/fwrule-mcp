"""
Unit tests for models/request.py — AnalysisRequest and ContextObjects validation.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from fwrule_mcp.models.request import AnalysisRequest, ContextObjects


VALID_PAYLOAD = "<config><rules><entry name='r1'/></rules></config>"


class TestAnalysisRequest:
    def test_valid_request(self):
        req = AnalysisRequest(
            vendor="panos",
            ruleset_payload=VALID_PAYLOAD,
            candidate_rule_payload="<entry name='candidate'/>",
        )
        assert req.vendor == "panos"

    def test_vendor_with_mixed_case_panos_accepted(self):
        """Validator lowercases input — 'PANOS' (all caps) normalizes to 'panos'."""
        req = AnalysisRequest(
            vendor="PANOS",
            ruleset_payload=VALID_PAYLOAD,
            candidate_rule_payload="<entry/>",
        )
        assert req.vendor == "panos"

    def test_vendor_panos_accepted(self):
        req = AnalysisRequest(
            vendor="panos",
            ruleset_payload=VALID_PAYLOAD,
            candidate_rule_payload="<entry/>",
        )
        assert req.vendor == "panos"

    def test_unsupported_vendor_raises(self):
        with pytest.raises(ValidationError, match="Unsupported vendor"):
            AnalysisRequest(
                vendor="fortigate",
                ruleset_payload=VALID_PAYLOAD,
                candidate_rule_payload="<entry/>",
            )

    def test_all_supported_vendors_accepted(self):
        from fwrule_mcp.models.request import SUPPORTED_VENDORS
        for vendor in SUPPORTED_VENDORS:
            req = AnalysisRequest(
                vendor=vendor,
                ruleset_payload=VALID_PAYLOAD,
                candidate_rule_payload="<entry/>",
            )
            assert req.vendor == vendor

    def test_empty_ruleset_raises(self):
        with pytest.raises(ValidationError, match="must not be empty"):
            AnalysisRequest(
                vendor="panos",
                ruleset_payload="   ",
                candidate_rule_payload="<entry/>",
            )

    def test_empty_candidate_raises(self):
        with pytest.raises(ValidationError, match="must not be empty"):
            AnalysisRequest(
                vendor="panos",
                ruleset_payload=VALID_PAYLOAD,
                candidate_rule_payload="",
            )

    def test_os_version_optional(self):
        req = AnalysisRequest(
            vendor="asa",
            ruleset_payload=VALID_PAYLOAD,
            candidate_rule_payload="access-list TEST extended permit ip any any",
        )
        assert req.os_version is None

    def test_os_version_stored(self):
        req = AnalysisRequest(
            vendor="asa",
            os_version="9.16",
            ruleset_payload=VALID_PAYLOAD,
            candidate_rule_payload="access-list TEST extended permit ip any any",
        )
        assert req.os_version == "9.16"

    def test_intended_position_ge_1(self):
        with pytest.raises(ValidationError):
            AnalysisRequest(
                vendor="panos",
                ruleset_payload=VALID_PAYLOAD,
                candidate_rule_payload="<entry/>",
                candidate_intended_position=0,
            )

    def test_context_optional(self):
        req = AnalysisRequest(
            vendor="panos",
            ruleset_payload=VALID_PAYLOAD,
            candidate_rule_payload="<entry/>",
            context=ContextObjects(
                address_objects={"WebServers": "10.1.2.0/24"},
                service_objects={"HTTPS": "tcp/443"},
            ),
        )
        assert req.context is not None
        assert req.context.address_objects == {"WebServers": "10.1.2.0/24"}

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            AnalysisRequest(
                vendor="panos",
                ruleset_payload=VALID_PAYLOAD,
                candidate_rule_payload="<entry/>",
                unknown_field="should_fail",
            )
