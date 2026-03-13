"""
Unit tests for models/response.py — AnalysisResponse, Finding, OverlapType, Severity.
"""

from __future__ import annotations

import pytest

from fwrule_mcp.models.response import (
    AnalysisMetadata,
    AnalysisResponse,
    Finding,
    OverlapType,
    Severity,
)


def _make_metadata(**kwargs) -> AnalysisMetadata:
    defaults = dict(
        vendor="panos",
        existing_rule_count=10,
        enabled_rule_count=9,
        analysis_duration_ms=42.0,
    )
    defaults.update(kwargs)
    return AnalysisMetadata(**defaults)


def _make_finding(
    overlap_type: OverlapType = OverlapType.PARTIAL_OVERLAP,
    severity: Severity = Severity.MEDIUM,
    rule_id: str = "rule_5",
    position: int = 5,
) -> Finding:
    return Finding(
        existing_rule_id=rule_id,
        existing_rule_position=position,
        overlap_type=overlap_type,
        severity=severity,
    )


class TestFinding:
    def test_basic_construction(self):
        f = _make_finding()
        assert f.existing_rule_id == "rule_5"
        assert f.overlap_type == OverlapType.PARTIAL_OVERLAP

    def test_is_critical_or_high(self):
        assert _make_finding(severity=Severity.CRITICAL).is_critical_or_high
        assert _make_finding(severity=Severity.HIGH).is_critical_or_high
        assert not _make_finding(severity=Severity.MEDIUM).is_critical_or_high
        assert not _make_finding(severity=Severity.LOW).is_critical_or_high

    def test_dimensions_as_dict(self):
        f = Finding(
            existing_rule_id="r1",
            existing_rule_position=1,
            overlap_type=OverlapType.SUBSET,
            severity=Severity.INFO,
            dimensions={"source_addresses": "subset", "services": "equal"},
        )
        assert f.dimensions["source_addresses"] == "subset"
        assert f.dimensions["services"] == "equal"

    def test_extra_fields_forbidden(self):
        with pytest.raises(Exception):
            Finding(
                existing_rule_id="r",
                existing_rule_position=1,
                overlap_type=OverlapType.NO_OVERLAP,
                severity=Severity.INFO,
                unknown_extra="x",
            )


class TestAnalysisResponse:
    def test_no_overlap_response(self):
        resp = AnalysisResponse(
            overlap_exists=False,
            findings=[],
            metadata=_make_metadata(),
        )
        assert not resp.overlap_exists
        assert resp.findings == []

    def test_with_finding(self):
        f = _make_finding(overlap_type=OverlapType.SHADOWED, severity=Severity.CRITICAL)
        resp = AnalysisResponse(
            overlap_exists=True,
            findings=[f],
            metadata=_make_metadata(),
        )
        assert resp.overlap_exists
        assert len(resp.findings) == 1
        assert resp.has_shadows()
        assert not resp.has_conflicts()
        assert not resp.has_exact_duplicates()

    def test_critical_findings_filter(self):
        findings = [
            _make_finding(severity=Severity.CRITICAL, rule_id="r1"),
            _make_finding(severity=Severity.MEDIUM, rule_id="r2"),
            _make_finding(severity=Severity.CRITICAL, rule_id="r3"),
        ]
        resp = AnalysisResponse(
            overlap_exists=True,
            findings=findings,
            metadata=_make_metadata(),
        )
        assert len(resp.critical_findings()) == 2
        assert len(resp.high_findings()) == 0

    def test_findings_by_type(self):
        findings = [
            _make_finding(overlap_type=OverlapType.CONFLICT, rule_id="r1"),
            _make_finding(overlap_type=OverlapType.PARTIAL_OVERLAP, rule_id="r2"),
            _make_finding(overlap_type=OverlapType.CONFLICT, rule_id="r3"),
        ]
        resp = AnalysisResponse(
            overlap_exists=True,
            findings=findings,
            metadata=_make_metadata(),
        )
        assert len(resp.findings_by_type(OverlapType.CONFLICT)) == 2
        assert len(resp.findings_by_type(OverlapType.SHADOWED)) == 0

    def test_has_exact_duplicates(self):
        f = _make_finding(overlap_type=OverlapType.EXACT_DUPLICATE, severity=Severity.CRITICAL)
        resp = AnalysisResponse(
            overlap_exists=True,
            findings=[f],
            metadata=_make_metadata(),
        )
        assert resp.has_exact_duplicates()

    def test_metadata_analysis_duration_nonnegative(self):
        with pytest.raises(Exception):
            _make_metadata(analysis_duration_ms=-1.0)
