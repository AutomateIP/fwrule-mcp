"""
Unit tests for models/response.py — AnalysisResponse, Finding, OverlapType, Severity.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from fwrule_mcp.models.response import (
    AnalysisMetadata,
    AnalysisResponse,
    DimensionDetail,
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
        explanation="Test explanation.",
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

    def test_remediation_optional(self):
        f = _make_finding()
        assert f.remediation is None

    def test_dimension_detail_included(self):
        f = Finding(
            existing_rule_id="r1",
            existing_rule_position=1,
            overlap_type=OverlapType.SUBSET,
            severity=Severity.INFO,
            explanation="Subset.",
            dimensions=[
                DimensionDetail(
                    dimension="source_address",
                    relationship="subset",
                    description="Candidate is subset of existing.",
                )
            ],
        )
        assert len(f.dimensions) == 1
        assert f.dimensions[0].dimension == "source_address"

    def test_extra_fields_forbidden(self):
        with pytest.raises(Exception):
            Finding(
                existing_rule_id="r",
                existing_rule_position=1,
                overlap_type=OverlapType.NO_OVERLAP,
                severity=Severity.INFO,
                explanation=".",
                unknown_extra="x",
            )


class TestAnalysisResponse:
    def test_no_overlap_response(self):
        resp = AnalysisResponse(
            overlap_exists=False,
            findings=[],
            analysis_summary="No overlaps detected.",
            metadata=_make_metadata(),
        )
        assert not resp.overlap_exists
        assert resp.findings == []

    def test_with_finding(self):
        f = _make_finding(overlap_type=OverlapType.SHADOWED, severity=Severity.CRITICAL)
        resp = AnalysisResponse(
            overlap_exists=True,
            findings=[f],
            analysis_summary="Candidate is shadowed.",
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
            analysis_summary="Multiple issues.",
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
            analysis_summary=".",
            metadata=_make_metadata(),
        )
        assert len(resp.findings_by_type(OverlapType.CONFLICT)) == 2
        assert len(resp.findings_by_type(OverlapType.SHADOWED)) == 0

    def test_has_exact_duplicates(self):
        f = _make_finding(overlap_type=OverlapType.EXACT_DUPLICATE, severity=Severity.CRITICAL)
        resp = AnalysisResponse(
            overlap_exists=True,
            findings=[f],
            analysis_summary="Duplicate.",
            metadata=_make_metadata(),
        )
        assert resp.has_exact_duplicates()

    def test_metadata_timestamp_utc(self):
        meta = _make_metadata()
        assert meta.timestamp.tzinfo == timezone.utc

    def test_metadata_analysis_duration_nonnegative(self):
        with pytest.raises(Exception):
            _make_metadata(analysis_duration_ms=-1.0)
