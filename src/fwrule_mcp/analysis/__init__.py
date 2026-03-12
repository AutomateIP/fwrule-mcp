"""
Analysis engine — pure set-theoretic overlap detection and classification.

This layer has no knowledge of vendors, parsing, or MCP protocol.
It operates exclusively on NormalizedRule / NormalizedCandidate objects and
produces AnalysisResult / RuleRelationship structures consumed by the result
generation layer.

Analysis passes (in order, all implemented via classify_overlap):
  1. Exact duplicate check   → OverlapType.EXACT_DUPLICATE
  2. Shadow analysis         → OverlapType.SHADOWED / SHADOWS_EXISTING
  3. Conflict detection      → OverlapType.CONFLICT
  4. Superset / subset       → OverlapType.SUPERSET / SUBSET
  5. Partial overlap         → OverlapType.PARTIAL_OVERLAP

Public surface
--------------
Classes:
  OverlapAnalysisEngine     — primary class-based interface
  AnalysisResult            — return type of engine.analyze()
  RuleRelationship          — per-rule relationship (from classifier)
  DimensionAnalysis         — per-dimension detail (from classifier)

Functions:
  analyze()                 — module-level convenience wrapper

Sub-modules (importable directly if needed):
  address    — AddressComparison, compare_address_sets()
  service    — ServiceComparison, compare_service_sets()
  zone       — ZoneComparison, compare_zone_sets()
  classifier — classify_overlap(), DimensionAnalysis, RuleRelationship
  engine     — OverlapAnalysisEngine, AnalysisResult, analyze()
"""

from fwrule_mcp.analysis.address import AddressComparison, compare_address_sets
from fwrule_mcp.analysis.service import ServiceComparison, compare_service_sets
from fwrule_mcp.analysis.zone import ZoneComparison, compare_zone_sets
from fwrule_mcp.analysis.classifier import (
    DimensionAnalysis,
    RuleRelationship,
    classify_overlap,
)
from fwrule_mcp.analysis.engine import (
    AnalysisResult,
    OverlapAnalysisEngine,
    analyze,
)

__all__ = [
    # Address
    "AddressComparison",
    "compare_address_sets",
    # Service
    "ServiceComparison",
    "compare_service_sets",
    # Zone
    "ZoneComparison",
    "compare_zone_sets",
    # Classifier
    "DimensionAnalysis",
    "RuleRelationship",
    "classify_overlap",
    # Engine
    "AnalysisResult",
    "OverlapAnalysisEngine",
    "analyze",
]
