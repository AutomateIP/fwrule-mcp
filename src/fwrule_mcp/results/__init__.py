"""
Result generation layer — assembles the final AnalysisResponse from raw findings.

Responsibilities:
  - Convert raw RuleRelationship objects into Finding objects
  - Generate per-finding DimensionDetail breakdown
  - Assign Severity based on OverlapType + action + ordering context
  - Generate natural-language explanation strings
  - Generate optional remediation suggestion strings
  - Assemble AnalysisResponse with summary and metadata
"""

from fwrule_mcp.results.explanations import (
    EXPLANATION_MAP,
    generate_explanation,
)
from fwrule_mcp.results.generator import ResultGenerator
from fwrule_mcp.results.remediation import suggest_remediation

__all__ = [
    "EXPLANATION_MAP",
    "ResultGenerator",
    "generate_explanation",
    "suggest_remediation",
]
