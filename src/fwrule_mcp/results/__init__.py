"""
Result generation layer — assembles the final AnalysisResponse from raw findings.

Responsibilities:
  - Convert raw RuleRelationship objects into Finding objects
  - Assign Severity based on OverlapType + action + ordering context
  - Assemble compact AnalysisResponse with metadata
"""

from fwrule_mcp.results.generator import ResultGenerator

__all__ = [
    "ResultGenerator",
]
