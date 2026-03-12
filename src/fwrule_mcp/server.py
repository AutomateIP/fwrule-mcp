"""
MCP Server entry point — FWRule MCP — Firewall Rule Analyzer.

This module registers the ``analyze_firewall_rule_overlap`` tool with FastMCP
and wires the request → parse → normalize → analyze → respond pipeline.

Pipeline per request:
  1. Validate inputs (vendor, payload sizes, context JSON)
  2. Get the appropriate VendorParser from the registry
  3. Parse the existing policy → ParsedPolicy
  4. Parse the candidate rule   → VendorRule
  5. Normalize both             → list[NormalizedRule], NormalizedCandidate
  6. Run the analysis engine    → AnalysisResult
  7. Generate the response      → AnalysisResponse
  8. Return as a dict (FastMCP serializes to JSON)

Error handling:
  - ValidationError, UnsupportedVendorError, and parse errors are caught at
    each stage and returned as structured error dicts (not server crashes).
  - Unexpected exceptions are caught at the top level and returned as
    internal_error responses with no payload content in the message.

Security notes:
  - Payload content is never logged — only metadata (vendor, size, rule counts).
  - XML payloads are validated with defusedxml before parsing.
  - Payload size limits are enforced before any parsing begins.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Optional

from fastmcp import FastMCP

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# FastMCP application instance
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "FWRule MCP — Firewall Rule Analyzer",
    instructions=(
        "Analyzes whether a candidate firewall rule overlaps with, duplicates, "
        "shadows, or conflicts with an existing policy ruleset. "
        "Supports Palo Alto PAN-OS, Cisco ASA, Cisco FTD, Check Point, and Juniper SRX."
    ),
)


# ---------------------------------------------------------------------------
# Internal pipeline helpers
# ---------------------------------------------------------------------------


def _build_error_response(
    error_code: str,
    message: str,
    field: Optional[str] = None,
    duration_ms: float = 0.0,
) -> dict:
    """
    Build a structured error response dict.

    Returns a dict rather than raising so that the MCP tool always returns a
    value (error responses are still valid tool results — they just convey
    failure).
    """
    result: dict = {
        "success": False,
        "error": {
            "code": error_code,
            "message": message,
        },
        "metadata": {
            "analysis_duration_ms": round(duration_ms, 2),
        },
    }
    if field:
        result["error"]["field"] = field
    return result


def _run_pipeline(
    vendor: str,
    ruleset_payload: str,
    candidate_rule_payload: str,
    os_version: Optional[str],
    context_objects: Optional[str],
    candidate_position: Optional[int],
) -> dict:
    """
    Execute the full analysis pipeline and return the result as a dict.

    This is the core implementation called by the MCP tool function.  All
    stages are wrapped in try/except so that errors are returned as structured
    dicts rather than propagating as uncaught exceptions.

    Returns:
        Either a full AnalysisResponse dict (with success=True) or an error
        dict (with success=False).
    """
    start_time = time.monotonic()

    # ------------------------------------------------------------------
    # Stage 1: Input validation
    # ------------------------------------------------------------------
    from fwrule_mcp.utils.validation import (
        ValidationError,
        validate_vendor,
        validate_payload_size,
        validate_context_objects,
    )
    from fwrule_mcp.utils.limits import (
        MAX_RULESET_PAYLOAD_BYTES,
        MAX_CANDIDATE_PAYLOAD_BYTES,
        MAX_RULES_FOR_ANALYSIS,
    )

    try:
        vendor = validate_vendor(vendor)
    except ValidationError as exc:
        return _build_error_response(
            "unsupported_vendor", exc.message, field=exc.field,
            duration_ms=(time.monotonic() - start_time) * 1000,
        )

    try:
        validate_payload_size(ruleset_payload, "ruleset_payload", MAX_RULESET_PAYLOAD_BYTES)
        validate_payload_size(candidate_rule_payload, "candidate_rule_payload", MAX_CANDIDATE_PAYLOAD_BYTES)
    except ValidationError as exc:
        return _build_error_response(
            "payload_too_large", exc.message, field=exc.field,
            duration_ms=(time.monotonic() - start_time) * 1000,
        )

    try:
        context_dict = validate_context_objects(context_objects)
    except ValidationError as exc:
        return _build_error_response(
            "invalid_context_objects", exc.message, field=exc.field,
            duration_ms=(time.monotonic() - start_time) * 1000,
        )

    # ------------------------------------------------------------------
    # Stage 2: Parser lookup
    # ------------------------------------------------------------------
    from fwrule_mcp.parsers.registry import registry, UnsupportedVendorError

    try:
        parser = registry.get_parser(vendor, os_version)
    except UnsupportedVendorError as exc:
        return _build_error_response(
            "unsupported_vendor",
            str(exc),
            duration_ms=(time.monotonic() - start_time) * 1000,
        )

    parser_id = type(parser).__name__

    logger.info(
        "Analysis request: vendor=%s os_version=%s parser=%s "
        "ruleset_bytes=%d candidate_bytes=%d candidate_position=%s",
        vendor,
        os_version or "any",
        parser_id,
        len(ruleset_payload.encode()),
        len(candidate_rule_payload.encode()),
        candidate_position,
    )

    # ------------------------------------------------------------------
    # Stage 3: Parse existing policy
    # ------------------------------------------------------------------
    from fwrule_mcp.parsers.base import ParsedPolicy

    try:
        parsed_policy: ParsedPolicy = parser.parse_policy(
            raw_payload=ruleset_payload,
            context=context_dict,
        )
    except Exception as exc:
        logger.error("Policy parse error (vendor=%s): %s", vendor, exc, exc_info=True)
        return _build_error_response(
            "parse_error",
            f"Failed to parse the existing ruleset for vendor '{vendor}': {exc}",
            field="ruleset_payload",
            duration_ms=(time.monotonic() - start_time) * 1000,
        )

    # ------------------------------------------------------------------
    # Stage 4: Parse candidate rule
    # ------------------------------------------------------------------
    try:
        vendor_candidate = parser.parse_single_rule(
            raw_rule=candidate_rule_payload,
            object_table=parsed_policy.object_table,
        )
    except Exception as exc:
        logger.error("Candidate parse error (vendor=%s): %s", vendor, exc, exc_info=True)
        return _build_error_response(
            "parse_error",
            f"Failed to parse the candidate rule for vendor '{vendor}': {exc}",
            field="candidate_rule_payload",
            duration_ms=(time.monotonic() - start_time) * 1000,
        )

    # ------------------------------------------------------------------
    # Stage 5: Normalize
    # ------------------------------------------------------------------
    from fwrule_mcp.normalization.normalizer import PolicyNormalizer

    try:
        from fwrule_mcp.normalization.resolver import ObjectResolver
        normalizer = PolicyNormalizer()
        normalized_rules = normalizer.normalize_policy(parsed_policy)
        # Build a resolver from the policy's object table so the candidate
        # can reference the same named objects as the existing policy.
        candidate_resolver = ObjectResolver(parsed_policy.object_table)
    except Exception as exc:
        logger.error("Normalization error (vendor=%s): %s", vendor, exc, exc_info=True)
        return _build_error_response(
            "normalization_error",
            f"Failed to normalize the policy rules: {exc}",
            duration_ms=(time.monotonic() - start_time) * 1000,
        )

    try:
        normalized_candidate = normalizer.normalize_candidate(
            vendor_rule=vendor_candidate,
            resolver=candidate_resolver,
            intended_position=candidate_position,
        )
    except Exception as exc:
        logger.error("Candidate normalization error (vendor=%s): %s", vendor, exc, exc_info=True)
        return _build_error_response(
            "normalization_error",
            f"Failed to normalize the candidate rule: {exc}",
            duration_ms=(time.monotonic() - start_time) * 1000,
        )

    logger.info(
        "Normalization complete: vendor=%s rules=%d candidate_id=%s",
        vendor,
        len(normalized_rules),
        normalized_candidate.rule_id,
    )

    # ------------------------------------------------------------------
    # Stage 6: Analysis
    # ------------------------------------------------------------------
    from fwrule_mcp.analysis.engine import OverlapAnalysisEngine

    try:
        engine = OverlapAnalysisEngine()
        analysis_result = engine.analyze(
            existing_rules=normalized_rules,
            candidate=normalized_candidate,
            candidate_position=candidate_position,
            max_rules=MAX_RULES_FOR_ANALYSIS,
        )
    except Exception as exc:
        logger.error("Analysis error (vendor=%s): %s", vendor, exc, exc_info=True)
        return _build_error_response(
            "analysis_error",
            f"Analysis engine encountered an unexpected error: {exc}",
            duration_ms=(time.monotonic() - start_time) * 1000,
        )

    # ------------------------------------------------------------------
    # Stage 7: Result generation
    # ------------------------------------------------------------------
    from fwrule_mcp.results.generator import ResultGenerator

    end_time = time.monotonic()

    try:
        generator = ResultGenerator()
        response = generator.generate(
            analysis_result=analysis_result,
            vendor=vendor,
            os_version=os_version,
            start_time_monotonic=start_time,
            end_time_monotonic=end_time,
            parser_id=parser_id,
        )
    except Exception as exc:
        logger.error("Result generation error (vendor=%s): %s", vendor, exc, exc_info=True)
        return _build_error_response(
            "result_generation_error",
            f"Failed to generate the analysis response: {exc}",
            duration_ms=(end_time - start_time) * 1000,
        )

    logger.info(
        "Analysis complete: vendor=%s findings=%d overlap=%s duration_ms=%.1f",
        vendor,
        len(response.findings),
        response.overlap_exists,
        response.metadata.analysis_duration_ms,
    )

    # Serialize to dict for FastMCP (Pydantic v2 model_dump)
    result = response.model_dump(mode="json")
    result["success"] = True
    return result


# ---------------------------------------------------------------------------
# MCP Tools
# ---------------------------------------------------------------------------


@mcp.tool(
    name="analyze_firewall_rule_overlap",
    description=(
        "Analyze whether a candidate firewall rule overlaps with an existing ruleset. "
        "Detects exact duplicates, shadowed rules, action conflicts, and partial overlaps. "
        "Supports Palo Alto PAN-OS (XML), Cisco ASA (text), Cisco FTD (JSON), "
        "Check Point (JSON), and Juniper SRX (set format)."
    ),
)
def analyze_firewall_rule_overlap(
    vendor: str,
    ruleset_payload: str,
    candidate_rule_payload: str,
    os_version: Optional[str] = None,
    context_objects: Optional[str] = None,
    candidate_position: Optional[int] = None,
) -> dict:
    """
    Analyze firewall rule overlap between a candidate rule and an existing policy.

    Args:
        vendor:
            Firewall vendor identifier. Supported values:
            - "panos"       — Palo Alto PAN-OS / Panorama (XML format)
            - "asa"         — Cisco ASA (show running-config text)
            - "ftd"         — Cisco FTD (JSON export from FMC)
            - "checkpoint"  — Check Point (show-access-rulebase JSON)
            - "juniper"     — Juniper SRX (set command format)

        ruleset_payload:
            The complete existing firewall policy in vendor-native format.
            - PAN-OS:    Full XML configuration export
            - ASA:       Output of "show running-config"
            - FTD:       JSON policy export from FMC
            - Check Point: JSON from show-access-rulebase API
            - Juniper:   Output of "show configuration | display set"

        candidate_rule_payload:
            The candidate rule to analyze, in the same vendor-native format.
            Must be a single rule (or a minimal config fragment containing
            exactly one rule).

        os_version:
            Optional OS version string (e.g., "10.2", "9.18", "7.4.1").
            Used to select the correct parser variant when a vendor has
            format differences across OS generations.  If omitted, the
            default parser for the vendor is used.

        context_objects:
            Optional JSON string containing supplemental address/service object
            definitions.  Provide when address objects are defined outside the
            main ruleset payload (common with Panorama, FMC, and Check Point
            management exports).
            Expected format (JSON object):
            {
              "address_objects": {"WebServers": "10.1.2.0/24"},
              "service_objects": {"HTTPS": "tcp/443"},
              "address_groups": {"DMZ": ["WebServers", "AppServers"]},
              "service_groups": {"WEB": ["HTTPS", "HTTP"]}
            }

        candidate_position:
            Optional 1-based intended insertion position for the candidate rule.
            When provided, shadow analysis only considers existing rules above
            this position as potential shadows of the candidate.  If omitted,
            the candidate is assumed to be appended at the end of the policy.

    Returns:
        A dict with the following structure:
        {
          "success": true,
          "overlap_exists": bool,
          "findings": [
            {
              "existing_rule_id": str,
              "existing_rule_position": int,
              "overlap_type": str,   # "shadowed", "conflict", "exact_duplicate", etc.
              "severity": str,       # "critical", "high", "medium", "low", "info"
              "explanation": str,    # Human-readable explanation
              "remediation": str,    # Optional remediation suggestion
              "dimensions": [...]    # Per-dimension breakdown
            }
          ],
          "analysis_summary": str,
          "metadata": {
            "vendor": str,
            "existing_rule_count": int,
            "enabled_rule_count": int,
            "analysis_duration_ms": float,
            "timestamp": str
          }
        }

        On error:
        {
          "success": false,
          "error": {
            "code": str,     # "unsupported_vendor", "parse_error", etc.
            "message": str,
            "field": str     # Optional — which input field caused the error
          }
        }
    """
    try:
        return _run_pipeline(
            vendor=vendor,
            ruleset_payload=ruleset_payload,
            candidate_rule_payload=candidate_rule_payload,
            os_version=os_version,
            context_objects=context_objects,
            candidate_position=candidate_position,
        )
    except Exception as exc:
        logger.error(
            "Unexpected error in analyze_firewall_rule_overlap (vendor=%s): %s",
            vendor, exc, exc_info=True,
        )
        return _build_error_response(
            "internal_error",
            "An unexpected internal error occurred. Check server logs for details.",
        )


@mcp.tool(
    name="list_supported_vendors",
    description=(
        "List all supported firewall vendors and their configuration format requirements. "
        "Use this to understand what vendor identifiers and payload formats are accepted "
        "by analyze_firewall_rule_overlap."
    ),
)
def list_supported_vendors() -> dict:
    """
    List all supported firewall vendors.

    Returns a dict with a ``vendors`` list.  Each entry describes a supported
    vendor, including the expected configuration format and supported OS versions.

    Returns:
        {
          "vendors": [
            {
              "id": str,          # Vendor identifier to pass to analyze_firewall_rule_overlap
              "name": str,        # Human-readable vendor name
              "format": str,      # Expected configuration format description
              "versions": str,    # Supported OS version range
              "notes": str        # Optional additional usage notes
            }
          ]
        }
    """
    return {
        "vendors": [
            {
                "id": "panos",
                "name": "Palo Alto Networks PAN-OS / Panorama",
                "format": "XML configuration export (show config running, or Panorama export)",
                "versions": "9.x - 11.x",
                "notes": (
                    "Supply the full XML config or a vsys/device-group fragment. "
                    "Address/service objects from Panorama shared context can be provided "
                    "via the context_objects parameter."
                ),
            },
            {
                "id": "asa",
                "name": "Cisco ASA",
                "format": "show running-config text output",
                "versions": "9.x+",
                "notes": (
                    "Use 'show running-config' or a relevant section thereof. "
                    "Access-list, object, and object-group definitions are all extracted "
                    "from the same payload."
                ),
            },
            {
                "id": "ftd",
                "name": "Cisco Firepower Threat Defense (FTD)",
                "format": "JSON export from Firepower Management Center (FMC)",
                "versions": "6.x - 7.x",
                "notes": (
                    "Use the FMC REST API policy export. Network/port object definitions "
                    "from shared libraries can be provided via context_objects."
                ),
            },
            {
                "id": "checkpoint",
                "name": "Check Point",
                "format": "JSON package export (show-access-rulebase API response)",
                "versions": "R80.x - R82.x",
                "notes": (
                    "Use the Management API 'show-access-rulebase' command output. "
                    "Object definitions from the object database can be provided "
                    "via context_objects when the rulebase export uses name references."
                ),
            },
            {
                "id": "juniper",
                "name": "Juniper SRX",
                "format": "set command format (show configuration | display set)",
                "versions": "19.x+",
                "notes": (
                    "Use 'show configuration security policies | display set' output. "
                    "Address book entries and application definitions are extracted "
                    "from the same payload."
                ),
            },
        ]
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Entry point for the ``fwrule-mcp`` CLI command."""
    import os

    # Suppress logging to stderr in stdio transport mode — some MCP hosts
    # (e.g., iagctl) may be confused by unexpected stderr output.
    log_level = os.environ.get("FWRULE_LOG_LEVEL", "WARNING").upper()
    logging.basicConfig(
        level=getattr(logging, log_level, logging.WARNING),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    # Disable FastMCP's PyPI version check and startup banner — the version
    # check can hang in restricted network environments and cause MCP client
    # connection timeouts.
    os.environ.setdefault("FASTMCP_CHECK_FOR_UPDATES", "0")
    os.environ.setdefault("FASTMCP_SHOW_SERVER_BANNER", "0")

    mcp.run(show_banner=False)


if __name__ == "__main__":
    main()
