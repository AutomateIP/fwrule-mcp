"""
MCP Server entry point — FWRule MCP — Firewall Rule Analyzer.

Three tools:
  1. analyze_firewall_rule_overlap — Hybrid: accepts vendor-native OR normalized JSON
  2. parse_policy — Parse vendor-native config and return normalized JSON schema
  3. list_supported_vendors — List supported vendors and formats

Two analysis paths (selected automatically by which parameters are provided):
  Path A (vendor parsers):  vendor + ruleset_payload + candidate_rule_payload
  Path B (normalized JSON): existing_rules + candidate_rule

Error handling:
  - All errors are returned as structured dicts (not server crashes).
  - Payload content is never logged — only metadata.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Optional, Union

from fastmcp import FastMCP

logger = logging.getLogger(__name__)


def _coerce_to_json_str(value: Union[str, dict, list, None]) -> Optional[str]:
    """Coerce a value that should be a JSON string.

    Some MCP clients (e.g. iagctl) send structured objects (dicts/lists)
    instead of JSON-encoded strings.  This normalizes them so downstream
    code that expects ``str`` works correctly.  Empty dicts/lists become
    None.
    """
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return json.dumps(value) if value else None
    return value


# ---------------------------------------------------------------------------
# FastMCP application instance
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "FWRule MCP — Firewall Rule Analyzer",
    instructions=(
        "Analyzes whether a candidate firewall rule overlaps with, duplicates, "
        "shadows, or conflicts with an existing policy ruleset. "
        "Accepts vendor-native configs (9 vendors) OR pre-normalized JSON rules. "
        "Use parse_policy to inspect what the built-in parsers extract before analysis."
    ),
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _build_error_response(
    error_code: str,
    message: str,
    field: Optional[str] = None,
    duration_ms: float = 0.0,
) -> dict:
    """Build a structured error response dict."""
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


def _run_analysis(
    normalized_rules: list,
    normalized_candidate,
    candidate_position: Optional[int],
    vendor: str,
    start_time: float,
) -> dict:
    """
    Run the analysis engine on already-normalized rules and return the result dict.

    Shared by both Path A (vendor parser) and Path B (normalized JSON).
    """
    from fwrule_mcp.analysis.engine import OverlapAnalysisEngine
    from fwrule_mcp.results.generator import ResultGenerator
    from fwrule_mcp.utils.limits import MAX_RULES_FOR_ANALYSIS

    try:
        engine = OverlapAnalysisEngine()
        analysis_result = engine.analyze(
            existing_rules=normalized_rules,
            candidate=normalized_candidate,
            candidate_position=candidate_position,
            max_rules=MAX_RULES_FOR_ANALYSIS,
        )
    except Exception as exc:
        logger.error("Analysis error: %s", exc, exc_info=True)
        return _build_error_response(
            "analysis_error",
            f"Analysis engine encountered an unexpected error: {exc}",
            duration_ms=(time.monotonic() - start_time) * 1000,
        )

    end_time = time.monotonic()

    try:
        generator = ResultGenerator()
        response = generator.generate(
            analysis_result=analysis_result,
            vendor=vendor,
            os_version=None,
            start_time_monotonic=start_time,
            end_time_monotonic=end_time,
        )
    except Exception as exc:
        logger.error("Result generation error: %s", exc, exc_info=True)
        return _build_error_response(
            "result_generation_error",
            f"Failed to generate the analysis response: {exc}",
            duration_ms=(end_time - start_time) * 1000,
        )

    result = response.model_dump(mode="json")
    result["success"] = True
    return result


def _run_vendor_pipeline(
    vendor: str,
    ruleset_payload: Optional[str],
    candidate_rule_payload: Optional[str],
    os_version: Optional[str],
    context_objects: Optional[str],
    candidate_position: Optional[int],
) -> dict:
    """Path A: vendor parser pipeline."""
    start_time = time.monotonic()

    from fwrule_mcp.utils.validation import (
        ValidationError,
        validate_vendor,
        validate_payload_size,
        validate_context_objects,
    )
    from fwrule_mcp.utils.limits import (
        MAX_RULESET_PAYLOAD_BYTES,
        MAX_CANDIDATE_PAYLOAD_BYTES,
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

    from fwrule_mcp.parsers.registry import registry, UnsupportedVendorError

    try:
        parser = registry.get_parser(vendor, os_version)
    except UnsupportedVendorError as exc:
        return _build_error_response(
            "unsupported_vendor", str(exc),
            duration_ms=(time.monotonic() - start_time) * 1000,
        )

    try:
        parsed_policy = parser.parse_policy(raw_payload=ruleset_payload, context=context_dict)
    except Exception as exc:
        return _build_error_response(
            "parse_error",
            f"Failed to parse the existing ruleset for vendor '{vendor}': {exc}",
            field="ruleset_payload",
            duration_ms=(time.monotonic() - start_time) * 1000,
        )

    try:
        vendor_candidate = parser.parse_single_rule(
            raw_rule=candidate_rule_payload,
            object_table=parsed_policy.object_table,
        )
    except Exception as exc:
        return _build_error_response(
            "parse_error",
            f"Failed to parse the candidate rule for vendor '{vendor}': {exc}",
            field="candidate_rule_payload",
            duration_ms=(time.monotonic() - start_time) * 1000,
        )

    from fwrule_mcp.normalization.normalizer import PolicyNormalizer
    from fwrule_mcp.normalization.resolver import ObjectResolver

    try:
        normalizer = PolicyNormalizer()
        normalized_rules = normalizer.normalize_policy(parsed_policy)
        candidate_resolver = ObjectResolver(parsed_policy.object_table)
        normalized_candidate = normalizer.normalize_candidate(
            vendor_rule=vendor_candidate,
            resolver=candidate_resolver,
            intended_position=candidate_position,
        )
    except Exception as exc:
        return _build_error_response(
            "normalization_error",
            f"Failed to normalize the policy rules: {exc}",
            duration_ms=(time.monotonic() - start_time) * 1000,
        )

    return _run_analysis(normalized_rules, normalized_candidate, candidate_position, vendor, start_time)


def _run_normalized_pipeline(
    existing_rules_json: str,
    candidate_rule_json: str,
    candidate_position: Optional[int],
) -> dict:
    """Path B: normalized JSON input pipeline."""
    start_time = time.monotonic()

    from pydantic import ValidationError as PydanticValidationError
    from fwrule_mcp.normalization.schema import (
        RuleInput,
        rule_input_to_normalized,
        rule_input_to_candidate,
    )

    # Parse and validate existing rules
    try:
        existing_raw = json.loads(existing_rules_json)
    except (json.JSONDecodeError, TypeError) as exc:
        return _build_error_response(
            "invalid_input",
            f"existing_rules is not valid JSON: {exc}",
            field="existing_rules",
            duration_ms=(time.monotonic() - start_time) * 1000,
        )

    if not isinstance(existing_raw, list):
        return _build_error_response(
            "invalid_input",
            "existing_rules must be a JSON array of rule objects.",
            field="existing_rules",
            duration_ms=(time.monotonic() - start_time) * 1000,
        )

    try:
        existing_inputs = [RuleInput(**r) for r in existing_raw]
    except (PydanticValidationError, TypeError) as exc:
        return _build_error_response(
            "invalid_input",
            f"existing_rules schema validation failed: {exc}",
            field="existing_rules",
            duration_ms=(time.monotonic() - start_time) * 1000,
        )

    # Parse and validate candidate rule
    try:
        candidate_raw = json.loads(candidate_rule_json)
    except (json.JSONDecodeError, TypeError) as exc:
        return _build_error_response(
            "invalid_input",
            f"candidate_rule is not valid JSON: {exc}",
            field="candidate_rule",
            duration_ms=(time.monotonic() - start_time) * 1000,
        )

    try:
        candidate_input = RuleInput(**candidate_raw)
    except (PydanticValidationError, TypeError) as exc:
        return _build_error_response(
            "invalid_input",
            f"candidate_rule schema validation failed: {exc}",
            field="candidate_rule",
            duration_ms=(time.monotonic() - start_time) * 1000,
        )

    # Convert to internal types
    try:
        normalized_rules = [rule_input_to_normalized(r) for r in existing_inputs]
        normalized_candidate = rule_input_to_candidate(candidate_input, candidate_position)
    except Exception as exc:
        return _build_error_response(
            "normalization_error",
            f"Failed to convert normalized input to internal types: {exc}",
            duration_ms=(time.monotonic() - start_time) * 1000,
        )

    return _run_analysis(normalized_rules, normalized_candidate, candidate_position, "normalized", start_time)


# ---------------------------------------------------------------------------
# MCP Tools
# ---------------------------------------------------------------------------


@mcp.tool(
    name="analyze_firewall_rule_overlap",
    description=(
        "Analyze whether a candidate firewall rule overlaps with an existing ruleset. "
        "Detects exact duplicates, shadowed rules, action conflicts, and partial overlaps. "
        "Two input modes: (1) vendor-native configs via vendor + ruleset_payload + "
        "candidate_rule_payload, or (2) pre-normalized JSON via existing_rules + candidate_rule. "
        "Use parse_policy first to inspect parser output before analysis."
    ),
)
def analyze_firewall_rule_overlap(
    vendor: Optional[str] = None,
    ruleset_payload: Union[str, list, dict, None] = None,
    candidate_rule_payload: Union[str, dict, None] = None,
    os_version: Optional[str] = None,
    context_objects: Union[str, dict, None] = None,
    candidate_position: Optional[int] = None,
    existing_rules: Union[str, list, None] = None,
    candidate_rule: Union[str, dict, None] = None,
) -> dict:
    """
    Analyze firewall rule overlap between a candidate rule and an existing policy.

    Supports two input modes — use whichever matches your data:

    MODE 1 — Vendor-native configs (built-in parsers handle format conversion):
        vendor:                 Vendor identifier ("panos", "asa", "ftd", "ios",
                                "iosxr", "checkpoint", "juniper", "junos", "sros")
        ruleset_payload:        Complete firewall config in vendor-native format
        candidate_rule_payload: Single candidate rule in vendor-native format
        os_version:             Optional OS version for parser selection
        context_objects:        Optional JSON with supplemental object definitions

    MODE 2 — Pre-normalized JSON (caller has already extracted structured rules):
        existing_rules:   JSON string — array of normalized rule objects:
                          [{"id": "rule-1", "position": 1, "action": "permit",
                            "source_addresses": ["10.0.0.0/24"],
                            "destination_addresses": ["any"],
                            "services": [{"protocol": "tcp", "ports": "443"}],
                            "source_zones": ["trust"],
                            "destination_zones": ["untrust"],
                            "applications": ["any"]}]
        candidate_rule:   JSON string — single normalized rule object (same schema)

    SHARED PARAMETER:
        candidate_position: Optional 1-based intended insertion position

    Returns a compact dict:
        {
          "success": true,
          "overlap_exists": bool,
          "findings": [{
            "existing_rule_id": str,
            "existing_rule_position": int,
            "overlap_type": str,
            "severity": str,
            "candidate_action": str,
            "existing_action": str,
            "dimensions": {"source_zones": "equal", "destination_addresses": "superset", ...}
          }],
          "metadata": {"vendor": str, "existing_rule_count": int, ...}
        }
    """
    # Coerce structured objects to JSON strings (iagctl sends dicts/lists)
    ruleset_payload = _coerce_to_json_str(ruleset_payload)
    candidate_rule_payload = _coerce_to_json_str(candidate_rule_payload)
    context_objects = _coerce_to_json_str(context_objects)
    existing_rules = _coerce_to_json_str(existing_rules)
    candidate_rule = _coerce_to_json_str(candidate_rule)

    # Route: normalized JSON takes precedence
    if existing_rules is not None and candidate_rule is not None:
        try:
            return _run_normalized_pipeline(existing_rules, candidate_rule, candidate_position)
        except Exception as exc:
            logger.error("Unexpected error in normalized pipeline: %s", exc, exc_info=True)
            return _build_error_response("internal_error", "Unexpected error in normalized pipeline.")

    # Route: vendor-native pipeline
    if vendor is not None and ruleset_payload is not None and candidate_rule_payload is not None:
        try:
            return _run_vendor_pipeline(
                vendor=vendor,
                ruleset_payload=ruleset_payload,
                candidate_rule_payload=candidate_rule_payload,
                os_version=os_version,
                context_objects=context_objects,
                candidate_position=candidate_position,
            )
        except Exception as exc:
            logger.error("Unexpected error in vendor pipeline: %s", exc, exc_info=True)
            return _build_error_response("internal_error", "Unexpected error in vendor pipeline.")

    # Neither path has sufficient parameters
    return _build_error_response(
        "missing_parameters",
        "Provide either (existing_rules + candidate_rule) for normalized input, "
        "or (vendor + ruleset_payload + candidate_rule_payload) for vendor-native input.",
    )


@mcp.tool(
    name="parse_policy",
    description=(
        "Parse a vendor-native firewall config and return normalized JSON rules. "
        "Use this to inspect what the built-in parser extracts — verify rule counts, "
        "object resolution, and address expansion before running overlap analysis. "
        "The output uses the same normalized schema accepted by analyze_firewall_rule_overlap."
    ),
)
def parse_policy(
    vendor: str,
    ruleset_payload: Union[str, list, dict] = "",
    os_version: Optional[str] = None,
    context_objects: Union[str, dict, None] = None,
) -> str:
    """
    Parse a vendor-native firewall configuration and return normalized rules.

    Args:
        vendor:          Vendor identifier (same values as analyze_firewall_rule_overlap)
        ruleset_payload: Complete firewall config in vendor-native format
        os_version:      Optional OS version string
        context_objects: Optional JSON with supplemental object definitions

    Returns a JSON string:
        {
          "success": true,
          "rules": [
            {
              "id": "rule-name",
              "position": 1,
              "enabled": true,
              "action": "permit",
              "source_zones": ["trust"],
              "destination_zones": ["untrust"],
              "source_addresses": ["10.0.0.0/24"],
              "destination_addresses": ["any"],
              "services": [{"protocol": "tcp", "ports": "443"}],
              "applications": ["any"]
            }
          ],
          "metadata": {
            "vendor": "panos",
            "parser": "PANOSParser",
            "rule_count": 7,
            "parse_warnings": []
          }
        }
    """
    start_time = time.monotonic()
    ruleset_payload = _coerce_to_json_str(ruleset_payload) or ""
    context_objects = _coerce_to_json_str(context_objects)

    from fwrule_mcp.utils.validation import ValidationError, validate_vendor, validate_payload_size, validate_context_objects
    from fwrule_mcp.utils.limits import MAX_RULESET_PAYLOAD_BYTES

    try:
        vendor = validate_vendor(vendor)
    except ValidationError as exc:
        return json.dumps({"success": False, "error": {"code": "unsupported_vendor", "message": exc.message}})

    try:
        validate_payload_size(ruleset_payload, "ruleset_payload", MAX_RULESET_PAYLOAD_BYTES)
    except ValidationError as exc:
        return json.dumps({"success": False, "error": {"code": "payload_too_large", "message": exc.message}})

    try:
        context_dict = validate_context_objects(context_objects)
    except ValidationError as exc:
        return json.dumps({"success": False, "error": {"code": "invalid_context_objects", "message": exc.message}})

    from fwrule_mcp.parsers.registry import registry, UnsupportedVendorError

    try:
        parser = registry.get_parser(vendor, os_version)
    except UnsupportedVendorError as exc:
        return json.dumps({"success": False, "error": {"code": "unsupported_vendor", "message": str(exc)}})

    parser_id = type(parser).__name__

    try:
        parsed_policy = parser.parse_policy(raw_payload=ruleset_payload, context=context_dict)
    except Exception as exc:
        return json.dumps({"success": False, "error": {"code": "parse_error", "message": str(exc)}})

    from fwrule_mcp.normalization.normalizer import PolicyNormalizer
    from fwrule_mcp.normalization.schema import normalized_rule_to_dict

    try:
        normalizer = PolicyNormalizer()
        normalized_rules = normalizer.normalize_policy(
            parsed_policy, include_implicit_rules=False,
        )
    except Exception as exc:
        return json.dumps({"success": False, "error": {"code": "normalization_error", "message": str(exc)}})

    rules_out = [normalized_rule_to_dict(r) for r in normalized_rules]

    duration_ms = (time.monotonic() - start_time) * 1000

    return json.dumps({
        "success": True,
        "rules": rules_out,
        "metadata": {
            "vendor": vendor,
            "parser": parser_id,
            "rule_count": len(rules_out),
            "parse_warnings": parsed_policy.warnings[:20],
            "duration_ms": round(duration_ms, 2),
        },
    })


@mcp.tool(
    name="list_supported_vendors",
    description=(
        "List all supported firewall vendors and their configuration format requirements. "
        "Use this to understand what vendor identifiers and payload formats are accepted "
        "by analyze_firewall_rule_overlap and parse_policy."
    ),
)
def list_supported_vendors() -> str:
    """List all supported firewall vendors."""
    return json.dumps({
        "vendors": [
            {"id": "panos", "aliases": ["paloalto", "panorama"], "format": "xml"},
            {"id": "asa", "aliases": ["cisco-asa"], "format": "text"},
            {"id": "ftd", "aliases": ["firepower", "fmc"], "format": "json"},
            {"id": "ios", "aliases": ["iosxe", "cisco-ios"], "format": "text"},
            {"id": "iosxr", "aliases": ["ios-xr", "xr"], "format": "text"},
            {"id": "checkpoint", "aliases": ["cp", "check-point"], "format": "json"},
            {"id": "juniper", "aliases": ["srx"], "format": "set-commands"},
            {"id": "junos", "aliases": ["mx", "ptx", "qfx"], "format": "set-commands"},
            {"id": "sros", "aliases": ["nokia", "sr-os", "md-cli"], "format": "md-cli"},
        ],
        "normalized_input": "Use existing_rules + candidate_rule params to bypass parsers.",
    })


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Entry point for the ``fwrule-mcp`` CLI command."""
    import os

    log_level = os.environ.get("FWRULE_LOG_LEVEL", "WARNING").upper()
    logging.basicConfig(
        level=getattr(logging, log_level, logging.WARNING),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    os.environ.setdefault("FASTMCP_CHECK_FOR_UPDATES", "0")
    os.environ.setdefault("FASTMCP_SHOW_SERVER_BANNER", "0")

    mcp.run(show_banner=False)


if __name__ == "__main__":
    main()
