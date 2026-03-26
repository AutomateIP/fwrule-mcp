"""
MCP Server entry point — FWRule MCP — Firewall Rule Analyzer.

Four tools:
  1. analyze_firewall_rule_overlap — Hybrid: accepts vendor-native OR normalized JSON
  2. parse_policy — Parse vendor-native config and return normalized JSON schema
  3. batch_analyze_overlap — Analyze multiple candidates against the same ruleset
  4. list_supported_vendors — List supported vendors and formats

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
from typing import Annotated, Optional

from fastmcp import FastMCP
from pydantic import BeforeValidator, Field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Type coercion for MCP clients that send dicts/lists instead of JSON strings
# ---------------------------------------------------------------------------

def _coerce_json(v):
    """Pre-validator: dict/list → JSON string, empty containers → None."""
    if v is None:
        return v
    if isinstance(v, (dict, list)):
        return json.dumps(v) if v else None
    return v


def _coerce_json_or_empty(v):
    """Pre-validator: like _coerce_json but returns '' instead of None."""
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        return json.dumps(v) if v else ""
    return v


def _coerce_to_list(v):
    """Pre-validator: JSON string → list, passthrough if already list."""
    if v is None:
        return v
    if isinstance(v, list):
        return v
    if isinstance(v, str):
        try:
            parsed = json.loads(v)
            if isinstance(parsed, list):
                return parsed
        except (json.JSONDecodeError, TypeError):
            pass
    return v


def _coerce_to_dict(v):
    """Pre-validator: JSON string → dict, passthrough if already dict."""
    if v is None:
        return v
    if isinstance(v, dict):
        return v
    if isinstance(v, str):
        try:
            parsed = json.loads(v)
            if isinstance(parsed, dict):
                return parsed
        except (json.JSONDecodeError, TypeError):
            pass
    return v


# ---------------------------------------------------------------------------
# FastMCP application instance
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "FWRule MCP — Firewall Rule Analyzer",
    instructions=(
        "Analyzes whether a candidate firewall rule overlaps with, duplicates, "
        "shadows, or conflicts with an existing policy ruleset. "
        "Accepts vendor-native configs (10 vendors) OR pre-normalized JSON rules. "
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
    existing_rules_input,
    candidate_rule_input,
    candidate_position: Optional[int],
) -> dict:
    """Path B: normalized JSON input pipeline.

    Accepts both JSON strings and native Python objects (list/dict) for
    existing_rules_input and candidate_rule_input.
    """
    start_time = time.monotonic()

    from pydantic import ValidationError as PydanticValidationError
    from fwrule_mcp.normalization.schema import (
        RuleInput,
        rule_input_to_normalized,
        rule_input_to_candidate,
    )

    # Parse existing rules — accept str or list
    if isinstance(existing_rules_input, str):
        try:
            existing_raw = json.loads(existing_rules_input)
        except (json.JSONDecodeError, TypeError) as exc:
            return _build_error_response(
                "invalid_input",
                f"existing_rules is not valid JSON: {exc}",
                field="existing_rules",
                duration_ms=(time.monotonic() - start_time) * 1000,
            )
    else:
        existing_raw = existing_rules_input

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

    # Parse candidate rule — accept str or dict
    if isinstance(candidate_rule_input, str):
        try:
            candidate_raw = json.loads(candidate_rule_input)
        except (json.JSONDecodeError, TypeError) as exc:
            return _build_error_response(
                "invalid_input",
                f"candidate_rule is not valid JSON: {exc}",
                field="candidate_rule",
                duration_ms=(time.monotonic() - start_time) * 1000,
            )
    else:
        candidate_raw = candidate_rule_input

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
    vendor: Annotated[Optional[str], BeforeValidator(_coerce_json), Field(
        description='Vendor identifier. One of: "panos", "asa", "ftd", "ios", "iosxr", "checkpoint", "juniper", "junos", "sros", "fortios". Required for Mode 1 (vendor-native).',
    )] = None,
    ruleset_payload: Annotated[Optional[str], BeforeValidator(_coerce_json), Field(
        description="Complete firewall config in vendor-native text format (e.g. full 'show access-lists' output for IOS). Required for Mode 1.",
    )] = None,
    candidate_rule_payload: Annotated[Optional[str], BeforeValidator(_coerce_json), Field(
        description="Single candidate rule in vendor-native text format (e.g. one ACL line for IOS). Required for Mode 1.",
    )] = None,
    os_version: Annotated[Optional[str], Field(
        description="Optional OS version string for parser selection.",
    )] = None,
    context_objects: Annotated[Optional[str], BeforeValidator(_coerce_json), Field(
        description="Optional JSON string with supplemental object definitions (address groups, service objects).",
    )] = None,
    candidate_position: Annotated[Optional[int], Field(
        description="Optional 1-based intended insertion position of the candidate rule.",
    )] = None,
    existing_rules: Annotated[Optional[list], BeforeValidator(_coerce_to_list), Field(
        description='Array of normalized rule objects from parse_policy output. Each object: {"id": "rule_1", "position": 1, "action": "permit"|"deny", "source_addresses": ["10.0.0.0/8"], "destination_addresses": ["any"], "services": [{"protocol": "tcp", "ports": "443"}], "source_zones": ["any"], "destination_zones": ["any"], "applications": ["any"]}. Required for Mode 2.',
    )] = None,
    candidate_rule: Annotated[Optional[dict], BeforeValidator(_coerce_to_dict), Field(
        description='Single normalized rule object (same schema as existing_rules elements). Example: {"id": "candidate", "position": 1, "action": "permit", "source_addresses": ["10.20.35.76/32"], "destination_addresses": ["172.16.20.0/24"], "services": [{"protocol": "tcp", "ports": "6379"}]}. Required for Mode 2.',
    )] = None,
) -> dict:
    """Analyze firewall rule overlap between a candidate rule and an existing policy.

    Two input modes (provide parameters for one mode only):
      Mode 1 (vendor-native): vendor + ruleset_payload + candidate_rule_payload
      Mode 2 (normalized JSON): existing_rules + candidate_rule (recommended — use parse_policy first)
    """
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
    vendor: Annotated[str, Field(
        description='Vendor identifier. One of: "panos", "asa", "ftd", "ios", "iosxr", "checkpoint", "juniper", "junos", "sros", "fortios".',
    )],
    ruleset_payload: Annotated[str, BeforeValidator(_coerce_json_or_empty), Field(
        description="Complete firewall config in vendor-native text format. For IOS: paste the full 'show access-lists <name>' output. For PAN-OS: paste the full XML config tree.",
    )] = "",
    os_version: Annotated[Optional[str], Field(
        description="Optional OS version string for parser variant selection.",
    )] = None,
    context_objects: Annotated[Optional[str], BeforeValidator(_coerce_json), Field(
        description="Optional JSON string with supplemental object definitions (address groups, service objects).",
    )] = None,
) -> str:
    """Parse a vendor-native firewall configuration and return normalized JSON rules.

    Returns {"success": true, "rules": [...], "metadata": {...}}.
    The rules array uses the same normalized schema accepted by analyze_firewall_rule_overlap existing_rules parameter.
    """
    start_time = time.monotonic()

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
    name="batch_analyze_overlap",
    description=(
        "Analyze multiple candidate rules against the same existing ruleset in a single call. "
        "More efficient than calling analyze_firewall_rule_overlap multiple times — "
        "existing_rules is parsed once and reused for each candidate. "
        "Use parse_policy first to get normalized rules, then pass all candidates at once."
    ),
)
def batch_analyze_overlap(
    existing_rules: Annotated[Optional[list], BeforeValidator(_coerce_to_list), Field(
        description='Array of normalized rule objects from parse_policy output. Parsed once and reused for all candidates.',
    )] = None,
    candidate_rules: Annotated[Optional[list], BeforeValidator(_coerce_to_list), Field(
        description='Array of candidate rule objects to analyze. Each object: {"id": "candidate-1", "position": 1, "action": "permit"|"deny", "source_addresses": ["CIDR"], "destination_addresses": ["CIDR"], "services": [{"protocol": "tcp", "ports": "443"}], "source_zones": ["any"], "destination_zones": ["any"], "applications": ["any"]}.',
    )] = None,
) -> dict:
    """Analyze multiple candidates against the same existing ruleset in one call.

    Returns {"success": true, "results": [{"candidate_id": str, ...analysis result...}, ...]}.
    """
    start_time = time.monotonic()

    if not existing_rules or not candidate_rules:
        return _build_error_response(
            "missing_parameters",
            "Both existing_rules and candidate_rules are required.",
            duration_ms=(time.monotonic() - start_time) * 1000,
        )

    from pydantic import ValidationError as PydanticValidationError
    from fwrule_mcp.normalization.schema import (
        RuleInput,
        rule_input_to_normalized,
        rule_input_to_candidate,
    )

    # Parse existing rules — accept str or list
    if isinstance(existing_rules, str):
        try:
            existing_raw = json.loads(existing_rules)
        except (json.JSONDecodeError, TypeError) as exc:
            return _build_error_response(
                "invalid_input", f"existing_rules is not valid JSON: {exc}",
                field="existing_rules",
                duration_ms=(time.monotonic() - start_time) * 1000,
            )
    else:
        existing_raw = existing_rules

    if not isinstance(existing_raw, list):
        return _build_error_response(
            "invalid_input", "existing_rules must be a JSON array of rule objects.",
            field="existing_rules",
            duration_ms=(time.monotonic() - start_time) * 1000,
        )

    try:
        existing_inputs = [RuleInput(**r) for r in existing_raw]
        normalized_rules = [rule_input_to_normalized(r) for r in existing_inputs]
    except (PydanticValidationError, TypeError, Exception) as exc:
        return _build_error_response(
            "invalid_input", f"existing_rules validation failed: {exc}",
            field="existing_rules",
            duration_ms=(time.monotonic() - start_time) * 1000,
        )

    # Parse candidate_rules — accept str or list
    if isinstance(candidate_rules, str):
        try:
            candidates_raw = json.loads(candidate_rules)
        except (json.JSONDecodeError, TypeError) as exc:
            return _build_error_response(
                "invalid_input", f"candidate_rules is not valid JSON: {exc}",
                field="candidate_rules",
                duration_ms=(time.monotonic() - start_time) * 1000,
            )
    else:
        candidates_raw = candidate_rules

    if not isinstance(candidates_raw, list):
        return _build_error_response(
            "invalid_input", "candidate_rules must be a JSON array of rule objects.",
            field="candidate_rules",
            duration_ms=(time.monotonic() - start_time) * 1000,
        )

    # Run analysis for each candidate, reusing parsed existing_rules
    results = []
    for i, cand_raw in enumerate(candidates_raw):
        cand_id = cand_raw.get("id", f"candidate_{i+1}") if isinstance(cand_raw, dict) else f"candidate_{i+1}"
        try:
            if isinstance(cand_raw, str):
                cand_raw = json.loads(cand_raw)
            candidate_input = RuleInput(**cand_raw)
            normalized_candidate = rule_input_to_candidate(candidate_input, None)
            cand_start = time.monotonic()
            result_dict = _run_analysis(normalized_rules, normalized_candidate, None, "normalized", cand_start)
            result_dict["candidate_id"] = cand_id
            results.append(result_dict)
        except Exception as exc:
            results.append({
                "success": False,
                "candidate_id": cand_id,
                "error": {"code": "analysis_error", "message": str(exc)},
            })

    duration_ms = (time.monotonic() - start_time) * 1000
    return {
        "success": True,
        "results": results,
        "metadata": {
            "existing_rule_count": len(normalized_rules),
            "candidates_analyzed": len(results),
            "total_duration_ms": round(duration_ms, 2),
        },
    }


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
            {"id": "fortios", "aliases": ["fortigate", "forti", "fortinet"], "format": "text"},
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
