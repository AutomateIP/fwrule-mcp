"""
Input validation utilities.

These helpers supplement Pydantic model validators with checks that require
vendor-specific knowledge or access to runtime constants from limits.py.

Called by the MCP server layer before dispatching to the parser, and optionally
by parsers themselves for format-specific structural validation.
"""

from __future__ import annotations

import ipaddress
import json
from typing import Optional

from fwrule_mcp.utils.limits import (
    MAX_CANDIDATE_PAYLOAD_BYTES,
    MAX_RULESET_PAYLOAD_BYTES,
)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ValidationError(Exception):
    """Raised when an input fails structural or content validation."""

    def __init__(self, field: str, message: str) -> None:
        super().__init__(f"Validation error on field '{field}': {message}")
        self.field = field
        self.message = message


# ---------------------------------------------------------------------------
# Supported vendors
# ---------------------------------------------------------------------------

SUPPORTED_VENDORS = frozenset({"panos", "asa", "ftd", "checkpoint", "juniper"})

# Common aliases that LLMs and users might use instead of the canonical ID.
VENDOR_ALIASES: dict[str, str] = {
    "paloalto": "panos",
    "palo_alto": "panos",
    "palo-alto": "panos",
    "pan-os": "panos",
    "panorama": "panos",
    "cisco_asa": "asa",
    "cisco-asa": "asa",
    "cisco_ftd": "ftd",
    "cisco-ftd": "ftd",
    "firepower": "ftd",
    "fmc": "ftd",
    "check_point": "checkpoint",
    "check-point": "checkpoint",
    "cp": "checkpoint",
    "juniper_srx": "juniper",
    "juniper-srx": "juniper",
    "srx": "juniper",
    "junos": "juniper",
}


# ---------------------------------------------------------------------------
# Vendor validation
# ---------------------------------------------------------------------------


def validate_vendor(vendor: str) -> str:
    """
    Validate and normalize a vendor identifier.

    Accepts canonical IDs (panos, asa, ftd, checkpoint, juniper) as well as
    common aliases (paloalto, panorama, firepower, srx, etc.).

    Args:
        vendor: Raw vendor string from the request.

    Returns:
        Normalized canonical vendor identifier.

    Raises:
        ValidationError: If the vendor is not recognized.
    """
    normalized = vendor.lower().strip().replace(" ", "_")
    # Check canonical IDs first
    if normalized in SUPPORTED_VENDORS:
        return normalized
    # Check aliases
    if normalized in VENDOR_ALIASES:
        return VENDOR_ALIASES[normalized]
    raise ValidationError(
        field="vendor",
        message=(
            f"Unsupported vendor '{vendor}'. "
            f"Supported values: {sorted(SUPPORTED_VENDORS)}. "
            f"Also accepted: {', '.join(sorted(VENDOR_ALIASES.keys()))}"
        ),
    )


# ---------------------------------------------------------------------------
# Payload size checks
# ---------------------------------------------------------------------------


def validate_payload_size(
    payload: str,
    field_name: str = "payload",
    max_bytes: Optional[int] = None,
) -> None:
    """
    Raise ValidationError if the UTF-8 encoding of ``payload`` exceeds ``max_bytes``.

    Args:
        payload:    The string to check.
        field_name: Used in the error message to identify which field failed.
        max_bytes:  Maximum allowed byte length.  Defaults to MAX_RULESET_PAYLOAD_BYTES.

    Raises:
        ValidationError: If the payload exceeds the size limit.
    """
    if max_bytes is None:
        max_bytes = MAX_RULESET_PAYLOAD_BYTES
    byte_len = len(payload.encode("utf-8"))
    if byte_len > max_bytes:
        raise ValidationError(
            field=field_name,
            message=(
                f"Payload exceeds maximum size of {max_bytes // (1024 * 1024)} MB "
                f"(actual: {byte_len // (1024 * 1024)} MB)."
            ),
        )


def check_payload_size(
    payload: str,
    max_bytes: int,
    field_name: str = "payload",
) -> None:
    """
    Raise ValidationError if the UTF-8 encoding of ``payload`` exceeds ``max_bytes``.

    Thin alias for validate_payload_size() with the max_bytes argument required.
    """
    validate_payload_size(payload, field_name=field_name, max_bytes=max_bytes)


# ---------------------------------------------------------------------------
# XML validation
# ---------------------------------------------------------------------------


def validate_xml_payload(payload: str, vendor: str) -> None:
    """
    Validate that ``payload`` is well-formed XML and does not contain dangerous
    constructs (XXE, Billion Laughs / entity expansion, DOCTYPE declarations).

    Uses defusedxml when available; falls back to a heuristic check that
    rejects DOCTYPE declarations outright.

    Args:
        payload: Raw XML string.
        vendor:  Vendor identifier (for error messages).

    Raises:
        ValidationError: If the payload is malformed or contains prohibited XML
                         constructs.
    """
    # Always reject DOCTYPE declarations — these enable XXE and entity attacks.
    payload_lower = payload.lstrip()
    if "<!DOCTYPE" in payload.upper():
        raise ValidationError(
            field="ruleset_payload",
            message=(
                f"[{vendor}] XML payload contains a DOCTYPE declaration, which is "
                f"prohibited for security reasons (XXE / entity expansion risk)."
            ),
        )

    # Try defusedxml first (preferred — provides complete protection)
    try:
        import defusedxml.ElementTree as ET
        try:
            ET.fromstring(payload)
        except Exception as exc:
            raise ValidationError(
                field="ruleset_payload",
                message=f"[{vendor}] XML is not well-formed: {exc}",
            ) from exc
        return
    except ImportError:
        pass

    # Fall back to stdlib xml.etree.ElementTree
    import xml.etree.ElementTree as ET  # noqa: S405 — defusedxml not available
    try:
        ET.fromstring(payload)
    except ET.ParseError as exc:
        raise ValidationError(
            field="ruleset_payload",
            message=f"[{vendor}] XML is not well-formed: {exc}",
        ) from exc


# ---------------------------------------------------------------------------
# JSON validation
# ---------------------------------------------------------------------------


def validate_json_payload(payload: str, vendor: str) -> None:
    """
    Validate that ``payload`` is well-formed JSON.

    Args:
        payload: Raw JSON string.
        vendor:  Vendor identifier (for error messages).

    Raises:
        ValidationError: If the payload cannot be parsed as JSON.
    """
    try:
        json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ValidationError(
            field="ruleset_payload",
            message=f"[{vendor}] JSON payload is not well-formed: {exc}",
        ) from exc


# ---------------------------------------------------------------------------
# IP address validation
# ---------------------------------------------------------------------------


def validate_ip_address_string(addr: str) -> Optional[str]:
    """
    Validate and normalize an IP address or CIDR string.

    Returns the normalized form (e.g., "10.0.0.0/24" for "10.0.0.0/255.255.255.0")
    or None if the string is not a valid address or CIDR.

    Args:
        addr: An IP address string, optionally in CIDR notation.

    Returns:
        Normalized CIDR string, or None if ``addr`` is not a valid IP/CIDR.
    """
    try:
        net = ipaddress.ip_network(addr, strict=False)
        return str(net)
    except ValueError:
        pass
    try:
        ipaddress.ip_address(addr)
        return addr
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Context objects validation
# ---------------------------------------------------------------------------


def validate_context_objects(context_json: Optional[str]) -> Optional[dict]:
    """
    Parse and validate a context_objects JSON string.

    The context_objects field is an optional JSON object with address/service
    object definitions.  This function parses the JSON, validates that it is
    a dict (not a list or primitive), and returns the parsed dict.

    Args:
        context_json: A JSON string or None.

    Returns:
        Parsed dict, or None if ``context_json`` is None or empty.

    Raises:
        ValidationError: If the string is not valid JSON or is not a JSON object.
    """
    if not context_json:
        return None
    try:
        parsed = json.loads(context_json)
    except json.JSONDecodeError as exc:
        raise ValidationError(
            field="context_objects",
            message=f"context_objects is not valid JSON: {exc}",
        ) from exc
    if not isinstance(parsed, dict):
        raise ValidationError(
            field="context_objects",
            message=(
                "context_objects must be a JSON object (dict), "
                f"got {type(parsed).__name__}."
            ),
        )
    return parsed
