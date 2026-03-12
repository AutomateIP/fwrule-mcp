"""
Request schema for the analyze_firewall_rule_overlap MCP tool.

AnalysisRequest is the top-level input object deserialized from the MCP tool
call.  Validation is structural and semantic at this layer — we confirm that
required fields are present, vendor is a recognized string, and payloads meet
minimum length requirements.  Parser-level format validation happens downstream.

ContextObjects is an optional supplemental payload for vendors that store
address objects, service objects, and zone definitions in separate files or
API responses from the main policy document.
"""

from __future__ import annotations

from typing import Annotated, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

# Recognized vendor identifiers.  This is the authoritative list; the parser
# registry validates against this when dispatching.
SUPPORTED_VENDORS: frozenset[str] = frozenset(
    {"panos", "asa", "ftd", "checkpoint", "juniper"}
)

# Hard upper limit on ruleset payload size to protect the server from
# accidental or malicious oversized inputs.  Parsers may enforce tighter
# per-format limits.  64 MB should accommodate even large Panorama exports.
MAX_PAYLOAD_BYTES: int = 64 * 1024 * 1024  # 64 MB


class ContextObjects(BaseModel):
    """
    Optional supplemental object definitions provided alongside the ruleset.

    Many vendor formats store address objects, service definitions, and zone
    mappings separately from the policy rules themselves.  The caller may supply
    them here so the normalization layer can resolve references that appear in
    the ruleset or candidate rule.

    Values are raw definition strings — the parser is responsible for
    interpreting their format (e.g., XML fragment, JSON object, text block).
    """

    address_objects: Optional[dict[str, str]] = Field(
        default=None,
        description=(
            "Map of address object name → raw definition string. "
            "e.g., {'WebServers': '10.1.2.0/24', 'DMZHosts': '10.2.0.0/16'}"
        ),
    )
    service_objects: Optional[dict[str, str]] = Field(
        default=None,
        description=(
            "Map of service object name → raw definition string. "
            "e.g., {'HTTPS': 'tcp/443', 'CustomApp': 'tcp/8080-8090'}"
        ),
    )
    zone_mappings: Optional[dict[str, str]] = Field(
        default=None,
        description=(
            "Map of vendor zone/interface identifier → canonical zone name. "
            "Used by the normalization layer when interface names need to be "
            "mapped to logical zone names for zone-based analysis."
        ),
    )
    address_groups: Optional[dict[str, list[str]]] = Field(
        default=None,
        description=(
            "Map of group name → list of member names.  Members may be address "
            "object names or nested group names.  The resolver handles recursive "
            "expansion with cycle detection."
        ),
    )
    service_groups: Optional[dict[str, list[str]]] = Field(
        default=None,
        description="Map of service group name → list of member service names.",
    )

    model_config = {"extra": "forbid"}


class AnalysisRequest(BaseModel):
    """
    Top-level request payload for the firewall rule overlap analysis tool.

    Required fields:
    - vendor: must be one of the SUPPORTED_VENDORS identifiers
    - ruleset_payload: the complete existing firewall policy in vendor format
    - candidate_rule_payload: a single candidate rule in the same vendor format

    Optional fields:
    - os_version: vendor OS version string (e.g., "10.2", "9.3.1") — used to
      select the correct parser variant when a vendor has format differences
      across OS generations.
    - context: supplemental object definitions (see ContextObjects)
    - candidate_intended_position: 1-based insert position hint for the candidate.
      When provided, shadow analysis only considers existing rules above this
      position.  When absent, the candidate is assumed to be appended at the end.
    """

    vendor: Annotated[
        str,
        Field(
            description=(
                f"Firewall vendor identifier. "
                f"Supported values: {sorted(SUPPORTED_VENDORS)}"
            )
        ),
    ]
    os_version: Optional[str] = Field(
        default=None,
        description=(
            "Vendor OS version string.  Used to select the correct parser "
            "variant.  Examples: '10.2.3', '9.16', '7.4.1'.  If omitted, "
            "the parser registry uses the default (latest) parser for the vendor."
        ),
    )
    ruleset_payload: str = Field(
        description=(
            "The complete existing firewall policy in the vendor's native format "
            "(XML for PAN-OS, text for ASA, JSON for FTD, etc.).  Must be "
            "non-empty and within the size limit."
        ),
    )
    candidate_rule_payload: str = Field(
        description=(
            "A single candidate firewall rule in the same vendor format as the "
            "ruleset.  The analysis determines how this rule interacts with the "
            "existing policy."
        ),
    )
    context: Optional[ContextObjects] = Field(
        default=None,
        description=(
            "Optional supplemental object definitions.  Provide this when "
            "address/service objects are defined outside the main ruleset payload "
            "(common with Panorama, FMC, and Check Point management exports)."
        ),
    )
    candidate_intended_position: Optional[int] = Field(
        default=None,
        ge=1,
        description=(
            "1-based position at which the candidate rule would be inserted in "
            "the policy.  Affects shadow analysis (only rules above this position "
            "can shadow the candidate).  Defaults to end-of-policy."
        ),
    )

    model_config = {"extra": "forbid"}

    # ------------------------------------------------------------------
    # Validators
    # ------------------------------------------------------------------

    @field_validator("vendor")
    @classmethod
    def vendor_must_be_supported(cls, v: str) -> str:
        normalized = v.lower().strip()
        if normalized not in SUPPORTED_VENDORS:
            raise ValueError(
                f"Unsupported vendor '{v}'. "
                f"Supported vendors: {sorted(SUPPORTED_VENDORS)}"
            )
        return normalized

    @field_validator("os_version")
    @classmethod
    def os_version_strip(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v = v.strip()
            if not v:
                return None
        return v

    @field_validator("ruleset_payload")
    @classmethod
    def ruleset_must_be_non_empty(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("ruleset_payload must not be empty.")
        if len(v.encode()) > MAX_PAYLOAD_BYTES:
            raise ValueError(
                f"ruleset_payload exceeds maximum size of "
                f"{MAX_PAYLOAD_BYTES // (1024 * 1024)} MB."
            )
        return v

    @field_validator("candidate_rule_payload")
    @classmethod
    def candidate_must_be_non_empty(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("candidate_rule_payload must not be empty.")
        if len(v.encode()) > MAX_PAYLOAD_BYTES:
            raise ValueError(
                f"candidate_rule_payload exceeds maximum size of "
                f"{MAX_PAYLOAD_BYTES // (1024 * 1024)} MB."
            )
        return v

    @model_validator(mode="after")
    def ruleset_and_candidate_differ(self) -> "AnalysisRequest":
        """
        Warn-level validation: if the ruleset and candidate payloads are byte-for-byte
        identical, the caller likely made a mistake.  We do not reject this (it could
        be a single-rule policy being compared against itself), but downstream analysis
        will likely flag an exact duplicate finding.
        """
        # No rejection — structural check only.
        return self
