"""
Normalization layer — transforms vendor-parsed rules into NormalizedRule objects.

Responsibilities:
  - Resolve named address objects → sets of IP prefixes (recursive, with cycle detection)
  - Resolve named service objects → sets of (protocol, port-range) tuples
  - Flatten object groups recursively
  - Map vendor action strings → canonical Action enum
  - Map vendor zone/interface names → canonical ZoneSet
  - Map vendor rule state (enabled/disabled) → bool
  - Record UNRESOLVABLE_REFERENCE warnings in rule metadata

This layer has no knowledge of vendors, MCP, or overlap logic.
It operates on the output of the parsing layer and produces NormalizedRule
objects consumed by the analysis engine.

Public API
----------
PolicyNormalizer      — main entry point; normalizes full policies and candidates
NormalizationResult   — container for normalized rules + warnings
ObjectResolver        — resolves named references against an ObjectTable
ResolutionWarning     — non-fatal warning from the resolution step
map_action()          — vendor action string → Action enum
parse_address_literal()  — raw string → AddressEntry | None
parse_service_literal()  — raw string → ServiceEntry | None
ACTION_MAP            — complete vendor action → Action mapping dict
WELL_KNOWN_SERVICES   — well-known service name → (protocol, port) dict
"""

from fwrule_mcp.normalization.mappers import (
    ACTION_MAP,
    WELL_KNOWN_SERVICES,
    map_action,
    parse_address_literal,
    parse_service_literal,
    wildcard_to_prefix,
)
from fwrule_mcp.normalization.normalizer import (
    NormalizationResult,
    PolicyNormalizer,
)
from fwrule_mcp.normalization.resolver import (
    ObjectResolver,
    ResolutionWarning,
)

__all__ = [
    # Normalizer
    "PolicyNormalizer",
    "NormalizationResult",
    # Resolver
    "ObjectResolver",
    "ResolutionWarning",
    # Mappers
    "map_action",
    "parse_address_literal",
    "parse_service_literal",
    "wildcard_to_prefix",
    "ACTION_MAP",
    "WELL_KNOWN_SERVICES",
]
