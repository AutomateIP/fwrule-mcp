"""
Resource limit constants.

These values protect server stability by bounding the computational work any
single analysis request can trigger.  They are intentionally conservative for
v1 and should be tuned based on observed production load patterns.

All constants are module-level so they can be overridden via environment
variables in a future configuration layer without code changes.

See Architecture §7.5 for the rationale behind these limits.
"""

from __future__ import annotations

import os

# ---------------------------------------------------------------------------
# Payload size limits
# ---------------------------------------------------------------------------

# Maximum raw payload size for the existing ruleset (bytes).
# 64 MB accommodates even large Panorama exports with thousands of rules.
MAX_RULESET_PAYLOAD_BYTES: int = int(
    os.getenv("FOMC_MAX_RULESET_BYTES", str(64 * 1024 * 1024))
)

# Maximum raw payload size for the candidate rule (bytes).
# Candidate rules are always single rules — 1 MB is generous.
MAX_CANDIDATE_PAYLOAD_BYTES: int = int(
    os.getenv("FOMC_MAX_CANDIDATE_BYTES", str(1 * 1024 * 1024))
)

# ---------------------------------------------------------------------------
# Rule count limits
# ---------------------------------------------------------------------------

# Maximum number of rules the normalization layer will process in a single request.
# Requests exceeding this limit receive a partial analysis with a warning.
MAX_RULES_PER_REQUEST: int = int(os.getenv("FOMC_MAX_RULES", "10000"))

# Maximum number of rules that will be fully analyzed (compared against the candidate).
# Rules beyond this position are skipped with a warning.  Typically the same as
# MAX_RULES_PER_REQUEST but can be set lower for performance tuning.
MAX_RULES_FOR_ANALYSIS: int = int(os.getenv("FOMC_MAX_ANALYSIS_RULES", "10000"))

# ---------------------------------------------------------------------------
# Object resolution limits
# ---------------------------------------------------------------------------

# Maximum depth for recursive object group expansion.
# Protects against deeply nested or circular group definitions.
MAX_GROUP_RECURSION_DEPTH: int = int(os.getenv("FOMC_MAX_GROUP_DEPTH", "32"))

# Maximum number of IP prefixes a single address object group can expand to.
# Prevents combinatorial explosion from very large nested groups.
MAX_EXPANDED_PREFIXES_PER_OBJECT: int = int(
    os.getenv("FOMC_MAX_PREFIXES_PER_OBJECT", "10000")
)

# ---------------------------------------------------------------------------
# Analysis time limits
# ---------------------------------------------------------------------------

# Wall-clock budget (seconds) for the complete analysis pipeline per request.
# If exceeded, partial results are returned with a timeout indicator.
ANALYSIS_TIMEOUT_SECONDS: float = float(os.getenv("FOMC_ANALYSIS_TIMEOUT", "30.0"))

# ---------------------------------------------------------------------------
# Response limits
# ---------------------------------------------------------------------------

# Maximum number of Finding objects to include in a single response.
# If the analysis produces more findings than this, the highest-severity
# findings are kept and the rest are summarized in analysis_summary.
MAX_FINDINGS_PER_RESPONSE: int = int(os.getenv("FOMC_MAX_FINDINGS", "500"))

# ---------------------------------------------------------------------------
# Aliases for backwards compatibility and alternate naming conventions
# ---------------------------------------------------------------------------

# Canonical alias for the ruleset payload size limit.
MAX_PAYLOAD_SIZE: int = MAX_RULESET_PAYLOAD_BYTES

# Maximum recursion depth for nested address/service group expansion.
# Alias for MAX_GROUP_RECURSION_DEPTH (used by some callers as MAX_RESOLUTION_DEPTH).
MAX_RESOLUTION_DEPTH: int = MAX_GROUP_RECURSION_DEPTH

# Analysis timeout in seconds (integer alias for ANALYSIS_TIMEOUT_SECONDS).
ANALYSIS_TIMEOUT: int = int(ANALYSIS_TIMEOUT_SECONDS)

# ---------------------------------------------------------------------------
# Supported vendor identifiers
# ---------------------------------------------------------------------------

# Canonical list of supported vendor identifiers.
# This list is the single source of truth — models/request.py and
# utils/validation.py both reference this.
SUPPORTED_VENDORS: frozenset[str] = frozenset({
    "panos",
    "asa",
    "ftd",
    "checkpoint",
    "juniper",
    "ios",
    "iosxr",
    "junos",
    "sros",
})
