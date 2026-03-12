"""
Object reference resolver for the normalization layer.

The resolver's job is to take a raw reference string (e.g., "WebServers",
"10.0.0.0/24", "HTTPS", "any") and expand it into a concrete list of address
entries or service dicts using the ObjectTable extracted by the parsing layer.

Key design decisions:
- Recursive resolution with a per-path visited-set for cycle detection.
- LRU-style result cache to avoid redundant work on large policies where the
  same object is referenced by hundreds of rules.
- All failures are non-fatal: unresolvable references produce a
  ResolutionWarning and are silently skipped, so the caller receives whatever
  partial results are available.
- Maximum recursion depth (MAX_DEPTH = 50) protects against degenerate group
  nesting regardless of whether cycles are present.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from fwrule_mcp.models.common import (
    AddressEntry,
    ServiceEntry,
)
from fwrule_mcp.normalization.mappers import (
    WELL_KNOWN_SERVICES,
    parse_address_literal,
    parse_service_literal,
)
from fwrule_mcp.parsers.base import ObjectTable

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Warning dataclass
# ---------------------------------------------------------------------------


@dataclass
class ResolutionWarning:
    """
    A non-fatal issue encountered while resolving an object reference.

    Attributes:
        object_name:  The reference string that triggered the warning.
        warning_type: One of "unresolvable", "circular", "depth_exceeded".
        message:      Human-readable explanation.
    """

    object_name: str
    warning_type: str   # "unresolvable" | "circular" | "depth_exceeded"
    message: str


# ---------------------------------------------------------------------------
# ObjectResolver
# ---------------------------------------------------------------------------


class ObjectResolver:
    """
    Resolves named object references from an ObjectTable.

    Usage:
        resolver = ObjectResolver(object_table)
        cidrs: list[str] = resolver.resolve_address("WebServers")
        services: list[dict] = resolver.resolve_service("HTTPS")
        warnings: list[ResolutionWarning] = resolver.warnings
    """

    #: Hard cap on group nesting depth to prevent runaway recursion.
    MAX_DEPTH: int = 50

    def __init__(self, object_table: ObjectTable) -> None:
        self.object_table = object_table
        self.warnings: list[ResolutionWarning] = []
        # Caches store fully-resolved results keyed by object name.
        # address cache: name → list of raw value strings (CIDR / host / range etc.)
        self._address_cache: dict[str, list[str]] = {}
        # service cache: name → list of {"protocol": ..., "ports": ..., ...} dicts
        self._service_cache: dict[str, list[dict]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def resolve_address(self, reference: str) -> list[str]:
        """
        Resolve an address reference to a list of raw address value strings.

        The returned strings are in canonical form (CIDR notation, IP range
        "start-end", FQDN, or the sentinel "any").  They can be passed
        directly to parse_address_literal() in the normalization step.

        Handles:
        - Literal IPs / CIDRs — returned as-is
        - Named address objects — value strings from the object table
        - Named address groups — recursively expanded member values
        - "any" and vendor keywords — returned as ["any"]
        - Circular references — warning emitted, partial results returned
        - Max depth exceeded — warning emitted, partial results returned
        - Missing objects — warning emitted, empty list returned
        """
        if reference in self._address_cache:
            return self._address_cache[reference]

        result = self._resolve_address_recursive(reference, visited=set(), depth=0)
        self._address_cache[reference] = result
        return result

    def resolve_service(self, reference: str) -> list[dict]:
        """
        Resolve a service reference to a list of service descriptor dicts.

        Each dict contains at minimum a "protocol" key.  For TCP/UDP it also
        contains "ports" (a port spec string or None for "any port").  For
        ICMP it contains optional "icmp_type" and "icmp_code" strings.

        Handles:
        - Named service objects
        - Named service groups (recursive)
        - Literal protocol specs ("tcp/443", "udp/53", "icmp")
        - Well-known service names ("http", "https", "ssh", …)
        - "any" keyword
        """
        if reference in self._service_cache:
            return self._service_cache[reference]

        result = self._resolve_service_recursive(reference, visited=set(), depth=0)
        self._service_cache[reference] = result
        return result

    def resolve_zone(self, raw_zone: str) -> str:
        """
        Return the canonical zone label for ``raw_zone``.

        The ObjectTable does not carry a zone mapping table — zone names are
        used directly as they appear in the vendor config.  This method is a
        passthrough, provided for symmetry and to allow future extension (e.g.,
        interface-to-zone mapping) without changing call sites.
        """
        return raw_zone

    def get_warnings(self) -> list[ResolutionWarning]:
        """Return accumulated resolution warnings (informational only)."""
        return list(self.warnings)

    def clear_warnings(self) -> None:
        """Clear accumulated warnings (useful between rule normalization passes)."""
        self.warnings.clear()

    # ------------------------------------------------------------------
    # Address resolution internals
    # ------------------------------------------------------------------

    def _resolve_address_recursive(
        self,
        name: str,
        visited: set[str],
        depth: int,
    ) -> list[str]:
        """
        Recursively resolve an address name to raw value strings.

        ``visited`` tracks the current resolution path for cycle detection.
        ``depth`` enforces the MAX_DEPTH guard independently of cycle detection
        (protects against very deep but non-cyclic group nesting).
        """
        # --- Depth guard ---
        if depth > self.MAX_DEPTH:
            self._warn(
                name,
                "depth_exceeded",
                f"Max resolution depth ({self.MAX_DEPTH}) exceeded while expanding "
                f"address reference {name!r}. Partial results returned.",
            )
            return []

        # --- ANY / vendor wildcard keywords ---
        if name.strip().lower() in ("any", "any4", "any6", "all", "0.0.0.0/0", "::/0"):
            return ["any"]

        # --- Literal IP / CIDR / range — parseable without object table lookup ---
        entry = parse_address_literal(name)
        if entry is not None:
            # Parsed successfully as a literal — return it directly.
            # Use "any" string for the ANY sentinel; otherwise the original value.
            from fwrule_mcp.models.common import AddressType
            if entry.addr_type == AddressType.ANY:
                return ["any"]
            return [name]

        # --- Cycle detection ---
        if name in visited:
            self._warn(
                name,
                "circular",
                f"Circular reference detected while resolving address group {name!r}. "
                f"Resolution path: {' → '.join(sorted(visited))} → {name!r}.",
            )
            return []

        new_visited = visited | {name}

        # --- Named address object lookup (leaf) ---
        if name in self.object_table.address_objects:
            values = self.object_table.address_objects[name]
            # Each value may itself be a name (for indirection) or a literal.
            # We recursively resolve each one.
            result: list[str] = []
            for v in values:
                resolved = self._resolve_address_recursive(v, new_visited, depth + 1)
                result.extend(resolved)
            return result

        # --- Named address group lookup (recursive expansion) ---
        if name in self.object_table.address_groups:
            members = self.object_table.address_groups[name]
            result = []
            for member in members:
                resolved = self._resolve_address_recursive(member, new_visited, depth + 1)
                result.extend(resolved)
            return result

        # --- Unresolvable ---
        self._warn(
            name,
            "unresolvable",
            f"Address reference {name!r} not found in object table and is not a "
            f"recognized literal. It will be omitted from the resolved address set.",
        )
        return []

    # ------------------------------------------------------------------
    # Service resolution internals
    # ------------------------------------------------------------------

    def _resolve_service_recursive(
        self,
        name: str,
        visited: set[str],
        depth: int,
    ) -> list[dict]:
        """
        Recursively resolve a service name to a list of service descriptor dicts.

        Service descriptor dict keys:
            protocol  (str)            required
            ports     (str|None)       optional; None = any port
            icmp_type (str|None)       optional
            icmp_code (str|None)       optional
        """
        # --- Depth guard ---
        if depth > self.MAX_DEPTH:
            self._warn(
                name,
                "depth_exceeded",
                f"Max resolution depth ({self.MAX_DEPTH}) exceeded while expanding "
                f"service reference {name!r}. Partial results returned.",
            )
            return []

        # --- ANY ---
        if name.strip().lower() in ("any", "ip", "all"):
            return [{"protocol": "any", "ports": None}]

        # --- Well-known service name lookup (shortcut before object table) ---
        lower_name = name.strip().lower()
        if lower_name in WELL_KNOWN_SERVICES:
            proto, port = WELL_KNOWN_SERVICES[lower_name]
            port_str = str(port) if port is not None else None
            return [{"protocol": proto, "ports": port_str}]

        # --- Literal service spec — try to parse it directly ---
        entry = parse_service_literal(name)
        if entry is not None:
            return [_service_entry_to_dict(entry)]

        # --- Cycle detection ---
        if name in visited:
            self._warn(
                name,
                "circular",
                f"Circular reference detected while resolving service group {name!r}. "
                f"Resolution path: {' → '.join(sorted(visited))} → {name!r}.",
            )
            return []

        new_visited = visited | {name}

        # --- Named service object lookup (leaf) ---
        if name in self.object_table.service_objects:
            svc_dict = self.object_table.service_objects[name]
            # The dict already has protocol/ports/icmp_type/icmp_code keys from the parser.
            # Normalize the protocol to lowercase and return.
            normalized = _normalize_service_dict(svc_dict)
            return [normalized] if normalized else []

        # --- Named service group lookup (recursive expansion) ---
        if name in self.object_table.service_groups:
            members = self.object_table.service_groups[name]
            result: list[dict] = []
            for member in members:
                resolved = self._resolve_service_recursive(member, new_visited, depth + 1)
                result.extend(resolved)
            return result

        # --- Unresolvable ---
        self._warn(
            name,
            "unresolvable",
            f"Service reference {name!r} not found in object table and is not a "
            f"recognized literal. It will be omitted from the resolved service set.",
        )
        return []

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _warn(self, object_name: str, warning_type: str, message: str) -> None:
        """Record a ResolutionWarning and log it at DEBUG level."""
        warning = ResolutionWarning(
            object_name=object_name,
            warning_type=warning_type,
            message=message,
        )
        self.warnings.append(warning)
        logger.debug("ResolutionWarning [%s] %r: %s", warning_type, object_name, message)


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _service_entry_to_dict(entry: ServiceEntry) -> dict:
    """Convert a ServiceEntry to a service descriptor dict."""
    result: dict = {"protocol": entry.protocol}
    if entry.ports is not None:
        # Express ports as a compact string for the cache dict
        port_parts = [str(pr) for pr in entry.ports]
        result["ports"] = ",".join(port_parts)
    else:
        result["ports"] = None
    if entry.icmp_type is not None:
        result["icmp_type"] = str(entry.icmp_type)
    if entry.icmp_code is not None:
        result["icmp_code"] = str(entry.icmp_code)
    return result


def _normalize_service_dict(raw: dict[str, str]) -> Optional[dict]:
    """
    Normalize a raw service dict from the ObjectTable into a canonical form.

    The dict must contain at least a "protocol" key.  Missing keys are
    treated as "any" (None).  Returns None if the dict is unusable.
    """
    protocol = raw.get("protocol", "")
    if not protocol:
        return None
    normalized: dict = {"protocol": protocol.lower().strip()}
    # Port field — may be keyed as "ports", "port", or "dst_ports"
    port_value = raw.get("ports") or raw.get("port") or raw.get("dst_ports")
    normalized["ports"] = port_value if port_value and port_value.lower() != "any" else None
    # ICMP fields
    if "icmp_type" in raw:
        normalized["icmp_type"] = raw["icmp_type"]
    if "icmp_code" in raw:
        normalized["icmp_code"] = raw["icmp_code"]
    return normalized
