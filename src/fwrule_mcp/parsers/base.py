"""
Abstract base class and shared data structures for all vendor parsers.

Responsibilities of the parsing layer:
- Extract object definitions (address objects/groups, service objects/groups)
- Extract the ordered rule list with raw (unresolved) field references
- Preserve positional order as an explicit index

Object resolution (turning "WebServers" → "10.1.2.0/24") is the responsibility
of the normalization layer, not the parsing layer.

Data flow:
  raw config text/XML/JSON
       ↓
  VendorParser.parse_policy()
       ↓
  ParsedPolicy  (VendorRule list  +  ObjectTable)
       ↓
  Normalization layer  →  NormalizedRule list
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Object table — extracted object definitions (all values are raw strings)
# ---------------------------------------------------------------------------


@dataclass
class ObjectTable:
    """
    All vendor-extracted object definitions for a single parsed policy.

    Values are raw strings exactly as they appear in the configuration —
    no IP validation or resolution is performed here.

    address_objects:
        Maps an object name to one or more raw address strings.
        Each string may be a CIDR ("10.0.0.0/24"), a host IP ("10.0.0.1"),
        a dotted-decimal-with-mask ("10.0.0.0 255.255.255.0"), an IP range
        ("10.0.0.1-10.0.0.10"), an FQDN, or a vendor keyword like "any".

    address_groups:
        Maps a group name to a list of member names (which may themselves be
        address objects or nested group names).

    service_objects:
        Maps a service name to a dict describing the service.  The dict
        contains at least one of:
            protocol  (str)    : "tcp", "udp", "icmp", "ip", etc.
            ports     (str)    : "80", "443", "8080-8090", "any"
            src_ports (str)    : source port spec (less common)
            icmp_type (str)    : ICMP type number
            icmp_code (str)    : ICMP code number
        The normalization layer is responsible for interpreting these strings.

    service_groups:
        Maps a group name to a list of member service object names.

    application_objects:
        Maps an application name to an opaque identifier string.  For PAN-OS
        App-ID these are names like "web-browsing"; for FTD these are category
        strings.  Kept opaque at this layer.
    """

    address_objects: dict[str, list[str]] = field(default_factory=dict)
    address_groups: dict[str, list[str]] = field(default_factory=dict)
    service_objects: dict[str, dict[str, str]] = field(default_factory=dict)
    service_groups: dict[str, list[str]] = field(default_factory=dict)
    application_objects: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# VendorRule — intermediate rule with unresolved references
# ---------------------------------------------------------------------------


@dataclass
class VendorRule:
    """
    A single firewall rule as extracted by a vendor parser.

    All address, service, zone, and application fields contain raw reference
    strings exactly as they appear in the configuration.  They may be:
      - Named object references: "WebServers", "PROD-HOSTS"
      - Inline literals: "10.0.0.0/24", "192.168.1.1"
      - Vendor keywords: "any", "any4", "any6"

    The normalization layer resolves these references against the ObjectTable
    to produce fully expanded AddressSet / ServiceSet / ZoneSet / ApplicationSet
    instances.

    Attributes:
        name:                  Rule name (from config), or None if unnamed.
        position:              0-based index of this rule in the policy list.
                               The normalization layer converts this to 1-based.
        enabled:               False if the rule is administratively disabled.
        source_zones:          List of source security zone names / "any".
        destination_zones:     List of destination security zone names / "any".
        source_addresses:      List of source address object names or literals.
        destination_addresses: List of destination address object names/literals.
        services:              List of service object names or inline specs.
        applications:          List of application names or "any".
        action:                Vendor-specific action string (e.g., "allow",
                               "BLOCK", "Accept").  Normalized to Action enum
                               by the normalization layer.
        negate_source:         True if the source address match is negated.
        negate_destination:    True if the destination address match is negated.
        description:           Optional free-text rule description.
        vendor_tags:           Arbitrary key-value pairs preserved for
                               traceability (hit counts, tags, logging flags).
    """

    name: Optional[str]
    position: int
    enabled: bool
    source_zones: list[str]
    destination_zones: list[str]
    source_addresses: list[str]
    destination_addresses: list[str]
    services: list[str]
    applications: list[str]
    action: str
    negate_source: bool = False
    negate_destination: bool = False
    description: str = ""
    vendor_tags: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# ParsedPolicy — complete output of a successful parse_policy call
# ---------------------------------------------------------------------------


@dataclass
class ParsedPolicy:
    """
    The complete result of parsing a vendor firewall configuration.

    Attributes:
        rules:       Ordered list of VendorRule instances.  Position 0 is the
                     first (highest-priority) rule in the policy.
        object_table: All address/service/group object definitions extracted
                      from the same configuration payload.
        vendor:       The canonical vendor identifier (e.g., "panos", "asa").
        os_version:  The OS/firmware version string detected from the payload,
                      or None if not detectable.
        warnings:    Non-fatal parse issues encountered (e.g., unrecognized
                      keywords, object references that could not be extracted).
    """

    rules: list[VendorRule]
    object_table: ObjectTable
    vendor: str
    os_version: Optional[str] = None
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# VendorParser — abstract base class
# ---------------------------------------------------------------------------


class VendorParser(ABC):
    """
    Abstract interface that all vendor parser implementations must satisfy.

    Design contract:
    - Parsers are stateless — no mutable state between parse_policy calls.
    - Parsers must handle malformed / partial inputs gracefully: catch
      exceptions internally, add warnings to ParsedPolicy, and return whatever
      partial results are available rather than raising.
    - Parsers must NOT resolve named object references to IP addresses.
      That is the normalization layer's job.
    - All XML parsing must disable external entities to prevent XXE attacks.

    Class attributes:
        VENDOR:      Canonical vendor identifier string (e.g., "panos").
        OS_FAMILIES: OS family prefixes this parser handles (e.g., ["10.", "11."]).
                     An empty list means "handle all versions for this vendor."
    """

    VENDOR: str = ""
    OS_FAMILIES: list[str] = []

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    def supported_vendors(self) -> list[tuple[str, Optional[str]]]:
        """
        Return a list of (vendor_id, os_family) tuples this parser handles.

        Examples:
            [("panos", None)]          — handles all PAN-OS versions
            [("asa", "9."), ("asa", "8.")]  — handles ASA 8.x and 9.x
        """
        ...

    @abstractmethod
    def parse_policy(
        self,
        raw_payload: str,
        context: Optional[dict[str, Any]] = None,
    ) -> ParsedPolicy:
        """
        Parse a complete firewall policy configuration.

        Args:
            raw_payload: Raw configuration text, XML, or JSON string.
            context:     Optional supplemental data (e.g., shared object
                         libraries from a management platform).

        Returns:
            ParsedPolicy with ordered rules and fully populated ObjectTable.
            On partial parse failure, returns whatever was successfully
            extracted with failure details in ParsedPolicy.warnings.

        Raises:
            ValueError: Only for catastrophic failures where zero rules could
                        be extracted and no useful partial result exists.
        """
        ...

    @abstractmethod
    def parse_single_rule(
        self,
        raw_rule: str,
        object_table: Optional[ObjectTable] = None,
    ) -> VendorRule:
        """
        Parse a single candidate rule string.

        The candidate rule is expressed in the same vendor syntax as a full
        policy.  The provided ObjectTable (if any) came from a prior
        parse_policy call on the existing policy, allowing the candidate to
        reference the same named objects.

        Args:
            raw_rule:     The raw candidate rule text/XML/JSON.
            object_table: Pre-built object table from the existing policy parse,
                          or None if the candidate stands alone.

        Returns:
            A single VendorRule instance at position 0.

        Raises:
            ValueError: If the candidate cannot be parsed at all.
        """
        ...

    # ------------------------------------------------------------------
    # Concrete helpers available to all subclasses
    # ------------------------------------------------------------------

    def vendor_id(self) -> str:
        """Return the canonical vendor identifier for this parser."""
        return self.VENDOR

    def _warn(self, warnings: list[str], message: str) -> None:
        """Append a warning message; used inside parse implementations."""
        warnings.append(f"[{self.VENDOR}] {message}")
