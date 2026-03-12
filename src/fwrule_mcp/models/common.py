"""
Core building-block data structures for firewall rule representation.

All structures here are vendor-agnostic.  They are produced by the normalization
layer and consumed exclusively by the analysis engine.  No vendor-specific
knowledge belongs in this module.

Key design choices:
- AddressEntry, PortRange, and ServiceEntry are plain Python dataclasses (not
  Pydantic models) because they are created in hot paths (thousands of objects
  per large policy) and do not need serialization at this layer.
- AddressSet, ServiceSet, ZoneSet, and ApplicationSet ARE Pydantic models because
  they appear inside NormalizedRule, which IS serialized.
- All set-theoretic methods (intersects, is_subset_of, is_superset_of, intersection)
  are fully implemented — no placeholders.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv4Network, IPv6Network, ip_network
from typing import Optional, Union

from pydantic import BaseModel, Field, model_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class AddressFamily(str, Enum):
    """IP address family."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"


class AddressType(str, Enum):
    """How an address is expressed in the original configuration."""

    CIDR = "cidr"       # 10.0.0.0/24 or 2001:db8::/32
    RANGE = "range"     # 10.0.0.1-10.0.0.100
    ANY = "any"         # Vendor "any" / "0.0.0.0/0" sentinel
    HOST = "host"       # Single host — stored as /32 or /128 CIDR
    FQDN = "fqdn"       # DNS name — kept opaque, matched by identity only


class Action(str, Enum):
    """Canonical action enum.  Vendor action strings are mapped here during normalization."""

    PERMIT = "permit"
    DENY = "deny"
    DROP = "drop"           # Silent deny (no RST / ICMP unreachable)
    REJECT = "reject"       # Deny with RST or ICMP unreachable
    LOG_ONLY = "log_only"   # Match and log but do not block
    UNKNOWN = "unknown"     # Unrecognized vendor string; treated conservatively


# Treat these actions as equivalent "blocking" for overlap analysis purposes.
BLOCKING_ACTIONS: frozenset[Action] = frozenset({Action.DENY, Action.DROP, Action.REJECT})


# ---------------------------------------------------------------------------
# Address structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AddressEntry:
    """
    A single resolved address component.

    For CIDR / HOST types, ``cidr`` holds an IPv4Network or IPv6Network (always
    with strict=False so host bits are zeroed).  For RANGE types, ``range_start``
    and ``range_end`` hold integer representations of the boundary IPs.  For FQDN
    types, ``fqdn`` holds the domain name string.  ANY entries have no payload
    fields populated beyond ``addr_type``.

    ``original_name`` is preserved for explanation generation (e.g., "WebServers"
    resolves to 10.1.2.0/24).
    """

    addr_type: AddressType
    addr_family: AddressFamily = AddressFamily.IPV4
    # CIDR / HOST
    cidr: Optional[Union[IPv4Network, IPv6Network]] = None
    # RANGE
    range_start: Optional[int] = None  # integer form of start IP
    range_end: Optional[int] = None    # integer form of end IP
    # FQDN
    fqdn: Optional[str] = None
    # Traceability
    original_name: Optional[str] = None

    # ------------------------------------------------------------------
    # Factory helpers
    # ------------------------------------------------------------------

    @classmethod
    def from_cidr(cls, cidr_str: str, original_name: Optional[str] = None) -> "AddressEntry":
        """Create an AddressEntry from a CIDR string like '10.0.0.0/24'."""
        net = ip_network(cidr_str, strict=False)
        family = AddressFamily.IPV4 if isinstance(net, IPv4Network) else AddressFamily.IPV6
        addr_type = AddressType.HOST if net.prefixlen == net.max_prefixlen else AddressType.CIDR
        return cls(
            addr_type=addr_type,
            addr_family=family,
            cidr=net,
            original_name=original_name or cidr_str,
        )

    @classmethod
    def from_range(
        cls,
        start: str,
        end: str,
        original_name: Optional[str] = None,
    ) -> "AddressEntry":
        """Create an AddressEntry from a start-end IP range string pair."""
        start_addr = ipaddress.ip_address(start)
        end_addr = ipaddress.ip_address(end)
        family = AddressFamily.IPV4 if start_addr.version == 4 else AddressFamily.IPV6
        return cls(
            addr_type=AddressType.RANGE,
            addr_family=family,
            range_start=int(start_addr),
            range_end=int(end_addr),
            original_name=original_name or f"{start}-{end}",
        )

    @classmethod
    def any_sentinel(cls) -> "AddressEntry":
        """Return the canonical ANY entry."""
        return cls(addr_type=AddressType.ANY, addr_family=AddressFamily.IPV4)

    @classmethod
    def from_fqdn(cls, fqdn: str) -> "AddressEntry":
        return cls(addr_type=AddressType.FQDN, fqdn=fqdn, original_name=fqdn)

    # ------------------------------------------------------------------
    # Conversion helpers
    # ------------------------------------------------------------------

    def _to_int_range(self) -> tuple[int, int]:
        """
        Return (start_int, end_int) for this entry regardless of representation.
        Raises ValueError for FQDN / ANY entries.
        """
        if self.addr_type == AddressType.ANY:
            raise ValueError("ANY has no integer range — use special-case handling")
        if self.addr_type == AddressType.FQDN:
            raise ValueError("FQDN entries cannot be expressed as integer ranges")
        if self.addr_type == AddressType.RANGE:
            return (self.range_start, self.range_end)  # type: ignore[return-value]
        # CIDR or HOST
        net = self.cidr
        return (int(net.network_address), int(net.broadcast_address))  # type: ignore[union-attr]

    def to_prefixes(self) -> list[Union[IPv4Network, IPv6Network]]:
        """
        Expand this entry to a list of CIDR prefixes.

        RANGE entries are converted via summarize_address_range.  CIDR / HOST
        entries return a single-element list.  FQDN and ANY return empty list
        (callers must handle these specially).
        """
        if self.addr_type in (AddressType.ANY, AddressType.FQDN):
            return []
        if self.addr_type == AddressType.RANGE:
            start_ip = ipaddress.ip_address(self.range_start)  # type: ignore[arg-type]
            end_ip = ipaddress.ip_address(self.range_end)  # type: ignore[arg-type]
            return list(ipaddress.summarize_address_range(start_ip, end_ip))
        return [self.cidr]  # type: ignore[list-item]

    # ------------------------------------------------------------------
    # Intersection / containment logic
    # ------------------------------------------------------------------

    def contains(self, other: "AddressEntry") -> bool:
        """
        Return True if this entry's address space fully contains ``other``'s.

        ANY contains everything.  An FQDN entry contains only the same FQDN.
        """
        if self.addr_type == AddressType.ANY:
            return True
        if other.addr_type == AddressType.ANY:
            return False  # specific cannot contain ANY
        if self.addr_type == AddressType.FQDN or other.addr_type == AddressType.FQDN:
            if self.addr_type == AddressType.FQDN and other.addr_type == AddressType.FQDN:
                return self.fqdn == other.fqdn
            return False  # FQDN vs. CIDR / RANGE — cannot determine containment
        if self.addr_family != other.addr_family:
            return False

        self_start, self_end = self._to_int_range()
        other_start, other_end = other._to_int_range()
        return self_start <= other_start and self_end >= other_end

    def intersects(self, other: "AddressEntry") -> bool:
        """
        Return True if this entry's address space overlaps ``other``'s at all.
        """
        if self.addr_type == AddressType.ANY or other.addr_type == AddressType.ANY:
            return True
        if self.addr_type == AddressType.FQDN or other.addr_type == AddressType.FQDN:
            if self.addr_type == AddressType.FQDN and other.addr_type == AddressType.FQDN:
                return self.fqdn == other.fqdn
            return False
        if self.addr_family != other.addr_family:
            return False

        self_start, self_end = self._to_int_range()
        other_start, other_end = other._to_int_range()
        return self_start <= other_end and other_start <= self_end


# ---------------------------------------------------------------------------
# Port / Service structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PortRange:
    """
    An inclusive TCP/UDP port range [start, end].

    A single port (e.g., 443) is represented as PortRange(443, 443).
    The wildcard "any ports" is represented by the caller as absence of a
    PortRange list (None in ServiceEntry.ports).
    """

    start: int
    end: int

    def __post_init__(self) -> None:
        if not (0 <= self.start <= 65535):
            raise ValueError(f"Port start {self.start} out of range [0, 65535]")
        if not (0 <= self.end <= 65535):
            raise ValueError(f"Port end {self.end} out of range [0, 65535]")
        if self.start > self.end:
            raise ValueError(f"Port range start {self.start} > end {self.end}")

    def intersects(self, other: "PortRange") -> bool:
        """Return True if the two ranges share at least one port number."""
        return self.start <= other.end and other.start <= self.end

    def intersection(self, other: "PortRange") -> Optional["PortRange"]:
        """Return the overlapping PortRange, or None if disjoint."""
        low = max(self.start, other.start)
        high = min(self.end, other.end)
        return PortRange(low, high) if low <= high else None

    def is_subset_of(self, other: "PortRange") -> bool:
        """Return True if every port in self is also in other."""
        return other.start <= self.start and self.end <= other.end

    def is_superset_of(self, other: "PortRange") -> bool:
        """Return True if every port in other is also in self."""
        return other.is_subset_of(self)

    def __repr__(self) -> str:
        return f"{self.start}" if self.start == self.end else f"{self.start}-{self.end}"


def _merge_port_ranges(ranges: list[PortRange]) -> list[PortRange]:
    """
    Merge a list of possibly-overlapping PortRange objects into a sorted,
    non-overlapping canonical form.
    """
    if not ranges:
        return []
    sorted_ranges = sorted(ranges, key=lambda r: (r.start, r.end))
    merged: list[PortRange] = [sorted_ranges[0]]
    for current in sorted_ranges[1:]:
        last = merged[-1]
        if current.start <= last.end + 1:
            # Overlapping or adjacent — extend the last range
            merged[-1] = PortRange(last.start, max(last.end, current.end))
        else:
            merged.append(current)
    return merged


def _intersect_port_range_lists(
    a: list[PortRange], b: list[PortRange]
) -> list[PortRange]:
    """
    Compute the intersection of two lists of PortRange objects, each assumed
    to be in canonical (sorted, non-overlapping) form.  Returns a canonical list.
    """
    result: list[PortRange] = []
    i, j = 0, 0
    while i < len(a) and j < len(b):
        overlap = a[i].intersection(b[j])
        if overlap:
            result.append(overlap)
        # Advance whichever range ends sooner
        if a[i].end < b[j].end:
            i += 1
        elif b[j].end < a[i].end:
            j += 1
        else:
            i += 1
            j += 1
    return result


@dataclass(frozen=True)
class ServiceEntry:
    """
    A single resolved protocol/port specification.

    ``protocol`` is a lowercase string: "tcp", "udp", "icmp", "icmpv6", "any",
    or a decimal IP protocol number string (e.g., "47" for GRE).

    ``ports`` is a canonical (sorted, non-overlapping) list of PortRange objects
    for TCP/UDP.  None means "any port" for that protocol.

    ``icmp_type`` and ``icmp_code`` are integers (0-255) or None for "any".

    ``app_id`` is an optional opaque application-layer tag (e.g., "ssl",
    "web-browsing" from PAN-OS App-ID).
    """

    protocol: str                          # "tcp", "udp", "icmp", "any", or proto number
    ports: Optional[tuple[PortRange, ...]] = None  # None = any port; tuple for hashability
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    app_id: Optional[str] = None          # vendor application identifier, kept opaque

    def intersects(self, other: "ServiceEntry") -> bool:
        """
        Return True if there exists traffic that matches both self and other.

        Protocol "any" intersects everything.  For TCP/UDP, port ranges must
        also intersect (or at least one side must be "any port").
        """
        # Protocol check
        if self.protocol != "any" and other.protocol != "any":
            if self.protocol != other.protocol:
                return False

        # For TCP/UDP, check port intersection
        proto = self.protocol if self.protocol != "any" else other.protocol
        if proto in ("tcp", "udp"):
            # None ports means "any port"
            if self.ports is None or other.ports is None:
                return True
            self_ports = list(self.ports)
            other_ports = list(other.ports)
            intersection = _intersect_port_range_lists(self_ports, other_ports)
            return len(intersection) > 0

        # For ICMP, check type/code intersection
        if proto in ("icmp", "icmpv6"):
            if self.icmp_type is not None and other.icmp_type is not None:
                if self.icmp_type != other.icmp_type:
                    return False
                if self.icmp_code is not None and other.icmp_code is not None:
                    return self.icmp_code == other.icmp_code
            return True

        # Other protocols: presence of the same protocol number = intersect
        return True


# ---------------------------------------------------------------------------
# Set types (Pydantic models for serialization)
# ---------------------------------------------------------------------------


class AddressSet(BaseModel):
    """
    Represents the union of all address entries in a single rule direction
    (source or destination).

    ``is_any`` is True when the effective set is the entire address space.
    When ``is_any`` is True, all set-theoretic methods behave accordingly
    regardless of the ``entries`` list content.
    """

    model_config = {"arbitrary_types_allowed": True}

    entries: list[AddressEntry] = Field(default_factory=list)
    is_any: bool = Field(
        default=False,
        description="True when this set represents 'any' (entire address space)",
    )

    @model_validator(mode="after")
    def _propagate_any(self) -> "AddressSet":
        """If any entry is an ANY sentinel, promote the whole set to is_any=True."""
        if any(e.addr_type == AddressType.ANY for e in self.entries):
            object.__setattr__(self, "is_any", True)
        return self

    # ------------------------------------------------------------------
    # Factories
    # ------------------------------------------------------------------

    @classmethod
    def any(cls) -> "AddressSet":
        return cls(entries=[AddressEntry.any_sentinel()], is_any=True)

    @classmethod
    def from_cidrs(cls, cidrs: list[str]) -> "AddressSet":
        entries = [AddressEntry.from_cidr(c) for c in cidrs]
        return cls(entries=entries)

    # ------------------------------------------------------------------
    # Set-theoretic operations
    # ------------------------------------------------------------------

    def intersects(self, other: "AddressSet") -> bool:
        """
        Return True if there is at least one IP address that belongs to both sets.

        ANY intersects everything.  Two FQDN-only sets intersect only if they
        share a common FQDN.
        """
        if self.is_any or other.is_any:
            return True
        # For each pair of entries, check if any pair intersects
        for a in self.entries:
            for b in other.entries:
                if a.intersects(b):
                    return True
        return False

    def is_subset_of(self, other: "AddressSet") -> bool:
        """
        Return True if every address in self is also in other.

        Formally: self ⊆ other.
        """
        if other.is_any:
            return True
        if self.is_any:
            return False  # ANY cannot be a subset of a specific set
        # Every entry in self must be contained by at least one entry in other
        for a in self.entries:
            if not any(b.contains(a) for b in other.entries):
                return False
        return True

    def is_superset_of(self, other: "AddressSet") -> bool:
        """Return True if self ⊇ other."""
        return other.is_subset_of(self)

    def intersection(self, other: "AddressSet") -> "AddressSet":
        """
        Return an AddressSet representing the intersection of self and other.

        For CIDR entries, the intersection is computed using ipaddress primitives
        and expressed as a list of collapsed CIDR prefixes.  FQDN entries that
        match by identity are preserved.

        Note: The resulting AddressSet may not be perfectly minimal (it may
        contain redundant more-specific prefixes), but it is correct for
        set-theoretic queries.
        """
        if self.is_any:
            return other
        if other.is_any:
            return self
        result_entries: list[AddressEntry] = []
        for a in self.entries:
            for b in other.entries:
                if a.addr_type == AddressType.FQDN and b.addr_type == AddressType.FQDN:
                    if a.fqdn == b.fqdn:
                        result_entries.append(a)
                    continue
                if a.addr_type in (AddressType.FQDN, AddressType.ANY) or b.addr_type in (
                    AddressType.FQDN,
                    AddressType.ANY,
                ):
                    continue
                if not a.intersects(b):
                    continue
                # Compute the numeric range intersection
                a_start, a_end = a._to_int_range()
                b_start, b_end = b._to_int_range()
                low = max(a_start, b_start)
                high = min(a_end, b_end)
                family = a.addr_family  # same family guaranteed by intersects()
                start_ip = ipaddress.ip_address(low)
                end_ip = ipaddress.ip_address(high)
                for prefix in ipaddress.summarize_address_range(start_ip, end_ip):
                    result_entries.append(
                        AddressEntry(
                            addr_type=AddressType.CIDR,
                            addr_family=family,
                            cidr=prefix,
                            original_name=f"intersection({a.original_name},{b.original_name})",
                        )
                    )
        return AddressSet(entries=result_entries, is_any=False)

    def __bool__(self) -> bool:
        return self.is_any or len(self.entries) > 0

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AddressSet):
            return NotImplemented
        return self.is_any == other.is_any and set(self.entries) == set(other.entries)

    def __hash__(self) -> int:
        return hash((self.is_any, frozenset(self.entries)))


class ServiceSet(BaseModel):
    """
    Represents the union of all service/protocol entries in a single rule.

    ``is_any`` is True when the service is "any" — any protocol, any port.
    """

    model_config = {"arbitrary_types_allowed": True}

    entries: list[ServiceEntry] = Field(default_factory=list)
    is_any: bool = Field(
        default=False,
        description="True when this set represents any protocol/port combination",
    )

    # ------------------------------------------------------------------
    # Factories
    # ------------------------------------------------------------------

    @classmethod
    def any(cls) -> "ServiceSet":
        return cls(
            entries=[ServiceEntry(protocol="any")],
            is_any=True,
        )

    @classmethod
    def tcp(cls, *port_ranges: PortRange) -> "ServiceSet":
        """Convenience factory: TCP with given port ranges (or any if none given)."""
        ports = tuple(port_ranges) if port_ranges else None
        return cls(entries=[ServiceEntry(protocol="tcp", ports=ports)])

    @classmethod
    def udp(cls, *port_ranges: PortRange) -> "ServiceSet":
        ports = tuple(port_ranges) if port_ranges else None
        return cls(entries=[ServiceEntry(protocol="udp", ports=ports)])

    # ------------------------------------------------------------------
    # Set-theoretic operations
    # ------------------------------------------------------------------

    def intersects(self, other: "ServiceSet") -> bool:
        """Return True if any entry pair produces an intersection."""
        if self.is_any or other.is_any:
            return True
        for a in self.entries:
            for b in other.entries:
                if a.intersects(b):
                    return True
        return False

    def is_subset_of(self, other: "ServiceSet") -> bool:
        """
        Return True if every service in self is covered by other.

        A full algorithmic proof for all edge cases would require interval tree
        union covering checks; for v1 this uses conservative approximation:
        each entry in self must find at least one entry in other that is
        a superset.  This is correct for the non-overlapping canonical form.
        """
        if other.is_any:
            return True
        if self.is_any:
            return False
        for a in self.entries:
            if not any(_service_entry_is_subset_of(a, b) for b in other.entries):
                return False
        return True

    def is_superset_of(self, other: "ServiceSet") -> bool:
        return other.is_subset_of(self)

    def intersection(self, other: "ServiceSet") -> "ServiceSet":
        """Return a new ServiceSet containing only matching traffic."""
        if self.is_any:
            return other
        if other.is_any:
            return self
        result: list[ServiceEntry] = []
        for a in self.entries:
            for b in other.entries:
                entry = _intersect_service_entries(a, b)
                if entry is not None:
                    result.append(entry)
        return ServiceSet(entries=result, is_any=False)

    def __bool__(self) -> bool:
        return self.is_any or len(self.entries) > 0

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ServiceSet):
            return NotImplemented
        return self.is_any == other.is_any and set(self.entries) == set(other.entries)

    def __hash__(self) -> int:
        return hash((self.is_any, frozenset(self.entries)))


class ZoneSet(BaseModel):
    """
    Represents the set of security zones referenced in one direction of a rule.

    ``is_any`` means the rule applies regardless of zone (or zone information
    was unavailable in the vendor configuration).
    """

    zones: set[str] = Field(default_factory=set)
    is_any: bool = Field(
        default=False,
        description="True when zone information is absent or explicitly 'any'",
    )

    # ------------------------------------------------------------------
    # Factories
    # ------------------------------------------------------------------

    @classmethod
    def any(cls) -> "ZoneSet":
        return cls(zones=set(), is_any=True)

    @classmethod
    def from_names(cls, names: list[str]) -> "ZoneSet":
        return cls(zones=set(names), is_any=False)

    # ------------------------------------------------------------------
    # Set-theoretic operations
    # ------------------------------------------------------------------

    def intersects(self, other: "ZoneSet") -> bool:
        if self.is_any or other.is_any:
            return True
        return bool(self.zones & other.zones)

    def is_subset_of(self, other: "ZoneSet") -> bool:
        if other.is_any:
            return True
        if self.is_any:
            return False
        return self.zones <= other.zones

    def is_superset_of(self, other: "ZoneSet") -> bool:
        return other.is_subset_of(self)

    def intersection(self, other: "ZoneSet") -> "ZoneSet":
        if self.is_any:
            return other
        if other.is_any:
            return self
        common = self.zones & other.zones
        return ZoneSet(zones=common, is_any=False)

    def __bool__(self) -> bool:
        return self.is_any or len(self.zones) > 0

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ZoneSet):
            return NotImplemented
        return self.is_any == other.is_any and self.zones == other.zones

    def __hash__(self) -> int:
        return hash((self.is_any, frozenset(self.zones)))


class ApplicationSet(BaseModel):
    """
    Represents the set of application-layer identifiers (e.g., PAN-OS App-ID,
    Cisco NBAR) referenced in a rule.

    Application identifiers are opaque strings — we do not attempt to map
    them to port numbers in v1.  When ``is_any`` is True (or when both sets
    have is_any=True), the analysis engine skips application-dimension checks.
    """

    applications: set[str] = Field(default_factory=set)
    is_any: bool = Field(
        default=True,
        description=(
            "True when no application restriction is applied or application "
            "information is unavailable.  Defaults to True (most rules do not "
            "restrict by application)."
        ),
    )

    # ------------------------------------------------------------------
    # Factories
    # ------------------------------------------------------------------

    @classmethod
    def any(cls) -> "ApplicationSet":
        return cls(applications=set(), is_any=True)

    @classmethod
    def from_names(cls, names: list[str]) -> "ApplicationSet":
        return cls(applications=set(names), is_any=False)

    # ------------------------------------------------------------------
    # Set-theoretic operations
    # ------------------------------------------------------------------

    def intersects(self, other: "ApplicationSet") -> bool:
        if self.is_any or other.is_any:
            return True
        return bool(self.applications & other.applications)

    def is_subset_of(self, other: "ApplicationSet") -> bool:
        if other.is_any:
            return True
        if self.is_any:
            return False
        return self.applications <= other.applications

    def is_superset_of(self, other: "ApplicationSet") -> bool:
        return other.is_subset_of(self)

    def intersection(self, other: "ApplicationSet") -> "ApplicationSet":
        if self.is_any:
            return other
        if other.is_any:
            return self
        return ApplicationSet(applications=self.applications & other.applications, is_any=False)

    def __bool__(self) -> bool:
        return self.is_any or len(self.applications) > 0

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ApplicationSet):
            return NotImplemented
        return self.is_any == other.is_any and self.applications == other.applications

    def __hash__(self) -> int:
        return hash((self.is_any, frozenset(self.applications)))


# ---------------------------------------------------------------------------
# ServiceEntry helper functions (module-level to avoid circular refs)
# ---------------------------------------------------------------------------


def _service_entry_is_subset_of(a: ServiceEntry, b: ServiceEntry) -> bool:
    """
    Return True if every traffic spec matched by ``a`` is also matched by ``b``.
    """
    # Protocol check
    if b.protocol != "any" and a.protocol != b.protocol:
        return False

    proto = a.protocol
    if proto in ("tcp", "udp"):
        if b.ports is None:
            return True  # b allows any port — a is a subset
        if a.ports is None:
            return False  # a allows any port but b is restricted
        # Every range in a must be a subset of some range in b
        b_list = list(b.ports)
        for pr_a in a.ports:
            if not any(pr_a.is_subset_of(pr_b) for pr_b in b_list):
                return False
        return True

    if proto in ("icmp", "icmpv6"):
        if b.icmp_type is None:
            return True  # b = any type
        if a.icmp_type != b.icmp_type:
            return False
        if b.icmp_code is None:
            return True
        return a.icmp_code == b.icmp_code

    return True  # Other protocols: same protocol = subset


def _intersect_service_entries(a: ServiceEntry, b: ServiceEntry) -> Optional[ServiceEntry]:
    """
    Return a ServiceEntry representing traffic matched by both a and b, or None
    if the two entries are disjoint.
    """
    # Determine effective protocol
    if a.protocol == "any":
        proto = b.protocol
    elif b.protocol == "any":
        proto = a.protocol
    elif a.protocol == b.protocol:
        proto = a.protocol
    else:
        return None  # disjoint protocols

    if proto in ("tcp", "udp"):
        if a.ports is None and b.ports is None:
            ports = None
        elif a.ports is None:
            ports = b.ports
        elif b.ports is None:
            ports = a.ports
        else:
            merged = _intersect_port_range_lists(list(a.ports), list(b.ports))
            if not merged:
                return None
            ports = tuple(merged)
        return ServiceEntry(protocol=proto, ports=ports)

    if proto in ("icmp", "icmpv6"):
        icmp_type: Optional[int]
        icmp_code: Optional[int]
        if a.icmp_type is None:
            icmp_type = b.icmp_type
        elif b.icmp_type is None:
            icmp_type = a.icmp_type
        elif a.icmp_type == b.icmp_type:
            icmp_type = a.icmp_type
        else:
            return None  # different ICMP types — disjoint

        if icmp_type is not None:
            if a.icmp_code is None:
                icmp_code = b.icmp_code
            elif b.icmp_code is None:
                icmp_code = a.icmp_code
            elif a.icmp_code == b.icmp_code:
                icmp_code = a.icmp_code
            else:
                return None  # different codes — disjoint
        else:
            icmp_code = None

        return ServiceEntry(protocol=proto, icmp_type=icmp_type, icmp_code=icmp_code)

    # Other protocol numbers — intersection is the protocol itself
    return ServiceEntry(protocol=proto)
