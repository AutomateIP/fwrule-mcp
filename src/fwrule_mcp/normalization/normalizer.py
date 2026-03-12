"""
PolicyNormalizer — converts vendor-parsed rules into NormalizedRule objects.

This is the top-level entry point for the normalization layer.  It orchestrates:
  1. ObjectResolver construction from the parsed policy's ObjectTable
  2. Per-rule normalization: address resolution, service resolution, action
     mapping, zone mapping, and metadata assembly
  3. Candidate rule normalization (same pipeline, different output type)

Design notes:
- normalize_policy() is the primary entry point; normalize_rule() and
  normalize_candidate() are exposed for use in tests and one-off conversions.
- All resolution warnings are collected per-rule and stored in
  RuleMetadata.unresolvable_references so the analysis engine can treat
  dimensions conservatively when data is missing.
- Negated address fields (negate_source / negate_destination) are propagated
  into RuleMetadata.vendor_tags rather than being resolved here; overlap
  analysis must account for them separately.
- Disabled rules are normalized (not skipped) so that position indices remain
  stable in the output list, matching VendorRule.position semantics.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from fwrule_mcp.models.common import (
    Action,
    AddressEntry,
    AddressSet,
    AddressType,
    ApplicationSet,
    PortRange,
    ServiceEntry,
    ServiceSet,
    ZoneSet,
)
from fwrule_mcp.models.normalized import (
    MatchSpec,
    NormalizedCandidate,
    NormalizedRule,
    RuleMetadata,
)
from fwrule_mcp.normalization.mappers import (
    map_action,
    parse_address_literal,
    parse_service_literal,
)
from fwrule_mcp.normalization.resolver import (
    ObjectResolver,
    ResolutionWarning,
)
from fwrule_mcp.parsers.base import ObjectTable, ParsedPolicy, VendorRule

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------


@dataclass
class NormalizationResult:
    """
    Complete result of normalizing a ParsedPolicy.

    Attributes:
        rules:     Ordered list of NormalizedRule objects (one per VendorRule).
        candidate: A NormalizedCandidate if normalize_candidate() was called,
                   or None when only the policy was normalized.
        warnings:  All ResolutionWarnings emitted across all rules.  Use
                   rule.metadata.unresolvable_references to inspect per-rule
                   issues.
    """

    rules: list[NormalizedRule] = field(default_factory=list)
    candidate: Optional[NormalizedCandidate] = None
    warnings: list[ResolutionWarning] = field(default_factory=list)


# ---------------------------------------------------------------------------
# PolicyNormalizer
# ---------------------------------------------------------------------------


class PolicyNormalizer:
    """
    Converts vendor-parsed rules (VendorRule) into normalized form (NormalizedRule).

    Instances are stateless between calls — create one instance and reuse it
    across many normalize_policy() calls.
    """

    def normalize_policy(self, parsed_policy: ParsedPolicy) -> list[NormalizedRule]:
        """
        Normalize all rules in a parsed policy.

        Steps:
        1. Build an ObjectResolver from parsed_policy.object_table.
        2. For each VendorRule (in order), call normalize_rule().
        3. Return the ordered list of NormalizedRule objects.

        Args:
            parsed_policy: Output of a VendorParser.parse_policy() call.

        Returns:
            List of NormalizedRule, one per VendorRule, in policy order.
        """
        resolver = ObjectResolver(parsed_policy.object_table)
        normalized_rules: list[NormalizedRule] = []

        for vendor_rule in parsed_policy.rules:
            try:
                norm_rule = self.normalize_rule(vendor_rule, resolver)
                normalized_rules.append(norm_rule)
            except Exception as exc:
                # Non-fatal — log and continue so one bad rule doesn't abort
                # the entire policy normalization.
                logger.error(
                    "Unexpected error normalizing rule %r (position %d): %s",
                    vendor_rule.name,
                    vendor_rule.position,
                    exc,
                    exc_info=True,
                )

        return normalized_rules

    def normalize_rule(
        self,
        vendor_rule: VendorRule,
        resolver: ObjectResolver,
    ) -> NormalizedRule:
        """
        Normalize a single VendorRule into a NormalizedRule.

        Steps:
        1. Clear resolver warnings for this rule.
        2. Resolve source addresses → AddressSet.
        3. Resolve destination addresses → AddressSet.
        4. Resolve services → ServiceSet.
        5. Map zones → ZoneSet (source and destination).
        6. Map applications → ApplicationSet.
        7. Map action string → Action enum.
        8. Assemble MatchSpec.
        9. Assemble RuleMetadata with warnings and vendor tags.
        10. Return NormalizedRule.

        The rule's 1-based position is derived from VendorRule.position + 1
        (VendorRule uses 0-based indexing per the parser contract).
        """
        resolver.clear_warnings()

        # --- Address resolution ---
        src_addresses = self._resolve_addresses(vendor_rule.source_addresses, resolver)
        dst_addresses = self._resolve_addresses(vendor_rule.destination_addresses, resolver)

        # --- Service resolution ---
        services = self._resolve_services(vendor_rule.services, resolver)

        # --- Zone mapping ---
        source_zones = self._resolve_zones(vendor_rule.source_zones, resolver)
        destination_zones = self._resolve_zones(vendor_rule.destination_zones, resolver)

        # --- Application mapping ---
        applications = self._resolve_applications(vendor_rule.applications)

        # --- Action mapping ---
        action = map_action(vendor_rule.action)

        # --- Assemble MatchSpec ---
        match = MatchSpec(
            source_zones=source_zones,
            destination_zones=destination_zones,
            source_addresses=src_addresses,
            destination_addresses=dst_addresses,
            services=services,
            applications=applications,
        )

        # --- Collect warnings and unresolvable references ---
        rule_warnings = resolver.get_warnings()
        unresolvable = [
            w.object_name
            for w in rule_warnings
            if w.warning_type == "unresolvable"
        ]

        # --- Assemble vendor_tags (preserve negate flags, description, raw tags) ---
        vendor_tags = dict(vendor_rule.vendor_tags)
        if vendor_rule.negate_source:
            vendor_tags["negate_source"] = True
        if vendor_rule.negate_destination:
            vendor_tags["negate_destination"] = True

        # --- RuleMetadata ---
        rule_id = vendor_rule.name or f"rule_{vendor_rule.position + 1}"
        metadata = RuleMetadata(
            original_name=vendor_rule.name,
            description=vendor_rule.description or "",
            vendor_tags=vendor_tags,
            parsed_from=None,   # populated by caller if needed
            unresolvable_references=unresolvable,
        )

        # VendorRule.position is 0-based; NormalizedRule.position is 1-based.
        return NormalizedRule(
            rule_id=rule_id,
            position=vendor_rule.position + 1,
            enabled=vendor_rule.enabled,
            match=match,
            action=action,
            metadata=metadata,
        )

    def normalize_candidate(
        self,
        vendor_rule: VendorRule,
        resolver: ObjectResolver,
        intended_position: Optional[int] = None,
    ) -> NormalizedCandidate:
        """
        Normalize a candidate VendorRule into a NormalizedCandidate.

        The candidate pipeline is identical to normalize_rule() except that:
        - The output type is NormalizedCandidate (not NormalizedRule).
        - ``intended_position`` is forwarded to the candidate (1-based;
          governs which existing rules are "above" it for shadow analysis).

        Args:
            vendor_rule:        The parsed candidate rule.
            resolver:           ObjectResolver built from the policy object table,
                                so the candidate can reference the same objects.
            intended_position:  1-based insert position hint, or None (= end).
        """
        resolver.clear_warnings()

        src_addresses = self._resolve_addresses(vendor_rule.source_addresses, resolver)
        dst_addresses = self._resolve_addresses(vendor_rule.destination_addresses, resolver)
        services = self._resolve_services(vendor_rule.services, resolver)
        source_zones = self._resolve_zones(vendor_rule.source_zones, resolver)
        destination_zones = self._resolve_zones(vendor_rule.destination_zones, resolver)
        applications = self._resolve_applications(vendor_rule.applications)
        action = map_action(vendor_rule.action)

        match = MatchSpec(
            source_zones=source_zones,
            destination_zones=destination_zones,
            source_addresses=src_addresses,
            destination_addresses=dst_addresses,
            services=services,
            applications=applications,
        )

        rule_warnings = resolver.get_warnings()
        unresolvable = [w.object_name for w in rule_warnings if w.warning_type == "unresolvable"]

        vendor_tags = dict(vendor_rule.vendor_tags)
        if vendor_rule.negate_source:
            vendor_tags["negate_source"] = True
        if vendor_rule.negate_destination:
            vendor_tags["negate_destination"] = True

        metadata = RuleMetadata(
            original_name=vendor_rule.name,
            description=vendor_rule.description or "",
            vendor_tags=vendor_tags,
            unresolvable_references=unresolvable,
        )

        rule_id = vendor_rule.name or "candidate"

        return NormalizedCandidate(
            rule_id=rule_id,
            intended_position=intended_position,
            enabled=vendor_rule.enabled,
            match=match,
            action=action,
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Private resolution helpers
    # ------------------------------------------------------------------

    def _resolve_addresses(
        self,
        references: list[str],
        resolver: ObjectResolver,
    ) -> AddressSet:
        """
        Resolve a list of raw address references to an AddressSet.

        Each reference is first passed through the resolver (which handles
        object table lookups and group expansion) to get raw value strings,
        then each value string is parsed into an AddressEntry via
        parse_address_literal().

        If all references resolve to "any" (or the list is empty due to
        missing objects), returns AddressSet.any().
        """
        if not references:
            return AddressSet.any()

        all_entries: list[AddressEntry] = []
        has_any = False

        for ref in references:
            raw_values = resolver.resolve_address(ref)
            for raw in raw_values:
                if raw.lower() in ("any", "any4", "any6", "0.0.0.0/0", "::/0"):
                    has_any = True
                    break
                entry = parse_address_literal(raw)
                if entry is not None:
                    if entry.addr_type == AddressType.ANY:
                        has_any = True
                        break
                    all_entries.append(entry)
            if has_any:
                break

        if has_any:
            return AddressSet.any()

        if not all_entries:
            # All references were unresolvable — conservative fallback.
            return AddressSet.any()

        return AddressSet(entries=all_entries)

    def _resolve_services(
        self,
        references: list[str],
        resolver: ObjectResolver,
    ) -> ServiceSet:
        """
        Resolve a list of raw service references to a ServiceSet.

        Each reference is expanded through the resolver into service descriptor
        dicts, then each dict is converted into a ServiceEntry.

        If any reference expands to "any", returns ServiceSet.any().
        """
        if not references:
            return ServiceSet.any()

        all_entries: list[ServiceEntry] = []
        has_any = False

        for ref in references:
            svc_dicts = resolver.resolve_service(ref)
            for svc in svc_dicts:
                protocol = svc.get("protocol", "any").lower()
                if protocol == "any":
                    has_any = True
                    break
                entry = _service_dict_to_entry(svc)
                if entry is not None:
                    all_entries.append(entry)
            if has_any:
                break

        if has_any:
            return ServiceSet.any()

        if not all_entries:
            # All references were unresolvable — conservative fallback.
            return ServiceSet.any()

        return ServiceSet(entries=all_entries)

    def _resolve_zones(
        self,
        zone_refs: list[str],
        resolver: ObjectResolver,
    ) -> ZoneSet:
        """
        Map a list of raw zone/interface names to a ZoneSet.

        If the list is empty or contains "any", returns ZoneSet.any().
        Zone names are kept as-is (they are opaque identifiers in the
        ObjectTable model — no lookup table transformation is needed).
        The analysis engine compares them by string identity.
        """
        if not zone_refs:
            return ZoneSet.any()

        canonical_zones: set[str] = set()
        for raw_zone in zone_refs:
            if raw_zone.lower() in ("any", "all", "*"):
                return ZoneSet.any()
            canonical_zones.add(raw_zone)

        return ZoneSet(zones=canonical_zones, is_any=False)

    def _resolve_applications(self, app_refs: list[str]) -> ApplicationSet:
        """
        Map a list of raw application identifiers to an ApplicationSet.

        Application names are kept opaque (no resolution needed) since the
        analysis engine compares them by identity.  "any" or empty list →
        ApplicationSet.any().
        """
        if not app_refs:
            return ApplicationSet.any()

        apps: set[str] = set()
        for ref in app_refs:
            if ref.lower() in ("any", "all"):
                return ApplicationSet.any()
            apps.add(ref)

        if not apps:
            return ApplicationSet.any()

        return ApplicationSet(applications=apps, is_any=False)


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _service_dict_to_entry(svc: dict) -> Optional[ServiceEntry]:
    """
    Convert a service descriptor dict (from the resolver) into a ServiceEntry.

    The dict is expected to have at minimum a "protocol" key.  Optional keys:
    "ports" (port spec string or None), "icmp_type", "icmp_code".

    Returns None if the dict cannot be converted into a valid ServiceEntry.
    """
    protocol = svc.get("protocol", "").lower().strip()
    if not protocol:
        return None

    if protocol == "any":
        return ServiceEntry(protocol="any")

    # --- ICMP / ICMPv6 ---
    if protocol in ("icmp", "icmpv6", "icmp6"):
        proto_name = "icmpv6" if protocol in ("icmpv6", "icmp6") else "icmp"
        icmp_type: Optional[int] = None
        icmp_code: Optional[int] = None
        if "icmp_type" in svc:
            try:
                icmp_type = int(svc["icmp_type"])
            except (ValueError, TypeError):
                pass
        if "icmp_code" in svc:
            try:
                icmp_code = int(svc["icmp_code"])
            except (ValueError, TypeError):
                pass
        return ServiceEntry(protocol=proto_name, icmp_type=icmp_type, icmp_code=icmp_code)

    # --- TCP / UDP / SCTP ---
    if protocol in ("tcp", "udp", "sctp"):
        port_spec = svc.get("ports")
        if port_spec is None or str(port_spec).lower() in ("any", ""):
            return ServiceEntry(protocol=protocol, ports=None)
        # Parse the port spec string into PortRange objects
        port_ranges = _parse_port_spec(str(port_spec))
        if port_ranges is None:
            # Try treating the whole thing as a service literal
            entry = parse_service_literal(f"{protocol}/{port_spec}")
            return entry
        return ServiceEntry(protocol=protocol, ports=tuple(port_ranges) if port_ranges else None)

    # --- Raw IP protocol number or other protocol string ---
    # No port semantics — just wrap the protocol identifier.
    return ServiceEntry(protocol=protocol)


def _parse_port_spec(spec: str) -> Optional[list[PortRange]]:
    """
    Parse a port specification string into a list of PortRange objects.

    Supports:
    - Single port: "80"
    - Range: "8080-8090"
    - Comma-separated: "80,443,8080-8090"

    Returns None if the spec cannot be parsed at all, or an empty list
    if the spec is "any" / empty.
    """
    if not spec or spec.lower() == "any":
        return []  # Caller should treat [] as "any port"

    ranges: list[PortRange] = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            sub = part.split("-", 1)
            try:
                start = int(sub[0].strip())
                end = int(sub[1].strip())
                ranges.append(PortRange(start, end))
            except (ValueError, IndexError):
                logger.debug("Could not parse port range %r", part)
                return None
        else:
            try:
                port = int(part)
                ranges.append(PortRange(port, port))
            except ValueError:
                logger.debug("Could not parse port value %r", part)
                return None

    return ranges
