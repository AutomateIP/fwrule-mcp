"""
Normalized input schema — JSON-friendly Pydantic models for the normalized input path.

These models validate JSON input from callers who have already normalized their
firewall rules (e.g., an AI agent that extracted structured data from device output).

Conversion functions translate validated input into the internal NormalizedRule /
NormalizedCandidate types consumed by the analysis engine.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Optional

from pydantic import BaseModel, Field, field_validator

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

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Action mapping
# ---------------------------------------------------------------------------

_ACTION_MAP: dict[str, Action] = {
    "permit": Action.PERMIT,
    "allow": Action.PERMIT,
    "accept": Action.PERMIT,
    "deny": Action.DENY,
    "drop": Action.DROP,
    "reject": Action.REJECT,
    "log": Action.LOG_ONLY,
}


# ---------------------------------------------------------------------------
# Service input model
# ---------------------------------------------------------------------------


class ServiceInput(BaseModel):
    """A single service entry in the normalized input schema."""

    protocol: str = Field(
        description="Protocol: 'tcp', 'udp', 'icmp', 'sctp', or IP protocol number.",
    )
    ports: Optional[str] = Field(
        default=None,
        description=(
            "Port specification. Single port: '443'. Range: '8080-8090'. "
            "Comma-separated: '80,443'. Omit or null for protocol-only match (e.g., ICMP)."
        ),
    )

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# Rule input model
# ---------------------------------------------------------------------------


class RuleInput(BaseModel):
    """
    A single firewall rule in the normalized input schema.

    This is the JSON schema that callers produce when they have already extracted
    and resolved firewall rules from vendor-native format.

    Address values:
      - "any" — matches all addresses
      - CIDR notation: "10.0.0.0/24", "192.168.1.1/32", "2001:db8::/32"
      - IP range: "10.0.0.1-10.0.0.100"

    Service values:
      - {"protocol": "tcp", "ports": "443"} — TCP port 443
      - {"protocol": "tcp", "ports": "8080-8090"} — TCP port range
      - {"protocol": "icmp"} — ICMP with no port
      - Omit services or use empty list for "any service"

    Zone values:
      - "any" — matches all zones
      - Zone name strings: "trust", "untrust", "dmz"
      - Omit or use empty list for "any zone"
    """

    id: str = Field(description="Rule identifier (name or generated ID).")
    position: int = Field(ge=1, description="1-based position in the policy.")
    enabled: bool = Field(default=True, description="Whether the rule is active.")
    action: str = Field(description="Rule action: 'permit', 'deny', 'drop', 'reject'.")
    source_zones: list[str] = Field(
        default_factory=lambda: ["any"],
        description="Source security zones. Use ['any'] or omit for unrestricted.",
    )
    destination_zones: list[str] = Field(
        default_factory=lambda: ["any"],
        description="Destination security zones.",
    )
    source_addresses: list[str] = Field(
        default_factory=lambda: ["any"],
        description="Source addresses in CIDR notation. Use ['any'] for unrestricted.",
    )
    destination_addresses: list[str] = Field(
        default_factory=lambda: ["any"],
        description="Destination addresses in CIDR notation.",
    )
    services: list[ServiceInput] = Field(
        default_factory=list,
        description="Service match criteria. Empty list means 'any service'.",
    )
    applications: list[str] = Field(
        default_factory=lambda: ["any"],
        description="Application identifiers. Use ['any'] for unrestricted.",
    )

    model_config = {"extra": "forbid"}

    @field_validator("action")
    @classmethod
    def validate_action(cls, v: str) -> str:
        v_lower = v.strip().lower()
        if v_lower not in _ACTION_MAP:
            raise ValueError(
                f"Unsupported action '{v}'. Must be one of: "
                f"{', '.join(sorted(_ACTION_MAP.keys()))}"
            )
        return v_lower


# ---------------------------------------------------------------------------
# Conversion: RuleInput → NormalizedRule / NormalizedCandidate
# ---------------------------------------------------------------------------


def _parse_addresses(refs: list[str]) -> AddressSet:
    """Convert a list of address strings to an AddressSet."""
    if not refs:
        return AddressSet.any()

    entries: list[AddressEntry] = []
    for ref in refs:
        ref_stripped = ref.strip()
        if ref_stripped.lower() in ("any", "any4", "any6", "0.0.0.0/0", "::/0"):
            return AddressSet.any()
        # Try CIDR
        try:
            entries.append(AddressEntry.from_cidr(ref_stripped))
            continue
        except (ValueError, TypeError):
            pass
        # Try IP range (start-end)
        if "-" in ref_stripped:
            parts = ref_stripped.split("-", 1)
            try:
                entries.append(AddressEntry.from_range(parts[0].strip(), parts[1].strip()))
                continue
            except (ValueError, TypeError):
                pass
        # Try single host IP
        try:
            ipaddress.ip_address(ref_stripped)
            entries.append(AddressEntry.from_cidr(f"{ref_stripped}/32"))
            continue
        except (ValueError, TypeError):
            pass
        # FQDN fallback
        entries.append(AddressEntry.from_fqdn(ref_stripped))

    if not entries:
        return AddressSet.any()
    return AddressSet(entries=entries)


def _parse_zones(refs: list[str]) -> ZoneSet:
    """Convert a list of zone strings to a ZoneSet."""
    if not refs:
        return ZoneSet.any()
    zones: set[str] = set()
    for ref in refs:
        if ref.strip().lower() in ("any", "all", "*"):
            return ZoneSet.any()
        zones.add(ref.strip())
    return ZoneSet(zones=zones, is_any=False) if zones else ZoneSet.any()


def _parse_applications(refs: list[str]) -> ApplicationSet:
    """Convert a list of application strings to an ApplicationSet."""
    if not refs:
        return ApplicationSet.any()
    apps: set[str] = set()
    for ref in refs:
        if ref.strip().lower() in ("any", "all"):
            return ApplicationSet.any()
        apps.add(ref.strip())
    return ApplicationSet(applications=apps, is_any=False) if apps else ApplicationSet.any()


def _parse_services(svc_inputs: list[ServiceInput]) -> ServiceSet:
    """Convert a list of ServiceInput to a ServiceSet."""
    if not svc_inputs:
        return ServiceSet.any()

    entries: list[ServiceEntry] = []
    for svc in svc_inputs:
        protocol = svc.protocol.strip().lower()
        if protocol == "any":
            return ServiceSet.any()

        if protocol in ("icmp", "icmpv6"):
            entries.append(ServiceEntry(protocol=protocol))
            continue

        if svc.ports is None or svc.ports.strip().lower() in ("", "any"):
            entries.append(ServiceEntry(protocol=protocol, ports=None))
            continue

        # Parse port spec
        port_ranges: list[PortRange] = []
        for part in svc.ports.split(","):
            part = part.strip()
            if "-" in part:
                sub = part.split("-", 1)
                try:
                    port_ranges.append(PortRange(int(sub[0].strip()), int(sub[1].strip())))
                except (ValueError, IndexError):
                    logger.warning("Could not parse port range %r", part)
                    continue
            else:
                try:
                    port = int(part)
                    port_ranges.append(PortRange(port, port))
                except ValueError:
                    logger.warning("Could not parse port value %r", part)
                    continue

        entries.append(
            ServiceEntry(
                protocol=protocol,
                ports=tuple(port_ranges) if port_ranges else None,
            )
        )

    if not entries:
        return ServiceSet.any()
    return ServiceSet(entries=entries)


def rule_input_to_normalized(rule: RuleInput) -> NormalizedRule:
    """Convert a validated RuleInput to a NormalizedRule."""
    action = _ACTION_MAP[rule.action]

    match = MatchSpec(
        source_zones=_parse_zones(rule.source_zones),
        destination_zones=_parse_zones(rule.destination_zones),
        source_addresses=_parse_addresses(rule.source_addresses),
        destination_addresses=_parse_addresses(rule.destination_addresses),
        services=_parse_services(rule.services),
        applications=_parse_applications(rule.applications),
    )

    return NormalizedRule(
        rule_id=rule.id,
        position=rule.position,
        enabled=rule.enabled,
        match=match,
        action=action,
        metadata=RuleMetadata(original_name=rule.id),
    )


def rule_input_to_candidate(
    rule: RuleInput,
    intended_position: Optional[int] = None,
) -> NormalizedCandidate:
    """Convert a validated RuleInput to a NormalizedCandidate."""
    action = _ACTION_MAP[rule.action]

    match = MatchSpec(
        source_zones=_parse_zones(rule.source_zones),
        destination_zones=_parse_zones(rule.destination_zones),
        source_addresses=_parse_addresses(rule.source_addresses),
        destination_addresses=_parse_addresses(rule.destination_addresses),
        services=_parse_services(rule.services),
        applications=_parse_applications(rule.applications),
    )

    return NormalizedCandidate(
        rule_id=rule.id,
        intended_position=intended_position,
        enabled=rule.enabled,
        match=match,
        action=action,
        metadata=RuleMetadata(original_name=rule.id),
    )


# ---------------------------------------------------------------------------
# Serialization: NormalizedRule → RuleInput-compatible dict
# ---------------------------------------------------------------------------


def normalized_rule_to_dict(rule: NormalizedRule) -> dict:
    """
    Serialize a NormalizedRule back to the normalized JSON schema.

    Used by the parse_policy tool to return parsed results in the standard schema.
    """
    # Addresses
    def _addr_set_to_list(addr_set: AddressSet) -> list[str]:
        if addr_set.is_any:
            return ["any"]
        result: list[str] = []
        for entry in addr_set.entries:
            if entry.addr_type == AddressType.ANY:
                return ["any"]
            elif entry.cidr is not None:
                result.append(str(entry.cidr))
            elif entry.range_start is not None and entry.range_end is not None:
                start = str(ipaddress.ip_address(entry.range_start))
                end = str(ipaddress.ip_address(entry.range_end))
                result.append(f"{start}-{end}")
            elif entry.fqdn:
                result.append(entry.fqdn)
        return result or ["any"]

    # Zones
    def _zone_set_to_list(zone_set: ZoneSet) -> list[str]:
        if zone_set.is_any:
            return ["any"]
        return sorted(zone_set.zones)

    # Applications
    def _app_set_to_list(app_set: ApplicationSet) -> list[str]:
        if app_set.is_any:
            return ["any"]
        return sorted(app_set.applications)

    # Services
    def _service_set_to_list(svc_set: ServiceSet) -> list[dict]:
        if svc_set.is_any:
            return []
        result: list[dict] = []
        for entry in svc_set.entries:
            svc: dict = {"protocol": entry.protocol}
            if entry.ports:
                port_parts: list[str] = []
                for pr in entry.ports:
                    if pr.start == pr.end:
                        port_parts.append(str(pr.start))
                    else:
                        port_parts.append(f"{pr.start}-{pr.end}")
                svc["ports"] = ",".join(port_parts)
            result.append(svc)
        return result

    m = rule.match
    return {
        "id": rule.rule_id,
        "position": rule.position,
        "enabled": rule.enabled,
        "action": rule.action.value,
        "source_zones": _zone_set_to_list(m.source_zones),
        "destination_zones": _zone_set_to_list(m.destination_zones),
        "source_addresses": _addr_set_to_list(m.source_addresses),
        "destination_addresses": _addr_set_to_list(m.destination_addresses),
        "services": _service_set_to_list(m.services),
        "applications": _app_set_to_list(m.applications),
    }
