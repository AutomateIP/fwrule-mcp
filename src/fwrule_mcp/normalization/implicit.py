"""
Vendor-specific implicit rule injection.

Every major firewall vendor enforces an implicit default action that is not
exported in configuration output.  This module synthesizes those implicit rules
so the analysis engine can account for them.

Rules are appended AFTER all explicit rules.  All synthesized rules have
``is_implicit=True`` and a descriptive ``rule_id``.

The ``_already_has_blanket_deny`` guard prevents double-injection when the
administrator has already configured an explicit catch-all deny.

Vendor coverage:
  ios, iosxr, asa, ftd  — implicit deny ip any any
  checkpoint            — implicit cleanup rule (deny all)
  juniper, junos        — implicit default deny
  sros                  — implicit default drop
  panos                 — implicit interzone deny (intrazone-allow NOT modeled in v1)
"""

from __future__ import annotations

import logging
from typing import Callable

from fwrule_mcp.models.common import (
    Action,
    AddressSet,
    ApplicationSet,
    BLOCKING_ACTIONS,
    ServiceSet,
    ZoneSet,
)
from fwrule_mcp.models.normalized import (
    MatchSpec,
    NormalizedRule,
    RuleMetadata,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_any_match(match: MatchSpec) -> bool:
    """Return True if a MatchSpec matches all traffic on all dimensions."""
    return (
        match.source_zones.is_any
        and match.destination_zones.is_any
        and match.source_addresses.is_any
        and match.destination_addresses.is_any
        and match.services.is_any
        and match.applications.is_any
    )


def _already_has_blanket_deny(rules: list[NormalizedRule]) -> bool:
    """
    Return True if the last enabled rule is already an all-traffic deny.

    Prevents double-injection when an admin has added an explicit
    ``deny ip any any`` (or equivalent).
    """
    for rule in reversed(rules):
        if not rule.enabled:
            continue
        if rule.action in BLOCKING_ACTIONS and _is_any_match(rule.match):
            return True
        # Stop at the first enabled rule from the end.
        break
    return False


def _make_implicit_deny(
    position: int,
    vendor: str,
    rule_id: str,
    description: str,
) -> NormalizedRule:
    """Build a synthetic deny-all NormalizedRule."""
    return NormalizedRule(
        rule_id=rule_id,
        position=position,
        enabled=True,
        is_implicit=True,
        match=MatchSpec(
            source_zones=ZoneSet.any(),
            destination_zones=ZoneSet.any(),
            source_addresses=AddressSet.any(),
            destination_addresses=AddressSet.any(),
            services=ServiceSet.any(),
            applications=ApplicationSet.any(),
        ),
        action=Action.DENY,
        metadata=RuleMetadata(
            original_name=rule_id,
            description=description,
            vendor_tags={"implicit_vendor": vendor},
        ),
    )


# ---------------------------------------------------------------------------
# Per-vendor factories
# ---------------------------------------------------------------------------


def _implicit_cisco(position: int, vendor: str) -> list[NormalizedRule]:
    """Cisco IOS/IOS-XE/IOS-XR/ASA/FTD — implicit deny ip any any."""
    return [_make_implicit_deny(
        position, vendor,
        rule_id="__implicit_deny_all__",
        description=f"Implicit deny ip any any ({vendor}). Every Cisco ACL ends with this rule.",
    )]


def _implicit_checkpoint(position: int, vendor: str) -> list[NormalizedRule]:
    """Check Point — implicit cleanup rule (deny all)."""
    return [_make_implicit_deny(
        position, vendor,
        rule_id="__implicit_cleanup_rule__",
        description="Implicit cleanup rule (Check Point). Denies all unmatched traffic.",
    )]


def _implicit_juniper(position: int, vendor: str) -> list[NormalizedRule]:
    """Juniper SRX/Junos — default deny."""
    return [_make_implicit_deny(
        position, vendor,
        rule_id="__implicit_default_deny__",
        description=f"Implicit default deny ({vendor}). All unmatched traffic is dropped.",
    )]


def _implicit_sros(position: int, vendor: str) -> list[NormalizedRule]:
    """Nokia SR OS — default drop for IP filter policies."""
    return [_make_implicit_deny(
        position, vendor,
        rule_id="__implicit_default_drop__",
        description="Implicit default drop (Nokia SR OS). Unmatched filter entries are dropped.",
    )]


def _implicit_panos(position: int, vendor: str) -> list[NormalizedRule]:
    """
    PAN-OS — implicit interzone deny.

    PAN-OS enforces two defaults:
      - Interzone-default: deny (traffic between different zones)
      - Intrazone-default: allow (traffic within the same zone)

    Only the interzone deny is modeled here.  The intrazone allow requires
    zone-equality semantics (source_zone == destination_zone) that the current
    ZoneSet model cannot express.  A warning is logged.
    """
    logger.info(
        "PAN-OS intrazone-allow default not modeled. "
        "Intrazone traffic is permitted by default unless explicitly denied."
    )
    return [_make_implicit_deny(
        position, vendor,
        rule_id="__implicit_interzone_deny__",
        description=(
            "Implicit interzone deny (PAN-OS). Traffic between different zones "
            "is denied by default. Note: intrazone-allow is NOT modeled."
        ),
    )]


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------


_IMPLICIT_FACTORIES: dict[str, Callable[[int, str], list[NormalizedRule]]] = {
    "ios": _implicit_cisco,
    "iosxr": _implicit_cisco,
    "asa": _implicit_cisco,
    "ftd": _implicit_cisco,
    "checkpoint": _implicit_checkpoint,
    "juniper": _implicit_juniper,
    "junos": _implicit_juniper,
    "sros": _implicit_sros,
    "panos": _implicit_panos,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def inject_implicit_rules(
    rules: list[NormalizedRule],
    vendor: str,
) -> list[NormalizedRule]:
    """
    Return rules with vendor-specific implicit rules appended, if applicable.

    Does NOT modify the input list.

    Rules are only injected when:
    1. The vendor has a known implicit default.
    2. The rule list is non-empty.
    3. The last enabled explicit rule is not already a blanket deny-all.
    """
    factory = _IMPLICIT_FACTORIES.get(vendor.lower())
    if factory is None:
        return rules

    if not rules:
        return rules

    if _already_has_blanket_deny(rules):
        logger.debug(
            "Skipping implicit rule injection for vendor %r — "
            "explicit blanket deny already terminates the policy.",
            vendor,
        )
        return rules

    last_pos = max(r.position for r in rules)
    implicit_rules = factory(last_pos + 1, vendor)
    return list(rules) + implicit_rules
