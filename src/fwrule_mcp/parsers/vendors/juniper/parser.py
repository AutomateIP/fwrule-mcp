"""
Juniper SRX security policy parser.

Supported input: ``set`` command format, as produced by:
  show configuration | display set
  show configuration security | display set

Set-format approach:
  1. Parse all ``set`` lines into a nested Python dict (the "config tree").
  2. Navigate the config tree for security policies, address books, and applications.

Config tree key paths of interest:
  security policies from-zone <zone> to-zone <zone> policy <name> match source-address <addr>
  security policies from-zone <zone> to-zone <zone> policy <name> match destination-address <addr>
  security policies from-zone <zone> to-zone <zone> policy <name> match application <app>
  security policies from-zone <zone> to-zone <zone> policy <name> then {permit|deny|reject}
  security policies from-zone <zone> to-zone <zone> policy <name> scheduler-name <name>

  security zones security-zone <zone> address-book address <name> <prefix>
  security zones security-zone <zone> address-book address-set <name> address <name>
  security zones security-zone <zone> address-book address-set <name> address-set <name>

  # Global address book (Junos 11.1+)
  security address-book global address <name> <prefix>
  security address-book global address-set <name> address <name>

  applications application <name> protocol <proto>
  applications application <name> destination-port <port>
  applications application <name> source-port <port>
  applications application <name> icmp-type <type>
  applications application <name> icmp-code <code>
  applications application-set <name> application <app>

Action mapping:
  permit  → permit
  deny    → deny
  reject  → reject

Policy ordering within a zone pair is preserved by parse order (line number).
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from typing import Any, Optional

from fwrule_mcp.parsers.base import (
    ObjectTable,
    ParsedPolicy,
    VendorParser,
    VendorRule,
)

logger = logging.getLogger(__name__)

JUNIPER_ACTION_MAP: dict[str, str] = {
    "permit": "permit",
    "deny": "deny",
    "reject": "reject",
}

# Well-known Juniper predefined application prefixes
JUNIPER_PREDEFINED_PREFIX = "junos-"


def _nested_set(d: dict, keys: list[str], value: Any) -> None:
    """
    Set d[keys[0]][keys[1]]...[keys[-1]] = value, creating intermediate dicts.

    For duplicate keys (e.g., multiple ``application`` entries under a policy),
    values are collected into lists using the special "__list__" convention.
    """
    node = d
    for key in keys[:-1]:
        if key not in node:
            node[key] = {}
        elif not isinstance(node[key], dict):
            # Collision with a scalar — wrap in a dict with a sentinel
            node[key] = {"__value__": node[key]}
        node = node[key]

    last_key = keys[-1]
    if last_key in node:
        existing = node[last_key]
        if isinstance(existing, list):
            existing.append(value)
        elif isinstance(existing, dict) and "__list__" in existing:
            existing["__list__"].append(value)
        else:
            # Convert to list
            node[last_key] = [existing, value]
    else:
        node[last_key] = value


def _get_nested(d: dict, *keys: str, default: Any = None) -> Any:
    """Navigate nested dict, returning default if any key is missing."""
    node = d
    for key in keys:
        if not isinstance(node, dict):
            return default
        node = node.get(key, default)
        if node is default:
            return default
    return node


def _as_list(value: Any) -> list:
    """Return value as a list, wrapping single items."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


class JuniperParser(VendorParser):
    """
    Parser for Juniper SRX security policies in set-command format.
    """

    VENDOR = "juniper"
    OS_FAMILIES: list[str] = []

    def supported_vendors(self) -> list[tuple[str, Optional[str]]]:
        return [("juniper", None), ("srx", None)]

    # ------------------------------------------------------------------
    # parse_policy
    # ------------------------------------------------------------------

    def parse_policy(
        self,
        raw_payload: str,
        context: Optional[dict[str, Any]] = None,
    ) -> ParsedPolicy:
        """
        Parse a Juniper SRX configuration in set-command format.
        """
        warnings: list[str] = []
        object_table = ObjectTable()
        rules: list[VendorRule] = []

        # Step 1: Build config tree from set lines
        config_tree: dict = {}
        policy_order: list[tuple[str, str, str]] = []  # (from_zone, to_zone, policy_name)

        lines = raw_payload.splitlines()
        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            self._process_set_line(
                stripped, config_tree, policy_order, warnings
            )

        # Step 2: Extract objects from config tree
        self._extract_address_objects(config_tree, object_table, warnings)
        self._extract_application_objects(config_tree, object_table, warnings)

        # Step 3: Extract rules in policy order
        security = config_tree.get("security", {})
        # Config tree structure: security.policies["from-zone"][fz]["to-zone"][tz]["policy"][name]
        policies = _get_nested(security, "policies") or {}

        position = 0
        seen_policies: set[tuple[str, str, str]] = set()

        # Walk policy_order list to preserve sequence
        for from_zone, to_zone, policy_name in policy_order:
            key = (from_zone, to_zone, policy_name)
            if key in seen_policies:
                continue
            seen_policies.add(key)

            # Navigate: policies["from-zone"][fz]["to-zone"][tz]["policy"][name]
            policy_data = _get_nested(
                policies,
                "from-zone", from_zone, "to-zone", to_zone, "policy", policy_name,
            )

            if policy_data is None:
                warnings.append(
                    f"Policy '{policy_name}' in {from_zone}→{to_zone} not found in config tree"
                )
                continue

            try:
                rule = self._build_rule(
                    policy_name,
                    from_zone,
                    to_zone,
                    policy_data,
                    position,
                    warnings,
                )
                rules.append(rule)
                position += 1
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"Skipping policy '{policy_name}': {exc}")

        # Also walk the config tree directly (catches policies not in order list)
        self._walk_policies_tree(
            policies, rules, seen_policies, position, warnings
        )

        return ParsedPolicy(
            rules=rules,
            object_table=object_table,
            vendor=self.VENDOR,
            os_version=self._detect_version(config_tree),
            warnings=warnings,
        )

    def parse_single_rule(
        self,
        raw_rule: str,
        object_table: Optional[ObjectTable] = None,
    ) -> VendorRule:
        """
        Parse a minimal set of ``set`` lines describing a single policy.

        The input should contain all ``set security policies from-zone ... policy ...``
        lines for one policy, plus any required address/application definitions.
        """
        warnings: list[str] = []
        config_tree: dict = {}
        policy_order: list[tuple[str, str, str]] = []

        for line in raw_rule.splitlines():
            stripped = line.strip()
            if stripped:
                self._process_set_line(stripped, config_tree, policy_order, warnings)

        local_obj_table = object_table or ObjectTable()
        self._extract_address_objects(config_tree, local_obj_table, warnings)
        self._extract_application_objects(config_tree, local_obj_table, warnings)

        if not policy_order:
            raise ValueError("No 'set security policies' lines found in candidate rule")

        from_zone, to_zone, policy_name = policy_order[0]
        security = config_tree.get("security", {})
        policies = _get_nested(security, "policies") or {}
        policy_data = _get_nested(
            policies,
            "from-zone", from_zone, "to-zone", to_zone, "policy", policy_name,
        )
        if policy_data is None:
            raise ValueError(f"Policy '{policy_name}' not found in parsed config tree")

        return self._build_rule(
            policy_name, from_zone, to_zone, policy_data, 0, warnings
        )

    # ------------------------------------------------------------------
    # Set-line parsing
    # ------------------------------------------------------------------

    def _process_set_line(
        self,
        line: str,
        config_tree: dict,
        policy_order: list,
        warnings: list[str],
    ) -> None:
        """
        Parse a single ``set`` line and insert it into the config tree.

        Also populates policy_order for sequence preservation.
        """
        # Normalize: strip leading "set " (or handle deactivate/delete lines)
        if line.lower().startswith("deactivate ") or line.lower().startswith("delete "):
            return  # Skip deactivate / delete lines
        if not line.lower().startswith("set "):
            return

        tokens = line[4:].split()  # Skip "set "
        if not tokens:
            return

        # Track policy ordering
        self._track_policy_order(tokens, policy_order)

        # Insert into config tree using all-but-last as path, last as value
        if len(tokens) == 1:
            _nested_set(config_tree, tokens, True)
        else:
            path = tokens[:-1]
            value = tokens[-1]
            _nested_set(config_tree, path, value)

    def _track_policy_order(
        self, tokens: list[str], policy_order: list[tuple[str, str, str]]
    ) -> None:
        """
        If this set line defines a security policy match/then field, record
        the (from_zone, to_zone, policy_name) tuple to preserve order.
        """
        # Expected: security policies from-zone <fz> to-zone <tz> policy <name> match|then ...
        if (
            len(tokens) >= 8
            and tokens[0] == "security"
            and tokens[1] == "policies"
            and tokens[2] == "from-zone"
            and tokens[4] == "to-zone"
            and tokens[6] == "policy"
            and tokens[8] in ("match", "then", "scheduler-name")
        ):
            from_zone = tokens[3]
            to_zone = tokens[5]
            policy_name = tokens[7]
            key = (from_zone, to_zone, policy_name)
            if key not in policy_order:
                policy_order.append(key)

    # ------------------------------------------------------------------
    # Object extraction
    # ------------------------------------------------------------------

    def _extract_address_objects(
        self,
        config_tree: dict,
        table: ObjectTable,
        warnings: list[str],
    ) -> None:
        """
        Extract address book entries from security zones and global address book.
        """
        security = config_tree.get("security", {})

        # Zone-based address books: security zones security-zone <zone> address-book
        zones = _get_nested(security, "zones", "security-zone") or {}
        if isinstance(zones, dict):
            for zone_name, zone_data in zones.items():
                if not isinstance(zone_data, dict):
                    continue
                addr_book = zone_data.get("address-book", {})
                if isinstance(addr_book, dict):
                    self._parse_address_book(addr_book, table, warnings, zone_prefix=zone_name)

        # Global address book: security address-book global
        global_book = _get_nested(security, "address-book", "global")
        if isinstance(global_book, dict):
            self._parse_address_book(global_book, table, warnings, zone_prefix=None)

        # Also handle: security address-book <bookname> (Junos 11.4+)
        all_address_books = security.get("address-book", {})
        if isinstance(all_address_books, dict):
            for book_name, book_data in all_address_books.items():
                if isinstance(book_data, dict) and book_name != "global":
                    self._parse_address_book(book_data, table, warnings, zone_prefix=None)

    def _parse_address_book(
        self,
        addr_book: dict,
        table: ObjectTable,
        warnings: list[str],
        zone_prefix: Optional[str],
    ) -> None:
        """Parse an address-book dict into table entries."""
        # Individual addresses
        addresses = addr_book.get("address", {})
        if isinstance(addresses, dict):
            for addr_name, addr_value in addresses.items():
                if isinstance(addr_value, str):
                    # Value is a prefix like "10.0.0.0/24" or "10.0.0.1/32"
                    table.address_objects[addr_name] = [addr_value]
                elif isinstance(addr_value, dict):
                    # May have a nested value
                    val = addr_value.get("__value__", "")
                    if val:
                        table.address_objects[addr_name] = [val]

        # Address sets (groups)
        address_sets = addr_book.get("address-set", {})
        if isinstance(address_sets, dict):
            for set_name, set_data in address_sets.items():
                members: list[str] = []
                if isinstance(set_data, dict):
                    # address members
                    addr_members = set_data.get("address", {})
                    if isinstance(addr_members, str):
                        members.append(addr_members)
                    elif isinstance(addr_members, list):
                        members.extend(addr_members)
                    elif isinstance(addr_members, dict):
                        members.extend(addr_members.keys())
                    # address-set members (nested sets)
                    set_members = set_data.get("address-set", {})
                    if isinstance(set_members, str):
                        members.append(set_members)
                    elif isinstance(set_members, list):
                        members.extend(set_members)
                    elif isinstance(set_members, dict):
                        members.extend(set_members.keys())
                elif isinstance(set_data, list):
                    members.extend(str(m) for m in set_data)
                table.address_groups[set_name] = members

    def _extract_application_objects(
        self,
        config_tree: dict,
        table: ObjectTable,
        warnings: list[str],
    ) -> None:
        """
        Extract application and application-set definitions.
        """
        applications = config_tree.get("applications", {})
        if not isinstance(applications, dict):
            return

        # Custom applications
        app_defs = applications.get("application", {})
        if isinstance(app_defs, dict):
            for app_name, app_data in app_defs.items():
                if not isinstance(app_data, dict):
                    continue
                svc_info = self._parse_app_data(app_data)
                if svc_info:
                    table.service_objects[app_name] = svc_info
                table.application_objects[app_name] = app_name

        # Application sets
        app_sets = applications.get("application-set", {})
        if isinstance(app_sets, dict):
            for set_name, set_data in app_sets.items():
                if not isinstance(set_data, dict):
                    continue
                members: list[str] = []
                app_members = set_data.get("application", {})
                if isinstance(app_members, str):
                    members.append(app_members)
                elif isinstance(app_members, list):
                    members.extend(str(m) for m in app_members)
                elif isinstance(app_members, dict):
                    members.extend(app_members.keys())
                table.service_groups[set_name] = members

    def _parse_app_data(self, app_data: dict) -> dict[str, str]:
        """Build a service_objects entry from an application definition dict."""
        svc_info: dict[str, str] = {}
        proto = app_data.get("protocol", "")
        if isinstance(proto, str) and proto:
            svc_info["protocol"] = proto.lower()
        dst_port = app_data.get("destination-port", "")
        if isinstance(dst_port, str) and dst_port:
            # Normalize port range: "80-443" or "80" or "any"
            svc_info["ports"] = dst_port
        src_port = app_data.get("source-port", "")
        if isinstance(src_port, str) and src_port:
            svc_info["src_ports"] = src_port
        icmp_type = app_data.get("icmp-type", "")
        if isinstance(icmp_type, str) and icmp_type:
            svc_info["icmp_type"] = icmp_type
        icmp_code = app_data.get("icmp-code", "")
        if isinstance(icmp_code, str) and icmp_code:
            svc_info["icmp_code"] = icmp_code
        return svc_info

    # ------------------------------------------------------------------
    # Rule building
    # ------------------------------------------------------------------

    def _walk_policies_tree(
        self,
        policies: dict,
        rules: list[VendorRule],
        seen: set,
        position: int,
        warnings: list[str],
    ) -> None:
        """
        Walk the entire policies subtree to catch any zone pairs not covered
        by the policy_order list.

        Actual tree layout (each token is a separate nested key):
          policies["from-zone"][<fz>]["to-zone"][<tz>]["policy"][<name>] = {...}
        """
        # Navigate: policies["from-zone"] -> {fz -> {"to-zone" -> {tz -> {"policy" -> {name -> data}}}}}
        from_zone_root = policies.get("from-zone", {})
        if not isinstance(from_zone_root, dict):
            return

        for from_zone, from_zone_data in from_zone_root.items():
            if not isinstance(from_zone_data, dict):
                continue
            to_zone_root = from_zone_data.get("to-zone", {})
            if not isinstance(to_zone_root, dict):
                continue
            for to_zone, to_zone_data in to_zone_root.items():
                if not isinstance(to_zone_data, dict):
                    continue
                policy_section = to_zone_data.get("policy", {})
                if not isinstance(policy_section, dict):
                    continue
                for policy_name, policy_data in policy_section.items():
                    key = (from_zone, to_zone, policy_name)
                    if key in seen:
                        continue
                    seen.add(key)
                    if not isinstance(policy_data, dict):
                        continue
                    try:
                        rule = self._build_rule(
                            policy_name, from_zone, to_zone, policy_data, position, warnings
                        )
                        rules.append(rule)
                        position += 1
                    except Exception as exc:  # noqa: BLE001
                        warnings.append(f"Skipping policy '{policy_name}': {exc}")

    def _build_rule(
        self,
        policy_name: str,
        from_zone: str,
        to_zone: str,
        policy_data: dict,
        position: int,
        warnings: list[str],
    ) -> VendorRule:
        """Build a VendorRule from a parsed policy data dict."""
        match_data = policy_data.get("match", {}) if isinstance(policy_data, dict) else {}
        then_data = policy_data.get("then", {}) if isinstance(policy_data, dict) else {}

        # Source addresses
        src_raw = match_data.get("source-address", [])
        src_addrs = _as_list(src_raw)
        if not src_addrs or src_addrs == ["any"]:
            src_addrs = ["any"]

        # Destination addresses
        dst_raw = match_data.get("destination-address", [])
        dst_addrs = _as_list(dst_raw)
        if not dst_addrs or dst_addrs == ["any"]:
            dst_addrs = ["any"]

        # Applications
        app_raw = match_data.get("application", [])
        app_list = _as_list(app_raw)
        if not app_list or app_list == ["any"]:
            app_list = ["any"]
            services = ["any"]
        else:
            # Applications in Juniper serve as both service and app identifiers
            services = app_list

        # Action
        action = "deny"  # safe default
        if isinstance(then_data, dict):
            for act_key in ("permit", "deny", "reject"):
                if act_key in then_data:
                    action = JUNIPER_ACTION_MAP.get(act_key, act_key)
                    break
        elif isinstance(then_data, str):
            action = JUNIPER_ACTION_MAP.get(then_data.lower(), then_data.lower())

        # Enabled — check if policy is deactivated
        # In set format, deactivated policies appear with "deactivate" lines (we skip those)
        enabled = True
        if isinstance(policy_data, dict) and policy_data.get("inactive") == "inactive":
            enabled = False

        # Description
        description = ""
        if isinstance(policy_data, dict):
            description = policy_data.get("description", "")

        # Vendor tags
        vendor_tags: dict[str, Any] = {
            "from_zone": from_zone,
            "to_zone": to_zone,
        }
        if isinstance(then_data, dict):
            if "count" in then_data:
                vendor_tags["count"] = then_data["count"]
            if "log" in then_data:
                vendor_tags["log"] = then_data["log"]
            if "syslog" in then_data:
                vendor_tags["syslog"] = then_data["syslog"]
            permit_data = then_data.get("permit", {})
            if isinstance(permit_data, dict) and "tunnel" in permit_data:
                vendor_tags["tunnel"] = permit_data["tunnel"]

        return VendorRule(
            name=policy_name,
            position=position,
            enabled=enabled,
            source_zones=[from_zone],
            destination_zones=[to_zone],
            source_addresses=src_addrs,
            destination_addresses=dst_addrs,
            services=services,
            applications=app_list,
            action=action,
            description=description,
            vendor_tags=vendor_tags,
        )

    # ------------------------------------------------------------------
    # Version detection
    # ------------------------------------------------------------------

    def _detect_version(self, config_tree: dict) -> Optional[str]:
        """
        Extract Junos version from configuration comments or version statements.
        """
        version = _get_nested(config_tree, "version")
        if isinstance(version, str):
            return version
        return None


class JuniperSRXAlias(JuniperParser):
    """
    Thin alias for JuniperParser registered under the "srx" vendor ID.

    Allows callers to use either ``get_parser("juniper")`` or
    ``get_parser("srx")`` interchangeably.
    """

    VENDOR = "srx"
    OS_FAMILIES: list[str] = []

    def supported_vendors(self) -> list[tuple[str, Optional[str]]]:
        return [("srx", None)]
