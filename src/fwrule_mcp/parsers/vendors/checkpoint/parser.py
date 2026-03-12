"""
Check Point management API JSON package parser.

Supported input: JSON export from Check Point ``show-package`` API command
(R80.x / R81.x and later).

The package export may be provided as:
  1. A single JSON document containing both "rulebase" and "objects-dictionary".
  2. A dict with a "policy" key (rulebase) and an "objects" key (object dictionary).
  3. A flat array of rule objects (legacy / simplified format).

Check Point rulebase structure:
  {
    "rulebase": [
      {
        "type": "access-rule",
        "uid": "...",
        "name": "...",
        "action": {"uid": "...", "name": "Accept"},
        "source": [{"uid": "...", "type": "host", ...}],
        "destination": [{"uid": "...", "type": "host", ...}],
        "service": [{"uid": "...", "type": "service-tcp", ...}],
        "from-zone": {"uid": "...", "name": "..."},
        "to-zone": {"uid": "...", "name": "..."},
        "enabled": true,
        "comments": "...",
        ...
      },
      {
        "type": "access-section",
        "uid": "...",
        "name": "Section Title",
        "rulebase": [ ... nested rules ... ]
      }
    ],
    "objects-dictionary": [
      {"uid": "...", "name": "...", "type": "host", "ipv4-address": "10.0.0.1"},
      {"uid": "...", "name": "...", "type": "network", "subnet4": "10.0.0.0", "mask-length4": 24},
      ...
    ]
  }

Action mapping:
  Accept       → permit
  Drop         → drop
  Reject       → reject
  Ask          → unknown
  Inform       → log_only
  UserCheck    → unknown

Special UIDs:
  Check Point uses a well-known UID for the "Any" network object.
  We detect any object named "Any" (case-insensitive) and treat it as any.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

from fwrule_mcp.parsers.base import (
    ObjectTable,
    ParsedPolicy,
    VendorParser,
    VendorRule,
)

logger = logging.getLogger(__name__)

CHECKPOINT_ACTION_MAP: dict[str, str] = {
    "accept": "permit",
    "allow": "permit",
    "drop": "drop",
    "discard": "drop",
    "reject": "reject",
    "ask": "unknown",
    "inform": "log_only",
    "usercheck": "unknown",
    "inner layer": "permit",  # sub-policy reference — treat as permit
}

# Well-known Check Point "Any" object UID (shared across all policies)
CP_ANY_UID = "97aeb369-9aea-11d5-bd16-0090272ccb30"


class CheckPointParser(VendorParser):
    """
    Parser for Check Point management API JSON package exports.
    """

    VENDOR = "checkpoint"
    OS_FAMILIES: list[str] = []

    def supported_vendors(self) -> list[tuple[str, Optional[str]]]:
        return [("checkpoint", None)]

    # ------------------------------------------------------------------
    # parse_policy
    # ------------------------------------------------------------------

    def parse_policy(
        self,
        raw_payload: str,
        context: Optional[dict[str, Any]] = None,
    ) -> ParsedPolicy:
        """
        Parse a Check Point JSON package export.
        """
        warnings: list[str] = []
        object_table = ObjectTable()
        rules: list[VendorRule] = []

        try:
            data = json.loads(raw_payload)
        except json.JSONDecodeError as exc:
            warnings.append(f"JSON parse error: {exc}")
            return ParsedPolicy(
                rules=rules,
                object_table=object_table,
                vendor=self.VENDOR,
                warnings=warnings,
            )

        # Build UID → object lookup table
        uid_map: dict[str, dict] = {}

        if isinstance(data, list):
            # Flat rules array — no objects dictionary available
            raw_rules_list = data
        elif isinstance(data, dict):
            # Locate objects dictionary
            for obj_key in ("objects-dictionary", "objects", "network-objects"):
                obj_list = data.get(obj_key, [])
                if obj_list and isinstance(obj_list, list):
                    self._build_uid_map(obj_list, uid_map)
                    self._populate_object_table(obj_list, object_table, uid_map, warnings)
                    break

            # Locate rulebase
            raw_rulebase = (
                data.get("rulebase")
                or data.get("access-rulebase")
                or data.get("rules")
                or data.get("items")
                or []
            )
            if isinstance(raw_rulebase, dict):
                # Sometimes wrapped as {"rulebase": {..., "rulebase": [...]}}
                raw_rulebase = raw_rulebase.get("rulebase", [])
            raw_rules_list = raw_rulebase if isinstance(raw_rulebase, list) else []
        else:
            warnings.append(f"Unexpected JSON root type: {type(data)}")
            return ParsedPolicy(
                rules=rules,
                object_table=object_table,
                vendor=self.VENDOR,
                warnings=warnings,
            )

        # Flatten rules (sections can contain nested rulebases)
        flat_rules = self._flatten_rulebase(raw_rules_list)

        position = 0
        for raw_rule in flat_rules:
            if not isinstance(raw_rule, dict):
                continue
            try:
                rule = self._parse_rule(raw_rule, position, uid_map, warnings)
                if rule is not None:
                    rules.append(rule)
                    position += 1
            except Exception as exc:  # noqa: BLE001
                name = raw_rule.get("name", f"<uid {raw_rule.get('uid', '?')}>")
                warnings.append(f"Skipping rule '{name}': {exc}")

        os_version = self._detect_version(data)

        return ParsedPolicy(
            rules=rules,
            object_table=object_table,
            vendor=self.VENDOR,
            os_version=os_version,
            warnings=warnings,
        )

    def parse_single_rule(
        self,
        raw_rule: str,
        object_table: Optional[ObjectTable] = None,
    ) -> VendorRule:
        """
        Parse a single Check Point rule JSON object.
        """
        try:
            data = json.loads(raw_rule)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Cannot parse Check Point rule JSON: {exc}") from exc

        if not isinstance(data, dict):
            raise ValueError("Expected a JSON object for Check Point rule")

        warnings: list[str] = []
        rule = self._parse_rule(data, position=0, uid_map={}, warnings=warnings)
        if rule is None:
            raise ValueError("Rule was a section header, not an access-rule")
        return rule

    # ------------------------------------------------------------------
    # UID map and object table
    # ------------------------------------------------------------------

    def _build_uid_map(
        self, obj_list: list, uid_map: dict[str, dict]
    ) -> None:
        """Index all objects by UID and by name for fast lookup."""
        for obj in obj_list:
            if not isinstance(obj, dict):
                continue
            uid = obj.get("uid", "")
            name = obj.get("name", "")
            if uid:
                uid_map[uid] = obj
            if name:
                # Name-based fallback — UIDs are preferred but names may appear inline
                uid_map[name] = obj

    def _populate_object_table(
        self,
        obj_list: list,
        table: ObjectTable,
        uid_map: dict[str, dict],
        warnings: list[str],
    ) -> None:
        """Build ObjectTable from Check Point objects dictionary."""
        for obj in obj_list:
            if not isinstance(obj, dict):
                continue
            obj_type = (obj.get("type") or "").lower()
            name = obj.get("name", "")
            if not name:
                continue

            try:
                if obj_type == "host":
                    addr = obj.get("ipv4-address") or obj.get("ipv6-address", "")
                    if addr:
                        table.address_objects[name] = [addr]

                elif obj_type == "network":
                    subnet = obj.get("subnet4") or obj.get("subnet", "")
                    mask = obj.get("mask-length4") or obj.get("subnet-mask", "")
                    if subnet and mask:
                        table.address_objects[name] = [f"{subnet}/{mask}"]

                elif obj_type in ("address-range", "multicast-address-range"):
                    start = obj.get("ipv4-address-first") or obj.get("ipv4-first", "")
                    end = obj.get("ipv4-address-last") or obj.get("ipv4-last", "")
                    if start and end:
                        table.address_objects[name] = [f"{start}-{end}"]

                elif obj_type in ("group", "network-group"):
                    members: list[str] = []
                    for member in obj.get("members", []):
                        if isinstance(member, dict):
                            member_name = member.get("name", "")
                            if member_name:
                                members.append(member_name)
                        elif isinstance(member, str):
                            # Could be a UID reference
                            if member in uid_map:
                                member_name = uid_map[member].get("name", member)
                                members.append(member_name)
                            else:
                                members.append(member)
                    table.address_groups[name] = members

                elif obj_type in ("service-tcp", "service-udp"):
                    proto = "tcp" if obj_type == "service-tcp" else "udp"
                    port = str(obj.get("port", ""))
                    src_port = str(obj.get("source-port", ""))
                    svc_info: dict[str, str] = {"protocol": proto}
                    if port:
                        svc_info["ports"] = port
                    if src_port:
                        svc_info["src_ports"] = src_port
                    table.service_objects[name] = svc_info

                elif obj_type == "service-icmp":
                    icmp_type = obj.get("icmp-type")
                    icmp_code = obj.get("icmp-code")
                    svc_info = {"protocol": "icmp"}
                    if icmp_type is not None:
                        svc_info["icmp_type"] = str(icmp_type)
                    if icmp_code is not None:
                        svc_info["icmp_code"] = str(icmp_code)
                    table.service_objects[name] = svc_info

                elif obj_type == "service-icmp6":
                    icmp_type = obj.get("icmp-type")
                    icmp_code = obj.get("icmp-code")
                    svc_info = {"protocol": "icmpv6"}
                    if icmp_type is not None:
                        svc_info["icmp_type"] = str(icmp_type)
                    if icmp_code is not None:
                        svc_info["icmp_code"] = str(icmp_code)
                    table.service_objects[name] = svc_info

                elif obj_type in ("service-other",):
                    proto = str(obj.get("ip-protocol", "ip"))
                    table.service_objects[name] = {"protocol": proto}

                elif obj_type in ("service-group",):
                    svc_members: list[str] = []
                    for member in obj.get("members", []):
                        if isinstance(member, dict):
                            m_name = member.get("name", "")
                            if m_name:
                                svc_members.append(m_name)
                        elif isinstance(member, str):
                            if member in uid_map:
                                svc_members.append(uid_map[member].get("name", member))
                            else:
                                svc_members.append(member)
                    table.service_groups[name] = svc_members

            except Exception as exc:  # noqa: BLE001
                warnings.append(f"Error processing object '{name}' ({obj_type}): {exc}")

    # ------------------------------------------------------------------
    # Rulebase flattening
    # ------------------------------------------------------------------

    def _flatten_rulebase(self, rulebase: list) -> list[dict]:
        """
        Recursively flatten a rulebase that may contain sections with nested rules.
        Sections (type=access-section) are skipped; their child rules are inlined.
        """
        flat: list[dict] = []
        for item in rulebase:
            if not isinstance(item, dict):
                continue
            item_type = (item.get("type") or "").lower()
            if item_type in ("access-section", "nat-section", "threat-prevention-section"):
                nested = item.get("rulebase", [])
                if isinstance(nested, list):
                    flat.extend(self._flatten_rulebase(nested))
            else:
                flat.append(item)
        return flat

    # ------------------------------------------------------------------
    # Rule parsing
    # ------------------------------------------------------------------

    def _parse_rule(
        self,
        raw_rule: dict,
        position: int,
        uid_map: dict[str, dict],
        warnings: list[str],
    ) -> Optional[VendorRule]:
        """
        Parse a single Check Point access-rule dict.

        Returns None for section headers (not actual rules).
        """
        rule_type = (raw_rule.get("type") or "access-rule").lower()
        if "section" in rule_type:
            return None

        name = raw_rule.get("name") or raw_rule.get("rule-number")
        if isinstance(name, int):
            name = str(name)

        enabled = bool(raw_rule.get("enabled", True))

        # Action
        action_field = raw_rule.get("action", {})
        if isinstance(action_field, dict):
            action_name = action_field.get("name", "")
        elif isinstance(action_field, str):
            action_name = action_field
        else:
            action_name = ""
        action = CHECKPOINT_ACTION_MAP.get(action_name.lower(), "unknown")

        # Source / destination zone (Check Point uses from/to zone in some contexts)
        src_zones = self._extract_zone_names(raw_rule, "from-zone")
        dst_zones = self._extract_zone_names(raw_rule, "to-zone")

        # Source / destination addresses
        src_addrs = self._extract_object_refs(raw_rule.get("source", []), uid_map)
        dst_addrs = self._extract_object_refs(raw_rule.get("destination", []), uid_map)

        # Negate flags
        negate_source = bool(raw_rule.get("source-negate", False))
        negate_destination = bool(raw_rule.get("destination-negate", False))

        # Services
        services = self._extract_object_refs(raw_rule.get("service", []), uid_map)

        # Applications (VP / Application & URL Filtering blade)
        applications = self._extract_app_refs(raw_rule.get("application", []), uid_map)

        # Comments / description
        description = raw_rule.get("comments", "") or raw_rule.get("comment", "")

        # Vendor tags
        vendor_tags: dict[str, Any] = {}
        rule_uid = raw_rule.get("uid", "")
        if rule_uid:
            vendor_tags["uid"] = rule_uid
        track = raw_rule.get("track", {})
        if isinstance(track, dict) and track.get("type", {}).get("name"):
            vendor_tags["track"] = track["type"]["name"]
        rule_number = raw_rule.get("rule-number")
        if rule_number is not None:
            vendor_tags["rule_number"] = rule_number

        return VendorRule(
            name=str(name) if name else None,
            position=position,
            enabled=enabled,
            source_zones=src_zones or ["any"],
            destination_zones=dst_zones or ["any"],
            source_addresses=src_addrs or ["any"],
            destination_addresses=dst_addrs or ["any"],
            services=services or ["any"],
            applications=applications or ["any"],
            action=action,
            negate_source=negate_source,
            negate_destination=negate_destination,
            description=description,
            vendor_tags=vendor_tags,
        )

    def _extract_zone_names(self, raw_rule: dict, key: str) -> list[str]:
        """Extract zone name(s) from a from-zone / to-zone field."""
        zone_field = raw_rule.get(key)
        if zone_field is None:
            return []
        if isinstance(zone_field, dict):
            name = zone_field.get("name", "")
            return [name] if name and name.lower() != "any" else []
        if isinstance(zone_field, str):
            return [zone_field] if zone_field.lower() != "any" else []
        if isinstance(zone_field, list):
            names = []
            for z in zone_field:
                if isinstance(z, dict):
                    n = z.get("name", "")
                    if n and n.lower() != "any":
                        names.append(n)
                elif isinstance(z, str) and z.lower() != "any":
                    names.append(z)
            return names
        return []

    def _extract_object_refs(
        self, obj_list: Any, uid_map: dict[str, dict]
    ) -> list[str]:
        """
        Resolve a list of Check Point object references to name strings.

        Input may be:
          - A list of dicts: [{"uid": "...", "name": "...", "type": "..."}]
          - A list of UID strings
          - A dict (single object)
          - "Any" keyword / well-known UID
        """
        if obj_list is None:
            return []

        # Normalize to list
        if isinstance(obj_list, dict):
            obj_list = [obj_list]
        elif not isinstance(obj_list, list):
            return []

        result: list[str] = []
        for item in obj_list:
            if isinstance(item, dict):
                uid = item.get("uid", "")
                name = item.get("name", "")
                item_type = (item.get("type") or "").lower()

                # Check for "Any" sentinel
                if uid == CP_ANY_UID or (name and name.lower() == "any"):
                    return ["any"]  # Any in source/dest means entire list is "any"

                if name:
                    result.append(name)
                elif uid and uid in uid_map:
                    resolved_name = uid_map[uid].get("name", uid)
                    if resolved_name.lower() == "any":
                        return ["any"]
                    result.append(resolved_name)
                elif uid:
                    result.append(uid)  # Unresolved UID — kept as-is

            elif isinstance(item, str):
                if item == CP_ANY_UID or item.lower() == "any":
                    return ["any"]
                if item in uid_map:
                    resolved_name = uid_map[item].get("name", item)
                    if resolved_name.lower() == "any":
                        return ["any"]
                    result.append(resolved_name)
                else:
                    result.append(item)

        return result

    def _extract_app_refs(
        self, app_field: Any, uid_map: dict[str, dict]
    ) -> list[str]:
        """Extract application names, returning empty list if not restricted."""
        if not app_field:
            return []
        refs = self._extract_object_refs(app_field, uid_map)
        # Filter out "Any" application
        return [r for r in refs if r.lower() not in ("any", "")]

    def _detect_version(self, data: Any) -> Optional[str]:
        """Extract Check Point version from package metadata."""
        if not isinstance(data, dict):
            return None
        for key in ("from", "header", "metadata", "policyPackage"):
            meta = data.get(key, {})
            if isinstance(meta, dict):
                for vkey in ("version", "gatewayVersion", "managementVersion"):
                    v = meta.get(vkey)
                    if v:
                        return str(v)
        return None
