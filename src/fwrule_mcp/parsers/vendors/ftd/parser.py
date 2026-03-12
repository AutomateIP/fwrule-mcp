"""
Cisco Firepower Threat Defense (FTD) / FMC JSON policy parser.

Supported input: JSON export from Firepower Management Center (FMC).

Expected JSON structure (FMC access policy export bundle):
{
  "rules": [
    {
      "id": "...",
      "name": "...",
      "action": "ALLOW|BLOCK|TRUST|MONITOR|BLOCK_RESET|BLOCK_INTERACTIVE",
      "enabled": true,
      "sourceNetworks": {
        "objects": [{"id": "...", "name": "...", "type": "Network|Host|Range|..."}],
        "literals": [{"type": "Host", "value": "10.0.0.1"},
                     {"type": "Network", "value": "10.0.0.0/24"}]
      },
      "destinationNetworks": { ... same structure ... },
      "sourcePorts": {
        "objects": [{"id": "...", "name": "...", "type": "ProtocolPortObject|..."}],
        "literals": [{"type": "PortLiteral", "protocol": "6", "port": "443"}]
      },
      "destinationPorts": { ... },
      "sourceZones": {
        "objects": [{"id": "...", "name": "..."}]
      },
      "destinationZones": { ... },
      "applications": {
        "applications": [{"id": "...", "name": "...", "type": "Application"}],
        "applicationFilters": [...]
      },
      "comments": [...],
      "metadata": {...}
    }
  ],
  "objects": [
    {
      "id": "...",
      "name": "...",
      "type": "Network|Host|Range|NetworkGroup|ProtocolPortObject|...",
      "value": "...",
      "objects": [...]   (for groups)
    }
  ]
}

Action mapping:
  ALLOW           → permit
  TRUST           → permit
  BLOCK           → deny
  BLOCK_RESET     → reject
  BLOCK_INTERACTIVE → deny
  MONITOR         → log_only
  INTRUSION_BLOCK → deny
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

FTD_ACTION_MAP: dict[str, str] = {
    "allow": "permit",
    "trust": "permit",
    "block": "deny",
    "block_reset": "reject",
    "block_interactive": "deny",
    "monitor": "log_only",
    "intrusion_block": "deny",
    "block_with_reset": "reject",
}


def _map_action(raw_action: str) -> str:
    return FTD_ACTION_MAP.get(raw_action.lower(), "unknown")


class FTDParser(VendorParser):
    """
    Parser for Cisco FTD/FMC JSON access policy export bundles.
    """

    VENDOR = "ftd"
    OS_FAMILIES: list[str] = []

    def supported_vendors(self) -> list[tuple[str, Optional[str]]]:
        return [("ftd", None)]

    # ------------------------------------------------------------------
    # parse_policy
    # ------------------------------------------------------------------

    def parse_policy(
        self,
        raw_payload: str,
        context: Optional[dict[str, Any]] = None,
    ) -> ParsedPolicy:
        """
        Parse an FMC access policy JSON export bundle.

        Accepts either:
          - A bundle with top-level "rules" and "objects" arrays.
          - A partial export with only "rules" (objects resolved inline).
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

        if not isinstance(data, dict):
            warnings.append("Unexpected JSON root type — expected object, got list or scalar")
            return ParsedPolicy(
                rules=rules,
                object_table=object_table,
                vendor=self.VENDOR,
                warnings=warnings,
            )

        # Build UID lookup table from top-level objects array
        uid_map: dict[str, dict] = {}
        raw_objects = data.get("objects", [])
        if isinstance(raw_objects, list):
            for obj in raw_objects:
                if isinstance(obj, dict) and obj.get("id"):
                    uid_map[obj["id"]] = obj
                    # Also index by name for name-based lookups
                    if obj.get("name"):
                        uid_map[obj["name"]] = obj
            self._populate_object_table(raw_objects, object_table, uid_map, warnings)

        # Also check for objects nested under different keys (FMC API variations)
        for key in ("networkObjects", "portObjects", "securityZones"):
            extra_objects = data.get(key, [])
            if isinstance(extra_objects, list):
                for obj in extra_objects:
                    if isinstance(obj, dict) and obj.get("id"):
                        uid_map[obj["id"]] = obj
                        if obj.get("name"):
                            uid_map[obj["name"]] = obj

        # Parse rules
        raw_rules = data.get("rules", [])
        if not isinstance(raw_rules, list):
            # FMC sometimes wraps rules in a "items" envelope
            raw_rules = data.get("items", [])

        for idx, raw_rule in enumerate(raw_rules):
            if not isinstance(raw_rule, dict):
                continue
            try:
                rule = self._parse_rule(raw_rule, idx, uid_map, warnings)
                rules.append(rule)
            except Exception as exc:  # noqa: BLE001
                name = raw_rule.get("name", f"<index {idx}>")
                warnings.append(f"Skipping rule '{name}': {exc}")

        # Detect FTD version from metadata if present
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
        Parse a single FTD rule JSON object.
        """
        try:
            data = json.loads(raw_rule)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Cannot parse FTD rule JSON: {exc}") from exc

        if not isinstance(data, dict):
            raise ValueError("Expected a JSON object for FTD rule")

        warnings: list[str] = []
        return self._parse_rule(data, position=0, uid_map={}, warnings=warnings)

    # ------------------------------------------------------------------
    # Object table population
    # ------------------------------------------------------------------

    def _populate_object_table(
        self,
        raw_objects: list,
        table: ObjectTable,
        uid_map: dict[str, dict],
        warnings: list[str],
    ) -> None:
        """Build ObjectTable from the FMC objects array."""
        for obj in raw_objects:
            if not isinstance(obj, dict):
                continue
            obj_type = (obj.get("type") or "").lower()
            name = obj.get("name", "")
            if not name:
                continue

            if obj_type in ("host",):
                value = obj.get("value", "")
                if value:
                    table.address_objects[name] = [value]

            elif obj_type in ("network",):
                value = obj.get("value", "")
                if value:
                    table.address_objects[name] = [value]

            elif obj_type in ("range",):
                value = obj.get("value", "")
                if value:
                    # FMC range format: "10.0.0.1-10.0.0.100"
                    table.address_objects[name] = [value]

            elif obj_type in ("networkgroup", "network-group", "hostgroup"):
                # Group of object references + literals
                members: list[str] = []
                for member_obj in obj.get("objects", []):
                    if isinstance(member_obj, dict) and member_obj.get("name"):
                        members.append(member_obj["name"])
                for literal in obj.get("literals", []):
                    if isinstance(literal, dict) and literal.get("value"):
                        members.append(literal["value"])
                table.address_groups[name] = members

            elif obj_type in ("protocolportobject", "portliteral", "icmpv4object", "icmpv6object"):
                svc_info = self._extract_service_info(obj)
                if svc_info:
                    table.service_objects[name] = svc_info

            elif obj_type in ("portobjectgroup", "portgroup", "servicegroup"):
                svc_members: list[str] = []
                for member_obj in obj.get("objects", []):
                    if isinstance(member_obj, dict) and member_obj.get("name"):
                        svc_members.append(member_obj["name"])
                table.service_groups[name] = svc_members

    def _extract_service_info(self, obj: dict) -> dict[str, str]:
        """Extract service info dict from an FMC port/service object."""
        obj_type = (obj.get("type") or "").lower()
        svc_info: dict[str, str] = {}

        if obj_type in ("icmpv4object", "icmpv6object"):
            svc_info["protocol"] = "icmpv6" if "v6" in obj_type else "icmp"
            icmp_type = obj.get("icmpType")
            icmp_code = obj.get("code")
            if icmp_type is not None:
                svc_info["icmp_type"] = str(icmp_type)
            if icmp_code is not None:
                svc_info["icmp_code"] = str(icmp_code)
            return svc_info

        # Protocol as number: 6=TCP, 17=UDP, 1=ICMP
        proto_raw = obj.get("protocol", "")
        proto = self._proto_number_to_name(str(proto_raw))
        if proto:
            svc_info["protocol"] = proto

        port = obj.get("port", "")
        if port and str(port) != "0":
            svc_info["ports"] = str(port)

        return svc_info

    def _proto_number_to_name(self, proto: str) -> str:
        """Convert numeric protocol to name, or pass through string protocols."""
        mapping = {
            "6": "tcp",
            "17": "udp",
            "1": "icmp",
            "58": "icmpv6",
            "0": "ip",
            "tcp": "tcp",
            "udp": "udp",
            "icmp": "icmp",
        }
        return mapping.get(proto.lower(), proto.lower())

    # ------------------------------------------------------------------
    # Rule parsing
    # ------------------------------------------------------------------

    def _parse_rule(
        self,
        raw_rule: dict,
        position: int,
        uid_map: dict[str, dict],
        warnings: list[str],
    ) -> VendorRule:
        """Parse a single FMC rule JSON object into a VendorRule."""
        name = raw_rule.get("name")
        enabled = bool(raw_rule.get("enabled", True))
        raw_action = raw_rule.get("action", "ALLOW")
        action = _map_action(raw_action)

        # Zones
        src_zones = self._extract_zone_names(raw_rule.get("sourceZones", {}))
        dst_zones = self._extract_zone_names(raw_rule.get("destinationZones", {}))

        # Addresses
        src_addrs = self._extract_address_refs(raw_rule.get("sourceNetworks", {}))
        dst_addrs = self._extract_address_refs(raw_rule.get("destinationNetworks", {}))

        # Services / ports
        services = self._extract_service_refs(
            raw_rule.get("sourcePorts", {}),
            raw_rule.get("destinationPorts", {}),
        )

        # Applications
        applications = self._extract_application_refs(raw_rule.get("applications", {}))

        # Description / comments
        description = raw_rule.get("description", "")
        if not description:
            comments = raw_rule.get("comments", [])
            if isinstance(comments, list) and comments:
                description = comments[0].get("comment", "") if isinstance(comments[0], dict) else str(comments[0])

        # Vendor tags
        vendor_tags: dict[str, Any] = {}
        rule_id = raw_rule.get("id", "")
        if rule_id:
            vendor_tags["fmc_rule_id"] = rule_id
        if raw_rule.get("logBegin"):
            vendor_tags["log_begin"] = raw_rule["logBegin"]
        if raw_rule.get("logEnd"):
            vendor_tags["log_end"] = raw_rule["logEnd"]
        if raw_rule.get("ipsPolicy"):
            vendor_tags["ips_policy"] = raw_rule["ipsPolicy"].get("name", "")
        metadata = raw_rule.get("metadata", {})
        if isinstance(metadata, dict) and metadata:
            vendor_tags["metadata"] = metadata

        return VendorRule(
            name=name,
            position=position,
            enabled=enabled,
            source_zones=src_zones or ["any"],
            destination_zones=dst_zones or ["any"],
            source_addresses=src_addrs or ["any"],
            destination_addresses=dst_addrs or ["any"],
            services=services or ["any"],
            applications=applications or ["any"],
            action=action,
            description=description,
            vendor_tags=vendor_tags,
        )

    def _extract_zone_names(self, zone_spec: Any) -> list[str]:
        """Extract zone names from a sourceZones / destinationZones structure."""
        if not isinstance(zone_spec, dict):
            return []
        zones: list[str] = []
        for obj in zone_spec.get("objects", []):
            if isinstance(obj, dict) and obj.get("name"):
                zones.append(obj["name"])
        return zones

    def _extract_address_refs(self, addr_spec: Any) -> list[str]:
        """
        Extract address references from an FMC sourceNetworks / destinationNetworks spec.

        Handles both named object references and inline literals.
        """
        if not isinstance(addr_spec, dict):
            return []
        refs: list[str] = []

        # Named object references
        for obj in addr_spec.get("objects", []):
            if isinstance(obj, dict) and obj.get("name"):
                refs.append(obj["name"])

        # Inline literals
        for literal in addr_spec.get("literals", []):
            if not isinstance(literal, dict):
                continue
            lit_type = (literal.get("type") or "").lower()
            value = literal.get("value", "")
            if not value:
                continue
            if lit_type in ("host",):
                refs.append(value)
            elif lit_type in ("network",):
                refs.append(value)
            elif lit_type in ("range",):
                # FMC range format: "10.0.0.1-10.0.0.100"
                refs.append(value)
            else:
                refs.append(value)

        return refs

    def _extract_service_refs(
        self, src_ports: Any, dst_ports: Any
    ) -> list[str]:
        """
        Extract service references from sourcePorts / destinationPorts structures.

        FTD separates source and destination ports.  For overlap analysis we
        focus on destination ports.  Source ports are preserved in vendor_tags
        by the caller.
        """
        # Use destination ports as the primary service spec
        spec = dst_ports if isinstance(dst_ports, dict) else {}
        refs: list[str] = []

        for obj in spec.get("objects", []):
            if isinstance(obj, dict) and obj.get("name"):
                refs.append(obj["name"])

        for literal in spec.get("literals", []):
            if not isinstance(literal, dict):
                continue
            lit_type = (literal.get("type") or "").lower()
            if lit_type in ("portliteral",):
                proto = self._proto_number_to_name(str(literal.get("protocol", "")))
                port = literal.get("port", "")
                if proto and port:
                    refs.append(f"{proto}:{port}")
                elif proto:
                    refs.append(proto)
            elif lit_type in ("icmpv4literal",):
                icmp_type = literal.get("icmpType", "")
                code = literal.get("code", "")
                spec_str = "icmp"
                if icmp_type:
                    spec_str += f":{icmp_type}"
                    if code:
                        spec_str += f"/{code}"
                refs.append(spec_str)
            elif lit_type in ("icmpv6literal",):
                icmp_type = literal.get("icmpType", "")
                refs.append(f"icmpv6:{icmp_type}" if icmp_type else "icmpv6")

        return refs

    def _extract_application_refs(self, app_spec: Any) -> list[str]:
        """Extract application names from an FMC applications structure."""
        if not isinstance(app_spec, dict):
            return []
        apps: list[str] = []
        for app in app_spec.get("applications", []):
            if isinstance(app, dict) and app.get("name"):
                apps.append(app["name"])
        # Application filters are treated as opaque tags
        for filt in app_spec.get("applicationFilters", []):
            if isinstance(filt, dict) and filt.get("name"):
                apps.append(f"filter:{filt['name']}")
        return apps

    def _detect_version(self, data: dict) -> Optional[str]:
        """Extract FTD/FMC version from bundle metadata."""
        meta = data.get("metadata", {})
        if isinstance(meta, dict):
            return meta.get("ftdVersion") or meta.get("fmcVersion") or meta.get("version")
        return None
