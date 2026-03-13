"""
Palo Alto Networks PAN-OS / Panorama parser.

Supported input: XML configuration export produced by:
  - ``show config running`` (NGFW CLI)
  - Panorama ``show config merged`` or device-group exports
  - Panorama API: GET /api/?type=config&action=get&xpath=...

XML structure targeted (standard vsys layout):
  Rules:         /config/devices/entry/vsys/entry/rulebase/security/rules/entry
  Panorama pre:  /config/devices/entry/device-group/entry/pre-rulebase/security/rules/entry
  Panorama post: /config/devices/entry/device-group/entry/post-rulebase/security/rules/entry
  Addresses:     /config/devices/entry/vsys/entry/address/entry
  Addr groups:   /config/devices/entry/vsys/entry/address-group/entry
  Services:      /config/devices/entry/vsys/entry/service/entry
  Svc groups:    /config/devices/entry/vsys/entry/service-group/entry
  Shared objs:   /config/shared/address/entry  (Panorama fallback)

Security: xml.etree.ElementTree is used with entity expansion disabled.
DTD processing is disabled by wrapping the payload to strip DOCTYPE declarations.

Action mapping:
  allow         → permit
  deny          → deny
  drop          → drop
  reset-client  → reject
  reset-server  → reject
  reset-both    → reject
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from typing import Any, Optional

from fwrule_mcp.parsers.base import (
    ObjectTable,
    ParsedPolicy,
    VendorParser,
    VendorRule,
)

logger = logging.getLogger(__name__)

# Map PAN-OS action strings to canonical action strings used by the normalization layer
PANOS_ACTION_MAP: dict[str, str] = {
    "allow": "permit",
    "deny": "deny",
    "drop": "drop",
    "reset-client": "reject",
    "reset-server": "reject",
    "reset-both": "reject",
}

# Regex to strip DOCTYPE declarations (prevents XXE via xml.etree)
_DOCTYPE_RE = re.compile(r"<!DOCTYPE[^>]*>", re.IGNORECASE | re.DOTALL)


def _safe_parse_xml(payload: str) -> ET.Element:
    """
    Parse XML with external entity expansion disabled.

    xml.etree.ElementTree does not support external entity resolution by
    default in CPython 3.8+, but we also strip any DOCTYPE declaration to
    be safe against entity injection via internal subsets.
    """
    # Remove DOCTYPE block to prevent internal entity expansion attempts
    sanitized = _DOCTYPE_RE.sub("", payload)
    # ET.fromstring raises xml.etree.ElementTree.ParseError on malformed XML
    return ET.fromstring(sanitized)


def _members(element: Optional[ET.Element]) -> list[str]:
    """
    Extract the text of all <member> child elements, stripping whitespace.
    Returns an empty list if element is None or has no <member> children.
    """
    if element is None:
        return []
    return [m.text.strip() for m in element.findall("member") if m.text]


def _text(element: Optional[ET.Element], default: str = "") -> str:
    """Return the text content of an element, or default if None/empty."""
    if element is None:
        return default
    return (element.text or default).strip()


class PANOSParser(VendorParser):
    """
    Parser for Palo Alto Networks PAN-OS and Panorama XML configuration exports.
    """

    VENDOR = "panos"
    OS_FAMILIES: list[str] = []  # Handles all PAN-OS versions

    # ------------------------------------------------------------------
    # VendorParser interface
    # ------------------------------------------------------------------

    def supported_vendors(self) -> list[tuple[str, Optional[str]]]:
        return [("panos", None)]

    def parse_policy(
        self,
        raw_payload: str,
        context: Optional[dict[str, Any]] = None,
    ) -> ParsedPolicy:
        """
        Parse a PAN-OS XML configuration export.

        Handles both single-vsys NGFW configs and Panorama device-group configs.
        Panorama shared objects are merged into the object table as a fallback
        when vsys-level objects are not found.
        """
        warnings: list[str] = []
        object_table = ObjectTable()
        rules: list[VendorRule] = []

        try:
            root = _safe_parse_xml(raw_payload)
        except ET.ParseError as exc:
            warnings.append(f"XML parse error: {exc}")
            return ParsedPolicy(
                rules=rules,
                object_table=object_table,
                vendor=self.VENDOR,
                warnings=warnings,
            )

        # Detect OS version from system info if present
        os_version = self._detect_version(root)

        # Extract shared objects (Panorama) first — vsys objects override these
        self._extract_objects_from_path(
            root, "./shared", object_table, warnings, label="shared"
        )

        # Extract vsys-level objects and rules
        vsys_entries = (
            root.findall("./devices/entry/vsys/entry")
            or root.findall("./config/devices/entry/vsys/entry")
        )

        if vsys_entries:
            for vsys_entry in vsys_entries:
                self._extract_objects_from_element(vsys_entry, object_table, warnings)
                vsys_rules = self._extract_rules_from_rulebase(
                    vsys_entry, len(rules), warnings
                )
                rules.extend(vsys_rules)
        else:
            # Try Panorama device-group structure
            dg_entries = (
                root.findall("./devices/entry/device-group/entry")
                or root.findall("./config/devices/entry/device-group/entry")
            )
            for dg_entry in dg_entries:
                self._extract_objects_from_element(dg_entry, object_table, warnings)
                pre_rules = self._extract_rules_from_rulebase(
                    dg_entry, len(rules), warnings, rulebase_type="pre-rulebase"
                )
                rules.extend(pre_rules)
                post_rules = self._extract_rules_from_rulebase(
                    dg_entry, len(rules), warnings, rulebase_type="post-rulebase"
                )
                rules.extend(post_rules)

        if not rules and not vsys_entries:
            # Last-resort: try to extract rules directly from the root element
            direct_rules = self._extract_rules_from_rulebase(root, 0, warnings)
            rules.extend(direct_rules)

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
        Parse a single PAN-OS security rule XML fragment.

        Expects an <entry> element in PAN-OS security rule format:
            <entry name="rule-name">
              <from><member>trust</member></from>
              ...
            </entry>
        """
        warnings: list[str] = []
        try:
            entry = _safe_parse_xml(raw_rule)
            # If the root is not an <entry>, find the security rule entry.
            # A security rule <entry> has an <action> child, which distinguishes
            # it from device/vsys/rulebase wrapper <entry> elements.
            if entry.tag != "entry" or entry.find("action") is None:
                found = None
                for candidate in entry.iter("entry"):
                    if candidate.find("action") is not None:
                        found = candidate
                        break
                if found is None:
                    # Fallback: try the deepest entry (last in document order)
                    all_entries = list(entry.iter("entry"))
                    found = all_entries[-1] if all_entries else None
                if found is None:
                    raise ValueError("No security rule <entry> element found in candidate XML")
                entry = found
        except ET.ParseError as exc:
            raise ValueError(f"Cannot parse candidate PAN-OS rule XML: {exc}") from exc

        rule = self._parse_rule_entry(entry, position=0, warnings=warnings)
        return rule

    # ------------------------------------------------------------------
    # Internal helpers — object extraction
    # ------------------------------------------------------------------

    def _extract_objects_from_path(
        self,
        root: ET.Element,
        xpath: str,
        table: ObjectTable,
        warnings: list[str],
        label: str = "",
    ) -> None:
        """Extract objects from a subtree located by xpath."""
        container = root.find(xpath)
        if container is not None:
            self._extract_objects_from_element(container, table, warnings)

    def _extract_objects_from_element(
        self,
        container: ET.Element,
        table: ObjectTable,
        warnings: list[str],
    ) -> None:
        """Extract all object types from a vsys/shared/device-group element."""
        self._extract_address_objects(container, table, warnings)
        self._extract_address_groups(container, table, warnings)
        self._extract_service_objects(container, table, warnings)
        self._extract_service_groups(container, table, warnings)
        self._extract_application_objects(container, table, warnings)

    def _extract_address_objects(
        self,
        container: ET.Element,
        table: ObjectTable,
        warnings: list[str],
    ) -> None:
        """
        Extract <address> entries.

        Handles:
          <entry name="obj-name">
            <ip-netmask>10.0.0.0/24</ip-netmask>   <!-- CIDR -->
            <ip-range>10.0.0.1-10.0.0.100</ip-range>  <!-- range -->
            <fqdn>www.example.com</fqdn>              <!-- FQDN -->
          </entry>
        """
        for entry in container.findall("./address/entry"):
            name = entry.get("name")
            if not name:
                continue
            values: list[str] = []
            for tag in ("ip-netmask", "ip-range", "fqdn", "ip-wildcard"):
                child = entry.find(tag)
                if child is not None and child.text:
                    values.append(child.text.strip())
            if values:
                # Do not overwrite vsys objects with shared objects
                if name not in table.address_objects:
                    table.address_objects[name] = values
            else:
                warnings.append(f"Address object '{name}' has no recognized value element")

    def _extract_address_groups(
        self,
        container: ET.Element,
        table: ObjectTable,
        warnings: list[str],
    ) -> None:
        """
        Extract <address-group> entries.

        Handles static groups (member list) and dynamic groups (filter tag).
        Dynamic groups are stored with a single synthetic member string prefixed
        with "dynamic:" so the normalization layer can flag them appropriately.
        """
        for entry in container.findall("./address-group/entry"):
            name = entry.get("name")
            if not name:
                continue
            static_el = entry.find("static")
            if static_el is not None:
                members = _members(static_el)
            else:
                # Dynamic address group — store filter as opaque reference
                dynamic_el = entry.find("dynamic/filter")
                filter_str = _text(dynamic_el, default="")
                members = [f"dynamic:{filter_str}"] if filter_str else []
            if name not in table.address_groups:
                table.address_groups[name] = members

    def _extract_service_objects(
        self,
        container: ET.Element,
        table: ObjectTable,
        warnings: list[str],
    ) -> None:
        """
        Extract <service> entries.

        Handles:
          <entry name="svc-https">
            <protocol>
              <tcp><port>443</port><source-port>any</source-port></tcp>
            </protocol>
          </entry>
        """
        for entry in container.findall("./service/entry"):
            name = entry.get("name")
            if not name:
                continue
            proto_el = entry.find("protocol")
            if proto_el is None:
                # "application-default" or similar — store as-is
                table.service_objects[name] = {"protocol": "application-default"}
                continue

            svc_info: dict[str, str] = {}
            for proto in ("tcp", "udp", "sctp"):
                p_el = proto_el.find(proto)
                if p_el is not None:
                    svc_info["protocol"] = proto
                    port_el = p_el.find("port")
                    if port_el is not None and port_el.text:
                        svc_info["ports"] = port_el.text.strip()
                    src_port_el = p_el.find("source-port")
                    if src_port_el is not None and src_port_el.text:
                        svc_info["src_ports"] = src_port_el.text.strip()
                    break

            icmp_el = proto_el.find("icmp") or proto_el.find("icmpv6")
            if icmp_el is not None:
                svc_info["protocol"] = icmp_el.tag
                type_el = icmp_el.find("type")
                code_el = icmp_el.find("code")
                if type_el is not None and type_el.text:
                    svc_info["icmp_type"] = type_el.text.strip()
                if code_el is not None and code_el.text:
                    svc_info["icmp_code"] = code_el.text.strip()

            if svc_info and name not in table.service_objects:
                table.service_objects[name] = svc_info

    def _extract_service_groups(
        self,
        container: ET.Element,
        table: ObjectTable,
        warnings: list[str],
    ) -> None:
        """Extract <service-group> entries."""
        for entry in container.findall("./service-group/entry"):
            name = entry.get("name")
            if not name:
                continue
            members = _members(entry.find("members"))
            if name not in table.service_groups:
                table.service_groups[name] = members

    def _extract_application_objects(
        self,
        container: ET.Element,
        table: ObjectTable,
        warnings: list[str],
    ) -> None:
        """
        Extract custom <application> entries (if any).
        Built-in App-IDs have no config XML entries but appear in rule members.
        """
        for entry in container.findall("./application/entry"):
            name = entry.get("name")
            if not name:
                continue
            category = _text(entry.find("category"), default="custom")
            table.application_objects[name] = category

    # ------------------------------------------------------------------
    # Internal helpers — rule extraction
    # ------------------------------------------------------------------

    def _extract_rules_from_rulebase(
        self,
        container: ET.Element,
        position_offset: int,
        warnings: list[str],
        rulebase_type: str = "rulebase",
    ) -> list[VendorRule]:
        """
        Extract security rules from a rulebase element.

        Searches for rules under:
          <{rulebase_type}>/security/rules/entry

        Args:
            container:        Parent element (vsys, device-group, or root).
            position_offset:  Starting position index for these rules.
            warnings:         Mutable list for non-fatal parse warnings.
            rulebase_type:    "rulebase", "pre-rulebase", or "post-rulebase".
        """
        rules: list[VendorRule] = []
        rule_entries = container.findall(f"./{rulebase_type}/security/rules/entry")

        for idx, entry in enumerate(rule_entries):
            try:
                rule = self._parse_rule_entry(
                    entry, position=position_offset + idx, warnings=warnings
                )
                rules.append(rule)
            except Exception as exc:  # noqa: BLE001
                name = entry.get("name", f"<position {position_offset + idx}>")
                warnings.append(f"Skipping rule '{name}': {exc}")

        return rules

    def _parse_rule_entry(
        self,
        entry: ET.Element,
        position: int,
        warnings: list[str],
    ) -> VendorRule:
        """
        Parse a single security rule <entry> element into a VendorRule.
        """
        name = entry.get("name")

        # Enabled / disabled
        disabled_el = entry.find("disabled")
        disabled = _text(disabled_el).lower() == "yes"
        enabled = not disabled

        # Zone membership
        source_zones = _members(entry.find("from")) or ["any"]
        destination_zones = _members(entry.find("to")) or ["any"]

        # Address membership
        negate_source = _text(entry.find("negate-source")).lower() == "yes"
        negate_destination = _text(entry.find("negate-destination")).lower() == "yes"
        source_addresses = _members(entry.find("source")) or ["any"]
        destination_addresses = _members(entry.find("destination")) or ["any"]

        # Service membership
        svc_el = entry.find("service")
        if svc_el is not None:
            service_members = _members(svc_el)
            if not service_members:
                # Single inline text like "application-default" or "any"
                svc_text = _text(svc_el)
                service_members = [svc_text] if svc_text else ["any"]
        else:
            service_members = ["any"]

        # Application membership
        app_el = entry.find("application")
        if app_el is not None:
            app_members = _members(app_el)
            if not app_members:
                app_text = _text(app_el)
                app_members = [app_text] if app_text else ["any"]
        else:
            app_members = ["any"]

        # Action
        action_el = entry.find("action")
        raw_action = _text(action_el, default="allow")
        action = PANOS_ACTION_MAP.get(raw_action.lower(), raw_action.lower())

        # Description
        description = _text(entry.find("description"))

        # Vendor tags — preserve additional metadata for traceability
        vendor_tags: dict[str, Any] = {}
        profile_setting = entry.find("profile-setting")
        if profile_setting is not None:
            group_el = profile_setting.find("group/member")
            if group_el is not None and group_el.text:
                vendor_tags["profile_group"] = group_el.text.strip()

        log_start = entry.find("log-start")
        log_end = entry.find("log-end")
        if log_start is not None:
            vendor_tags["log_start"] = _text(log_start)
        if log_end is not None:
            vendor_tags["log_end"] = _text(log_end)

        tag_el = entry.find("tag")
        if tag_el is not None:
            vendor_tags["tags"] = _members(tag_el)

        return VendorRule(
            name=name,
            position=position,
            enabled=enabled,
            source_zones=source_zones,
            destination_zones=destination_zones,
            source_addresses=source_addresses,
            destination_addresses=destination_addresses,
            services=service_members,
            applications=app_members,
            action=action,
            negate_source=negate_source,
            negate_destination=negate_destination,
            description=description,
            vendor_tags=vendor_tags,
        )

    # ------------------------------------------------------------------
    # Version detection
    # ------------------------------------------------------------------

    def _detect_version(self, root: ET.Element) -> Optional[str]:
        """
        Attempt to extract PAN-OS version from the XML structure.

        Panorama configs sometimes embed version in system/version or
        in a comment block.  Returns None if not found.
        """
        for xpath in (
            "./system/sw-version",
            "./devices/entry/system/sw-version",
            "./config/devices/entry/system/sw-version",
        ):
            el = root.find(xpath)
            if el is not None and el.text:
                return el.text.strip()
        return None
