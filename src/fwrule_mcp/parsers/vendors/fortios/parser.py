"""
Fortinet FortiOS flat-text configuration parser.

Supported input: FortiOS full backup config (``show full-configuration`` or
backup file from FortiManager/FortiGate).

Handles:
  - config firewall policy / config firewall policy6 (IPv6)
  - config firewall address / config firewall addrgrp
  - config firewall service custom / config firewall service group
  - Inline address literals (host IPs, CIDRs)
  - Multi-interface source/destination (multiple set srcintf / set dstintf)
  - Policy status (enable/disable)
  - NAT flag
  - FortiOS action keywords: accept, deny, ipsec, ssl-vpn, redirect, isolate

Parsing strategy:
  Recursive block parser.  FortiOS config is structured as nested
  ``config <section> / edit <id> / set <key> <value> ... / next / end``
  blocks.  The parser first extracts all address and service objects into an
  ObjectTable, then walks the firewall policy block to produce VendorRules.

Action mapping:
  accept   → permit
  deny     → deny
  ipsec    → permit   (VPN policy — treated as permit for overlap analysis)
  ssl-vpn  → permit   (SSL-VPN policy)
  redirect → permit
  isolate  → deny     (quarantine — treated as deny)
"""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import Any, Optional

from fwrule_mcp.parsers.base import (
    ObjectTable,
    ParsedPolicy,
    VendorParser,
    VendorRule,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# FortiOS named service → (protocol, port) resolution tables
# ---------------------------------------------------------------------------

FORTI_NAMED_SERVICES: dict[str, dict[str, str]] = {
    "ALL":          {"protocol": "any",  "ports": "any"},
    "ALL_TCP":      {"protocol": "tcp",  "ports": "any"},
    "ALL_UDP":      {"protocol": "udp",  "ports": "any"},
    "ALL_ICMP":     {"protocol": "icmp", "ports": "any"},
    "ALL_ICMP6":    {"protocol": "icmpv6", "ports": "any"},
    "HTTP":         {"protocol": "tcp",  "ports": "80"},
    "HTTPS":        {"protocol": "tcp",  "ports": "443"},
    "SSH":          {"protocol": "tcp",  "ports": "22"},
    "TELNET":       {"protocol": "tcp",  "ports": "23"},
    "FTP":          {"protocol": "tcp",  "ports": "21"},
    "SMTP":         {"protocol": "tcp",  "ports": "25"},
    "SMTPS":        {"protocol": "tcp",  "ports": "465"},
    "DNS":          {"protocol": "udp",  "ports": "53"},
    "NTP":          {"protocol": "udp",  "ports": "123"},
    "SNMP":         {"protocol": "udp",  "ports": "161"},
    "SNMPTRAP":     {"protocol": "udp",  "ports": "162"},
    "SYSLOG":       {"protocol": "udp",  "ports": "514"},
    "LDAP":         {"protocol": "tcp",  "ports": "389"},
    "LDAPS":        {"protocol": "tcp",  "ports": "636"},
    "RDP":          {"protocol": "tcp",  "ports": "3389"},
    "VNC":          {"protocol": "tcp",  "ports": "5900"},
    "MYSQL":        {"protocol": "tcp",  "ports": "3306"},
    "MSSQL":        {"protocol": "tcp",  "ports": "1433"},
    "IMAP":         {"protocol": "tcp",  "ports": "143"},
    "IMAPS":        {"protocol": "tcp",  "ports": "993"},
    "POP3":         {"protocol": "tcp",  "ports": "110"},
    "POP3S":        {"protocol": "tcp",  "ports": "995"},
    "RADIUS":       {"protocol": "udp",  "ports": "1812"},
    "PING":         {"protocol": "icmp", "ports": "any"},
    "TRACEROUTE":   {"protocol": "udp",  "ports": "33434-33534"},
    "SAMBA":        {"protocol": "tcp",  "ports": "445"},
    "KERBEROS":     {"protocol": "tcp",  "ports": "88"},
    "BGP":          {"protocol": "tcp",  "ports": "179"},
    "OSPF":         {"protocol": "any",  "ports": "any"},
    "SIP":          {"protocol": "udp",  "ports": "5060"},
    "H323":         {"protocol": "tcp",  "ports": "1720"},
    "DHCP":         {"protocol": "udp",  "ports": "67-68"},
    "TFTP":         {"protocol": "udp",  "ports": "69"},
    "GRE":          {"protocol": "gre",  "ports": "any"},
    "ESP":          {"protocol": "esp",  "ports": "any"},
    "AH":           {"protocol": "ah",   "ports": "any"},
    "IKE":          {"protocol": "udp",  "ports": "500"},
    "IKE-NAT-T":    {"protocol": "udp",  "ports": "4500"},
    "IMAP4":        {"protocol": "tcp",  "ports": "143"},
    "NNTP":         {"protocol": "tcp",  "ports": "119"},
    "PPTP":         {"protocol": "tcp",  "ports": "1723"},
    "L2TP":         {"protocol": "udp",  "ports": "1701"},
    "WEBPROXY":     {"protocol": "tcp",  "ports": "8080"},
    "INTERNET-LOCALDOMAIN": {"protocol": "any", "ports": "any"},
}

FORTI_ACTION_MAP: dict[str, str] = {
    "accept":   "permit",
    "deny":     "deny",
    "ipsec":    "permit",
    "ssl-vpn":  "permit",
    "redirect": "permit",
    "isolate":  "deny",
}


def _forti_subnet_to_cidr(subnet_str: str) -> str:
    """
    Convert FortiOS subnet notation (``10.0.0.0 255.255.255.0``) to CIDR.
    Also handles already-CIDR strings and bare host IPs.
    """
    parts = subnet_str.strip().split()
    if len(parts) == 2:
        try:
            net = ipaddress.IPv4Network(f"{parts[0]}/{parts[1]}", strict=False)
            return str(net)
        except ValueError:
            return subnet_str
    if len(parts) == 1:
        val = parts[0]
        if "/" in val:
            try:
                return str(ipaddress.IPv4Network(val, strict=False))
            except ValueError:
                return val
        # Bare host IP — return as /32
        try:
            ipaddress.IPv4Address(val)
            return f"{val}/32"
        except ValueError:
            return val
    return subnet_str


# ---------------------------------------------------------------------------
# Low-level block tokeniser
# ---------------------------------------------------------------------------

def _tokenise_forti_config(text: str) -> list[tuple[str, str]]:
    """
    Tokenise a FortiOS config into a flat list of (token_type, value) tuples.

    token_type values:
      "config"  — ``config <section_name>``  (opens a block)
      "edit"    — ``edit <id>``              (opens a sub-entry)
      "set"     — ``set <key> <rest>``       (key-value assignment)
      "next"    — ``next``                   (closes an edit block)
      "end"     — ``end``                    (closes a config block)
      "unset"   — ``unset <key>``            (ignored by parser)
      "other"   — everything else
    """
    tokens: list[tuple[str, str]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        lower = line.lower()
        if lower.startswith("config "):
            tokens.append(("config", line[7:].strip()))
        elif lower == "end":
            tokens.append(("end", ""))
        elif lower.startswith("edit "):
            tokens.append(("edit", line[5:].strip()))
        elif lower == "next":
            tokens.append(("next", ""))
        elif lower.startswith("set "):
            rest = line[4:].strip()
            # Split into key and value (value may contain spaces)
            kv = rest.split(None, 1)
            key = kv[0] if kv else ""
            val = kv[1] if len(kv) > 1 else ""
            tokens.append(("set", f"{key} {val}"))
        elif lower.startswith("unset "):
            tokens.append(("unset", line[6:].strip()))
        else:
            tokens.append(("other", line))
    return tokens


def _extract_quoted_list(value: str) -> list[str]:
    """
    Extract individual items from a FortiOS multi-value ``set`` line.

    FortiOS uses space-separated quoted strings:
      ``"Item One" "Item Two" "all"``
    Returns a flat list with quotes stripped.
    """
    # Find all double-quoted tokens first
    quoted = re.findall(r'"([^"]*)"', value)
    if quoted:
        return [q.strip() for q in quoted if q.strip()]
    # Fall back to whitespace splitting for unquoted values
    return [v.strip() for v in value.split() if v.strip()]


# ---------------------------------------------------------------------------
# Main parser class
# ---------------------------------------------------------------------------


class FortiOSParser(VendorParser):
    """
    Parser for Fortinet FortiOS flat-text configuration backups.

    Supports:
      - FortiOS 5.x, 6.x, 7.x config format
      - IPv4 firewall policy (``config firewall policy``)
      - IPv6 firewall policy (``config firewall policy6``) — zones/addresses
        resolved identically; IPv6 CIDRs passed through to normalisation layer
      - Address objects, address groups
      - Service custom objects, service groups
      - Inline object name references (resolved via ObjectTable)
    """

    VENDOR = "fortios"
    OS_FAMILIES: list[str] = []

    def supported_vendors(self) -> list[tuple[str, Optional[str]]]:
        return [("fortios", None), ("fortigate", None), ("forti", None)]

    # ------------------------------------------------------------------
    # VendorParser interface
    # ------------------------------------------------------------------

    def parse_policy(
        self,
        raw_payload: str,
        context: Optional[dict[str, Any]] = None,
    ) -> ParsedPolicy:
        warnings: list[str] = []
        tokens = _tokenise_forti_config(raw_payload)

        # Pass 1 — build ObjectTable from address / service sections
        object_table = self._extract_objects(tokens, warnings)

        # Pass 2 — extract firewall policy rules
        rules = self._extract_firewall_policies(tokens, object_table, warnings)

        return ParsedPolicy(
            rules=rules,
            object_table=object_table,
            vendor=self.VENDOR,
            os_version=self._detect_version(raw_payload),
            warnings=warnings,
        )

    def parse_single_rule(
        self,
        raw_rule: str,
        object_table: Optional[ObjectTable] = None,
    ) -> VendorRule:
        """
        Parse a single FortiOS policy entry.

        The raw_rule should be the body of a single ``edit <id> ... next``
        block (or a full ``config firewall policy / edit ... / next / end``
        wrapper).
        """
        warnings: list[str] = []
        # Wrap in a minimal firewall policy block if not already wrapped
        if "config firewall policy" not in raw_rule.lower():
            wrapped = f"config firewall policy\n    edit 1\n{raw_rule}\n    next\nend"
        else:
            wrapped = raw_rule

        tokens = _tokenise_forti_config(wrapped)
        ot = object_table or ObjectTable()
        rules = self._extract_firewall_policies(tokens, ot, warnings)
        if not rules:
            raise ValueError(f"Cannot parse FortiOS policy rule: {raw_rule!r}")
        return rules[0]

    # ------------------------------------------------------------------
    # Object extraction — Pass 1
    # ------------------------------------------------------------------

    def _extract_objects(
        self, tokens: list[tuple[str, str]], warnings: list[str]
    ) -> ObjectTable:
        table = ObjectTable()
        i = 0
        while i < len(tokens):
            ttype, tval = tokens[i]
            if ttype == "config":
                section = tval.lower()
                if section == "firewall address":
                    i = self._parse_address_objects(tokens, i + 1, table, warnings)
                    continue
                elif section == "firewall addrgrp":
                    i = self._parse_address_groups(tokens, i + 1, table, warnings)
                    continue
                elif section == "firewall service custom":
                    i = self._parse_service_objects(tokens, i + 1, table, warnings)
                    continue
                elif section == "firewall service group":
                    i = self._parse_service_groups(tokens, i + 1, table, warnings)
                    continue
                else:
                    # Skip unknown config blocks
                    depth = 1
                    i += 1
                    while i < len(tokens) and depth > 0:
                        tt, _ = tokens[i]
                        if tt == "config":
                            depth += 1
                        elif tt == "end":
                            depth -= 1
                        i += 1
                    continue
            i += 1
        return table

    def _parse_address_objects(
        self,
        tokens: list[tuple[str, str]],
        start: int,
        table: ObjectTable,
        warnings: list[str],
    ) -> int:
        """Parse ``config firewall address`` block into ObjectTable.address_objects."""
        i = start
        while i < len(tokens):
            ttype, tval = tokens[i]
            if ttype == "end":
                return i + 1
            if ttype == "edit":
                obj_name = tval.strip('"')
                obj_vals: list[str] = []
                i += 1
                while i < len(tokens):
                    tt, tv = tokens[i]
                    if tt == "next":
                        i += 1
                        break
                    if tt == "set":
                        key, _, val = tv.partition(" ")
                        key = key.lower()
                        if key == "subnet":
                            obj_vals.append(_forti_subnet_to_cidr(val))
                        elif key == "fqdn":
                            obj_vals.append(val.strip('"'))
                        elif key == "start-ip":
                            # range start — peek for end-ip
                            obj_vals.append(f"_range_start:{val.strip()}")
                        elif key == "end-ip":
                            # combine with start
                            for idx2, v in enumerate(obj_vals):
                                if v.startswith("_range_start:"):
                                    start_ip = v.split(":", 1)[1]
                                    obj_vals[idx2] = f"{start_ip}-{val.strip()}"
                                    break
                            else:
                                obj_vals.append(val.strip())
                        elif key == "wildcard":
                            # wildcard <ip> <mask>
                            obj_vals.append(_forti_subnet_to_cidr(val))
                        elif key == "iprange":
                            obj_vals.append(val.strip())
                        elif key == "type":
                            pass  # ipmask, iprange, fqdn, etc. — handled by key above
                    i += 1
                # Clean up any unconsumed _range_start entries
                obj_vals = [v for v in obj_vals if not v.startswith("_range_start:")]
                if obj_name and obj_vals:
                    table.address_objects[obj_name] = obj_vals
                continue
            i += 1
        return i

    def _parse_address_groups(
        self,
        tokens: list[tuple[str, str]],
        start: int,
        table: ObjectTable,
        warnings: list[str],
    ) -> int:
        """Parse ``config firewall addrgrp`` block into ObjectTable.address_groups."""
        i = start
        while i < len(tokens):
            ttype, tval = tokens[i]
            if ttype == "end":
                return i + 1
            if ttype == "edit":
                grp_name = tval.strip('"')
                members: list[str] = []
                i += 1
                while i < len(tokens):
                    tt, tv = tokens[i]
                    if tt == "next":
                        i += 1
                        break
                    if tt == "set":
                        key, _, val = tv.partition(" ")
                        if key.lower() == "member":
                            members = _extract_quoted_list(val)
                    i += 1
                if grp_name and members:
                    table.address_groups[grp_name] = members
                continue
            i += 1
        return i

    def _parse_service_objects(
        self,
        tokens: list[tuple[str, str]],
        start: int,
        table: ObjectTable,
        warnings: list[str],
    ) -> int:
        """Parse ``config firewall service custom`` block into ObjectTable.service_objects."""
        i = start
        while i < len(tokens):
            ttype, tval = tokens[i]
            if ttype == "end":
                return i + 1
            if ttype == "edit":
                svc_name = tval.strip('"')
                svc_info: dict[str, str] = {}
                i += 1
                while i < len(tokens):
                    tt, tv = tokens[i]
                    if tt == "next":
                        i += 1
                        break
                    if tt == "set":
                        key, _, val = tv.partition(" ")
                        key = key.lower()
                        val = val.strip().strip('"')
                        if key == "protocol":
                            proto = val.lower()
                            if proto == "tcp/udp/sctp":
                                svc_info["protocol"] = "tcp"
                            else:
                                svc_info["protocol"] = proto
                        elif key == "tcp-portrange":
                            # Format: "80 443" or "8080-8090" or "80:1024-65535" (dst:src)
                            dst_port = val.split(":")[0].split()[0]
                            svc_info["ports"] = dst_port.replace(" ", ",")
                            svc_info.setdefault("protocol", "tcp")
                        elif key == "udp-portrange":
                            dst_port = val.split(":")[0].split()[0]
                            svc_info["ports"] = dst_port.replace(" ", ",")
                            svc_info.setdefault("protocol", "udp")
                        elif key == "sctp-portrange":
                            dst_port = val.split(":")[0].split()[0]
                            svc_info["ports"] = dst_port.replace(" ", ",")
                            svc_info.setdefault("protocol", "sctp")
                        elif key == "icmptype":
                            svc_info["icmp_type"] = val
                            svc_info.setdefault("protocol", "icmp")
                        elif key == "icmpcode":
                            svc_info["icmp_code"] = val
                    i += 1
                # Look up well-known name if no protocol parsed
                if svc_name and not svc_info:
                    well_known = FORTI_NAMED_SERVICES.get(svc_name.upper())
                    if well_known:
                        svc_info = dict(well_known)
                if svc_name and svc_info:
                    table.service_objects[svc_name] = svc_info
                continue
            i += 1
        return i

    def _parse_service_groups(
        self,
        tokens: list[tuple[str, str]],
        start: int,
        table: ObjectTable,
        warnings: list[str],
    ) -> int:
        """Parse ``config firewall service group`` block into ObjectTable.service_groups."""
        i = start
        while i < len(tokens):
            ttype, tval = tokens[i]
            if ttype == "end":
                return i + 1
            if ttype == "edit":
                grp_name = tval.strip('"')
                members: list[str] = []
                i += 1
                while i < len(tokens):
                    tt, tv = tokens[i]
                    if tt == "next":
                        i += 1
                        break
                    if tt == "set":
                        key, _, val = tv.partition(" ")
                        if key.lower() == "member":
                            members = _extract_quoted_list(val)
                    i += 1
                if grp_name and members:
                    table.service_groups[grp_name] = members
                continue
            i += 1
        return i

    # ------------------------------------------------------------------
    # Firewall policy extraction — Pass 2
    # ------------------------------------------------------------------

    def _extract_firewall_policies(
        self,
        tokens: list[tuple[str, str]],
        table: ObjectTable,
        warnings: list[str],
    ) -> list[VendorRule]:
        """Walk token stream and extract rules from firewall policy blocks."""
        rules: list[VendorRule] = []
        position = 0
        i = 0
        while i < len(tokens):
            ttype, tval = tokens[i]
            if ttype == "config" and tval.lower() in (
                "firewall policy",
                "firewall policy6",
            ):
                i, new_rules = self._parse_policy_block(
                    tokens, i + 1, table, warnings, position
                )
                rules.extend(new_rules)
                position += len(new_rules)
                continue
            i += 1
        return rules

    def _parse_policy_block(
        self,
        tokens: list[tuple[str, str]],
        start: int,
        table: ObjectTable,
        warnings: list[str],
        base_position: int,
    ) -> tuple[int, list[VendorRule]]:
        """Parse one ``config firewall policy`` block; return (next_idx, rules)."""
        rules: list[VendorRule] = []
        i = start
        position = base_position
        while i < len(tokens):
            ttype, tval = tokens[i]
            if ttype == "end":
                return i + 1, rules
            if ttype == "edit":
                policy_id = tval.strip('"')
                i, rule = self._parse_single_policy(
                    tokens, i + 1, table, warnings, position, policy_id
                )
                if rule:
                    rules.append(rule)
                    position += 1
                continue
            i += 1
        return i, rules

    def _parse_single_policy(
        self,
        tokens: list[tuple[str, str]],
        start: int,
        table: ObjectTable,
        warnings: list[str],
        position: int,
        policy_id: str,
    ) -> tuple[int, Optional[VendorRule]]:
        """Parse the body of a single ``edit <id> ... next`` policy entry."""
        fields: dict[str, Any] = {
            "name": None,
            "status": "enable",
            "action": "accept",
            "srcintf": [],
            "dstintf": [],
            "srcaddr": [],
            "dstaddr": [],
            "service": [],
            "nat": "disable",
            "comments": "",
            "logtraffic": "utm",
            "utm_status": "disable",
        }
        i = start
        while i < len(tokens):
            ttype, tval = tokens[i]
            if ttype in ("next", "end"):
                break
            if ttype == "set":
                key, _, val = tval.partition(" ")
                key = key.lower()
                val = val.strip()
                if key == "name":
                    fields["name"] = val.strip('"')
                elif key == "status":
                    fields["status"] = val.lower()
                elif key == "action":
                    fields["action"] = val.lower()
                elif key == "srcintf":
                    fields["srcintf"] = _extract_quoted_list(val)
                elif key == "dstintf":
                    fields["dstintf"] = _extract_quoted_list(val)
                elif key == "srcaddr":
                    fields["srcaddr"] = _extract_quoted_list(val)
                elif key == "dstaddr":
                    fields["dstaddr"] = _extract_quoted_list(val)
                elif key == "service":
                    fields["service"] = _extract_quoted_list(val)
                elif key == "nat":
                    fields["nat"] = val.lower()
                elif key == "comments":
                    fields["comments"] = val.strip('"\'')
                elif key == "logtraffic":
                    fields["logtraffic"] = val.lower()
                elif key == "utm-status":
                    fields["utm_status"] = val.lower()
            i += 1

        # Skip to after "next"
        next_i = i + 1 if i < len(tokens) and tokens[i][0] == "next" else i

        # Resolve action
        action = FORTI_ACTION_MAP.get(fields["action"], "permit")
        enabled = fields["status"] == "enable"

        # Resolve source addresses
        src_addrs = self._resolve_addresses(fields["srcaddr"], table)
        dst_addrs = self._resolve_addresses(fields["dstaddr"], table)

        # Resolve services → service spec strings for normalization layer
        services = self._resolve_services(fields["service"], table)

        rule = VendorRule(
            name=fields["name"] or f"policy-{policy_id}",
            position=position,
            # Store numeric policy_id in vendor_tags for traceability
            # The name field is used as the rule identifier in the analysis engine
            enabled=enabled,
            source_zones=fields["srcintf"] if fields["srcintf"] else ["any"],
            destination_zones=fields["dstintf"] if fields["dstintf"] else ["any"],
            source_addresses=src_addrs,
            destination_addresses=dst_addrs,
            services=services,
            applications=["any"],
            action=action,
            description=fields.get("comments", ""),
            vendor_tags={
                "policy_id": policy_id,
                "nat": fields["nat"],
                "logtraffic": fields["logtraffic"],
                "utm_status": fields["utm_status"],
                "forti_action": fields["action"],
            },
        )
        return next_i, rule

    # ------------------------------------------------------------------
    # Object resolution helpers
    # ------------------------------------------------------------------

    def _resolve_addresses(
        self, addr_refs: list[str], table: ObjectTable
    ) -> list[str]:
        """
        Expand address object/group names to their constituent raw values.

        Returns a flat list of raw address strings (CIDRs, IPs, FQDNs).
        Unknown names are passed through as-is for the normalization layer.
        """
        if not addr_refs:
            return ["any"]
        resolved: list[str] = []
        for ref in addr_refs:
            if ref.lower() == "all":
                resolved.append("any")
            elif ref in table.address_objects:
                resolved.extend(table.address_objects[ref])
            elif ref in table.address_groups:
                # Recursively expand group members (one level)
                for member in table.address_groups[ref]:
                    if member in table.address_objects:
                        resolved.extend(table.address_objects[member])
                    elif member in table.address_groups:
                        # Two levels deep — flatten
                        for m2 in table.address_groups[member]:
                            if m2 in table.address_objects:
                                resolved.extend(table.address_objects[m2])
                            else:
                                resolved.append(m2)
                    else:
                        resolved.append(member)
            else:
                # Pass through — may be an inline CIDR or an unresolved ref
                resolved.append(ref)

        if not resolved:
            return ["any"]
        # Deduplicate while preserving order
        seen: set[str] = set()
        out: list[str] = []
        for v in resolved:
            if v not in seen:
                seen.add(v)
                out.append(v)
        return out

    def _resolve_services(
        self, svc_refs: list[str], table: ObjectTable
    ) -> list[str]:
        """
        Expand service object/group names to service spec strings.

        Returns strings in the format understood by the normalization layer:
          "any"          — matches all traffic
          "tcp:443"      — TCP port 443
          "udp:53"       — UDP port 53
          "tcp:8080-8090" — TCP port range
          "icmp"         — ICMP any type
        """
        if not svc_refs:
            return ["any"]
        specs: list[str] = []
        for ref in svc_refs:
            upper_ref = ref.upper()
            # Check well-known table first
            if upper_ref in FORTI_NAMED_SERVICES:
                info = FORTI_NAMED_SERVICES[upper_ref]
                proto = info["protocol"]
                ports = info["ports"]
                if proto == "any":
                    specs.append("any")
                elif ports == "any":
                    specs.append(proto)
                else:
                    specs.append(f"{proto}:{ports}")
            elif ref in table.service_objects:
                info = table.service_objects[ref]
                proto = info.get("protocol", "any")
                ports = info.get("ports", "any")
                if proto == "any":
                    specs.append("any")
                elif ports == "any":
                    specs.append(proto)
                else:
                    specs.append(f"{proto}:{ports}")
            elif ref in table.service_groups:
                # Recursively resolve group members
                member_specs = self._resolve_services(
                    table.service_groups[ref], table
                )
                specs.extend(member_specs)
            else:
                # Unknown service — pass through; normalization layer handles
                specs.append(ref)

        if not specs:
            return ["any"]
        seen: set[str] = set()
        out: list[str] = []
        for v in specs:
            if v not in seen:
                seen.add(v)
                out.append(v)
        return out

    # ------------------------------------------------------------------
    # Version detection
    # ------------------------------------------------------------------

    def _detect_version(self, raw_payload: str) -> Optional[str]:
        """
        Attempt to extract FortiOS version from config header.

        FortiOS config headers look like:
          #config-version=FGT60E-6.4.5-FW-build1828-210415:opmode=0:vdom=0:...
          #config-version=FG120G-7.4.11-FW-build2878-260126:...
        """
        for line in raw_payload.splitlines()[:10]:
            m = re.search(r"#config-version=\S+-(\d+\.\d+[\.\d]*)-FW", line)
            if m:
                return m.group(1)
            # Alternative: version in comments
            m2 = re.search(r"FortiGate[^\d]*(\d+\.\d+[\.\d]*)", line, re.IGNORECASE)
            if m2:
                return m2.group(1)
        return None
