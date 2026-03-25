"""
Cisco IOS / IOS-XE flat-text configuration parser.

Supported input: output of ``show running-config`` or a saved config file.

Handles:
  - Standard numbered ACLs:
      access-list <num> {permit|deny} <source> [<wildcard>]
  - Extended numbered ACLs:
      access-list <num> {permit|deny} <protocol> <src> <src-wc> <dst> <dst-wc>
      [eq|range|gt|lt <port>]
  - Named extended ACLs:
      ip access-list extended <name>
       permit tcp 10.0.0.0 0.0.0.255 any eq 80
       deny ip any any
  - Named standard ACLs:
      ip access-list standard <name>
       permit 10.0.0.0 0.0.0.255
       deny any
  - IOS-XE object-group network:
      object-group network SERVERS
       host 10.1.1.1
       10.1.2.0 0.0.0.255
       description Some servers
  - IOS-XE object-group service:
      object-group service WEB_PORTS
       tcp eq www
       tcp range 8080 8090
  - Keywords: any, host <ip>, wildcard masks (inverted to CIDR)
  - Named ports: www=80, https=443, ssh=22, etc.

Parsing strategy:
  Line-by-line state machine.  Named ACL bodies are detected by indented
  continuation lines.  Numbered ACLs are parsed in a single pass.

Action mapping:
  permit → permit
  deny   → deny
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
# Named port resolution table (shared with ASA-style parsers)
# ---------------------------------------------------------------------------

NAMED_PORTS: dict[str, int] = {
    "ftp-data": 20,
    "ftp": 21,
    "ssh": 22,
    "telnet": 23,
    "smtp": 25,
    "domain": 53,
    "dns": 53,
    "bootps": 67,
    "bootpc": 68,
    "tftp": 69,
    "http": 80,
    "www": 80,
    "pop2": 109,
    "pop3": 110,
    "sunrpc": 111,
    "ident": 113,
    "nntp": 119,
    "ntp": 123,
    "netbios-ns": 137,
    "netbios-dgm": 138,
    "netbios-ssn": 139,
    "imap4": 143,
    "snmp": 161,
    "snmptrap": 162,
    "ldap": 389,
    "https": 443,
    "smtps": 465,
    "syslog": 514,
    "ldaps": 636,
    "imap": 143,
    "imaps": 993,
    "pop3s": 995,
    "mssql": 1433,
    "oracle": 1521,
    "radius": 1812,
    "radius-acct": 1813,
    "nfs": 2049,
    "rdp": 3389,
    "mysql": 3306,
    "sip": 5060,
    "sips": 5061,
    "vnc": 5900,
    "kerberos": 88,
    "bgp": 179,
    "irc": 194,
    "pptp": 1723,
    "cmd": 514,
    "exec": 512,
    "login": 513,
    "tacacs": 49,
    "pim-auto-rp": 496,
    "echo": 7,
    "discard": 9,
    "chargen": 19,
    "daytime": 13,
    "time": 37,
    "whois": 43,
    "gopher": 70,
    "finger": 79,
}

NAMED_PROTOCOLS: dict[str, str] = {
    "ip": "ip",
    "tcp": "tcp",
    "udp": "udp",
    "icmp": "icmp",
    "icmpv6": "icmpv6",
    "ipv6": "ipv6",
    "ospf": "89",
    "eigrp": "88",
    "gre": "47",
    "esp": "50",
    "ahp": "51",
    "ah": "51",
    "pim": "103",
    "igmp": "2",
    "nos": "94",
    "igrp": "9",
}

IOS_ACTION_MAP: dict[str, str] = {
    "permit": "permit",
    "deny": "deny",
}


def _resolve_port(port_str: str) -> str:
    """Resolve a named port to its numeric string equivalent."""
    lower = port_str.lower()
    if lower in NAMED_PORTS:
        return str(NAMED_PORTS[lower])
    return port_str


def _wildcard_to_cidr(ip_str: str, wildcard_str: str) -> str:
    """
    Convert an IOS wildcard-mask address pair to CIDR notation.

    IOS uses inverted (wildcard) masks: 0.0.0.255 means /24.
    """
    try:
        wc_int = int(ipaddress.IPv4Address(wildcard_str))
        mask_int = (~wc_int) & 0xFFFFFFFF
        ip_int = int(ipaddress.IPv4Address(ip_str))
        network_int = ip_int & mask_int
        network = ipaddress.IPv4Network(
            f"{ipaddress.IPv4Address(network_int)}/{ipaddress.IPv4Address(mask_int)}",
            strict=False,
        )
        return str(network)
    except (ValueError, ipaddress.AddressValueError):
        return f"{ip_str}/{wildcard_str}"


def _looks_like_ip(token: str) -> bool:
    """Return True if the token looks like a dotted-decimal IPv4 address."""
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", token))


class IOSParser(VendorParser):
    """
    Parser for Cisco IOS / IOS-XE running-configuration text.

    Handles both numbered and named ACLs, as well as IOS-XE object-groups.
    """

    VENDOR = "ios"
    OS_FAMILIES: list[str] = []

    def supported_vendors(self) -> list[tuple[str, Optional[str]]]:
        return [("ios", None)]

    # ------------------------------------------------------------------
    # parse_policy
    # ------------------------------------------------------------------

    def parse_policy(
        self,
        raw_payload: str,
        context: Optional[dict[str, Any]] = None,
    ) -> ParsedPolicy:
        """Parse a full IOS/IOS-XE running-configuration."""
        warnings: list[str] = []
        lines = raw_payload.splitlines()

        # Pass 1 — extract object-group definitions
        object_table = self._extract_objects(lines, warnings)

        # Pass 2 — extract ACL rules (numbered + named)
        rules = self._extract_rules(lines, object_table, warnings)

        return ParsedPolicy(
            rules=rules,
            object_table=object_table,
            vendor=self.VENDOR,
            os_version=self._detect_version(lines),
            warnings=warnings,
        )

    def parse_single_rule(
        self,
        raw_rule: str,
        object_table: Optional[ObjectTable] = None,
    ) -> VendorRule:
        """Parse a single IOS ACL line or named ACL entry as a candidate rule."""
        warnings: list[str] = []
        lines = raw_rule.strip().splitlines()

        # Try as a numbered ACL line first
        for line in lines:
            stripped = line.strip()
            rule = self._parse_numbered_acl_line(stripped, position=0, warnings=warnings)
            if rule is not None:
                return rule

        # Try as a named ACL entry (indented style or bare action line)
        for line in lines:
            stripped = line.strip()
            if re.match(r"^(permit|deny)\s+", stripped, re.IGNORECASE):
                rule = self._parse_named_acl_entry(
                    stripped, acl_name="<candidate>", acl_type="extended",
                    position=0, warnings=warnings
                )
                if rule is not None:
                    return rule

        raise ValueError(f"Cannot parse IOS ACL line: {raw_rule!r}")

    # ------------------------------------------------------------------
    # Object extraction — Pass 1
    # ------------------------------------------------------------------

    def _extract_objects(self, lines: list[str], warnings: list[str]) -> ObjectTable:
        """Extract object-group definitions from the configuration."""
        table = ObjectTable()
        i = 0
        while i < len(lines):
            line = lines[i]
            stripped = line.strip()

            # object-group network <name>
            m = re.match(r"^object-group\s+network\s+(\S+)\s*$", stripped, re.IGNORECASE)
            if m:
                name = m.group(1)
                i, members = self._parse_network_group_body(lines, i + 1, warnings)
                table.address_groups[name] = members
                continue

            # object-group service <name> [tcp|udp|tcp-udp]
            m = re.match(
                r"^object-group\s+service\s+(\S+)(?:\s+(tcp|udp|tcp-udp|sctp))?\s*$",
                stripped, re.IGNORECASE
            )
            if m:
                name = m.group(1)
                default_proto = (m.group(2) or "").lower() or None
                i, members = self._parse_service_group_body(lines, i + 1, default_proto, warnings)
                table.service_groups[name] = members
                continue

            i += 1

        return table

    def _parse_network_group_body(
        self, lines: list[str], start: int, warnings: list[str]
    ) -> tuple[int, list[str]]:
        """Parse indented body of an object-group network block."""
        members: list[str] = []
        i = start
        while i < len(lines):
            line = lines[i]
            if not line.startswith(" ") and not line.startswith("\t"):
                break
            stripped = line.strip()
            if not stripped or stripped.startswith("description") or stripped.startswith("!"):
                i += 1
                continue
            if stripped.startswith("host "):
                members.append(stripped[5:].strip())
            elif stripped.startswith("group-object "):
                members.append(stripped[13:].strip())
            else:
                # Could be "10.1.2.0 0.0.0.255" (address + wildcard) or "10.0.0.0/24"
                parts = stripped.split()
                if len(parts) == 2 and _looks_like_ip(parts[0]) and _looks_like_ip(parts[1]):
                    members.append(_wildcard_to_cidr(parts[0], parts[1]))
                elif len(parts) == 1:
                    members.append(parts[0])
            i += 1
        return i, members

    def _parse_service_group_body(
        self,
        lines: list[str],
        start: int,
        default_proto: Optional[str],
        warnings: list[str],
    ) -> tuple[int, list[str]]:
        """Parse indented body of an object-group service block."""
        members: list[str] = []
        i = start
        while i < len(lines):
            line = lines[i]
            if not line.startswith(" ") and not line.startswith("\t"):
                break
            stripped = line.strip()
            if not stripped or stripped.startswith("description") or stripped.startswith("!"):
                i += 1
                continue
            if stripped.startswith("group-object "):
                members.append(stripped[13:].strip())
            else:
                # Formats: "tcp eq www", "tcp range 8080 8090", "udp eq 53"
                parts = stripped.split()
                if parts:
                    proto = NAMED_PROTOCOLS.get(parts[0].lower(), parts[0].lower())
                    port_spec = self._extract_port_spec(parts[1:])
                    if port_spec:
                        members.append(f"{proto}:{port_spec}")
                    else:
                        members.append(proto)
            i += 1
        return i, members

    def _extract_port_spec(self, parts: list[str]) -> Optional[str]:
        """Extract a port spec from tokens like ['eq', 'www'] or ['range', '80', '443']."""
        if not parts:
            return None
        qualifier = parts[0].lower()
        if qualifier == "eq" and len(parts) >= 2:
            return _resolve_port(parts[1])
        elif qualifier == "range" and len(parts) >= 3:
            return f"{_resolve_port(parts[1])}-{_resolve_port(parts[2])}"
        elif qualifier == "lt" and len(parts) >= 2:
            end = int(_resolve_port(parts[1])) - 1
            return f"1-{end}"
        elif qualifier == "gt" and len(parts) >= 2:
            start = int(_resolve_port(parts[1])) + 1
            return f"{start}-65535"
        return None

    # ------------------------------------------------------------------
    # Rule extraction — Pass 2
    # ------------------------------------------------------------------

    def _extract_rules(
        self,
        lines: list[str],
        table: ObjectTable,
        warnings: list[str],
    ) -> list[VendorRule]:
        """Extract all ACL entries from both numbered and named ACL forms."""
        rules: list[VendorRule] = []
        position = 0
        i = 0

        while i < len(lines):
            line = lines[i]
            stripped = line.strip()

            # Skip comments / blank lines
            if not stripped or stripped.startswith("!") or stripped.startswith("#"):
                i += 1
                continue

            # Numbered ACL: "access-list <num|name> ..."
            if re.match(r"^access-list\s+", stripped, re.IGNORECASE):
                rule = self._parse_numbered_acl_line(stripped, position, warnings)
                if rule is not None:
                    rules.append(rule)
                    position += 1
                i += 1
                continue

            # Named ACL header: "ip access-list {extended|standard} <name>"
            # Also matches "show access-lists" output: "Extended IP access list <name>"
            m = re.match(
                r"^ip\s+access-list\s+(extended|standard)\s+(\S+)\s*$",
                stripped, re.IGNORECASE
            ) or re.match(
                r"^(Extended|Standard)\s+IP\s+access\s+list\s+(\S+)\s*$",
                stripped, re.IGNORECASE
            )
            if m:
                acl_type = m.group(1).lower()
                acl_name = m.group(2)
                i += 1
                # Consume indented body lines
                while i < len(lines):
                    body_line = lines[i]
                    body_stripped = body_line.strip()
                    # End of body when non-indented, non-empty, non-remark line appears
                    if (body_stripped
                            and not body_line.startswith(" ")
                            and not body_line.startswith("\t")
                            and not body_stripped.startswith("!")):
                        break
                    if body_stripped and not body_stripped.startswith("!"):
                        # Skip sequence numbers (IOS-XE sometimes adds them)
                        entry = re.sub(r"^\d+\s+", "", body_stripped)
                        # Skip 'remark' lines
                        if entry.lower().startswith("remark"):
                            i += 1
                            continue
                        rule = self._parse_named_acl_entry(
                            entry, acl_name, acl_type, position, warnings
                        )
                        if rule is not None:
                            rules.append(rule)
                            position += 1
                    i += 1
                continue

            i += 1

        return rules

    # ------------------------------------------------------------------
    # Numbered ACL line parser
    # ------------------------------------------------------------------

    def _parse_numbered_acl_line(
        self, line: str, position: int, warnings: list[str]
    ) -> Optional[VendorRule]:
        """
        Parse a numbered ACL line.

        Formats:
          Standard: access-list <num> {permit|deny} <src> [<wildcard>]
          Extended: access-list <num> {permit|deny} <proto> <src> <wc> <dst> <wc>
                    [eq|range <port>]
        """
        if "remark" in line.lower():
            return None

        m = re.match(r"^access-list\s+(\S+)\s+(permit|deny)\s+(.+)$", line, re.IGNORECASE)
        if not m:
            return None

        acl_name = m.group(1)
        action_str = m.group(2).lower()
        action = IOS_ACTION_MAP.get(action_str, action_str)
        rest = m.group(3).split()

        if not rest:
            return None

        # Determine if this is extended (first token is a protocol keyword or number)
        first_token = rest[0].lower()
        is_extended = (
            first_token in NAMED_PROTOCOLS
            or first_token.isdigit()
        )

        try:
            if is_extended:
                return self._parse_extended_tokens(
                    rest, acl_name, action, position, warnings
                )
            else:
                # Standard ACL — source only
                src_addrs, _ = self._consume_address(rest, 0)
                return VendorRule(
                    name=None,
                    position=position,
                    enabled=True,
                    source_zones=["any"],
                    destination_zones=["any"],
                    source_addresses=src_addrs,
                    destination_addresses=["any"],
                    services=["any"],
                    applications=["any"],
                    action=action,
                    vendor_tags={"acl_name": acl_name, "acl_type": "standard"},
                )
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"[ios] Skipping ACL line (parse error: {exc}): {line!r}")
            return None

    # ------------------------------------------------------------------
    # Named ACL entry parser
    # ------------------------------------------------------------------

    def _parse_named_acl_entry(
        self,
        entry: str,
        acl_name: str,
        acl_type: str,
        position: int,
        warnings: list[str],
    ) -> Optional[VendorRule]:
        """
        Parse a single entry from within a named ACL body.

        Extended entry format:
          {permit|deny} <protocol> <src-spec> [<src-port>] <dst-spec> [<dst-port>]
        Standard entry format:
          {permit|deny} <src-spec>
        """
        m = re.match(r"^(permit|deny)\s+(.+)$", entry, re.IGNORECASE)
        if not m:
            return None

        action_str = m.group(1).lower()
        action = IOS_ACTION_MAP.get(action_str, action_str)
        rest = m.group(2).split()

        if not rest:
            return None

        try:
            if acl_type == "standard":
                src_addrs, _ = self._consume_address(rest, 0)
                return VendorRule(
                    name=None,
                    position=position,
                    enabled=True,
                    source_zones=["any"],
                    destination_zones=["any"],
                    source_addresses=src_addrs,
                    destination_addresses=["any"],
                    services=["any"],
                    applications=["any"],
                    action=action,
                    vendor_tags={"acl_name": acl_name, "acl_type": "standard"},
                )
            else:
                # Extended
                return self._parse_extended_tokens(
                    rest, acl_name, action, position, warnings
                )
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"[ios] Skipping named ACL entry (parse error: {exc}): {entry!r}")
            return None

    def _parse_extended_tokens(
        self,
        tokens: list[str],
        acl_name: str,
        action: str,
        position: int,
        warnings: list[str],
    ) -> Optional[VendorRule]:
        """
        Parse the token list for an extended ACL entry starting with protocol.
        """
        idx = 0

        # Protocol
        proto_token = tokens[idx].lower()
        if proto_token == "object-group" and idx + 1 < len(tokens):
            proto = tokens[idx + 1]
            idx += 2
        else:
            proto = NAMED_PROTOCOLS.get(proto_token, proto_token)
            idx += 1

        # Source address
        src_addrs, idx = self._consume_address(tokens, idx)

        # Source port (only for tcp/udp)
        src_port_str: Optional[str] = None
        if proto in ("tcp", "udp") and idx < len(tokens):
            src_port_str, idx = self._try_consume_port(tokens, idx)

        # Destination address
        dst_addrs, idx = self._consume_address(tokens, idx)

        # Destination port
        dst_port_str: Optional[str] = None
        if proto in ("tcp", "udp", "sctp") and idx < len(tokens):
            dst_port_str, idx = self._try_consume_port(tokens, idx)

        services = self._build_service(proto, dst_port_str)
        vendor_tags: dict[str, Any] = {"acl_name": acl_name}
        if src_port_str:
            vendor_tags["src_ports"] = src_port_str

        return VendorRule(
            name=None,
            position=position,
            enabled=True,
            source_zones=["any"],
            destination_zones=["any"],
            source_addresses=src_addrs,
            destination_addresses=dst_addrs,
            services=services,
            applications=["any"],
            action=action,
            vendor_tags=vendor_tags,
        )

    def _consume_address(
        self, tokens: list[str], idx: int
    ) -> tuple[list[str], int]:
        """
        Consume an address specification and return ([addr_strings], new_idx).

        Handles:
          any                      → ["any"]
          host <ip>                → ["<ip>"]
          <ip> <wildcard>          → ["<cidr>"]
          object-group <name>      → ["<name>"]
          <ip/cidr>                → ["<ip/cidr>"]
        """
        if idx >= len(tokens):
            return ["any"], idx

        token = tokens[idx].lower()

        if token in ("any", "any4", "any6"):
            return ["any"], idx + 1

        if token == "host":
            if idx + 1 < len(tokens):
                return [tokens[idx + 1]], idx + 2
            return ["any"], idx + 1

        if token == "object-group":
            if idx + 1 < len(tokens):
                return [tokens[idx + 1]], idx + 2
            return ["any"], idx + 1

        # Check for <ip> <wildcard> (two dotted-decimal tokens)
        if _looks_like_ip(tokens[idx]) and idx + 1 < len(tokens) and _looks_like_ip(tokens[idx + 1]):
            cidr = _wildcard_to_cidr(tokens[idx], tokens[idx + 1])
            return [cidr], idx + 2

        # Bare CIDR or host
        if "/" in tokens[idx] or _looks_like_ip(tokens[idx]):
            return [tokens[idx]], idx + 1

        return ["any"], idx

    def _try_consume_port(
        self, tokens: list[str], idx: int
    ) -> tuple[Optional[str], int]:
        """Attempt to consume eq/range/lt/gt port spec. Returns (spec, new_idx)."""
        if idx >= len(tokens):
            return None, idx

        qualifier = tokens[idx].lower()
        if qualifier not in ("eq", "range", "lt", "gt", "neq"):
            return None, idx

        if qualifier == "eq" and idx + 1 < len(tokens):
            return _resolve_port(tokens[idx + 1]), idx + 2
        elif qualifier == "range" and idx + 2 < len(tokens):
            return (
                f"{_resolve_port(tokens[idx + 1])}-{_resolve_port(tokens[idx + 2])}",
                idx + 3,
            )
        elif qualifier == "lt" and idx + 1 < len(tokens):
            end = int(_resolve_port(tokens[idx + 1])) - 1
            return f"1-{end}", idx + 2
        elif qualifier == "gt" and idx + 1 < len(tokens):
            start = int(_resolve_port(tokens[idx + 1])) + 1
            return f"{start}-65535", idx + 2
        elif qualifier == "neq":
            # Negated port — skip token + port value; treat as any
            return None, idx + 2

        return None, idx

    def _build_service(self, protocol: str, port_spec: Optional[str]) -> list[str]:
        """Build service spec list from protocol and optional port."""
        proto_lower = protocol.lower()
        if proto_lower in ("ip", "any", "0"):
            return ["any"]
        if port_spec:
            return [f"{proto_lower}:{port_spec}"]
        return [proto_lower]

    # ------------------------------------------------------------------
    # Version detection
    # ------------------------------------------------------------------

    def _detect_version(self, lines: list[str]) -> Optional[str]:
        """Extract IOS version from config header."""
        for line in lines[:30]:
            # "! IOS Software, Version 15.2(4)M3"
            m = re.search(
                r"(?:IOS(?:-XE)?\s+(?:Software[,\s]+)?(?:Version\s+)?)(\d+[\w.()]+)",
                line, re.IGNORECASE
            )
            if m:
                return m.group(1)
            # "version 15.2"
            m2 = re.match(r"^version\s+(\S+)", line, re.IGNORECASE)
            if m2:
                return m2.group(1)
        return None
