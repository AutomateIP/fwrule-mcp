"""
Cisco ASA flat-text configuration parser.

Supported input: output of ``show running-config`` or a saved ASA config file.

Handles:
  - Extended ACLs: ``access-list <name> extended {permit|deny} ...``
  - Standard ACLs: ``access-list <name> standard {permit|deny} ...``
  - Network objects: ``object network <name>``
  - Network object-groups: ``object-group network <name>``
  - Service objects: ``object service <name>``
  - Service object-groups: ``object-group service <name> [tcp|udp|tcp-udp]``
  - Protocol object-groups: ``object-group protocol <name>``
  - ICMP object-groups: ``object-group icmp-type <name>``
  - Wildcard mask inversion (ASA uses 0.0.0.255 for /24 — we invert to CIDR)
  - Named services: http, https, ssh, ftp, telnet, smtp, dns, etc.
  - any / any4 / any6 keywords

Parsing strategy:
  Line-by-line state machine.  Multi-line constructs (object-group members,
  object definitions) are detected by indented continuation lines.  The state
  machine tracks the current ``context`` (which object/group is being defined).

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
# Named port / protocol resolution tables
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
    "klogin": 543,
    "kshell": 544,
    "bgp": 179,
    "irc": 194,
    "pim-auto-rp": 496,
    "pptp": 1723,
    "citrix-ica": 1494,
    "h323": 1720,
}

NAMED_PROTOCOLS: dict[str, str] = {
    "ip": "ip",
    "tcp": "tcp",
    "udp": "udp",
    "icmp": "icmp",
    "icmpv6": "icmpv6",
    "ospf": "89",
    "eigrp": "88",
    "gre": "47",
    "esp": "50",
    "ah": "51",
    "pim": "103",
    "igmp": "2",
}

ASA_ACTION_MAP: dict[str, str] = {
    "permit": "permit",
    "deny": "deny",
}


def _resolve_port(port_str: str) -> str:
    """
    Resolve a named port to its numeric string equivalent.
    Returns the original string if it is already numeric or unknown.
    """
    lower = port_str.lower()
    if lower in NAMED_PORTS:
        return str(NAMED_PORTS[lower])
    return port_str


def _wildcard_to_cidr(ip_str: str, wildcard_str: str) -> str:
    """
    Convert an ASA wildcard-mask address pair to CIDR notation.

    ASA uses inverted (wildcard) masks: 0.0.0.255 means /24.
    We invert the wildcard to get the regular subnet mask, then
    combine with the network address to produce a CIDR string.
    """
    try:
        # Invert wildcard to get subnet mask
        wc_int = int(ipaddress.IPv4Address(wildcard_str))
        mask_int = (~wc_int) & 0xFFFFFFFF
        # Zero out host bits in the base address
        ip_int = int(ipaddress.IPv4Address(ip_str))
        network_int = ip_int & mask_int
        network = ipaddress.IPv4Network(
            f"{ipaddress.IPv4Address(network_int)}/{ipaddress.IPv4Address(mask_int)}",
            strict=False,
        )
        return str(network)
    except (ValueError, ipaddress.AddressValueError):
        # Fall back to keeping original form; normalization layer will handle
        return f"{ip_str}/{wildcard_str}"


def _subnet_mask_to_cidr(ip_str: str, mask_str: str) -> str:
    """Convert a dotted-decimal subnet mask to CIDR notation."""
    try:
        network = ipaddress.IPv4Network(f"{ip_str}/{mask_str}", strict=False)
        return str(network)
    except ValueError:
        return f"{ip_str}/{mask_str}"


class ASAParser(VendorParser):
    """
    Parser for Cisco ASA flat-text configuration.
    """

    VENDOR = "asa"
    OS_FAMILIES: list[str] = []

    def supported_vendors(self) -> list[tuple[str, Optional[str]]]:
        return [("asa", None)]

    # ------------------------------------------------------------------
    # parse_policy
    # ------------------------------------------------------------------

    def parse_policy(
        self,
        raw_payload: str,
        context: Optional[dict[str, Any]] = None,
    ) -> ParsedPolicy:
        """
        Parse a full ASA running-configuration.

        Returns all ACL entries as VendorRules.  Access-group bindings (which
        ACL applies to which interface/direction) are preserved in vendor_tags
        for the normalization layer to use when mapping interfaces to zones.
        """
        warnings: list[str] = []
        lines = raw_payload.splitlines()

        # Pass 1 — extract all object/object-group definitions
        object_table = self._extract_objects(lines, warnings)

        # Pass 2 — extract ACL entries
        rules = self._extract_acl_rules(lines, object_table, warnings)

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
        """
        Parse a single ``access-list`` line as a candidate rule.
        """
        warnings: list[str] = []
        line = raw_rule.strip()
        rule = self._parse_acl_line(line, position=0, warnings=warnings)
        if rule is None:
            raise ValueError(f"Cannot parse ASA ACL line: {raw_rule!r}")
        return rule

    # ------------------------------------------------------------------
    # Object extraction — Pass 1
    # ------------------------------------------------------------------

    def _extract_objects(self, lines: list[str], warnings: list[str]) -> ObjectTable:
        """
        Walk configuration lines and extract all object/object-group definitions.
        """
        table = ObjectTable()
        i = 0
        while i < len(lines):
            line = lines[i]
            stripped = line.strip()

            # object network <name>
            m = re.match(r"^object\s+network\s+(\S+)\s*$", stripped)
            if m:
                name = m.group(1)
                i, values = self._parse_network_object_body(lines, i + 1)
                table.address_objects[name] = values
                continue

            # object-group network <name>
            m = re.match(r"^object-group\s+network\s+(\S+)\s*$", stripped)
            if m:
                name = m.group(1)
                i, members = self._parse_network_group_body(lines, i + 1, warnings)
                table.address_groups[name] = members
                continue

            # object service <name>
            m = re.match(r"^object\s+service\s+(\S+)\s*$", stripped)
            if m:
                name = m.group(1)
                i, svc_info = self._parse_service_object_body(lines, i + 1)
                if svc_info:
                    table.service_objects[name] = svc_info
                continue

            # object-group service <name> [tcp|udp|tcp-udp]
            m = re.match(r"^object-group\s+service\s+(\S+)(?:\s+(tcp|udp|tcp-udp|sctp))?\s*$", stripped)
            if m:
                name = m.group(1)
                default_proto = (m.group(2) or "").lower() or None
                i, members = self._parse_service_group_body(
                    lines, i + 1, default_proto, table, warnings
                )
                table.service_groups[name] = members
                continue

            # object-group protocol <name>
            m = re.match(r"^object-group\s+protocol\s+(\S+)\s*$", stripped)
            if m:
                name = m.group(1)
                i, members = self._parse_protocol_group_body(lines, i + 1)
                # Treat protocol groups as service groups with no port restriction
                table.service_groups[name] = members
                continue

            # object-group icmp-type <name>
            m = re.match(r"^object-group\s+icmp-type\s+(\S+)\s*$", stripped)
            if m:
                name = m.group(1)
                i, types = self._parse_icmp_group_body(lines, i + 1)
                # Store as service entries with protocol=icmp
                members = [f"icmp:{t}" for t in types]
                table.service_groups[name] = members
                continue

            i += 1

        return table

    def _parse_network_object_body(
        self, lines: list[str], start: int
    ) -> tuple[int, list[str]]:
        """Parse indented body lines of an `object network` block."""
        values: list[str] = []
        i = start
        while i < len(lines):
            line = lines[i]
            if not line.startswith(" ") and not line.startswith("\t"):
                break
            stripped = line.strip()
            if stripped.startswith("host "):
                values.append(stripped[5:].strip())
            elif stripped.startswith("subnet "):
                parts = stripped[7:].split()
                if len(parts) == 2:
                    values.append(_subnet_mask_to_cidr(parts[0], parts[1]))
            elif stripped.startswith("range "):
                parts = stripped[6:].split()
                if len(parts) == 2:
                    values.append(f"{parts[0]}-{parts[1]}")
            elif stripped.startswith("fqdn "):
                values.append(stripped[5:].strip())
            elif stripped.startswith("nat "):
                pass  # Skip NAT statements inside object network blocks
            i += 1
        return i, values

    def _parse_network_group_body(
        self, lines: list[str], start: int, warnings: list[str]
    ) -> tuple[int, list[str]]:
        """Parse indented body lines of an `object-group network` block."""
        members: list[str] = []
        i = start
        while i < len(lines):
            line = lines[i]
            if not line.startswith(" ") and not line.startswith("\t"):
                break
            stripped = line.strip()
            if stripped.startswith("network-object host "):
                members.append(stripped[20:].strip())
            elif stripped.startswith("network-object "):
                rest = stripped[15:].strip()
                parts = rest.split()
                if len(parts) == 2:
                    # ip mask form
                    members.append(_wildcard_to_cidr(parts[0], parts[1]))
                elif len(parts) == 1:
                    # Could be a prefix like 10.0.0.0/24 or an object name
                    members.append(parts[0])
            elif stripped.startswith("group-object "):
                members.append(stripped[13:].strip())
            elif stripped.startswith("description "):
                pass  # Skip description lines
            i += 1
        return i, members

    def _parse_service_object_body(
        self, lines: list[str], start: int
    ) -> tuple[int, dict[str, str]]:
        """Parse indented body of an `object service` block."""
        svc_info: dict[str, str] = {}
        i = start
        while i < len(lines):
            line = lines[i]
            if not line.startswith(" ") and not line.startswith("\t"):
                break
            stripped = line.strip()
            if stripped.startswith("service "):
                # service tcp destination eq 80
                # service udp destination range 8080 8090
                parts = stripped.split()
                if len(parts) >= 2:
                    proto = parts[1].lower()
                    svc_info["protocol"] = NAMED_PROTOCOLS.get(proto, proto)
                    # Look for destination port spec
                    port_spec = self._extract_port_spec_from_parts(parts[2:], "destination")
                    if port_spec:
                        svc_info["ports"] = port_spec
                    src_spec = self._extract_port_spec_from_parts(parts[2:], "source")
                    if src_spec:
                        svc_info["src_ports"] = src_spec
            i += 1
        return i, svc_info

    def _parse_service_group_body(
        self,
        lines: list[str],
        start: int,
        default_proto: Optional[str],
        table: ObjectTable,
        warnings: list[str],
    ) -> tuple[int, list[str]]:
        """
        Parse indented body of an `object-group service` block.

        Returns a list of synthetic service spec strings that the normalization
        layer can decode.  Format: "proto:port" or "proto:port_start-port_end"
        or just a group name for group-object references.
        """
        members: list[str] = []
        i = start
        while i < len(lines):
            line = lines[i]
            if not line.startswith(" ") and not line.startswith("\t"):
                break
            stripped = line.strip()

            if stripped.startswith("port-object eq "):
                port = _resolve_port(stripped[15:].strip())
                proto = default_proto or "tcp-udp"
                members.append(f"{proto}:{port}")
            elif stripped.startswith("port-object range "):
                parts = stripped[18:].strip().split()
                if len(parts) >= 2:
                    p_start = _resolve_port(parts[0])
                    p_end = _resolve_port(parts[1])
                    proto = default_proto or "tcp-udp"
                    members.append(f"{proto}:{p_start}-{p_end}")
            elif stripped.startswith("group-object "):
                members.append(stripped[13:].strip())
            elif stripped.startswith("service-object "):
                # service-object tcp destination eq https
                rest = stripped[15:].strip()
                parts = rest.split()
                if parts:
                    proto = NAMED_PROTOCOLS.get(parts[0].lower(), parts[0].lower())
                    port_spec = self._extract_port_spec_from_parts(parts[1:], "destination")
                    if port_spec:
                        members.append(f"{proto}:{port_spec}")
                    else:
                        members.append(proto)
            i += 1
        return i, members

    def _parse_protocol_group_body(
        self, lines: list[str], start: int
    ) -> tuple[int, list[str]]:
        """Parse body of an `object-group protocol` block."""
        members: list[str] = []
        i = start
        while i < len(lines):
            line = lines[i]
            if not line.startswith(" ") and not line.startswith("\t"):
                break
            stripped = line.strip()
            if stripped.startswith("protocol-object "):
                proto = stripped[16:].strip().lower()
                members.append(NAMED_PROTOCOLS.get(proto, proto))
            elif stripped.startswith("group-object "):
                members.append(stripped[13:].strip())
            i += 1
        return i, members

    def _parse_icmp_group_body(
        self, lines: list[str], start: int
    ) -> tuple[int, list[str]]:
        """Parse body of an `object-group icmp-type` block."""
        types: list[str] = []
        i = start
        while i < len(lines):
            line = lines[i]
            if not line.startswith(" ") and not line.startswith("\t"):
                break
            stripped = line.strip()
            if stripped.startswith("icmp-object "):
                types.append(stripped[12:].strip())
            elif stripped.startswith("group-object "):
                types.append(stripped[13:].strip())
            i += 1
        return i, types

    def _extract_port_spec_from_parts(
        self, parts: list[str], direction: str
    ) -> Optional[str]:
        """
        Extract port specification from a token list following a direction keyword.

        Example: ["destination", "eq", "443"]  → "443"
                 ["destination", "range", "8080", "8090"]  → "8080-8090"
                 ["source", "eq", "1024"]  → "1024" (if direction == "source")
        """
        # Find the direction keyword (or handle absent-direction shorthand)
        if direction in parts:
            idx = parts.index(direction)
            parts = parts[idx + 1:]
        elif "source" not in parts and "destination" not in parts:
            # No direction keywords — assume all remaining tokens are the spec
            pass
        else:
            return None

        if not parts:
            return None

        qualifier = parts[0].lower() if parts else ""
        if qualifier == "eq" and len(parts) >= 2:
            return _resolve_port(parts[1])
        elif qualifier == "range" and len(parts) >= 3:
            return f"{_resolve_port(parts[1])}-{_resolve_port(parts[2])}"
        elif qualifier == "lt" and len(parts) >= 2:
            return f"1-{_resolve_port(parts[1])}"
        elif qualifier == "gt" and len(parts) >= 2:
            start_port = int(_resolve_port(parts[1])) + 1
            return f"{start_port}-65535"
        elif qualifier == "neq":
            # Negated port — return None; normalization layer handles conservatively
            return None
        return None

    # ------------------------------------------------------------------
    # ACL rule extraction — Pass 2
    # ------------------------------------------------------------------

    def _extract_acl_rules(
        self,
        lines: list[str],
        table: ObjectTable,
        warnings: list[str],
    ) -> list[VendorRule]:
        """Extract all access-list extended/standard lines as VendorRules."""
        rules: list[VendorRule] = []
        position = 0
        for line in lines:
            stripped = line.strip()
            if re.match(r"^access-list\s+\S+\s+extended\s+", stripped):
                rule = self._parse_acl_line(stripped, position, warnings)
                if rule is not None:
                    rules.append(rule)
                    position += 1
            elif re.match(r"^access-list\s+\S+\s+standard\s+", stripped):
                rule = self._parse_standard_acl_line(stripped, position, warnings)
                if rule is not None:
                    rules.append(rule)
                    position += 1
        return rules

    def _parse_acl_line(
        self, line: str, position: int, warnings: list[str]
    ) -> Optional[VendorRule]:
        """
        Parse an extended ACL line.

        Grammar (simplified):
          access-list <name> extended {permit|deny} <protocol>
              <src-spec> [<src-port-spec>]
              <dst-spec> [<dst-port-spec>]
              [log [level] [interval <n>]]
              [inactive]

        Where <*-spec> is one of:
          any | any4 | any6
          host <ip>
          <ip> <wildcard>
          object <name>
          object-group <name>
          interface <name>
        """
        # Tokenize — remove remarks/comments
        if "remark" in line:
            return None

        parts = line.split()
        try:
            # access-list <name> extended <action> ...
            if len(parts) < 5:
                return None
            acl_name = parts[1]
            acl_type = parts[2].lower()
            if acl_type != "extended":
                return None
            action_str = parts[3].lower()
            action = ASA_ACTION_MAP.get(action_str, action_str)

            # Check for inactive flag
            enabled = "inactive" not in line.lower()

            idx = 4  # pointer into parts[]

            # Protocol
            proto, idx = self._consume_protocol(parts, idx)

            # Source address spec
            src_addrs, idx = self._consume_address_spec(parts, idx)

            # Source port spec (only for tcp/udp)
            src_ports_str: Optional[str] = None
            if proto in ("tcp", "udp", "tcp-udp") and idx < len(parts):
                src_port, idx = self._try_consume_port_spec(parts, idx)
                src_ports_str = src_port

            # Destination address spec
            dst_addrs, idx = self._consume_address_spec(parts, idx)

            # Destination port spec
            dst_ports_str: Optional[str] = None
            if proto in ("tcp", "udp", "tcp-udp", "sctp") and idx < len(parts):
                dst_port, idx = self._try_consume_port_spec(parts, idx)
                dst_ports_str = dst_port

            # Build service spec string
            services = self._build_service_spec(proto, dst_ports_str)
            vendor_tags: dict[str, Any] = {"acl_name": acl_name}
            if src_ports_str:
                vendor_tags["src_ports"] = src_ports_str

            return VendorRule(
                name=None,
                position=position,
                enabled=enabled,
                source_zones=["any"],
                destination_zones=["any"],
                source_addresses=src_addrs,
                destination_addresses=dst_addrs,
                services=services,
                applications=["any"],
                action=action,
                vendor_tags=vendor_tags,
            )

        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Skipping ACL line (parse error: {exc}): {line!r}")
            return None

    def _parse_standard_acl_line(
        self, line: str, position: int, warnings: list[str]
    ) -> Optional[VendorRule]:
        """
        Parse a standard ACL line (source address only, no destination or port).
        """
        parts = line.split()
        try:
            if len(parts) < 5:
                return None
            acl_name = parts[1]
            action_str = parts[3].lower()
            action = ASA_ACTION_MAP.get(action_str, action_str)
            enabled = "inactive" not in line.lower()
            idx = 4
            src_addrs, idx = self._consume_address_spec(parts, idx)
            return VendorRule(
                name=None,
                position=position,
                enabled=enabled,
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
            warnings.append(f"Skipping standard ACL line ({exc}): {line!r}")
            return None

    def _consume_protocol(self, parts: list[str], idx: int) -> tuple[str, int]:
        """
        Consume a protocol token and return (protocol_str, new_idx).

        Handles named protocols and numeric protocol numbers.
        """
        if idx >= len(parts):
            return "ip", idx
        token = parts[idx].lower()
        if token == "object-group":
            # object-group <name> — return group name as protocol reference
            idx += 1
            if idx < len(parts):
                return parts[idx], idx + 1
            return "any", idx
        if token == "object":
            idx += 1
            if idx < len(parts):
                return parts[idx], idx + 1
            return "any", idx
        proto = NAMED_PROTOCOLS.get(token, token)
        return proto, idx + 1

    def _consume_address_spec(
        self, parts: list[str], idx: int
    ) -> tuple[list[str], int]:
        """
        Consume an address specification and return ([addr_strings], new_idx).

        Handles:
          any | any4 | any6             → ["any"]
          host <ip>                     → ["<ip>"]
          <ip> <wildcard>               → ["<cidr>"]
          object <name>                 → ["<name>"]   (object reference)
          object-group <name>           → ["<name>"]   (group reference)
          interface <iface>             → ["interface:<iface>"]
        """
        if idx >= len(parts):
            return ["any"], idx

        token = parts[idx].lower()

        if token in ("any", "any4", "any6"):
            return ["any"], idx + 1

        if token == "host":
            if idx + 1 < len(parts):
                return [parts[idx + 1]], idx + 2
            return ["any"], idx + 1

        if token in ("object-group", "object"):
            if idx + 1 < len(parts):
                return [parts[idx + 1]], idx + 2
            return ["any"], idx + 1

        if token == "interface":
            if idx + 1 < len(parts):
                return [f"interface:{parts[idx + 1]}"], idx + 2
            return ["any"], idx + 1

        # Try <ip> <wildcard/mask>  (two tokens)
        if idx + 1 < len(parts) and self._looks_like_ip(token) and self._looks_like_ip(parts[idx + 1]):
            cidr = _wildcard_to_cidr(token, parts[idx + 1])
            return [cidr], idx + 2

        # Try bare CIDR (one token)
        if "/" in token or self._looks_like_ip(token):
            return [token], idx + 1

        return ["any"], idx

    def _try_consume_port_spec(
        self, parts: list[str], idx: int
    ) -> tuple[Optional[str], int]:
        """
        Attempt to consume a port specification.  Returns (port_str, new_idx)
        where port_str is None if no port spec was found at this position.
        """
        if idx >= len(parts):
            return None, idx

        qualifier = parts[idx].lower()
        if qualifier not in ("eq", "neq", "lt", "gt", "range"):
            return None, idx

        if qualifier == "eq" and idx + 1 < len(parts):
            return _resolve_port(parts[idx + 1]), idx + 2
        elif qualifier == "range" and idx + 2 < len(parts):
            return f"{_resolve_port(parts[idx + 1])}-{_resolve_port(parts[idx + 2])}", idx + 3
        elif qualifier == "lt" and idx + 1 < len(parts):
            end = int(_resolve_port(parts[idx + 1])) - 1
            return f"1-{end}", idx + 2
        elif qualifier == "gt" and idx + 1 < len(parts):
            start = int(_resolve_port(parts[idx + 1])) + 1
            return f"{start}-65535", idx + 2
        elif qualifier == "neq":
            # Negated port — skip the qualifier and port token
            return None, idx + 2

        return None, idx

    def _build_service_spec(
        self, protocol: str, port_spec: Optional[str]
    ) -> list[str]:
        """Build a service specification list from protocol and port strings."""
        proto_lower = protocol.lower()
        if proto_lower == "ip" or proto_lower == "any":
            return ["any"]
        if port_spec:
            return [f"{proto_lower}:{port_spec}"]
        return [proto_lower]

    def _looks_like_ip(self, token: str) -> bool:
        """Return True if the token looks like a dotted-decimal IPv4 address."""
        return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", token))

    def _detect_version(self, lines: list[str]) -> Optional[str]:
        """Extract ASA software version from config header comments."""
        for line in lines[:20]:
            m = re.match(r"^:\s*Saved|^ASA Version\s+(\S+)", line)
            if m and m.group(1):
                return m.group(1)
            m2 = re.match(r"^!\s*ASA\s+Version\s+(\S+)", line, re.IGNORECASE)
            if m2:
                return m2.group(1)
        return None
