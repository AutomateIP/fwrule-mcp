"""
Cisco IOS-XR flat-text configuration parser.

Supported input: output of ``show running-config`` from IOS-XR devices.

Handles:
  - IPv4 named ACLs:
      ipv4 access-list OUTSIDE_IN
       10 permit tcp any host 10.1.1.1 eq www
       20 deny ipv4 any any
  - IPv6 named ACLs:
      ipv6 access-list INSIDE_V6
       10 permit tcp 2001:db8::/32 any eq 443
  - Sequence numbers on ACL lines (10, 20, 30 ...)
  - Object-group network (ipv4 and ipv6):
      object-group network ipv4 SERVERS
       host 10.1.1.1
       10.1.2.0/24
  - Object-group port:
      object-group port WEB_PORTS
       eq www
       range 8080 8089
  - Keywords: any, host <ip>, CIDR notation (not wildcard masks)
  - Named ports: same table as IOS parser

Key differences from IOS:
  - Uses ``ipv4`` keyword instead of ``ip`` for protocol in ACL entries
  - Prefers CIDR notation (10.0.0.0/24) over wildcard masks
  - Sequence numbers on every ACL entry line
  - object-group network uses ``ipv4`` or ``ipv6`` qualifier

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
# Port / protocol tables (reuse IOS-style names)
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
    "pptp": 1723,
    "tacacs": 49,
}

# IOS-XR protocol names (ipv4 is the catch-all like "ip" in IOS)
NAMED_PROTOCOLS: dict[str, str] = {
    "ipv4": "ip",
    "ipv6": "ipv6",
    "ip": "ip",
    "tcp": "tcp",
    "udp": "udp",
    "icmp": "icmp",
    "icmpv6": "icmpv6",
    "ospf": "89",
    "eigrp": "88",
    "gre": "47",
    "esp": "50",
    "ahp": "51",
    "pim": "103",
    "igmp": "2",
    "rsvp": "46",
    "sctp": "132",
    "nos": "94",
}

IOSXR_ACTION_MAP: dict[str, str] = {
    "permit": "permit",
    "deny": "deny",
}


def _resolve_port(port_str: str) -> str:
    """Resolve a named port to its numeric string equivalent."""
    lower = port_str.lower()
    if lower in NAMED_PORTS:
        return str(NAMED_PORTS[lower])
    return port_str


def _looks_like_ip(token: str) -> bool:
    """Return True if the token looks like a dotted-decimal IPv4 address."""
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", token))


def _looks_like_ipv6(token: str) -> bool:
    """Return True if the token looks like an IPv6 address (contains colon)."""
    return ":" in token


class IOSXRParser(VendorParser):
    """
    Parser for Cisco IOS-XR running-configuration text.

    Handles IPv4/IPv6 ACLs with sequence numbers and XR-style object-groups.
    """

    VENDOR = "iosxr"
    OS_FAMILIES: list[str] = []

    def supported_vendors(self) -> list[tuple[str, Optional[str]]]:
        return [("iosxr", None)]

    # ------------------------------------------------------------------
    # parse_policy
    # ------------------------------------------------------------------

    def parse_policy(
        self,
        raw_payload: str,
        context: Optional[dict[str, Any]] = None,
    ) -> ParsedPolicy:
        """Parse a full IOS-XR running-configuration."""
        warnings: list[str] = []
        lines = raw_payload.splitlines()

        # Pass 1 — extract object-group definitions
        object_table = self._extract_objects(lines, warnings)

        # Pass 2 — extract ACL rules
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
        """Parse a single IOS-XR ACL entry as a candidate rule."""
        warnings: list[str] = []
        lines = raw_rule.strip().splitlines()

        for line in lines:
            stripped = line.strip()
            # Strip leading sequence number if present
            stripped = re.sub(r"^\d+\s+", "", stripped)
            if re.match(r"^(permit|deny)\s+", stripped, re.IGNORECASE):
                rule = self._parse_acl_entry(
                    stripped, acl_name="<candidate>",
                    acl_family="ipv4", position=0, warnings=warnings
                )
                if rule is not None:
                    return rule

        raise ValueError(f"Cannot parse IOS-XR ACL entry: {raw_rule!r}")

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

            # object-group network [ipv4|ipv6] <name>
            m = re.match(
                r"^object-group\s+network\s+(?:ipv[46]\s+)?(\S+)\s*$",
                stripped, re.IGNORECASE
            )
            if m:
                name = m.group(1)
                i, members = self._parse_network_group_body(lines, i + 1, warnings)
                table.address_groups[name] = members
                continue

            # object-group port <name>
            m = re.match(r"^object-group\s+port\s+(\S+)\s*$", stripped, re.IGNORECASE)
            if m:
                name = m.group(1)
                i, members = self._parse_port_group_body(lines, i + 1, warnings)
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
                # Could be CIDR "10.0.0.0/24", IPv6 "2001:db8::/32", or bare host
                parts = stripped.split()
                if parts:
                    members.append(parts[0])
            i += 1
        return i, members

    def _parse_port_group_body(
        self, lines: list[str], start: int, warnings: list[str]
    ) -> tuple[int, list[str]]:
        """Parse indented body of an object-group port block."""
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
            parts = stripped.split()
            if not parts:
                i += 1
                continue
            # IOS-XR port group entries: "eq www", "range 8080 8089"
            qualifier = parts[0].lower()
            if qualifier == "eq" and len(parts) >= 2:
                members.append(f"tcp-udp:{_resolve_port(parts[1])}")
            elif qualifier == "range" and len(parts) >= 3:
                members.append(
                    f"tcp-udp:{_resolve_port(parts[1])}-{_resolve_port(parts[2])}"
                )
            elif parts[0].lower() == "group-object" and len(parts) >= 2:
                members.append(parts[1])
            i += 1
        return i, members

    # ------------------------------------------------------------------
    # Rule extraction — Pass 2
    # ------------------------------------------------------------------

    def _extract_rules(
        self,
        lines: list[str],
        table: ObjectTable,
        warnings: list[str],
    ) -> list[VendorRule]:
        """Extract all ACL entries from IPv4/IPv6 named ACLs."""
        rules: list[VendorRule] = []
        position = 0
        i = 0

        while i < len(lines):
            line = lines[i]
            stripped = line.strip()

            if not stripped or stripped.startswith("!") or stripped.startswith("#"):
                i += 1
                continue

            # IPv4 ACL header: "ipv4 access-list <name>"
            m4 = re.match(r"^ipv4\s+access-list\s+(\S+)\s*$", stripped, re.IGNORECASE)
            # IPv6 ACL header: "ipv6 access-list <name>"
            m6 = re.match(r"^ipv6\s+access-list\s+(\S+)\s*$", stripped, re.IGNORECASE)

            if m4 or m6:
                acl_name = (m4 or m6).group(1)  # type: ignore[union-attr]
                acl_family = "ipv4" if m4 else "ipv6"
                i += 1

                while i < len(lines):
                    body_line = lines[i]
                    body_stripped = body_line.strip()

                    if (body_stripped
                            and not body_line.startswith(" ")
                            and not body_line.startswith("\t")
                            and not body_stripped.startswith("!")):
                        break

                    if body_stripped and not body_stripped.startswith("!"):
                        # Strip leading sequence number
                        entry = re.sub(r"^\d+\s+", "", body_stripped)
                        if entry.lower().startswith("remark"):
                            i += 1
                            continue
                        rule = self._parse_acl_entry(
                            entry, acl_name, acl_family, position, warnings
                        )
                        if rule is not None:
                            rules.append(rule)
                            position += 1
                    i += 1
                continue

            i += 1

        return rules

    def _parse_acl_entry(
        self,
        entry: str,
        acl_name: str,
        acl_family: str,
        position: int,
        warnings: list[str],
    ) -> Optional[VendorRule]:
        """
        Parse a single ACL entry line (already stripped of sequence number).

        Format:
          {permit|deny} <protocol> <src-spec> [<src-port>] <dst-spec> [<dst-port>]
        """
        m = re.match(r"^(permit|deny)\s+(.+)$", entry, re.IGNORECASE)
        if not m:
            return None

        action_str = m.group(1).lower()
        action = IOSXR_ACTION_MAP.get(action_str, action_str)
        tokens = m.group(2).split()

        if not tokens:
            return None

        try:
            idx = 0

            # Protocol
            proto_raw = tokens[idx].lower()
            if proto_raw == "object-group" and idx + 1 < len(tokens):
                proto = tokens[idx + 1]
                idx += 2
            else:
                proto = NAMED_PROTOCOLS.get(proto_raw, proto_raw)
                idx += 1

            # Source address
            src_addrs, idx = self._consume_address(tokens, idx, acl_family)

            # Source port
            src_port_str: Optional[str] = None
            if proto in ("tcp", "udp") and idx < len(tokens):
                src_port_str, idx = self._try_consume_port(tokens, idx)

            # Destination address
            dst_addrs, idx = self._consume_address(tokens, idx, acl_family)

            # Destination port
            dst_port_str: Optional[str] = None
            if proto in ("tcp", "udp", "sctp") and idx < len(tokens):
                dst_port_str, idx = self._try_consume_port(tokens, idx)

            services = self._build_service(proto, dst_port_str)
            vendor_tags: dict[str, Any] = {
                "acl_name": acl_name,
                "acl_family": acl_family,
            }
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

        except Exception as exc:  # noqa: BLE001
            warnings.append(f"[iosxr] Skipping ACL entry (parse error: {exc}): {entry!r}")
            return None

    def _consume_address(
        self, tokens: list[str], idx: int, acl_family: str
    ) -> tuple[list[str], int]:
        """
        Consume an address specification.

        IOS-XR ACLs use CIDR notation by default. Wildcard masks may appear
        in older configs but CIDR is standard here.
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

        if token in ("object-group",):
            if idx + 1 < len(tokens):
                return [tokens[idx + 1]], idx + 2
            return ["any"], idx + 1

        # Try CIDR or bare host (IPv4 or IPv6)
        addr_token = tokens[idx]
        if "/" in addr_token:
            # Already CIDR — normalize
            try:
                net = ipaddress.ip_network(addr_token, strict=False)
                return [str(net)], idx + 1
            except ValueError:
                return [addr_token], idx + 1

        # Bare dotted-decimal could have a following wildcard mask (legacy)
        if _looks_like_ip(addr_token) and idx + 1 < len(tokens) and _looks_like_ip(tokens[idx + 1]):
            # Wildcard mask form — convert
            try:
                wc_int = int(ipaddress.IPv4Address(tokens[idx + 1]))
                mask_int = (~wc_int) & 0xFFFFFFFF
                ip_int = int(ipaddress.IPv4Address(addr_token))
                network_int = ip_int & mask_int
                network = ipaddress.IPv4Network(
                    f"{ipaddress.IPv4Address(network_int)}/{ipaddress.IPv4Address(mask_int)}",
                    strict=False,
                )
                return [str(network)], idx + 2
            except ValueError:
                pass

        # IPv6 bare address or host
        if _looks_like_ipv6(addr_token):
            try:
                net = ipaddress.ip_network(addr_token, strict=False)
                return [str(net)], idx + 1
            except ValueError:
                pass

        # Bare host IPv4
        if _looks_like_ip(addr_token):
            return [addr_token], idx + 1

        return ["any"], idx

    def _try_consume_port(
        self, tokens: list[str], idx: int
    ) -> tuple[Optional[str], int]:
        """Attempt to consume eq/range/lt/gt port spec."""
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
            return None, idx + 2

        return None, idx

    def _build_service(self, protocol: str, port_spec: Optional[str]) -> list[str]:
        """Build service spec list from protocol and optional port."""
        proto_lower = protocol.lower()
        if proto_lower in ("ip", "ipv4", "any", "0"):
            return ["any"]
        if port_spec:
            return [f"{proto_lower}:{port_spec}"]
        return [proto_lower]

    # ------------------------------------------------------------------
    # Version detection
    # ------------------------------------------------------------------

    def _detect_version(self, lines: list[str]) -> Optional[str]:
        """Extract IOS-XR version from config header."""
        for line in lines[:30]:
            m = re.search(
                r"IOS[\s-]XR\s+(?:Software[,\s]+)?(?:Version\s+)?(\d+[\w.()]+)",
                line, re.IGNORECASE
            )
            if m:
                return m.group(1)
            # Bare "!! IOS XR Software, Version 7.3.2"
            m2 = re.search(r"Version\s+(\d+\.\d+[\w.]*)", line, re.IGNORECASE)
            if m2 and "xr" in line.lower():
                return m2.group(1)
        return None
