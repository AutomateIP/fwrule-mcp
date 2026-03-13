"""
Nokia SR OS MD-CLI IP filter parser.

Supported input formats:
  1. Hierarchical MD-CLI ``info`` output (braced/indented):
       configure {
           filter {
               ip-filter "OUTSIDE_FILTER" {
                   default-action drop
                   entry 10 {
                       match {
                           protocol tcp
                           src-ip 10.0.0.0/24
                           dst-ip 192.168.1.0/24
                           dst-port {
                               eq 80
                           }
                       }
                       action {
                           accept
                       }
                   }
               }
           }
       }

  2. Flat MD-CLI command format:
       /configure filter ip-filter "OUTSIDE_FILTER" default-action drop
       /configure filter ip-filter "OUTSIDE_FILTER" entry 10 match protocol tcp
       /configure filter ip-filter "OUTSIDE_FILTER" entry 10 match src-ip 10.0.0.0/24
       /configure filter ip-filter "OUTSIDE_FILTER" entry 10 match dst-ip 192.168.1.0/24
       /configure filter ip-filter "OUTSIDE_FILTER" entry 10 match dst-port eq 80
       /configure filter ip-filter "OUTSIDE_FILTER" entry 10 action accept

  3. IP prefix list (match-list):
       configure filter match-list {
           ip-prefix-list "SERVERS" {
               prefix 10.1.1.0/24
               prefix 10.1.2.0/24
           }
       }
       Referenced in filters as: src-ip ip-prefix-list "SERVERS"

Match fields: protocol, src-ip, dst-ip, src-port, dst-port (with eq/range/lt/gt)
Actions: accept (→permit), drop (→deny), reject (→reject), forward

Action mapping:
  accept  → accept   (normalization maps to permit)
  drop    → drop     (normalization maps to deny)
  reject  → reject
"""

from __future__ import annotations

import ipaddress
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

# ---------------------------------------------------------------------------
# Action mapping
# ---------------------------------------------------------------------------

SROS_ACTION_MAP: dict[str, str] = {
    "accept": "accept",
    "drop": "drop",
    "reject": "reject",
    "forward": "accept",
    "nat": "accept",
}

# ---------------------------------------------------------------------------
# Named port resolution
# ---------------------------------------------------------------------------

NAMED_PORTS: dict[str, int] = {
    "ftp-data": 20,
    "ftp": 21,
    "ssh": 22,
    "telnet": 23,
    "smtp": 25,
    "domain": 53,
    "dns": 53,
    "tftp": 69,
    "http": 80,
    "www": 80,
    "pop3": 110,
    "ntp": 123,
    "imap": 143,
    "snmp": 161,
    "snmptrap": 162,
    "ldap": 389,
    "https": 443,
    "syslog": 514,
    "ldaps": 636,
    "imaps": 993,
    "pop3s": 995,
    "mssql": 1433,
    "rdp": 3389,
    "mysql": 3306,
    "bgp": 179,
    "sip": 5060,
    "kerberos": 88,
    "tacacs": 49,
    "radius": 1812,
    "radius-acct": 1813,
}

NAMED_PROTOCOLS: dict[str, str] = {
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
    "rsvp": "46",
    "sctp": "132",
    "ip": "ip",
}


def _resolve_port(port_str: str) -> str:
    """Resolve a named port to its numeric string equivalent."""
    lower = port_str.lower()
    if lower in NAMED_PORTS:
        return str(NAMED_PORTS[lower])
    return port_str


# ---------------------------------------------------------------------------
# Internal data structures for parsed filter state
# ---------------------------------------------------------------------------


class _FilterEntry:
    """Holds the parsed match + action state for a single SR OS filter entry."""

    def __init__(self, entry_id: int, filter_name: str) -> None:
        self.entry_id = entry_id
        self.filter_name = filter_name
        self.protocol: Optional[str] = None
        self.src_ip: list[str] = []
        self.dst_ip: list[str] = []
        self.src_port: Optional[str] = None
        self.dst_port: Optional[str] = None
        self.icmp_type: Optional[str] = None
        self.icmp_code: Optional[str] = None
        self.action: Optional[str] = None
        self.enabled: bool = True


class SROSParser(VendorParser):
    """
    Parser for Nokia SR OS MD-CLI IP filter configurations.

    Supports both hierarchical (info-style) and flat (/configure ...) formats.
    """

    VENDOR = "sros"
    OS_FAMILIES: list[str] = []

    def supported_vendors(self) -> list[tuple[str, Optional[str]]]:
        return [("sros", None)]

    # ------------------------------------------------------------------
    # parse_policy
    # ------------------------------------------------------------------

    def parse_policy(
        self,
        raw_payload: str,
        context: Optional[dict[str, Any]] = None,
    ) -> ParsedPolicy:
        """Parse an SR OS configuration containing IP filter definitions."""
        warnings: list[str] = []
        object_table = ObjectTable()

        lines = raw_payload.splitlines()

        # Detect format: flat vs hierarchical
        is_flat = self._detect_flat_format(lines)

        if is_flat:
            entries, prefix_lists = self._parse_flat_format(lines, warnings)
        else:
            entries, prefix_lists = self._parse_hierarchical_format(lines, warnings)

        # Populate object table from prefix lists
        for pl_name, prefixes in prefix_lists.items():
            object_table.address_groups[pl_name] = prefixes

        # Build rules from entries (sorted by entry ID within each filter)
        rules: list[VendorRule] = []
        position = 0

        # Group entries by filter, maintaining order within each filter
        filter_order: list[str] = []
        filters: dict[str, list[_FilterEntry]] = defaultdict(list)
        for entry in entries:
            fname = entry.filter_name
            if fname not in filter_order:
                filter_order.append(fname)
            filters[fname].append(entry)

        for fname in filter_order:
            # Sort entries by entry_id (ascending) — this is the match order
            sorted_entries = sorted(filters[fname], key=lambda e: e.entry_id)
            for fentry in sorted_entries:
                try:
                    rule = self._build_rule(fentry, position, warnings)
                    if rule is not None:
                        rules.append(rule)
                        position += 1
                except Exception as exc:  # noqa: BLE001
                    warnings.append(
                        f"[sros] Skipping filter entry {fentry.entry_id} "
                        f"in '{fentry.filter_name}': {exc}"
                    )

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
        """Parse a single SR OS filter entry as a candidate rule."""
        warnings: list[str] = []
        local_table = object_table or ObjectTable()
        lines = raw_rule.strip().splitlines()

        is_flat = self._detect_flat_format(lines)

        if is_flat:
            entries, prefix_lists = self._parse_flat_format(lines, warnings)
        else:
            entries, prefix_lists = self._parse_hierarchical_format(lines, warnings)

        for pl_name, prefixes in prefix_lists.items():
            local_table.address_groups[pl_name] = prefixes

        if not entries:
            raise ValueError("No SR OS filter entries found in candidate rule")

        rule = self._build_rule(entries[0], position=0, warnings=warnings)
        if rule is None:
            raise ValueError("Could not build rule from SR OS filter entry")
        return rule

    # ------------------------------------------------------------------
    # Format detection
    # ------------------------------------------------------------------

    def _detect_flat_format(self, lines: list[str]) -> bool:
        """
        Return True if any line looks like a flat /configure ... command.

        Flat format lines start with "/configure" or "configure" followed by
        keywords on one line without braces.
        """
        for line in lines[:50]:
            stripped = line.strip()
            if re.match(
                r"^/?configure\s+filter\s+ip-filter\s+",
                stripped, re.IGNORECASE
            ):
                return True
        return False

    # ------------------------------------------------------------------
    # Flat format parser
    # ------------------------------------------------------------------

    def _parse_flat_format(
        self, lines: list[str], warnings: list[str]
    ) -> tuple[list[_FilterEntry], dict[str, list[str]]]:
        """
        Parse flat MD-CLI command lines.

        Format:
          /configure filter ip-filter "<name>" entry <id> match protocol tcp
          /configure filter ip-filter "<name>" entry <id> match src-ip <cidr>
          /configure filter ip-filter "<name>" entry <id> match dst-port eq 80
          /configure filter ip-filter "<name>" entry <id> action accept
          /configure filter match-list ip-prefix-list "<name>" prefix <cidr>
        """
        # entries_map[filter_name][entry_id] = _FilterEntry
        entries_map: dict[str, dict[int, _FilterEntry]] = defaultdict(dict)
        prefix_lists: dict[str, list[str]] = {}
        # Track order of (filter_name, entry_id) pairs
        entry_order: list[tuple[str, int]] = []

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Remove leading slash from /configure
            stripped = re.sub(r"^/", "", stripped)

            # ip-prefix-list
            m = re.match(
                r"configure\s+filter\s+match-list\s+ip-prefix-list\s+"
                r'"?([^"]+?)"?\s+prefix\s+(\S+)',
                stripped, re.IGNORECASE
            )
            if m:
                pl_name = m.group(1)
                prefix = m.group(2)
                if pl_name not in prefix_lists:
                    prefix_lists[pl_name] = []
                prefix_lists[pl_name].append(prefix)
                continue

            # filter ip-filter <name> entry <id> ...
            m = re.match(
                r'configure\s+filter\s+ip-filter\s+"?([^"]+?)"?\s+'
                r'entry\s+(\d+)\s+(.+)$',
                stripped, re.IGNORECASE
            )
            if m:
                filter_name = m.group(1)
                entry_id = int(m.group(2))
                rest = m.group(3).strip()

                key = (filter_name, entry_id)
                if key not in entry_order:
                    entry_order.append(key)

                if entry_id not in entries_map[filter_name]:
                    entries_map[filter_name][entry_id] = _FilterEntry(
                        entry_id, filter_name
                    )
                fentry = entries_map[filter_name][entry_id]

                self._apply_flat_entry_line(fentry, rest, warnings)
                continue

        # Flatten to ordered list
        entries: list[_FilterEntry] = []
        seen: set[tuple[str, int]] = set()
        for fname, eid in entry_order:
            if (fname, eid) not in seen and eid in entries_map[fname]:
                entries.append(entries_map[fname][eid])
                seen.add((fname, eid))

        return entries, prefix_lists

    def _apply_flat_entry_line(
        self, fentry: _FilterEntry, rest: str, warnings: list[str]
    ) -> None:
        """
        Apply a single flat-format directive to the filter entry.

        ``rest`` is everything after "entry <id>", e.g.:
          "match protocol tcp"
          "match src-ip 10.0.0.0/24"
          "match dst-port eq 80"
          "action accept"
          "action drop"
        """
        parts = rest.split()
        if not parts:
            return

        directive = parts[0].lower()

        if directive == "match" and len(parts) >= 2:
            key = parts[1].lower()
            value_parts = parts[2:]
            self._apply_match_field(fentry, key, value_parts, warnings)

        elif directive == "action" and len(parts) >= 2:
            action_word = parts[1].lower()
            fentry.action = SROS_ACTION_MAP.get(action_word, action_word)

        elif directive in SROS_ACTION_MAP:
            # Some formats omit "action" keyword
            fentry.action = SROS_ACTION_MAP[directive]

    def _apply_match_field(
        self,
        fentry: _FilterEntry,
        key: str,
        value_parts: list[str],
        warnings: list[str],
    ) -> None:
        """Apply a match field key+values to the filter entry."""
        if not value_parts:
            return

        if key == "protocol":
            proto = value_parts[0].lower()
            fentry.protocol = NAMED_PROTOCOLS.get(proto, proto)

        elif key == "src-ip":
            addr = self._parse_ip_value(value_parts)
            if addr:
                fentry.src_ip.append(addr)

        elif key == "dst-ip":
            addr = self._parse_ip_value(value_parts)
            if addr:
                fentry.dst_ip.append(addr)

        elif key == "src-port":
            fentry.src_port = self._parse_port_value(value_parts)

        elif key == "dst-port":
            fentry.dst_port = self._parse_port_value(value_parts)

        elif key == "icmp-type":
            fentry.icmp_type = value_parts[0]

        elif key == "icmp-code":
            fentry.icmp_code = value_parts[0]

        elif key == "fragment":
            pass  # Fragment matching — not used in overlap analysis

    def _parse_ip_value(self, value_parts: list[str]) -> Optional[str]:
        """
        Parse an SR OS IP value. May be:
          - "10.0.0.0/24"          (CIDR)
          - "10.0.0.1"             (host)
          - "ip-prefix-list \"SERVERS\""  (group reference)
        """
        if not value_parts:
            return None

        # ip-prefix-list reference
        if value_parts[0].lower() == "ip-prefix-list":
            # Name may be quoted
            if len(value_parts) >= 2:
                name = " ".join(value_parts[1:]).strip('"').strip("'")
                return name  # Group reference by name
            return None

        # CIDR or host address
        addr_token = value_parts[0].strip('"')
        try:
            net = ipaddress.ip_network(addr_token, strict=False)
            return str(net)
        except ValueError:
            pass

        # Host address without prefix
        try:
            ipaddress.ip_address(addr_token)
            return addr_token
        except ValueError:
            pass

        return addr_token  # Return as-is; normalization will handle

    def _parse_port_value(self, value_parts: list[str]) -> Optional[str]:
        """
        Parse an SR OS port value. Formats:
          eq 80 | eq www
          range 80 90
          lt 80
          gt 80
        """
        if not value_parts:
            return None

        qualifier = value_parts[0].lower()

        if qualifier == "eq" and len(value_parts) >= 2:
            return _resolve_port(value_parts[1])
        elif qualifier == "range" and len(value_parts) >= 3:
            return f"{_resolve_port(value_parts[1])}-{_resolve_port(value_parts[2])}"
        elif qualifier == "lt" and len(value_parts) >= 2:
            end = int(_resolve_port(value_parts[1])) - 1
            return f"1-{end}"
        elif qualifier == "gt" and len(value_parts) >= 2:
            start = int(_resolve_port(value_parts[1])) + 1
            return f"{start}-65535"
        elif qualifier.isdigit():
            return qualifier  # Bare port number (uncommon in SR OS but handle it)

        return None

    # ------------------------------------------------------------------
    # Hierarchical format parser
    # ------------------------------------------------------------------

    def _parse_hierarchical_format(
        self, lines: list[str], warnings: list[str]
    ) -> tuple[list[_FilterEntry], dict[str, list[str]]]:
        """
        Parse MD-CLI hierarchical / braced info format.

        We use a lightweight state machine that tracks brace depth and
        context to extract filter entries.
        """
        entries_map: dict[str, dict[int, _FilterEntry]] = defaultdict(dict)
        prefix_lists: dict[str, list[str]] = {}
        entry_order: list[tuple[str, int]] = []

        # State
        context_stack: list[str] = []  # tracks nested context: filter, entry, match, action
        current_filter: Optional[str] = None
        current_entry: Optional[_FilterEntry] = None
        in_match = False
        in_action = False
        in_dst_port = False
        in_src_port = False
        in_prefix_list = False
        current_prefix_list: Optional[str] = None

        def push_ctx(ctx: str) -> None:
            context_stack.append(ctx)

        def pop_ctx() -> Optional[str]:
            return context_stack.pop() if context_stack else None

        def current_ctx() -> Optional[str]:
            return context_stack[-1] if context_stack else None

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Opening brace may appear on same line or next line
            has_open = "{" in stripped
            has_close = "}" in stripped

            # Handle match-list ip-prefix-list
            m = re.match(
                r'ip-prefix-list\s+"?([^"]+?)"?\s*\{',
                stripped, re.IGNORECASE
            )
            if m:
                current_prefix_list = m.group(1)
                in_prefix_list = True
                if current_prefix_list not in prefix_lists:
                    prefix_lists[current_prefix_list] = []
                push_ctx("prefix-list")
                continue

            if in_prefix_list:
                if has_close:
                    if "}" in stripped:
                        in_prefix_list = False
                        current_prefix_list = None
                        pop_ctx()
                        continue
                m = re.match(r"prefix\s+(\S+)", stripped)
                if m and current_prefix_list:
                    prefix_lists[current_prefix_list].append(m.group(1))
                continue

            # ip-filter "<name>" {
            m = re.match(
                r'ip-filter\s+"?([^"]+?)"?\s*\{',
                stripped, re.IGNORECASE
            )
            if m:
                current_filter = m.group(1)
                push_ctx("filter")
                continue

            # entry <id> {
            if current_filter:
                m = re.match(r"entry\s+(\d+)\s*\{", stripped, re.IGNORECASE)
                if m:
                    entry_id = int(m.group(1))
                    if entry_id not in entries_map[current_filter]:
                        entries_map[current_filter][entry_id] = _FilterEntry(
                            entry_id, current_filter
                        )
                    current_entry = entries_map[current_filter][entry_id]
                    key = (current_filter, entry_id)
                    if key not in entry_order:
                        entry_order.append(key)
                    push_ctx("entry")
                    continue

            # match { or action {
            if current_entry and has_open:
                if re.match(r"^match\s*\{", stripped, re.IGNORECASE):
                    in_match = True
                    in_action = False
                    push_ctx("match")
                    continue
                if re.match(r"^action\s*\{", stripped, re.IGNORECASE):
                    in_action = True
                    in_match = False
                    push_ctx("action")
                    continue
                # dst-port { or src-port {
                if re.match(r"^dst-port\s*\{", stripped, re.IGNORECASE):
                    in_dst_port = True
                    push_ctx("dst-port")
                    continue
                if re.match(r"^src-port\s*\{", stripped, re.IGNORECASE):
                    in_src_port = True
                    push_ctx("src-port")
                    continue

            # Closing brace
            if has_close and not has_open:
                ctx = pop_ctx()
                if ctx == "match":
                    in_match = False
                elif ctx == "action":
                    in_action = False
                elif ctx == "dst-port":
                    in_dst_port = False
                elif ctx == "src-port":
                    in_src_port = False
                elif ctx == "entry":
                    current_entry = None
                elif ctx == "filter":
                    current_filter = None
                elif ctx == "prefix-list":
                    in_prefix_list = False
                    current_prefix_list = None
                continue

            # Inline field assignments within match/action blocks
            if not stripped or has_open or has_close:
                continue

            # Inside dst-port/src-port sub-block
            if in_dst_port and current_entry:
                parts = stripped.split()
                val = self._parse_port_value(parts)
                if val:
                    current_entry.dst_port = val
                continue

            if in_src_port and current_entry:
                parts = stripped.split()
                val = self._parse_port_value(parts)
                if val:
                    current_entry.src_port = val
                continue

            # Inside match block
            if in_match and current_entry:
                parts = stripped.split()
                if not parts:
                    continue
                key = parts[0].lower()
                value_parts = parts[1:]

                # Handle "default-action" as a filter-level attribute (ignore in match)
                if key == "default-action":
                    continue

                self._apply_match_field(current_entry, key, value_parts, warnings)
                continue

            # Inside action block
            if in_action and current_entry:
                parts = stripped.split()
                if parts:
                    action_word = parts[0].lower()
                    resolved = SROS_ACTION_MAP.get(action_word)
                    if resolved:
                        current_entry.action = resolved
                continue

            # Filter-level attributes (default-action etc.) outside entry context
            if current_filter and not current_entry:
                m = re.match(r"default-action\s+(\S+)", stripped, re.IGNORECASE)
                if m:
                    pass  # Could track default-action per filter if needed
                    continue

        # Flatten to ordered list
        entries: list[_FilterEntry] = []
        seen: set[tuple[str, int]] = set()
        for fname, eid in entry_order:
            if (fname, eid) not in seen and eid in entries_map[fname]:
                entries.append(entries_map[fname][eid])
                seen.add((fname, eid))

        return entries, prefix_lists

    # ------------------------------------------------------------------
    # Rule building
    # ------------------------------------------------------------------

    def _build_rule(
        self,
        fentry: _FilterEntry,
        position: int,
        warnings: list[str],
    ) -> Optional[VendorRule]:
        """Build a VendorRule from a parsed _FilterEntry."""
        src_addrs = fentry.src_ip if fentry.src_ip else ["any"]
        dst_addrs = fentry.dst_ip if fentry.dst_ip else ["any"]

        services = self._build_services(fentry)

        # Default action if not explicitly set is drop (SR OS default-deny)
        action = fentry.action or "drop"

        vendor_tags: dict[str, Any] = {
            "filter_name": fentry.filter_name,
            "entry_id": fentry.entry_id,
        }
        if fentry.src_port:
            vendor_tags["src_port"] = fentry.src_port

        return VendorRule(
            name=f"{fentry.filter_name}:entry-{fentry.entry_id}",
            position=position,
            enabled=fentry.enabled,
            source_zones=["any"],
            destination_zones=["any"],
            source_addresses=src_addrs,
            destination_addresses=dst_addrs,
            services=services,
            applications=["any"],
            action=action,
            vendor_tags=vendor_tags,
        )

    def _build_services(self, fentry: _FilterEntry) -> list[str]:
        """Build a service spec list from the filter entry's match fields."""
        proto = (fentry.protocol or "").lower()
        dst_port = fentry.dst_port

        if not proto and not dst_port:
            return ["any"]

        if proto in ("ip", "any", "") and not dst_port:
            return ["any"]

        if proto in ("tcp", "udp", "sctp"):
            if dst_port:
                return [f"{proto}:{dst_port}"]
            return [proto]

        if proto == "icmp":
            if fentry.icmp_type:
                svc = f"icmp/{fentry.icmp_type}"
                if fentry.icmp_code:
                    svc += f"/{fentry.icmp_code}"
                return [svc]
            return ["icmp"]

        if proto == "icmpv6":
            return ["icmpv6"]

        if proto:
            if dst_port:
                return [f"{proto}:{dst_port}"]
            return [proto]

        # No protocol but has ports — use tcp-udp spec
        if dst_port:
            return [f"tcp:{dst_port}"]

        return ["any"]

    # ------------------------------------------------------------------
    # Version detection
    # ------------------------------------------------------------------

    def _detect_version(self, lines: list[str]) -> Optional[str]:
        """Extract SR OS version from config header."""
        for line in lines[:30]:
            m = re.search(
                r"TiMOS-[BC]-(\d+[\w.]+)\s+",
                line, re.IGNORECASE
            )
            if m:
                return m.group(1)
            m2 = re.search(r"SR[\s_]?OS\s+(?:Release\s+)?(\d+\.\d+[\w.]*)", line, re.IGNORECASE)
            if m2:
                return m2.group(1)
        return None
