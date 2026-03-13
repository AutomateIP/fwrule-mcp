"""
Juniper Junos router firewall filter parser.

Supported input: ``show configuration | display set`` text output from Junos
routers (MX, PTX, QFX) that use firewall family inet/inet6 filters.

NOTE: This parser handles Junos *router* firewall filters, which are distinct
from SRX security policies handled by the ``juniper`` (SRX) parser.

Handles:
  - Firewall family inet/inet6 filter terms:
      set firewall family inet filter <name> term <term> from source-address <pfx>
      set firewall family inet filter <name> term <term> from destination-address <pfx>
      set firewall family inet filter <name> term <term> from protocol <proto>
      set firewall family inet filter <name> term <term> from source-port <port>
      set firewall family inet filter <name> term <term> from destination-port <port>
      set firewall family inet filter <name> term <term> from port <port>
      set firewall family inet filter <name> term <term> then accept
      set firewall family inet filter <name> term <term> then discard
      set firewall family inet filter <name> term <term> then reject
  - Prefix lists:
      set policy-options prefix-list MGMT_NETS 10.0.0.0/24
      set firewall family inet filter X term Y from source-prefix-list MGMT_NETS
  - Multiple source/destination addresses per term (accumulated across set lines)
  - Port ranges: "http", "https", "80-443"

Structure: firewall → filter → term → from/then

Action mapping:
  accept  → permit
  discard → deny
  reject  → reject
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

# ---------------------------------------------------------------------------
# Action mapping
# ---------------------------------------------------------------------------

JUNOS_FILTER_ACTION_MAP: dict[str, str] = {
    "accept": "accept",
    "discard": "discard",
    "reject": "reject",
    "log": "log",
    "count": "count",
    "next": "next",
    "sample": "sample",
}

# Canonical action strings understood by the normalization layer
# accept → permit,  discard → deny,  reject → reject
JUNOS_FILTER_CANONICAL_ACTION: dict[str, str] = {
    "accept": "accept",
    "discard": "discard",
    "reject": "reject",
    "log": "log",
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
    "bootps": 67,
    "bootpc": 68,
    "tftp": 69,
    "http": 80,
    "www": 80,
    "pop2": 109,
    "pop3": 110,
    "sunrpc": 111,
    "ident": 113,
    "ntp": 123,
    "netbios-ns": 137,
    "netbios-dgm": 138,
    "netbios-ssn": 139,
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
    "tacacs": 49,
    "kerberos": 88,
}


def _resolve_port(port_str: str) -> str:
    """Resolve a Junos named port to its numeric string equivalent."""
    lower = port_str.lower()
    if lower in NAMED_PORTS:
        return str(NAMED_PORTS[lower])
    return port_str


def _parse_junos_port_spec(value: str) -> Optional[str]:
    """
    Parse a Junos port value into a normalized port spec string.

    Junos port values may be:
      - Numeric: "80"
      - Named: "http", "https"
      - Range: "8080-8090" or "8080 to 8090" (less common in set format)
    """
    if not value:
        return None
    # Handle range: "8080-8090"
    range_m = re.match(r"^(\d+)-(\d+)$", value)
    if range_m:
        return f"{range_m.group(1)}-{range_m.group(2)}"
    # Handle named port or numeric
    resolved = _resolve_port(value)
    if resolved.isdigit():
        return resolved
    # Could not resolve
    return value


class JunosFilterParser(VendorParser):
    """
    Parser for Juniper Junos router firewall filters in set-command format.

    Handles ``firewall family inet filter`` constructs (not SRX security
    policies — use the ``juniper`` vendor for those).
    """

    VENDOR = "junos"
    OS_FAMILIES: list[str] = []

    def supported_vendors(self) -> list[tuple[str, Optional[str]]]:
        return [("junos", None)]

    # ------------------------------------------------------------------
    # parse_policy
    # ------------------------------------------------------------------

    def parse_policy(
        self,
        raw_payload: str,
        context: Optional[dict[str, Any]] = None,
    ) -> ParsedPolicy:
        """Parse a Junos configuration containing firewall filter definitions."""
        warnings: list[str] = []
        object_table = ObjectTable()

        # Step 1: Build config data from set lines
        # term_data[filter_name][term_name] = {"from": {...}, "then": [...]}
        # We track term order via term_order[filter_name] = [term_names_in_order]
        term_data: dict[str, dict[str, dict]] = defaultdict(lambda: defaultdict(
            lambda: {"from": defaultdict(list), "then": []}
        ))
        term_order: dict[str, list[str]] = defaultdict(list)
        prefix_lists: dict[str, list[str]] = {}

        lines = raw_payload.splitlines()
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            self._process_set_line(
                stripped, term_data, term_order, prefix_lists, object_table, warnings
            )

        # Step 2: Populate object table from prefix lists
        for pl_name, prefixes in prefix_lists.items():
            if prefixes:
                object_table.address_groups[pl_name] = prefixes

        # Step 3: Build rules from term data
        rules: list[VendorRule] = []
        position = 0

        for filter_name, terms in term_data.items():
            # Walk terms in order they were seen
            seen_terms: set[str] = set()
            ordered = term_order.get(filter_name, list(terms.keys()))

            for term_name in ordered:
                if term_name in seen_terms:
                    continue
                seen_terms.add(term_name)

                if term_name not in terms:
                    continue

                tdata = terms[term_name]
                try:
                    rule = self._build_rule(
                        filter_name, term_name, tdata, position, warnings
                    )
                    if rule is not None:
                        rules.append(rule)
                        position += 1
                except Exception as exc:  # noqa: BLE001
                    warnings.append(
                        f"[junos] Skipping term '{term_name}' in filter '{filter_name}': {exc}"
                    )

            # Catch any terms not in ordered list
            for term_name, tdata in terms.items():
                if term_name not in seen_terms:
                    try:
                        rule = self._build_rule(
                            filter_name, term_name, tdata, position, warnings
                        )
                        if rule is not None:
                            rules.append(rule)
                            position += 1
                    except Exception as exc:  # noqa: BLE001
                        warnings.append(
                            f"[junos] Skipping term '{term_name}' in filter '{filter_name}': {exc}"
                        )

        return ParsedPolicy(
            rules=rules,
            object_table=object_table,
            vendor=self.VENDOR,
            os_version=None,
            warnings=warnings,
        )

    def parse_single_rule(
        self,
        raw_rule: str,
        object_table: Optional[ObjectTable] = None,
    ) -> VendorRule:
        """
        Parse a set of ``set firewall family inet filter`` lines as a single term.
        """
        warnings: list[str] = []
        local_table = object_table or ObjectTable()

        term_data: dict[str, dict[str, dict]] = defaultdict(lambda: defaultdict(
            lambda: {"from": defaultdict(list), "then": []}
        ))
        term_order: dict[str, list[str]] = defaultdict(list)
        prefix_lists: dict[str, list[str]] = {}

        for line in raw_rule.splitlines():
            stripped = line.strip()
            if stripped:
                self._process_set_line(
                    stripped, term_data, term_order, prefix_lists, local_table, warnings
                )

        for pl_name, prefixes in prefix_lists.items():
            if prefixes:
                local_table.address_groups[pl_name] = prefixes

        if not term_data:
            raise ValueError(
                "No 'set firewall family inet filter' lines found in candidate rule"
            )

        # Take the first filter/term found
        filter_name = next(iter(term_data))
        terms = term_data[filter_name]
        if not terms:
            raise ValueError(f"No terms found in filter '{filter_name}'")

        term_name = next(iter(terms))
        tdata = terms[term_name]
        rule = self._build_rule(filter_name, term_name, tdata, 0, warnings)
        if rule is None:
            raise ValueError(
                f"Could not build rule from term '{term_name}' in filter '{filter_name}'"
            )
        return rule

    # ------------------------------------------------------------------
    # Set-line processing
    # ------------------------------------------------------------------

    def _process_set_line(
        self,
        line: str,
        term_data: dict,
        term_order: dict,
        prefix_lists: dict,
        object_table: ObjectTable,
        warnings: list[str],
    ) -> None:
        """
        Parse a single ``set`` line and insert data into the term_data or prefix_lists.

        Recognized patterns:
          set firewall family inet[6] filter <name> term <term> from <key> <value>
          set firewall family inet[6] filter <name> term <term> then <action>
          set policy-options prefix-list <name> <prefix>
        """
        if not line.lower().startswith("set "):
            return

        tokens = line[4:].split()  # Skip leading "set "
        if len(tokens) < 2:
            return

        # policy-options prefix-list <name> <prefix>
        if (
            len(tokens) >= 4
            and tokens[0].lower() == "policy-options"
            and tokens[1].lower() == "prefix-list"
        ):
            pl_name = tokens[2]
            prefix = tokens[3]
            if pl_name not in prefix_lists:
                prefix_lists[pl_name] = []
            prefix_lists[pl_name].append(prefix)
            return

        # firewall family inet[6] filter <name> term <term> from|then ...
        if (
            len(tokens) >= 8
            and tokens[0].lower() == "firewall"
            and tokens[1].lower() == "family"
            and tokens[2].lower() in ("inet", "inet6")
            and tokens[3].lower() == "filter"
            and tokens[5].lower() == "term"
        ):
            filter_name = tokens[4]
            term_name = tokens[6]
            rest = tokens[7:]

            # Track order
            if term_name not in term_order[filter_name]:
                term_order[filter_name].append(term_name)

            term = term_data[filter_name][term_name]

            if not rest:
                return

            clause = rest[0].lower()

            if clause == "from" and len(rest) >= 2:
                key = rest[1].lower()
                value = rest[2] if len(rest) > 2 else ""
                self._apply_from_clause(term["from"], key, value, warnings)

            elif clause == "then":
                # then <action> [<sub-action>]
                # Actions: accept, discard, reject, log, count, sample, next term
                action_tokens = rest[1:]
                if action_tokens:
                    action_word = action_tokens[0].lower()
                    if action_word in JUNOS_FILTER_ACTION_MAP:
                        if action_word not in term["then"]:
                            term["then"].append(action_word)

    def _apply_from_clause(
        self,
        from_data: dict,
        key: str,
        value: str,
        warnings: list[str],
    ) -> None:
        """Apply a ``from <key> <value>`` clause to the term's from-data dict."""
        if key == "source-address":
            from_data["source-address"].append(value)
        elif key == "destination-address":
            from_data["destination-address"].append(value)
        elif key == "protocol":
            # Protocols may be listed multiple times
            if "protocol" not in from_data:
                from_data["protocol"] = []
            if isinstance(from_data["protocol"], str):
                from_data["protocol"] = [from_data["protocol"]]
            from_data["protocol"].append(value.lower())
        elif key == "source-port":
            if "source-port" not in from_data:
                from_data["source-port"] = []
            port_spec = _parse_junos_port_spec(value)
            if port_spec:
                from_data["source-port"].append(port_spec)
        elif key == "destination-port":
            if "destination-port" not in from_data:
                from_data["destination-port"] = []
            port_spec = _parse_junos_port_spec(value)
            if port_spec:
                from_data["destination-port"].append(port_spec)
        elif key == "port":
            # "port" matches both source and destination
            if "port" not in from_data:
                from_data["port"] = []
            port_spec = _parse_junos_port_spec(value)
            if port_spec:
                from_data["port"].append(port_spec)
        elif key == "source-prefix-list":
            if "source-prefix-list" not in from_data:
                from_data["source-prefix-list"] = []
            from_data["source-prefix-list"].append(value)
        elif key == "destination-prefix-list":
            if "destination-prefix-list" not in from_data:
                from_data["destination-prefix-list"] = []
            from_data["destination-prefix-list"].append(value)
        elif key in ("icmp-type", "icmp-code"):
            from_data[key] = value
        elif key in ("tcp-flags", "ttl", "precedence", "dscp", "forwarding-class", "fragment-flags"):
            from_data[key] = value
        # Other from clauses silently ignored (not relevant to overlap analysis)

    # ------------------------------------------------------------------
    # Rule building
    # ------------------------------------------------------------------

    def _build_rule(
        self,
        filter_name: str,
        term_name: str,
        tdata: dict,
        position: int,
        warnings: list[str],
    ) -> Optional[VendorRule]:
        """Build a VendorRule from a parsed term dict."""
        from_data = tdata.get("from", {})
        then_list = tdata.get("then", [])

        # Source addresses
        src_addrs: list[str] = []
        src_addrs.extend(from_data.get("source-address", []))
        for pl_name in from_data.get("source-prefix-list", []):
            src_addrs.append(pl_name)  # Name reference; normalization layer resolves
        if not src_addrs:
            src_addrs = ["any"]

        # Destination addresses
        dst_addrs: list[str] = []
        dst_addrs.extend(from_data.get("destination-address", []))
        for pl_name in from_data.get("destination-prefix-list", []):
            dst_addrs.append(pl_name)
        if not dst_addrs:
            dst_addrs = ["any"]

        # Services — build from protocol + ports
        services = self._build_services(from_data, warnings)

        # Action — first terminal action wins; default to "discard" if no then
        action = "discard"  # default-deny
        for act in then_list:
            if act in JUNOS_FILTER_CANONICAL_ACTION:
                action = JUNOS_FILTER_CANONICAL_ACTION[act]
                break
        # If only non-terminal actions (log, count), treat as permit+log
        if not then_list or all(a not in ("accept", "discard", "reject") for a in then_list):
            if then_list:
                action = "accept"  # implicit accept with logging/counting
            # else truly empty then clause — treat as default discard
            else:
                action = "discard"

        vendor_tags: dict[str, Any] = {
            "filter_name": filter_name,
            "term_name": term_name,
        }

        return VendorRule(
            name=term_name,
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

    def _build_services(self, from_data: dict, warnings: list[str]) -> list[str]:
        """Build a service spec list from the from-clause data."""
        protocols = from_data.get("protocol", [])
        if isinstance(protocols, str):
            protocols = [protocols]

        dst_ports = from_data.get("destination-port", [])
        src_ports = from_data.get("source-port", [])
        ports = from_data.get("port", [])

        # If no protocol and no ports → any
        if not protocols and not dst_ports and not ports:
            return ["any"]

        services: list[str] = []

        if not protocols:
            protocols = ["ip"]

        for proto in protocols:
            proto_lower = proto.lower()
            if proto_lower in ("ip", "any", "ipv4", "ipv6"):
                # Use dst ports if specified
                effective_ports = dst_ports or ports
                if effective_ports:
                    for port in effective_ports:
                        services.append(f"tcp:{port}")  # Best-effort — no proto known
                else:
                    return ["any"]
            elif proto_lower in ("tcp", "udp", "sctp"):
                effective_ports = dst_ports or ports
                if effective_ports:
                    for port in effective_ports:
                        services.append(f"{proto_lower}:{port}")
                else:
                    services.append(proto_lower)
            elif proto_lower == "icmp":
                icmp_type = from_data.get("icmp-type")
                icmp_code = from_data.get("icmp-code")
                if icmp_type:
                    svc = f"icmp/{icmp_type}"
                    if icmp_code:
                        svc += f"/{icmp_code}"
                    services.append(svc)
                else:
                    services.append("icmp")
            elif proto_lower == "icmpv6":
                services.append("icmpv6")
            else:
                services.append(proto_lower)

        return services if services else ["any"]
