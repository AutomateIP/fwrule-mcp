"""
Vendor value mappers for the normalization layer.

This module provides:
- ACTION_MAP: vendor action string → canonical Action enum
- WELL_KNOWN_SERVICES: service name → (protocol, port) tuple
- parse_address_literal(): raw string → AddressEntry | None
- parse_service_literal(): raw string → ServiceEntry | None
- wildcard_to_prefix(): Cisco wildcard mask → CIDR prefix length

All functions are pure (no I/O, no side effects) and safe to call from hot
paths.  They return None rather than raising when inputs are unparseable, so
callers can emit warnings and continue instead of crashing.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import Optional

from fwrule_mcp.models.common import (
    Action,
    AddressEntry,
    AddressFamily,
    AddressType,
    PortRange,
    ServiceEntry,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Action mapping
# ---------------------------------------------------------------------------

#: Maps every recognized vendor action string to its canonical Action enum
#: value.  The lookup is performed after lower-casing the vendor string.
ACTION_MAP: dict[str, Action] = {
    # --- PAN-OS ---
    "allow": Action.PERMIT,
    "deny": Action.DENY,
    "drop": Action.DROP,
    "reset-client": Action.REJECT,
    "reset-server": Action.REJECT,
    "reset-both": Action.REJECT,
    # --- Cisco ASA / IOS ---
    "permit": Action.PERMIT,
    # (deny already mapped above)
    # --- Cisco FTD / FMC ---
    "allow": Action.PERMIT,         # duplicate, same value
    "block": Action.DENY,
    "trust": Action.PERMIT,
    "monitor": Action.LOG_ONLY,
    "block with reset": Action.REJECT,
    "interactive block": Action.DENY,
    "interactive block with reset": Action.REJECT,
    # --- Check Point ---
    "accept": Action.PERMIT,
    "drop": Action.DROP,            # duplicate, same value
    "reject": Action.REJECT,
    "ask": Action.UNKNOWN,
    "inform": Action.LOG_ONLY,
    "userauth": Action.PERMIT,
    "client auth": Action.PERMIT,
    # --- Juniper SRX / ScreenOS ---
    "permit": Action.PERMIT,        # duplicate, same value
    "deny": Action.DENY,            # duplicate
    "reject": Action.REJECT,        # duplicate
    "log": Action.LOG_ONLY,
    # --- FortiGate ---
    "accept": Action.PERMIT,        # duplicate
    "deny": Action.DENY,            # duplicate
    "ipsec": Action.PERMIT,
    "ssl-vpn": Action.PERMIT,
    # --- Juniper Junos router firewall filters (family inet filter) ---
    # (accept already mapped above via Check Point)
    # discard already mapped above
    # reject already mapped above
    # --- Nokia SR OS MD-CLI ip-filter ---
    # accept already mapped above
    # drop already mapped above
    # reject already mapped above
    # --- Generic / catch-all synonyms ---
    "pass": Action.PERMIT,
    "forward": Action.PERMIT,
    "discard": Action.DROP,
    "block_all": Action.DENY,
    "log_only": Action.LOG_ONLY,
    "unknown": Action.UNKNOWN,
    # --- Cisco IOS / IOS-XE / IOS-XR ---
    # permit and deny already mapped above
}


def map_action(vendor_action: str) -> Action:
    """
    Map a vendor-specific action string to the canonical Action enum.

    The lookup is case-insensitive and strips surrounding whitespace.
    Returns Action.UNKNOWN for any unrecognized string and logs a warning.
    """
    normalized = vendor_action.strip().lower()
    result = ACTION_MAP.get(normalized)
    if result is None:
        logger.warning("Unrecognized action string %r — mapping to UNKNOWN", vendor_action)
        return Action.UNKNOWN
    return result


# ---------------------------------------------------------------------------
# Well-known service names
# ---------------------------------------------------------------------------

#: Maps a well-known service name (lower-case) to a (protocol, port) tuple.
#: The port value is an integer for single ports, or a string "start-end" for
#: ranges (rare but included for completeness).
WELL_KNOWN_SERVICES: dict[str, tuple[str, int | str]] = {
    # Web
    "http": ("tcp", 80),
    "https": ("tcp", 443),
    "http-alt": ("tcp", 8080),
    "https-alt": ("tcp", 8443),
    # File transfer
    "ftp": ("tcp", 21),
    "ftp-data": ("tcp", 20),
    "sftp": ("tcp", 22),       # shares port with ssh
    "tftp": ("udp", 69),
    # Remote access
    "ssh": ("tcp", 22),
    "telnet": ("tcp", 23),
    "rdp": ("tcp", 3389),
    "vnc": ("tcp", 5900),
    "rsh": ("tcp", 514),
    "rlogin": ("tcp", 513),
    # Email
    "smtp": ("tcp", 25),
    "smtps": ("tcp", 465),
    "submission": ("tcp", 587),
    "pop3": ("tcp", 110),
    "pop3s": ("tcp", 995),
    "imap": ("tcp", 143),
    "imaps": ("tcp", 993),
    # DNS / NTP / DHCP
    "dns": ("udp", 53),
    "dns-tcp": ("tcp", 53),
    "ntp": ("udp", 123),
    "dhcp": ("udp", 67),
    "dhcp-client": ("udp", 68),
    # SNMP / Syslog / Monitoring
    "snmp": ("udp", 161),
    "snmp-trap": ("udp", 162),
    "syslog": ("udp", 514),
    "syslog-tcp": ("tcp", 514),
    # Directory / Auth
    "ldap": ("tcp", 389),
    "ldaps": ("tcp", 636),
    "kerberos": ("tcp", 88),
    "kerberos-udp": ("udp", 88),
    "radius": ("udp", 1812),
    "radius-acct": ("udp", 1813),
    "tacacs": ("tcp", 49),
    # Database
    "mysql": ("tcp", 3306),
    "postgres": ("tcp", 5432),
    "mssql": ("tcp", 1433),
    "oracle": ("tcp", 1521),
    "redis": ("tcp", 6379),
    "mongodb": ("tcp", 27017),
    # Routing / Network management
    "bgp": ("tcp", 179),
    "ospf": ("tcp", 89),       # also IP protocol 89 — port here for completeness
    "netconf": ("tcp", 830),
    "netconf-call-home": ("tcp", 4334),
    "restconf": ("tcp", 443),  # shares HTTPS port
    # Windows / SMB / AD
    "smb": ("tcp", 445),
    "netbios-ns": ("udp", 137),
    "netbios-dgm": ("udp", 138),
    "netbios-ssn": ("tcp", 139),
    "msrpc": ("tcp", 135),
    # Tunneling / VPN
    "ike": ("udp", 500),
    "ipsec-nat-t": ("udp", 4500),
    "l2tp": ("udp", 1701),
    "pptp": ("tcp", 1723),
    "openvpn": ("udp", 1194),
    "wireguard": ("udp", 51820),
    # Other common
    "nfs": ("tcp", 2049),
    "rpcbind": ("tcp", 111),
    "irc": ("tcp", 6667),
    "xmpp": ("tcp", 5222),
    "mqtt": ("tcp", 1883),
    "mqtts": ("tcp", 8883),
    "sip": ("udp", 5060),
    "sip-tls": ("tcp", 5061),
}


# ---------------------------------------------------------------------------
# Address literal parsing
# ---------------------------------------------------------------------------

# Regex patterns
_CIDR_RE = re.compile(
    r"^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$"           # IPv4 CIDR
    r"|^([0-9a-fA-F:]+)/(\d{1,3})$"                     # IPv6 CIDR
)
_RANGE_RE = re.compile(
    r"^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3})$"   # IPv4 range
)
_WILDCARD_RE = re.compile(
    r"^(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})$"  # address + wildcard/mask
)
_HOST_RE = re.compile(
    r"^(\d{1,3}(?:\.\d{1,3}){3})$"   # bare IPv4 host
    r"|^([0-9a-fA-F:]+)$"            # bare IPv6 host
)
_FQDN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def wildcard_to_prefix(address: str, wildcard: str) -> Optional[str]:
    """
    Convert a Cisco-style address + wildcard mask to a CIDR prefix string.

    Cisco wildcard masks are the bitwise inverse of a subnet mask.
    Example: "10.0.0.0 0.0.0.255" → "10.0.0.0/24"

    Returns the CIDR string (e.g., "10.0.0.0/24") or None if the wildcard
    mask does not represent a contiguous block (non-standard wildcard).
    """
    try:
        addr_int = int(ipaddress.IPv4Address(address))
        wild_int = int(ipaddress.IPv4Address(wildcard))
        # Invert wildcard to get subnet mask bits
        mask_int = (~wild_int) & 0xFFFFFFFF
        # Verify the mask is contiguous (valid prefix mask)
        # A valid prefix mask in binary is all 1s followed by all 0s.
        # After inverting mask_int (getting back wild_int-like value), check:
        inverted = (~mask_int) & 0xFFFFFFFF
        # inverted must be 2^n - 1 (all 1s in low bits) for a contiguous block
        if inverted & (inverted + 1) != 0:
            # Non-contiguous wildcard — cannot express as CIDR
            return None
        prefix_len = bin(mask_int).count("1")
        # Zero out host bits
        network_int = addr_int & mask_int
        network_addr = ipaddress.IPv4Address(network_int)
        return f"{network_addr}/{prefix_len}"
    except (ValueError, OverflowError):
        return None


def parse_address_literal(value: str) -> Optional[AddressEntry]:
    """
    Parse a raw address string into an AddressEntry.

    Handled forms:
    - "any" / "any4" / "any6" / "0.0.0.0/0" / "::/0"  → ANY sentinel
    - "10.0.0.0/24" (CIDR)                              → CIDR entry
    - "10.0.0.1" (bare host IPv4)                       → HOST entry
    - "2001:db8::1" (bare host IPv6)                    → HOST entry
    - "10.0.0.1-10.0.0.100" (range)                    → RANGE entry
    - "10.0.0.0 255.255.255.0" (addr + subnet mask)    → CIDR entry
    - "10.0.0.0 0.0.0.255" (addr + wildcard mask)      → CIDR entry (if contiguous)
    - "host 10.0.0.1" (Cisco "host" keyword)            → HOST entry
    - "hostname.example.com" (FQDN)                     → FQDN entry

    Returns None if the value cannot be parsed into any recognized form.
    """
    if not value or not isinstance(value, str):
        return None

    stripped = value.strip()

    # --- ANY variants ---
    if stripped.lower() in ("any", "any4", "any6", "all", "0.0.0.0/0", "::/0"):
        return AddressEntry.any_sentinel()

    # --- Cisco "host <ip>" keyword ---
    if stripped.lower().startswith("host "):
        host_part = stripped[5:].strip()
        return parse_address_literal(host_part)

    # --- Try direct CIDR parse via ipaddress (handles both IPv4 and IPv6) ---
    try:
        net = ipaddress.ip_network(stripped, strict=False)
        # 0.0.0.0/0 and ::/0 are ANY
        if net.prefixlen == 0:
            return AddressEntry.any_sentinel()
        return AddressEntry.from_cidr(str(net), original_name=stripped)
    except ValueError:
        pass

    # --- IP range (IPv4 only: "start-end") ---
    range_match = _RANGE_RE.match(stripped)
    if range_match:
        start_str, end_str = range_match.group(1), range_match.group(2)
        try:
            start_addr = ipaddress.IPv4Address(start_str)
            end_addr = ipaddress.IPv4Address(end_str)
            if int(start_addr) <= int(end_addr):
                return AddressEntry.from_range(start_str, end_str, original_name=stripped)
        except ValueError:
            pass

    # --- "address wildcard/mask" two-token form ---
    wildcard_match = _WILDCARD_RE.match(stripped)
    if wildcard_match:
        addr_str = wildcard_match.group(1)
        mask_str = wildcard_match.group(2)
        # Try as subnet mask first (high bit set → subnet mask style)
        try:
            mask_addr = ipaddress.IPv4Address(mask_str)
            mask_int = int(mask_addr)
            # If high bit is set, treat as subnet mask; otherwise as wildcard
            if mask_int & 0x80000000:
                # Subnet mask: convert directly
                cidr_str = wildcard_to_prefix(addr_str, _subnet_to_wildcard(mask_str))
            else:
                # Wildcard mask
                cidr_str = wildcard_to_prefix(addr_str, mask_str)
            if cidr_str:
                return AddressEntry.from_cidr(cidr_str, original_name=stripped)
        except ValueError:
            pass

    # --- FQDN ---
    if _FQDN_RE.match(stripped):
        return AddressEntry.from_fqdn(stripped)

    logger.debug("parse_address_literal: could not parse %r", value)
    return None


def _subnet_to_wildcard(subnet_mask: str) -> str:
    """Invert a subnet mask string to its wildcard mask equivalent."""
    mask_int = int(ipaddress.IPv4Address(subnet_mask))
    wildcard_int = (~mask_int) & 0xFFFFFFFF
    return str(ipaddress.IPv4Address(wildcard_int))


# ---------------------------------------------------------------------------
# Service literal parsing
# ---------------------------------------------------------------------------

# Matches "tcp/80", "udp/53", "tcp/8080-8090", "tcp/any"
_SVC_PROTO_PORT_RE = re.compile(
    r"^(tcp|udp|sctp)(?:[/:](.+))?$", re.IGNORECASE
)
# Matches "icmp/8/0" or "icmp/8" or just "icmp"
_SVC_ICMP_RE = re.compile(
    r"^(icmp(?:v6)?|icmp6)(?:[/:](\d+)(?:[/:](\d+))?)?$", re.IGNORECASE
)
# Matches bare protocol number
_PROTO_NUM_RE = re.compile(r"^(\d{1,3})$")
# Port range: "80", "443", "8080-8090"
_PORT_RE = re.compile(r"^(\d{1,5})(?:-(\d{1,5}))?$")


def parse_service_literal(value: str) -> Optional[ServiceEntry]:
    """
    Parse a raw service string into a ServiceEntry.

    Handled forms:
    - "any"                     → protocol="any", ports=None
    - "tcp/80"                  → TCP port 80
    - "udp/53"                  → UDP port 53
    - "tcp/8080-8090"           → TCP port range 8080-8090
    - "tcp/any" or "tcp"        → TCP, any port
    - "icmp"                    → ICMP, any type/code
    - "icmp/8"                  → ICMP type 8 (echo request)
    - "icmp/8/0"                → ICMP type 8 code 0
    - "icmpv6" / "icmp6"        → ICMPv6
    - "6" / "17" / "47"         → Raw IP protocol numbers
    - Well-known name "http"    → resolved via WELL_KNOWN_SERVICES

    Returns None if the value cannot be recognized.
    """
    if not value or not isinstance(value, str):
        return None

    stripped = value.strip().lower()

    # --- ANY ---
    if stripped in ("any", "ip", "all"):
        return ServiceEntry(protocol="any")

    # --- Well-known service name lookup ---
    if stripped in WELL_KNOWN_SERVICES:
        proto, port = WELL_KNOWN_SERVICES[stripped]
        if isinstance(port, int):
            return ServiceEntry(
                protocol=proto,
                ports=(PortRange(port, port),),
            )
        # port is a "start-end" string (rare)
        parts = str(port).split("-")
        if len(parts) == 2:
            pr = _parse_port_range(str(port))
            if pr:
                return ServiceEntry(protocol=proto, ports=(pr,))

    # --- ICMP / ICMPv6 ---
    icmp_match = _SVC_ICMP_RE.match(stripped)
    if icmp_match:
        raw_proto = icmp_match.group(1).lower()
        protocol = "icmpv6" if raw_proto in ("icmpv6", "icmp6") else "icmp"
        icmp_type = int(icmp_match.group(2)) if icmp_match.group(2) else None
        icmp_code = int(icmp_match.group(3)) if icmp_match.group(3) else None
        return ServiceEntry(protocol=protocol, icmp_type=icmp_type, icmp_code=icmp_code)

    # --- TCP / UDP / SCTP with optional port ---
    proto_port_match = _SVC_PROTO_PORT_RE.match(stripped)
    if proto_port_match:
        protocol = proto_port_match.group(1).lower()
        port_spec = proto_port_match.group(2)
        if port_spec is None or port_spec in ("any", ""):
            return ServiceEntry(protocol=protocol, ports=None)
        pr = _parse_port_range(port_spec)
        if pr is not None:
            return ServiceEntry(protocol=protocol, ports=(pr,))
        # port_spec might be comma-separated ranges
        ranges = _parse_multi_port(port_spec)
        if ranges:
            return ServiceEntry(protocol=protocol, ports=tuple(ranges))
        return None

    # --- Raw IP protocol number ---
    proto_num_match = _PROTO_NUM_RE.match(stripped)
    if proto_num_match:
        num = int(proto_num_match.group(1))
        if 0 <= num <= 255:
            # Map well-known numbers to names
            _proto_names = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmpv6"}
            proto_name = _proto_names.get(num, str(num))
            return ServiceEntry(protocol=proto_name)

    logger.debug("parse_service_literal: could not parse %r", value)
    return None


def _parse_port_range(spec: str) -> Optional[PortRange]:
    """
    Parse a port spec string ("80", "443", "8080-8090") into a PortRange.
    Returns None if unparseable or out of range.
    """
    m = _PORT_RE.match(spec.strip())
    if not m:
        return None
    try:
        start = int(m.group(1))
        end = int(m.group(2)) if m.group(2) else start
        return PortRange(start, end)
    except ValueError:
        return None


def _parse_multi_port(spec: str) -> list[PortRange]:
    """
    Parse a comma-separated list of port specs into a list of PortRanges.
    Example: "80,443,8080-8090"
    """
    ranges: list[PortRange] = []
    for part in spec.split(","):
        pr = _parse_port_range(part.strip())
        if pr is not None:
            ranges.append(pr)
    return ranges
