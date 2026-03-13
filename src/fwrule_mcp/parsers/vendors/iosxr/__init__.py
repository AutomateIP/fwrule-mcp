"""
Cisco IOS-XR parser.

Configuration format: flat text (``show running-config`` from IOS-XR devices).

Handles:
  - IPv4 and IPv6 named ACLs with sequence-numbered entries
  - object-group network (ipv4/ipv6) and object-group port definitions
  - CIDR notation (preferred) and legacy wildcard mask forms
  - Named port resolution (www=80, https=443, ssh=22, etc.)

Key differences from IOS parser:
  - ACL keyword is ``ipv4 access-list`` / ``ipv6 access-list``
  - Protocol keyword ``ipv4`` replaces ``ip``
  - Sequence numbers precede every permit/deny entry
  - object-group port uses ``eq`` / ``range`` without a protocol prefix
"""

from fwrule_mcp.parsers.vendors.iosxr.parser import IOSXRParser
from fwrule_mcp.parsers.registry import registry

registry.register(IOSXRParser())
