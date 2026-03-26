"""
Fortinet FortiOS firewall policy parser.

Configuration format: FortiOS flat-text backup
(``show full-configuration`` or device backup from FortiManager).

Handles:
  - ``config firewall policy`` and ``config firewall policy6``
  - Address objects (``config firewall address``)
  - Address groups (``config firewall addrgrp``)
  - Service custom objects (``config firewall service custom``)
  - Service groups (``config firewall service group``)
  - Multi-interface source/destination policies
  - Policy enable/disable status
  - FortiOS action keywords: accept, deny, ipsec, ssl-vpn, redirect, isolate

Vendor identifiers accepted by the registry:
  "fortios", "fortigate", "forti"
"""

from fwrule_mcp.parsers.vendors.fortios.parser import FortiOSParser
from fwrule_mcp.parsers.registry import registry

_parser_instance = FortiOSParser()

# Register under all supported aliases so callers can use any of them
registry.register(_parser_instance)
