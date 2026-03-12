"""
Juniper SRX parser.

Configuration formats supported:
  - Hierarchical set format (``show configuration | display set``) — PRIMARY
  - Bracketed/curly-brace format (``show configuration``) — SECONDARY

Target policy types:
  - security policies (zone-based policy)
  - firewall family inet filter (interface-based ACL) — v2 consideration

Hierarchical set format approach:
  - Parse flat ``set`` command lines into a nested dictionary
  - Navigate the ``security policies`` subtree for zone-policy pairs
  - Navigate ``security zones`` for address book entries (address objects)
  - Navigate ``applications`` and ``application-sets`` for service definitions

Zone-based model:
  - Juniper SRX uses from-zone / to-zone pairs to organize policies
  - Zone pairs are preserved in ZoneSet.source_zones / destination_zones
"""

from fwrule_mcp.parsers.vendors.juniper.parser import JuniperParser, JuniperSRXAlias
from fwrule_mcp.parsers.registry import registry

_parser = JuniperParser()
registry.register(_parser)

# Register SRX as an alias so get_parser("srx") works
registry.register(JuniperSRXAlias())
