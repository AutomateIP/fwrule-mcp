"""
Nokia SR OS MD-CLI IP filter parser.

Configuration format: Nokia SR OS MD-CLI ``info`` output or flat /configure
command format.

Handles:
  - Hierarchical (braced) ip-filter entry definitions with match + action blocks
  - Flat /configure filter ip-filter "<name>" entry <id> match/action directives
  - match-list ip-prefix-list definitions (resolved as address groups)
  - Match fields: protocol, src-ip, dst-ip, src-port, dst-port, icmp-type/code
  - Port operators: eq, range, lt, gt
  - Actions: accept (→permit), drop (→deny), reject

Entry ordering within each filter is preserved by entry ID (ascending).
Filters are presented in the order they appear in the configuration.
"""

from fwrule_mcp.parsers.vendors.sros.parser import SROSParser
from fwrule_mcp.parsers.registry import registry

registry.register(SROSParser())
