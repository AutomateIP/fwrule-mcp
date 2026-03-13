"""
Juniper Junos router firewall filter parser.

Configuration format: ``show configuration | display set`` output from Junos
routers (MX, PTX, QFX) using ``firewall family inet/inet6 filter`` constructs.

This parser is SEPARATE from the ``juniper`` (SRX security policy) parser:
  - ``juniper`` vendor: SRX zone-based security policies (from-zone/to-zone)
  - ``junos`` vendor:   Router firewall filters (filter/term, accept/discard)

Handles:
  - firewall family inet/inet6 filter <name> term <name> from/then clauses
  - source-address, destination-address, protocol, source-port, destination-port
  - source-prefix-list, destination-prefix-list references
  - policy-options prefix-list definitions
  - Actions: accept (→permit), discard (→deny), reject

Term ordering is preserved by parse order.
"""

from fwrule_mcp.parsers.vendors.junos.parser import JunosFilterParser
from fwrule_mcp.parsers.registry import registry

registry.register(JunosFilterParser())
