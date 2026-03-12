"""
Cisco ASA parser.

Configuration format: flat text (``show running-config`` or saved config file).

Handles:
  - Extended ACLs (access-list <name> extended ...)
  - Object definitions (object network, object service)
  - Object-group definitions (object-group network, object-group service,
    object-group protocol)
  - Named interface-to-zone mapping (``nameif`` → zone name)
  - Access-group bindings (which ACL is applied to which interface/direction)

Parsing approach: line-by-line state machine.  Multi-line constructs (object
groups with multiple object members) are handled by tracking indent context.
"""

from fwrule_mcp.parsers.vendors.asa.parser import ASAParser
from fwrule_mcp.parsers.registry import registry

registry.register(ASAParser())
