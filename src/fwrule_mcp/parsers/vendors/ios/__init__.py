"""
Cisco IOS / IOS-XE parser.

Configuration format: flat text (``show running-config`` or saved config file).

Handles:
  - Standard and extended numbered ACLs (access-list <num> ...)
  - Named extended and standard ACLs (ip access-list extended|standard <name>)
  - IOS-XE object-group network and service definitions
  - Wildcard mask inversion (0.0.0.255 → /24)
  - Named port resolution (www=80, https=443, ssh=22, etc.)

Parsing approach: line-by-line state machine with named-ACL body detection
via indentation.
"""

from fwrule_mcp.parsers.vendors.ios.parser import IOSParser
from fwrule_mcp.parsers.registry import registry

registry.register(IOSParser())
