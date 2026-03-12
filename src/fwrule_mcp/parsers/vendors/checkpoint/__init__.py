"""
Check Point parser.

Configuration format: JSON package exported via Check Point management API
``show-package`` command (R80.x and above).

Package structure:
  - rulebase array      : access rule entries
  - objects-dictionary  : network objects, service objects, groups (UID-keyed)
  - NAT rulebase        : NAT rules (out of scope for v1)

Cross-referencing: All rule fields reference objects by UID.  The parser builds
a UID → object lookup table from the objects-dictionary before processing the
rulebase.

Check Point-specific concerns:
  - Objects can inherit from base objects — resolution must follow inheritance
    chains (implementation detail for the normalization layer).
  - "Any" network object has a specific well-known UID in Check Point exports.
  - Inline layers and sub-policies require recursive rulebase traversal.
"""

from fwrule_mcp.parsers.vendors.checkpoint.parser import CheckPointParser
from fwrule_mcp.parsers.registry import registry

registry.register(CheckPointParser())
