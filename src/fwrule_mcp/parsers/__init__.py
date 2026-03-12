"""
Parsers package — vendor-specific configuration parsing layer.

Each vendor parser implements the VendorParser interface (parsers/base.py) and
registers itself with the plugin registry (parsers/registry.py).  The registry
is queried at runtime by the MCP server layer to dispatch to the correct parser
for a given (vendor, os_version) tuple.

Public API:
  from fwrule_mcp.parsers import registry
  from fwrule_mcp.parsers.base import VendorParser, ParsedPolicy, VendorRule, ObjectTable
  from fwrule_mcp.parsers.registry import registry, UnsupportedVendorError

Adding a new vendor:
  1. Create a new subdirectory under parsers/vendors/<vendor>/
  2. Implement VendorParser subclass in parser.py
  3. Set VENDOR and OS_FAMILIES class attributes
  4. Call registry.register(<ParserInstance>()) from the vendor's __init__.py
  5. Add the vendor package to _auto_import_vendors() in registry.py
"""

from fwrule_mcp.parsers.base import (
    ObjectTable,
    ParsedPolicy,
    VendorParser,
    VendorRule,
)
from fwrule_mcp.parsers.registry import (
    ParserRegistry,
    UnsupportedVendorError,
    registry,
)

__all__ = [
    "ObjectTable",
    "ParsedPolicy",
    "VendorParser",
    "VendorRule",
    "ParserRegistry",
    "UnsupportedVendorError",
    "registry",
]
