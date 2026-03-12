"""
firewall-overlap-mcp — Firewall Rule Overlap Analysis MCP Server.

Analyzes whether a candidate firewall rule overlaps, conflicts with, or is
shadowed by rules in an existing policy across multiple vendor formats.

Supported vendors: PAN-OS, Cisco ASA, Cisco FTD, Check Point, Juniper SRX.

Usage:
    # Run as MCP server (stdio transport):
    from fwrule_mcp.server import main
    main()

    # Access the FastMCP application instance directly:
    from fwrule_mcp.server import mcp
    mcp.run()
"""

__version__ = "0.1.0"
__author__ = "firewall-overlap-mcp contributors"
__license__ = "Apache-2.0"

# The FastMCP app instance is intentionally NOT imported here at package init
# time to avoid triggering FastMCP startup (and its import overhead) for code
# that only needs the data models or analysis engine.
#
# Import it explicitly when needed:
#   from fwrule_mcp.server import mcp

__all__ = [
    "__version__",
    "__author__",
    "__license__",
]
