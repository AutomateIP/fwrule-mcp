"""
Palo Alto Networks PAN-OS / Panorama parser.

Configuration format: XML (exported via ``show config running`` CLI or Panorama
API export).

Handles:
  - Security policy rules (vsys and Panorama device groups)
  - Address objects and address groups (including nested groups)
  - Service objects and service groups
  - Application-default service mapping (preserved as opaque tag)
  - Panorama shared object inheritance

XML structure targets:
  - Rules: /config/devices/entry/vsys/entry/rulebase/security/rules/entry
  - Panorama rules: /config/devices/entry/device-group/entry/pre-rulebase/...
  - Address objects: /config/devices/entry/vsys/entry/address/entry
  - Address groups: /config/devices/entry/vsys/entry/address-group/entry

Security note: All XML parsing must use defusedxml or equivalent — external
entities, DTD, and entity expansion must be disabled to prevent XXE attacks.
"""

from fwrule_mcp.parsers.vendors.panos.parser import PANOSParser
from fwrule_mcp.parsers.registry import registry

registry.register(PANOSParser())
