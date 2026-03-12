"""
Cisco Firepower Threat Defense (FTD) parser.

Configuration format: JSON export from Firepower Management Center (FMC) REST API.

Primary endpoints (FMC):
  - Access control policy export: GET /api/fmc_config/v1/domain/{id}/policy/accesspolicies
  - Network objects: GET /api/fmc_config/v1/domain/{id}/object/networks
  - Port objects: GET /api/fmc_config/v1/domain/{id}/object/ports
  - Security zones: GET /api/fmc_config/v1/domain/{id}/object/securityzones

The caller is expected to provide a JSON bundle containing the policy and
referenced objects.  The bundle should contain top-level "rules" and "objects"
arrays as exported by the FMC show-package API.

FTD-specific dimensions supported:
  - Security Intelligence zones
  - Application detectors (mapped to ApplicationSet)
  - Intrusion policy references (preserved in vendor_tags, not analyzed)
"""

from fwrule_mcp.parsers.vendors.ftd.parser import FTDParser
from fwrule_mcp.parsers.registry import registry

registry.register(FTDParser())
