"""
Models package — vendor-agnostic data structures for the overlap analysis system.

Public surface:
  from fwrule_mcp.models.common import (
      Action, AddressEntry, AddressFamily, AddressSet, AddressType,
      ApplicationSet, PortRange, ServiceEntry, ServiceSet, ZoneSet,
      BLOCKING_ACTIONS,
  )
  from fwrule_mcp.models.normalized import (
      MatchSpec, NormalizedCandidate, NormalizedRule, RuleMetadata,
  )
  from fwrule_mcp.models.request import (
      AnalysisRequest, ContextObjects, SUPPORTED_VENDORS,
  )
  from fwrule_mcp.models.response import (
      AnalysisMetadata, AnalysisResponse,
      Finding, OverlapType, Severity,
  )
"""

from fwrule_mcp.models.common import (
    BLOCKING_ACTIONS,
    Action,
    AddressEntry,
    AddressFamily,
    AddressSet,
    AddressType,
    ApplicationSet,
    PortRange,
    ServiceEntry,
    ServiceSet,
    ZoneSet,
)
from fwrule_mcp.models.normalized import (
    MatchSpec,
    NormalizedCandidate,
    NormalizedRule,
    RuleMetadata,
)
from fwrule_mcp.models.request import (
    SUPPORTED_VENDORS,
    AnalysisRequest,
    ContextObjects,
)
from fwrule_mcp.models.response import (
    AnalysisMetadata,
    AnalysisResponse,
    Finding,
    OverlapType,
    Severity,
)

__all__ = [
    # common
    "BLOCKING_ACTIONS",
    "Action",
    "AddressEntry",
    "AddressFamily",
    "AddressSet",
    "AddressType",
    "ApplicationSet",
    "PortRange",
    "ServiceEntry",
    "ServiceSet",
    "ZoneSet",
    # normalized
    "MatchSpec",
    "NormalizedCandidate",
    "NormalizedRule",
    "RuleMetadata",
    # request
    "SUPPORTED_VENDORS",
    "AnalysisRequest",
    "ContextObjects",
    # response
    "AnalysisMetadata",
    "AnalysisResponse",
    "Finding",
    "OverlapType",
    "Severity",
]
