"""
Service-dimension comparison logic for the overlap analysis engine.

Compares two ServiceSet objects and returns a structured ServiceComparison
describing their set-theoretic relationship.  Delegates containment and
intersection checks to the ServiceSet / ServiceEntry methods from common.py.

Relationship vocabulary (matches DimensionDetail.relationship):
  equal        — both sets cover exactly the same protocol/port traffic
  subset       — candidate is entirely within existing (candidate ⊆ existing)
  superset     — candidate entirely covers existing (candidate ⊇ existing)
  intersecting — partial overlap; neither fully contains the other
  disjoint     — no common traffic exists between the two sets
"""

from __future__ import annotations

from dataclasses import dataclass

from fwrule_mcp.models.common import PortRange, ServiceEntry, ServiceSet


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass
class ServiceComparison:
    """Result of comparing two ServiceSets on the service dimension."""

    relationship: str
    """One of: 'equal', 'subset', 'superset', 'intersecting', 'disjoint'."""

    intersection_description: str
    """Human-readable summary of the overlapping service space."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _summarize_port_range(pr: PortRange) -> str:
    """Format a PortRange as 'N' (single) or 'N-M' (range)."""
    return str(pr.start) if pr.start == pr.end else f"{pr.start}-{pr.end}"


def _summarize_service_entry(entry: ServiceEntry) -> str:
    """Return a concise human-readable string for one ServiceEntry."""
    if entry.protocol == "any":
        return "any"

    proto = entry.protocol.upper()

    if entry.protocol in ("tcp", "udp"):
        if entry.ports is None:
            return f"{proto}/any"
        port_parts = [_summarize_port_range(pr) for pr in entry.ports]
        ports_str = ", ".join(port_parts)
        return f"{proto}/{ports_str}"

    if entry.protocol in ("icmp", "icmpv6"):
        if entry.icmp_type is None:
            return proto
        if entry.icmp_code is None:
            return f"{proto} type={entry.icmp_type}"
        return f"{proto} type={entry.icmp_type} code={entry.icmp_code}"

    return proto


def _summarize_service_set(svc_set: ServiceSet) -> str:
    """Return a concise human-readable string for a ServiceSet."""
    if svc_set.is_any:
        return "any"
    if not svc_set.entries:
        return "(empty)"

    parts = [_summarize_service_entry(e) for e in svc_set.entries]
    if len(parts) == 1:
        return parts[0]
    return "{" + ", ".join(parts) + "}"


def _summarize_intersection(a: ServiceSet, b: ServiceSet) -> str:
    """Compute and summarize the service intersection of two sets."""
    try:
        inter = a.intersection(b)
    except Exception:
        return "(intersection could not be computed)"

    if inter.is_any:
        return "any"
    if not inter.entries:
        return "(empty)"

    return _summarize_service_set(inter)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def compare_service_sets(
    candidate: ServiceSet,
    existing: ServiceSet,
) -> ServiceComparison:
    """
    Compare two ServiceSets and determine their relationship.

    Parameters
    ----------
    candidate:
        The service set from the candidate rule.
    existing:
        The service set from an existing rule.

    Returns
    -------
    ServiceComparison
        Populated relationship string and a human-readable description.
    """
    # --- fast paths for any/empty ---------------------------------------
    if candidate.is_any and existing.is_any:
        return ServiceComparison(
            relationship="equal",
            intersection_description="services: both are 'any' (all protocols/ports)",
        )

    if candidate.is_any and not existing.is_any:
        existing_str = _summarize_service_set(existing)
        return ServiceComparison(
            relationship="superset",
            intersection_description=(
                f"services: candidate is 'any' (superset), existing is {existing_str}"
            ),
        )

    if not candidate.is_any and existing.is_any:
        candidate_str = _summarize_service_set(candidate)
        return ServiceComparison(
            relationship="subset",
            intersection_description=(
                f"services: candidate {candidate_str} is a subset of existing 'any'"
            ),
        )

    # --- both are specific sets -----------------------------------------
    candidate_str = _summarize_service_set(candidate)
    existing_str = _summarize_service_set(existing)

    # Disjoint
    if not candidate.intersects(existing):
        return ServiceComparison(
            relationship="disjoint",
            intersection_description=(
                f"services: candidate {candidate_str} and existing {existing_str} "
                f"share no common protocol/port traffic"
            ),
        )

    # Equal
    cand_sub_exist = candidate.is_subset_of(existing)
    exist_sub_cand = existing.is_subset_of(candidate)

    if cand_sub_exist and exist_sub_cand:
        return ServiceComparison(
            relationship="equal",
            intersection_description=(
                f"services: candidate {candidate_str} equals existing {existing_str}"
            ),
        )

    # Subset (candidate ⊆ existing)
    if cand_sub_exist:
        return ServiceComparison(
            relationship="subset",
            intersection_description=(
                f"services: candidate {candidate_str} is a subset of "
                f"existing {existing_str}"
            ),
        )

    # Superset (candidate ⊇ existing)
    if exist_sub_cand:
        return ServiceComparison(
            relationship="superset",
            intersection_description=(
                f"services: candidate {candidate_str} is a superset of "
                f"existing {existing_str}"
            ),
        )

    # Partial intersection
    inter_str = _summarize_intersection(candidate, existing)
    return ServiceComparison(
        relationship="intersecting",
        intersection_description=(
            f"services: candidate {candidate_str} and existing {existing_str} "
            f"partially overlap; intersection is {inter_str}"
        ),
    )
