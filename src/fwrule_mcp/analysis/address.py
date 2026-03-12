"""
Address-dimension comparison logic for the overlap analysis engine.

Compares two AddressSet objects and returns a structured AddressComparison
describing their set-theoretic relationship.  All computation delegates to
the fully-implemented methods on AddressSet / AddressEntry from common.py.

Relationship vocabulary (matches DimensionDetail.relationship in response.py):
  equal        — both sets cover exactly the same IP space
  subset       — candidate is entirely within existing (candidate ⊆ existing)
  superset     — candidate entirely covers existing (candidate ⊇ existing)
  intersecting — partial overlap; neither fully contains the other
  disjoint     — no common IP address exists between the two sets
"""

from __future__ import annotations

from dataclasses import dataclass

from fwrule_mcp.models.common import AddressEntry, AddressSet, AddressType


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass
class AddressComparison:
    """Result of comparing two AddressSets on one match dimension."""

    relationship: str
    """One of: 'equal', 'subset', 'superset', 'intersecting', 'disjoint'."""

    intersection_description: str
    """Human-readable summary of the overlapping address space (or the reason
    there is none).  Used verbatim in DimensionDetail.description."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _summarize_address_set(addr_set: AddressSet) -> str:
    """Return a concise human-readable string for an AddressSet."""
    if addr_set.is_any:
        return "any"
    if not addr_set.entries:
        return "(empty)"

    parts: list[str] = []
    for entry in addr_set.entries:
        if entry.addr_type == AddressType.ANY:
            return "any"
        if entry.addr_type == AddressType.FQDN:
            parts.append(entry.fqdn or "(fqdn)")
        elif entry.addr_type == AddressType.RANGE:
            # Reconstruct the range string from integer bounds
            import ipaddress
            start_ip = ipaddress.ip_address(entry.range_start)  # type: ignore[arg-type]
            end_ip = ipaddress.ip_address(entry.range_end)  # type: ignore[arg-type]
            parts.append(f"{start_ip}-{end_ip}")
        else:
            # CIDR or HOST
            parts.append(str(entry.cidr) if entry.cidr else (entry.original_name or "?"))

    if len(parts) == 1:
        return parts[0]
    return "{" + ", ".join(parts) + "}"


def _summarize_intersection(a: AddressSet, b: AddressSet) -> str:
    """Compute and summarize the address intersection of two sets."""
    try:
        inter = a.intersection(b)
    except Exception:
        return "(intersection could not be computed)"

    if inter.is_any:
        return "any"
    if not inter.entries:
        return "(empty)"

    return _summarize_address_set(inter)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def compare_address_sets(
    candidate: AddressSet,
    existing: AddressSet,
    dimension_label: str = "addresses",
) -> AddressComparison:
    """
    Compare two AddressSets and determine their relationship.

    Parameters
    ----------
    candidate:
        The address set from the candidate rule.
    existing:
        The address set from an existing rule.
    dimension_label:
        Human-readable label used in descriptions (e.g., "source addresses",
        "destination addresses").

    Returns
    -------
    AddressComparison
        Populated relationship string and a human-readable intersection description.
    """
    # --- fast paths for any/empty ---------------------------------------
    if candidate.is_any and existing.is_any:
        return AddressComparison(
            relationship="equal",
            intersection_description=f"{dimension_label}: both are 'any' (entire address space)",
        )

    if candidate.is_any and not existing.is_any:
        existing_str = _summarize_address_set(existing)
        return AddressComparison(
            relationship="superset",
            intersection_description=(
                f"{dimension_label}: candidate is 'any' (superset), "
                f"existing is {existing_str}"
            ),
        )

    if not candidate.is_any and existing.is_any:
        candidate_str = _summarize_address_set(candidate)
        return AddressComparison(
            relationship="subset",
            intersection_description=(
                f"{dimension_label}: candidate {candidate_str} is a subset of "
                f"existing 'any'"
            ),
        )

    # --- both are specific sets -----------------------------------------
    candidate_str = _summarize_address_set(candidate)
    existing_str = _summarize_address_set(existing)

    # Disjoint — fastest failure path
    if not candidate.intersects(existing):
        return AddressComparison(
            relationship="disjoint",
            intersection_description=(
                f"{dimension_label}: candidate {candidate_str} and existing "
                f"{existing_str} share no common addresses"
            ),
        )

    # Equal
    cand_sub_exist = candidate.is_subset_of(existing)
    exist_sub_cand = existing.is_subset_of(candidate)

    if cand_sub_exist and exist_sub_cand:
        return AddressComparison(
            relationship="equal",
            intersection_description=(
                f"{dimension_label}: candidate {candidate_str} equals existing {existing_str}"
            ),
        )

    # Subset (candidate ⊆ existing)
    if cand_sub_exist:
        return AddressComparison(
            relationship="subset",
            intersection_description=(
                f"{dimension_label}: candidate {candidate_str} is a subset of "
                f"existing {existing_str}"
            ),
        )

    # Superset (candidate ⊇ existing)
    if exist_sub_cand:
        return AddressComparison(
            relationship="superset",
            intersection_description=(
                f"{dimension_label}: candidate {candidate_str} is a superset of "
                f"existing {existing_str}"
            ),
        )

    # Partial intersection
    inter_str = _summarize_intersection(candidate, existing)
    return AddressComparison(
        relationship="intersecting",
        intersection_description=(
            f"{dimension_label}: candidate {candidate_str} and existing {existing_str} "
            f"partially overlap; intersection is {inter_str}"
        ),
    )
