"""
Zone-dimension comparison logic for the overlap analysis engine.

Compares two ZoneSet objects and returns a structured ZoneComparison describing
their set-theoretic relationship.  Zone identifiers are opaque strings — no
vendor-specific knowledge of zone hierarchy is applied here.

Relationship vocabulary (matches DimensionDetail.relationship):
  equal        — both sets reference the same zone identifiers
  subset       — candidate zones are a strict subset of existing zones
  superset     — candidate zones are a strict superset of existing zones
  intersecting — candidate and existing share some zones but not all
  disjoint     — no common zone exists between the two sets

The 'any' sentinel means "match regardless of zone" (also used when zone
information was absent in the vendor config).  Any set compared against 'any'
behaves as described in common.py: any.intersects(x) is always True,
any.is_superset_of(x) is always True, specific.is_subset_of(any) is True.
"""

from __future__ import annotations

from dataclasses import dataclass

from fwrule_mcp.models.common import ZoneSet


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass
class ZoneComparison:
    """Result of comparing two ZoneSets on one match dimension."""

    relationship: str
    """One of: 'equal', 'subset', 'superset', 'intersecting', 'disjoint'."""

    intersection_description: str
    """Human-readable summary of the zone relationship."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _summarize_zone_set(zone_set: ZoneSet, label: str = "zones") -> str:
    """Return a concise human-readable string for a ZoneSet."""
    if zone_set.is_any:
        return "any"
    if not zone_set.zones:
        return "(empty)"
    sorted_zones = sorted(zone_set.zones)
    if len(sorted_zones) == 1:
        return sorted_zones[0]
    return "{" + ", ".join(sorted_zones) + "}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def compare_zone_sets(
    candidate: ZoneSet,
    existing: ZoneSet,
    dimension_label: str = "zones",
) -> ZoneComparison:
    """
    Compare two ZoneSets and determine their relationship.

    Parameters
    ----------
    candidate:
        The zone set from the candidate rule.
    existing:
        The zone set from an existing rule.
    dimension_label:
        Human-readable label used in descriptions (e.g., "source zones",
        "destination zones").

    Returns
    -------
    ZoneComparison
        Populated relationship string and a human-readable description.
    """
    # --- fast paths for any ---------------------------------------------
    if candidate.is_any and existing.is_any:
        return ZoneComparison(
            relationship="equal",
            intersection_description=f"{dimension_label}: both are 'any'",
        )

    if candidate.is_any and not existing.is_any:
        existing_str = _summarize_zone_set(existing)
        return ZoneComparison(
            relationship="superset",
            intersection_description=(
                f"{dimension_label}: candidate is 'any' (superset), "
                f"existing is {existing_str}"
            ),
        )

    if not candidate.is_any and existing.is_any:
        candidate_str = _summarize_zone_set(candidate)
        return ZoneComparison(
            relationship="subset",
            intersection_description=(
                f"{dimension_label}: candidate {candidate_str} is a subset of "
                f"existing 'any'"
            ),
        )

    # --- both are specific sets -----------------------------------------
    candidate_str = _summarize_zone_set(candidate)
    existing_str = _summarize_zone_set(existing)

    # Disjoint — no zones in common
    if not candidate.intersects(existing):
        return ZoneComparison(
            relationship="disjoint",
            intersection_description=(
                f"{dimension_label}: candidate {candidate_str} and existing "
                f"{existing_str} share no common zones"
            ),
        )

    # Equal
    cand_sub_exist = candidate.is_subset_of(existing)
    exist_sub_cand = existing.is_subset_of(candidate)

    if cand_sub_exist and exist_sub_cand:
        return ZoneComparison(
            relationship="equal",
            intersection_description=(
                f"{dimension_label}: candidate {candidate_str} equals "
                f"existing {existing_str}"
            ),
        )

    # Subset (candidate ⊆ existing)
    if cand_sub_exist:
        common = sorted(candidate.zones & existing.zones)
        return ZoneComparison(
            relationship="subset",
            intersection_description=(
                f"{dimension_label}: candidate {candidate_str} is a subset of "
                f"existing {existing_str} "
                f"(common: {{{', '.join(common)}}})"
            ),
        )

    # Superset (candidate ⊇ existing)
    if exist_sub_cand:
        common = sorted(candidate.zones & existing.zones)
        return ZoneComparison(
            relationship="superset",
            intersection_description=(
                f"{dimension_label}: candidate {candidate_str} is a superset of "
                f"existing {existing_str} "
                f"(existing zones all covered)"
            ),
        )

    # Partial intersection
    common_zones = sorted(candidate.zones & existing.zones)
    return ZoneComparison(
        relationship="intersecting",
        intersection_description=(
            f"{dimension_label}: candidate {candidate_str} and existing "
            f"{existing_str} share zones "
            f"{{{', '.join(common_zones)}}}"
        ),
    )
