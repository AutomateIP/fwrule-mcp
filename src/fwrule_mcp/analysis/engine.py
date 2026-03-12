"""
Main analysis orchestration engine.

OverlapAnalysisEngine is the single entry point for the analysis layer.  It
accepts a list of NormalizedRule objects (the existing policy) and a
NormalizedCandidate (the proposed new rule) and returns an AnalysisResult
containing a RuleRelationship for every existing rule that has a non-disjoint
relationship with the candidate.

Design decisions:
  - The engine is stateless and thread-safe: instantiate once, call analyze()
    from multiple threads.
  - Disabled rules are skipped but counted so that the caller can report them.
  - The pre-filter (_is_disjoint_fast) checks zones first (cheapest: string
    set intersection), then services (protocol + port), then addresses (most
    expensive: CIDR arithmetic).  This mirrors the order prescribed in the
    architecture document and matches the MatchSpec.intersects() strategy.
  - The engine does NOT produce Finding objects (response layer types).  That
    responsibility belongs to the result generator.  This separation keeps the
    pure set-theoretic logic independent from presentation concerns.

Five passes (all implemented via classify_overlap):
  1. Exact duplication check   — OverlapType.EXACT_DUPLICATE
  2. Shadow analysis           — OverlapType.SHADOWED / SHADOWS_EXISTING
  3. Conflict detection        — OverlapType.CONFLICT
  4. Partial overlap detection — OverlapType.PARTIAL_OVERLAP / SUBSET / SUPERSET
  5. Disabled rule annotation  — tracked in AnalysisResult.disabled_rule_count

The five "passes" are conceptual: they correspond to distinct OverlapType
values returned by classify_overlap() in a single per-rule call.  There is no
literal loop for each pass — the engine makes one classify_overlap() call per
enabled existing rule and the OverlapType returned encodes the pass result.

Backward-compatible module-level ``analyze()`` function is also provided for
callers that do not need the class-based interface.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from fwrule_mcp.models.normalized import NormalizedCandidate, NormalizedRule
from fwrule_mcp.models.response import OverlapType

# Re-export classifier types so callers only need to import from this module.
from fwrule_mcp.analysis.classifier import (  # noqa: F401
    DimensionAnalysis,
    RuleRelationship,
    classify_overlap,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# AnalysisResult — aggregate result for all existing rules
# ---------------------------------------------------------------------------


@dataclass
class AnalysisResult:
    """
    The complete output of OverlapAnalysisEngine.analyze().

    ``relationships`` contains one entry per enabled existing rule where the
    pre-filter determined a possible intersection AND classify_overlap() did
    not return NO_OVERLAP.  Trivially-disjoint rules are not included.

    ``candidate`` is retained for result generation.
    ``existing_rule_count`` is the total count including disabled rules.
    ``disabled_rule_count`` is how many rules were skipped because enabled=False.
    ``skipped_count`` counts rules skipped due to an optional hard limit.
    ``warnings`` accumulates advisory messages (e.g., unresolvable references).
    """

    candidate: NormalizedCandidate
    """The candidate rule that was analysed."""

    existing_rule_count: int
    """Total number of rules in the policy (enabled + disabled)."""

    disabled_rule_count: int = 0
    """Number of rules skipped because enabled=False."""

    skipped_count: int = 0
    """Number of rules skipped due to an optional analysis limit."""

    relationships: list[RuleRelationship] = field(default_factory=list)
    """One RuleRelationship per existing rule with a non-disjoint relationship."""

    warnings: list[str] = field(default_factory=list)
    """Advisory messages produced during analysis (unresolvable refs, etc.)."""

    @property
    def overlap_relationships(self) -> list[RuleRelationship]:
        """Return relationships that represent a real overlap (not NO_OVERLAP)."""
        return [r for r in self.relationships if r.overlap_type != OverlapType.NO_OVERLAP]

    @property
    def has_overlaps(self) -> bool:
        """True if any real overlap was found."""
        return bool(self.overlap_relationships)

    def relationships_by_type(self, overlap_type: OverlapType) -> list[RuleRelationship]:
        """Return all relationships matching a specific OverlapType."""
        return [r for r in self.relationships if r.overlap_type == overlap_type]


# ---------------------------------------------------------------------------
# Engine class
# ---------------------------------------------------------------------------


class OverlapAnalysisEngine:
    """
    Core analysis engine.  Operates purely on normalized data structures.

    This class has no vendor knowledge and no dependency on the MCP or parsing
    layers.  It is safe to instantiate once and reuse across requests.

    Usage::

        engine = OverlapAnalysisEngine()
        result = engine.analyze(existing_rules, candidate, candidate_position=5)
        for rel in result.overlap_relationships:
            print(rel.overlap_type, rel.existing_rule.rule_id)
    """

    def analyze(
        self,
        existing_rules: list[NormalizedRule],
        candidate: NormalizedCandidate,
        candidate_position: int | None = None,
        max_rules: Optional[int] = None,
    ) -> AnalysisResult:
        """
        Analyse a candidate rule against all existing rules.

        Performs five conceptual passes via classify_overlap():
          1. Exact duplication check
          2. Shadowing check (rules preceding candidate)
          3. Conflict check (overlapping match, different action)
          4. Partial overlap detection
          5. Expansion / narrowing analysis (SUBSET / SUPERSET)

        Parameters
        ----------
        existing_rules:
            The current firewall policy in evaluation order (sorted by position).
        candidate:
            The proposed rule to evaluate.
        candidate_position:
            1-based position at which the candidate would be inserted.
            Overrides candidate.intended_position when provided.
            If both are None, the candidate is assumed to be appended at the
            end of the policy.
        max_rules:
            If set, stop after analysing this many enabled rules.  The count
            of skipped rules is available in AnalysisResult.skipped_count.

        Returns
        -------
        AnalysisResult
            Contains all detected relationships.  Trivially-disjoint pairs
            are excluded (fail-fast pre-filter applied).
        """
        # Resolve effective candidate position (explicit arg takes precedence)
        eff_pos = candidate_position if candidate_position is not None else candidate.intended_position

        total_count = len(existing_rules)
        disabled_count = 0
        analyzed_enabled = 0
        skipped_count = 0
        relationships: list[RuleRelationship] = []
        warnings: list[str] = []

        # Surface unresolvable-reference warnings from the candidate itself
        if candidate.metadata.unresolvable_references:
            warnings.append(
                f"Candidate rule has {len(candidate.metadata.unresolvable_references)} "
                f"unresolvable reference(s): "
                + ", ".join(candidate.metadata.unresolvable_references)
            )

        for rule in existing_rules:
            # --- Skip disabled rules ----------------------------------------
            if not rule.enabled:
                disabled_count += 1
                logger.debug(
                    "Skipping disabled rule %s (position %d)",
                    rule.rule_id,
                    rule.position,
                )
                continue

            # --- Optional hard limit ----------------------------------------
            if max_rules is not None and analyzed_enabled >= max_rules:
                skipped_count += 1
                continue

            analyzed_enabled += 1

            # Surface unresolvable references in existing rules
            if rule.metadata.unresolvable_references:
                warnings.append(
                    f"Rule {rule.rule_id!r} (pos {rule.position}) has "
                    f"{len(rule.metadata.unresolvable_references)} unresolvable "
                    f"reference(s): "
                    + ", ".join(rule.metadata.unresolvable_references)
                )

            # --- Fast pre-filter: skip trivially-disjoint pairs -------------
            if self._is_disjoint_fast(candidate, rule):
                logger.debug(
                    "Fast-path disjoint: candidate vs rule %s (position %d)",
                    rule.rule_id,
                    rule.position,
                )
                continue

            # --- Full classification -----------------------------------------
            relationship = classify_overlap(
                candidate=candidate,
                existing=rule,
                candidate_position=eff_pos,
            )

            logger.debug(
                "Classified candidate vs rule %s (pos %d): %s",
                rule.rule_id,
                rule.position,
                relationship.overlap_type.value,
            )

            # NO_OVERLAP from classify_overlap means the fast-path let a
            # borderline case through; exclude it from results.
            if relationship.overlap_type == OverlapType.NO_OVERLAP:
                continue

            relationships.append(relationship)

        return AnalysisResult(
            candidate=candidate,
            existing_rule_count=total_count,
            disabled_rule_count=disabled_count,
            skipped_count=skipped_count,
            relationships=relationships,
            warnings=warnings,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _is_disjoint_fast(
        self,
        candidate: NormalizedCandidate,
        existing: NormalizedRule,
    ) -> bool:
        """
        Quick pre-filter: check if the candidate and an existing rule are
        trivially disjoint before invoking the full classifier.

        Checks dimensions in increasing order of computational cost:
          1. Source zones       (string set intersection — very fast)
          2. Destination zones  (string set intersection)
          3. Applications       (string set — skipped when either side is any)
          4. Services           (protocol + port range — moderate)
          5. Source addresses   (IP arithmetic — most expensive)
          6. Destination addresses

        Returns True only when we can be certain no traffic can match both
        rules.  Returns False when in doubt (the full classifier decides).
        """
        cand_match = candidate.match
        exist_match = existing.match

        # 1. Source zones
        if not cand_match.source_zones.intersects(exist_match.source_zones):
            return True

        # 2. Destination zones
        if not cand_match.destination_zones.intersects(exist_match.destination_zones):
            return True

        # 3. Applications — only test when both sides are specific
        #    (is_any on either side always intersects)
        if (
            not cand_match.applications.is_any
            and not exist_match.applications.is_any
            and not cand_match.applications.intersects(exist_match.applications)
        ):
            return True

        # 4. Services
        if not cand_match.services.intersects(exist_match.services):
            return True

        # 5. Source addresses
        if not cand_match.source_addresses.intersects(exist_match.source_addresses):
            return True

        # 6. Destination addresses
        if not cand_match.destination_addresses.intersects(
            exist_match.destination_addresses
        ):
            return True

        return False


# ---------------------------------------------------------------------------
# Module-level convenience function (backward-compatible)
# ---------------------------------------------------------------------------

_default_engine = OverlapAnalysisEngine()


def analyze(
    candidate: NormalizedCandidate,
    existing_rules: list[NormalizedRule],
    candidate_position: int | None = None,
    max_rules: Optional[int] = None,
) -> AnalysisResult:
    """
    Module-level convenience wrapper around OverlapAnalysisEngine.analyze().

    Suitable for one-off calls.  For repeated analysis (e.g., per-request in
    a server), prefer instantiating OverlapAnalysisEngine directly to avoid
    the module-level singleton.

    Parameters
    ----------
    candidate:
        The proposed rule to evaluate.
    existing_rules:
        The ordered existing policy.
    candidate_position:
        1-based insertion position.  None = append at end.
    max_rules:
        Optional hard limit on the number of enabled rules to analyse.

    Returns
    -------
    AnalysisResult
    """
    return _default_engine.analyze(
        existing_rules=existing_rules,
        candidate=candidate,
        candidate_position=candidate_position,
        max_rules=max_rules,
    )
