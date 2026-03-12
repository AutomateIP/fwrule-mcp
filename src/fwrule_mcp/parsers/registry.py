"""
Parser plugin registry.

The registry maps (vendor, os_family) tuples to VendorParser instances.
Parsers self-register at import time by calling registry.register(instance).

Version matching strategy:
  - Parsers declare OS_FAMILIES = ["10.", "11."] to handle prefix-matched versions.
  - An empty OS_FAMILIES list means "handle any version for this vendor."
  - When get_parser() is called with an os_version, the registry walks each
    registered parser for that vendor and picks the one whose OS_FAMILIES
    prefix best matches (longest prefix wins).
  - If no prefix match is found, the parser with OS_FAMILIES=[] is used as the
    default fallback.
  - If multiple parsers match at the same prefix length, the first registered wins.

Auto-discovery:
  The first call to get_parser() (or list_vendors()) triggers a one-time import
  of all vendor sub-packages so that their __init__.py files run and register
  their parsers.
"""

from __future__ import annotations

import logging
from typing import Optional

from fwrule_mcp.parsers.base import VendorParser

logger = logging.getLogger(__name__)


class UnsupportedVendorError(Exception):
    """Raised when no parser is registered for the requested vendor/version."""

    def __init__(self, vendor: str, os_version: Optional[str] = None) -> None:
        version_str = f" (os_version={os_version!r})" if os_version else ""
        super().__init__(
            f"No parser registered for vendor '{vendor}'{version_str}. "
            f"Ensure the vendor parser module is imported."
        )
        self.vendor = vendor
        self.os_version = os_version


class ParserRegistry:
    """
    Singleton registry mapping vendor identifiers to VendorParser instances.

    Internal storage:
        _parsers: dict mapping vendor_id (str) → list of (os_families, parser)
                  tuples, ordered by registration time.
    """

    def __init__(self) -> None:
        # vendor_id -> list of (os_families: list[str], parser: VendorParser)
        self._parsers: dict[str, list[tuple[list[str], VendorParser]]] = {}
        self._auto_imported = False

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, parser: VendorParser) -> None:
        """
        Register a VendorParser instance.

        Called from each vendor's __init__.py at import time.

        Args:
            parser: An instantiated VendorParser subclass.  Its VENDOR and
                    OS_FAMILIES class attributes are used as registration keys.

        Raises:
            ValueError: If the parser's VENDOR attribute is empty.
        """
        if not parser.VENDOR:
            raise ValueError(
                f"VendorParser {type(parser).__name__} has an empty VENDOR attribute. "
                "Set VENDOR = '<vendor_id>' on the class before registering."
            )
        vendor = parser.VENDOR.lower()
        os_families = [f.lower() for f in parser.OS_FAMILIES]

        if vendor not in self._parsers:
            self._parsers[vendor] = []

        self._parsers[vendor].append((os_families, parser))
        logger.debug(
            "Registered parser %s for vendor=%r os_families=%r",
            type(parser).__name__,
            vendor,
            os_families,
        )

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def get_parser(self, vendor: str, os_version: Optional[str] = None) -> VendorParser:
        """
        Return the best-matching VendorParser for the given vendor/version.

        Matching algorithm:
        1. Normalize vendor to lowercase.
        2. Collect all parsers registered for that vendor.
        3. Among those, find the parser whose OS_FAMILIES entry is the longest
           prefix of os_version.  Parsers with OS_FAMILIES=[] are treated as
           wildcard defaults (prefix length 0).
        4. If no parsers are registered for this vendor, raise UnsupportedVendorError.

        Args:
            vendor:     Vendor identifier string (case-insensitive).
            os_version: Optional OS version string (e.g., "10.2.3").

        Returns:
            The VendorParser instance that best matches.

        Raises:
            UnsupportedVendorError: If no parser is registered for this vendor.
        """
        self._ensure_auto_imported()

        vendor_lower = vendor.lower()
        if vendor_lower not in self._parsers:
            raise UnsupportedVendorError(vendor, os_version)

        candidates = self._parsers[vendor_lower]

        if not os_version:
            # Return the first registered parser (or the one with empty OS_FAMILIES)
            # Prefer empty OS_FAMILIES (universal) over version-specific ones
            for os_families, parser in candidates:
                if not os_families:
                    return parser
            return candidates[0][1]

        version_lower = os_version.lower()
        best_parser: Optional[VendorParser] = None
        best_prefix_len = -1

        for os_families, parser in candidates:
            if not os_families:
                # Universal parser — matches with length 0 (lowest priority)
                if best_prefix_len < 0:
                    best_parser = parser
                    best_prefix_len = 0
            else:
                for family_prefix in os_families:
                    if version_lower.startswith(family_prefix):
                        prefix_len = len(family_prefix)
                        if prefix_len > best_prefix_len:
                            best_parser = parser
                            best_prefix_len = prefix_len

        if best_parser is None:
            raise UnsupportedVendorError(vendor, os_version)

        return best_parser

    def list_vendors(self) -> list[str]:
        """Return a sorted list of all registered vendor identifiers."""
        self._ensure_auto_imported()
        return sorted(self._parsers.keys())

    def list_parsers(self) -> list[dict]:
        """
        Return metadata for all registered parsers (useful for diagnostics).

        Each dict contains:
            vendor:      str
            os_families: list[str]
            parser_class: str (class name)
        """
        self._ensure_auto_imported()
        result = []
        for vendor, entries in sorted(self._parsers.items()):
            for os_families, parser in entries:
                result.append({
                    "vendor": vendor,
                    "os_families": os_families,
                    "parser_class": type(parser).__name__,
                })
        return result

    # ------------------------------------------------------------------
    # Auto-discovery
    # ------------------------------------------------------------------

    def _ensure_auto_imported(self) -> None:
        """
        Import all vendor sub-packages on the first registry query so that
        each vendor's __init__.py runs and self-registers its parser.

        Uses a flag to ensure this only runs once per process.
        """
        if self._auto_imported:
            return
        self._auto_imported = True
        _auto_import_vendors()


def _auto_import_vendors() -> None:
    """
    Import each vendor sub-package so parsers self-register.

    Errors from individual vendor imports are logged and swallowed so that
    one broken vendor parser does not prevent all others from loading.
    """
    vendor_packages = [
        "fwrule_mcp.parsers.vendors.panos",
        "fwrule_mcp.parsers.vendors.asa",
        "fwrule_mcp.parsers.vendors.ftd",
        "fwrule_mcp.parsers.vendors.checkpoint",
        "fwrule_mcp.parsers.vendors.juniper",
    ]
    for pkg in vendor_packages:
        try:
            __import__(pkg)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to import vendor parser package %r: %s", pkg, exc)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

registry = ParserRegistry()
