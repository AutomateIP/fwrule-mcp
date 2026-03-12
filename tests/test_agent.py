#!/usr/bin/env python3
"""
Firewall Rule Overlap Testing Agent.

Runs comprehensive tests across all vendors with mock payloads and prints a
formatted analysis report.  Suitable as a quick smoke-test or a CI gate.

Usage:
    uv run python tests/test_agent.py
    uv run python tests/test_agent.py --vendor panos
    uv run python tests/test_agent.py --scenario conflict
    uv run python tests/test_agent.py --vendor asa --scenario duplicate
    uv run python tests/test_agent.py --verbose
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VENDORS = ["panos", "asa", "ftd", "checkpoint", "juniper"]

SCENARIOS = ["duplicate", "shadowed", "conflict", "partial", "no_overlap"]

# Expected overlap_type values per scenario.
# For "no_overlap", None means findings list should be empty.
# For others, the value is checked against all finding overlap_type strings.
EXPECTED_TYPES: dict[str, Optional[str]] = {
    "duplicate": "exact_duplicate",
    "shadowed": "shadowed",       # or "subset" — both are acceptable
    "conflict": "conflict",
    "partial": "partial_overlap", # or "superset"/"shadows_existing" — broad intersection
    "no_overlap": None,
}

# Acceptable alternate overlap types per scenario (in addition to the primary).
ACCEPTABLE_ALTERNATES: dict[str, list[str]] = {
    "shadowed": ["subset"],
    "partial": ["superset", "shadows_existing", "conflict", "subset"],
    "duplicate": [],
    "conflict": [],
    "no_overlap": [],
}

# File extension per vendor
VENDOR_EXTENSIONS: dict[str, str] = {
    "panos": "xml",
    "asa": "conf",
    "ftd": "json",
    "checkpoint": "json",
    "juniper": "txt",
}

# Policy fixture filenames per vendor
POLICY_FILES: dict[str, str] = {
    "panos": "panos_policy.xml",
    "asa": "asa_policy.conf",
    "ftd": "ftd_policy.json",
    "checkpoint": "checkpoint_policy.json",
    "juniper": "juniper_policy.txt",
}

# Candidate filename pattern: {vendor}_{scenario}.{ext}
# "partial" uses "partial" in the filename
SCENARIO_FILE_NAMES: dict[str, str] = {
    "duplicate": "duplicate",
    "shadowed": "shadowed",
    "conflict": "conflict",
    "partial": "partial",
    "no_overlap": "no_overlap",
}

FIXTURES = Path(__file__).parent / "fixtures"
CANDIDATES = FIXTURES / "candidates"

# ---------------------------------------------------------------------------
# ANSI colour helpers (disabled when not a TTY)
# ---------------------------------------------------------------------------

_USE_COLOR = sys.stdout.isatty()

GREEN = "\033[92m" if _USE_COLOR else ""
RED = "\033[91m" if _USE_COLOR else ""
YELLOW = "\033[93m" if _USE_COLOR else ""
CYAN = "\033[96m" if _USE_COLOR else ""
BOLD = "\033[1m" if _USE_COLOR else ""
RESET = "\033[0m" if _USE_COLOR else ""


def _green(s: str) -> str:
    return f"{GREEN}{s}{RESET}"


def _red(s: str) -> str:
    return f"{RED}{s}{RESET}"


def _yellow(s: str) -> str:
    return f"{YELLOW}{s}{RESET}"


def _cyan(s: str) -> str:
    return f"{CYAN}{s}{RESET}"


def _bold(s: str) -> str:
    return f"{BOLD}{s}{RESET}"


# ---------------------------------------------------------------------------
# Scenario runner
# ---------------------------------------------------------------------------


def load_fixture(path: Path) -> str:
    """Read a fixture file, raising a clear error if missing."""
    if not path.exists():
        raise FileNotFoundError(f"Fixture file not found: {path}")
    return path.read_text()


def candidate_path(vendor: str, scenario: str) -> Path:
    """Return the Path to a candidate fixture file."""
    ext = VENDOR_EXTENSIONS[vendor]
    fname = SCENARIO_FILE_NAMES[scenario]
    return CANDIDATES / f"{vendor}_{fname}.{ext}"


def _overlap_types(result: dict) -> list[str]:
    """Extract overlap_type strings from all findings."""
    return [f["overlap_type"] for f in result.get("findings", [])]


def _check_result(scenario: str, result: dict) -> tuple[bool, str]:
    """
    Validate the result dict against the scenario's expected outcome.

    Returns (passed: bool, reason: str).
    """
    if not result.get("success"):
        err = result.get("error", {})
        return False, f"Pipeline error: [{err.get('code')}] {err.get('message')}"

    expected_type = EXPECTED_TYPES[scenario]
    types = _overlap_types(result)

    if expected_type is None:
        # no_overlap: expect empty findings
        if result.get("overlap_exists"):
            return False, f"Expected no overlap but got findings: {types}"
        return True, "No overlap (correct)"

    # Overlapping scenario: expect at least one matching finding
    if not result.get("overlap_exists"):
        return False, f"Expected overlap_exists=True but got no findings"

    alternates = ACCEPTABLE_ALTERNATES.get(scenario, [])
    acceptable = {expected_type} | set(alternates)

    matched = [t for t in types if t in acceptable]
    if not matched:
        return False, (
            f"Expected one of {sorted(acceptable)} in findings but got: {types}"
        )

    return True, f"Found: {types}"


def run_scenario(
    vendor: str,
    scenario: str,
    verbose: bool = False,
) -> tuple[bool, float]:
    """
    Run one vendor+scenario analysis and return (passed, duration_ms).

    Prints per-scenario output.
    """
    from fwrule_mcp.server import analyze_firewall_rule_overlap

    policy_file = FIXTURES / POLICY_FILES[vendor]
    cand_file = candidate_path(vendor, scenario)

    # Load fixtures (may raise FileNotFoundError)
    policy_payload = load_fixture(policy_file)
    candidate_payload = load_fixture(cand_file)

    t0 = time.monotonic()
    result = analyze_firewall_rule_overlap(
        vendor=vendor,
        ruleset_payload=policy_payload,
        candidate_rule_payload=candidate_payload,
    )
    elapsed_ms = (time.monotonic() - t0) * 1000

    passed, reason = _check_result(scenario, result)

    if verbose:
        status = _green("PASS") if passed else _red("FAIL")
        print(
            f"  [{status}] {vendor:12s} | {scenario:12s} | {elapsed_ms:7.1f}ms | {reason}"
        )
        if not passed and result.get("success"):
            # Print findings details on failure for debugging
            for finding in result.get("findings", []):
                print(
                    f"           -> {finding['overlap_type']:20s} "
                    f"(rule: {finding.get('existing_rule_id', '?')}, "
                    f"severity: {finding.get('severity', '?')})"
                )
    else:
        status = _green("PASS") if passed else _red("FAIL")
        print(f"  [{status}] {vendor}.{scenario}")

    return passed, elapsed_ms


# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------


def print_summary_table(results: dict[str, dict[str, bool]]) -> None:
    """
    Print a formatted summary table.

        Vendor       | duplicate | shadowed | conflict | partial | no_overlap
        panos        |   PASS    |   PASS   |   PASS   |  PASS   |    PASS
        asa          |   PASS    |   PASS   |   PASS   |  PASS   |    PASS
    """
    scenarios = SCENARIOS
    col_width = 11
    vendor_col = 14

    # Header
    header = _bold(f"{'Vendor':<{vendor_col}}") + " | " + " | ".join(
        _bold(f"{s:^{col_width}}") for s in scenarios
    )
    sep = "-" * (vendor_col + 3 + (col_width + 3) * len(scenarios))

    print()
    print(_bold("=" * len(sep)))
    print(_bold(" SUMMARY TABLE"))
    print(_bold("=" * len(sep)))
    print(header)
    print(sep)

    total_pass = 0
    total_fail = 0

    for vendor in VENDORS:
        if vendor not in results:
            continue
        row = f"{vendor:<{vendor_col}} | "
        cells = []
        for sc in scenarios:
            if sc not in results[vendor]:
                cells.append(f"{'SKIP':^{col_width}}")
            elif results[vendor][sc]:
                cells.append(_green(f"{'PASS':^{col_width}}"))
                total_pass += 1
            else:
                cells.append(_red(f"{'FAIL':^{col_width}}"))
                total_fail += 1
        row += " | ".join(cells)
        print(row)

    print(sep)
    total = total_pass + total_fail
    pct = (total_pass / total * 100) if total else 0
    summary_color = _green if total_fail == 0 else _red
    print(
        f"\n{summary_color(f'{total_pass}/{total} tests passed ({pct:.0f}%)')}"
    )
    if total_fail > 0:
        print(_red(f"{total_fail} test(s) FAILED"))
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Firewall Rule Overlap Testing Agent — runs all vendor/scenario combinations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--vendor",
        choices=VENDORS,
        default=None,
        help="Run only this vendor (default: all vendors)",
    )
    parser.add_argument(
        "--scenario",
        choices=SCENARIOS,
        default=None,
        help="Run only this scenario (default: all scenarios)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show per-finding details on failures",
    )
    args = parser.parse_args()

    vendors_to_run = [args.vendor] if args.vendor else VENDORS
    scenarios_to_run = [args.scenario] if args.scenario else SCENARIOS

    print()
    print(_bold(_cyan("=" * 64)))
    print(_bold(_cyan(" Firewall Rule Overlap Testing Agent")))
    print(_bold(_cyan("=" * 64)))
    print(f" Vendors:   {', '.join(vendors_to_run)}")
    print(f" Scenarios: {', '.join(scenarios_to_run)}")
    print()

    # results[vendor][scenario] = passed (bool)
    all_results: dict[str, dict[str, bool]] = {}
    any_failure = False
    total_duration_ms = 0.0

    for vendor in vendors_to_run:
        all_results[vendor] = {}
        print(_bold(f"-- {vendor.upper()} " + "-" * (50 - len(vendor))))
        for scenario in scenarios_to_run:
            try:
                passed, dur = run_scenario(vendor, scenario, verbose=args.verbose)
            except FileNotFoundError as exc:
                print(f"  [{_red('ERR')}] {vendor}.{scenario} — {exc}")
                passed = False
                dur = 0.0
            except Exception as exc:
                print(f"  [{_red('ERR')}] {vendor}.{scenario} — Unexpected: {exc}")
                passed = False
                dur = 0.0

            all_results[vendor][scenario] = passed
            total_duration_ms += dur
            if not passed:
                any_failure = True

        print()

    print_summary_table(all_results)
    print(f" Total analysis time: {total_duration_ms:.0f}ms")
    print()

    return 1 if any_failure else 0


if __name__ == "__main__":
    sys.exit(main())
