# FWRule MCP — Firewall Rule Analyzer

An MCP server that analyzes firewall rule overlap, duplication, shadowing, and conflicts across multi-vendor firewall policies.

## Supported Vendors

| Vendor | Format | Versions |
|--------|--------|----------|
| Palo Alto PAN-OS / Panorama | XML config export | 9.x - 11.x |
| Cisco ASA | `show running-config` text | 9.x+ |
| Cisco FTD | JSON export from FMC | 6.x - 7.x |
| Cisco IOS / IOS-XE | `show running-config` text | 12.x - 17.x |
| Cisco IOS-XR | `show running-config` text | 6.x+ |
| Check Point | JSON `show-access-rulebase` | R80.x - R82.x |
| Juniper SRX | `display set` format | 19.x+ |
| Juniper Junos (MX/PTX/QFX) | `display set` format | 18.x+ |
| Nokia SR OS | MD-CLI info/flat format | 20.x+ |

## Quick Start

```bash
# Install
uv sync

# Run tests
uv run pytest

# Start the MCP server
uv run fwrule-mcp
```

## MCP Tools

### `analyze_firewall_rule_overlap`

Analyze whether a candidate firewall rule overlaps with an existing ruleset. Supports two input modes.

**Mode 1 — Vendor-native configs** (built-in parsers):
- `vendor` — Vendor identifier (`panos`, `asa`, `ftd`, `ios`, `iosxr`, `checkpoint`, `juniper`, `junos`, `sros`)
- `ruleset_payload` — Complete firewall config in vendor-native format
- `candidate_rule_payload` — Single candidate rule in vendor-native format
- `os_version` — Optional OS version string
- `context_objects` — Optional JSON with supplemental object definitions

**Mode 2 — Pre-normalized JSON** (caller extracts structured rules):
- `existing_rules` — JSON string: array of normalized rule objects
- `candidate_rule` — JSON string: single normalized rule object

**Shared:**
- `candidate_position` — Optional 1-based intended insertion position

**Normalized rule schema:**
```json
{
  "id": "rule-1",
  "position": 1,
  "enabled": true,
  "action": "permit",
  "source_zones": ["trust"],
  "destination_zones": ["untrust"],
  "source_addresses": ["10.0.0.0/24", "192.168.1.0/24"],
  "destination_addresses": ["any"],
  "services": [{"protocol": "tcp", "ports": "443"}],
  "applications": ["any"]
}
```

**Detects:**
- Exact duplicates
- Shadowed rules (candidate would never fire)
- Action conflicts (overlapping traffic, opposing actions)
- Partial overlaps
- Superset/subset relationships

### `parse_policy`

Parse a vendor-native firewall config and return normalized JSON rules. Use this to inspect what the built-in parser extracts before running overlap analysis.

- `vendor` — Vendor identifier
- `ruleset_payload` — Complete firewall config
- `os_version` — Optional OS version string
- `context_objects` — Optional JSON with supplemental object definitions

Returns the same normalized schema accepted by `analyze_firewall_rule_overlap`.

### `list_supported_vendors`

List all supported firewall vendors with format requirements.

## Testing

```bash
# Full test suite
uv run pytest

# Mock payload tests (vendor parsers)
uv run pytest tests/test_mock_payloads.py -v

# Normalized input tests
uv run pytest tests/test_normalized_input.py -v

# Testing agent with formatted report
uv run python tests/test_agent.py

# Single vendor / scenario
uv run python tests/test_agent.py --vendor panos --scenario conflict --verbose
```

## Architecture

```
MCP Client Request
       │
       ├── Mode 1: vendor + raw config
       │         │
       │         v
       │    Vendor Parser (plugin registry)
       │    [PAN-OS │ ASA │ FTD │ IOS │ IOS-XR │ CP │ SRX │ Junos │ SR OS]
       │         │
       │         v
       │    Normalization Layer (object resolution, address expansion)
       │         │
       │         └──────────────┐
       │                        v
       ├── Mode 2: normalized JSON ──> Schema Validation
       │                        │
       │                        v
       └──────────────────> Analysis Engine (6-dimension set intersection)
                                │
                                v
                          Result Generator
                                │
                                v
                       Compact JSON Response
```

## License

Apache 2.0

---

## Addendum: Why Two Input Modes?

This MCP server is designed for automated compliance checking over large firewall rulesets where false positives and false negatives have real security consequences. The architecture balances two competing concerns:

### The case for built-in parsers (Mode 1)

Firewall configs contain **named object graphs** — a rule may reference `PROD-SERVERS`, which is an address group containing `WEB-TIER` and `DB-TIER`, each referencing CIDRs. Resolving these correctly requires recursive expansion with cycle detection and conservative fallback (unresolvable references treated as `any` to avoid false negatives). The built-in parsers do this deterministically. An LLM doing this via reasoning will occasionally miss nested group members or hallucinate resolutions — margins that matter for security policy decisions.

### The case for normalized input (Mode 2)

The vendor parsers are the fragility source. Each parser is ~400 lines of format-specific code that can break when vendor OS versions change output formats. We've already seen bugs in the PAN-OS parser (wrong XML element selection in wrapped configs). When a parser gets a format wrong, the analysis engine produces incorrect results — and the caller has no way to know.

### The hybrid solution

Mode 2 (normalized JSON) addresses the fragility problem while preserving correctness:

- **When the caller already has structured data** (e.g., from a REST API, or when the AI agent can reliably extract fields), it bypasses the fragile parsers entirely and sends resolved addresses directly to the analysis engine.
- **When the caller has raw CLI/config output**, Mode 1's parsers handle the complex extraction and object resolution.
- **`parse_policy` bridges the gap** — the caller can inspect what the parser extracted, verify rule counts and address resolution, and decide whether to trust the parser output or re-extract manually.

The analysis engine — the part that does CIDR arithmetic, port range intersection, and multi-dimensional set comparison — is the irreplaceable value. It's vendor-agnostic, deterministic, and well-tested. The parsers are a convenience layer; the normalized schema is the true API surface.
