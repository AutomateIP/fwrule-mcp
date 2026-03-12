# FWRule MCP — Firewall Rule Analyzer

An MCP server that analyzes firewall rule overlap, duplication, shadowing, and conflicts across multi-vendor firewall policies.

## Supported Vendors

| Vendor | Format | Versions |
|--------|--------|----------|
| Palo Alto PAN-OS / Panorama | XML config export | 9.x - 11.x |
| Cisco ASA | `show running-config` text | 9.x+ |
| Cisco FTD | JSON export from FMC | 6.x - 7.x |
| Check Point | JSON `show-access-rulebase` | R80.x - R82.x |
| Juniper SRX | `display set` format | 19.x+ |

## Quick Start

```bash
# Install
uv sync

# Run tests
uv run pytest

# Run the testing agent
uv run python tests/test_agent.py

# Start the MCP server
uv run fwrule-mcp
```

## MCP Tools

### `analyze_firewall_rule_overlap`

Analyze whether a candidate firewall rule overlaps with an existing ruleset.

**Inputs:**
- `vendor` — Firewall vendor (`panos`, `asa`, `ftd`, `checkpoint`, `juniper`)
- `ruleset_payload` — Complete firewall configuration in vendor-native format
- `candidate_rule_payload` — The candidate rule to analyze
- `os_version` — Optional OS version string
- `context_objects` — Optional JSON with supplemental object definitions
- `candidate_position` — Optional intended insertion position (1-based)

**Detects:**
- Exact duplicates
- Shadowed rules (candidate would never fire)
- Action conflicts (overlapping traffic, opposing actions)
- Partial overlaps
- Superset/subset relationships

### `list_supported_vendors`

List all supported firewall vendors with format requirements.

## Testing

```bash
# Full test suite (419 tests)
uv run pytest

# Mock payload tests only
uv run pytest tests/test_mock_payloads.py -v

# Testing agent with formatted report
uv run python tests/test_agent.py

# Single vendor / scenario
uv run python tests/test_agent.py --vendor panos --scenario conflict --verbose
```

## Development

```bash
uv sync --dev
uv run pytest
uv run ruff check src/
```

## Architecture

```
MCP Client Request
       |
       v
  FastMCP Server (fwrule_mcp.server)
       |
       v
  Vendor Parser (plugin registry)
  [PAN-OS | ASA | FTD | Check Point | Juniper]
       |
       v
  Normalization Layer (object resolution, address/service expansion)
       |
       v
  Analysis Engine (6-dimension set intersection, fail-fast)
       |
       v
  Result Generator (findings, explanations, remediation)
       |
       v
  Structured JSON Response
```

## License

Apache 2.0
