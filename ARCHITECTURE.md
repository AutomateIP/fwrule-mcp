# Firewall Rule Overlap Analysis MCP Server — Architecture Design Document

**Version:** 1.0
**Date:** 2026-03-12
**Classification:** Open Source Architecture Plan

---

## Phase 1 — Problem Framing

### 1.1 Problem Restatement

Firewall administrators and network automation engineers routinely need to evaluate whether a candidate firewall rule is safe, redundant, or problematic to add to an existing policy. Today this analysis is either manual (error-prone, slow) or handled by expensive proprietary tools. The goal is to build an open-source MCP server that accepts a firewall vendor, OS version, existing ruleset, and a candidate rule, then returns a structured, machine-readable analysis of rule overlap relationships.

The system must serve both human-driven workflows (an operator querying an AI assistant) and automated pipelines (CI/CD, change management workflows, compliance checks). By exposing analysis as an MCP tool, any MCP-capable client — including Claude, automation platforms, and custom tooling — can consume the capability without bespoke integration.

### 1.2 Primary Challenges

**Vendor Heterogeneity**
Each firewall vendor uses a fundamentally different configuration format, object naming convention, and rule evaluation model. Palo Alto uses XML-based configurations with named address and service objects. Cisco ASA uses ACL-style flat text. Check Point uses a proprietary database export. Juniper uses a hierarchical set/tree format. There is no universal intermediate format in wide adoption.

**Implicit Object Resolution**
Rules rarely enumerate raw IP addresses and port numbers directly. They reference named objects, object groups, and service definitions. Meaningful overlap analysis requires resolving these references before any comparison can occur. An "any" address in one vendor's syntax may mean something subtly different than in another's.

**Rule Ordering Semantics**
Firewall policies are ordered lists. A rule is "shadowed" only relative to rules above it. Analysis must be order-aware, not just set-theoretic. The comparison logic must preserve and reason about position.

**Protocol and Service Complexity**
IP protocols, TCP/UDP ports, ICMP types, application-layer identifiers (Palo Alto App-ID, Cisco NBAR), and custom service objects all require normalization into comparable structures. A candidate rule permitting "https" must be recognized as overlapping with a rule permitting TCP/443.

**Partial Overlap Classification**
Pure duplication is easy to detect. The hard cases are partial overlaps — where a candidate rule's source range partially intersects an existing rule's destination, or where a protocol match is broader in one rule and narrower in another. These partial overlaps require interval and set-intersection logic, not simple equality checks.

**Explainability Requirement**
The output cannot simply be a boolean. Automation consumers need to know which specific rules interact, how they interact, and ideally why. This requires the analysis engine to produce traceable reasoning, not opaque results.

### 1.3 Key Assumptions

- The caller is responsible for supplying the complete relevant ruleset and candidate rule. The server does not fetch configurations from live devices.
- Vendor and OS version are provided explicitly; the server does not attempt to auto-detect format.
- Object definitions (address objects, service objects, zones) may be supplied as optional context payloads alongside the ruleset, since many vendor formats store objects separately from policy rules.
- Rule ordering in the submitted policy reflects the actual enforcement order on the device.
- The server is stateless per request; it does not persist rulesets between calls unless a caching layer is explicitly designed in.
- "Conflict" in this context means two rules with overlapping match criteria but opposite or incompatible actions (e.g., permit vs. deny for the same traffic class).
- The system targets analyst-grade accuracy, not device-emulation accuracy. Edge cases in vendor-specific ASIC behavior are out of scope for v1.

### 1.4 Questions to Answer Before Implementation

1. What is the maximum expected ruleset size per request? (Hundreds? Thousands? Tens of thousands?) This drives parsing performance requirements and whether streaming ingestion is needed.
2. Should the server support stateful session context, where an operator uploads a ruleset once and then submits multiple candidate rules in succession? Or is each request fully self-contained?
3. Are application-layer identifiers (App-ID, NBAR) in scope for overlap analysis, or only network-layer attributes?
4. What does "partial overlap" mean for the consuming workflow? Does a 10% address overlap qualify for flagging, or only a meaningful threshold?
5. Should zone-based policies and interface-based policies be treated as fundamentally different models, or normalized into the same zone abstraction?
6. What serialization format should the MCP response use for the structured output — nested JSON objects, or a flatter schema?
7. Are IPv6 policies in scope from day one, or a v2 consideration?
8. Should the system produce remediation suggestions (e.g., "reorder rule X above rule Y") or only analytical findings?
9. What license is appropriate for the open-source release, considering that some vendor configuration formats have usage restrictions in documentation?
10. Should the system be deployable as a standalone server, a Python library, or both?

---

## Phase 2 — System Architecture

### 2.1 Architectural Overview

The system is structured as five cooperating layers, each with a clear responsibility boundary. The architecture follows a pipeline pattern: data enters at the MCP boundary, flows through parsing and normalization, enters the analysis engine, and exits as a structured response. Vendor-specific logic is fully contained within the parsing layer.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        MCP Server Layer                              │
│   (FastMCP, tool registration, request validation, response schema) │
└─────────────────────────────┬───────────────────────────────────────┘
                              │ Validated request payload
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  Vendor Parsing Layer                                │
│   (Plugin registry, vendor dispatching, raw config → parsed rules)  │
│                                                                      │
│   ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌───────────┐ │
│   │ PAN-OS Parser│ │  ASA Parser  │ │  FTD Parser  │ │  CP Parser│ │
│   └──────────────┘ └──────────────┘ └──────────────┘ └───────────┘ │
└─────────────────────────────┬───────────────────────────────────────┘
                              │ Vendor-parsed rule structures
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  Rule Normalization Layer                            │
│   (Object resolution, address expansion, service normalization,     │
│    zone mapping, action mapping → NormalizedRule objects)           │
└─────────────────────────────┬───────────────────────────────────────┘
                              │ NormalizedRule list + NormalizedCandidate
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│              Rule Comparison & Analysis Engine                       │
│   (Address set intersection, port/protocol intersection,            │
│    overlap classification, ordering analysis, conflict detection)   │
└─────────────────────────────┬───────────────────────────────────────┘
                              │ Raw analysis findings
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  Result Generation Layer                             │
│   (Finding assembly, explanation generation, severity scoring,      │
│    remediation suggestions, structured JSON output)                 │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 Component Descriptions

**MCP Server Layer**
The outermost boundary. Built on FastMCP, this layer owns tool registration, input schema definition, request deserialization, and response serialization. It enforces the contract between MCP clients and the internal system. It is intentionally thin — it delegates all business logic downstream. The layer also handles error surfacing, converting internal exceptions into structured MCP error responses.

**Vendor Parsing Layer**
A plugin registry maps (vendor, os_family) tuples to parser implementations. Each parser is a self-contained module that accepts the raw configuration payload — whether XML, text, JSON, or binary export — and emits a vendor-neutral intermediate structure: a list of partially-parsed rule objects with references still intact. The parsing layer also extracts the object definition tables (address objects, service objects, groups) that the normalization layer will need.

Object extraction is separated from rule extraction within each parser because object tables are structurally distinct in every vendor format and must be available before rule normalization can proceed.

**Rule Normalization Layer**
Takes vendor-parsed rule objects and resolves all references — named objects are expanded to their constituent IP prefixes, port ranges, and protocols. Groups are recursively flattened. Vendor-specific action semantics ("permit"/"deny"/"drop"/"reject") are mapped to a canonical action enum. Zones and interfaces are normalized to a zone abstraction. The output is a list of NormalizedRule objects, each expressed entirely in concrete, comparable terms.

**Rule Comparison and Analysis Engine**
The analytical core. Receives the normalized existing ruleset and the normalized candidate rule. Performs set-theoretic and interval-arithmetic comparisons across all relevant match dimensions. Classifies the relationship between the candidate and each existing rule. This layer has no knowledge of vendors, parsing, or MCP — it operates purely on normalized data structures.

**Result Generation Layer**
Consumes the raw analysis findings and produces the final structured response. Assembles human-readable explanations, assigns severity and classification labels, groups related findings, and optionally generates remediation guidance. This layer also handles response schema compliance.

### 2.3 System Boundaries

- The system boundary is the MCP tool interface. Everything outside that boundary — the client, the device, the configuration management system — is external.
- Configuration payloads are accepted as strings (the raw config text or serialized format). The server never makes network calls to live devices.
- The vendor parsing layer boundary is the plugin interface contract. All vendor-specific knowledge lives inside this boundary.
- The normalization layer boundary is the NormalizedRule schema. Below this boundary, nothing vendor-specific exists.

### 2.4 Separation of Responsibilities

| Layer | Knows About | Does NOT Know About |
|---|---|---|
| MCP Server | MCP protocol, input schema, transport | Vendors, rule logic |
| Vendor Parsers | Vendor syntax, object models | Other vendors, NormalizedRule |
| Normalization | NormalizedRule schema, object resolution | Vendors, overlap logic |
| Analysis Engine | NormalizedRule, overlap algorithms | Vendors, MCP, formatting |
| Result Generation | Finding structure, explanation templates | Vendors, parsing, algorithms |

---

## Phase 3 — Data Flow Design

### 3.1 Full Request Lifecycle

**Step 1 — MCP Request Ingestion**

The MCP client sends a tool call to `analyze_firewall_rule_overlap`. The FastMCP layer receives the call and validates that all required fields are present and well-typed. Validation at this stage is structural only: is `vendor` a recognized string? Is `ruleset_payload` a non-empty string? Is `candidate_rule` present?

If validation fails, FastMCP returns a structured error immediately. No downstream processing begins.

The request is deserialized into an `AnalysisRequest` value object containing: vendor identifier, OS/version string, raw ruleset payload, raw candidate rule payload, and an optional context object containing address object definitions, service definitions, and zone mappings.

**Step 2 — Vendor Parser Dispatch**

The plugin registry is queried with the (vendor, os_version) tuple. The registry returns the appropriate parser instance. If no parser is registered for the requested vendor/version combination, a structured `UNSUPPORTED_VENDOR` error is returned.

The selected parser operates in two sub-phases:
- Object extraction: Parse all named address objects, service objects, and groups from the configuration payload (or from the supplied context object if provided separately).
- Rule extraction: Parse the ordered list of rules from the configuration payload, producing vendor-parsed rule objects that retain their original field names and reference strings. Rule ordering is preserved as an explicit position index.

The parser emits a `ParsedPolicy` structure: an ordered list of `VendorRule` objects plus an `ObjectTable` mapping object names to their definitions.

**Step 3 — Existing Ruleset Normalization**

The normalization layer receives the `ParsedPolicy`. For each `VendorRule` in positional order, it:
- Resolves all named source address references to sets of IP prefixes (with recursive group expansion)
- Resolves all named destination address references similarly
- Resolves all service references to sets of (protocol, port-range) tuples
- Maps vendor zone/interface identifiers to canonical zone names
- Maps vendor action values to the canonical `Action` enum
- Maps vendor rule state (enabled/disabled) to a boolean
- Assigns a stable rule identifier (original name if present, or positional index)

The output is an ordered list of `NormalizedRule` objects. The original ordering is preserved through explicit position indices.

**Step 4 — Candidate Rule Normalization**

The candidate rule payload is parsed using the same vendor parser (since the candidate is expressed in the same vendor syntax as the ruleset). It produces a single `VendorRule`. This is passed through the same normalization pipeline, using the same `ObjectTable` from Step 2 to resolve any object references the candidate rule contains.

The result is a single `NormalizedCandidate` object, structurally identical to `NormalizedRule`.

**Step 5 — Overlap Analysis**

The analysis engine receives the ordered `NormalizedRule` list and the `NormalizedCandidate`. It performs the following comparisons in order:

First pass — exact duplication check: Compares the candidate's complete match specification against each existing rule. Exact duplicates are flagged immediately.

Second pass — shadowing check: For each existing rule that appears before any position the candidate would occupy, check whether the existing rule's match set is a superset of the candidate's match set across all dimensions. If so, the candidate would never be reached for any traffic it intends to match.

Third pass — conflict check: For rules where the match specification overlaps (at least partially) but the action differs, a conflict is recorded.

Fourth pass — partial overlap detection: For all remaining interactions, compute the intersection across each dimension and record partial overlaps with specifics about which dimension(s) intersect and to what degree.

Fifth pass — expansion/narrowing analysis: Assess whether the candidate rule is broader than or narrower than any overlapping existing rule, providing context for whether the candidate is extending or restricting current policy.

Each finding records: the interacting rule's identifier, position, the relationship type, and the specific dimensions involved.

**Step 6 — Structured Response Generation**

The result generator receives the list of findings and assembles the response:
- A boolean `overlap_exists` flag
- A list of `Finding` objects, each with: rule reference, overlap type enum, affected dimensions, a natural-language explanation string, and an optional remediation suggestion
- An overall `analysis_summary` string
- Metadata: analysis timestamp, vendor/version processed, rule counts

The response is serialized to JSON and returned through FastMCP as the tool result.

---

## Phase 4 — Normalized Rule Model

### 4.1 Design Principles

The normalized rule model must be:
- Vendor-agnostic: no field names, identifiers, or concepts tied to any vendor
- Fully resolved: no unresolved references remain; all named objects are expanded
- Order-preserving: position in the policy is explicit
- Dimension-complete: every dimension relevant to overlap analysis is represented
- Extensible: new dimensions (e.g., application-layer identifiers) can be added without breaking existing analysis logic

### 4.2 Address Representation

Addresses are represented as sets of IP prefix/range structures. Each structure holds:
- Address family: IPv4 or IPv6
- Representation type: CIDR prefix, explicit range (start-end), or a special `ANY` sentinel
- The original reference name (for traceability in explanations)

A single rule's source or destination is a set of these structures, representing the union of all matched addresses. The `ANY` sentinel short-circuits intersection logic.

Freeform host names are not resolved to IPs by the normalization layer (that would require DNS); they are preserved as opaque identifiers that can only match other rules referencing the same name.

### 4.3 Service and Protocol Representation

Services are represented as sets of protocol-match structures. Each structure holds:
- IP protocol number (or `ANY`)
- For TCP/UDP: a set of port ranges (start-end pairs), or `ANY`
- For ICMP: type and code values, or `ANY`
- Application-layer identifier (optional, vendor-specific string): preserved as an opaque tag

A service set represents the union of all matched traffic classes.

### 4.4 Zone Representation

Zones are represented as a canonical zone name (string) or an `ANY` sentinel. In zone-based policy models, a rule has source zones and destination zones. In interface-based models, interface names are mapped to synthesized zone names.

If zone information is not present in the vendor configuration, the field is populated with `ANY` to preserve analysis correctness.

### 4.5 Action Representation

Actions are a closed enum:
- `PERMIT`
- `DENY`
- `DROP` (silent deny)
- `REJECT` (deny with RST/ICMP unreachable)
- `LOG_ONLY`
- `UNKNOWN` (for unrecognized vendor action strings)

For overlap analysis, `DENY`, `DROP`, and `REJECT` are treated as equivalent in the blocking dimension but are preserved distinctly for explanation purposes.

### 4.6 Complete NormalizedRule Structure (Conceptual)

```
NormalizedRule:
  rule_id: string                     # vendor name or positional index
  position: integer                   # 1-based order in policy
  enabled: boolean
  
  match:
    source_zones: ZoneSet             # set of zone names or ANY
    destination_zones: ZoneSet
    source_addresses: AddressSet      # set of IP prefixes/ranges or ANY
    destination_addresses: AddressSet
    services: ServiceSet              # set of protocol/port structures or ANY
    applications: ApplicationSet      # optional: app-layer identifiers
    
  action: Action                      # PERMIT / DENY / DROP / REJECT
  
  metadata:
    original_name: string
    description: string
    vendor_tags: dict                 # vendor-specific fields preserved for traceability
    parsed_from: string              # parser identifier that produced this
```

### 4.7 Extensibility Considerations

Application-layer identifiers (App-ID, NBAR) are included as an optional set but are not required for network-layer overlap analysis. The analysis engine checks for their presence and incorporates them when available, but degrades gracefully when they are absent.

Future dimensions — VLAN tags, user identity groups, URL categories — can be added to the `match` block without modifying the core comparison logic, as long as the analysis engine is designed to iterate over match dimensions dynamically.

---

## Phase 5 — Vendor Abstraction Strategy

### 5.1 Plugin Architecture

Each vendor parser is implemented as a separate module conforming to a `VendorParser` abstract interface. The interface contract specifies:
- A registration declaration: which (vendor, os_family) tuples this parser handles
- A `parse_policy(raw_payload, context)` method returning a `ParsedPolicy`
- A `parse_single_rule(raw_rule, object_table)` method for candidate rule parsing

The plugin registry is populated at startup. Each parser module registers itself with the registry on import. New vendors are added by creating a new parser module and registering it — no changes to core system code are required.

The registry supports version ranges, so a parser can declare that it handles PAN-OS 9.x through 11.x, with a separate parser optionally handling a legacy 8.x format.

### 5.2 Vendor Configuration Formats

Each supported vendor requires a different parsing approach:

**Palo Alto (PAN-OS / Panorama)**
Configuration is exported as XML. The parser uses an XML tree-walking strategy. Address objects, address groups, service objects, service groups, and security policies live in well-known XPaths. Panorama introduces device groups and shared object inheritance, which the parser must handle by building a merged object table respecting inheritance order.

**Cisco ASA**
Configuration is a flat text file using a keyword-indented syntax. The parser uses line-by-line text parsing with state-machine logic. ACL entries, object definitions, and object-group definitions are extracted in separate passes. Network objects, service objects, and protocol objects each have distinct syntax patterns.

**Cisco FTD**
FTD policies can be exported via FMC REST API or as structured JSON. The parser targets the JSON export format. Access control rules have a well-defined JSON schema. FTD introduces Security Intelligence zones and Application detectors, which are mapped to the optional application dimension.

**Check Point**
Check Point policies are exported as a JSON package (via the management API's `show-package` command). The parser navigates the package structure: rulebase objects, network objects, and service objects are stored in separate JSON arrays and cross-referenced by UID. The parser builds a UID-to-object lookup table before resolving rule references.

**Juniper**
Juniper SRX configurations use either the hierarchical `set` command format or the bracketed configuration format. Both can be exported. The parser handles the hierarchical set format as the primary target, building a nested dictionary from the flat set commands and then navigating the `firewall family inet` or `security policies` subtree.

### 5.3 Object Reference Resolution

Object resolution is handled in the normalization layer, not the parsing layer. The parsing layer's responsibility is to faithfully extract the object table and rule references. The normalization layer's responsibility is to resolve them.

Resolution is recursive. A named address group may reference other groups. The normalizer uses a depth-first traversal with cycle detection (to handle malformed configs with circular references). The resolved output is the complete set of leaf-level IP prefixes or port ranges.

When an object reference cannot be resolved (the object is missing from the provided payload), the normalizer records an `UNRESOLVABLE_REFERENCE` warning in the rule's metadata rather than failing the entire analysis. The affected dimension is marked as `UNKNOWN`, which the analysis engine treats conservatively (it cannot assert overlap or non-overlap for unknown dimensions).

### 5.4 Normalizing Vendor Differences

Key vendor semantic differences that must be handled explicitly:

- **"Any" semantics:** All vendors have an "any" concept, but some vendors use it to mean any address within a defined zone while others mean globally any. The normalizer preserves this distinction through the zone dimension.
- **Negated objects:** Some vendors support negated address objects (Palo Alto uses "negate source"). These must be represented in the address set as a complement operation.
- **Service-object inheritance:** Check Point service objects can inherit from base objects. The resolver must follow the inheritance chain.
- **Application-default ports:** Palo Alto's "application-default" service value means "use the default ports for the specified application." This cannot be resolved without an application signature database; it is mapped to `UNKNOWN_PORTS` with the application name preserved.
- **Hit counts and statistics:** These are parsed and preserved in vendor_tags but do not influence overlap analysis.

### 5.5 Adding a New Vendor

The process for adding a new vendor parser is:
1. Create a new module under `parsers/vendors/`
2. Implement the `VendorParser` interface
3. Register the parser with the (vendor, os_family) identifiers
4. Add the object extraction logic
5. Add the rule extraction logic
6. Add a test fixture with a representative configuration snippet
7. Add the vendor to documentation

No changes to the normalization layer, analysis engine, or MCP server are required.

---

## Phase 6 — Rule Overlap Analysis Strategy

### 6.1 Foundational Approach

Firewall rule overlap is fundamentally a multi-dimensional set intersection problem. A firewall rule matches traffic when all of its dimensions are simultaneously satisfied: source zone AND source address AND destination zone AND destination address AND protocol/service. Two rules interact when there exists at least one packet that matches both rules' criteria simultaneously.

The analysis therefore requires computing the intersection across all dimensions. If the intersection across all dimensions is non-empty, the rules interact. The nature of the interaction then depends on the action and the relative ordering.

### 6.2 Duplicate Detection

Two rules are exact duplicates when every match dimension of the candidate rule is set-theoretically equal to the corresponding dimension of an existing rule. Equality for address sets means the same collection of IP prefixes (after prefix normalization — e.g., 10.0.0.0/24 and 10.0.0.0-10.0.0.255 are equal). Equality for service sets means the same collection of protocol/port-range pairs.

Exact duplication is checked first because it is the simplest case and allows early exit.

### 6.3 Shadow Analysis

A rule is shadowed when a preceding rule's match set is a superset of the candidate's match set. This means: for every packet the candidate would match, the preceding rule would also match it and act on it first.

The superset check is performed dimension by dimension. An existing rule's address set is a superset of the candidate's address set when every IP prefix in the candidate's set is fully contained within some IP prefix in the existing set. For services, a port range [80-80] is a subset of [1-65535]. `ANY` in the existing rule is always a superset of any candidate value.

Shadow analysis is order-sensitive: only rules with a lower position index than the candidate's intended insertion position are checked for shadowing.

Partial shadowing (where the existing rule is a superset on some dimensions but not all) is classified separately as a partial overlap, not a shadow.

### 6.4 Conflict Detection

A conflict exists when the candidate rule and an existing rule have overlapping match criteria but opposing actions (PERMIT vs. DENY/DROP/REJECT). The intersection of their match sets is non-empty, but they would produce different outcomes for packets in that intersection.

The significance of a conflict depends on rule ordering. If the conflicting existing rule precedes the candidate, the candidate's action would never be reached for conflicting traffic — this is a shadow conflict. If the candidate would precede the conflicting existing rule, the candidate overrides it for the intersecting traffic class.

### 6.5 Partial Overlap Classification

Partial overlap is the most common and most complex case. It is detected when the multi-dimensional intersection is non-empty but neither rule is a full superset/subset of the other.

The analysis records which dimensions contribute to the intersection and which do not. For example: "candidate source address 10.0.1.0/24 partially overlaps existing rule's source range 10.0.0.0/22 (10.0.1.0/24 is a subset). Destination: no overlap. Service: full overlap."

The explanation identifies the intersecting sub-ranges explicitly. For IP prefixes, this means computing the actual overlapping prefix. For port ranges, this means computing the overlapping range boundary.

Partial overlaps are further sub-classified:
- **Subset relationship:** Candidate matches are a strict subset of an existing rule's matches
- **Superset relationship:** Candidate matches are a strict superset of an existing rule's matches
- **Intersecting:** Neither is a subset of the other; they share a proper intersection

### 6.6 Expansion and Narrowing Analysis

Beyond overlap classification, the analysis identifies whether the candidate rule expands or narrows the effective policy:
- **Expansion:** The candidate permits traffic not currently permitted by any existing rule, or denies traffic not currently denied.
- **Narrowing:** The candidate creates a more specific exception to a broader existing rule.

This contextual analysis helps operators understand policy impact, not just overlap presence.

### 6.7 Algorithmic Strategies

**IP Prefix Intersection:**
Use prefix trie (radix tree) data structures for efficient subset/superset/intersection checks across large address sets. An interval arithmetic approach works for explicit ranges.

**Port Range Intersection:**
Simple integer range intersection. A service set is a union of disjoint ranges; intersection with another union-of-ranges produces another union of disjoint ranges.

**Zone Intersection:**
Zone matching is set intersection on string identifiers, with `ANY` as the universal set. Zone matrix relationships (which zones can communicate) are not in scope for v1 — zone names are treated opaquely.

**Multi-Dimensional Intersection:**
The overall match intersection is the Cartesian product condition: all dimension intersections must be non-empty. This allows early exit on the first empty dimension intersection (fail-fast strategy).

**Performance Note:**
For large rulesets, prefix trie construction is O(n log n) with O(log n) lookup, making it practical even for thousands of rules. The analysis of M existing rules against one candidate is O(M * D) where D is the cost of dimension intersection — manageable without distributed computing for typical policy sizes.

---

## Phase 7 — Performance Planning

### 7.1 Baseline Sizing Assumptions

A realistic enterprise firewall policy contains:
- Small: 100-500 rules, 500-2000 address objects
- Medium: 500-2000 rules, 2000-10000 address objects
- Large: 2000-10000 rules, 10000-50000 address objects
- Extra-large (Panorama / MSSP): 10000+ rules, 100000+ address objects

The system must handle medium workloads with sub-second response time and large workloads within a few seconds. Extra-large workloads may require optimization strategies.

### 7.2 Parsing Performance

Parsing is typically the most expensive phase for large configurations. Strategies:

**Lazy object resolution:** Do not resolve all objects in the policy during normalization. Only resolve objects that appear in rules intersecting with the candidate's dimensions. Since most rules will not interact with the candidate, this can dramatically reduce resolution work.

**Incremental parsing:** For stateful session scenarios (future), parse the policy once and cache the `ParsedPolicy` and `ObjectTable`. Subsequent candidate analyses reuse the cached state.

**Streaming parsing:** For very large XML or text configs, use streaming parsers (SAX-style) rather than loading the entire document into memory before parsing begins.

### 7.3 Analysis Engine Performance

**Pre-filtering:** Before performing expensive set-intersection calculations, apply fast pre-filter checks. If the candidate's source CIDR and an existing rule's source CIDR share no common bits in the first octet, full intersection calculation is unnecessary. Pre-filters reduce the number of rules requiring full analysis.

**Trie-based acceleration:** Build a prefix trie from all source address sets in the existing policy. Query the trie with the candidate's source addresses to identify candidate-intersecting rules in O(log n) rather than O(n).

**Dimension ordering:** Check the most selective dimension first. If zone information is present and the candidate's zones are narrow, zone filtering alone may eliminate the majority of existing rules from full analysis.

**Parallel analysis:** The overlap check of the candidate against each existing rule is embarrassingly parallel. For large rulesets, analysis of different existing rules can proceed concurrently.

### 7.4 Memory Management

Large configuration payloads can be memory-intensive. Strategies:
- Stream large payloads rather than holding them fully in memory during parsing
- Release raw payload strings after parsing; only retain the normalized structures
- For the `ObjectTable`, use lazy materialization — expand groups only when first referenced, and cache the expanded result

### 7.5 Request-Level Constraints

To protect server stability:
- Define maximum payload size limits per configuration type
- Implement a maximum rule count threshold beyond which the server returns a warning and processes a configurable subset (e.g., first N rules)
- Set analysis time budgets with early termination and partial-result return

### 7.6 Future Scaling Considerations

If the system evolves to handle continuous integration workflows with hundreds of simultaneous analyses:
- Stateless design allows horizontal scaling behind a load balancer
- A shared cache layer (Redis or similar) for parsed policy state enables session reuse across scaled instances
- Asynchronous processing with job IDs would decouple submission from result retrieval for very large workloads

---

## Phase 8 — Security Considerations

### 8.1 Threat Model

The server processes untrusted input: firewall configuration payloads supplied by callers. A malicious or malformed payload could attempt to exploit the parsing layer, exhaust server resources, or extract information about the server environment.

The server also handles potentially sensitive network topology data. The configurations it processes describe real network architectures.

### 8.2 Input Validation and Sanitization

**Structural validation:** Before dispatching to any parser, validate that the payload conforms to the expected format at a high level. For XML payloads, validate well-formedness. For JSON payloads, validate schema compliance. Reject structurally invalid payloads at the MCP layer before any parsing begins.

**XML-specific risks:** XML parsers are vulnerable to XML External Entity (XXE) attacks, Billion Laughs (entity expansion) attacks, and DOCTYPE injection. All XML parsers must be configured with: external entity processing disabled, DTD processing disabled, entity expansion limits enforced.

**Size limits:** Enforce maximum payload sizes at the MCP ingestion layer. Define separate limits for the ruleset payload, the candidate rule payload, and the optional context object. Payloads exceeding limits are rejected with a clear error.

**Content validation:** Validate that object names, rule names, and address values conform to expected patterns. Reject payloads containing characters outside the expected character set for the vendor format.

### 8.3 Resource Exhaustion Mitigation

**Recursive group expansion depth limit:** Object groups can theoretically be arbitrarily nested (or maliciously constructed to be deeply nested or circular). Impose a maximum recursion depth on group resolution. Detect and break cycles. Return a warning for truncated resolutions.

**Analysis time budget:** Each analysis request runs with a maximum wall-clock time limit. If the analysis does not complete within the budget, return partial results with a timeout indicator rather than hanging indefinitely.

**Memory limits:** Enforce per-request memory quotas if running in a managed environment. Return a resource-limit error rather than OOM-crashing.

**Rule count limits:** Reject rulesets exceeding the configured maximum rule count.

### 8.4 Dependency Supply Chain

Vendor parsers will likely use third-party parsing libraries (XML parsers, JSON parsers, YAML parsers, potentially parser-combinators). These are attack surface. Strategies:
- Pin dependency versions explicitly (no floating version ranges)
- Run dependency vulnerability scanning in CI
- Prefer well-audited standard library parsers over obscure third-party alternatives where possible
- Regularly update dependencies and re-run security scans

### 8.5 Data Sensitivity

Firewall configurations are sensitive. The server should:
- Not log the contents of configuration payloads (only metadata: vendor, rule count, analysis duration)
- Not persist any configuration data beyond the scope of a single request
- Document clearly in the README that the server processes potentially sensitive network topology data and should be deployed with appropriate access controls
- Recommend TLS and authentication for any network-exposed deployment

### 8.6 Deployment Security

- The server should run as a non-root, minimal-privilege process
- Deployments behind an API gateway or mTLS-enforcing proxy are recommended for production use
- Docker images should be based on minimal base images with no unnecessary tools

---

## Phase 9 — Repository and Project Structure

### 9.1 Repository Layout

```
firewall-overlap-mcp/
│
├── README.md                     # Project overview, quick start, use cases
├── CONTRIBUTING.md               # Contribution guide, parser extension tutorial
├── LICENSE                       # Open source license (Apache 2.0 recommended)
├── CHANGELOG.md                  # Version history
│
├── pyproject.toml                # Package metadata, dependencies
├── Makefile                      # Common dev tasks: test, lint, format, build
│
├── src/
│   └── firewall_overlap_mcp/
│       ├── __init__.py
│       ├── server.py             # FastMCP app, tool registration
│       │
│       ├── models/               # Data models and schemas
│       │   ├── request.py        # AnalysisRequest schema
│       │   ├── response.py       # AnalysisResponse, Finding schema
│       │   ├── normalized.py     # NormalizedRule, NormalizedCandidate
│       │   └── common.py         # AddressSet, ServiceSet, ZoneSet, Action enum
│       │
│       ├── parsers/              # Vendor parsing layer
│       │   ├── base.py           # VendorParser abstract interface
│       │   ├── registry.py       # Plugin registry, dispatch logic
│       │   └── vendors/
│       │       ├── panos/        # Palo Alto PAN-OS parser
│       │       │   ├── __init__.py
│       │       │   ├── parser.py
│       │       │   └── objects.py
│       │       ├── asa/          # Cisco ASA parser
│       │       ├── ftd/          # Cisco FTD parser
│       │       ├── checkpoint/   # Check Point parser
│       │       └── juniper/      # Juniper SRX parser
│       │
│       ├── normalization/        # Rule normalization layer
│       │   ├── normalizer.py     # NormalizedRule assembly
│       │   ├── resolver.py       # Object reference resolution
│       │   └── mappers.py        # Vendor-specific action/zone mappers
│       │
│       ├── analysis/             # Rule comparison engine
│       │   ├── engine.py         # Main analysis orchestration
│       │   ├── address.py        # IP prefix/range intersection logic
│       │   ├── service.py        # Protocol/port intersection logic
│       │   ├── zone.py           # Zone matching logic
│       │   └── classifier.py     # Overlap type classification
│       │
│       ├── results/              # Result generation layer
│       │   ├── generator.py      # Finding assembly
│       │   ├── explanations.py   # Natural language explanation templates
│       │   └── remediation.py    # Remediation suggestion logic
│       │
│       └── utils/
│           ├── validation.py     # Input validation utilities
│           ├── limits.py         # Resource limit constants
│           └── logging.py        # Structured logging setup
│
├── tests/
│   ├── unit/
│   │   ├── test_models.py
│   │   ├── test_normalization.py
│   │   ├── test_analysis_engine.py
│   │   ├── test_address_intersection.py
│   │   ├── test_service_intersection.py
│   │   └── parsers/
│   │       ├── test_panos.py
│   │       ├── test_asa.py
│   │       ├── test_ftd.py
│   │       ├── test_checkpoint.py
│   │       └── test_juniper.py
│   │
│   ├── integration/
│   │   ├── test_mcp_tool.py      # End-to-end MCP tool tests
│   │   └── test_full_pipeline.py # Full request lifecycle tests
│   │
│   └── fixtures/
│       ├── panos/                # Sample PAN-OS configs
│       ├── asa/                  # Sample ASA configs
│       ├── ftd/                  # Sample FTD configs
│       ├── checkpoint/           # Sample Check Point exports
│       └── juniper/              # Sample Juniper configs
│
├── docs/
│   ├── architecture.md
│   ├── mcp-usage.md
│   ├── supported-vendors.md
│   ├── extending-vendors.md
│   ├── overlap-analysis-explained.md
│   └── deployment.md
│
├── examples/
│   ├── basic_analysis.py
│   ├── panos_example.py
│   └── asa_example.py
│
└── .github/
    ├── workflows/
    │   ├── ci.yml                # Test + lint on PR
    │   └── release.yml           # Publish to PyPI
    └── ISSUE_TEMPLATE/
        ├── bug_report.md
        └── vendor_request.md     # Template for requesting new vendor support
```

### 9.2 Package Naming and Versioning

The package follows semantic versioning. Minor versions may introduce new vendor parsers. Patch versions fix parsing bugs. Breaking changes to the MCP tool schema or NormalizedRule model increment the major version.

### 9.3 Development Environment

A `Makefile` provides standardized targets: `make test`, `make lint`, `make format`, `make build`, `make dev-server`. This ensures contributor onboarding is frictionless regardless of IDE.

---

## Phase 10 — Testing Strategy

### 10.1 Testing Pyramid

The test suite follows a pyramid structure: many unit tests, fewer integration tests, targeted end-to-end tests.

**Unit tests** cover every discrete function in isolation: address intersection, port range intersection, zone matching, overlap classification, object resolution, and each vendor parser independently. These tests are fast and run on every commit.

**Integration tests** cover the full pipeline from parsed input through to structured output, using realistic fixture configurations. These verify that the layers compose correctly.

**End-to-end tests** exercise the MCP tool interface directly, submitting full tool calls and validating the complete response structure.

### 10.2 Vendor Parser Testing

Each vendor parser requires a comprehensive fixture library. Fixtures should cover:
- Minimal valid configuration (single rule, no objects)
- Configuration with named address objects and groups
- Configuration with nested groups (multiple levels deep)
- Configuration with all supported service types
- Configuration with zone-based policy
- Configuration with negated objects (where vendor supports them)
- Malformed configuration (expect graceful error, not crash)
- Large configuration (performance regression testing)
- Configuration with circular object references (expect safe handling)

Fixtures should be sanitized samples from real vendor documentation and lab environments. No production data should be committed.

### 10.3 Analysis Engine Testing

The analysis engine tests are the most critical and should cover every overlap classification:
- Two identical rules: expect DUPLICATE
- Broad existing rule followed by narrow candidate: expect SHADOWED
- Narrow existing rule followed by broad candidate: expect PARTIAL_OVERLAP (superset)
- Overlapping source ranges, non-overlapping destinations: expect PARTIAL_OVERLAP with dimension detail
- Permit rule followed by deny candidate with same match criteria: expect CONFLICT
- Completely disjoint rules: expect NO_OVERLAP
- ANY source in existing rule: expect SHADOWED for any candidate source
- IPv6 candidate against IPv4 ruleset: expect NO_OVERLAP
- Candidate with unresolvable object references: expect UNKNOWN_DIMENSION handling

### 10.4 Address Intersection Testing

Address intersection logic is the analytical foundation. Tests must cover:
- Exact CIDR match: 10.0.0.0/24 ∩ 10.0.0.0/24
- Subset: 10.0.1.0/24 ∩ 10.0.0.0/22
- Superset: 10.0.0.0/22 ∩ 10.0.1.0/24
- Disjoint: 10.0.0.0/24 ∩ 192.168.0.0/24
- ANY ∩ any prefix: expect non-empty
- Range ∩ CIDR: 10.0.0.1-10.0.0.50 ∩ 10.0.0.0/24
- IPv4 ∩ IPv6: expect empty
- Multi-prefix set intersection

### 10.5 MCP Interface Testing

MCP integration tests should validate:
- Valid tool call returns expected response schema
- Missing required fields return structured error
- Unknown vendor returns UNSUPPORTED_VENDOR error
- Oversized payload returns payload-limit error
- Malformed XML payload returns PARSE_ERROR
- Response contains all required fields in schema-compliant format

### 10.6 Continuous Integration

All tests run on pull request. The CI pipeline enforces:
- 100% unit test pass rate required to merge
- Minimum 80% code coverage on the analysis engine and normalization layers
- Linting and type checking pass
- No new security vulnerabilities introduced in dependencies (automated scan)

---

## Phase 11 — Documentation Strategy

### 11.1 Documentation Inventory

**README.md**
The entry point for new users. Covers: what the project does, who it is for, quick-start instructions (install, run server, submit first analysis), and links to detailed docs. Should be useful in under 5 minutes of reading.

**docs/architecture.md**
Technical deep-dive for contributors and power users. Covers the five-layer architecture, data flow, component responsibilities, and design decisions. Includes the system diagram and data flow walkthrough from Phase 2 and 3 of this document.

**docs/mcp-usage.md**
Reference guide for MCP clients. Documents the `analyze_firewall_rule_overlap` tool: input schema with all fields, types, and constraints; output schema with all fields; example request/response pairs for each overlap type; error codes and their meanings. This is the primary reference for integration developers.

**docs/supported-vendors.md**
Per-vendor documentation: supported OS versions, expected configuration format, how to export the configuration, any known limitations or unsupported features, example configuration snippet. Updated each time a vendor parser is added.

**docs/extending-vendors.md**
Step-by-step guide for contributors adding a new vendor parser. Covers: implementing the `VendorParser` interface, building the object extractor, building the rule extractor, registering the parser, writing fixtures, writing tests, updating docs. Includes a worked example.

**docs/overlap-analysis-explained.md**
Conceptual explanation of the five overlap types (duplicate, shadowed, conflict, partial overlap, expansion/narrowing). Explains what each type means operationally, how to interpret the findings, and what remediation actions are typically appropriate. Written for firewall administrators, not software developers.

**docs/deployment.md**
Covers deployment scenarios: running as a local MCP server (stdio transport), running as a network service, Docker deployment, security recommendations, environment variables and configuration options.

### 11.2 In-Code Documentation

All public functions and classes carry docstrings. The `VendorParser` abstract interface is extensively documented since external contributors must implement it. Overlap type enums and the NormalizedRule schema fields carry inline comments explaining semantics.

### 11.3 Changelog Discipline

Every change to the MCP tool schema, the NormalizedRule model, or the vendor support matrix is documented in CHANGELOG.md with the version and a plain-language description. This allows operators to assess upgrade impact.

---

## Phase 12 — Development Roadmap

### 12.1 Roadmap Philosophy

The roadmap is structured to deliver working value at each milestone. The first milestone produces a testable MCP server with a synthetic normalizer (no real vendor parser). Each subsequent milestone adds a real capability. The project is useful before it is complete.

### 12.2 Milestone 1 — Architecture Foundation (Weeks 1-3)

**Goal:** Running MCP server with defined interfaces, no real vendor parsing yet.

Deliverables:
- FastMCP server scaffolding with `analyze_firewall_rule_overlap` tool registered
- Complete NormalizedRule model implemented
- Analysis engine implemented using synthetic (hand-crafted) NormalizedRule inputs
- Full test suite for analysis engine (duplicate, shadow, conflict, partial overlap, no overlap)
- Full test suite for address and service intersection logic
- Repository structure, CI pipeline, linting, type checking
- Architecture documentation
- Context7 integration: use during development to pull current FastMCP documentation and ensure API compatibility

Success criteria: Analysis engine correctly classifies all overlap types given hand-crafted NormalizedRule inputs. MCP server starts and responds to tool calls with synthetic data.

### 12.3 Milestone 2 — Normalization Engine (Weeks 4-5)

**Goal:** Complete normalization pipeline with object resolution.

Deliverables:
- Object resolver with recursive group expansion and cycle detection
- Address set normalization (CIDR, range, ANY)
- Service set normalization (protocol, port ranges, ICMP)
- Zone normalization
- Action mapping
- Full test suite for normalization layer
- Result generator with explanation templates

Success criteria: Given a hand-crafted ParsedPolicy (not yet from a real vendor parser), the normalization layer produces correct NormalizedRule objects. End-to-end pipeline test passes from ParsedPolicy to AnalysisResponse.

### 12.4 Milestone 3 — First Vendor Parser: Palo Alto PAN-OS (Weeks 6-8)

**Goal:** Real-world usability with the most widely deployed next-gen firewall.

Deliverables:
- PAN-OS XML parser for security policies
- Address object, address group, service object, service group extraction
- Panorama device group support (basic)
- Comprehensive PAN-OS fixture library
- Parser test suite
- `docs/supported-vendors.md` with PAN-OS section

Success criteria: A real exported PAN-OS configuration can be submitted via MCP tool call and return a correct overlap analysis.

### 12.5 Milestone 4 — Second Vendor Parser: Cisco ASA (Weeks 9-10)

**Goal:** Broad coverage of traditional firewall estates.

Deliverables:
- Cisco ASA text parser
- ACL entry, network object, service object, object group extraction
- ASA fixture library and test suite
- `docs/supported-vendors.md` updated

### 12.6 Milestone 5 — Vendor Expansion: FTD, Check Point, Juniper (Weeks 11-16)

**Goal:** Full coverage of the five required vendors.

Deliverables (per vendor, staggered):
- Cisco FTD JSON parser
- Check Point package parser
- Juniper SRX parser
- Fixtures, tests, and documentation for each

The `extending-vendors.md` developer guide is completed after the third vendor is added, using the progression as a reference.

### 12.7 Milestone 6 — Hardening and Performance (Weeks 17-19)

**Goal:** Production-readiness for enterprise rulesets.

Deliverables:
- Large ruleset performance testing (2000+ rules, 10000+ objects)
- Trie-based address lookup optimization if benchmarks indicate need
- Pre-filter optimization for large ruleset analysis
- Resource limit enforcement (payload size, rule count, time budget)
- Security review of all XML parsers (XXE, entity expansion)
- Payload validation hardening

### 12.8 Milestone 7 — Documentation and Release (Week 20)

**Goal:** Open-source release readiness.

Deliverables:
- Complete documentation suite
- PyPI package publication
- Docker image publication
- GitHub release with CHANGELOG
- Example scripts for each vendor
- Contributor guide finalized

### 12.9 Post-Release Roadmap (Future Milestones)

- Stateful session support: submit policy once, analyze multiple candidates
- Application-layer overlap analysis (App-ID, NBAR)
- IPv6 support across all parsers
- Panorama full hierarchy support (multi-vsys, shared policies)
- Policy optimization recommendations (redundant rule removal)
- MCP resource registration for policy context reuse
- Additional vendors (Fortinet FortiGate, AWS Security Groups, Azure NSGs)

---

## Summary and Key Architectural Decisions

| Decision | Choice | Rationale |
|---|---|---|
| MCP framework | FastMCP | Hard constraint; well-suited to tool-first design |
| Architecture pattern | Layered pipeline | Clear separation of vendor logic from analysis logic |
| Vendor extension | Plugin registry | New vendors require no changes to core code |
| Object resolution | Normalization layer, not parsing layer | Keeps parsers simple; resolution logic is shared |
| Rule representation | Fully resolved, dimension-complete NormalizedRule | Enables pure set-theoretic analysis engine |
| Analysis approach | Multi-dimensional set intersection | Correct foundation for all overlap classifications |
| Address structures | Trie/interval arithmetic | Performance-appropriate for large policies |
| State model | Stateless per request (v1) | Simplest deployment; horizontal scaling natural |
| Security posture | Input validation + resource limits at ingestion | Protect server before any parsing begins |
| Testing approach | Fixture-heavy, analysis engine unit tests | Vendor parsers change; analysis logic must be stable |

This architecture provides a clean, extensible, and secure foundation for firewall rule overlap analysis as an MCP-native capability. The separation between vendor knowledge and analytical logic is the central design choice — it ensures that adding vendor support never risks breaking the analysis engine, and that improving the analysis engine never requires touching vendor parsers.

---

**Cost: ~12K input / ~9K output → ~$0.17**
