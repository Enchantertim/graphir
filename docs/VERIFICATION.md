# Verification Architecture — How graphir Proves Truth

## The Problem

AI-driven forensic investigation faces a fundamental trust problem. Language models hallucinate. They produce confident, plausible-sounding findings that may have no basis in the underlying evidence. In incident response, a false finding is not merely unhelpful — it is actively harmful:

- It sends analysts on wild goose chases during time-critical incidents
- It can contaminate legal proceedings and regulatory reports
- It erodes trust in automated tooling, pushing teams back to manual workflows
- It creates false confidence in containment that leaves real attack paths open

An investigation tool that reports **"insufficient evidence"** is categorically more valuable than one that hallucinates a finding.

## Design Principles

graphir's verification architecture borrows three principles from IBM Parallel Sysplex mainframe transaction processing, adapted for AI-driven investigation:

### Principle 1: Data Origin Recording & Propagation

Every piece of evidence carries its origin through the entire chain.

When a SIFT tool produces output, that output is tagged with: which tool, which parameters, which source artifact (disk image offset, registry hive path, event log channel). When that output becomes a graph vertex, the origin propagates. When a finding references that vertex, the origin is still there.

**No finding exists without a traceable path back to raw source data.**

Implementation: every graph entity carries `_origin_*` properties:

| Property | Content | Example |
|----------|---------|---------|
| `_origin_tool` | MCP tool that created this entity | `ingest_timeline` |
| `_origin_artifact` | Source file or disk image path | `/evidence/Security.evtx` |
| `_origin_parser` | Plaso parser that extracted the event | `winevtx` |
| `_origin_data_type` | Plaso data type classification | `windows:evtx:record` |
| `_origin_source_line` | Line number in source JSONL | `1060301` |

The `trace_origin` tool allows any entity to be walked back to its source:

```
trace_origin("mimikatz.exe")
→ Process node
  → origin_tool: ingest_timeline
  → origin_artifact: /Windows/Prefetch/MIMIKATZ.EXE-12345678.pf
  → origin_parser: winprefetch
  → origin_source_line: 2847391
```

The `check_provenance_integrity` tool audits the entire graph. Results from a real 678K-event investigation:

```
check_provenance_integrity()
→ total_entities: 674,831
→ with_complete_origin: 672,299
→ provenance_coverage: 99.6%
→ by_type:
    Event:   661,359 / 661,359  (100%)
    Process:  10,940 /  13,215  ( 83%)
    File:          0 /     244  (  0%)
    User:          0 /      13  (  0%)
```

Events have 100% provenance. The 17% gap in Process nodes comes from parent process stubs created by SPAWNED MERGE operations — these inherit origin from the child event that triggered them. File and User nodes are created by MERGE operations from evidence that doesn't carry per-entity origin (LNK targets, SAM accounts). The provenance gap is documented, not hidden.

### Principle 2: Result Chain Provability

Every finding is a chain:

```
natural language query
  → agent reasoning ("I should check for lateral movement")
  → MCP tool call (find_evil / query_graph)
  → raw tool output (Cypher results)
  → graph vertex/edge (the evidence)
  → verification query (structural check)
  → finding (with confidence level)
```

Each link in the chain is logged with timestamps. An auditor — or a hackathon judge — can take any finding and walk backwards through the chain to the raw artifact.

**If any link is broken or missing, the finding is automatically flagged as unprovable.** The system will not silently report a finding that it cannot trace. This is fail-safe, not fail-silent.

### Principle 3: Dual-Path Verification

Inspired by IBM Parallel Sysplex coupling where two independent computation paths must agree before a result is committed to the ledger.

```
┌─────────────────────────────────────────────────────────┐
│                    FINDING                               │
│                                                          │
│  Path 1 (Inference)     Path 2 (Structural Validation)  │
│  LLM reasons about  →   Graph query checks              │
│  tool output             INDEPENDENT prerequisites       │
│                                                          │
│         ┌──── AGREE ────┐                                │
│         │               │                                │
│    CONFIRMED       CONFIRMED                             │
│                                                          │
│         ┌──── DIVERGE ──┐                                │
│         │               │                                │
│    Return to SOURCE     NOT "retry same query"           │
│    Re-examine raw       Go back to the original          │
│    artifact via MCP     evidence via a different          │
│    with adjusted        tool or parameters               │
│    parameters                                            │
│         │                                                │
│    ├── Still diverges?                                   │
│    │   → INFERENCE (downgraded, not CONFIRMED)           │
│    │   → Flag in accuracy report                         │
│    │   → Record: what diverged, why, which query         │
│    │                                                     │
│    └── Agrees on retry?                                  │
│        → CONFIRMED                                       │
│        → Self-correction documented in chain             │
└─────────────────────────────────────────────────────────┘
```

## What Makes Path 2 Independent (Not a Confirmatory Mirror)

This is critical. If the LLM infers "lateral movement occurred" and the graph validator merely checks "does a LOGGED_ON edge exist?", Path 2 is a transformed restatement of the same inference — not an independent check. The graph was built from the same data the LLM reasoned about.

**Independence means: Path 2 checks conditions the LLM did not explicitly reason about.**

For a lateral movement finding, the LLM might reason:
> "I see a Type 3 logon from 192.168.1.50 to DC01 — this looks like lateral movement."

Path 2 then checks prerequisites the LLM skipped:

| Predicate | What it checks | Why it's independent |
|-----------|---------------|---------------------|
| `auth_edge_exists` | LOGGED_ON edge exists between specific user and target host | Validates the entity resolution — did the LLM identify the right user? |
| `network_logon_type` | Logon type is 3 or 10 (not 2, 5, 7, 11) | Validates the semantic interpretation — Type 3 ≠ always lateral movement |
| `source_host_connection` | Network CONNECTED_TO edge exists from source host | Checks a prerequisite the LLM may not have considered — was there actually a network path? |
| `temporal_plausibility` | Logon timestamps form a plausible sequence | Checks temporal consistency — are the events in causal order, or is the LLM connecting unrelated events? |

If the LLM says "lateral movement" but there is no authentication edge between the claimed hosts, that is not a retry scenario. That is a structural contradiction. The finding is downgraded.

## Atomic Claims and Predicate Grouping

A single atomic claim is verified by **multiple predicates** — required and supporting. One claim = "lateral movement occurred", verified by four independent structural checks. This is not one-claim-per-predicate — that would create orphan claims with no required predicates that can never reach CONFIRMED.

For a single claim like "SYSTEM performed lateral movement via Type 3 logon":

```
Claim: "SYSTEM performed lateral movement via Type 3 logon"
  ✓* auth_edge_exists          (required — LOGGED_ON edge between user and host)
  ✓* network_logon_type        (required — logon type is 3 or 10)
  ✓  source_host_connection    (supporting — network path exists)
  ✓  temporal_plausibility     (supporting — timestamps form coherent sequence)
→ CONFIRMED (all required pass, supporting predicates corroborate)
```

Required predicates (marked `*`) must ALL pass for CONFIRMED. Supporting predicates strengthen the finding but cannot block confirmation on their own.

### Compound Narratives

When the LLM produces a compound statement like *"The attacker used PsExec for lateral movement to DC01 after dumping credentials from LSASS on WORKSTATION01"*, this decomposes into **separate atomic claims**, each verified independently with its own predicate set:

| # | Atomic Claim | Finding Type | Predicates |
|---|-------------|-------------|------------|
| 1 | Credentials accessed on WORKSTATION01 | credential_access | LSASS edge, non-system accessor, execution evidence |
| 2 | Remote authentication to DC01 | lateral_movement | auth edge, logon type, source connection, temporal |
| 3 | PsExec service installed | persistence_service | service event, binary evidence, temporal ordering |

Each claim gets its own confidence. The compound finding's confidence is the **minimum** — if one claim is INSUFFICIENT_EVIDENCE, the compound cannot be CONFIRMED.

### Verified Against Real Data

The following results are from graphir running against a 4.7M event Plaso timeline from a Windows 11 Pro 26H1 corporate workstation (678K events ingested, 661K EVTX records, 13K processes, 13 users):

```
Test                                              Confidence             Predicates
─────────────────────────────────────────────────────────────────────────────────────
SYSTEM Type 3 logon (TRUE)                        CONFIRMED              ✓*auth  ✓*type3  ✓conn  ✓temporal
a-gpetrus admin logon (NOT Type 3)                INFERENCE              ✓*auth  ✗*type3  ✓conn  ✓temporal
                                                    ↳ network_logon_type: absent_data → complementary_artifact
notepad.exe LSASS dump (FAKE)                     INSUFFICIENT_EVIDENCE  ✗*lsass ✗*non_system ✓exec
                                                    ↳ lsass_access_edge: absent_data → complementary_artifact
                                                    ↳ non_system_accessor: absent_data → complementary_artifact
PSEXESVC persistence (FAKE)                       INSUFFICIENT_EVIDENCE  ✗*svc_event ✗binary ✗temporal
                                                    ↳ service_event_exists: absent_data → complementary_artifact
FortiFilter driver (TRUE)                         CONFIRMED              ✓*svc_event ✗binary ✓temporal
P_Svatun interactive logon (NOT lateral movement) INFERENCE              ✓*auth  ✗*type3  ✓conn  ✓temporal
                                                    ↳ network_logon_type: absent_data → complementary_artifact
```

Key observations:

- **SYSTEM Type 3 → CONFIRMED.** All four predicates pass. The SYSTEM account authenticates via network logon (Type 3), a network connection edge exists, and timestamps are coherent.
- **a-gpetrus → INFERENCE.** The admin account logged on, but NOT via Type 3/10. The system correctly identifies this is not lateral movement — it is an interactive or service logon. The divergence on `network_logon_type` triggers a suggestion to check `complementary_artifact` (e.g., look for RDP event logs).
- **notepad.exe LSASS → INSUFFICIENT_EVIDENCE.** Both required predicates fail. No LSASS access edge, no non-system accessor. The fake claim is definitively rejected.
- **PSEXESVC → INSUFFICIENT_EVIDENCE.** No service event, no binary, no temporal evidence. Clean rejection of a fabricated claim.
- **FortiFilter → CONFIRMED.** Service registry entry found via CONTAINS match, temporal ordering after initial logon confirmed. Binary not found (it's a kernel driver, not a user process) but that predicate is non-required.
- **P_Svatun → INFERENCE.** The primary user has auth edges but logs on interactively, not via network. The system does not falsely elevate this to lateral movement.

The system confirms true claims, infers when evidence is partial, and rejects fabrications. No false confirmations.

## Mechanical Confidence Transitions

Confidence levels are not intuitive judgements. They are code-enforced state transitions with exact rules:

### CONFIRMED

All three conditions must hold:
1. **All required predicates pass** — structural graph queries return supporting evidence
2. **No material contradiction** — no predicate returned evidence that contradicts the claim
3. **No chain breaks** — no predicate flagged `DivergenceReason.CHAIN_BROKEN`

### INFERENCE

The claim has partial structural support:
- Some but not all required predicates passed (e.g., auth edge exists but logon type is wrong)
- At least one predicate provides supporting evidence
- The inference basis is plausible

This is the critical middle state. INFERENCE means: "the evidence partially supports this claim, but structural verification is incomplete. A human analyst should evaluate before acting on this finding."

### INSUFFICIENT_EVIDENCE

Any one of:
- **ALL required predicates failed** — no structural support exists
- **Material contradiction** — evidence actively contradicts the claim (`DivergenceReason.CONTRADICTORY`)
- **Source chain broken** — entity lacks provenance metadata (`DivergenceReason.CHAIN_BROKEN`)
- **Second divergence** on the same claim after correction attempt

Note the distinction from the original design: when ALL required predicates fail (not just some), the claim goes directly to INSUFFICIENT_EVIDENCE. It does not pass through INFERENCE first. A claim with zero structural support is not "partially supported" — it is unsupported.

These transitions are implemented in `AtomicClaim.evaluate()` — a mechanical method, not a prompt. The code:

```python
if all required predicates pass and no contradictions:
    → CONFIRMED
elif ALL required predicates failed:
    → INSUFFICIENT_EVIDENCE
elif some required failed (partial support):
    → INFERENCE (with divergence recorded)
elif no required predicates exist but inference basis + some support:
    → INFERENCE
else:
    → INSUFFICIENT_EVIDENCE
```

## Divergence Handling

When Path 1 (inference) and Path 2 (structural validation) diverge, the system does NOT retry the same computation. It captures rich metadata about what failed and follows a bounded correction strategy.

### Divergence Metadata

Each divergence records:

```json
{
  "divergence_number": 1,
  "predicate": "auth_edge_exists",
  "reason": "absent_data",
  "detail": "Required structural evidence not found in graph",
  "failure_detail": "No LOGGED_ON edge between user 'jdoe' and host 'DC01'",
  "cypher": "MATCH (u:User)-[r:LOGGED_ON]->(h:Host) WHERE ...",
  "params": {"username": "jdoe", "target_host": "DC01"},
  "suggested_correction": "complementary_artifact"
}
```

### Divergence Reasons

| Reason | Meaning | Example |
|--------|---------|---------|
| `absent_data` | Required evidence not in graph | No auth edge between hosts |
| `contradictory` | Evidence exists but contradicts claim | Logon type is 2 (interactive), not 3 (network) |
| `temporal_implausible` | Timestamps don't support claimed sequence | Service install predates logon |
| `scope_too_broad` | Query returned noise, not signal | Too many matching processes |
| `resolution_failure` | Entity couldn't be resolved in graph | Username not found |
| `chain_broken` | Provenance chain is broken | Entity missing `_origin_*` |

### Bounded Correction Strategies

On first divergence, the system applies exactly one correction from a closed set:

| Strategy | When applied | What it does |
|----------|-------------|-------------|
| `broaden_time_window` | temporal_implausible | Re-query with wider time bounds |
| `alternate_tool` | contradictory | Re-examine same artifact with a different SIFT tool |
| `complementary_artifact` | absent_data | Look for the same evidence in a different artifact type |
| `tighten_entity_scope` | scope_too_broad | Add constraints to narrow the query |
| `verify_resolution` | resolution_failure | Re-check entity identity (hostname, SID, etc.) |
| `escalate` | second divergence | Stop. Downgrade to INFERENCE. Flag for human review. |

**On second divergence: always escalate.** The system does not enter an open-ended correction loop. Two strikes and the finding is downgraded — this is intentional. An expensive re-examination loop that still produces the same answer is wasted compute. Better to report "INFERENCE — insufficient structural evidence because no auth path exists between Host A and Host B despite process evidence suggesting remote execution" and let the human analyst decide.

## Implementation

### Core Types

```python
class Confidence(Enum):
    CONFIRMED = "CONFIRMED"
    INFERENCE = "INFERENCE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"

class DivergenceReason(Enum):
    ABSENT_DATA = "absent_data"
    CONTRADICTORY = "contradictory"
    TEMPORAL_IMPLAUSIBLE = "temporal_implausible"
    SCOPE_TOO_BROAD = "scope_too_broad"
    RESOLUTION_FAILURE = "resolution_failure"
    CHAIN_BROKEN = "chain_broken"

class CorrectionStrategy(Enum):
    BROADEN_TIME_WINDOW = "broaden_time_window"
    ALTERNATE_TOOL = "alternate_tool"
    COMPLEMENTARY_ARTIFACT = "complementary_artifact"
    TIGHTEN_ENTITY_SCOPE = "tighten_entity_scope"
    VERIFY_RESOLUTION = "verify_resolution"
    ESCALATE = "escalate"
```

### MCP Tools

| Tool | Purpose |
|------|---------|
| `verify_finding` | Decompose narrative into atomic claims, verify each against structural predicates |
| `trace_origin` | Walk any entity back to its raw source artifact |
| `check_provenance_integrity` | Audit entire graph for provenance completeness |

### Files

| File | Responsibility |
|------|---------------|
| `provenance.py` | Origin, ResultChain, AtomicClaim, Finding, Predicate, all enums, predicate templates |
| `verification.py` | VerificationEngine — single-claim and compound verification, predicate execution, origin tracing |
| `batch_ingest.py` | High-performance UNWIND batched ingestion with origin propagation on every entity |
| `server.py` | MCP tool wrappers that expose verification to Claude Code |

### Verification Methods

The `VerificationEngine` provides two verification strategies:

**`verify_single_claim()`** — one claim, all predicates. The default. Use this when verifying a specific assertion like "lateral movement occurred."

**`decompose_compound()`** — multiple claims from one narrative. Use this when the LLM produces a compound statement that should be split into independently verifiable parts.

Both delegate to the same mechanical `AtomicClaim.evaluate()` method. The difference is how many claims feed into the Finding.

## Why This Wins

Most hackathon submissions will verify findings by asking the LLM to re-read its own output. That is self-confirmation, not verification.

graphir verifies findings by querying structural relationships in a graph database using predicates that are independent of the LLM's reasoning path. When paths disagree, it goes back to the raw forensic artifact — not to the same text that confused it the first time.

This is the difference between:
- "I re-read the output and I still think it's lateral movement" (worthless)
- "The graph contains a Type 3 LOGGED_ON edge from User SYSTEM to Host ATGEWINB0114, a CONNECTED_TO edge from 127.0.0.1, and timestamps spanning 2026-02-22 to 2026-02-24 — all four predicates pass → CONFIRMED" (verifiable)

The first is a language model being confident. The second is evidence.

Tested against a real 4.7M event Windows 11 forensic timeline: true claims confirmed, false claims rejected, partial evidence correctly downgraded. Zero false confirmations.
