# Accuracy Report Methodology

## Overview

This document describes graphir's approach to measuring and reporting the accuracy of its autonomous investigation findings. Accuracy is not claimed — it is measured, with explicit reporting of false positives, false negatives, hallucination detection, and evidence integrity.

## Measurement Framework

### What We Measure

| Metric | Definition | How Measured |
|--------|-----------|-------------|
| **True Positives** | Findings that are CONFIRMED and correct per ground truth | Compare against labelled dataset |
| **False Positives** | Findings reported that did not occur | CONFIRMED/INFERENCE findings not in ground truth |
| **False Negatives** | Real events missed by the investigation | Ground truth techniques not found by graphir |
| **Hallucination Rate** | Claims the LLM made that have no structural evidence | Count of findings downgraded from INFERENCE to INSUFFICIENT_EVIDENCE during verification |
| **Provenance Coverage** | Percentage of graph entities with intact origin chains | `check_provenance_integrity()` |
| **Self-Correction Rate** | How often the agent corrects its own findings | Count of divergence events in verification chains |

### What We Do NOT Claim

- We do not claim 100% detection of all ATT&CK techniques
- We do not claim zero false positives
- We do not claim the LLM never hallucinates
- We acknowledge that graph coverage depends on what evidence was ingested

Honest reporting of limitations is a feature, not a weakness.

## Confidence Level Distribution

Every finding produced by graphir carries one of three confidence levels. The distribution across an investigation tells you how much to trust the output:

| Distribution Pattern | Interpretation |
|---------------------|----------------|
| Mostly CONFIRMED | High-quality evidence, well-connected graph, reliable findings |
| Mixed CONFIRMED + INFERENCE | Partial evidence; some findings need human validation |
| Mostly INFERENCE | Sparse evidence; the graph lacks connectivity; treat as hypotheses |
| Any INSUFFICIENT_EVIDENCE | These findings were caught and flagged — the system is working |

**A healthy investigation has some INSUFFICIENT_EVIDENCE findings.** This means the verification engine is actively rejecting unsupported claims rather than rubber-stamping everything.

## Hallucination Detection

graphir detects hallucinations through structural falsification:

1. **The LLM claims a fact** (e.g., "mimikatz.exe accessed LSASS")
2. **The graph is queried for structural evidence** (ACCESSED edge from mimikatz to lsass.exe)
3. **If no evidence exists**, the claim is flagged

This is not prompt-based hallucination detection ("are you sure?"). It is structural: the claim either has evidence in the graph or it doesn't.

### Hallucination Categories

| Category | Example | Detection Method |
|----------|---------|-----------------|
| **Entity hallucination** | LLM names a process that doesn't exist in evidence | Entity lookup returns empty |
| **Relationship hallucination** | LLM claims connection that has no edge | Path query returns no results |
| **Temporal hallucination** | LLM claims sequence that timestamps contradict | Temporal ordering check fails |
| **Technique hallucination** | LLM maps to ATT&CK technique without supporting evidence | Technique-specific predicates fail |

## Evidence Integrity

### Chain of Custody (Digital)

Every graph entity carries `_origin_*` metadata that forms a digital chain of custody:

```
Finding: "Lateral movement to DC01 via Type 3 logon"
  └── Verified by: auth_edge_exists predicate
      └── Graph edge: (jdoe)-[:LOGGED_ON {logon_type: 3}]->(DC01)
          └── Origin tool: ingest_timeline
              └── Origin parser: winevtx
                  └── Origin artifact: /Windows/System32/winevt/Logs/Security.evtx
                      └── Origin source line: 1,234,567
                          └── Raw Plaso event: {event_identifier: 4624, ...}
```

An auditor can follow this chain from any finding to the raw artifact.

### Integrity Audit

Before generating a report, `check_provenance_integrity()` audits the graph:

- Entities missing `_origin_tool` are flagged
- Entities missing `_origin_artifact` are flagged
- The percentage of entities with complete provenance is reported
- Findings that reference entities with broken chains are automatically downgraded

## Test Methodology

### Datasets

graphir is tested against publicly available, labelled forensic datasets where ground truth is known:

| Dataset | Source | Techniques | Purpose |
|---------|--------|-----------|---------|
| EVTX-ATTACK-SAMPLES | github.com/sbousseaden | ATT&CK-labelled EVTX | Precision/recall on known techniques |
| SecurityDatasets (Mordor) | securitydatasets.com | Simulated attacks with labels | End-to-end investigation accuracy |
| NIST CFReDS | cfreds.nist.gov | Reference forensic images | Baseline correctness |

### Evaluation Process

1. Ingest dataset into graphir
2. Run autonomous investigation (`find evil`)
3. Collect all findings with confidence levels
4. Compare against ground truth labels
5. Calculate: TP, FP, FN, precision, recall
6. Report hallucination detection rate (claims caught by verification)
7. Report provenance coverage

### Preliminary Results

**Win11 Pro 26H1 corporate workstation (clean machine):**
Tested against a 5M event Plaso timeline (487K deduplicated events in 90 seconds):

| Metric | Result |
|--------|--------|
| Provenance coverage | 99.9% |
| True positive verification | SYSTEM Type 3 logon → CONFIRMED |
| True negative verification | notepad.exe LSASS → INSUFFICIENT_EVIDENCE (rejected) |
| Contradictory detection | a-gpetrus Type 2 logon → CONTRADICTORY (not lateral movement) |
| Self-correction | Agent flagged a-gpetrus as FP (IR responder, not attacker) |
| False confirmations | **0** |
| Conclusion | Correctly identified as clean machine with IR responder activity |

**Windows XP compromised workstation (real incident from 2011 CSIRT investigation):**
Tested against a 7M event Plaso timeline from DT043 — a machine compromised via PsExec lateral movement and NETLOGON malware distribution.

| Metric | Result |
|--------|--------|
| Provenance coverage | 99.7% |
| Findings from original report matched | **7 of 8** (87.5%) |
| Findings missed | spoolsv.exe C2 beacon (requires memory analysis) |
| Self-correction | RECYCLER Dc##.exe initially flagged as malware, self-corrected to FP (printer drivers) |
| MACB analysis | mso11.dll + ado.dll found via temporal anomaly (born within 1 second, incident date) |
| Temporal correlation | 130.142.76.196.exe and code.exe executed within 250ms — identified as coordinated pair |
| ATT&CK techniques mapped | 6 (T1021, T1036.005, T1053, T1059, T1204, T1070.006) |
| False confirmations | **0** |
| Investigation time | 2.5 minutes autonomous |

### What Success Looks Like

A successful accuracy report shows:
- **High precision on CONFIRMED findings** — if we say CONFIRMED, it's real. Zero false confirmations in testing.
- **Acceptable recall** — we find most of what's there
- **Active hallucination detection** — fabricated claims are caught and downgraded
- **High provenance coverage** — 99.6% achieved on real data
- **Honest gaps** — explicit list of what we missed and why (process origin gaps documented)

## Limitations

### Known Limitations

1. **Graph coverage depends on ingestion.** If Plaso doesn't parse a particular artifact type, the graph won't contain that evidence, and findings depending on it will be INSUFFICIENT_EVIDENCE.

2. **Predicate templates are finite.** The current verification engine has predicate templates for lateral movement, process chains, credential access, and persistence. Novel attack techniques without matching templates will not benefit from structural verification.

3. **Process name trust.** Detection relies on process names which can be spoofed via process hollowing/doppelgänging. A malicious payload injected into a legitimate `svchost.exe` would bypass name-based allowlists in the credential access predicates. Future work: ancestry validation (svchost must have services.exe parent) and hash-based matching.

4. **LLM parameter selection.** The `verify_finding` tool relies on the LLM to supply entity names for verification. If the LLM hallucinates the entity parameters, it could inadvertently confirm a false claim by selecting a legitimate entity that happens to match. The predicates check structural prerequisites the LLM didn't reason about (logon type, temporal ordering), which mitigates but does not eliminate this risk.

5. **Artifact timestamp skew.** Different Windows artifact types have different timestamp semantics. Shimcache timestamps depend on system shutdown, registry keys use lazy-write. Strict temporal ordering comparisons across artifact types (e.g., EVTX vs amcache) may produce false TEMPORAL_IMPLAUSIBLE divergences.

6. **Single-host focus.** Multi-host investigations require ingesting multiple timelines. FQDN is preserved in Host nodes for disambiguation, but cross-host entity resolution (linking the same user across different domain controllers) is basic.

7. **LLM reasoning quality.** Path 1 (inference) depends on the underlying LLM. The verification architecture catches bad inferences but cannot improve them.

### Failure Modes

| Failure Mode | Impact | Mitigation |
|-------------|--------|------------|
| Plaso parser bug | Missing or malformed events | Multiple evidence sources (prefetch + amcache + shimcache) provide redundancy |
| Neo4j query timeout | Incomplete results on large graphs | LIMIT clauses on all queries; result cap on query_graph (200 default) |
| LLM context overflow | Agent loses track of investigation state | State stored in graph + JSONL log, not in context window; result caps prevent overflow |
| Novel attack technique | No matching predicate template | Falls through to generic verification; reported as INFERENCE |
| Process hollowing | Malicious code in legitimate binary name | Name-based detection bypassed; future: ancestry + hash validation |
| Case-variant evasion | `powershell -eNc` vs `-enc` | Mitigated: all hunt queries use `toLower()` for case-insensitive matching |
| Double ingestion | Duplicate events inflate counts | Mitigated: deterministic event_hash with MERGE — idempotent ingestion |
| MCP server restart | Investigation log state lost | Mitigated: InvestigationLog reloads from JSONL on init |
