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

### Preliminary Results (Win11 Pro 26H1 corporate workstation)

Tested against a 4.7M event Plaso timeline (678K priority events ingested in 91 seconds):

| Metric | Result |
|--------|--------|
| Provenance coverage | 99.6% (672,299 / 674,831 entities with origin) |
| Events with origin | 100% (661,359 / 661,359) |
| True positive verification | SYSTEM Type 3 logon → CONFIRMED |
| True positive verification | FortiFilter service install → CONFIRMED |
| True negative verification | notepad.exe LSASS access → INSUFFICIENT_EVIDENCE (correctly rejected) |
| True negative verification | PSEXESVC persistence → INSUFFICIENT_EVIDENCE (correctly rejected) |
| Nuanced result | a-gpetrus admin logon → INFERENCE (auth edge exists, but NOT Type 3 — correctly identifies non-lateral-movement logon) |
| Nuanced result | P_Svatun interactive logon → INFERENCE (same pattern — logged on, but interactively) |
| False confirmations | **0** — no fabricated claims were confirmed |

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

3. **Hostname resolution.** Many Plaso data types (prefetch, amcache, shimcache, LNK) do not include `computer_name`. graphir auto-discovers the hostname from EVTX records, but if EVTX is absent, hostname resolution depends on the user-supplied default.

4. **Single-host scope.** The current implementation focuses on single-host forensic images. Multi-host investigations require ingesting multiple timelines and resolving cross-host entity references.

5. **LLM reasoning quality.** Path 1 (inference) quality depends on the underlying LLM. The verification architecture catches bad inferences but cannot improve them.

### Failure Modes

| Failure Mode | Impact | Mitigation |
|-------------|--------|------------|
| Plaso parser bug | Missing or malformed events | Multiple evidence sources (prefetch + amcache + shimcache) provide redundancy |
| Neo4j query timeout | Incomplete results on large graphs | LIMIT clauses on all queries; pagination |
| LLM context overflow | Agent loses track of investigation state | State stored in graph, not in context window |
| Novel attack technique | No matching predicate template | Falls through to generic verification; reported as INFERENCE |
