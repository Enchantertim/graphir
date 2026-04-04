# graphir — Devpost Project Description

## What it does

graphir is an autonomous incident response agent that investigates forensic evidence by reasoning about a graph, not by searching flat logs.

Point it at a forensic timeline. Say "find evil." It ingests the evidence into a Neo4j graph where entities (hosts, users, processes, files, connections) are vertices and their relationships (executed, spawned, accessed, logged on, connected to) are edges. Then it investigates — running structural hunt patterns, tracing attack paths, and verifying every finding against the graph before reporting it.

The key innovation: every finding passes through dual-path verification inspired by IBM Parallel Sysplex transaction processing. The LLM's inference is one computation path. An independent structural graph query is the second. Both must agree before a finding is marked CONFIRMED. When they disagree, the system goes back to the raw forensic artifact — not to the same text that confused it the first time.

An investigation tool that reports "insufficient evidence" is more valuable than one that hallucinates a finding.

## How we built it

**MCP Server (Python):** 11 typed tools exposed to Claude Code via the Model Context Protocol. Investigation tools (query_graph, find_evil, shortest_path, entity_neighborhood, temporal_chain), an ingestion tool (ingest_timeline for Plaso JSON-L), and verification tools (verify_finding, trace_origin, check_provenance_integrity).

**Neo4j Graph:** 6 vertex types (Host, User, Process, File, Connection, Event) and 6 edge types (EXECUTED, SPAWNED, ACCESSED, CONNECTED_TO, LOGGED_ON, MODIFIED). Every entity carries `_origin_*` metadata tracing it back to the raw forensic artifact that produced it.

**Verification Architecture:** Findings decompose into atomic claims. Each claim is verified against structural predicates that check prerequisites the LLM didn't explicitly reason about — temporal plausibility, multi-source corroboration, authentication edge existence, process ancestry consistency. Three mechanical confidence levels: CONFIRMED, INFERENCE, INSUFFICIENT_EVIDENCE.

**Provenance System:** Data origin recording on every graph entity. Full result chains from finding → Cypher query → MCP tool → raw artifact. Broken chains automatically flag findings as unprovable.

## Challenges we ran into

**Independence of verification paths.** The first design had Path 2 simply confirming what Path 1 inferred — a confirmatory mirror, not a validator. We redesigned the predicates to check conditions the LLM didn't explicitly reason about: temporal plausibility, network path existence, multi-source corroboration.

**Compound vs. atomic verification.** Verifying a narrative like "PsExec lateral movement after credential dump" as a single blob either over-confirms or over-downgrades. Decomposing into five atomic claims with independent confidence levels solved this.

**Hostname resolution.** Most Plaso data types (prefetch, amcache, shimcache, LNK) don't include computer_name. Only EVTX records carry it. We implemented auto-discovery: the first EVTX record's computer_name becomes the default for all other artifacts.

**Scale.** A real forensic timeline produces millions of events. We implemented priority-based ingestion (EVTX, prefetch, amcache, shimcache, registry, LNK, USN first) and skip non-forensic artifacts (browser cache, fs:stat) by default.

## Accomplishments we're proud of

**The verification architecture.** Most AI investigation tools re-read their own output to "verify" findings. graphir checks structural relationships in a graph database using predicates that are independent of the LLM's reasoning path. This is categorically different from self-confirmation.

**Provenance coverage.** Every entity in the graph is traceable back to the raw forensic artifact that produced it. An auditor can take any finding and walk backwards through the chain: finding → predicate → graph entity → origin tool → source file → line number.

**Honest accuracy reporting.** The system explicitly reports what it cannot prove. INSUFFICIENT_EVIDENCE is not a failure — it's the system working correctly.

## What we learned

Graph databases change the fundamental nature of IR investigation. When relationships are explicit edges rather than implicit correlations an analyst holds in their head, an AI agent can reason structurally about attack paths. "How did the attacker get from the phishing email to the domain controller?" is a single `shortestPath` query, not hours of manual log correlation.

The Parallel Sysplex principle — dual independent computation paths that must agree — applies far beyond mainframe transaction processing. Any system where an AI produces findings that humans will act on benefits from structural verification against a source of truth the AI doesn't control.

## What's next

- **Multi-host investigations:** Ingest multiple timelines with cross-host entity resolution
- **Sigma rule generation:** For each confirmed ATT&CK technique, generate a vendor-neutral detection rule
- **Output package:** PDF reports at three management levels, ATT&CK Navigator layers, evidence chain JSON
- **Accuracy benchmarking:** Systematic testing against EVTX-ATTACK-SAMPLES and Mordor datasets with precision/recall metrics
