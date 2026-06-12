# graphir — Devpost Project Description

## What it does

graphir is an autonomous incident response agent that investigates forensic evidence by reasoning about a graph, not by searching flat logs.

Point it at a forensic timeline. Say "find evil." It ingests the evidence into a Neo4j graph where entities (hosts, users, processes, files, connections) are vertices and their relationships (executed, spawned, accessed, logged on, connected to) are edges. Then it investigates — running structural hunt patterns, tracing attack paths, and verifying every finding against the graph before reporting it.

The key innovation: every finding passes through dual-path verification inspired by IBM Parallel Sysplex transaction processing. The LLM's inference is one computation path. An independent structural graph query is the second. Both must agree before a finding is marked CONFIRMED. When they disagree, the system goes back to the raw forensic artifact — not to the same text that confused it the first time.

An investigation tool that reports "insufficient evidence" is more valuable than one that hallucinates a finding.

## How we built it

**MCP Server (Python):** 26 typed tools exposed to Claude Code via the Model Context Protocol. Investigation tools (find_evil with 22 hunt patterns, query_graph, shortest_path, entity_neighborhood, temporal_chain), ingestion tools (run_plaso, ingest_timeline, ingest_multi for multi-host), verification tools (verify_finding, trace_origin, check_provenance_integrity), correction tools (flag_correction, check_corrections), enrichment tools (lookup_hash, enrich_executables), and output generators (Sigma rules, ATT&CK Navigator, evidence chain, audit report, investigative report MD/PDF/DOCX).

graphir is a custom MCP server implementing **architectural approach #2** from the hackathon guidelines, providing typed forensic functions as an alternative to Protocol SIFT's shell-based tool surface.

graphir works on whatever evidence you could actually collect during an active incident. Full disk image? KAPE targeted collection? Individual EVTX exports? Same ingest path, same investigation quality, same graph. Anything Plaso can parse is graphir-ingestible — the tool meets IR reality instead of assuming a luxury collection.

**Neo4j Graph:** 8 vertex types (Host, User, Process, Executable, File, Connection, Event, Correction) and 9 edge types (EXECUTED_ON, SPAWNED, ACCESSED, CONNECTED_TO, LOGGED_ON, MODIFIED, HAS_EXECUTABLE, ON_HOST, CORRECTS). Every entity carries `_origin_*` metadata tracing it back to the raw forensic artifact that produced it. MACB timestamps (born, modified, accessed, changed) preserved on File nodes.

**Verification Architecture:** Findings decompose into atomic claims. Each claim is verified against structural predicates that check prerequisites the LLM didn't explicitly reason about — temporal plausibility, multi-source corroboration, authentication edge existence, process ancestry consistency. Three mechanical confidence levels: CONFIRMED, INFERENCE, INSUFFICIENT_EVIDENCE.

**Provenance System:** Data origin recording on every graph entity. Full result chains from finding → Cypher query → MCP tool → raw artifact. Broken chains automatically flag findings as unprovable.

## Challenges we ran into

**Independence of verification paths.** The first design had Path 2 simply confirming what Path 1 inferred — a confirmatory mirror, not a validator. We redesigned the predicates to check conditions the LLM didn't explicitly reason about: temporal plausibility, network path existence, multi-source corroboration.

**"Absent" vs "Contradictory" evidence.** Early verification couldn't tell the difference between "no evidence found" and "evidence found but it contradicts the claim." If the LLM claims lateral movement via Type 3 logon, but the user only has Type 2 (interactive) logons, that's not missing data — it's a contradiction. We redesigned predicates to return data with evaluation flags (`is_expected`), enabling three-state detection: absent, contradictory, or confirmed.

**The Process God-Node.** Early versions merged all execution evidence (4688, prefetch, amcache, shimcache) into one Process node per name. This meant `svchost.exe` became a single super-node with 10,000 edges, destroying forensic specificity. We split into Process (per-execution-instance, CREATE) and Executable (per-binary, MERGE) with separate edge types.

**Super-node shortest paths.** Every Process connects to the Host node via EXECUTED_ON. The "shortest path" between any two processes was always 2 hops through the Host hub — useless. We now exclude EXECUTED_ON and ON_HOST from attack path traversals, forcing paths through forensically meaningful edges (SPAWNED, ACCESSED, MODIFIED).

**Compound vs. atomic verification.** Verifying a narrative like "PsExec lateral movement after credential dump" as a single blob either over-confirms or over-downgrades. Decomposing into atomic claims with independent confidence levels solved this.

**Hostname resolution.** Most Plaso data types don't include computer_name — only EVTX does. We normalize FQDNs to short uppercase hostnames and auto-discover from the first EVTX record.

**Scale.** 4.7M events in a real Plaso timeline. Per-event Cypher calls took overnight. UNWIND batch ingestion (500 events per transaction) brought this down to ~100 seconds.

**Parent process provenance.** Parent stubs created by SPAWNED MERGE weren't directly observed in logs. Early versions falsely attributed the child's source line to the parent. We now mark these `_origin_tool='inferred_parent'` with an explicit derivation pointer.

**Read-only enforcement.** Initial approach used string-matching to block write keywords in Cypher queries. This was trivially bypassed via APOC procedures (`CALL apoc.cypher.doIt("CREATE...")`). Replaced with Neo4j native `session.execute_read()` which enforces read-only at the database protocol level — cannot be bypassed regardless of query content.

**Context window overflow.** Unbounded Cypher queries (`MATCH (n) RETURN n`) could return millions of rows, blowing the LLM's context window. Added mandatory result caps (default 200 rows) at the application layer.

**Case-sensitive evasion.** Hunt patterns using `CONTAINS` were case-sensitive — an attacker typing `powershell -eNc` instead of `-enc` would bypass detection. All hunt queries now use `toLower()` for case-insensitive matching.

**Event duplication on re-ingest.** Running ingestion twice on the same timeline doubled every Event node. Added deterministic SHA-256 event hashing with MERGE instead of CREATE — safe to re-ingest, deduplication is automatic (974K → 487K on first test).

**Absent vs Contradictory evidence.** Early verification couldn't distinguish "no evidence found" from "evidence found but it contradicts the claim." Redesigned predicates to return data with `is_expected` evaluation flags, enabling three-state detection. A user with only Type 2 (interactive) logons is now flagged as CONTRADICTORY for a lateral movement claim, not just ABSENT.

**Compound finding confidence collapse.** Using `min()` of all claim confidences meant one unprovable theory masked confirmed attack steps. Introduced PARTIAL confidence: confirmed claims remain actionable even when other claims in the same finding lack evidence.

## Accomplishments we're proud of

**Validated against a real compromised machine.** graphir autonomously found 7 of 8 indicators from a real 2011 Philips CSIRT investigation of a compromised Windows XP workstation: PsExec lateral movement, NETLOGON malware distribution from a compromised DC, admin$ payload deployment, scheduled task abuse, and persistence DLLs masquerading as Office/ADO components. The only missed finding (spoolsv.exe C2 beacon) required memory analysis.

**MACB-aware filesystem analysis.** Files carry born/modified/accessed/changed timestamps as separate properties. The `recent_executables_by_date` hunt found mso11.dll and ado.dll — two persistence DLLs born within 1 second of each other on the incident date, hiding among thousands of legitimate files in C:\Program Files\Common Files\.

**The verification architecture.** Most AI investigation tools re-read their own output to "verify" findings. graphir checks structural relationships in a graph database using predicates that are independent of the LLM's reasoning path. Three-state detection: ABSENT (no evidence), CONTRADICTORY (evidence disproves the claim), CONFIRMED (evidence supports).

**Self-correction in practice.** On the XP investigation, the agent initially flagged RECYCLER\Dc##.exe files as "malware hiding in recycle bin." After investigating (querying the subdirectory, finding Xerox printer driver DLLs), it self-corrected with a flag_correction — recording why the initial assessment was wrong.

**Provenance coverage.** 99.7% of entities traceable to raw artifacts. An auditor can walk from any finding to the exact source line in the Plaso JSONL.

**Honest accuracy reporting.** The system reports what it cannot prove. All XP findings are INFERENCE (not CONFIRMED) because XP lacks EVTX process chains — and the report explains why.

**Human oversight at the review layer, not the execution layer.** graphir produces a complete evidence chain — every finding traces through provenance metadata back to the raw artifact, with structural verification at each step. An analyst reviewing a graphir investigation spends 5 minutes validating the chain, not 5 hours validating every tool call.

## What we learned

Graph databases change the fundamental nature of IR investigation. When relationships are explicit edges rather than implicit correlations an analyst holds in their head, an AI agent can reason structurally about attack paths.

MACB timestamps are not just metadata — they ARE the investigation. Two DLLs born within 1 second of each other in a directory where every other file is years old tells a story that no text search can find. The graph makes temporal anomalies visible.

The Parallel Sysplex principle — dual independent computation paths that must agree — applies far beyond mainframe transaction processing. But "independent" must be real independence: the verifier must check conditions the LLM didn't reason about, not just confirm what it already said.

An AI that says "insufficient evidence" is more valuable than one that hallucinates a finding. Honesty under uncertainty is a feature, not a limitation.

## What's next

- **Multi-host investigations:** Ingest multiple timelines with cross-host entity resolution
- **Accuracy benchmarking:** Systematic testing against EVTX-ATTACK-SAMPLES and Mordor/SecurityDatasets
- **Executive summary PDF:** 1-page board-ready report with visual confidence indicators
- **Three-tier recommendations:** Operational (now), tactical (this week), strategic (this quarter)
- **Demo video:** 5-minute screencast showing find evil → investigation → self-correction → output package
