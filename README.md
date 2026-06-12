# graphir — Graph-based Autonomous Incident Response

**SANS Find Evil! AI Hackathon 2026**

One command. One forensic image. Full autonomous investigation.

```
claude "find evil in /evidence/case001"
```

graphir is an autonomous IR agent that externalises the analyst's mental model into a Neo4j graph, then reasons structurally about attack paths instead of searching flat logs. Every finding is independently verified against the graph before it is reported — an investigation tool that says "insufficient evidence" is more valuable than one that hallucinates a finding.

## Quick Start

```bash
# 1. Start Neo4j
docker compose up -d

# 2. Install graphir
uv venv && uv pip install -e .

# 3. Start Claude Code from this directory (auto-discovers .mcp.json)
claude

# 4. Investigate
> ingest the timeline at /evidence/timeline.jsonl
> find evil
> who did this?
> how do we stop this?
```

## Works With Whatever Evidence You Actually Have

graphir works on whatever evidence you could collect during an active incident.
Full disk image? Great. KAPE targeted collection grabbed in 15 minutes while the
adversary is still on the box? Also great — same ingest path, same investigation
quality, same graph. The tool meets IR reality instead of assuming a luxury
collection. Anything Plaso can parse is graphir-ingestible.

## Validated Against Real Compromised Machines

**Windows XP workstation (DT043) — real 2011 CSIRT investigation:**
graphir autonomously found 7 of 8 indicators from the original forensic report:
PsExec lateral movement, NETLOGON malware distribution from a compromised DC,
admin$ payload deployment, scheduled task abuse, and two persistence DLLs
(mso11.dll + ado.dll) hiding among thousands of legitimate files in Common Files — 
detected via MACB temporal anomaly (born within 1 second on the incident date).
Only miss: spoolsv.exe C2 beacon (requires memory analysis).

**Multi-host SANS 508 (4 machines, 1 incident):**
Full APT reconstruction in 8 minutes 50 seconds. Identified the attacker account
(vibranium), traced lateral movement from workstation to domain controller,
found Mimikatz variant (hydrakatz.exe) deployed to multiple hosts, mapped
11 ATT&CK techniques, generated 7 Sigma rules, self-corrected 1 false positive.

**Clean Win11 Pro workstation:** Zero false positives. Correctly identified
as clean with IR responder activity only.

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │           Claude Code (LLM)              │
                    │    Autonomous IR Analyst reasoning        │
                    │    "find evil" / "who did this?"          │
                    ├──────────────┬──────────────────────────┤
                    │              │ MCP (stdio, typed tools)  │
                    │              ▼                            │
                    │   ┌──────────────────────┐               │
                    │   │   graphir MCP Server  │               │
                    │   │   20 typed tools      │               │
                    │   │                        │               │
                    │   │  Investigation:        │               │
                    │   │   ingest_timeline      │               │
                    │   │   query_graph (R/O)    │               │
                    │   │   find_evil            │               │
                    │   │   shortest_path        │               │
                    │   │   entity_neighborhood  │               │
                    │   │   temporal_chain        │               │
                    │   │   graph_stats          │               │
                    │   │                        │               │
                    │   │  Verification:         │               │
                    │   │   verify_finding       │               │
                    │   │   trace_origin         │               │
                    │   │   check_provenance     │               │
                    │   │    _integrity          │               │
                    │   │                        │               │
                    │   │  Corrections:          │               │
                    │   │   flag_correction      │               │
                    │   │   check_corrections    │               │
                    │   │   investigation_summary│               │
                    │   └──────────┬─────────────┘               │
                    │              │ Bolt protocol               │
                    │              ▼                              │
                    │   ┌──────────────────────┐                 │
                    │   │   Neo4j 5 Community   │                 │
                    │   │   graphir-neo4j       │                 │
                    │   │                        │                 │
                    │   │   Vertices:            │                 │
                    │   │    Host, User, Process │                 │
                    │   │    Executable, File,   │                 │
                    │   │    Connection, Event,  │                 │
                    │   │    Correction          │                 │
                    │   │                        │                 │
                    │   │   Edges:               │                 │
                    │   │    EXECUTED_ON, SPAWNED │                 │
                    │   │    ACCESSED,            │                 │
                    │   │    CONNECTED_TO,        │                 │
                    │   │    LOGGED_ON, MODIFIED  │                 │
                    │   │    HAS_EXECUTABLE,      │                 │
                    │   │    ON_HOST, CORRECTS    │                 │
                    │   └────────────────────────┘                 │
                    └─────────────────────────────────────────────┘

Trust boundaries:
  Claude Code ←→ MCP Server : typed function interface (no shell access)
  MCP Server  ←→ Neo4j     : parameterised Cypher (no injection)
                               query_graph enforces read-only at application layer
  MCP Server  ←→ SIFT tools: subprocess with validated arguments
```

## How It Works

### 1. Ingestion

Plaso JSON-L (from log2timeline / psort) is parsed into a typed graph.
Each event becomes vertices and edges with full data origin metadata:

```
_origin_tool       → which MCP tool created this entity
_origin_artifact   → which source file / disk image path
_origin_parser     → which Plaso parser produced the event
_origin_data_type  → the Plaso data type classification
_origin_source_line → line number in source JSONL file
```

Every entity in the graph is traceable back to the raw forensic artifact
that produced it. There are no orphan findings.

### 2. Investigation

The agent reasons in three modes:

- **"find evil"** — broad triage: runs battery of hunt patterns, ranks by severity
- **"who did this?"** — attribution: traces lateral movement, maps user accounts
- **"how do we stop this?"** — remediation: generates Sigma rules + recommendations

Hunt patterns are structural graph queries, not regex:

```cypher
// Suspicious process chain — structural, not text matching
MATCH (parent:Process)-[:SPAWNED]->(child:Process)
WHERE parent.name IN ['explorer.exe', 'svchost.exe', 'services.exe']
  AND child.name IN ['cmd.exe', 'powershell.exe', 'wscript.exe']
RETURN parent.name, child.name, child.cmdline

// Attack path tracing — "how did the attacker get from A to B?"
MATCH path = shortestPath((src:Host)-[*..10]-(dst:Host))
RETURN [n IN nodes(path) | n.name] AS chain
```

### 3. Verification — How graphir Proves Truth

This is the core differentiator. See [VERIFICATION.md](docs/VERIFICATION.md)
for the full architecture.

**The problem:** LLMs hallucinate. An IR tool that reports a false finding
is worse than one that reports nothing — it sends analysts chasing ghosts
and can contaminate legal proceedings.

**The solution:** Every finding is verified through a dual-path architecture
inspired by IBM Parallel Sysplex transaction processing. The LLM's inference
is one path. An independent structural query against the graph is the second
path. Both must agree before a finding is marked CONFIRMED.

```
Path 1 (Inference):    LLM reasons → "attacker used PsExec for lateral movement"
Path 2 (Structural):   Graph query → does auth edge exist? is logon type 3?
                                       is service install timestamped correctly?
                                       does process ancestry match?

  AGREE    → CONFIRMED (high confidence)
  DIVERGE  → Return to SOURCE, not retry. Re-examine raw artifact.
             Still diverges? → INFERENCE (downgraded, flagged)
```

Each claim is verified by **multiple independent predicates** — required and supporting.
Compound narratives decompose into separately verified atomic claims.

Tested against a real 4.7M event Windows 11 forensic timeline:

```
SYSTEM Type 3 logon (true)       → CONFIRMED              ✓*auth ✓*type3 ✓conn ✓temporal
a-gpetrus admin (not T3)         → INSUFFICIENT_EVIDENCE   ✓*auth ✗*type3(CONTRADICTORY) ✓conn ✓temporal
notepad.exe LSASS dump (fake)    → INSUFFICIENT_EVIDENCE   ✗*lsass(absent) ✗*accessor(absent) ✓exec
PSEXESVC persistence (fake)      → INSUFFICIENT_EVIDENCE   ✗*event(absent) ✗binary ✗temporal
```

Three failure modes detected: CONFIRMED (evidence supports), ABSENT (no evidence),
CONTRADICTORY (evidence exists but disproves the claim). Zero false confirmations.

## Graph Model: Process vs Executable

A key design decision: **Process and Executable are separate node types.**

- **Process** — a specific execution instance (from Event 4688 / process creation).
  Has PID, cmdline, timestamp, user. Created with `CREATE` — every execution is unique.
- **Executable** — a binary on disk (from prefetch, amcache, shimcache).
  Has name, path, SHA-1 hash, run count. Created with `MERGE` on name — one per binary.

This prevents the "God-Node" problem where `MERGE (p:Process {name: 'svchost.exe'})`
collapses 10,000 execution instances into one node. Process instances connect to each
other via SPAWNED edges. Executables connect to Hosts via HAS_EXECUTABLE edges.

## Project Structure

```
graphir/
├── docker-compose.yml          # Neo4j container (graphir-neo4j)
├── .mcp.json                   # Claude Code MCP server config
├── pyproject.toml
├── LICENSE                     # MIT
├── src/graphir/
│   ├── server.py               # MCP server — 29 typed tools
│   ├── reconstruct.py          # Verified attack-chain reconstruction (narrative + Mermaid)
│   ├── temporal_integrity.py   # Clock-tamper / time-compression detection (RecordNumber vs timestamp)
│   ├── graph.py                # Neo4j schema (12 vertex types, 14 edge types)
│   ├── batch_ingest.py         # High-performance UNWIND batched ingestion (MACB-aware)
│   ├── hunts.py                # Hunt pattern definitions (22 queries)
│   ├── provenance.py           # Origin tracking, atomic claims, predicate templates
│   ├── verification.py         # Dual-path verification engine
│   ├── corrections.py          # FP/hallucination tracking as graph entities
│   ├── investigation_log.py    # Structured JSONL investigation logging
│   ├── sigma.py                # Sigma rule generator (typed, not LLM YAML)
│   ├── navigator.py            # ATT&CK Navigator layer generator
│   ├── evidence_chain.py       # Evidence provenance chain generator
│   ├── audit_report.py         # Technical audit report (JSON + Markdown)
│   ├── investigative_report.py # Full 10-section IR report (MD + PDF + DOCX)
│   ├── report_render.py        # Markdown → PDF / DOCX / HTML renderer
│   └── enrichment.py           # VT hash lookup + ThreatIntel graph enrichment
├── docs/
│   ├── VERIFICATION.md         # Verification architecture (detailed)
│   ├── ACCURACY.md             # Accuracy report methodology
│   ├── ARCHITECTURE.md         # Architecture diagram + trust boundaries
│   └── DEVPOST.md              # Devpost submission description
├── tests/
│   └── test_data.jsonl         # Synthetic attack scenario for testing
└── logs/                       # Investigation execution logs (JSONL)
```

## Judging Criteria Mapping

| Criterion | How graphir addresses it |
|-----------|------------------------|
| **Autonomous Execution Quality** (tiebreaker) | Graph-based self-correction: agent validates claims structurally, not by re-reading text. Three investigation modes. Visible reasoning chain. |
| **IR Accuracy** | Dual-path verification with atomic claim decomposition. Three confidence levels with mechanical transitions. Hallucination detection via graph consistency. |
| **Constraint Implementation** | MCP server = architectural constraint. Typed tools, no shell access. Parameterised Cypher prevents injection. |
| **Audit Trail Quality** | Every entity carries `_origin_*` metadata. Full result chains from finding → query → tool → raw artifact. Broken chains auto-flagged. |
| **Usability** | `docker compose up && claude "find evil"`. One command setup, one command investigation. |

## License

MIT — see [LICENSE](LICENSE)
