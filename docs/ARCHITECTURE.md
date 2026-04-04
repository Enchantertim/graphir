# Architecture

## System Overview

graphir is a Model Context Protocol (MCP) server that bridges Claude Code to a Neo4j investigation graph. The architecture enforces constraints at the type system level — not via prompts.

```
┌──────────────────────────────────────────────────────────────────┐
│                         Claude Code                               │
│                    (Autonomous IR Analyst)                         │
│                                                                    │
│  Receives natural language query ("find evil", "who did this?")    │
│  Selects and sequences tools autonomously                          │
│  Reasons about findings, decides next investigation steps          │
│  Self-corrects via dual-path verification                          │
│  Produces structured investigation report                          │
├────────────────────────────┬─────────────────────────────────────┤
│                            │                                       │
│                    MCP Protocol (stdio)                             │
│                    JSON-RPC, typed tools                            │
│                    No shell access                                  │
│                            │                                       │
│   ┌────────────────────────▼─────────────────────────────────┐     │
│   │              graphir MCP Server (Python)                  │     │
│   │                                                            │     │
│   │  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐   │     │
│   │  │ Investigation│  │  Ingestion    │  │  Verification  │   │     │
│   │  │              │  │              │  │                │   │     │
│   │  │ query_graph  │  │ ingest_      │  │ verify_finding │   │     │
│   │  │ find_evil    │  │  timeline    │  │ trace_origin   │   │     │
│   │  │ shortest_path│  │              │  │ check_         │   │     │
│   │  │ entity_      │  │ Plaso JSONL  │  │  provenance_   │   │     │
│   │  │  neighborhood│  │  → Graph     │  │  integrity     │   │     │
│   │  │ temporal_    │  │              │  │                │   │     │
│   │  │  chain       │  │ Origin       │  │ Atomic claims  │   │     │
│   │  │ graph_stats  │  │ propagation  │  │ Dual-path      │   │     │
│   │  │              │  │ on every     │  │ verification   │   │     │
│   │  │              │  │ entity       │  │                │   │     │
│   │  └──────┬───────┘  └──────┬───────┘  └───────┬────────┘   │     │
│   │         │                 │                   │            │     │
│   │         └────────────┬────┘───────────────────┘            │     │
│   │                      │                                      │     │
│   │              Parameterised Cypher                           │     │
│   │              (no string interpolation)                      │     │
│   │                      │                                      │     │
│   └──────────────────────┼──────────────────────────────────────┘     │
│                          │                                             │
│                   Bolt Protocol                                        │
│                          │                                             │
│   ┌──────────────────────▼──────────────────────────────────────┐     │
│   │                Neo4j 5 Community                              │     │
│   │                graphir-neo4j (Docker)                          │     │
│   │                                                                │     │
│   │  Graph Schema:                                                 │     │
│   │                                                                │     │
│   │  (Host)──EXECUTED──>(Process)──SPAWNED──>(Process)             │     │
│   │    │                    │                    │                  │     │
│   │    │               ACCESSED              ACCESSED               │     │
│   │    │                    │                    │                  │     │
│   │    │                    ▼                    ▼                  │     │
│   │  LOGGED_ON          (File)              (Process)              │     │
│   │    │                                     lsass.exe             │     │
│   │    ▼                                                           │     │
│   │  (User)──LOGGED_ON──>(Host)──CONNECTED_TO──>(Connection)       │     │
│   │                                                                │     │
│   │  Every entity carries _origin_* metadata                       │     │
│   │  Constraints: Host.hostname UNIQUE, User.sid UNIQUE            │     │
│   │  Indexes: on all temporal edges, Process(pid,ts), File(path)   │     │
│   └────────────────────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────────────────────┘
```

## Trust Boundaries

### Boundary 1: Claude Code ↔ MCP Server

- **Interface:** MCP protocol over stdio (JSON-RPC)
- **Constraint:** Claude Code can ONLY call typed MCP tools with defined input schemas. It cannot execute arbitrary shell commands against the evidence or the graph.
- **Why this matters:** A prompt-based guardrail ("don't run rm") can be overridden by sufficiently creative prompting. A typed interface cannot — the tool either exists or it doesn't.

### Boundary 2: MCP Server ↔ Neo4j

- **Interface:** Bolt protocol with parameterised Cypher
- **Constraint:** All Cypher queries use `$parameters`, never string interpolation. This prevents Cypher injection the same way parameterised SQL prevents SQL injection.
- **Why this matters:** The `query_graph` tool accepts arbitrary Cypher from the agent. Parameterisation ensures the agent's queries are syntactically constrained even when semantically open-ended.

### Boundary 3: MCP Server ↔ SIFT Tools

- **Interface:** Subprocess calls with validated arguments
- **Constraint:** Each SIFT tool wrapper validates its input (file paths must exist, no path traversal, no shell metacharacters)
- **Why this matters:** The MCP server mediates all access to forensic tools. The agent cannot bypass the wrapper to run arbitrary commands.

## Data Flow

```
Forensic Image (.E01, .dd, .raw)
    │
    ▼
log2timeline (Plaso) ──── runs on SIFT Workstation
    │
    ▼
timeline.jsonl (Plaso JSON-L output)
    │
    ▼
ingest_timeline (MCP tool)
    │
    ├── Parse each JSON line
    ├── Route by data_type (evtx, prefetch, amcache, shimcache, ...)
    ├── Create vertices: Host, User, Process, File, Connection, Event
    ├── Create edges: EXECUTED, SPAWNED, ACCESSED, CONNECTED_TO, LOGGED_ON, MODIFIED
    ├── Attach _origin_* metadata to every entity
    │
    ▼
Neo4j Investigation Graph
    │
    ├── find_evil() ─── hunt patterns (5+ structural queries)
    ├── query_graph() ── ad-hoc Cypher from agent reasoning
    ├── shortest_path() ── attack chain tracing
    ├── temporal_chain() ── time-windowed activity
    │
    ▼
Findings (with dual-path verification)
    │
    ├── verify_finding() ── atomic claim decomposition + structural predicates
    ├── trace_origin() ──── walk entity back to raw artifact
    │
    ▼
Investigation Output Package
    ├── Executive summary (PDF)
    ├── Technical report (PDF)
    ├── Attack chain (SVG)
    ├── Timeline (SVG)
    ├── ATT&CK Navigator layer (JSON)
    ├── Sigma rules (YAML, vendor-neutral)
    ├── Recommendations (operational / tactical / strategic)
    └── Evidence chain (JSON, full provenance)
```

## Why Graph, Not Flat Logs

Traditional IR tools process events as flat rows. The analyst manually pivots between them, holding the investigation model in their head. This does not scale.

A graph database externalises the analyst's mental model:
- **Relationships ARE the investigation.** "Process A spawned Process B" is a traversable edge, not a text string to grep for.
- **Shortest path = attack chain.** "How did the attacker get from the phishing email to the domain controller?" is a single graph query, not hours of manual log correlation.
- **Self-correction is structural.** "I claimed lateral movement but there's no auth edge between Host A and Host B" is a falsifiable graph query. The agent doesn't re-read text — it checks structure.

The AI agent doesn't search for indicators. It traverses attack paths.

## Technology Choices

| Component | Choice | Reason |
|-----------|--------|--------|
| Graph DB | Neo4j 5 Community | Best Cypher support, APOC library, free, Docker-friendly |
| MCP framework | FastMCP (Python) | Official MCP SDK, typed tool definitions, stdio transport |
| LLM | Claude Code (Anthropic) | Hackathon partner, strong reasoning, native MCP support |
| Ingestion format | Plaso JSON-L | Standard output from SIFT Workstation's log2timeline |
| Container | Docker Compose | One-command setup |
| Language | Python 3.11+ | Ecosystem: neo4j driver, MCP SDK, Plaso compatibility |
