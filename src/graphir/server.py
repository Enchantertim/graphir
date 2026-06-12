"""graphir MCP server — exposes Neo4j graph investigation tools to Claude Code."""

import json
import os

from mcp.server.fastmcp import FastMCP
from neo4j import GraphDatabase

from graphir.graph import init_schema, link_binaries
from graphir.reconstruct import reconstruct, materialize_findings
from graphir.temporal_integrity import (
    backfill_record_numbers, summary_query, detail_query,
    corroboration_query, classify_host,
)
from graphir.batch_ingest import BatchIngester
from graphir.verification import VerificationEngine
from graphir.corrections import (
    record_correction, check_existing_corrections, get_correction_summary,
)
from graphir.hunts import HUNT_QUERIES
from graphir.sigma import generate_sigma_rule, generate_rules_from_findings, write_sigma_rules
from graphir.navigator import generate_layer_from_findings, write_navigator_layer
from graphir.evidence_chain import generate_evidence_chain, write_evidence_chain
from graphir.enrichment import vt_hash_lookup, enrich_executables_from_graph, enrich_files_by_hash
from graphir.report_render import render_report
from graphir.investigative_report import generate_investigative_report
from graphir.audit_report import generate_audit_report
from graphir.investigation_log import InvestigationLog

# --- Config ---
NEO4J_URI = os.getenv("GRAPHIR_NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("GRAPHIR_NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("GRAPHIR_NEO4J_PASSWORD", "graphir-hackathon")

mcp = FastMCP(
    "graphir",
    instructions="Graph-based Autonomous Incident Response — Neo4j investigation tools for DFIR analysis",
)

# --- Investigation log (global, one per server session) ---
_investigation_log = InvestigationLog()

# --- Neo4j connection ---
_driver = None


def get_driver():
    global _driver
    if _driver is None:
        _driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    return _driver


def run_cypher(query: str, params: dict | None = None) -> list[dict]:
    """Execute a Cypher query and return results as list of dicts."""
    driver = get_driver()
    with driver.session() as session:
        result = session.run(query, params or {})
        return [record.data() for record in result]


def run_cypher_readonly(query: str, params: dict | None = None) -> list[dict]:
    """Execute a READ-ONLY Cypher query using Neo4j native read transactions.

    Uses session.execute_read() which enforces read-only at the database level.
    This cannot be bypassed via APOC procedures or creative Cypher — Neo4j itself
    rejects any write attempt inside a read transaction.
    """
    driver = get_driver()
    with driver.session() as session:
        result = session.execute_read(
            lambda tx: [record.data() for record in tx.run(query, params or {})]
        )
        return result


# --- MCP Tools ---


@mcp.tool()
def graphir_help() -> str:
    """Show what graphir can do — investigation modes and available tools.

    Tell the user about the investigation modes they can use:
      find evil          — autonomous triage (run all hunts, verify, report)
      find [keyword]     — targeted investigation (lateral movement, persistence,
                           credentials, a process name, username, hostname)
      find timeline      — time-bounded activity analysis
      find report        — generate full output package from current findings
    """
    return json.dumps({
        "graphir": "Graph-based Autonomous Incident Response",
        "modes": {
            "find evil": "Autonomous triage — run all hunt patterns, verify findings, generate reports",
            "find lateral movement": "Focus on network logons, cross-host connections, remote services",
            "find persistence": "Focus on service installs, registry run keys, scheduled tasks",
            "find credentials": "Focus on LSASS access, credential dumping indicators",
            "find [process]": "Investigate a specific process — execution chain, cmdline, parent/child",
            "find [username]": "Investigate a user — logon history, executions, hosts touched",
            "find [hostname]": "Investigate a host — who logged on, what ran, what was installed",
            "find timeline [start] [end]": "Activity within a time window",
            "find report": "Generate full output package (Sigma rules, ATT&CK layer, evidence chain)",
        },
        "tools": 18,
        "verification": "Every finding is structurally verified. Confidence: CONFIRMED / PARTIAL / INFERENCE / INSUFFICIENT_EVIDENCE",
        "tip": "Start with 'find evil' for broad triage, then drill into specific areas.",
    }, indent=2)


@mcp.tool()
def ping() -> str:
    """Health check — verify the graphir MCP server is running and Neo4j is reachable."""
    try:
        run_cypher("RETURN 1 AS ok")
        return json.dumps({"status": "ok", "neo4j": "connected"})
    except Exception as e:
        return json.dumps({"status": "ok", "neo4j": f"error: {e}"})


@mcp.tool()
def run_plaso(image_path: str, output_dir: str = "data") -> str:
    """Run log2timeline + psort on a forensic disk image to produce a Plaso JSON-L timeline.

    This wraps the SIFT Workstation tools (log2timeline, psort) into a single
    MCP tool call. The output .njson file can then be fed to ingest_timeline.

    Supports: E01, raw (.dd, .img, .raw), VMDK, split images.
    Requires: log2timeline and psort installed (available on SIFT Workstation).

    Args:
        image_path: Path to the forensic disk image.
        output_dir: Directory to write .plaso and .njson files (default: data/).
    """
    import subprocess
    import shutil
    from pathlib import Path

    # Check tools exist
    log2timeline = shutil.which("log2timeline") or shutil.which("log2timeline.py")
    psort_cmd = shutil.which("psort") or shutil.which("psort.py")

    if not log2timeline:
        return json.dumps({"error": "log2timeline not found. Install Plaso or run on SIFT Workstation."})
    if not psort_cmd:
        return json.dumps({"error": "psort not found. Install Plaso or run on SIFT Workstation."})

    img = Path(image_path)
    if not img.exists():
        return json.dumps({"error": f"Image not found: {image_path}"})

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    stem = img.stem
    plaso_path = out_dir / f"{stem}.plaso"
    njson_path = out_dir / f"{stem}.njson"

    try:
        # Run log2timeline
        result = subprocess.run(
            [log2timeline, "--storage_file", str(plaso_path), "--status_view", "none", str(img)],
            capture_output=True, text=True, timeout=7200,  # 2h max
        )
        if result.returncode != 0:
            return json.dumps({"error": f"log2timeline failed: {result.stderr[:500]}"})

        # Run psort
        result = subprocess.run(
            [psort_cmd, "--status_view", "none", "-o", "json_line", "-w", str(njson_path), str(plaso_path)],
            capture_output=True, text=True, timeout=3600,  # 1h max
        )
        if result.returncode != 0:
            return json.dumps({"error": f"psort failed: {result.stderr[:500]}"})

        # Count events
        line_count = sum(1 for _ in open(njson_path))
        size_mb = njson_path.stat().st_size / (1024 * 1024)

        return json.dumps({
            "status": "ok",
            "njson_path": str(njson_path),
            "plaso_path": str(plaso_path),
            "events": line_count,
            "size_mb": round(size_mb, 1),
            "message": f"Timeline ready. Run: ingest_timeline('{njson_path}')",
        }, indent=2)
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "Processing timed out (>2h for log2timeline or >1h for psort)"})
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def ingest_timeline(path: str, default_hostname: str = "unknown",
                    priority_only: bool = True, max_events: int = 0) -> str:
    """Ingest a Plaso JSON-L timeline file into the Neo4j investigation graph.

    Parses Plaso jsonl output (from log2timeline/psort) and creates graph nodes
    and edges: Host, User, Process, File, Connection, Event vertices with
    temporal edges (EXECUTED, SPAWNED, ACCESSED, CONNECTED_TO, LOGGED_ON, MODIFIED).

    Run this first before any investigation queries.

    Args:
        path: Absolute path to a Plaso JSON-L (.jsonl/.njson) file.
        default_hostname: Hostname to use for artifacts that lack computer_name
            (most non-EVTX artifacts). Will auto-discover from EVTX records.
        priority_only: If True (default), only ingest forensically-important types
            (EVTX, prefetch, amcache, shimcache, registry, services, LNK, USN).
            Set False to ingest everything including browser history and fs:stat.
        max_events: Stop after ingesting this many events. 0 = no limit.
    """
    try:
        init_schema(run_cypher)
        ingester = BatchIngester(run_cypher, default_hostname=default_hostname)
        stats = ingester.ingest_file(path, priority_only=priority_only,
                                     max_events=max_events)
        stats["binary_links"] = link_binaries(run_cypher)
        return json.dumps(stats, default=str, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def ingest_multi(directory: str, priority_only: bool = True) -> str:
    """Ingest ALL Plaso JSON-L files from a directory into the graph.

    For multi-host investigations: each .njson/.jsonl file is ingested
    separately with its own hostname auto-discovery. Cross-host entity
    resolution happens naturally — the same User SID or Host hostname
    from different timelines will MERGE into the same graph node.

    Args:
        directory: Path to a directory containing .njson/.jsonl files.
        priority_only: If True (default), only ingest forensically-important types.
    """
    try:
        from pathlib import Path
        dir_path = Path(directory)
        if not dir_path.is_dir():
            return json.dumps({"error": f"Not a directory: {directory}"})

        files = sorted(list(dir_path.glob("*.njson")) + list(dir_path.glob("*.jsonl")))
        if not files:
            return json.dumps({"error": f"No .njson/.jsonl files in {directory}"})

        init_schema(run_cypher)
        all_stats = []
        for f in files:
            # Use filename (without extension) as default hostname fallback
            default_host = f.stem.upper()
            ingester = BatchIngester(run_cypher, default_hostname=default_host)
            stats = ingester.ingest_file(str(f), priority_only=priority_only)
            stats["file"] = f.name
            stats["discovered_hostname"] = ingester._discovered_hostname or default_host
            all_stats.append(stats)

        total = {
            "files_ingested": len(all_stats),
            "total_events": sum(s.get("events_processed", 0) for s in all_stats),
            "total_errors": sum(s.get("errors", 0) for s in all_stats),
            "binary_links": link_binaries(run_cypher),
            "per_file": all_stats,
        }
        return json.dumps(total, default=str, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def query_graph(cypher: str, max_results: int = 200) -> str:
    """Execute a READ-ONLY Cypher query against the investigation graph.

    Use this for ad-hoc investigation queries. The agent writes Cypher based on
    what it's investigating. Returns results as JSON.

    Enforces read-only via Neo4j native read transactions (cannot be bypassed).
    Results are capped at max_results to prevent context window overflow.

    Args:
        cypher: A valid read-only Cypher query string.
        max_results: Maximum rows to return (default 200). Prevents context
            overflow from unbounded queries like MATCH (n) RETURN n.
    """
    try:
        results = run_cypher_readonly(cypher)
        truncated = len(results) > max_results
        results = results[:max_results]
        output = {"results": results, "count": len(results)}
        if truncated:
            output["truncated"] = True
            output["message"] = f"Results capped at {max_results}. Add LIMIT to your Cypher or increase max_results."
        return json.dumps(output, default=str, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


# Hunts whose hits map onto a verification predicate family.
# (finding_type, fn(row) -> (entity, target) or None to skip the row)
_VERIFIABLE_HUNTS = {
    "lateral_movement_logons": (
        "lateral_movement",
        lambda row: (row.get("user"), row.get("host"))
        if row.get("user") and row.get("host") else None,
    ),
    "suspicious_process_chain": (
        "process_chain",
        lambda row: (row.get("ancestor"), row.get("child"))
        if row.get("ancestor") and row.get("child") else None,
    ),
    "lsass_access": (
        "credential_access",
        lambda row: (row.get("accessor"), "")
        if row.get("accessor") else None,
    ),
    "service_installation": (
        "persistence_service",
        lambda row: (row.get("examples", [None])[0], "")
        if row.get("examples") else None,
    ),
}

_AUTO_VERIFY_MAX_PER_HUNT = 3


def _auto_verify_hunt(engine, hunt_name: str, rows: list[dict]) -> dict | list:
    """Structurally verify the top hits of a hunt, if it has a predicate family."""
    mapping = _VERIFIABLE_HUNTS.get(hunt_name)
    if not mapping:
        return {"status": "no_predicate_family",
                "note": "verify manually with verify_finding before reporting"}
    finding_type, extract = mapping

    verifications = []
    for row in rows[:_AUTO_VERIFY_MAX_PER_HUNT]:
        extracted = extract(row)
        if not extracted:
            continue
        entity, target = extracted
        narrative = f"[auto-verify:{hunt_name}] {entity}" + (
            f" -> {target}" if target else "")
        try:
            verify = {
                "lateral_movement": lambda: engine.verify_lateral_movement(
                    entity, target, narrative),
                "process_chain": lambda: engine.verify_process_chain(
                    entity, target, narrative),
                "credential_access": lambda: engine.verify_credential_access(
                    entity, narrative),
                "persistence_service": lambda: engine.verify_persistence(
                    entity, narrative),
            }[finding_type]
            finding = verify()
            failed = [p.name for c in finding.claims
                      for p in c.predicates if p.passed is False]
            confidence = str(finding.confidence)
            verifications.append({
                "entity": entity,
                **({"target": target} if target else {}),
                "confidence": confidence,
                **({"failed_predicates": failed} if failed else {}),
            })
            _investigation_log.log_verification(
                narrative, confidence,
                [p.name for c in finding.claims
                 for p in c.predicates if p.passed],
                failed,
            )
        except Exception as e:
            verifications.append({"entity": entity, "error": str(e)})
    return verifications


@mcp.tool()
def find_evil(summarize: bool = True, auto_verify: bool = True) -> str:
    """Run all predefined hunt patterns against the investigation graph.

    Executes a battery of generic DFIR detection queries and returns scored findings.
    Use this as the first step in any investigation to get initial indicators.

    With auto_verify (default), hunts that map to a verification predicate family
    (lateral movement, process chains, lsass access, service persistence) have their
    top hits pushed through the VerificationEngine automatically — triage output
    arrives pre-labeled CONFIRMED / INFERENCE / INSUFFICIENT_EVIDENCE with failed
    predicates named. Hunts without a predicate family report
    verification: "no_predicate_family" — verify those manually before reporting.

    Args:
        summarize: If True (default), consolidate results by grouping duplicates
                  and returning counts + top examples instead of raw rows.
                  Set False for full raw results (may be large).
        auto_verify: If True (default), structurally verify top hits of
                  verifiable hunts and attach per-hit confidence labels.
    """
    findings = []
    MAX_RESULTS_PER_HUNT = 10  # Cap per-hunt results to keep output manageable

    engine = VerificationEngine(run_cypher) if auto_verify else None

    for hunt_name, hunt in HUNT_QUERIES.items():
        try:
            q = hunt.get("summarize_query") if summarize else hunt["query"]
            results = run_cypher(q)
            if results:
                total_count = len(results)
                capped = results[:MAX_RESULTS_PER_HUNT]
                entry = {
                    "hunt": hunt_name,
                    "description": hunt["description"],
                    "tactic": hunt["tactic"],
                    "technique": hunt["technique"],
                    "hit_count": total_count,
                    "results": capped,
                }
                if total_count > MAX_RESULTS_PER_HUNT:
                    entry["truncated"] = True
                    entry["showing"] = MAX_RESULTS_PER_HUNT
                if engine:
                    entry["verification"] = _auto_verify_hunt(
                        engine, hunt_name, capped)
                findings.append(entry)
        except Exception as e:
            findings.append(
                {"hunt": hunt_name, "error": str(e)}
            )

    if not findings:
        return json.dumps({"status": "clean", "message": "No findings from initial hunt patterns. Consider ingesting more evidence or running targeted queries."})

    return json.dumps(findings, default=str, indent=2)


@mcp.tool()
def shortest_path(source_name: str, target_name: str,
                  attack_path_only: bool = True) -> str:
    """Find the shortest path between two entities in the investigation graph.

    Core graph advantage: answers 'how did the attacker get from A to B?'

    By default, traverses only attack-relevant edges (SPAWNED, ACCESSED,
    MODIFIED, CONNECTED_TO, LOGGED_ON) — excludes EXECUTED_ON and ON_HOST
    to avoid the super-node problem where every path shortcuts through the
    Host hub node.

    Args:
        source_name: Name or identifier of the source entity.
        target_name: Name or identifier of the target entity.
        attack_path_only: If True (default), only traverse attack-relevant
            edges. Set False to include all edge types (may return trivial
            paths through the Host node).
    """
    if attack_path_only:
        query = """
            MATCH (src), (dst)
            WHERE src.name CONTAINS $source AND dst.name CONTAINS $target
            MATCH path = shortestPath(
                (src)-[:SPAWNED|ACCESSED|MODIFIED|CONNECTED_TO|LOGGED_ON*1..10]-(dst)
            )
            RETURN [n IN nodes(path) | {labels: labels(n), name: n.name}] AS nodes,
                   [r IN relationships(path) | {type: type(r), ts: r.timestamp}] AS edges,
                   length(path) AS hops
            LIMIT 5
        """
    else:
        query = """
            MATCH (src), (dst)
            WHERE src.name CONTAINS $source AND dst.name CONTAINS $target
            MATCH path = shortestPath((src)-[*..10]-(dst))
            RETURN [n IN nodes(path) | {labels: labels(n), name: n.name}] AS nodes,
                   [r IN relationships(path) | {type: type(r), ts: r.timestamp}] AS edges,
                   length(path) AS hops
            LIMIT 5
        """
    try:
        results = run_cypher(query, {"source": source_name, "target": target_name})
        if not results:
            return json.dumps({"status": "no_path", "message": f"No path found between '{source_name}' and '{target_name}'. They may be unconnected — consider querying intermediate entities."})
        return json.dumps(results, default=str, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def entity_neighborhood(entity_name: str, hops: int = 2,
                        exclude_hubs: bool = True) -> str:
    """Return all entities within N hops of a given entity.

    The 'show me everything connected to this' query. Useful for understanding
    the context around a suspicious entity.

    By default excludes Host nodes from traversal to avoid the super-node
    problem (a Host can have millions of ON_HOST/EXECUTED_ON edges).

    Args:
        entity_name: Name or identifier of the entity to explore.
        hops: Number of relationship hops to traverse (default 2, max 4).
        exclude_hubs: If True (default), exclude Host nodes from results
            and use only attack-relevant edge types for traversal.
    """
    hops = min(hops, 4)
    if exclude_hubs:
        query = f"""
            MATCH p = (start)-[*1..{hops}]-(neighbor)
            WHERE (start.name = $name OR start.name CONTAINS $name)
              AND NONE(n IN nodes(p) WHERE n:Host)
              AND NOT neighbor:Host
            WITH neighbor, relationships(p) AS rels
            UNWIND rels AS rel
            WITH DISTINCT neighbor, rel
            RETURN labels(neighbor) AS labels, neighbor.name AS name,
                   type(rel) AS relationship, rel.timestamp AS ts
            ORDER BY rel.timestamp
            LIMIT 100
        """
    else:
        query = f"""
            MATCH (start {{name: $name}})-[r*1..{hops}]-(neighbor)
            UNWIND r AS rel
            WITH DISTINCT neighbor, rel
            RETURN labels(neighbor) AS labels, neighbor.name AS name,
                   type(rel) AS relationship, rel.timestamp AS ts
            ORDER BY rel.timestamp
            LIMIT 100
        """
    try:
        results = run_cypher(query, {"name": entity_name})
        if not results:
            return json.dumps({"status": "no_neighbors", "message": f"No entities found within {hops} hops of '{entity_name}'."})
        return json.dumps(results, default=str, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def temporal_chain(entity_name: str, start_time: str, end_time: str) -> str:
    """All activity involving an entity within a time window, ordered chronologically.

    Timeline reconstruction via graph traversal.

    Args:
        entity_name: Name or identifier of the entity.
        start_time: ISO 8601 start time (e.g. '2024-03-15T00:00:00Z').
        end_time: ISO 8601 end time (e.g. '2024-03-15T23:59:59Z').
    """
    query = """
        MATCH (e {name: $name})-[r]-(other)
        WHERE r.timestamp >= datetime($start) AND r.timestamp <= datetime($end)
        RETURN labels(e) AS entity_labels, e.name AS entity,
               type(r) AS relationship, r.timestamp AS ts,
               labels(other) AS other_labels, other.name AS other_name
        ORDER BY r.timestamp
        LIMIT 200
    """
    try:
        results = run_cypher(
            query,
            {"name": entity_name, "start": start_time, "end": end_time},
        )
        if not results:
            return json.dumps({"status": "no_activity", "message": f"No activity for '{entity_name}' in the specified time window."})
        return json.dumps(results, default=str, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def reconstruct_attack(username: str = "", materialize: bool = True) -> str:
    """Reconstruct the attack chain from the graph as a structured narrative.

    Walks the evidence graph (not your memory) and assembles ordered phases:
    lateral movement (each hop independently verified — per-hop CONFIRMED /
    INFERENCE / INSUFFICIENT_EVIDENCE), cross-host tool deployment with MACB
    anomalies via SAME_BINARY edges, service persistence, and anti-forensics.
    Returns a `mermaid` field — paste it into the investigation report to
    render the attack-chain diagram.

    With materialize=True (default), findings are written into the graph as
    (:Finding) vertices with SUPPORTED_BY edges to their evidence entities,
    so the narrative itself becomes traversable: finding -> entity -> event
    -> raw artifact line. Idempotent.

    Args:
        username: Focus account. Empty = auto-select the human account with
                  network logons to the most hosts.
        materialize: Write (:Finding)-[:SUPPORTED_BY]-> nodes into the graph.
    """
    try:
        engine = VerificationEngine(run_cypher)
        result = reconstruct(run_cypher, engine, username=username)
        if materialize and result.get("phases"):
            result["materialized"] = materialize_findings(
                run_cypher, result, _investigation_log.investigation_id)
        for phase in result.get("phases", []):
            if phase["phase"] == "lateral_movement":
                _investigation_log.log_finding(
                    f"Attack chain reconstructed for {result['actor']}: "
                    f"{len(phase.get('hops', []))} hops",
                    "CONFIRMED" if any(
                        h.get("confidence") == "CONFIRMED"
                        for h in phase.get("hops", [])) else "INFERENCE",
                    tactic=phase["tactic"], technique=phase["technique"],
                )
        return json.dumps(result, default=str, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def temporal_integrity(inversion_min_seconds: int = 60,
                       forward_jump_days: int = 7) -> str:
    """Detect clock tampering / time compression from EVTX write-order vs timestamps.

    EVTX stamps every record with a monotonic RecordNumber at write time,
    independent of the system clock. Ordering a provider channel by RecordNumber
    must yield non-decreasing timestamps. Two violations expose a manipulated clock:

      INVERSION (high confidence): RecordNumber increases but the timestamp moves
        backward by more than inversion_min_seconds. Near-impossible on a single
        channel without the clock being set back — the scar of host-side clock
        control (VM time compression) or anti-forensic clock manipulation.
      FORWARD_JUMP (supporting): an implausibly large calendar gap between adjacent
        records. Sparse provider channels gap naturally, so treat as corroborating,
        not proof.

    Cross-source corroboration: a clock move perturbs every logging subsystem at
    once; log *editing* touches one channel. So per host we count how many
    INDEPENDENT providers show a >1-day backward jump and classify:
      SYSTEM_CLOCK_MANIPULATION  — inversions span >=3 providers (clock moved)
      ISOLATED_LOG_ANOMALY       — confined to 1-2 (possible single-log tampering)

    This is how staged / time-compressed images are caught without the raw VMDK:
    the timestamps lie, the RecordNumber sequence does not. It cannot recover the
    true wall-clock or see VMDK-container manipulation (that needs the raw image).

    Backfills record_number from message text on first run (older graphs).

    Args:
        inversion_min_seconds: Minimum backward step to count as an inversion
            (default 60 — floors out routine sub-minute NTP corrections).
        forward_jump_days: Forward gap (days) between adjacent records to flag.
    """
    try:
        backfilled = backfill_record_numbers(run_cypher)
        summary = run_cypher(summary_query(inversion_min_seconds, forward_jump_days))
        detail = run_cypher(detail_query(inversion_min_seconds, forward_jump_days))
        corroboration = run_cypher(corroboration_query(inversion_min_days=1.0))

        # Attach the cross-source classification to each host.
        spread = {r["host"]: r for r in corroboration}
        for row in summary:
            c = spread.get(row["host"])
            providers = c["providers_with_inversions"] if c else 0
            row["classification"] = classify_host(providers)
            row["providers_with_significant_inversions"] = providers

        # System-wide manipulation on any host is the tampering verdict; a backward
        # step > 1 day already exceeds any timezone/DST/NTP explanation.
        if any(r["classification"] == "SYSTEM_CLOCK_MANIPULATION" for r in summary):
            verdict = "CLOCK_TAMPERING_DETECTED"
        elif any(r["classification"] == "ISOLATED_LOG_ANOMALY" for r in summary):
            verdict = "ISOLATED_LOG_ANOMALY"
        else:
            verdict = "NO_SIGNIFICANT_INVERSIONS"

        return json.dumps({
            "verdict": verdict,
            "record_numbers_backfilled": backfilled,
            "thresholds": {"inversion_min_seconds": inversion_min_seconds,
                           "forward_jump_days": forward_jump_days,
                           "system_wide_provider_threshold": 3},
            "per_host": summary,
            "corroboration": corroboration,
            "anomalies": detail,
            "note": "INVERSION = high-confidence clock tampering; FORWARD_JUMP = "
                    "supporting (sparse channels gap naturally). "
                    "SYSTEM_CLOCK_MANIPULATION = inversions span multiple "
                    "independent providers (clock moved, not a log edited).",
        }, default=str, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def graph_stats() -> str:
    """Return summary statistics about the current investigation graph.

    Useful for understanding what data has been ingested and the graph's scope.
    """
    queries = {
        "node_counts": "MATCH (n) RETURN labels(n)[0] AS label, count(*) AS count ORDER BY count DESC",
        "edge_counts": "MATCH ()-[r]->() RETURN type(r) AS type, count(*) AS count ORDER BY count DESC",
        "time_range": """
            MATCH ()-[r]->()
            WHERE r.timestamp IS NOT NULL
            RETURN min(r.timestamp) AS earliest, max(r.timestamp) AS latest
        """,
    }
    stats = {}
    for name, query in queries.items():
        try:
            stats[name] = run_cypher(query)
        except Exception as e:
            stats[name] = {"error": str(e)}

    return json.dumps(stats, default=str, indent=2)


# --- Verification Tools (Parallel Sysplex Principles) ---


@mcp.tool()
def verify_finding(finding_type: str, narrative: str,
                   entity_name: str, target_name: str = "") -> str:
    """Dual-path verification of a finding via atomic claim decomposition.

    Decomposes a narrative into atomic claims, each verified independently
    against structural graph predicates. Predicates check prerequisites the
    LLM didn't explicitly reason about (not confirmatory mirrors).

    Confidence is MECHANICAL:
      CONFIRMED — source chain intact + all required predicates pass + no contradictions
      INFERENCE — plausible reasoning + partial structural support
      INSUFFICIENT_EVIDENCE — broken chain, absent predicates, or contradictions

    On divergence: returns which predicate failed, why (absent_data, contradictory,
    temporal_implausible, scope_too_broad, resolution_failure), and a suggested
    correction strategy (broaden_time_window, alternate_tool, complementary_artifact,
    tighten_entity_scope, verify_resolution, or escalate).

    Args:
        finding_type: One of: lateral_movement, process_chain, credential_access,
                     persistence_service
        narrative: The compound finding to decompose and verify
        entity_name: Primary entity (username, process name, service name)
        target_name: Secondary entity if needed (target host, child process)
    """
    engine = VerificationEngine(run_cypher)

    param_map = {
        "lateral_movement": lambda: engine.verify_lateral_movement(
            entity_name, target_name, narrative),
        "process_chain": lambda: engine.verify_process_chain(
            entity_name, target_name, narrative),
        "credential_access": lambda: engine.verify_credential_access(
            entity_name, narrative),
        "persistence_service": lambda: engine.verify_persistence(
            entity_name, narrative),
    }

    if finding_type not in param_map:
        return json.dumps({
            "error": f"Unknown finding type: {finding_type}",
            "valid_types": list(param_map.keys()),
        })

    try:
        finding = param_map[finding_type]()

        # Log verification per CLAIM (granular)
        for claim in finding.claims:
            passed = [p.name for p in claim.predicates if p.passed]
            failed = [p.name for p in claim.predicates if not p.passed]
            _investigation_log.log_verification(
                claim.statement or narrative,
                claim.confidence.value,
                passed, failed,
                claim.divergences,
            )

        # Log finding ONCE per compound finding (not per claim)
        _investigation_log.log_finding(
            narrative,
            finding.confidence,  # already a string from CompoundConfidence
            tactic=finding.claims[0].tactic if finding.claims else "",
            technique=finding.claims[0].technique if finding.claims else "",
            claim_summary=finding.claim_summary,
        )

        # NOTE: We deliberately do NOT auto-materialize Correction nodes for
        # routine verification misses. That would flood the graph with noise
        # for every exploratory verify_finding call. Corrections are reserved
        # for meaningful claim-state transitions — the agent should explicitly
        # call flag_correction when it decides a finding should be corrected.
        #
        # The verification result (INSUFFICIENT/INFERENCE/CONFIRMED) is logged
        # in the investigation log and returned to the agent for reasoning.

        return json.dumps(finding.to_dict(), default=str, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def trace_origin(entity_name: str) -> str:
    """Trace a graph entity back to its raw source artifact.

    Returns the full provenance chain: entity → origin tool → source artifact
    → parser → source file line number. If any link is missing, the entity
    is flagged as unprovable.

    Use this to validate that a finding has a traceable evidence chain.

    Args:
        entity_name: Name of the entity to trace (process name, hostname,
                    service name, username, etc.)
    """
    try:
        engine = VerificationEngine(run_cypher)
        result = engine.trace_origin(entity_name)
        return json.dumps(result, default=str, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def check_provenance_integrity() -> str:
    """Audit all graph entities for provenance completeness.

    Reports how many entities have intact origin chains vs broken/missing
    provenance. Broken chains = unprovable findings = auto-flagged.

    Run this before generating reports to assess evidence integrity.
    """
    try:
        engine = VerificationEngine(run_cypher)
        result = engine.check_chain_integrity()
        return json.dumps(result, default=str, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


# --- Correction Tools ---


@mcp.tool()
def flag_correction(entity_name: str, correction_type: str, reason: str,
                    original_claim: str, corrected_by: str = "agent",
                    original_confidence: str = "",
                    corrected_confidence: str = "INSUFFICIENT_EVIDENCE") -> str:
    """Record a correction (false positive, hallucination, retraction) in the graph.

    Creates a Correction node linked to the relevant entity. This is a first-class
    graph entity — not just a log line. Prevents re-generation of the same
    false finding and provides an auditable self-correction trail.

    Use this when:
    - The agent discovers a previous finding was wrong (self-correction)
    - An analyst flags a finding as false positive
    - Verification downgrades a finding and you want to record why

    Args:
        entity_name: The entity the correction is about (process, user, service, host)
        correction_type: One of: false_positive, hallucination, retracted, downgraded,
                        scope_error, analyst_override
        reason: Why this correction is being made
        original_claim: What was originally asserted
        corrected_by: Who made the correction ("agent" or analyst name)
        original_confidence: Previous confidence level
        corrected_confidence: New confidence level after correction
    """
    result = record_correction(
        run_cypher, correction_type, reason, original_claim, entity_name,
        corrected_by=corrected_by,
        original_confidence=original_confidence,
        corrected_confidence=corrected_confidence,
    )

    # Log the correction
    _investigation_log.log_correction(
        correction_type, reason, original_claim, entity_name,
        corrected_by=corrected_by,
        original_confidence=original_confidence,
        new_confidence=corrected_confidence,
    )

    return json.dumps(result, default=str, indent=2)


@mcp.tool()
def check_corrections(entity_name: str, claim: str = "") -> str:
    """Check if an entity or claim has any existing corrections recorded.

    Call this BEFORE re-asserting a claim about an entity that may have been
    previously flagged. Prevents hallucination re-generation.

    Matches both entity-level (Correction CORRECTS this entity) and
    claim-level (a Correction's original_claim text mentions the entity or
    overlaps the supplied claim text).

    Args:
        entity_name: The entity to check for existing corrections.
        claim: Optional — the claim you are about to assert. Also returns
               corrections whose original_claim contains this text.
    """
    results = check_existing_corrections(run_cypher, entity_name, claim)
    if not results:
        return json.dumps({"entity": entity_name, "corrections": [],
                          "message": "No existing corrections for this entity or claim."})
    return json.dumps({"entity": entity_name, "correction_count": len(results),
                       "corrections": results}, default=str, indent=2)


@mcp.tool()
def investigation_summary() -> str:
    """Get a summary of the current investigation session.

    Returns: total log entries, findings by confidence, verification count,
    corrections count, self-corrections count, elapsed time, and a curated
    `milestones` list — the 5-12 entries that tell the investigation story
    (ingestion, CONFIRMED findings, verification refusals, self-corrections).
    Present the milestones to the user when narrating investigation progress;
    the full JSONL log remains the audit trail.

    Use this to get an overview of what the investigation has done so far.
    """
    summary = _investigation_log.get_summary()
    summary["milestones"] = _investigation_log.get_milestones()

    # Also get graph-level correction summary
    try:
        correction_stats = get_correction_summary(run_cypher)
        summary["graph_corrections"] = correction_stats
    except Exception:
        pass

    return json.dumps(summary, default=str, indent=2)


# --- Sigma Rule Generation Tools ---


@mcp.tool()
def create_sigma_rule(title: str, description: str, logsource_type: str,
                      selection: str, level: str = "medium",
                      technique_id: str = "", tactic: str = "",
                      filter_fields: str = "",
                      false_positives: str = "") -> str:
    """Create a single Sigma detection rule from typed parameters.

    The rule is constructed programmatically from validated inputs — the LLM
    does NOT write raw YAML. This prevents hallucinated field names, invalid
    modifiers, and broken YAML spacing.

    Args:
        title: Short rule title (e.g., "Suspicious PowerShell Execution")
        description: What this rule detects and why
        logsource_type: One of: process_creation, logon, service_install,
                       registry, network, powershell, file
        selection: JSON string of field→value detection pairs.
            Example: '{"Image|endswith": "\\\\cmd.exe", "ParentImage|endswith": "\\\\explorer.exe"}'
        level: Severity: informational, low, medium, high, critical
        technique_id: MITRE ATT&CK technique (e.g., "T1059.001")
        tactic: MITRE ATT&CK tactic (e.g., "execution")
        filter_fields: Optional JSON string of fields to exclude from detection.
        false_positives: Comma-separated list of known false positive scenarios.
    """
    try:
        selection_dict = json.loads(selection) if selection else {}
        filter_dict = json.loads(filter_fields) if filter_fields else {}
        fp_list = [s.strip() for s in false_positives.split(",") if s.strip()] if false_positives else None

        detection = {"selection": selection_dict}
        if filter_dict:
            detection["filter"] = filter_dict

        result = generate_sigma_rule(
            title=title,
            description=description,
            logsource_type=logsource_type,
            detection=detection,
            level=level,
            technique_id=technique_id,
            tactic=tactic,
            false_positives=fp_list,
        )

        _investigation_log.log_tool_call(
            "create_sigma_rule", {"title": title, "technique": technique_id},
            f"Generated rule: {title}",
        )

        return json.dumps({
            "status": "ok",
            "rule_id": result["rule_id"],
            "title": title,
            "level": level,
            "yaml": result["yaml"],
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def generate_sigma_from_findings() -> str:
    """Auto-generate Sigma rules from all current find_evil results.

    Runs find_evil, maps each finding type to appropriate Sigma logsource
    and detection logic, writes rules to investigation-output/sigma-rules/.

    Returns summary of generated rules.
    """
    try:
        # Run find_evil to get current findings
        findings_json = find_evil(summarize=True)
        findings = json.loads(findings_json)

        if isinstance(findings, dict) and findings.get("status") == "clean":
            return json.dumps({"status": "no_findings", "message": "No findings to generate rules from."})

        # Generate rules
        rules = generate_rules_from_findings(run_cypher, findings)

        # Write to disk
        result = write_sigma_rules(rules)

        _investigation_log.log_tool_call(
            "generate_sigma_from_findings", {},
            f"Generated {result['rules_written']} Sigma rules",
        )

        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


# --- ATT&CK Navigator Layer ---


@mcp.tool()
def generate_attack_navigator() -> str:
    """Generate a MITRE ATT&CK Navigator layer from investigation findings.

    Runs find_evil, maps each finding to ATT&CK techniques, checks for
    corrections, and produces a JSON layer file loadable in the ATT&CK
    Navigator web tool (https://mitre-attack.github.io/attack-navigator/).

    Color-coded by confidence:
      Red    = CONFIRMED (structural evidence)
      Orange = PARTIAL (some evidence)
      Yellow = INFERENCE (plausible, unverified)
      Grey   = CORRECTED (flagged as FP)

    Output: investigation-output/navigator-layer.json
    """
    try:
        # Get findings
        findings_json = find_evil(summarize=True)
        findings = json.loads(findings_json)

        if isinstance(findings, dict) and findings.get("status") == "clean":
            return json.dumps({"status": "no_findings",
                              "message": "No findings to map to ATT&CK."})

        # Generate layer
        layer = generate_layer_from_findings(run_cypher, findings,
                                              investigation_log=_investigation_log)

        # Write to disk
        result = write_navigator_layer(layer)

        _investigation_log.log_tool_call(
            "generate_attack_navigator", {},
            f"Generated ATT&CK layer with {result['techniques_mapped']} techniques",
        )

        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


# --- Evidence Chain ---


@mcp.tool()
def generate_evidence_chain_report() -> str:
    """Generate a full evidence chain JSON from investigation findings.

    For every finding, traces through the graph to collect all referenced
    entities with their _origin_* provenance metadata. Produces a JSON file
    that maps: finding → entities → origin tool → source artifact → line number.

    An auditor can take any finding and walk backwards through the chain
    to the exact line in the source Plaso JSONL file.

    Includes: provenance coverage stats, correction data, sample results.
    Output: investigation-output/evidence-chain.json
    """
    try:
        findings_json = find_evil(summarize=True)
        findings = json.loads(findings_json)

        if isinstance(findings, dict) and findings.get("status") == "clean":
            return json.dumps({"status": "no_findings",
                              "message": "No findings to trace."})

        chain = generate_evidence_chain(
            run_cypher, findings,
            investigation_id=_investigation_log.investigation_id,
        )
        result = write_evidence_chain(chain)

        _investigation_log.log_tool_call(
            "generate_evidence_chain_report", {},
            f"Evidence chain: {result['findings']} findings, "
            f"{result['total_entities']} entities, "
            f"{result['provenance_coverage']} coverage",
        )

        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


# --- Audit Report ---


@mcp.tool()
def generate_audit_report_tool() -> str:
    """Generate a complete audit report for the investigation.

    Produces both JSON and Markdown reports containing:
    - Executive summary (hosts, users, findings, duration)
    - All findings with confidence levels and evidence
    - Full verification audit trail (predicates passed/failed, divergences)
    - Corrections (FP, hallucination, unsupported — with reasons)
    - Provenance integrity (coverage stats per entity type)
    - Graph overview (node/edge counts, time range)
    - List of all generated output artifacts
    - Investigation metadata (session ID, tool calls, elapsed time)

    Output:
      investigation-output/audit-report.json  (machine-readable)
      investigation-output/audit-report.md    (human-readable)
    """
    try:
        # Get current findings
        findings_json = find_evil(summarize=True)
        findings = json.loads(findings_json)
        if isinstance(findings, dict) and findings.get("status") == "clean":
            findings = []

        result = generate_audit_report(
            run_cypher,
            _investigation_log,
            findings,
        )

        _investigation_log.log_tool_call(
            "generate_audit_report", {},
            f"Audit report: {result['findings_count']} findings, "
            f"{result['provenance_coverage']} provenance",
        )

        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


# --- Investigative Report ---


@mcp.tool()
def generate_investigation_report(formats: str = "md,pdf,docx") -> str:
    """Generate a full investigative report — the deliverable a senior IR analyst would produce.

    Structure: Management Summary → Scope → Findings (with evidence tables,
    ATT&CK mapping, confidence levels) → Recommendations (operational/tactical/
    strategic) → Next Steps → Closing Statement.

    Automatically rendered to Markdown (source of truth) + PDF (board/legal)
    + DOCX (analyst copy-paste).

    This is the "analytical reasoning" deliverable required by the hackathon rules.
    """
    try:
        # Get current findings
        findings_json = find_evil(summarize=True)
        findings = json.loads(findings_json)
        if isinstance(findings, dict) and findings.get("status") == "clean":
            findings = []

        # Generate markdown report
        result = generate_investigative_report(
            run_cypher, _investigation_log, findings
        )

        # Render to requested formats
        md_path = result.get("markdown_path", "")
        if md_path:
            render_result = render_report(md_path, output_dir="investigation-output",
                                          formats=[f.strip() for f in formats.split(",")])
            result["rendered"] = render_result.get("rendered", {})
            result["render_errors"] = render_result.get("errors", [])

        _investigation_log.log_tool_call(
            "generate_investigation_report",
            {"formats": formats},
            f"Report: {result['findings_count']} findings, rendered to {list(result.get('rendered', {}).keys())}",
        )

        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


# --- Report Rendering ---


@mcp.tool()
def render_investigation_report(formats: str = "md,pdf,docx") -> str:
    """Render the audit report to multiple formats: PDF, DOCX, Markdown.

    Takes the existing audit-report.md and renders it via pandoc.
    Markdown is the source of truth — PDF and DOCX are render targets:
      - PDF: for board/legal/compliance (formatted, professional)
      - DOCX: for analysts (copy-paste into existing reports)
      - MD: for IR teams (version control, tooling, portability)

    Requires pandoc installed (available on SIFT Workstation).
    PDF requires a LaTeX engine (pdflatex/xelatex).

    Args:
        formats: Comma-separated list of formats. Default: "md,pdf,docx".
                 Supported: md, pdf, docx, html.
    """
    md_path = "investigation-output/audit-report.md"
    fmt_list = [f.strip() for f in formats.split(",") if f.strip()]

    try:
        result = render_report(md_path, output_dir="investigation-output", formats=fmt_list)
        _investigation_log.log_tool_call(
            "render_investigation_report", {"formats": fmt_list},
            f"Rendered: {list(result.get('rendered', {}).keys())}",
        )
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


# --- Threat Intelligence Enrichment ---


@mcp.tool()
def lookup_hash(file_hash: str) -> str:
    """Look up a file hash on VirusTotal. Hash-only — NEVER uploads files.

    Zero customer data exfiltration. "Unknown hash" is itself a meaningful
    signal (novel malware vs known family).

    Requires VT_API_KEY environment variable.

    Args:
        file_hash: SHA256, SHA1, or MD5 hash string.
    """
    result = vt_hash_lookup(file_hash)
    _investigation_log.log_tool_call(
        "lookup_hash", {"hash": file_hash},
        f"VT: {result.get('status')} — {result.get('detection_rate', 'N/A')}",
    )
    return json.dumps(result, default=str, indent=2)


@mcp.tool()
def enrich_executables(max_lookups: int = 20) -> str:
    """Batch-enrich Executable nodes with VirusTotal threat intelligence.

    Queries VT for each executable that has a hash but hasn't been enriched yet.
    Results written back to graph as ThreatIntel nodes linked via ENRICHED_BY edges.
    Skips known Windows/ProgramFiles paths.

    Rate-limited to respect VT free tier (4 req/min). Set VT_API_KEY env var.

    Args:
        max_lookups: Maximum VT API calls (default 20, free tier allows 500/day).
    """
    try:
        result = enrich_executables_from_graph(run_cypher, max_lookups=max_lookups)
        _investigation_log.log_tool_call(
            "enrich_executables", {"max_lookups": max_lookups},
            f"Enriched: {result['found']} found, {result['malicious']} malicious, "
            f"{result['not_found']} unknown to VT",
        )
        return json.dumps(result, default=str, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


# --- Entrypoint ---


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
