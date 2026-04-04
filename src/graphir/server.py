"""graphir MCP server — exposes Neo4j graph investigation tools to Claude Code."""

import json
import os

from mcp.server.fastmcp import FastMCP
from neo4j import GraphDatabase

from graphir.graph import init_schema
from graphir.batch_ingest import BatchIngester
from graphir.verification import VerificationEngine
from graphir.corrections import (
    record_correction, check_existing_corrections, get_correction_summary,
)
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


# --- MCP Tools ---


@mcp.tool()
def ping() -> str:
    """Health check — verify the graphir MCP server is running and Neo4j is reachable."""
    try:
        run_cypher("RETURN 1 AS ok")
        return json.dumps({"status": "ok", "neo4j": "connected"})
    except Exception as e:
        return json.dumps({"status": "ok", "neo4j": f"error: {e}"})


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
        return json.dumps(stats, default=str, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def query_graph(cypher: str) -> str:
    """Execute an arbitrary Cypher query against the investigation graph.

    Use this for ad-hoc investigation queries. The agent writes Cypher based on
    what it's investigating. Returns results as JSON.

    Args:
        cypher: A valid Cypher query string.
    """
    try:
        results = run_cypher(cypher)
        return json.dumps(results, default=str, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def find_evil(summarize: bool = True) -> str:
    """Run all predefined hunt patterns against the investigation graph.

    Executes a battery of generic DFIR detection queries and returns scored findings.
    Use this as the first step in any investigation to get initial indicators.

    Args:
        summarize: If True (default), consolidate results by grouping duplicates
                  and returning counts + top examples instead of raw rows.
                  Set False for full raw results (may be large).
    """
    findings = []

    hunt_queries = {
        "suspicious_process_chain": {
            "description": "Suspicious parent-child process relationships",
            "query": """
                MATCH (parent:Process)-[:SPAWNED]->(child:Process)
                WHERE parent.name IN ['explorer.exe', 'svchost.exe', 'services.exe',
                                       'winlogon.exe', 'lsass.exe', 'taskhost.exe']
                  AND child.name IN ['cmd.exe', 'powershell.exe', 'wscript.exe',
                                      'cscript.exe', 'mshta.exe', 'regsvr32.exe',
                                      'rundll32.exe', 'certutil.exe']
                RETURN parent.name AS parent, child.name AS child,
                       child.cmdline AS cmdline, child.timestamp AS ts
                ORDER BY child.timestamp
                LIMIT 200
            """,
            "summarize_query": """
                MATCH (parent:Process)-[:SPAWNED]->(child:Process)
                WHERE parent.name IN ['explorer.exe', 'svchost.exe', 'services.exe',
                                       'winlogon.exe', 'lsass.exe', 'taskhost.exe']
                  AND child.name IN ['cmd.exe', 'powershell.exe', 'wscript.exe',
                                      'cscript.exe', 'mshta.exe', 'regsvr32.exe',
                                      'rundll32.exe', 'certutil.exe']
                WITH parent.name AS parent, child.name AS child, count(*) AS occurrences,
                     collect(DISTINCT child.cmdline)[0..3] AS sample_cmdlines,
                     min(child.timestamp) AS first_seen, max(child.timestamp) AS last_seen
                RETURN parent, child, occurrences, sample_cmdlines, first_seen, last_seen
                ORDER BY occurrences DESC
            """,
            "tactic": "Execution",
            "technique": "T1059",
        },
        "lateral_movement_logons": {
            "description": "Network logons (Type 3/10) across hosts — potential lateral movement",
            "query": """
                MATCH (u:User)-[r:LOGGED_ON]->(dst:Host)
                WHERE r.logon_type IN [3, 10]
                RETURN u.name AS user, dst.hostname AS destination,
                       r.logon_type AS logon_type, r.src_ip AS src_ip,
                       r.timestamp AS ts
                ORDER BY r.timestamp
                LIMIT 200
            """,
            "summarize_query": """
                MATCH (u:User)-[r:LOGGED_ON]->(dst:Host)
                WHERE r.logon_type IN [3, 10]
                WITH u.name AS user, dst.hostname AS host,
                     count(*) AS sessions,
                     collect(DISTINCT r.src_ip) AS source_ips,
                     collect(DISTINCT r.logon_type) AS logon_types,
                     min(r.timestamp) AS first_seen, max(r.timestamp) AS last_seen
                RETURN user, host, sessions, source_ips, logon_types, first_seen, last_seen
                ORDER BY sessions DESC
            """,
            "tactic": "Lateral Movement",
            "technique": "T1021",
        },
        "lsass_access": {
            "description": "Non-system processes accessing LSASS — potential credential dumping",
            "query": """
                MATCH (p:Process)-[:ACCESSED]->(target:Process {name: 'lsass.exe'})
                WHERE NOT p.name IN ['svchost.exe', 'csrss.exe', 'services.exe', 'wininit.exe']
                RETURN p.name AS accessor, p.cmdline AS cmdline,
                       p.pid AS pid, p.timestamp AS ts
                ORDER BY p.timestamp
                LIMIT 200
            """,
            "summarize_query": """
                MATCH (p:Process)-[:ACCESSED]->(target:Process {name: 'lsass.exe'})
                WHERE NOT p.name IN ['svchost.exe', 'csrss.exe', 'services.exe', 'wininit.exe']
                WITH p.name AS accessor, count(*) AS access_count,
                     collect(DISTINCT p.cmdline)[0..3] AS sample_cmdlines,
                     min(p.timestamp) AS first_seen, max(p.timestamp) AS last_seen
                RETURN accessor, access_count, sample_cmdlines, first_seen, last_seen
                ORDER BY access_count DESC
            """,
            "tactic": "Credential Access",
            "technique": "T1003.001",
        },
        "service_installation": {
            "description": "Service installations — potential persistence or lateral movement",
            "query": """
                MATCH (e:Event)-[:ON_HOST]->(h:Host)
                WHERE e.event_id = 7045 OR e.event_id = 'registry_service'
                RETURN e.service_name AS service, e.service_path AS path,
                       h.hostname AS host, e.timestamp AS ts
                ORDER BY e.timestamp
                LIMIT 200
            """,
            "summarize_query": """
                MATCH (e:Event)-[:ON_HOST]->(h:Host)
                WHERE (e.event_id = 7045 OR e.event_id = 'registry_service')
                  AND e.service_name IS NOT NULL AND e.service_name <> ''
                WITH e.service_name AS service, e.service_path AS path,
                     h.hostname AS host, count(*) AS install_count,
                     min(e.timestamp) AS first_seen, max(e.timestamp) AS last_seen
                RETURN service, path, host, install_count, first_seen, last_seen
                ORDER BY first_seen
            """,
            "tactic": "Persistence",
            "technique": "T1543.003",
        },
        "rare_processes": {
            "description": "Rarely executed processes — anomaly detection by frequency",
            "query": """
                MATCH (p:Process)
                WITH p.name AS proc_name, count(*) AS exec_count
                WHERE exec_count <= 2
                RETURN proc_name, exec_count
                ORDER BY exec_count ASC
                LIMIT 100
            """,
            "summarize_query": """
                MATCH (p:Process)
                WITH p.name AS proc_name, count(*) AS exec_count,
                     collect(DISTINCT p.cmdline)[0..2] AS sample_cmdlines,
                     collect(DISTINCT p.user)[0..2] AS users
                WHERE exec_count <= 2
                RETURN proc_name, exec_count, sample_cmdlines, users
                ORDER BY exec_count ASC
                LIMIT 50
            """,
            "tactic": "Discovery",
            "technique": "T1057",
        },
        "encoded_commands": {
            "description": "Encoded/obfuscated command line arguments",
            "summarize_query": """
                MATCH (p:Process)
                WHERE p.cmdline CONTAINS '-enc ' OR p.cmdline CONTAINS '-EncodedCommand'
                   OR p.cmdline CONTAINS 'frombase64' OR p.cmdline CONTAINS 'hidden'
                   OR p.cmdline CONTAINS '-w hidden' OR p.cmdline CONTAINS '-nop'
                RETURN p.name AS process, p.cmdline AS cmdline,
                       p.user AS user, p.timestamp AS ts
                ORDER BY p.timestamp
                LIMIT 50
            """,
            "query": """
                MATCH (p:Process)
                WHERE p.cmdline CONTAINS '-enc ' OR p.cmdline CONTAINS '-EncodedCommand'
                   OR p.cmdline CONTAINS 'frombase64' OR p.cmdline CONTAINS 'hidden'
                   OR p.cmdline CONTAINS '-w hidden' OR p.cmdline CONTAINS '-nop'
                RETURN p.name AS process, p.cmdline AS cmdline,
                       p.user AS user, p.timestamp AS ts
                ORDER BY p.timestamp
                LIMIT 50
            """,
            "tactic": "Defense Evasion",
            "technique": "T1027",
        },
        "discovery_commands": {
            "description": "Reconnaissance / discovery commands",
            "summarize_query": """
                MATCH (p:Process)
                WHERE p.name IN ['whoami.exe', 'ipconfig.exe', 'net.exe', 'net1.exe',
                                  'nltest.exe', 'systeminfo.exe', 'tasklist.exe',
                                  'nslookup.exe', 'quser.exe', 'arp.exe',
                                  'route.exe', 'findstr.exe', 'netstat.exe']
                WITH p.name AS tool, count(*) AS exec_count,
                     collect(DISTINCT p.cmdline)[0..3] AS sample_cmdlines,
                     collect(DISTINCT p.user)[0..2] AS users,
                     min(p.timestamp) AS first_seen, max(p.timestamp) AS last_seen
                RETURN tool, exec_count, sample_cmdlines, users, first_seen, last_seen
                ORDER BY first_seen
            """,
            "query": """
                MATCH (p:Process)
                WHERE p.name IN ['whoami.exe', 'ipconfig.exe', 'net.exe', 'net1.exe',
                                  'nltest.exe', 'systeminfo.exe', 'tasklist.exe',
                                  'nslookup.exe', 'quser.exe', 'arp.exe',
                                  'route.exe', 'findstr.exe', 'netstat.exe']
                RETURN p.name AS tool, p.cmdline AS cmdline, p.user AS user,
                       p.timestamp AS ts
                ORDER BY p.timestamp
                LIMIT 200
            """,
            "tactic": "Discovery",
            "technique": "T1082",
        },
    }

    for hunt_name, hunt in hunt_queries.items():
        try:
            q = hunt.get("summarize_query") if summarize else hunt["query"]
            results = run_cypher(q)
            if results:
                findings.append(
                    {
                        "hunt": hunt_name,
                        "description": hunt["description"],
                        "tactic": hunt["tactic"],
                        "technique": hunt["technique"],
                        "hit_count": len(results),
                        "results": results,
                    }
                )
        except Exception as e:
            findings.append(
                {"hunt": hunt_name, "error": str(e)}
            )

    if not findings:
        return json.dumps({"status": "clean", "message": "No findings from initial hunt patterns. Consider ingesting more evidence or running targeted queries."})

    return json.dumps(findings, default=str, indent=2)


@mcp.tool()
def shortest_path(source_name: str, target_name: str) -> str:
    """Find the shortest path between two entities in the investigation graph.

    Core graph advantage: answers 'how did the attacker get from A to B?'

    Args:
        source_name: Name or identifier of the source entity.
        target_name: Name or identifier of the target entity.
    """
    query = """
        MATCH (src {name: $source}), (dst {name: $target}),
              path = shortestPath((src)-[*..10]-(dst))
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
def entity_neighborhood(entity_name: str, hops: int = 2) -> str:
    """Return all entities within N hops of a given entity.

    The 'show me everything connected to this' query. Useful for understanding
    the context around a suspicious entity.

    Args:
        entity_name: Name or identifier of the entity to explore.
        hops: Number of relationship hops to traverse (default 2, max 4).
    """
    hops = min(hops, 4)
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
            finding.confidence.value,
            tactic=finding.claims[0].tactic if finding.claims else "",
            technique=finding.claims[0].technique if finding.claims else "",
            claim_summary=finding.claim_summary,
        )

        # Auto-record correction if finding is rejected
        # Correction type semantics:
        #   "unsupported" — all required predicates returned absent_data
        #     (evidence may exist but wasn't ingested, or claim is outside graph coverage)
        #   "downgraded" — some predicates failed for mixed reasons
        #   "hallucination" reserved for analyst/explicit agent flag only
        if finding.confidence.value == "INSUFFICIENT_EVIDENCE":
            all_divergences = [d for c in finding.claims for d in c.divergences]
            if all_divergences:
                all_absent = all(
                    d["reason"] == "absent_data" for d in all_divergences
                )
                record_correction(
                    run_cypher,
                    correction_type="unsupported" if all_absent else "downgraded",
                    reason="; ".join(d["detail"] for d in all_divergences[:3]),
                    original_claim=narrative,
                    entity_name=entity_name,
                    corrected_by="agent",
                    original_confidence="INFERENCE",
                    corrected_confidence="INSUFFICIENT_EVIDENCE",
                    divergence_data=all_divergences,
                    investigation_id=_investigation_log.investigation_id,
                    finding_id=finding.finding_id,
                )
                _investigation_log.log_correction(
                    "unsupported" if all_absent else "downgraded",
                    all_divergences[0].get("detail", ""),
                    narrative, entity_name,
                )

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
def check_corrections(entity_name: str) -> str:
    """Check if an entity has any existing corrections recorded against it.

    Call this BEFORE re-asserting a claim about an entity that may have been
    previously flagged. Prevents hallucination re-generation.

    Args:
        entity_name: The entity to check for existing corrections.
    """
    results = check_existing_corrections(run_cypher, entity_name)
    if not results:
        return json.dumps({"entity": entity_name, "corrections": [],
                          "message": "No existing corrections for this entity."})
    return json.dumps({"entity": entity_name, "correction_count": len(results),
                       "corrections": results}, default=str, indent=2)


@mcp.tool()
def investigation_summary() -> str:
    """Get a summary of the current investigation session.

    Returns: total log entries, findings by confidence, verification count,
    corrections count, self-corrections count, and elapsed time.

    Use this to get an overview of what the investigation has done so far.
    """
    summary = _investigation_log.get_summary()

    # Also get graph-level correction summary
    try:
        correction_stats = get_correction_summary(run_cypher)
        summary["graph_corrections"] = correction_stats
    except Exception:
        pass

    return json.dumps(summary, default=str, indent=2)


# --- Entrypoint ---


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
