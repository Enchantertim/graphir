"""Attack reconstruction — orders verified evidence into a structured narrative.

Walks the graph (not the LLM's memory) to assemble the attack story:
account hops, tool deployment, persistence, anti-forensics — each phase
timestamped, each lateral hop independently verified by the
VerificationEngine before it enters the narrative.

Completes the fractal L0 layer: with materialize=True, findings become
first-class (:Finding) vertices with SUPPORTED_BY edges down to the
entities that evidence them, so the investigation itself is traversable —
incident narrative → finding → entity → event → raw artifact line.
"""

import hashlib
import json

_SYSTEM_ACCOUNTS = ["anonymous logon", "local service", "network service",
                    "system", "dwm-1", "umfd-0"]

_MAX_VERIFIED_HOPS = 10


def _fid(*parts: str) -> str:
    """Deterministic finding id so materialization is idempotent."""
    return hashlib.sha1("|".join(parts).encode()).hexdigest()[:12]


def reconstruct(run_cypher, engine, username: str = "") -> dict:
    """Reconstruct the attack chain from the graph.

    Args:
        run_cypher: Cypher execution function
        engine: VerificationEngine for per-hop structural verification
        username: Focus account. Empty = auto-select the human account with
                  network logons to the most hosts (machine accounts and
                  well-known service principals excluded).
    """
    phases = []

    # --- Account selection -------------------------------------------------
    candidates = run_cypher("""
        MATCH (u:User)-[r:LOGGED_ON]->(h:Host)
        WHERE r.logon_type IN [3, 9, 10]
          AND NOT u.name ENDS WITH '$'
          AND NOT toLower(u.name) IN $system_accounts
        WITH u.name AS user, count(DISTINCT h) AS host_count,
             count(*) AS sessions, min(r.timestamp) AS first_seen
        WHERE host_count >= 2
        RETURN user, host_count, sessions, first_seen
        ORDER BY host_count DESC, sessions DESC
        LIMIT 10
    """, {"system_accounts": _SYSTEM_ACCOUNTS})

    if username:
        focus = username
    elif candidates:
        focus = candidates[0]["user"]
    else:
        return {"status": "no_multi_host_accounts",
                "note": "No human account with network logons to >=2 hosts. "
                        "Specify username explicitly or investigate manually."}

    # --- Phase: lateral movement (verified hop by hop) ----------------------
    hops = run_cypher("""
        MATCH (u:User)-[r:LOGGED_ON]->(h:Host)
        WHERE toLower(u.name) = toLower($user) AND r.logon_type IN [3, 9, 10]
        WITH h.hostname AS host, min(r.timestamp) AS first_ts,
             max(r.timestamp) AS last_ts, count(*) AS sessions,
             collect(DISTINCT r.logon_type) AS logon_types,
             collect(DISTINCT r.src_ip)[0..3] AS src_ips
        RETURN host, first_ts, last_ts, sessions, logon_types, src_ips
        ORDER BY first_ts
    """, {"user": focus})

    verified_hops = []
    for hop in hops[:_MAX_VERIFIED_HOPS]:
        finding = engine.verify_lateral_movement(
            focus, hop["host"],
            f"[reconstruct] {focus} -> {hop['host']}")
        verified_hops.append({**hop, "confidence": str(finding.confidence)})
    for hop in hops[_MAX_VERIFIED_HOPS:]:
        verified_hops.append({**hop, "confidence": "NOT_VERIFIED (hop cap)"})

    if verified_hops:
        phases.append({
            "phase": "lateral_movement",
            "tactic": "Lateral Movement", "technique": "T1021",
            "actor": focus,
            "first_ts": str(verified_hops[0]["first_ts"]),
            "hops": verified_hops,
        })

    # --- Phase: tool deployment (cross-host binaries + MACB via SAME_BINARY) -
    deployments = run_cypher("""
        MATCH (h:Host)-[r:HAS_EXECUTABLE]->(x:Executable)
        WITH x, collect(DISTINCT h.hostname) AS hosts,
             collect(DISTINCT r.source) AS sources
        WHERE size(hosts) >= 2
          AND NOT toLower(x.path) CONTAINS 'windows\\\\winsxs'
        OPTIONAL MATCH (x)-[:SAME_BINARY]->(f:File)
        WITH x.name AS binary, hosts, sources,
             min(f.born_time) AS earliest_born, max(f.born_time) AS latest_born
        RETURN binary, hosts, sources, earliest_born, latest_born
        ORDER BY size(hosts) DESC
        LIMIT 25
    """)
    # Timestomp signal: the SAME file path on the SAME host with CONFLICTING
    # born times, for binaries that have execution evidence. Same-path
    # restriction kills the noise from generic basenames (update.exe in
    # hundreds of Windows Update GUID dirs); cross-host spread is benign.
    macb_conflicts = run_cypher("""
        MATCH (x:Executable)-[:SAME_BINARY]->(f:File)<-[:MODIFIED]-(h:Host)
        WHERE f.born_time IS NOT NULL
        WITH h.hostname AS host, toLower(f.path) AS file,
             collect(DISTINCT f.born_time) AS born_times
        WHERE size(born_times) > 1
          AND duration.between(
                reduce(a = head(born_times), t IN born_times |
                       CASE WHEN t < a THEN t ELSE a END),
                reduce(a = head(born_times), t IN born_times |
                       CASE WHEN t > a THEN t ELSE a END)).months >= 6
        RETURN file, host, born_times[0..6] AS born_times,
               size(born_times) AS distinct_born_count
        ORDER BY distinct_born_count DESC
        LIMIT 15
    """)
    if deployments or macb_conflicts:
        phases.append({
            "phase": "tool_deployment",
            "tactic": "Execution", "technique": "T1570",
            "note": "cross_host_binaries are present on multiple hosts; "
                    "macb_conflicts are binaries with conflicting born times "
                    "on the SAME host (timestomping/recreation signal)",
            "cross_host_binaries": deployments,
            "macb_conflicts": macb_conflicts,
        })

    # --- Phase: persistence (service installs) ------------------------------
    services = run_cypher("""
        MATCH (e:Event)-[:ON_HOST]->(h:Host)
        WHERE e.event_id IN [7045, 4697]
          AND e.service_path IS NOT NULL
          AND NOT toLower(e.service_path) CONTAINS 'system32'
          AND NOT toLower(e.service_path) IN ['running', 'stopped']
        RETURN e.service_name AS service, e.service_path AS path,
               h.hostname AS host, min(e.timestamp) AS installed
        ORDER BY installed
        LIMIT 20
    """)
    if services:
        phases.append({
            "phase": "persistence",
            "tactic": "Persistence", "technique": "T1543.003",
            "services": services,
        })

    # --- Phase: defense evasion (anti-forensics) -----------------------------
    wipers = run_cypher("""
        MATCH (h:Host)-[r:HAS_EXECUTABLE]->(x:Executable)
        WHERE any(t IN ['ccleaner', 'bleachbit', 'sdelete', 'bcwipe',
                        'eraser', 'privazer']
                  WHERE toLower(x.path) CONTAINS t)
        RETURN x.name AS tool, collect(DISTINCT h.hostname) AS hosts,
               collect(DISTINCT r.source) AS surviving_evidence
    """)
    log_clears = run_cypher("""
        MATCH (e:Event)-[:ON_HOST]->(h:Host)
        WHERE e.event_id IN [1102, 104]
        RETURN h.hostname AS host, count(*) AS clear_events,
               min(e.timestamp) AS first, max(e.timestamp) AS last
    """)
    if wipers or log_clears:
        phases.append({
            "phase": "defense_evasion",
            "tactic": "Defense Evasion", "technique": "T1070",
            "wiper_tools": wipers,
            "log_clearing": log_clears,
            "note": "absence of evidence on these hosts is ambiguous — "
                    "treat INSUFFICIENT_EVIDENCE verdicts as 'possibly destroyed'",
        })

    return {
        "actor": focus,
        "actor_candidates": candidates,
        "phases": phases,
        "mermaid": _mermaid(focus, verified_hops, wipers),
    }


def _mermaid(actor: str, hops: list[dict], wipers: list[dict]) -> str:
    """Render the verified attack chain as a Mermaid diagram.

    GitHub and the MD report render this natively — paste into the
    investigation report's attack-chain section.
    """
    def node_id(host: str) -> str:
        return "H" + hashlib.sha1(host.encode()).hexdigest()[:6]

    lines = ["graph LR", f'    A["{actor}"]:::actor']
    prev = "A"
    for hop in hops:
        hid = node_id(hop["host"])
        conf = hop.get("confidence", "")
        badge = {"CONFIRMED": "✓", "INFERENCE": "~"}.get(conf, "?")
        ts = str(hop.get("first_ts", ""))[:16]
        lines.append(f'    {hid}["{hop["host"]}"]')
        lines.append(
            f'    {prev} -->|"{badge} type {"/".join(map(str, hop.get("logon_types", [])))}, {ts}"| {hid}')
        prev = hid
    wiped_hosts = {h for w in (wipers or []) for h in w.get("hosts", [])}
    chain_hosts = {hop["host"] for hop in hops}
    for host in sorted(wiped_hosts):
        hid = node_id(host)
        if host not in chain_hosts:
            lines.append(f'    {hid}["{host}"]')
        lines.append(f'    {hid} -.->|"evidence wiped"| W(("anti-forensics")):::wiped')
    lines.append("    classDef actor fill:#b91c1c,color:#fff")
    lines.append("    classDef wiped fill:#78716c,color:#fff,stroke-dasharray: 5 5")
    return "\n".join(lines)


def materialize_findings(run_cypher, result: dict,
                         investigation_id: str = "") -> dict:
    """Write the reconstruction into the graph as (:Finding) vertices.

    Completes the L0 investigation layer: each phase finding gets
    SUPPORTED_BY edges to the entities that evidence it, making the
    narrative traversable down to raw artifacts. Idempotent (MERGE on
    deterministic finding_id).
    """
    created = 0
    actor = result.get("actor", "")
    for phase in result.get("phases", []):
        name = phase["phase"]
        if name == "lateral_movement":
            for hop in phase.get("hops", []):
                run_cypher("""
                    MERGE (fi:Finding {finding_id: $fid})
                    SET fi.phase = $phase, fi.tactic = $tactic,
                        fi.technique = $technique, fi.confidence = $conf,
                        fi.summary = $summary,
                        fi.investigation_id = $inv,
                        fi._origin_tool = 'reconstruct_attack'
                    WITH fi
                    OPTIONAL MATCH (u:User) WHERE toLower(u.name) = toLower($actor)
                    FOREACH (_ IN CASE WHEN u IS NULL THEN [] ELSE [1] END |
                        MERGE (fi)-[:SUPPORTED_BY]->(u))
                    WITH fi
                    OPTIONAL MATCH (h:Host) WHERE toLower(h.hostname) = toLower($host)
                    FOREACH (_ IN CASE WHEN h IS NULL THEN [] ELSE [1] END |
                        MERGE (fi)-[:SUPPORTED_BY]->(h))
                """, {
                    "fid": _fid("lm", actor, hop["host"]),
                    "phase": name, "tactic": phase["tactic"],
                    "technique": phase["technique"],
                    "conf": hop.get("confidence", ""),
                    "summary": f"{actor} -> {hop['host']} "
                               f"(types {hop.get('logon_types')}, "
                               f"{hop.get('sessions')} sessions)",
                    "inv": investigation_id,
                    "actor": actor, "host": hop["host"],
                })
                created += 1
        elif name == "defense_evasion":
            for w in phase.get("wiper_tools", []):
                run_cypher("""
                    MERGE (fi:Finding {finding_id: $fid})
                    SET fi.phase = $phase, fi.tactic = 'Defense Evasion',
                        fi.technique = 'T1070.004', fi.confidence = 'CONFIRMED',
                        fi.summary = $summary, fi.investigation_id = $inv,
                        fi._origin_tool = 'reconstruct_attack'
                    WITH fi
                    MATCH (x:Executable) WHERE toLower(x.name) = toLower($tool)
                    MERGE (fi)-[:SUPPORTED_BY]->(x)
                """, {
                    "fid": _fid("wiper", w["tool"]),
                    "phase": name,
                    "summary": f"evidence-destruction tool {w['tool']} on "
                               f"{', '.join(w.get('hosts', []))} "
                               f"(survives in {', '.join(w.get('surviving_evidence', []))})",
                    "inv": investigation_id,
                    "tool": w["tool"],
                })
                created += 1
    return {"findings_materialized": created}
